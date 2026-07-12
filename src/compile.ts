// Top-level pipeline orchestrator (directive §5): source -> tokens/AST -> subset
// validation -> semantic analysis + type check -> storage layout -> Yul -> solc
// -> bytecode + ABI.
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { parse } from './parser.js';
import { expandDiamond } from './diamond.js';
import { DiagnosticBag, CompileError, Diagnostic, demangleModuleName } from './diagnostics.js';
import { validateSubset } from './validator.js';
import { analyze } from './analyzer.js';
import { emitYul, emitLibraryYul, UnsupportedError } from './yul.js';
import { compileYul, LinkReferences } from './solc.js';
import { emitAbi, AbiItem } from './abi.js';
import { bundleImports, detectLegacyPragma, isReferenceIdentifier, remapDiagnostics, BundleSegment } from './imports.js';
import type { ContractIR } from './ir.js';
import { displayName } from './types.js';

export interface StorageLayoutEntry {
  name: string;
  type: string;
  slot: number;
  offset: number;
}

/** Phase B: a compiled external (delegatecall) library object, deployed separately and linked into
 *  the contract at deploy time. `creationBytecode` deploys it; its address is substituted at every
 *  `linkReferences` position of the contract's creation/runtime bytecode. */
export interface CompiledLibrary {
  name: string;
  creationBytecode: string; // hex, no 0x
  runtimeBytecode: string; // hex, no 0x
  // Positions inside THIS library's OWN creation bytecode where ANOTHER external library's address must
  // be linked (an @external library that calls another @external library carries the callee's placeholder
  // in its bytecode). Empty/absent when the library references no other library. Consumed by deployLinked
  // to link + deploy libraries bottom-up (a callee library is deployed and substituted before its caller).
  linkReferences?: LinkReferences;
}

export interface CompileResult {
  contractName: string;
  abi: AbiItem[];
  creationBytecode: string; // hex, no 0x
  runtimeBytecode: string; // hex, no 0x
  yul: string;
  storageLayout: StorageLayoutEntry[];
  ir: ContractIR;
  diagnostics: Diagnostic[];
  // Phase B: present ONLY when the contract references an external (delegatecall) library. `libraries`
  // are the separately-deployed library objects; `linkReferences` are the contract's creation-bytecode
  // placeholder positions (library name -> positions) to substitute with each library's deployed
  // address. Absent (undefined) for an ordinary single-contract compile (backward compatible).
  libraries?: CompiledLibrary[];
  linkReferences?: LinkReferences;
}

export interface CompileOptions {
  fileName?: string;
  evmVersion?: string;
  /** Multi-file compilation: path -> source text for every importable file. When provided, the entry
   *  source's `import { A } from "./file.jeth"` statements resolve against this map (relative to the
   *  importing file), and diagnostics point into the original files. Without it, JETH compiles a single
   *  file and an import statement is a clear reject (JETH035). */
  sources?: Record<string, string>;
}

/**
 * Item #2 (private members): a JS `#`-prefixed member name (`#f()` / `#y`) is JETH's spelling of
 * Solidity `private`. Because private is byte-identical to internal (visibility is a compile-time
 * concept, not a bytecode one), we lower a `#` member exactly like an internal one - by rewriting
 * each PrivateIdentifier (both the `#f`/`#y` DECLARATION and every `this.#x` ACCESS) to a plain,
 * Yul-safe identifier keyed by the CONTAINING contract: `#x` in contract `C` -> `$p$C$x`.
 *
 * Per-contract keying does the visibility enforcement for free: a DERIVED contract's `this.#x`
 * mangles to `$p$D$x`, which `D` never declared, so downstream name resolution finds nothing and
 * rejects - exactly solc's "private is not visible in a derived contract" (JETH runs its own
 * checker; TS's `#` privacy is not otherwise enforced here). It also keeps `#x` distinct from a
 * plain `x`, and one contract's `#x` distinct from another's. No downstream site ever sees a `#`,
 * so the rest of the pipeline is untouched and the emitted bytecode equals solc's `private`.
 */
function manglePrivateMembers(sf: ts.SourceFile): void {
  const f = ts.factory;
  const rewrite = (node: ts.Node, contract: string | undefined): void => {
    const cur = ts.isClassDeclaration(node) && node.name ? node.name.text : contract;
    const named = node as ts.Node & { name?: ts.Node };
    const nm = named.name;
    if (nm && ts.isPrivateIdentifier(nm) && cur) {
      const bare = nm.text.replace(/^#/, '');
      const mangled = f.createIdentifier(`$p$${cur}$${bare}`);
      ts.setTextRange(mangled, nm);
      (mangled as unknown as { parent: ts.Node }).parent = nm.parent ?? node;
      named.name = mangled;
    }
    ts.forEachChild(node, (c) => rewrite(c, cur));
  };
  ts.forEachChild(sf, (n) => rewrite(n, undefined));
}

// Stage 2: the dual-syntax system was removed - native syntax is the ONLY syntax. A source still carrying
// the retired `// use @decorators` pragma is a hard error (JETH480, detectLegacyPragma in imports.ts), and
// the legacy structural decorators (@contract/@external/@view/...) are rejected by collectBannedDecorators
// below with a pointer to their native form.

/**
 * Item #7: a `static` contract field is a compile-time constant / a ctor-set immutable. In idiomatic TS a
 * static member is read as `ClassName.K` (a `this.K` on a static member is a TS type error), but JETH's
 * const/immutable resolution is keyed on `this.K`. Bridge the two by rewriting every `ClassName.K` access
 * (where `ClassName` names a class in this file and `K` is one of its `static` fields) to `this.K`, so the
 * user writes idiomatic, IDE-clean `C.K` while the existing this.<constant> resolver does the work. Both
 * spellings end up valid. Only STATIC-field accesses are touched; `Foo(addr).m()` (a call, not a bare
 * identifier receiver) and any non-static member are left alone.
 */
function rewriteStaticFieldAccess(sf: ts.SourceFile): void {
  // A class's kind decorators (a bare / abstract class carries none; a @struct/@interface/@library class is
  // NOT a contract and its `static` field is not a contract constant, so it must not feed the rewrite map).
  const classDecs = (cls: ts.ClassDeclaration): string[] =>
    (ts.getDecorators(cls) ?? [])
      .map((d) => (ts.isIdentifier(d.expression) ? d.expression.text : ts.isCallExpression(d.expression) && ts.isIdentifier(d.expression.expression) ? d.expression.expression.text : ''))
      .filter(Boolean);
  // Harvest, ONLY from contract-shaped classes, PER CLASS: its static member names and its direct
  // `extends` names. The rewrite is SITE-AWARE: `C.K` at a site inside class E rewrites only when C is E
  // itself or one of E's transitive extends ancestors AND K is a static of C's own chain - exactly the
  // qualified spellings solc's member lookup accepts. An UNRELATED contract-shaped class (not in the
  // site's chain) is never a valid qualifier: rewriting `B.K` there used to silently bind the site
  // chain's same-named K (wrong value); now it is left alone and the analyzer rejects it, like solc.
  const classes = new Map<string, { statics: Set<string>; parents: string[] }>();
  let anyStatics = false;
  const scan = (n: ts.Node): void => {
    // Skip non-contract classes: @struct/@interface/@library decorated, AND a native `static class`
    // (= a library) - its `L.f(a)` calls resolve via the library qualified-name machinery; rewriting them
    // to `this.f(a)` would hijack the call into the contract's own namespace.
    const isStaticClass = ts.isClassDeclaration(n) && (ts.getModifiers(n) ?? []).some((m) => m.kind === ts.SyntaxKind.StaticKeyword);
    if (ts.isClassDeclaration(n) && n.name && !isStaticClass && !classDecs(n).some((d) => d === 'struct' || d === 'interface' || d === 'library')) {
      const statics = new Set<string>();
      for (const m of n.members) {
        // static FIELDS (constant/immutable) AND static METHODS / `get` accessors (class-level functions)
        // are all read/called as `ClassName.x` - harvest every static member name.
        if (!(ts.isPropertyDeclaration(m) || ts.isMethodDeclaration(m) || ts.isGetAccessor(m)) || !ts.isIdentifier(m.name)) continue;
        if ((ts.getModifiers(m) ?? []).some((x) => x.kind === ts.SyntaxKind.StaticKeyword)) statics.add(m.name.text);
      }
      const parents: string[] = [];
      for (const h of n.heritageClauses ?? []) {
        if (h.token !== ts.SyntaxKind.ExtendsKeyword) continue;
        for (const t of h.types) if (ts.isIdentifier(t.expression)) parents.push(t.expression.text);
      }
      classes.set(n.name.text, { statics, parents });
      if (statics.size > 0) anyStatics = true;
    }
    ts.forEachChild(n, scan);
  };
  ts.forEachChild(sf, scan);
  if (!anyStatics) return;
  // name -> the class + its transitive extends ancestors (cycle-safe; an extends cycle is the analyzer's
  // reject, the walk just must not loop). Memoized: chains are tiny but the walk runs per access site.
  const chainMemo = new Map<string, Set<string>>();
  const chainOf = (name: string): Set<string> => {
    const memo = chainMemo.get(name);
    if (memo) return memo;
    const out = new Set<string>();
    const stack = [name];
    while (stack.length > 0) {
      const c = stack.pop()!;
      if (out.has(c)) continue;
      const info = classes.get(c);
      if (!info) continue;
      out.add(c);
      stack.push(...info.parents);
    }
    chainMemo.set(name, out);
    return out;
  };
  const chainHasStatic = (qualifier: string, member: string): boolean => {
    for (const c of chainOf(qualifier)) if (classes.get(c)!.statics.has(member)) return true;
    return false;
  };
  // Every locally-bound name (parameter / let / const / var / destructuring binding). A syntactic pre-pass
  // has no scope analysis, so if a class name is ALSO used as a local/param anywhere, a `C.K` there may bind
  // to the shadowing local (solc: local scope wins) - do NOT rewrite accesses on that name; the ordinary
  // resolver reads the local's field (or rejects), matching solc. Conservative but sound.
  const bound = new Set<string>();
  const collectBound = (n: ts.Node): void => {
    if ((ts.isParameter(n) || ts.isVariableDeclaration(n) || ts.isBindingElement(n)) && ts.isIdentifier(n.name))
      bound.add(n.name.text);
    ts.forEachChild(n, collectBound);
  };
  ts.forEachChild(sf, collectBound);
  const rewrite = (n: ts.Node, encl: string | undefined): void => {
    // track the innermost enclosing CONTRACT-SHAPED class: its chain defines the valid qualifiers here.
    if (ts.isClassDeclaration(n) && n.name && classes.has(n.name.text)) encl = n.name.text;
    if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) && ts.isIdentifier(n.name)) {
      const qual = n.expression.text;
      if (
        encl !== undefined &&
        chainOf(encl).has(qual) &&
        chainHasStatic(qual, n.name.text) &&
        !bound.has(qual)
      ) {
        const thisExpr = ts.factory.createThis();
        ts.setTextRange(thisExpr, n.expression);
        (thisExpr as unknown as { parent: ts.Node }).parent = n;
        (n as { expression: ts.Expression }).expression = thisExpr;
      }
    }
    ts.forEachChild(n, (c) => rewrite(c, encl));
  };
  ts.forEachChild(sf, (n) => rewrite(n, undefined));
}

/**
 * A `static` class member is class-level: its body (or initializer) must not touch `this` (TS semantics;
 * previously this was SILENTLY accepted and read instance state). Another static is read as `ClassName.x`
 * (the rewrite below resolves it). Scans every static method / get accessor / field initializer.
 */
function rejectThisInStaticMembers(sf: ts.SourceFile, diags: DiagnosticBag): void {
  const scanBody = (root: ts.Node, memberName: string): void => {
    const visit = (n: ts.Node): void => {
      if (n.kind === ts.SyntaxKind.ThisKeyword) {
        diags.error(
          n,
          'JETH354',
          `a static member ('${memberName}') cannot use \`this\` (a static belongs to the class, not the instance); read another static as ClassName.<name>`,
        );
      }
      ts.forEachChild(n, visit);
    };
    visit(root); // check the root itself too (a bare `= this` initializer has no children to recurse into)
  };
  const visit = (n: ts.Node): void => {
    if (ts.isClassDeclaration(n)) {
      for (const m of n.members) {
        const isStatic = ts.canHaveModifiers(m) && (ts.getModifiers(m) ?? []).some((x) => x.kind === ts.SyntaxKind.StaticKeyword);
        if (!isStatic) continue;
        const nm = m.name && ts.isIdentifier(m.name) ? m.name.text : '<member>';
        if ((ts.isMethodDeclaration(m) || ts.isGetAccessor(m)) && m.body) scanBody(m.body, nm);
        else if (ts.isPropertyDeclaration(m) && m.initializer) scanBody(m.initializer, nm);
      }
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);
}

/**
 * v3 module scoping: the bundler assigned each DEP file's top-level declarations module-scoped internal
 * names (`Utils` -> `$mN$Utils`) and resolved every import binding - plain or `A as B` aliased - to its
 * target's scoped name. Here each file's DECLARATION-NAME and reference-position identifiers are renamed
 * IN PLACE per that file's map (mutating escapedText keeps the node and its source positions, so
 * diagnostics stay exact). Member names (`x.f`, `this.X`, object keys) are never renamed - members are
 * class-scoped, not module-scoped. The bundler rejected every hazardous shadow up front, so the rewrite
 * cannot hijack an unrelated binding; hash-sensitive spellings (error/event signatures, external-library
 * link symbols and object names) demangle `$mN$` back at their boundaries (demangleModuleName), and the
 * ENTRY file's own declarations are never renamed, so single-file behavior is invariant by construction.
 */
function rewriteModuleScopes(
  sf: ts.SourceFile,
  segments: BundleSegment[],
  renamesByFile: Map<string, Map<string, string>>,
): void {
  if (renamesByFile.size === 0) return;
  const fileOf = (node: ts.Node): string | undefined => {
    const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
    const l = line + 1;
    for (const seg of segments) {
      if (l >= seg.startLine && l < seg.startLine + seg.lineCount) return seg.file;
    }
    return undefined;
  };
  // a dep's TOP-LEVEL class/type/interface/enum name is the declaration side of its rename (in the
  // bundle, every file's statements sit at the one SourceFile's top level).
  const isTopLevelDeclName = (n: ts.Identifier): boolean => {
    const p = n.parent;
    return (
      (ts.isClassDeclaration(p) || ts.isTypeAliasDeclaration(p) || ts.isInterfaceDeclaration(p) || ts.isEnumDeclaration(p)) &&
      p.name === n &&
      p.parent === sf
    );
  };
  const rewrite = (n: ts.Node): void => {
    if (ts.isIdentifier(n) && (isReferenceIdentifier(n) || isTopLevelDeclName(n))) {
      const file = fileOf(n);
      const to = file ? renamesByFile.get(file)?.get(n.text) : undefined;
      if (to) {
        (n as unknown as { escapedText: ts.__String }).escapedText = ts.escapeLeadingUnderscores(to);
      }
    }
    ts.forEachChild(n, rewrite);
  };
  ts.forEachChild(sf, rewrite);
}

/** `$m<N>$` identifiers are reserved for the v3 module-scoping rename (src/imports.ts): a user-written
 *  one would collide with the rename space, and demangleModuleName would silently rewrite it at every
 *  hash boundary (an error named `$m1$X` would get selector keccak('X(...)') - a name not in the source).
 *  Checked on the PRE-RENAME AST so it sees only user-written spellings. */
function rejectReservedModuleIdentifiers(sf: ts.SourceFile, diags: DiagnosticBag): void {
  const visit = (n: ts.Node): void => {
    if (ts.isIdentifier(n) && /^\$m\d+\$/.test(n.text)) {
      // the raw spelling is NOT quoted in the message: the message demangler would strip its `$m<N>$`
      // prefix and misquote it; the diagnostic's source span already points at the identifier.
      diags.error(n, 'JETH036', `this identifier uses the reserved '$m<N>$' module-scoping prefix; rename it`);
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);
}

// ---------------------------------------------------------------------------------------------
// STAGE 2 - LEGACY DECORATOR BAN (JETH481). Native syntax is now the ONLY syntax, so every structural
// decorator that has a native spelling is rejected LOUDLY with a pointer to that spelling. compileUnit scans
// the ORIGINAL USER SOURCE (never the diamond-expanded text - expandDiamond synthesizes @contract/@external/
// ... internally, and scanning that would ban the compiler's OWN decorators) and surfaces the pointer before
// every other front-end diagnostic (a diamond's pre-parse gate errors, JETH41x, still precede it). Legacy
// visibility decorators @public/@internal/@private are banned here too (native visibility is a return marker
// / bare-default / leading `#`). The KEEP set stays legal and is NOT listed here: @virtual / @override /
// @modifier (and every user-named MODIFIER APPLICATION - those name none of the banned spellings) /
// @nonReentrant / @using / @diamond / @storage / @anonymous, the deployable-kind decorators @proxy / @beacon
// / @facet (no native spelling, same rationale as @diamond), plus @payable ON A CONSTRUCTOR (there is no
// native constructor-payable spelling).
// ---------------------------------------------------------------------------------------------
const BANNED_DECORATOR_POINTERS: Record<string, string> = {
  contract: 'a bare `class C { ... }` is the deployed contract; drop @contract',
  abstract: 'an `abstract class C { ... }` is an abstract base; drop @abstract',
  struct: 'a struct is a `type P = { a: T; ... }` object-type alias; drop @struct',
  interface: 'an interface is native `interface I { m(args): View<T> }`; drop @interface',
  library: 'a library is a `static class L { ... }`; drop @library',
  external: 'a method is exposed with `f(args): External<T>` (Payable<T> if payable); a field with `x: Visible<T>`',
  public: 'a method is exposed with `f(): External<T>` (Payable<T> if payable); a field with `x: Visible<T>`',
  internal: 'internal is the default: drop @internal (a bare method/field is internal)',
  private: 'a private member is spelled with a leading `#` (e.g. `#x`, `#f()`)',
  view: 'mutability is inferred from the body - a read-only method needs no marker (`get f(args): View<T>` declares an explicitly-view accessor; `f(args): View<T>` marks an interface method)',
  pure: 'mutability is inferred from the body - a pure method needs no marker (`get f(args): Pure<T>` declares an explicitly-pure accessor; `f(args): Pure<T>` marks an interface method)',
  read: 'mutability is inferred from the body - a read-only method needs no marker',
  payable: 'a payable method returns `Payable<T>`; @payable is legal only on a constructor',
  state: 'a bare field `x: T` is contract state; drop @state',
  constant: 'a compile-time constant is a `static K: T = ...` field; drop @constant',
  immutable: 'a ctor-set immutable is a `static K: T;` field (no initializer); drop @immutable',
  event: 'an event is `E: event<{ ... }>` (a field) or file-level `type E = event<{ ... }>`; drop @event',
  error: 'an error is `E: error<{ ... }>` (a field) or file-level `type E = error<{ ... }>`; drop @error',
  indexed: 'an indexed event parameter is `x: indexed<T>` inside the event<{ ... }> shape; drop @indexed',
  receive: 'the ether-receive entry is a method named `receive()`; drop @receive',
  fallback: 'the fallback entry is a method named `fallback()`; drop @fallback',
};

/** Stage 2: collect a JETH481 diagnostic for every RETIRED structural decorator (positions are
 *  bundle-relative; the caller remaps for a multi-file compilation). @payable is exempt on a constructor
 *  (its sole kept placement). A user-named modifier application names none of the banned spellings, so it
 *  is never caught here. */
function collectBannedDecorators(sf: ts.SourceFile, fileName: string): Diagnostic[] {
  const out: Diagnostic[] = [];
  const nameOf = (d: ts.Decorator): string | undefined => {
    const e = d.expression;
    if (ts.isIdentifier(e)) return e.text;
    if (ts.isCallExpression(e) && ts.isIdentifier(e.expression)) return e.expression.text;
    return undefined;
  };
  const report = (d: ts.Decorator, name: string): void => {
    const start = d.getStart(sf);
    const { line, character } = sf.getLineAndCharacterOfPosition(start);
    out.push({
      severity: 'error',
      code: 'JETH481',
      message: `@${name} was removed (JETH is native-syntax only): ${BANNED_DECORATOR_POINTERS[name]}`,
      file: fileName,
      line: line + 1,
      column: character + 1,
      length: Math.max(1, d.getEnd() - start),
    });
  };
  const visit = (n: ts.Node): void => {
    if (ts.isConstructorDeclaration(n)) {
      // A ctor's decorators are not reachable via ts.canHaveDecorators (decorating a ctor is not legal TS),
      // but the parser records them; @payable there is the ONE kept ctor spelling, so exempt it.
      for (const d of ts.getDecorators(n as unknown as ts.HasDecorators) ?? []) {
        const name = nameOf(d);
        if (name && name !== 'payable' && Object.prototype.hasOwnProperty.call(BANNED_DECORATOR_POINTERS, name)) report(d, name);
      }
    } else if (ts.canHaveDecorators(n)) {
      for (const d of ts.getDecorators(n) ?? []) {
        const name = nameOf(d);
        if (name && Object.prototype.hasOwnProperty.call(BANNED_DECORATOR_POINTERS, name)) report(d, name);
      }
    } else if (ts.isTypeAliasDeclaration(n) || ts.isInterfaceDeclaration(n) || ts.isEnumDeclaration(n)) {
      // A `type`/`interface`/`enum` declaration cannot legally carry a decorator (canHaveDecorators=false,
      // getDecorators()=[]), but the parser still records a stray `@banned` in node.modifiers with only a
      // GRAMMAR-phase error (TS1206, not a parse diagnostic) - so a retired decorator on its NATIVE form
      // (e.g. `@struct type P = { ... }`) used to be SILENTLY dropped instead of firing the ban. Scan the
      // modifiers directly and report banned names (the sibling of the JETH479 VariableStatement hole).
      for (const m of (n as { modifiers?: ts.NodeArray<ts.ModifierLike> }).modifiers ?? []) {
        if (ts.isDecorator(m)) {
          const name = nameOf(m);
          if (name && Object.prototype.hasOwnProperty.call(BANNED_DECORATOR_POINTERS, name)) report(m, name);
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);
  return out;
}

// ---------------------------------------------------------------------------------------------
// MIGRATION CAPTURE (dev-only, P0c): when JETH_MIGRATE_CAPTURE=<dir> is set, every compile() call
// is recorded - success (creationBytecode) or CompileError (sorted diagnostic codes) - and then the
// result/error passes through UNCHANGED. The records feed scripts/migrate/verify.mjs, which proves
// a codemodded test file behaves IDENTICALLY (bytecode-equal accepts, code-list-equal rejects).
// One JSONL file per worker PID (the suite runs isolate:false parallel), append-only, so parallel
// workers never interleave writes. With the env unset this is a single falsy check - zero behavior
// change (the full suite runs the exact pre-existing path).
// ---------------------------------------------------------------------------------------------
type CaptureOutcome = { ok: true; creationBytecode: string } | { ok: false; codes: string[] };

/** Per-testFile compile ordinal (module-level: one counter space per worker process). The pairing key
 *  for the verifier is (testFile, ordinal): a test file executes its compile calls in a deterministic
 *  order, so the Nth compile of a file pairs with the Nth compile of the same file in the other run. */
const captureOrdinals = new Map<string, number>();

function recordMigrateCapture(dir: string, source: string, opts: CompileOptions, outcome: CaptureOutcome): void {
  try {
    // the first stack frame inside a test file names the test that issued this compile; helper
    // modules (test/_solidity.ts etc.) do not match the `.test.ts` suffix.
    const stack = new Error().stack ?? '';
    const m = stack.match(/\/test\/[^):\s]+\.test\.ts/);
    const testFile = m ? m[0] : '<unknown>';
    const ordinal = captureOrdinals.get(testFile) ?? 0;
    captureOrdinals.set(testFile, ordinal + 1);
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(
      path.join(dir, `capture-${process.pid}.jsonl`),
      JSON.stringify({
        testFile,
        ordinal,
        fileName: opts.fileName ?? null,
        source,
        sources: opts.sources ?? null,
        outcome,
      }) + '\n',
    );
  } catch {
    // capture must NEVER change compile behavior - swallow any recording failure.
  }
}

export function compile(source: string, opts: CompileOptions = {}): CompileResult {
  const captureDir = process.env.JETH_MIGRATE_CAPTURE;
  if (!captureDir) return compileGuarded(source, opts);
  try {
    const result = compileGuarded(source, opts);
    recordMigrateCapture(captureDir, source, opts, { ok: true, creationBytecode: result.creationBytecode });
    return result;
  } catch (e) {
    recordMigrateCapture(
      captureDir,
      source,
      opts,
      e instanceof CompileError
        ? { ok: false, codes: e.diagnostics.map((d) => d.code).sort() }
        : // a non-CompileError throw is recorded too so the two runs' per-file counts stay aligned;
          // the verifier surfaces any asymmetry as a mismatch.
          { ok: false, codes: [`UNCAUGHT:${e instanceof Error ? e.constructor.name : typeof e}`] },
    );
    throw e;
  }
}

/** JETH477: a pathologically deep source (a 2000-term `1n + 1n + ...` chain) overflows the JS call stack
 *  in whichever recursive AST visitor runs first, escaping as a raw RangeError with no diagnostics. solc
 *  compiles such chains (so this is a documented SAFE over-rejection, not parity), but a raw crash is a
 *  bar violation - convert ANY RangeError from ANY phase into a clean CompileError instead of rewriting
 *  every visitor iteratively. The catch runs AFTER the stack has unwound, so building the diagnostic is
 *  safe. A CompileError passes through untouched (it is not a RangeError). */
function compileGuarded(source: string, opts: CompileOptions = {}): CompileResult {
  try {
    return compileUnit(source, opts);
  } catch (e) {
    if (e instanceof RangeError) {
      throw new CompileError([
        {
          severity: 'error',
          code: 'JETH477',
          message:
            'source too deeply nested for the compiler; simplify the expression/statement nesting (e.g. split a very long operator chain into intermediate locals)',
          file: opts.fileName ?? 'contract.jeth',
          line: 1,
          column: 1,
          length: 1,
        },
      ]);
    }
    throw e;
  }
}

function compileUnit(source: string, opts: CompileOptions): CompileResult {
  const fileName = opts.fileName ?? 'contract.jeth';

  // Stage 2: the legacy `// use @decorators` mode was removed - JETH is native-syntax only. A source still
  // carrying the retired pragma is a hard error (JETH480), reported at the directive line BEFORE any other
  // pass (parse, diamond expansion, bundling) so the pointer is the first thing a legacy file sees.
  const legacyPragma = detectLegacyPragma(source);
  if (legacyPragma) {
    throw new CompileError([
      {
        severity: 'error',
        code: 'JETH480',
        message: `the legacy decorator mode was removed; JETH is native-syntax only - drop the '// use @decorators' pragma and use native syntax (see docs/SUPPORTED.md)`,
        file: fileName,
        line: legacyPragma.line,
        column: 1,
        length: 1,
      },
    ]);
  }

  // Phase 3 (DIAMOND): expand a `@diamond('array')` class into the synthesized `@contract` BEFORE parse
  // (a source-text transform, like the parser's enum hoist). Gate diagnostics (positions in the ORIGINAL
  // source) are surfaced first; on a gate error we throw without parsing the (now invalid) expansion.
  const dia = expandDiamond(source, fileName);
  if (dia.diagnostics.length > 0) {
    throw new CompileError(
      dia.diagnostics.map((d) => ({
        severity: 'error' as const,
        code: d.code,
        message: d.message,
        file: fileName,
        line: d.line,
        column: d.column,
        length: d.length,
      })),
    );
  }
  const effectiveSource = dia.expanded ? dia.source : source;

  // Multi-file compilation: resolve the entry's imports against opts.sources into ONE bundled unit
  // (deps first, entry last; imports blanked line-preservingly), keeping a per-file line map so every
  // diagnostic points into its ORIGINAL file. Without opts.sources JETH stays single-file (an import
  // statement is a clear JETH035 reject in the validator).
  let unitSource = effectiveSource;
  let bundleSegments: BundleSegment[] | undefined;
  let bundleVisibility: Map<string, Set<string>> | undefined;
  let bundleRenames: Map<string, Map<string, string>> | undefined;
  if (opts.sources && Object.keys(opts.sources).length > 0) {
    const bundle = bundleImports(effectiveSource, fileName, opts.sources);
    unitSource = bundle.text;
    bundleSegments = bundle.segments;
    bundleVisibility = bundle.visibleByFile;
    bundleRenames = bundle.renamesByFile;
  }

  const parsed = parse(unitSource, fileName);
  const diags = new DiagnosticBag(parsed.sourceFile, fileName);
  // Stage 2: reject every RETIRED structural decorator (each with a pointer to its native form) BEFORE any
  // other front-end diagnostic. The scan runs on the ORIGINAL USER SOURCE, never the diamond-expanded text:
  // expandDiamond rewrites a @diamond class into synthesized @contract/@external/@state/@event/... source,
  // so scanning `parsed.sourceFile` (built from `effectiveSource`) would ban the compiler's OWN synthesized
  // decorators (a fully-native @diamond file would collect ~26x JETH481 and fail to compile). When the entry
  // was NOT diamond-expanded, `parsed.sourceFile` already IS the original user source (single-file) or the
  // bundle of original user files (multi-file - deps are never diamond-expanded), so it is reused unchanged.
  // When it WAS expanded, re-derive the scan target from `source`: parse the entry directly (single-file),
  // or re-bundle the ORIGINAL entry so imported dep decorators keep their file/position mapping (multi-file).
  let banSf = parsed.sourceFile;
  let banSegments = bundleSegments;
  if (dia.expanded) {
    if (opts.sources && Object.keys(opts.sources).length > 0) {
      const banBundle = bundleImports(source, fileName, opts.sources);
      banSf = parse(banBundle.text, fileName).sourceFile;
      banSegments = banBundle.segments;
    } else {
      banSf = parse(source, fileName).sourceFile;
      banSegments = undefined;
    }
  }
  const bannedDecorators = collectBannedDecorators(banSf, fileName);
  if (bannedDecorators.length > 0) {
    if (banSegments) remapDiagnostics(bannedDecorators, banSegments);
    throw new CompileError(bannedDecorators);
  }
  // JETH484: a class-body enum written with a modifier keyword (`const enum E {}` / `export enum E {}` /
  // `static enum E {}` / ...). The hoist pre-pass (parser.ts hoistInClassEnums) deliberately refuses to
  // hoist it: moving only the `enum ... }` text would strand the modifier in the class body, where TS
  // error-recovers it into a modifier on the NEXT member or a keyword-named phantom property - silently
  // accepted residue (the JETH476/479 family), and `static` would even change the next member's meaning.
  // Reject loudly BEFORE analysis ever sees the error-recovered AST. File-level `export enum` (the
  // multi-file import mechanism) is untouched: the scanner tracks modifiers only inside a class body.
  if (parsed.classEnumModifierErrors.length > 0) {
    const modErrors: Diagnostic[] = parsed.classEnumModifierErrors.map((e) => {
      const { line, character } = parsed.sourceFile.getLineAndCharacterOfPosition(e.start);
      return {
        severity: 'error' as const,
        code: 'JETH484',
        message: `a class-body enum cannot carry '${e.modifiers.join(' ')}'; declare it as a plain 'enum ${e.name || 'E'} { ... }' or move it to file level`,
        file: fileName,
        line: line + 1,
        column: character + 1,
        length: Math.max(1, e.end - e.start),
      };
    });
    if (bundleSegments) remapDiagnostics(modErrors, bundleSegments);
    throw new CompileError(modErrors);
  }
  // `$m<N>$` is the v3 module-scoping mangle: a SOURCE identifier spelled that way would collide with the
  // rename space, and the demangle at hash boundaries (error/event selectors, link symbols, ABI names)
  // would silently rewrite it to a name that appears nowhere in the source. Reserved EVERYWHERE - checked
  // pre-rename so it sees only user-written spellings (single-file and bundles alike).
  rejectReservedModuleIdentifiers(parsed.sourceFile, diags);
  // v3 module scoping FIRST: rename each dep's top-level declarations (and every file's import bindings)
  // to their `$mN$` scoped names, so every later pass (the # mangle, the static-member rewrite, all name
  // resolution) sees one consistent namespace with per-file scoping already applied.
  if (bundleSegments && bundleRenames) rewriteModuleScopes(parsed.sourceFile, bundleSegments, bundleRenames);
  // Item #2: rewrite JS `#` private members to contract-scoped internal names BEFORE validation /
  // analysis, so `#f()` / `this.#x` lower like internal members and derived access rejects.
  manglePrivateMembers(parsed.sourceFile);
  // Native syntax (bare class = contract, type = struct, abstract class = abstract base, static member =
  // class-level const/immutable/function) is now the ONLY syntax, so these two pre-passes run
  // unconditionally.
  // A `static` member belongs to the CLASS, not the instance: `this` inside a static body is invalid TS
  // semantics and would silently read instance state. Enforced BEFORE the ClassName.x rewrite below, which
  // legitimately INTRODUCES synthesized `this` nodes for `C.K`/`C.f(...)` accesses.
  rejectThisInStaticMembers(parsed.sourceFile, diags);
  // Item #7 + static methods: a `static` field is a constant/immutable and a `static` method / `get` is a
  // class-level function; TS accesses both idiomatically as `ClassName.x`. Rewrite `ClassName.x` ->
  // `this.x` so the ordinary resolution handles them. Runs after the `#` mangle so a private static name is
  // in its final form.
  rewriteStaticFieldAccess(parsed.sourceFile);

  // Phase 0: subset validation (collects, does not throw yet).
  validateSubset(parsed.sourceFile, diags);

  // Phase 1: semantic analysis + type checking. importScope (multi-file only) lets the analyzer scope
  // `self`-convention ATTACHED calls to each file's import edges (they name no library identifier, so the
  // bundler's identifier-based reference check cannot see them).
  const ir = analyze(
    parsed.sourceFile,
    diags,
    dia.expanded && dia.name ? { name: dia.name, variant: dia.variant ?? 'array' } : undefined,
    bundleSegments && bundleVisibility ? { segments: bundleSegments, visibleByFile: bundleVisibility } : undefined,
  );

  // Surface all front-end diagnostics together.
  // Multi-file: map bundle-relative diagnostic positions back to their original files before surfacing.
  if (bundleSegments) remapDiagnostics(diags.items, bundleSegments);
  diags.throwIfErrors();
  if (!ir) throw new CompileError(diags.items);

  // Lowering -> Yul.
  let yul: string;
  try {
    yul = emitYul(ir);
  } catch (e) {
    if (e instanceof UnsupportedError) {
      throw new CompileError([
        {
          severity: 'error',
          code: e.code,
          message: e.message,
          file: fileName,
          line: 1,
          column: 1,
          length: 1,
        },
      ]);
    }
    throw e;
  }

  // Backend -> bytecode. A failure here means codegen emitted invalid Yul (an
  // internal compiler bug); surface it as a clean diagnostic, not a raw crash.
  let out;
  try {
    out = compileYul(yul, ir.name, opts.evmVersion);
  } catch (e) {
    throw new CompileError([
      {
        severity: 'error',
        code: 'JETH901',
        message: `internal compiler error: the backend rejected generated Yul: ${
          e instanceof Error ? e.message : String(e)
        }`,
        file: fileName,
        line: 1,
        column: 1,
        length: 1,
      },
    ]);
  }

  // stateVars only ever holds @state vars, which the planner lays out at small sequential slots
  // (@storage('ns') namespaced fields are NOT in stateVars - they live at their keccak base and are
  // never exported here), so narrowing to number for the debug layout table is exact and lossless.
  const storageLayout: StorageLayoutEntry[] = ir.stateVars.map((v) => ({
    name: v.name,
    type: displayName(v.type),
    slot: Number(v.slot),
    offset: v.offset,
  }));

  // Phase B: compile each referenced external (delegatecall) library to its own bytecode. The contract
  // carries a `linkersymbol(...)` placeholder per library; solc returns its positions in linkReferences.
  let libraries: CompiledLibrary[] | undefined;
  let linkReferences: LinkReferences | undefined;
  if (ir.libraries && ir.libraries.length > 0) {
    libraries = ir.libraries.map((lib) => {
      // v3 module scoping: a dep-declared library's IR name may carry the `$mN$` scope mangle; the
      // artifact boundary (its Yul object name, the compileYul lookup, the published CompiledLibrary
      // name, and the linkersymbol in the contract) all speak the demangled SOURCE name - the analyzer
      // rejects two external libraries sharing one source name, so the demangle cannot collide.
      const libName = demangleModuleName(lib.name);
      let libYul: string;
      try {
        libYul = emitLibraryYul(lib);
      } catch (e) {
        // Surface a lowering rejection inside a library body as the same clean diagnostic the
        // contract path produces (previously an UnsupportedError here escaped as a raw throw).
        if (e instanceof UnsupportedError) {
          throw new CompileError([
            { severity: 'error', code: e.code, message: e.message, file: fileName, line: 1, column: 1, length: 1 },
          ]);
        }
        throw e;
      }
      let libOut;
      try {
        libOut = compileYul(libYul, libName, opts.evmVersion);
      } catch (e) {
        throw new CompileError([
          {
            severity: 'error',
            code: 'JETH901',
            message: `internal compiler error: the backend rejected generated library Yul for '${libName}': ${
              e instanceof Error ? e.message : String(e)
            }`,
            file: fileName,
            line: 1,
            column: 1,
            length: 1,
          },
        ]);
      }
      // libOut.creationLinkReferences records where OTHER libraries' placeholders sit inside THIS
      // library's creation bytecode (present when an @external library calls another @external library).
      return {
        name: libName,
        creationBytecode: libOut.creationBytecode,
        runtimeBytecode: libOut.runtimeBytecode,
        linkReferences: libOut.creationLinkReferences,
      };
    });
    linkReferences = out.creationLinkReferences;
  }

  return {
    contractName: ir.name,
    abi: emitAbi(ir),
    creationBytecode: out.creationBytecode,
    runtimeBytecode: out.runtimeBytecode,
    yul,
    storageLayout,
    ir,
    diagnostics: diags.items,
    libraries,
    linkReferences,
  };
}
