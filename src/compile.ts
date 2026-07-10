// Top-level pipeline orchestrator (directive §5): source -> tokens/AST -> subset
// validation -> semantic analysis + type check -> storage layout -> Yul -> solc
// -> bytecode + ABI.
import ts from 'typescript';
import { parse } from './parser.js';
import { expandDiamond } from './diamond.js';
import { DiagnosticBag, CompileError, Diagnostic, demangleModuleName } from './diagnostics.js';
import { validateSubset } from './validator.js';
import { analyze } from './analyzer.js';
import { emitYul, emitLibraryYul, UnsupportedError } from './yul.js';
import { compileYul, LinkReferences } from './solc.js';
import { emitAbi, AbiItem } from './abi.js';
import { bundleImports, isDecoratorModeSource, isReferenceIdentifier, remapDiagnostics, BundleSegment } from './imports.js';
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

// Dual-syntax mode (items 3-10): mode is PER-FILE - a file whose leading comment block contains the exact
// line `// use @decorators` is DECORATOR mode (legacy syntax); any other file is NATIVE mode (the default,
// a PERMISSIVE SUPERSET during migration). The scanner lives in imports.ts (isDecoratorModeSource), shared
// with the multi-file bundler which enforces one mode per compilation.

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

/** JETH477: a pathologically deep source (a 2000-term `1n + 1n + ...` chain) overflows the JS call stack
 *  in whichever recursive AST visitor runs first, escaping as a raw RangeError with no diagnostics. solc
 *  compiles such chains (so this is a documented SAFE over-rejection, not parity), but a raw crash is a
 *  bar violation - convert ANY RangeError from ANY phase into a clean CompileError instead of rewriting
 *  every visitor iteratively. The catch runs AFTER the stack has unwound, so building the diagnostic is
 *  safe. A CompileError passes through untouched (it is not a RangeError). */
export function compile(source: string, opts: CompileOptions = {}): CompileResult {
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
  // `nativeMode` selects the native-declaration syntax (bare class = contract, type = struct, abstract
  // class = abstract base, static member = class-level const/immutable/function) as an additive superset.
  const nativeMode = !isDecoratorModeSource(source);
  // A `static` member belongs to the CLASS, not the instance: `this` inside a static body is invalid TS
  // semantics and would silently read instance state. Enforced BEFORE the ClassName.x rewrite below, which
  // legitimately INTRODUCES synthesized `this` nodes for `C.K`/`C.f(...)` accesses.
  if (nativeMode) rejectThisInStaticMembers(parsed.sourceFile, diags);
  // Item #7 + static methods: a `static` field is a constant/immutable and a `static` method / `get` is a
  // class-level function; TS accesses both idiomatically as `ClassName.x`. Rewrite `ClassName.x` ->
  // `this.x` so the ordinary resolution handles them. Native mode only (a static member is not a JETH
  // concept in decorator mode). Runs after the `#` mangle so a private static name is in its final form.
  if (nativeMode) rewriteStaticFieldAccess(parsed.sourceFile);

  // Phase 0: subset validation (collects, does not throw yet).
  validateSubset(parsed.sourceFile, diags);

  // Phase 1: semantic analysis + type checking. importScope (multi-file only) lets the analyzer scope
  // `self`-convention ATTACHED calls to each file's import edges (they name no library identifier, so the
  // bundler's identifier-based reference check cannot see them).
  const ir = analyze(
    parsed.sourceFile,
    diags,
    dia.expanded && dia.name ? { name: dia.name, variant: dia.variant ?? 'array' } : undefined,
    nativeMode,
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
