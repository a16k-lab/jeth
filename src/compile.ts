// Top-level pipeline orchestrator (directive §5): source -> tokens/AST -> subset
// validation -> semantic analysis + type check -> storage layout -> Yul -> solc
// -> bytecode + ABI.
import ts from 'typescript';
import { parse } from './parser.js';
import { expandDiamond } from './diamond.js';
import { DiagnosticBag, CompileError, Diagnostic } from './diagnostics.js';
import { validateSubset } from './validator.js';
import { analyze } from './analyzer.js';
import { emitYul, emitLibraryYul, UnsupportedError } from './yul.js';
import { compileYul, LinkReferences } from './solc.js';
import { emitAbi, AbiItem } from './abi.js';
import { bundleImports, isDecoratorModeSource, remapDiagnostics, BundleSegment } from './imports.js';
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
  // Harvest, ONLY from contract-shaped classes: the set of their NAMES, and the UNION of all their static
  // field names. All contract-shaped classes in a file are the deployed contract + its abstract bases (one
  // contract per file), whose statics all flatten into the deployed contract, reachable via `this.K`. So a
  // union lets `C.BK` reach an INHERITED base static too, while a @struct/@interface/@library class (not a
  // contract) contributes nothing and thus never hijacks a `TypeName.member`.
  const contractClassNames = new Set<string>();
  const staticNames = new Set<string>();
  const scan = (n: ts.Node): void => {
    // Skip non-contract classes: @struct/@interface/@library decorated, AND a native `static class`
    // (= a library) - its `L.f(a)` calls resolve via the library qualified-name machinery; rewriting them
    // to `this.f(a)` would hijack the call into the contract's own namespace.
    const isStaticClass = ts.isClassDeclaration(n) && (ts.getModifiers(n) ?? []).some((m) => m.kind === ts.SyntaxKind.StaticKeyword);
    if (ts.isClassDeclaration(n) && n.name && !isStaticClass && !classDecs(n).some((d) => d === 'struct' || d === 'interface' || d === 'library')) {
      contractClassNames.add(n.name.text);
      for (const m of n.members) {
        // static FIELDS (constant/immutable) AND static METHODS / `get` accessors (class-level functions)
        // are all read/called as `ClassName.x` - harvest every static member name.
        if (!(ts.isPropertyDeclaration(m) || ts.isMethodDeclaration(m) || ts.isGetAccessor(m)) || !ts.isIdentifier(m.name)) continue;
        if ((ts.getModifiers(m) ?? []).some((x) => x.kind === ts.SyntaxKind.StaticKeyword)) staticNames.add(m.name.text);
      }
    }
    ts.forEachChild(n, scan);
  };
  ts.forEachChild(sf, scan);
  if (staticNames.size === 0) return;
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
  const rewrite = (n: ts.Node): void => {
    if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) && ts.isIdentifier(n.name)) {
      if (contractClassNames.has(n.expression.text) && staticNames.has(n.name.text) && !bound.has(n.expression.text)) {
        const thisExpr = ts.factory.createThis();
        ts.setTextRange(thisExpr, n.expression);
        (thisExpr as unknown as { parent: ts.Node }).parent = n;
        (n as { expression: ts.Expression }).expression = thisExpr;
      }
    }
    ts.forEachChild(n, rewrite);
  };
  ts.forEachChild(sf, rewrite);
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

export function compile(source: string, opts: CompileOptions = {}): CompileResult {
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
  if (opts.sources && Object.keys(opts.sources).length > 0) {
    const bundle = bundleImports(effectiveSource, fileName, opts.sources);
    unitSource = bundle.text;
    bundleSegments = bundle.segments;
    bundleVisibility = bundle.visibleByFile;
  }

  const parsed = parse(unitSource, fileName);
  // Item #2: rewrite JS `#` private members to contract-scoped internal names BEFORE validation /
  // analysis, so `#f()` / `this.#x` lower like internal members and derived access rejects.
  manglePrivateMembers(parsed.sourceFile);
  // `nativeMode` selects the native-declaration syntax (bare class = contract, type = struct, abstract
  // class = abstract base, static member = class-level const/immutable/function) as an additive superset.
  const nativeMode = !isDecoratorModeSource(source);
  const diags = new DiagnosticBag(parsed.sourceFile, fileName);
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
        libOut = compileYul(libYul, lib.name, opts.evmVersion);
      } catch (e) {
        throw new CompileError([
          {
            severity: 'error',
            code: 'JETH901',
            message: `internal compiler error: the backend rejected generated library Yul for '${lib.name}': ${
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
        name: lib.name,
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
