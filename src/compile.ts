// Top-level pipeline orchestrator (directive §5): source -> tokens/AST -> subset
// validation -> semantic analysis + type check -> storage layout -> Yul -> solc
// -> bytecode + ABI.
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { parse, decoratorNames } from './parser.js';
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
import { resolvePrimitiveName } from './typeresolver.js';

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
  // MULTI-CONTRACT FILE: present ONLY when the source declares MORE THAN ONE deployable contract, in which
  // case solc emits one separate artifact per contract and so does JETH. Holds every contract's full
  // artifact in DOCUMENT ORDER, with `contracts[0] === this result object` (identity) - the singular fields
  // above are always the FIRST contract's, so an existing single-contract caller is completely unaffected.
  // Absent (undefined) for a single-contract file: check `contracts` to detect the multi-contract case.
  contracts?: CompileResult[];
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
  // Names the member-vs-imported-type pre-pass (collectImportedMemberTypeCollisions) already REJECTED
  // (JETH133) for a class, keyed by every class in the rejected contract's `extends` chain. For exactly
  // those (class, name) pairs the member shadow below is DISABLED, so the reference is renamed to the
  // import as usual and binds the file-level symbol - reproducing the SINGLE-FILE analyzer's resolution
  // (its blanket decl-level JETH133 fires and a bare `Bad(...)` still binds the file-level declaration,
  // so no companion JETH129/JETH147/JETH013 is emitted). The program is already rejected when a name is
  // in this map, so the override can never turn a reject into an accept - it only aligns the companion
  // code list with the single-file twin's. Same-kind coexistence pairs (member error<{}> x imported
  // error, member event<{}> x imported event) never fire the pre-pass, so their shadow - and the C2
  // member-binding semantics it carries - is untouched.
  memberCollisionRejects?: Map<ts.ClassDeclaration, Set<string>>,
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
  // MEMBER-SHADOW (multi-file): a contract VALUE MEMBER (state field / constant / immutable / mapping /
  // struct-typed / public field - `Bad: u256` / `static Bad` / `Bad: mapping<_,_>` / `Bad: S` /
  // `Bad: Visible<u256>`, INCLUDING an error/event member `Bad: error<{...}>` / `Bad: event<{...}>`) SHADOWS
  // a same-named IMPORTED (or file-level) symbol INSIDE that contract - solc resolves a bare `Bad(...)` /
  // `revert(Bad(...))` / `emit(Bad(...))` / a type-position `Bad`/`Bad[]`/`mapping<_,Bad>` / an enum use
  // `Bad.A` / an interface cast `Bad(a)` to the MEMBER, never to the import. The v3 module rename would
  // otherwise rewrite that bare reference to the imported `$mN$Bad` and route AROUND the member (a
  // pre-existing over-acceptance family). So a reference identifier whose name matches a value member of its
  // enclosing class (or of a base reached through `extends`) is left UNRENAMED; downstream name resolution
  // then binds it to the member. Since the 2026-07-16 ruling (single-file parity for the whole
  // name-collision family) the CROSS-KIND collisions this shadow used to surface are rejected at the
  // DECLARATION by collectImportedMemberTypeCollisions (JETH133, exactly the single-file gate), and
  // memberCollisionRejects disables the shadow for those names so companions match single-file. What the
  // shadow still carries: the SAME-KIND coexistence pairs (member error<{}> x imported error, member
  // event<{}> x imported event - the member shadows, byte-identical to solc), library-body members (a
  // library is outside the contract-member gate; its use-site rejects are a kept deliberate multi-file
  // over-rejection), and shadows of imports OUTSIDE the 5-kind gate (an imported class/const). The set is
  // REFERENCE-SENSITIVE (only reference identifiers are skipped, never the member's own declaration).
  // METHOD members are deliberately EXCLUDED: a bare call to a same-named method needs true overload-set
  // resolution, and a declaration-level skip there would over-reject; method behavior is left exactly as it
  // was. The member-access spelling `this.Bad(...)` is a property name (not a reference identifier), so it
  // is untouched and already resolved to the member.
  const topClasses: ts.ClassDeclaration[] = [];
  sf.forEachChild((c) => { if (ts.isClassDeclaration(c) && c.name) topClasses.push(c); });
  // a class name resolves, after this file's rename map, to its FINAL (possibly `$mN$`-scoped) name; the
  // rename map is keyed by ORIGINAL name and this precomputation runs BEFORE any mutation, so lookups are
  // stable. An entry class's `extends B` reference and the imported base's `class B` decl both land on the
  // same final name, so cross-file inheritance resolves uniformly.
  const finalNameOf = (name: ts.Identifier): string => {
    const file = fileOf(name);
    return (file ? renamesByFile.get(file)?.get(name.text) : undefined) ?? name.text;
  };
  const classByFinalName = new Map<string, ts.ClassDeclaration>();
  for (const cls of topClasses) {
    if (!cls.name) continue;
    const fn = finalNameOf(cls.name);
    if (!classByFinalName.has(fn)) classByFinalName.set(fn, cls);
  }
  const ownValueMemberNames = (cls: ts.ClassDeclaration): string[] => {
    const out: string[] = [];
    for (const m of cls.members) {
      if (ts.isPropertyDeclaration(m) && m.name && ts.isIdentifier(m.name)) out.push(m.name.text);
    }
    return out;
  };
  const baseClassOf = (cls: ts.ClassDeclaration): ts.ClassDeclaration | undefined => {
    const ext = cls.heritageClauses?.find((h) => h.token === ts.SyntaxKind.ExtendsKeyword);
    const expr = ext?.types[0]?.expression;
    if (!expr || !ts.isIdentifier(expr)) return undefined;
    return classByFinalName.get(finalNameOf(expr));
  };
  // per-class shadow set = own value-member names UNION every inherited value-member name up the `extends`
  // chain (cycle-guarded). Memoized; precomputed for every top-level class BEFORE the rewrite mutates any
  // identifier so base resolution reads pristine names.
  const shadowByClass = new Map<ts.ClassDeclaration, Set<string>>();
  const shadowNamesFor = (cls: ts.ClassDeclaration): Set<string> => {
    const cached = shadowByClass.get(cls);
    if (cached) return cached;
    const s = new Set<string>();
    const seen = new Set<ts.ClassDeclaration>();
    let cur: ts.ClassDeclaration | undefined = cls;
    while (cur && !seen.has(cur)) {
      seen.add(cur);
      for (const nm of ownValueMemberNames(cur)) s.add(nm);
      cur = baseClassOf(cur);
    }
    shadowByClass.set(cls, s);
    return s;
  };
  for (const cls of topClasses) shadowNamesFor(cls);
  // The base-class identifier of an `extends` heritage clause is a reference, but solc shadows a name
  // only in expression/type positions - NEVER in the `is X` heritage clause. So even when a value member
  // shares the base's name, the heritage reference must still be renamed to `$mN$Base` (else base-class
  // resolution/merge fails and a previously-valid `class C extends ImportedBase { Base: u256 }` over-rejects).
  const isHeritageBaseIdent = (id: ts.Identifier): boolean =>
    ts.isExpressionWithTypeArguments(id.parent) && ts.isHeritageClause(id.parent.parent);
  const rewrite = (n: ts.Node, shadow: Set<string> | undefined, rejected: Set<string> | undefined): void => {
    // entering a class, the shadow set becomes that class's value-member names (own + inherited) and the
    // rejected-collision override becomes that class's pre-pass-fired names; at file level between
    // classes both are `undefined` again.
    const isCls = ts.isClassDeclaration(n);
    const inner = isCls ? shadowNamesFor(n as ts.ClassDeclaration) : shadow;
    const innerRejected = isCls ? memberCollisionRejects?.get(n as ts.ClassDeclaration) : rejected;
    if (ts.isIdentifier(n) && (isReferenceIdentifier(n) || isTopLevelDeclName(n))) {
      const file = fileOf(n);
      const to = file ? renamesByFile.get(file)?.get(n.text) : undefined;
      // skip the rename when a value member of the enclosing class shadows this bare-name reference,
      // EXCEPT in an `extends` heritage clause (solc never shadows there - the base must still resolve)
      // and EXCEPT for a name whose member/import collision the pre-pass already rejected JETH133 (the
      // reference then binds the import, exactly as the single-file analyzer binds the file-level decl).
      if (
        to &&
        !(isReferenceIdentifier(n) && inner?.has(n.text) && !innerRejected?.has(n.text) && !isHeritageBaseIdent(n))
      ) {
        (n as unknown as { escapedText: ts.__String }).escapedText = ts.escapeLeadingUnderscores(to);
      }
    }
    ts.forEachChild(n, (c) => rewrite(c, inner, innerRejected));
  };
  ts.forEachChild(sf, (c) => rewrite(c, undefined, undefined));
}

/**
 * MEMBER-vs-IMPORTED-TYPE collision (multi-file only). USER RULING (2026-07-16): across the whole
 * name-collision family, MULTI-FILE behavior must equal SINGLE-FILE behavior EXACTLY, thrown code lists
 * included. The single-file analyzer's cross-scope gate (analyzeContract, the memberKinds x fileKinds loops)
 * rejects JETH133 when a file-level error / event / struct / enum / interface / Brand newtype shares a name
 * with ANY contract member of a single kind - function (method / get accessor), storage (plain / static
 * constant / immutable / mapping / struct-typed / Visible / funcref / array field), member error<{...}>,
 * member event<{...}>, or @modifier - with EXACTLY three coexistence exemptions (witnessed): a member
 * error<{}> with a file-level ERROR, a member event<{}> with a file-level EVENT (the member shadows, C2),
 * and a @modifier with a file-level TYPE (a modifier name is never used in a type position). The v3 module
 * rename mangles an imported `Bad` to `$mN$Bad` BEFORE the analyzer runs, so the analyzer never sees the
 * member-vs-import collision and a BUNDLE routes AROUND the gate. This pre-pass restores the reject by
 * mirroring that gate over renamed (import-scoped) declarations, emitting the SAME JETH133 code and message
 * the single-file path produces, for the SAME class the single-file path checks:
 *
 * ROUTE CLASS - the one class whose linearized members the single-file gate actually counts:
 *   - DEPLOYED route: the first deployable class (decorated @proxy/@beacon/@facet/@contract-from-@diamond,
 *     else the first native bare class not extended by another), exactly findContractClasses' classes[0].
 *   - NON-DEPLOYABLE route (no deployable class): the single abstract LEAF, with analyzeNonDeployableUnit's
 *     short-circuits emulated - if TWO OR MORE abstract leaves exist (JETH041) or any abstract class carries
 *     a bare bodyless method/get (JETH489; JETH040 returns the same way), the analyzer returns BEFORE its
 *     JETH133 gate, so the single-file code list carries NO JETH133 and this pre-pass emits nothing (the
 *     analyzer's own JETH041/JETH489 is the reject on both paths).
 * Member kinds are collected over the route class's OWN members UNION every class reached through `extends`
 * (multi-level, multiple-base / diamond, cycle-guarded; an interface base is walked through but contributes
 * NO member - the single-file linearization gate accepts a contract that merely inherits an interface
 * signature). A member whose type annotation does not resolve (unknown name, or a reference to an
 * error/event ALIAS - member error/event types must be inline error<{}>/event<{}>) is NOT counted, exactly
 * as the single-file path leaves it out of memberKinds (it rejects JETH013/JETH045/JETH485 on its own).
 * A name carrying MORE THAN ONE member kind is skipped here - that is the analyzer's WITHIN-scope member
 * clash, which fires identically on the merged bundle (members are never renamed).
 *
 * The colliding declaration is resolved through the scope of the route class's file AND of each file
 * declaring a chain class (an inherited member collides with a type in scope where it is declared - the
 * single-file flat namespace makes both arrangements JETH133). A declaration whose FINAL name equals the
 * member name (an entry-file declaration, never renamed) is left to the analyzer's own gate, which sees
 * that pair and fires JETH133 with its native companion diagnostics - firing here too would double-report.
 *
 * NON-ROUTE contract-kind classes (strays off the deployed/leaf chain, and the extra deployables behind a
 * JETH041) keep the NARROWER legacy scan - VISIBLE METHODS ONLY, cross-file collisions only. The single-file
 * gate never counts a stray's members (it accepts them), so the legacy stray reject is a known deliberate
 * multi-file-only over-rejection kept because removing it would flip a reject to an accept (forbidden).
 *
 * Runs on PRISTINE identifiers (BEFORE rewriteModuleScopes mutates any name); final (scoped) names are
 * computed from renamesByFile exactly as rewriteModuleScopes does. The reject fires regardless of whether
 * the colliding name is USED - matching the single-file path, which also rejects the no-use collision (solc
 * accepts the no-use shadow, so this is the endorsed, consistent single/multi-file deliberate
 * over-rejection: members are camelCase, types/errors/events are PascalCase).
 *
 * RETURNS the fired names keyed by every CLASS in the route chain: rewriteModuleScopes disables the
 * value-member reference shadow for exactly those (class, name) pairs, so a bare reference binds the import
 * - the single-file analyzer's resolution - and the multi-file companion list matches the single-file one
 * (e.g. field x error USED is [JETH133] alone on both paths, never [JETH133, JETH129]).
 */
function collectImportedMemberTypeCollisions(
  sf: ts.SourceFile,
  segments: BundleSegment[],
  renamesByFile: Map<string, Map<string, string>>,
  diags: DiagnosticBag,
  // MULTI-CONTRACT FILE: which deployable contract is THIS route (document order), mirroring the analyzer's
  // routeIndex. The scan is scoped to the route's own class + chain, so with N deployables in a bundle each
  // route must scope from ITS OWN class - a hard-coded classes[0] would judge route 1 against route 0's
  // member namespace and emit a JETH133 the single-file twin never gives (and miss route 1's real one).
  routeIndex = 0,
): Map<ts.ClassDeclaration, Set<string>> {
  const fired = new Map<ts.ClassDeclaration, Set<string>>();
  if (renamesByFile.size === 0) return fired;
  const fileOf = (node: ts.Node): string | undefined => {
    const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
    const l = line + 1;
    for (const seg of segments) {
      if (l >= seg.startLine && l < seg.startLine + seg.lineCount) return seg.file;
    }
    return undefined;
  };
  // The FINAL (post-rename) name of source identifier `name` as it is seen inside `file`: the file's rename
  // map resolves both its own top-level declarations and its import bindings to their `$mN$` scoped names;
  // an unmapped name (the entry's own decls, a bare non-imported reference) stays as written.
  const finalNameIn = (file: string | undefined, name: string): string =>
    (file ? renamesByFile.get(file)?.get(name) : undefined) ?? name;
  // Every file-level error / event / struct / enum / interface / Brand-newtype declaration in the bundle,
  // keyed by its FINAL scoped name. Classification MIRRORS the analyzer's file-scope buckets exactly (so the
  // multi-file reject set matches the single-file one - no spurious JETH133 the single-file path would not
  // give):
  //   `type X = error<{...}>`  -> 'error'   (isErrorEventAliasRHS)
  //   `type X = event<{...}>`  -> 'event'
  //   `type X = { ... }`       -> 'type'    (a STRUCT object literal)
  //   `type X = Brand<T>`      -> 'type'    (a branded newtype - witnessed: the single-file gate counts it;
  //                                          a NON-Brand alias `type X = u256` / `type X = u256[]` is itself
  //                                          rejected JETH015 on both paths and is NOT counted)
  //   `enum X { ... }`         -> 'type'
  //   `interface X { ... }`    -> 'type'
  // v3 scoping guarantees each declaration has a unique final name, so this map never conflates two distinct
  // declarations.
  const declByFinal = new Map<string, { kind: 'error' | 'event' | 'type'; file: string | undefined }>();
  sf.forEachChild((n) => {
    let nameNode: ts.Identifier | undefined;
    let kind: 'error' | 'event' | 'type' | undefined;
    if (ts.isTypeAliasDeclaration(n) && n.name) {
      const t = n.type;
      if (ts.isTypeReferenceNode(t) && ts.isIdentifier(t.typeName) && (t.typeName.text === 'error' || t.typeName.text === 'event')) {
        nameNode = n.name;
        kind = t.typeName.text as 'error' | 'event';
      } else if (ts.isTypeLiteralNode(t)) {
        nameNode = n.name;
        kind = 'type'; // a struct object-literal alias
      } else if (ts.isTypeReferenceNode(t) && ts.isIdentifier(t.typeName) && t.typeName.text === 'Brand') {
        nameNode = n.name;
        kind = 'type'; // a branded newtype (UDVT)
      }
    } else if (ts.isEnumDeclaration(n) && n.name) {
      nameNode = n.name;
      kind = 'type';
    } else if (ts.isInterfaceDeclaration(n) && n.name) {
      nameNode = n.name;
      kind = 'type';
    }
    if (nameNode && kind) {
      const file = fileOf(nameNode);
      declByFinal.set(finalNameIn(file, nameNode.text), { kind, file });
    }
  });
  if (declByFinal.size === 0) return fired;
  const hasMod = (node: ts.Node, kind: ts.SyntaxKind): boolean =>
    ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((m) => m.kind === kind);
  const KIND_DECS = ['contract', 'struct', 'interface', 'abstract', 'library', 'proxy', 'beacon', 'facet', 'diamond'];
  // extends targets by FINAL name - the analyzer computes extendedClassNames on the post-rename AST, where
  // every identifier already carries its `$mN$` scoped spelling; finalNameIn reproduces that spelling here.
  const extendedFinal = new Set<string>();
  const collectExtends = (n: ts.Node): void => {
    if (ts.isClassDeclaration(n)) {
      for (const h of n.heritageClauses ?? []) {
        if (h.token === ts.SyntaxKind.ExtendsKeyword) {
          for (const b of h.types)
            if (ts.isIdentifier(b.expression)) extendedFinal.add(finalNameIn(fileOf(b.expression), b.expression.text));
        }
      }
    }
    ts.forEachChild(n, collectExtends);
  };
  ts.forEachChild(sf, collectExtends);
  // ROUTE DETERMINATION - mirrors the analyzer's findContractClasses / analyzeNonDeployableUnit predicates
  // on pristine names via finalNameIn, recursing exactly as those visitors do. The deployable routes are
  // the UNION, in DOCUMENT ORDER, of the decorated deployables (@contract - the @diamond expansion
  // synthesizes it upstream of this pre-pass - @proxy, @beacon, @facet) and the native bare classes (no
  // kind decorator, not `abstract`, not `static`, not extended by another class); document order decides
  // classes[0]. This mirrors findContractClasses' single union visitor: the bare scan is NOT a fallback
  // behind the decorated one (that split silently dropped every bare contract in a mixed file).
  const deployables: ts.ClassDeclaration[] = [];
  const abstractClasses: ts.ClassDeclaration[] = [];
  // The exact JETH489 trigger (analyzeNonDeployableUnit): a bodyless method or `get` accessor on an
  // abstract class, with neither the @virtual decorator nor the `abstract` member keyword.
  const tripsBodylessVirtualGate = (cls: ts.ClassDeclaration): boolean => {
    for (const m of cls.members) {
      if (!((ts.isMethodDeclaration(m) || ts.isGetAccessorDeclaration(m)) && m.body === undefined)) continue;
      if (decoratorNames(m).includes('virtual') || hasMod(m, ts.SyntaxKind.AbstractKeyword)) continue;
      return true;
    }
    return false;
  };
  let anyBareBodyless = false;
  const scanClasses = (n: ts.Node): void => {
    if (ts.isClassDeclaration(n)) {
      const decs = decoratorNames(n);
      const isAbstract = hasMod(n, ts.SyntaxKind.AbstractKeyword) || decs.includes('abstract');
      if (decs.includes('contract') || decs.includes('proxy') || decs.includes('beacon') || decs.includes('facet') || decs.includes('diamond')) {
        deployables.push(n);
      } else if (
        !isAbstract &&
        !hasMod(n, ts.SyntaxKind.StaticKeyword) &&
        !KIND_DECS.some((d) => decs.includes(d)) &&
        !(n.name && extendedFinal.has(finalNameIn(fileOf(n.name), n.name.text)))
      ) {
        deployables.push(n);
      }
      if (n.name && isAbstract) {
        abstractClasses.push(n);
        if (tripsBodylessVirtualGate(n)) anyBareBodyless = true;
      }
    }
    ts.forEachChild(n, scanClasses);
  };
  ts.forEachChild(sf, scanClasses);
  const anyDeployed = deployables.length > 0;
  let routeClass: ts.ClassDeclaration | undefined;
  if (anyDeployed) {
    // MULTI-CONTRACT FILE: the analyzer's findContractClasses collects the decorated deployables and the
    // native bare classes into ONE document-order list, so the route list here is that same union. Index
    // into it exactly as the analyzer's classes[routeIndex] does. Clamped to [0] for safety (the driver
    // derives the count from routeCount, which comes from this same predicate).
    routeClass = deployables[routeIndex] ?? deployables[0];
  } else {
    const leaves = abstractClasses.filter(
      (ac) => ac.name && !extendedFinal.has(finalNameIn(fileOf(ac.name), ac.name.text)),
    );
    // SHORT-CIRCUIT EMULATION (single-file parity for the non-deployable route). analyzeNonDeployableUnit
    // returns BEFORE its JETH133 linearization gate when two or more abstract leaves exist (JETH041) or any
    // abstract class declares a bare bodyless method/get (JETH489) - so the single-file code list for such
    // a program carries NO JETH133 ([JETH041] / [JETH489] alone; the earlier JETH040 gate returns the same
    // way and has no member-bearing class to collide anyway). The multi-file analyzer fires the identical
    // JETH041/JETH489 over the merged bundle (imported abstract bases included), so BOTH scans emit nothing
    // here and the analyzer's own reject is the whole code list, exactly as in the single-file all-in-one.
    // The DEPLOYED route has no such short-circuit (witnessed: a deployed contract with a bare-bodyless
    // colliding method rejects [JETH483,JETH380,JETH133] single-file, the linearization gate still counting
    // the member), so a bundle WITH a deployable class never suppresses.
    if (leaves.length > 1 || anyBareBodyless) return fired;
    routeClass = leaves[0]; // undefined for an interface-only unit: analyzeContract never runs there either
  }
  // A class that carries solc's contract MEMBER namespace: a bare / @contract-family / abstract class. A
  // @library / `static class` (library) / @struct object type / native `interface`-as-class / @diamond does
  // not participate in this member-vs-file-level collision.
  const isContractKindClass = (cls: ts.ClassDeclaration): boolean => {
    const decs = decoratorNames(cls);
    if (decs.includes('library') || decs.includes('struct') || decs.includes('interface') || decs.includes('diamond'))
      return false;
    if ((ts.getModifiers(cls) ?? []).some((m) => m.kind === ts.SyntaxKind.StaticKeyword)) return false; // static class = library
    return true;
  };
  // The INHERITANCE resolver (merged AST). A class/interface declaration is keyed by its FINAL (post-rename)
  // name, so an entry `extends B` reference and the imported dep `class B` decl land on the SAME key - the
  // exact resolution rewriteModuleScopes' value-member shadow uses (finalNameOf + classByFinalName). Both
  // class bases (abstract/contract) and interface bases participate in the walk.
  type BaseNode = ts.ClassDeclaration | ts.InterfaceDeclaration;
  const classByFinal = new Map<string, ts.ClassDeclaration>();
  const ifaceByFinal = new Map<string, ts.InterfaceDeclaration>();
  sf.forEachChild((n) => {
    if (ts.isClassDeclaration(n) && n.name) {
      const fn = finalNameIn(fileOf(n.name), n.name.text);
      if (!classByFinal.has(fn)) classByFinal.set(fn, n);
    } else if (ts.isInterfaceDeclaration(n) && n.name) {
      const fn = finalNameIn(fileOf(n.name), n.name.text);
      if (!ifaceByFinal.has(fn)) ifaceByFinal.set(fn, n);
    }
  });
  // Direct `extends` bases of a class/interface, resolved to their merged-AST declarations. Handles multiple
  // bases (`extends A, B` -> diamond), the call-form base (`extends A(7)`), and a base that is a native
  // interface. A base whose expression is not a bare/called identifier, or that resolves to no known
  // declaration, is dropped (fail-safe - the walk simply does not inherit through it).
  const basesOf = (node: BaseNode): BaseNode[] => {
    const out: BaseNode[] = [];
    for (const clause of node.heritageClauses ?? []) {
      if (clause.token !== ts.SyntaxKind.ExtendsKeyword) continue;
      for (const t of clause.types) {
        let e: ts.Expression = t.expression;
        if (ts.isCallExpression(e)) e = e.expression;
        if (!ts.isIdentifier(e)) continue;
        const fn = finalNameIn(fileOf(e), e.text);
        const base = classByFinal.get(fn) ?? ifaceByFinal.get(fn);
        if (base) out.push(base);
      }
    }
    return out;
  };
  // The route class's `extends` chain (route class first, cycle-guarded, diamond bases visited once).
  const chainOf = (root: BaseNode): BaseNode[] => {
    const seen = new Set<BaseNode>();
    const out: BaseNode[] = [];
    const stack: BaseNode[] = [root];
    while (stack.length > 0) {
      const cur = stack.pop()!;
      if (seen.has(cur)) continue;
      seen.add(cur);
      out.push(cur);
      for (const base of basesOf(cur)) stack.push(base);
    }
    return out;
  };
  // ---- MEMBER-TYPE CLASSIFICATION (mirrors the analyzer's memberKinds buckets) ------------------------
  // Does this type-annotation node resolve to a JETH STORAGE type? Mirrors resolveType's shapes: primitive
  // names, `string`, mapping<K,V>, Arr<T,N>, Visible<T>, T[], funcref `(a: T) => R`, a struct/enum/
  // interface/Brand alias (declByFinal 'type'), and a contract/interface value type (classByFinal /
  // ifaceByFinal). A reference to an error/event ALIAS or to an unknown name does NOT resolve - the
  // single-file analyzer rejects such a member JETH013 on its own and never counts it in memberKinds.
  const isStorageTypeNode = (t: ts.TypeNode, file: string | undefined): boolean => {
    if (ts.isParenthesizedTypeNode(t)) return isStorageTypeNode(t.type, file);
    if (t.kind === ts.SyntaxKind.StringKeyword) return true;
    if (ts.isArrayTypeNode(t)) return isStorageTypeNode(t.elementType, file);
    if (ts.isFunctionTypeNode(t)) {
      for (const p of t.parameters) {
        if (!p.type || !isStorageTypeNode(p.type, file)) return false;
      }
      return t.type.kind === ts.SyntaxKind.VoidKeyword || isStorageTypeNode(t.type, file);
    }
    if (!ts.isTypeReferenceNode(t)) return false;
    if (ts.isQualifiedName(t.typeName)) return true; // a library-qualified struct type - permissive
    const name = t.typeName.text;
    if (name === 'mapping')
      return t.typeArguments?.length === 2 && t.typeArguments.every((a) => isStorageTypeNode(a, file));
    if (name === 'Arr') return t.typeArguments?.length === 2 && isStorageTypeNode(t.typeArguments[0]!, file);
    if (name === 'Visible') return t.typeArguments?.length === 1 && isStorageTypeNode(t.typeArguments[0]!, file);
    if (name === 'error' || name === 'event') return false; // inline error/event is its OWN member kind
    if (resolvePrimitiveName(name) !== undefined) return true;
    const fn = finalNameIn(file, name);
    const d = declByFinal.get(fn);
    if (d) return d.kind === 'type'; // an error/event ALIAS as a member type is JETH013, never storage
    return classByFinal.has(fn) || ifaceByFinal.has(fn); // contract / interface value type
  };
  type MemberKind = 'function' | 'storage' | 'error' | 'event' | 'modifier';
  // The member kind of one class member, or undefined for a member the single-file gate never counts
  // (constructor, set accessor - JETH043 - a `#`-private name, an untyped/unresolvable property).
  const memberKindOf = (m: ts.ClassElement, file: string | undefined): { name: string; kind: MemberKind } | undefined => {
    if (!m.name || !ts.isIdentifier(m.name)) return undefined;
    const name = m.name.text;
    if (ts.isMethodDeclaration(m)) {
      return { name, kind: decoratorNames(m).includes('modifier') ? 'modifier' : 'function' };
    }
    if (ts.isGetAccessorDeclaration(m)) return { name, kind: 'function' };
    if (ts.isPropertyDeclaration(m)) {
      const t = m.type;
      if (!t) return undefined; // untyped member: JETH045/JETH485 on both paths, never counted
      if (ts.isTypeReferenceNode(t) && ts.isIdentifier(t.typeName) && t.typeName.text === 'error')
        return { name, kind: 'error' };
      if (ts.isTypeReferenceNode(t) && ts.isIdentifier(t.typeName) && t.typeName.text === 'event')
        return { name, kind: 'event' };
      return isStorageTypeNode(t, file) ? { name, kind: 'storage' } : undefined;
    }
    return undefined;
  };
  // ---- ROUTE-CLASS SCAN (the single-file gate's mirror, ALL member kinds) -----------------------------
  const routeChain = routeClass ? chainOf(routeClass) : [];
  if (routeClass && isContractKindClass(routeClass)) {
    const kindsByName = new Map<string, Set<MemberKind>>();
    const scopeFilesByName = new Map<string, Set<string | undefined>>();
    for (const node of routeChain) {
      // An interface base is a C3 ordering node only: its method SIGNATURES are never counted (the
      // single-file gate accepts a contract that merely inherits the signature - witnessed).
      if (ts.isInterfaceDeclaration(node)) continue;
      const nfile = fileOf(node.name ?? node);
      for (const m of node.members) {
        const mk = memberKindOf(m, nfile);
        if (!mk) continue;
        let kinds = kindsByName.get(mk.name);
        if (!kinds) kindsByName.set(mk.name, (kinds = new Set()));
        kinds.add(mk.kind);
        let files = scopeFilesByName.get(mk.name);
        if (!files) scopeFilesByName.set(mk.name, (files = new Set()));
        files.add(nfile);
      }
    }
    const routeFile = fileOf(routeClass.name ?? routeClass);
    for (const [nm, kinds] of kindsByName) {
      // A name carrying MORE THAN ONE member kind is the analyzer's WITHIN-scope member clash (its own
      // JETH133, "a function and a storage share the name"), which fires identically on the merged bundle -
      // the single-file cross-scope loop skips it (mk.size !== 1) and so does this mirror.
      if (kinds.size !== 1) continue;
      const mk = [...kinds][0]!;
      // Resolve the member name through the route class's file scope AND each declaring class's file scope
      // (an inherited member collides with a type in scope where it is declared; the single-file flat
      // namespace rejects both arrangements - witnessed).
      const scopeFiles = new Set<string | undefined>([routeFile, ...(scopeFilesByName.get(nm) ?? [])]);
      let hit: { kind: 'error' | 'event' | 'type' } | undefined;
      let analyzerSees = false;
      for (const f of scopeFiles) {
        const key = finalNameIn(f, nm);
        const d = declByFinal.get(key);
        if (!d) continue;
        if (key === nm) {
          // The declaration kept its source name (an entry-file decl): the analyzer's own cross-scope gate
          // sees this exact pair post-rename and fires JETH133 with its native companion diagnostics -
          // firing here too would double-report the same collision.
          analyzerSees = true;
          break;
        }
        if (!hit) hit = d;
      }
      if (analyzerSees || !hit) continue;
      // The witnessed single-file coexistence exemptions - and ONLY these: member error<{}> x file error,
      // member event<{}> x file event (the member shadows, same-kind - the C2 lift), @modifier x file type
      // (a modifier name is never used in a type position).
      const bothError = mk === 'error' && hit.kind === 'error';
      const bothEvent = mk === 'event' && hit.kind === 'event';
      const modifierType = mk === 'modifier' && hit.kind === 'type';
      if (bothError || bothEvent || modifierType) continue;
      diags.error(
        routeClass,
        'JETH133',
        `identifier '${nm}' is already declared (a file-level ${hit.kind} and a contract-member ${mk} share the name; solc's member shadow leaves the file-level unusable inside the contract - only a matching error/error or event/event pair may coexist)`,
      );
      // Record the fired name for EVERY class in the chain: rewriteModuleScopes disables the value-member
      // reference shadow there, so a bare use binds the import - the single-file resolution - and the
      // companion code list matches the single-file twin's exactly.
      for (const node of routeChain) {
        if (!ts.isClassDeclaration(node)) continue;
        let set = fired.get(node);
        if (!set) fired.set(node, (set = new Set()));
        set.add(nm);
      }
    }
  }
  // ---- LEGACY NON-ROUTE SCAN (methods only, cross-file only) ------------------------------------------
  // Strays off the route chain (and the extra deployables behind a JETH041) keep the original narrower
  // method-vs-imported-type reject: the single-file gate never counts a stray's members, but this multi-file
  // reject predates the ruling and removing it would flip a reject to an accept (forbidden). A same-file
  // pair (d.file === cfile) stays exempt here - a dep base whose same-file method shadows a same-file type
  // is the pure shadow solc + the single-file path both accept when that base is not the route contract.
  const routeChainSet = new Set<BaseNode>(routeChain);
  const ownMethodNames = (node: BaseNode): string[] => {
    const out: string[] = [];
    for (const m of node.members) {
      if (ts.isMethodDeclaration(m) && ts.isIdentifier(m.name)) {
        if (decoratorNames(m).includes('modifier')) continue;
        out.push(m.name.text);
      }
    }
    return out;
  };
  const visibleMethodNames = (cls: ts.ClassDeclaration): Set<string> => {
    const names = new Set<string>();
    for (const node of chainOf(cls)) {
      if (ts.isInterfaceDeclaration(node)) continue;
      for (const nm of ownMethodNames(node)) names.add(nm);
    }
    return names;
  };
  sf.forEachChild((n) => {
    if (!ts.isClassDeclaration(n) || !n.name || !isContractKindClass(n) || routeChainSet.has(n)) return;
    const cfile = fileOf(n.name);
    const reported = new Set<string>();
    for (const mname of visibleMethodNames(n)) {
      if (reported.has(mname)) continue;
      const d = declByFinal.get(finalNameIn(cfile, mname));
      if (!d || d.file === cfile) continue;
      reported.add(mname);
      diags.error(
        n,
        'JETH133',
        `identifier '${mname}' is already declared (a file-level ${d.kind} and a contract-member function share the name; solc's member shadow leaves the file-level unusable inside the contract - only a matching error/error or event/event pair may coexist)`,
      );
    }
  });
  return fired;
}

/** `$m<N>$` and `$p$` identifiers are reserved for the compiler's internal mangles - the v3
 *  module-scoping rename (src/imports.ts) and the `#`-private member mangle (`#x` in class C ->
 *  `$p$C$x`, below). A user-written spelling would collide with the mangle space: `$m1$X` would be
 *  silently demangled at every hash boundary (selector keccak('X(...)') - a name not in the source),
 *  and a user-written `this.$p$B$x` was a confirmed `#`-PRIVACY BYPASS (it bound base B's private
 *  `#x` for read AND write, where solc rejects the twin as undeclared - a live over-acceptance found
 *  by the 2026-07-12 OR-catalogue live audit). Checked on the PRE-MANGLE AST, so every `$p$`/`$m`
 *  identifier seen here is user-written by construction; both fail CLOSED, declaration and access
 *  sites alike. */
function rejectReservedModuleIdentifiers(sf: ts.SourceFile, diags: DiagnosticBag): void {
  const visit = (n: ts.Node): void => {
    // the raw spelling is NOT quoted in either message: the message demanglers would strip/rewrite
    // the prefix and misquote it; the diagnostic's source span already points at the identifier.
    if (ts.isIdentifier(n) && /^\$m\d+\$/.test(n.text)) {
      diags.error(n, 'JETH036', `this identifier uses the reserved '$m<N>$' module-scoping prefix; rename it`);
    } else if (ts.isIdentifier(n) && n.text.startsWith('$p$')) {
      diags.error(n, 'JETH036', `this identifier uses the reserved '$p$' private-member mangle prefix; rename it`);
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
  view: 'mutability is inferred from the body - a read-only method needs no marker (`get f(args): T`, or `get f(args): External<T>` to expose it); View<T> is an interface-only marker (`f(args): View<T>` marks an interface method)',
  pure: 'mutability is inferred from the body - a pure method needs no marker (a body that reads no state/env infers pure; `static f(args): T` / `static get f(args): T` has no `this`, so it cannot read state); Pure<T> is an interface-only marker (`f(args): Pure<T>` marks an interface method)',
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
// STAGE 2b - DECORATOR POSITION GATE (JETH490). A decorator whose name is legal only in ANOTHER
// position (e.g. @nonReentrant / @virtual / @override on a class), an UNKNOWN name - notably a TYPO
// of a real decorator (`@storag('ns')`, `@diamon('array')`, `@nonReentrent`) - or a MIS-SHAPED
// decorator (`@a.b`, `@a[0]`) in CLASS / FIELD / PARAM position used to be SILENTLY DROPPED: a
// `@storag('ns')` lost the storage namespace, a `@diamon('array')` lost the whole diamond, with no
// diagnostic. Reject it loudly, naming the position's legal set - the exact mirror of the already
// closed METHOD position (an unknown method decorator is a @modifier APPLICATION the analyzer rejects
// as JETH329 when it names no declared modifier). The METHOD / GET / SET / CONSTRUCTOR positions are
// therefore NOT gated here (a constructor also takes modifier applications + @payable, both an open
// set this pre-analysis scan cannot resolve); their PARAMETERS still are (no parameter decorator is
// legal). An event/error FIELD (`E: event<{...}>`) is gated by the analyzer's JETH353 (only
// @anonymous is legal there), so it is skipped here to keep that one code. A banned retired name is
// left to collectBannedDecorators (JETH481) so it is never double-reported.
// ---------------------------------------------------------------------------------------------
const CLASS_DECORATORS = new Set(['diamond', 'storage', 'proxy', 'beacon', 'facet', 'using', 'uups']);
const FIELD_DECORATORS = new Set(['storage', 'override', 'virtual']);

function collectStrayDecorators(sf: ts.SourceFile, fileName: string): Diagnostic[] {
  const out: Diagnostic[] = [];
  // Canonical name, unwrapping a parenthesized `@(x)`; undefined for a MIS-SHAPED decorator
  // (`@a.b`, `@a[0]`, a computed expression) that names no bare/called identifier.
  const nameOf = (e: ts.Expression): string | undefined => {
    let x = e;
    while (ts.isParenthesizedExpression(x)) x = x.expression;
    if (ts.isIdentifier(x)) return x.text;
    if (ts.isCallExpression(x) && ts.isIdentifier(x.expression)) return x.expression.text;
    return undefined;
  };
  const report = (d: ts.Decorator, message: string): void => {
    const start = d.getStart(sf);
    const { line, character } = sf.getLineAndCharacterOfPosition(start);
    out.push({
      severity: 'error',
      code: 'JETH490',
      message,
      file: fileName,
      line: line + 1,
      column: character + 1,
      length: Math.max(1, d.getEnd() - start),
    });
  };
  // `E: event<{...}>` / `X: error<{...}>` field: its stray-decorator rule (only @anonymous) is the
  // analyzer's JETH353; skip it here so that one code survives unchanged.
  const isEventOrErrorField = (m: ts.PropertyDeclaration): boolean => {
    const t = m.type;
    return (
      !!t && ts.isTypeReferenceNode(t) && ts.isIdentifier(t.typeName) && (t.typeName.text === 'event' || t.typeName.text === 'error')
    );
  };
  const gate = (d: ts.Decorator, allowed: Set<string> | undefined, positionMsg: string): void => {
    const name = nameOf(d.expression);
    // A banned retired name is reported by collectBannedDecorators (JETH481); do not double-report.
    if (name !== undefined && Object.prototype.hasOwnProperty.call(BANNED_DECORATOR_POINTERS, name)) return;
    if (name !== undefined && allowed?.has(name)) return;
    const shown = name !== undefined ? '@' + name : '@' + d.expression.getText(sf).trim();
    report(d, `${shown} ${positionMsg}`);
  };
  const visit = (n: ts.Node): void => {
    if (ts.isClassDeclaration(n)) {
      for (const d of ts.getDecorators(n) ?? [])
        gate(
          d,
          CLASS_DECORATORS,
          'is not a valid class decorator (a class may carry only @diamond, @storage, @proxy, @beacon, @facet, @using, or @uups)',
        );
    } else if (ts.isPropertyDeclaration(n)) {
      if (!isEventOrErrorField(n))
        for (const d of ts.getDecorators(n) ?? [])
          gate(d, FIELD_DECORATORS, 'is not a valid field decorator (a field may carry only @storage, @override, or @virtual)');
    } else if (ts.isParameter(n)) {
      for (const d of ts.getDecorators(n) ?? [])
        gate(
          d,
          undefined,
          'cannot decorate a parameter (parameters take no decorators; an indexed event parameter is spelled `indexed<T>`)',
        );
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

/** MULTI-CONTRACT FILE (JETH041 lifted on the deployed path): solc compiles a file declaring N contracts
 *  into N SEPARATE artifacts, one per contract, each seeing the same file-level scope. compileUnit is the
 *  driver: it compiles route 0 (which reports how many deployable contracts the unit declares), then runs
 *  the remaining routes and returns them in DOCUMENT ORDER.
 *
 *  API is ADDITIVE. Every singular field of the returned result stays route 0's artifact (the first
 *  deployable contract in document order) exactly as before, and `contracts` is:
 *    - UNDEFINED for a single-contract file (the overwhelmingly common case) - so no existing caller sees
 *      any change whatsoever;
 *    - the full document-order list otherwise, with `contracts[0] === the returned result object` itself.
 *
 *  *** EACH ROUTE GETS ITS OWN FULL PIPELINE RUN, INCLUDING A FRESH PARSE. *** This is not an accident of
 *  structure - it is the correctness requirement. The analyzer strips the External/Payable/View/Pure return
 *  markers (and Visible<T> field markers, and receive/fallback markers) off the AST member nodes IN PLACE,
 *  so a second route re-analyzing the SAME tree silently demotes every marker-carrying member of a SHARED
 *  abstract base to internal, dropping those functions from route 1's dispatcher. Re-parsing is the whole
 *  fix; it is cheap (solc's Yul backend dominates a compile at ~92%). */
function compileUnit(source: string, opts: CompileOptions): CompileResult {
  const first = compileRoute(source, opts, 0);
  const routeCount = first.ir.routeCount ?? 1;
  if (routeCount <= 1) return first; // single-contract file: `contracts` stays undefined, result unchanged
  const contracts: CompileResult[] = [first];
  for (let i = 1; i < routeCount; i++) contracts.push(compileRoute(source, opts, i));
  // contracts[0] IS `first` (identity, not a copy), so a caller may use either handle interchangeably.
  first.contracts = contracts;
  return first;
}

/** JETH491 - ASCII-only inter-token whitespace. solc's lexer accepts only ASCII space (0x20), tab (0x09),
 *  CR (0x0D) and LF (0x0A) between tokens; TypeScript's scanner additionally skips a dozen Unicode
 *  whitespace / format code points (NBSP U+00A0, the U+2000-U+200A space family, OGHAM U+1680, NNBSP
 *  U+202F, MMSP U+205F, IDEOGRAPHIC U+3000, ZWSP U+200B, the U+2028/U+2029 line/paragraph separators) as
 *  well as the C0 controls VT (0x0B) and FF (0x0C), and treats a leading BOM/ZWNBSP (U+FEFF) as
 *  insignificant. Any of those in SEPARATOR position let a source through that solc rejects (an
 *  over-acceptance; the bytecode is byte-identical to the ASCII-clean mirror, so never a miscompile).
 *
 *  A pre-parse char scan (mirroring the parser's hoistInClassEnums string/comment tracking) rejects the
 *  FIRST code point outside a string/template literal or comment that is not printable ASCII (0x20-0x7E)
 *  nor one of tab/CR/LF - UNLESS it is a Unicode identifier-part character (é, 函, a combining mark). Those
 *  form or continue an identifier, so they reach the analyzer as a non-ASCII identifier and get the more
 *  specific JETH478 ("identifiers are ASCII-only") - this scan must not steal that diagnostic. Every char
 *  solc's ASCII-only lexer forbids as a SEPARATOR (a Unicode space/format char, a BOM, VT/FF, U+2028/2029)
 *  is `isIdentifierPart === false`, so the exemption is exact. A valid JETH program is pure ASCII outside
 *  literals (keywords, operators and numbers are ASCII; identifiers ASCII per JETH478), so this never
 *  rejects a program solc accepts. Contents of strings, template literals and comments are left untouched -
 *  a Unicode char THERE is legal content, and a raw char inside a plain string is solc's own separate
 *  concern (unicode"..."). */
function rejectNonAsciiSeparators(text: string, fileName: string): void {
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i]!;
    if (c === '"' || c === "'" || c === '`') {
      const q = c;
      i++;
      while (i < n) {
        if (text[i] === '\\') {
          i += 2;
          continue;
        }
        if (text[i] === q) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (c === '/' && text[i + 1] === '/') {
      i += 2;
      while (i < n && text[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    const cp = text.codePointAt(i)!;
    // Allowed outside a literal: tab, LF, CR, a printable ASCII byte, or a Unicode identifier-part char
    // (deferred to JETH478). Anything else (a Unicode space/format char, a stray C0/C1 control, DEL, or a
    // BOM) is a character solc's lexer rejects as a separator.
    const allowed =
      cp === 0x09 ||
      cp === 0x0a ||
      cp === 0x0d ||
      (cp >= 0x20 && cp <= 0x7e) ||
      ts.isIdentifierPart(cp, ts.ScriptTarget.Latest);
    if (!allowed) {
      let line = 1;
      let col = 1;
      for (let k = 0; k < i; k++) {
        if (text[k] === '\n') {
          line++;
          col = 1;
        } else {
          col++;
        }
      }
      const hex = cp.toString(16).toUpperCase().padStart(4, '0');
      throw new CompileError([
        {
          severity: 'error',
          code: 'JETH491',
          message: `disallowed character U+${hex} outside a string or comment; only ASCII space, tab, CR and LF are valid between tokens (Solidity's lexer is ASCII-only) - a Unicode space, format character or BOM here is not accepted`,
          file: fileName,
          line,
          column: col,
          length: 1,
        },
      ]);
    }
    i += cp > 0xffff ? 2 : 1;
  }
}

/** Compile ONE deployable contract (`routeIndex`, document order) out of `source`, front-to-back: parse,
 *  the full front-end, analysis of that route only, Yul emission and the backend. Every call re-parses, so
 *  no route can observe another route's in-place AST edits (see compileUnit). */
function compileRoute(source: string, opts: CompileOptions, routeIndex: number): CompileResult {
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

  // JETH491: reject any non-ASCII / control code point used as inter-token whitespace (a separator solc's
  // ASCII-only lexer forbids) BEFORE parse - scanning the raw entry source and every dependency source, so
  // a Unicode space / BOM in any original file is caught at its own file's position. Literal/comment
  // contents are skipped, so legal Unicode string/comment text is untouched.
  rejectNonAsciiSeparators(source, fileName);
  if (opts.sources) {
    for (const [depName, depText] of Object.entries(opts.sources)) {
      if (depName !== fileName) rejectNonAsciiSeparators(depText, depName);
    }
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
  const bannedDecorators = [...collectBannedDecorators(banSf, fileName), ...collectStrayDecorators(banSf, fileName)];
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
  // OA close (multi-file): a contract MEMBER of any kind (method / get accessor / storage field of every
  // flavor / member error<{}> / member event<{}> / @modifier) whose name collides with a same-named IMPORTED
  // file-level error/event/struct/enum/interface/Brand is an "Identifier already declared" reject the
  // SINGLE-FILE analyzer already gives (JETH133, its cross-scope gate). The v3 rename below would mangle the
  // imported symbol to `$mN$X` and route the bundle AROUND that gate, so detect the collision here on
  // PRISTINE names (before the rename mutates them) and emit the same JETH133 the single-file path produces.
  // The fired (class, name) pairs feed rewriteModuleScopes, which disables the value-member reference shadow
  // for exactly those pairs so the companion code list matches the single-file twin's (see the pre-pass doc).
  const memberCollisionRejects =
    bundleSegments && bundleRenames
      ? collectImportedMemberTypeCollisions(parsed.sourceFile, bundleSegments, bundleRenames, diags, routeIndex)
      : undefined;
  // v3 module scoping FIRST: rename each dep's top-level declarations (and every file's import bindings)
  // to their `$mN$` scoped names, so every later pass (the # mangle, the static-member rewrite, all name
  // resolution) sees one consistent namespace with per-file scoping already applied.
  if (bundleSegments && bundleRenames)
    rewriteModuleScopes(parsed.sourceFile, bundleSegments, bundleRenames, memberCollisionRejects);
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
    routeIndex,
  );

  // Surface all front-end diagnostics together.
  // Multi-file: map bundle-relative diagnostic positions back to their original files before surfacing.
  if (bundleSegments) remapDiagnostics(diags.items, bundleSegments);
  diags.throwIfErrors();
  if (!ir) throw new CompileError(diags.items);

  // ABSTRACT-ONLY / INTERFACE-ONLY unit: the analyzer type-checked every member but nothing is
  // deployable (an abstract contract / interface is not instantiable). Match solc, which accepts such a
  // file and emits EMPTY creation bytecode: skip Yul emission + the backend and return the empty artifact.
  if (ir.nonDeployable) {
    return {
      contractName: ir.name,
      abi: emitAbi(ir),
      creationBytecode: '',
      runtimeBytecode: '',
      yul: '',
      storageLayout: [],
      ir,
      diagnostics: diags.items,
    };
  }

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
