// Multi-file import system (v1: BUNDLING). JETH's analyzer works on ONE compilation unit; imports are
// resolved by splicing the imported files' text (deps first, entry last) into a single bundle BEFORE
// parse, with the import statements blanked out (whitespace-preserving, so every file keeps its own line
// numbers) and a per-file line map so diagnostics point back into the ORIGINAL files.
//
// Semantics (v1):
//  - `import { A, B } from "./file.jeth"` - NAMED imports only; relative paths only. Default (`import X`),
//    namespace (`* as X`), and side-effect (`import "./x"`) forms are rejected.
//  - CONVENIENCE aliases work: `import { A as B }` renames A to B locally (compile() rewrites B -> A in
//    the importing file post-parse, position-preserving; the alias must be a FREE name there). Aliases do
//    NOT enable two same-named exports in one program - the bundle is one namespace, so that still rejects
//    (JETH037); per-file declaration scoping is the v3 module system.
//  - Only `export`-marked top-level declarations are importable (TS-strict; `export` finally MEANS
//    something). A named import that is not an exported declaration of the target file rejects.
//  - An imported file may declare libraries (static class / @library), types, interfaces, abstract bases,
//    enums - but NOT a deployed contract (one contract per ENTRY file; a dep's concrete class rejects).
//  - Every file must share the entry's syntax mode (native vs `// use @decorators`) - the bundle is one
//    unit with one mode; a cross-mode import is a clear error (migrate the file or the entry).
//  - Import cycles reject with the cycle path; diamond imports (A->B, A->C, B&C->D) dedupe (D once).
//  - v2 PER-NAME SCOPING: after bundling, every file's references are checked - using a name declared in
//    ANOTHER file requires an import edge for that name (JETH039 "not imported; add `import {X}`"), and an
//    unexported declaration is unreachable from outside its file (JETH039 "not exported"). The check is
//    purely ADDITIVE (it runs before analysis and only turns programs into rejects), conservative about
//    shadowing (a local/param/type-param with the same name suppresses the check for that name), and
//    identifier-based - one KNOWN gap: a `self`-convention ATTACHED call (`a.min(b)`) names no library
//    identifier, so a transitively-bundled library's self-functions can attach without an import edge.
import ts from 'typescript';
import { CompileError, Diagnostic } from './diagnostics.js';
import { resolvePrimitiveName } from './typeresolver.js';

export interface BundleSegment {
  file: string;
  startLine: number; // 1-based line in the bundle where this file's text begins
  lineCount: number;
}

export interface BundleResult {
  text: string;
  segments: BundleSegment[];
  /** Per file: the names VISIBLE to it (its own declarations, recursively, plus its named imports - by
   *  ORIGINAL name, so `import { A as B }` contributes A). Used by the analyzer to scope `self`-convention
   *  ATTACHED calls (which name no library identifier, so the identifier-based reference check cannot see
   *  them) to each file's import edges. */
  visibleByFile: Map<string, Set<string>>;
  /** Per file: alias -> original for `import { A as B }` bindings. compile() rewrites each B reference in
   *  that file back to A after parse (position-preserving), so everything downstream sees original names. */
  aliasesByFile: Map<string, Map<string, string>>;
}

/** Per-file syntax mode: a file whose leading comment run contains the exact line `// use @decorators` is
 *  DECORATOR mode; any other file is NATIVE mode. Tolerates \r\n / lone-\r line endings and benign
 *  spacing/slash variants of the directive; an SPDX-style leading comment keeps scanning; the first code
 *  or block-comment line closes the pragma window. */
export function isDecoratorModeSource(source: string): boolean {
  for (const raw of source.split(/\r\n|\r|\n/)) {
    const line = raw.trim();
    if (line === '') continue; // blank line: keep scanning
    if (line.startsWith('//')) {
      const body = line.replace(/^\/+/, '').replace(/\s+/g, ' ').trim();
      if (body === 'use @decorators') return true;
      continue; // another leading line-comment (e.g. an SPDX header): keep scanning
    }
    break; // first code / block-comment line: the pragma window is closed
  }
  return false;
}

/** Remap bundle-relative diagnostics back to their ORIGINAL file + line via the segment map. Column and
 *  length are already file-local (blanking preserves every line's layout). */
export function remapDiagnostics(items: Diagnostic[], segments: BundleSegment[]): void {
  for (const d of items) {
    for (const seg of segments) {
      if (d.line >= seg.startLine && d.line < seg.startLine + seg.lineCount) {
        d.file = seg.file;
        d.line = d.line - seg.startLine + 1;
        break;
      }
    }
  }
}

function dirOf(p: string): string {
  const i = p.lastIndexOf('/');
  return i < 0 ? '' : p.slice(0, i);
}

/** Normalize a joined path: resolve `.` / `..` segments, collapse `//`. Purely lexical (no filesystem). */
function normalizePath(p: string): string {
  const out: string[] = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (out.length > 0 && out[out.length - 1] !== '..') out.pop();
      else out.push(seg);
    } else out.push(seg);
  }
  return out.join('/');
}

function fail(file: string, sf: ts.SourceFile, node: ts.Node, message: string): never {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  throw new CompileError([
    {
      severity: 'error',
      code: 'JETH036',
      message,
      file,
      line: line + 1,
      column: character + 1,
      length: Math.max(1, node.getEnd() - node.getStart(sf)),
    },
  ]);
}

/** The exported top-level declaration names of a parsed file (class / type / interface / enum carrying the
 *  `export` modifier). Only these are importable. */
function exportedNames(sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  for (const s of sf.statements) {
    if (
      (ts.isClassDeclaration(s) || ts.isTypeAliasDeclaration(s) || ts.isInterfaceDeclaration(s) || ts.isEnumDeclaration(s)) &&
      s.name &&
      (ts.getModifiers(s) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
    ) {
      names.add(s.name.text);
    }
  }
  return names;
}

/** Names an import ALIAS may not take: the rewrite renames every reference-position use of the alias, so
 *  an alias shadowing a marker/global would hijack unrelated syntax (primitives are checked separately via
 *  resolvePrimitiveName - `import { A as u256 }` would rewrite every u256 type annotation in the file). */
const RESERVED_ALIAS_NAMES = new Set(['External', 'Payable', 'View', 'Pure', 'error', 'event', 'indexed', 'msg', 'abi', 'block', 'tx', 'self', 'Brand', 'Arr', 'mapping']);

const DEPLOYABLE_DECORATORS = new Set(['contract', 'proxy', 'beacon', 'facet', 'diamond']);
const NON_CONTRACT_KIND_DECORATORS = new Set(['struct', 'interface', 'library', 'abstract']);

function classDecoratorNames(cls: ts.ClassDeclaration): string[] {
  return (ts.getDecorators(cls) ?? [])
    .map((d) =>
      ts.isIdentifier(d.expression)
        ? d.expression.text
        : ts.isCallExpression(d.expression) && ts.isIdentifier(d.expression.expression)
          ? d.expression.expression.text
          : '',
    )
    .filter(Boolean);
}

/** An imported (non-entry) file may not declare a deployed contract: reject @contract/@proxy/... in any
 *  mode, and (native mode) a BARE concrete class - which the contract fallback would otherwise pick up as
 *  a second deployable (JETH041 confusion). Libraries / types / interfaces / abstract bases are the
 *  importable kinds. */
function rejectDepContracts(file: string, sf: ts.SourceFile, nativeMode: boolean): void {
  // RECURSIVE walk: the analyzer's contract discovery is recursive too, so a class hidden inside a nested
  // block (`{ @contract class Rogue {} }`) would otherwise smuggle a deployed contract past a top-level-only
  // scan - and a decorated dep contract would then silently REPLACE the entry's contract as the artifact.
  const visit = (s: ts.Node): void => {
    if (ts.isClassDeclaration(s)) {
      const decs = classDecoratorNames(s);
      if (decs.some((d) => DEPLOYABLE_DECORATORS.has(d))) {
        fail(file, sf, s, `an imported file cannot declare a deployed contract ('${s.name?.text ?? '<anon>'}'); only libraries, types, interfaces, and abstract bases are importable - the contract lives in the entry file`);
      }
      const mods = ts.getModifiers(s) ?? [];
      const isAbstract = mods.some((m) => m.kind === ts.SyntaxKind.AbstractKeyword);
      const isStatic = mods.some((m) => m.kind === ts.SyntaxKind.StaticKeyword);
      if (nativeMode && !isAbstract && !isStatic && !decs.some((d) => NON_CONTRACT_KIND_DECORATORS.has(d))) {
        fail(file, sf, s, `an imported file cannot declare a concrete contract class ('${s.name?.text ?? '<anon>'}'); make it \`abstract\` (a base), \`static\` (a library), or move it to the entry file`);
      }
    }
    ts.forEachChild(s, visit);
  };
  ts.forEachChild(sf, visit);
}

/** Blank a [start,end) span in `text`, preserving newlines so every line keeps its number and layout. */
function blankSpan(text: string, start: number, end: number): string {
  let mid = '';
  for (let i = start; i < end; i++) {
    const ch = text[i]!;
    mid += ch === '\n' || ch === '\r' ? ch : ' ';
  }
  return text.slice(0, start) + mid + text.slice(end);
}

function countLines(s: string): number {
  return s.split(/\r\n|\r|\n/).length;
}

// ---- v2 per-name import scoping ------------------------------------------------------------------

/** Every declaration name in the file that could be referenced cross-file: class (any kind), type alias,
 *  interface, enum. RECURSIVE (a nested declaration still occupies the unit's namespace once bundled), so
 *  an own nested name never false-positives as a cross-file reference. */
function declaredNames(sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  const visit = (n: ts.Node): void => {
    if (
      (ts.isClassDeclaration(n) || ts.isTypeAliasDeclaration(n) || ts.isInterfaceDeclaration(n) || ts.isEnumDeclaration(n)) &&
      n.name
    ) {
      names.add(n.name.text);
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);
  return names;
}

/** Conservative shadow set: every locally-bound value/type name in the file (params, locals, binding
 *  elements, type parameters). A cross-file-looking reference that shares a name with ANY local binding is
 *  skipped - the analyzer's normal resolution decides it; this check must never false-positive. */
function shadowNames(sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  const visit = (n: ts.Node): void => {
    if ((ts.isParameter(n) || ts.isVariableDeclaration(n) || ts.isBindingElement(n)) && ts.isIdentifier(n.name)) {
      names.add(n.name.text);
    }
    if (ts.isTypeParameterDeclaration(n)) names.add(n.name.text);
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);
  return names;
}

/** Is this identifier a REFERENCE (a use of a name), as opposed to a member-name / key / a declaration's
 *  own name? The property side of `x.f` / `A.B`, an object key, and any node's own `name` are not
 *  references; a shorthand property (`{ MathLib }`) IS one. (Exported: the alias rewrite in compile.ts
 *  renames exactly these positions.) */
export function isReferenceIdentifier(n: ts.Identifier): boolean {
  const p = n.parent as ts.Node | undefined;
  if (!p) return false;
  if (ts.isPropertyAccessExpression(p) && p.name === n) return false;
  if (ts.isQualifiedName(p) && p.right === n) return false;
  if (ts.isShorthandPropertyAssignment(p)) return true; // `{ X }` is a value reference to X
  if ((p as { name?: ts.Node }).name === n) return false; // its own declaration / key name
  return true;
}

interface FileInfo {
  display: string;
  blanked: string;
  imported: Set<string>; // LOCAL names (an alias counts as its local name for the reference check)
  importedOriginals: Set<string>; // ORIGINAL names (attachment visibility keys on the real library name)
  aliases: Map<string, string>; // alias -> original
}

/** v2 scoping: a reference to a name declared in ANOTHER file requires an import edge for that name; an
 *  unexported declaration is unreachable from outside its file. Reports EVERY offending name (deduped per
 *  file+name, first occurrence) in one CompileError, each positioned in its own file. */
function checkCrossFileReferences(files: FileInfo[]): void {
  if (files.length < 2) return;
  const parsed = files.map((f) => ({ ...f, sf: ts.createSourceFile(f.display, f.blanked, ts.ScriptTarget.Latest, true) }));
  // name -> its declaring file (+ exported?). Duplicate declarations across files are the analyzer's
  // JETH037 concern; the first declarer is attribution enough here.
  const declaredBy = new Map<string, { file: string; exported: boolean }>();
  for (const f of parsed) {
    const exp = exportedNames(f.sf);
    for (const nm of declaredNames(f.sf)) {
      if (!declaredBy.has(nm)) declaredBy.set(nm, { file: f.display, exported: exp.has(nm) });
    }
  }
  const errors: Diagnostic[] = [];
  for (const f of parsed) {
    const own = declaredNames(f.sf);
    const shadows = shadowNames(f.sf);
    const reported = new Set<string>();
    const visit = (n: ts.Node): void => {
      if (ts.isIdentifier(n) && isReferenceIdentifier(n)) {
        const nm = n.text;
        if (!own.has(nm) && !f.imported.has(nm) && !shadows.has(nm) && !reported.has(nm)) {
          const d = declaredBy.get(nm);
          if (d && d.file !== f.display) {
            reported.add(nm);
            const { line, character } = f.sf.getLineAndCharacterOfPosition(n.getStart(f.sf));
            errors.push({
              severity: 'error',
              code: 'JETH039',
              message: d.exported
                ? `'${nm}' is declared in '${d.file}' but not imported here; add \`import { ${nm} } from "./${d.file}"\` (adjust the relative path)`
                : `'${nm}' is declared in '${d.file}' but not exported; mark it \`export\` there and import it here`,
              file: f.display,
              line: line + 1,
              column: character + 1,
              length: nm.length,
            });
          }
        }
      }
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(f.sf, visit);
  }
  if (errors.length > 0) throw new CompileError(errors);
}

/**
 * Resolve the entry file's imports (recursively) against `sources` (path -> source text) and produce ONE
 * bundled compilation unit: imported files first (dependency post-order, deduped), the entry last, each
 * file's import statements blanked in place. Throws CompileError (JETH036, positioned in the ORIGINAL
 * file) on: an unsupported import form, an unresolvable path, a name that is not an exported declaration,
 * an import cycle, a cross-mode import, or a deployed contract in an imported file.
 */
export function bundleImports(entryText: string, entryFile: string, sources: Record<string, string>): BundleResult {
  const entryMode = isDecoratorModeSource(entryText);
  // Normalize line endings up front (\r\n and lone \r -> \n): line/column numbering is unchanged, but the
  // bundle join becomes safe - a file ENDING in a lone \r would otherwise merge with the join's \n into ONE
  // \r\n terminator while the segment math counted two lines, shifting every later file's diagnostics.
  const normalizeEol = (s: string): string => s.replace(/\r\n?/g, '\n');
  const byPath = new Map<string, string>();
  for (const [k, v] of Object.entries(sources)) {
    const nk = normalizePath(k);
    const nv = normalizeEol(v);
    const prior = byPath.get(nk);
    if (prior !== undefined && prior !== nv) {
      throw new CompileError([
        { severity: 'error', code: 'JETH036', message: `ambiguous sources: two keys normalize to '${nk}' with different contents (e.g. 'x.jeth' and './x.jeth'); provide one`, file: k, line: 1, column: 1, length: 1 },
      ]);
    }
    byPath.set(nk, nv);
  }
  const entryKey = normalizePath(entryFile);

  const order: { file: string; text: string }[] = [];
  const fileInfos: FileInfo[] = [];
  const visited = new Set<string>();
  const inStack: string[] = [];

  const visit = (fileKey: string, displayName: string, text: string, isEntry: boolean): void => {
    if (inStack.includes(fileKey)) {
      const cycle = [...inStack.slice(inStack.indexOf(fileKey)), fileKey].join(' -> ');
      throw new CompileError([
        { severity: 'error', code: 'JETH036', message: `import cycle: ${cycle}`, file: displayName, line: 1, column: 1, length: 1 },
      ]);
    }
    if (visited.has(fileKey)) return;
    inStack.push(fileKey);

    const sf = ts.createSourceFile(displayName, text, ts.ScriptTarget.Latest, true);
    const fileMode = isDecoratorModeSource(text);
    if (fileMode !== entryMode) {
      throw new CompileError([
        {
          severity: 'error',
          code: 'JETH036',
          message: `'${displayName}' is ${fileMode ? 'decorator' : 'native'}-mode but the entry file is ${entryMode ? 'decorator' : 'native'}-mode; all files of one compilation share the entry's syntax mode`,
          file: displayName,
          line: 1,
          column: 1,
          length: 1,
        },
      ]);
    }
    if (!isEntry) rejectDepContracts(displayName, sf, !entryMode);

    let blanked = text;
    const importedHere = new Set<string>();
    const importedOriginals = new Set<string>();
    const aliasesHere = new Map<string, string>();
    for (const s of sf.statements) {
      if (ts.isImportEqualsDeclaration(s)) fail(displayName, sf, s, `'import =' is not supported; use \`import { A, B } from "./file.jeth"\``);
      if (!ts.isImportDeclaration(s)) continue;
      const clause = s.importClause;
      if (!clause) fail(displayName, sf, s, `a side-effect import has no meaning in JETH; use \`import { A, B } from "./file.jeth"\``);
      if (clause.name) fail(displayName, sf, s, `a default import is not supported; use \`import { ${clause.name.text} } from ...\` with an exported named declaration`);
      const bindings = clause.namedBindings;
      if (!bindings || !ts.isNamedImports(bindings)) fail(displayName, sf, s, `a namespace import (\`* as X\`) is not supported; use \`import { A, B } from "./file.jeth"\``);
      if (!ts.isStringLiteral(s.moduleSpecifier)) fail(displayName, sf, s, `an import path must be a plain string literal`);
      const spec = s.moduleSpecifier.text;
      if (!spec.startsWith('./') && !spec.startsWith('../')) {
        fail(displayName, sf, s.moduleSpecifier, `import paths are relative ('./' or '../'); got '${spec}'`);
      }
      const targetKey = normalizePath(dirOf(fileKey) === '' ? spec : `${dirOf(fileKey)}/${spec}`);
      const targetText = byPath.get(targetKey);
      if (targetText === undefined) {
        fail(displayName, sf, s.moduleSpecifier, `cannot resolve import '${spec}' (looked for '${targetKey}' in the provided sources)`);
      }
      // resolve the target FIRST (deps precede importers in the bundle), then validate the named list.
      visit(targetKey, targetKey, targetText, false);
      const targetSf = ts.createSourceFile(targetKey, targetText, ts.ScriptTarget.Latest, true);
      const exported = exportedNames(targetSf);
      for (const el of bindings.elements) {
        // `import { A as B }`: A (propertyName) is the ORIGINAL exported declaration; B (name) is the
        // LOCAL alias. compile() rewrites B -> A in this file after parse, so the alias must be a FREE
        // name here - it may not collide with anything the rewrite could hijack.
        const original = el.propertyName?.text ?? el.name.text;
        const local = el.name.text;
        if (!exported.has(original)) {
          const avail = [...exported].sort().join(', ') || '<nothing exported>';
          fail(displayName, sf, el, `'${original}' is not an exported declaration of '${targetKey}' (exported: ${avail}); mark it \`export\` there`);
        }
        if (el.propertyName) {
          if (resolvePrimitiveName(local) || RESERVED_ALIAS_NAMES.has(local)) {
            fail(displayName, sf, el.name, `import alias '${local}' shadows a builtin type, global, or native marker; pick another name`);
          }
          if (importedHere.has(local)) {
            fail(displayName, sf, el.name, `import alias '${local}' collides with another import in this file`);
          }
          aliasesHere.set(local, original);
        } else if (aliasesHere.has(local)) {
          fail(displayName, sf, el.name, `'${local}' collides with an import alias in this file`);
        }
        importedHere.add(local);
        importedOriginals.add(original);
      }
      blanked = blankSpan(blanked, s.getStart(sf), s.getEnd());
    }
    // The alias rewrite renames every reference-position `alias` in THIS file - so the alias may not also
    // be a declared name or a local binding here (the rewrite would hijack them). Conservative and loud,
    // exactly the ClassName.x rewrite's shadow discipline.
    if (aliasesHere.size > 0) {
      const declared = declaredNames(sf);
      const shadows = shadowNames(sf);
      for (const [alias] of aliasesHere) {
        if (declared.has(alias)) fail(displayName, sf, sf, `import alias '${alias}' collides with a declaration in this file; pick another name`);
        if (shadows.has(alias)) fail(displayName, sf, sf, `import alias '${alias}' collides with a local binding (a parameter or variable) in this file; pick another name`);
      }
    }

    inStack.pop();
    visited.add(fileKey);
    order.push({ file: displayName, text: blanked });
    fileInfos.push({ display: displayName, blanked, imported: importedHere, importedOriginals, aliases: aliasesHere });
  };

  visit(entryKey, entryFile, normalizeEol(entryText), true);

  // v2 per-name scoping: cross-file references need an import edge; unexported declarations stay private.
  checkCrossFileReferences(fileInfos);

  const visibleByFile = new Map<string, Set<string>>();
  const aliasesByFile = new Map<string, Map<string, string>>();
  for (const f of fileInfos) {
    const sf = ts.createSourceFile(f.display, f.blanked, ts.ScriptTarget.Latest, true);
    // attachment visibility keys on ORIGINAL names (an aliased import still makes the real library visible).
    visibleByFile.set(f.display, new Set([...declaredNames(sf), ...f.importedOriginals]));
    if (f.aliases.size > 0) aliasesByFile.set(f.display, f.aliases);
  }

  const segments: BundleSegment[] = [];
  let line = 1;
  const parts: string[] = [];
  for (const { file, text } of order) {
    const lines = countLines(text);
    segments.push({ file, startLine: line, lineCount: lines });
    parts.push(text);
    line += lines;
  }
  return { text: parts.join('\n'), segments, visibleByFile, aliasesByFile };
}
