// Multi-file import system (v1: BUNDLING). JETH's analyzer works on ONE compilation unit; imports are
// resolved by splicing the imported files' text (deps first, entry last) into a single bundle BEFORE
// parse, with the import statements blanked out (whitespace-preserving, so every file keeps its own line
// numbers) and a per-file line map so diagnostics point back into the ORIGINAL files.
//
// Semantics (v1):
//  - `import { A, B } from "./file.jeth"` - NAMED imports only; relative paths only. Default (`import X`),
//    namespace (`* as X`), side-effect (`import "./x"`), and alias (`A as B`) forms are rejected.
//  - Only `export`-marked top-level declarations are importable (TS-strict; `export` finally MEANS
//    something). A named import that is not an exported declaration of the target file rejects.
//  - An imported file may declare libraries (static class / @library), types, interfaces, abstract bases,
//    enums - but NOT a deployed contract (one contract per ENTRY file; a dep's concrete class rejects).
//  - Every file must share the entry's syntax mode (native vs `// use @decorators`) - the bundle is one
//    unit with one mode; a cross-mode import is a clear error (migrate the file or the entry).
//  - Import cycles reject with the cycle path; diamond imports (A->B, A->C, B&C->D) dedupe (D once).
// v1 looseness (documented): bundling puts EVERY top-level declaration of an imported file in scope, not
// just the named ones - the named list is validated (typo + export enforcement), but unnamed siblings are
// reachable too (the TS IDE flags them; strict per-name scoping is a v2 item).
import ts from 'typescript';
import { CompileError, Diagnostic } from './diagnostics.js';

export interface BundleSegment {
  file: string;
  startLine: number; // 1-based line in the bundle where this file's text begins
  lineCount: number;
}

export interface BundleResult {
  text: string;
  segments: BundleSegment[];
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
  for (const s of sf.statements) {
    if (!ts.isClassDeclaration(s)) continue;
    const decs = classDecoratorNames(s);
    if (decs.some((d) => DEPLOYABLE_DECORATORS.has(d))) {
      fail(file, sf, s, `an imported file cannot declare a deployed contract ('${s.name?.text ?? '<anon>'}'); only libraries, types, interfaces, and abstract bases are importable - the contract lives in the entry file`);
    }
    if (!nativeMode) continue; // decorator mode: bare classes were always inert
    const mods = ts.getModifiers(s) ?? [];
    const isAbstract = mods.some((m) => m.kind === ts.SyntaxKind.AbstractKeyword);
    const isStatic = mods.some((m) => m.kind === ts.SyntaxKind.StaticKeyword);
    if (!isAbstract && !isStatic && !decs.some((d) => NON_CONTRACT_KIND_DECORATORS.has(d))) {
      fail(file, sf, s, `an imported file cannot declare a concrete contract class ('${s.name?.text ?? '<anon>'}'); make it \`abstract\` (a base), \`static\` (a library), or move it to the entry file`);
    }
  }
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

/**
 * Resolve the entry file's imports (recursively) against `sources` (path -> source text) and produce ONE
 * bundled compilation unit: imported files first (dependency post-order, deduped), the entry last, each
 * file's import statements blanked in place. Throws CompileError (JETH036, positioned in the ORIGINAL
 * file) on: an unsupported import form, an unresolvable path, a name that is not an exported declaration,
 * an import cycle, a cross-mode import, or a deployed contract in an imported file.
 */
export function bundleImports(entryText: string, entryFile: string, sources: Record<string, string>): BundleResult {
  const entryMode = isDecoratorModeSource(entryText);
  const byPath = new Map<string, string>();
  for (const [k, v] of Object.entries(sources)) byPath.set(normalizePath(k), v);
  const entryKey = normalizePath(entryFile);

  const order: { file: string; text: string }[] = [];
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
        if (el.propertyName) fail(displayName, sf, el, `import aliases ('${el.propertyName.text} as ${el.name.text}') are not supported yet`);
        if (!exported.has(el.name.text)) {
          const avail = [...exported].sort().join(', ') || '<nothing exported>';
          fail(displayName, sf, el, `'${el.name.text}' is not an exported declaration of '${targetKey}' (exported: ${avail}); mark it \`export\` there`);
        }
      }
      blanked = blankSpan(blanked, s.getStart(sf), s.getEnd());
    }

    inStack.pop();
    visited.add(fileKey);
    order.push({ file: displayName, text: blanked });
  };

  visit(entryKey, entryFile, entryText, true);

  const segments: BundleSegment[] = [];
  let line = 1;
  const parts: string[] = [];
  for (const { file, text } of order) {
    const lines = countLines(text);
    segments.push({ file, startLine: line, lineCount: lines });
    parts.push(text);
    line += lines;
  }
  return { text: parts.join('\n'), segments };
}
