// Frontend: parse JETH source into a TypeScript *syntactic* AST.
//
// We deliberately use ts.createSourceFile (parser only), not ts.createProgram
// (full type checker): JETH's annotations (u256, address, mapping<K,V>) are not
// real TS types, so the TS checker is the wrong tool. We own type checking.
import ts from 'typescript';

export interface ParsedSource {
  sourceFile: ts.SourceFile;
  fileName: string;
  text: string;
  /** Class-body enums preceded by a modifier keyword (`const enum E {}`, `export enum E {}`, ...):
   *  deliberately NOT hoisted; compile() rejects each loudly (JETH484) before analysis. */
  classEnumModifierErrors: ClassEnumModifierError[];
}

/** A class-body enum that carries one or more modifier keywords. Hoisting only the `enum Name { ... }`
 *  text would leave the modifier behind in the class body, where TS error-recovers it into a modifier
 *  on the NEXT member (possibly changing its meaning, e.g. `static`) or a keyword-named phantom
 *  property that the analyzer would silently ignore - the JETH476/479 silent-recovery family. */
export interface ClassEnumModifierError {
  start: number; // offset of the first modifier keyword
  end: number; // offset just past the enum body's closing `}` (or past `enum` when malformed)
  modifiers: string[]; // the modifier words, in source order (e.g. ['export', 'const'])
  name: string; // the enum's name, '' when unreadable
}

export function parse(text: string, fileName = 'contract.jeth'): ParsedSource {
  // Solidity allows `enum` inside a contract, but TS refuses an enum as a class member
  // (it closes the class empty and silently drops the rest of the body -> empty contract).
  // Hoist any in-class enum to top level before parsing. Offsets are preserved (the enum is
  // blanked in place with equal-length whitespace and appended at the end), so diagnostic
  // spans for the rest of the file are unchanged. No-op when no in-class enum is present.
  const { text: hoisted, errors } = hoistInClassEnums(text);
  const sourceFile = ts.createSourceFile(
    fileName,
    hoisted,
    ts.ScriptTarget.Latest,
    /*setParentNodes*/ true,
    ts.ScriptKind.TS,
  );
  return { sourceFile, fileName, text: hoisted, classEnumModifierErrors: errors };
}

/** Every TS modifier keyword that could be written in front of a class-body `enum`. None of them is
 *  legal there (solc contract-scoped enums carry no modifiers), and hoisting past one would strand it
 *  as silent error-recovery residue, so the scanner refuses to hoist and records a JETH484 error. */
const CLASS_ENUM_MODIFIER_WORDS = new Set([
  'const',
  'export',
  'declare',
  'static',
  'abstract',
  'readonly',
  'override',
  'public',
  'private',
  'protected',
  'async',
  'accessor',
]);

/** Move `enum Name { ... }` declarations that sit DIRECTLY inside a class body out to top level.
 *  A char scanner tracks string/comment state and a brace stack (each entry records whether that
 *  brace opened a `class` body). An enum is hoistable only when the brace directly enclosing it is a
 *  class body: an enum nested inside a method body / block is left in place so it reaches the analyzer
 *  as an illegal statement-position declaration (solc rejects `enum` outside file/contract scope).
 *  Each hoisted enum is blanked where it sat (newlines kept, so offsets/line numbers are stable) and
 *  re-appended at the end of the source, where collectEnums (a position-agnostic recursive walk)
 *  registers it. No-op when no directly-in-class enum is present.
 *
 *  A class-body enum PRECEDED by a modifier keyword (`const enum E {}`, `export const enum E {}`,
 *  `static enum E {}`, ...) is NOT hoisted: hoisting only the `enum ... }` text would leave the
 *  modifier stranded in the class body, where TS error-recovers it into a modifier on the NEXT member
 *  (`static` would silently change that member's meaning) or a keyword-named phantom property. The
 *  scanner records the span in `errors` instead; compile() rejects it loudly (JETH484). Modifier words
 *  are tracked ONLY directly inside a class body, so file-level `export enum` (the multi-file import
 *  mechanism) is untouched. */
function hoistInClassEnums(text: string): { text: string; errors: ClassEnumModifierError[] } {
  const isWord = (ch: string) => /[A-Za-z0-9_$]/.test(ch);
  const spans: { start: number; end: number }[] = [];
  const errors: ClassEnumModifierError[] = [];
  const n = text.length;
  // Brace stack: true iff this `{` opened a class body. `pendingClass` is set when the `class`
  // keyword has been seen and its opening `{` is still awaited (past the name / heritage clause).
  const braceIsClass: boolean[] = [];
  let pendingClass = false;
  // Modifier keyword(s) seen directly in a class body whose following token is still awaited.
  // Comments and whitespace keep the run alive; any other token clears it. If the next token is
  // `enum`, the run becomes a JETH484 error instead of a hoist.
  let pendingMods: { start: number; words: string[] } | null = null;
  let i = 0;
  const inClassBody = () => braceIsClass.length > 0 && braceIsClass[braceIsClass.length - 1] === true;
  while (i < n) {
    const c = text[i]!;
    if (c === '"' || c === "'" || c === '`') {
      pendingMods = null;
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
    if (
      c === 'c' &&
      text.startsWith('class', i) &&
      !isWord(text[i - 1] ?? '') &&
      !isWord(text[i + 5] ?? '')
    ) {
      pendingMods = null;
      pendingClass = true;
      i += 5;
      continue;
    }
    if (c === '{') {
      pendingMods = null;
      braceIsClass.push(pendingClass);
      pendingClass = false;
      i++;
      continue;
    }
    if (c === '}') {
      pendingMods = null;
      braceIsClass.pop();
      i++;
      continue;
    }
    if (
      inClassBody() &&
      c === 'e' &&
      text.startsWith('enum', i) &&
      !isWord(text[i - 1] ?? '') &&
      !isWord(text[i + 4] ?? '')
    ) {
      let j = i + 4;
      while (j < n && text[j] !== '{' && text[j] !== '}' && text[j] !== ';') j++;
      if (j < n && text[j] === '{') {
        let d2 = 0;
        let k = j;
        for (; k < n; k++) {
          if (text[k] === '{') d2++;
          else if (text[k] === '}') {
            d2--;
            if (d2 === 0) {
              k++;
              break;
            }
          }
        }
        if (pendingMods !== null) {
          // Modifier-preceded class-body enum: refuse to hoist, record a loud error instead.
          const nameMatch = /^enum\s+([A-Za-z_$][A-Za-z0-9_$]*)/.exec(text.slice(i, j + 1));
          errors.push({
            start: pendingMods.start,
            end: k,
            modifiers: pendingMods.words,
            name: nameMatch?.[1] ?? '',
          });
          pendingMods = null;
          i = k;
          continue;
        }
        spans.push({ start: i, end: k });
        i = k;
        continue;
      }
      // Malformed enum (`const enum;` / body never opens): leave it for TS error recovery; the
      // parse-diagnostics guard rejects a silently-accepted malformed source. The `enum` word itself
      // is a token, so it ends any pending modifier run.
      pendingMods = null;
      i += 4;
      continue;
    }
    if (inClassBody() && /[A-Za-z]/.test(c) && !isWord(text[i - 1] ?? '')) {
      let e = i + 1;
      while (e < n && isWord(text[e] ?? '')) e++;
      const word = text.slice(i, e);
      if (CLASS_ENUM_MODIFIER_WORDS.has(word)) {
        if (pendingMods === null) pendingMods = { start: i, words: [word] };
        else pendingMods.words.push(word);
      } else {
        pendingMods = null; // any other word token ends the modifier run
      }
      i = e;
      continue;
    }
    if (pendingMods !== null && !/\s/.test(c)) pendingMods = null;
    i++;
  }
  if (spans.length === 0) return { text, errors };
  let out = '';
  let cursor = 0;
  const moved: string[] = [];
  for (const s of spans) {
    out += text.slice(cursor, s.start);
    const body = text.slice(s.start, s.end);
    moved.push(body);
    out += body.replace(/[^\n]/g, ' '); // blank in place, keep newlines
    cursor = s.end;
  }
  out += text.slice(cursor);
  return { text: out + '\n' + moved.join('\n') + '\n', errors };
}

/** Extract decorator names (e.g. ["contract"], ["external","view"]) from a node. */
export function decoratorNames(node: ts.Node): string[] {
  if (!ts.canHaveDecorators(node)) return [];
  const decs = ts.getDecorators(node);
  if (!decs) return [];
  const names: string[] = [];
  for (const d of decs) {
    const e = d.expression;
    if (ts.isIdentifier(e)) names.push(e.text);
    else if (ts.isCallExpression(e) && ts.isIdentifier(e.expression)) names.push(e.expression.text);
  }
  return names;
}

/** Decorator names on a constructor. TS reports `ts.canHaveDecorators(ctor) === false`
 *  for a ConstructorDeclaration (decorating a constructor is not legal TS), so the
 *  guarded `decoratorNames` above returns [] and would silently drop a ctor's @payable.
 *  The parser still records the decorators, reachable via ts.getDecorators directly. */
export function ctorDecoratorNames(node: ts.ConstructorDeclaration): string[] {
  const names: string[] = [];
  // ts.getDecorators' type excludes ConstructorDeclaration (decorating a ctor is not legal TS),
  // but the parser still records them and the call works at runtime; cast past the type guard.
  for (const d of ts.getDecorators(node as unknown as ts.HasDecorators) ?? []) {
    const e = d.expression;
    if (ts.isIdentifier(e)) names.push(e.text);
    else if (ts.isCallExpression(e) && ts.isIdentifier(e.expression)) names.push(e.expression.text);
  }
  return names;
}

/** Return the decorator CallExpression for a given decorator name, if it was
 *  written in call form (e.g. @state({ slot: 3 })). */
export function decoratorCall(node: ts.Node, name: string): ts.CallExpression | undefined {
  if (!ts.canHaveDecorators(node)) return undefined;
  for (const d of ts.getDecorators(node) ?? []) {
    const e = d.expression;
    if (ts.isCallExpression(e) && ts.isIdentifier(e.expression) && e.expression.text === name) {
      return e;
    }
  }
  return undefined;
}

/** A base contract reference from a `class C extends A, B(7) { ... }` heritage clause.
 *  Each `extends` type node's `.expression` is either a bare `Identifier` (`A`, no base-ctor
 *  args) or a `CallExpression` (`B(7)`, the heritage call-form carrying base-constructor args).
 *  `node` is the type node, for diagnostic spans. */
export interface HeritageBase {
  name: string;
  args?: ts.Expression[]; // present (possibly empty `B()`) when the call-form was used; undefined for a bare `A`
  node: ts.Node;
}

/** Extract the base contracts of a class from its `extends` clause, in SOURCE order
 *  (`extends A, B` -> [A, B]). TS puts every base in `heritageClauses[0].types` (a single
 *  ExtendsKeyword clause); a TS class cannot have an `implements` clause without `extends`, and
 *  JETH classes never implement, so only the ExtendsKeyword clause is consulted. A base written
 *  in call-form (`B(7)`) yields `args`; a bare base (`A`) yields `args: undefined`. A base whose
 *  expression is neither a plain identifier nor `Ident(...)` is skipped (caller reports it). */
export function heritageBases(cls: ts.ClassDeclaration): HeritageBase[] {
  const out: HeritageBase[] = [];
  for (const clause of cls.heritageClauses ?? []) {
    if (clause.token !== ts.SyntaxKind.ExtendsKeyword) continue;
    for (const t of clause.types) {
      const e = t.expression;
      if (ts.isIdentifier(e)) {
        out.push({ name: e.text, node: t });
      } else if (ts.isCallExpression(e) && ts.isIdentifier(e.expression)) {
        out.push({ name: e.expression.text, args: [...e.arguments], node: t });
      } else {
        // an unsupported base expression (e.g. a qualified name); record nothing, let the caller
        // see a missing base name and report it. Keep a placeholder so counts line up.
        out.push({ name: e.getText(), node: t });
      }
    }
  }
  return out;
}
