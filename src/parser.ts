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
}

export function parse(text: string, fileName = 'contract.jeth'): ParsedSource {
  // Solidity allows `enum` inside a contract, but TS refuses an enum as a class member
  // (it closes the class empty and silently drops the rest of the body -> empty contract).
  // Hoist any in-class enum to top level before parsing. Offsets are preserved (the enum is
  // blanked in place with equal-length whitespace and appended at the end), so diagnostic
  // spans for the rest of the file are unchanged. No-op when no in-class enum is present.
  const hoisted = hoistInClassEnums(text);
  const sourceFile = ts.createSourceFile(
    fileName,
    hoisted,
    ts.ScriptTarget.Latest,
    /*setParentNodes*/ true,
    ts.ScriptKind.TS,
  );
  return { sourceFile, fileName, text: hoisted };
}

/** Move `enum Name { ... }` declarations that sit inside a class body (brace depth >= 1) out to
 *  top level. A char scanner tracks string/comment state and brace depth; each in-class enum is
 *  blanked where it sat (newlines kept, so offsets/line numbers are stable) and re-appended at the
 *  end of the source, where collectEnums (a position-agnostic recursive walk) registers it. */
function hoistInClassEnums(text: string): string {
  const isWord = (ch: string) => /[A-Za-z0-9_$]/.test(ch);
  const spans: { start: number; end: number }[] = [];
  const n = text.length;
  let depth = 0;
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
    if (c === '{') {
      depth++;
      i++;
      continue;
    }
    if (c === '}') {
      depth--;
      i++;
      continue;
    }
    if (
      depth >= 1 &&
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
        spans.push({ start: i, end: k });
        i = k;
        continue;
      }
    }
    i++;
  }
  if (spans.length === 0) return text;
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
  return out + '\n' + moved.join('\n') + '\n';
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
