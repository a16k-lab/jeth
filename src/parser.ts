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
  const sourceFile = ts.createSourceFile(
    fileName,
    text,
    ts.ScriptTarget.Latest,
    /*setParentNodes*/ true,
    ts.ScriptKind.TS,
  );
  return { sourceFile, fileName, text };
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
