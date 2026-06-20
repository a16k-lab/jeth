// Subset validator (directive §4.1, §5.2). Walk the TS AST and reject constructs
// that have no deterministic on-chain meaning, with source-span diagnostics.
//
// Coarse syntactic gate only: it flags whole categories that JETH never supports
// (async, generators, closures over state, eval, exceptions, regex, ...). Finer
// type-level checks (integer widths, BigInt literals, mapping indexing) live in
// the type checker.
import ts from 'typescript';
import type { DiagnosticBag } from './diagnostics.js';

export function validateSubset(sourceFile: ts.SourceFile, diags: DiagnosticBag): void {
  const visit = (node: ts.Node): void => {
    // Solidity reserves `_` (the @modifier placeholder), so it cannot be a DECLARED identifier name
    // anywhere (local, parameter, field, enum member, method, contract/struct, type alias). The
    // placeholder itself is an ExpressionStatement (`_;`), not a declaration, so it is unaffected.
    const declName =
      ts.isVariableDeclaration(node) || ts.isParameter(node) || ts.isPropertyDeclaration(node) ||
      ts.isEnumMember(node) || ts.isMethodDeclaration(node) || ts.isClassDeclaration(node) ||
      ts.isTypeAliasDeclaration(node)
        ? node.name
        : undefined;
    if (declName && ts.isIdentifier(declName) && declName.text === '_') {
      diags.error(declName, 'JETH034', "'_' is a reserved identifier (the @modifier placeholder) and cannot be used as a name");
    }

    switch (node.kind) {
      case ts.SyntaxKind.AwaitExpression:
        diags.error(node, 'JETH020', 'async/await has no on-chain meaning (the EVM is synchronous)');
        break;
      case ts.SyntaxKind.YieldExpression:
        diags.error(node, 'JETH021', 'generators/yield are not supported');
        break;
      case ts.SyntaxKind.NewExpression:
        diags.error(node, 'JETH023', "'new' (object/contract construction) is not supported in the MVP");
        break;
      case ts.SyntaxKind.ArrowFunction:
      case ts.SyntaxKind.FunctionExpression:
      case ts.SyntaxKind.FunctionDeclaration:
        diags.error(node, 'JETH024', 'closures / free functions are not supported; use contract methods');
        break;
      case ts.SyntaxKind.ThrowStatement:
        diags.error(node, 'JETH025', 'throw is not supported; use revert(...) / require(...)');
        break;
      case ts.SyntaxKind.TryStatement:
        diags.error(node, 'JETH026', 'try/catch is not supported in the MVP');
        break;
      case ts.SyntaxKind.RegularExpressionLiteral:
        diags.error(node, 'JETH027', 'regular expressions have no on-chain meaning');
        break;
      case ts.SyntaxKind.SpreadElement:
        // array / call spread ([...a], f(...a)) has no deterministic on-chain meaning.
        // Object spread (`...base` in a struct literal) IS supported; the type checker
        // validates it precisely against the target struct type.
        diags.error(node, 'JETH028', 'array/call spread/rest is not supported');
        break;
      case ts.SyntaxKind.TemplateExpression:
      case ts.SyntaxKind.TaggedTemplateExpression:
        diags.error(node, 'JETH029', 'template literals are not supported in the MVP');
        break;
      case ts.SyntaxKind.TypeOfExpression:
        diags.error(node, 'JETH030', "'typeof' is not supported");
        break;
      // `delete x` (Solidity storage reset) is handled by the analyzer in statement
      // position; the type checker rejects a non-lvalue or unsupported operand.
      case ts.SyntaxKind.AnyKeyword:
        diags.error(node, 'JETH002', "'any' is not allowed in JETH");
        break;
      case ts.SyntaxKind.NumberKeyword:
        diags.error(
          node,
          'JETH001',
          "the JS 'number' type has no on-chain meaning; use a sized integer (u256, i128, ...)",
        );
        break;
    }

    // Generator marker on methods.
    if (
      (ts.isMethodDeclaration(node) || ts.isFunctionDeclaration(node)) &&
      node.asteriskToken
    ) {
      diags.error(node, 'JETH021', 'generators are not supported');
    }

    // async modifier anywhere.
    if (ts.canHaveModifiers(node)) {
      for (const m of ts.getModifiers(node) ?? []) {
        if (m.kind === ts.SyntaxKind.AsyncKeyword) {
          diags.error(m, 'JETH020', 'async has no on-chain meaning (the EVM is synchronous)');
        }
      }
    }

    // `instanceof` / `in` / float numeric literals in expression position.
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (op === ts.SyntaxKind.InstanceOfKeyword) {
        diags.error(node.operatorToken, 'JETH032', "'instanceof' is not supported");
      } else if (op === ts.SyntaxKind.InKeyword) {
        diags.error(node.operatorToken, 'JETH033', "the 'in' operator is not supported");
      }
    }

    // Float literal (contains a '.' or exponent) anywhere.
    if (ts.isNumericLiteral(node) && /[.eE]/.test(node.getText())) {
      diags.error(node, 'JETH003', 'floating-point literals have no on-chain meaning (the EVM has only 256-bit integers)');
    }

    // eval(...) call.
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'eval') {
      diags.error(node, 'JETH022', "'eval' is not supported");
    }

    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sourceFile, visit);
}
