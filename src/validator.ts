// Subset validator (directive §4.1, §5.2). Walk the TS AST and reject constructs
// that have no deterministic on-chain meaning, with source-span diagnostics.
//
// Coarse syntactic gate only: it flags whole categories that JETH never supports
// (async, generators, closures over state, eval, exceptions, regex, ...). Finer
// type-level checks (integer widths, BigInt literals, mapping indexing) live in
// the type checker.
import ts from 'typescript';
import type { DiagnosticBag } from './diagnostics.js';
import { numericLiteralWholeValue } from './types.js';

/** True if `node` (a fractional numeric literal) is a sub-term of a constant ARITHMETIC expression whose
 *  enclosing expression the analyzer folds exactly (`4 * 0.5`, `(1.5 + 0.5)`, `-0.5 + 1`). Walk UP through
 *  parentheses and unary +/-/~ to the nearest meaningful ancestor: a binary +,-,*,/,%,**,<<,>>,&,|,^ makes
 *  it a foldable rational sub-term (the analyzer range-checks only the final value). Any other position
 *  (a variable initializer, call argument, return value, index, comparison, etc.) is a bare fractional
 *  literal that no fold can make whole, so the validator rejects it here (JETH003), matching solc. */
function isConstArithmeticOperand(node: ts.Node): boolean {
  let cur: ts.Node = node;
  let parent = cur.parent;
  while (
    parent &&
    (ts.isParenthesizedExpression(parent) ||
      (ts.isPrefixUnaryExpression(parent) &&
        (parent.operator === ts.SyntaxKind.MinusToken ||
          parent.operator === ts.SyntaxKind.PlusToken ||
          parent.operator === ts.SyntaxKind.TildeToken)))
  ) {
    cur = parent;
    parent = cur.parent;
  }
  if (parent && ts.isBinaryExpression(parent)) {
    switch (parent.operatorToken.kind) {
      case ts.SyntaxKind.PlusToken:
      case ts.SyntaxKind.MinusToken:
      case ts.SyntaxKind.AsteriskToken:
      case ts.SyntaxKind.SlashToken:
      case ts.SyntaxKind.PercentToken:
      case ts.SyntaxKind.AsteriskAsteriskToken:
      case ts.SyntaxKind.LessThanLessThanToken:
      case ts.SyntaxKind.GreaterThanGreaterThanToken:
      case ts.SyntaxKind.AmpersandToken:
      case ts.SyntaxKind.BarToken:
      case ts.SyntaxKind.CaretToken:
        return true;
    }
  }
  return false;
}

export function validateSubset(sourceFile: ts.SourceFile, diags: DiagnosticBag): void {
  const visit = (node: ts.Node): void => {
    // Solidity reserves `_` (the @modifier placeholder), so it cannot be a DECLARED identifier name
    // anywhere (local, parameter, field, enum member, method, contract/struct, type alias). The
    // placeholder itself is an ExpressionStatement (`_;`), not a declaration, so it is unaffected.
    const declName =
      ts.isVariableDeclaration(node) ||
      ts.isParameter(node) ||
      ts.isPropertyDeclaration(node) ||
      ts.isEnumMember(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isClassDeclaration(node) ||
      ts.isTypeAliasDeclaration(node)
        ? node.name
        : undefined;
    if (declName && ts.isIdentifier(declName) && declName.text === '_') {
      diags.error(
        declName,
        'JETH034',
        "'_' is a reserved identifier (the @modifier placeholder) and cannot be used as a name",
      );
    }

    switch (node.kind) {
      case ts.SyntaxKind.AwaitExpression:
        diags.error(node, 'JETH020', 'async/await has no on-chain meaning (the EVM is synchronous)');
        break;
      case ts.SyntaxKind.YieldExpression:
        diags.error(node, 'JETH021', 'generators/yield are not supported');
        break;
      case ts.SyntaxKind.NewExpression: {
        // allow `new Array<T>(n)` (dynamic memory-array allocation); the analyzer validates its
        // exact shape. Every other `new` (object/contract construction) is unsupported.
        const ne = node as ts.NewExpression;
        if (ts.isIdentifier(ne.expression) && ne.expression.text === 'Array') break;
        diags.error(
          node,
          'JETH023',
          "'new' is only supported as 'new Array<T>(n)' (dynamic memory array); object/contract construction is not supported",
        );
        break;
      }
      case ts.SyntaxKind.ArrowFunction:
      case ts.SyntaxKind.FunctionExpression:
      case ts.SyntaxKind.FunctionDeclaration:
        diags.error(node, 'JETH024', 'closures / free functions are not supported; use contract methods');
        break;
      case ts.SyntaxKind.ThrowStatement:
        diags.error(node, 'JETH025', 'throw is not supported; use revert(...) / require(...)');
        break;
      // try/catch is supported around a high-level interface call (Feature 2): the analyzer validates
      // the controlling-call shape, the catch binding, and the scoped this.reason/this.panic helpers.
      // The validator still recurses into both bodies, so any unsupported construct inside them is
      // rejected normally. (A bare `throw` inside is still JETH025.)
      case ts.SyntaxKind.RegularExpressionLiteral:
        diags.error(node, 'JETH027', 'regular expressions have no on-chain meaning');
        break;
      case ts.SyntaxKind.SpreadElement:
        // array / call spread ([...a], f(...a)) has no deterministic on-chain meaning.
        // Object spread (`...base` in a struct literal) IS supported; the type checker
        // validates it precisely against the target struct type.
        diags.error(node, 'JETH028', 'array/call spread/rest is not supported');
        break;
      // a plain TemplateExpression (`Hello ${x}`) IS supported: the analyzer desugars it to a
      // string.concat of the cooked literal parts + the interpolated string expressions (byte-identical
      // to solc string.concat). Fall through to the default child recursion so the `${...}` expressions
      // are still validated. A TAGGED template (tag`...`) has no on-chain meaning and stays rejected.
      case ts.SyntaxKind.TaggedTemplateExpression:
        diags.error(node, 'JETH029', 'tagged template literals are not supported');
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
    if ((ts.isMethodDeclaration(node) || ts.isFunctionDeclaration(node)) && node.asteriskToken) {
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

    // Genuine float literal: a DECIMAL literal with a '.' or e/E exponent whose exact rational is NOT a
    // whole number (1.5, 1e-1, 25e-1, 0.5). A whole-number decimal/scientific literal (1e18, 1.5e18, 10e-1,
    // 1.0) IS a valid integer to solc and is accepted (its value computed exactly downstream). A HEX literal
    // (0x..) is excluded here entirely: e/E are hex DIGITS, not an exponent, and it has no fractional form.
    //
    // A fractional literal that is an OPERAND of a constant arithmetic/paren/unary expression is a solc
    // `rational_const` sub-term whose enclosing expression may fold to a whole number (`4 * 0.5` == 2); the
    // ANALYZER folds those exactly and range-checks only the FINAL value (a non-integer final value ->
    // JETH079). So the coarse validator only rejects a fractional literal in a NON-arithmetic position
    // (`let x: u256 = 0.5`, `f(1.5)`), where no fold can make it whole. This mirrors solc, which accepts a
    // fractional sub-term iff the whole constant expression reduces to an integer of the target type.
    if (
      ts.isNumericLiteral(node) &&
      !/^0[xX]/.test(node.getText()) &&
      /[.eE]/.test(node.getText()) &&
      numericLiteralWholeValue(node.getText()) === undefined &&
      !isConstArithmeticOperand(node)
    ) {
      diags.error(
        node,
        'JETH003',
        'floating-point literals have no on-chain meaning (the EVM has only 256-bit integers)',
      );
    }

    // eval(...) call.
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'eval') {
      diags.error(node, 'JETH022', "'eval' is not supported");
    }

    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sourceFile, visit);
}
