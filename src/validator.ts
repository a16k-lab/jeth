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

/** JETH485: the class-member sibling of the JETH479 stray-token family. A stray keyword in a class
 *  body is error-recovered by TS into shapes the analyzer used to ignore SILENTLY:
 *    (a) `const` / `export` attach as a MODIFIER on the next member (`class C { const get g() ... }`)
 *        with only a grammar-phase error (not a parse diagnostic); neither is legal TS on a class
 *        member. `declare` on a member IS legal TS (ambient), but has no on-chain meaning, mirroring
 *        the JETH479 declare-on-let reject. The file-level `export` modifier (the multi-file import
 *        mechanism) sits on DECLARATIONS, not class members, and stays allowed.
 *    (b) a lone keyword followed by a line break becomes a keyword-named PropertyDeclaration with no
 *        type and no initializer (`const` -> a phantom field named 'const'). A typeless,
 *        initializerless field has no on-chain meaning for ANY name, so reject it loudly; a real
 *        field keeps its type annotation (`constant: u256` is untouched).
 *  Kept OUT of the recursive `visit` (called once per node) so visit's stack frame stays small: a deep
 *  operator chain recurses ~1 visit frame per term, and extra inline locals measurably lowered the
 *  JETH477 usable-depth threshold. */
function checkStrayClassBodyKeywords(node: ts.Node, diags: DiagnosticBag): void {
  if (ts.isClassElement(node) && ts.canHaveModifiers(node)) {
    for (const m of ts.getModifiers(node) ?? []) {
      if (m.kind === ts.SyntaxKind.ConstKeyword || m.kind === ts.SyntaxKind.ExportKeyword) {
        diags.error(
          m,
          'JETH485',
          `'${m.getText()}' is not a valid class-member modifier (a stray token error-recovered by the parser); remove it`,
        );
      } else if (m.kind === ts.SyntaxKind.DeclareKeyword) {
        diags.error(
          m,
          'JETH485',
          "'declare' (a TS ambient declaration) has no on-chain meaning on a class member; remove it",
        );
      }
    }
  }
  if (ts.isPropertyDeclaration(node) && ts.isIdentifier(node.name) && !node.type && !node.initializer) {
    const isKeywordName = ts.identifierToKeywordKind(node.name) !== undefined;
    diags.error(
      node,
      'JETH485',
      isKeywordName
        ? `stray '${node.name.text}' keyword in a class body (error-recovered into a typeless member); remove it`
        : `class member '${node.name.text}' has no type and no initializer, so it has no on-chain meaning; add a type (e.g. '${node.name.text}: u256') or remove it`,
    );
  }
}

/** JETH501: solc's top level admits ONLY declarations (pragma / import / contract / interface / library /
 *  struct / enum / error / event / using / constant / function / type). TypeScript, by contrast, parses a
 *  bare ExpressionStatement, stray identifier, literal, control-flow statement, block, or a non-const
 *  variable at the SOURCE-FILE top level, and the analyzer used to process only the declarations and
 *  SILENTLY IGNORE the junk - a trailing `z`, `z;`, `5n;`, `if (...) {}`, `for(;;){}`, `{}`, a bare `;`,
 *  a top-level `throw this.E({})`, or a file-level `let x = 5n` all compiled - while solc rejects the whole
 *  file ("Expected pragma or contract/interface/library/... but got ..."). That silent acceptance is an
 *  over-acceptance: this pass rejects EVERY top-level statement that is not one of JETH's supported
 *  declaration kinds (class / interface / type alias / enum / file-level const), closing the full axis.
 *
 *  Runs on the DIRECT children of the source file only - a nested ExpressionStatement / if / for / block
 *  inside a method body is ordinary control flow and stays untouched (the recursive `visit` below validates
 *  those). Kinds that the recursive walk already rejects with a MORE SPECIFIC diagnostic (a free
 *  FunctionDeclaration -> JETH024; an import / `import =` / `export {..}` / `export default` statement ->
 *  JETH035) are skipped here so we do not double-report; a non-const file-level VariableStatement (`let` /
 *  `var`, previously silently ignored) is rejected here to match solc's "only constant variables are
 *  allowed at file level". Multi-file safe: the bundler blanks import lines and concatenates every file's
 *  declarations into one unit, so a stray statement in ANY original file surfaces here and remapDiagnostics
 *  attributes it to its source file. */
function checkTopLevelStatements(sourceFile: ts.SourceFile, diags: DiagnosticBag): void {
  for (const s of sourceFile.statements) {
    switch (s.kind) {
      // Supported top-level declarations. (A `type X = { ... }` struct, a `type X = Brand<T>` newtype, and a
      // `type X = error<{...}>` / `event<{...}>` are all TypeAliasDeclaration; a native `interface I {..}`,
      // a `class` contract/library/abstract base, and a `@interface`/`@struct` class are Class/Interface
      // declarations. The `export` modifier used by the multi-file import mechanism sits ON these nodes, so
      // `export class` / `export type` / `export const` stay recognized.)
      case ts.SyntaxKind.ClassDeclaration:
      case ts.SyntaxKind.InterfaceDeclaration:
      case ts.SyntaxKind.TypeAliasDeclaration:
      case ts.SyntaxKind.EnumDeclaration:
        continue;
      // Already rejected by the recursive subset walk with a more specific code - leave them to it so a
      // top-level occurrence is not reported twice.
      case ts.SyntaxKind.FunctionDeclaration: // JETH024 (free functions)
      case ts.SyntaxKind.ImportDeclaration: // JETH035 (single-file; blanked in a multi-file bundle)
      case ts.SyntaxKind.ImportEqualsDeclaration: // JETH035
      case ts.SyntaxKind.ExportDeclaration: // JETH035 (`export { x }` / `export * from ...`)
      case ts.SyntaxKind.ExportAssignment: // JETH035 (`export = x` / `export default ...`)
        continue;
      case ts.SyntaxKind.VariableStatement: {
        const vs = s as ts.VariableStatement;
        // A file-level `const` is the array-length / constant declaration form (collectFileLevelIntConsts);
        // keep it. A non-const `let` / `var` at file level has no on-chain meaning and solc rejects it.
        if ((vs.declarationList.flags & ts.NodeFlags.Const) !== 0) continue;
        const first = vs.declarationList.declarations[0];
        const nm = first && ts.isIdentifier(first.name) ? first.name.text : undefined;
        diags.error(
          s,
          'JETH501',
          nm
            ? `file-level variable '${nm}' must be declared 'const'; only constant variables are allowed at file level`
            : `file-level variables must be declared 'const'; only constant variables are allowed at file level`,
        );
        continue;
      }
      default:
        diags.error(
          s,
          'JETH501',
          'unexpected top-level statement; a source file may contain only declarations (contract / library classes, interfaces, structs, enums, type aliases, file-level constants, and imports), not a statement or expression',
        );
    }
  }
}

export function validateSubset(sourceFile: ts.SourceFile, diags: DiagnosticBag): void {
  // Top-level grammar boundary: reject any non-declaration statement / non-const variable that TS parsed at
  // the source-file top level but the analyzer would silently ignore (JETH501). Kept OUT of the recursive
  // `visit` (that closure runs once per node; this needs the DIRECT children only, and keeping visit's stack
  // frame small preserves the JETH477 usable-depth threshold).
  checkTopLevelStatements(sourceFile, diags);

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

    // JETH478: solc's lexer accepts only ASCII identifiers ([a-zA-Z0-9_$]); TS accepts full Unicode, so a
    // non-ASCII identifier (`café`, `函数`) used to sail through to codegen and ICE as JETH901 ("backend
    // rejected generated Yul: Illegal token"). Rejecting EVERY identifier occurrence (declaration or
    // reference) mirrors solc, which rejects at the lexer before name resolution. STRING content is
    // untouched (a raw unicode string literal is byte-identical); ASCII `$`/`_` stay legal (the reserved
    // `$m<N>$` prefix has its own gate).
    if ((ts.isIdentifier(node) || ts.isPrivateIdentifier(node)) && /[^\x00-\x7F]/.test(node.text)) {
      diags.error(
        node,
        'JETH478',
        `identifier '${node.text}' contains non-ASCII characters; identifiers are ASCII-only (letters, digits, '_', '$'), matching Solidity`,
      );
    }

    // JETH479: TS cannot decorate a VariableStatement (canHaveDecorators=false, getDecorators()=[]), but
    // the parser still stores the `@dec(...)` in node.modifiers with only a GRAMMAR-phase error (TS1206,
    // not a parse diagnostic) - so `@only(this.boom()) let x = 7n;` used to compile SILENTLY, dropping the
    // decorator AND its argument's side effects (a lost state write). `declare` is TS ambient syntax with
    // no on-chain meaning; it was silently treated as a plain `let`. Both reject loudly here (invalid in
    // Solidity too - nothing to mirror). Legal member/class decorators are untouched (different nodes).
    if (ts.isVariableStatement(node)) {
      for (const m of node.modifiers ?? []) {
        if (m.kind === ts.SyntaxKind.Decorator) {
          diags.error(
            m,
            'JETH479',
            'a decorator on a variable declaration statement is not supported (decorators go on class members); remove it',
          );
        } else if (m.kind === ts.SyntaxKind.DeclareKeyword) {
          diags.error(m, 'JETH479', "'declare' (a TS ambient declaration) has no on-chain meaning; remove it");
        }
      }
    }

    // JETH485 stray-keyword residue on class members: logic lives in a helper, NOT inline, so the
    // recursive `visit` frame stays small (a deep operator chain recurses ~1 frame per term; inline
    // locals here measurably lowered the JETH477 depth threshold).
    checkStrayClassBodyKeywords(node, diags);

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
      // Imports were previously SILENTLY IGNORED (parsed, resolved to nothing): the imported name then
      // failed downstream with a misleading unknown-identifier error while the import looked legitimate.
      // JETH compiles a SINGLE file (one compilation unit); reject loudly until a real multi-file import
      // system lands. The `export` MODIFIER on declarations stays allowed (harmless; forward-compatible
      // with export-means-importable once imports exist).
      case ts.SyntaxKind.ImportDeclaration:
      case ts.SyntaxKind.ImportEqualsDeclaration:
        diags.error(node, 'JETH035', 'imports are not supported yet: JETH compiles a single file; declarations must live in this file');
        break;
      case ts.SyntaxKind.ExportDeclaration: // `export { x }` / `export * from "..."` (re-export forms)
      case ts.SyntaxKind.ExportAssignment: // `export = x` / `export default <expr>`
        diags.error(node, 'JETH035', 'export statements are not supported (JETH compiles a single file); the `export` modifier on a declaration is allowed');
        break;
      case ts.SyntaxKind.ThrowStatement: {
        // Native raise sugar: `throw this.X({...})` (a this-property CALL) is the ONE permitted throw
        // shape - the analyzer validates that X is a declared custom error and lowers it to the same
        // revert. Every other throw (a string, `new Error()`, a bare value) stays rejected here.
        const ex = (node as ts.ThrowStatement).expression;
        const isThisCall =
          ts.isCallExpression(ex) &&
          ts.isPropertyAccessExpression(ex.expression) &&
          ex.expression.expression.kind === ts.SyntaxKind.ThisKeyword;
        if (!isThisCall) {
          diags.error(node, 'JETH025', 'throw is not supported; use `throw this.<error>({...})` for a declared custom error, or revert(...) / require(...)');
        }
        break;
      }
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
