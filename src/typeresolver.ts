// Resolve a TypeScript type annotation node into a JethType. JETH's primitive
// type names (u8..u256, i8..i256, address, bool, bytesN, bytes, string) are plain
// identifiers; mapping<K,V> and T[] / T[N] are structural.
import ts from 'typescript';
import type { JethType } from './types.js';
import { numericLiteralWholeValue } from './types.js';
import type { DiagnosticBag } from './diagnostics.js';

/** BigInt(raw) but never throws: returns undefined for a malformed hex spelling. */
function safeBigInt(raw: string): bigint | undefined {
  try {
    return BigInt(raw);
  } catch {
    return undefined;
  }
}

/** The exact original source spelling of a numeric-literal node, or undefined when it cannot be read
 *  faithfully. A node produced by ts.factory (e.g. the analyzer's for-of / switch desugaring) is either
 *  span-less (getText throws / is empty) OR has had an UNRELATED anchor range stitched on via
 *  ts.setTextRange, so getText() returns that anchor's text ("xs", not "2"). To stay robust in both
 *  cases, accept the spelling only when it is itself a well-formed numeric literal; otherwise the caller
 *  falls back to NumericLiteral.text (exact for any value that could have been synthesized). This is used
 *  to read a fixed-array length exactly, since .text is a lossy JS-double for a source value above 2^53. */
function sourceSpelling(node: ts.Node): string | undefined {
  if (node.pos < 0 || node.end < 0) return undefined; // synthesized: no source span
  let text: string;
  try {
    text = node.getText();
  } catch {
    return undefined;
  }
  const raw = text.replace(/_/g, '');
  // a decimal / scientific / hex integer-literal spelling only (nothing else can be a length literal)
  return /^0[xX][0-9a-fA-F]+$/.test(raw) || /^[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(raw)
    ? text
    : undefined;
}

const UINT_RE =
  /^u(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)$/;
const INT_RE =
  /^i(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)$/;
const BYTESN_RE = /^bytes([1-9]|[12][0-9]|3[0-2])$/; // bytes1..bytes32

/** Resolve a primitive identifier type name. Returns undefined if not primitive. */
export function resolvePrimitiveName(name: string): JethType | undefined {
  if (name === 'bool') return { kind: 'bool' };
  if (name === 'address') return { kind: 'address', payable: false };
  if (name === 'bytes') return { kind: 'bytes' };
  if (name === 'string') return { kind: 'string' };
  const u = UINT_RE.exec(name);
  if (u) return { kind: 'uint', bits: Number(u[1]) };
  const i = INT_RE.exec(name);
  if (i) return { kind: 'int', bits: Number(i[1]) };
  const b = BYTESN_RE.exec(name);
  if (b) return { kind: 'bytesN', size: Number(b[1]) };
  return undefined;
}

/** Resolve a TS type node into a JethType, or undefined (with a diagnostic) if
 *  it is not a valid JETH type. `structs` maps @struct names to their resolved type. */
export function resolveType(
  node: ts.TypeNode | undefined,
  diags: DiagnosticBag,
  structs?: Map<string, JethType>,
): JethType | undefined {
  if (!node) {
    return undefined;
  }
  // A parenthesized type `(T)` -> resolve the inner type. Needed for a dynamic array of an internal
  // function pointer written `((x: T) => R)[]`: the `[]` binds tighter than `=>`, so the element must be
  // parenthesized, giving an ArrayTypeNode whose elementType is a ParenthesizedTypeNode wrapping the arrow.
  if (ts.isParenthesizedTypeNode(node)) return resolveType(node.type, diags, structs);

  // void
  if (node.kind === ts.SyntaxKind.VoidKeyword) return { kind: 'void' };
  // `string` is a TS keyword (not a type-reference identifier); map it to the
  // JETH dynamic string type so callers can resolve and then gate it by phase.
  if (node.kind === ts.SyntaxKind.StringKeyword) return { kind: 'string' };

  // An internal function-pointer type `(p1: T1, p2: T2, ...) => R` -> a JETH funcref. Each parameter
  // annotation and the return type must themselves resolve; `=> void` yields a void-returning pointer.
  // This is the surface for Solidity's `function(T1, T2) returns(R)` internal function type. External
  // function types / mutability keywords are out of scope (the arrow syntax cannot express them).
  if (ts.isFunctionTypeNode(node)) {
    const params: JethType[] = [];
    for (const p of node.parameters) {
      // a rest/optional/defaulted parameter, or a missing annotation, is not a valid function-pointer
      // signature (a Solidity `function(T) returns(R)` type carries neither optionality nor a default).
      if (p.dotDotDotToken || p.questionToken || p.initializer || !p.type) {
        diags.error(node, 'JETH014', 'a function-pointer type parameter must have a plain type annotation');
        return undefined;
      }
      const pt = resolveType(p.type, diags, structs);
      if (!pt) return undefined;
      params.push(pt);
    }
    // L10b: a TUPLE return annotation `(a, b) => [T1, T2]` is a MULTI-VALUE-return pointer type
    // (Solidity `function(...) returns (T1, T2)`). A 1-tuple `[T]` normalizes to the single-return
    // form; an empty tuple `[]` has no Solidity spelling (`returns ()` is invalid) and rejects.
    if (ts.isTupleTypeNode(node.type)) {
      const rets: JethType[] = [];
      for (const el of node.type.elements) {
        // a named tuple member `[x: T]` carries its type on .type; a plain member IS the type node.
        const tn = ts.isNamedTupleMember(el) ? el.type : el;
        const rt = resolveType(tn, diags, structs);
        if (!rt) return undefined;
        if (rt.kind === 'void') {
          diags.error(el, 'JETH014', 'void is not a valid tuple-return component in a function-pointer type');
          return undefined;
        }
        rets.push(rt);
      }
      if (rets.length === 0) {
        diags.error(node.type, 'JETH014', 'a function-pointer type cannot return an empty tuple');
        return undefined;
      }
      if (rets.length === 1) return { kind: 'funcref', params, ret: rets[0] };
      return { kind: 'funcref', params, ret: undefined, rets };
    }
    const ret = resolveType(node.type, diags, structs);
    if (!ret) return undefined;
    return { kind: 'funcref', params, ret: ret.kind === 'void' ? undefined : ret };
  }

  // T[] array (fixed-length T[N] is written via a tuple-ish annotation; TS arrays
  // are always dynamic here -> JETH dynamic array).
  if (ts.isArrayTypeNode(node)) {
    const element = resolveType(node.elementType, diags, structs);
    if (!element) return undefined;
    return { kind: 'array', element };
  }

  if (ts.isTypeReferenceNode(node)) {
    const name = ts.isIdentifier(node.typeName) ? node.typeName.text : node.typeName.getText();

    // mapping<K, V>
    if (name === 'mapping') {
      const args = node.typeArguments;
      if (!args || args.length !== 2) {
        diags.error(node, 'JETH010', 'mapping requires exactly two type arguments: mapping<K, V>');
        return undefined;
      }
      const key = resolveType(args[0], diags, structs);
      const value = resolveType(args[1], diags, structs);
      if (!key || !value) return undefined;
      return { kind: 'mapping', key, value };
    }

    // fixed array helper: Arr<T, N> -> T[N]   (TS has no T[N] syntax)
    if (name === 'Arr') {
      const args = node.typeArguments;
      if (!args || args.length !== 2) {
        diags.error(node, 'JETH011', 'fixed array requires Arr<T, N>');
        return undefined;
      }
      const element = resolveType(args[0], diags, structs);
      if (!element) return undefined;
      const lenNode = args[1];
      if (!lenNode || !ts.isLiteralTypeNode(lenNode) || !ts.isNumericLiteral(lenNode.literal)) {
        diags.error(lenNode ?? node, 'JETH012', 'fixed array length must be a numeric literal');
        return undefined;
      }
      // Read the ORIGINAL source spelling (getText), NOT NumericLiteral.text: `.text` is a JS-double
      // normalization that silently rounds a large integer (9007199254740993 -> 9007199254740992), which
      // would mislay every subsequent storage slot. `numericLiteralWholeValue` computes the exact bigint
      // for a decimal / scientific literal; a hex literal (0x..) is exact via BigInt. A SYNTHESIZED literal
      // node (e.g. from for-of element-type desugaring) has no source span, so getText() throws / is empty;
      // fall back to .text there (a synthesized length is always small and exact - no lossy rounding).
      const rawLen = (sourceSpelling(lenNode.literal) ?? lenNode.literal.text).replace(/_/g, '');
      const exactLen = /^0[xX]/.test(rawLen) ? safeBigInt(rawLen) : numericLiteralWholeValue(rawLen);
      if (exactLen === undefined) {
        diags.error(lenNode, 'JETH012', 'fixed array length must be a whole-number integer literal');
        return undefined;
      }
      if (exactLen <= 0n) {
        // solc rejects a zero-length fixed array in every position (it would consume
        // no storage and alias the following slot). Mirror that compile error.
        diags.error(lenNode, 'JETH445', 'fixed array length must be greater than zero');
        return undefined;
      }
      // JethType.array.length is a JS number; a length beyond Number.MAX_SAFE_INTEGER cannot be stored
      // without a lossy double round (which would silently corrupt the storage layout of every following
      // slot). Reject it as a sound fail-safe: such an array (>= 2^53 slots) is physically unusable anyway.
      const length = Number(exactLen);
      if (!Number.isSafeInteger(length) || BigInt(length) !== exactLen) {
        diags.error(
          lenNode,
          'JETH446',
          `fixed array length ${exactLen} is too large (exceeds ${Number.MAX_SAFE_INTEGER}); such an array is not representable`,
        );
        return undefined;
      }
      return { kind: 'array', element, length };
    }

    // Brand<Base> is only meaningful inside a named alias (`type X = Brand<Base>`), where the
    // alias name becomes the nominal tag; an inline Brand<...> has no name.
    if (name === 'Brand') {
      diags.error(node, 'JETH015', 'Brand<...> must be used in a named type alias: `type X = Brand<BaseType>`');
      return undefined;
    }

    const prim = resolvePrimitiveName(name);
    const st = prim ? undefined : structs?.get(name); // @struct / branded-newtype alias, both in `structs`
    const resolved = prim ?? st;
    if (resolved) {
      // A NON-generic type reference (primitive, @struct, enum, branded alias) carries no type parameters;
      // the generic forms (mapping<K,V>, Arr<T,N>, Brand<Base>) were handled above. TS parses a stray
      // `u256<u8>` / `MyStruct<T>` into a type reference with typeArguments; solc has no such syntax and
      // errors on it, so reject rather than silently ignore the extra arguments.
      if (node.typeArguments && node.typeArguments.length > 0) {
        diags.error(node, 'JETH460', `type arguments not allowed on '${name}'`);
        return undefined;
      }
      return resolved;
    }

    diags.error(node, 'JETH013', `unknown JETH type '${name}'`);
    return undefined;
  }

  // Reject `number`, floats, `any`, etc. with a precise message.
  if (node.kind === ts.SyntaxKind.NumberKeyword) {
    diags.error(node, 'JETH001', "the JS 'number' type has no on-chain meaning; use a sized integer (u256, i128, ...)");
    return undefined;
  }
  if (node.kind === ts.SyntaxKind.AnyKeyword) {
    diags.error(node, 'JETH002', "'any' is not allowed in JETH");
    return undefined;
  }

  diags.error(node, 'JETH014', `unsupported type annotation: ${node.getText()}`);
  return undefined;
}
