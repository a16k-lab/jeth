// Resolve a TypeScript type annotation node into a JethType. JETH's primitive
// type names (u8..u256, i8..i256, address, bool, bytesN, bytes, string) are plain
// identifiers; mapping<K,V> and T[] / T[N] are structural.
import ts from 'typescript';
import type { JethType } from './types.js';
import type { DiagnosticBag } from './diagnostics.js';

const UINT_RE = /^u(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)$/;
const INT_RE = /^i(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)$/;
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
  // void
  if (node.kind === ts.SyntaxKind.VoidKeyword) return { kind: 'void' };
  // `string` is a TS keyword (not a type-reference identifier); map it to the
  // JETH dynamic string type so callers can resolve and then gate it by phase.
  if (node.kind === ts.SyntaxKind.StringKeyword) return { kind: 'string' };

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
      const length = Number(lenNode.literal.text);
      if (length <= 0) {
        // solc rejects a zero-length fixed array in every position (it would consume
        // no storage and alias the following slot). Mirror that compile error.
        diags.error(lenNode, 'JETH013', 'fixed array length must be greater than zero');
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
    if (prim) return prim;

    // @struct type reference, or a registered branded newtype alias (both live in `structs`).
    const st = structs?.get(name);
    if (st) return st;

    diags.error(node, 'JETH013', `unknown JETH type '${name}'`);
    return undefined;
  }

  // Reject `number`, floats, `any`, etc. with a precise message.
  if (node.kind === ts.SyntaxKind.NumberKeyword) {
    diags.error(
      node,
      'JETH001',
      "the JS 'number' type has no on-chain meaning; use a sized integer (u256, i128, ...)",
    );
    return undefined;
  }
  if (node.kind === ts.SyntaxKind.AnyKeyword) {
    diags.error(node, 'JETH002', "'any' is not allowed in JETH");
    return undefined;
  }

  diags.error(node, 'JETH014', `unsupported type annotation: ${node.getText()}`);
  return undefined;
}
