// The JETH type system. These types ARE the EVM/Solidity types (directive §4.2);
// the surface syntax is TypeScript annotations but the semantics are Solidity's.

// `brand` is a compile-time-only nominal tag (a branded newtype, `type X = Brand<Base>`).
// It is ERASED at codegen / ABI / selectors (which switch on kind/bits/size), so a branded
// value is byte-identical to its base at runtime; it only adds a distinct compile-time identity.
export type JethType =
  // an enum is a BRANDED uint8 carrying its member names (`enumMembers`); the brand gives nominal
  // identity, the uint8 base gives storage/ABI/codegen for free, and the member list drives
  // member-access constants + the `< N` range check on explicit conversion / calldata decode.
  | { kind: 'uint'; bits: number; brand?: string; enumMembers?: string[] } // u8..u256, bits multiple of 8
  | { kind: 'int'; bits: number; brand?: string } // i8..i256
  | { kind: 'bool'; brand?: string }
  | { kind: 'address'; payable: boolean; brand?: string }
  | { kind: 'bytesN'; size: number; brand?: string } // bytes1..bytes32
  | { kind: 'bytes' } // dynamic
  | { kind: 'string' } // dynamic
  | { kind: 'mapping'; key: JethType; value: JethType }
  | { kind: 'array'; element: JethType; length?: number } // T[N] | T[]
  | { kind: 'struct'; name: string; fields: StructField[] } // @struct class
  | { kind: 'void' };

/** A struct field with its resolved storage location relative to the struct base. */
export interface StructField {
  name: string;
  type: JethType;
  slot: number; // slot offset relative to the struct's base slot
  offset: number; // byte offset within that slot (packing)
}

export const U256: JethType = { kind: 'uint', bits: 256 };
export const I256: JethType = { kind: 'int', bits: 256 };
export const BOOL: JethType = { kind: 'bool' };
export const VOID: JethType = { kind: 'void' };

/** Canonical Solidity/ABI type name (directive §2.5): uint256 not uint, etc. */
export function canonicalName(t: JethType): string {
  switch (t.kind) {
    case 'uint':
      return `uint${t.bits}`;
    case 'int':
      return `int${t.bits}`;
    case 'bool':
      return 'bool';
    case 'address':
      return 'address';
    case 'bytesN':
      return `bytes${t.size}`;
    case 'bytes':
      return 'bytes';
    case 'string':
      return 'string';
    case 'array':
      return `${canonicalName(t.element)}[${t.length ?? ''}]`;
    case 'mapping':
      // mappings are not ABI-encodable; this is for diagnostics only.
      return `mapping(${canonicalName(t.key)} => ${canonicalName(t.value)})`;
    case 'struct':
      // ABI tuple form: (t1,t2,...)
      return `(${t.fields.map((f) => canonicalName(f.type)).join(',')})`;
    case 'void':
      return 'void';
  }
}

/** Human-facing JETH name (u256, i8, ...) for diagnostics. */
export function displayName(t: JethType): string {
  const br = (t as { brand?: string }).brand;
  if (br) return br; // a branded newtype shows its name (e.g. TokenId) in diagnostics
  switch (t.kind) {
    case 'uint':
      return `u${t.bits}`;
    case 'int':
      return `i${t.bits}`;
    case 'address':
      return t.payable ? 'address payable' : 'address';
    case 'array':
      return `${displayName(t.element)}[${t.length ?? ''}]`;
    case 'mapping':
      return `mapping<${displayName(t.key)}, ${displayName(t.value)}>`;
    case 'struct':
      return t.name;
    default:
      return canonicalName(t);
  }
}

/** True if the value type is dynamically sized in the ABI head/tail sense. */
export function isDynamicType(t: JethType): boolean {
  switch (t.kind) {
    case 'bytes':
    case 'string':
      return true;
    case 'array':
      return t.length === undefined || isDynamicType(t.element);
    case 'struct':
      return t.fields.some((f) => isDynamicType(f.type));
    default:
      return false;
  }
}

/** Number of contiguous 32-byte storage slots a type occupies inline. */
export function storageSlotCount(t: JethType): number {
  if (t.kind === 'struct') {
    if (t.fields.length === 0) return 1;
    const last = t.fields[t.fields.length - 1]!;
    return last.slot + storageSlotCount(last.type);
  }
  if (t.kind === 'array' && t.length !== undefined) {
    const elemBytes = storageByteSize(t.element);
    if (elemBytes < 32 && t.element.kind !== 'struct' && t.element.kind !== 'array') {
      const perSlot = Math.floor(32 / elemBytes);
      return Math.ceil(t.length / perSlot);
    }
    return t.length * storageSlotCount(t.element); // stride = whole slots/elem
  }
  return 1; // value types, mappings, bytes/string header
}

/** Fully static for ABI head-only encoding (no tail), possibly multi-word. */
export function isStaticType(t: JethType): boolean {
  if (isStaticValueType(t)) return true;
  if (t.kind === 'struct') return t.fields.every((f) => isStaticType(f.type));
  if (t.kind === 'array') return t.length !== undefined && isStaticType(t.element);
  return false;
}

/** Flatten a static type into its ABI head leaf words: each entry gives a leaf's
 *  word offset within the type's head and its value type (used to clean/validate
 *  narrow leaves). The entry count equals abiHeadWords(t). The ABI head is
 *  UNPACKED (one full 32-byte word per leaf), unlike storage packing. */
export function abiLeaves(t: JethType): { wordOffset: number; type: JethType }[] {
  if (t.kind === 'struct') {
    const out: { wordOffset: number; type: JethType }[] = [];
    let w = 0;
    for (const f of t.fields) {
      for (const leaf of abiLeaves(f.type)) out.push({ wordOffset: w + leaf.wordOffset, type: leaf.type });
      w += abiHeadWords(f.type);
    }
    return out;
  }
  if (t.kind === 'array' && t.length !== undefined) {
    const out: { wordOffset: number; type: JethType }[] = [];
    const ew = abiHeadWords(t.element);
    for (let i = 0; i < t.length; i++) {
      for (const leaf of abiLeaves(t.element)) out.push({ wordOffset: i * ew + leaf.wordOffset, type: leaf.type });
    }
    return out;
  }
  return [{ wordOffset: 0, type: t }];
}

/** ABI head word count for a static type (per-field/per-element leaf words). */
export function abiHeadWords(t: JethType): number {
  if (t.kind === 'struct') return t.fields.reduce((n, f) => n + abiHeadWords(f.type), 0);
  if (t.kind === 'array' && t.length !== undefined) return t.length * abiHeadWords(t.element);
  return 1;
}

/** Map each value leaf of a static type to BOTH its ABI head word index (unpacked)
 *  and its STORAGE location (slot + byte offset), all relative to the type's base.
 *  Used to transcode a packed storage aggregate into its unpacked ABI encoding. */
export function structStorageLeaves(
  t: JethType,
): { abiWord: number; storageSlot: number; storageOffset: number; type: JethType }[] {
  const out: { abiWord: number; storageSlot: number; storageOffset: number; type: JethType }[] = [];
  function walk(ty: JethType, abiBase: number, slotBase: number, byteOff: number): void {
    if (ty.kind === 'struct') {
      let aw = abiBase;
      for (const f of ty.fields) {
        walk(f.type, aw, slotBase + f.slot, f.offset);
        aw += abiHeadWords(f.type);
      }
    } else if (ty.kind === 'array' && ty.length !== undefined) {
      const ew = abiHeadWords(ty.element);
      if (ty.element.kind === 'struct' || ty.element.kind === 'array') {
        // a struct OR a NESTED fixed-array element: recurse to flatten its leaves (each
        // element spans storageSlotCount(element) slots / abiHeadWords(element) ABI words).
        const sc = storageSlotCount(ty.element);
        for (let j = 0; j < ty.length; j++) walk(ty.element, abiBase + j * ew, slotBase + j * sc, 0);
      } else {
        const packs = arrayElemPacks(ty.element);
        for (let j = 0; j < ty.length; j++) {
          if (packs.packed) {
            out.push({
              abiWord: abiBase + j,
              storageSlot: slotBase + Math.floor(j / packs.perSlot),
              storageOffset: (j % packs.perSlot) * packs.size,
              type: ty.element,
            });
          } else {
            out.push({ abiWord: abiBase + j, storageSlot: slotBase + j, storageOffset: 0, type: ty.element });
          }
        }
      }
    } else {
      out.push({ abiWord: abiBase, storageSlot: slotBase, storageOffset: byteOff, type: ty });
    }
  }
  walk(t, 0, 0, 0);
  return out;
}

/** Storage byte-width of a value type for packing (directive §2.3). 32 for
 * anything that occupies a full slot or is dynamic/reference. */
export function storageByteSize(t: JethType): number {
  switch (t.kind) {
    case 'uint':
    case 'int':
      return t.bits / 8;
    case 'bool':
      return 1;
    case 'address':
      return 20;
    case 'bytesN':
      return t.size;
    case 'struct':
      return storageSlotCount(t) * 32;
    case 'array':
      return t.length === undefined ? 32 : storageSlotCount(t) * 32;
    default:
      // mappings, dynamic types occupy whole slots.
      return 32;
  }
}

/** Whether two types are exactly equal. */
export function typesEqual(a: JethType, b: JethType): boolean {
  if (a.kind !== b.kind) return false;
  // branded newtypes are NOMINAL: a brand only equals the same brand (and a brand never
  // equals its unbranded base). Non-value kinds have no brand, so this is a no-op for them.
  if ((a as { brand?: string }).brand !== (b as { brand?: string }).brand) return false;
  switch (a.kind) {
    case 'uint':
    case 'int':
      return a.bits === (b as typeof a).bits;
    case 'bytesN':
      return a.size === (b as typeof a).size;
    case 'address':
      return a.payable === (b as typeof a).payable;
    case 'array': {
      const bb = b as typeof a;
      return a.length === bb.length && typesEqual(a.element, bb.element);
    }
    case 'mapping': {
      const bb = b as typeof a;
      return typesEqual(a.key, bb.key) && typesEqual(a.value, bb.value);
    }
    case 'struct':
      // structs are nominal in Solidity: equal iff same name.
      return a.name === (b as typeof a).name;
    default:
      return true;
  }
}

export function isUnsigned(t: JethType): t is { kind: 'uint'; bits: number } {
  return t.kind === 'uint';
}
export function isInteger(t: JethType): boolean {
  return t.kind === 'uint' || t.kind === 'int';
}

/** True iff `t` is an enum: a branded uint8 carrying `enumMembers`. Enums reuse the uint8
 *  base for storage/ABI/codegen, so most paths treat them as integers; this helper marks the
 *  spots where enum semantics diverge (forbidden arithmetic, `< N` range check). */
export function isEnum(t: JethType): boolean {
  return t.kind === 'uint' && (t as { enumMembers?: string[] }).enumMembers !== undefined;
}

/** True iff `from` -> `to` is a Solidity IMPLICIT WIDENING conversion: uintN -> uintM
 *  or intN -> intM with M >= N (same signedness), or bytesN -> bytesM with M >= N. A
 *  canonical narrow value is already a valid wider value (uint: high bits zero; int:
 *  sign-extended; bytesN: left-aligned), so the conversion is a no-op at the word level.
 *  uint<->int mixes and narrowing are excluded (they need an explicit cast). */
export function isImplicitWiden(from: JethType, to: JethType): boolean {
  // a branded newtype never implicitly converts to/from a different brand (or its base):
  // crossing a brand boundary requires an explicit wrap/unwrap cast.
  if ((from as { brand?: string }).brand !== (to as { brand?: string }).brand) return false;
  if (from.kind === 'uint' && to.kind === 'uint') return to.bits >= from.bits;
  if (from.kind === 'int' && to.kind === 'int') return to.bits >= from.bits;
  if (from.kind === 'bytesN' && to.kind === 'bytesN') return to.size >= from.size;
  return false;
}

/** The common type two operands widen to for a binary op, Solidity-identical: the wider
 *  of two same-signedness integers (uintN/uintM -> max, intN/intM -> max) or two bytesN
 *  (-> larger size). undefined when there is no implicit common type (e.g. uint vs int). */
export function commonNumericType(a: JethType, b: JethType): JethType | undefined {
  // operands must share a brand (so the result keeps it); a brand never mixes with its base
  // or a different brand in one operation - unwrap explicitly to combine them.
  if ((a as { brand?: string }).brand !== (b as { brand?: string }).brand) return undefined;
  if (a.kind === 'uint' && b.kind === 'uint') return a.bits >= b.bits ? a : b;
  if (a.kind === 'int' && b.kind === 'int') return a.bits >= b.bits ? a : b;
  if (a.kind === 'bytesN' && b.kind === 'bytesN') return a.size >= b.size ? a : b;
  return undefined;
}

/** Static (fixed-size, head-only) value types: encodable as a single 32-byte word.
 *  Used to gate Phase 2 features (error/event params, calldata decode) to the set
 *  that needs no head/tail ABI machinery. */
export function isStaticValueType(t: JethType): boolean {
  return t.kind === 'uint' || t.kind === 'int' || t.kind === 'bool' || t.kind === 'address' || t.kind === 'bytesN';
}

/** The two dynamic byte-sequence types, which share an identical storage and ABI
 *  layout (Phase 4). */
export function isBytesLike(t: JethType): boolean {
  return t.kind === 'bytes' || t.kind === 'string';
}

/** An array whose ELEMENT is dynamic (a bytes/string, or a dynamic nested array) with a value or
 *  bytes/string leaf: string[], bytes[], u256[][], string[][], Arr<string,N>, Arr<u256[],N>, ... .
 *  These route to the packed-padded indexed-event topic codec (yul encodeArrayTopicBlob), whose
 *  preimage walks the element OFFSET TABLE. The element MUST be dynamic for that walk to be correct -
 *  an array with a STATIC element (uint256[2][], P_static[], Arr<u256,N>[]) is laid out INLINE (no
 *  offset table) and is handled byte-identically by the value-element / static-element path instead;
 *  a fully-static aggregate (Arr<u256,N>) by the static-agg path. A STRUCT leaf is excluded (a
 *  separate, unsupported case). */
export function isDynLeafTopicArray(t: JethType): boolean {
  if (t.kind !== 'array') return false;
  const el = t.element;
  if (isBytesLike(el)) return true; // string[] / bytes[] / Arr<string,N> / Arr<bytes,N>
  // a DYNAMIC struct element (P[] / Arr<P,N> where P has a bytes/string field): topic-encode each
  // element's members packed-padded (yul packTopicStructFromAbi). A STATIC-struct element array
  // (P_static[]) stays on the inline value-element path. The element struct's fields must all be
  // value / bytes-string / static-aggregate (deeper dynamic fields stay a clean reject).
  if (el.kind === 'struct' && isDynamicType(el) && isTopicEncodableDynStruct(el)) return true;
  if (el.kind === 'array' && isDynamicType(el)) {
    // a dynamic nested-array element (u256[][], string[][], Arr<u256[],N>, ...): leaf must be
    // value or bytes/string (no struct leaf).
    let leaf: JethType = el;
    while (leaf.kind === 'array') leaf = leaf.element;
    return isStaticValueType(leaf) || isBytesLike(leaf);
  }
  return false;
}

/** A DYNAMIC struct whose indexed-event TOPIC payload the packed-padded codec can lay out from its
 *  ABI memory layout (packTopicStructFromAbi): each field is a value type (inline word), a static
 *  aggregate (inline leaf words), bytes/string (offset -> content padded), a DYNAMIC array whose leaf is
 *  topic-encodable (Edge C: tags: u256[], names: string[], grid: u256[][]), or a NESTED DYNAMIC struct
 *  that is itself topic-encodable (Edge C: inner: Q). The recursion mirrors packTopicArray /
 *  packTopicStructFromAbi exactly. */
export function isTopicEncodableDynStruct(t: JethType): boolean {
  if (t.kind !== 'struct' || !isDynamicType(t)) return false;
  return t.fields.every(
    (f) =>
      isStaticType(f.type) ||
      isBytesLike(f.type) ||
      (f.type.kind === 'array' && f.type.length === undefined && isTopicEncodableArray(f.type)) ||
      (f.type.kind === 'struct' && isDynamicType(f.type) && isTopicEncodableDynStruct(f.type)),
  );
}

/** An array whose elements the packed-padded indexed-topic codec (packTopicArray) can lay out: a value
 *  element (inline), a static aggregate element (inline), bytes/string (padded), a nested array whose
 *  leaf is itself topic-encodable, or a DYNAMIC struct element that is topic-encodable. Mirrors
 *  packTopicArray's element dispatch. */
export function isTopicEncodableArray(t: JethType): boolean {
  if (t.kind !== 'array') return false;
  const e = t.element;
  if (isStaticType(e)) return true; // value / static struct / static fixed-array element (inline, no offset table)
  if (isBytesLike(e)) return true; // bytes/string element
  if (e.kind === 'array') return isTopicEncodableArray(e); // nested array
  if (e.kind === 'struct' && isDynamicType(e)) return isTopicEncodableDynStruct(e); // dynamic struct element
  return false;
}

/** A MULTI-DIMENSIONAL memory array whose ultimate leaf elements are all VALUE types
 *  (uint/int/bool/address/bytesN/enum): u256[][], Arr<Arr<u256,2>,2>, Arr<u256[],2>,
 *  u256[][][], ... Every nesting level may be dynamic (T[]) or fixed (Arr<T,N>); the
 *  innermost element must be a value type. bytes/string/struct leaves are excluded (the
 *  recursive memory codec only lays out value leaves). Used to gate the nested
 *  memory-array-local feature (a flat value array `u256[]` / `Arr<u256,N>` is NOT
 *  "nested" - it has a value element - so this returns false for it). */
export function isNestedValueArray(t: JethType): boolean {
  if (t.kind !== 'array') return false;
  if (!(t.element.kind === 'array')) return false; // a flat value/static array is not nested
  return isValueLeafArray(t);
}

/** Residual B (this pass) scope: a DYNAMIC array `E[]` whose element `E` is an aggregate or
 *  byte-sequence leaf that the pointer-headed nested-memory codec can lay out, but which
 *  isNestedValueArray excludes (the leaf is not a pure value):
 *   - B1: a STATIC struct element (`P[]`, P all value/static fields): each element is an
 *     inline abiHeadWords(P) block in the image and an inline ABI block in the encoding.
 *   - B2: a bytes/string element (`bytes[]`/`string[]`): each element is one absolute-pointer
 *     word to a `[len][data]` blob.
 *   - B3: a DYNAMIC-field struct element (`P[]`, P with a bytes/string or dynamic value-array
 *     field): each element is one absolute-pointer word to a pointer-headed dyn-struct image
 *     (the same image a single dynamic-field struct memory local uses). Gated to the field set
 *     isDynStructLeaf admits (value / bytes / string / dynamic value-array fields).
 *   - B4: a nested-dynamic-leaf array element (`bytes[][]`/`string[][]`, and deeper): each
 *     element is one absolute-pointer word to its own inner aggregate-leaf / nested-value image.
 *  DEFERRED (kept rejecting): any FIXED outer (`Arr<P,N>`, `Arr<bytes,N>`), and any struct
 *  element with a static-aggregate / nested-struct / non-value-element-array field. */
export function isAggregateLeafArray(t: JethType): boolean {
  if (t.kind !== 'array' || t.length !== undefined) return false; // flat DYNAMIC outer only
  const e = t.element;
  if (e.kind === 'struct') return isStaticType(e) || isDynStructLeaf(e); // B1 static / B3 dynamic struct
  if (isBytesLike(e)) return true; // B2: bytes/string element
  // B4: a nested array element whose ultimate leaf is a DYNAMIC byte-sequence (bytes[][]/string[][],
  // and deeper, e.g. bytes[][][]). The inner array image is itself laid out by the recursive codec.
  // Cat B: a static-struct-leaf nested array (P[][], and deeper) is ALSO admitted now - static structs
  // are pointer-headed, so the inner P[] is a pointer-headed image the recursive codec builds/reads
  // exactly like B4, and pp[i][j].f / abi.encode/decode / aliasing are byte-identical to solc.
  if (e.kind === 'array') return isDynBytesLeafArray(e) || isStaticStructLeafArray(e);
  return false;
}

/** Cat B: a DYNAMIC array whose ultimate leaf (descending through any number of DYNAMIC-array nesting
 *  levels) is a STATIC struct: P[][], P[][][], ... (the inner levels must be dynamic; a fixed level
 *  Arr<P,N>[] stays gated). Each level is pointer-headed, so the recursive memory codec handles it. */
export function isStaticStructLeafArray(t: JethType): boolean {
  if (t.kind !== 'array' || t.length !== undefined) return false;
  if (t.element.kind === 'struct') return isStaticType(t.element);
  if (t.element.kind === 'array') return isStaticStructLeafArray(t.element);
  return false;
}

/** Batch A: a FIXED array (`Arr<P,N>`) whose ultimate leaf is a STATIC struct, reachable through any
 *  mix of further FIXED or DYNAMIC static-struct levels: `Arr<P,N>`, `Arr<P,N>[]`, `Arr<Arr<P,N>,M>`,
 *  `Arr<P,N>[][]`, ... The outermost level MUST be fixed (`t.length !== undefined`); a dynamic outer
 *  is owned by isAggregateLeafArray / isStaticStructLeafArray. Each level is POINTER-HEADED in memory
 *  (a static struct, and a static-struct-leaf array, are reference types: one absolute-pointer word per
 *  element, NO inline length header on the fixed level), so the recursive memory codec lays it out the
 *  same way it does a dynamic static-struct array, minus the [len] word. A FIXED array whose leaf is a
 *  VALUE type (`Arr<u256,N>`, `Arr<u256,N>[]`) is NOT matched here - those stay INLINE and byte-invariant
 *  (owned by the fixed-of-value / nested-value paths). Used ONLY to widen the local-decl / read gates and
 *  the codec's codecSourced checks; do NOT widen isAggregateLeafArray / isStaticStructLeafArray with it. */
export function isStaticStructFixedLeafArray(t: JethType): boolean {
  if (t.kind !== 'array' || t.length === undefined) return false; // FIXED outer only
  const e = t.element;
  if (e.kind === 'struct') return isStaticType(e);
  // descend through a further fixed (Arr<P,N>) or dynamic (P[]) static-struct level.
  if (e.kind === 'array') return isStaticStructAnyLeafArray(e);
  return false;
}

/** Batch A (codec scope): a memory array whose ultimate leaf is a STATIC struct, reachable through ANY
 *  mix of fixed (`Arr<P,N>`) or dynamic (`P[]`) levels at ANY position: `P[]`, `Arr<P,N>`, `Arr<P,N>[]`,
 *  `P[][]`, `Arr<P,N>[][]`, `Arr<Arr<P,N>,M>`, ... Every level is POINTER-HEADED, so the recursive memory
 *  codec (buildNestedMemArrayLit / abiEncFromMem / abiDecFromMem(ToImage)) lays it out uniformly. A VALUE
 *  leaf (`u256[]`, `Arr<u256,N>[]`) is excluded (those stay inline / on the value codec). Used ONLY at the
 *  codec dispatch sites (where the type is already known to be a memory array routed through the codec);
 *  the local-decl / read GATES use the narrower per-shape predicates so the reject set is unchanged. */
export function isStaticStructAnyLeafArray(t: JethType): boolean {
  if (t.kind !== 'array') return false;
  if (t.element.kind === 'struct') return isStaticType(t.element);
  if (t.element.kind === 'array') return isStaticStructAnyLeafArray(t.element);
  return false;
}

/** True if `t` is a DYNAMIC array whose ultimate leaf (descending through any number of dynamic-array
 *  nesting levels) is a bytes/string byte-sequence: bytes[], string[], bytes[][], string[][][], ...
 *  Used to gate B4 (nested-dynamic-leaf arrays). A value leaf, static-struct leaf, or dyn-struct leaf
 *  returns false (those are owned by isNestedValueArray / B1 / B3 respectively). */
export function isDynBytesLeafArray(t: JethType): boolean {
  if (t.kind !== 'array' || t.length !== undefined) return false;
  if (isBytesLike(t.element)) return true;
  if (t.element.kind === 'array') return isDynBytesLeafArray(t.element);
  return false;
}

/** Cat C: a dynamic-field struct FIELD that is a NESTED-DYNAMIC-LEAF array - `bytes[]`, `string[]`,
 *  or a `T[][]` (nested VALUE array bearing a dynamic outer level: u256[][], u256[][][], ...). Its
 *  pointer-headed memory image is the SAME B4 image a standalone such array uses, so the dyn-struct
 *  head word holds an absolute pointer to it and encode/decode/read DELEGATE to the existing B4
 *  machinery (abiEncFromMem / abiDecFromMemToImage / the memArrayExpr element codec). A struct-element
 *  array field (`P[]`) and any FIXED outer (`Arr<bytes,N>`) are EXCLUDED here - those stay gated. */
export function isDynStructLeafArrayField(t: JethType): boolean {
  if (t.kind !== 'array' || t.length !== undefined) return false; // dynamic outer only
  if (isStaticValueType(t.element)) return false; // a flat value array (u256[]) is the 3rd clause, not this
  // bytes[] / string[] / deeper byte-sequence-leaf arrays (bytes[][], string[][][], ...)
  if (isDynBytesLeafArray(t)) return true;
  // T[][] and deeper nested VALUE arrays (the inner levels may be dynamic OR fixed; the leaf is a value).
  return isNestedValueArray(t);
}

/** A struct whose every field is one of the pointer-headed dyn-struct-image leaves the codec
 *  can build (value -> inline head word; bytes/string -> head pointer to [len][data]; dynamic
 *  value-element array -> head pointer to [len][elems]; a NESTED-DYNAMIC-LEAF array (bytes[]/string[]/
 *  T[][]) -> head pointer to the B4 pointer-headed image) AND which has at least one dynamic field (so
 *  it is a genuine dynamic-field struct, not a static struct that B1 owns). Mirrors
 *  Analyzer.isSupportedDynStructLocal (kept here so the array gate can recurse without an
 *  Analyzer instance). Static-array / nested-struct / struct-element-array fields stay gated. */
export function isDynStructLeaf(t: JethType): boolean {
  if (t.kind !== 'struct' || !isDynamicType(t)) return false;
  return t.fields.every(
    (f) =>
      isStaticValueType(f.type) ||
      isBytesLike(f.type) ||
      (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element)) ||
      isDynStructLeafArrayField(f.type) ||
      // B(1) mirror of Analyzer.isSupportedDynStructLocal: a NESTED STATIC AGGREGATE field (nested static
      // struct / static fixed array Arr<T,N>) stored INLINE as flattened head words. Keep byte-parallel.
      (f.type.kind === 'struct' && isStaticType(f.type)) ||
      (f.type.kind === 'array' && f.type.length !== undefined && isStaticType(f.type)),
  );
}

/** storage-to-mem-copy scope: a REFERENCE type (`let row: bytes[] = this.blobs`) whose deep copy
 *  from STORAGE into a fresh pointer-headed memory image is PROVABLY byte-identical to solc - i.e.
 *  every leaf abiDecFromStorageToImage / buildDynStructFromStorage can lay out. Conservatively scoped
 *  so any unhandled shape stays a CLEAN analyzer reject (JETH200) rather than crashing the codegen:
 *   - bytes/string leaf, static value type (inline word) - always OK.
 *   - a STATIC struct (all leaves copied inline from storage).
 *   - a dynamic/fixed array: recurse on the element.
 *   - a DYNAMIC-field struct: every field must itself be storage-copyable AND must NOT be a
 *     nested-dynamic-leaf array field (bytes[]/string[]/T[][]) - the storage dyn-struct copier
 *     (buildDynStructFromStorage) does not yet transcode that field, so it is excluded here. */
export function isStorageCopyableRef(t: JethType): boolean {
  if (isBytesLike(t)) return true;
  if (isStaticValueType(t)) return true;
  if (t.kind === 'array') return isStorageCopyableRef(t.element);
  if (t.kind === 'struct') {
    if (isStaticType(t)) return true; // a static struct copies all leaves inline
    // a dynamic-field struct: gate to the field set buildDynStructFromStorage handles (value / bytes /
    // string / dynamic value-array / nested static aggregate). A nested-dynamic-leaf array field
    // (bytes[]/string[]/T[][]) is NOW transcoded from storage too (commit 19aa9a1:
    // buildDynStructFromStorage builds its pointer-headed B4 image via abiDecFromStorageToImage), so it
    // is admitted. Any other unhandled field (e.g. a nested DYNAMIC-field sub-struct) still excludes the
    // shape -> clean JETH200 reject upstream rather than wrong bytes.
    return t.fields.every(
      (f) =>
        isStaticValueType(f.type) ||
        isBytesLike(f.type) ||
        (f.type.kind === 'array' && f.type.length === undefined && isStaticValueType(f.type.element)) ||
        isDynStructLeafArrayField(f.type) || // bytes[] / string[] / T[][] (the new lift)
        (f.type.kind === 'struct' && isStaticType(f.type)) ||
        (f.type.kind === 'array' && f.type.length !== undefined && isStaticType(f.type)),
    );
  }
  return false;
}

/** A memory array (any mix of dynamic/fixed levels) whose ultimate leaf elements are all
 *  VALUE types. The base of isNestedValueArray's recursion: `u256[]`, `Arr<u256,2>`,
 *  `u256[][]`, `Arr<u256[],2>`, etc. all qualify; anything with a bytes/string/struct
 *  leaf does not. */
export function isValueLeafArray(t: JethType): boolean {
  if (t.kind !== 'array') return false;
  if (isStaticValueType(t.element)) return true;
  return isValueLeafArray(t.element);
}

/** Storage packing of a dynamic-array element. Solidity packs small value types
 *  (bool, uintN<256, intN<256, bytesN<32) several per slot, but NOT address (it
 *  is whole-slot in arrays despite being 20 bytes) nor full-word types. Verified. */
export function arrayElemPacks(t: JethType): { perSlot: number; size: number; packed: boolean } {
  const size = storageByteSize(t);
  const packable =
    t.kind === 'bool' ||
    (t.kind === 'uint' && t.bits < 256) ||
    (t.kind === 'int' && t.bits < 256) ||
    (t.kind === 'bytesN' && t.size < 32);
  return packable ? { perSlot: Math.floor(32 / size), size, packed: true } : { perSlot: 1, size: 32, packed: false };
}

/** Inclusive value range for an integer type. */
export function intRange(t: JethType): { min: bigint; max: bigint } {
  if (t.kind === 'uint') return { min: 0n, max: (1n << BigInt(t.bits)) - 1n };
  if (t.kind === 'int') {
    const half = 1n << BigInt(t.bits - 1);
    return { min: -half, max: half - 1n };
  }
  throw new Error(`intRange on non-integer ${t.kind}`);
}
