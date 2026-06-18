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
            out.push({ abiWord: abiBase + j, storageSlot: slotBase + Math.floor(j / packs.perSlot), storageOffset: (j % packs.perSlot) * packs.size, type: ty.element });
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
  return (
    t.kind === 'uint' ||
    t.kind === 'int' ||
    t.kind === 'bool' ||
    t.kind === 'address' ||
    t.kind === 'bytesN'
  );
}

/** The two dynamic byte-sequence types, which share an identical storage and ABI
 *  layout (Phase 4). */
export function isBytesLike(t: JethType): boolean {
  return t.kind === 'bytes' || t.kind === 'string';
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
