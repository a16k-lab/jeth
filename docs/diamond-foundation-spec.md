# Diamond foundation spec: `@storage('ns')` namespaced storage + bigint base-slot widen

> **Historical (design/build record).** JETH is now native-syntax only: the decorator spellings below are
> the retired legacy surface (`// use @decorators` -> JETH480, structural decorators -> JETH481). `@storage`
> and `@diamond` remain legal. See the
> [native-spelling table](../SUPPORTED.md#legacy-decorator-removal-native-syntax-only). The described
> semantics are unchanged; only the surface syntax was replaced.

This is the FIRST shared-core deliverable for the EIP-2535 diamond work (see docs/proxy-design.md "Phase 3").
It is a self-contained, independently byte-checkable unit: a contract with `@storage('ns')` fields laid out at
an ERC-7201 keccak-derived base slot, byte-identical to a hand-written solc namespaced-storage struct. Everything
else in the diamond build (the selector router, `diamondCut`, the loupe, the three storage models) is layered on
top of this.

## Why this requires a bigint widen
A namespace base slot is `keccak256(...) & ~0xff` - a full 256-bit number that overflows JS `number` (2^53).
Today every storage base slot in the IR is typed `number` and folded with JS-number arithmetic in `lowerPlace`
(src/yul.ts ~3328: `let constSlot: number | null = path.baseSlot; constSlot += step.fieldSlot; ...`). For a
namespaced base this silently truncates. The fix is to widen the **base-slot anchor** fields (NOT the small step
offsets) to `bigint` and do the folding in bigint.

KEY SAFETY FACT: `String(5n) === "5" === String(5)`. For every existing (small) slot the emitted Yul literal is
IDENTICAL, so the widen is byte-identical for the whole existing suite (265 files / 2237 tests MUST stay green).
The only new behavior is huge bases surviving the arithmetic. DO NOT "fix" a TS error by wrapping a base slot in
`Number(...)` - that reintroduces the truncation and is the one thing this change exists to prevent.

## Part A - bigint base-slot widen

Widen these **base-slot anchor** fields in src/ir.ts from `number` to `bigint` (these are the SEED/anchor slot of
a storage access; their value can be a keccak base):
- `stateRead.slot` (ir.ts ~64)
- `mapGet.baseSlot` (~91)
- `dynStateRead.slot` (~96)
- `structValue.baseSlot` (~214)
- `mapStorageValue.baseSlot` (~221)
- `mapDynValue.baseSlot` (~222)
- `AccessPath.baseSlot` (~270)
- Place `stateArray.slot` (~320), `fixedArray.baseSlot` (~322), `mapArray.baseSlot` (~323)
- Place `state.slot` (~352), the place `baseSlot` (~359), `dynState.slot` (~364), `mapDynState.baseSlot` (~365)
- `StateVar.slot` (~516)

KEEP these as `number` (they are always small relative offsets/strides, never a keccak base):
- step `field.fieldSlot`, `field.fieldOffset`; `packedIndex/packedDynIndex.perSlot/size/length`; index
  `strideSlots`; every `offset`. `RawStateVar`/`LayoutResult` internal slot counters in src/layout.ts stay
  `number` (planLayout lays a contract out from 0 sequentially; the namespace BASE is added afterward - see Part B).

Consumers to convert (src/yul.ts):
- `lowerPlace` (~3323): `let constSlot: bigint | null = path.baseSlot;` `let slot = String(path.baseSlot);`.
  Convert each fold to bigint: `constSlot += BigInt(step.fieldSlot)`; for index `const add = BigInt(step.index.value)
  * BigInt(step.strideSlots)` then `constSlot += add`; for packedIndex `const slotAdd = BigInt(k) / BigInt(step.perSlot)`
  (bigint division truncates toward zero, == Math.floor for non-negative, which these always are) and
  `offset = Number(BigInt(k) % BigInt(step.perSlot)) * step.size`; `String(constSlot)` everywhere a slot string is
  emitted. The runtime-`add(...)` branches already take a string and are unchanged. `mstore(0x20, ${cur})` where
  `cur = String(constSlot)` - a bigint stringifies to a decimal Yul literal, accepted by solc.
- `mappingSlot` (~7460-7484): seed the base slot as bigint -> `String(slot)`.
- Every other reader of a widened field that emits it into Yul (search `String(` near these fields and bare
  interpolations `${...slot}`): bigint flows through `String()`/template interpolation identically.

Producers to convert (src/analyzer.ts, src/layout.ts): wherever a base-slot anchor field is CONSTRUCTED from a
planLayout `number` slot, wrap with `BigInt(slot)`. The flat-inheritance layout call (analyzer.ts ~1154) and the
per-contract call (~526) feed `StateVar.slot` - convert at the StateVar construction site so all downstream IR
gets bigint.

tsc MUST be clean. Full suite MUST be byte-identical-green (265 files / 2237). If a test's emitted Yul changed,
the conversion introduced a hex-vs-decimal or fold difference - find and fix it; do not relax the test.

## Part B - `@storage('ns')` namespaced storage

### Surface (user-confirmed)
```typescript
@contract class C {
  @storage('myapp.counter') count: u256;     // base slot = ERC-7201(ns), packed sequentially within the ns
  @storage('myapp.counter') owner: address;  // same ns -> shares the namespaced struct (next slot/packed)
  @storage('other.ns')      flag: bool;      // different ns -> isolated base slot
  @external inc(): void { this.count += 1n; }       // accessed exactly like @state
  @external @view who(): address { return this.owner; }
}
```
- `@storage('ns')` is an alternative to `@state` for a storage field. All fields (across the whole compilation
  unit, any contract/facet) sharing the same `ns` STRING form ONE logical namespaced struct, laid out internally
  from slot 0 by the EXISTING `planLayout` (sequential + packing, src/layout.ts), then every field's slot is
  OFFSET by the namespace base. Fields with different `ns` strings are isolated.
- Access is identical to `@state`: `this.count`, `this.m[k]`, `this.arr[i]`, packing, structs, mappings, dynamic
  arrays - ALL reuse the existing place/lowerPlace machinery, just seeded with the bigint namespace base.
- A field may carry EITHER `@state` OR `@storage('ns')`, never both. Mixing `@state` and `@storage` fields in one
  contract is allowed (they live in disjoint slot spaces: @state at sequential 0.., each ns at its keccak base).

### Namespace base derivation (ERC-7201, EIP-7201 - byte-identity target)
```
base(ns) = keccak256(abi.encode(uint256(keccak256(bytes(ns))) - 1)) & ~bytes32(uint256(0xff))
```
i.e. inner = keccak256(utf8 bytes of ns) as a uint256; minus 1; abi.encode(uint256) = its 32-byte big-endian word;
keccak256 of that 32-byte word; then clear the low byte (`& ~0xff`). Compute this at COMPILE time (reuse the keccak
in src/selectors.ts). This is the documented OpenZeppelin/EIP-7201 formula; the verification mirror uses the
identical formula so raw storage slots match.

### Layout pass
Add a per-namespace layout: collect all `@storage('ns')` fields with the same ns (declaration order, most-base-first
across an inheritance chain just like @state), run the EXISTING planLayout to get sequential slot+offset within the
namespace, then set each field's IR `slot`/`baseSlot` = `base(ns) + relativeSlot` (bigint). Keep these fields OUT of
`rawState` (the @state sequential list) so they never shift or collide with @state slots. A `@storage` field resolves
in `this.<name>` exactly as a @state field does, but its StateVar.slot is the bigint namespaced slot.

### Analyzer plumbing
- Recognize `@storage('<string-literal>')` as a field decorator (parser already surfaces decorator args; mirror how
  `@state`/`@constant`/`@immutable` are detected). Require exactly one string-literal arg (else a clean diagnostic).
- Route `@storage` fields to the namespace layout pass; exclude them from rawState/planLayout's sequential list.
- Gate (clean diagnostics, pick free JETH codes): `@storage` combined with `@state`/`@constant`/`@immutable` on one
  field; a non-string / empty / multi arg; otherwise everything a `@state` field supports, a `@storage` field
  supports (value types, packing, structs, mappings, fixed/dynamic arrays, bytes/string).

## Verification (byte-identical to solc ERC-7201 namespaced storage)
Write test/namespaced-storage.test.ts. For a JETH `@contract` with `@storage('ns')` fields and a solc mirror using
the ERC-7201 formula + `assembly { s.slot := LOC }`, diff RAW STORAGE SLOTS (the load-bearing check - a wrong base
or a truncated fold lands the write in the wrong slot) AND returndata, across: (1) a scalar `u256` at the base;
(2) two packed fields (address+uint96 / multiple small types) sharing the base slot; (3) a `mapping(K=>V)` whose
element slot = keccak(key . base) - confirms the bigint base flows into the keccak; (4) a dynamic `T[]` (length at
base+k, data at keccak(base+k)); (5) a fixed `Arr<T,N>`; (6) a struct field; (7) TWO different namespaces are
disjoint (writes to ns A do not touch ns B); (8) `@state` and `@storage` fields in the same contract are disjoint.
Use the project's compileSolidity {creation, storageLayout} + raw `getStorage` reads (NOT a solc ABI). The huge-base
slots are the whole point: if any fold truncated, slot (3)/(4) keccak inputs differ and the differential fails.
