# Arch over-rejection #3: aggregate abi.decode targets (struct / struct-array / bytes[] / string[] / nested)

A SAFE over-rejection (JETH cleanly rejects, solc 0.8.35 accepts; never a miscompile). Close it byte-identical
to solc's abi.decode-from-MEMORY semantics. THIRD of three architectural items; do ONLY this one (after #1).

## What solc accepts that JETH rejects (JETH322 / JETH200)
```typescript
let p: P = abi.decode(b, P);                     // a struct target               (JETH322)
let [n, p]: [u256, P] = abi.decode(b, [u256, P]);// a tuple with a struct member  (JETH322)
let ps: P[] = abi.decode(b, P[]);                // a struct array                (JETH200)
let bs: bytes[] = abi.decode(b, bytes[]);        // dynamic-bytes array           (JETH200)
let ss: string[] = abi.decode(b, string[]);      // string array                  (JETH200)
let m: u256[][] = abi.decode(b, u256[][]);       // nested array                  (JETH200)
```
(`abi.decode` of value types / value-arrays T[] / static Arr<T,N> / tuples of those already WORKS.)

## Why it was "architectural" + the machinery that NOW exists
The historical blocker: JETH's dynamic-field-struct MEMORY image is POINTER-HEADED (each bytes/string/dyn-array
field's head word is an ABSOLUTE memory pointer), NOT the standard ABI-offset image (relative tail offsets). A
naive memory decode (abiDecFromMem) produces the ABI-offset image, which a JETH struct local cannot read.
BUT the constructor-parity work (commit 9f704dc) already added `buildDynStructFromMemBlob` (src/yul.ts ~4553):
it decodes a dynamic-field struct FROM a memory blob INTO the pointer-headed image (value fields inline; each
dynamic field's tail bounds-checked against the blob end, copied to fresh memory, the head set to the absolute
pointer). So the struct case is now tractable - reuse it.

Anchors: src/analyzer.ts `decodeSupported(t)` (the gate, ~686/~701/~6412; currently allows value types, bytes,
string, value-arrays, static Arr<T,N>, tuples-of-those; rejects struct=JETH322 + struct-array/bytes[]/string[]/
nested=JETH200), `resolveAbiDecode`/`resolveAbiDecodeTuple` (~6840-6892). src/yul.ts `abiDecFromMem` (the
value/value-array/tuple memory decoder), `buildDynStructFromMemBlob` (struct-from-memory), the `lowerAbiDecode`
/ abiDecode lowering, the memArray / memDynStruct representations, `arrayDataSlotHelper` is storage-only (not
relevant; this is all memory).

## Fix (build in this order; close what you can byte-identical, document any residual)
1. STRUCT target `abi.decode(b, P)` (static AND dynamic-field P): extend `decodeSupported` to allow a struct
   that `isSupportedDynStructLocal` admits. In the abiDecode lowering, decode the struct from the decode-source
   memory blob: a STATIC struct via abiDecFromMem (its flat image is fine - value fields only); a DYNAMIC-field
   struct via `buildDynStructFromMemBlob` (the pointer-headed image). The decode source is a bytes value
   materialized to memory (the existing abi.decode-from-bytes path), and the struct is at the head offset (a
   single dynamic param: head = offset to the struct; abiDecFromMem/buildDynStructFromMemBlob read from there).
2. TUPLE with a struct member `abi.decode(b, [u256, P])`: extend the tuple decode (resolveAbiDecodeTuple +
   the tuple abiDecode DestructureSource) to allow struct components, decoding each component at its head/tail
   the same way (value -> word; struct -> buildDynStructFromMemBlob / abiDecFromMem at the component's tail).
3. STRUCT ARRAY `abi.decode(b, P[])`: a dynamic array whose elements are structs. Allocate a memDynStruct[]
   (array of struct pointers); for each element decode the struct (buildDynStructFromMemBlob) from its ABI tail
   offset within the array. (Mirror how the array codec walks elements, but materialize each element to a
   struct image.) If this proves too costly, document it as a residual and keep the struct + tuple cases.
4. bytes[] / string[] target: a dynamic array of dynamic bytes/string. Allocate the array; for each element
   decode the bytes/string (the existing bytes/string memory decode) from its tail offset. (JETH already
   supports string[]/bytes[] as STORAGE/element reads; this is the memory-decode-target form.)
5. NESTED value arrays `u256[][]` etc.: depends on the nested memory-array-local codec (architectural item #2);
   if #2 is not yet done, DEFER the nested-array decode target and document it. Do NOT block 1-2 on it.

## Byte-identity (vs solc 0.8.35, MEMORY-decode semantics)
abi.decode of a MEMORY blob uses the MEMORY-decode revert behavior (Panic(0x41) on an oversized length alloc
cap; EMPTY revert on an out-of-range offset) - the EXACT behavior abiDecFromMem / buildDynStructFromMemBlob
already encode (this is WHY reusing them gives parity; do NOT hand-roll a new decode loop). Verify against a
solc mirror that abi-encodes the value then abi.decodes it: a round-trip (encode P -> decode P -> read fields);
a tuple [u256, P]; (if built) a P[] and a bytes[]; plus MALFORMED-blob parity (a truncated / bad-offset blob
-> both revert the same way - Panic 0x41 vs empty revert).

## Constraints + verification
tsc clean; full suite stays green and byte-identical; NEVER edit/relax an existing test except one asserting
EXACTLY a lifted JETH322/JETH200 abi.decode case (flip to acceptance) - and ONLY the abi.decode ones, not the
unrelated JETH200/322 memory-local or modifier reuses. Do NOT change any currently-accepted program's output;
do NOT introduce an acceptance solc rejects (a genuinely-unsupported target must still reject - e.g. a struct
shape isSupportedDynStructLocal excludes). Add test/arch-abi-decode-aggregate.test.ts: encode-then-decode
round-trips vs a solc mirror (returndata + the malformed-blob revert parity). Report which targets you closed
(struct / tuple-with-struct / struct-array / bytes[] / string[] / nested) and which you left as a documented
residual, with the reason. Project rule: graphify FIRST, then read exact lines.
