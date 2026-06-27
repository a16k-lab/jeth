# Residual C: abi.decode ARRAY targets (lift JETH322/200)

Goal: `abi.decode(b, T)` where T is an ARRAY type, byte-identical to solc 0.8.35's memory-decode
semantics (truncated/malformed blob -> the SAME revert solc raises). Depends on Residual B (the memory
representations for P[]/bytes[]/string[] locals); the nested value-array case reuses the #2 codec.

## Prime directive
BYTE-IDENTICAL to solc 0.8.35 on returndata + revert. ZERO miscompiles, ZERO over-acceptances. The
reuse of the existing decoders (abiDecFromMem / buildDynStructFromMemBlob) is what gives revert parity
on a bad blob - keep decoding THROUGH them. node v22: `export PATH="$HOME/.nvm/versions/node/v22.22.2/bin:$PATH"`.
graphify-first.

## SCOPE
- C1: `abi.decode(b, u256[][])` and other NESTED VALUE arrays (the #2 value-nested image - this does
  NOT need B; it needs the DECODE twin of abiEncFromMem: ABI blob -> pointer-headed nested image).
- C2: `abi.decode(b, P[])` where P is a STATIC struct (decode into B1's inline-block representation;
  for a static struct the ABI layout already IS the inline image, so it is close to a verbatim copy +
  a payload-fit bound check).
- C3: `abi.decode(b, bytes[])` / `abi.decode(b, string[])` (decode into B2's pointer-array-of-blobs).
Also the in-call/in-object forms reuse the same abiDecode IR (decode:T and a tuple member), so a
tuple `[u256, P[]]` works for free once the component decoder exists.

## DEFER (clean rejections)
Dynamic-struct array `P[]` (P dynamic) decode; nested aggregate `P[][]`/`bytes[][]` decode. Keep them
rejecting (decodeSupported returns false -> JETH322/200) until B3/B4 exist.

## Existing machinery (commit f44e3f6, arch #3)
- `decodeSupported` (analyzer.ts ~10579): the gate. Today admits value/static + a supported struct.
  Extend to admit the C1-C3 array types (and ONLY those; reuse the same predicates B uses).
- `lowerAbiDecode` (yul.ts ~6329): its dynamic-component branch routes a struct through
  `buildDynStructFromMemBlob` and a value/array through `abiDecFromMem` at a pointer. Add routing for
  the array targets: a nested value array -> the new nested decoder; a static-struct array -> the
  struct-array decoder; a bytes/string array -> the bytes-array decoder. All must validate the blob
  against `blobEnd` (the same payload-fit checks abiDecFromMem already does) so a truncated blob reverts
  exactly like solc's memory decode.
- The dyn-struct localDecl `okInit` set (analyzer.ts ~7063) and `buildDynStructLocal` (yul.ts ~4628)
  show how #3 accepted an `abiDecode` initializer for an aggregate memory local. The B memArray locals
  must likewise accept an `abiDecode` init (extend B's localDecl branch to allow `e.kind === 'abiDecode'`
  with a type-matched target, and lower it through lowerAbiDecode like #3 did for the struct case).

## Decoders to add (mirror abiEncFromMem's structure, but ABI blob -> memory image)
- C1 nested value array: read `[len]`, validate the offset table + inner tails fit within blobEnd,
  decode each inner via recursion, producing the #2 pointer-headed image (`[len][ptr0]...`). This is the
  inverse of abiEncFromMem's dynamic-array branch. The existing `abiDecFromMem` already decodes a FLAT
  value array; extend it (or add a sibling) so a nested element produces the inner image pointer.
- C2 static-struct array: read `[len]`; for each element copy abiHeadWords(P) words (validating fit)
  into the inline block - identical layout to B1's materializer output. (A static struct has no inner
  offsets, so this is a bounded copy.)
- C3 bytes/string array: read `[len]` + the per-element offset table; for each element decode the
  `[len][data]` tail into a blob pointer (reuse the bytes/string memory decoder used by
  abi.decode(b, bytes)), storing the pointer in B2's pointer array.

## Verification (MANDATORY)
Mirror test/arch-abi-decode-aggregate.test.ts. For each of u256[][], P[] (static), bytes[], string[]:
- encode a known value with solc's abi.encode (or hand-build the ABI blob), decode in BOTH JETH and
  solc, return a derived value (e.g. m[0][0], ps[0].a, bs[0].length), assert returnHex + success equal;
- a TRUNCATED/malformed blob must revert in BOTH (same success=false). Build the calldata wrapper the
  same way arch-abi-decode-aggregate.test.ts does (W(0x20) + W(len) + blob).
- Assert the DEFERRED targets (dynamic-struct P[], P[][], bytes[][]) STILL produce a JETH diagnostic.
Update test/arch-abi-decode-aggregate.test.ts: its "still rejects the residual array decode targets"
block currently asserts P[]/bytes[]/u256[][] all reject - flip the now-supported ones to a byte-identical
acceptance check, keep the genuinely-deferred ones rejecting.

Report exactly which decode targets now work byte-identical, which stay rejected, and any you could not
make byte-identical (leave THOSE rejecting).
