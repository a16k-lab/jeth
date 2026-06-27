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

## CRITICAL representation insight (read before writing any decoder)
`abiDecFromMem` (yul.ts ~6329) ALREADY decodes dynamic arrays, BUT for a DYNAMIC element it writes a
RELATIVE OFFSET into the dst image (`mstore(dstHead + i*0x20, sub(cursor, dstHead))`) - i.e. the
STANDARD ABI image (self-describing relative offsets), which is what #3's struct/tuple readers consume.
Residual B's memory-array readers expect a DIFFERENT image: ABSOLUTE POINTERS for a dynamic element
(bytes[]/u256[][]: each element word is an absolute pointer to the inner blob/array, exactly what
`buildNestedMemArrayLit` produces and `abiEncFromMem` READS). So:
- C2 (static-struct P[]): a static struct has NO dynamic elements, so abiDecFromMem's output for a
  dynamic array of a STATIC element is `[len][P0 inline][P1 inline]...` == B1's exact inline-block image.
  Route C2 STRAIGHT through abiDecFromMem into a fresh image and bind it to the P[] memArray local. (Reuse,
  not new codegen.)
- C1 (u256[][]) and C3 (bytes[]/string[]): these have DYNAMIC elements, so abiDecFromMem's relative-offset
  output does NOT match B's absolute-pointer image. Add a NEW decoder `abiDecFromMemToImage(t, src,
  blobEnd, out): ptr` (the decode twin of abiEncFromMem, the inverse of buildNestedMemArrayLit) that
  ALLOCATES and returns a pointer to a B-FORMAT image:
  * value/static leaf or static element: inline (validated), same as abiDecFromMem's static path.
  * dynamic array, dynamic element: alloc `[len]` + an `len`-word pointer table; per element read the ABI
    offset (relative to elemRegion), bounds-check vs blobEnd (EXACT same checks abiDecFromMem does, for
    revert parity), recursively decode the element into a FRESH sub-image, store its ABSOLUTE pointer in
    the table.
  * bytes/string leaf: alloc a `[len][data]` blob, return its absolute pointer.
  Use this for C1/C3; the element-access (B's readers) then mloads absolute pointers correctly.
  IMPORTANT: keep ALL the bounds/cap/payload-fit checks abiDecFromMem already performs so a truncated or
  malformed blob reverts BYTE-IDENTICALLY to solc's memory decode.

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
