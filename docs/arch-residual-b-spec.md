# Residual B: aggregate/bytes-leaf MEMORY-array locals (lift JETH200)

Goal: support MEMORY LOCALS whose element is an aggregate or bytes/string, byte-identical to solc
0.8.35. This extends the #2 nested-value-array memory codec (`buildNestedMemArrayLit`,
`buildNestedMemArrayValue`, `abiEncFromMem` in src/yul.ts) from value/static leaves to STRUCT and
BYTES/STRING leaves. It is the foundation that unblocks Residual C (abi.decode into P[]/bytes[]).

## Prime directive (non-negotiable)
BYTE-IDENTICAL to solc 0.8.35 on returndata + revert data, AND matching compile-time accept/reject.
ZERO miscompiles, ZERO over-acceptances. A pure function's observable is the canonical ABI encoding
of the returned array (layout-independent), so the INTERNAL memory layout is free as long as
construction, element/field/length access, return, and abi.encode all produce correct observables.
Use node v22: `export PATH="$HOME/.nvm/versions/node/v22.22.2/bin:$PATH"`. Run a single test file with
`npx vitest run test/<file>`. graphify-first: run `graphify query "<q>"` before grepping/reading source.

## SCOPE (this pass)
- B1: a DYNAMIC array of a STATIC struct: `P[]` (P a struct with only value/static fields).
- B2: a DYNAMIC array of bytes/string: `bytes[]`, `string[]`.
Both as a MEMORY LOCAL: `let xs: P[] = [P(1n,2n), P(3n,4n)];` / `let bs: bytes[] = [bytes("a"), bs2];`.
Support: construction from an array literal; `new Array<P>(n)` / `new Array<bytes>(n)` (zero-init);
element read `xs[i]` (a struct image / a bytes value); field/length on the element (`xs[i].a`,
`bs[i].length`, `bs[i][j]`); `xs.length`; `return xs`; `abi.encode(xs)`; passing `xs` as a call/event/
error/encode argument (reuse the return encoder path).

## DEFER (leave as documented JETH200 residuals - do NOT attempt, keep them rejecting cleanly)
- B3: a DYNAMIC struct element (P with a bytes/string or dynamic-array field): `P[]` where P is dynamic.
- B4: NESTED aggregate-leaf arrays (`P[][]`, `bytes[][]`), and FIXED aggregate arrays (`Arr<P,N>`,
  `Arr<bytes,N>`). Element WRITE (`xs[i] = P(...)`, `bs[i] = ...`) is also deferred (reads only).
Keep test/arch-nested-memory-array.test.ts's struct/bytes-leaf "stay rejected" assertions for the
NESTED shapes (P[][], bytes[][]) passing - those are B4.

## KEY INSIGHT (already-working machinery - do not rebuild)
The #2 codec ALREADY does most of B1:
- `buildNestedMemArrayLit` (yul.ts ~4492), dynamic-outer + `isStaticType(elem)` branch: lays out
  `[len]` then inline element blocks via `writeStaticElemBlock(elem, el, ptr, 1 + k*ew, ...)`.
  `writeStaticElemBlock` (yul.ts) already routes a NON-value static element to
  `writeAggToMem(el, ptr, wordBase)` - i.e. a static STRUCT element's inline image is ALREADY written
  correctly. So a `P[]` (static struct) literal materializes correctly THROUGH THIS PATH once routed.
- `abiEncFromMem` (yul.ts ~6171): its dynamic-array + `isStaticType(t.element)` branch copies
  `abiHeadWords(element)` words per element inline. For a static struct element that IS the struct's
  ABI encoding, so `return xs` / `abi.encode(xs)` for a static-struct P[] ALREADY encodes correctly
  once routed.
- `lowerArrayGet` (yul.ts ~4107) memory branch: for an ARRAY element with `ref.staticElem` it returns
  the INLINE base `add(dataBase, mul(i, ew))`. A static struct element is also inline (ew =
  abiHeadWords(P) words), so `xs[i]` should likewise return the inline base = the struct image pointer.

So B1's gaps are mostly ROUTING + ACCESS, not new codegen:
1. A predicate/route so `P[]` (flat dynamic array, static-struct element) reaches the codec. Today
   `isNestedValueArray` (types.ts) requires `t.element.kind === 'array'` (nesting) AND a value leaf, so
   a FLAT struct array is excluded and the localDecl gate at analyzer.ts ~7286 rejects it (JETH200).
2. localDecl (analyzer.ts ~7286): add a branch BEFORE that JETH200 for a supported aggregate/bytes-leaf
   array: register the name in `memArrayLocals` (dynamic outer), check init is `arrayLit` or `newArray`,
   push the localDecl. Mirror the nested-value branch at ~7203.
3. Element access: `xs[i]` for a STATIC STRUCT element must yield the inline struct-image base, and
   `xs[i].a` must read field `a` from it (a memory field read at a's word offset). Wire `xs[i]` into a
   struct-image base the existing memory-struct field resolver can consume (see resolveMemAggregateField
   / memChainRoot, and lowerArrayGet's static-element inline base). `lowerArrayGet` must treat a static
   STRUCT element like a static ARRAY element (inline base), so set `memStaticElem` for a struct element
   in resolveArrayExpr (analyzer ~9890) and broaden the `ref.elem.kind === 'array'` check in
   lowerArrayGet to also cover a static struct element.
4. `.length` (mload(ptr)) and `return`/`abi.encode` already work once routed.

## B2 (bytes[]/string[]) - the genuinely new codegen
bytes/string is DYNAMIC, so a `bytes[]` element is a POINTER word (like the dynamic-element branch).
- `buildNestedMemArrayValue` (yul.ts): add a case for a bytes/string element -> materialize a
  `[len][data]` blob pointer. Reuse the existing bytes/string materializer (the one behind
  `let s: bytes = X` and `lowerDynamic` - find it via `graphify query "materialize bytes string memory
  blob pointer"`). An array literal element may be a `bytesLit`, a `bytes(...)` cast, a string template,
  another bytes/string memory value, etc - lower each to a blob pointer.
- `abiEncFromMem` (yul.ts ~6171): the leaf branch `if (t.kind !== 'array')` currently copies
  abiHeadWords words inline; that is WRONG for bytes/string. Add: `if (isBytesLike(t)) { ... }` that
  encodes `[len][data padded to 32]` from the blob pointer at memPtr, returning its byte size. This is
  the standard dynamic-bytes ABI tail; mirror the existing bytes/string return encoder.
- Element access `bs[i]`: a bytes value (the blob pointer). `bs[i].length` -> mload(ptr);
  `bs[i][j]` -> byte index into the blob; `return bs[i]` / keccak / concat reuse the bytes codec.
- `new Array<bytes>(n)`: n pointer words, each pointing to a fresh EMPTY `[0]` blob (solc zero-inits
  each element to an empty bytes). Mirror `zeroInitNestedMemArray`.

## Verification (MANDATORY - byte-identical vs solc, not just "compiles")
Write a differential harness like test/arch-residual-a-nested-array-assign.test.ts: a JETH contract and
the equivalent solc contract (`pragma solidity 0.8.35`), deploy both via Harness, call matching
selectors, assert `returnHex` and `success` are equal. Cover, for BOTH P[] and bytes[]/string[]:
- construct a literal, return the whole array (ABI-encode parity);
- read an element field/length and return it (xs[i].a, bs[i].length, bs[i][j]);
- abi.encode(xs) and return the bytes;
- new Array<P>(n)/new Array<bytes>(n) then return (all-zero / all-empty parity);
- an empty array literal `[]` typed P[]/bytes[].
solc mirrors: `P[]` = `P[] memory`, `bytes[]` = `bytes[] memory`. Build solc P[] via
`P[] memory xs = new P[](2); xs[0] = P(1,2); ...` and bytes[] similarly.
Also assert the DEFERRED shapes (P[][], bytes[][], Arr<P,N>, dynamic-struct P[], element WRITE) STILL
throw a JETH diagnostic (clean over-rejection, must not silently miscompile).

Return a concise report: exactly which shapes now compile + are byte-identical, which stay rejected,
the files/functions changed, and any case where you could NOT achieve byte-identical (leave THAT
rejecting rather than ship a miscompile).
