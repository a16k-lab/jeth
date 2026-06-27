# Arch over-rejection #2: nested / multi-dim MEMORY-array locals

A SAFE over-rejection (JETH cleanly rejects, solc 0.8.35 accepts; never a miscompile). Close it byte-identical.
SECOND of three architectural items; do ONLY this one (after #1, before #3 - #3's nested-array decode needs it).

## What solc accepts that JETH rejects (JETH200)
```typescript
let m: u256[][] = [[1n,2n],[3n]];                 // dynamic array of dynamic arrays
let f: Arr<Arr<u256,2>,2> = [[1n,2n],[3n,4n]];    // fixed array of fixed arrays
let g: Arr<u256[],2> = [[1n],[2n,3n]];            // fixed array of dynamic arrays
let h: u256[][][] = new Array<u256[][]>(2n);      // new Array of a nested element type
```
(A FLAT value-element memory array `let xs: u256[] = [...]` / `new Array<u256>(n)` already works; only NESTED
element types are gated. STORAGE nested arrays `u256[][]` already work fully.)

## Why it is gated + the machinery to extend
src/yul.ts has the memory-array-local codec (the `memArray` representation + the array-literal lowering +
`new Array<T>(n)` + `materializeArrayArg`) that builds a memory array whose ELEMENTS are VALUE words (one
32-byte word per element). It does NOT recurse when the element type is itself an ARRAY: a nested array's outer
array must hold, per element, an OFFSET/POINTER to the inner array's own memory image (solc's memory layout for
`T[][]`: the outer array is [len][off0][off1]... where each off is the relative offset to an inner [len][data]
block; a fixed `Arr<Arr<T,N>,M>` is M contiguous inner [data] blocks of N words each, no length headers).

Anchors: src/yul.ts the array-literal / memArray materialization, `new Array` lowering, `encodeArrayReturn`
(abi.encode/return of an array - the byte-identity surface), `materializeArrayArg`, `storeStaticAggFromMem`;
src/analyzer.ts the JETH200 gate on a nested memory-array LOCAL (and on a nested array literal / new Array of a
nested element type), and where memArrayLocals are registered.

## Fix
Extend the memory-array-local codec to recurse on the element type:
- DYNAMIC outer `T[]` whose element is an array: lay out [len] then, per element, materialize the inner array to
  its own [len][data] (dynamic inner) or [data] (fixed inner) block and store the element's word as the
  pointer/offset solc uses. An array LITERAL `[[..],[..]]` materializes each inner literal recursively; a
  `new Array<T[]>(n)` zero-inits (each outer element = a pointer to an empty inner array, matching solc's
  active zero-init).
- FIXED outer `Arr<Arr<T,N>,M>`: M contiguous inner blocks (fixed inner = N words each; dynamic inner = a
  pointer per element). Mirror solc's memory layout exactly.
- Element read/write `m[i]` / `m[i][j]`, `.length`, and flowing the nested array into abi.encode / a return /
  a struct field must all work via the recursive codec.
KEEP the analyzer accepting only the element types it can lay out; a still-unsupported nesting stays JETH200.

## Byte-identity (vs solc 0.8.35)
The MEMORY representation is internal, but it becomes OBSERVABLE when the nested array is abi.encode'd, RETURNED
(ABI-encoded as a dynamic array of dynamic/fixed arrays), or hashed (keccak of abi.encode). Verify against a
solc mirror: build the nested array in a memory local, RETURN it (`returns(uint[][] memory)`) and diff the ABI
returndata; also `abi.encode(m)` keccak parity; element reads `m[i][j]`; `.length` of the outer and an inner;
mutate `m[i][j]` then return. Cover u256[][], Arr<Arr<u256,2>,2>, Arr<u256[],2>, and new Array<u256[][]>(n)
zero-init returned.

## Constraints + verification
tsc clean; full suite stays green and byte-identical; NEVER edit/relax an existing test except one asserting
EXACTLY a lifted nested-memory-array JETH200 (flip to acceptance) - only the nested-memory-array-LOCAL ones, not
unrelated JETH200 reuses. Do NOT change any currently-accepted program's output; do NOT introduce an acceptance
solc rejects. Add test/arch-nested-memory-array.test.ts (deploy + diff ABI returndata of the returned nested
array + abi.encode keccak parity + element reads). Report which nestings you closed and any residual with the
reason. Project rule: graphify FIRST, then read exact lines. integer literals need the `n` suffix.
