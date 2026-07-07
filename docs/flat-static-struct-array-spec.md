# Flat memory representation for `Arr<In,N>` (In a static struct)

## CONCLUSION (2026-07-07): DO NOT FLATTEN - the pointer-headed representation is correct

This flatten was **investigated and rejected**. solc's memory model for `In[N] memory` (a fixed array of a
static struct) is itself **pointer-headed with per-element re-point aliasing**: a memory-to-memory element
assignment `m[i] = m[j]` creates a **reference**, so `m[1] = m[0]; m[0].a = 7` makes `m[1].a` read `7`
(shared), and `abi.encode(m)` after such aliasing reflects the shared payload. A FLAT (inline, value-copy)
representation provably cannot reproduce this - it would return the stale value, a **miscompile**. JETH's
**current pointer-headed** `Arr<In,N>` representation already reproduces solc's memory model byte-for-byte,
**including the aliasing** (verified: `m[1]=m[0]; m[0].a=7; return m[1].a` is `MATCH` = 7 on both). So the
flat flip has **no correctness upside and a definite aliasing-miscompile downside**.

The 7 verbatim-copy consumer miscompiles that motivated this doc were never a sign the *representation* was
wrong - they were individual consumers that flat-copied a pointer-headed image incorrectly; each is fixed
byte-identically by making that consumer **pointer-aware** (the right fix, all landed). The flat-representation
premise below ("flat matches solc byte-for-byte") holds only for the ABI *encoding* (which the pointer-headed
encoder already produces via per-element deref), NOT for the memory mutation/aliasing model. `test/flat-static-
struct-array-stage0-matrix.test.ts` pins the pointer-headed correctness (incl. the `reptTri`/`reptEnc`
re-point rows) so any future flip fails loudly. **Keep pointer-headed.** The design below is retained only as
the record of what was analyzed and why it does not apply.

---

## Motivation

`Arr<In,N>` where `In` is a **static** struct (all static fields) is ABI-static (fixed size) but JETH
currently stores it in memory as **pointer-headed**: N absolute-pointer words, each -> a fresh per-element
struct image. This reuses the machinery Lift #4 built for `Arr<DynStruct,N>` (which must be pointer-headed).
solc lays `Arr<StaticStruct,N>` **flat**: `N*abiHeadWords(In)` contiguous inline words, no pointer table.

The pointer-headed representation caused a recurring miscompile family: any consumer that verbatim-copies
the memory image (mcopy / sstore-loop / `allocAggFromCalldata` flat / the struct-value encoder) treats it as
flat and drops the payload. Seven sites were found and patched incrementally (internal-call arg, tuple
return, mem/cd->storage copy+push, inline struct-ctor return+encode). The **durable** fix is to give
`Arr<StaticStruct,N>` a FLAT memory representation matching solc, so every consumer is correct with no
special-casing. `Arr<DynStruct,N>` stays pointer-headed.

## Target flat layout

A contiguous block of `abiHeadWords(Arr<In,N>) = N*abiHeadWords(In)` words at pointer P. Element k occupies
words `[k*abiHeadWords(In) .. (k+1)*abiHeadWords(In))` inline, each `In` leaf ABI-unpacked (one word/leaf, in
field order) exactly as `structStorageLeaves`/`abiLeaves`/`abiHeadWords` already enumerate. `Arr<Arr<In,N>,M>`
= `M*N*abiHeadWords(In)` contiguous words. A DYNAMIC-outer `In[]` stays `[len]` + `len*abiHeadWords(In)` inline
words. **Invariant:** image bytes == the type's inline ABI-head bytes, so `structStorageLeaves(t).abiWord*32`
indexes directly with no deref. This is byte-for-byte what `allocAggToMem` + `writeAggToMem` already build for
a struct-of-arrays.

## Linchpin

`isPointerHeadedStaticElem` (src/yul.ts:80) is the single fork: it currently returns `isStaticType(e)` for a
struct element and `isStaticStructFixedLeafArray(e)` for a nested fixed sub-array. **Flip both to FALSE for a
static struct / static-struct-leaf array**, so a static-struct element becomes an inline value-word aggregate
(`isInlineValueWordElem` trues), routing it onto the existing inline machinery `Arr<u256,N>` already uses.
Confirm `isValueWordAggregate` (types.ts:352) trues for a static struct (widen if not).

## Coexistence

Selector = `isStaticType(element)` per array level. FLAT: a FIXED-outer array whose element is static
(`Arr<u256,N>` already; `Arr<In,N>`/`Arr<Arr<In,N>,M>` now). POINTER-HEADED (unchanged): any DYNAMIC-outer
`T[]` incl `In[]` ([len] header); a FIXED-outer array with a DYNAMIC element (`Arr<string,N>`,
`Arr<u256[],N>`, `Arr<DynIn,N>`); dynamic-field structs. **Hazard:** a static-struct element of a DYNAMIC-outer
`In[]` stays pointer-headed while the same `In` as a `Arr<In,N>` element goes flat; the dynamic-outer codec
must still deref its outer pointer to reach the (now-flat) per-element image and copy it verbatim - which the
existing deref-then-copy branches already do.

## Staged plan (each stage byte-identical vs solc + full-suite green + tsc clean)

- **Stage 0** - Freeze a ~40-contract differential matrix covering every site (literal/storage/calldata build;
  `m[i]` read/write; `m[i].f`; `return m`; `abi.encode(m)`; `emit E(m)` indexed+data; internal-call arg;
  `S(tag,m)` ctor field from literal AND storage/memory src; `this.g=m` (JETH470); `push`; zero-init; nested
  `Arr<Arr<In,N>,M>`; **regression rows**: DYNAMIC-outer `In[]` and `Arr<DynIn,N>` must stay pointer-headed).
  This is the sacred-bar tripwire for every later stage.
- **Stage 1** - Add a narrow predicate; do not wire it. tsc + suite green (pure addition).
- **Stage 2 (highest-risk, ATOMIC)** - Flip `isPointerHeadedStaticElem` (yul.ts:80) + `memElemStatic`
  (analyzer.ts:15761) to treat a static struct as inline, AND drop the `!isStaticStructFixedLeafArray`
  exclusions in `abiEncFromMem` (9532), `abiDecFromMemToImage` (9881), `abiDecFromCdToImage` (10084),
  `abiDecFromStorageToImage` (10265), `zeroImageFor` (8369), AND route the literal local (yul.ts:1858) +
  `aggArgToMemPtr` arrayLit (8733) to `allocAggToMem`. Build+read+encode+store must flip **atomically** (a
  half-flip is itself a miscompile). Verify the full Stage-0 matrix + In[]/Arr<DynIn,N> UNCHANGED + full suite
  + a fresh adversarial sweep before proceeding.
- **Stage 3** - Route storage/calldata `Arr<In,N>` sources to the flat copy (allocAggFromStorage /
  echoStaticParam / allocAggFromCalldataBase). Verify `let m=this.fa` / `let m=p` rows.
- **Stage 4** - Retire the flatten bridge (`flattenPointerHeadedStaticAgg` 9214, `isPointerHeadedStaticAggArg`
  9199); trim the dead static-struct sub-branches in `abiEncFromMem` (keep nested-pointer only for dyn-leaf).
- **Stage 5** - Dead-code sweep + repoint/retire `isStaticStructFixedLeafArray` (27 callers) for static
  structs. Full suite + fresh 4k-case adversarial sweep across all 12 surfaces.
- **Stage 6** - Lift the now-liftable JETH465 inline-struct-ctor **transient** (return/abi.encode/event-data)
  reject to a byte-identical accept. Keep the **persistent** aliasing throw. Keep **JETH470/JETH467**
  (mem/cd->storage struct-array copy) as rejects (solc legacy rejects them; lifting = over-acceptance).

## Risks (all guarded by the Stage-0 matrix + per-stage suite/sweep)

- R1 coexistence-boundary silent miscompile (dyn-outer In[] wrongly flattened) - fork applied only at
  fixed-outer element level; In[]/Arr<DynIn,N> regression rows.
- R2 `m[i]=struct` becomes an inline value copy (JETH429) - solc also copies; differential mutate-and-read.
- R3 `let p=m[i]` aliasing (flat element = base pointer into parent, writes through) - solc memory ref also
  aliases; differential alias write-through both directions.
- R4 decode revert-ordering (one contiguous bounds check vs per-element table cap) - flat MATCHES solc better;
  truncated/oversized calldata rows.
- R5 must not perturb the already-flat `Arr<u256,N>` family - the dropped exclusions were only ever true for
  struct leaves; no-op for values.

## Recommendation

Execute as a scoped, staged effort starting at Stage 0 (the tripwire matrix) before touching any predicate;
treat Stage 2 as the highest-risk atomic change with a mandatory adversarial sweep before Stage 3. The flat
builder already exists, so this is re-routing + an atomic fork flip, not new codec code; it also closes a
latent `S(tag,m)`-from-storage-src ctor-field miscompile and deletes the `flattenPointerHeadedStaticAgg`
special-case family (net-positive on soundness and simplicity).
