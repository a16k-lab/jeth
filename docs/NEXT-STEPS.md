# NEXT STEPS (quick reference)

## Status: the pointer-headed coverage campaign is COMPLETE (2026-07-07)

The handoff below was executed to convergence. **FULLY-COVERED-CLEAN at HEAD `1a3c4c3`**
(suite 396 files / 3612 tests green, `tsc` clean, all pushed). Full history in
[`docs/HANDOFF-pointer-headed-coverage.md`](./HANDOFF-pointer-headed-coverage.md) (now historical).

What was proven, at HEAD `1a3c4c3` vs solc 0.8.35 legacy: the pointer-headed `Arr<In,N>` family
(fixed arrays of static structs - ABI-static, pointer-headed in memory) is fully covered. Every
analyzer-accepted (expression-kind x consumer-channel) cross - kinds re-derived exhaustively from
`src/ir.ts`, channels from every consumption site in `src/yul.ts` - either routes through the
pointer-headed transcode byte-identically or terminates in a loud clean diagnostic. The four
pointer-headedness mirror lists (analyzer ternary gate, `isPointerHeadedStaticAggArg`,
`memFixedSrc`, `aggArgToMemPtr`) are drift-free, structurally and behaviorally.

### The five fix rounds (each committed + suite-green + pushed individually)

| Round | Finding | Fix | Commit |
|-------|---------|-----|--------|
| Step 1 | tuple-return of a fixed-array ELEMENT `m[i]: Arr<In,N>` offset-encoded as dynamic | inline via `abiEncFromMem` (mirror of `e33d131`); also fixed value-array elements | `b2ca7ca` |
| R1 | indexed-event TOPIC of an abiDecode-sourced `Arr<In,N>` keccak'd pointer words | `abiDecode` added to `isPointerHeadedStaticAggArg` | `2589e16` |
| R2 | the TERNARY channel: abiDecode branches (5 MC witnesses), flat internal-arg (2), cd\|storage location mix over-accepted family-wide | analyzer gate + `aggArgToMemPtr` ternary transcode + a general data-location gate | `5576656` |
| R3 | memory-parent `aggFieldRead` (`xs[i].pre`) through internal-arg / internal-return / element-write (4 witnesses) | REJECT (solc live-references; a copy loses mutations) | `034bd6f` |
| R4 | storage MULTI-HOP `placeRead`-of-array (`this.ps[i].pre` / `this.pa[i].pre` / `this.w.p.pre`) through the same channels (7 witnesses) + the memory-parent ternary aliasing edge | LIFT via `abiDecFromStorageToImage` (solc copies storage->memory, so the transcode is exact) + ternary gate | `1a3c4c3` |

Fix philosophy that crystallized: **memory parents -> reject** (solc passes live references; a
copy cannot preserve aliasing), **storage/calldata parents -> lift** (solc copies; the
pointer-headed transcode is semantics-preserving).

### Final certificate (Round 5, zero findings)

106-case storage-parent residual hunt (mapping / mapping-of-array / 3-hop nested / dyn-in-dyn /
post-delete / post-pop roots x 4 pointer-headed channels + 5 flat consumers + In3/N=3/In2 shape
variants) + 80-case full kind-x-channel enumeration and 4-way mirror audit. Zero miscompiles,
zero over-acceptances, nothing reachable falls through, exact-value non-vacuity anchors and
entry-wise log comparison throughout.

### Residual surface (all SAFE catalogued over-rejections, never wrong bytes)

- memory-parent `aggFieldRead` through pointer channels (the deliberate R3 aliasing reject).
- bound-memory-local / aggFieldRead ternary branches (JETH074, aliasing).
- `let m: Arr<In,2> = this.ps[i].pre` local bind (JETH200; direct consumption works, so no workaround needed).
- cdPlaceReadAgg `q.pre` + calldata element binds through pointer channels (JETH900/200; flat consumers match).
- storage->storage assign/push of a multi-hop field (JETH900, JETH470-family sibling).
- ternary as a tuple-return component (JETH900); `o[i] = this.psv[i].vals` value-array element write (JETH429, liftable later).

## What's next (nothing pending from this campaign)

- Optional lifts from the residual list above (each is a documented safe reject today).
- The broader roadmap: remaining language over-rejection long tail (SUPPORTED.md), tooling
  (CLI polish, source maps, ABI tuple JSON shape), and the AI-layer milestone
  (proposer + verifier loop over the byte-identical oracle).
