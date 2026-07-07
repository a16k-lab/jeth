# Over-rejection catalogue

**Status: live-audited at HEAD f0e3761 (2026-07-07).** All 61 catalogued shapes across three
pools (the 2026-07-06 sweep catalogue, the pointer-headed Arr<In,N> campaign catalogue, and
SUPPORTED.md's old gated list) were re-probed differentially (run+decode vs solc 0.8.35 legacy,
non-vacuous seeded values). Result: 25 entries LIFTED (stale), 1 false entry (both compilers
reject), 32 distinct remaining over-rejections in 16 families, ZERO miscompiles, ZERO
over-acceptances. Diagnostic codes below are current at this HEAD; several drifted from the
original catalogue.

## Deliberate rejects (aliasing-sound, must stay)

One family: pointer-headed `Arr<In,N>` shapes where flattening/transcoding was investigated and
rejected because it breaks aliasing with a live parent or branch. These are CORRECT rejects; a
clean reject beats wrong bytes. Do not lift without a pointer-preserving lowering proof.

| ID | Shape | Code | Why it must stay |
|----|-------|------|------------------|
| B-7 | `c ? this.produce() : this.sx` (ext-call result vs storage ternary) | JETH074 | Branches live in different location classes; copying either diverges from solc aliasing |
| B-21 | `xs[1n].pre` (memory-parent element) through internal-arg | JETH900 | Flat copy would detach from the live memory parent (R3) |
| B-24 | `c ? loc : this.sx` (memory local vs storage), let-bind and for-of | JETH074 | Mixed location classes; flatten rejected on aliasing grounds |

## Liftable over-rejections (15 families, 29 shapes)

Every row is a CLEAN reject with a verified solc-runs-fine mirror (success=true, decoded values
checked). Ordered roughly by expected lift leverage.

| Family | Shape (witnesses) | Code(s) | Workaround |
|--------|-------------------|---------|------------|
| L1 tuple-return producer | Direct Arr<In,N> producer in a tuple slot: internal-call result `this.mk2()` (B-1); inline literal `[In(..),In(..)]` (B-2); `abi.decode(b, Arr<In,2>)` (B-3); storage-storage ternary (B-4); nested calldata elem `a[i]` (B-12) | JETH900 | Bind to a memory local first (where the bind is supported), or split into single-value returns |
| L2 ternary-of-aggregates consume | let-bind of storage-storage Arr<In,N> ternary (B-8); `(c?A:B).length` / `[0n].x` (B-9); `abi.encode(c ? lit : this.sx)` (B-10); `(c ? this.s1 : this.s2).a` direct member access on a struct ternary (C-7, narrowed: bind and whole-return of the same ternary are lifted) | JETH200/074, JETH202/074, JETH213, JETH074 | Rewrite as if/else with per-branch statements |
| L3 Arr<In,N> cross-location bind | `let m = a` whole calldata param (B-11); `q.pre` cd-struct field via internal-arg (B-13); `let m = this.ps[0n].pre` storage multi-hop (B-14) | JETH200+074, JETH900, JETH200+074 | Element-wise copy loop into a fresh memory array; direct consumption of B-14's source is lifted |
| L4 Arr<In,N> storage-to-storage copy | `this.tgt = this.ps[0n].pre` and `.push(...)` (B-15); `this.s = this.mp[5n]` where JETH470 over-fires on a legacy-supported s2s copy (B-19) | JETH900; JETH470 | Per-element copy via top-level storage element writes |
| L5 storage struct-field array elem ops | `return this.st.f[1n]` (B-16); `this.st.f[0n] = In(..)` and nested `this.ns[0n][0n] = In(..)` / `this.gx[0n][0n] = In(..)` (B-17, B-23 same shape) ; `this.st.f.length` (B-18) | JETH151, JETH151/152, JETH202 | Restructure state as top-level arrays, or field-wise scalar reads/writes |
| L6 value-array elem write | `o[0n] = this.psv[0n].vals` storage-sourced Arr<u256,2> into a memory nested array (B-20) | JETH429 | Scalar copy per element |
| L7 memory struct ctor/whole-field (HALF-LIFTED) | ctor with bound array var `S1(a, 5n)` (JETH465); whole-field `s.f` return/encode/internal-arg (JETH245). Leaf reads `s.f[1n].x` through a literal-ctor struct are LIFTED (B-22) | JETH465, JETH245 | Literal-ctor the struct; consume leaves, not the whole field |
| L8 memory field-alias bind | `let ys: u256[][] = m.g` then `ys[i][j]` (F2-3) | JETH200, JETH151 | Index directly through `m.g[i][j]` |
| L9 ref-element array literal | `let m: Arr<u256[],2> = [a, b]` from calldata/memory u256[] params (F2-4) | JETH900 | `new Array` the outer, assign elements |
| L10 funcref non-word returns | `(x: u256) => string` funcref local (F4-1); tuple-return funcref, destructured call (F4-2) | JETH900; JETH014/066/072 | Dispatch via if/else over named internal fns |
| L11 funcref as struct field | funcref + dyn-string fields, positional ctor `Fd(this.inc, "hi")` (F3-2); ternary over funcref-field struct locals (F4-3) | JETH200/074; JETH074 | Store a tag field, dispatch via if/else |
| L12 short storage array literal | `@state arr: Arr<u256,3> = [11n, 22n]` partial fill (F3-3) | JETH048 (drifted from JETH226) | Pad the literal to full length: `[11n, 22n, 0n]` |
| L13 nested bytes byte write | `p.tags[0n][1n] = 0x21n` into a memory struct's bytes[] element (F6-1) | JETH151 (drifted from JETH900) | Rebuild the bytes value (concat/slice) instead of in-place byte write |
| L14 struct getter as interface impl | `@external @state g: S6` implementing `g(): [u256,u256]` from an @interface (F6-2) | JETH385; +JETH433 with @override | Write an explicit @external method returning the tuple |
| L15 generic @modifier | `@modifier lim<T>(v: T)`, explicit or inferred instantiation (C-12). Feature gap vs JETH's own generic fns; solc has no generic modifiers | JETH327 (+JETH013/JETH329 cascades) | Monomorphize: one modifier per concrete type |

## Lifted history (stale entries removed by the f0e3761 audit)

25 previously catalogued shapes are now byte-identical to solc (run+decode verified, non-vacuous):

- **Family 1 aggregate-through-struct-field, all 6 shapes** (was JETH230/074/212/173/900):
  dyn-struct-array element field elems, struct-element-array field reads, abi.encode of
  fixed-value-array / nested-static-struct / struct-element-array fields, struct ctor with a
  storage-string field arg. Lifted by the Tier-1 campaign.
- **Family 2 partial**: memory dyn-struct locals with struct-array / u256[] fields incl.
  element assign + default-init reads (was JETH200).
- **Family 5 cast-constant, both shapes**: `bytes4("abcd")` @constant, nested widening
  `bytes4(bytes2(0x1234n))`. Lifted by the Tier-2 campaign.
- **Tuple-return components**: memory nested-array element in a tuple slot (b2ca7ca) and a
  whole static calldata Arr<In,2> param in a tuple slot (was JETH900).
- **SUPPORTED.md old gated list, 13 of 15 entries**: calldata-struct dyn-field elems (JETH230),
  aggregate params/returns through internal calls (JETH242), memory struct locals with dyn
  fields (JETH200/900), whole fixed-array storage element assign (JETH226), storage inner
  dyn-array assign from calldata, packed u8[] in mapping-struct, modifiers with multiple
  placeholders / aggregate params / bare return / post-code on aggregate fns
  (JETH320/322/325/323), string[3][] public nested getter (JETH217), msg.data[i].
- **Removed as a false entry**: `P(1n, [])` empty-array-literal ctor arg; solc 0.8.35 also
  rejects it ("Unable to deduce common type for array elements"). Parity, never an OR.

Audit method: differential deploy+call+decode via the scratchpad diff.mjs harness, identical
calldata both sides, distinct non-zero seeds checked arithmetically, expanded-tuple selectors
used for struct params (vacuous-selector trap avoided), OOB/require branches exercised. 96
probes, ~170 call comparisons, zero miscompiles, zero over-acceptances.
