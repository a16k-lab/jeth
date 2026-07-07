# Over-rejection catalogue

**Status: live-audited at f0e3761; Tier-1 lifts landed + adversarially verified at `1b330fb`
(2026-07-07).** The f0e3761 audit re-probed all 61 historical candidates (run+decode vs solc 0.8.35
legacy): 25 already-lifted stale entries, 1 false entry, 32 remaining in 16 families. The Tier-1
round then lifted 12 shapes across 4 families (verified CLEAN by a 3-slice adversarial workflow,
~153 cases incl. parent-commit class-change comparison: zero miscompiles, zero over-acceptances,
zero regressions) and catalogued 1 new pre-existing family. **Current remaining: 21 shapes in 14
families** (3 shapes / 1 family deliberate, 18 shapes / 13 families liftable). Codes are current at
`1b330fb`.

## Deliberate rejects (aliasing-sound, must stay)

One family: pointer-headed `Arr<In,N>` shapes where flattening/transcoding was investigated and
rejected because it breaks aliasing with a live parent or branch. These are CORRECT rejects; a
clean reject beats wrong bytes. Do not lift without a pointer-preserving lowering proof.

| ID | Shape | Code | Why it must stay |
|----|-------|------|------------------|
| B-7 | `c ? this.produce() : this.sx` (ext-call result vs storage ternary) | JETH074 | Branches live in different location classes; copying either diverges from solc aliasing |
| B-21 | `xs[1n].pre` (memory-parent element) through internal-arg | JETH900 | Flat copy would detach from the live memory parent (R3) |
| B-24 | `c ? loc : this.sx` (memory local vs storage), let-bind and for-of | JETH074 (emitted twice, two spans - cosmetic) | Mixed location classes; flatten rejected on aliasing grounds |

## Liftable over-rejections (13 families, 18 shapes)

Every row is a CLEAN reject with a verified solc-runs-fine mirror. Ordered roughly by expected
lift leverage.

| Family | Shape (witnesses) | Code(s) | Workaround |
|--------|-------------------|---------|------------|
| NEW mapping-rooted fixed-array element | whole-struct element ops on a pure-mapping-rooted `Arr<In,N>`: `this.mf[k][i]` read, `this.mp[k][i] = In(..)` write (incl. nested-map + packed variants). Leaf writes `this.mp[k][i].x = v` and the whole-array copy (B-19) are accepted; dynamic mapping values (`mapping<K, In[]>`) fully work | JETH152 | Leaf-wise reads/writes; or copy the whole value out via B-19 |
| L2 ternary-of-aggregates consume | let-bind of storage-storage `Arr<In,2>` ternary (B-8); `(c?A:B).length` (JETH202) / `(c?A:B)[0n].x` (JETH074) (B-9, per-spelling codes); `abi.encode(c ? lit : this.sx)` (B-10); `(c ? this.s1 : this.s2).a` direct member access on a struct ternary (C-7; bind and whole-return forms are lifted) | JETH200/074, JETH202, JETH074, JETH213 | Rewrite as if/else with per-branch statements |
| L4 remainder: s2s of a multi-hop field | `this.tgt = this.ps[0n].pre` and `this.stk.push(this.ps[0n].pre)` (B-15). The mapping-RHS half (B-19) is lifted | JETH900 | Per-element copy via top-level storage element writes |
| L6 value-array elem write | `o[0n] = this.psv[0n].vals` storage-sourced `Arr<u256,2>` into a memory nested array (B-20) | JETH429 | Scalar copy per element |
| L7 memory struct ctor/whole-field (HALF-LIFTED) | ctor with a bound FIXED-array var `S1(a, 5n)` (JETH465 - fires only for fixed-array ctor args; a `u256[][]`-field ctor from a bound var compiles clean); whole-field `s.f` return/encode/internal-arg (JETH245). Leaf reads through a literal-ctor struct are LIFTED (B-22) | JETH465, JETH245 | Literal-ctor the struct; consume leaves, not the whole field |
| L8 memory field-alias bind | `let ys: u256[][] = m.g` then `ys[i][j]` (F2-3) | JETH200, JETH151 | Index directly through `m.g[i][j]` |
| L9 ref-element array literal | `let m: Arr<u256[],2> = [a, b]` from calldata/memory u256[] params (F2-4) | JETH900 | `new Array` the outer, assign elements |
| L10 funcref non-word returns | `(x: u256) => string` funcref local (F4-1); tuple-return funcref, destructured call (F4-2) | JETH900; JETH014/066/072 | Dispatch via if/else over named internal fns |
| L11 funcref as struct field | funcref + dyn-string fields, positional ctor `Fd(this.inc, "hi")` (F3-2); ternary over funcref-field struct locals (F4-3) | JETH200/074; JETH074 | Store a tag field, dispatch via if/else |
| L12 short storage array literal | `@state arr: Arr<u256,3> = [11n, 22n]` partial fill (F3-3) | JETH048 | Pad the literal to full length: `[11n, 22n, 0n]` |
| L13 nested bytes byte write | `p.tags[0n][1n] = 0x21n` into a memory struct's bytes[] element (F6-1) | JETH151 | Rebuild the bytes value (concat/slice) instead of in-place byte write |
| L14 struct getter as interface impl | `@external @state g: S6` implementing `g(): [u256,u256]` from an @interface (F6-2) | JETH385; +JETH433 with @override | Write an explicit @external method returning the tuple |
| L15 generic @modifier | `@modifier lim<T>(v: T)` (C-12). Feature gap vs JETH's own generic fns; solc has no generic modifiers | JETH327 (+JETH013/JETH329 cascades) | Monomorphize: one modifier per concrete type |

Footnote: the cd|storage ternary mix is BOTH-REJECT (solc TypeErrors it too) - parity, never an OR.

## Lifted history

**Tier-1 round at `1b330fb` (12 catalogued shapes + bonus, all run+decode byte-identical; CLEAN
3-slice adversarial verification incl. dirty-calldata validation parity, evaluation-order probes,
copy/snapshot locality both ways, OOB Panic parity, parent-commit class comparison):**

- **L1 tuple-return producers, entire family** (was JETH900): internal-call result (B-1, incl. a
  dynamic `u256[]` and a dynamic `In[]` producer), inline literal (B-2), `abi.decode` (B-3),
  accepted storage ternary (B-4), fixed-outer calldata element `a[i]` (B-12, a cdPlaceReadAgg
  leaf; dirty-u8 validate-only-what-you-copy parity both directions). Two producers per tuple,
  first/middle/last positions, mixed producer+string, left-to-right evaluation order all verified.
- **L3 cross-location binds, entire family** (was JETH200/074 and JETH900): whole static calldata
  param bind (B-11), `q.pre` static cd-struct leaf through internal-arg + the bind spelling (B-13;
  dirty-u8 revert parity), multi-hop storage bind `let m = this.ps[i].pre` (B-14; snapshot
  semantics vs post-bind storage mutation proven). Bonus from the same gate: `q.inner` (a flat
  static cd-struct STRUCT leaf) through internal-arg, with callee-mutation copy locality.
- **L4 partial: B-19** (JETH470 over-fire): `this.s = this.mp[k]` s2s copy with a mapping RHS -
  fixed-array AND struct values, pre-dirtied destinations fully overwritten, packed slots
  preserved, nested-mapping RHS also accepted and byte-identical.
- **L5 storage struct-field array element ops, entire family** (was JETH151/152/202):
  `this.st.f[i]` whole-element read (literal + runtime index + OOB Panic), whole-element writes in
  all three spellings (`this.st.f[i]=In(..)`, `this.gx[i][j]=In(..)`, `this.ns[0n][0n]=In(..)`),
  `.length` constant fold (incl. for-loop bounds and require conditions, effect-ful bases still
  reject - the fold cannot elide side effects). Bonus: mapping-then-field chains
  (`this.ms[k].f[i]`), `delete this.st.f[0n]` with zeroed read-back parity, RHS-before-index
  evaluation order proven with a shared side-effect counter.

**f0e3761 audit (25 stale entries confirmed lifted earlier):** all of Family-1
aggregate-through-struct-field (6 shapes, Tier-1 campaign), Family-2 partial (memory dyn-struct
locals with struct-array / u256[] fields), Family-5 cast-constants (both, Tier-2), tuple-slot
memory-element + whole-static-cd-param components, and 13 of 15 old SUPPORTED.md gates
(JETH230/242/200/900/226/320/322/325/323/217 forms, packed u8[] in mapping-struct, msg.data[i]).

**Removed as a false entry:** `P(1n, [])` empty-array-literal ctor arg (solc also rejects:
"Unable to deduce common type for array elements").

Audit method: differential deploy+call+decode via the scratchpad diff.mjs harness, identical
calldata both sides, distinct non-zero seeds checked arithmetically on both sides; OOB and revert
branches exercised where applicable.
