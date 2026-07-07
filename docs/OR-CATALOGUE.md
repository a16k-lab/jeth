# Over-rejection catalogue

**Status: live-audited at f0e3761; Tier-1 lifts verified at `1b330fb`; Tier-2 lifts verified at
`d42e6de` (2026-07-07).** The f0e3761 audit re-probed all 61 historical candidates (run+decode vs
solc 0.8.35 legacy): 25 stale, 1 false, 32 remaining in 16 families. Tier-1 lifted 12 shapes
(4 families); Tier-2 lifted 10 more groups incl. the mapping-rooted JETH152 family and bonus lifts,
verified CLEAN by a 3-slice adversarial workflow (~404 cases, dual-commit bytecode-equality proof of
zero codegen drift, zero miscompiles / over-acceptances / regressions), catalogued 3 new pre-existing
residuals, and reclassified the memory-struct ctor to deliberate. **Current remaining: 16 shapes in
9 families** (4 shapes / 1 family deliberate, 12 shapes / 8 families liftable). Codes current at
`d42e6de`.

## Deliberate rejects (aliasing-sound, must stay)

One family: shapes where solc holds a LIVE REFERENCE that JETH's flat memory image can only copy -
lifting would trade a clean reject for a mutation-visibility miscompile. Do not lift without a
pointer-preserving lowering proof.

| ID | Shape | Code | Why it must stay |
|----|-------|------|------------------|
| B-7 | `c ? this.produce() : this.sx` (ext-call result vs storage ternary) | JETH074 | Branches live in different location classes; copying either diverges from solc aliasing |
| B-21 | memory-parent `xs[1n].pre` AND memory-struct `s.f` through the POINTER channels (internal-arg / element-write / internal-return / 2-hop) | JETH900 | A flat copy would detach from the live memory parent (R3); the FLAT consumers of the same expressions are lifted (L7b) |
| B-24 | `c ? loc : this.sx` (memory local vs storage), let-bind and for-of | JETH074 (one per occurrence) | Mixed location classes; flatten rejected on aliasing grounds |
| L7(a) | memory-struct ctor with a BOUND fixed-array var `S1(a, 5n)` | JETH465 | solc stores a live reference to `a` in the struct field; JETH's flat inline field can only copy. The fully-inline literal ctor `S1([In..,In..], 5n)` IS accepted and byte-identical |

## Liftable over-rejections (8 families, 12 shapes)

Every row is a CLEAN reject with a verified solc-runs-fine mirror.

| Family | Shape (witnesses) | Code(s) | Workaround |
|--------|-------------------|---------|------------|
| L2 residuals (ternary consumption) | both-literal-branch encode `abi.encode(c ? [In(1n,2n)] : [In(3n,4n)])` (struct + value spellings); ternary-chain LVALUE `(c ? this.A : this.B2)[i].y = v` (the desugar guard correctly refuses writes); bytes-typed member `(c ? a : b).t` on memory structs (value-field spellings are LIFTED) | JETH213 x2; JETH067; JETH074 | Bind a branch to a local first / if-else per branch |
| L6 value-array elem write | `o[0n] = this.psv[0n].vals` storage-sourced `Arr<u256,2>` into a memory nested array (B-20) | JETH429 | Scalar copy per element |
| L9 ref-element array literal | `let m: Arr<u256[],2> = [a, b]` from calldata/memory u256[] params (F2-4) | JETH900 | `new Array` the outer, assign elements |
| L10 funcref non-word returns | `(x: u256) => string` funcref local (F4-1); tuple-return funcref, destructured call (F4-2) | JETH900; JETH014/066/072 | Dispatch via if/else over named internal fns |
| L11 funcref as struct field | funcref + dyn-string fields, positional ctor `Fd(this.inc, "hi")` (F3-2); ternary over funcref-field struct locals (F4-3) | JETH200/074; JETH074 | Store a tag field, dispatch via if/else |
| L13 nested bytes byte write | `p.tags[0n][1n] = 0x21n` into a memory struct's bytes[] element (F6-1). Scope refined: a plain LOCAL bytes byte-write is ACCEPTED; the OR is specific to struct-FIELD bytes elements | JETH055 (drifted from JETH151) | Rebuild the bytes value instead of in-place byte write |
| L14 struct getter as interface impl | `@external @state g: S6` implementing `g(): [u256,u256]` from an @interface (F6-2) | JETH385; +JETH433 with @override | Write an explicit @external method returning the tuple |
| L15 generic @modifier | `@modifier lim<T>(v: T)` (C-12). Feature gap vs JETH's own generic fns; solc has no generic modifiers | JETH327 (+JETH013/JETH329 cascades) | Monomorphize: one modifier per concrete type |

Parity footnotes (both-reject, never ORs): cd|storage ternary mixes (solc TypeError); an OVERSIZE
state-init literal (now JETH065+JETH211; solc TypeErrors too).

## Lifted history

**Tier-2 round at `d42e6de`** (10 groups + bonus, ~404-case CLEAN verification incl. dual-commit
bytecode equality): L12 fixed-array STATE INITIALIZERS (full + short partial-fill, packed u8
mid-layout, bool, i8 sign-extension incl. -128, bytes4 lanes, enum, @storage(ns), inherited base);
the NEW mapping-rooted JETH152 family (whole-struct element read/write on `mapping<K, Arr<In,N>>`,
nested maps, packed, delete, OOB); B-15 s2s assign + push of multi-hop fields (incl. mapping-valued
stacks); L8 field-alias binds (calldata deep-copy + memory alias, mutations visible both ways, bound-
var ctor); B-8 ternary bind (copy locality); B-10 literal-branch ternary encode both orders; B-9/C-7
access chains on ternaries (.length / [i].x / .a value fields, memory + storage, nested ternaries,
side-effect eval-count parity) via the guarded branch-push desugar; BONUS: the cd|cd INDEXED ternary
(per-branch calldata reads validate dirty elements exactly like solc's calldata ref); L7(b) whole
`s.f` through FLAT consumers (return / encode / tuple incl. mutate-mid-tuple frozen-at-position
semantics / indexed topic / error data / 2-hop `s.inner.f` / nested `Arr<Arr<In,2>,2>` fields).

**Tier-1 round at `1b330fb`** (12 shapes): L1 tuple-return producers (call / literal / decode /
ternary / cd element); L3 cross-location binds (cd param, cd leaf `q.pre` + `q.inner`, storage
multi-hop); B-19 s2s mapping-RHS copies; L5 storage struct-field array element ops (read / write /
.length, runtime idx, OOB).

**f0e3761 audit** (25 stale entries): Family-1 aggregate-through-struct-field (6), Family-2 partial,
Family-5 cast-constants, tuple-slot components, and 13 of 15 old SUPPORTED.md gates. Removed as a
false entry: `P(1n, [])` (solc also rejects).

Audit method: differential deploy+call+decode via the scratchpad diff.mjs harness, identical calldata
both sides, distinct non-zero seeds checked arithmetically; OOB/revert branches exercised; log
surfaces compared entry-wise where events are involved; dual-commit (HEAD vs parent) compilation for
class-change and bytecode-drift detection.
