# Over-rejection catalogue

**Status: live-audited at f0e3761; Tier-1 verified at `1b330fb`; Tier-2 at `d42e6de`; Tier-3 at
`cef1148` + the soundness fix `8174afc`; long-tail batch A (M-BYTES + T-LVALUE, 6 shapes) lifted
on top of `fbd357a` (2026-07-08).** The Tier-3 round lifted the final 12 shapes
of the f0e3761 list (L9, three L2 residuals, L10a/b, L11a/b, L13, L14, L15; L6 reclassified
deliberate) and was verified by a 4-slice adversarial workflow (381 cases: lift-consumer matrix,
funcref ABI-leak + semantic hunt, dual-commit drift vs the pre-Tier-3 parent, catalogue re-probe;
every claimed violation adversarially re-verified). The workflow caught ONE real regression, fixed
at `8174afc`: funcref-bearing structs leaked through the @event (both arms) and @error parameter
gates (the gates delegated to isSupportedStructReturn, which L11a widened); a dedicated
typeHasFuncref screen (JETH229) now fires at both gates, and the other 34 probed ABI boundaries
were already rejecting. Dual-commit drift check: CLEAN (44 identical-source comparisons, zero
class or bytecode drift on unchanged paths).

Two audit corrections from the same round:
- The old deliberate rows **B-7 and B-24 were wrong when written** (an f0e3761 reconstruction
  error, proven by compile bisect back to 2589e16): the struct-typed, u256[] and dyn-struct
  spellings of `c ? <mem> : <storage>` COMPILE and are byte-identical to solc INCLUDING aliasing,
  snapshot and single-evaluation witnesses. Their true residual scope is the fixed STRUCT-array
  spelling only (see deliberate table).
- Tier-3 also widened DYN-outer ref-element array literals (`let m: u256[][] = [a, b]`), verified
  byte-identical against solc's equivalent new+assign mirror (cd deep-copy, storage deep-copy,
  memory alias witnesses); its cd+storage element mix is a NEW over-rejection (solc's dyn-outer
  equivalent runs, unlike the fixed-outer mix which is a parity both-reject).

**Current remaining: ~22 shapes** = 9 deliberate (6 rows) + 13 liftable (5 families). Codes
current at the long-tail batch A commit. Batch A lifted all 6 M-BYTES/T-LVALUE shapes AND fixed
three pre-existing bar violations its probes uncovered in the ternary-chain desugars: two
OVER-ACCEPTANCES (branch base types that do not unify - `(c ? Arr<In,2> : Arr<In,3>)[0n].y` -
were branch-pushed past solc's TypeError on BOTH the read and the write desugar) and one
MISCOMPILE (`(c ? this.A : m)[0n].y = v`, storage|memory: solc writes into a MEMORY COPY of the
storage branch, JETH's branch-push wrote storage directly). The mismatches are now both-rejects;
the location mix is the new deliberate row TERN-LV-MIX below.

## Deliberate rejects (must stay)

Shapes where lifting is proven unsound (solc holds a LIVE REFERENCE a flat copy cannot mirror, or
solc's literal typing cannot be reproduced) - a lift would trade a clean reject for a miscompile.

| ID | Shape | Code | Why it must stay |
|----|-------|------|------------------|
| B-21 | memory-parent `xs[1n].pre` AND memory-struct `s.f` through the POINTER channels (internal-arg / element-write / internal-return / 2-hop) | JETH900 | A flat copy would detach from the live memory parent (R3); the FLAT consumers of the same expressions are lifted (L7b) |
| TERN-STRUCT-ARR | `c ? <mem> : <storage>` ternary where both branches are a fixed STRUCT array `Arr<In,N>` (bind + for-of) or a dyn struct array `In[]` (bind). The B-7/B-24 residual scope: value, u256[], bytes and dyn-struct spellings are LIFTED and aliasing-verified | JETH074 | Pointer-headed struct-array branches; no aliasing-witness study has cleared a copy lowering yet (lift candidate only with one) |
| TERN-LV-MIX | ternary-chain LVALUE with mixed-location branches: `(c ? this.A : m)[0n].y = v` / `+= v` / `++` (storage|memory; the calldata-branch spellings reject on the read-only branch). solc runs: it unifies the ternary to a MEMORY COPY, so the storage branch's write lands in the DISCARDED copy (probed: solc's A stays 0) | JETH067/JETH074 | Branch-pushing the write would hit storage the copy semantics never touch (this was a live miscompile before batch A); same-location branches (st|st, mem|mem) ARE lifted. Lift candidate only via real copy-materializing codegen |
| L6 | `o[0n] = <storage/whole-agg>` writing into an inline value-word element of a nested memory array | JETH429 | The prior-alias witness (solc re-points, an earlier alias keeps OLD values) proves NO RHS source is liftable; a flat layout can only copy |
| L7(a) | memory-struct ctor with a BOUND fixed-array var `S1(a, 5n)` | JETH465 | solc stores a live reference to `a`; the inline literal ctor `S1([In..,In..], 5n)` IS accepted and byte-identical |
| L2-MOBILE | both-literal ternary encode with BARE int/bool elements `abi.encode(c ? [1n,2n] : [3n,4n])` | JETH213 | solc's mobile type is uint8[2]/bool[2]; JETH's u256 typing would encode differently (parity gate, not a feature gap) |

Parity footnotes (both-reject, never ORs): FIXED-outer cd|storage array-literal element mixes and
cd|storage ternary mixes (solc TypeErrors); oversize state-init literals (JETH065+JETH211).
Likely-deliberate singleton: trailing-hole destructure `let [p, ] = g(a, b)` (JETH066+JETH072; TS
parses `[p,]` as 1 element, so JETH sees an arity mismatch; the leading-hole form `let [, q]` is
lifted and byte-identical).

## Liftable over-rejections (5 families, 13 shapes)

Every row re-probed at `cef1148`/`8174afc` with a verified solc-runs-fine mirror. (The former
M-BYTES and T-LVALUE rows were lifted by long-tail batch A - see Lifted history.)

| Family | Shape (witnesses) | Code(s) | Workaround |
|--------|-------------------|---------|------------|
| F-CALLEE funcref expression callees | calling a funcref-valued EXPRESSION: `(c ? this.inc : this.dec)(v)` direct; `(c ? a : b).f(10n)` struct-ternary member; `this.mk().f(4n)` call-result member; `this.pick(c)(v)` chained | JETH074 | let-bind the funcref/struct first (all bound forms lifted) |
| F-TYPES funcref type gaps | struct-returning funcref annotation `let g: (a: u256) => In = this.mk`; dyn-ARRAY-returning funcref `(x) => u256[]` (string/bytes returns are lifted); nested funcref-bearing struct `Outer { fd: Fd }` | JETH900+074; JETH151; JETH229 (+228/074 cascades) | Named internal fns / flatten the struct |
| F-CONSUMERS funcref-struct consumers | internal fn RETURNING `Fd` or `[Fd, u256]`; `Fd[]` memory array literal | JETH243/074; JETH427/074 | Return a tag, rebuild the struct; individual locals |
| F-MULTIRET multi-return call positions | statement-position discard `g(a, b);`; direct `return g(a, b)` as the external tuple (destructure-then-return works) | JETH244; JETH060 | Destructure to named locals |
| A-LIT array-literal crosses | ternary over ref-element literals `abi.encode(c ? [a,b] : [b,a])` / bind spelling; tuple-return `[Arr<u256[],2>, u256]` from a ref-element literal; DYN-outer cd+storage mix `let m: u256[][] = [a, this.s1]` (solc's new+assign runs); cast-typed literal self-typing `abi.encode([u256(1n), u256(2n)])` + its ternary (solc: uint256[2]) | JETH900 / 200+151; JETH243/151; JETH074+151; JETH213 | Bind branches/elements first; new+assign |
| MOD-GEN generic modifier at aggregates | `@ne(bytes("ab"))` with `@modifier ne<T>(v: T)` (value-type instantiations are lifted, L15; the non-generic bytes modifier MATCHes) | JETH291 | Monomorphize per concrete type |

(A-LIT counts 4 shapes, F-TYPES 3, F-CONSUMERS 2, F-MULTIRET 2, F-CALLEE 1 family of 4 spellings,
MOD-GEN 1: 13 shapes.)

## Lifted history

**Long-tail batch A on top of `fbd357a`** (6 shapes + 2 bonus, ~60-case CLEAN closure): M1/M2
plain + nested memory-struct bytes-field byte WRITES (`q.b[2n] = 0x2an`, `r.inner.b[1n] = v`, a
new checkLValue branch keyed on memDynStructFieldType emitting the in-place mstore8; alias-visible,
OOB Panic 0x32, runtime idx, internal-param bases; storage byteIndexStore + calldata rejects
unchanged; string fields stay JETH205); M2-read (the nested-chain byte READ, the one-hop branch
widened) and M3 (byte READ rvalue through a bytes[] field chain, the Residual-B2 gate now mirrors
the L13 write gate); T1 ternary-chain whole-ELEMENT writes (storage AND memory branches, the
desugar's final-type gate widened to bytes-like/struct/array; RHS-cond-idx order counter-verified);
T2 compound ops (all ten, div-by-zero/underflow Panics, order [RHS, cond, idx] = solc's probed
trace) + BONUS ++/-- in statement AND value position (cond-idx order, prefix + postfix); T3 nested
ternary chains (recursive probe + emission; 3-level, ternary-in-cond, nested whole-element, nested
compound; nested order [RHS, outer-cond, inner-cond, idx] = solc). Also fixed 3 pre-existing bar
violations (2 branch-type-mismatch OVER-ACCEPTANCES on the read+write desugars, 1 storage|memory
lvalue-desugar MISCOMPILE -> the TERN-LV-MIX deliberate row). Regression file:
test/lift-longtail-batchA.test.ts.

**Tier-3 round at `661cd1c` + `cef1148` (+ soundness fix `8174afc`)** (12 shapes, 381-case CLEAN
verification): L9 ref-element array literals (cd/storage deep-copy, memory alias, the cd+storage
parity gate; bonus dyn-outer widening); L2 residuals (both-struct-literal ternary encode, bytes
member on struct ternaries, ternary-chain lvalue `.y = v` with solc eval order); L10a
dynamic-return funcref calls; L10b multi-return funcref calls (destructured); L11a funcref-typed
struct fields as internal values (ALL ABI boundaries reject, incl the event/error gates fixed at
8174afc); L11b ternaries over funcref-field structs; L13 byte-writes into bytes[] field elements
(in-place mstore8, alias-visible, OOB Panic); L14 statement-position internal calls with
bytes/string args; L15 generic modifier instantiation at value types. L6 reclassified deliberate
(prior-alias witness).

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
false entry: `P(1n, [])` (solc also rejects). Post-Tier-3 correction: the audit's B-7/B-24 rows were
reconstruction errors (see status).

Audit method: differential deploy+call+decode via the scratchpad diff.mjs harness, identical calldata
both sides, distinct non-zero seeds checked arithmetically; OOB/revert branches exercised; log
surfaces compared entry-wise where events are involved; dual-commit (HEAD vs parent) compilation for
class-change and bytecode-drift detection; per-finding adversarial re-verification (default stance:
the finder made a probe mistake). Probe pitfalls that produced false alarms: contract not named `C`;
`bytes("aabbcc")` (6 ASCII chars) mirrored as `hex"aabbcc"` (3 bytes); missing `n` literal suffixes;
JETH event/revert spellings are `emit(E(x))` / `revert(Bad(x))` (an `emit E(x)` probe is vacuous).
