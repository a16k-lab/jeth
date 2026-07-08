# Over-rejection catalogue

**Status: live-audited at f0e3761; Tier-1 verified at `1b330fb`; Tier-2 at `d42e6de`; Tier-3 at
`cef1148` + the soundness fix `8174afc`; long-tail batch A (M-BYTES + T-LVALUE, 6 shapes) lifted
on top of `fbd357a`; long-tail batch B (A-LIT array-literal crosses, 4 shapes + closure lifts)
lifted on top of batch A; long-tail batch C (the funcref expression surface: F-CALLEE, F-TYPES,
F-CONSUMERS, F-MULTIRET, 11 shapes + bonus lifts) lifted on top of batch B (2026-07-08).** The Tier-3 round lifted the final 12 shapes
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
  memory alias witnesses); its cd+storage element mix was a NEW over-rejection (solc's dyn-outer
  equivalent runs, unlike the fixed-outer mix which is a parity both-reject) - lifted by batch B.

**Current remaining: ~16 shapes** = 13 deliberate (8 rows) + 3 liftable (2 families). Codes
current at the long-tail batch C commit. Batch C lifted the whole funcref expression surface
(all four F-rows, 11 shapes) plus bonus lifts its closure produced: the whole nested
funcref-field WRITE `o.fd = mkFd()` (solc re-point alias semantics witness-verified), plain
dyn-struct tuple components from INTERNAL calls (`let [a, s] = this.mk(x)`, the old JETH243
pin), and `new Array<Fd>(n)`. It also fixed a LATENT pre-existing miscompile: solc's legacy
pipeline evaluates a call's ARGUMENTS before its FUNCTION EXPRESSION, and all three funcRefCall
lowerings (value/statement/destructure) now match (`arr[idx()](a1(), a2())` logged 512 vs solc's
125 before). New deliberate row FUNCREF-PURE below (funcref types carry no mutability). Batch B lifted the whole A-LIT row (4 shapes) plus the
closure lifts riding the same machinery (storage/memAggregate/nested-ternary branches of the
pointer-headed nested-value ternary, direct index + write-through, tuple forward, dyn-outer and
flat-fixed tuple components, address/bool/string/typed-var literal self-typing); its literal
residuals (mixed bytesN widths, enum elements, the cast+bare mix) are the new deliberate
A-LIT-RESID row + an L2-MOBILE extension. Batch A lifted all 6 M-BYTES/T-LVALUE shapes AND fixed
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
| L2-MOBILE | array literals with BARE int elements, alone or ternary (`abi.encode([1n, 2n])`, `abi.encode(c ? [1n,2n] : [3n,4n])`), AND the cast+bare mix `abi.encode([u256(1n), 2n])` (batch B) | JETH213 | solc's mobile type is the smallest fitting width (uint8[2] for [1,2]; the mix folds the bare value into the common type, [u8(1),300] -> uint16[2]); JETH's typing cannot mirror it - a lift would encode different lanes. Bool literals ARE lifted ([true,false] -> bool[2], no width hazard); cast-typed elements are lifted (B4) |
| FUNCREF-PURE | a @pure function calling through a funcref whose SIGNATURE has a state-writing address-taken target elsewhere in the contract (dispatcher-set poisoning): `@pure b()` using `Fd.f` of sig `(u256)=>u256` rejects when `ord()` address-takes state-writing `linc/ldec` of the same sig | JETH055 | JETH funcref types carry NO mutability (solc's `function(...) pure returns(...)` pointer types do), so the purity checker soundly assumes the sig-key dispatcher set; a lift needs mutability in the funcref type grammar. Workaround: drop @pure, or avoid impure address-takes of the same signature |
| A-LIT-RESID | batch B literal residuals: mixed bytesN widths `[bytes4(..), bytes8(..)]` (solc widens right-padded; JETH's literal coerce rejects the re-type); ENUM elements `[Color.Green, cb]` (no verified enum fixed-array encode path); a whole calldata-param branch in a pointer-headed nested ternary `c ? p : [a, b]` (p: Arr<u256[],N> cd param; the copy does not replicate solc's cd-ref validation) | JETH213 / JETH074 | Spell bytesN at one width; cast enums to uintN; bind the cd param to a memory local first |

Parity footnotes (both-reject, never ORs): FIXED-outer cd|storage array-literal element mixes and
cd|storage ternary mixes (solc TypeErrors); oversize state-init literals (JETH065+JETH211).
Likely-deliberate singleton: trailing-hole destructure `let [p, ] = g(a, b)` (JETH066+JETH072; TS
parses `[p,]` as 1 element, so JETH sees an arity mismatch; the leading-hole form `let [, q]` is
lifted and byte-identical).

## Liftable over-rejections (2 families, 3 shapes)

Every row re-probed live with a verified solc-runs-fine mirror. (The former M-BYTES and T-LVALUE
rows were lifted by long-tail batch A, the A-LIT row by batch B, all four F-rows by batch C -
see Lifted history.)

| Family | Shape (witnesses) | Code(s) | Workaround |
|--------|-------------------|---------|------------|
| MOD-GEN generic modifier at aggregates | `@ne(bytes("ab"))` with `@modifier ne<T>(v: T)` (value-type instantiations are lifted, L15; the non-generic bytes modifier MATCHes) | JETH291 | Monomorphize per concrete type |
| F-RESID funcref containers beyond batch C | `Arr<Fd,N>` FIXED array of funcref structs (the dyn `Fd[]` is lifted); `@state o: Outer` funcref-bearing struct in STORAGE (solc stores fn pointers; JETH has no storage funcref layout) | JETH427/074; JETH229 family | Dyn array / memory locals + a tag field in storage |

(MOD-GEN 1, F-RESID 2: 3 shapes.)

Parity footnote confirmed during the batch C close-out: `.length` on a STRING value (local or
struct field) rejects in BOTH compilers (JETH202; solc strings have no .length, a bytes cast is
required) - a both-reject, never an OR. bytes fields (`s.b.length`) work.

A pre-existing adjacency found during the batch B closure was lifted with it: pushing a
nested-array ELEMENT or a ternary source to a storage stack (`this.st.push(m[1n])`,
`this.st.push(c ? a : b)`) - the push-arg mem-prep now lowers a memArrayExpr-based source to its
element/branch image pointer (was a JETH900 lowering throw; solc runs).

## Lifted history

**Long-tail batch C on top of batch B** (the funcref expression surface: 11 shapes + bonus lifts;
~70-case closure incl. the 33-boundary ABI-leak matrix, all BOTH-REJECT): F-CALLEE all four
expression-callee spellings (funcrefCalleeSigDeep derives the callee signature - ternary branches
must agree - and buildFuncRefCall checks with it, so branch address-takes resolve like let-bound
forms) + the ORDER FIX (solc legacy evaluates call ARGUMENTS before the FUNCTION EXPRESSION; all
three funcRefCall lowerings now lower args first - this also fixed a LATENT pre-existing
miscompile on the already-lifted element/field callee paths). F-TYPES struct-returning funcrefs
(dispatcher forwards the image pointer), In[]-returning funcrefs, nested funcref-bearing structs
`Outer { fd: Fd }` (decl gate + isSupportedStructReturn admit via isSupportedDynStructLocal;
o.fd.f rides memDynNestedField). F-CONSUMERS internal returns of `Fd`/`[Fd, u256]` (resolveTupleCall
admits supported dyn-struct components - also lifting plain `[Q, u256]`, the old JETH243 pin in
library-tuple-dyn-struct.test.ts, flipped) and `Fd[]` memory literals via isFuncrefDynStructLeaf
(the funcref TWIN of isDynStructLeaf, kept separate so every ABI codec keyed on isDynStructLeaf
keeps rejecting). F-MULTIRET statement discards (`g(a,b);`, `this.two(x);`) and direct
`return g(a, b)` tuple returns (desugared to destructure-then-return). BONUS: whole nested
funcref-field WRITE `o.fd = mkFd()` byte-identical incl. re-point alias witnesses;
`new Array<Fd>(n)`. SOUNDNESS: the full 33-entry ABI-leak matrix (funcref, Fd, Outer, Fd[],
[Fd,u256] x encode/encodePacked/decode/encodeWith*/external+public params+returns/events both
arms/errors/getters/mapping-getter/ctor params/interface types) all reject, pinned in
test/lift-longtail-batchC.test.ts. New deliberate row FUNCREF-PURE (dispatcher-set purity
poisoning; JETH funcref types carry no mutability).

**Long-tail batch B on top of batch A** (the A-LIT row: 4 shapes + closure lifts, ~45-case CLEAN
closure incl. aliasing/deep-copy witnesses and an OA hunt): B1 ternary over ref-element array
literals, encode + bind spellings (`abi.encode(c ? [a,b] : [b,a])`, `let m: Arr<u256[],2> = c ?
[a,b] : [b,a]`): the lit|lit ternary self-types each branch via the new general literal
self-typing; the fixed-array ternary LOWERING routes pointer-headed nested-value branches through
aggArgToMemPtr (canonical image - literal fresh, memory ALIAS witness-verified, storage deep-copy
witness-verified) instead of the flat aggToMemPtr; materializeArrayArg gained the
ternary->abiEncFromMem tail branch (also lifts emit(E(<ternary>))). Closure: memAggregate-local
branches (c ? m1 : m2 aliased), STORAGE branches (c ? this.sA : [a,b], st|st), nested ternary
chains, direct index `(c ? .. : ..)[i][j]` + write-through `(c ? m1 : m2)[0n][0n] = v` (the
P1-13 resolveArrayExpr gate widened), internal-arg + external-return consumers, the storage-WRITE
consumer (`this.sA = c ? [a,b] : [b,a]` incl. a storage branch with shrink semantics and the
static value-array twin, via a ternary route in the fixed-array assign memSrc), and the PUSH
consumers (`this.st.push(m[1n])` / `push(c ? a : b)`, a pre-existing memArrayExpr-source gap).
B2 tuple-return
of ref-element literals (`g(): [Arr<u256[],2>, u256]` + destructure): resolveTupleCall admits
nested value-word + flat fixed value-array components; the `return this.g()` tuple FORWARD
registers/reads the new kinds and encodeReturnTupleInner materializes a DYNAMIC-type array
memAggregate component as a producer (alias + abiEncFromMem); dyn-outer components, external
tuple literal, mutate-after-destructure, re-encode all verified. B3 DYN-outer cd+storage literal
element mix (`let m: u256[][] = [a, this.s1]`): the L9 parity gate now fires for the FIXED-outer
literal only (solc TypeErrors that literal; the dyn-outer JETH sugar mirrors new+assign, which
runs) - deep-copy witnesses on both elements; bytes[]/P[] mixes verified. B4 cast-typed literal
self-typing (`abi.encode([u256(1n), u256(2n)])` + ternary): checkExpr's no-expected arrayLit path
self-types from INTRINSIC element types (explicitCast-flagged folded casts, bytesN/address-typed
literals, typed vars, struct ctors, bool literals); same-family integer casts unify to the widest
width ([u8(1n),u256(x)] -> uint256[2], [i8(-1n),i256(x)] -> int256[2], probed); cross-family
mixes both-reject; runtime-cast truncation (u8(x) at 300), packed lanes, keccak parity verified.
Residuals -> the A-LIT-RESID deliberate row + the L2-MOBILE cast+bare extension. Regression file:
test/lift-longtail-batchB.test.ts.

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
