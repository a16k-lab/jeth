# Over-rejection catalogue

**Status: live-audited at f0e3761; Tier-1 verified at `1b330fb`; Tier-2 at `d42e6de`; Tier-3 at
`cef1148` + the soundness fix `8174afc`; long-tail batch A (M-BYTES + T-LVALUE, 6 shapes) lifted
on top of `fbd357a`; long-tail batch B (A-LIT array-literal crosses, 4 shapes + closure lifts)
lifted on top of batch A; long-tail batch C (the funcref expression surface: F-CALLEE, F-TYPES,
F-CONSUMERS, F-MULTIRET, 11 shapes + bonus lifts) lifted on top of batch B (2026-07-08);
long-tail batch D (MOD-GEN generic modifiers at aggregate types + the F-RESID `Arr<Fd,N>`
stretch, 2 shapes) lifted on top of batch C (2026-07-08).**

**LIFT-ALL-13 FINAL CAMPAIGN (HEAD `3621b27`, suite 415 files / 3712 tests):** an attempt to lift
every remaining OR. Witness-verified solc semantics first, then lifted the 8 that can be
byte-identical (OR clusters 1/3/4): TERN-LV-MIX + TERN-STRUCT-ARR (ternary mem|storage
copy-or-alias, `55000f0`), the two funcref-element-value shapes + calldata struct-array byte
access + `xs[i].tags[j][k]` (`69afb58`), A-LIT-RESID mixed-bytesN widen + L2-MOBILE bare-literal
mobile-type (`9110ce3`). KEPT as SOUND REJECTS (5): **LT5** (stored funcref raw storage diverges,
mathematically impossible), **B-21 / L7a / L6** (JETH's inline vs solc's pointer-headed memory
layout for value/struct fixed-array fields; the compiler code at yul.ts:8944 documents this with 4
prior miscompile witnesses - a naive lift corrupts the payload or loses live-reference
mutation-visibility; a real lift needs a ~400-site layout rework), **FUNCREF-PURE** (needs
mutability added to the funcref type). The 3 verification sweeps over these lifts found + fixed 2
more PRE-EXISTING silent miscompiles (byte-identical bytecode at the pre-lift parent, not
introduced by the lifts): BYTE-CD-1 (calldata struct-array element byte read - already fixed
earlier) and MC-ARRLIT-STOR-SCRATCH (`3621b27`: a static array/struct literal encoded to the
0x00-based ABI buffer whose elements read a keccak-addressed storage location - dynamic array /
mapping - zeroed an earlier slot because the keccak scratch at 0x00-0x40 overlapped the buffer;
fixed by hoisting all element values to temps before the buffer writes, in encodeArrayLitHead +
encodeStructReturn). The whole scratch-clobber class re-swept CLEAN (event/error/tuple/nested).
Net: 21 of the 26 remaining ORs lifted across all long-tail rounds; the 5 residuals are
architecturally/mathematically unliftable without introducing a miscompile.

The Tier-3 round lifted the final 12 shapes
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

**FINAL VERIFICATION (429-case adversarial workflow over batches A-D, every finding re-verified).**
It confirmed THREE bar violations, all now fixed and pinned in test/fix-longtail-verification.test.ts:
- MC-MEMARR-BYTES-WRITE (silent miscompile, campaign-exposed): `xs[i].b[j] = v` (byte write into a
  `bytes` field of a MEMORY struct-ARRAY element) dropped the store; now rejects JETH217 like the
  read side (resolveMemDynStructArrayField bytes-field guard).
- DRIFT-MC-1 (silent miscompile, pre-existing): `(c ? this.a : this.b)[i] = v` on storage
  value-arrays wrote a discarded memory copy; the ternary-chain branch-push desugar now fires for
  ANY ternary-bottomed write (a JETH ternary is a value, never a reference), landing the write in
  storage. A storage|memory mix stays a clean reject (TERN-LV-MIX). A FOLLOW-UP verification found
  the first fix closed only the FLAT case; NESTED chains `(c ? a : (e ? b : d))[i] = v` still
  dropped the store (ternLValueQuiet tried the direct value-copy lvalue before the recursive probe,
  so an inner branch reported loc=mem and broke the outer storage unification). Closed at `9ab81a1`
  by trying the recursive probe first. An exhaustive 78-case confirmation pass (depths 1-4, all
  ops/locations/target kinds, eval-order traces) then came back CLEAN.
- MATRIX-OA-1 (over-acceptance, root pre-existing): `(c ? this.A : this.B)[i] = P(9n)` (wrong
  struct) was accepted; the static-struct local-decl nominal name check is now blanket over every
  initializer kind, closing both the desugar path and the underlying `let a: In = P(...)` hole.
The workflow also corrected two stale catalogue claims: F-RESID `@state o: Outer` (storage
funcref-bearing struct) is FULLY IMPLEMENTED and byte-identical (every ABI boundary still sealed),
so the last "liftable" family is empty; and it re-probed all deliberate rows (soundness witnesses
intact). Dual-commit drift vs the pre-campaign parent: CLEAN (53 programs).

**Current remaining: ~13 shapes** = 13 deliberate (8 rows) + 0 liftable planned (a thin long-tail
of single-field-funcref-struct and memory-struct-array byte-access residuals remains, all clean
rejects; see below). Codes current at the final-verification-fix commit. Batch C lifted the whole funcref expression surface
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

## Liftable over-rejections: two small ones from the v3 scoping sweep (2026-07-10)

Both PRE-EXISTING (single-file, identical multi-file), both LOUD rejects, found in passing by the v3
per-file declaration-scoping adversarial sweep (1047 cases, 0 MC / 0 OA / 0 crash for v3 itself):

- **ICE-LIB-SIG (JETH901 internal-compiler-error surface)**: an EXTERNAL library whose own external
  fn shares a signature with an external-library fn it CALLS in another external library dies in the
  Yul backend with `DeclarationError: Duplicate case "0x6e9410b6"` - the callee's delegatecall
  wrapper is emitted as a second dispatcher case colliding with the caller's own external fn of the
  same selector. solc accepts the equivalent (`library High { function m(uint256 x) public ... {
  return Low.m(x) * 2; } }`). Trigger is exactly caller-lib-own-external-sig ==
  called-external-lib-fn-sig; distinct names, same-sig-but-uncalled, and a contract calling two
  same-sig libs are all fine. Lift = scope/suffix the callee wrapper out of the dispatcher switch;
  until then a loud (if ugly) reject, not a bar violation.
- **USING-ON-ABSTRACT (cryptic JETH074)**: `@using(L)` on an `@abstract` class is not consumed and
  falls through as `unsupported expression: CallExpression` at the class line. solc allows `using L
  for T;` inside an abstract contract. Lift = consume @using on abstract bases (attaching for the
  deployed linearization) or at minimum emit a targeted "attachments live on @contract/@library"
  diagnostic.

The 19-shape tier list plus the F-RESID family are all lifted (batches A-D) or reclassified. The
final verification found that `@state o: Outer` (a storage funcref-bearing struct) is already fully
implemented and byte-identical, so the last "liftable" row is retired.

FINAL-5 MICRO-ROUND (commits `bfd31cd` + `3ece104`, suite 410/3692): the 5-shape thin long-tail
was worked to ground. LIFTED byte-identical (4): LT1 single-field funcref static struct internal
return `mk(): Fd` + chained `this.mk().f(v)` (isSupportedStructReturn admits a funcref value-word
field; ABI-leak matrix all 17 boundaries reject); LT2 `Arr<Fd,N>` element dispatch `a[i].f(v)`
(pointer-headed per-element image, a store-layout miscompile caught + fixed mid-implementation);
LT3 memory struct-array element byte READ `xs[i].b[j]`; LT4 the byte WRITE twin (in-place mstore8,
alias-visible, neighbor-safe, both bytes-field positions). KEPT REJECT (1, sound): LT5 storage push
of a funcref-field struct - a stored funcref DIVERGES from solc on RAW STORAGE (JETH dispatch
ordinal vs solc code offset), and the bar includes raw storage, so no stored funcref in a struct or
array can be byte-identical. This is a documented internal-representation modeling difference (types.ts),
in the same "genuinely unmatchable" class as gasleft; the dispatch RESULT is byte-identical and every
ABI boundary is sealed. The final-5 adversarial workflow (230 cases) also found + fixed a PRE-EXISTING
calldata miscompile (BYTE-CD-1: calldata struct-array element byte read `xs[i].b[j]` silently returned
0x00; now rejects JETH217, bind-a-local workaround byte-identical) and a compiler CRASH on an
uninitialized funcref-bearing static struct (`let d: Fd;` now defaults the funcref to id 0, Panic 0x51
on call, byte-identical). Nested calldata field byte access `d.inner.b[j]` and plain `d.b[j]` remain
byte-identical.

REMAINING over-rejections (all sound clean rejects; solc runs them, JETH rejects loudly with a
workaround; none are miscompiles or over-acceptances):
- LT5 storage push of a funcref-field struct `xs.push(Fd(this.inc))` (JETH217/210) - raw-storage
  divergence, effectively unmatchable (see above).
- calldata struct-array element bytes-field byte access `xs[i].b[j]` (read + write, JETH217) - bind
  the field to a `bytes` local first (byte-identical). The MEMORY twin (LT3/LT4) is lifted.
- whole funcref-struct array element bound to a local then called (`let e: Fd = a[i]; e.f(v)`,
  JETH230/074) and the ternary-of-elements `(c ? a[0] : a[1]).f(v)` (JETH074) - dispatch the element
  directly (`a[i].f(v)`, lifted) instead of materializing it as an intermediate value.
- `xs[i].tags[j][k]` bytes[]-field byte access on a memory struct-array element (JETH226).

A follow-up byte-access miscompile hunt (407 differential cases) confirmed the ENTIRE byte-access
surface byte-identical (170+ read + 229 write shapes: local / storage / calldata / memory bases,
struct fields at every position, bytes[] elements, struct-array element fields, mapping values,
OOB Panic parity, alias + neighbor integrity) EXCEPT one more pre-existing silent MISCOMPILE, now
fixed (`f0f3ee0`): the non-JETH calldata colon-slice `x[s:e][j]` is not valid TypeScript; TS
error-recovered it into a truncated `x[s]`, which JETH silently compiled to the slice-start byte
with no bounds check. Root fix: JETH now rejects any source it would SILENTLY ACCEPT despite a
(non-1011) TS parse diagnostic - a general malformed-input robustness win. The `abi.decode(b, T[])`
array-type-in-value-position feature (TS code 1011) and the analyzer's semantic rejects are
preserved. The byte-identical form is `x.slice(s, e)[j]`.

Earlier live re-audit at `5627d90` CORRECTED two stale entries: array-typed event params
(`@event E(a: u256[])`) MATCH byte-identically, and a calldata struct-array element aggregate field
bound to a memory local (`let p: In = s[i].pre`) is a BOTH-REJECT (parity), not an OR.

Parity footnote confirmed during the batch C close-out: `.length` on a STRING value (local or
struct field) rejects in BOTH compilers (JETH202; solc strings have no .length, a bytes cast is
required) - a both-reject, never an OR. bytes fields (`s.b.length`) work.

A pre-existing adjacency found during the batch B closure was lifted with it: pushing a
nested-array ELEMENT or a ternary source to a storage stack (`this.st.push(m[1n])`,
`this.st.push(c ? a : b)`) - the push-arg mem-prep now lowers a memArrayExpr-based source to its
element/branch image pointer (was a JETH900 lowering throw; solc runs).

## Lifted history

**Long-tail batch D on top of batch C** (MOD-GEN + the F-RESID `Arr<Fd,N>` stretch, 2 shapes;
~35-case closure): MOD-GEN generic @modifier instantiation at AGGREGATE/DYNAMIC/FUNCREF types
(`@ne(bytes("ab"))`, string, u256[], Arr<u256,2>, static + dynamic structs, funcrefs): the L15
monomorphization previously routed every type argument through the generic-FUNCTION value gate
(JETH291); a modifier-specific gate (gateModifierGenericTypeArg) now admits ANY type a concrete
@modifier parameter admits - the monomorph is collected through the normal concrete-modifier
pipeline, so each shape accepts or re-rejects exactly where a hand-written modifier would (the
funcref-array instantiation matches the non-generic JETH900 class; mapping/void keep JETH291).
The specialization mangle gained an INJECTIVE tag for non-value types (structs by NAME - JETH
structs are nominal; recursive serialization, charcode-escaped, `$`-free) so distinct types can
never collapse to one cache key; value-type tags unchanged byte-for-byte. Verified: multi-
instantiation dispatch (bytes+u256+u256[] of ONE modifier + a reverting witness), post-placeholder
bodies, stacked-modifier arg eval order (side-effect counters = solc), storage-read / calldata-
param / literal arg sources, ctor applications, T-used-twice, nested generics, same-layout
distinct structs (nominal split), dedup, mismatch both-rejects. Deliberate residuals: INFERENCE
from a bare literal / bare method reference rejects (JETH213/065/074) exactly like every other
no-context position in the language (explicit type args or typed sources lift); generic FUNCTIONS
stay value-only (a separate row, JETH291). F-RESID stretch: `Arr<Fd,2>` (FIXED array of
funcref-bearing dyn structs) as a MEMORY LOCAL - pure routing via the new
types.isFuncrefDynStructFixedLeafArray (the fixed-outer twin of batch C's isFuncrefDynStructLeaf,
kept separate so ABI codecs keep rejecting) OR'd at the localDecl gate, resolveArrayExpr's fixed
memAggregate branch, nestedMemArrayElemAccess, and yul's fixed pointer-headed localDecl route.
Literal / element read / `o[i].f(v)` dispatch / whole-element write / element-to-local / for-of /
alias write-through / OOB Panic 0x32 all byte-identical; const-OOB both-rejects. GUARD added with
the lift: the JETH467 mem->storage copy gates gained the funcref twin - the newly-reachable
`this.g = o` would have been an OVER-ACCEPTANCE (solc legacy rejects with
UnimplementedFeatureError). Deeper nestings (Arr<Arr<Fd,2>,2>, Arr<Fd,2>[]) keep JETH427; the
funcref-FIELD write through an element chain (`o[i].f = g`) keeps the family JETH200 reject (the
dyn-outer `Fd[]` rejects identically); the storage-source bind matches the dyn-outer JETH200
class; the full ABI-leak matrix (return/encode/event/error/getter/external param) still rejects.
Regression file: test/lift-longtail-batchD.test.ts.

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
