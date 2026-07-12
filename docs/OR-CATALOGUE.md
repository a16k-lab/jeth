# Over-rejection catalogue

> **Native-syntax only (2026-07).** JETH no longer has a decorator "mode": the `// use @decorators`
> pragma is a hard error (JETH480) and the 21 legacy structural decorators are removed (JETH481) - see
> the [native-spelling table](../SUPPORTED.md#legacy-decorator-removal-native-syntax-only). This
> catalogue is a running audit ledger: the dated rounds below use the decorator spellings that were
> current when each finding was recorded, kept verbatim for historical continuity. Where an older entry
> presented a "legacy X spelling" as a working workaround, that spelling is now retired - use the native
> replacement from the table.

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

**Current remaining (live-audited 2026-07-10 at `3206f08`, 12-row adversarial re-probe, zero
regressions/ICE-drift): 7 deliberate table rows + LT5 + the trailing-hole singleton + 2 small
liftable ORs (ICE-LIB-SIG, USING-ON-ABSTRACT).** The audit found the table had gone stale against
the LIFT-ALL-13 narrative: TERN-LV-MIX retired (fully lifted), TERN-STRUCT-ARR / L2-MOBILE /
A-LIT-RESID / B-21 narrowed to their true residual scopes (each formerly-listed spelling that now
accepts was runtime-verified identical to solc before trimming). Codes current at the final-verification-fix commit. Batch C lifted the whole funcref expression surface
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
| B-21 | a fixed STRUCT-array field (`Arr<In,N>`) of a memory struct / struct-array element (`xs[1n].pre`, `s.pre`) through the POINTER channels (internal-arg / element-write / internal-return / 2-hop). VALUE-array field spellings (`Arr<u256,N>`) are LIFTED through internal-arg / internal-return / 2-hop (live-pointer aliasing runtime-verified vs solc, 2026-07-10 audit); their element-WRITE spelling rejects under L6/JETH429, not here | JETH900 | A flat copy would detach from the live memory parent (R3); the FLAT consumers of the same expressions are lifted (L7b) |
| TERN-STRUCT-ARR | `c ? <mem> : <storage>` ternary where both branches are a DYN struct array `In[]` (let-bind AND return position). The fixed `Arr<In,N>` spellings (bind + for-of) were LIFTED at `55000f0` (test/lift-forof-ternary.test.ts, test/lift-return-ternary-struct-array.test.ts; copy-vs-alias semantics runtime-verified identical to solc, 2026-07-10 audit) | JETH074 | Pointer-headed dyn struct-array branches; no aliasing-witness study has cleared a copy lowering yet (lift candidate only with one) |
| L6 | `o[0n] = <storage/whole-agg>` writing into an inline value-word element of a nested memory array | JETH429 | The prior-alias witness (solc re-points, an earlier alias keeps OLD values) proves NO RHS source is liftable; a flat layout can only copy |
| L7(a) | memory-struct ctor with a BOUND fixed-array var `S1(a, 5n)` | JETH465 | solc stores a live reference to `a`; the inline literal ctor `S1([In..,In..], 5n)` IS accepted and byte-identical |
| L2-MOBILE | the CAST+BARE int mix in an array literal: `abi.encode([u256(1n), 2n])`, `[u8(1n), 300n]`. The pure-bare spellings (`abi.encode([1n, 2n])`, the bare ternary) were LIFTED at `9110ce3` (encode pads elements to 32 bytes, width-independent; test/lift-or-cluster4.test.ts; runtime-verified identical, 2026-07-10 audit) | JETH213 | solc folds the bare value into the cast's common type ([u8(1),300] -> uint16[2]); JETH keeps no-common-type. Bool literals and fully cast-typed elements are lifted. Workaround: cast every element |
| FUNCREF-PURE | a pure (inferred) function calling through a funcref whose SIGNATURE has a state-writing address-taken target elsewhere in the contract (dispatcher-set poisoning): a pure `b()` using `Fd.f` of sig `(u256)=>u256` rejects when `ord()` address-takes state-writing `linc/ldec` of the same sig | JETH055 | JETH funcref types carry NO mutability (solc's `function(...) pure returns(...)` pointer types do), so the purity checker soundly assumes the sig-key dispatcher set; a lift needs mutability in the funcref type grammar. Workaround: make the function non-pure (read state so it infers view), or avoid impure address-takes of the same signature |
| A-LIT-RESID | a whole calldata-param branch in a pointer-headed nested ternary `c ? p : [a, b]` (p: `Arr<u256[],N>` cd param; the copy does not replicate solc's cd-ref validation). The mixed-bytesN and ENUM-element spellings were LIFTED (`9110ce3` + test/lift-enum-array-literal.test.ts; runtime-verified identical incl. OOB-enum Panic parity, 2026-07-10 audit) | JETH074 | Bind the cd param to a memory local first |

Retired from this table by the 2026-07-10 live audit (12-row adversarial re-probe at HEAD, zero
regressions): **TERN-LV-MIX** - the mixed-location ternary-chain lvalue `(c ? this.A : m)[0n].y = v`
/ `+=` / `++` was fully LIFTED at `55000f0` (test/lift-or-cluster1.test.ts) with solc's
discarded-memory-copy write semantics runtime-verified identical; the row's "must stay" rationale
was superseded by the copy-materializing lowering the LIFT-ALL-13 campaign shipped. The table rows
above are now consistent with the campaign narrative in the header (they had never been trimmed).

Parity footnotes (both-reject, never ORs): FIXED-outer cd|storage array-literal element mixes and
cd|storage ternary mixes (solc TypeErrors); oversize state-init literals (JETH065+JETH211).
Likely-deliberate singleton: trailing-hole destructure `let [p, ] = g(a, b)` (JETH066+JETH072; TS
parses `[p,]` as 1 element, so JETH sees an arity mismatch; the leading-hole form `let [, q]` is
lifted and byte-identical).

## RETIRED 2026-07-10: the two v3-sweep liftables are LIFTED (both byte-identical, adversarially verified)

- **ICE-LIB-SIG - LIFTED** (`7b144e9`): the cross-library delegatecall entry is no longer pulled
  into the caller library's object, so a caller-lib external fn sharing a signature with a called
  external-lib fn compiles and dispatches its OWN body. Verified over a 40+-cell deploy+link
  differential (canonical chain, 3-level, same-sig diamond, fan-out, overloads, revert-data parity,
  native `static class` spelling, own-uncalled-same-sig anti-miscompile cell); dual-commit drift
  showed only the removed stray dispatcher case. Regression net: `test/library-cross-sig.test.ts`.
  Noted in passing (pre-existing, unchanged): an INTRA-library external->external call compiles to a
  SELF linkersymbol that the standard bottom-up deploy flow refuses loudly (solc emits an internal
  jump) - a safe, undeployable-not-wrong-bytes corner.
- **USING-ON-ABSTRACT - LIFTED, and the whole `@using` ownership model made LEXICAL at solc parity**
  (3-commit stack `d1a9854` + `68245e5` + `3a74e99`, landed as one range): per-class @using maps
  (deployed + every abstract base), owner-only `attachedFnsFor` (no deployed-map fall-through), the
  native `self`-convention kept file-wide by design in its own map. The lift itself: `@using(L)` on
  `@abstract` consumed for the base's OWN bodies (both decorator orders), incl. base ctors, generics
  declared in the base, and JETH391 arg validation. The lexical redesign also CLOSED, in the same
  stack, bar violations that were live at base `2a48186`:
  - over-acceptances R1/R2/R5 + MIN-R4 family (bodies of other classes reaching the DEPLOYED
    contract's @using map; solc: Member not found) - now clean both-rejects;
  - MISCOMPILE MOD1: a base-declared `@modifier` body resolved via the deployed map (1007 vs solc
    2007) - modifier bodies now owned by their DECLARING class (MOD2 over-rejection lifted, 2009);
  - MISCOMPILE base-ctor ARGS: a mid-level `super(seed.tag())` arg resolved via the deployed map
    (1007 vs solc 2007) - provider-class ownership (heritage form included), sibling over-rejection
    lifted (2004);
  - MISCOMPILE inline `@immutable` initializers: a base-declared initializer resolved via the
    deployed map (1009 vs solc 2009; 3-level pins the DECLARING class, 3013) - per-field
    declaring-class owner windows in `immutableInitStmts`.
  Final adversarial verify: zero MC / zero OA across the family; leak hunt over every remaining body
  context (event/error raises, ctor-invoked base methods, 3-class chains, generics, accessors,
  triple-window composition) all MATCH; receive/fallback proven unreachable (gated by JETH387).
  Boundary kept (parity both-reject): the CHILD writing an inherited attachment directly (solc does
  not inherit `using`). Regression net: `test/using-on-abstract.test.ts` (40 cells).

Safe over-rejections seen in passing during these lifts (pre-existing, clean, uncatalogued before):

- **USING-ON-LIBRARY (JETH074)**: `@using(M)` on a `static class` library is not consumed (solc accepts `using`
  inside a library body). In-file, a library body's only attachment source is the self-convention.
- **JETH387 receive/fallback internal-call gate**: a `receive()`/`fallback()` body may not call ANY
  internal fn (attachment calls included); solc accepts. Placement-independent, fully gates that
  surface.
- **JETH065 accessor property-read**: reading an internal `get` accessor with property syntax
  (`this.x` instead of `this.x()`) rejects even same-class with no @using; call syntax works.

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
(an event with a `u256[]` parameter, `E: event<{ a: u256[] }>`) MATCH byte-identically, and a calldata struct-array element aggregate field
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

## 2026-07-10 WHOLE-LANGUAGE AUDIT (native-mode emphasis): 1602 cases / 12 surfaces at 23a1515

**8 bar violations found + FIXED (commits `cfad297` + `278020e` + `e779196`, each adversarially
verified):** the attached-call evaluation-order MISCOMPILE (receiver was read before the args; solc
legacy evaluates args first L-to-R, then the whole receiver - external delegatecall libraries are the
exception, receiver first; both @using and self-convention channels now byte-identical);
msg.data-in-receive OA (JETH471); bodyless native receive/fallback declarations materializing
implemented entries OA (JETH472; the legal abstract bodyless-@virtual idiom is preserved);
@nonReentrant-on-get OA (JETH473 - the legacy @view spelling already rejected JETH260; the non-get
inferred lane is FLOORED to nonpayable ABI instead of rejected, verified byte-identical vs the solc
transient-mutex twin); import-line silent parse-recovery (JETH476 - bundleImports now inspects every
file's parseDiagnostics, 1011 exemption preserved); deep-expression stack-overflow crash -> clean
JETH477 reject; unicode-identifier JETH901 ICE -> clean JETH478 parity reject (raw unicode STRING
content stays accepted + byte-identical); decorator-on-VariableStatement silent side-effect drop ->
JETH479 (declare-statements too).

**New SAFE over-rejection rows (clean rejects, solc accepts; catalogue candidates from the audit -
each has a verified workaround):**
- **STR-EQ-LIT - LIFTED (2026-07-12, `79fbf89`)**: `s == "hi"` / `"hi" == s` / `!=` now type the bare
  literal from the sibling string operand, byte-identical to the `string("hi")` cast twin (60-cell
  verify + 43 runtime calls vs the solc keccak mirror). Ordered compares (`s < "hi"`) and mixed-type
  operands keep rejecting at solc parity; the bytesN-literal asymmetry (`b4 == "abcd"` accepts,
  `"abcd" == b4` rejects) is solc's own.

**New safe-OR rows found by the 2026-07-12 lift/fix verifies (each a clean reject, solc accepts,
pre-existing at `750d262` - byte-for-byte identical on the pre-lift parent):**
- **OVERRIDE-VAR-MULTIHEAD - LIFTED (2026-07-12, `9a77971`)**: the headline shape (a plain
  `x: Visible<u256>` + `@override(A, B)` over two same-sig interfaces) turned out ALREADY lifted at
  `6e46949` (the audit pin was stale); `9a77971` lifted the witnessed RESIDUALS: Visible CONSTANTS and
  IMMUTABLES as `@override` getter vars (single/multi-head, mixed base+iface heads, solc mutability
  rule: a constant getter counts as PURE, immutable/state as VIEW) plus the solc-0.8.8 no-override
  single-head interface implementation by statics at the leaf AND at non-abstract middles. Same commit
  closed 4 pre-existing over-acceptances in the shared machinery: immutable `@override`-of-nothing,
  `@virtual` on an immutable, and an unattached same-file interface legitimizing `@override` getter
  vars (state var AND immutable flavors) - all now solc-witnessed rejects.
- **IFACE-OVERLOADS** (JETH342): an interface declaring overloads of one method name rejects at the
  interface; solc accepts a fully-implementing contract. Workaround: distinct method names.
- **PURE-GET-OBLIGATION** (JETH352): an interface `p(): Pure<u256>` obligation implemented by a
  `get p(): Pure<u256>` rejects while the solc mirror accepts. Workaround: declare the obligation
  `View<T>` (or bare) and keep the impl's stricter body.
- **STRING-FIELD-INIT - LIFTED (2026-07-12)**: a `string`/`bytes` state field WITH a string-literal
  initializer (`s: string = "x"`, `Visible<string>`, `b: bytes = "ab"`, short/long/empty/unicode/
  no-sub template) now compiles: desugared into the implicit-constructor assignment (the exact
  byte-identical workaround twin), emitted at the TOP of the merged constructor - solc 0.8.35 runs
  ALL state-var initializers before any ctor body, ctor modifier, or base ctor body across the whole
  chain (witnessed: a base ctor's virtual call sees a derived field's init; a ctor modifier's
  pre-code sees the init; initializer-only creation is non-payable). Oracle: bc(field-init) ===
  bc(twin) per shape + solc runtime differentials (test/string-field-init.test.ts). RESIDUAL safe
  ORs kept (each a clean JETH048; solc accepts): **FIELD-INIT-EXPR** - a NON-literal initializer
  (`"a" + "b"`, a substitution template, `this.a + 1n` - solc even allows reading other state vars,
  declaration-order-evaluated with fwd refs reading the zero default, witnessed) and
  **FIELD-INIT-NS** - a `@storage('ns')` field initializer. Invalid UTF-8 rejects JETH447 like the
  twin (solc "Contains invalid UTF-8 sequence"); `static s: string` stays JETH310 (solc: "Immutable
  variables cannot have a non-value type").
- **TWO-BASE-GET-DIAMOND - LIFTED (2026-07-12, `9a77971`)**: the headline get-form leaf
  `@override(A2, B2)` was ALREADY accepted at the audit base (stale pin); `9a77971` lifted the VAR
  form: a getter var (plain / constant / immutable) with `@override(A2, B2)` unifying a get declared
  by two base contracts (implemented AND bodyless flavors; the base signature group drops out of the
  dispatch/super chains), with per-direct-base contract-head MAXIMALITY so a deep-diamond var
  `@override(M1, M2)` is complete while naming the non-maximal root still rejects (solc parity).
- **JETH477-DEPTH**: expression/statement nesting beyond the compiler's recursion budget (~2000-term
  binary chains cold) is a clean reject; solc compiles. Deliberate robustness boundary.
- **ABSTRACT-METHOD-DECL** (JETH375/374): TS `abstract f(): External<void>;` is not consumed as the
  virtual bodyless declaration; spell it `@virtual f(): ...;` (byte-identical). Aligns with the
  deferred implicit-virtual item.
- **NATIVE-IFACE-EXTENDS - RESOLVED (P0a, 2026-07-11)**: a native `interface I` IS an extendable
  base (`class C extends I`), byte-identical to solc's implements path (test/native-interface-extends.test.ts;
  live-probed ACCEPTS at 557e23e). **IFACE-EXTENDS-IFACE - RESOLVED (2026-07-12)**: an
  `interface B extends A` chain (2/3-level, multi-parent, common-grandparent diamond) is the native
  spelling of solc's `interface B is A`: B's callable surface is the UNION of the chain (each method
  keeps its ORIGINAL declaration's selector + STATICCALL/CALL marker), a `class C extends B` owes the
  full union (JETH385 per original declaring interface), C3 ordering/`@override` heads/`type(I)
  .interfaceId` (own-methods-only) all witnessed vs 0.8.35 (test/native-interface-extends-interface.test.ts).
  JETH349 now fires only for an invalid parent: a non-interface base, a base declared BELOW the
  derived interface (solc: "Definition of base has to precede" - which also covers extends CYCLES),
  or a type-argument/qualified base. Residual SAFE over-rejections in the chain (each a clean
  reject with a verified workaround = declare the method once in the chain):
  **IFACE-CHAIN-REDECLARE** (JETH342: identical redeclare of an inherited method; solc accepts),
  **IFACE-CHAIN-TIGHTEN** (JETH387: same-signature redeclare tightening mutability, e.g. bare ->
  View; solc accepts the tightening, rejects the loosening - JETH rejects both),
  **IFACE-CHAIN-OVERLOAD** (JETH342: same name, different params across the chain; solc treats it as
  an overload - same policy as the in-body JETH342 no-overloading rule), and
  **IFACE-DIAMOND-OVERRIDE-LIST** (JETH430: two DISTINCT parents declaring the same signature needs a
  redeclare carrying `override(A, B)`, which a TS interface method cannot spell; solc-reject parity
  for the bare shape, OR only for the unspellable redeclare cell).
- **MANGLE-INJECT** (JETH373/434/044/065/374/375): a user identifier spelled like a `#` mangle
  product (`$p$C$x`) fails CLOSED in all four spellings (never merges storage/dispatch).
- **CONST-FWD-REF** (JETH048/065): constant initializers are declaration-order-dependent; solc's are
  order-independent. Declare in dependency order.
- **LIB-CONST / LIB-MEMBER-EVENT / LIB-MEMBER-ERROR** (JETH388/390 family): a library may not declare
  constants or member events/errors (solc allows all three). Workarounds: hoist the constant;
  file-level `type X = event<{...}>`/`error<{...}>` raised from lib fns is byte-identical incl logs +
  revert data.
- **BYTES-CONST** (JETH050): a `bytes`-typed constant rejects; string/bytesN constants are lifted.
- **IMM-INIT-SHADOW** (JETH074, native only): an immutable initializer whose RHS reads a member of a
  ctor local/param named exactly like the contract class; rename or stage through a temp. Fails
  closed on the wrong-bind trap.
- **PAREN-CALLEE** (JETH074): `(C.dbl)(4n)` / `(this.dbl)(4n)`; drop the parens.
- **DEFAULT-ARG-CONST** (JETH250): `b: u256 = C.K` default param (JETH-only feature; C.K is foldable,
  a plausible lift).
- **NAMED-RAISE-EXCLUSIVITY** (JETH227/148): named-arg raise only via the member `this.X({...})`
  form; file-level named `revert(Bad({...}))`/`emit(T({...}))` reject (bare object literals mean
  struct literals - deliberate). Positional file-level raise is byte-identical.
- **JETH434-DISAMBIGUABLE**: named-arg emit of an overloaded event rejects even when the key SET
  uniquely selects an overload; the blanket is sound but narrowable.
- **MEMBER-SHADOWS-FILE-EVENT** (JETH353): same-name different-signature member vs file-level event;
  solc shadows with a warning. Sound anti-shadowing reject.
- **MOD-SPECIAL-ENTRY** (JETH386): a @modifier on receive/fallback; solc accepts. Inline the guard.
- **REDUNDANT-MARKER** (JETH385/386, test-pinned): `receive(): Payable<void>` / `fallback():
  External<void>` markers are redundant and reject by design.
- **WIDEN-RCVR** (JETH074): an attached call on a receiver narrower than the lib fn's first param
  (u8 receiver on a u256 self).
- **STR-ESC-ASTRAL** (JETH420/447): TS `\u{1F600}` code-point and surrogate-pair escapes reject; the
  RAW character is accepted + byte-identical vs solc `unicode"..."` (lone surrogates stay sound
  rejects - no valid-UTF-8 mirror exists).
- **GET-EXTLIB-VIEW** (JETH043): a `get` accessor calling an External<T> (delegatecall) library fn -
  JETH classifies any delegatecall as state-modifying; solc keeps `pure`. Drop `get` (byte-identical).
- **NATIVE-GET-MUT-HEADROOM**: LIFTED (GET-MUT-HEADROOM item). `get f(): View<T>` / `get f(): Pure<T>`
  on a contract get accessor DECLARE the mutability (exactly solc's explicit `view`/`pure`): the
  declared value anchors the override ladder + the ABI stateMutability, so a `@virtual get f():
  View<u256>` with a pure body takes a state-reading override, byte-identical to the solc declared-view
  mirror. A looser-than-declared body rejects (JETH054/055/164 = solc's "declared view/pure but ..."
  TypeErrors); the markers stay get-only (plain method JETH013, field JETH482, #-private/@nonReentrant/
  arity JETH352/260). The inferred-pure base spelling (External<T>) still rejects a view override
  (JETH378) - the headroom opens ONLY via the declared marker. test/get-declared-mutability.test.ts.
- **STRUCT-FIELD-LENGTH** (JETH202): a struct field literally named `length` cannot be read (the
  .length builtin check fires first); solc allows it.
- **SPECIAL-NAME-METHOD** (JETH386/384/084): an ordinary external method NAMED receive/fallback is
  rejected by the special-entry gates (solc: plain function + warning). Deliberate-protective.
- **COMMA-FORUPDATE** (JETH073): a comma expression in a for-update clause (no solc comma operator;
  parity-debatable).

**RESOLVED (JETH483, parity reject):** the formerly-OPEN over-acceptance - a non-`abstract` base class
carrying a bodyless `@virtual` member (plain method, `get` accessor, or receive/fallback special
entry) plus an implemented `@override` in the deployed entry - now rejects, matching solc's
'Contract "B" should be marked as abstract.'. Enforced two ways: (1) a syntactic declarer rule (ANY
non-abstract contract-kind class declaring a bodyless method/get fires JETH483 at the member), and
(2) an inherited rule (a non-abstract class anywhere in the chain - a MIDDLE included - whose own
view leaves an inherited bodyless member, getter-var overrides honored, or a bodyless special entry
unimplemented fires JETH483 at the class), both witnessed vs solc per shape. As FIRST landed, the
inherited rule walked only CONTRACT-declared version groups; an INTERFACE-declared obligation was
enforced at the deployed leaf alone (JETH385), so an implementing leaf still masked a non-abstract
middle over a native `interface` base (the JETH483-IFACE-MIDDLE residual, verify-found). The rule
now also covers interface obligations: for each non-abstract class X above the leaf, every method of
every interface in X's own view (direct base, an `interface B extends A` UNION obligation, a
multi-interface heritage, diamond siblings each on their own row) must be satisfied at-or-above X by
a bodied function, a validated `@override x: Visible<T>` getter var, or a plain `Visible<T>` state
var whose auto-getter matches - else JETH483 (in enforceInterfaceImplementation), witnessed vs solc
per shape including the View-getter flavor and a getter-var impl declared only at the leaf. The
legal abstract idiom (`abstract class` declarer + implementing leaf, abstract middles) stays
accepted byte-identical. Regression: test/abstract-required-bodyless-virtual.test.ts.

Also confirmed in passing (safe, pre-existing): the JETH387 receive/fallback internal-call gate and
the batch-C funcRefCall ordering are unregressed; solc-legacy stack-too-deep at 40 params is a
LEGACY-WALL where JETH is strictly more capable (documented in distinctive-features section 4).
