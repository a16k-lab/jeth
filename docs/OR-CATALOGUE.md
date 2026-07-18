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

CURRENT STATE (live-audited 2026-07-18 @ HEAD `13ac6c8`). The complete Group B "must stay" set is SEVEN
rejects - the SIX rows in the table below PLUS **LT5** (stored funcref pushed to storage, JETH217; documented
in full in the 2026-07-08 long-tail section, not repeated here). Of the seven:
- **Whole shape still rejects (4):** B-21 (JETH900), L6 (JETH429), REC-STRUCT-MEMLOCAL (JETH495), LT5 (JETH217).
- **RESIDUAL only - the easy subset was LIFTED this session, the hard subset rejects (3):** L7(a) escaping
  (JETH465; the dead-after pure-literal subset lifted `1ced397`), TERN deeper chain (JETH074; the `Arr<In,N>[]`
  single-fixed-level mixed ternary lifted `af70dc7`), FUNCREF-PURE untrackable sources (JETH055; the
  non-escaping local-struct subset lifted `62c6d50`).
Why each cannot be lifted further: B-21 / L6 / L7a-escaping / TERN-deeper are ONE weakness - solc holds a LIVE
memory reference (or pointer-headed layout) JETH's inline-member layout cannot mirror; closing them = the
~176-site abiHeadWords rework that also regresses gas (B-21/L6 excluded by user ruling; L7a-escaping and
TERN-deeper are coupled to that same rework). LT5 is mathematically unmatchable (JETH stores a dispatch ORDINAL,
solc a code OFFSET - raw storage diverges by construction, like gasleft). FUNCREF-PURE's untrackable sources need
funcref-type-mutability SYNTAX (a design decision, interacts with the JETH498 interface-only-markers ruling).
REC-STRUCT was ATTEMPTED 2026-07-18 and BLOCKED - UNPROVABLE IN ISOLATION (its populated-tree deep-copy source is
UNCONSTRUCTIBLE in JETH; see the row). **NO OPEN LIFT CANDIDATE remains in Group B** - every entry is a proven
miscompile, mathematically unmatchable, or blocked on a feature that cannot ship in isolation.
FULLY LIFTED + RETIRED from this table this session (no longer ORs): L2-MOBILE (`017799b`, #9), A-LIT-RESID
(`790135b`, #10), TERN-STRUCT-ARR dyn `In[]` ternary (`790135b`, #10), TERN-LV-MIX (`55000f0`), trailing-hole
destructure - see the "Retired from this table" note after the table.

| ID | Shape | Code | Why it must stay |
|----|-------|------|------------------|
| B-21 | a fixed STRUCT-array field (`Arr<In,N>`) of a memory struct / struct-array element (`xs[1n].pre`, `s.pre`) through the POINTER channels (internal-arg / element-write / internal-return / 2-hop). VALUE-array field spellings (`Arr<u256,N>`) are LIFTED through internal-arg / internal-return / 2-hop (live-pointer aliasing runtime-verified vs solc, 2026-07-10 audit); their element-WRITE spelling rejects under L6/JETH429, not here | JETH900 | A flat copy would detach from the live memory parent (R3); the FLAT consumers of the same expressions are lifted (L7b) |
| ~~TERN-STRUCT-ARR~~ RESIDUAL LIFTED 2026-07-18 | UPDATED 2026-07-17: the DYN `In[]` ternary was LIFTED at `790135b` (#10; ASYMMETRIC rule, mem arm ALIASED / storage arm DEEP-COPIED, the ternary IS the copy-desugar). **2026-07-18 (`af70dc7`, merged to main): the MIXED fixed/dyn chain `Arr<In,N>[]` ternary (dyn outer of a FIXED static-struct array) is now LIFTED too** - a precise per-shape predicate `isStaticStructFixedElemDynArray` at the two OR-gates, reusing the #10 per-arm lazy lowering; 22 decoded witnesses byte-identical (no raw-pointer 288 leak - the #10 first attempt 628a5bc miscompiled this before `682a71f` fixed the allocator). Admits EXACTLY one fixed level. | JETH074 (deeper only) | *** The DEEPER chain `Arr<Arr<In,2>,2>[]` (two+ fixed levels) STILL REJECTS *** - it leaks a raw pointer (B-21 member-layout family, KEEP-THE-REJECT). Lifted: let-bind / index / element-write / whole-array return / abi.encode, both mem\|storage and storage\|storage arms |
| L6 | `o[0n] = <storage/whole-agg>` writing into an inline value-word element of a nested memory array | JETH429 | The prior-alias witness (solc re-points, an earlier alias keeps OLD values) proves NO RHS source is liftable; a flat layout can only copy |
| L7(a) (RESIDUAL only) | UPDATED 2026-07-18: the DEAD-AFTER PURE-LITERAL subset was LIFTED at `1ced397` (merged to main). When `let a: Arr<In,2> = [literal]` is a compile-time constant and `a` is DEAD after `S1(a, N)` (single structural reference = the capture, via `countLocalRefs===1`), an IR->IR fold (src/yul.ts `liftDeadAggCaptureBodies`) rewrites it to the inline form `S1([literal], N)` VERBATIM, so it is bytecode-sha256-IDENTICAL to the already-accepted inline form BY CONSTRUCTION. The residual that STILL rejects is the ESCAPING subset: `a` read/written/aliased/passed after the ctor (a live reference solc mirrors, a copy cannot), and non-pure-literal inits | JETH465 | The escaping subset is a genuine live-reference miscompile (mutate-after: solc decodes 99 via the alias, a copy=1); ~20 aliasing witnesses stay rejected. Lifting the escaping subset needs the pointer-headed member layout (B-21 family) or an interprocedural mutation analysis + a runtime-only copy - deliberately NOT attempted (the copy-vs-reference family is the highest-miscompile-risk area) |
| LT5 | a funcref pushed to / stored in a STORAGE array (`this.xs.push(Fd(this.inc))`) | JETH217 / JETH210 | Mathematically UNMATCHABLE: JETH stores a dispatch ORDINAL where solc stores a code OFFSET, so the raw STORAGE bytes diverge by construction (same class as `gasleft`). The dispatch RESULT is byte-identical; only the stored raw-storage word diverges. Lifting needs adopting solc's funcref representation wholesale. Full writeup in the 2026-07-08 long-tail section |
| FUNCREF-PURE (RESIDUAL only) | a DECLARED-pure function (native spelling: `static`) calling through a funcref whose SIGNATURE has a state-writing address-taken target elsewhere (dispatcher-set poisoning) rejects JETH055. **2026-07-18 (`62c6d50`, merged to main): the NON-ESCAPING LOCAL-STRUCT-LITERAL subset is now LIFTED** - a funcref field of a local struct literal (`let z: Fd = { f: C.d }; return z.f(v)`, z not reassigned/aliased/passed) is discriminated per-(struct,offset), extending the W5D-2 tracking; completeness by TWO chokepoints (checkLValue for writes rooted at the struct + the bare-identifier chokepoint for every whole-struct value use). CHECK-ONLY (codegen unchanged, byte-identical). The RESIDUAL that still rejects: the UNTRACKABLE sources - a funcref from a PARAM, a STORAGE round-trip, a CALL RESULT, or a reassigned/escaped struct | JETH055 | JETH funcref types carry NO mutability (solc's pointer types do - it needs TWO struct types to hold a pure vs nonpayable pointer, which JETH's single `(x: u256) => u256` cannot express). The untrackable-source residual needs funcref-type-mutability SYNTAX (a design decision, interacts with the JETH498 interface-only-markers ruling). Workarounds (runtime-verified MATCH): plain nonpayable method; or a TRACKED `let` local / now a non-escaping local struct. CORRECTED 2026-07-16: "read state so it infers view" does NOT work (poisoned set has a WRITER -> view as invalid as pure) |
| REC-STRUCT-MEMLOCAL | a RECURSIVE struct (`type P = { x: u256; kids: P[] }`) as a MEMORY LOCAL (`let m: P = this.p`), an uninitialized/ctor local, or an internal `P memory` return. solc lowers `P memory m = p` to an UNBOUNDED RUNTIME-RECURSIVE DEEP COPY of the whole tree (witnessed on a populated 3-level tree: a pointer-headed image at 0x80..0x340 whose size depends on every level's runtime array length; mutating `m` leaves storage untouched). The reject-parity direction (`p = m`, memory->storage) solc ALSO rejects (legacy "Copying of type struct P memory[] memory to storage is not supported"). Pinned in test/lift-recursive-ref-struct.test.ts | JETH495 / JETH074 (was JETH200 pre-2026-07-16; the Group-A targeted diagnostic JETH495 now fires) | JETH's recursive back-edge is a `recursiveRef` EMPTY-FIELDS sentinel (storageSlotCount(sentinel)=1 not 2, isDynamicType=false, abiHeadWords=0, no fields), and JETH has no runtime-recursive struct-copy codegen. Admitting the local would lay out zero/one word per `kids` element and DROP the nested payload (the EXACT MC that reverted REC-STRUCT-CONSUMERS). **2026-07-18 BLOCKED-with-a-stronger-reason (attempted, no code shipped): the lift is UNPROVABLE IN ISOLATION - the bar demands a populated >=3-level storage tree as the deep-copy source, but that tree is UNCONSTRUCTIBLE in JETH: deep storage nav (`this.p.kids[0].x = 20`) rejects JETH210 (the sentinel has no field), and both mem->storage populate paths (`p = m`, `p = P(...)`) reject on BOTH JETH and solc. So `let m = this.p` could only ever copy an empty-kids tree = the VACUOUS probe the bar forbids as evidence. A real lift needs ALSO a storage-side recursive-nav/push subsystem (compiler-wide, same sentinel blocker at ~20+ sites). solc's populated-tree semantics witnessed (10/20/21/30/31); JETH cannot reproduce the seed.** A clean reject beats the miscompile |

Retired from this table (fully LIFTED, no longer ORs; each live-audited): **TERN-LV-MIX** (`55000f0`,
2026-07-10) - the mixed-location ternary-chain lvalue `(c ? this.A : m)[0n].y = v` / `+=` / `++`, solc's
discarded-memory-copy write semantics runtime-verified identical. **L2-MOBILE** (`017799b`, #9, 2026-07-16) -
the CAST+BARE int mix in an array literal (`abi.encode([u8(1n), 300n])`) now self-types to solc's common type
(mobile-seed + commonType fold, order-sensitive, smallest-fit). **A-LIT-RESID** (`790135b`, #10, 2026-07-17) -
the calldata-param branch of a nested ternary `c ? p : [a, b]`, cd->mem copy emitted lazily inside its own arm.
**TERN-STRUCT-ARR dyn `In[]` ternary** (`790135b`, #10) - was a full row, now only its mixed/deeper residual
remains (see the TERN row above).

Parity footnotes (both-reject, never ORs): FIXED-outer cd|storage array-literal element mixes and
cd|storage ternary mixes (solc TypeErrors); oversize state-init literals (JETH065+JETH211).
~~Likely-deliberate singleton: trailing-hole destructure `let [p, ] = g(a, b)` (JETH066+JETH072; TS
parses `[p,]` as 1 element, so JETH sees an arity mismatch; the leading-hole form `let [, q]` is
lifted and byte-identical).~~ **RETIRED 2026-07-17 (STALE ROW): live-audited at HEAD 5d87e86 -
`let [p, ] = this.g(1n, 2n)` ACCEPTS and is byte-identical to solc's `(uint256 p, ) = g(1, 2)`
(run+decode MATCH). Both the leading- AND trailing-hole forms are lifted; the row had never been
retired after the lift.**

### Deliberate DESIGN rejects (footgun / deprecated / no-storage-ref locals): JETH492 / JETH493 / JETH494

Three shapes solc ACCEPTS but JETH intentionally does NOT support - not because a lift would miscompile,
but because each is a deliberate LANGUAGE-DESIGN choice (a USER RULING: never lift). They were given
targeted diagnostics (replacing the generic `JETH074 unsupported expression` catch-all) so a future
exhaustion audit sees them on the deliberate list and never re-flags them as material liftable. Each stays
REJECTED and accepted programs are byte-identical (the diagnostic only reclassifies an already-guaranteed
reject). Regression net: `test/deliberate-reject-diagnostics.test.ts`.

| ID | Shape | Code | Why it must stay (deliberate) |
|----|-------|------|-------------------------------|
| ADDR-TRANSFER-SEND | `<address>.transfer(v)` / `<address>.send(v)` on a PLAIN address/payable receiver | JETH492 | solc's ETH send forwards a FIXED 2300-gas stipend, a known footgun since EIP-1884 repriced SLOAD (a recipient's receive/fallback can then run out of gas). JETH's canonical value transfer is the checked low-level `t.call({ data, value, success })`. RECEIVER-TYPE-GATED (`trialExprType` + `isNominalAddressValue`): a contract/interface-VALUE `.transfer`/`.send` is real external DISPATCH (resolved earlier, byte-identical) and is UNAFFECTED, as are a contract's OWN transfer/send method and a user field/local named transfer/send |
| SELFDESTRUCT | `selfdestruct(a)` (bare or `selfdestruct(payable(a))`) | JETH493 | deprecated; neutered by EIP-6780 (contract self-destruction now only within the same transaction as creation), so it no longer does what code written against the old semantics expects |
| PUSH-NOARG-VALUE | `arr.push()` (no argument) used as a VALUE, e.g. `let r: P = this.arr.push()` | JETH494 | solc returns a STORAGE REFERENCE to the appended element; JETH deliberately has NO storage-reference locals. The no-arg push STATEMENT (append a zero element) IS supported and byte-identical; `arr.push(value)` is the supported value form. Fires for state / mapping-value / struct-field dynamic storage arrays |

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

- **USING-ON-LIBRARY - LIFTED**: `@using(M)` on a `static class` library IS now consumed for that library's
  own bodies (`x.f()` inside library L under `@using(M)` -> `M.f(x, ...)`), matching solc's lexical scoping
  of `using M for T` to the declaring scope (a library counts). Pure resolution layer: the attached form is
  byte-identical JETH-vs-JETH to the explicit `M.f(x)` form, which is already byte-identical to solc.
  buildLibraryAttachments registers a per-library @using map keyed by the library name; ownerUsingAttachments
  serves it via currentLibrary (bodyOwnerContract is undefined in a library body). Guards intact: a contract's
  @using does NOT leak into a library body, one library's @using does NOT leak into another, @using naming a
  non-library rejects (JETH391), an unattached method rejects (JETH074). Regression net:
  `test/using-on-library.test.ts` (11 cells, incl. an external delegatecall library, run+decode + raw storage).
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
- **IFACE-OVERLOADS - LIFTED (2026-07-12)**: a native interface may declare same-name
  different-params overloads (in-body, via `extends`, and across a two-parent diamond of different
  sigs); each overload keeps its own selector, is a per-signature obligation (missing one ->
  JETH385 leaf / JETH483 middle, solc "should be marked as abstract"), and the call site resolves by
  arity then an exact-fit type trial (both-fit = JETH434, no-fit = JETH355/precise arg error, all
  solc "Member not unique / not found after argument-dependent lookup" parity, incl. the u8-widens-
  into-both ambiguity). `type(I).interfaceId` XORs every overload; a bare overloaded member
  reference (`I.f.selector` -> JETH074, `abi.encodeCall(I.f, ...)` -> JETH434) fails closed like
  solc's "Member not unique". A same-name same-params duplicate stays JETH342 (solc "defined
  twice", return type ignored). The same lift closed a PRE-EXISTING OVER-ACCEPTANCE in the same
  machinery: two different signatures in an interface's callable union sharing one 4-byte selector
  (e.g. blockHashAskewLimitary(uint256) / blockHashAddendsInexpansible(uint256), both 0x00000000)
  compiled silently while solc rejects "Function signature hash collision" - now JETH044 (in-body,
  same-name mined pair, and across a chain). Verified by runtime differentials with a solc-authored
  callee + state readback (test/native-interface-overloads.test.ts). The chain rows
  IFACE-CHAIN-REDECLARE (JETH342) / IFACE-CHAIN-TIGHTEN (JETH387) / IFACE-DIAMOND-OVERRIDE-LIST
  same-sig JETH430 are UNCHANGED; the IFACE-CHAIN-OVERLOAD row is lifted by this work.
- **PURE-GET-OBLIGATION - RESOLVED (stale pin; lifted by GET-MUT-HEADROOM `9a77971`)**: the
  recorded shape (`p(): Pure<u256>` obligation implemented by `get p(): Pure<u256>`) ACCEPTS on the
  base and runs byte-equal to the solc mirror; the ladder matches solc exactly (pure impl of a View
  obligation accepts; a view/state-reading impl of a Pure obligation rejects JETH387 = solc
  'changes state mutability from "pure" to "view"'). Pinned in
  test/native-interface-overloads.test.ts (Row B section).
- **TWO-BASE-GET-DIAMOND - LIFTED (2026-07-12, `9a77971`)**: the headline get-form leaf
  `@override(A2, B2)` was ALREADY accepted at the audit base (stale pin); `9a77971` lifted the VAR
  form: a getter var (plain / constant / immutable) with `@override(A2, B2)` unifying a get declared
  by two base contracts (implemented AND bodyless flavors; the base signature group drops out of the
  dispatch/super chains), with per-direct-base contract-head MAXIMALITY so a deep-diamond var
  `@override(M1, M2)` is complete while naming the non-maximal root still rejects (solc parity).
- **JETH477-DEPTH**: expression/statement nesting beyond the compiler's recursion budget (~2000-term
  binary chains cold) is a clean reject; solc compiles. Deliberate robustness boundary.
- **ABSTRACT-METHOD-DECL - LIFTED (2026-07-12)**: the TS `abstract` member modifier on a method /
  `get` accessor (and on `receive`/`fallback`) inside an `abstract class` IS the native spelling of
  the bodyless `@virtual` declaration - byte-identical to the `@virtual` twin across the whole
  matrix (method/get, External/Payable/View/Pure markers, internal bare, string params, abstract
  middles, bodyless-over-bodyless redeclares, diamond `@override(A, B)`, Visible<T> getter-var
  override leaf, special entries; test/abstract-method-decl.test.ts) and runtime-differential-equal
  to the solc mirrors. The pre-lift behavior was the modifier consumed as a plain bodyless member
  (one extra JETH375 over the twin; the get flavor dropped the modifier in synthesis). Both
  spellings coexist (`@virtual` is KEEP-list). New misuse gate **JETH486** (each shape is invalid
  TS whose grammar error the checker - not parseDiagnostics - reports, so JETH must reject
  explicitly): an abstract member WITH a body, `static abstract`, an abstract constructor
  (pre-lift: silently accepted), an abstract FIELD (pre-lift: silently became a state var; the
  obligation form is `abstract get x(): T`), and `abstract` on an interface member (pre-lift:
  silently eaten).
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
  **IFACE-CHAIN-OVERLOAD - LIFTED (2026-07-12, with IFACE-OVERLOADS)**: same name, different params
  across the chain now MERGES into the overload union exactly like solc (in-body overloading landed
  in the same commit; see the IFACE-OVERLOADS row above), and
  **IFACE-DIAMOND-OVERRIDE-LIST** (JETH430: two DISTINCT parents declaring the same signature needs a
  redeclare carrying `override(A, B)`, which a TS interface method cannot spell; solc-reject parity
  for the bare shape, OR only for the unspellable redeclare cell; two parents contributing
  DIFFERENT signatures of one name merge as overloads - lifted, witnessed).
- **MANGLE-INJECT - CLOSED as a bar violation (2026-07-12 live audit)**: the four DECLARATION-collision
  spellings always failed closed (JETH373/434/044/352/065), but the audit found the ACCESS side
  fail-OPEN: a user-written `this.$p$B$x` in a derived class silently bound base B's PRIVATE `#x` for
  READ and WRITE (solc rejects the twin as undeclared) - a `#`-privacy-bypass OVER-ACCEPTANCE, live
  since the mangle pre-pass landed (post-mangle a user spelling is indistinguishable). Fixed the
  fail-closed way: the pre-mangle reserved-identifier scan (the `$m<N>$` guard's home in compile.ts)
  now rejects EVERY user-written `$p$`-prefixed identifier (JETH036), declaration and access sites
  alike. Standalone `$p$C$x` declarations (previously accept-side parity) deliberately became safe
  rejects - a documented OR in exchange for a closed privacy hole. Regression:
  test/private-hash-member.test.ts (reserved-$p$ describe).
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
- **NAMED-RAISE-EXCLUSIVITY** (JETH227/148, CONTRACT body only): a bare file-level named
  `revert(Bad({...}))`/`emit(T({...}))` in a CONTRACT body still rejects - only the member `this.X({...})`
  form is native there (bare object literals mean struct literals - deliberate). Positional file-level raise
  is byte-identical. LIFTED inside a LIBRARY body: see FILE-LEVEL-NAMEDARG-IN-LIB below.
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

**DUP-BODYLESS-VIRTUAL - CLOSED (2026-07-12, `b322386`):** a same-class duplicate signature
involving a bodyless declaration (identical `@virtual` pair, TS `abstract` pair, MIXED pair,
bodyless+concrete either order, bodyless get pair, triple, and a middle-class-of-chain pair) was
silently accepted byte-identical to the single declaration - a bodyless declaration never became a
FunctionIR, so the concrete-duplicate JETH044 check never saw it. Now every flavor rejects JETH044
with the concrete-duplicate message shape (solc-witnessed: DeclarationError "Function with same name
and parameter types defined twice"). Distinct-signature overloads, cross-class chain redeclaration,
interface implementations, and diamond shared-root/sibling declarers all stay accepting,
byte-identical (test/dup-bodyless-virtual.test.ts).

## 2026-07-12 LIVE AUDIT (post native-only removal, HEAD b8b7ae8 -> fix): 34 rows / 9 clusters re-probed

Every still-open row reconstructed in native syntax and differential-checked vs solc 0.8.35. One bar
violation found + FIXED; three rows were stale pins (already lifted); two need one-line text
precision. All other rows INTACT.

**BAR VIOLATION FOUND + FIXED - MANGLE-INJECT (over-acceptance / `#`-privacy bypass):** a user-written
identifier spelled like the private mangle product (`this.$p$B$x` in a class `C extends B`) silently
bound base `B`'s private `#x` for READ and WRITE - solc rejects the twin as an undeclared identifier.
Root cause: `manglePrivateMembers` (the `#x` -> `$p$C$x` pre-pass) made a user-written `$p$...` token
indistinguishable from a real mangle afterward, and the existing guards only covered declaration
collisions (JETH373/434/044) and ABI exposure (JETH352/065), never the access site. FIXED by extending
`rejectReservedModuleIdentifiers` (compile.ts, already reserving the `$m<N>$` module prefix PRE-rename)
to also reject any user-written `$p$`-prefixed identifier, declaration and access sites alike - fail
closed everywhere. Regression: test/private-hash-member.test.ts ("reserved $p$ prefix fails closed").
Suite 4219 green.

**STALE PINS (already lifted by `69afb58` / `ea98210`, the 2026-07-08 cluster-3 lift; catalogue header
L23 recorded the lift but the older "REMAINING over-rejections" narrative L205-212 kept the old rows):**
- **CD-BYTE-ACCESS** - the calldata read `xs[i].b[j]` ACCEPTS + runtime byte-identical (incl. both OOB
  Panic axes). The calldata WRITE is a parity both-reject (JETH151; solc: calldata is read-only), not
  an OR - reclassify.
- **FUNCREF-ELEM-LOCAL** - `let e: Fd = a[i]; e.f(v)` and `(c ? a[0n] : a[1n]).f(v)` both ACCEPT +
  byte-identical (incl. mixed value+funcref field elements).
- **TAGS-JK** - `xs[i].tags[j][k]` on a memory struct-array element ACCEPTS read AND write,
  byte-identical (the calldata twin was lifted separately at `ea98210`).

**PRECISION CORRECTIONS (row stands, text should tighten):**
- **FIELD-INIT-NS** - only a string/bytes-LITERAL initializer on a `@storage(ns)` field rejects
  (JETH048); a CONSTANT scalar initializer (`@storage('ns') x: u256 = 5n`) has ALWAYS accepted and is
  runtime-identical to the ERC-7201 twin. Narrow the row to "string/bytes-literal initializer".
- **JETH434-DISAMBIGUABLE** - the row claims solc has no named-arg emit; solc 0.8.35 DOES
  (`emit E({...})`) and resolves overloads by key set / arg types. So this is a genuine OR vs solc,
  not a JETH-only ergonomic row - upgrade the framing (strengthens the lift case).

**INTACT rows re-confirmed (all clean rejects, solc accepts, verified workaround; grouped by lift value):**
- LIFT-CANDIDATES (solc accepts, a byte-identical path is plausible): FIELD-INIT-EXPR (non-literal
  field initializers via the implicit-ctor desugar), LIB-CONST / LIB-MEMBER-EVENT / LIB-MEMBER-ERROR
  (library-scoped constants + member events/errors; the file-level workaround proves the lowering is
  byte-identical), BYTES-CONST (add `bytes` to the constant whitelist), USING-ON-LIBRARY (@using inside
  a library body), GET-EXTLIB-VIEW (a read-only External-lib call surface), RECEIVE-INTERNAL-CALL
  (internal calls from receive/fallback), GET-PROPERTY-READ (property-syntax read of an argless get),
  PAREN-CALLEE (peel a parenthesized callee), DEFAULT-ARG-CONST (fold `C.K` at a default-arg site),
  JETH434-DISAMBIGUABLE (unique-key-set named-arg emit).
- DELIBERATE / parity (must stay): CONST-FWD-REF, WIDEN-RCVR, MOD-SPECIAL-ENTRY, SPECIAL-NAME-METHOD,
  IFACE-CHAIN-REDECLARE, IFACE-CHAIN-TIGHTEN (loosening half is parity), IFACE-DIAMOND-OVERRIDE-LIST
  (bare shape both-rejects; only the unspellable-redeclare cell is the OR), STRUCT-FIELD-LENGTH,
  IMM-INIT-SHADOW, NAMED-RAISE-EXCLUSIVITY, MEMBER-SHADOWS-FILE-EVENT, STR-ESC-ASTRAL (escapes; raw
  char lifted), JETH477-DEPTH (robustness boundary), LT5 (stored-funcref raw-storage divergence),
  COMMA-FORUPDATE (parity both-reject - Solidity has no comma operator).
- CONTROLS (post native-only sanity): keep-list decorators (@using/@modifier/@virtual/@override) and
  get call-syntax all unregressed, zero spurious JETH481.

## 2026-07-13 SMALL-CLUSTER LIFT (top 4 from the 2026-07-12 audit, HEAD 42dd241, suite 453/4229)

Four small over-rejections lifted, each byte-identical to solc 0.8.35 (or to its own call/literal twin
where solc has no spelling), verified by a 4-lens 458-case adversarial workflow (bytes-const /
paren-callee / default+getprop / cross-fuzz). Regression: test/lift-cluster-small-four.test.ts.

- **BYTES-CONST - LIFTED**: a `bytes`-typed constant `static B: bytes = "ab"` / `bytes("ab")` /
  `abi.encodePacked(...)` now compiles (was JETH050). Stored as a byte payload via `constByteString`;
  every read materializes a fresh memory bytes through the SAME `stringLiteral` IR the string-constant
  path uses (string and bytes share one in-memory ABI), so the getter / keccak / concat / encode parity
  already proven for string constants carries over. No UTF-8 constraint (unlike `string`). Residual
  clean rejects (both a bytes VALUE also rejects, so not bytes-const-specific): direct index of the
  const `C.B[i]` (bind a local first) and `abi.encodePacked(<non-string-literal>)` in the initializer.
- **PAREN-CALLEE - LIFTED (narrowed)**: a parenthesized DIRECT callee `(this.f)(v)` / `(C.f)(v)` /
  `(L.f)(v)` / `((this.f))(v)` now compiles (was JETH074) by peeling the parens and re-checking. NARROWED
  to solc parity (parenCalleeDiverges): `(payable)(x)` (a mutability keyword, solc ParserError) and an
  OVERLOADED `(g)(v)` (parenthesizing forces a value lookup with no unique function type - solc: "No
  matching declaration after variable lookup" / "Member not unique") stay a clean JETH074 reject. Both
  were over-acceptances the adversarial sweep caught + fixed BEFORE the commit landed. Elementary-type
  casts `(u8)(x)` (byte-identical to `u8(x)`) and funcref-ternary callees `(c?a:b)(v)` still work.
- **DEFAULT-ARG-CONST - LIFTED**: a value-type constant as an internal-fn default param `add(a: u256,
  b: u256 = C.K)` now compiles (was JETH250), byte-identical to the literal-default twin. Only the
  property form `this.K` (the spelling `C.K` becomes `this.K` pre-analysis) - caller-independent. A STATE
  var default, an IMMUTABLE default, and a bare-identifier default `= K` all still reject JETH250 (they
  would introduce a caller-scope dependency); a non-value-type (bytes/string/struct) default stays
  JETH252/050.
- **GET-PROPERTY-READ - LIFTED**: an argless `get x()` accessor read as a PROPERTY `this.x` now compiles
  and is byte-identical to the call `this.x()` (was JETH065), same-class and inherited, with virtual/
  override dispatch and mutability enforced identically. A getter WITH params, a plain (non-get) method,
  a genuinely unknown name, and an lvalue `this.x = v` all still reject JETH065. Residual clean reject:
  field access on the property form `this.pp.a` where `pp` is a struct-returning getter (bind a local
  first; the local-bind is accepted byte-identical) - a pure routing gap, not a bar violation.

LESSON (re-affirmed): a syntactic peel/desugar is only "pure grouping" for the shapes solc also treats
as grouping - a parenthesized OVERLOADED name and a mutability keyword are NOT, so the peel needed a
solc-parity divergence gate. The adversarial sweep caught both over-acceptances before they shipped;
the other three lifts were clean across all 458 cases.

## 2026-07-13 LIBRARY-DECLARATIONS LIFT (LIB-CONST / LIB-MEMBER-EVENT / LIB-MEMBER-ERROR, HEAD eb7b1ec, suite 454/4238)

A `static class` library may now declare constants, events, and errors (solc parity), all PER-LIBRARY
scoped (proven necessary against solc: a global table would both over-reject two libraries sharing a
name and over-accept a bare name resolving cross-scope). Investigated by a 3-agent probe-backed
planning workflow, verified by a 4-lens 307-case adversarial workflow. Regression:
test/lib-member-decls.test.ts.

- **LIB-CONST - LIFTED**: `static K: T = <literal>` (value / string / bytes) in a library, read as `L.K`
  from a contract fn and bare `K` inside the library (a local/param shadows it); no storage slot, no
  getter (folded literal, byte-identical to solc `library L { T internal constant K = v; }`). Reused the
  extracted foldConstantField (identical fold + diagnostics) + a per-library table.
- **LIB-MEMBER-ERROR - LIFTED**: `Bad: error<{...}>` raised bare `revert(Bad(a))` / `require(cond,
  Bad(a))` inside the library and qualified `revert(L.Bad(a))` from a contract; revert selector + data
  byte-identical to solc (bare-signature keccak, scope-independent), internal + external(delegatecall).
- **LIB-MEMBER-EVENT - LIFTED**: `E: event<{...}>` emitted `emit(E(a))` inside the library; logs
  (topic0 + indexed topics + data + emitter address under delegatecall) byte-identical to solc.
  RESIDUAL clean over-rejection (deferred): qualified `emit(L.E(a))` from a CONTRACT rejects JETH146
  (the error qualified form is supported; the event one needs emit-site surgery - bind via a lib fn).

Closes TWO pre-existing over-acceptances the scoping exposed: a lib fn raising/emitting a bare CONTRACT
decl now rejects (JETH129 / JETH147) - a library cannot see a contract's errors/events (solc parity).

The 307-case sweep found + FIXED three over-acceptances the lifts opened (all scope/declaration gaps,
none touching the byte-identical lowering): (1) a CROSS-KIND name collision in a library (a const/fn/
event/error sharing a name) is now JETH133, mirroring the contract path (a library has one member
namespace); (2) an EVENT SCOPE LEAK where a lib fn bound a same-named CONTRACT event overload through
the file-level fallback (eventsByName mixes file-level + contract overloads under one name) - now
filtered to file-level-only via an EventIR.fileLevel tag; (3) a QUALIFIED-ERROR SHADOW where
`revert(L.Bad(a))` ignored a param/local/state var shadowing the library name - now guarded with
!isVisibleLocal / !stateByName, matching the constant-read and library-call siblings.

LESSON (re-affirmed): a new declaration namespace needs the SAME cross-kind + shadow + scope discipline
the existing (contract) path already enforces; the per-library maps handled scoping but each new lookup
site (fallback filter, qualified-raise guard, cross-namespace dedup) had to be checked against solc
independently. The adversarial sweep caught all three before they shipped; every runtime path was
byte-identical across the four lenses.

## 2026-07-13 LIVE AUDIT (29 rows re-probed at HEAD e649cc6, 0 regressions/miscompiles)

Confirmed RETIRED (now accept, byte-identical to solc): BYTES-CONST, PAREN-CALLEE (guards intact:
overloaded/`payable` still reject), DEFAULT-ARG-CONST (state/immutable/bare defaults still reject),
GET-PROPERTY-READ, LIB-CONST, LIB-MEMBER-ERROR, LIB-MEMBER-EVENT. MANGLE-INJECT confirmed CLOSED
(this.$p$B$x rejects JETH036 at decl + access; parity both-reject).

Additional STALE rows the audit found already-lifted (catalogue text was behind):
- **USING-ON-LIBRARY - NOW LIFTED** (`@using(M)` inside a static-class library body accepts, runtime +
  bytecode byte-identical - see the LIFTED entry above). CORRECTION: this row previously claimed the
  `@using(M)` case was already lifted; it was not - only the native SELF-CONVENTION (a first param named
  `self`, no `@using`, a JETH-only superset ergonomic) worked file-wide, while an EXPLICIT `@using(M)` on a
  library body still rejected JETH074 at the base. The `@using(M)` resolution inside a library body is lifted
  by extending the per-class @using ownership maps to register a library as an owner. A NON-`self` first param
  without `@using` still correctly rejects JETH074 (no global attachment leak), unchanged.
- **IMM-INIT-SHADOW - already LIFTED** (a ctor param/local named like the contract class binds the
  local; runtime byte-identical incl. the wrong-bind trap - reads the local, not a same-named static).
- **MEMBER-SHADOWS-FILE-EVENT - different-signature case LIFTED** (a member event shadows a same-named
  file-level event; emit resolves to the member, topic0 verified). RESIDUAL still INTACT: a SAME-signature
  member event vs file-level event rejects JETH144 (solc shadows same-sig too).

**Current genuinely-liftable ORs (solc accepts, byte-identical path plausible):** LIB-EVENT-QUALIFIED
(qualified `emit(L.E(a))` from a contract, JETH146 - smallest, mirror the working `revert(L.Bad(a))`),
JETH434-DISAMBIGUABLE (unique-key-set named-arg emit, JETH434), RECEIVE-INTERNAL-CALL (internal call
from receive/fallback, JETH387), STRUCT-FIELD-LENGTH (a struct field named `length`, JETH202 - small +
safe), FIELD-INIT-EXPR (non-literal state-field initializer, JETH048), FIELD-INIT-NS (@storage(ns)
string/bytes literal init, JETH048), GET-EXTLIB-VIEW (a get calling a view external-lib fn, JETH043),
MEMBER-SHADOWS-FILE-EVENT same-sig residual (JETH144), and the interface-chain redeclare/tighten rows
(JETH342/JETH387, deliberate-leaning). Deliberate/parity keeps (unchanged, sound): FUNCREF-PURE,
L2-MOBILE (cast+bare mix), L6, L7a, B-21 (the pointer-headed fixed-array layout family), STR-ESC-ASTRAL,
MOD-SPECIAL-ENTRY, NAMED-RAISE-EXCLUSIVITY, LT5, trailing-hole destructure; COMMA-FORUPDATE is a parity
both-reject (not an OR).

## 2026-07-14 LIFT-ALL-LIFTABLE CAMPAIGN (9 ORs lifted; 3 fresh bar violations found + fixed; suite 455/4250)

Lifted all 9 genuinely-liftable ORs from the 2026-07-13 audit, then ran an adversarial verification
sweep (4 finders x solc-differential + verify) over the change surface. The sweep found THREE bar
violations no incremental work caught - two INTRODUCED by lifts in this same campaign, one PRE-EXISTING
that a lift newly exposed. All three fixed; bar (0 MC / 0 OA) re-proven.

**LIFTED (byte-identical to solc 0.8.35, tests in test/lift-all-or-cluster.test.ts unless noted):**
- **STRUCT-FIELD-LENGTH** (was JETH202): a struct field named `length` reads the field, not the array
  builtin. Guarded by a side-effect-free `declaredExprType` (NOT a trial-type - see LESSON below).
- **LIB-EVENT-QUALIFIED** (was JETH146): `emit(L.E(a))` from a contract resolves L's per-library event.
- **JETH434-DISAMBIGUABLE**: a named-arg emit of an OVERLOADED member event disambiguates by key set
  (0 match -> JETH130, 1 -> force+reorder, >1 -> JETH434) via a `forcedEmitEvent` hand-off.
- **RECEIVE-INTERNAL-CALL** (was JETH387): `receive()`/`fallback()` may call internal helpers.
- **FIELD-INIT-EXPR** (was JETH048): a PROVABLY-ORDER-INDEPENDENT string/bytes state-field init
  (literals, templates whose `${}` spans are all literals, literal concats) routes through the ctor-top
  desugar. See the MC finding below - the lifted set was NARROWED after the sweep.
- **FIELD-INIT-NS** (was JETH048): a `@storage(ns)` string/bytes LITERAL init (same guard).
- **GET-EXTLIB-VIEW** (was JETH043): a `get` accessor may call a pure/view external-lib fn (a new
  `currentIsGetter` defers the eager conservative write to the purity fixpoint for getters only).
- **IFACE-CHAIN-REDECLARE / IFACE-CHAIN-TIGHTEN** (were JETH342/JETH387): an identical interface method
  redeclare across an extends-chain is a no-op; a mutability TIGHTEN (payable>nonpayable>view>pure)
  accepts unless it crosses the payable boundary. Tests in native-interface-{overloads,extends-interface}.

**BAR VIOLATIONS the sweep found + fixed (the reason the sweep exists):**
1. **FIELD-INIT-EXPR MISCOMPILE** (introduced by this campaign's FIELD-INIT lift): `s: string = mk()`
   where `mk()` is a bare internal call reading a LATER const-folded value-type field - JETH baked the
   folded value into the deploy image (reads 42), solc runs declaration-order (mk() reads 0). The first
   guard (`!exprAccessesThisMember`) was SYNTACTIC-only and missed the indirect state read through the
   call. FIX: replaced with `isOrderIndependentInit` - the init must be built ONLY from literals/
   templates-with-literal-spans/literal-concats (reads nothing, calls nothing), so ctor-top vs inline is
   value-identical. A cast `bytes("a")` (order-independent but a call) is now a SAFE over-rejection.
2. **LIB-SHADOW OVER-ACCEPTANCE family** (introduced/widened by the library-declaration + qualified-emit
   work): a contract member named like a library L shadows it in solc (`L.x` becomes member access on
   that value -> "Member x not found"), so solc REJECTS. JETH accepted for CONSTANT / IMMUTABLE / METHOD
   shadows across every member kind (internal call / ext-delegatecall call / const read / event / error
   / funcref). FIX: one shared `libraryBindsInScope(name)` guard (state + constant + immutable + local +
   contract-method via `candidatesByName`) routed through ALL ~9 library-value-resolution sites; the
   method axis was the sweep's confirmed find. A param/local/state shadow already rejected; type/interface
   name-collisions reject at declaration in both (parity). Unshadowed `L.x` still binds (controls pinned).
3. **LIB-CALLVALUE MISCOMPILE** (PRE-EXISTING; the RECEIVE-INTERNAL-CALL lift newly exposed it on the
   receive path): a value-bearing caller (receive / payable fn / payable fallback / payable ctor) that
   DELEGATECALLs a non-payable external library fn reverted, because the LIBRARY OBJECT's runtime
   dispatcher emitted the non-payable `if callvalue() { revert }` guard. A delegatecall inherits the
   caller's callvalue and solc's library dispatchers carry NO such guard, so solc succeeds - JETH
   reverted (confirmed via linked harness: solc total=6/8, JETH revert). Reachable pre-lift via a plain
   payable fn too. FIX: `emittingLibraryObject` flag suppresses the runtime-dispatch callvalue guard for
   library objects (src/yul.ts). Regression test in test/library-external.test.ts (receive + payable fn +
   payable fallback, value sent, byte-identical to solc). The CONTRACT dispatcher guard is untouched
   (a non-payable contract fn / receive-less contract still reverts on value - verified).

**NEW sound over-rejections found (fail closed; catalogued, NOT lifted this round):**
- **FALLBACK-EXTERNAL-MARKER** (JETH386): `fallback(input: bytes): External<bytes>` rejects; solc accepts
  a returning fallback. DELIBERATE keep - a fallback is not an ABI function reached by a selector, so the
  `External<T>` marker is meaningless on it; the working native form is `fallback(input: bytes): bytes`
  (bare return), which JETH already accepts. solc has no External<T> marker concept, so nothing to match.
- **LIB-EVENT-NAMEDARG / LIB-NAMEDARG - LIFTED** (was JETH148 event / JETH130 error): a NAMED-argument
  raise `{ name: value }` of a LIBRARY-scoped event/error now reorders the keys to the declaration's param
  order and lowers through the positional path, byte-identical to the positional twin. Covers the qualified
  `emit(L.E({...}))` / `revert(L.Bad({...}))` (inside a lib fn AND from a contract) and the bare
  `emit(E({...}))` / `revert(Bad({...}))` inside the owning library; event overloads disambiguate by key
  set (JETH434 residual unchanged). Root cause was a wiring gap: the named-arg reorder lived only in the
  `this.X` desugar; the qualified/bare library entry points passed the object literal straight to the
  arity check. FIX: a shared `reorderNamedRaiseArgs` reached from the `this.X` desugar, the `checkEmit`
  library-event path, and the `checkRevertReason` / `LIB-MEMBER-ERROR` library-error paths. NON-library
  named raises are UNCHANGED: a contract's own event/error bare-named raise still rejects (only `this.E`
  is native), and `this.E` inside a library stays a correct both-reject (solc: "Member E not found in
  library L", JETH394). Verified byte-identical (logs + revert data) across scrambled key orders, indexed
  + non-indexed fields, and overloaded events.
- **FILE-LEVEL-NAMEDARG-IN-LIB - LIFTED** (was JETH148 event / JETH130 error): a bare NAMED-argument raise
  `emit(Ev({...}))` / `revert(Bad({...}))` of a FILE-LEVEL event/error (`type X = event<{...}>` /
  `error<{...}>`) inside a LIBRARY body now reorders the keys to the declaration's param order and lowers
  through the positional path, byte-identical to the positional twin (verified: logs + revert data across
  scrambled key orders, indexed / all-indexed / dynamic-string fields, forwarded through a contract call).
  Extends the LIB-EVENT-NAMEDARG lift: `checkEmit`'s reorder gate now fires for a file-level event inside a
  library (`fileLevelErrorEvents.has(evName)`), and the `checkRevertReason` library-error block resolves the
  decl via `resolveErrorDeclInScope` (library-own OR file-level) instead of the library-own table alone.
  A bare file-level named raise in a CONTRACT body is UNCHANGED (still NAMED-RAISE-EXCLUSIVITY); positional
  file-level-in-lib and the library-scoped named raise are untouched; unknown-key / wrong-arity / duplicate-key
  reject at solc parity (JETH130); a single-struct-param event with field-name keys stays a both-reject (no
  over-acceptance). Regression: test/lib-member-decls.test.ts (FILE-LEVEL-NAMEDARG-IN-LIB describe).
- **LIB-CREATION-VALUE** (out of scope): deploying a standalone external-library OBJECT with value reverts
  in JETH (creation-code callvalue guard) while solc's library creation accepts value. Library objects are
  not asserted byte-identical to solc (different runtime), no JETH source construct controls this, and the
  observable delegatecall behavior (fixed above) IS byte-identical. Pre-existing deployment-tooling edge.

**LESSONS:** (1) a syntactic `this.member` guard cannot prove order-independence - a bare internal CALL
reads state indirectly; require the init to read/call NOTHING. (2) A shadow rule must be a SINGLE shared
predicate hit by every resolution site (call/const/event/error/funcref, statement + value position); the
sweep found the one axis - contract methods - that per-site guards had all missed. (3) A library object
is DELEGATECALLed and inherits caller callvalue: its dispatcher must omit the non-payable guard, or every
value-bearing caller into a library miscompiles. (4) A side-effecting trial-type at a hot generic site
(every `.length`) leaks analyzer state cross-file under isolate:false - use a side-effect-free resolver.

## 2026-07-14 WHOLE-SURFACE HARD AUDIT (16 surfaces, 45 agents, ~120 verified probes; 6 OA fixed, 1 MC-candidate = documented deviation, 17 sound ORs)

A 16-surface adversarial audit (each surface: a solc-differential finder + per-finding adversarial verify)
of value-types/ops, control-flow, functions/mutability, inheritance/C3, storage, memory/calldata, structs,
arrays, events/errors, abi, libraries, interfaces, low-level/crypto, proxies/diamonds, native-syntax,
robustness. Coverage was deep and byte-verified (deploy-both + compare returndata/logs/state/raw-slots):
control-flow (1000+ probes, 0 divergences), inheritance/C3 (750+, incl. 253-case diamond + 250-case storage
fuzzers), storage (90, raw-slot + residue), abi (100+, 0 divergences), events/errors (2 fuzzers, 246 cases),
low-level/crypto (all precompiles + ecrecover vectors), all clean. 24 divergences confirmed - 6 real OA
(fixed), 1 MC-candidate that turned out to be a documented deviation (JETH matches viaIR semantics), 17 sound
ORs:

**6 OVER-ACCEPTANCES FIXED (bar violations; test/audit-hardening.test.ts):**
- **ARR-SIZE-ALIAS**: `let b: Arr<u256,3> = a` where a is Arr<u256,2> (same element type) - solc rejects as
  non-convertible; JETH aliased the shorter image, so `b[2]` read PAST it (an OOB adjacent-memory leak, a
  memory-safety OA). Fixed: the fixed-array localDecl init now guards the source LENGTH (JETH085), not just
  the element type (src/analyzer.ts checkLocalDecl value-word branch).
- **LIB-RECEIVE / LIB-FALLBACK**: a native `receive()`/`fallback()` (a method literally named receive/fallback)
  inside a `static class L` - solc: "Libraries cannot have receive/fallback ether functions." The decorator-
  only ban missed the bare native form; fixed with a member-name gate in the library member loop (JETH390).
- **LIB-VIRTUAL / LIB-OVERRIDE**: `@virtual`/`@override` on a library function - solc rejects (a library cannot
  be inherited). Added both to the library banned-decorator list (JETH390).
- **DECO-SHAPE-DROP**: a decorator in a non-identifier shape (`@a.nonReentrant` property-access) on a METHOD
  was SILENTLY DROPPED - a `@a.nonReentrant`/`@storag` typo of `@nonReentrant` yielded an UNGUARDED contract
  with zero diagnostics (a silently stripped reentrancy guard). Fixed: decoratorNames unwraps parens + surfaces
  non-standard shapes; the modifier-application collector routes an unknown shape to the resolver -> JETH329.
  `@(nonReentrant)` (paren) now correctly APPLIES the guard (byte-verified == bare `@nonReentrant`). RESIDUAL
  (lower severity, not a solc differential - JETH-only decorators have no mirror): a decorator on a CLASS
  (`@storag`), FIELD, or PARAM position is still silently dropped; a hardening follow-up should reject any
  decorator outside the position's keep-list.

**1 "MISCOMPILE" candidate - RESOLVED as a DOCUMENTED KNOWN DEVIATION (not a bug; no action):**
- **FUNCREF-EQ**: `p == q` / `p != q` on two INTERNAL function pointers whose target functions have BYTE-
  IDENTICAL bodies (e.g. `a(){return 7n}` and `b(){return 7n}`). The audit's finder diffed against the
  differential harness's reference (solc legacy optimizer ON, runs 200) and saw JETH `false` vs solc `true`,
  flagging an MC. But this is the ALREADY-DOCUMENTED deviation in docs/distinctive-features.md section 6 /
  test/internal-fn-pointers.test.ts:246. Empirically (2026-07-14, 4-config probe) JETH's `false` matches solc
  in 3 of 4 configs - optimizer-OFF, viaIR+optimizer-ON, and viaIR+optimizer-OFF all return `false`; ONLY the
  legacy-optimizer-ON config returns `true`, because its ASSEMBLY-BLOCK DEDUPLICATOR collapses the two
  identical bodies onto one jump tag so the pointers collide. That is a legacy-optimizer ARTIFACT, not language
  semantics: viaIR (solc's present/future codegen) agrees with JETH. JETH never returns semantically-wrong
  bytes, and CALLS through such pointers dispatch byte-identically in every config. Making JETH return `true`
  would (a) require replicating the legacy assembly deduplicator - infeasible without solc's optimizer (solc
  folds `3+4`->7 and normalizes `x+1`==`1+x`, which JETH cannot see at pre-optimization id-assignment time),
  and (b) make JETH DIVERGE from viaIR semantics. So it is left AS-IS by deliberate, documented choice - the
  semantically-correct value. NOT a bar violation. (The funcref machinery is behaviorally-equivalent, not
  byte-identical, to solc anyway - JETH uses integer dispatch ids + a switch, solc uses code offsets.)

**17 SOUND OVER-REJECTIONS (fail-closed, clean diagnostic; catalogued for future lift, none a bar violation):**
value-types: SHIFT-ASSIGN-SIGNED-LIT (`i256 >>= 1n` bare literal, JETH081). functions: GET-SELF-VIEWCALL (a
`get` doing `this.g()` to a view external, JETH043 - the self message-call flavor of GET-EXTLIB-VIEW not yet
extended); QUALIFIED-SELECTOR (`C.g.selector`/`I.g.selector`, JETH074/013 - only `this.g.selector` works).
structs: RECURSIVE-REF-STRUCT was LIFTED (see below - two-phase struct registration + `recursiveRef`
sentinel; storage var + static-value-leaf byte-identical, ABI/memory/kids-codec consumers still reject).
arrays: UNINIT-ARRAY-LOCAL (`let a: Arr<u256,3>;`, JETH200 - solc
zero-inits); ARRLIT-DIRECT-INDEX (`[a,b,c][i]`, JETH151 - bind-to-local works). events: CONTRACT-TYPE-PARAM (a
contract/interface-typed event/error/getter param, JETH041/013 - solc lowers it to `address`). libraries:
LIB-CONST-IN-CONST (`static M = L.K + 1n`, JETH048 - a library constant is not foldable into another
constant's init); LIB-MODIFIER - **LIFTED** (`@modifier` in a library: registered under a qualified `L.name`
key + threaded through the existing modifier-application machinery, expanding at the library-fn definition
site; concrete only, generic/@virtual/@override deferred; see the 2026-07-14 LIB-MODIFIER section below).
interfaces: IFACE-VALUE-TYPE (an interface
name as a field/param/return/self-ref value type, JETH013 - only `I(addr).m()` inline works); IFACE-EVENT-MEMBER
+ IFACE-ERROR-MEMBER (`E: event<{...}>`/`Bad: error<{...}>` in an interface, JETH341); TYPED-CATCH (`catch
Error(string)`/`catch Panic(uint)`, JETH074/361 - `catch (e: bytes)` works). native-syntax: CONST-ARRAY-DIM
(`Arr<u256, N>` with a static-constant N, JETH012); ABSTRACT-ONLY-FILE (a file whose only class is abstract,
JETH040); MULTI-CONTRACT-FILE (more than one deployable class per file, JETH041 - documented MVP limit).

Two surfaces (memory-calldata, proxies-diamonds) returned no confirmed findings; their diamond `_init`
degenerate-revert-reason candidate was REFUTED (JETH-only generator, no solc program to be identical to).
LESSONS: a decorator collector that reads only identifier/call shapes silently DROPS a mis-shaped decorator
(surface every shape, reject the unknown); a memory-alias local-decl must guard the fixed LENGTH, not just the
element type, or an in-bounds index reads OOB; a library-context validation gate must cover the NATIVE special-
entry name (receive/fallback), not only the decorator form.

### 2026-07-14 OR-TRIAGE + 8 LIFTS (of the 17 above; each re-probed on main + checked vs tests/docs/commits first)

Per the user, EVERY one of the 17 was triaged against the current codebase BEFORE lifting (a 16-agent
workflow re-probing solc parity + grepping test/docs/git): none was already-fixed; 2 are deliberate rejects;
8 were genuinely open + byte-identically liftable and are LIFTED; 6 are LIFTABLE-HARD/low-value and KEPT.
Regression suite test/lift-audit-ors.test.ts (deploy-both byte/behaviour diff per row). Suite 457/4260.

**8 LIFTED byte-identical:**
- **SHIFT-ASSIGN-SIGNED-LIT** (JETH081->accept): `i256 >>= 1n`. The shift AMOUNT is now typed by itself, not
  the LHS (4 compound-assign sites), exactly as the already-accepted `a >> 1n`. Signed-VARIABLE amount still JETH081.
- **UNINIT-ARRAY-LOCAL** (JETH200->accept): `let a: Arr<u256,3>;` synthesizes the all-zero image via
  defaultStaticValue (byte-identical to solc `T[N] memory a;`). Dynamic-array uninit still rejects.
- **QUALIFIED-SELECTOR** (JETH074->accept): `C.g.selector` resolves the DIRECTLY-declared member via the
  collected candidate set (native `get`/`External<T>` forms), scoped by definingContract == the type - EXACTLY
  solc's rule (verified: `C.m.selector` direct accepts, `C.g.selector` inherited-via-derived rejects in both).
- **IFACE-EVENT-MEMBER / IFACE-ERROR-MEMBER** (JETH341->accept): an `E: event<{...}>` / `Bad: error<{...}>`
  member in an interface routes to the shared collector, scoped to the interface (inert; interfaceId unchanged).
- **GET-SELF-VIEWCALL** (JETH043->accept): a `get` calling `this.g()` to a view/pure external defers the write
  to the purity fixpoint (mirrors GET-EXTLIB-VIEW); a writer callee still JETH043. Behavioural parity (self-calls
  are behaviour-identical, not byte-identical, in JETH - like external-self-call.test.ts).
- **LIB-CONST-IN-CONST** (JETH048->accept): a library constant `L.K` folds into a contract constant's
  initializer exactly like the same-class `C.K` (constIntRef/constTypedRefType/evalTypedConst/foldConstBool),
  inheriting the identical wrap/reject behaviour (no new MC path); a shadowing member blocks the fold.
- **ARRLIT-DIRECT-INDEX** (JETH151->accept): `[a,b,c][i]` desugars to `let __t = [a,b,c]; __t[i]` via the
  statement hoist buffer (whole-statement context only, for source-order eval safety); OOB Panic byte-identical.

**2 KEPT as DELIBERATE rejects (verified, do NOT lift):** TYPED-CATCH (`catch Error(string)`/`catch Panic(uint)`
JETH074/361 - the native `catch (e: bytes)` + `this.reason`/`this.panic` forms work + are byte-identical, pinned
in try-catch.test.ts) and MULTI-CONTRACT-FILE (JETH041 - the one-contract-per-file MVP limit, pinned in
native-mode-declarations.test.ts:93/137; per-file + multi-file-import is the model).

RECURSIVE-REF-STRUCT LIFTED (2026-07-14, lift-recursive-ref-struct.test.ts): a struct that references itself
(directly or mutually) through a REFERENCE-type field (`P[]` / `mapping<K,P>`) is now accepted, byte-identical
to solc, via TWO-PHASE struct registration (shells -> resolve -> cycle-classify -> gate) plus a `recursiveRef`
sentinel that breaks the object-graph back-edge so every compile-time type-walk terminates. A by-value cycle
(`next: P`, `Arr<P,N>`, mutual by-value) stays a clean reject (JETH487 = solc "Recursive struct definition").
PROVEN byte-identical (deploy-both + raw storage): storage var + static-value-leaf read/write (`p.x`), the
auto-getter (returns only value members), top-level `P[]`/`mapping<K,P>` push/index/read/length, packed leaves,
mutual + mapping-field self-reference, forward/mutual acyclic references. solc-rejected consumers (external
return, abi.encode, event param) stay rejected. Also byte-identical: the recursive field's own
push/pop/length + whole-struct storage-to-storage copy (the recursiveRef sentinel only appears where the
element CONTENT is provably zero - `kids[i]` indexing rejects - so no stride/codec divergence is observable).
SAFE residual over-rejections (solc accepts, JETH cleanly rejects, no miscompile): indexing INTO a recursive
field (`kids[i].x`, JETH210), reading a bytes/string leaf of a recursive struct (JETH202), and a recursive
struct as a memory local / internal-memory return (JETH074/200).

### 2026-07-14 ALL 6 LIFTABLE-HARD ORs LIFTED byte-identical (worktree fan-out -> sequential integrate -> cross-verify)

The 6 remaining hard ORs were each implemented + adversarially verified byte-identical in an ISOLATED git
worktree (a 6-agent fan-out), then integrated onto one branch SEQUENTIALLY (rebuild + regression per step; the
three that extend `resolveType` - CONST-ARRAY-DIM `constDim`, IFACE-VALUE-TYPE `interfaces`, CONTRACT-TYPE-PARAM
`refNames` - reconciled into ONE 6-param signature `resolveType(node,diags,structs,constDim,interfaces,refNames)`).
LIFTED: **CONST-ARRAY-DIM** (`Arr<u256,N>` bare in-scope integer const), **LIB-MODIFIER** (a `@modifier` in a
library, per-library `L.name`-keyed, expanded at the lib-fn definition site), **IFACE-VALUE-TYPE** (an interface
name as a first-class VALUE type -> the `address` kind with the interface as a nominal brand: field/param/return/
local/mapping-value/array-element + `x.m()` dispatch reusing the inline `I(addr).m()` lowering),
**CONTRACT-TYPE-PARAM** (a contract/interface type as an EVENT/ERROR member -> branded address, canonicalName ->
"address" so topic0 = keccak("E(address)"); scoped to member position, concrete-contract param/field kept a SAFE
residual), **RECURSIVE-REF-STRUCT** (self/mutual ref through a `P[]`/`mapping` field, via two-phase registration
+ a `recursiveRef` sentinel), **ABSTRACT-ONLY-FILE** (an abstract/interface-only unit compiles to empty bytecode).

A merged-tree adversarial CROSS-VERIFICATION (5 axes) then found + fixed 2 over-acceptances the isolated checks
could not see: **MERGE-OA-1** a bodyless abstract method without `@virtual` slipped through the newly-unmasked
non-deployable path (solc: "must be marked virtual") -> JETH489; **MERGE-OA-2** a recursive struct as an event/
error member was accepted (solc: "recursive type not allowed as event parameter") -> JETH488 via
`typeContainsRecursiveRef`. The iface x contract-type overlap, the const-dim x iface x struct cross-products, and
the recursive-struct codec were all byte-identical / reject-parity clean. Suite 464/4316, flake gate green.
LESSON: independently-verified lifts do NOT compose for free - a shared resolver (resolveType) reconciled by hand
+ a fresh adversarial cross-verification of the MERGED tree caught interaction OAs no per-lift check saw.

### 2026-07-14 CONST-ARRAY-DIM LIFTED byte-identical (bare in-scope name only)

**CONST-ARRAY-DIM** (JETH012->accept for a bare name): `a: Arr<u256, N>` with a compile-time integer
`static N` now resolves N to its bigint, producing the SAME JethType as the bare-literal `Arr<u256, 3>`
(hence byte-identical to solc's `uint256[N]`). A scope-aware resolver (`Analyzer.namedDim`) is threaded as a
4th arg into `resolveType`; the Arr branch (typeresolver.ts) accepts a bare `Identifier` length that resolves
to a whole-integer @constant declared in the CURRENTLY-analyzed contract or one of its bases
(`currentLinNames`), reusing the JETH445 (<=0) / JETH446 (>2^53) fail-safes. Verified deploy-both byte-
identical (returndata over all indices, OOB Panic, raw storage slots, second-field placement, u32 packing,
nested `Arr<Arr<u256,N>,M>`, inherited-base N) in test/const-array-dim.test.ts.

KEY CORRECTION to the earlier assumption: solc 0.8.35 accepts ONLY a bare name here. It REJECTS every
QUALIFIED form ("Invalid array length, expected integer literal or constant expression"): self `C.N`, a base
`B.N`, a library `L.N`, another contract `O.N`; and it REJECTS a bare name that is out of scope ("Undeclared
identifier", e.g. a constant declared only in an unrelated contract). So JETH KEEPS the JETH012 reject for a
qualified name AND for an out-of-scope bare name (the linearization-scope check is REQUIRED because
constantsByName is global/never-cleared - without it, `uint[N]` in an unrelated contract would over-accept). A
constant EXPRESSION (`N + 1`) is not a valid TS type argument (grammar-phase reject) and stays JETH012 - JETH
does not fold a type-position expression (a divergent fold would miscompile the storage layout). SAFE RESIDUAL
over-rejections kept (all match nothing solc-accepts or are simply not lifted here): a struct-member const dim
(structs are collected before constants) and a file-level `const N` (not in constantsByName).

### 2026-07-14 RESIDUAL LIFTS (4 hard-lift residuals; 1 reverted for an MC, 3 lifted; +4 OAs closed)

The safe-over-rejection residuals from the hard-lift campaign, via worktree fan-out -> sequential integrate ->
merged-tree cross-verify. LIFTED byte-identical: **IFACE-STRUCT-FIELD** (an interface name as a STRUCT FIELD
type -> branded address; a name-only interface pre-scan before collectStructs), **CONST-DIM-RESIDUALS** (a
file-level `const N` and a struct-member const dim as an `Arr<T,N>` length; collectFileLevelIntConsts, gated to
GLOBALLY-shadow-free bare integer names), **CONCRETE-CONTRACT-VALUE** (a concrete/abstract contract name as a
field/param/return/local/immutable value -> `__ctref:` branded address, with fail-closed gates on the raw
address surface). REVERTED: **REC-STRUCT-CONSUMERS** (storage `p.kids[i].x`) - its isolated check only tested
EMPTY kids; the merged-tree cross-verify proved that with a POPULATED kids array, `this.p=this.q` DROPS the
element payload and `delete this.p` LEAVES stale storage (the aggregate copy/delete paths use the recursiveRef
sentinel's stub layout). Keeping it a clean JETH210 reject is the bar-respecting outcome (lifting it needs
runtime-recursive copy/delete codegen or gating every consumer). CLOSED 4 over-acceptances (reject-only gates):
the nominal contract/interface value CAST surface (payable/uN/iN/bytesN - the cast gates matched only the
`__ctref:` brand, missing interface brands; now isNominalAddressValue), the raw-address MEMBER surface on an
interface value (.balance/.code/.codehash, JETH352), and a RECURSIVE struct in an external/public signature
(JETH488) or abi.encode/encodePacked (JETH173) - the latter two PRE-EXISTING since the base recursive-ref-struct
lift. Suite 467/4333, flake green. LESSON (reinforced): an isolated lift verification can miss a consumer that
only miscompiles under state the lift newly enables (populated recursive field); the merged-tree adversarial
cross-verify is what caught the 2 MCs + 4 OAs, and reverting the un-fixable-cheaply lift beats shipping an MC.

### 2026-07-15 CTR-TYPE-AGG LIFT (a contract/abstract-contract type in the AGGREGATE positions)

The residual left by CONCRETE-CONTRACT-VALUE (2026-07-14): a concrete/abstract contract name was a first-class
VALUE type (field/param/return/local/immutable, `__ctref:` branded address) but stayed a JETH013 over-rejection
in the AGGREGATE positions - a STRUCT FIELD, a dynamic-array element, an `Arr<T,N>` element, and a mapping value
- because `refNames` was not threaded into those recursive type-resolution sites (the interface brand already
was, via `interfaces`, so an @interface name accepted there - the template mirrored here). LIFTED byte-identical
by (1) threading `refNames` through every recursive `resolveType` call (array element, mapping key/value, Arr
element, parenthesized, funcref param/return) exactly as `interfaces` is, and (2) a name-only `contractNamesEarly`
pre-scan in collectStructs (mirroring registerContractClasses's predicate) passed as `refNames` at the struct-
field resolution site (the same reason interfaceNamesEarly exists: struct fields resolve before classByName is
built). Everything erases to `address` at storage/ABI/selectors/codecs, so a contract-typed aggregate program is
byte-identical to the same program written with a plain `address` there (proven at the bytecode level across 14
consumers) AND to the solc mirror using the contract type (66-cell oracle + a run+decode sweep vs solc under
POPULATED state). The REC-STRUCT-CONSUMERS trap was re-checked directly: `this.p = this.q` (distinct-populated
structs) and `delete this.p`, plus array-element delete and storage array-to-array copy, are all byte-identical
to solc - unlike the reverted recursive-ref lift, a contract-ref aggregate uses the ordinary address layout
(no recursiveRef sentinel), so the copy/delete paths carry the full payload. GUARDS held: a value read OUT OF an
aggregate is still NOMINAL - `.balance`/`.code`/`.codehash` (JETH210/JETH352), a uN/iN/bytesN/payable cast
(JETH170), and an implicit contract<->address conversion (JETH085) all fail closed with the `__ctref:` brand
visible; a plain address does not implicitly convert INTO a contract element; a library name stays a JETH013
element reject; MULTI-CONTRACT-FILE / dep-file concrete gates are untouched. RESIDUAL (unchanged, documented):
a METHOD CALL on a contract-ref value (`t.v()`) is JETH074 in EVERY position (value AND aggregate) - contract-
value dispatch was never built (interfaces have it); solc accepts it, so JETH's clean reject is a SAFE
over-rejection. This lift threads only the TYPE brand; it does not add dispatch, keeping value and aggregate
consistent. Suite 468/4340. LESSON: the byte-identity-to-the-address-twin invariant (a branded address must
produce IDENTICAL codegen to a plain address) is a fast, strong miscompile detector across the whole consumer
axis - any divergence localizes exactly where the brand leaked into codegen.

### 2026-07-15 FIX-ALL CAMPAIGN completion (DECORATOR-POSITION + == OA + tsc + keep-reject + merged-tree cross-verify)

The fix-all round (user: lift everything liftable, fix anything that comes out - MC/OA/OR/flake/bug). On top of
the CTR-TYPE-AGG lift above:
- **DECORATOR-POSITION hardening (JETH490)** - a decorator in CLASS / FIELD / PARAM position was SILENTLY
  DROPPED, including TYPOS of real decorators (`@storag("ns")` on a class silently lost the storage namespace;
  `@diamon('array')` silently lost the diamond - byte-identical to a bare class). The METHOD position was
  already closed (JETH329). A pre-analysis TS-AST scan (collectStrayDecorators, compile.ts) now rejects a
  decorator whose name is not in the legal per-position allow-set (CLASS = diamond/storage/proxy/beacon/facet/
  using/uups; FIELD = storage/override/virtual; PARAM = none), derived from the analyzer's real consumption
  sites. Pure rejection-adder: 17/17 legal keep-list shapes byte-identical, full suite green.
- **== / != nominal-vs-address OA closed (JETH083)** - `==`/`!=` between a plain address and a nominal-branded
  (contract/abstract-class/interface ref) value, or between two DIFFERENT nominal brands, was accepted by JETH;
  solc rejects "operator == cannot be applied to types address and contract T". Root cause: an address-literal
  operand (`address(0)`) failed retypeLiteral quietly, so buildBinary returned undefined and return-site
  error-recovery emitted bytecode solc never compiles. A gate in buildBinary now rejects when both operands are
  address-kind and their brands differ with >=1 nominal. Same-nominal / plain==plain / explicit `address(t)==`
  stay byte-identical. Found by the CTR-TYPE-AGG adversarial verify in passing (pre-existing, systemic across
  value/param/interface/aggregate positions).
- **REC-STRUCT-MEMLOCAL kept a clean reject (JETH200/074)** - a recursive struct as a MEMORY LOCAL
  (`let m: P = this.p`) is a SAFE over-rejection: solc lowers `P memory m = p` to an UNBOUNDED runtime-recursive
  DEEP COPY (witnessed on a populated 3-level tree, mutation-independent from storage), which JETH's recursiveRef
  sentinel cannot reproduce; admitting it would miscompile. Pinned in test/lift-recursive-ref-struct.test.ts.
- **tsc cleanliness restored** - 5 real `tsc --noEmit` errors had shipped on 3529351 (the suite is green because
  vitest/esbuild does not typecheck): the decorator `@(m)` unwrap widening, two fixed-array-memory-local
  diagnostics passing `Expression | undefined`, and a `noUncheckedIndexedAccess` tuple-destructure. All type-only.

STALE CATALOGUE ROWS RETIRED (re-probed live at 3529351, each ALREADY ACCEPTS - the row was stale): the
recursive-struct BYTES/STRING leaf read (`this.p.s.length`), a const-REFERENCING-const array dim
(`static M = N; Arr<T,M>`), and the `bytes("a")` string cast. NOT liftable (TS grammar, not a JETH gap): a const
EXPRESSION array dim (`Arr<u256, N+1>`) is not a valid TS type argument (grammar-phase reject).

MERGED-TREE ADVERSARIAL CROSS-VERIFY: 430 cases across 5 axes (CTR-TYPE-AGG consumers under POPULATED state +
raw-storage decode; the == gate base-vs-merged-vs-solc isolation; the decorator gate x the legal keep-list
corpus; cross-products - contract-type aggregate in diamond/proxy/library, recursive struct with a contract
field; a 16-program combinatorial matrix). Verdict CLEAN: zero MC, zero OA, zero new OR. Every over-rejection
observed is a PRE-EXISTING documented safe reject (proven base==merged). Suite 470/4362, tsc clean, flake gate
green (deterministic across repeated runs).

### 2026-07-15 EXHAUSTION-AUDIT round (2 lifts + 8 stale rows retired + 1 false-premise)

A read-only exhaustion audit (~98 differential cases, canonical corpus syntax) re-probed the full residual
surface at HEAD to determine whether the liftable set was empty. It found 2 genuine liftables (now lifted),
8 STALE rows (accept byte-identically at HEAD - the catalogue had drifted), 1 FALSE-PREMISE row, and ZERO
over-acceptances.

LIFTED byte-identical:
- **USING-ON-LIBRARY** (`8b263ff`, JETH074): `@using(M)` inside a `static class` (library) body is now
  consumed - a per-library lexical @using map keyed by library name (mirroring the USING-ON-ABSTRACT
  per-class maps); `x.dbl()` in library L resolves to `M.dbl(x)`, the emitted call byte-identical to writing
  `M.dbl(x)` directly (a resolution layer only). Proven across u256/struct/bytesN receivers, multi-method,
  internal + external/delegatecall libraries; leaks all fail closed (JETH393 ambiguous / JETH391 non-library
  / JETH074 not-found). Suite 475/4407.
- **TRAILING-HOLE** (`126b8bb`, JETH066/072): a `let`-declaration tuple destructure with an elided trailing
  hole `let [p, ] = g()` (TS drops the trailing comma) now binds a truncated pattern, treating the missing
  tail as discarded holes - byte-identical to solc `(uint p, ) = g()` and the leading-hole twin. The discarded
  component is still EVALUATED (raw-storage witness under populated state proved side effects run), the exact
  reverted-sibling failure mode, and it holds. Genuine arity mismatches still both-reject.

FALSE-PREMISE (NOT an OR - both-reject at solc parity, no lift, test-only pin `234e809`):
- **MEM-STRUCT-DYNARRAY-FIELD**: `let s: S = { arr: [3n, 4n] }` (a memory struct with a dynamic-array field
  built from a FIXED-array literal) - solc REJECTS this too ("Invalid implicit conversion from uint256[2] to
  uint256[]"); JETH's JETH226 is correct parity. The CORRECTLY-constructed feature (`new Array<u256>(n)` then
  element writes, then the whole read/write/copy/alias/delete surface under populated multi-element state) was
  found to ALREADY work byte-identically today. LESSON: a fixed-array literal `[a,b]` is `T[K]`, not `T[]`; an
  audit/probe that assigns one to a dynamic field manufactures a false liftable (solc rejects it too).

STALE ROWS RETIRED (re-probed accept + byte-identical at HEAD): JETH387 receive/fallback internal-call gate;
JETH065 accessor property-read (`this.val` == solc `val()`); funcref-struct element bound-to-local
(`let e: Fd = a[i]; e.f(v)`); funcref-struct ternary `(c ? a[0] : a[1]).f(v)`; calldata struct-array element
byte access `xs[i].b[j]`; nested-array whole-inner assignment `m[i] = [...]`; `bytes[][]` nested dynamic-leaf
array; array/struct of function pointers (fixed + dynamic). These earlier catalogue/SUPPORTED.md "rejects" now
compile identically to solc.

REMAINING KNOWN LIFTABLE (found in passing, next): the tuple-ASSIGNMENT trailing hole `[a, ] = two()` (no
`let`) still over-rejects JETH066 while solc accepts `(a, ) = two()` - symmetric to the TRAILING-HOLE let-decl
lift, same machinery on the assignment path.

### 2026-07-15 FINAL-AUDIT tail lifts (4 lifts across 2 rounds; audit convergence)

A final read-only exhaustion audit (~140 cases, canonical-syntax discipline, classifying on compile-acceptance
directly since the harness runtime class masks accept-but-revert) found the liftable set effectively exhausted:
zero over-acceptances, and a thin tail of same-family routing/reorder micro-gaps, each lifted byte-identical:
- **DECODE-DIRECT-RETURN** (`7bc10d2`, JETH060): multi-value `return abi.decode(b, [T,U])` now feeds the
  multi-value return path (a routing gap - it was a tuple producer in destructure-assign but not direct-return);
  byte-identical to the bind-first twin + solc. Implicit-widen route lifted soundly too.
- **LIB-NAMEDARG** (`37d92c7`, JETH148/130): a NAMED-arg raise of a LIBRARY-scoped event/error is reordered to
  declaration order (reusing the positional lowering, byte-identical). RE-EXAMINED the stale "deliberate" label
  (it had no miscompile witness) and found it was merely unwired - not miscompile-bound.
- **FILE-LEVEL-NAMEDARG-IN-LIB** (`13198dd`, JETH148/130): the file-level-owner analogue - a `type Ev = event<{}>`
  / `type Bad = error<{}>` raised with named args inside a library body, same reorder; scope-leak + shadow hunts
  clean.
- **DECODE-SINGLE-RETURN** (`46456e7`, JETH323): `return abi.decode(b, [T])` (single-element list) routes to the
  canonical single-value `abi.decode(b, T)`, byte-identical.

ADDITIONAL STALE ROWS (SUPPORTED.md "Still gated" section lags; all re-probed ACCEPT + byte-identical at HEAD):
`this.g[i] = arr` whole fixed-array element assign; `this.dd[i] = xs` whole-inner dyn-array assign (cd source);
ternary over a dynamic storage struct/array read; aggregate array/bytes params+returns through an internal call
(was JETH242); struct-with-dyn-array-field cd->storage; packed element of a nested dyn array `this.m[k].arr[i]`;
whole static calldata aggregate as a multi-value-return component; modifier gates (multiple `_`, aggregate param,
post-code on multi-return/dyn-param); MEMBER-SHADOWS-FILE-EVENT same-signature. These are safe over-rejections
that were closed by later work and never un-gated in SUPPORTED.md.

REMAINING (sub-marginal, documented, NOT auto-lifted - non-canonical spellings / declaration-scope asymmetries
no real program hits): contract-body bare file-level named raise (native form is `this.E({...})`); a file-level
error + same-named CONTRACT-member error coexisting (JETH128, distinct scopes in solc); same-key-set overloaded
library event (JETH434, a deliberate ambiguity reject). Plus the standing DELIBERATE miscompile-avoiding rejects
(rec-struct mem-local/indexing, the pointer-headed fixed-array memory family, TYPED-CATCH, MULTI-CONTRACT-FILE,
FUNCREF-PURE, LT5, L2-MOBILE, LIB-CREATION-VALUE, FALLBACK-EXTERNAL-MARKER). No MATERIAL solc-coverage gap remains.

### 2026-07-15 DELIBERATE-REJECT DIAGNOSTICS (3 targeted messages replacing a generic JETH074; no shape lifted)

A diagnostic-quality pass over three shapes solc accepts but JETH deliberately rejects (a USER RULING: never lift).
Each previously fell to the generic `JETH074 unsupported expression` catch-all and now emits a clear, targeted
message. No shape was made to compile and no accepted program changed: a byte-identity sweep of the whole guard
matrix (interface + contract-value `.transfer` DISPATCH, a contract's OWN transfer/send method, `push(value)`,
the no-arg push STATEMENT, `t.call({ value })`, and field/local named transfer/send) is IDENTICAL to base at
c9a277c. The three new codes (see the "Deliberate DESIGN rejects" table above):
- **JETH492** `<address>.transfer/.send`: solc's fixed 2300-gas-stipend ETH send (a footgun since EIP-1884).
  RECEIVER-TYPE-GATED (`trialExprType` + `isNominalAddressValue`) so ONLY a PLAIN address/payable receiver is
  flagged; a nominal contract/interface receiver dispatches exactly as before.
- **JETH493** `selfdestruct(...)`: deprecated, neutered by EIP-6780.
- **JETH494** `arr.push()` no-arg used as a VALUE (a storage-reference local): the no-arg push STATEMENT stays
  supported; `push(value)` is the value form. Fires on state / mapping-value / struct-field storage arrays.

Implemented as `Analyzer.deliberateRejectDiag`, called at the tail of `checkExpr` immediately before the JETH074
catch-all - so every real resolver (interface/contract dispatch, low-level `.call`, attached library, the
array-mutator STATEMENT path) runs first and accepted programs cannot be reached. Regression net:
`test/deliberate-reject-diagnostics.test.ts` (8 tests, including runtime byte-identity of the guards vs solc 0.8.35).

### 2026-07-15 Group-C resolution (C1/C2 lifted, C3 retired, MEMBER-SHADOWS OA closed)

The three "Group C" catalogue rows were re-probed live and resolved (89c8bfa, suite 480/4467):
- **C1 LIFTED** (JETH227/130): a NAMED-arg raise of a FILE-LEVEL event/error from a CONTRACT body
  (`emit(Ev({a:x}))` / `revert(Bad({a:x}))`) reorders to declaration order, byte-identical to the positional
  twin + solc (extends the named-arg reorder machinery to the contract-body owner). Scrambled-key non-vacuity,
  decoded topic0/selector.
- **C2 LIFTED** (JETH128): a file-level EVENT or ERROR may coexist with a same-named contract-MEMBER
  event/error; the member SHADOWS the file-level inside the contract (`this.Bad`/bare `Bad` -> member; a raise
  fitting the file-level sig but not the member REJECTS at solc parity). Event/error only.
- **C3 RETIRED - was never an OR**: "same-key-set overloaded library event -> JETH434" was miscatalogued. A
  genuinely-ambiguous overloaded event emit is a BOTH-REJECT (solc rejects "not unique" too - verified live
  across positional literal/library/named-arg cases); JETH434 is a sound ambiguity guard, not an over-rejection.
- **MEMBER-SHADOWS-FILE-EVENT OA CLOSED**: the pre-existing over-acceptance (a same-named contract member did
  NOT shadow the file-level event on the positional channel, so a raise matching the file-level sig picked the
  file-level) is closed on BOTH positional + named channels.

GUARD (a broken isolated attempt was caught by the adversarial verify before landing): a file-level
STRUCT/ENUM/INTERFACE sharing a name with a contract member STAYS rejected (JETH133) - solc has one namespace
for types (the member shadows the type name, making it unusable); only event/error cross-scope-coexist. The
first C2 attempt over-broadened this and introduced a struct/enum over-acceptance (JETH accepts + deploys a
contract using the shadowed struct as a type; solc rejects) - the merged verify's decoded witness caught it and
it never reached main.

FOLLOW-UP (in flight): the multi-file analogue - an IMPORTED file-level event/error colliding with a same-named
contract member - bypasses the member shadow via the V3 per-file alpha-rename (a bare raise routes to the
imported symbol), a pre-existing OVER-ACCEPTANCE surfaced by the Group-C verify; being fixed separately.

### 2026-07-16 Group A addition (USER RULING): method-vs-type/error/event name collision is a DELIBERATE accepted reject

A method sharing a name with a same-named type/error/event (`class C { get Bad(): External<u256> {...} }` where
`type Bad = error<{...}>` / `type Bad = { ... }` / `type Bad = event<{...}>` exists) rejects JETH133 while solc
accepts (solc keeps a function name and a same-named type/error/event in ONE overload set, resolving by reference
context). This is NOT a gap to lift - it is a DELIBERATE accepted reject (Group A), per the JETH naming
convention: types/errors/events are PascalCase, methods are camelCase, so the two namespaces never collide in
idiomatic code. A collision only arises when a method is (mis)named PascalCase; JETH rejecting it ENFORCES the
convention. Workaround is trivial + idiomatic: name the method camelCase (`bad()`), which never collides.
Lifting it would require true overload-set resolution (a name being both a callable and a type in one scope,
disambiguated by context) with its own miscompile risk - deliberately declined. Applies single-file and to the
multi-file import variant (JETH133/074/085). REMOVES this from the "liftable" set: it is now a Group A deliberate
reject alongside .transfer/.send (JETH492), selfdestruct (JETH493), push-no-arg (JETH494).

### 2026-07-16 CLOSED: the multi-file METHOD-name-collision OVER-ACCEPTANCE family (own + inherited)

The Group-A documentation ruling (method-vs-type/error/event collision = deliberate JETH133 reject) exposed a
MIRROR bar violation: the single-file path correctly REJECTS a method colliding with a same-named
type/error/event (JETH133), but the MULTI-FILE bundler alpha-renames imported symbols BEFORE the analyzer runs,
so the collision routed AROUND the JETH133 gate and JETH ACCEPTED where solc (and single-file JETH) REJECT - an
over-acceptance. Closed in two verified commits + one corrective:
- 786b88e: a contract's OWN method colliding with a same-named IMPORTED file-level error/event/struct/enum/
  interface (5 kinds) now rejects JETH133 in multi-file, matching single-file (new collectImportedMethodType
  Collisions in src/compile.ts, run before the v3 rename; methods only; cross-file only). Verify CLEAN.
- 7d7ffaa: the INHERITED-method variant (the method reaches the use-site contract through the extends chain -
  base+type in the same dep file, three-file, 2-level chain, diamond-through-2nd-base, override) now also rejects
  JETH133 (generalized to VISIBLE methods = own UNION inherited via a merged-AST extends-chain walk). The first
  attempt (6bc5726) over-reached by counting unimplemented INTERFACE method SIGNATURES as shadowing members
  (adversarial verify caught it: single-file + solc both ACCEPT an abstract contract inheriting an unimplemented
  interface method colliding with an in-scope type); the corrective drops the ts.isMethodSignature branch so only
  concrete/bodyless-@virtual CLASS MethodDeclarations shadow - the exact single-file line. Verify CLEAN.
The rule, consistent single/multi-file: a CLASS method (own or inherited, any file) whose name collides with an
in-scope file-level error/event/struct/enum/interface rejects JETH133; an interface MethodSignature does NOT
shadow (matches solc + single-file). The no-use collision rejecting JETH133 (solc accepts the pure shadow) is the
DELIBERATE Group-A over-rejection applied consistently. Suite 483 files / 4531 tests, tsc clean. The whole
name-collision subsystem (value-member shadow + own-method + inherited-method) is now DRY: zero OA, zero MC.

### 2026-07-16 RULING + UNIFICATION: the name-collision rule is "match single-file everywhere" (89e152f)

USER RULING (final): single-file JETH's blanket DECLARATION-LEVEL JETH133 is the language rule for the whole
member-vs-file-level-type name-collision family, on BOTH compilation paths. Any contract member (plain field,
static constant, immutable, mapping, struct-typed field, funcref/array field, Visible<T> field, get accessor,
@virtual getter, method, @modifier-vs-error/event) whose name collides with an in-scope file-level
error/event/struct/enum/interface/Brand rejects JETH133, used or unused, own or inherited. EXEMPT (member
shadows, coexistence allowed): member error<{}> x file-level error, member event<{}> x file-level event,
@modifier x type. This supersedes the reference-sensitive multi-file value-member design (which matched solc:
unused shadows accepted, uses rejected via binding); those cells are now DELIBERATE over-rejections per the
same naming-convention rationale as the Group-A method ruling (types PascalCase, members camelCase).
Fix 89e152f: collectImportedMethodTypeCollisions generalized to collectImportedMemberTypeCollisions mirroring
the analyzer's cross-scope gate (same code + kind-worded message) over the route class + extends chain; fired
names disable the reference shadow so companions match ([JETH133] alone, never [JETH133,JETH129]). Adversarial
verify CLEAN: 256 paired single-vs-multi cells zero set-mismatches; 99 non-vacuous accept->reject flips + 72
code realignments; 20 byte-identity guard shapes (F4 coexistence binds the MEMBER, decoded selector 830c4ac2);
14 solc twins prove every new reject is a deliberate over-rejection (solc accepts each; none masked a solc
reject); zero reject->accept flips. Suite 485 files / 4683 tests, tsc clean.

Documented residuals (all reject-side or solc-correct, none a bar violation):
- COMPANION deltas on already-rejected programs: interface-cast/brand bare-construction carries a single-file-
  only JETH074 next to the shared JETH133; multi-diagnostic bags order the pre-pass JETH133 first (sets equal).
- STRAY-class scan keeps multi-only JETH133 rejects where single accepts (stray abstract method, second
  deployable behind JETH041); removing them would be a reject->accept flip, forbidden by the ruling.
- LIBRARY-body member shadow keeps the multi-only use-site JETH129 (single accepts; the single-file library
  accept is itself questionable vs solc, out of scope).
- MODIFIER-APPLICATION x imported STRUCT (@modifier Bad + @Bad applied): multi [JETH329] vs single ACCEPT,
  pre-existing and unchanged; fixing = forbidden reject->accept flip; candidate for a future ruling.
- SCOPE BOUNDARY (correct, not a defect): a colliding type reachable only in dep-file scopes with no path to
  the route class ACCEPTS in multi while the FLATTENED single twin rejects - flattening changes scope; the
  multi behavior equals solc multi-file scoping and is the documented pre-pass boundary.

### 2026-07-16 USER-DIRECTED ROUND: 2 lifts, 2 Group-A rulings, 1 live OA closed, 2 liftability rulings

**LIFTED (both byte-identical, adversarially verified CLEAN):**
- **L2-MOBILE (was JETH213) - LIFTED `017799b`**: an array literal mixing a CAST element with BARE int
  literals now self-types to solc's common type. The rule was DERIVED from solc via a `bytes32 z = [..]`
  type-error oracle (which forces solc to name its inferred type), not guessed: seed with element 0's MOBILE
  type, then fold Type::commonType over the rest. Two witnesses killed the first model AND an in-repo comment:
  the fold is ORDER-SENSITIVE (`[-1,1]` IS int8[2] but `[1,-1]` REJECTS - the old comment claimed "mixed sign
  has NO common type", an over-generalization, now corrected + `[-1,1]` lifted), and widening is SMALLEST-FIT
  not next-power-of-two (`[uint16(1),70000]` -> uint24[2], NOT uint32). Elements now carry solc's EXACT width.
  Verified: 648-case sweep + a 484-pair TERNARY WIDTH ORACLE (`abi.encode(c?A:B)` compiles iff type(A)==type(B),
  so JETH's inferred types must partition the literals into exactly solc's classes - 78 accepts each, 0
  divergences). 0 MC / 0 OA. Deliberate narrow keep: solc converts ONLY the zero literal to bytesN.
- **FALLBACK-EXTERNAL-MARKER (was JETH386) - LIFTED `b5bc190`**: `External<T>` on `receive`/`fallback` is now a
  REDUNDANT SYNONYM of the bare canonical form, byte-identical BY CONSTRUCTION (it unwraps to the bare return
  type; the identical path decides it). Every reject witnessed against solc first and matched: returning receive
  / parameterized receive / `fallback(bytes)` with no return / `fallback():External<u256>` -> JETH384; nested
  markers rejected; `receive(): Payable<void>` stays JETH385. NON-VACUITY over RAW calldata dispatch: the
  non-payable `External<void>` fallback still REVERTS on value while the Payable twin succeeds (the marker
  cannot smuggle payability).

**NEW Group-A DELIBERATE DESIGN rejects (USER RULING - moved out of the miscompile-avoiding table, now with
targeted diagnostics per the JETH492/493/494 pattern; `5a1f43a`, diagnostic-only, proven set-identical):**
- **JETH495 REC-STRUCT-MEMLOCAL** (was JETH200/JETH243/JETH074): a recursive struct as a MEMORY LOCAL /
  uninit-or-ctor local / internal `P memory` return. Deliberate: solc lowers it to an UNBOUNDED runtime-recursive
  DEEP COPY; JETH deliberately has no runtime-recursive struct-copy codegen (its back-edge is a compile-time
  recursiveRef sentinel), so materializing one would SILENTLY DROP the nested payload. Workaround in-message.
- **JETH496 TYPED-CATCH** (was JETH074/JETH361): `catch Error(string)` / `catch Panic(uint)`. Deliberate: the
  native `catch (e: bytes)` + `this.reason`/`this.panic` forms cover it and are byte-identical.

**LIVE OVER-ACCEPTANCE CLOSED (bar violation, PRE-EXISTING at base, exposed by the L2-MOBILE lift): `6655898`,
new code JETH497.** JETH pushed the declared/expected type INTO an array literal, so it accepted any MEMORY
landing whose declared element type was merely WIDER than solc's element-inferred type. THE RULE (derived from a
~20-position solc witness matrix = ArrayType::isImplicitlyConvertibleTo's two branches): a copy INTO STORAGE
converts ELEMENT-WISE (so `uint256[2] s; s = [1,2]` ACCEPTS, and dyn-sizedness/length checks are skipped),
while MEMORY / calldata / a storage POINTER requires an IDENTICAL element type. The location is decided at the
LITERAL's LANDING, not the enclosing statement (`s = S([1,2])` and `s = id([1,2])` are TypeErrors even though `s`
is storage, because the literal lands in a MEMORY parameter). 13 live OA cells closed (memory local/assign/return/
internal-arg/external-arg/struct-ctor-field/event-arg/nested/struct-ctor-into-storage/memory-elem/ternary-at-memory);
the whole STORAGE path + exact-width memory rows keep accepting byte-identically (orchestrator re-verified: 11/11
rows byte-identical to base, zero drift; 106 live over-rejection-hunt cells byte-identical). Suite 488/4790.

**LIFTABILITY RULINGS (evidence-based, this round):**
- **#6 B-21 / L6 / L7a - USER RULING: KEEP THE REJECT.** Two CORRECTIONS to this catalogue's own prior text:
  (1) the anchor `yul.ts:8944` is STALE - at HEAD it is `src/yul.ts:8989` (aggArgToMemPtr) with a twin gate at
  `src/yul.ts:7667` (assertInlineAggCaptureSound, JETH465); origin commit 034bd6f. (2) the row MISCHARACTERIZES
  the divergence: it is NOT "JETH lays fixed arrays INLINE while solc is pointer-headed" - a STANDALONE
  `Arr<In,N>` memory local IS pointer-headed in JETH and byte-identical to solc (a passing control in
  test/inline-struct-ctor-pointer-headed-static-array-field.test.ts). The true divergence is at the MEMBER level:
  JETH inlines a static aggregate member into the parent image (memory image == ABI image), while solc gives
  EVERY member exactly one word (value, or a POINTER if reference-typed) at every nesting level; proof at
  analyzer.ts:17743 (memFieldOffset computes the MEMORY offset as `w += abiHeadWords(f.type)`). It also affects
  VALUE-array members (`Arr<u256,2>`), not just struct arrays. HONEST SCOPE (the "~400-site" claim is wrong in
  both directions): the assumption concentrates in ONE predicate, abiHeadWords (src/types.ts:186), which
  CONFLATES the ABI head-word count (correct) with the memory word offset (wrong vs solc) across 176 call sites /
  ~70 functions, plus ~50 mcopy contiguity assumptions = ~200-230 direct sites; 391 of 485 test files touch memory
  aggregates. There is NO single chokepoint (abiHeadWords cannot tell whether a caller wants ABI or memory
  semantics). KEPT because adopting solc's model destroys the "memory image == ABI image" invariant that makes
  static-aggregate ABI encode a zero-cost mcopy (every encode/decode becomes a recursive transcode = worse gas)
  for a rare shape with a working workaround.
- **#11 MULTI-CONTRACT-FILE (JETH041) - USER RULING: LIFT IT.** NOT YET DONE (queued). Verdict LIFTABLE-WITH-WORK
  (~2-3 days, mostly verification). The stated blocker (analyzer.ts:2016-2018: "two INDEPENDENT abstract contracts
  would require running analyzeContract more than once, which accumulates shared selector/registry state") is
  SIDESTEPPABLE: use a FRESH Analyzer per route class rather than making analyzeContract reentrant. Multi-artifact
  emission ALREADY EXISTS and was verified running (a 2-library file returns N independent Yul objects through the
  backend in ONE compile() call, compile.ts:1344-1392), but CompiledLibrary is a narrow subordinate shape (no
  abi/ir/storageLayout) so it is not reusable as a peer type. Separability PROVEN by run+decode (not "both
  compile"): each contract's slice matches solc's artifact for that contract, incl. constructor + immutables +
  independent storage layouts. PLAN: outer loop over findContractClasses() in compileUnit with a fresh Analyzer/
  YulEmitter per route; make CompileResult ADDITIVE (`contracts?: CompileResult[]`, singular fields stay =
  classes[0]) so the 1076 existing compile() call sites are untouched; drop ONLY the deployed-path JETH041
  (analyzer.ts:746-748); KEEP the abstract-leaf JETH041 (analyzer.ts:2019-2021) and diamond.ts:68. RISK is
  concentrated in the collision pre-pass (compile.ts:528-572 hard-codes ONE route), not in codegen.
- **#10 TERN-STRUCT-ARR / A-LIT-RESID - THE BLOCKER IS GONE; LIFT PENDING.** The row said "lift candidate only
  with an aliasing-witness study" - THE STUDY IS DONE and it CLEARS the lift. solc does NOT hold a live
  reference: it unifies `c ? <In[] memory> : <In[] storage>` to a MEMORY reference with an ASYMMETRIC rule -
  the MEMORY branch is ALIASED (pointer passthrough), the STORAGE branch is DEEP-COPIED (recursively, incl.
  nested dyn fields). Witnesses: post-bind `st[0].a=999` reads 100 through the binding (copy); a write through
  the binding never reaches storage; but a write through the binding IS visible in the memory source (777) =
  alias. EQUIVALENCE: the ternary vs the desugar `In[] memory r; if(c){r=m;}else{r=st;}` are 14/14 OBSERVABLY
  IDENTICAL in solc-vs-solc (because `r=m` mem->mem IS an alias and `r=st` storage->mem IS a deep copy, the
  desugar reproduces the asymmetry for free). A JETH constructive proof matched solc on every decoded cell.
  TRAP: a BLANKET copy of both arms MISCOMPILES the memory arm (write-through returns 1 instead of 777) - each
  arm must lower INSIDE ITS OWN ARM (lazy); the calldata arm's cd->mem copy likewise (hoisting it REVERTS where
  solc returns 7). SITE: the gate at analyzer.ts:22765 (`isStaticStructFixedLeafArray`, types.ts:538-545, excludes
  a dyn outer at :539); the sibling `isStaticStructAnyLeafArray` is the natural target.

### 2026-07-17 #10 + #11 LIFTED; TWO LIVE MISCOMPILES FOUND ON MAIN AND CLOSED (HEAD e563a16, suite 491/4815)

**#10 TERN-STRUCT-ARR + A-LIT-RESID - LIFTED `790135b`.** solc unifies `c ? <mem In[]> : <storage In[]>` to a
MEMORY reference with an ASYMMETRIC rule: the MEMORY arm is ALIASED (pointer passthrough), the STORAGE arm is
DEEP-COPIED. The ternary IS the copy-desugar (`In[] memory r; if(c){r=m;}else{r=st;}`) - 14/14 observably
identical in solc-vs-solc, because `r=m` mem->mem IS an alias and `r=st` storage->mem IS a deep copy. The lift
needed NO yul change: lowerExpr's ternary cases already emit each arm inside its OWN switch-case block, so the
per-arm lazy materialization was structurally present. ADMITTED: `In[]`, `In[][]`, `In[][][]` (all-dynamic to a
static-struct leaf), the pre-existing fixed-outer cluster-1 (`Arr<In,N>`, `Arr<Arr<In,N>,M>`), and A-LIT-RESID
`Arr<u256[],N>` calldata branch. EXCLUDED: every chain MIXING fixed and dynamic levels. Detector pinned
non-vacuously: memory-arm write-through reads **777** (a blanket copy would give 1); storage-arm post-bind
mutation reads **100** (a blanket alias would give 999). Lazy cd-copy proven by an oversized INNER length
(c=1 REVERTs, c=0 returns 11 == solc) - NOTE the outer-offset witness is VACUOUS (solc's entry decoder rejects
it before the body runs, so both arms revert regardless).

**LIVE MISCOMPILE #1 FOUND ON MAIN AND FIXED BYTE-IDENTICALLY `682a71f`** (NOT rejected - the first brief's
premise that this was B-21 was FALSE, and this catalogue's own #6 correction says so). ROOT CAUSE
(src/yul.ts emptyInnerImage ~L6910): zeroInitNestedMemArray routes a POINTER-HEADED element to emptyInnerImage,
which had cases for a dyn-field struct and a STATIC struct then fell through to a DYNAMIC-array tail emitting a
single `[len=0]` word. `Arr<In,2>` is NOT a dynamic array (N absolute-pointer words, no `[len]` header), so
every outer slot pointed at a ONE-WORD image. `new Array<Arr<In,2>>(n)` then leaked RAW MEMORY POINTERS.
Closed MANY live base MCs, all now MATCH: `m[0][0].a` (288 vs 1), whole-array return (leaked ptr 0x1e0),
abi.encode, for-of (499 vs 18), elementwise field assign (303 vs 103), mixed-width packing, and the EVENT/LOG
path (leaked raw pointer 480 into the log payload). A REJECT was IMPOSSIBLE at minimal scope: three PASSING
byte-identical tests use the shape (test/storage-multihop-static-struct-array-field.test.ts:46-50). Fix = 3
lines reusing the existing emptyFixedDynImage builder. *** INVISIBLE unless BOTH inner elements are assigned -
a one-element probe of this family is VACUOUS, which is why 4790 tests missed it. ***
RESIDUAL REJECTED (this one genuinely IS B-21, USER RULING KEEP): a DEEPER fixed level `Arr<Arr<In,2>,2>[]` -
the element READ path and the ABI ENCODER disagree about the image (a storage bind leaked a raw 0x140, also
live on main). New per-shape predicate isStaticStructFixedElemDynArray (src/types.ts).
LESSON: `isStaticStructAnyLeafArray`'s own docstring reserves it for CODEC DISPATCH sites ("the local-decl /
read GATES use the narrower per-shape predicates so the reject set is unchanged"); the first #10 attempt reused
it AT A GATE. Read a predicate's contract before reusing it at a gate.

**#11 MULTI-CONTRACT-FILE - LIFTED `e563a16`** (USER RULING: lift it). N deployable contracts per entry file,
one artifact each, byte-identical to solc's artifact for THAT contract from the SAME source. API is ADDITIVE:
`CompileResult.contracts?: CompileResult[]` in DOCUMENT ORDER with `contracts[0] === the result object`; every
singular field stays classes[0]'s artifact; a single-contract file leaves `contracts` UNDEFINED, so the ~1076
existing compile() call sites are untouched (64 single-contract programs, incl. all 34 examples/*.jeth,
sha256-identical base vs fix over creation+runtime+abi+storageLayout). KEPT: the abstract-leaf JETH041
(leaves.length > 1 - an abstract-only unit emits NO bytecode so there is no artifact to prove byte-identical;
its stale "re-analysis is impossible" rationale was corrected) and diamond.ts's one-@diamond-per-file. DROPPED
only the deployed-path soft JETH041. The collision pre-pass now takes a routeIndex (JETH133 parity NOT
regressed; 238 collision-family tests green + probed with two deployables present).

**LIVE MISCOMPILE #2 - the FIRST #11 attempt (`8be22da`, NOT LANDED) introduced one; adversarial verify caught
it.** Its premise "a FRESH Analyzer per route sidesteps the state hazard" is INCOMPLETE: a fresh Analyzer fixes
INSTANCE state but analyzeContract MUTATES THE SHARED AST BY DESIGN (analyzer.ts:370 says so verbatim: it
"strips the External/Payable/View/Pure return markers OFF THE SHARED AST NODES"). Route 0 stripped the markers
off a shared abstract base; every LATER route saw the member as marker-less = INTERNAL and silently dropped it
from that route's dispatcher/ABI (B.bump() absent, reverts, gn()=0 vs solc 2). `get` accessors survived
(externality comes from the `get` keyword), making the damage SILENT and PARTIAL. Route order decided the victim.
THE REDO found the write sites the verifier could not grep - the cast form is
`(member as unknown as { type?: ts.TypeNode }).type = args[0]`, matching neither `.type =` nor `as any).x =` -
and there are **FOUR** destructive sites (analyzer.ts:2637 library method, :6279 receive/fallback, :7625
Visible<T> FIELD, :8328 method markers), which is exactly why the fix is RE-PARSE PER ROUTE (compileUnit is now
a driver; compileRoute() runs the full pipeline including its own parse()) rather than surgically undoing one
known mutation. Confirmed no module-level mutable state, so fresh parse + fresh Analyzer = full route
independence. Non-vacuity proven by INJECTION: re-introducing the shared-AST model turns 4 of the new tests RED.
*** LESSON (the sharpest of the round): the first attempt shipped a GREEN 30/30 suite WITH the live miscompile,
because its "shared abstract base" test used `bump(): void` - a MARKER-LESS member with nothing to strip.
Vacuous coverage of exactly the bug it was meant to catch. A green suite is not evidence. ***

Documented ABI-metadata divergences (PRE-EXISTING, base==fix, NOT bar violations, bytecode unaffected):
an UNUSED file-level event appears in JETH's ABI but not solc's; JETH never emits `receive`/`fallback` ABI
entries though the dispatcher is byte-correct; `@diamond class D {}` + a plain contract silently emits ONLY D
(pre-existing, unchanged by the multi-contract lift - a candidate for a future round).

### 2026-07-17 SILENT CONTRACT DROP closed (`58820e8`) - it was never a @diamond bug

USER-REPORTED as "@diamond + a plain contract silently emits ONLY D". Investigation showed the diamond is only
the shape the bug was SEEN through. ROOT CAUSE: findContractClasses (src/analyzer.ts:2098) pushed DECORATED
deployables (@contract/@proxy/@beacon/@facet) and ran the native-bare scan ONLY inside `if (out.length === 0)`.
Its own comment gave the rationale - "a pure FALLBACK ... so an existing decorated file (which may carry
unrelated bare helper classes) is never re-read" - which was TRUE in the legacy era and is STALE in native-only
mode: legacy decorators were removed (JETH481), a user CANNOT write @contract, and native item #4 makes a bare
non-abstract unextended class THE deployable contract, so "unrelated bare helper classes" no longer exist as a
category. @diamond enters this path only because expandDiamond SYNTHESIZES `@contract class D`. The same phase
split was mirrored in the collision pre-pass (compile.ts:588).
BLAST RADIUS (all silently dropped, compile() SUCCEEDED, artifact simply absent): @facet+bare, bare+@facet
(document order IGNORED), @proxy+bare, @beacon+bare, @diamond+bare, @diamond+2-bare (BOTH gone), across all 3
diamond variants x both orders = 12 rows. A SILENT DROP is the worst failure mode available - worse than a
reject.
FIX (enabled by #11 e563a16): routes = the UNION of decorated + native-bare in DOCUMENT ORDER, per #11's
convention (contracts[] document order, contracts[0] === the result object, singular fields = classes[0]).
Native-bare eligibility unchanged (isNativeContractClass + not-extended).

A SECOND, UNPINNED BUG THE UNION EXPOSED (found + fixed in the same commit): the diamond route-scoping flags
(isDiamond / diamondVariant / diamondStorageBase / diamondSel2FacetSlot, analyzer.ts:4171-4179, and the JETH414
builtin gate at :22366) read `this.diamond` = the FILE-level expansion flag, NOT whether the ROUTE is the
diamond. Its ctor doc said "this compilation unit's deployed contract" (singular) - an assumption that only held
while bare siblings were being dropped. Now route-scoped via `private get diamond()` gated on `routeIsDiamond`
(set as analyzeContract's first act). LESSON: a latent singular-deployable assumption can hide behind a bug that
made it true; lifting the bug exposes it.

ONE INTENTIONAL REJECT CHANGE (an OVER-ACCEPTANCE CLOSURE, not a regression): `@diamond('array') class D {}` +
`class C { c(): External<void> { diamondInit(msg.sender); } }` was ACCEPTED at base ONLY because C was dropped
wholesale so its invalid call was never analyzed; now JETH414 ("only valid inside a @diamond"). A loud reject
replacing a silent drop.

VERIFIED (adversarial, CLEAN): 12/12 drop rows fixed + every newly-emitted contract DEPLOYS and DECODES;
zero synthesized helpers leaked into contracts[] (all 3 diamond variants + proxy/beacon/facet; the verifier went
further and declared USER classes named like every synthesized helper - array synthesizes all 4 -> JETH272 each;
packed/solidstate synthesize only 2, so the other names are genuine user contracts, correctly emitted and
byte-identical to their solo twins); the DECORATED artifact did NOT shift (sha256 creation+runtime+ABI+layout ==
its decorated-only file's, both orders - diamond bytecode did not move); 51 programs (all 34 examples/*.jeth + 17
synthetic) sha256-identical base vs fix with `contracts` presence unshifted; every gate still fires (two @diamond
JETH041, two abstract leaves JETH041, duplicate names JETH037, contract-vs-file-level-type JETH272, no-deployable
JETH040, @beacon's ctor rule JETH407); #11 invariants intact. Suite 492 files / 4847 tests, tsc clean.

AUDIT NOTE: the `bare + decorated` singular-field shift (contractName F -> C) required ZERO test/example updates -
no examples/*.jeth carries a decorated deployable at all, and the only test matching the shape uses it for the
two-@diamond JETH041 gate. Nothing had been asserting the dropped-contract behaviour.
NOTE on the earlier "@beacon + bare -> JETH407" pin: that probe was MALFORMED (`@beacon class B { }` declares no
constructor; the gate legitimately requires `constructor(impl: address) {}`). With the canonical spelling the
beacon row is the SAME silent drop and is fixed by the union; the JETH407 rule itself is sound and untouched.

### 2026-07-17 MUTABILITY-SURFACE ROUND (USER RULINGS): JETH498 marker ban + `static` DECLARES pure, 2 live OAs closed

Four commits on `c4a1b0f`, each adversarially verified CLEAN. HEAD `d0d08fd`, suite 495 files / 4881 tests, tsc
clean, bar met. TWO of these are USER LANGUAGE RULINGS that deliberately ADD over-rejections; two are soundness
fixes. The rulings are recorded here so a future exhaustion audit sees them on the deliberate list and never
re-flags them as gaps.

**RULING 1 - `View<T>` / `Pure<T>` are INTERFACE-ONLY (JETH498, `ee9702e`).** In a class context (contract
`class C`, `abstract class B`, library `static class L`) the ONLY mutability forms are `get` (inferred),
`static` (pure) and `static get` (pure). The markers are banned in every class context; an interface is bodyless
so it MUST declare mutability, a class has a body so mutability is inferred. One choke point (analyzer
collectFunction) covers all three contexts; interfaces use a separate collector and are untouched by
construction. 34 spellings rejected, 0 holes (incl. bodyless `@virtual get a(): View<T>;`, private `get #a`,
nested `View<Arr<u256,2>>`, and the previously-ACCIDENTAL rejects `static a(): View<T>` which used to report
"unknown type" JETH013). A library `get` stays JETH043 (marker-independent, fires first - JETH498's pointer
"use `get a(): T`" would be wrong advice inside a library). Interfaces verified 23/23 byte-identical.
- *** THE TRAP IN THE ORCHESTRATOR'S OWN BRIEF ***: `View<T>` on a `get` did not only declare mutability, it
  ALSO implied EXTERNAL (`get f(): View<T>` was documented "EXTERNAL, DECLARED view"). The briefed migration
  ("just drop the marker") would have SILENTLY made every exposed accessor INTERNAL and deleted it from the ABI.
  The correct migration is `get f(): External<T>`. 30 markers across 7 test files; examples/ had zero.
- DELIBERATE OVER-REJECTIONS this creates (accepted by the author with the cost named): declaring `view` on a
  PURE body is now INEXPRESSIBLE (solc ACCEPTS `function f() external view returns (uint256) { return 1; }`);
  12 migrated sites flip ABI view -> pure (a flip happens EXACTLY when a `View<T>` site had a pure body). A
  DECLARED-pure caller is likewise inexpressible (2 contract-value-call parity cells kept, now JETH498 instead
  of JETH164). The removed feature's own test (get-declared-mutability.test.ts, GET-MUT-HEADROOM) is retired.

**RULING 2 - `static` DECLARES the member PURE (`d0d08fd`).** Previously `static` meant ONLY "class-level, no
`this`" and mutability was ALWAYS body-inferred; JETH354 is a `this`-BAN pre-pass (compile.ts:228), NOT a purity
gate. So `static a(): u256 { return msg.value; }` inferred `view` and MATCHED solc's honest twin
(`function a() internal view`) byte-for-byte + ABI-identical. The author ruled that `static` must DECLARE pure.
This is a DELIBERATE OVER-REJECTION, not a soundness fix - every newly-rejected program is one solc compiles as
`view`. Implementation: collectFunction sets mutability='pure' for a static member, and the get-accessor
synthesis now FORWARDS StaticKeyword (it was DROPPING it - mutation-tested: removing that alone fails 8 tests,
i.e. every `static get` silently escaped the ruling).
- REVIVES three DEAD codes. After JETH481 (decorator ban) + JETH498, NOTHING could declare a mutability, so
  JETH054/055/056/149/164 were all unreachable (the repo already knew: phase3-diagnostics.test.ts:6 and
  internal-calls-gate.test.ts:44 carried comments asserting exactly that). Now live: **JETH164** = a declared-pure
  static reads the environment (msg.*/block.*/tx.*/address(this), or an IMMUTABLE); **JETH055** = touches state
  (transitive emit via a callee; alongside JETH354 on storage-via-`this`); **JETH149** = a direct emit (its
  message named `@pure`, a JETH481-banned decorator - reworded to name the declared PROPERTY, never a spelling).
- PURE-LEGAL SET MATCHES SOLC EXACTLY (verified at the source, checkGlobal ~analyzer.ts:21529: `msg.data` returns
  EARLY before any env flag, `msg.sig` is cat 'calldata' and flags nothing, only cat 'value'/'env' set
  currentReadsEnv - so readsEnv already encoded solc's boundary and needed no change): msg.sig / msg.data /
  keccak256 / type(u256).max / a `static` constant stay PURE-LEGAL and still publish `pure`; an IMMUTABLE read is
  JETH164 (solc calls it environment). A constant folds (pure); an immutable does not.
- NEW REJECT THE RULING IMPLIES: `@nonReentrant static ...` -> JETH260. `static` declares pure; a reentrancy
  guard TSTOREs. See the miscompile below - rejecting is the only sound answer.

*** THE MISCOMPILE THE RULING'S OWN ~15-LINE PLAN WOULD HAVE SHIPPED (found + closed in the same commit) ***: a
declared-pure static SKIPS the post-fixpoint inference branch, which is ALSO the only home of JETH043 / JETH473 /
JETH352. The planned change alone silently dropped all three for statics. Two were lost diagnostics; the third
shipped a WRONG ARTIFACT - `@nonReentrant static a(): External<void>` went from ACCEPT/nonpayable (correct) to
ACCEPT with an ABI row claiming **pure** while the body TSTOREs the reentrancy mutex, so every staticcall /
eth_call reverts against a pure promise. NEITHER the 4856-test suite NOR a 141-case single-axis static sweep
caught it; it took crossing `static` with the CONSUMER axis (decorators x markers). Closed twice: RawFunction.
staticPure splits the branch (the mutability ASSIGNMENT stays inference-only, the VALIDATION runs for a
declared-pure static) PLUS a root-cause JETH260 at collection.

**SOUNDNESS FIX - an UNEXTENDED ABSTRACT CLASS WAS NEVER TYPE-CHECKED (`8a0ece0`, a live OA).** JETH analyzed
only the ROUTE class + its extends chain, so an abstract base nothing extends was DEAD CODE that was never
checked: `abstract class B { get a(): NoSuchType { return 1n; } }` + a deployable ACCEPTED, while solc
type-checks EVERY contract in a file and REJECTS. New checkStandaloneClassMemberTypes walks the SAME stray-class
set the existing checkStandaloneClassMemberDuplicates pass already walks (precedent: DUP-ID-ABSTRACT), resolving
each member's SIGNATURE types into the real bag (the same JETH013 the deployed path emits). Two load-bearing
details: a return/field MARKER is unwrapped FIRST (the deployed path strips markers in place and never ran for a
stray class, so the raw annotation would report a spurious "unknown type 'External'"), and a multi-value return
`[T1,T2]` resolves ELEMENT-WISE. NARROWED BY DESIGN: BODY-level type errors in a never-extended abstract still
accept (`get a(): u256 { return "not a number"; }`) - closing that needs full body analysis over a class with no
linearization, which is where the over-rejection tail lives; signatures were the sound half. 30/30 legit
unextended abstract bases still compile with the deployable byte-identical.

**DIAGNOSTIC FIX - JETH055 stopped lying (`a5488e6`).** It claimed "@pure function 'b' accesses state" for a
function that touches NO state (the funcref sig-union poisoning), and named `@pure`, a JETH481-banned decorator.
RETARGETED on discovery that the whole family was unreachable (see RULING 2). Now reworded to name the declared
PROPERTY, never a spelling, so it survives a future anchor change - which RULING 2 promptly proved right by
reviving it.

LESSONS (the orchestrator was wrong THREE times this round; every catch came from an agent refusing the brief):
1. *** THE VACUITY TRAP, ON THIS EXACT TOPIC ***: comparing `static a(): u256 { return 1n; }` to
   `a(): u256 { return 1n; }` proves NOTHING about whether `static` forces pure - a body that reads nothing
   infers pure EITHER WAY. That vacuous probe produced the false claim "static is silently ignored". EVERY
   mutability probe needs a DISCRIMINATING body: reads storage / reads env / writes / genuinely pure.
2. *** CIRCULAR SEVERITY ***: "solc REJECTS the twin" was argued from a twin that DECLARED pure - i.e. it assumed
   the conclusion. Against the HONEST twin (what JETH actually infers: `internal view`) the artifact MATCHED
   byte-for-byte. When asking "is this a bug", compare against the honest twin; the declared twin only answers
   "what would the ruling make illegal".
3. *** BUGS LIVE AT THE CROSSING OF TWO AXES ***: the @nonReentrant x static wrong-ABI was invisible to the full
   suite and to a 141-case single-axis sweep. Sweep the CONSUMER axis (decorators / markers / positions), not
   just the shape axis.
4. A MARKER CAN CARRY MORE THAN ITS NAME: `View<T>` on a `get` also implied EXTERNAL. "Just drop the marker"
   would have silently deleted accessors from the ABI. Check what a spelling ACTUALLY anchors before migrating it.
5. A TEST WHOSE HEADER CONTRADICTS ITS BODY IS RULE-DRIFT: class-mutability-marker-ban.test.ts asserted
   "static => PURE" in its header while its body asserted the opposite and warned "do not fix without an author
   ruling". The header was right. The body's reasoning had a concrete WRONG STEP - it claimed forcing pure "would
   emit an ABI solc REJECTS = an OVER-ACCEPTANCE", but forcing pure does NOT emit a pure ABI for an env-reading
   body, it REJECTS the program (an over-rejection, always safe). That error let the rule drift.
6. AUDIT DIAGNOSTIC REACHABILITY AFTER A LANGUAGE CHANGE: JETH054/055/056/149/164 all became dead code the moment
   nothing could declare a mutability. Dead diagnostics rot (JETH149 still named a banned decorator).

### 2026-07-17 CLOSED: getter-var-override of an INFERRED-PURE base (OA), single-head + multi-head (c3db959 + cde3a9f)

A pre-existing OVER-ACCEPTANCE (found during the JETH498 round, independent of it, live on main c4a1b0f). A public
getter VAR overriding a native contract base whose body INFERS pure was accepted; solc REJECTS the pure->view
loosening ("Overriding public state variable changes state mutability from pure to view").
  `abstract class A2 { @virtual get g(): External<u256> { return 1n; } }` (body infers PURE)
  `class C extends A2 { @override static g: Visible<u256>; constructor() { this.g = 5n; } }` -> JETH ACCEPT, solc REJECT
ROOT CAUSE: the JETH433 getter-var mutability check ran at COLLECTION time (analyzer.ts:5851), when a native base's
`base.mutability` still held the provisional nonpayable default (pureness is only inferred later by the purity
fixpoint). The interface-head axis was ALWAYS sound (an interface DECLARES its mutability, final at collection).
The obvious defer-to-post-fixpoint fix FAILS: a base whose ONLY override is a getter var is DROPPED from the
dispatched winners (analyzer.ts:5015-5018 - a public state-var override is terminal in solc), so it never reaches
the `functions` array the fixpoint iterates and is never inferred at all.
FIX (c3db959): a byte-neutral BASE-EFFECTS PASS runs checkFunction on each dropped, non-bodyless base and stores
its direct effects into the `effects` MAP ONLY (never into `functions`, so nothing is emitted); the transitive
fixpoint then closes those effects through the base's ordinary callees (TRANSITIVE-correct: a base calling a
storage/env helper stays view->ACCEPT; a base calling only pure helpers is pure->REJECT). The check moved
post-fixpoint. *** It snapshots + restores the 6 GLOBAL EMISSION collections (addressTaken/internallyCalled/
specialization/etc.) around the base checkFunction *** - without that, a constructed witness (a dropped base body
taking `&writer` + an external fn with an unresolvable storage-funcref call) flipped that fn's mutability AND its
BYTECODE. A getter over an inferred-VIEW base still ACCEPTS (view->view legal); a CONSTANT getter (pure) over a
pure base still ACCEPTS.

*** ADVERSARIAL VERIFY CAUGHT A SURVIVING OA IN THE SAME FAMILY (c3db959 shipped 495/4881 GREEN over it) ***:
multi-head `@override(A2, B2)` with ONE pure head + one view head was still accepted (deploys, emits g:view,
runs) while solc rejects. ROOT CAUSE: the base-effects pass keyed the effects map by the bare getter fkey, so two
same-signature jointly-overridden heads (A2.g + B2.g) COLLIDED on the single key "g" and `effects.has(bkey)`
skipped all-but-first; the deferred check's `be.rf === base` guard then let the skipped head fall back to
provisional nonpayable. ORDER-DEPENDENT: pure-head-first over-accepted, pure-head-last happened to reject. The fix
had rewritten its OWN multi-head regression cells to VIEW bases (the VACUITY TRAP again - tests changed to match
the code, not the spec), so nothing asserted the pure-head case.
CORRECTIVE (cde3a9f): the base-effects pass computes EACH overridden head's effects under its OWN synthetic key
(`baseEffKey: Map<RawFunction,string>`, never the colliding fkey - safe because a dropped base is never a callee
target, while its own callees stay real fkeys the shared fixpoint resolves); getterVarBaseMutPairs became one
entry-per-getter carrying `bases: RawFunction[]`, and the post-fixpoint check rejects if ANY overridden head is
pure-and-getter-not-pure (or payable). Also closed a SECONDARY over-rejection c3db959 introduced: the base-effects
checkFunction did not restore the DIAGNOSTICS bag, so a dropped base with a JETH-unlowerable body (e.g. a
recursive-struct memory local, JETH495) LEAKED a spurious reject; now snapshot+truncate `this.diags.items` around
the pass (a dropped base is not deployed, so solc only reads its mutability here, not its body deployability).
Verified CLEAN: multi-head closed in EVERY head order (pure-first/middle/last, extends-order swap, 3- and 4-head
pure-at-any-position, 2-level transitive-pure chains, deep-diamond) at solc parity via deploy+run+decode;
byte-identical over 66 programs; mutation-tested RED on c3db959 (5/10 new cells fail without the corrective, the 5
order-lucky ones pass - directly demonstrating the order-dependence). Suite 495 files / 4891 tests, tsc clean.
LESSON: the env-read-first ordering in the diags-restore witness is load-bearing - when checkFunction ABORTS on an
unlowerable construct the later storage read is lost, so an env read placed BEFORE it keeps VIEW inference robust
(otherwise the base misinfers pure and JETH433 wrongly fires). A base-effects pass that computes effects for
NON-DEPLOYED code must isolate BOTH its emission side effects AND its diagnostics from the deployed compilation.

### 2026-07-18 FULL-AUDIT RESUME: 14 soundness fixes (2 MC + ~12 OA families) + 4 documented keeps

The 2026-07-18 100% differential audit (resumed from its weekly-limit stop at `3a169c2`) verified all 10
original MC/OA candidates deploy+run+DECODE, then ran FOUR adversarial rounds - fix -> merged-tree
cross-verify -> close holes -> loop-until-dry re-sweep - each round finding holes the prior one left. Every
confirmed miscompile / over-acceptance is now closed; the tightenings were proven (re-sweep, 12 agents) to add
ZERO new over-rejection of a valid program. HEAD `053b718`, suite 499 files / 5102 tests, tsc clean, flake gate
(`--sequence.shuffle.files`) green.

**MISCOMPILES CLOSED (2):**
- **MC1 @nonReentrant name-collision** (`5ab9463`, JETH499): a user `@modifier nonReentrant() {...}` was
  silently treated as the built-in transient-storage guard, DROPPING the user body (a run-diff miscompile).
  USER RULING: reject the collision.
- **MC3 @diamond diamondCut Remove-underflow** (`df09ce6`): the packed/solidstate synthesized Remove loops used
  a raw `sub` for the selector count; a remove-from-empty returned the not-found Error/SelectorNotFound instead
  of solc's Panic(0x11). Routed through the checked-sub helper (USER RULING: match mudgen).

**OVER-ACCEPTANCES CLOSED (~12 families):**
- OA5 interface+class same-sig ambiguity bypassed JETH430 (`4d717b7`) - extended the diamond check to
  single-version (interface-competing) groups.
- OA4 / OA4b stray-abstract member types (`3646208` + `ef921de`) - undefined types in an event/error field
  (object-literal AND bare/positional), ctor param, or @modifier param now JETH013; indexed-on-error JETH129.
- OA6 / OA6b / EXPANDED reserved-word identifiers (`5ab9463` + `ef921de` + `2fc530d`, JETH500) - the FULL
  solc-0.8.35 reserved-word list (69 words), at every declaration-name position. `receive`/`fallback` (JETH
  special-entry method names) and `error` (a legal solc identifier) are EXCLUDED. USER RULING: expand to the
  full list. Residual: `abstract` as a plain local/field name still accepts (TS parses it as a modifier
  keyword, so the walker sees no identifier node) - a rare safe over-acceptance, documented.
- OA7 / OA7b signed + bytesN + address/bool + dynamic-outer storage array-literal convertibility (`6b5021f` +
  `ef921de`, JETH497) - the element-only common-type fold + storage element-wise-copy convertibility now match
  solc; valid widening/same-type dynamic assigns stay byte-identical.
- OA8 / OA8b unicode/BOM/format whitespace as token separators + the full `//` comment line-terminator set
  (`80a85d2` + `ef921de`, JETH491).
- H1 stray top-level non-declaration statement (`7637c96`, JETH501) - a bare identifier / expression / `if` /
  `for` / `return` / `;` / non-const file-level `let` was silently ignored; now rejected.
- H2 non-printable/non-ASCII content in a REGULAR `"..."`/`'...'` string literal (`7637c96`, JETH499) - solc
  requires printable-ASCII-or-escape; escapes and TEMPLATE literals stay accepted + byte-identical.
- unextended-abstract-class member BODY type-checking (`6836006`) - a broken body (undeclared id, bad type,
  illegal @override, view-mutation, return-arity) in a never-extended abstract was accepted; now re-parsed and
  fully analyzed. Also made stray event/error fields consistent with the deployed path (bare positional
  `event<u256>` rejects JETH353; the object-literal `event<{x:T}>` is the canonical form).
- unused-@modifier body type-checking - a declared-but-never-applied modifier's broken body was accepted (a
  modifier body is otherwise only checked when inlined at an application site); now checked standalone across
  the WHOLE modifier family: contract modifiers + the override-loser base declaration (`053b718`); LIBRARY
  modifiers (`5d813fc`, which also closed a bonus pre-existing OA: `this.<field>` contract-state access in a
  library modifier body); and unapplied SELF-GENERIC modifier templates (`9702e8f`, via a probe set of concrete
  type-parameter bindings so a body valid at some type is not over-rejected + only type-parameter-independent
  errors are reported; extended by `f9801a6` to also reject a MULTI-SITE conflict broken under every probe at
  different spans, and by `80f6295` to use the CROSS-PRODUCT of probes over the type params so a valid
  heterogeneous MULTI-type-param body `m<A,B>(a: A, b: B)` is not over-rejected).
- integer-vs-address arithmetic/bitwise operator on the address-literal operand path (`c3d60dd`, JETH083) -
  `u256var + address(0)` (and `-`/`*`/`&`/..., both orders, plus the `address(0) == intVar` comparison
  mismatch) was accepted; root cause was `retypeLiteral` declining an address-typed literal SILENTLY so
  `unifyOperands` returned undefined with no diagnostic. The address-variable path already rejected via
  JETH083; now the literal path emits the same. Found incidentally by the library-modifier verification.

**NEW SAFE OVER-REJECTION (the only genuine new OR from this audit):** a user `@modifier` named `nonReentrant`
is rejected (JETH499) where solc accepts `modifier nonReentrant()` - a deliberate reject to prevent the MC1
silent-drop miscompile (USER RULING). The reserved-word / string-content / top-level / whitespace rejects are
all BOTH-REJECT PARITY with solc, NOT over-rejections.

**DOCUMENTED KEEPS (not bar violations - sound bytes or unmatchable):**
- **MC2 internal-funcref `==` with identical bodies**: solc's optimizer dedups two byte-identical function
  bodies to one code offset so the funcref pointers compare EQUAL; JETH gives distinct dispatch ordinals so
  UNEQUAL (same ordinal-vs-code-offset root as LT5). USER RULING: keep, documented. NB: a SILENT divergence vs
  the optimizer-on test reference - a loud reject would be strictly bar-consistent if ever desired.
- **Ragged / nested dynamic array literal** `[[1n,2n],[3n]]`: JETH accepts and builds a correct jagged array;
  solc rejects ("Unable to deduce common type"). USER RULING: keep as a native-mode superset, same family as
  the shipped `let a: T[] = [1n,2n,3n]` dynamic-array-literal feature (solc rejects that too; JETH's bytes are
  byte-identical to solc's `new+assign`).
- **deep-nesting** (~200+ levels): solc stack-overflows / crashes; JETH accepts with correct bytecode.
  Genuinely unmatchable (like `gasleft`).

**RARE PRE-EXISTING RESIDUAL OVER-ACCEPTANCES (documented, out of scope; sound bytes, never a miscompile):**
- an `abstract` used as a plain local/field identifier (TS parses `abstract` as a modifier keyword, so the
  JETH500 walker sees no identifier node; it fires for `abstract` in the positions TS does yield a node).
- a broken body inside an unapplied SELF-GENERIC modifier that reaches a NESTED-aggregate struct field or an
  enum member through the bare type param (valid only at a type outside the finite probe set) stays a clean
  reject - never instantiated, never a miscompile (the concrete / library / depth-1-struct generic cases ARE
  closed).
- ~~an UNAPPLIED @modifier body whose array param is used in a DATA-LOCATION CHIMERA~~ **CLOSED (`bcfb8ad`).**
  `@modifier m(v: u256[]) { v.push(1n); _; }` (and its `v.push(1n); v = new Array<u256>(3n)` chimera and generic
  variants) was over-accepted while solc rejects the memory-array push at every monomorphization. ROOT CAUSE (the
  earlier residual note misdiagnosed it): the `u256[]` param IS already a `memArray` base; a memory-array push was
  simply rejected only at CODEGEN (the generic JETH900 in yul.ts), which fires solely when the body is lowered -
  and a declared-but-UNAPPLIED @modifier body is type-checked into a discarded sink and never lowered, so JETH900
  never ran. FIX: one analysis-time gate in `checkArrayMutator` (`analyzer.ts:~13008`) - a `memArray`/`memArrayExpr`
  base emits JETH210, the memory analog of the calldata (JETH214) / fixed (JETH218) rejects just above it. Because
  it fires during type-checking it catches the never-lowered body; the generic + chimera cases close for free (the
  generic probe checker routes every monomorphization through the same body path). SOUND: solc never accepts
  push/pop on a memory array, so it only turns an over-acceptance (or the normal-fn codegen reject) into a clean
  analysis-time reject - proven with a 29-case no-new-over-rejection control sweep (v.length / v[i] / abi.encode(v)
  / pass-to-internal-fn / storage `this.arr.push` / nested `this.dd[i].push` / applied-modifier valid body all still
  accept + byte-identical). Diagnostics-only; byte-identity unaffected. (Residual: a struct-element `P[]` /
  dyn-struct `D[]` memory array param push/pop rejects via JETH214 rather than JETH210 - a clean reject on both
  sides, pre-existing, code/message-only difference, not a bar violation.)

The whole unused-@modifier-body family (contract / abstract / library / self-generic) is now closed; the
library-modifier residual noted in earlier revisions is CLOSED (`5d813fc`).

**APPLIED generic `@modifier` U-typed body local / annotation - LIFTED byte-identical (`9b780cd`).** An
APPLIED generic `@modifier` whose body declares a local typed with the type parameter (`let y: U = v`, or any
U-typed annotation in the body) was over-rejected JETH013 "unknown type U": `collectModifier` stores the body's
RAW TS statements and they were re-checked at each application site OUTSIDE the monomorphization `withTypeBinding`
that was active during collection, so `U` did not resolve. FIX: `RawModifier` now carries the concrete
`binding` (type-param -> instantiation type) captured at monomorphization; `withModifierTypeBinding` restores it
around the body lowering at all three application sites (`buildModifierWrap`, `inlineModifier`,
`inlineModifierBodyIntoCtor`), so `U` resolves to the concrete type - matching solc's monomorphized modifier
body. The binding is restored ONLY around the modifier body (the caller-scope application args stay outside it),
so it does not leak into the wrapped function / sibling methods / the arg expressions. SOUND: a 6-lens adversarial
verify (deploy+run+decode, 0 confirmed bar violations) proved zero MC / zero OA / zero NEW over-rejection - a
body broken AT the concrete instantiation still rejects (the checker is as strict as solc on the substituted
body), the binding is a genuine no-op for non-generic modifiers (byte-identical creation/runtime bytecode,
stash-diff verified), and byte-identity holds across value / bytes / string / dynamic-array / fixed-array /
struct / funcref / enum / branded instantiations and every body shape (pre-only / post-placeholder /
conditional / whole-body / constructor-applied) plus multi-type-param.

**Generic `@modifier` on a CONSTRUCTOR with a pointer-headed AGGREGATE whole-value - LIFTED byte-identical
(`4541fd1`).** A generic `@modifier` applied to a **CONSTRUCTOR** using a pointer-headed aggregate type argument
(struct / dynamic-field struct / fixed array `Arr<T,N>`) as a **WHOLE VALUE** - `this.sp = v` (whole storage
assign), a body local `let y: T = v; this.sp = y`, `this.sum(y)` (internal-fn arg), `emit(Ev(y))` (event arg) -
was over-rejected JETH085 "cannot assign u256 to P" where the solc monomorph compiles + runs. ROOT CAUSE (an
ANALYSIS-ORDERING bug, NOT codegen - the earlier "inlineModifierBodyIntoCtor resolves the rvalue to u256"
diagnosis was WRONG, corrected by instrumenting the JETH085 emission stack): the standalone unapplied-generic-
modifier-body pass type-checks a generic body under a FINITE probe set (u256/i256/bool/address/bytes/string/
bytes32/array/enum/synthesized-struct) and rejects only errors firing under EVERY probe. A ctor-applied generic
was not yet in `appliedGenericModifierNames` when that pass ran (constructor lowering runs LATER than function
lowering), so a body valid ONLY at the real non-probe instantiation type - a user struct `P` - errored under
every probe and was wrongly rejected as uninstantiable. A FUNCTION application already marks the template applied
before the pass, which is exactly why the same body accepted on a function but not a constructor. FIX: pre-scan
the route's constructor chain (`this.ctorChain`) for generic-modifier application names and add them to
`appliedGenericModifierNames` before the standalone pass, excluding a ctor-applied template from it (identical to
how a function application suppresses it). The real monomorph is still type-checked at the ctor inline site (which
runs for every ctor in the chain, including the abstract-check route), so a genuinely broken ctor-applied body is
still caught there. CODEGEN-NEUTRAL (the ctor inline codegen was always correct, only gated behind the spurious
analysis reject). SOUND: a 4-lens adversarial verify (~122 cases, git-stash-proven non-vacuous) found 0 MC / 0 OA
/ 0 new over-rejection - byte-identical across struct / nested / dyn-field / bytes-and-string-field / enum /
`Arr<u256,N>` instantiations x whole-assign / body-local / internal-fn-arg / emit(+logs) / abi.encode / return
consumers x inheritance / multi-level / merged-ctor / payable / mixed-modifier / multi-type-param / all body
shapes; a broken ctor-applied body still rejects at the inline site; a sibling never-applied broken generic is
still checked (no over-suppression); `Arr<In,N>` whole mem->storage copy stays a matching both-reject (JETH470 =
solc legacy UnimplementedFeatureError). Note the diagnostic cascade also improved: pre-`9b780cd` the body-local
form additionally emitted JETH013 for `let y:T`; the U-typed-local lift removed that, and this fix removes the
remaining JETH085.

**PRE-EXISTING SAFE over-rejections in the same neighbourhood (NOT introduced by either lift; orthogonal, kept):**
(1) a struct with a dynamic array field constructed from an INLINE fixed-array literal - `D(7n, [u256(1n),2n,3n])`
where `D = { a: u256; xs: u256[] }` - rejects JETH226 ("struct field xs expects u256[], got u256[3]"); the same
literal is rejected identically in a plain body local / function arg (a general fixed-array-literal-to-dynamic-
array-field coercion gap, not modifier-specific; the helper-built `@m(this.mk())` path is byte-identical). (2) a
bare string LITERAL as a generic `@modifier` param argument - `@m("hi")` with `v: T` - is over-rejected ("a
string literal is only valid where a string/bytes value is expected"); it also fires on a FUNCTION application, so
it is a general generic-modifier string-literal-arg gap (a NON-generic modifier string param accepts). Both are
safe (never wrong bytes) and independent of the ctor path.
