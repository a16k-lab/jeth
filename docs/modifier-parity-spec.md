# Modifier parity: lift JETH320 / JETH322 / JETH323 / JETH325 (the last modifier over-rejections)

Four SAFE over-rejections in the `@modifier` mechanism (JETH cleanly rejects valid Solidity that solc 0.8.35
accepts; never miscompiles). Close them byte-identical to solc. All four were confirmed real over-rejections by
a JETH-vs-solc triage (solc ACCEPTS each). The modifier infra is mature (pre/post code, buffered return,
conditional placeholder all already work) - these extend it.

Anchors: src/analyzer.ts collectModifier (~4360+), wrapModifiers (~4123), buildModifierWrap (~4194), the
`{kind:'modifierBody'}` marker + `placeholderInner` in-place `_;` replacement (~155-181, ~4222-4240),
inlineModifier (~4194), RawModifier (~147). Gate sites: JETH320 ~4400, JETH322 ~4379, JETH323 ~4145/4157/4165/
4176/4287/4298, JETH325 ~4429. The buffered-userfn path (the wrapped body is a synthesized Yul function the
`modifierBody` marker calls as `ret := userfn_<key>(...)`) is the key mechanism. src/yul.ts emitDispatchCase
modifierWrap branch + the modifierBody lowering.

## JETH320 - MULTIPLE `_` placeholders
solc accepts `modifier m() { _; _; }` (the wrapped body runs N times; for a value-return the LAST run's value
is returned). CURRENT: collectModifier rejects >1 placeholder (~4400). FIX: allow N placeholders. Route the
modifier through the whole-body buffered path (like the conditional-placeholder path) where EACH `_;` is
replaced in place by the `modifierBody` marker (the `placeholderInner` replacement must replace ALL N
occurrences, not just the first). Each marker lowers to `ret := userfn_<key>(...)`, so the body runs N times
and `ret` holds the last run's value - byte-identical to solc. Pre/post/inter-placeholder code runs in
declaration order.

## JETH322 - AGGREGATE modifier parameter
solc accepts `modifier chk(uint[] memory xs) { require(xs.length>0); _; }`. CURRENT: collectModifier rejects a
non-value modifier param (~4379). FIX: allow the SAME aggregate/dynamic param types function params support
(T[], Arr<T,N>, structs, bytes, string). A modifier arg is materialized ONCE in the param scope (the existing
arg-materialization); an aggregate arg (e.g. an array literal `@chk([1n,2n])`) materializes to memory and the
param is registered as a memory local (reuse the function/ctor aggregate-param materialization - the ctor work
added registerAggregateCtorParam + abiDecFromMem; the modifier arg is an already-in-memory value, so it is
simpler: bind the materialized aggregate as the param's memory local). KEEP the mapping reject.

## JETH323 - post-code on an AGGREGATE-PARAM / MULTI-VALUE-RETURN / AGGREGATE-RETURN function
solc accepts a function with an aggregate/dynamic PARAM, a MULTI-VALUE return, or an aggregate RETURN that ALSO
has a modifier with POST-code (the buffered path). CURRENT: the buffered-userfn path is gated to value/bytes/
string SINGLE-return, value-only params (the 6 JETH323 sites ~4145-4298). FIX: extend the buffered userfn to
handle what FUNCTIONS already support - the synthesized userfn_<key> can take aggregate/dynamic params (it is a
normal internal function) and return an aggregate or a multi-value tuple; the dispatch captures the userfn's
return(s) into the buffered `ret` var(s) and encodes once after the post-code. For a multi-value return, `ret`
becomes multiple vars (ret0,ret1,...); for an aggregate return, `ret` holds the pointer. KEEP the genuine
remaining gate: a CONSTRUCTOR with post-code modifier (the ~4287/4298 sites - no userfn body in creation code)
stays JETH323. Only the FUNCTION shapes (aggregate param, multi-value return, aggregate return) are lifted.

## JETH325 - a `return` inside a modifier body
solc accepts `modifier m() { _; return; }` (a bare `return;` in a modifier returns from the wrapped function
with the CURRENT return values). CURRENT: collectModifier rejects any `return` in the modifier body (~4429).
FIX: allow a BARE `return;` in a modifier body; lower it to `leave` (exit the dispatch with the current `ret`
var(s) - their zero-init or whatever the body/modifier set so far), matching solc. KEEP rejecting a VALUE
return `return expr;` in a modifier (a modifier has no return type - that is a real error, solc rejects it too;
verify with a probe and keep that reject).

## Constraints
- tsc clean. Full suite stays green and byte-identical (currently 272 files / 2298 tests). NEVER edit/relax an
  existing test EXCEPT one asserting EXACTLY a lifted over-rejection (flip to assert acceptance, like the prior
  parity work; check test/modifier.test.ts for JETH320/322/323/325 assertions to update). Do NOT change any
  currently-accepted program's output. Do NOT introduce any acceptance solc rejects (a value-return modifier,
  an aggregate-param ctor-with-post-code, etc. must STILL reject).

## Verification (byte-identical to solc 0.8.35)
Add test/modifier-parity.test.ts. For each, deploy a JETH contract + a solc mirror with the same modifier
shape; diff returndata + raw storage slots + revert:
- JETH320: `m(){ _; _; }` on a value-return f() (returns the last run's value) and a state-writing g() (writes
  twice); also `pre; _; mid; _; post;` ordering.
- JETH322: `chk(uint[] xs){ require(xs.length>0); _; }` applied with an array-literal arg; the require fires on
  empty and passes on non-empty (both branches vs solc).
- JETH323: a modifier `g(){ _; <post state write>; }` on (a) a fn taking `xs: u256[]`, (b) a fn returning
  `(u256,u256)` multi-value, (c) a fn returning `u256[]` - each with the post-code running after the body.
- JETH325: `m(){ _; return; }` and `m(){ if (c) { return; } _; }` (early-out) - the function returns the zero
  value when the modifier returns early, runs the body otherwise.
Confirm the kept rejects still fire: a value-return modifier (`m(){ return 5n; }`) and a constructor with a
post-code modifier still reject. Read raw slots via h.evm.stateManager.getStorage; compileSolidity returns
{creation, storageLayout} (no abi); JETH modifiers take NO return type (`@modifier m(...) { ... }`); integer
literals need the `n` suffix.
