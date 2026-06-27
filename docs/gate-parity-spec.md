# Gate parity: lift JETH312 (public-immutable getter) + JETH321 (modifier conditional placeholder)

The last two SAFE over-rejections (JETH cleanly rejects valid Solidity that solc 0.8.35 accepts; never
miscompiles). Close them byte-identical to solc. Two independent, small fixes. Do NOT touch the constructor
gates (JETH302/303 - already done, commit 9f704dc).

## JETH312 - `@external @immutable` (a public immutable's auto-getter)
CURRENT: src/analyzer.ts ~3400-3411 rejects an `@immutable` field that ALSO carries any
visibility/mutability decorator, because solc auto-generates a view getter for a `public immutable` which
JETH's ABI emitter does not produce. solc ACCEPTS `uint public immutable x;` (with a synthesized
`function x() external view returns (uint)` getter).

FIX: when an `@immutable` field is also `@external`, SYNTHESIZE its view getter instead of rejecting:
- Add the getter to the ABI + the runtime selector dispatch: `<name>() returns (T)` (T = the immutable's
  value type), state mutability VIEW (an immutable read is `loadimmutable`, which sets the env-read flag so it
  needs @view not @pure - it does NOT read storage).
- The getter body returns the immutable value via the SAME `loadimmutable` mechanism a runtime `this.<name>`
  read uses (see how @immutable fields are read at runtime). It consumes NO storage slot.
- Look at how a `@external @state` field's getter is synthesized today (the publicStateNames / getter path) and
  mirror it for an immutable, swapping the storage read for the loadimmutable read.
KEEP REJECTING the other decorators on an immutable (`@view`/`@pure`/`@payable`/`@public`/`@internal`/`@private`/
`@hidden` are nonsensical or removed) - only `@external` (the getter) becomes valid. So the `extra` check should
ALLOW `external` (and trigger getter synthesis) while still rejecting the rest.
BYTE-IDENTITY: the getter's selector = `keccak(name + "()")[:4]`, returndata = the immutable value (ABI-encoded),
identical to solc's auto-generated `public immutable` getter. Verify the value AND the selector match.

## JETH321 - a `@modifier` with the `_` placeholder inside a conditional (the 0-or-N-times shape)
CURRENT: src/analyzer.ts ~4324-4333 requires the `_` placeholder to be a TOP-LEVEL statement of the modifier
body; a placeholder nested in an `if`/`for`/`while` is rejected (the "conditionally runs the body 0-or-N times"
shape). solc ACCEPTS `modifier m(bool c) { if (c) { _; } }` (the wrapped function runs 0 or 1 times; if it does
not run, the function returns its zero value).

FIX: relax the top-level-placeholder requirement to ALSO allow a placeholder nested inside a conditional/loop.
The full-modifiers mechanism already lowers the wrapped function body as a SYNTHESIZED Yul function
(`userfn_<key>`) and the modifier wrap carries a `modifierBody` IR marker that lowers to `ret := userfn_<key>(...)`
(or a bare call for void). For a conditional placeholder, the `modifierBody` marker simply sits INSIDE the
conditional, so the wrap runs the body 0-or-N times naturally; on a 0-times path `ret` keeps its zero-init,
which matches solc (a modifier that skips `_` returns the function's zero value).
- Relax the placeholder-position gate (the `topIdx`/`findIndex` top-level check) to find the placeholder
  anywhere (incl. nested), and split pre/post relative to it as needed, OR lower the whole modifier body with the
  placeholder replaced in place by the `modifierBody` marker (recursing into conditionals/loops to find it).
- The wrap-lowering (yul) must find/replace the `modifierBody` marker even when it is nested in an if/for/while
  (recurse). The 0-times path must leave `ret` at its zero value and skip the body call.
- KEEP the existing OTHER modifier gates unchanged: still reject more than one placeholder, and still reject a
  `return` inside the modifier body (the early-out shape - a DIFFERENT gate, not in scope here). Only the
  single-placeholder-inside-a-conditional case is being lifted.
BYTE-IDENTITY: a modifier `m(bool c) { if (c) { _; } }` applied to `f(): T` returns the body's value when c is
true and the zero value of T when c is false, identical to solc. Verify both branches over a value return and a
void return, and that pre/post code around the conditional still runs (e.g. `pre; if (c) { _; } post;`).

## Constraints
- tsc clean. Full suite stays green and byte-identical (currently 271 files / 2287 tests); NEVER edit/relax an
  existing test (except a test that asserted EXACTLY the lifted over-rejection - flip it to assert acceptance,
  like the constructor work did for its two JETH302/303 assertions). Do NOT change any currently-accepted
  program's output. Do NOT introduce any acceptance solc rejects.

## Verification (byte-identical to solc 0.8.35)
Add test/gate-parity.test.ts:
- JETH312: a `@external @immutable x: u256` (set in the ctor) - deploy a JETH contract + a solc
  `uint public immutable x` mirror; call `x()`; diff the returndata (the immutable value) AND confirm the
  selector dispatches. Also a bytes32/address immutable getter.
- JETH321: `@modifier maybe(c: bool) { if (c) { _; } }` on a value-returning `f()` and a void `g()`; call with
  c=true (body runs, value returned / state written) and c=false (body skipped, zero value returned / no state
  change); diff returndata + raw storage vs a solc mirror with the same modifier. Add a `pre; if(c){_;} post;`
  shape to confirm surrounding code runs in both branches.
Read raw slots via h.evm.stateManager.getStorage; compileSolidity returns {creation, storageLayout} (no abi);
events are emit(E(args)); JETH integer literals need the `n` suffix.
