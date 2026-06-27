# Parity batch: close the remaining tractable over-acceptances + over-rejections from the broad sweep

A broad differential sweep (JETH vs solc 0.8.35) found these. The one SOUNDNESS over-acceptance (aggregate
`==`/`!=`) is already FIXED (JETH088, commit c445057). This batch closes the remaining TRACTABLE divergences.
Two genuinely-architectural over-rejections are DEFERRED (documented at the bottom) - do NOT attempt them here.

Invariant: byte-identical to solc on returndata + raw storage + logs + revert, and matching accept/reject.
Constraints (ALL fixes): tsc clean; full suite stays green and byte-identical (currently 273 files / 2315
tests + the new aggregate-comparison file); NEVER edit/relax an existing test except one asserting EXACTLY a
lifted gate; do NOT change any currently-accepted program's output; do NOT introduce any acceptance solc
rejects. Use graphify FIRST then read exact lines (project rule). Add tests for each fix (a codes()-style
accept/reject assertion for the gate changes; a byte-identity differential vs a solc mirror for the codegen
lifts). Node v22 for vitest: `export PATH="$HOME/.nvm/versions/node/v22.22.2/bin:$PATH"`.

## (A) OVER-ACCEPTANCE: uninitialized `mapping` local  [analyzer gate, trivial]
`let m: mapping<u256,u256>;` is ACCEPTED by JETH (inert, no codegen) but solc REJECTS ("Uninitialized mapping.
Mappings cannot be created dynamically"). FIX: in the local-variable-declaration check, reject a local whose
type IS or CONTAINS a mapping (reuse `typeHasMapping`, the same predicate the ctor-param JETH247 gate uses).
Pick a clear diagnostic (a fresh JETHxxx, e.g. "a mapping cannot be a local variable - mappings are
storage-only"). This is benign today (every USE is already independently rejected) so the change is purely the
declaration gate; confirm no currently-accepted program declared such a local.

## (B) OVER-ACCEPTANCE: `@using(L)` attached fn name collides with a receiver-type BUILT-IN member  [analyzer]
When an `@using(L)` library function's name equals a BUILT-IN member of the SAME type it is attached to (e.g. a
lib `length(xs: u256[])` vs the built-in `.length` on `u256[]`, or `push` on a storage array, or `balance` on
address), solc makes the member access AMBIGUOUS and REJECTS ("Member \"length\" not unique after
argument-dependent lookup in uint256[] memory"). JETH currently silently lets the BUILT-IN win and ACCEPTS
(value-correct, but a divergence). FIX: at member-access / attached-call resolution (resolveAttachedLibraryCall
~7758 and the member-access dispatch sites ~4863/~13149), when a member name resolves to a BUILT-IN member of
the receiver type AND an `@using` library also attaches a function of that exact name for the receiver type,
emit a clean ambiguity diagnostic (reject) instead of preferring the built-in. Only the SAME-receiver-type
collision is ambiguous; a lib fn attached to a DIFFERENT type than the receiver is NOT a collision (stays
accepted). ALSO correct SUPPORTED.md: the claim "a built-in method of the receiver type wins over an attached
library method (matching solc)" is WRONG - solc errors on the ambiguity; update it to say a same-name collision
is rejected as ambiguous (and the no-collision attached path still works).

## (C) OVER-REJECTION: default-init struct memory local `let p: P;`  [codegen lift, common idiom]
`let p: P; p.a = 5n; return p.a;` is REJECTED (JETH200/067) but solc ACCEPTS (a struct memory local is
zero-initialized, then field-assigned). FIX: recognize an uninitialized struct-typed local and lower it to the
EXISTING zero-init path (the analyzer already builds `P(0n, 0n, ...)` for a struct literal / the default value;
synthesize that as the initializer). Value-type-field structs first (the common case); a dynamic-field struct
local (bytes/array fields) is the existing G10/JETH200 gate - keep it deferred if the zero-init is not trivially
expressible, and document which struct shapes are lifted. Verify byte-identical to a solc `P memory p;` mirror
(raw returndata for the field reads/writes).

## (D) OVER-REJECTION: member access on a struct-returning call `this.mk(a).x`  [codegen lift]
`return this.mk(a).x;` where `mk` returns a struct is REJECTED (JETH074) but solc ACCEPTS (member access whose
base is a CallExpression returning a struct). FIX: lower a PropertyAccess whose base is a struct-returning
internal call - materialize the call result to a memory struct (the internal-call-returning-a-struct path
already exists when bound to a local) and read the field. The idiomatic workaround (bind to a local first) works
today, so the lowering exists nearby; extend it to the direct member-on-call form. Verify byte-identical.

## (E) OVER-REJECTION: function `.selector`  [codegen lift, medium]
`this.g.selector` / `g.selector` (-> bytes4) is REJECTED (JETH074) but solc ACCEPTS (the 4-byte selector of a
function). FIX: support `.selector` on a function reference -> the compile-time bytes4 selector constant (it is
known at compile time: `functionSelector(signature)`; `abi.encodeWithSelector` with a literal bytes4 already
works, so this just surfaces the same constant as an expression). Cover an external/public function reference
(`this.f.selector`). Verify the bytes4 value byte-identical to solc's `f.selector`.

## DEFERRED (architectural / codegen-heavy - DO NOT attempt here; document honestly in SUPPORTED.md)
- A memory struct local initialized FROM a CALLDATA struct-array element (`let p: P = ps[0n];`, ps: P[] calldata)
  and `for (const p of ps)` over a calldata struct array (JETH900) - the manual index loop works; the binding
  lowering is codegen-heavy.
- NESTED / multi-dim memory-array LOCALS (`u256[][]`, `Arr<Arr<T,N>,M>`, `new Array<u256[][]>(n)`) - JETH200;
  the value-element memory-array-local codec does not yet recurse into nested element types (storage nesting
  works).
- Aggregate `abi.decode` targets (struct, struct-array, bytes[]/string[], nested) - JETH322/JETH200; JETH's
  dynamic-struct memory image is POINTER-HEADED, not ABI-offset, so this needs a real new decode codec. This is
  a genuine architectural deferral, not a quick gate.

## Verification (each fix)
Add focused tests: parity-batch.test.ts. For (A)/(B): codes() asserts the now-rejection (+ a companion that the
non-colliding / value-type case still accepts). For (C)/(D)/(E): deploy a JETH contract + a solc mirror, diff
returndata (+ raw storage where relevant). Report PRECISELY which of A-E you closed, which (if any) you found
too costly and left deferred (with the reason), the tsc + full-suite result, and the new-test result.
