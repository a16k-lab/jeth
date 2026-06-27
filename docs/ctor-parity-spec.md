# Constructor parity: lift JETH302 (aggregate/dynamic ctor params) + JETH303 (ctor internal calls)

Two of the last remaining over-rejections (JETH rejects, solc 0.8.35 accepts; both SAFE = clean diagnostics,
never miscompiles). Close them byte-identical to solc. Both are about the CONSTRUCTOR's codegen environment.
The other two remaining gates (JETH312 immutable getter, JETH321 modifier conditional placeholder) are a
SEPARATE follow-up - do NOT touch them here.

## JETH302 - aggregate / dynamic constructor parameters
CURRENT: src/analyzer.ts ~2459 (checkConstructor) and ~2686 (mergeConstructors base-ctor params) reject any
ctor param that is not `isStaticValueType` (uintN/intN/bool/address/bytesN/enum/branded). solc ACCEPTS
`constructor(uint[] memory xs)`, `constructor(bytes memory b)`, `constructor(string memory s)`,
`constructor(S memory s)`, `constructor(uint[3] memory)`, etc.

FIX: allow the SAME aggregate/dynamic param types that FUNCTION params already support (dynamic arrays `T[]`,
fixed arrays `Arr<T,N>`, structs incl. dynamic-field structs, `bytes`, `string`). KEEP the existing rejects:
a param whose type contains a mapping (JETH247) and a defaulted ctor param (JETH304).

The ctor decodes its params from the CREATION ARGS (ABI-encoded, appended after the runtime code, copied to
memory by the creation code - the existing value-type path does datasize/codesize/codecopy to a memory region,
then decodes value types from it). For aggregates/dynamics, REUSE the existing MEMORY-sourced ABI decoder
`abiDecFromMem` (src/yul.ts - the exact decoder `abi.decode(<bytes>, T)` uses) to decode each aggregate param
from the args memory blob, materializing it as a memory local EXACTLY like a function aggregate param
(register it in memArrayLocals / memAggregateLocals / memDynLocals / memDynStructLocals as appropriate - note
checkConstructor clears these maps at ~2483-2486, so the aggregate param declaration must populate them just as
checkFunction does for its aggregate params). After decoding, the free pointer advances past the decoded data
(matching the value-type path's free-ptr discipline).

BYTE-IDENTITY: solc decodes ctor aggregate params from the appended args with the same ABI rules; in
particular the SHORT-ARGS / malformed-offset revert behavior must match the memory-decode path (the same
Panic/empty-revert behavior abi.decode-from-memory already produces - abiDecFromMem already encodes solc's
memory-decode revert semantics, which is WHY reusing it gives parity). Both the main ctor and a base ctor's
params (mergeConstructors) must support aggregates.

## JETH303 - constructor calling an internal/private function
CURRENT: src/analyzer.ts ~2516 rejects when the ctor body calls ANY internal/private function
(`currentCallees.size > 0`) because those callees are emitted as `userfn_<key>` ONLY in the RUNTIME object,
unreachable from the creation code. The code comment names the intended fix: "a later increment will
duplicate the callee into the creation object."

FIX: emit the internal/private functions TRANSITIVELY reachable from the constructor into the CREATION object
too (in addition to the runtime object), so the ctor body's calls resolve. Collect the ctor's transitive
internal callees (the call graph already has the keys; `currentCallees` captures the direct ones - walk to
transitive closure), and emit each as a Yul function in the creation block (reuse the same emitter the runtime
uses, emitInternalFunction / the userfn emission). Then REMOVE the JETH303 gate at ~2516 (and the related one
at ~2957 if it is the same constructor-internal-call gate - verify it is not an unrelated reuse of the code).
A ctor modifier that calls an internal fn (inlined into the ctor body) is covered by the same fix.

BYTE-IDENTITY: solc emits/inlines the called functions in the creation code; the observable result (the ctor's
state writes + the deployed runtime bytecode behavior) must match. A ctor-called internal fn that itself calls
another internal fn must also work (transitive).

## Constraints
- tsc clean. Full suite stays green and byte-identical (currently 270 files / 2273 tests); NEVER edit/relax an
  existing test. test/constructor.test.ts must stay green.
- These are OVER-rejection lifts: do not introduce any new acceptance that solc rejects, and do not change any
  currently-accepted program's output (byte-identity preserved).

## Verification (byte-identical to solc 0.8.35)
Add test/ctor-parity.test.ts. Deploy a JETH contract and a solc mirror with identical creation args; diff
returndata + raw storage slots + revert:
- a ctor taking `xs: u256[]` (decode + store xs[0], length), `b: bytes` (store b.length + a byte), `s: string`,
  a value-struct `S` param, and a fixed `Arr<u256,3>` param;
- a ctor calling an internal helper (`this.x = this.helper()`), and a helper that calls a second helper (transitive);
- SHORT-ARGS parity: deploy with truncated args -> both revert;
- a ctor combining an aggregate param + an internal call.
Pass the SAME ABI-encoded constructor args to both (append to the creation bytecode). compileSolidity returns
{creation, storageLayout} (no abi); read raw slots via h.evm.stateManager.getStorage. JETH integer literals
need the `n` suffix. BONUS to note (not required here): JETH302 lifting makes a born-frozen diamond with a
`FacetCut[]` constructor param expressible - a future follow-up.
