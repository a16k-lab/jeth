# JETH libraries - design spec (solc 0.8.35-verified)

> **Historical (design record).** JETH is now native-syntax only: the decorator spellings below are the
> retired legacy surface (`// use @decorators` -> JETH480, structural decorators -> JETH481; a library is
> now a `static class L { ... }`, `@using` remains legal). See the
> [native-spelling table](../SUPPORTED.md#legacy-decorator-removal-native-syntax-only). The described
> semantics are unchanged; only the surface syntax was replaced.

Two phases. **Phase A (this spec): INTERNAL libraries** - functions inlined into the caller, byte-identical
to solc's internal library functions (verified: a contract using internal lib funcs deploys as ONE contract,
no linking, no delegatecall; `L.add(3,4)`=7, `x.double()`=42). **Phase B (later): EXTERNAL libraries** -
deployed separately + DELEGATECALL + link-time address substitution. Do NOT build Phase B yet.

## Surface (all parse in the TS subset - verified)

- `@library class L { add(a: u256, b: u256): u256 { return a + b; } }` - a library declaration. `@library`
  parses (a bare-identifier class decorator, like `@contract`/`@struct`/`@abstract`). Functions are INTERNAL
  (inlined); no `@external` in Phase A. Mutability via `@pure`/`@view` or `@read` inference, same as a
  contract's internal functions.
- `L.add(a, b)` - a QUALIFIED library call. `L.add` parses as a PropertyAccess on the library-name identifier.
- `@using(L)` on a `@contract` (call-form decorator, read via `decoratorCall(cls, 'using')`): attaches L's
  functions as methods on their FIRST parameter's type, so `x.add(b)` desugars to `L.add(x, b)` when `x`'s
  type matches `L.add`'s first param type. `using L for T` does NOT parse in TS (`using` is the disposable
  keyword) - that is why the decorator form is used.

## solc-verified semantics

1. **Internal library functions are INLINED** - no separate deployment, no delegatecall, no linking. The
   result is byte-identical to writing the function body inline. JETH already emits internal functions as Yul
   `userfn_` functions (an internal JUMP, not literal inlining), which is observably identical (returndata /
   storage / logs). So a library's functions are emitted exactly like a contract's internal functions.
2. **Libraries have NO state variables** and NO constructor (solc rejects them). A `@state`/`@immutable`/
   `@constant`-bearing `@library`, or a constructor in a library -> a clean JETH reject.
3. **Library functions cannot be `@external`/`@payable` in Phase A** (those are Phase B external/delegatecall).
   Reject `@external`/`@payable` on a library method with a clear diagnostic.
4. **Calling convention**: `L.f(args)` and the attached `x.f(args)` (== `L.f(x, ...args)`) are internal calls -
   the library function runs in the CALLER's context (it is inlined), so it sees the caller's `msg.*` and can
   call the caller's other internal functions only through values passed in (a library cannot reference a
   contract's state directly in Phase A - scope to value/memory/calldata params).
5. **`@using(L)` attachment**: `x.f(args)` resolves to `L.f(x, args)` ONLY when L has a function `f` whose
   FIRST parameter type equals `x`'s type. If no match, `x.f` is not a library method (fall through to the
   normal member-access handling). Multiple `@using(L1) @using(L2)` allowed; a name collision (two attached
   libs both define `f` for T) -> reject. The receiver `x` is evaluated ONCE (bind it, then pass).
6. **Param scope (Phase A)**: value types, memory/calldata bytes/string, structs, arrays - the same param
   types JETH internal functions already accept. DEFER storage-reference params (solc's `using For` over a
   storage type that mutates caller storage, e.g. EnumerableSet) - JETH has no storage-ref param; gate it.

## JETH integration plan

- **Parser**: `@library` is a bare class decorator (decoratorNames). `@using(L)` is call-form
  (decoratorCall(cls,'using') -> the `L` identifier argument(s)). Both already parse.
- **Analyzer collection** (near findContractClasses ~L681 / registerContractClasses ~L700): collect `@library`
  classes into a `libraryByName` registry; collect each library's functions (reuse `collectFunction` ~L2512)
  into a per-library function table keyed by name (allow overloading by arity/types like the #47 fkey scheme).
  Emit them as internal `userfn_`s (forced internallyCalled) with a library-qualified key (e.g. `L__f` or the
  existing fkey machinery namespaced by library) so they do not collide with contract functions.
- **`L.f(args)` resolution** (in checkCall, near the interface-call / abiDecode dispatch ~L10900): a
  CallExpression whose expression is a PropertyAccess `L.f` where `L` is a known library name (and not a local/
  state/enum) -> resolve `f` in L's table by arity+types, type-check args, emit an internal call to the
  library function's key. Returns a single value, a tuple (multi-return, destructured), or void (statement).
- **`@using(L)` + `x.f(args)`**: when the contract has `@using` decorators, build an attachment map
  {(libFn.firstParamType, fnName) -> libFnKey}. In the member-call dispatch, for `x.f(args)` where `x` is a
  value of type T and (T, f) is in the attachment map, desugar to the library call `L.f(x, ...args)` (evaluate
  x once). Place this AFTER the existing method resolvers (.slice/.concat/.decode/interface) so it does not
  shadow them; a built-in method on T wins over an attached library method (matches solc).
- **codegen (yul)**: NONE new - library functions are ordinary internal `userfn_`s; `L.f(args)` / `x.f(args)`
  lower to the existing internal-call path. (This is the whole reason internal libraries are byte-identical
  for free.)

## Gates (each a distinct diagnostic, never a crash/miscompile)

`@state`/`@immutable`/`@constant` in a `@library`; a constructor in a library; `@external`/`@payable` on a
library method; `L.f` where L is a library but `f` is not a function of L; `x.f(args)` attached-but-ambiguous
(two `@using` libs define `f` for T); a library param/return type JETH internal functions do not support
(defer storage-ref). `@library` extending/being extended (no inheritance for libraries in Phase A).

## Verification (byte-identical to solc 0.8.35)

Differential probes on returndata + storage + logs: a pure-math library (add/mul/double) called qualified
`L.f(x)` and attached `x.f()`; a library function returning bytes/string (e.g. a hex/string util); a library
function taking + returning a struct / array; a library calling ANOTHER library function; overloaded library
functions; a library function used inside a loop / require / event; the `@using` attachment vs a built-in
method of the same name (built-in wins); the full accept/reject gate matrix vs solc (state in a library,
ctor, @external method, unknown member, ambiguous attachment). Mirror each against a solc
`library L { function f(...) internal ... }` + `using L for T;` contract.

---

# Phase B: EXTERNAL (delegatecall) libraries - design spec (solc 0.8.35 + Yul-linkersymbol verified)

External/public library functions are deployed SEPARATELY and called via DELEGATECALL to a link-time
address. VERIFIED feasible end-to-end: (a) solc external lib -> a separate library bytecode + the calling
contract carries a `__$<34hex>$__` placeholder with `evm.bytecode.linkReferences {start,length:20}`; deploy
lib -> link (substitute the 20-byte deployed address at each ref position) -> deploy contract -> the
delegatecall runs (`C.g(3,4)`=8 for `add(a,b){return a+b+1}`). (b) solc's **Yul mode supports
`linkersymbol("Name")`** and emits the same placeholder + linkReferences - so JETH emits
`delegatecall(gas(), linkersymbol("L"), ...)` and solc produces the link reference for free.

## Surface
- An `@external` function in a `@library` is an EXTERNAL (delegatecall) function (lift the Phase-A JETH390
  gate for `@external` on a library method). Mutability `@view`/`@pure` or inferred; `@payable` stays
  REJECTED (a library delegatecall cannot take value). A library may MIX internal (inlined, Phase A) and
  external (delegatecall) functions.
- Call sites unchanged: `L.f(args)` qualified and `@using(L)` -> `x.f(args)` attached. The analyzer chooses
  inlined-internal-call (Phase A) vs delegatecall (Phase B) by whether `f` is `@external`.

## solc-verified semantics
1. **Call = DELEGATECALL** to the library (always, even for view/pure) so the lib runs in the CALLER's
   context. Lower `L.f(args)`: ABI-encode `(selector_f, args)` to memory; `let ok := delegatecall(gas(),
   linkersymbol("L"), inPtr, inLen, 0, 0)`; `if iszero(ok) { returndatacopy + revert(...) }` (bubble the raw
   revert); ABI-decode the return from returndata. `selector_f` = the 4-byte selector of the library
   function's Solidity signature (same scheme as a contract external fn). Reuse the existing extCall encode/
   decode + abiDecode machinery; this is a delegatecall variant of the extCall path (op = 'delegatecall').
2. **Library artifact**: emit each `@library` that HAS an external function as its OWN deployable Yul object
   (creation returns runtime; runtime = a selector dispatcher over its external functions: callvalue guard,
   decode args, run body, ABI-encode return / bubble revert) - structurally the SAME as a contract's runtime
   dispatcher, minus state/constructor. A library internal function CALLED BY an external one is emitted as a
   `userfn_` inside the library object. Scope params/returns to value/memory/calldata (NO storage-ref).
3. **Linking**: the contract's creation bytecode carries one `__$..$__` placeholder per referenced external
   library; `evm.bytecode.linkReferences` (and deployedBytecode) gives the positions. The deployer
   substitutes the deployed library's 20-byte address at each position.

## JETH integration
- **analyzer**: classify a `@library` function as internal (bare) vs external (`@external`). Reject
  `@payable`/storage-ref. For an external library call build a new IR (e.g. `libExtCall { lib, fnKey,
  selector, args, returnType(s) }`) instead of the internal `{kind:'call'}`. Track which libraries are
  referenced externally (-> which library objects to emit + link).
- **ir/yul**: a `libExtCall` lowers to encode -> `delegatecall(gas(), linkersymbol(lib), ...)` -> bubble ->
  decode (reuse emitExtCall's structure with op delegatecall and a linkersymbol target; NO addr/value/gas
  operands). Emit each referenced library as a separate top-level Yul object via a new emitter entry; the
  library's external fns get a dispatcher.
- **compile.ts / solc.ts**: solc.ts adds `evm.bytecode.linkReferences` + `evm.deployedBytecode.linkReferences`
  to outputSelection and returns them. compile.ts: after analyze, if external libraries are referenced,
  compile each library's Yul object to its own bytecode AND compile the contract; return a richer result:
  `{ creationBytecode, runtimeBytecode, yul, libraries?: { name, creationBytecode, runtimeBytecode }[],
  linkReferences? }`. Keep the existing single-contract result shape when no external libraries are used
  (backward compatible - do NOT break the 2140 existing tests).
- **test harness (test/_solidity.ts + a new test/_link.ts or evm.ts helper)**: `compileSolidity` gains a
  link-aware variant (compile lib + contract with linkReferences, deploy lib, substitute, deploy contract).
  A JETH-side `deployLinked(build)` helper: deploy each `build.libraries[i]`, substitute its address into
  `build.linkReferences` positions of the creation bytecode, deploy the linked contract.

## Verification (byte-identical to solc 0.8.35)
Deploy-lib + link + deploy-contract + call, diff returndata + storage + logs + revert data vs the solc
external-library mirror (`library L { function f(...) public ... }` + `contract C { ... L.f(...) }`):
a pure-math external lib (qualified + attached); an external lib fn returning bytes/string and taking/
returning a struct/array; an external lib fn that REVERTS (string + custom error) - the revert must bubble
byte-identically; a contract using TWO external libraries (two placeholders/links); a library that MIXES an
internal (inlined) and an external (delegatecall) function; @using attachment over an external lib fn. Gate
(reject parity): @payable external lib fn; a storage-ref param.
