# JETH proxies - design spec (OZ 5.x / EIP-1167 / EIP-1967 verified)

> **Historical (design record).** JETH is now native-syntax only: the decorator spellings below are the
> retired legacy surface (`// use @decorators` -> JETH480, structural decorators -> JETH481; `@proxy` /
> `@beacon` / `@facet` / `@diamond` / `@storage` remain legal). See the
> [native-spelling table](../SUPPORTED.md#legacy-decorator-removal-native-syntax-only). The described
> semantics are unchanged; only the surface syntax was replaced.

The whole-system safety rule: there is NO `addr.delegatecall(...)` primitive in user code. delegatecall is
reachable ONLY through these structured, byte-identical-to-OpenZeppelin patterns. Four patterns, built in
phases. **Phase 1 (THIS spec): the MINIMAL PROXY (EIP-1167 clone) + immutable args.** It is self-contained -
it needs CREATE/CREATE2 + EIP-1167 emission, NOT the EIP-1967 slots / delegate fallback (those are Phase 2+,
the upgradeable Transparent/UUPS/Beacon variants).

## Verified baseline (on the @ethereumjs harness, against hand-written OZ-Clones assembly)
- A plain EIP-1167 clone deploys via CREATE and correctly delegatecalls the impl (clone.initialize(99) then
  clone.who() == 99). The harness supports CREATE.
- EIP-1167 RUNTIME (45 bytes = 0x2d): `363d3d373d3d3d363d73 <impl:20> 5af43d82803e903d91602b57fd5bf3`.
- Plain clone CREATION code (the OZ Clones.clone bytecode):
  `3d602d80600a3d3981f3 363d3d373d3d3d363d73<impl>5af43d82803e903d91602b57fd5bf3` (init returns the 45-byte
  runtime). create(0, ptr, 0x37).
- Immutable-args clone CREATION code (OZ 5.1 cloneWithImmutableArgs): a MODIFIED init that returns
  runtime+args. `61 <len:2> 3d81600a3d39f3` (PUSH2 len; RETURNDATASIZE DUP2 PUSH1 0x0a RETURNDATASIZE CODECOPY
  RETURN; 10 bytes = 0x0a) ++ the 45-byte EIP-1167 runtime ++ `<immutableArgs>`, where len = 0x2d + args.length.
  (NOTE: appending args to the PLAIN init does NOT work - the plain init returns only 45 bytes, dropping args.)
- The impl reads its clone's immutable args by EXTCODECOPY of its OWN code tail past offset 0x2d
  (`extcodecopy(address(), dst, 0x2d, argsLen)`), since address(this) == the clone under delegatecall. OZ
  `Clones.fetchCloneArgs(instance)` = instance.code[0x2d:].

## Surface (proposed builtins, byte-identical to OZ Clones 5.1)
- `isContract(addr: address): bool` -> `gt(extcodesize(addr), 0)` (OZ `addr.code.length > 0`).
- `clone(impl: address): address` -> EIP-1167 via CREATE; reverts (empty) on a zero return (OZ
  `Clones.clone`, error `ERC1167FailedCreateClone` / a plain revert is acceptable byte-target since OZ's is a
  custom error - MATCH OZ: it reverts `Create2FailedDeployment`/`ERC1167FailedCreateClone()` selector; gate to
  a clean revert and confirm the success-path bytes - the failure path is degenerate).
- `cloneDeterministic(impl: address, salt: bytes32): address` -> CREATE2 (same creation code).
- `cloneWithArgs(impl: address, args: bytes): address` / `cloneDeterministicWithArgs(impl, salt, args)` ->
  the modified-init creation code with `args` appended.
- `predictClone(impl: address, salt: bytes32): address` /
  `predictCloneWithArgs(impl, salt, args): address` -> CREATE2 address =
  `keccak256(0xff ++ address(this) ++ salt ++ keccak256(creationCode))[12:]` (the CREATE2 formula over the
  EXACT creation code above). Verify against the address `cloneDeterministic*` actually deploys to.
- `cloneArgs(): bytes` -> read THIS contract's own appended immutable args (extcodecopy of own code [0x2d:]).
  Only valid inside a contract that is meant to run as a clone impl. `cloneArgs().decode(T)` composes with the
  existing abi.decode-on-bytes to read typed args.

## JETH integration
- ir.ts: a `cloneDeploy` Expr { impl, args?, salt?, deterministic } and a `cloneArgs` Expr (bytes). `isContract`
  can be a `global`-ish or a small dedicated Expr (or desugar to `extcodesize(addr) > 0`).
- yul.ts: emit the EXACT creation code into memory (plain or modified-init+args), then
  `create(0, ptr, len)` / `create2(0, ptr, len, salt)`; revert on a zero result. `cloneArgs` ->
  extcodecopy(address(), allocBlob+0x20, 0x2d, sub(extcodesize(address()), 0x2d)) into a fresh [len][data]
  bytes value. `predictClone*` -> build the creation code, keccak it, then the CREATE2-address keccak.
- analyzer.ts: recognize the builtins in checkCall; `impl`/`addr` must be `address`, `salt` `bytes32`, `args`
  `bytes`; result `address` (or `bool` for isContract, `bytes` for cloneArgs). A deploying call writes state
  (CREATE is state-changing) -> requires a nonpayable (bare @external) or @payable caller, NOT @view/@pure
  (matches solc: a function that deploys cannot be view/pure).
- validator.ts: the `new` JETH023/JETH028 gates are unchanged (these are dedicated builtins, not `new`).

## Gates (clean reject, parity where solc has one)
- `clone`/`cloneDeterministic` from a @view/@pure function -> reject (CREATE mutates). `cloneArgs` is a pure
  read of own code (allowed in @view; it reads code, not state - confirm vs solc extcodecopy mutability).
- non-address impl, non-bytes32 salt, non-bytes args -> type error.

## Verification (byte-identical to OZ / a hand-written EIP-1167 factory in solc 0.8.35)
Deploy a JETH factory + impl and a solc factory (hand-written EIP-1167 assembly, OZ Clones-equivalent) + impl;
diff: (1) the deployed clone's RUNTIME code is byte-identical (the EIP-1167 stub, plain and with args);
(2) the clone delegatecalls the impl (initialize + a state read round-trip match); (3) cloneDeterministic
deploys to the address predictClone predicted, AND that address matches solc's CREATE2 of the same creation
code; (4) cloneArgs reads back the exact appended args (single + multiple, value + bytes via .decode);
(5) two clones of one impl are independent (separate storage); (6) the @view/@pure-deploy gate. Mirror the
immutable-args case against the modified-init solc factory.

---

# Phase 2: EIP-1967 UPGRADEABLE proxies (Transparent / UUPS / Beacon) - verified baseline

Verified on the harness: a hand-written ERC1967 proxy (raw `sstore`/`sload` at the EIP-1967 impl slot
`0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` + a delegate fallback) forwards calls
into the proxy's own storage (impl storage untouched), upgrade swaps the logic, and a non-admin upgrade
reverts. So the two new primitives are: (1) raw FIXED-SLOT sstore/sload at the EIP-1967 addresses; (2) the
canonical DELEGATE FALLBACK `calldatacopy(0,0,calldatasize()); r:=delegatecall(gas(),impl,0,calldatasize(),
0,0); returndatacopy(0,0,returndatasize()); switch r case 0 {revert(0,returndatasize())} default
{return(0,returndatasize())}`.

## Foundation (Phase 2a - build first, the shared core of all 3 upgradeable variants)
- `@proxy class P { ... }` decorator: marks a proxy contract. JETH GENERATES the delegate fallback (forward
  all calldata to the EIP-1967 impl slot). The proxy has NO @state of its own (storage belongs to the impl).
- Constructor builtin `proxyInit(impl: address, initData: bytes)`: require(isContract(impl)); write the
  EIP-1967 impl slot; if initData.length>0 delegatecall(impl, initData) and bubble its revert; emit
  Upgraded(impl) (event topic = the EIP-1967 layout, an indexed address).
- `upgradeProxy(newImpl: address, data: bytes)`: require(isContract(newImpl)); write impl slot; emit
  Upgraded; if data.length>0 delegatecall(newImpl, data) + bubble. The user gates WHO can call it.
- `proxyImplementation(): address` / `proxyAdmin(): address`: read the EIP-1967 impl / admin slots.
- EIP-1967 slots are FIXED constants (collision-resistant): impl 0x360894…, admin 0xb53127…, beacon 0xa3f0ad….
  The user never sees a raw slot number - only these named builtins.

## Variant routing (Phase 2b/c/d, on top of the foundation)
- **Transparent (Phase 2b - DONE)**: `@proxy('transparent') class P { ... }` (a call-form variant arg on the
  existing @proxy decorator; the empty/absent form stays the plain Phase-2a delegate-only proxy). The proxy
  stores an admin (EIP-1967 admin slot, set in proxyInit's 2nd arg). The synthesized fallback routes by
  caller(): caller()==admin requires the call be upgradeToAndCall(address,bytes) (selector 0x4f1ef286) and
  runs the EIP-1967 upgrade in the proxy (isContract guard, sstore impl slot, emit Upgraded(indexed), if
  data.length>0 delegatecall+bubble), returning empty; ANY OTHER admin selector reverts the OZ
  ProxyDeniedAdminAccess() selector 0xd2b576ec (4 bytes, no args). caller()!=admin -> delegate to the impl,
  EVEN for the upgradeToAndCall selector (this defeats the proxy/impl selector clash). A transparent proxy
  exposes NO own functions: the user writes only the constructor (proxyInit with an admin); an @external
  method is rejected (JETH401). An unknown/non-string/extra @proxy(...) argument is rejected (JETH400).
  Byte-identical to OZ TransparentUpgradeableProxy 5.x (verified differentially in test/transparent-proxy.test.ts).
- **UUPS**: `@uups @contract class Logic` - the IMPL opts in; @uups generates upgradeToAndCall (calls the
  user-defined authorizeUpgrade(newImpl), writes the impl slot via upgradeProxy) + proxiableUUID() returning
  the impl slot (anti-brick). The proxy is the minimal foundation @proxy (delegate-only fallback). OZ
  ERC1967Proxy + UUPSUpgradeable.
- **Beacon (Phase 2d - DONE)**: TWO pieces, byte-identical (observable: returndata/storage/logs/revert) to
  OZ BeaconProxy + UpgradeableBeacon 5.x (verified differentially in test/beacon-proxy.test.ts).
  (1) `@proxy('beacon') class P { constructor(beacon: address, ...) { proxyInitBeacon(beacon, initData); } }` -
  the beacon PROXY. Its synthesized fallback reads the EIP-1967 BEACON slot
  (0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50 = keccak256("eip1967.proxy.beacon")-1),
  STATICCALLs beacon.implementation() (selector 0x5c60da1b) for the CURRENT impl on EVERY call (revert on a
  failed/short staticcall), then the standard delegate tail (calldatacopy + delegatecall + returndatacopy +
  switch). `proxyInitBeacon(beacon, initData)`: require(isContract(beacon)); sstore the BEACON slot; emit
  BeaconUpgraded(address indexed beacon) (topic0 0x1cf3b03a...); if initData.length>0, fetch the impl via the
  beacon staticcall then delegatecall(impl, initData) + bubble. `proxyBeacon(): address` reads the BEACON
  slot. A beacon proxy exposes NO own functions (an @external method is rejected, JETH405). This is the
  upgrade-all-at-once property: the proxy holds NO impl of its own; the beacon dictates the impl for ALL its
  proxies at once.
  (2) `@beacon class B { constructor(impl: address) {} }` - the UpgradeableBeacon. JETH GENERATES the whole
  surface (the user writes only the empty-bodied ctor): a synthesized creation (owner = msg.sender at storage
  slot 0 [OZ Ownable._owner], require(isContract(impl)), impl at slot 1, emit Upgraded(indexed impl)) plus
  three @external entries - upgradeTo(address) (owner-gated; revert OwnableUnauthorizedAccount(caller)
  [0x118cdaa7] on a non-owner; isContract; sstore slot 1; emit Upgraded(indexed)), implementation() (SLOAD
  slot 1) and owner() (SLOAD slot 0). Gates: a @beacon may not declare @state/@constant/@immutable (JETH406),
  a @receive/@fallback (JETH406), inheritance (JETH406), a clashing upgradeTo/implementation/owner (JETH408);
  it MUST declare `constructor(impl: address) {}` with exactly one address param + an empty non-payable body
  (JETH407). Decorators: `@proxy('beacon')` (extends the existing JETH400 variant set) + a new `@beacon` class
  decorator (a deployable contract, like @proxy, needing no separate @contract). Diagnostics: JETH405 (beacon
  proxy @external method), JETH406/407/408 (@beacon gates). NOTE: the DEPLOYED bytecode is JETH's own Yul, so
  it differs from solc's optimizer output (true for every JETH-vs-solc contract); the byte-identity target is
  the OBSERVABLE behaviour (returndata/storage/logs/revert), diffed word-for-word in the tests.

## JETH integration (Phase 2a)
- analyzer: `@proxy` class decorator -> a ProxyIR flag; the proxy gets a synthesized delegate fallback (no
  user @receive/@fallback allowed alongside). proxyInit/upgradeProxy/proxyImplementation/proxyAdmin builtins
  (writes-state for init/upgrade -> nonpayable/@payable; reads for the getters). isContract reused from Phase1.
- yul: emit the EIP-1967 slot sstore/sload at the fixed constants; the delegate fallback in the runtime
  dispatcher's fallback position; the init/upgrade delegatecall reuses the libraries' delegatecall codegen.

## Verification (byte-identical to a hand-written OZ-equivalent ERC1967/Transparent proxy in solc 0.8.35)
Deploy a JETH proxy + V1/V2 impls and a solc proxy + impls; diff returndata + the proxy's STORAGE (impl slot
+ the impl's state slots, which live in the proxy) + the Upgraded event + revert: a call routed through the
proxy hits V1 and writes the PROXY's storage (impl's own storage untouched); proxyImplementation == the impl;
upgrade swaps to V2 (behaviour + event); the init delegatecall runs once; a non-authorized upgrade reverts;
isContract guard on a non-contract impl reverts. Then the variant-specific routing per b/c/d.

---

# Phase 3: DIAMOND (EIP-2535) - research-verified build spec (source-fetched 2026-06-27)

Six research agents fetched the actual mudgen sources + the EIP text + audited JETH infra. Key findings below.

## What "diamond models" actually are (honest catalog)
- The EIP-2535 SPEC itself ships ONE reference implementation (single-file + multi-file organization of the
  same code). It does NOT define diamond-1/2/3 and draws no model comparison. The diamond-1/2/3 names are Nick
  Mudge's EXTERNAL repos; they differ ONLY in the INTERNAL selector/loupe STORAGE LAYOUT + gas profile, never
  in the external interface. So the byte-identity-relevant axis is: which storage layout you mirror.
- There are really TWO distinct on-chain storage layouts among the references:
  - **ARRAY-STORING** (diamond-1-hardhat / diamond-3-hardhat): the 5-field struct
    `selectorToFacetAndPosition: mapping(bytes4 => {address facetAddress; uint96 functionSelectorPosition})`,
    `facetFunctionSelectors: mapping(address => {bytes4[] functionSelectors; uint256 facetAddressPosition})`,
    `facetAddresses: address[]`, `supportedInterfaces: mapping(bytes4=>bool)`, `contractOwner: address`. Loupe
    reads are near-DIRECT array returns (cheap loupe, more SSTOREs on cut). Add appends; Remove is
    SWAP-WITH-LAST-then-pop on both the per-facet `bytes4[]` and `facetAddresses[]` (the swap order is
    storage- and loupe-observable, so byte-identity load-bearing). This is the simplest to make byte-checkable
    and the most-targeted layout. RECOMMENDED default.
  - **PACKED-SELECTOR** (diamond-2-hardhat / solidstate): `facets: mapping(bytes4 => bytes32)` (address in high
    20 bytes | uint16 position in low bytes), `selectorSlots: mapping(uint256 => bytes32)` packing 8 bytes4
    selectors per slot (MSB-first, bit offset `(k & 7) << 5`), `selectorCount: uint16`, supportedInterfaces,
    owner. Cheaper cut (fewer SSTOREs), loupe RECONSTRUCTS facet grouping in memory with the
    `mstore(arrayptr, newLen)` over-allocate-then-shrink trick. Higher byte-identity risk (exact bit math).
- Shared by ALL three: same slot base `keccak256("diamond.standard.diamond.storage")` (the RAW keccak of the
  dotted string, NOT the EIP-1967 minus-1 form, NOT abi.encode-wrapped); same `Diamond.sol` fallback
  (`facet = ds...selectorToFacet[msg.sig]; require(facet != 0, "Diamond: Function does not exist");`
  calldatacopy/delegatecall/returndatacopy/switch-return-or-revert); same `IDiamondCut`/`IDiamondLoupe`/
  `IERC173`/`IERC165`; same `FacetCutAction {Add=0, Replace=1, Remove=2}`; same
  `FacetCut {address facetAddress; FacetCutAction action; bytes4[] functionSelectors}`; same
  `event DiamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata)` (ZERO indexed params, whole
  aggregate in data); same `_init`/`_calldata` delegatecall with revert-bubbling +
  `InitializationFunctionReverted(address,bytes)` custom error fallback.

## Mandatory vs optional (EIP-2535)
- MANDATORY for compliance: the four loupe fns `facets()` / `facetFunctionSelectors(address)` /
  `facetAddresses()` / `facetAddress(bytes4)` (struct `Facet {address facetAddress; bytes4[] functionSelectors}`),
  the selector-routed fallback, and a `DiamondCut` event emitted on EVERY add/replace/remove AND at deploy.
- OPTIONAL: `IDiamondCut.diamondCut` itself (an IMMUTABLE diamond omits it), ERC-165 `supportsInterface`
  (interface IDs: `IDiamondCut` = `diamondCut.selector`; `IDiamondLoupe` = XOR of the 4 loupe selectors;
  written by `DiamondInit.init()`, NOT during the cut), the `_init` contract, a default function.
- Architectural variants the EIP DOES recognize (the real "models" axis): UPGRADEABLE (cut facet present) vs
  IMMUTABLE/FROZEN (born-frozen single-cut = cut facet never registered; or finalizable = remove the
  diamondCut selector later via a self-cut); IMMUTABLE FUNCTIONS defined in the diamond itself (facet ==
  diamond's own address, execute WITHOUT delegatecall, loupe reports the diamond address); storage CONVENTION
  (Diamond-Storage per-facet hashed slots [recommended] vs AppStorage struct-at-slot-0 [Aavegotchi, a
  collision footgun] vs ERC-7201 namespaced).
- A diamond that DROPS the loupe is NOT EIP-2535 compliant (it is an ERC-1538-style generic multi-facet proxy).

## JETH feasibility (audited against the live tree)
Both load-bearing pieces are byte-identically implementable on EXISTING infra; NO new Yul codegen primitive.
- **Namespaced `@storage("ns")` storage** (a struct rooted at a keccak base instead of sequential slot 0):
  the within-namespace layout is the EXISTING `planLayout` (sequential + packing, src/layout.ts:32-66); the
  runtime slot derivation (`lowerPlace` src/yul.ts:3323-3443, `mappingSlot` 7460-7484, array-data
  keccak(lenSlot)) ALREADY operates over an arbitrary 256-bit base. THE ONE LOAD-BEARING PREREQUISITE: widen
  `baseSlot` from `number` to `bigint` across ir.ts (~9 sites: ir.ts:91,214,221,222,270,322,323,359,365) +
  ~10 yul.ts arithmetic sites (the `constSlot += add` at yul.ts:3337/3347/3368 and the `Math.floor` packing
  assume a JS number, which silently breaks above 2^53 for a keccak base). Plus an analyzer `@storage`
  decorator that routes those fields to a namespace-offset layout pass and keeps them OUT of `rawState`. The
  ERC-7201 / diamond base is a COMPILE-TIME keccak (reuse src/selectors.ts). MEDIUM effort.
- **The diamond router fallback** (sload the facet for msg.sig, then delegatecall): every primitive exists -
  selector extract `shr(224, calldataload(0))` (yul.ts:449/475), `mapping(bytes4=>address)` load via
  `mappingSlot` keccak (yul.ts:7476-7481), and the delegatecall-and-return-or-bubble tail (yul.ts:461-467).
  NEEDED: a new synthesized `isDiamond` fallback mode parallel to the `isProxy` branch (yul.ts:402-467) that
  replaces the fixed-impl sload with the facet-mapping load, and a `diamondCut` admin entry that writes the
  facets mapping (analogous to `lowerProxyMutate` at yul.ts:6444-6528). Raw user-level delegatecall stays
  OMITTED (the router is fully synthesized, keeping the safer-subset philosophy).
- ALL storage types a mirror needs are ALREADY supported + tested: mapping with a struct value containing a
  dynamic-array field, `address[]`, packed `address+uint96` struct, `bytes4[]`, mapping(bytes4=>bool). The
  `Facet[] = {address, bytes4[]}[]` loupe return is a dynamic-array-of-dynamic-tuples (JETH's ABI-v2 codec
  handles it); `DiamondCut` is a non-indexed dynamic-aggregate event (supported).

## SAFER-than-reference stance (the JETH philosophy applied)
- ENFORCE namespaced `@storage("ns")` for facet state (kills the #1 diamond footgun: storage-slot collisions
  across facets). Reject AppStorage-at-slot-0 (the colliding convention).
- `diamondCut` is owner-gated (ERC-173); no raw `delegatecall`/`CREATE` in user code; facets deploy SEPARATELY
  (like external libraries) and are cut in - the diamond never `new`s a facet.
- Offer an IMMUTABLE/born-frozen diamond as a first-class safe default (no upgrade footgun), with the
  upgradeable diamond as the opt-in.

## Recommended scope + build order
1. SHARED CORE (the bulk, needed by every model): bigint `baseSlot` widen -> `@storage("ns")` namespaced
   storage -> the `@diamond` selector-router fallback -> `diamondCut(FacetCut[], _init, _calldata)` builtin
   (Add/Replace/Remove + init delegatecall + DiamondCut event) -> the 4 loupe fns + ERC-165.
2. DEFAULT MODEL: the ARRAY-STORING (diamond-1/3) layout (simplest byte-identity, direct loupe).
3. Both LIFECYCLES: upgradeable (cut facet) + immutable/born-frozen (no cut facet) - cheap, same codegen.
4. OPTIONAL later: the PACKED-SELECTOR (diamond-2) layout as a second gas-optimized model (higher risk), and
   solidstate's default-fallback-address feature.

## Verification (byte-identical to a hand-written solc diamond-3-hardhat-equivalent in 0.8.35)
Deploy a JETH `@diamond` + facets and a solc diamond + the same facets; diff returndata + the diamond's raw
storage (the namespaced struct slots, post swap-and-pop) + the DiamondCut/OwnershipTransferred logs + revert:
selector routing into each facet, add/replace/remove (esp. the swap-and-pop ORDER, observable via
facets()/facetFunctionSelectors() + raw slots), all four loupe returns, the owner gate, the `_init`
delegatecall, ERC-165, and the "function does not exist" revert. Mirror the immutable/frozen variant too.
