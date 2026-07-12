# Diamond SOLIDSTATE model - build spec

> **Historical (design/build record).** JETH is now native-syntax only: the decorator spellings below are
> the retired legacy surface (`// use @decorators` -> JETH480, structural decorators -> JETH481). `@storage`
> and `@diamond` remain legal. See the
> [native-spelling table](../SUPPORTED.md#legacy-decorator-removal-native-syntax-only). The described
> semantics are unchanged; only the surface syntax was replaced.

The third and final EIP-2535 model: `@diamond('solidstate')`, byte-identical to solidstate-network/
solidstate-solidity's diamond. It REUSES the framework built for `@diamond('array')` and `@diamond('packed')`
(src/diamond.ts `expandDiamond`, the selector-router fallback, the runtime-address delegatecall, the
`diamondInit` builtin, the `_init` delegatecall, the gates, the DiamondCut event, the packed-selector cut +
reconstruct loupe from the diamond-2 model). solidstate's on-chain selector storage is DERIVED FROM mudgen
diamond-2 (the same 8-selectors-per-slot packing), so the cut + loupe codegen is largely the packed model's.
What is DISTINCTIVE to solidstate (build these):

1. A different storage BASE and struct (solidstate uses its own namespace, NOT the mudgen
   "diamond.standard.diamond.storage"). FETCH the exact layout (below).
2. A settable DEFAULT FALLBACK ADDRESS: `getFallbackAddress() -> address` and
   `setFallbackAddress(address)` (owner-gated). The router, on a selector MISS, delegatecalls the stored
   fallback address if it is non-zero (instead of reverting); it reverts only when no fallback is set. This is
   solidstate's headline feature mudgen lacks.
3. SafeOwnable (2-step ownership): `owner()`, `nomineeOwner()`, `transferOwnership(address)` (owner-gated, sets
   the NOMINEE, does not transfer), `acceptOwnership()` (the nominee finalizes). Events per solidstate.

## FETCH solidstate's source FIRST (byte-identity target)
Use WebFetch (load via ToolSearch "select:WebFetch") on the solidstate-network/solidstate-solidity repo
(raw.githubusercontent.com/solidstate-network/solidstate-solidity/master/contracts/...). Get the EXACT:
- `proxy/diamond/base/DiamondBaseStorage.sol` (the STORAGE_SLOT string + the struct: the facets mapping, the
  selectorSlots representation [array vs mapping], selectorCount, the fallbackAddress field, and their ORDER).
- `proxy/diamond/base/DiamondBase.sol` + `fallback/DiamondFallback.sol` (the fallback: selector lookup -> if
  found delegatecall the facet; else if a default fallback address is set, delegatecall IT; else revert).
- `proxy/diamond/writable/DiamondWritableInternal.sol` (the diamondCut / add-remove-replace - confirm it is the
  diamond-2 packed algorithm, and the exact require strings/custom errors).
- `proxy/diamond/readable/DiamondReadableInternal.sol` (the loupe reconstruction).
- `access/ownable/OwnableStorage.sol` + `access/ownable/SafeOwnable*.sol` (the Ownable/SafeOwnable storage slot
  string + the owner + nominee fields + the 2-step flow + events).
- The interface IDs solidstate registers for ERC-165.
Build byte-identical to what you find. If a WebFetch fails, mirror solidstate's documented design (packed
diamond-2 storage at the solidstate base + the default-fallback + SafeOwnable) and DOCUMENT in the test that
the target is a faithful solc reconstruction (consistent with JETH's "byte-identical to some solc equivalent"
philosophy), not the exact upstream bytecode.

## Storage (solidstate, derived from diamond-2)
At base = the solidstate DiamondBaseStorage slot (the exact keccak string from the fetched source; likely
keccak256("solidstate.contracts.storage.DiamondBase") or an ERC-7201 form - USE WHAT YOU FETCH). The packed
selector storage (facets mapping + selectorSlots + selectorCount) + the fallbackAddress field. Ownership lives
in a SEPARATE namespace (the OwnableStorage slot), unlike mudgen's owner-in-diamond-storage; reproduce that.
Reuse the `@storage('ns','raw')` (or ERC-7201) base machinery for both namespaces.

## Router (the distinctive part)
Extend the diamond router (src/yul.ts isDiamond branch) with a `solidstate` sub-mode: the own-selector switch
(loupe/cut/owner/fallback-admin) first; then the facet lookup (HIGH 20 bytes of facets[msg.sig], the packed
read); on a HIT delegatecall the facet; on a MISS, load the fallback address: if non-zero delegatecall it,
else "Diamond: Function does not exist"-equivalent revert (use solidstate's exact revert).

## Gates / surface
`@diamond('solidstate')` accepted (extend the JETH412 variant set). `getFallbackAddress`/`setFallbackAddress`
synthesized in the diamond; `setFallbackAddress` is owner-gated. Everything else (no @state/@external/@receive/
@fallback/events on the diamond) identical to the other models.

## Verification (byte-identical to a solc solidstate mirror)
Write test/diamond-solidstate.test.ts. Deploy facets in identical order so CREATE addresses align. Diff vs a
solc mirror (built from the fetched solidstate source, or the documented design) over: routing into facets
(packed storage), the cut (Add multi-slot / Replace / Remove slot-crossing - reuse the packed model's coverage
since the cut is shared), all 4 loupe returns, facetAddress, ERC-165, the SafeOwnable 2-step
(transferOwnership sets nominee, acceptOwnership finalizes, the events, the non-nominee accept revert), AND THE
HEADLINE FEATURE: a selector MISS with NO fallback set reverts; setFallbackAddress(X) then the SAME miss now
delegatecalls X (returndata from X, X runs in the diamond's storage context); getFallbackAddress()==X; a
non-owner setFallbackAddress reverts. Read raw slots via h.evm.stateManager.getStorage; integer literals need
`n`; events are emit(E(args)); compileSolidity returns {creation, storageLayout}.
