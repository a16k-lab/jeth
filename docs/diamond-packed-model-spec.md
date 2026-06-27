# Diamond PACKED model (diamond-2 layout) - build spec

The second EIP-2535 storage model: `@diamond('packed')`, byte-identical to a hand-written solc 0.8.35
diamond-2-hardhat. It REUSES the whole framework already built for `@diamond('array')` (src/diamond.ts
`expandDiamond` source-text expansion, the selector-router fallback, the synthesis-only runtime-address
delegatecall, the `diamondInit` builtin, the gates JETH411-414, the `_init` delegatecall, the DiamondCut /
OwnershipTransferred events, ERC-165, owner/transferOwnership). ONLY the diamond storage LAYOUT and the
cut + loupe operations change. The external surface (selectors, signatures, the FacetCut/Facet ABI shapes,
the router behavior, the "Diamond: Function does not exist" revert) is IDENTICAL to the array model.

Read src/diamond.ts (the array model's expansion) first, then add a `'packed'` branch. Read
docs/diamond-array-model-spec.md for the shared framework.

## Storage layout (diamond-2, at the RAW keccak base, same base string as array)
At base = keccak256("diamond.standard.diamond.storage") (the existing @storage('ns','raw') mode), the EXACT
struct (field order byte-identity critical):
```
mapping(bytes4 => bytes32) facets;          // base+0: selector -> (facet addr in HIGH 20 bytes | uint16 position in LOW bytes)
mapping(uint256 => bytes32) selectorSlots;  // base+1: slotIndex (= selectorCount>>3) -> 8 packed bytes4 selectors
uint16 selectorCount;                        // base+2: total installed selectors (right-aligned, alone in its slot)
mapping(bytes4 => bool) supportedInterfaces; // base+3
address contractOwner;                       // base+4
```
Constants:
```
CLEAR_ADDRESS_MASK  = bytes32(uint256(0xffffffffffffffffffffffff))   // low 12 bytes set (keep position, clear addr)
CLEAR_SELECTOR_MASK = bytes32(uint256(0xffffffff) << 224)            // top 4 bytes set
```
A selector's bit offset inside its slot is `selectorInSlotPosition = (count & 7) << 5` measured from the
MSB/left. Stored as `bytes32(selector) >> pos`; read back as `bytes4(slot << pos)`. slotIndex = `count >> 3`.

## diamondCut (diamond-2 algorithm - replicate EXACTLY; storage is observable)
diamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata): owner-gated. Read
originalSelectorCount = selectorCount; if (selectorCount & 7 > 0) preload selectorSlot =
selectorSlots[selectorCount >> 3]. Loop each FacetCut applying addReplaceRemove (below). After the loop: if
selectorCount != original, write selectorCount; if (selectorCount & 7 > 0) flush
selectorSlots[selectorCount >> 3] = selectorSlot. Then emit DiamondCut + initializeDiamondCut(_init,_calldata)
(SAME as array model - reuse it).

addReplaceRemove(selectorCount, selectorSlot, facetAddress, action, selectors) - the three actions thread
selectorCount + the in-memory selectorSlot through and return the updated pair:
- ADD (action 0): require extcodesize(facetAddress)>0. Per selector: require facets[sel]==0 (no addr) else
  revert (already exists); facets[sel] = bytes20(facetAddress) | bytes32(selectorCount);
  selectorSlot = (selectorSlot & ~(CLEAR_SELECTOR_MASK >> pos)) | (bytes32(sel) >> pos) where
  pos=(selectorCount & 7)<<5; if pos==224 (slot just filled its 8th) flush selectorSlots[selectorCount>>3] =
  selectorSlot and selectorSlot = 0; selectorCount++.
- REPLACE (action 1): require extcodesize(facetAddress)>0. Per selector: oldFacet = address(bytes20(facets[sel]));
  require oldFacet != address(this) (immutable), != facetAddress (same), != 0 (must exist); rewrite addr keeping
  the low position: facets[sel] = (facets[sel] & CLEAR_ADDRESS_MASK) | bytes20(facetAddress). selectorSlots
  untouched.
- REMOVE (action 2): require facetAddress == 0. selectorSlotCount = selectorCount>>3, selectorInSlotIndex =
  selectorCount&7. Per selector: step the cursor BACK (if selectorInSlotIndex==0 then selectorSlotCount--,
  selectorSlot = selectorSlots[selectorSlotCount], selectorInSlotIndex=7; else selectorInSlotIndex--); read
  oldFacet for the removed selector, require it exists and != address(this); lastSelector =
  bytes4(selectorSlot << (selectorInSlotIndex<<5)); if lastSelector != sel, move the last selector's record over
  the removed one: facets[lastSelector] = (oldFacetRecord & CLEAR_ADDRESS_MASK) | bytes20(facets[lastSelector]);
  delete facets[sel]; recover the removed selector's old slot position oldSelectorCount = uint16(uint256(oldFacet
  record)), oldSelectorsSlotCount = oldSelectorCount>>3, oldPos = (oldSelectorCount&7)<<5; write lastSelector into
  that gap (load the target slot if different from the working selectorSlot, clear its selector at oldPos and OR
  in bytes32(lastSelector)>>oldPos, store back; else edit the in-memory selectorSlot); if selectorInSlotIndex==0
  delete selectorSlots[selectorSlotCount] and selectorSlot=0. After the loop selectorCount = selectorSlotCount*8
  + selectorInSlotIndex.
The EXACT details are in /tmp/jeth_diamond_research.txt (the DIAMOND-2 section, source-verified) and the
docs/proxy-design.md "PACKED-SELECTOR" notes - follow them precisely; the swap-into-gap + selectorCount
arithmetic is observable through the loupe and raw slots.

## Loupe (diamond-2 RECONSTRUCTS - the hard part)
No facet-grouped data is stored; every loupe call recomputes from selectorSlots + the facets mapping. The
COMMON SCAN: for slotIndex while selectorIndex < selectorCount, load selectorSlots[slotIndex]; inner 0..7
selectorIndex++ (1-based), break if > selectorCount, decode sel = bytes4(slot << (j<<5)), facetAddr =
address(bytes20(facets[sel])).
- facets(): over-allocate Facet[](selectorCount) + parallel counts, linear-search-dedupe facet addresses, then
  TRUNCATE each functionSelectors array and the outer array via the assembly `mstore(arrayPtr, realLen)` trick.
- facetFunctionSelectors(addr): over-allocate bytes4[](selectorCount), append matching, mstore-truncate.
- facetAddresses(): over-allocate address[](selectorCount), dedupe, mstore-truncate.
- facetAddress(bytes4 sel): address(bytes20(facets[sel])) (single read, 0 if absent).
IMPLEMENTATION NOTE: the mstore-on-array-length truncation is not expressible in plain JETH source. Implement
the four loupe functions as RAW-YUL encoders (the way the array model's facets() was done - a
lowerDiamondFacetsReturn-style emitter), reading the packed storage directly. Each returns the SAME ABI shape
as the array model (Facet[] = {address,bytes4[]}[], bytes4[], address[], address). The RETURN BYTES must be
byte-identical to the solc diamond-2 loupe output (same facet order = first-seen order during the scan, same
selector order within a facet).

## ERC-165 / ownership / events / router / lifecycle
IDENTICAL to the array model - reuse diamondInit (sets the 4 interface ids + owner +
OwnershipTransferred(0,owner)), the router fallback (the facets-mapping read changes: facet =
address(bytes20(sload(keccak(sel . base+0)))) - high 20 bytes, vs the array model's low 160 bits), owner()/
transferOwnership, supportsInterface, the DiamondCut event. The router's facet lookup MUST take the HIGH 20
bytes of the packed facets[sel] value (address(bytes20(value))), not the low 160 bits.

## Gates
`@diamond('packed')` is accepted (extend the JETH412 variant set to include 'packed'). Everything else (no
@state/@external/@receive/@fallback/events on the diamond, @facet not also @diamond) is identical.

## Verification (byte-identical to a solc diamond-2-hardhat mirror)
Write test/diamond-packed.test.ts mirroring test/diamond-array.test.ts but against a hand-written solc
diamond-2 LibDiamond (the packed selectorSlots layout + the masks + the reconstruct loupe). Deploy facets in
identical order so CREATE addresses align; diff over an Add (enough selectors to cross the 8-per-slot boundary,
e.g. 9+ selectors so selectorSlots uses >1 slot) / Replace / Remove sequence: selector routing, the raw
DiamondStorage slots (facets mapping values, the packed selectorSlots, selectorCount), all 4 loupe returns,
facetAddress, ERC-165, owner/transferOwnership, the DiamondCut event, the owner gate, the _init delegatecall,
and the function-not-found revert. CRITICAL: include a cut with >8 selectors (multi-slot selectorSlots) and a
Remove that crosses a slot boundary - that is where the packed bit-math diverges if wrong.
