# Diamond ARRAY model (diamond-1/3 layout) - build spec

Builds the first complete EIP-2535 diamond on the `@storage('ns')` foundation (commit 2652595, see
docs/diamond-foundation-spec.md). Byte-identity target: a hand-written solc 0.8.35 diamond using the
diamond-3-hardhat storage layout + IN-DIAMOND loupe/cut/owner dispatch (NOT separate facets). The harness
baseline in test (see the Verification section) is the confirmed oracle. Byte-identity is OBSERVABLE
(returndata + raw storage slots + logs + revert), never raw bytecode.

The loupe + diamondCut + ownership are synthesized as the diamond's OWN functions (dispatched directly in the
runtime selector switch, like an "immutable function" in EIP-2535 terms), NOT as separate cut-in facets. This
is EIP-2535-compliant and is also how the later solidstate model works, so the three models share this
framework and differ only in the STORAGE LAYOUT. Follow the existing synthesis pattern used by @beacon /
@proxy (analyzer marks the contract, yul emitRuntime synthesizes the surface) - read those first.

## Surface (user-confirmed)
```typescript
@facet class CounterFacet {
  @storage('myapp.counter') count: u256;          // ERC-7201 namespaced (foundation); collision-safe
  @external inc(): void { this.count += 1n; }
  @external @view get(): u256 { return this.count; }
}
@diamond('array') class MyDiamond {
  constructor(owner: address) { diamondInit(owner); }   // sets contractOwner; registers no facets (cut later)
}
```
- `@facet class F { ... }`: a contract whose @external functions are meant to run via delegatecall in a
  diamond's context. It compiles to an ORDINARY contract (its own deployable bytecode + selector dispatch); the
  ONLY difference from @contract is (a) it may use `@storage('ns')` freely (already supported) and (b) it is
  tagged so the diamond/tooling can introspect its selectors. A @facet is deployed standalone and cut in.
- `@diamond('array') class D`: a diamond. JETH synthesizes the whole EIP-2535 surface (below). The user writes
  ONLY a constructor that calls `diamondInit(owner)`. A @diamond may NOT declare @state, @external methods, or a
  user @receive/@fallback (all synthesized). Gate codes JETH41x.
- `diamondInit(owner: address)`: a constructor-only builtin. Sets the synthesized `contractOwner` storage field
  = owner and emits `OwnershipTransferred(address(0), owner)`. (It does NOT register diamondCut as a facet,
  because diamondCut is an in-diamond immutable function, not a facet.)

## Synthesized diamond storage (diamond-3 layout, RAW diamond-standard base)
A synthesized namespaced struct at base = keccak256("diamond.standard.diamond.storage") - the RAW keccak of the
dotted string (NOT the ERC-7201 minus-1/&~0xff user formula; this base byte-matches mudgen). Reuse the
foundation's bigint-base namespaced layout but with this raw-keccak base (add a synthesis-only "raw namespace"
path; the user @storage('ns') stays ERC-7201). The 5 fields, EXACT order (byte-identity critical):
```
// base + 0:
mapping(bytes4 => FacetAddressAndPosition) selectorToFacetAndPosition;
// base + 1:
mapping(address => FacetFunctionSelectors) facetFunctionSelectors;
// base + 2:
address[] facetAddresses;
// base + 3:
mapping(bytes4 => bool) supportedInterfaces;
// base + 4:
address contractOwner;
```
with helper structs:
```
struct FacetAddressAndPosition { address facetAddress; uint96 functionSelectorPosition; }   // packed, 1 slot
struct FacetFunctionSelectors  { bytes4[] functionSelectors; uint256 facetAddressPosition; }
```
All of these are EXPRESSIBLE with JETH storage types already verified at a namespaced base (the foundation
probes covered packed address+uint96 structs, mapping(K=>struct), mapping(addr=>struct{dyn-array, uint}),
address[]). So the cut/loupe storage ops can be SYNTHESIZED AS JETH-level functions/IR reusing the existing
storage codegen - byte-identity then follows from the verified storage machinery. Only two things are NOT
expressible in JETH and need codegen: the router and the runtime-address delegatecall (next two sections).

## New codegen primitive: synthesis-only runtime-address delegatecall
JETH currently only delegatecalls a link-time `linkersymbol("L")` (external libraries). Add an INTERNAL
(synthesis-only, NOT user-exposed) runtime-address delegatecall, used by (a) the router and (b)
initializeDiamondCut's `_init` call. emitExtCall already forwards a runtime addr for call/staticcall and has a
delegate branch (yul.ts ~6688-6757); extend it to accept a runtime address operand for op:'delegatecall'.
Behavior: `delegatecall(gas(), addr, argPtr, argLen, 0, 0)`, capture returndata, bubble the raw revert on
failure (the diamond-3 init bubbles via `revert(add(32,error), mload(error))`).

## Synthesized router fallback (codegen, emitRuntime - diamond branch parallel to isProxy)
After the diamond's OWN selector switch (the synthesized loupe/cut/owner/supportsInterface functions dispatch
first), the fallback:
```
let sig := shr(224, calldataload(0))
mstore(0x00, sig)
mstore(0x20, <base+0>)                 // selectorToFacetAndPosition slot
let facet := and(sload(keccak256(0x00, 0x40)), 0xffffffffffffffffffffffffffffffffffffffff)   // low 160 bits
if iszero(facet) { <revert "Diamond: Function does not exist"> }    // mudgen revert string (Error(string))
calldatacopy(0, 0, calldatasize())
let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
returndatacopy(0, 0, returndatasize())
switch result case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
```
The "Diamond: Function does not exist" revert is the standard `Error(string)` (0x08c379a0 + abi.encode(string)).

## diamondCut + the diamond-3 add/replace/remove algorithm (synthesized functions)
`diamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata)` is an in-diamond @external-equivalent:
1. `enforceIsContractOwner`: require(msg.sender == contractOwner, "LibDiamond: Must be contract owner").
2. for each FacetCut: dispatch on action (Add=0, Replace=1, Remove=2), else revert IncorrectFacetCutAction.
3. emit `DiamondCut(_diamondCut, _init, _calldata)` (NO indexed params; the whole FacetCut[] aggregate + _init +
   _calldata go in data).
4. initializeDiamondCut(_init, _calldata): if _init==0 return; else require extcodesize(_init)>0; delegatecall
   _init with _calldata; on failure bubble returndata (or revert InitializationFunctionReverted if empty).

FacetCut = `{ address facetAddress; uint8 action; bytes4[] functionSelectors }`. FacetCutAction {Add=0,Replace=1,
Remove=2}. The structs/enum are synthesized.

ADD (addFunctions(facetAddress, selectors)): require selectors.length>0; require facetAddress!=0
(CannotAddSelectorsToZeroAddress, mudgen uses custom errors but a plain require-revert is an acceptable
byte-target for the degenerate error paths - PREFER matching the custom-error selectors where cheap, document
where not). selectorPosition = uint96(facetFunctionSelectors[facetAddress].functionSelectors.length). If
selectorPosition==0 -> addFacet: require extcodesize(facetAddress)>0;
facetFunctionSelectors[facetAddress].facetAddressPosition = facetAddresses.length; facetAddresses.push(facetAddress).
For each selector: oldFacet = selectorToFacetAndPosition[selector].facetAddress; require(oldFacet==0)
(CannotAddFunctionThatAlreadyExists); addFunction: selectorToFacetAndPosition[selector].functionSelectorPosition =
selectorPosition; facetFunctionSelectors[facetAddress].functionSelectors.push(selector);
selectorToFacetAndPosition[selector].facetAddress = facetAddress; selectorPosition++.

REPLACE (replaceFunctions): same setup. For each selector: oldFacet = selectorToFacetAndPosition[selector].facetAddress;
require(oldFacet != facetAddress) (CannotReplaceFunctionWithSameFunctionFromSameFacet); require(oldFacet != 0)
(CannotReplaceFunctionThatDoesNotExists); require(oldFacet != address(this)) (CannotReplaceImmutableFunction). Then
removeFunction(oldFacet, selector); addFunction(selector, selectorPosition, facetAddress); selectorPosition++.

REMOVE (removeFunctions): require facetAddress==0 (RemoveFacetAddressMustBeZeroAddress). For each selector:
oldFacet = selectorToFacetAndPosition[selector].facetAddress; removeFunction(oldFacet, selector).

removeFunction(facetAddress, selector) - THE SWAP-AND-POP (storage-order load-bearing; replicate EXACTLY):
  require(facetAddress != 0) (CannotRemoveFunctionThatDoesNotExist);
  require(facetAddress != address(this)) (CannotRemoveImmutableFunction);
  selectorPosition = selectorToFacetAndPosition[selector].functionSelectorPosition;
  lastSelectorPosition = facetFunctionSelectors[facetAddress].functionSelectors.length - 1;
  if (selectorPosition != lastSelectorPosition) {
      lastSelector = facetFunctionSelectors[facetAddress].functionSelectors[lastSelectorPosition];
      facetFunctionSelectors[facetAddress].functionSelectors[selectorPosition] = lastSelector;
      selectorToFacetAndPosition[lastSelector].functionSelectorPosition = uint96(selectorPosition);
  }
  facetFunctionSelectors[facetAddress].functionSelectors.pop();
  delete selectorToFacetAndPosition[selector];
  if (lastSelectorPosition == 0) {   // facet now empty -> swap-and-pop facetAddresses
      lastFacetAddressPosition = facetAddresses.length - 1;
      facetAddressPosition = facetFunctionSelectors[facetAddress].facetAddressPosition;
      if (facetAddressPosition != lastFacetAddressPosition) {
          lastFacetAddress = facetAddresses[lastFacetAddressPosition];
          facetAddresses[facetAddressPosition] = lastFacetAddress;
          facetFunctionSelectors[lastFacetAddress].facetAddressPosition = facetAddressPosition;
      }
      facetAddresses.pop();
      delete facetFunctionSelectors[facetAddress].facetAddressPosition;
  }

## The 4 loupe functions (synthesized, @view; diamond-3 = direct reads)
- `facets() -> Facet[]` where `Facet { address facetAddress; bytes4[] functionSelectors }`: allocate
  `new Facet[](facetAddresses.length)`; for i: facets_[i].facetAddress = facetAddresses[i];
  facets_[i].functionSelectors = facetFunctionSelectors[facetAddresses[i]].functionSelectors. Order = insertion
  order (post swap-and-pop). ABI: dynamic array of dynamic tuples.
- `facetFunctionSelectors(address _facet) -> bytes4[]`: facetFunctionSelectors[_facet].functionSelectors.
- `facetAddresses() -> address[]`: facetAddresses.
- `facetAddress(bytes4 _functionSelector) -> address`: selectorToFacetAndPosition[_functionSelector].facetAddress
  (address(0) if absent, no revert).

## ERC-165 + ownership (synthesized)
- `supportsInterface(bytes4 id) -> bool`: supportedInterfaces[id]. diamondInit sets supportedInterfaces[true] for
  type(IERC165).interfaceId (0x01ffc9a7), the IDiamondCut id (diamondCut.selector = 0x1f931c1c), the IDiamondLoupe
  id (facets^facetFunctionSelectors^facetAddresses^facetAddress = 0x48e2b093), and the IERC173 id (0x7f5828d0).
- `owner() -> address`: contractOwner. `transferOwnership(address newOwner)`: enforceIsContractOwner; set
  contractOwner = newOwner; emit OwnershipTransferred(old, newOwner). Events: `OwnershipTransferred(address indexed
  previousOwner, address indexed newOwner)` (both indexed), `DiamondCut(FacetCut[] _diamondCut, address _init, bytes
  _calldata)` (none indexed).

## Lifecycle
- `@diamond('array')` (default): upgradeable - diamondCut is present.
- `@diamond('array', 'frozen')`: born-immutable - the diamondCut function is OMITTED (the selector is not in the
  diamond's dispatch, so calling it routes to the facet router and reverts "Function does not exist" unless a
  facet provides it). The loupe + owner + ERC-165 stay. diamondInit still wires owner; facets are added in the
  constructor instead (a `frozen` diamond's constructor takes the initial FacetCut[] and applies it once). DESIGN
  the frozen constructor surface in a follow-up if it complicates the first cut; the upgradeable variant is the
  priority for THIS deliverable.

## Gates (clean diagnostics)
@diamond with @state / @external method / user @receive|@fallback -> reject; @diamond('<bad arg>') -> reject;
diamondInit outside a @diamond constructor -> reject; @facet that is also @diamond -> reject. Pick free JETH4xx
codes.

## Verification (byte-identical to a solc diamond-3 mirror - the confirmed oracle)
Extend the harness baseline already proven in this session (a solc LibDiamond + Diamond + facets, with a
hand-rolled FacetCut[] ABI encoder). Deploy a JETH @diamond('array') + JETH @facets and a solc diamond-3 mirror
(IN-DIAMOND loupe/cut/owner, same layout) + the same facets; run identical cut sequences; diff:
- selector routing: a business-facet call returns identical returndata and writes the DIAMOND's storage.
- raw storage slots of the DiamondStorage struct after Add, Replace, and Remove (the swap-and-pop ORDER is
  observable - verify facetAddresses[] and each facet's functionSelectors[] match solc slot-for-slot).
- all 4 loupe returns (facets() especially - the Facet[] dynamic-tuple encoding), facetAddress, ERC-165
  supportsInterface for the 4 ids, owner()/transferOwnership + OwnershipTransferred, the DiamondCut event
  (topic0 + the full FacetCut[] data), the owner gate revert, the _init delegatecall (an initializer that sets a
  facet's namespaced storage), and the "Diamond: Function does not exist" revert.
Write test/diamond-array.test.ts. JETH integer literals REQUIRE the `n` suffix; events are `emit(E(args))`;
compileSolidity returns {creation, storageLayout} (no abi) - read raw slots via stateManager.getStorage.
