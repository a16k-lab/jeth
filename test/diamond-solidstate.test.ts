// Phase 3 (DIAMOND): `@diamond('solidstate')` - an EIP-2535 diamond on the SOLIDSTATE layout (solidstate-
// network/solidstate-solidity v0.0.61). solidstate's on-chain selector storage is DERIVED FROM mudgen
// diamond-2 (the SAME 8-selectors-per-slug packing + address-in-high-20-bytes facet record), so the cut +
// the four loupe reconstructors reuse the packed model's framework. What is DISTINCTIVE to solidstate and
// proven byte-identical here:
//   - its OWN storage bases (NOT mudgen's "diamond.standard.diamond.storage") with ownership + supported
//     interfaces in SEPARATE namespaces:
//       DiamondBase  = keccak256("solidstate.contracts.storage.DiamondBase") :
//         selectorInfo(slot+0), selectorCount uint16(slot+1), selectorSlugs(slot+2), fallbackAddress(slot+3)
//       Ownable      = keccak256("solidstate.contracts.storage.Ownable")     : owner(slot+0)
//       SafeOwnable  = keccak256("solidstate.contracts.storage.SafeOwnable") : nomineeOwner(slot+0)
//       ERC165Base   = keccak256("solidstate.contracts.storage.ERC165Base")  : supportedInterfaces(slot+0)
//   - the settable DEFAULT FALLBACK ADDRESS (the headline feature): getFallbackAddress()/setFallbackAddress
//     (owner-gated); on a selector MISS the router delegatecalls the stored fallback when it is non-zero,
//     else reverts Proxy__ImplementationIsNotContract() (selector 0x87c9fc34).
//   - SafeOwnable 2-step ownership: transferOwnership(account) sets the NOMINEE only (no transfer, no event);
//     acceptOwnership() (nominee-gated) finalizes (nominee becomes owner, emits OwnershipTransferred, clears
//     the nominee); a non-nominee acceptOwnership reverts SafeOwnable__NotNomineeOwner() (0xefd1052d), and a
//     non-owner transferOwnership/setFallbackAddress reverts Ownable__NotOwner() (0x2f7a8ee1).
//
// Byte-identity target: a hand-written solc 0.8.35 solidstate mirror that faithfully reconstructs solidstate
// v0.0.61's design (the exact storage bases, struct field order, custom errors, SafeOwnable 2-step flow and
// fallback feature). As with the packed/array models, the diamond's OWN selectors are dispatched by the
// contract's normal function dispatch (NOT pre-registered into the selector storage by a constructor
// self-cut), so the loupe over storage sees only facet selectors; both worlds follow the identical routing
// model, so all observable output (returndata + raw slots + logs + revert) is diffed word-for-word.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { Address, hexToBytes } from '@ethereumjs/util';

const keccakHex = (b: Uint8Array | string): bigint => BigInt('0x' + toHex(keccak(b)));

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const OWNER = new Address(hexToBytes('0x00000000000000000000000000000000000000aa'));
const STRANGER = new Address(hexToBytes('0x00000000000000000000000000000000000000bb'));
const NOMINEE = new Address(hexToBytes('0x00000000000000000000000000000000000000cc'));
const ZERO = '0x' + '0'.repeat(40);

const word32 = (v: bigint): Uint8Array => {
  const b = new Uint8Array(32);
  let x = ((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n);
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
};

// solidstate's raw keccak256 namespace bases.
const DB_BASE = keccakHex('solidstate.contracts.storage.DiamondBase');
const OW_BASE = keccakHex('solidstate.contracts.storage.Ownable');
const SO_BASE = keccakHex('solidstate.contracts.storage.SafeOwnable');
const E165_BASE = keccakHex('solidstate.contracts.storage.ERC165Base');
const SELINFO_SLOT = DB_BASE + 0n; // mapping(bytes4 => bytes32) selectorInfo
const COUNT_SLOT = DB_BASE + 1n; // uint16 selectorCount (alone in its slot)
const SLUGS_SLOT = DB_BASE + 2n; // mapping(uint256 => bytes32) selectorSlugs
const FALLBACK_SLOT = DB_BASE + 3n; // address fallbackAddress
const OWNER_SLOT = OW_BASE + 0n; // address owner
const NOMINEE_SLOT = SO_BASE + 0n; // address nomineeOwner
const OWNERSHIP_TRANSFERRED = '0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0';

// ---- ABI helpers ------------------------------------------------------------
const w = (v: bigint) => pad32(v);
const addrW = (a: string) => pad32(BigInt(a));
const selW = (s: string) => s.replace('0x', '').padEnd(64, '0'); // bytes4 left-aligned

/** Encode diamondCut((address,uint8,bytes4[])[], address, bytes) calldata by hand (ABI v2). */
function encodeDiamondCut(
  cuts: { facet: string; action: number; selectors: string[] }[],
  init: string,
  calldata: string,
): string {
  const s = sel('diamondCut((address,uint8,bytes4[])[],address,bytes)');
  const arr: string[] = [w(BigInt(cuts.length))];
  const tails: string[] = [];
  let off = cuts.length * 32;
  const offs: number[] = [];
  for (const c of cuts) {
    offs.push(off);
    const t: string[] = [addrW(c.facet), w(BigInt(c.action)), w(0x60n), w(BigInt(c.selectors.length))];
    for (const se of c.selectors) t.push(selW(se));
    tails.push(t.join(''));
    off += t.length * 32;
  }
  for (const o of offs) arr.push(w(BigInt(o)));
  for (const t of tails) arr.push(t);
  const cutsBlob = arr.join('');
  const cd = calldata.replace('0x', '');
  const cdBytes = cd.length / 2;
  const cdEnc = w(BigInt(cdBytes)) + (cdBytes ? cd.padEnd(Math.ceil(cdBytes / 32) * 64, '0') : '');
  const head = [w(BigInt(3 * 32)), addrW(init), w(BigInt(3 * 32 + cutsBlob.length / 2))];
  return '0x' + s + head.join('') + cutsBlob + cdEnc;
}

// solc mapping(K=>V) element slot = keccak256(key . mappingBaseSlot). bytes4 key LEFT-aligned; uint key raw.
function bytes4MapSlot(mapBase: bigint, selector4: string): bigint {
  const keyWord = hexToBytes((selector4.startsWith('0x') ? selector4 : '0x' + selector4).padEnd(66, '0') as `0x${string}`);
  const buf = new Uint8Array(64);
  buf.set(keyWord.slice(0, 32), 0);
  buf.set(word32(mapBase), 32);
  return keccakHex(buf);
}
function uintMapSlot(mapBase: bigint, key: bigint): bigint {
  const buf = new Uint8Array(64);
  buf.set(word32(key), 0);
  buf.set(word32(mapBase), 32);
  return keccakHex(buf);
}

// ---- the JETH diamond + facets ----------------------------------------------
const DIAMOND_JETH = `@diamond('solidstate') class MyDiamond {
  constructor(owner: address) { diamondInitSolidstate(owner); }
}`;

// FacetBig: nine selectors (forces selectorSlugs to span >1 slot: 9 = slug0[0..7] + slug1[0]).
const FACET_BIG_JETH = `@facet class FacetBig {
  @storage('app.big') v: u256;
  f1(x: u256): External<void> { this.v = x; }
  get f2(): External<u256> { return this.v; }
  f3(x: u256): External<void> { this.v = x + 1n; }
  get f4(): External<u256> { return this.v + 2n; }
  f5(x: u256): External<void> { this.v = x + 3n; }
  get f6(): External<u256> { return this.v + 4n; }
  f7(x: u256): External<void> { this.v = x + 5n; }
  get f8(): External<u256> { return this.v + 6n; }
  get f9(): External<u256> { return this.v + 7n; }
}`;
const FACET_SMALL_JETH = `@facet class FacetSmall {
  @storage('app.small') s: u256;
  g1(x: u256): External<void> { this.s = x; }
  get g2(): External<u256> { return this.s; }
  get g3(): External<u256> { return 99n; }
}`;
// A "default fallback" implementation: writes the diamond's storage when delegatecalled on a selector miss.
const FALLBACK_JETH = `class FallbackImpl {
  @storage('app.fb') hit: u256;
  get ping(): External<u256> { return 0xfeedn; }
  fallback(): void { this.hit = 0xc0ffeen; }
}`;
const INIT_JETH = `class DInit {
  @storage('app.init') flag: u256;
  init(v: u256): External<void> { this.flag = v; }
}`;

// ---- the solc solidstate v0.0.61 mirror -------------------------------------
// A faithful reconstruction: the exact storage bases + struct order + custom errors + SafeOwnable 2-step +
// the fallback feature. Own selectors are dispatched by solc's normal function dispatch (not pre-registered
// into the selector storage), matching the JETH routing model.
const DIAMOND_SOL =
  SPDX +
  `
struct DiamondBaseLayout {
  mapping(bytes4 => bytes32) selectorInfo;
  uint16 selectorCount;
  mapping(uint256 => bytes32) selectorSlugs;
  address fallbackAddress;
}
struct OwnableLayout { address owner; }
struct SafeOwnableLayout { address nomineeOwner; }
struct ERC165Layout { mapping(bytes4 => bool) supportedInterfaces; }
struct Facet { address target; bytes4[] selectors; }
struct FacetCut { address target; uint8 action; bytes4[] selectors; }
contract Diamond {
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
  event DiamondCut(FacetCut[] facetCuts, address target, bytes data);
  error Ownable__NotOwner();
  error SafeOwnable__NotNomineeOwner();
  error Proxy__ImplementationIsNotContract();
  error DiamondWritable__SelectorNotSpecified();
  error DiamondWritable__SelectorIsImmutable();
  error DiamondWritable__TargetHasNoCode();
  error DiamondWritable__SelectorAlreadyAdded();
  error DiamondWritable__SelectorNotFound();
  error DiamondWritable__ReplaceTargetIsIdentical();
  error DiamondWritable__RemoveTargetNotZeroAddress();
  bytes32 constant DB = keccak256("solidstate.contracts.storage.DiamondBase");
  bytes32 constant OWS = keccak256("solidstate.contracts.storage.Ownable");
  bytes32 constant SOS = keccak256("solidstate.contracts.storage.SafeOwnable");
  bytes32 constant E165 = keccak256("solidstate.contracts.storage.ERC165Base");
  bytes32 constant CLEAR_ADDRESS_MASK = bytes32(uint256(0xffffffffffffffffffffffff));
  bytes32 constant CLEAR_SELECTOR_MASK = bytes32(uint256(0xffffffff << 224));
  function db() internal pure returns (DiamondBaseLayout storage s) { bytes32 p = DB; assembly { s.slot := p } }
  function ow() internal pure returns (OwnableLayout storage s) { bytes32 p = OWS; assembly { s.slot := p } }
  function so() internal pure returns (SafeOwnableLayout storage s) { bytes32 p = SOS; assembly { s.slot := p } }
  function e1() internal pure returns (ERC165Layout storage s) { bytes32 p = E165; assembly { s.slot := p } }
  constructor(address owner) {
    ow().owner = owner;
    emit OwnershipTransferred(address(0), owner);
    e1().supportedInterfaces[0xbd02b73c] = true; // IDiamondFallback
    e1().supportedInterfaces[0x1f931c1c] = true; // IERC2535DiamondCut
    e1().supportedInterfaces[0x48e2b093] = true; // IERC2535DiamondLoupe
    e1().supportedInterfaces[0x01ffc9a7] = true; // IERC165
    e1().supportedInterfaces[0x7f5828d0] = true; // IERC173
  }
  // ---- Ownable / SafeOwnable (2-step) ----
  function owner() external view returns (address) { return ow().owner; }
  function nomineeOwner() external view returns (address) { return so().nomineeOwner; }
  function transferOwnership(address account) external {
    if (msg.sender != ow().owner) revert Ownable__NotOwner();
    so().nomineeOwner = account;
  }
  function acceptOwnership() external {
    if (msg.sender != so().nomineeOwner) revert SafeOwnable__NotNomineeOwner();
    address prev = ow().owner;
    ow().owner = msg.sender;
    emit OwnershipTransferred(prev, msg.sender);
    delete so().nomineeOwner;
  }
  // ---- default fallback address ----
  function getFallbackAddress() external view returns (address) { return db().fallbackAddress; }
  function setFallbackAddress(address a) external {
    if (msg.sender != ow().owner) revert Ownable__NotOwner();
    db().fallbackAddress = a;
  }
  // ---- ERC-165 ----
  function supportsInterface(bytes4 id) external view returns (bool) { return e1().supportedInterfaces[id]; }
  // ---- loupe ----
  function facetAddress(bytes4 s) external view returns (address) { return address(bytes20(db().selectorInfo[s])); }
  function facetAddresses() external view returns (address[] memory addrs) {
    DiamondBaseLayout storage d = db();
    addrs = new address[](d.selectorCount);
    uint256 numFacets;
    uint256 selectorIndex;
    for (uint256 slugIndex; selectorIndex < d.selectorCount; slugIndex++) {
      bytes32 slug = d.selectorSlugs[slugIndex];
      for (uint256 si; si < 8; si++) {
        selectorIndex++;
        if (selectorIndex > d.selectorCount) break;
        bytes4 s = bytes4(slug << (si << 5));
        address fa = address(bytes20(d.selectorInfo[s]));
        bool found;
        for (uint256 k; k < numFacets; k++) { if (addrs[k] == fa) { found = true; break; } }
        if (!found) { addrs[numFacets] = fa; numFacets++; }
      }
    }
    assembly { mstore(addrs, numFacets) }
  }
  function facetFunctionSelectors(address f) external view returns (bytes4[] memory sels) {
    DiamondBaseLayout storage d = db();
    sels = new bytes4[](d.selectorCount);
    uint256 numSelectors;
    uint256 selectorIndex;
    for (uint256 slugIndex; selectorIndex < d.selectorCount; slugIndex++) {
      bytes32 slug = d.selectorSlugs[slugIndex];
      for (uint256 si; si < 8; si++) {
        selectorIndex++;
        if (selectorIndex > d.selectorCount) break;
        bytes4 s = bytes4(slug << (si << 5));
        if (f == address(bytes20(d.selectorInfo[s]))) { sels[numSelectors] = s; numSelectors++; }
      }
    }
    assembly { mstore(sels, numSelectors) }
  }
  function facets() external view returns (Facet[] memory facets_) {
    DiamondBaseLayout storage d = db();
    facets_ = new Facet[](d.selectorCount);
    uint8[] memory numFacetSelectors = new uint8[](d.selectorCount);
    uint256 numFacets;
    uint256 selectorIndex;
    for (uint256 slugIndex; selectorIndex < d.selectorCount; slugIndex++) {
      bytes32 slug = d.selectorSlugs[slugIndex];
      for (uint256 si; si < 8; si++) {
        selectorIndex++;
        if (selectorIndex > d.selectorCount) break;
        bytes4 s = bytes4(slug << (si << 5));
        address fa = address(bytes20(d.selectorInfo[s]));
        bool continueLoop;
        for (uint256 k; k < numFacets; k++) {
          if (facets_[k].target == fa) {
            facets_[k].selectors[numFacetSelectors[k]] = s;
            require(numFacetSelectors[k] < 255);
            numFacetSelectors[k]++;
            continueLoop = true;
            break;
          }
        }
        if (continueLoop) continue;
        facets_[numFacets].target = fa;
        facets_[numFacets].selectors = new bytes4[](d.selectorCount);
        facets_[numFacets].selectors[0] = s;
        numFacetSelectors[numFacets] = 1;
        numFacets++;
      }
    }
    for (uint256 fi; fi < numFacets; fi++) {
      uint256 numSelectors = numFacetSelectors[fi];
      bytes4[] memory selectors = facets_[fi].selectors;
      assembly { mstore(selectors, numSelectors) }
    }
    assembly { mstore(facets_, numFacets) }
  }
  // ---- cut ----
  function diamondCut(FacetCut[] calldata facetCuts, address target, bytes calldata data) external {
    if (msg.sender != ow().owner) revert Ownable__NotOwner();
    DiamondBaseLayout storage d = db();
    uint256 originalSelectorCount = d.selectorCount;
    uint256 selectorCount = originalSelectorCount;
    bytes32 slug;
    if (selectorCount & 7 != 0) slug = d.selectorSlugs[selectorCount >> 3];
    for (uint256 i; i < facetCuts.length; i++) {
      uint8 action = facetCuts[i].action;
      if (facetCuts[i].selectors.length == 0) revert DiamondWritable__SelectorNotSpecified();
      if (action == 0) {
        (selectorCount, slug) = add(d, selectorCount, slug, facetCuts[i].target, facetCuts[i].selectors);
      } else if (action == 1) {
        replace(d, facetCuts[i].target, facetCuts[i].selectors);
      } else if (action == 2) {
        (selectorCount, slug) = remove(d, selectorCount, slug, facetCuts[i].target, facetCuts[i].selectors);
      }
    }
    if (selectorCount != originalSelectorCount) d.selectorCount = uint16(selectorCount);
    if (selectorCount & 7 != 0) d.selectorSlugs[selectorCount >> 3] = slug;
    emit DiamondCut(facetCuts, target, data);
    initialize(target, data);
  }
  function isContract(address a) internal view returns (bool) { return a.code.length > 0; }
  function insert(bytes32 slug, bytes4 selector, uint256 bitIndex) internal pure returns (bytes32) {
    return (slug & ~(CLEAR_SELECTOR_MASK >> bitIndex)) | (bytes32(selector) >> bitIndex);
  }
  function add(DiamondBaseLayout storage d, uint256 selectorCount, bytes32 lastSlug, address target, bytes4[] calldata selectors) internal returns (uint256, bytes32) {
    if (isContract(target)) { if (target == address(this)) revert DiamondWritable__SelectorIsImmutable(); }
    else if (target != address(this)) revert DiamondWritable__TargetHasNoCode();
    for (uint256 i; i < selectors.length; i++) {
      bytes4 selector = selectors[i];
      if (d.selectorInfo[selector] != bytes32(0)) revert DiamondWritable__SelectorAlreadyAdded();
      d.selectorInfo[selector] = bytes32(selectorCount) | bytes20(target);
      uint256 pos = (selectorCount & 7) << 5;
      lastSlug = insert(lastSlug, selector, pos);
      if (pos == 224) d.selectorSlugs[selectorCount >> 3] = lastSlug;
      selectorCount++;
    }
    return (selectorCount, lastSlug);
  }
  function replace(DiamondBaseLayout storage d, address target, bytes4[] calldata selectors) internal {
    if (!isContract(target)) revert DiamondWritable__TargetHasNoCode();
    for (uint256 i; i < selectors.length; i++) {
      bytes4 selector = selectors[i];
      bytes32 selectorInfo = d.selectorInfo[selector];
      address oldFacet = address(bytes20(selectorInfo));
      if (oldFacet == address(0)) revert DiamondWritable__SelectorNotFound();
      if (oldFacet == address(this)) revert DiamondWritable__SelectorIsImmutable();
      if (oldFacet == target) revert DiamondWritable__ReplaceTargetIsIdentical();
      d.selectorInfo[selector] = (selectorInfo & CLEAR_ADDRESS_MASK) | bytes20(target);
    }
  }
  function remove(DiamondBaseLayout storage d, uint256 selectorCount, bytes32 lastSlug, address target, bytes4[] calldata selectors) internal returns (uint256, bytes32) {
    if (target != address(0)) revert DiamondWritable__RemoveTargetNotZeroAddress();
    for (uint256 i; i < selectors.length; i++) {
      selectorCount--;
      bytes4 selector = selectors[i];
      bytes32 selectorInfo = d.selectorInfo[selector];
      delete d.selectorInfo[selector];
      if (address(bytes20(selectorInfo)) == address(0)) revert DiamondWritable__SelectorNotFound();
      if (address(bytes20(selectorInfo)) == address(this)) revert DiamondWritable__SelectorIsImmutable();
      if (selectorCount & 7 == 7) lastSlug = d.selectorSlugs[selectorCount >> 3];
      bytes4 lastSelector = bytes4(lastSlug << ((selectorCount & 7) << 5));
      if (lastSelector != selector) {
        d.selectorInfo[lastSelector] = (selectorInfo & CLEAR_ADDRESS_MASK) | bytes20(d.selectorInfo[lastSelector]);
      }
      uint256 slugIndex = uint16(uint256(selectorInfo)) >> 3;
      uint256 pos = (uint16(uint256(selectorInfo)) & 7) << 5;
      if (slugIndex == selectorCount >> 3) {
        lastSlug = insert(lastSlug, lastSelector, pos);
      } else {
        d.selectorSlugs[slugIndex] = insert(d.selectorSlugs[slugIndex], lastSelector, pos);
      }
    }
    return (selectorCount, lastSlug);
  }
  function initialize(address target, bytes memory data) internal {
    if (target == address(0)) return;
    if (target != address(this)) { require(isContract(target)); }
    (bool ok, bytes memory err) = target.delegatecall(data);
    if (!ok) { assembly { revert(add(32, err), mload(err)) } }
  }
  // ---- router (DiamondFallback._getImplementation + Proxy.fallback) ----
  fallback() external payable {
    DiamondBaseLayout storage d = db();
    address impl = address(bytes20(d.selectorInfo[msg.sig]));
    if (impl == address(0)) impl = d.fallbackAddress;
    if (impl.code.length == 0) revert Proxy__ImplementationIsNotContract();
    assembly {
      calldatacopy(0, 0, calldatasize())
      let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
      returndatacopy(0, 0, returndatasize())
      switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
    }
  }
  receive() external payable {}
}
`;
const FACET_BIG_SOL =
  SPDX +
  `
contract FacetBig {
  bytes32 constant S = keccak256(abi.encode(uint256(keccak256(bytes("app.big"))) - 1)) & ~bytes32(uint256(0xff));
  struct St { uint256 v; }
  function s() internal pure returns (St storage st) { bytes32 p = S; assembly { st.slot := p } }
  function f1(uint256 x) external { s().v = x; }
  function f2() external view returns (uint256) { return s().v; }
  function f3(uint256 x) external { s().v = x + 1; }
  function f4() external view returns (uint256) { return s().v + 2; }
  function f5(uint256 x) external { s().v = x + 3; }
  function f6() external view returns (uint256) { return s().v + 4; }
  function f7(uint256 x) external { s().v = x + 5; }
  function f8() external view returns (uint256) { return s().v + 6; }
  function f9() external view returns (uint256) { return s().v + 7; }
}`;
const FACET_SMALL_SOL =
  SPDX +
  `
contract FacetSmall {
  bytes32 constant S = keccak256(abi.encode(uint256(keccak256(bytes("app.small"))) - 1)) & ~bytes32(uint256(0xff));
  struct St { uint256 s_; }
  function s() internal pure returns (St storage st) { bytes32 p = S; assembly { st.slot := p } }
  function g1(uint256 x) external { s().s_ = x; }
  function g2() external view returns (uint256) { return s().s_; }
  function g3() external pure returns (uint256) { return 99; }
}`;
const FALLBACK_SOL =
  SPDX +
  `
contract FallbackImpl {
  bytes32 constant S = keccak256(abi.encode(uint256(keccak256(bytes("app.fb"))) - 1)) & ~bytes32(uint256(0xff));
  struct St { uint256 hit; }
  function s() internal pure returns (St storage st) { bytes32 p = S; assembly { st.slot := p } }
  function ping() external pure returns (uint256) { return 0xfeed; }
  fallback() external payable { s().hit = 0xc0ffee; }
}`;
const INIT_SOL =
  SPDX +
  `
contract DInit {
  bytes32 constant S = keccak256(abi.encode(uint256(keccak256(bytes("app.init"))) - 1)) & ~bytes32(uint256(0xff));
  struct St { uint256 flag; }
  function s() internal pure returns (St storage st) { bytes32 p = S; assembly { st.slot := p } }
  function init(uint256 v) external { s().flag = v; }
}`;

// ---- deploy helpers (SAME deploy order -> CREATE addresses align) -----------
async function deployJeth() {
  const h = await Harness.create();
  const facetBig = await h.deploy(compile(FACET_BIG_JETH, { fileName: 'Big.jeth' }).creationBytecode);
  const facetSmall = await h.deploy(compile(FACET_SMALL_JETH, { fileName: 'Small.jeth' }).creationBytecode);
  const fallbackImpl = await h.deploy(compile(FALLBACK_JETH, { fileName: 'F.jeth' }).creationBytecode);
  const dinit = await h.deploy(compile(INIT_JETH, { fileName: 'I.jeth' }).creationBytecode);
  const dc = compile(DIAMOND_JETH, { fileName: 'D.jeth' });
  const diamond = await h.deploy(dc.creationBytecode + pad32(BigInt(OWNER.toString())), { caller: OWNER });
  return { h, diamond, facetBig, facetSmall, fallbackImpl, dinit };
}
async function deploySol() {
  const h = await Harness.create();
  const facetBig = await h.deploy(compileSolidity(FACET_BIG_SOL, 'FacetBig').creation);
  const facetSmall = await h.deploy(compileSolidity(FACET_SMALL_SOL, 'FacetSmall').creation);
  const fallbackImpl = await h.deploy(compileSolidity(FALLBACK_SOL, 'FallbackImpl').creation);
  const dinit = await h.deploy(compileSolidity(INIT_SOL, 'DInit').creation);
  const diamond = await h.deploy(compileSolidity(DIAMOND_SOL, 'Diamond').creation + pad32(BigInt(OWNER.toString())), {
    caller: OWNER,
  });
  return { h, diamond, facetBig, facetSmall, fallbackImpl, dinit };
}

const BIG9 = ['f1(uint256)', 'f2()', 'f3(uint256)', 'f4()', 'f5(uint256)', 'f6()', 'f7(uint256)', 'f8()', 'f9()'];
const SMALL = ['g1(uint256)', 'g2()', 'g3()'];
const selsOf = (sigs: string[]) => sigs.map((s) => '0x' + sel(s));
const addAll = (big: string, small: string) => [
  { facet: big, action: 0, selectors: selsOf(BIG9) },
  { facet: small, action: 0, selectors: selsOf(SMALL) },
];

describe('diamond-solidstate: byte-identity vs a solc solidstate v0.0.61 mirror', () => {
  it('owner() + initial ERC-165 + raw owner slot (separate Ownable namespace) + OwnershipTransferred(0,owner)', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    for (const env of [j, s]) {
      const r = await env.h.call(env.diamond, '0x' + sel('owner()'), { caller: STRANGER });
      expect(BigInt(r.returnHex)).toBe(BigInt(OWNER.toString()));
      // nominee starts zero
      const n = await env.h.call(env.diamond, '0x' + sel('nomineeOwner()'), {});
      expect(BigInt(n.returnHex)).toBe(0n);
      // fallback address starts zero
      const fa = await env.h.call(env.diamond, '0x' + sel('getFallbackAddress()'), {});
      expect(BigInt(fa.returnHex)).toBe(0n);
      for (const id of ['bd02b73c', '1f931c1c', '48e2b093', '01ffc9a7', '7f5828d0']) {
        const si = await env.h.call(env.diamond, '0x' + sel('supportsInterface(bytes4)') + id.padEnd(64, '0'), {});
        expect(BigInt(si.returnHex)).toBe(1n);
      }
      const un = await env.h.call(env.diamond, '0x' + sel('supportsInterface(bytes4)') + 'deadbeef'.padEnd(64, '0'), {});
      expect(BigInt(un.returnHex)).toBe(0n);
    }
    // raw owner slot (Ownable namespace, separate from the diamond struct) byte-identical
    expect(await readSlot(j.h, j.diamond, OWNER_SLOT)).toBe(await readSlot(s.h, s.diamond, OWNER_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, OWNER_SLOT))).toBe(BigInt(OWNER.toString()));
    // raw supportedInterfaces (ERC165Base namespace) byte-identical for a representative id
    const ifcKey = bytes4MapSlot(E165_BASE, '0xbd02b73c');
    expect(await readSlot(j.h, j.diamond, ifcKey)).toBe(await readSlot(s.h, s.diamond, ifcKey));
    expect(BigInt(await readSlot(j.h, j.diamond, ifcKey))).toBe(1n);
    // identical CREATE addresses (same deploy order/caller)
    expect(j.facetBig.toString()).toBe(s.facetBig.toString());
    expect(j.facetSmall.toString()).toBe(s.facetSmall.toString());
    expect(j.fallbackImpl.toString()).toBe(s.fallbackImpl.toString());
  });

  it('Add CROSSING the 8-selector slug boundary: routing + raw packed slots (solidstate layout) + count + loupe', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    const jr = await j.h.call(j.diamond, encodeDiamondCut(addAll(j.facetBig.toString(), j.facetSmall.toString()), ZERO, '0x'), { caller: OWNER });
    const sr = await s.h.call(s.diamond, encodeDiamondCut(addAll(s.facetBig.toString(), s.facetSmall.toString()), ZERO, '0x'), { caller: OWNER });
    expect(jr.success).toBe(true);
    expect(sr.success).toBe(true);

    for (const env of [j, s]) {
      const setF = await env.h.call(env.diamond, '0x' + sel('f1(uint256)') + w(7n), { caller: OWNER });
      expect(setF.success).toBe(true);
      const getF = await env.h.call(env.diamond, '0x' + sel('f2()'), {});
      expect(BigInt(getF.returnHex)).toBe(7n);
      const getF9 = await env.h.call(env.diamond, '0x' + sel('f9()'), {});
      expect(BigInt(getF9.returnHex)).toBe(14n); // 7 + 7 (f9 crossed into slug1)
    }

    // selectorCount == 12 in the DiamondBase namespace slot+1 (NOT slot+2 like mudgen)
    expect(await readSlot(j.h, j.diamond, COUNT_SLOT)).toBe(await readSlot(s.h, s.diamond, COUNT_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, COUNT_SLOT))).toBe(12n);

    // raw packed selectorSlugs[0] + [1] byte-identical (solidstate slugs base = DiamondBase slot+2)
    for (const k of [0n, 1n]) {
      const slotKey = uintMapSlot(SLUGS_SLOT, k);
      expect(await readSlot(j.h, j.diamond, slotKey)).toBe(await readSlot(s.h, s.diamond, slotKey));
    }
    // raw selectorInfo[selector] packed value byte-identical
    for (const sig of [...BIG9, ...SMALL]) {
      const key = bytes4MapSlot(SELINFO_SLOT, sel(sig));
      expect(await readSlot(j.h, j.diamond, key)).toBe(await readSlot(s.h, s.diamond, key));
    }

    // facetAddress(f1) == facetBig
    const jfa = await j.h.call(j.diamond, '0x' + sel('facetAddress(bytes4)') + selW('0x' + sel('f1(uint256)')), {});
    expect(BigInt(jfa.returnHex)).toBe(BigInt(j.facetBig.toString()));

    // all 4 loupe returns byte-identical
    for (const call of [
      '0x' + sel('facetAddresses()'),
      '0x' + sel('facets()'),
      '0x' + sel('facetFunctionSelectors(address)') + addrW(j.facetBig.toString()),
    ]) {
      const callS = call.replace(j.facetBig.toString().slice(2), s.facetBig.toString().slice(2));
      const jc = await j.h.call(j.diamond, call, {});
      const sc = await s.h.call(s.diamond, callS, {});
      expect(jc.success).toBe(true);
      expect(sc.success).toBe(true);
      expect(jc.returnHex).toBe(sc.returnHex);
    }
    const jffs = await j.h.call(j.diamond, '0x' + sel('facetFunctionSelectors(address)') + addrW(j.facetSmall.toString()), {});
    const sffs = await s.h.call(s.diamond, '0x' + sel('facetFunctionSelectors(address)') + addrW(s.facetSmall.toString()), {});
    expect(jffs.returnHex).toBe(sffs.returnHex);
  });

  it('Replace: rewrite a selector to another facet; raw selectorInfo + loupe identical', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    for (const env of [j, s]) {
      const big = env.facetBig.toString(),
        small = env.facetSmall.toString();
      await env.h.call(env.diamond, encodeDiamondCut(addAll(big, small), ZERO, '0x'), { caller: OWNER });
      const rep = await env.h.call(env.diamond, encodeDiamondCut([{ facet: big, action: 1, selectors: ['0x' + sel('g3()')] }], ZERO, '0x'), { caller: OWNER });
      expect(rep.success).toBe(true);
    }
    const jr = await j.h.call(j.diamond, '0x' + sel('facetAddress(bytes4)') + selW('0x' + sel('g3()')), {});
    expect(BigInt(jr.returnHex)).toBe(BigInt(j.facetBig.toString()));
    const g3key = bytes4MapSlot(SELINFO_SLOT, sel('g3()'));
    expect(await readSlot(j.h, j.diamond, g3key)).toBe(await readSlot(s.h, s.diamond, g3key));
    expect(await readSlot(j.h, j.diamond, COUNT_SLOT)).toBe(await readSlot(s.h, s.diamond, COUNT_SLOT));
    const jf = await j.h.call(j.diamond, '0x' + sel('facets()'), {});
    const sf = await s.h.call(s.diamond, '0x' + sel('facets()'), {});
    expect(jf.returnHex).toBe(sf.returnHex);
  });

  it('Remove CROSSING a slug boundary: swap-into-gap packed bit-math + raw slots + loupe identical', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    for (const env of [j, s]) {
      const big = env.facetBig.toString(),
        small = env.facetSmall.toString();
      await env.h.call(env.diamond, encodeDiamondCut(addAll(big, small), ZERO, '0x'), { caller: OWNER });
      const rm = await env.h.call(env.diamond, encodeDiamondCut([
        { facet: ZERO, action: 2, selectors: ['0x' + sel('f1(uint256)'), '0x' + sel('f3(uint256)')] },
      ], ZERO, '0x'), { caller: OWNER });
      expect(rm.success).toBe(true);
    }
    expect(await readSlot(j.h, j.diamond, COUNT_SLOT)).toBe(await readSlot(s.h, s.diamond, COUNT_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, COUNT_SLOT))).toBe(10n);
    for (const k of [0n, 1n]) {
      const slotKey = uintMapSlot(SLUGS_SLOT, k);
      expect(await readSlot(j.h, j.diamond, slotKey)).toBe(await readSlot(s.h, s.diamond, slotKey));
    }
    for (const sig of [...BIG9, ...SMALL]) {
      const key = bytes4MapSlot(SELINFO_SLOT, sel(sig));
      expect(await readSlot(j.h, j.diamond, key)).toBe(await readSlot(s.h, s.diamond, key));
    }
    // removed selector routes to "does not exist" (no fallback set) -> Proxy__ImplementationIsNotContract
    const jn = await j.h.call(j.diamond, '0x' + sel('f1(uint256)') + w(1n), { caller: OWNER });
    const sn = await s.h.call(s.diamond, '0x' + sel('f1(uint256)') + w(1n), { caller: OWNER });
    expect(jn.success).toBe(false);
    expect(sn.success).toBe(false);
    expect(jn.returnHex).toBe(sn.returnHex);
    const fa = await j.h.call(j.diamond, '0x' + sel('facetAddress(bytes4)') + selW('0x' + sel('f1(uint256)')), {});
    expect(BigInt(fa.returnHex)).toBe(0n);
    for (const sig of ['facetAddresses()', 'facets()']) {
      const jc = await j.h.call(j.diamond, '0x' + sel(sig), {});
      const sc = await s.h.call(s.diamond, '0x' + sel(sig), {});
      expect(jc.returnHex).toBe(sc.returnHex);
    }
  });

  it('DiamondCut event + owner gate (Ownable__NotOwner) + _init delegatecall + not-found revert identical', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    const cut = (big: string) => [{ facet: big, action: 0, selectors: ['0x' + sel('f1(uint256)')] }];
    const jr = await j.h.call(j.diamond, encodeDiamondCut(cut(j.facetBig.toString()), ZERO, '0x'), { caller: OWNER });
    const sr = await s.h.call(s.diamond, encodeDiamondCut(cut(s.facetBig.toString()), ZERO, '0x'), { caller: OWNER });
    expect(jr.logs.length).toBe(1);
    expect(sr.logs.length).toBe(1);
    expect(jr.logs[0]!.topics[0]).toBe(sr.logs[0]!.topics[0]);
    expect(jr.logs[0]!.data).toBe(sr.logs[0]!.data);

    // non-owner diamondCut reverts identically (Ownable__NotOwner custom error)
    const jg = await j.h.call(j.diamond, encodeDiamondCut(cut(j.facetBig.toString()), ZERO, '0x'), { caller: STRANGER });
    const sg = await s.h.call(s.diamond, encodeDiamondCut(cut(s.facetBig.toString()), ZERO, '0x'), { caller: STRANGER });
    expect(jg.success).toBe(false);
    expect(sg.success).toBe(false);
    expect(jg.returnHex).toBe(sg.returnHex);
    expect(jg.returnHex.slice(0, 10)).toBe('0x2f7a8ee1'); // Ownable__NotOwner()

    // _init delegatecall runs in the diamond context
    for (const env of [j, s]) {
      const r = await env.h.call(env.diamond, encodeDiamondCut(
        [{ facet: env.facetBig.toString(), action: 0, selectors: ['0x' + sel('f5(uint256)')] }],
        env.dinit.toString(),
        '0x' + sel('init(uint256)') + w(77n),
      ), { caller: OWNER });
      expect(r.success).toBe(true);
    }
    const innerI = (keccakHex('app.init') - 1n + (1n << 256n)) % (1n << 256n);
    const INIT_SLOT = keccakHex(word32(innerI)) & ~0xffn;
    expect(BigInt(await readSlot(j.h, j.diamond, INIT_SLOT))).toBe(77n);
    expect(await readSlot(j.h, j.diamond, INIT_SLOT)).toBe(await readSlot(s.h, s.diamond, INIT_SLOT));

    // unknown selector with no fallback -> Proxy__ImplementationIsNotContract revert identical
    const jn = await j.h.call(j.diamond, '0x' + sel('nope()'), {});
    const sn = await s.h.call(s.diamond, '0x' + sel('nope()'), {});
    expect(jn.success).toBe(false);
    expect(sn.success).toBe(false);
    expect(jn.returnHex).toBe(sn.returnHex);
    expect(jn.returnHex.slice(0, 10)).toBe('0x87c9fc34'); // Proxy__ImplementationIsNotContract()
  });

  it('HEADLINE: default fallback address - miss with no fallback reverts; set it then the same miss delegatecalls it', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    const MISS = '0x' + sel('mystery(uint256)') + w(1n);

    for (const env of [j, s]) {
      // (a) selector miss with NO fallback set -> revert
      const r0 = await env.h.call(env.diamond, MISS, {});
      expect(r0.success).toBe(false);
    }
    // both revert identically (Proxy__ImplementationIsNotContract)
    {
      const jr = await j.h.call(j.diamond, MISS, {});
      const srr = await s.h.call(s.diamond, MISS, {});
      expect(jr.returnHex).toBe(srr.returnHex);
      expect(jr.returnHex.slice(0, 10)).toBe('0x87c9fc34');
    }

    // (b) a non-owner setFallbackAddress reverts (Ownable__NotOwner)
    for (const env of [j, s]) {
      const r = await env.h.call(env.diamond, '0x' + sel('setFallbackAddress(address)') + addrW(env.fallbackImpl.toString()), { caller: STRANGER });
      expect(r.success).toBe(false);
      expect(r.returnHex.slice(0, 10)).toBe('0x2f7a8ee1');
    }

    // (c) owner sets the fallback to the FallbackImpl contract
    for (const env of [j, s]) {
      const r = await env.h.call(env.diamond, '0x' + sel('setFallbackAddress(address)') + addrW(env.fallbackImpl.toString()), { caller: OWNER });
      expect(r.success).toBe(true);
    }
    // getFallbackAddress() == fallbackImpl + raw fallbackAddress slot (DiamondBase slot+3) byte-identical
    for (const env of [j, s]) {
      const g = await env.h.call(env.diamond, '0x' + sel('getFallbackAddress()'), {});
      expect(BigInt(g.returnHex)).toBe(BigInt(env.fallbackImpl.toString()));
    }
    expect(await readSlot(j.h, j.diamond, FALLBACK_SLOT)).toBe(await readSlot(s.h, s.diamond, FALLBACK_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, FALLBACK_SLOT))).toBe(BigInt(j.fallbackImpl.toString()));

    // (d) NOW the same selector miss delegatecalls the fallback (which writes the DIAMOND's app.fb storage)
    const innerFb = (keccakHex('app.fb') - 1n + (1n << 256n)) % (1n << 256n);
    const FB_SLOT = keccakHex(word32(innerFb)) & ~0xffn;
    for (const env of [j, s]) {
      const r = await env.h.call(env.diamond, MISS, {});
      expect(r.success).toBe(true);
      // the fallback ran in the diamond's storage context: app.fb.hit == 0xc0ffee in the DIAMOND, not the impl
      expect(BigInt(await readSlot(env.h, env.diamond, FB_SLOT))).toBe(0xc0ffeen);
      expect(BigInt(await readSlot(env.h, env.fallbackImpl, FB_SLOT))).toBe(0n);
    }
    expect(await readSlot(j.h, j.diamond, FB_SLOT)).toBe(await readSlot(s.h, s.diamond, FB_SLOT));
  });

  it('SafeOwnable 2-step: transferOwnership sets nominee (no transfer/event); acceptOwnership finalizes; non-nominee accept reverts', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    // (a) transferOwnership(NOMINEE) by the owner sets the NOMINEE only - owner unchanged, NO event
    for (const env of [j, s]) {
      const t = await env.h.call(env.diamond, '0x' + sel('transferOwnership(address)') + addrW(NOMINEE.toString()), { caller: OWNER });
      expect(t.success).toBe(true);
      expect(t.logs.length).toBe(0); // solidstate emits NO event on transferOwnership
      // owner still OWNER, nominee now NOMINEE
      const o = await env.h.call(env.diamond, '0x' + sel('owner()'), {});
      expect(BigInt(o.returnHex)).toBe(BigInt(OWNER.toString()));
      const n = await env.h.call(env.diamond, '0x' + sel('nomineeOwner()'), {});
      expect(BigInt(n.returnHex)).toBe(BigInt(NOMINEE.toString()));
    }
    // raw owner + nominee slots byte-identical (and in their separate namespaces)
    expect(await readSlot(j.h, j.diamond, OWNER_SLOT)).toBe(await readSlot(s.h, s.diamond, OWNER_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, OWNER_SLOT))).toBe(BigInt(OWNER.toString()));
    expect(await readSlot(j.h, j.diamond, NOMINEE_SLOT)).toBe(await readSlot(s.h, s.diamond, NOMINEE_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, NOMINEE_SLOT))).toBe(BigInt(NOMINEE.toString()));

    // (b) a NON-nominee acceptOwnership reverts (SafeOwnable__NotNomineeOwner) identically
    {
      const jr = await j.h.call(j.diamond, '0x' + sel('acceptOwnership()'), { caller: STRANGER });
      const srr = await s.h.call(s.diamond, '0x' + sel('acceptOwnership()'), { caller: STRANGER });
      expect(jr.success).toBe(false);
      expect(srr.success).toBe(false);
      expect(jr.returnHex).toBe(srr.returnHex);
      expect(jr.returnHex.slice(0, 10)).toBe('0xefd1052d'); // SafeOwnable__NotNomineeOwner()
    }

    // (c) the NOMINEE accepts -> becomes owner, emits OwnershipTransferred(OWNER, NOMINEE), clears the nominee
    const ja = await j.h.call(j.diamond, '0x' + sel('acceptOwnership()'), { caller: NOMINEE });
    const sa = await s.h.call(s.diamond, '0x' + sel('acceptOwnership()'), { caller: NOMINEE });
    expect(ja.success).toBe(true);
    expect(sa.success).toBe(true);
    expect(ja.logs.length).toBe(1);
    expect(sa.logs.length).toBe(1);
    expect(ja.logs[0]!.topics).toEqual(sa.logs[0]!.topics);
    expect(ja.logs[0]!.topics[0]).toBe(OWNERSHIP_TRANSFERRED);
    // topics[1] = old owner (OWNER), topics[2] = new owner (NOMINEE)
    expect(BigInt(ja.logs[0]!.topics[1]!)).toBe(BigInt(OWNER.toString()));
    expect(BigInt(ja.logs[0]!.topics[2]!)).toBe(BigInt(NOMINEE.toString()));

    // owner now NOMINEE, nominee cleared - raw slots byte-identical
    for (const env of [j, s]) {
      const o = await env.h.call(env.diamond, '0x' + sel('owner()'), {});
      expect(BigInt(o.returnHex)).toBe(BigInt(NOMINEE.toString()));
      const n = await env.h.call(env.diamond, '0x' + sel('nomineeOwner()'), {});
      expect(BigInt(n.returnHex)).toBe(0n);
    }
    expect(await readSlot(j.h, j.diamond, OWNER_SLOT)).toBe(await readSlot(s.h, s.diamond, OWNER_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, OWNER_SLOT))).toBe(BigInt(NOMINEE.toString()));
    expect(await readSlot(j.h, j.diamond, NOMINEE_SLOT)).toBe(await readSlot(s.h, s.diamond, NOMINEE_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, NOMINEE_SLOT))).toBe(0n);

    // (d) the old owner can no longer transfer (Ownable__NotOwner); the new owner can
    const jold = await j.h.call(j.diamond, '0x' + sel('transferOwnership(address)') + addrW(STRANGER.toString()), { caller: OWNER });
    expect(jold.success).toBe(false);
    expect(jold.returnHex.slice(0, 10)).toBe('0x2f7a8ee1');
    const jnew = await j.h.call(j.diamond, '0x' + sel('transferOwnership(address)') + addrW(STRANGER.toString()), { caller: NOMINEE });
    expect(jnew.success).toBe(true);
  });
});

describe('diamond-solidstate: gates', () => {
  const codes = (src: string): string[] => {
    try {
      compile(src, { fileName: 'C.jeth' });
      return [];
    } catch (e: unknown) {
      return ((e as { diagnostics?: { code: string }[] }).diagnostics ?? []).map((d) => d.code);
    }
  };
  it("accepts @diamond('solidstate')", () => {
    expect(codes(DIAMOND_JETH)).toEqual([]);
  });
  it('rejects an unknown @diamond model (JETH412)', () => {
    expect(codes(`@diamond('frozen') class D { constructor(o: address) { diamondInitSolidstate(o); } }`)).toContain('JETH412');
  });
});
