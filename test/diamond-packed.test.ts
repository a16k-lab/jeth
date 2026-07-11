// Phase 3 (DIAMOND): `@diamond('packed')` - an EIP-2535 diamond on the PACKED (diamond-2-hardhat) layout.
// JETH synthesizes the WHOLE surface (the diamond-2 namespaced storage struct, diamondCut + the four
// loupe fns + ERC-165 + ownership, the DiamondCut/OwnershipTransferred events) reusing the array model's
// framework; ONLY the diamond storage layout, the cut add/replace/remove, the 4 loupe reconstructors, and
// the router's facet read change. The cut + loupe are raw-Yul builtins (the packed bit-math and the loupe's
// over-allocate-then-shrink reconstruction are not expressible in plain JETH).
//
// Byte-identity target: a hand-written solc 0.8.35 diamond-2 mirror with the IDENTICAL diamond-2 storage
// layout (base = keccak256("diamond.standard.diamond.storage")), the two masks, the 8-selectors-per-bytes32
// packing, the swap-into-gap removal, and the IN-DIAMOND reconstruct loupe. We diff the OBSERVABLE output
// (returndata + raw DiamondStorage slots + logs + revert), word-for-word, across: selector routing, an Add
// that CROSSES the 8-per-slot boundary (multi-slot selectorSlots), Replace, a Remove that CROSSES a slot
// boundary, all four loupe returns, facetAddress, ERC-165, owner/transferOwnership, the DiamondCut event,
// the owner gate, the _init delegatecall, and the "Diamond: Function does not exist" revert.
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
// keccak256("diamond.standard.diamond.storage") - the raw diamond-2 base slot.
const DS_BASE = keccakHex('diamond.standard.diamond.storage');
const FACETS_SLOT = DS_BASE + 0n; // mapping(bytes4 => bytes32)
const SLOTS_SLOT = DS_BASE + 1n; // mapping(uint256 => bytes32)
const COUNT_SLOT = DS_BASE + 2n; // uint16 selectorCount (alone in its slot)
const OWNER_SLOT = DS_BASE + 4n; // address contractOwner
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

// solc mapping(K=>V) element slot = keccak256(key . mappingBaseSlot). bytes4 key is LEFT-aligned; uint256
// key is the raw value.
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
const DIAMOND_JETH = `@diamond('packed') class MyDiamond {
  constructor(owner: address) { diamondInit(owner); }
}`;

// FacetBig: nine selectors (forces selectorSlots to span >1 slot: 9 = slot0[0..7] + slot1[0]).
// Each writes/reads a distinct namespaced storage word so routing into the diamond is verifiable.
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
const INIT_JETH = `class DInit {
  @storage('app.init') flag: u256;
  init(v: u256): External<void> { this.flag = v; }
}`;

// ---- the solc diamond-2 mirror (IN-DIAMOND dispatch, exact mudgen LibDiamond layout) -------
const DIAMOND_SOL =
  SPDX +
  `
struct DiamondStorage {
  mapping(bytes4 => bytes32) facets;
  mapping(uint256 => bytes32) selectorSlots;
  uint16 selectorCount;
  mapping(bytes4 => bool) supportedInterfaces;
  address contractOwner;
}
struct Facet { address facetAddress; bytes4[] functionSelectors; }
struct FacetCut { address facetAddress; uint8 action; bytes4[] functionSelectors; }
contract Diamond {
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
  event DiamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata);
  bytes32 constant DSP = keccak256("diamond.standard.diamond.storage");
  bytes32 constant CLEAR_ADDRESS_MASK = bytes32(uint256(0xffffffffffffffffffffffff));
  bytes32 constant CLEAR_SELECTOR_MASK = bytes32(uint256(0xffffffff << 224));
  function ds() internal pure returns (DiamondStorage storage s) { bytes32 p = DSP; assembly { s.slot := p } }
  constructor(address owner) {
    ds().contractOwner = owner;
    emit OwnershipTransferred(address(0), owner);
    ds().supportedInterfaces[0x01ffc9a7] = true;
    ds().supportedInterfaces[0x1f931c1c] = true;
    ds().supportedInterfaces[0x48e2b093] = true;
    ds().supportedInterfaces[0x7f5828d0] = true;
  }
  function owner() external view returns (address) { return ds().contractOwner; }
  function transferOwnership(address newOwner) external {
    require(msg.sender == ds().contractOwner, "LibDiamond: Must be contract owner");
    address prev = ds().contractOwner; ds().contractOwner = newOwner;
    emit OwnershipTransferred(prev, newOwner);
  }
  function supportsInterface(bytes4 id) external view returns (bool) { return ds().supportedInterfaces[id]; }
  function facetAddress(bytes4 s) external view returns (address) { return address(bytes20(ds().facets[s])); }
  function facetAddresses() external view returns (address[] memory addrs) {
    DiamondStorage storage d = ds();
    addrs = new address[](d.selectorCount);
    uint256 numFacets;
    uint256 selectorIndex;
    for (uint256 slotIndex; selectorIndex < d.selectorCount; slotIndex++) {
      bytes32 slot = d.selectorSlots[slotIndex];
      for (uint256 si; si < 8; si++) {
        selectorIndex++;
        if (selectorIndex > d.selectorCount) break;
        bytes4 s = bytes4(slot << (si << 5));
        address fa = address(bytes20(d.facets[s]));
        bool found;
        for (uint256 k; k < numFacets; k++) { if (addrs[k] == fa) { found = true; break; } }
        if (!found) { addrs[numFacets] = fa; numFacets++; }
      }
    }
    assembly { mstore(addrs, numFacets) }
  }
  function facetFunctionSelectors(address f) external view returns (bytes4[] memory sels) {
    DiamondStorage storage d = ds();
    sels = new bytes4[](d.selectorCount);
    uint256 numSelectors;
    uint256 selectorIndex;
    for (uint256 slotIndex; selectorIndex < d.selectorCount; slotIndex++) {
      bytes32 slot = d.selectorSlots[slotIndex];
      for (uint256 si; si < 8; si++) {
        selectorIndex++;
        if (selectorIndex > d.selectorCount) break;
        bytes4 s = bytes4(slot << (si << 5));
        if (f == address(bytes20(d.facets[s]))) { sels[numSelectors] = s; numSelectors++; }
      }
    }
    assembly { mstore(sels, numSelectors) }
  }
  function facets() external view returns (Facet[] memory facets_) {
    DiamondStorage storage d = ds();
    facets_ = new Facet[](d.selectorCount);
    uint16[] memory numFacetSelectors = new uint16[](d.selectorCount);
    uint256 numFacets;
    uint256 selectorIndex;
    for (uint256 slotIndex; selectorIndex < d.selectorCount; slotIndex++) {
      bytes32 slot = d.selectorSlots[slotIndex];
      for (uint256 si; si < 8; si++) {
        selectorIndex++;
        if (selectorIndex > d.selectorCount) break;
        bytes4 s = bytes4(slot << (si << 5));
        address fa = address(bytes20(d.facets[s]));
        bool continueLoop;
        for (uint256 k; k < numFacets; k++) {
          if (facets_[k].facetAddress == fa) {
            facets_[k].functionSelectors[numFacetSelectors[k]] = s;
            numFacetSelectors[k]++;
            continueLoop = true;
            break;
          }
        }
        if (continueLoop) continue;
        facets_[numFacets].facetAddress = fa;
        facets_[numFacets].functionSelectors = new bytes4[](d.selectorCount);
        facets_[numFacets].functionSelectors[0] = s;
        numFacetSelectors[numFacets] = 1;
        numFacets++;
      }
    }
    for (uint256 fi; fi < numFacets; fi++) {
      uint256 numSelectors = numFacetSelectors[fi];
      bytes4[] memory selectors = facets_[fi].functionSelectors;
      assembly { mstore(selectors, numSelectors) }
    }
    assembly { mstore(facets_, numFacets) }
  }
  function diamondCut(FacetCut[] calldata _diamondCut, address _init, bytes calldata _calldata) external {
    require(msg.sender == ds().contractOwner, "LibDiamond: Must be contract owner");
    DiamondStorage storage d = ds();
    uint256 originalSelectorCount = d.selectorCount;
    uint256 selectorCount = originalSelectorCount;
    bytes32 selectorSlot;
    if (selectorCount & 7 > 0) { selectorSlot = d.selectorSlots[selectorCount >> 3]; }
    for (uint256 fi; fi < _diamondCut.length; fi++) {
      (selectorCount, selectorSlot) = arr(selectorCount, selectorSlot, _diamondCut[fi].facetAddress, _diamondCut[fi].action, _diamondCut[fi].functionSelectors);
    }
    if (selectorCount != originalSelectorCount) { d.selectorCount = uint16(selectorCount); }
    if (selectorCount & 7 > 0) { d.selectorSlots[selectorCount >> 3] = selectorSlot; }
    emit DiamondCut(_diamondCut, _init, _calldata);
    initD(_init, _calldata);
  }
  function arr(uint256 _selectorCount, bytes32 _selectorSlot, address _newFacetAddress, uint8 _action, bytes4[] memory _selectors) internal returns (uint256, bytes32) {
    DiamondStorage storage d = ds();
    require(_selectors.length > 0, "LibDiamondCut: No selectors in facet to cut");
    if (_action == 0) {
      enforceCode(_newFacetAddress, "LibDiamondCut: Add facet has no code");
      for (uint256 si; si < _selectors.length; si++) {
        bytes4 selector = _selectors[si];
        bytes32 oldFacet = d.facets[selector];
        require(address(bytes20(oldFacet)) == address(0), "LibDiamondCut: Can't add function that already exists");
        d.facets[selector] = bytes20(_newFacetAddress) | bytes32(_selectorCount);
        uint256 pos = (_selectorCount & 7) << 5;
        _selectorSlot = (_selectorSlot & ~(CLEAR_SELECTOR_MASK >> pos)) | (bytes32(selector) >> pos);
        if (pos == 224) { d.selectorSlots[_selectorCount >> 3] = _selectorSlot; _selectorSlot = 0; }
        _selectorCount++;
      }
    } else if (_action == 1) {
      enforceCode(_newFacetAddress, "LibDiamondCut: Replace facet has no code");
      for (uint256 si; si < _selectors.length; si++) {
        bytes4 selector = _selectors[si];
        bytes32 oldFacet = d.facets[selector];
        address old = address(bytes20(oldFacet));
        require(old != address(this), "LibDiamondCut: Can't replace immutable function");
        require(old != _newFacetAddress, "LibDiamondCut: Can't replace function with same function");
        require(old != address(0), "LibDiamondCut: Can't replace function that doesn't exist");
        d.facets[selector] = (oldFacet & CLEAR_ADDRESS_MASK) | bytes20(_newFacetAddress);
      }
    } else if (_action == 2) {
      require(_newFacetAddress == address(0), "LibDiamondCut: Remove facet address must be address(0)");
      uint256 selectorSlotCount = _selectorCount >> 3;
      uint256 selectorInSlotIndex = _selectorCount & 7;
      for (uint256 si; si < _selectors.length; si++) {
        if (selectorInSlotIndex == 0) {
          selectorSlotCount--;
          _selectorSlot = d.selectorSlots[selectorSlotCount];
          selectorInSlotIndex = 7;
        } else { selectorInSlotIndex--; }
        bytes4 lastSelector;
        uint256 oldSelectorsSlotCount;
        uint256 oldSelectorInSlotPosition;
        {
          bytes4 selector = _selectors[si];
          bytes32 oldFacet = d.facets[selector];
          require(address(bytes20(oldFacet)) != address(0), "LibDiamondCut: Can't remove function that doesn't exist");
          require(address(bytes20(oldFacet)) != address(this), "LibDiamondCut: Can't remove immutable function");
          lastSelector = bytes4(_selectorSlot << (selectorInSlotIndex << 5));
          if (lastSelector != selector) {
            d.facets[lastSelector] = (oldFacet & CLEAR_ADDRESS_MASK) | bytes20(d.facets[lastSelector]);
          }
          delete d.facets[selector];
          uint256 oldSelectorCount = uint16(uint256(oldFacet));
          oldSelectorsSlotCount = oldSelectorCount >> 3;
          oldSelectorInSlotPosition = (oldSelectorCount & 7) << 5;
        }
        if (oldSelectorsSlotCount != selectorSlotCount) {
          bytes32 oldSelectorSlot = d.selectorSlots[oldSelectorsSlotCount];
          oldSelectorSlot = (oldSelectorSlot & ~(CLEAR_SELECTOR_MASK >> oldSelectorInSlotPosition)) | (bytes32(lastSelector) >> oldSelectorInSlotPosition);
          d.selectorSlots[oldSelectorsSlotCount] = oldSelectorSlot;
        } else {
          _selectorSlot = (_selectorSlot & ~(CLEAR_SELECTOR_MASK >> oldSelectorInSlotPosition)) | (bytes32(lastSelector) >> oldSelectorInSlotPosition);
        }
        if (selectorInSlotIndex == 0) { delete d.selectorSlots[selectorSlotCount]; _selectorSlot = 0; }
      }
      _selectorCount = selectorSlotCount * 8 + selectorInSlotIndex;
    } else { revert("LibDiamondCut: Incorrect FacetCutAction"); }
    return (_selectorCount, _selectorSlot);
  }
  function enforceCode(address a, string memory err) internal view {
    uint256 cs; assembly { cs := extcodesize(a) }
    require(cs > 0, err);
  }
  function initD(address _init, bytes memory _calldata) internal {
    if (_init == address(0)) return;
    enforceCode(_init, "LibDiamondCut: _init address has no code");
    (bool ok, bytes memory err) = _init.delegatecall(_calldata);
    if (!ok) { if (err.length > 0) { assembly { revert(add(32, err), mload(err)) } } else revert("init failed"); }
  }
  fallback() external payable {
    DiamondStorage storage d;
    bytes32 p = DSP; assembly { d.slot := p }
    address facet = address(bytes20(d.facets[msg.sig]));
    require(facet != address(0), "Diamond: Function does not exist");
    assembly {
      calldatacopy(0, 0, calldatasize())
      let r := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
      returndatacopy(0, 0, returndatasize())
      switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
    }
  }
  receive() external payable {}
}
`;
// solc facet mirrors (must write the SAME namespaced slots as the JETH facets). solc ERC-7201.
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
  function st() internal pure returns (St storage x) { bytes32 p = S; assembly { x.slot := p } }
  function g1(uint256 x) external { st().s_ = x; }
  function g2() external view returns (uint256) { return st().s_; }
  function g3() external pure returns (uint256) { return 99; }
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

// Deploy helpers: a JETH world and a solc world, each with the diamond + the facets (SAME order -> the
// CREATE addresses align).
async function deployJeth() {
  const h = await Harness.create();
  const facetBig = await h.deploy(compile(FACET_BIG_JETH, { fileName: 'Big.jeth' }).creationBytecode);
  const facetSmall = await h.deploy(compile(FACET_SMALL_JETH, { fileName: 'Small.jeth' }).creationBytecode);
  const dinit = await h.deploy(compile(INIT_JETH, { fileName: 'I.jeth' }).creationBytecode);
  const dc = compile(DIAMOND_JETH, { fileName: 'D.jeth' });
  const diamond = await h.deploy(dc.creationBytecode + pad32(BigInt(OWNER.toString())), { caller: OWNER });
  return { h, diamond, facetBig, facetSmall, dinit };
}
async function deploySol() {
  const h = await Harness.create();
  const facetBig = await h.deploy(compileSolidity(FACET_BIG_SOL, 'FacetBig').creation);
  const facetSmall = await h.deploy(compileSolidity(FACET_SMALL_SOL, 'FacetSmall').creation);
  const dinit = await h.deploy(compileSolidity(INIT_SOL, 'DInit').creation);
  const diamond = await h.deploy(compileSolidity(DIAMOND_SOL, 'Diamond').creation + pad32(BigInt(OWNER.toString())), {
    caller: OWNER,
  });
  return { h, diamond, facetBig, facetSmall, dinit };
}

const BIG9 = [
  'f1(uint256)',
  'f2()',
  'f3(uint256)',
  'f4()',
  'f5(uint256)',
  'f6()',
  'f7(uint256)',
  'f8()',
  'f9()',
];
const SMALL = ['g1(uint256)', 'g2()', 'g3()'];
const selsOf = (sigs: string[]) => sigs.map((s) => '0x' + sel(s));

describe('diamond-packed: byte-identity vs a solc diamond-2 mirror', () => {
  it('owner() + initial ERC-165 + raw owner slot + OwnershipTransferred(0,owner) on deploy', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    for (const env of [j, s]) {
      const r = await env.h.call(env.diamond, '0x' + sel('owner()'), { caller: STRANGER });
      expect(BigInt(r.returnHex)).toBe(BigInt(OWNER.toString()));
      for (const id of ['01ffc9a7', '1f931c1c', '48e2b093', '7f5828d0']) {
        const si = await env.h.call(env.diamond, '0x' + sel('supportsInterface(bytes4)') + id.padEnd(64, '0'), {});
        expect(BigInt(si.returnHex)).toBe(1n);
      }
      const un = await env.h.call(env.diamond, '0x' + sel('supportsInterface(bytes4)') + 'deadbeef'.padEnd(64, '0'), {});
      expect(BigInt(un.returnHex)).toBe(0n);
    }
    expect(await readSlot(j.h, j.diamond, OWNER_SLOT)).toBe(await readSlot(s.h, s.diamond, OWNER_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, OWNER_SLOT))).toBe(BigInt(OWNER.toString()));
    // identical CREATE addresses (same deploy order/caller) -> all later raw-slot diffs are meaningful
    expect(j.facetBig.toString()).toBe(s.facetBig.toString());
    expect(j.facetSmall.toString()).toBe(s.facetSmall.toString());
  });

  it('Add CROSSING the 8-selector slot boundary: routing + raw packed slots + selectorCount + loupe', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    // 9 selectors on facetBig (slot0 fills 8, slot1 gets 1) + 3 on facetSmall (slot1[1..3]) = 12 total.
    const cut = (big: string, small: string) => [
      { facet: big, action: 0, selectors: selsOf(BIG9) },
      { facet: small, action: 0, selectors: selsOf(SMALL) },
    ];
    const jr = await j.h.call(j.diamond, encodeDiamondCut(cut(j.facetBig.toString(), j.facetSmall.toString()), ZERO, '0x'), { caller: OWNER });
    const sr = await s.h.call(s.diamond, encodeDiamondCut(cut(s.facetBig.toString(), s.facetSmall.toString()), ZERO, '0x'), { caller: OWNER });
    expect(jr.success).toBe(true);
    expect(sr.success).toBe(true);

    // route f1(7) -> f2() through the diamond (writes the DIAMOND's app.big storage)
    for (const env of [j, s]) {
      const setF = await env.h.call(env.diamond, '0x' + sel('f1(uint256)') + w(7n), { caller: OWNER });
      expect(setF.success).toBe(true);
      const getF = await env.h.call(env.diamond, '0x' + sel('f2()'), {});
      expect(BigInt(getF.returnHex)).toBe(7n);
      // f9() (the selector that crossed into slot1) routes too
      const getF9 = await env.h.call(env.diamond, '0x' + sel('f9()'), {});
      expect(BigInt(getF9.returnHex)).toBe(14n); // 7 + 7
    }

    // selectorCount == 12, raw slot identical (uint16 right-aligned alone in COUNT_SLOT)
    expect(await readSlot(j.h, j.diamond, COUNT_SLOT)).toBe(await readSlot(s.h, s.diamond, COUNT_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, COUNT_SLOT))).toBe(12n);

    // raw packed selectorSlots[0] (8 selectors) and selectorSlots[1] (4 selectors) byte-identical
    for (const k of [0n, 1n]) {
      const slotKey = uintMapSlot(SLOTS_SLOT, k);
      expect(await readSlot(j.h, j.diamond, slotKey)).toBe(await readSlot(s.h, s.diamond, slotKey));
    }
    // raw facets[selector] packed value (addr high 20 | position low) byte-identical for each selector
    for (const sig of [...BIG9, ...SMALL]) {
      const key = bytes4MapSlot(FACETS_SLOT, sel(sig));
      expect(await readSlot(j.h, j.diamond, key)).toBe(await readSlot(s.h, s.diamond, key));
    }

    // facetAddress(f1) == facetBig (each world's own)
    const jfa = await j.h.call(j.diamond, '0x' + sel('facetAddress(bytes4)') + selW('0x' + sel('f1(uint256)')), {});
    expect(BigInt(jfa.returnHex)).toBe(BigInt(j.facetBig.toString()));
    const sfa = await s.h.call(s.diamond, '0x' + sel('facetAddress(bytes4)') + selW('0x' + sel('f1(uint256)')), {});
    expect(BigInt(sfa.returnHex)).toBe(BigInt(s.facetBig.toString()));

    // all 4 loupe returns byte-identical (identical facet addresses across worlds)
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
    // facetFunctionSelectors(facetSmall)
    const jffs = await j.h.call(j.diamond, '0x' + sel('facetFunctionSelectors(address)') + addrW(j.facetSmall.toString()), {});
    const sffs = await s.h.call(s.diamond, '0x' + sel('facetFunctionSelectors(address)') + addrW(s.facetSmall.toString()), {});
    expect(jffs.returnHex).toBe(sffs.returnHex);
  });

  it('Replace: rewrite a selector to another facet; raw facets value + loupe identical', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    for (const env of [j, s]) {
      const big = env.facetBig.toString(),
        small = env.facetSmall.toString();
      await env.h.call(env.diamond, encodeDiamondCut([
        { facet: big, action: 0, selectors: selsOf(BIG9) },
        { facet: small, action: 0, selectors: selsOf(SMALL) },
      ], ZERO, '0x'), { caller: OWNER });
      // Replace g3() (currently on facetSmall) to be served by facetBig.
      const rep = await env.h.call(env.diamond, encodeDiamondCut([{ facet: big, action: 1, selectors: ['0x' + sel('g3()')] }], ZERO, '0x'), { caller: OWNER });
      expect(rep.success).toBe(true);
    }
    // facetAddress(g3) now == facetBig in both; selectorSlots untouched (position kept)
    const jr = await j.h.call(j.diamond, '0x' + sel('facetAddress(bytes4)') + selW('0x' + sel('g3()')), {});
    expect(BigInt(jr.returnHex)).toBe(BigInt(j.facetBig.toString()));
    // raw facets[g3] packed value identical (addr swapped, low position preserved)
    const g3key = bytes4MapSlot(FACETS_SLOT, sel('g3()'));
    expect(await readSlot(j.h, j.diamond, g3key)).toBe(await readSlot(s.h, s.diamond, g3key));
    // selectorCount unchanged (Replace doesn't add/remove), raw slot identical
    expect(await readSlot(j.h, j.diamond, COUNT_SLOT)).toBe(await readSlot(s.h, s.diamond, COUNT_SLOT));
    // facets() return identical
    const jf = await j.h.call(j.diamond, '0x' + sel('facets()'), {});
    const sf = await s.h.call(s.diamond, '0x' + sel('facets()'), {});
    expect(jf.returnHex).toBe(sf.returnHex);
  });

  it('Remove CROSSING a slot boundary: swap-into-gap packed bit-math + raw slots + loupe identical', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    for (const env of [j, s]) {
      const big = env.facetBig.toString(),
        small = env.facetSmall.toString();
      await env.h.call(env.diamond, encodeDiamondCut([
        { facet: big, action: 0, selectors: selsOf(BIG9) }, // 9 -> slot0[0..7], slot1[0]
        { facet: small, action: 0, selectors: selsOf(SMALL) }, // 3 -> slot1[1..3] ; count=12
      ], ZERO, '0x'), { caller: OWNER });
      // Remove f1 (in slot0) and f3 (in slot0): the globally-LAST selectors (in slot1) swap down into the
      // freed slot0 positions -> the gap-fill writes a DIFFERENT slot than the working slot (cross-slot).
      const rm = await env.h.call(env.diamond, encodeDiamondCut([
        { facet: ZERO, action: 2, selectors: ['0x' + sel('f1(uint256)'), '0x' + sel('f3(uint256)')] },
      ], ZERO, '0x'), { caller: OWNER });
      expect(rm.success).toBe(true);
    }
    // selectorCount == 10, raw identical
    expect(await readSlot(j.h, j.diamond, COUNT_SLOT)).toBe(await readSlot(s.h, s.diamond, COUNT_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, COUNT_SLOT))).toBe(10n);
    // raw packed selectorSlots[0] and selectorSlots[1] after the cross-slot swap byte-identical
    for (const k of [0n, 1n]) {
      const slotKey = uintMapSlot(SLOTS_SLOT, k);
      expect(await readSlot(j.h, j.diamond, slotKey)).toBe(await readSlot(s.h, s.diamond, slotKey));
    }
    // raw facets[selector] for every still-present + the removed selectors byte-identical
    for (const sig of [...BIG9, ...SMALL]) {
      const key = bytes4MapSlot(FACETS_SLOT, sel(sig));
      expect(await readSlot(j.h, j.diamond, key)).toBe(await readSlot(s.h, s.diamond, key));
    }
    // removed selectors route to "does not exist"
    const gone = await j.h.call(j.diamond, '0x' + sel('f1(uint256)') + w(1n), { caller: OWNER });
    expect(gone.success).toBe(false);
    // facetAddress(f1) == 0 (no revert)
    const fa = await j.h.call(j.diamond, '0x' + sel('facetAddress(bytes4)') + selW('0x' + sel('f1(uint256)')), {});
    expect(BigInt(fa.returnHex)).toBe(0n);
    // all 4 loupe returns byte-identical after the cross-slot remove
    for (const sig of ['facetAddresses()', 'facets()']) {
      const jc = await j.h.call(j.diamond, '0x' + sel(sig), {});
      const sc = await s.h.call(s.diamond, '0x' + sel(sig), {});
      expect(jc.returnHex).toBe(sc.returnHex);
    }
    const jffs = await j.h.call(j.diamond, '0x' + sel('facetFunctionSelectors(address)') + addrW(j.facetBig.toString()), {});
    const sffs = await s.h.call(s.diamond, '0x' + sel('facetFunctionSelectors(address)') + addrW(s.facetBig.toString()), {});
    expect(jffs.returnHex).toBe(sffs.returnHex);
  });

  it('Remove a whole facet (all selectors): facetAddresses dedupe shrinks identically', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    for (const env of [j, s]) {
      const big = env.facetBig.toString(),
        small = env.facetSmall.toString();
      await env.h.call(env.diamond, encodeDiamondCut([
        { facet: big, action: 0, selectors: selsOf(BIG9) },
        { facet: small, action: 0, selectors: selsOf(SMALL) },
      ], ZERO, '0x'), { caller: OWNER });
      // remove ALL of facetSmall's selectors (in slot1 tail) -> facetSmall disappears from the loupe
      const rm = await env.h.call(env.diamond, encodeDiamondCut([
        { facet: ZERO, action: 2, selectors: selsOf(SMALL) },
      ], ZERO, '0x'), { caller: OWNER });
      expect(rm.success).toBe(true);
    }
    expect(await readSlot(j.h, j.diamond, COUNT_SLOT)).toBe(await readSlot(s.h, s.diamond, COUNT_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, COUNT_SLOT))).toBe(9n);
    for (const sig of ['facetAddresses()', 'facets()']) {
      const jc = await j.h.call(j.diamond, '0x' + sel(sig), {});
      const sc = await s.h.call(s.diamond, '0x' + sel(sig), {});
      expect(jc.returnHex).toBe(sc.returnHex);
    }
    // facetSmall now empty
    const jffs = await j.h.call(j.diamond, '0x' + sel('facetFunctionSelectors(address)') + addrW(j.facetSmall.toString()), {});
    const sffs = await s.h.call(s.diamond, '0x' + sel('facetFunctionSelectors(address)') + addrW(s.facetSmall.toString()), {});
    expect(jffs.returnHex).toBe(sffs.returnHex);
  });

  it('DiamondCut event + owner gate + transferOwnership + _init delegatecall + not-found revert identical', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    const cut = (big: string) => [{ facet: big, action: 0, selectors: ['0x' + sel('f1(uint256)')] }];
    const jr = await j.h.call(j.diamond, encodeDiamondCut(cut(j.facetBig.toString()), ZERO, '0x'), { caller: OWNER });
    const sr = await s.h.call(s.diamond, encodeDiamondCut(cut(s.facetBig.toString()), ZERO, '0x'), { caller: OWNER });
    // DiamondCut event: no indexed params -> topic0 + whole data blob byte-identical
    expect(jr.logs.length).toBe(1);
    expect(sr.logs.length).toBe(1);
    expect(jr.logs[0]!.topics[0]).toBe(sr.logs[0]!.topics[0]);
    expect(jr.logs[0]!.data).toBe(sr.logs[0]!.data);

    // owner gate: non-owner diamondCut reverts identically
    const jg = await j.h.call(j.diamond, encodeDiamondCut(cut(j.facetBig.toString()), ZERO, '0x'), { caller: STRANGER });
    const sg = await s.h.call(s.diamond, encodeDiamondCut(cut(s.facetBig.toString()), ZERO, '0x'), { caller: STRANGER });
    expect(jg.success).toBe(false);
    expect(sg.success).toBe(false);
    expect(jg.returnHex).toBe(sg.returnHex);

    // transferOwnership + OwnershipTransferred(old,new)
    const jt = await j.h.call(j.diamond, '0x' + sel('transferOwnership(address)') + addrW(STRANGER.toString()), { caller: OWNER });
    const st = await s.h.call(s.diamond, '0x' + sel('transferOwnership(address)') + addrW(STRANGER.toString()), { caller: OWNER });
    expect(jt.success).toBe(true);
    expect(st.success).toBe(true);
    expect(jt.logs[0]!.topics).toEqual(st.logs[0]!.topics);
    expect(jt.logs[0]!.topics[0]).toBe(OWNERSHIP_TRANSFERRED);
    expect(await readSlot(j.h, j.diamond, OWNER_SLOT)).toBe(await readSlot(s.h, s.diamond, OWNER_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, OWNER_SLOT))).toBe(BigInt(STRANGER.toString()));
  });

  it('_init delegatecall runs in the diamond context + "does not exist" revert identical', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    for (const env of [j, s]) {
      const initCalldata = '0x' + sel('init(uint256)') + w(77n);
      const r = await env.h.call(env.diamond, encodeDiamondCut(
        [{ facet: env.facetBig.toString(), action: 0, selectors: ['0x' + sel('f1(uint256)')] }],
        env.dinit.toString(),
        initCalldata,
      ), { caller: OWNER });
      expect(r.success).toBe(true);
    }
    const innerI = (keccakHex('app.init') - 1n + (1n << 256n)) % (1n << 256n);
    const INIT_SLOT = keccakHex(word32(innerI)) & ~0xffn;
    expect(BigInt(await readSlot(j.h, j.diamond, INIT_SLOT))).toBe(77n);
    expect(await readSlot(j.h, j.diamond, INIT_SLOT)).toBe(await readSlot(s.h, s.diamond, INIT_SLOT));

    const jn = await j.h.call(j.diamond, '0x' + sel('nope()'), {});
    const sn = await s.h.call(s.diamond, '0x' + sel('nope()'), {});
    expect(jn.success).toBe(false);
    expect(sn.success).toBe(false);
    expect(jn.returnHex).toBe(sn.returnHex);
  });
});

describe('diamond-packed: gates', () => {
  const codes = (src: string): string[] => {
    try {
      compile(src, { fileName: 'C.jeth' });
      return [];
    } catch (e: unknown) {
      return ((e as { diagnostics?: { code: string }[] }).diagnostics ?? []).map((d) => d.code);
    }
  };
  const accepts = (src: string) => {
    compile(src, { fileName: 'C.jeth' });
  };
  it('accepts @diamond(\'packed\')', () => {
    expect(() => accepts(`@diamond('packed') class D { constructor(o: address){ diamondInit(o); } }`)).not.toThrow();
  });
  it('rejects an unknown @diamond variant (JETH412)', () => {
    expect(codes(`@diamond('frozen') class D { constructor(o: address){ diamondInit(o); } }`)).toContain('JETH412');
  });
  it('rejects @diamond(\'packed\') storage/method/receive/fallback (JETH413)', () => {
    expect(codes(`@diamond('packed') class D { @state x: u256 = 0n; constructor(o: address){ diamondInit(o); } }`)).toContain('JETH413');
    expect(codes(`@diamond('packed') class D { @external f(): void {} constructor(o: address){ diamondInit(o); } }`)).toContain('JETH413');
  });
});
