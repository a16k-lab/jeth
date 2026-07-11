// Phase 3 (DIAMOND): `@diamond('array')` - an EIP-2535 diamond on the array-storing (diamond-1/3-hardhat)
// layout. JETH synthesizes the WHOLE surface (the diamond-3 namespaced storage struct, diamondCut +
// the four loupe fns + ERC-165 + ownership, the DiamondCut/OwnershipTransferred events) as ordinary
// contract members reusing the verified storage/function/event machinery, then emitRuntime adds the
// selector-routed delegatecall fallback (the router). The user writes only `@diamond('array') class D {
// constructor(owner) { diamondInit(owner); } }` plus separately-deployed `@facet`s.
//
// Byte-identity target: a hand-written solc 0.8.35 diamond with the IDENTICAL diamond-3 storage layout
// (base = keccak256("diamond.standard.diamond.storage")) and IN-DIAMOND loupe/cut/owner dispatch. We diff
// the OBSERVABLE output (returndata + raw DiamondStorage slots + logs + revert data), word-for-word, across:
// selector routing into a facet (writes the DIAMOND's storage), Add/Replace/Remove (the swap-and-pop ORDER
// is storage- and loupe-observable), all four loupe returns, facetAddress, ERC-165 supportsInterface,
// owner()/transferOwnership + OwnershipTransferred, the DiamondCut event, the owner gate, the _init
// delegatecall, and the "Diamond: Function does not exist" revert.
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

// A 32-byte big-endian word from a bigint (for keccak of a slot number).
const word32 = (v: bigint): Uint8Array => {
  const b = new Uint8Array(32);
  let x = ((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n);
  for (let i = 31; i >= 0; i--) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
};
// keccak256("diamond.standard.diamond.storage") - the raw diamond-3 base slot.
const DS_BASE = keccakHex('diamond.standard.diamond.storage');
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
  // FacetCut[] blob: [len] [offset table] [each FacetCut tuple]. Each FacetCut is dynamic (bytes4[] field).
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

// ---- the JETH diamond + facets ----------------------------------------------
const DIAMOND_JETH = `@diamond('array') class MyDiamond {
  constructor(owner: address) { diamondInit(owner); }
}`;

// FacetA: two functions writing namespaced storage. FacetB: two more. A shared selector for Replace.
// Uses the @facet decorator (the spec surface): an ordinary deployable contract, tagged, cut in separately.
const FACET_A_JETH = `@facet class FacetA {
  @storage('app.a') x: u256;
  setX(v: u256): External<void> { this.x = v; }
  get getX(): External<u256> { return this.x; }
}`;
const FACET_B_JETH = `@facet class FacetB {
  @storage('app.b') y: u256;
  setY(v: u256): External<void> { this.y = v; }
  get getY(): External<u256> { return this.y; }
  get getXviaB(): External<u256> { return 42n; }
}`;
// An initializer facet for the _init delegatecall: writes a namespaced flag.
const INIT_JETH = `class DInit {
  @storage('app.init') flag: u256;
  init(v: u256): External<void> { this.flag = v; }
  get flag_(): External<u256> { return this.flag; }
}`;

// ---- the solc diamond-3 mirror (IN-DIAMOND dispatch, identical layout) -------
const DIAMOND_SOL =
  SPDX +
  `
struct FacetAddressAndPosition { address facetAddress; uint96 functionSelectorPosition; }
struct FacetFunctionSelectors { bytes4[] functionSelectors; uint256 facetAddressPosition; }
struct DiamondStorage {
  mapping(bytes4 => FacetAddressAndPosition) selectorToFacetAndPosition;
  mapping(address => FacetFunctionSelectors) facetFunctionSelectors;
  address[] facetAddresses;
  mapping(bytes4 => bool) supportedInterfaces;
  address contractOwner;
}
struct Facet { address facetAddress; bytes4[] functionSelectors; }
struct FacetCut { address facetAddress; uint8 action; bytes4[] functionSelectors; }
contract Diamond {
  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
  event DiamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata);
  bytes32 constant DSP = keccak256("diamond.standard.diamond.storage");
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
  function facetAddresses() external view returns (address[] memory) { return ds().facetAddresses; }
  function facetAddress(bytes4 s) external view returns (address) { return ds().selectorToFacetAndPosition[s].facetAddress; }
  function facetFunctionSelectors(address f) external view returns (bytes4[] memory) { return ds().facetFunctionSelectors[f].functionSelectors; }
  function facets() external view returns (Facet[] memory facets_) {
    DiamondStorage storage d = ds();
    uint256 n = d.facetAddresses.length;
    facets_ = new Facet[](n);
    for (uint256 i; i < n; i++) {
      address a = d.facetAddresses[i];
      facets_[i].facetAddress = a;
      facets_[i].functionSelectors = d.facetFunctionSelectors[a].functionSelectors;
    }
  }
  function diamondCut(FacetCut[] calldata _diamondCut, address _init, bytes calldata _calldata) external {
    require(msg.sender == ds().contractOwner, "LibDiamond: Must be contract owner");
    for (uint256 i; i < _diamondCut.length; i++) {
      uint8 act = _diamondCut[i].action;
      if (act == 0) addF(_diamondCut[i].facetAddress, _diamondCut[i].functionSelectors);
      else if (act == 1) repF(_diamondCut[i].facetAddress, _diamondCut[i].functionSelectors);
      else if (act == 2) remF(_diamondCut[i].facetAddress, _diamondCut[i].functionSelectors);
      else revert("LibDiamondCut: Incorrect FacetCutAction");
    }
    emit DiamondCut(_diamondCut, _init, _calldata);
    initD(_init, _calldata);
  }
  function addF(address facet, bytes4[] calldata sels) internal {
    require(sels.length > 0, "LibDiamondCut: No selectors in facet to cut");
    require(facet != address(0), "LibDiamondCut: Add facet can't be address(0)");
    DiamondStorage storage d = ds();
    uint96 sp = uint96(d.facetFunctionSelectors[facet].functionSelectors.length);
    if (sp == 0) addFacet(d, facet);
    for (uint256 i; i < sels.length; i++) {
      bytes4 s = sels[i];
      require(d.selectorToFacetAndPosition[s].facetAddress == address(0), "LibDiamondCut: Can't add function that already exists");
      addFunc(d, s, sp, facet); sp++;
    }
  }
  function repF(address facet, bytes4[] calldata sels) internal {
    require(sels.length > 0, "LibDiamondCut: No selectors in facet to cut");
    require(facet != address(0), "LibDiamondCut: Add facet can't be address(0)");
    DiamondStorage storage d = ds();
    uint96 sp = uint96(d.facetFunctionSelectors[facet].functionSelectors.length);
    if (sp == 0) addFacet(d, facet);
    for (uint256 i; i < sels.length; i++) {
      bytes4 s = sels[i];
      address old = d.selectorToFacetAndPosition[s].facetAddress;
      require(old != facet, "LibDiamondCut: Can't replace function with same function");
      require(old != address(0), "LibDiamondCut: Can't replace function that doesn't exist");
      require(old != address(this), "LibDiamondCut: Can't replace immutable function");
      removeFunc(d, old, s); addFunc(d, s, sp, facet); sp++;
    }
  }
  function remF(address facet, bytes4[] calldata sels) internal {
    require(sels.length > 0, "LibDiamondCut: No selectors in facet to cut");
    require(facet == address(0), "LibDiamondCut: Remove facet address must be address(0)");
    DiamondStorage storage d = ds();
    for (uint256 i; i < sels.length; i++) {
      bytes4 s = sels[i];
      removeFunc(d, d.selectorToFacetAndPosition[s].facetAddress, s);
    }
  }
  function addFacet(DiamondStorage storage d, address facet) internal {
    require(facet.code.length > 0, "LibDiamondCut: New facet has no code");
    d.facetFunctionSelectors[facet].facetAddressPosition = d.facetAddresses.length;
    d.facetAddresses.push(facet);
  }
  function addFunc(DiamondStorage storage d, bytes4 s, uint96 sp, address facet) internal {
    d.selectorToFacetAndPosition[s].functionSelectorPosition = sp;
    d.facetFunctionSelectors[facet].functionSelectors.push(s);
    d.selectorToFacetAndPosition[s].facetAddress = facet;
  }
  function removeFunc(DiamondStorage storage d, address facet, bytes4 s) internal {
    require(facet != address(0), "LibDiamondCut: Can't remove function that doesn't exist");
    require(facet != address(this), "LibDiamondCut: Can't remove immutable function");
    uint256 sp = d.selectorToFacetAndPosition[s].functionSelectorPosition;
    uint256 lastSp = d.facetFunctionSelectors[facet].functionSelectors.length - 1;
    if (sp != lastSp) {
      bytes4 last = d.facetFunctionSelectors[facet].functionSelectors[lastSp];
      d.facetFunctionSelectors[facet].functionSelectors[sp] = last;
      d.selectorToFacetAndPosition[last].functionSelectorPosition = uint96(sp);
    }
    d.facetFunctionSelectors[facet].functionSelectors.pop();
    delete d.selectorToFacetAndPosition[s];
    if (lastSp == 0) {
      uint256 lastFap = d.facetAddresses.length - 1;
      uint256 fap = d.facetFunctionSelectors[facet].facetAddressPosition;
      if (fap != lastFap) {
        address lastFa = d.facetAddresses[lastFap];
        d.facetAddresses[fap] = lastFa;
        d.facetFunctionSelectors[lastFa].facetAddressPosition = fap;
      }
      d.facetAddresses.pop();
      delete d.facetFunctionSelectors[facet].facetAddressPosition;
    }
  }
  function initD(address _init, bytes memory _calldata) internal {
    if (_init == address(0)) return;
    require(_init.code.length > 0, "LibDiamondCut: _init address has no code");
    (bool ok, bytes memory err) = _init.delegatecall(_calldata);
    if (!ok) { if (err.length > 0) { assembly { revert(add(32, err), mload(err)) } } else revert("init failed"); }
  }
  fallback() external payable {
    DiamondStorage storage d;
    bytes32 p = DSP; assembly { d.slot := p }
    address facet = d.selectorToFacetAndPosition[msg.sig].facetAddress;
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
// The solc facet mirrors (must write the SAME namespaced slots as the JETH facets). solc ERC-7201.
const FACET_A_SOL =
  SPDX +
  `
contract FacetA {
  bytes32 constant S = keccak256(abi.encode(uint256(keccak256(bytes("app.a"))) - 1)) & ~bytes32(uint256(0xff));
  struct St { uint256 x; }
  function s() internal pure returns (St storage st) { bytes32 p = S; assembly { st.slot := p } }
  function setX(uint256 v) external { s().x = v; }
  function getX() external view returns (uint256) { return s().x; }
}`;
const FACET_B_SOL =
  SPDX +
  `
contract FacetB {
  bytes32 constant S = keccak256(abi.encode(uint256(keccak256(bytes("app.b"))) - 1)) & ~bytes32(uint256(0xff));
  struct St { uint256 y; }
  function s() internal pure returns (St storage st) { bytes32 p = S; assembly { st.slot := p } }
  function setY(uint256 v) external { s().y = v; }
  function getY() external view returns (uint256) { return s().y; }
  function getXviaB() external pure returns (uint256) { return 42; }
}`;
const INIT_SOL =
  SPDX +
  `
contract DInit {
  bytes32 constant S = keccak256(abi.encode(uint256(keccak256(bytes("app.init"))) - 1)) & ~bytes32(uint256(0xff));
  struct St { uint256 flag; }
  function s() internal pure returns (St storage st) { bytes32 p = S; assembly { st.slot := p } }
  function init(uint256 v) external { s().flag = v; }
  function flag_() external view returns (uint256) { return s().flag; }
}`;

// Deploy helpers: a JETH world and a solc world, each with the diamond + the three facets.
async function deployJeth() {
  const h = await Harness.create();
  const facetA = await h.deploy(compile(FACET_A_JETH, { fileName: 'A.jeth' }).creationBytecode);
  const facetB = await h.deploy(compile(FACET_B_JETH, { fileName: 'B.jeth' }).creationBytecode);
  const dinit = await h.deploy(compile(INIT_JETH, { fileName: 'I.jeth' }).creationBytecode);
  const dc = compile(DIAMOND_JETH, { fileName: 'D.jeth' });
  const diamond = await h.deploy(dc.creationBytecode + pad32(BigInt(OWNER.toString())), { caller: OWNER });
  return { h, diamond, facetA, facetB, dinit };
}
async function deploySol() {
  const h = await Harness.create();
  const facetA = await h.deploy(compileSolidity(FACET_A_SOL, 'FacetA').creation);
  const facetB = await h.deploy(compileSolidity(FACET_B_SOL, 'FacetB').creation);
  const dinit = await h.deploy(compileSolidity(INIT_SOL, 'DInit').creation);
  const diamond = await h.deploy(compileSolidity(DIAMOND_SOL, 'Diamond').creation + pad32(BigInt(OWNER.toString())), {
    caller: OWNER,
  });
  return { h, diamond, facetA, facetB, dinit };
}

// Read N consecutive raw DiamondStorage-related slots into a hex array.
async function dumpSlots(h: Harness, addr: Address, slots: bigint[]): Promise<string[]> {
  const out: string[] = [];
  for (const s of slots) out.push(await readSlot(h, addr, s));
  return out;
}

// The observable DiamondStorage anchor slots + derived array data slots. base+2 = facetAddresses[] length;
// its data lives at keccak256(base+2). base+4 = contractOwner. We diff these directly.
const FA_LEN_SLOT = DS_BASE + 2n;
const OWNER_SLOT = DS_BASE + 4n;
function arrDataSlot(lenSlot: bigint): bigint {
  return keccakHex(word32(lenSlot));
}
// solc mapping(K=>V) element slot = keccak256(key . mappingBaseSlot). For an address key the key word is
// right-aligned (the address). Returns the struct's base slot (its field 0).
function mapStructSlot(mapBase: bigint, addr: string): bigint {
  const keyWord = word32(BigInt(addr));
  const baseWord = word32(mapBase);
  const buf = new Uint8Array(64);
  buf.set(keyWord, 0);
  buf.set(baseWord, 32);
  return keccakHex(buf);
}

describe('diamond-array: byte-identity vs a solc diamond-3 mirror', () => {
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
      const un = await env.h.call(
        env.diamond,
        '0x' + sel('supportsInterface(bytes4)') + 'deadbeef'.padEnd(64, '0'),
        {},
      );
      expect(BigInt(un.returnHex)).toBe(0n);
    }
    // raw owner slot identical
    expect(await readSlot(j.h, j.diamond, OWNER_SLOT)).toBe(await readSlot(s.h, s.diamond, OWNER_SLOT));
    expect(BigInt(await readSlot(j.h, j.diamond, OWNER_SLOT))).toBe(BigInt(OWNER.toString()));
  });

  it('Add: routing + raw facetAddresses[] slots + all loupe returns identical', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    const cut = (facetA: string, facetB: string) => [
      { facet: facetA, action: 0, selectors: ['0x' + sel('setX(uint256)'), '0x' + sel('getX()')] },
      {
        facet: facetB,
        action: 0,
        selectors: ['0x' + sel('setY(uint256)'), '0x' + sel('getY()'), '0x' + sel('getXviaB()')],
      },
    ];
    const jr = await j.h.call(j.diamond, encodeDiamondCut(cut(j.facetA.toString(), j.facetB.toString()), ZERO, '0x'), {
      caller: OWNER,
    });
    const sr = await s.h.call(s.diamond, encodeDiamondCut(cut(s.facetA.toString(), s.facetB.toString()), ZERO, '0x'), {
      caller: OWNER,
    });
    expect(jr.success).toBe(true);
    expect(sr.success).toBe(true);

    // route setX(7) + getX() through the diamond -> writes the DIAMOND's storage (app.a slot)
    for (const env of [j, s]) {
      const setX = await env.h.call(env.diamond, '0x' + sel('setX(uint256)') + w(7n), { caller: OWNER });
      expect(setX.success).toBe(true);
      const getX = await env.h.call(env.diamond, '0x' + sel('getX()'), {});
      expect(BigInt(getX.returnHex)).toBe(7n);
    }

    // RAW DiamondStorage slots: both worlds deploy 3 facets + the diamond in the SAME order from the same
    // default caller, so the CREATE addresses are identical -> the raw facetAddresses[] length + each data
    // word + the contractOwner slot must be byte-identical (the swap-and-pop INSERTION ORDER is observable).
    expect(j.facetA.toString()).toBe(s.facetA.toString()); // deterministic CREATE -> identical addresses
    expect(j.facetB.toString()).toBe(s.facetB.toString());
    expect(await readSlot(j.h, j.diamond, FA_LEN_SLOT)).toBe(await readSlot(s.h, s.diamond, FA_LEN_SLOT));
    const dataSlot = arrDataSlot(FA_LEN_SLOT);
    for (let i = 0n; i < 2n; i++) {
      const jw = await readSlot(j.h, j.diamond, dataSlot + i);
      const sw = await readSlot(s.h, s.diamond, dataSlot + i);
      expect(jw).toBe(sw); // facetAddresses[i] raw slot identical
    }
    // each facet's FacetFunctionSelectors struct slot (facetAddressPosition + the bytes4[] length word) raw-identical
    for (const facet of [j.facetA.toString(), j.facetB.toString()]) {
      const structSlot = mapStructSlot(DS_BASE + 1n, facet); // facetFunctionSelectors[facet]
      const jStruct = await readSlot(j.h, j.diamond, structSlot); // bytes4[] length (field 0)
      const sStruct = await readSlot(s.h, s.diamond, structSlot);
      expect(jStruct).toBe(sStruct);
      const jPos = await readSlot(j.h, j.diamond, structSlot + 1n); // facetAddressPosition (field 1)
      const sPos = await readSlot(s.h, s.diamond, structSlot + 1n);
      expect(jPos).toBe(sPos);
    }

    // facetAddresses() returndata SHAPE identical (len=2); facetAddress(selector) routes; loupe returns shape
    for (const env of [j, s]) {
      const fas = await env.h.call(env.diamond, '0x' + sel('facetAddresses()'), {});
      expect(fas.success).toBe(true);
      // [offset][len=2][addrA][addrB]
      expect(BigInt('0x' + fas.returnHex.slice(2 + 64, 2 + 128))).toBe(2n);
    }
    // facetAddress(setX) == facetA (each world's own facetA)
    const jfa = await j.h.call(j.diamond, '0x' + sel('facetAddress(bytes4)') + selW('0x' + sel('setX(uint256)')), {});
    expect(BigInt(jfa.returnHex)).toBe(BigInt(j.facetA.toString()));
    const sfa = await s.h.call(s.diamond, '0x' + sel('facetAddress(bytes4)') + selW('0x' + sel('setX(uint256)')), {});
    expect(BigInt(sfa.returnHex)).toBe(BigInt(s.facetA.toString()));

    // facetFunctionSelectors(facetB) returndata IDENTICAL (selectors are address-independent)
    const jffs = await j.h.call(
      j.diamond,
      '0x' + sel('facetFunctionSelectors(address)') + addrW(j.facetB.toString()),
      {},
    );
    const sffs = await s.h.call(
      s.diamond,
      '0x' + sel('facetFunctionSelectors(address)') + addrW(s.facetB.toString()),
      {},
    );
    expect(jffs.returnHex).toBe(sffs.returnHex);

    // facets() : the dynamic-array-of-dynamic-tuples encoding. With identical facet addresses across
    // worlds, the WHOLE returndata blob must be byte-identical (head offsets + address words + bytes4[] tails).
    const jf = await j.h.call(j.diamond, '0x' + sel('facets()'), {});
    const sf = await s.h.call(s.diamond, '0x' + sel('facets()'), {});
    expect(jf.success).toBe(true);
    expect(sf.success).toBe(true);
    expect(jf.returnHex).toBe(sf.returnHex);
  });

  it('Replace: swap a selector to another facet; loupe + raw slots reflect it identically', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    for (const env of [j, s]) {
      const A = env.facetA.toString(),
        B = env.facetB.toString();
      await env.h.call(
        env.diamond,
        encodeDiamondCut(
          [
            { facet: A, action: 0, selectors: ['0x' + sel('setX(uint256)'), '0x' + sel('getX()')] },
            { facet: B, action: 0, selectors: ['0x' + sel('getXviaB()')] },
          ],
          ZERO,
          '0x',
        ),
        { caller: OWNER },
      );
      // Replace getX() to be served by facetB? facetB has no getX; replace getXviaB onto facetA instead.
      const rep = await env.h.call(
        env.diamond,
        encodeDiamondCut([{ facet: A, action: 1, selectors: ['0x' + sel('getXviaB()')] }], ZERO, '0x'),
        { caller: OWNER },
      );
      expect(rep.success).toBe(true);
    }
    // facetAddress(getXviaB) now == facetA in both
    const jr = await j.h.call(j.diamond, '0x' + sel('facetAddress(bytes4)') + selW('0x' + sel('getXviaB()')), {});
    expect(BigInt(jr.returnHex)).toBe(BigInt(j.facetA.toString()));
    // facetB's selector list (now empty -> facet removed) loupe IDENTICAL
    const jffsB = await j.h.call(
      j.diamond,
      '0x' + sel('facetFunctionSelectors(address)') + addrW(j.facetB.toString()),
      {},
    );
    const sffsB = await s.h.call(
      s.diamond,
      '0x' + sel('facetFunctionSelectors(address)') + addrW(s.facetB.toString()),
      {},
    );
    expect(jffsB.returnHex).toBe(sffsB.returnHex);
    // facetAddresses() length (facetB swap-popped out) identical
    expect(await readSlot(j.h, j.diamond, FA_LEN_SLOT)).toBe(await readSlot(s.h, s.diamond, FA_LEN_SLOT));
  });

  it('Remove: swap-and-pop order is observable + identical', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    for (const env of [j, s]) {
      const A = env.facetA.toString(),
        B = env.facetB.toString();
      await env.h.call(
        env.diamond,
        encodeDiamondCut(
          [
            { facet: A, action: 0, selectors: ['0x' + sel('setX(uint256)'), '0x' + sel('getX()')] },
            {
              facet: B,
              action: 0,
              selectors: ['0x' + sel('setY(uint256)'), '0x' + sel('getY()'), '0x' + sel('getXviaB()')],
            },
          ],
          ZERO,
          '0x',
        ),
        { caller: OWNER },
      );
      // remove the FIRST selector of facetA (setX) -> swap-and-pop within facetA's bytes4[]; getX moves
      const rm = await env.h.call(
        env.diamond,
        encodeDiamondCut([{ facet: ZERO, action: 2, selectors: ['0x' + sel('setX(uint256)')] }], ZERO, '0x'),
        { caller: OWNER },
      );
      expect(rm.success).toBe(true);
    }
    // facetFunctionSelectors(facetA) after the swap-and-pop: [getX] (setX was popped, getX stays). IDENTICAL.
    const jffs = await j.h.call(
      j.diamond,
      '0x' + sel('facetFunctionSelectors(address)') + addrW(j.facetA.toString()),
      {},
    );
    const sffs = await s.h.call(
      s.diamond,
      '0x' + sel('facetFunctionSelectors(address)') + addrW(s.facetA.toString()),
      {},
    );
    expect(jffs.returnHex).toBe(sffs.returnHex);
    // setX now routes to "does not exist"
    const gone = await j.h.call(j.diamond, '0x' + sel('setX(uint256)') + w(1n), { caller: OWNER });
    expect(gone.success).toBe(false);
    // facetAddress(setX) == 0 (no revert)
    const fa = await j.h.call(j.diamond, '0x' + sel('facetAddress(bytes4)') + selW('0x' + sel('setX(uint256)')), {});
    expect(BigInt(fa.returnHex)).toBe(0n);
    // raw facetAddresses[] length identical
    expect(await readSlot(j.h, j.diamond, FA_LEN_SLOT)).toBe(await readSlot(s.h, s.diamond, FA_LEN_SLOT));
  });

  it('DiamondCut event topic + data, owner gate revert, transferOwnership + event', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    const cut = (A: string) => [{ facet: A, action: 0, selectors: ['0x' + sel('getX()')] }];
    const jr = await j.h.call(j.diamond, encodeDiamondCut(cut(j.facetA.toString()), ZERO, '0x'), { caller: OWNER });
    const sr = await s.h.call(s.diamond, encodeDiamondCut(cut(s.facetA.toString()), ZERO, '0x'), { caller: OWNER });
    // DiamondCut event: no indexed params -> 1 topic (topic0). With identical facet addresses, the FULL
    // topic0 + the whole data blob (the FacetCut[] aggregate + _init + _calldata) is byte-identical.
    expect(jr.logs.length).toBe(1);
    expect(sr.logs.length).toBe(1);
    expect(jr.logs[0]!.topics[0]).toBe(sr.logs[0]!.topics[0]); // topic0 identical
    expect(jr.logs[0]!.data).toBe(sr.logs[0]!.data); // whole non-indexed data blob byte-identical

    // owner gate: a non-owner diamondCut reverts identically
    const jg = await j.h.call(j.diamond, encodeDiamondCut(cut(j.facetA.toString()), ZERO, '0x'), { caller: STRANGER });
    const sg = await s.h.call(s.diamond, encodeDiamondCut(cut(s.facetA.toString()), ZERO, '0x'), { caller: STRANGER });
    expect(jg.success).toBe(false);
    expect(sg.success).toBe(false);
    expect(jg.returnHex).toBe(sg.returnHex); // Error("LibDiamond: Must be contract owner")

    // transferOwnership + OwnershipTransferred(old,new)
    const jt = await j.h.call(j.diamond, '0x' + sel('transferOwnership(address)') + addrW(STRANGER.toString()), {
      caller: OWNER,
    });
    const st = await s.h.call(s.diamond, '0x' + sel('transferOwnership(address)') + addrW(STRANGER.toString()), {
      caller: OWNER,
    });
    expect(jt.success).toBe(true);
    expect(st.success).toBe(true);
    expect(jt.logs[0]!.topics).toEqual(st.logs[0]!.topics); // both args indexed -> topic0,old,new identical
    expect(jt.logs[0]!.topics[0]).toBe(OWNERSHIP_TRANSFERRED);
    // raw owner slot updated identically
    expect(BigInt(await readSlot(j.h, j.diamond, OWNER_SLOT))).toBe(BigInt(STRANGER.toString()));
    expect(await readSlot(j.h, j.diamond, OWNER_SLOT)).toBe(await readSlot(s.h, s.diamond, OWNER_SLOT));
  });

  it('_init delegatecall runs in the diamond context + "does not exist" revert identical', async () => {
    const j = await deployJeth();
    const s = await deploySol();
    // diamondCut with _init = DInit + calldata init(99): runs DInit.init via delegatecall -> writes the
    // DIAMOND's app.init storage. Then read it back via a routed flag_().
    for (const env of [j, s]) {
      const initCalldata = '0x' + sel('init(uint256)') + w(99n);
      const r = await env.h.call(
        env.diamond,
        encodeDiamondCut(
          [{ facet: env.facetA.toString(), action: 0, selectors: ['0x' + sel('getX()')] }],
          env.dinit.toString(),
          initCalldata,
        ),
        { caller: OWNER },
      );
      expect(r.success).toBe(true);
    }
    // the app.init namespaced slot in the DIAMOND is now 99 in both worlds (raw slot identical). app.init's
    // ERC-7201 base = keccak(word32(keccak("app.init") - 1)) & ~0xff; the flag field is at base + 0.
    const inner = (keccakHex('app.init') - 1n + (1n << 256n)) % (1n << 256n);
    const INIT_SLOT = keccakHex(word32(inner)) & ~0xffn;
    expect(BigInt(await readSlot(j.h, j.diamond, INIT_SLOT))).toBe(99n);
    expect(await readSlot(j.h, j.diamond, INIT_SLOT)).toBe(await readSlot(s.h, s.diamond, INIT_SLOT));

    // "Diamond: Function does not exist" revert (Error(string)) IDENTICAL
    const jn = await j.h.call(j.diamond, '0x' + sel('nope()'), {});
    const sn = await s.h.call(s.diamond, '0x' + sel('nope()'), {});
    expect(jn.success).toBe(false);
    expect(sn.success).toBe(false);
    expect(jn.returnHex).toBe(sn.returnHex);
  });
});

describe('diamond-array: gates + facet surface (clean diagnostics)', () => {
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

  it('rejects @diamond storage/method/receive/fallback (JETH413)', () => {
    expect(
      codes(`@diamond('array') class D { @state x: u256 = 0n; constructor(o: address){ diamondInit(o); } }`),
    ).toContain('JETH413');
    expect(
      codes(`@diamond('array') class D { @external f(): void {} constructor(o: address){ diamondInit(o); } }`),
    ).toContain('JETH413');
    expect(
      codes(`@diamond('array') class D { @receive r(): void {} constructor(o: address){ diamondInit(o); } }`),
    ).toContain('JETH413');
    expect(
      codes(`@diamond('array') class D { @fallback f(): void {} constructor(o: address){ diamondInit(o); } }`),
    ).toContain('JETH413');
  });
  it('rejects a bad @diamond variant (JETH412)', () => {
    // 'packed' is now a SUPPORTED model (the diamond-2 layout, test/diamond-packed.test.ts); use a
    // genuinely-unknown variant to exercise the JETH412 unknown-model rejection.
    expect(codes(`@diamond('frozen') class D { constructor(o: address){ diamondInit(o); } }`)).toContain('JETH412');
  });
  it('rejects @facet + @diamond on one class (JETH411)', () => {
    expect(codes(`@facet @diamond('array') class D { constructor(o: address){ diamondInit(o); } }`)).toContain(
      'JETH411',
    );
  });
  it('rejects diamondInit / the reserved builtins outside a @diamond (JETH414)', () => {
    expect(codes(`class C { f(): External<void> { diamondInit(address(0n)); } }`)).toContain('JETH414');
    expect(codes(`class C { get f(): External<u256> { return __diamondFacets().length; } }`)).toContain(
      'JETH414',
    );
  });
  it('accepts @diamond with array / () / bare, and a plain @facet contract', () => {
    expect(() => accepts(`@diamond('array') class D { constructor(o: address){ diamondInit(o); } }`)).not.toThrow();
    expect(() => accepts(`@diamond() class D { constructor(o: address){ diamondInit(o); } }`)).not.toThrow();
    expect(() => accepts(`@diamond class D { constructor(o: address){ diamondInit(o); } }`)).not.toThrow();
    expect(() =>
      accepts(
        `@facet class F { @storage('app') x: u256; set(v: u256): External<void> { this.x = v; } get get(): External<u256> { return this.x; } }`,
      ),
    ).not.toThrow();
  });
});
