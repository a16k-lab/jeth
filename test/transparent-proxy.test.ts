// Phase 2b: the TRANSPARENT proxy variant `@proxy('transparent')` (byte-identical to OZ
// TransparentUpgradeableProxy 5.x). The synthesized fallback routes by CALLER:
//   - caller() == admin: the call MUST be upgradeToAndCall(address,bytes) (selector 0x4f1ef286); decode
//     (newImpl, data), run the EIP-1967 upgrade (isContract guard, sstore impl slot, emit Upgraded,
//     if data.length>0 delegatecall + bubble), return empty. ANY OTHER admin selector reverts
//     ProxyDeniedAdminAccess() (selector 0xd2b576ec).
//   - caller() != admin: delegate to the impl - EVEN a upgradeToAndCall selector (this defeats the
//     selector clash; a non-admin's upgradeToAndCall runs in the impl, or reverts via the impl).
// A @proxy('transparent') exposes NO own functions to non-admins (the user writes only the constructor;
// @external methods are rejected). We deploy a JETH transparent proxy + V1/V2 impls and a hand-written
// solc TransparentUpgradeableProxy-equivalent + impls, then diff returndata + the proxy's STORAGE + the
// Upgraded event + revert across the admin/non-admin routing.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { Address, hexToBytes, bytesToHex } from '@ethereumjs/util';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);
const strip = (h: string) => (h.startsWith('0x') ? h.slice(2) : h);

// EIP-1967 fixed slots + the OZ transparent-proxy selectors.
const IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbcn;
const ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103n;
const UPGRADED_TOPIC = '0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b';
const UPGRADE_TO_AND_CALL = sel('upgradeToAndCall(address,bytes)'); // 4f1ef286
const PROXY_DENIED = sel('ProxyDeniedAdminAccess()'); // d2b576ec

const ADMIN = new Address(hexToBytes('0x00000000000000000000000000000000000000aa'));
const STRANGER = new Address(hexToBytes('0x00000000000000000000000000000000000000bb'));

function jethAccepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
const jethRejects = (src: string) => !jethAccepts(src);
function jethCodes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    const diags = (e as { diagnostics?: { code: string }[] }).diagnostics ?? [];
    return diags.map((d) => d.code);
  }
}

// ---- V1 / V2 implementations (normal JETH @contracts with an exact solc mirror). slot0 = value,
// slot1 = initialized. initialize(x) sets both ONCE; V1.value_() returns value; V2.value_() returns
// value*2; both have bump(). V2 ALSO declares upgradeToAndCall(address,bytes) (selector 0x4f1ef286) so
// we can prove a NON-admin's upgradeToAndCall delegates INTO the impl (the clash-defeat). ----
const V1_JETH = `@contract class V1 {
  @state value: u256 = 0n;
  @state initialized: bool = false;
  @external initialize(x: u256): void {
    require(!this.initialized, "init");
    this.initialized = true;
    this.value = x;
  }
  @external bump(): void { this.value = this.value + 1n; }
  @external @view value_(): u256 { return this.value; }
  @external @view version(): u256 { return 1n; }
}`;
const V1_SOL = `contract V1 {
  uint256 value;
  bool initialized;
  function initialize(uint256 x) external { require(!initialized, "init"); initialized = true; value = x; }
  function bump() external { value = value + 1; }
  function value_() external view returns (uint256) { return value; }
  function version() external view returns (uint256) { return 1; }
}`;

// V2 also exposes a function whose selector EQUALS upgradeToAndCall(address,bytes) so a non-admin call
// to that selector, delegated into the impl, returns a sentinel (proves the clash-defeat reaches V2).
const V2_JETH = `@contract class V2 {
  @state value: u256 = 0n;
  @state initialized: bool = false;
  @external initialize(x: u256): void {
    require(!this.initialized, "init");
    this.initialized = true;
    this.value = x;
  }
  @external bump(): void { this.value = this.value + 1n; }
  @external @view value_(): u256 { return this.value * 2n; }
  @external @view version(): u256 { return 2n; }
  @external upgradeToAndCall(newImpl: address, data: bytes): u256 { return 0xC1A54n; }
}`;
const V2_SOL = `contract V2 {
  uint256 value;
  bool initialized;
  function initialize(uint256 x) external { require(!initialized, "init"); initialized = true; value = x; }
  function bump() external { value = value + 1; }
  function value_() external view returns (uint256) { return value * 2; }
  function version() external view returns (uint256) { return 2; }
  function upgradeToAndCall(address newImpl, bytes calldata data) external pure returns (uint256) { return 0xC1A54; }
}`;

// ---- The JETH transparent proxy: ONLY a constructor (proxyInit with an admin). No @external methods. ----
const INIT_SEL = sel('initialize(uint256)');
const PROXY_JETH = `@proxy('transparent') class P {
  constructor(impl: address, admin: address, initVal: u256) {
    proxyInit(impl, admin, abi.encodeWithSelector(0x${INIT_SEL}n, initVal));
  }
}`;

// ---- The hand-written solc TransparentUpgradeableProxy-equivalent (OZ 5.x behaviour): the fallback
// routes by caller; admin may ONLY call upgradeToAndCall else ProxyDeniedAdminAccess(); non-admin
// delegates. Constructor: proxyInit(impl, admin, initData). ----
const PROXY_SOL = `contract P {
  bytes32 constant IMPL = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
  bytes32 constant ADMIN = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
  event Upgraded(address indexed implementation);
  error ProxyDeniedAdminAccess();
  constructor(address impl, address admin_, bytes memory initData) {
    require(impl.code.length > 0);
    assembly { sstore(ADMIN, admin_) }
    assembly { sstore(IMPL, impl) }
    emit Upgraded(impl);
    if (initData.length > 0) {
      (bool ok, ) = impl.delegatecall(initData);
      if (!ok) { assembly { returndatacopy(0, 0, returndatasize()) revert(0, returndatasize()) } }
    }
  }
  function _upgrade(address newImpl, bytes memory data) private {
    require(newImpl.code.length > 0);
    assembly { sstore(IMPL, newImpl) }
    emit Upgraded(newImpl);
    if (data.length > 0) {
      (bool ok, ) = newImpl.delegatecall(data);
      if (!ok) { assembly { returndatacopy(0, 0, returndatasize()) revert(0, returndatasize()) } }
    }
  }
  fallback() external payable {
    address a; assembly { a := sload(ADMIN) }
    if (msg.sender == a) {
      if (msg.sig != bytes4(0x4f1ef286)) revert ProxyDeniedAdminAccess();
      (address newImpl, bytes memory data) = abi.decode(msg.data[4:], (address, bytes));
      _upgrade(newImpl, data);
      return;
    }
    assembly {
      let impl := sload(IMPL)
      calldatacopy(0, 0, calldatasize())
      let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
      returndatacopy(0, 0, returndatasize())
      switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
    }
  }
}`;

function solCtorArgs(impl: Address, admin: Address, initData: string): string {
  const id = strip(initData);
  const len = id.length / 2;
  const padded = id + '0'.repeat((64 - (id.length % 64)) % 64);
  return W(BigInt(impl.toString())) + W(BigInt(admin.toString())) + W(0x60n) + W(BigInt(len)) + padded;
}
function jethCtorArgs(impl: Address, admin: Address, initVal: bigint): string {
  return W(BigInt(impl.toString())) + W(BigInt(admin.toString())) + W(initVal);
}
const initData = (val: bigint) => '0x' + INIT_SEL + W(val);

/** upgradeToAndCall(address,bytes) calldata with arbitrary data bytes (default empty). */
function upgradeCall(newImpl: Address, data = '0x'): string {
  const d = strip(data);
  const dlen = d.length / 2;
  const dpad = d + '0'.repeat((64 - (d.length % 64)) % 64);
  return '0x' + UPGRADE_TO_AND_CALL + W(BigInt(newImpl.toString())) + W(0x40n) + W(BigInt(dlen)) + dpad;
}

async function setup(initVal: bigint) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const v1j = await hj.deploy(compile(V1_JETH, { fileName: 'V1.jeth' }).creationBytecode);
  const v2j = await hj.deploy(compile(V2_JETH, { fileName: 'V2.jeth' }).creationBytecode);
  const v1s = await hs.deploy(compileSolidity(SPDX + V1_SOL, 'V1').creation);
  const v2s = await hs.deploy(compileSolidity(SPDX + V2_SOL, 'V2').creation);
  const pjBuild = compile(PROXY_JETH, { fileName: 'P.jeth' });
  const psBuild = compileSolidity(SPDX + PROXY_SOL, 'P');
  const pj = await hj.deploy(pjBuild.creationBytecode + jethCtorArgs(v1j, ADMIN, initVal));
  const ps = await hs.deploy(psBuild.creation + solCtorArgs(v1s, ADMIN, initData(initVal)));
  return { hj, hs, v1j, v2j, v1s, v2s, pj, ps };
}

function addrFromWord(returnHex: string): Address {
  const h = strip(returnHex);
  return new Address(hexToBytes(('0x' + h.slice(24, 64)) as `0x${string}`));
}

describe('transparent-proxy (Phase 2b)', () => {
  it('(1) a NON-admin call to an impl function delegates and writes the PROXY storage (== solc)', async () => {
    const { hj, hs, v1j, v1s, pj, ps } = await setup(7n);
    const rj = await hj.call(pj, '0x' + sel('value_()'), { caller: STRANGER });
    const rs = await hs.call(ps, '0x' + sel('value_()'), { caller: STRANGER });
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(BigInt(rj.returnHex)).toBe(7n);
    // a state-writing non-admin call writes the PROXY's slot0
    await hj.call(pj, '0x' + sel('bump()'), { caller: STRANGER });
    await hs.call(ps, '0x' + sel('bump()'), { caller: STRANGER });
    expect(await readSlot(hj, pj, 0n)).toBe(await readSlot(hs, ps, 0n));
    expect(BigInt(await readSlot(hj, pj, 0n))).toBe(8n);
    // the impl's OWN storage stays untouched
    expect(BigInt(await readSlot(hj, v1j, 0n))).toBe(0n);
    expect(BigInt(await readSlot(hs, v1s, 0n))).toBe(0n);
  });

  it('(2) a NON-admin upgradeToAndCall selector STILL delegates to the impl (the clash defeat == solc)', async () => {
    // Upgrade to V2 first (V2 declares upgradeToAndCall returning a sentinel). Then a NON-admin call with
    // the upgradeToAndCall selector must delegate INTO V2 and return the sentinel - NOT run the proxy
    // upgrade. (The proxy upgrade path is admin-only.)
    const { hj, hs, v2j, v2s, pj, ps } = await setup(3n);
    // admin upgrades to V2 (no data)
    await hj.call(pj, upgradeCall(v2j), { caller: ADMIN });
    await hs.call(ps, upgradeCall(v2s), { caller: ADMIN });
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString()).toBe(v2j.toString());
    // a NON-admin upgradeToAndCall(<anything>): delegates to V2.upgradeToAndCall -> sentinel 0xC1A54
    const probe = upgradeCall(v2j); // payload is irrelevant; it hits V2's function selector
    const probeS = upgradeCall(v2s);
    const rj = await hj.call(pj, probe, { caller: STRANGER });
    const rs = await hs.call(ps, probeS, { caller: STRANGER });
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    expect(BigInt(rj.returnHex)).toBe(0xc1a54n);
    expect(rj.returnHex).toBe(rs.returnHex);
    // CRUCIAL: the non-admin upgradeToAndCall did NOT change the impl slot (no proxy upgrade ran) and
    // emitted NO Upgraded event - it delegated into the impl.
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString()).toBe(v2j.toString());
    expect(rj.logs.length).toBe(0);
    expect(rs.logs.length).toBe(0);
  });

  it('(2b) a non-admin upgradeToAndCall reverts via the IMPL when the impl has no such function (== solc)', async () => {
    // On V1 (no upgradeToAndCall function), a NON-admin upgradeToAndCall selector delegates to V1 and
    // reverts there (unknown selector -> V1's dispatcher reverts), NOT the proxy's deny path.
    const { hj, hs, v1j, v1s, pj, ps } = await setup(2n);
    const rj = await hj.call(pj, upgradeCall(v1j), { caller: STRANGER });
    const rs = await hs.call(ps, upgradeCall(v1s), { caller: STRANGER });
    expect(rj.success).toBe(false);
    expect(rs.success).toBe(false);
    // it is NOT a ProxyDeniedAdminAccess revert (that is admin-only); the impl reverted (empty here)
    expect(rj.returnHex.startsWith('0x' + PROXY_DENIED)).toBe(false);
    expect(rj.returnHex).toBe(rs.returnHex);
    // impl slot unchanged
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString()).toBe(v1j.toString());
  });

  it('(3) the ADMIN calling upgradeToAndCall(V2, data) upgrades + emits Upgraded(indexed V2) + runs data once (== solc)', async () => {
    const { hj, hs, v2j, v2s, pj, ps } = await setup(5n);
    // before: value_() == 5 (V1)
    expect(BigInt((await hj.call(pj, '0x' + sel('value_()'))).returnHex)).toBe(5n);
    // admin upgrades to V2 with NO data
    const uj = await hj.call(pj, upgradeCall(v2j), { caller: ADMIN });
    const us = await hs.call(ps, upgradeCall(v2s), { caller: ADMIN });
    expect(uj.success).toBe(true);
    expect(us.success).toBe(true);
    // the admin upgrade returns EMPTY returndata (OZ TransparentUpgradeableProxy behaviour)
    expect(uj.returnHex).toBe('0x');
    expect(us.returnHex).toBe('0x');
    // Upgraded(address indexed implementation): topic0 + indexed impl, no data; identical on both
    expect(uj.logs.length).toBe(1);
    expect(us.logs.length).toBe(1);
    expect(uj.logs[0]!.topics[0]).toBe(UPGRADED_TOPIC);
    expect(uj.logs[0]!.topics[0]).toBe(us.logs[0]!.topics[0]);
    expect(addrFromWord(uj.logs[0]!.topics[1]!).toString()).toBe(v2j.toString());
    expect(uj.logs[0]!.data).toBe('0x');
    expect(us.logs[0]!.data).toBe('0x');
    // impl slot now V2; behaviour swapped (value_() == 10, value preserved = 5)
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString()).toBe(v2j.toString());
    expect(await readSlot(hj, pj, IMPL_SLOT)).toBe(await readSlot(hs, ps, IMPL_SLOT));
    const vj = await hj.call(pj, '0x' + sel('value_()'), { caller: STRANGER });
    const vs = await hs.call(ps, '0x' + sel('value_()'), { caller: STRANGER });
    expect(vj.returnHex).toBe(vs.returnHex);
    expect(BigInt(vj.returnHex)).toBe(10n);
  });

  it('(3b) the ADMIN upgradeToAndCall WITH data runs the data via delegatecall (bubbles a revert == solc)', async () => {
    // V1 init set initialized=true; upgrading to V2 with initialize(99) data must REVERT ("init") since
    // the proxy's slot1 is already 1 - the delegatecall bubbles the revert through the admin path.
    const { hj, hs, v2j, v2s, pj, ps } = await setup(3n);
    const di = initData(99n);
    const uj = await hj.call(pj, upgradeCall(v2j, di), { caller: ADMIN });
    const us = await hs.call(ps, upgradeCall(v2s, di), { caller: ADMIN });
    expect(uj.success).toBe(false);
    expect(us.success).toBe(false);
    expect(uj.returnHex).toBe(us.returnHex); // identical bubbled Error("init")
    // the impl slot WAS written before the delegatecall bubbled (sstore happens first), on both
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString()).toBe(
      addrFromWord(await readSlot(hs, ps, IMPL_SLOT)).toString(),
    );
  });

  it('(3c) the ADMIN upgradeToAndCall WITH data succeeds + runs the data once (state set via delegatecall)', async () => {
    // Deploy a proxy whose V1 init left initialized=false: set initVal that does NOT initialize? The
    // proxyInit always runs initialize, so slot1 is already 1. Instead: upgrade to V2 with data = bump()
    // and verify value increments once via the delegatecall through the admin path.
    const { hj, hs, v2j, v2s, pj, ps } = await setup(10n);
    const bumpData = '0x' + sel('bump()');
    const uj = await hj.call(pj, upgradeCall(v2j, bumpData), { caller: ADMIN });
    const us = await hs.call(ps, upgradeCall(v2s, bumpData), { caller: ADMIN });
    expect(uj.success).toBe(true);
    expect(us.success).toBe(true);
    // value went 10 -> 11 exactly once (the data bump ran once via delegatecall)
    expect(BigInt(await readSlot(hj, pj, 0n))).toBe(11n);
    expect(await readSlot(hj, pj, 0n)).toBe(await readSlot(hs, ps, 0n));
    // exactly one Upgraded event
    expect(uj.logs.length).toBe(1);
    expect(us.logs.length).toBe(1);
  });

  it('(4) the ADMIN calling any OTHER selector reverts ProxyDeniedAdminAccess (== solc)', async () => {
    const { hj, hs, pj, ps } = await setup(4n);
    // admin calls value_() (a normal impl selector) -> deny, NOT delegate
    const rj = await hj.call(pj, '0x' + sel('value_()'), { caller: ADMIN });
    const rs = await hs.call(ps, '0x' + sel('value_()'), { caller: ADMIN });
    expect(rj.success).toBe(false);
    expect(rs.success).toBe(false);
    expect(rj.returnHex).toBe('0x' + PROXY_DENIED); // ProxyDeniedAdminAccess() selector
    expect(rj.returnHex).toBe(rs.returnHex);
    // admin with EMPTY calldata also denied (msg.sig 0 != upgradeToAndCall)
    const ej = await hj.call(pj, '0x', { caller: ADMIN });
    const es = await hs.call(ps, '0x', { caller: ADMIN });
    expect(ej.success).toBe(false);
    expect(es.success).toBe(false);
    expect(ej.returnHex).toBe('0x' + PROXY_DENIED);
    expect(ej.returnHex).toBe(es.returnHex);
  });

  it('(5) state is preserved across an admin upgrade (== solc)', async () => {
    const { hj, hs, v2j, v2s, pj, ps } = await setup(21n);
    // non-admin bumps to 22 before the upgrade
    await hj.call(pj, '0x' + sel('bump()'), { caller: STRANGER });
    await hs.call(ps, '0x' + sel('bump()'), { caller: STRANGER });
    await hj.call(pj, upgradeCall(v2j), { caller: ADMIN });
    await hs.call(ps, upgradeCall(v2s), { caller: ADMIN });
    // slot0 still 22 after upgrade; V2.value_() == 44
    expect(BigInt(await readSlot(hj, pj, 0n))).toBe(22n);
    expect(await readSlot(hj, pj, 0n)).toBe(await readSlot(hs, ps, 0n));
    const vj = await hj.call(pj, '0x' + sel('value_()'), { caller: STRANGER });
    const vs = await hs.call(ps, '0x' + sel('value_()'), { caller: STRANGER });
    expect(BigInt(vj.returnHex)).toBe(44n);
    expect(vj.returnHex).toBe(vs.returnHex);
  });

  it('(6) the isContract guard: admin upgradeToAndCall to a NON-contract reverts (impl slot unchanged == solc)', async () => {
    const { hj, hs, v1j, pj, ps } = await setup(1n);
    const eoa = STRANGER; // never-deployed
    const uj = await hj.call(pj, upgradeCall(eoa), { caller: ADMIN });
    const us = await hs.call(ps, upgradeCall(eoa), { caller: ADMIN });
    expect(uj.success).toBe(false);
    expect(us.success).toBe(false);
    // impl slot unchanged (still V1)
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString().toLowerCase()).toBe(v1j.toString().toLowerCase());
    expect(await readSlot(hj, pj, IMPL_SLOT)).toBe(await readSlot(hs, ps, IMPL_SLOT));
  });

  // ---- (6-SEC) SECURITY: malformed admin upgradeToAndCall calldata must NOT upgrade. The synthesized
  // admin entry decodes (address newImpl, bytes data) EXACTLY like solc's `abi.decode(msg.data[4:],
  // (address, bytes))` (a `bytes memory` decode) BEFORE any state change. A malformed calldata word
  // (bad/OOB bytes offset, dirty address, too-short) must EMPTY-revert (or Panic(0x41) on an oversized
  // length, matching solc's memory-allocation panic) with the impl slot unchanged and NO Upgraded log.
  // Before the fix these reverting-in-solc shapes performed a real upgrade + emitted Upgraded (a critical
  // proxy-hijack via garbage calldata). ----
  describe('(6-SEC) malformed admin upgradeToAndCall calldata never upgrades (== solc)', () => {
    const raw = (impl: Address, tail: string) =>
      '0x' + UPGRADE_TO_AND_CALL + W(BigInt(impl.toString())) + tail;
    async function assertNoUpgrade(build: (v2: Address) => string) {
      const { hj, hs, v1j, v2j, v1s, v2s, pj, ps } = await setup(7n);
      const rj = await hj.call(pj, build(v2j), { caller: ADMIN });
      const rs = await hs.call(ps, build(v2s), { caller: ADMIN });
      // both revert with byte-identical returndata (EMPTY or Panic 0x41)
      expect(rj.success).toBe(false);
      expect(rs.success).toBe(false);
      expect(rj.returnHex).toBe(rs.returnHex);
      // no Upgraded log on either
      expect(rj.logs.length).toBe(0);
      expect(rs.logs.length).toBe(0);
      // impl slot UNCHANGED (still V1) on both - the upgrade did NOT run
      expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString().toLowerCase()).toBe(
        v1j.toString().toLowerCase(),
      );
      expect(addrFromWord(await readSlot(hs, ps, IMPL_SLOT)).toString().toLowerCase()).toBe(
        v1s.toString().toLowerCase(),
      );
      // v2 was never installed anywhere
      expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString().toLowerCase()).not.toBe(
        v2j.toString().toLowerCase(),
      );
    }
    it('an out-of-bounds bytes offset (0x1000, no tail) EMPTY-reverts, no upgrade/log', async () => {
      await assertNoUpgrade((v2) => raw(v2, W(0x1000n)));
    });
    it('a dirty address word (high 96 bits set) reverts, no upgrade/log', async () => {
      // dirty address with an otherwise well-formed empty-bytes tail:
      await assertNoUpgrade(
        (v2) => '0x' + UPGRADE_TO_AND_CALL + W((0xdeadn << 160n) | BigInt(v2.toString())) + W(0x40n) + W(0n),
      );
    });
    it('a too-short calldata (only the address word, no offset word) reverts, no upgrade/log', async () => {
      await assertNoUpgrade((v2) => raw(v2, ''));
    });
    it('a bytes offset that overlaps the head (0x20) reverts, no upgrade/log', async () => {
      await assertNoUpgrade((v2) => raw(v2, W(0x20n) + W(0n)));
    });
    it('a declared length that runs past calldata (off=0x40 len=0x20 no data) EMPTY-reverts, no upgrade/log', async () => {
      await assertNoUpgrade((v2) => raw(v2, W(0x40n) + W(0x20n)));
    });
    it('an oversized declared length (off=0x40 len=2^64-1) Panics(0x41) like solc, no upgrade/log', async () => {
      await assertNoUpgrade((v2) => raw(v2, W(0x40n) + W(0xffffffffffffffffn)));
    });
    it('control: a WELL-FORMED empty-bytes admin upgradeToAndCall still upgrades + logs (== solc)', async () => {
      const { hj, hs, v2j, v2s, pj, ps } = await setup(7n);
      const cd = (v2: Address) => '0x' + UPGRADE_TO_AND_CALL + W(BigInt(v2.toString())) + W(0x40n) + W(0n);
      const rj = await hj.call(pj, cd(v2j), { caller: ADMIN });
      const rs = await hs.call(ps, cd(v2s), { caller: ADMIN });
      expect(rj.success).toBe(true);
      expect(rs.success).toBe(true);
      expect(rj.logs.length).toBe(1);
      expect(rs.logs.length).toBe(1);
      expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString().toLowerCase()).toBe(
        v2j.toString().toLowerCase(),
      );
    });
  });

  it('(EIP-1967 slots) the proxy admin/impl slots match solc byte-for-byte', async () => {
    const { hj, hs, v1j, v1s, pj, ps } = await setup(7n);
    expect(await readSlot(hj, pj, IMPL_SLOT)).toBe(await readSlot(hs, ps, IMPL_SLOT));
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString()).toBe(v1j.toString());
    expect(addrFromWord(await readSlot(hs, ps, IMPL_SLOT)).toString()).toBe(v1s.toString());
    const adminJ = await readSlot(hj, pj, ADMIN_SLOT);
    const adminS = await readSlot(hs, ps, ADMIN_SLOT);
    expect(adminJ).toBe(adminS);
    expect(addrFromWord(adminJ).toString().toLowerCase()).toBe(ADMIN.toString().toLowerCase());
  });

  it('(deploy) proxyInit emits Upgraded exactly once at deploy (== solc)', async () => {
    const hj = await Harness.create();
    const hs = await Harness.create();
    const v1j = await hj.deploy(compile(V1_JETH, { fileName: 'V1.jeth' }).creationBytecode);
    const v1s = await hs.deploy(compileSolidity(SPDX + V1_SOL, 'V1').creation);
    const pjBuild = compile(PROXY_JETH, { fileName: 'P.jeth' });
    const psBuild = compileSolidity(SPDX + PROXY_SOL, 'P');
    const cj = pjBuild.creationBytecode + jethCtorArgs(v1j, ADMIN, 7n);
    const cs = psBuild.creation + solCtorArgs(v1s, ADMIN, initData(7n));
    const rj = await hj.evm.runCall({ data: hexToBytes(('0x' + strip(cj)) as `0x${string}`), gasLimit: 10_000_000n });
    const rs = await hs.evm.runCall({ data: hexToBytes(('0x' + strip(cs)) as `0x${string}`), gasLimit: 10_000_000n });
    const logsJ = (rj.execResult.logs ?? []) as [Uint8Array, Uint8Array[], Uint8Array][];
    const logsS = (rs.execResult.logs ?? []) as [Uint8Array, Uint8Array[], Uint8Array][];
    expect(logsJ.length).toBe(1);
    expect(logsS.length).toBe(1);
    expect(bytesToHex(logsJ[0]![1][0]!)).toBe(UPGRADED_TOPIC);
    expect(bytesToHex(logsJ[0]![1][0]!)).toBe(bytesToHex(logsS[0]![1][0]!));
    expect(addrFromWord(bytesToHex(logsJ[0]![1][1]!)).toString()).toBe(v1j.toString());
    expect(bytesToHex(logsJ[0]![2])).toBe('0x');
  });

  // ---- (7) accept/reject GATES (compile-time) ----
  describe('(7) gates', () => {
    it('a valid @proxy(\'transparent\') (ctor-only) compiles', () => {
      expect(jethAccepts(PROXY_JETH)).toBe(true);
    });
    it('a @proxy(\'transparent\') class may NOT declare an @external method (JETH401)', () => {
      const src = `@proxy('transparent') class P {
        constructor(i: address, a: address) { proxyInit(i, a, abi.encode()); }
        @external foo(): u256 { return 1n; }
      }`;
      expect(jethRejects(src)).toBe(true);
      expect(jethCodes(src)).toContain('JETH401');
    });
    it('an @external @view method on a transparent proxy is also rejected', () => {
      const src = `@proxy('transparent') class P {
        constructor(i: address, a: address) { proxyInit(i, a, abi.encode()); }
        @external @view bar(): u256 { return 1n; }
      }`;
      expect(jethRejects(src)).toBe(true);
      expect(jethCodes(src)).toContain('JETH401');
    });
    it('an unknown @proxy variant is rejected (JETH400)', () => {
      // ('transparent' and 'beacon' are the supported variants; 'diamond' is not.)
      const src = `@proxy('diamond') class P { constructor(i: address) { proxyInit(i, abi.encode()); } }`;
      expect(jethRejects(src)).toBe(true);
      expect(jethCodes(src)).toContain('JETH400');
    });
    it('a non-string @proxy variant argument is rejected (JETH400)', () => {
      const src = `@proxy(5) class P { constructor(i: address) { proxyInit(i, abi.encode()); } }`;
      expect(jethRejects(src)).toBe(true);
      expect(jethCodes(src)).toContain('JETH400');
    });
    it('more than one @proxy argument is rejected (JETH400)', () => {
      const src = `@proxy('transparent', 'x') class P { constructor(i: address, a: address) { proxyInit(i, a, abi.encode()); } }`;
      expect(jethRejects(src)).toBe(true);
      expect(jethCodes(src)).toContain('JETH400');
    });
    it('the plain @proxy (no arg) still accepts @external methods (Phase 2a unchanged)', () => {
      expect(jethAccepts(`@proxy class P { @external up(n: address, d: bytes): void { upgradeProxy(n, d); } }`)).toBe(true);
    });
    it('the empty call-form @proxy() is the plain proxy (accepts @external)', () => {
      expect(jethAccepts(`@proxy() class P { @external up(n: address, d: bytes): void { upgradeProxy(n, d); } }`)).toBe(true);
    });
    it('a transparent proxy may NOT declare @state of its own (JETH399)', () => {
      const src = `@proxy('transparent') class P { @state x: u256 = 0n; constructor(i: address, a: address) { proxyInit(i, a, abi.encode()); } }`;
      expect(jethRejects(src)).toBe(true);
      expect(jethCodes(src)).toContain('JETH399');
    });
    it('a transparent proxy may NOT declare a @receive/@fallback (JETH398)', () => {
      expect(jethRejects(`@proxy('transparent') class P { @receive r(): void {} }`)).toBe(true);
      expect(jethRejects(`@proxy('transparent') class P { @fallback f(): void {} }`)).toBe(true);
    });
  });
});
