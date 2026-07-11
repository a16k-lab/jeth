// Phase 2a proxies: the EIP-1967 UPGRADEABLE-PROXY foundation (byte-identical to a hand-written OZ
// ERC1967 / transparent-style proxy in solc 0.8.35). A JETH @proxy + V1/V2 impls and a hand-written
// solc ERC1967 proxy + impls are deployed on the @ethereumjs harness; we diff returndata + the proxy's
// STORAGE (the EIP-1967 impl/admin slots + the impl's state slots, which live in the proxy) + the
// Upgraded event + revert data:
//   (1) a call routed through the @proxy hits V1's logic and writes the PROXY's storage; the impl's own
//       storage stays untouched;
//   (2) proxyImplementation() == the impl, proxyAdmin() == the admin;
//   (3) upgradeProxy to V2 swaps behaviour + emits Upgraded;
//   (4) the init delegatecall in proxyInit runs exactly once (an initializer that sets state);
//   (5) an unauthorized upgrade reverts (user-gated);
//   (6) proxyInit/upgradeProxy with a non-contract impl reverts (isContract guard);
//   (7) a @view/@pure caller of upgradeProxy/proxyInit is rejected.
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
const ZERO = '0x' + '00'.repeat(32);

// EIP-1967 fixed slots (collision-resistant constants).
const IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbcn;
const ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103n;
const UPGRADED_TOPIC = '0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b';

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

// ---- V1 / V2 implementations (normal JETH @contracts, with an exact solc mirror). ----
// Storage layout: slot0 = value (uint256), slot1 = initialized (bool). initialize(x) sets both ONCE;
// V1.value() returns value; V2.value() returns value*2 (the upgrade swaps behaviour); both have bump().
const V1_JETH = `class V1 {
  value: u256 = 0n;
  initialized: bool = false;
  initialize(x: u256): External<void> {
    require(!this.initialized, "init");
    this.initialized = true;
    this.value = x;
  }
  bump(): External<void> { this.value = this.value + 1n; }
  get value_(): External<u256> { return this.value; }
  get version(): External<u256> { return 1n; }
}`;
const V1_SOL = `contract V1 {
  uint256 value;
  bool initialized;
  function initialize(uint256 x) external { require(!initialized, "init"); initialized = true; value = x; }
  function bump() external { value = value + 1; }
  function value_() external view returns (uint256) { return value; }
  function version() external view returns (uint256) { return 1; }
}`;

const V2_JETH = `class V2 {
  value: u256 = 0n;
  initialized: bool = false;
  initialize(x: u256): External<void> {
    require(!this.initialized, "init");
    this.initialized = true;
    this.value = x;
  }
  bump(): External<void> { this.value = this.value + 1n; }
  get value_(): External<u256> { return this.value * 2n; }
  get version(): External<u256> { return 2n; }
}`;
const V2_SOL = `contract V2 {
  uint256 value;
  bool initialized;
  function initialize(uint256 x) external { require(!initialized, "init"); initialized = true; value = x; }
  function bump() external { value = value + 1; }
  function value_() external view returns (uint256) { return value * 2; }
  function version() external view returns (uint256) { return 2; }
}`;

// ---- The JETH @proxy. The constructor takes (impl, admin) value-type args + an init value, builds the
// initialize(uint256) calldata internally, and proxyInit's it. upgradeTo is admin-gated. ----
const INIT_SEL = sel('initialize(uint256)'); // 4 bytes hex
const PROXY_JETH = `@proxy class P {
  constructor(impl: address, admin: address, initVal: u256) {
    proxyInit(impl, admin, abi.encodeWithSelector(0x${INIT_SEL}n, initVal));
  }
  upgradeTo(newImpl: address, data: bytes): External<void> {
    require(msg.sender == proxyAdmin(), "not admin");
    upgradeProxy(newImpl, data);
  }
  get implementation(): External<address> { return proxyImplementation(); }
  get admin(): External<address> { return proxyAdmin(); }
}`;

// ---- The hand-written solc ERC1967 proxy (the verified baseline assembly): raw sstore/sload at the
// EIP-1967 slots + the canonical delegate fallback. Constructor takes (impl, admin, initData). ----
const PROXY_SOL = `contract P {
  bytes32 constant IMPL = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
  bytes32 constant ADMIN = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
  event Upgraded(address indexed implementation);
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
  function upgradeTo(address newImpl, bytes calldata data) external {
    address a; assembly { a := sload(ADMIN) }
    require(msg.sender == a, "not admin");
    require(newImpl.code.length > 0);
    assembly { sstore(IMPL, newImpl) }
    emit Upgraded(newImpl);
    if (data.length > 0) {
      (bool ok, ) = newImpl.delegatecall(data);
      if (!ok) { assembly { returndatacopy(0, 0, returndatasize()) revert(0, returndatasize()) } }
    }
  }
  function implementation() external view returns (address a) { assembly { a := sload(IMPL) } }
  function admin() external view returns (address a) { assembly { a := sload(ADMIN) } }
  fallback() external payable {
    assembly {
      let impl := sload(IMPL)
      calldatacopy(0, 0, calldatasize())
      let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
      returndatacopy(0, 0, returndatasize())
      switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
    }
  }
}`;

/** ABI-encode (address impl, address admin, bytes initData) for the SOLC proxy constructor. */
function solCtorArgs(impl: Address, admin: Address, initData: string): string {
  const id = strip(initData);
  const len = id.length / 2;
  const padded = id + '0'.repeat((64 - (id.length % 64)) % 64);
  // head: impl(32), admin(32), offset(32)=0x60; tail: len(32) + padded data
  return W(BigInt(impl.toString())) + W(BigInt(admin.toString())) + W(0x60n) + W(BigInt(len)) + padded;
}
/** ABI-encode (address impl, address admin, uint256 initVal) for the JETH proxy constructor. */
function jethCtorArgs(impl: Address, admin: Address, initVal: bigint): string {
  return W(BigInt(impl.toString())) + W(BigInt(admin.toString())) + W(initVal);
}

const initData = (val: bigint) => '0x' + INIT_SEL + W(val);

/** Deploy V1, V2, and the proxy (init'd with V1, initVal) on a JETH harness and a solc harness. */
async function setup(initVal: bigint) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  // impls
  const v1j = await hj.deploy(compile(V1_JETH, { fileName: 'V1.jeth' }).creationBytecode);
  const v2j = await hj.deploy(compile(V2_JETH, { fileName: 'V2.jeth' }).creationBytecode);
  const v1s = await hs.deploy(compileSolidity(SPDX + V1_SOL, 'V1').creation);
  const v2s = await hs.deploy(compileSolidity(SPDX + V2_SOL, 'V2').creation);
  // proxies: JETH ctor args (impl, admin, initVal); solc ctor args (impl, admin, initData=initialize(initVal))
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

describe('upgradeable-proxy (Phase 2a foundation)', () => {
  it('(1) a call through the @proxy hits V1 and writes the PROXY storage; impl storage untouched', async () => {
    const { hj, hs, v1j, v1s, pj, ps } = await setup(7n);
    // value_() routed through the proxy reads the proxy's slot0 (set to 7 by the init delegatecall)
    const rj = await hj.call(pj, '0x' + sel('value_()'));
    const rs = await hs.call(ps, '0x' + sel('value_()'));
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(BigInt(rj.returnHex)).toBe(7n);
    // bump() (state-writing) through the proxy: writes the PROXY's slot0
    await hj.call(pj, '0x' + sel('bump()'));
    await hs.call(ps, '0x' + sel('bump()'));
    // the PROXY's slot0 == 8 on both; slot1 (initialized) == 1 on both
    expect(await readSlot(hj, pj, 0n)).toBe(await readSlot(hs, ps, 0n));
    expect(BigInt(await readSlot(hj, pj, 0n))).toBe(8n);
    expect(await readSlot(hj, pj, 1n)).toBe(await readSlot(hs, ps, 1n));
    expect(BigInt(await readSlot(hj, pj, 1n))).toBe(1n);
    // the impl's OWN storage is untouched (slot0/slot1 stay zero) on both
    expect(BigInt(await readSlot(hj, v1j, 0n))).toBe(0n);
    expect(BigInt(await readSlot(hs, v1s, 0n))).toBe(0n);
    expect(BigInt(await readSlot(hj, v1j, 1n))).toBe(0n);
  });

  it('(EIP-1967 slots) the proxy storage at the impl/admin slots matches solc byte-for-byte', async () => {
    const { hj, hs, v1j, v1s, pj, ps } = await setup(7n);
    // impl slot holds V1 (right-aligned address)
    const implJ = await readSlot(hj, pj, IMPL_SLOT);
    const implS = await readSlot(hs, ps, IMPL_SLOT);
    expect(implJ).toBe(implS);
    expect(addrFromWord(implJ).toString()).toBe(v1j.toString());
    expect(addrFromWord(implS).toString()).toBe(v1s.toString());
    // admin slot holds ADMIN on both
    const adminJ = await readSlot(hj, pj, ADMIN_SLOT);
    const adminS = await readSlot(hs, ps, ADMIN_SLOT);
    expect(adminJ).toBe(adminS);
    expect(addrFromWord(adminJ).toString().toLowerCase()).toBe(ADMIN.toString().toLowerCase());
  });

  it('(2) proxyImplementation() == the impl, proxyAdmin() == the admin (== solc)', async () => {
    const { hj, hs, v1j, v1s, pj, ps } = await setup(7n);
    const ij = await hj.call(pj, '0x' + sel('implementation()'));
    const is = await hs.call(ps, '0x' + sel('implementation()'));
    expect(ij.returnHex).toBe(is.returnHex);
    expect(addrFromWord(ij.returnHex).toString()).toBe(v1j.toString());
    const aj = await hj.call(pj, '0x' + sel('admin()'));
    const as = await hs.call(ps, '0x' + sel('admin()'));
    expect(aj.returnHex).toBe(as.returnHex);
    expect(addrFromWord(aj.returnHex).toString().toLowerCase()).toBe(ADMIN.toString().toLowerCase());
  });

  it('(3) upgradeTo V2 swaps behaviour + emits Upgraded (topic + data == solc)', async () => {
    const { hj, hs, v2j, v2s, pj, ps } = await setup(5n);
    // before upgrade: value_() == 5 (V1 returns value)
    expect(BigInt((await hj.call(pj, '0x' + sel('value_()'))).returnHex)).toBe(5n);
    // upgrade to V2 with NO init data (empty bytes) by the admin
    const dataJ = '0x' + sel('upgradeTo(address,bytes)') + W(BigInt(v2j.toString())) + W(0x40n) + W(0n);
    const dataS = '0x' + sel('upgradeTo(address,bytes)') + W(BigInt(v2s.toString())) + W(0x40n) + W(0n);
    const uj = await hj.call(pj, dataJ, { caller: ADMIN });
    const us = await hs.call(ps, dataS, { caller: ADMIN });
    expect(uj.success).toBe(true);
    expect(us.success).toBe(true);
    // the Upgraded event: topic0 = keccak("Upgraded(address)"), topic1 = the new impl (indexed), no data
    expect(uj.logs.length).toBe(1);
    expect(us.logs.length).toBe(1);
    expect(uj.logs[0]!.topics[0]).toBe(UPGRADED_TOPIC);
    expect(uj.logs[0]!.topics[0]).toBe(us.logs[0]!.topics[0]);
    expect(addrFromWord(uj.logs[0]!.topics[1]!).toString()).toBe(v2j.toString());
    expect(uj.logs[0]!.data).toBe('0x'); // indexed-only event: no data
    expect(us.logs[0]!.data).toBe('0x');
    // impl slot now holds V2 on both
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString()).toBe(v2j.toString());
    expect(await readSlot(hj, pj, IMPL_SLOT)).toBe(await readSlot(hs, ps, IMPL_SLOT));
    // behaviour swapped: V2.value_() returns value*2 == 10 (value still 5; state preserved across upgrade)
    const vj = await hj.call(pj, '0x' + sel('value_()'));
    const vs = await hs.call(ps, '0x' + sel('value_()'));
    expect(vj.returnHex).toBe(vs.returnHex);
    expect(BigInt(vj.returnHex)).toBe(10n);
    // version() now == 2 on both
    expect(BigInt((await hj.call(pj, '0x' + sel('version()'))).returnHex)).toBe(2n);
    expect((await hj.call(pj, '0x' + sel('version()'))).returnHex).toBe(
      (await hs.call(ps, '0x' + sel('version()'))).returnHex,
    );
  });

  it('(3b) upgradeTo with init data: runs the new impl initializer via delegatecall', async () => {
    // Deploy a fresh proxy on V1 with initVal 0 but initialized=false would re-init; instead upgrade to V2
    // and re-run initialize on a FRESH proxy whose initialized flag is still false. Simpler: a proxy whose
    // V1 init set initialized=true; upgrading to V2 with initialize(99) data must REVERT ("init") since the
    // proxy's slot1 is already 1 - the delegatecall bubbles the revert. That proves the data path runs.
    const { hj, hs, v2j, v2s, pj, ps } = await setup(3n);
    const di = initData(99n); // initialize(99)
    const dlen = strip(di).length / 2;
    const dpad = strip(di).slice(8); // the 32-byte arg word (selector is 4 bytes)
    const callJ =
      '0x' + sel('upgradeTo(address,bytes)') + W(BigInt(v2j.toString())) + W(0x40n) + W(BigInt(dlen)) +
      INIT_SEL + dpad + '0'.repeat((64 - ((INIT_SEL + dpad).length % 64)) % 64);
    const callS =
      '0x' + sel('upgradeTo(address,bytes)') + W(BigInt(v2s.toString())) + W(0x40n) + W(BigInt(dlen)) +
      INIT_SEL + dpad + '0'.repeat((64 - ((INIT_SEL + dpad).length % 64)) % 64);
    const uj = await hj.call(pj, callJ, { caller: ADMIN });
    const us = await hs.call(ps, callS, { caller: ADMIN });
    // both bubble the "init" require revert from the delegatecalled initializer (proxy already initialized)
    expect(uj.success).toBe(false);
    expect(us.success).toBe(false);
    expect(uj.returnHex).toBe(us.returnHex); // identical Error("init") revert bytes bubbled
  });

  it('(4) the init delegatecall in proxyInit runs exactly once (initializer set state once)', async () => {
    const { hj, hs, pj, ps } = await setup(42n);
    // slot0 == 42 (the init delegatecall ran), slot1 == 1 (the once-guard flag was set) - on both
    expect(BigInt(await readSlot(hj, pj, 0n))).toBe(42n);
    expect(await readSlot(hj, pj, 0n)).toBe(await readSlot(hs, ps, 0n));
    expect(BigInt(await readSlot(hj, pj, 1n))).toBe(1n);
    // calling initialize() AGAIN through the proxy reverts ("init") - the once-guard already tripped
    const rj = await hj.call(pj, '0x' + sel('initialize(uint256)') + W(1n));
    const rs = await hs.call(ps, '0x' + sel('initialize(uint256)') + W(1n));
    expect(rj.success).toBe(false);
    expect(rs.success).toBe(false);
    expect(rj.returnHex).toBe(rs.returnHex);
    // exactly one Upgraded event was emitted at deploy (verified via re-deploy + log capture below)
  });

  it('(4b) proxyInit emits Upgraded exactly once at deploy (topic + indexed impl == solc)', async () => {
    // Re-deploy capturing the creation logs. Harness.deploy does not expose logs, so deploy via a raw
    // runCall to read the constructor-emitted Upgraded event.
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
    expect(bytesToHex(logsJ[0]![2])).toBe('0x'); // no data
    expect(bytesToHex(logsS[0]![2])).toBe('0x');
  });

  it('(5) an unauthorized (non-admin) upgrade reverts on both (user-gated)', async () => {
    const { hj, hs, v2j, v2s, pj, ps } = await setup(1n);
    const dataJ = '0x' + sel('upgradeTo(address,bytes)') + W(BigInt(v2j.toString())) + W(0x40n) + W(0n);
    const dataS = '0x' + sel('upgradeTo(address,bytes)') + W(BigInt(v2s.toString())) + W(0x40n) + W(0n);
    const uj = await hj.call(pj, dataJ, { caller: STRANGER });
    const us = await hs.call(ps, dataS, { caller: STRANGER });
    expect(uj.success).toBe(false);
    expect(us.success).toBe(false);
    expect(uj.returnHex).toBe(us.returnHex); // identical Error("not admin") revert bytes
    // the impl slot is UNCHANGED (still V1)
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString()).not.toBe(v2j.toString());
  });

  it('(6) proxyInit/upgradeProxy with a non-contract impl reverts (isContract guard)', async () => {
    const { hj, hs, pj, ps } = await setup(1n);
    // upgradeTo a NON-contract address (an EOA) -> the isContract guard reverts empty on both
    const eoa = STRANGER; // never-deployed account
    const dataJ = '0x' + sel('upgradeTo(address,bytes)') + W(BigInt(eoa.toString())) + W(0x40n) + W(0n);
    const dataS = '0x' + sel('upgradeTo(address,bytes)') + W(BigInt(eoa.toString())) + W(0x40n) + W(0n);
    const uj = await hj.call(pj, dataJ, { caller: ADMIN });
    const us = await hs.call(ps, dataS, { caller: ADMIN });
    expect(uj.success).toBe(false);
    expect(us.success).toBe(false);
    // the impl slot is unchanged
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString().toLowerCase()).not.toBe(eoa.toString().toLowerCase());

    // proxyInit (the constructor) with a non-contract impl: DEPLOY must revert on both
    const pjBuild = compile(PROXY_JETH, { fileName: 'P.jeth' });
    const psBuild = compileSolidity(SPDX + PROXY_SOL, 'P');
    let jethReverted = false;
    let solReverted = false;
    try {
      await hj.deploy(pjBuild.creationBytecode + jethCtorArgs(eoa, ADMIN, 0n));
    } catch {
      jethReverted = true;
    }
    try {
      await hs.deploy(psBuild.creation + solCtorArgs(eoa, ADMIN, initData(0n)));
    } catch {
      solReverted = true;
    }
    expect(jethReverted).toBe(true);
    expect(solReverted).toBe(true);
  });

  // ---- (7) accept/reject GATES (compile-time) ----
  describe('(7) gates', () => {
    it('a @view caller of upgradeProxy is rejected', () => {
      expect(jethRejects(`@proxy class P { @external @view bad(n: address): void { upgradeProxy(n, abi.encode()); } }`)).toBe(true);
    });
    it('a @pure caller of upgradeProxy is rejected', () => {
      expect(jethRejects(`@proxy class P { @external @pure bad(n: address): void { upgradeProxy(n, abi.encode()); } }`)).toBe(true);
    });
    it('a @view caller of proxyInit is rejected', () => {
      expect(jethRejects(`@proxy class P { @external @view bad(n: address): void { proxyInit(n, abi.encode()); } }`)).toBe(true);
    });
    it('a @pure caller of proxyInit is rejected', () => {
      expect(jethRejects(`@proxy class P { @external @pure bad(n: address): void { proxyInit(n, abi.encode()); } }`)).toBe(true);
    });
    it('a @view caller of proxyImplementation()/proxyAdmin() is ACCEPTED (a storage read)', () => {
      expect(jethAccepts(`@proxy class P { get i(): External<address> { return proxyImplementation(); } }`)).toBe(true);
      expect(jethAccepts(`@proxy class P { get a(): External<address> { return proxyAdmin(); } }`)).toBe(true);
    });
    it('a @pure caller of proxyImplementation()/proxyAdmin() is rejected (it SLOADs)', () => {
      expect(jethRejects(`@proxy class P { @external @pure i(): address { return proxyImplementation(); } }`)).toBe(true);
      expect(jethRejects(`@proxy class P { @external @pure a(): address { return proxyAdmin(); } }`)).toBe(true);
    });
    it('a @proxy class may NOT declare a @receive entry', () => {
      expect(jethRejects(`@proxy class P { receive(): void {} }`)).toBe(true);
    });
    it('a @proxy class may NOT declare a @fallback entry', () => {
      expect(jethRejects(`@proxy class P { fallback(): void {} }`)).toBe(true);
    });
    it('a @proxy class may NOT declare @state of its own', () => {
      expect(jethRejects(`@proxy class P { x: u256 = 0n; }`)).toBe(true);
    });
    it('proxyInit non-bytes initData / non-address impl is rejected', () => {
      expect(jethRejects(`@proxy class P { g(a: address): External<void> { proxyInit(a, 5n); } }`)).toBe(true);
      expect(jethRejects(`@proxy class P { g(): External<void> { proxyInit(5n, abi.encode()); } }`)).toBe(true);
    });
    it('proxyInit/upgradeProxy wrong arity is rejected', () => {
      expect(jethRejects(`@proxy class P { g(a: address): External<void> { proxyInit(a); } }`)).toBe(true);
      expect(jethRejects(`@proxy class P { g(a: address): External<void> { upgradeProxy(a); } }`)).toBe(true);
    });
    it('the proxy builtins are usable in a normal @contract too (not gated to @proxy)', () => {
      expect(jethAccepts(`class C {
        g(a: address): External<void> { upgradeProxy(a, abi.encode()); }
        get i(): External<address> { return proxyImplementation(); }
      }`)).toBe(true);
    });
    it('a usable end-to-end @proxy (ctor + admin-gated upgrade + getters) compiles', () => {
      expect(jethAccepts(PROXY_JETH)).toBe(true);
    });
  });
});
