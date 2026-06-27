// Phase 2c: the UUPS proxy variant. The PROXY is the plain Phase-2a `@proxy` (delegate-only fallback);
// the UPGRADE LOGIC lives in the IMPLEMENTATION via the `@uups` decorator on a normal `@contract`. A
// `@uups @contract` synthesizes two @external entries (byte-identical to OZ UUPSUpgradeable 5.x):
//   - upgradeToAndCall(address newImpl, bytes data) payable: (1) call the user gate authorizeUpgrade(newImpl);
//     (2) the anti-brick proxiableUUID() STATICCALL on newImpl - a failed/short staticcall reverts
//     ERC1967InvalidImplementation(address) (0x4c9c8ce3); a returned slot != the EIP-1967 impl slot reverts
//     UUPSUnsupportedProxiableUUID(bytes32) (0xaa1d49a4); (3) the EIP-1967 upgrade (sstore impl slot, emit
//     Upgraded(indexed), data.length>0 -> delegatecall+bubble), return empty.
//   - proxiableUUID() view returns bytes32: the EIP-1967 impl slot constant 0x360894...
// upgradeToAndCall is called THROUGH the plain proxy (the proxy delegatecalls into the impl, so it runs in
// the PROXY's storage and rewrites the PROXY's EIP-1967 impl slot). We deploy a JETH plain @proxy + V1/V2
// @uups impls and a hand-written solc ERC1967-proxy + UUPS-equivalent impls, then diff returndata + the
// proxy's STORAGE (impl slot + the impl's state slots, which live in the proxy) + the Upgraded event +
// reverts (the auth gate, the two anti-brick selectors+args).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { Address, hexToBytes } from '@ethereumjs/util';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);
const strip = (h: string) => (h.startsWith('0x') ? h.slice(2) : h);

// EIP-1967 fixed impl slot + the UUPS selectors / anti-brick errors.
const IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbcn;
const UPGRADED_TOPIC = '0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b';
const UPGRADE_TO_AND_CALL = sel('upgradeToAndCall(address,bytes)'); // 4f1ef286
const PROXIABLE_UUID = sel('proxiableUUID()'); // 52d1902d
const ERC1967_INVALID_IMPL = sel('ERC1967InvalidImplementation(address)'); // 4c9c8ce3
const UUPS_UNSUPPORTED = sel('UUPSUnsupportedProxiableUUID(bytes32)'); // aa1d49a4

const OWNER = new Address(hexToBytes('0x00000000000000000000000000000000000000aa'));
const STRANGER = new Address(hexToBytes('0x00000000000000000000000000000000000000bb'));

function jethCodes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    const diags = (e as { diagnostics?: { code: string }[] }).diagnostics ?? [];
    return diags.map((d) => d.code);
  }
}
const jethAccepts = (src: string) => jethCodes(src).length === 0;

// ---- V1 / V2 UUPS implementations. STORAGE: slot0 = owner (address), slot1 = value (u256). initialize(o,v)
// sets both ONCE (only when owner is still zero). value_() returns value (V1) / value*2 (V2). bump() adds 1.
// authorizeUpgrade(newImpl) gates on msg.sender == owner. The solc mirror has the IDENTICAL layout +
// the UUPS upgrade machinery matching the JETH synthesized entries byte-for-byte. ----
const V1_JETH = `@uups @contract class V1 {
  @state owner: address = address(0n);
  @state value: u256 = 0n;
  authorizeUpgrade(newImpl: address): void {
    require(msg.sender == this.owner, "not authorized");
  }
  @external initialize(o: address, v: u256): void {
    require(this.owner == address(0n), "init");
    this.owner = o;
    this.value = v;
  }
  @external bump(): void { this.value = this.value + 1n; }
  @external @view value_(): u256 { return this.value; }
  @external @view version(): u256 { return 1n; }
}`;

const V2_JETH = `@uups @contract class V2 {
  @state owner: address = address(0n);
  @state value: u256 = 0n;
  authorizeUpgrade(newImpl: address): void {
    require(msg.sender == this.owner, "not authorized");
  }
  @external initialize(o: address, v: u256): void {
    require(this.owner == address(0n), "init");
    this.owner = o;
    this.value = v;
  }
  @external bump(): void { this.value = this.value + 1n; }
  @external @view value_(): u256 { return this.value * 2n; }
  @external @view version(): u256 { return 2n; }
}`;

// A plain contract WITHOUT proxiableUUID (the anti-brick STATICCALL fails -> ERC1967InvalidImplementation).
const NO_UUID_JETH = `@contract class NoUuid {
  @external @view ping(): u256 { return 42n; }
}`;

// A contract whose proxiableUUID() returns a WRONG slot (-> UUPSUnsupportedProxiableUUID(thatSlot)).
const WRONG_SLOT = 0x1111111111111111111111111111111111111111111111111111111111111111n;
const WRONG_UUID_JETH = `@contract class WrongUuid {
  @external @view proxiableUUID(): bytes32 { return bytes32(0x${WRONG_SLOT.toString(16)}n); }
}`;

// ---- The JETH plain proxy (Phase 2a delegate-only). Constructor: proxyInit(impl, initData) (NO admin -
// UUPS keeps the upgrade logic in the impl). initData = initialize(OWNER, initVal). ----
const INIT_SEL = sel('initialize(address,uint256)');
const PROXY_JETH = `@proxy class P {
  constructor(impl: address, owner: address, initVal: u256) {
    proxyInit(impl, abi.encodeWithSelector(0x${INIT_SEL}n, owner, initVal));
  }
}`;

// ---- The hand-written solc mirrors. A plain ERC1967 proxy (delegate-only fallback) + a UUPS impl with
// upgradeToAndCall / proxiableUUID matching the JETH synthesized entries EXACTLY (order: authorizeUpgrade,
// then the proxiableUUID staticcall anti-brick, then the EIP-1967 upgrade). ----
const V_SOL = (valueExpr: string, version: string) => `contract V {
  address owner;          // slot 0
  uint256 value;          // slot 1
  bytes32 constant IMPL = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
  event Upgraded(address indexed implementation);
  error ERC1967InvalidImplementation(address implementation);
  error UUPSUnsupportedProxiableUUID(bytes32 slot);
  function _authorizeUpgrade(address) internal view { require(msg.sender == owner, "not authorized"); }
  function initialize(address o, uint256 v) external { require(owner == address(0), "init"); owner = o; value = v; }
  function bump() external { value = value + 1; }
  function value_() external view returns (uint256) { return ${valueExpr}; }
  function version() external view returns (uint256) { return ${version}; }
  function proxiableUUID() external pure returns (bytes32) { return IMPL; }
  function upgradeToAndCall(address newImpl, bytes calldata data) external payable {
    _authorizeUpgrade(newImpl);
    // anti-brick: STATICCALL newImpl.proxiableUUID() (selector 0x52d1902d).
    (bool ok, bytes memory ret) = newImpl.staticcall(abi.encodeWithSelector(0x52d1902d));
    if (!ok || ret.length < 32) revert ERC1967InvalidImplementation(newImpl);
    bytes32 slot = abi.decode(ret, (bytes32));
    if (slot != IMPL) revert UUPSUnsupportedProxiableUUID(slot);
    // EIP-1967 upgrade.
    require(newImpl.code.length > 0);
    assembly { sstore(IMPL, newImpl) }
    emit Upgraded(newImpl);
    if (data.length > 0) {
      (bool ok2, ) = newImpl.delegatecall(data);
      if (!ok2) { assembly { returndatacopy(0, 0, returndatasize()) revert(0, returndatasize()) } }
    }
  }
}`;
const V1_SOL = V_SOL('value', '1');
const V2_SOL = V_SOL('value * 2', '2');

const NO_UUID_SOL = `contract NoUuid { function ping() external pure returns (uint256) { return 42; } }`;
const WRONG_UUID_SOL = `contract WrongUuid { function proxiableUUID() external pure returns (bytes32) { return bytes32(uint256(0x${WRONG_SLOT.toString(16)})); } }`;

const PROXY_SOL = `contract P {
  bytes32 constant IMPL = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
  event Upgraded(address indexed implementation);
  constructor(address impl, address owner, uint256 initVal) {
    require(impl.code.length > 0);
    assembly { sstore(IMPL, impl) }
    emit Upgraded(impl);
    bytes memory initData = abi.encodeWithSelector(bytes4(0x${INIT_SEL}), owner, initVal);
    (bool ok, ) = impl.delegatecall(initData);
    if (!ok) { assembly { returndatacopy(0, 0, returndatasize()) revert(0, returndatasize()) } }
  }
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

function jethCtorArgs(impl: Address, owner: Address, initVal: bigint): string {
  return W(BigInt(impl.toString())) + W(BigInt(owner.toString())) + W(initVal);
}
function solCtorArgs(impl: Address, owner: Address, initVal: bigint): string {
  return W(BigInt(impl.toString())) + W(BigInt(owner.toString())) + W(initVal);
}

/** upgradeToAndCall(address,bytes) calldata with arbitrary data bytes (default empty). */
function upgradeCall(newImpl: Address, data = '0x'): string {
  const d = strip(data);
  const dlen = d.length / 2;
  const dpad = d + '0'.repeat((64 - (d.length % 64)) % 64);
  return '0x' + UPGRADE_TO_AND_CALL + W(BigInt(newImpl.toString())) + W(0x40n) + W(BigInt(dlen)) + dpad;
}

function addrFromWord(returnHex: string): Address {
  const h = strip(returnHex);
  return new Address(hexToBytes(('0x' + h.slice(24, 64)) as `0x${string}`));
}

async function setup(initVal: bigint) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const v1j = await hj.deploy(compile(V1_JETH, { fileName: 'V1.jeth' }).creationBytecode);
  const v2j = await hj.deploy(compile(V2_JETH, { fileName: 'V2.jeth' }).creationBytecode);
  const v1s = await hs.deploy(compileSolidity(SPDX + V1_SOL, 'V').creation);
  const v2s = await hs.deploy(compileSolidity(SPDX + V2_SOL, 'V').creation);
  const pjBuild = compile(PROXY_JETH, { fileName: 'P.jeth' });
  const psBuild = compileSolidity(SPDX + PROXY_SOL, 'P');
  // The proxy's init delegatecall runs initialize(OWNER, initVal) -> owner = OWNER (so OWNER can upgrade).
  const pj = await hj.deploy(pjBuild.creationBytecode + jethCtorArgs(v1j, OWNER, initVal));
  const ps = await hs.deploy(psBuild.creation + solCtorArgs(v1s, OWNER, initVal));
  return { hj, hs, v1j, v2j, v1s, v2s, pj, ps };
}

describe('uups-proxy (Phase 2c)', () => {
  it('(1) a call routed through the plain proxy hits V1 and writes the PROXY storage (== solc)', async () => {
    const { hj, hs, v1j, v1s, pj, ps } = await setup(7n);
    const rj = await hj.call(pj, '0x' + sel('value_()'), { caller: STRANGER });
    const rs = await hs.call(ps, '0x' + sel('value_()'), { caller: STRANGER });
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(BigInt(rj.returnHex)).toBe(7n);
    // a state-writing call writes the PROXY's slot1 (value)
    await hj.call(pj, '0x' + sel('bump()'), { caller: STRANGER });
    await hs.call(ps, '0x' + sel('bump()'), { caller: STRANGER });
    expect(await readSlot(hj, pj, 1n)).toBe(await readSlot(hs, ps, 1n));
    expect(BigInt(await readSlot(hj, pj, 1n))).toBe(8n);
    // the impl's OWN storage stays untouched
    expect(BigInt(await readSlot(hj, v1j, 1n))).toBe(0n);
    expect(BigInt(await readSlot(hs, v1s, 1n))).toBe(0n);
    // the proxy's EIP-1967 impl slot == V1
    expect(await readSlot(hj, pj, IMPL_SLOT)).toBe(await readSlot(hs, ps, IMPL_SLOT));
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString()).toBe(v1j.toString());
  });

  it('(2) proxy.upgradeToAndCall(V2) by the OWNER swaps the impl + emits Upgraded(indexed V2) (== solc)', async () => {
    const { hj, hs, v2j, v2s, pj, ps } = await setup(5n);
    // before: value_() == 5 (V1)
    expect(BigInt((await hj.call(pj, '0x' + sel('value_()'))).returnHex)).toBe(5n);
    const uj = await hj.call(pj, upgradeCall(v2j), { caller: OWNER });
    const us = await hs.call(ps, upgradeCall(v2s), { caller: OWNER });
    expect(uj.success).toBe(true);
    expect(us.success).toBe(true);
    // upgradeToAndCall returns empty returndata (void)
    expect(uj.returnHex).toBe('0x');
    expect(us.returnHex).toBe('0x');
    // exactly one Upgraded(address indexed implementation): topic0 + indexed impl, no data
    expect(uj.logs.length).toBe(1);
    expect(us.logs.length).toBe(1);
    expect(uj.logs[0]!.topics[0]).toBe(UPGRADED_TOPIC);
    expect(uj.logs[0]!.topics[0]).toBe(us.logs[0]!.topics[0]);
    expect(addrFromWord(uj.logs[0]!.topics[1]!).toString()).toBe(v2j.toString());
    expect(uj.logs[0]!.data).toBe('0x');
    expect(us.logs[0]!.data).toBe('0x');
    // the proxy's impl slot now V2; behaviour swapped (value_() == 10, value preserved = 5)
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString()).toBe(v2j.toString());
    expect(await readSlot(hj, pj, IMPL_SLOT)).toBe(await readSlot(hs, ps, IMPL_SLOT));
    const vj = await hj.call(pj, '0x' + sel('value_()'), { caller: STRANGER });
    const vs = await hs.call(ps, '0x' + sel('value_()'), { caller: STRANGER });
    expect(vj.returnHex).toBe(vs.returnHex);
    expect(BigInt(vj.returnHex)).toBe(10n);
    // state preserved: slot1 (value) still 5 on both
    expect(BigInt(await readSlot(hj, pj, 1n))).toBe(5n);
    expect(await readSlot(hj, pj, 1n)).toBe(await readSlot(hs, ps, 1n));
  });

  it('(2b) upgradeToAndCall WITH data runs the data once via delegatecall (== solc)', async () => {
    const { hj, hs, v2j, v2s, pj, ps } = await setup(10n);
    const bumpData = '0x' + sel('bump()');
    const uj = await hj.call(pj, upgradeCall(v2j, bumpData), { caller: OWNER });
    const us = await hs.call(ps, upgradeCall(v2s, bumpData), { caller: OWNER });
    expect(uj.success).toBe(true);
    expect(us.success).toBe(true);
    // value went 10 -> 11 exactly once (the data bump ran once via delegatecall through the proxy)
    expect(BigInt(await readSlot(hj, pj, 1n))).toBe(11n);
    expect(await readSlot(hj, pj, 1n)).toBe(await readSlot(hs, ps, 1n));
    expect(uj.logs.length).toBe(1); // exactly one Upgraded
    expect(us.logs.length).toBe(1);
  });

  it('(3) an UNAUTHORIZED upgrade (non-owner) reverts via authorizeUpgrade, bytes-identical (== solc)', async () => {
    const { hj, hs, v2j, v2s, pj, ps } = await setup(3n);
    const uj = await hj.call(pj, upgradeCall(v2j), { caller: STRANGER });
    const us = await hs.call(ps, upgradeCall(v2s), { caller: STRANGER });
    expect(uj.success).toBe(false);
    expect(us.success).toBe(false);
    // identical Error("not authorized") revert payload
    expect(uj.returnHex).toBe(us.returnHex);
    // the impl slot is UNCHANGED (authorizeUpgrade ran first, before any sstore)
    expect(addrFromWord(await readSlot(hj, pj, IMPL_SLOT)).toString()).toBe(
      addrFromWord(await readSlot(hs, ps, IMPL_SLOT)).toString(),
    );
    // no Upgraded event emitted
    expect(uj.logs.length).toBe(0);
    expect(us.logs.length).toBe(0);
  });

  it('(4a) ANTI-BRICK: upgrade to an impl WITHOUT proxiableUUID reverts ERC1967InvalidImplementation (== solc)', async () => {
    const { hj, hs, pj, ps } = await setup(2n);
    const noUuidJ = await hj.deploy(compile(NO_UUID_JETH, { fileName: 'N.jeth' }).creationBytecode);
    const noUuidS = await hs.deploy(compileSolidity(SPDX + NO_UUID_SOL, 'NoUuid').creation);
    const uj = await hj.call(pj, upgradeCall(noUuidJ), { caller: OWNER });
    const us = await hs.call(ps, upgradeCall(noUuidS), { caller: OWNER });
    expect(uj.success).toBe(false);
    expect(us.success).toBe(false);
    // revert = ERC1967InvalidImplementation(address) selector + the new impl address word. The address
    // arg necessarily differs (each harness deploys NoUuid at its own address), so we assert each side
    // encodes ITS OWN new-impl address, and the selector + length + structure match byte-for-byte.
    expect(uj.returnHex.startsWith('0x' + ERC1967_INVALID_IMPL)).toBe(true);
    expect(us.returnHex.startsWith('0x' + ERC1967_INVALID_IMPL)).toBe(true);
    expect(addrFromWord('0x' + strip(uj.returnHex).slice(8)).toString()).toBe(noUuidJ.toString());
    expect(addrFromWord('0x' + strip(us.returnHex).slice(8)).toString()).toBe(noUuidS.toString());
    expect(strip(uj.returnHex).length).toBe(strip(us.returnHex).length); // selector + one word = 4+32 bytes
    expect(strip(uj.returnHex).length).toBe((4 + 32) * 2);
    expect(strip(uj.returnHex).slice(0, 8)).toBe(strip(us.returnHex).slice(0, 8)); // identical selector
    // when the two harnesses deploy NoUuid at the SAME address, the revert is byte-identical
    if (noUuidJ.toString().toLowerCase() === noUuidS.toString().toLowerCase()) {
      expect(uj.returnHex.toLowerCase()).toBe(us.returnHex.toLowerCase());
    }
    // impl slot unchanged on both (still V1)
    expect(await readSlot(hj, pj, IMPL_SLOT)).not.toBe(W(BigInt(noUuidJ.toString())));
  });

  it('(4b) ANTI-BRICK: upgrade to an impl whose proxiableUUID returns a WRONG slot reverts UUPSUnsupportedProxiableUUID(slot) (== solc)', async () => {
    const { hj, hs, pj, ps } = await setup(2n);
    const wrongJ = await hj.deploy(compile(WRONG_UUID_JETH, { fileName: 'W.jeth' }).creationBytecode);
    const wrongS = await hs.deploy(compileSolidity(SPDX + WRONG_UUID_SOL, 'WrongUuid').creation);
    const uj = await hj.call(pj, upgradeCall(wrongJ), { caller: OWNER });
    const us = await hs.call(ps, upgradeCall(wrongS), { caller: OWNER });
    expect(uj.success).toBe(false);
    expect(us.success).toBe(false);
    // revert = UUPSUnsupportedProxiableUUID(bytes32) selector + the WRONG slot value (identical on both)
    const expected = '0x' + UUPS_UNSUPPORTED + W(WRONG_SLOT).toLowerCase();
    expect(uj.returnHex.toLowerCase()).toBe(expected);
    expect(us.returnHex.toLowerCase()).toBe(expected);
    expect(uj.returnHex).toBe(us.returnHex);
  });

  it('(5) proxiableUUID() returns the EIP-1967 impl slot constant (== solc)', async () => {
    const { hj, hs, pj, ps } = await setup(9n);
    const rj = await hj.call(pj, '0x' + PROXIABLE_UUID, { caller: STRANGER });
    const rs = await hs.call(ps, '0x' + PROXIABLE_UUID, { caller: STRANGER });
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(BigInt(rj.returnHex)).toBe(IMPL_SLOT);
  });

  it('(5b) the impl contract itself exposes proxiableUUID() (direct call == the slot)', async () => {
    const { hj, v1j } = await setup(1n);
    const r = await hj.call(v1j, '0x' + PROXIABLE_UUID, { caller: STRANGER });
    expect(r.success).toBe(true);
    expect(BigInt(r.returnHex)).toBe(IMPL_SLOT);
  });

  it('(6) GATE: @uups WITHOUT authorizeUpgrade is rejected (JETH402)', () => {
    const src = `@uups @contract class L { @state v: u256 = 0n; @external f(): void { this.v = 1n; } }`;
    expect(jethCodes(src)).toContain('JETH402');
  });

  it('(6b) GATE: @uups + @proxy rejected (JETH404); a user upgradeToAndCall/proxiableUUID rejected (JETH403)', () => {
    expect(jethCodes(`@uups @proxy class L { authorizeUpgrade(n: address): void {} }`)).toContain('JETH404');
    expect(
      jethCodes(`@uups @contract class L { authorizeUpgrade(n: address): void {} @external upgradeToAndCall(n: address, d: bytes): void {} }`),
    ).toContain('JETH403');
    expect(
      jethCodes(`@uups @contract class L { authorizeUpgrade(n: address): void {} @external @view proxiableUUID(): bytes32 { return 0x0n as bytes32; } }`),
    ).toContain('JETH403');
    // an authorizeUpgrade with a wrong param type / @external visibility is NOT a valid gate -> JETH402
    expect(jethCodes(`@uups @contract class L { authorizeUpgrade(n: u256): void {} }`)).toContain('JETH402');
    expect(jethCodes(`@uups @contract class L { @external authorizeUpgrade(n: address): void {} }`)).toContain('JETH402');
  });

  it('(6c) GATE: a valid @uups impl with a bare-internal authorizeUpgrade compiles', () => {
    expect(jethAccepts(V1_JETH)).toBe(true);
    expect(jethAccepts(V2_JETH)).toBe(true);
  });
});
