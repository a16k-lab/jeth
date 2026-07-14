// CONTRACT-TYPE-VALUE (JETH013 lift): a CONCRETE / ABSTRACT contract name is a first-class VALUE type
// (field / param / return / local / immutable), lowered THROUGH `address` (20-byte, 160-bit-masked
// storage / ABI / packing) carrying the contract name as a nominal `__ctref:<Name>` brand. solc treats a
// contract-typed value NOMINALLY: only `address(c)` (unwrap) and the declared value operations
// (assignment of the same type, ==, !=, <, <=, >, >=, abi.encode, a public getter) are allowed. The raw
// address capability surface (.balance / .code / .codehash / .call / .staticcall / .send / .transfer),
// an implicit contract<->address conversion, a uN()/bytesN()/payable() cast, and a cross-contract-type
// assignment ALL stay REJECTED (they are over-acceptances if the address machinery lets them through).
//
// Each accept row deploys a JETH `C` and a solc `C` and diffs success + returndata + raw storage. The
// negatives that must STILL reject (no over-acceptance) are pinned against solc reject-parity.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const accepts = (src: string): boolean => {
  try { compile(src, { fileName: 'C.jeth' }); return true; } catch (e) {
    if (e instanceof CompileError) return false; throw e;
  }
};
const bothReject = (j: string, s: string): boolean => {
  const jr = !accepts(j);
  let sr = false;
  try { compileSolidity(SPDX + s, 'C'); } catch { sr = true; }
  return jr && sr;
};
const toHex = (u: Uint8Array) => '0x' + Array.from(u).map((b) => b.toString(16).padStart(2, '0')).join('');
const keyB = (slot: number | bigint) => {
  const x = pad32(BigInt(slot)).replace(/^0x/, '');
  const u = new Uint8Array(32);
  for (let i = 0; i < 32; i++) u[i] = parseInt(x.substr(i * 2, 2), 16);
  return u;
};

describe('CONTRACT-TYPE-VALUE: a concrete/abstract contract name as a first-class value type', () => {
  it('stores / masks / packs / returns byte-identically to solc, and reverts on dirty address bits', async () => {
    const h = await Harness.create();
    const rd = async (a: Awaited<ReturnType<Harness['deploy']>>, slot: number) =>
      toHex(await h.evm.stateManager.getStorage(a, keyB(slot)));
    const impl = await h.deploy(compileSolidity(SPDX + 'contract Impl { }', 'Impl').creation);
    const clean = pad32(BigInt(impl.toString())).replace(/^0x/, '');
    const dirty = 'ffffffffffffffffffffffff' + impl.toString().slice(2);

    const J = `class C {
  a: u96;
  c: C;
  set(x: C): External<void> { this.c = x; }
  seta(n: u96): External<void> { this.a = n; }
  get who(): External<address> { return address(this.c); }
  get geta(): External<u96> { return this.a; }
  get getc(): External<C> { return this.c; }
  get passT(x: C): External<address> { return address(x); }
}`;
    const S = `contract C {
  uint96 a;
  C c;
  function set(C x) external { c = x; }
  function seta(uint96 n) external { a = n; }
  function who() external view returns(address){ return address(c); }
  function geta() external view returns(uint96){ return a; }
  function getc() external view returns(C){ return c; }
  function passT(C x) external pure returns(address){ return address(x); }
}`;
    expect(accepts(J)).toBe(true);
    const cj = await h.deploy(bc(J));
    const cs = await h.deploy(compileSolidity(SPDX + S, 'C').creation);

    // dirty high bits in the address-typed arg word -> BOTH revert identically (solc validates the C param)
    {
      const dj = await h.call(cj, sel('set(address)') + dirty);
      const ds = await h.call(cs, sel('set(address)') + dirty);
      expect(dj.success).toBe(false);
      expect(dj.success).toBe(ds.success);
      expect(dj.returnHex).toBe(ds.returnHex);
    }
    // clean set: 20-byte storage packing + address(this.c) getter + whole contract-value getter
    await h.call(cj, sel('set(address)') + clean);
    await h.call(cs, sel('set(address)') + clean);
    expect(await rd(cj, 0)).toBe(await rd(cs, 0));
    expect((await h.call(cj, sel('who()'))).returnHex).toBe((await h.call(cs, sel('who()'))).returnHex);
    expect((await h.call(cj, sel('getc()'))).returnHex).toBe((await h.call(cs, sel('getc()'))).returnHex);
    // the stored address round-trips to the seeded impl address (non-vacuous)
    expect((await h.call(cj, sel('who()'))).returnHex.replace(/^0x0*/, '')).toBe(impl.toString().slice(2).toLowerCase());

    // packed slot0: a(u96) + c(address) share slot 0 (byte-identical 20-byte packing)
    await h.call(cj, sel('seta(uint96)') + W(0x1234));
    await h.call(cs, sel('seta(uint96)') + W(0x1234));
    expect(await rd(cj, 0)).toBe(await rd(cs, 0));
    expect((await h.call(cj, sel('geta()'))).returnHex).toBe((await h.call(cs, sel('geta()'))).returnHex);

    // contract-typed param: clean passes through, dirty reverts identically
    expect((await h.call(cj, sel('passT(address)') + clean)).returnHex)
      .toBe((await h.call(cs, sel('passT(address)') + clean)).returnHex);
    {
      const dj = await h.call(cj, sel('passT(address)') + dirty);
      const ds = await h.call(cs, sel('passT(address)') + dirty);
      expect(dj.success).toBe(false);
      expect(dj.success).toBe(ds.success);
    }
  });

  it('compares (== != < <=), abi.encodes, and exposes a Visible<C> getter byte-identically', async () => {
    const h = await Harness.create();
    const rd = async (a: Awaited<ReturnType<Harness['deploy']>>, slot: number) =>
      toHex(await h.evm.stateManager.getStorage(a, keyB(slot)));
    const i1 = await h.deploy(compileSolidity(SPDX + 'contract Impl { }', 'Impl').creation);
    const i2 = await h.deploy(compileSolidity(SPDX + 'contract I2 { }', 'I2').creation);
    const A1 = pad32(BigInt(i1.toString())).replace(/^0x/, '');
    const A2 = pad32(BigInt(i2.toString())).replace(/^0x/, '');

    const J = `class C {
  a: C; b: C; z: Visible<C>;
  seta(x: C): External<void> { this.a = x; }
  setb(x: C): External<void> { this.b = x; }
  setz(x: C): External<void> { this.z = x; }
  get lt(): External<bool> { return this.a < this.b; }
  get le(): External<bool> { return this.a <= this.b; }
  get eqf(): External<bool> { return this.a == this.b; }
  get nef(): External<bool> { return this.a != this.b; }
  get enc(): External<bytes> { return abi.encode(this.a); }
}`;
    const S = `contract C {
  C a; C b; C public z;
  function seta(C x) external { a = x; }
  function setb(C x) external { b = x; }
  function setz(C x) external { z = x; }
  function lt() external view returns(bool){ return a < b; }
  function le() external view returns(bool){ return a <= b; }
  function eqf() external view returns(bool){ return a == b; }
  function nef() external view returns(bool){ return a != b; }
  function enc() external view returns(bytes memory){ return abi.encode(a); }
}`;
    expect(accepts(J)).toBe(true);
    const cj = await h.deploy(bc(J));
    const cs = await h.deploy(compileSolidity(SPDX + S, 'C').creation);

    for (const [fn, addr] of [['seta(address)', A1], ['setb(address)', A2], ['setz(address)', A1]] as const) {
      await h.call(cj, sel(fn) + addr);
      await h.call(cs, sel(fn) + addr);
    }
    expect(await rd(cj, 0)).toBe(await rd(cs, 0));
    expect(await rd(cj, 1)).toBe(await rd(cs, 1));
    expect(await rd(cj, 2)).toBe(await rd(cs, 2));
    for (const fn of ['lt()', 'le()', 'eqf()', 'nef()', 'enc()', 'z()']) {
      expect((await h.call(cj, sel(fn))).returnHex).toBe((await h.call(cs, sel(fn))).returnHex);
    }
    // equal case (a == b): all comparisons flip identically
    await h.call(cj, sel('setb(address)') + A1);
    await h.call(cs, sel('setb(address)') + A1);
    for (const fn of ['lt()', 'le()', 'eqf()', 'nef()']) {
      expect((await h.call(cj, sel(fn))).returnHex).toBe((await h.call(cs, sel(fn))).returnHex);
    }
  });

  it('an ABSTRACT contract name is a value type too (field / return, byte-identical)', async () => {
    const h = await Harness.create();
    const impl = await h.deploy(compileSolidity(SPDX + 'contract Impl { }', 'Impl').creation);
    const clean = pad32(BigInt(impl.toString())).replace(/^0x/, '');
    const J = `abstract class D { foo(): External<void> {} }
class C extends D { d: D; set(x: D): External<void> { this.d = x; } get who(): External<address> { return address(this.d); } }`;
    const S = `abstract contract D { function foo() external {} }
contract C is D { D d; function set(D x) external { d = x; } function who() external view returns(address){ return address(d); } }`;
    expect(accepts(J)).toBe(true);
    const cj = await h.deploy(bc(J));
    const cs = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(cj, sel('set(address)') + clean);
    await h.call(cs, sel('set(address)') + clean);
    expect((await h.call(cj, sel('who()'))).returnHex).toBe((await h.call(cs, sel('who()'))).returnHex);
  });

  it('does NOT over-accept: the raw address surface / casts / conversions stay rejected exactly like solc', () => {
    const P = (b: string) => `class C { c: C; ${b} }`;
    const SP = (b: string) => `contract C { C c; ${b} }`;
    // address capability members are NOT on a contract value (solc: use address(c).<member>)
    for (const [m, jret, sret] of [
      ['balance', 'u256', 'uint256'], ['code', 'bytes', 'bytes memory'], ['codehash', 'bytes32', 'bytes32'],
    ] as const) {
      expect(bothReject(
        P(`get f(): External<${jret}> { return this.c.${m}; }`),
        SP(`function f() external view returns(${sret}){ return c.${m}; }`),
      )).toBe(true);
    }
    // no implicit contract -> address and address -> contract
    expect(bothReject(
      P(`get f(): External<address> { let a: address = this.c; return a; }`),
      SP(`function f() external view returns(address){ address a = c; return a; }`),
    )).toBe(true);
    expect(bothReject(
      `class C { get f(a: address): External<address> { let c: C = a; return address(c); } }`,
      `contract C { function f(address a) external pure returns(address){ C c = a; return address(c); } }`,
    )).toBe(true);
    // no uN() / bytesN() / payable() cast of a contract value
    for (const [jc, sc] of [
      ['u256', 'uint256'], ['u160', 'uint160'], ['bytes20', 'bytes20'], ['bytes32', 'bytes32'],
    ] as const) {
      expect(bothReject(
        P(`get f(): External<${jc}> { return ${jc}(this.c); }`),
        SP(`function f() external view returns(${sc}){ return ${sc}(c); }`),
      )).toBe(true);
    }
    expect(bothReject(
      P(`get f(): External<address> { return payable(this.c); }`),
      SP(`function f() external view returns(address){ return payable(c); }`),
    )).toBe(true);
    // no cross-contract-type assignment (C to a different contract type D)
    expect(bothReject(
      `abstract class D {} class C extends D { c: C; d: D; set(): External<void> { this.c = this.d; } }`,
      `abstract contract D {} contract C is D { C c; D d; function set() external { c = d; } }`,
    )).toBe(true);
    // a library name is NOT a value type
    expect(bothReject(
      `static class L { g(): u256 { return 1n; } } class C { l: L; }`,
      `library L { function g() internal pure returns(uint256){ return 1; } } contract C { L l; }`,
    )).toBe(true);
  });
});
