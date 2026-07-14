// IFACE-STRUCT-FIELD (JETH013 lift): an @interface / native-interface name used as a STRUCT FIELD type.
// solc treats an interface field as `address` (20-byte, 160-bit-masked storage / packing / ABI), so JETH
// lowers it THROUGH the branded `address` kind exactly as an interface state var / param does
// (IFACE-VALUE-TYPE). The fix populates the interface-name table before struct-field resolution.
//
// Each row deploys a JETH contract and the solc mirror against the SAME solc `Impl` target and diffs
// success + returndata + raw storage. The interface field is packed adjacent to a u96 to prove the
// 20-byte slot sharing is byte-identical, set from a DIRTY-high-bits address to prove masking, and used
// for dispatch (p.a.m()). The negatives that must STILL reject (no over-acceptance) are pinned to solc.
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

const IMPL = `contract Impl {
  uint256 public v;
  function read() external view returns(uint256){ return 42; }
  function bump(uint256 x) external returns(uint256){ v = x; return x + 1000; }
}`;

describe('IFACE-STRUCT-FIELD: an interface name as a struct field type', () => {
  it('packs at 20 bytes with an adjacent u96, masks a dirty address, dispatches, byte-identical storage', async () => {
    const h = await Harness.create();
    const rd = async (a: Awaited<ReturnType<Harness['deploy']>>, slot: number) => {
      const t = toHex(await h.evm.stateManager.getStorage(a, keyB(slot)));
      return pad32(t && t !== '0x' ? BigInt(t) : 0n);
    };
    const impl = await h.deploy(compileSolidity(SPDX + IMPL, 'Impl').creation);
    const clean = pad32(BigInt(impl.toString())).replace(/^0x/, '');
    const dirty = 'ffffffffffffffffffffffff' + impl.toString().slice(2);

    // P = { a: I; n: u96 } -> `a`(address, 20B) + `n`(u96, 12B) share slot 0 (struct base). The whole
    // struct P is a single state var `p` at slot 0.
    const J = `interface I { read(): View<u256>; bump(x: u256): u256; }
type P = { a: I; n: u96 };
class C {
  p: P;
  seta(x: address): External<void> { this.p.a = I(x); }
  setn(k: u96): External<void> { this.p.n = k; }
  get who(): External<address> { return address(this.p.a); }
  get getn(): External<u96> { return this.p.n; }
  get geti(): External<I> { return this.p.a; }
  get callRead(): External<u256> { return this.p.a.read(); }
  callBump(x: u256): External<u256> { return this.p.a.bump(x); }
}`;
    const S = `interface I { function read() external view returns(uint256); function bump(uint256 x) external returns(uint256); }
contract C {
  struct P { I a; uint96 n; }
  P p;
  function seta(address x) external { p.a = I(x); }
  function setn(uint96 k) external { p.n = k; }
  function who() external view returns(address){ return address(p.a); }
  function getn() external view returns(uint96){ return p.n; }
  function geti() external view returns(I){ return p.a; }
  function callRead() external view returns(uint256){ return p.a.read(); }
  function callBump(uint256 x) external returns(uint256){ return p.a.bump(x); }
}`;
    expect(accepts(J)).toBe(true);
    const cj = await h.deploy(bc(J));
    const cs = await h.deploy(compileSolidity(SPDX + S, 'C').creation);

    // dirty high bits in the address arg word -> BOTH revert identically (solc validates address params)
    {
      const dj = await h.call(cj, sel('seta(address)') + dirty);
      const ds = await h.call(cs, sel('seta(address)') + dirty);
      expect(dj.success).toBe(false);
      expect(dj.success).toBe(ds.success);
      expect(dj.returnHex).toBe(ds.returnHex);
    }
    // set the interface field from a CLEAN address: storage masking + address(this.p.a) getter
    await h.call(cj, sel('seta(address)') + clean);
    await h.call(cs, sel('seta(address)') + clean);
    // set the adjacent u96: must land in the SAME slot 0 without disturbing the address bytes
    await h.call(cj, sel('setn(uint96)') + W(0xABCDn));
    await h.call(cs, sel('setn(uint96)') + W(0xABCDn));
    // RAW STORAGE slot 0 compare: the packed (a | n<<160) word must match solc bit-for-bit
    expect(await rd(cj, 0)).toBe(await rd(cs, 0));

    const [wj, ws] = [await h.call(cj, sel('who()')), await h.call(cs, sel('who()'))];
    expect(wj.returnHex).toBe(ws.returnHex);
    expect(wj.returnHex.replace(/^0x/, '').toLowerCase()).toBe(clean.toLowerCase());
    // the adjacent u96 getter reads back cleanly (packing did not corrupt it)
    expect((await h.call(cj, sel('getn()'))).returnHex).toBe((await h.call(cs, sel('getn()'))).returnHex);
    expect(BigInt((await h.call(cj, sel('getn()'))).returnHex)).toBe(0xABCDn);
    // interface-typed getter returns the masked address
    expect((await h.call(cj, sel('geti()'))).returnHex).toBe((await h.call(cs, sel('geti()'))).returnHex);
    // STATICCALL through the interface field
    const [rrj, rrs] = [await h.call(cj, sel('callRead()')), await h.call(cs, sel('callRead()'))];
    expect(rrj.returnHex).toBe(rrs.returnHex);
    expect(BigInt(rrj.returnHex)).toBe(42n);
    // CALL through the interface field (mutates the callee identically)
    const [bj, bs] = [await h.call(cj, sel('callBump(uint256)') + W(9)), await h.call(cs, sel('callBump(uint256)') + W(9))];
    expect(bj.returnHex).toBe(bs.returnHex);
    expect(await rd(impl, 0)).toBe(W(9));
  });

  it('an @interface (decorator) name as a struct field behaves identically to the native form', async () => {
    const h = await Harness.create();
    const impl = await h.deploy(compileSolidity(SPDX + IMPL, 'Impl').creation);
    const A = pad32(BigInt(impl.toString())).replace(/^0x/, '');
    const J = `interface I { read(): View<u256>; }
type P = { a: I; n: u256 };
class C { p: P; seta(x: address): External<void> { this.p.a = I(x); } get callk(): External<u256> { return this.p.a.read(); } }`;
    const S = `interface I { function read() external view returns(uint256); }
contract C { struct P { I a; uint256 n; } P p; function seta(address x) external { p.a = I(x); } function callk() external view returns(uint256){ return p.a.read(); } }`;
    expect(accepts(J)).toBe(true);
    const cj = await h.deploy(bc(J));
    const cs = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(cj, sel('seta(address)') + A);
    await h.call(cs, sel('seta(address)') + A);
    expect((await h.call(cj, sel('callk()'))).returnHex).toBe((await h.call(cs, sel('callk()'))).returnHex);
  });

  it('the struct-field lowering matches an equivalent PLAIN-address field bit-for-bit (creation bytecode)', () => {
    // An interface struct field is JUST a branded address: replacing `a: I` with `a: address` (and the
    // dispatch site with an inline cast-call) must produce identical creation bytecode.
    const iface = `interface I { read(): View<u256>; }
type P = { a: I; n: u96 };
class C { p: P; set(x: address): External<void> { this.p.a = I(x); } get r(): External<u256> { return this.p.a.read(); } get who(): External<address> { return address(this.p.a); } }`;
    const addr = `interface I { read(): View<u256>; }
type P = { a: address; n: u96 };
class C { p: P; set(x: address): External<void> { this.p.a = x; } get r(): External<u256> { return I(this.p.a).read(); } get who(): External<address> { return this.p.a; } }`;
    expect(accepts(iface)).toBe(true);
    expect(accepts(addr)).toBe(true);
    expect(bc(iface)).toBe(bc(addr));
  });

  it('does NOT over-accept: a LIBRARY name as a struct field still rejects (only interfaces lift)', () => {
    // solc: a library type is NOT a value type, so it cannot be a struct member.
    expect(bothReject(
      `static class L { static f(x: u256): u256 { return x; } }
type P = { a: L; n: u256 };
class C { p: P; get f(): External<u256> { return this.p.n; } }`,
      `library L { function f(uint256 x) internal pure returns(uint256){ return x; } }
contract C { struct P { L a; uint256 n; } P p; function f() external view returns(uint256){ return p.n; } }`,
    )).toBe(true);
    // a plain address is NOT assignable to an interface struct field without an I(...) conversion
    expect(bothReject(
      `interface I { m(): View<u256>; } type P = { a: I }; class C { p: P; set(x: address): External<void> { this.p.a = x; } }`,
      `interface I { function m() external view returns(uint256); } contract C { struct P { I a; } P p; function set(address x) external { p.a = x; } }`,
    )).toBe(true);
    // a method not declared by the interface, called through the field
    expect(bothReject(
      `interface I { m(): View<u256>; } type P = { a: I }; class C { p: P; get f(): External<u256> { return this.p.a.z(); } }`,
      `interface I { function m() external view returns(uint256); } contract C { struct P { I a; } P p; function f() external view returns(uint256){ return p.a.z(); } }`,
    )).toBe(true);
    // an interface field does NOT implicitly convert to an integer
    expect(bothReject(
      `interface I { m(): View<u256>; } type P = { a: I; n: u256 }; class C { p: P; get f(): External<u256> { return this.p.a; } }`,
      `interface I { function m() external view returns(uint256); } contract C { struct P { I a; uint256 n; } P p; function f() external view returns(uint256){ return p.a; } }`,
    )).toBe(true);
    // an UNKNOWN name as a struct field still rejects (the lift did not open a hole for arbitrary names)
    expect(bothReject(
      `type P = { a: Nope; n: u256 }; class C { p: P; get f(): External<u256> { return this.p.n; } }`,
      `contract C { struct P { Nope a; uint256 n; } P p; function f() external view returns(uint256){ return p.n; } }`,
    )).toBe(true);
  });
});
