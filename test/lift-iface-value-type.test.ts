// IFACE-VALUE-TYPE (JETH013 lift): an @interface name is a first-class VALUE type (field / param /
// return / local / mapping-value / array-element), lowered THROUGH `address` (20-byte, 160-bit-masked
// storage / ABI / packing) carrying the interface name as its nominal brand. A method call on such a
// value routes to the SAME external-call lowering the inline `IFoo(addr).m()` cast-call uses.
//
// Each row deploys a JETH caller and a solc caller against the SAME solc `Impl` target and diffs
// success + returndata + raw storage. The inline-vs-variable dispatch is ALSO proven byte-identical at
// the BYTECODE level (same contract, one method inline, one via a let-bound interface local). The
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

const IMPL = `contract Impl {
  uint256 public v;
  function read() external view returns(uint256){ return 42; }
  function bump(uint256 x) external returns(uint256){ v = x; return x + 1000; }
  function pair() external view returns(uint256,uint256){ return (11,22); }
}`;

describe('IFACE-VALUE-TYPE: an interface name as a first-class value type', () => {
  it('stores / masks / packs / dispatches byte-identically to solc, and reverts on dirty address bits', async () => {
    const h = await Harness.create();
    const rd = async (a: Awaited<ReturnType<Harness['deploy']>>, slot: number) => {
      const t = toHex(await h.evm.stateManager.getStorage(a, keyB(slot)));
      return pad32(t && t !== '0x' ? BigInt(t) : 0n);
    };
    const impl = await h.deploy(compileSolidity(SPDX + IMPL, 'Impl').creation);
    const clean = pad32(BigInt(impl.toString())).replace(/^0x/, '');
    const dirty = 'ffffffffffffffffffffffff' + impl.toString().slice(2);

    const J = `interface I { read(): View<u256>; bump(x: u256): u256; }
class C {
  a: u96;
  i: I;
  set(x: address): External<void> { this.i = I(x); }
  seta(n: u96): External<void> { this.a = n; }
  get who(): External<address> { return address(this.i); }
  get geta(): External<u96> { return this.a; }
  get geti(): External<I> { return this.i; }
  get callRead(): External<u256> { return this.i.read(); }
  callBump(x: u256): External<u256> { return this.i.bump(x); }
  get passThrough(j: I): External<address> { return address(j); }
  get callVia(j: I): External<u256> { return j.read(); }
}`;
    const S = `interface I { function read() external view returns(uint256); function bump(uint256 x) external returns(uint256); }
contract C {
  uint96 a;
  I i;
  function set(address x) external { i = I(x); }
  function seta(uint96 n) external { a = n; }
  function who() external view returns(address){ return address(i); }
  function geta() external view returns(uint96){ return a; }
  function geti() external view returns(I){ return i; }
  function callRead() external view returns(uint256){ return i.read(); }
  function callBump(uint256 x) external returns(uint256){ return i.bump(x); }
  function passThrough(I j) external pure returns(address){ return address(j); }
  function callVia(I j) external view returns(uint256){ return j.read(); }
}`;
    expect(accepts(J)).toBe(true);
    const cj = await h.deploy(bc(J));
    const cs = await h.deploy(compileSolidity(SPDX + S, 'C').creation);

    // dirty high bits in the address arg word -> BOTH revert identically (solc validates address params)
    {
      const dj = await h.call(cj, sel('set(address)') + dirty);
      const ds = await h.call(cs, sel('set(address)') + dirty);
      expect(dj.success).toBe(false);
      expect(dj.success).toBe(ds.success);
      expect(dj.returnHex).toBe(ds.returnHex);
    }
    // set from a CLEAN address: storage-slot masking + address(this.i) getter
    await h.call(cj, sel('set(address)') + clean);
    await h.call(cs, sel('set(address)') + clean);
    expect(await rd(cj, 1)).toBe(await rd(cs, 1));
    const [wj, ws] = [await h.call(cj, sel('who()')), await h.call(cs, sel('who()'))];
    expect(wj.returnHex).toBe(ws.returnHex);
    expect(wj.returnHex.replace(/^0x/, '').toLowerCase()).toBe(pad32(BigInt(impl.toString())).replace(/^0x/, '').toLowerCase());
    // STATICCALL through the stored interface
    const [rrj, rrs] = [await h.call(cj, sel('callRead()')), await h.call(cs, sel('callRead()'))];
    expect(rrj.returnHex).toBe(rrs.returnHex);
    expect(BigInt(rrj.returnHex)).toBe(42n);
    // CALL through the stored interface (mutates the callee's state identically)
    const [bj, bs] = [await h.call(cj, sel('callBump(uint256)') + W(7)), await h.call(cs, sel('callBump(uint256)') + W(7))];
    expect(bj.returnHex).toBe(bs.returnHex);
    expect(await rd(impl, 0)).toBe(W(7));
    // packed slot0: a(u96) + i(address) share slot 0 (20-byte packing, byte-identical layout)
    await h.call(cj, sel('seta(uint96)') + W(0x1234));
    await h.call(cs, sel('seta(uint96)') + W(0x1234));
    expect(await rd(cj, 0)).toBe(await rd(cs, 0));
    expect((await h.call(cj, sel('geta()'))).returnHex).toBe((await h.call(cs, sel('geta()'))).returnHex);
    expect((await h.call(cj, sel('geti()'))).returnHex).toBe((await h.call(cs, sel('geti()'))).returnHex);
    // interface-typed param + return, and interface-typed param used for dispatch
    expect((await h.call(cj, sel('passThrough(address)') + clean)).returnHex)
      .toBe((await h.call(cs, sel('passThrough(address)') + clean)).returnHex);
    expect((await h.call(cj, sel('callVia(address)') + clean)).returnHex)
      .toBe((await h.call(cs, sel('callVia(address)') + clean)).returnHex);
  });

  it('variable dispatch reuses the inline cast-call lowering VERBATIM (byte-identical bytecode)', () => {
    const inline = `interface I { read(): View<u256>; }\nclass C { get f(x: address): External<u256> { return I(x).read(); } }`;
    const variable = `interface I { read(): View<u256>; }\nclass C { get f(x: address): External<u256> { let j: I = I(x); return j.read(); } }`;
    expect(accepts(inline)).toBe(true);
    expect(accepts(variable)).toBe(true);
    expect(bc(inline)).toBe(bc(variable));
    // same for a tuple-returning method
    const inlineT = `interface I { pair(): View<[u256,u256]>; }\nclass C { get f(x: address): External<u256> { let [a,b] = I(x).pair(); return a+b; } }`;
    const varT = `interface I { pair(): View<[u256,u256]>; }\nclass C { get f(x: address): External<u256> { let j: I = I(x); let [a,b] = j.pair(); return a+b; } }`;
    expect(bc(inlineT)).toBe(bc(varT));
  });

  it('dispatches through a mapping value, an array element, and a tuple destructure (byte-identical)', async () => {
    const h = await Harness.create();
    const impl = await h.deploy(compileSolidity(SPDX + IMPL, 'Impl').creation);
    const A = pad32(BigInt(impl.toString())).replace(/^0x/, '');

    const Jmap = `interface I { read(): View<u256>; }
class C { m: mapping<u256, I>; setm(k: u256, x: address): External<void> { this.m[k] = I(x); } get callk(k: u256): External<u256> { return this.m[k].read(); } }`;
    const Smap = `interface I { function read() external view returns(uint256); }
contract C { mapping(uint256 => I) m; function setm(uint256 k, address x) external { m[k] = I(x); } function callk(uint256 k) external view returns(uint256){ return m[k].read(); } }`;
    expect(accepts(Jmap)).toBe(true);
    const mj = await h.deploy(bc(Jmap));
    const ms = await h.deploy(compileSolidity(SPDX + Smap, 'C').creation);
    await h.call(mj, sel('setm(uint256,address)') + W(5) + A);
    await h.call(ms, sel('setm(uint256,address)') + W(5) + A);
    expect((await h.call(mj, sel('callk(uint256)') + W(5))).returnHex)
      .toBe((await h.call(ms, sel('callk(uint256)') + W(5))).returnHex);

    const Jarr = `interface I { read(): View<u256>; }
class C { xs: I[]; add(x: address): External<void> { this.xs.push(I(x)); } get calli(k: u256): External<u256> { return this.xs[k].read(); } }`;
    const Sarr = `interface I { function read() external view returns(uint256); }
contract C { I[] xs; function add(address x) external { xs.push(I(x)); } function calli(uint256 k) external view returns(uint256){ return xs[k].read(); } }`;
    expect(accepts(Jarr)).toBe(true);
    const aj = await h.deploy(bc(Jarr));
    const as = await h.deploy(compileSolidity(SPDX + Sarr, 'C').creation);
    await h.call(aj, sel('add(address)') + A);
    await h.call(as, sel('add(address)') + A);
    expect((await h.call(aj, sel('calli(uint256)') + W(0))).returnHex)
      .toBe((await h.call(as, sel('calli(uint256)') + W(0))).returnHex);

    const Jtup = `interface I { pair(): View<[u256, u256]>; }
class C { i: I; set(x: address): External<void> { this.i = I(x); } get sum(): External<u256> { let [a, b] = this.i.pair(); return a + b; } }`;
    const Stup = `interface I { function pair() external view returns(uint256,uint256); }
contract C { I i; function set(address x) external { i = I(x); } function sum() external view returns(uint256){ (uint256 a, uint256 b) = i.pair(); return a + b; } }`;
    expect(accepts(Jtup)).toBe(true);
    const tj = await h.deploy(bc(Jtup));
    const ts = await h.deploy(compileSolidity(SPDX + Stup, 'C').creation);
    await h.call(tj, sel('set(address)') + A);
    await h.call(ts, sel('set(address)') + A);
    expect((await h.call(tj, sel('sum()'))).returnHex).toBe((await h.call(ts, sel('sum()'))).returnHex);
  });

  it('does NOT over-accept: interface nominal typing rejects exactly what solc rejects', () => {
    // a plain address is NOT assignable to an interface field without an I(...) conversion
    expect(bothReject(
      `interface I { m(): View<u256>; } class C { i: I; set(a: address): External<void> { this.i = a; } }`,
      `interface I { function m() external view returns(uint256); } contract C { I i; function set(address a) external { i = a; } }`,
    )).toBe(true);
    // a DIRECT conversion between two different interfaces (needs an explicit address())
    expect(bothReject(
      `interface I1 { m(): View<u256>; } interface I2 { n(): View<u256>; } class C { a: I1; b: I2; set(): External<void> { this.b = I2(this.a); } }`,
      `interface I1 { function m() external view returns(uint256); } interface I2 { function n() external view returns(uint256); } contract C { I1 a; I2 b; function set() external { b = I2(a); } }`,
    )).toBe(true);
    // assigning one interface type to a field of a different interface type
    expect(bothReject(
      `interface I1 { m(): View<u256>; } interface I2 { n(): View<u256>; } class C { a: I1; b: I2; set(): External<void> { this.b = this.a; } }`,
      `interface I1 { function m() external view returns(uint256); } interface I2 { function n() external view returns(uint256); } contract C { I1 a; I2 b; function set() external { b = a; } }`,
    )).toBe(true);
    // a method that the interface does not declare
    expect(bothReject(
      `interface I { m(): View<u256>; } class C { i: I; get f(): External<u256> { return this.i.z(); } }`,
      `interface I { function m() external view returns(uint256); } contract C { I i; function f() external view returns(uint256){ return i.z(); } }`,
    )).toBe(true);
    // I(<non-address>) needs an explicit address() first
    expect(bothReject(
      `interface I { m(): View<u256>; } class C { get f(x: u256): External<u256> { return I(x).m(); } }`,
      `interface I { function m() external view returns(uint256); } contract C { function f(uint256 x) external view returns(uint256){ return I(x).m(); } }`,
    )).toBe(true);
    // an interface value does NOT implicitly convert to an integer
    expect(bothReject(
      `interface I { m(): View<u256>; } class C { a: I; get f(): External<u256> { return this.a; } }`,
      `interface I { function m() external view returns(uint256); } contract C { I a; function f() external view returns(uint256){ return a; } }`,
    )).toBe(true);
    // the bare conversion is a value, not a call target for { value }; options need a method call
    expect(accepts(`interface I { m(): Payable<u256>; } class C { get f(a: address): External<u256> { let j: I = I(a, { value: 1n }); return j.m(); } }`)).toBe(false);
  });
});
