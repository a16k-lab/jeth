// CTR-TYPE-AGG (JETH013 lift): a CONCRETE / ABSTRACT contract name is a first-class MEMBER type in the
// AGGREGATE positions - a struct field, a dynamic-array element, a fixed-array (`Arr<T,N>`) element, and a
// mapping value - exactly as an @interface name already is (IFACE-VALUE-TYPE / lift-iface-value-type). solc
// lowers a contract-typed aggregate THROUGH `address` (20-byte, 160-bit-masked storage / ABI / packing), so
// JETH resolves the member type to a `__ctref:<Name>`-branded `address`: the brand is erased at
// storage / ABI / selectors / codecs (byte-identical to the same program written with a plain `address`
// there) but keeps the value NOMINAL, so the raw address surface / a scalar-or-bytesN cast / an implicit
// contract<->address conversion / a cross-contract-type assignment ALL stay rejected even when the value is
// read OUT OF the aggregate (the exact place a naive lift would open an over-acceptance).
//
// Each accept row deploys a JETH `C` and a solc `C`, exercises them under POPULATED state, and diffs
// success + returndata + RAW STORAGE slots. Byte-identity to the plain-`address` program is proven at the
// bytecode level. The negatives that must STILL reject are pinned against solc reject-parity.
//
// NOTE (documented residual, unchanged by this lift): a METHOD CALL on a contract-ref value (`t.v()`) is a
// pre-existing gap - it is JETH074-rejected in EVERY position (value AND aggregate alike), unlike an
// interface value. solc accepts it; JETH's clean reject is a SAFE over-rejection (a contract-value dispatch
// lowering was never built). This lift only threads the TYPE brand into the aggregate positions; it does not
// add contract-value dispatch, so the gap stays consistent between the value and aggregate positions.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';
import { keccak256 } from 'ethereum-cryptography/keccak.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const accepts = (src: string): boolean => {
  try { compile(src, { fileName: 'C.jeth' }); return true; } catch (e) {
    if (e instanceof CompileError) return false; throw e;
  }
};
const rejectCodes = (src: string): string[] | null => {
  try { compile(src, { fileName: 'C.jeth' }); return null; } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e;
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
const hexToBytes = (h: string) => keyB(BigInt('0x' + h.replace(/^0x/, '')));
const arrBase = (slot: number) => BigInt('0x' + toHex(keccak256(keyB(slot))).slice(2));
const mapSlot = (keyHex: string, slot: number) => {
  const buf = new Uint8Array(64);
  buf.set(keyB(BigInt('0x' + keyHex.replace(/^0x/, ''))), 0);
  buf.set(keyB(slot), 32);
  return BigInt('0x' + toHex(keccak256(buf)).slice(2));
};

// abstract contract type T (JETH) / T (solc). C never deploys T; it only stores T-typed addresses.
const JT = 'abstract class T { @virtual v(): View<u256>; }\n';
const ST = 'abstract contract T { function v() external view virtual returns(uint256); }\n';

describe('CTR-TYPE-AGG: a concrete/abstract contract name as a struct/array/mapping member type', () => {
  it('PIN: the four aggregate positions now ACCEPT (interface already did; value positions already lifted)', () => {
    // every one of these was a JETH013 over-rejection before this lift.
    expect(accepts(JT + `type P = { t: T; n: u256 }\nclass C { p: P; get f(): External<u256> { return 0n; } }`)).toBe(true);
    expect(accepts(JT + `class C { xs: T[]; get f(): External<u256> { return 0n; } }`)).toBe(true);
    expect(accepts(JT + `class C { m: mapping<address, T>; get f(): External<u256> { return 0n; } }`)).toBe(true);
    expect(accepts(JT + `class C { xs: Arr<T, 2>; get f(): External<u256> { return 0n; } }`)).toBe(true);
    // an UNKNOWN name in the same position still rejects JETH013 (the gate is intact, not blanket-opened).
    expect(rejectCodes(`class C { xs: Nope[]; get f(): External<u256> { return 0n; } }`)).toContain('JETH013');
  });

  it('struct field (packed with a u96 neighbor): storage / getter / abi.encode byte-identical to solc', async () => {
    const h = await Harness.create();
    const rd = async (a: Awaited<ReturnType<Harness['deploy']>>, slot: number) =>
      toHex(await h.evm.stateManager.getStorage(a, keyB(slot)));
    const impl = await h.deploy(compileSolidity(SPDX + 'contract Impl { }', 'Impl').creation);
    const clean = pad32(BigInt(impl.toString())).replace(/^0x/, '');

    const J = JT + `type P = { t: T; n: u96 }
class C {
  p: P;
  set(x: T, n: u96): External<void> { this.p = { t: x, n }; }
  get gt(): External<address> { return address(this.p.t); }
  get gn(): External<u96> { return this.p.n; }
  setn(n: u96): External<void> { this.p.n = n; }
  get enc(): External<bytes> { return abi.encode(this.p.t); }
}`;
    const S = ST + `contract C {
  struct P { T t; uint96 n; }
  P p;
  function set(T x, uint96 n) external { p = P(x, n); }
  function gt() external view returns(address){ return address(p.t); }
  function gn() external view returns(uint96){ return p.n; }
  function setn(uint96 n) external { p.n = n; }
  function enc() external view returns(bytes memory){ return abi.encode(p.t); }
}`;
    expect(accepts(J)).toBe(true);
    // byte-identity to the plain-address program (proves storage layout / ABI / selectors / codecs).
    expect(bc(J)).toBe(bc(`type P = { t: address; n: u96 }
class C {
  p: P;
  set(x: address, n: u96): External<void> { this.p = { t: x, n }; }
  get gt(): External<address> { return this.p.t; }
  get gn(): External<u96> { return this.p.n; }
  setn(n: u96): External<void> { this.p.n = n; }
  get enc(): External<bytes> { return abi.encode(this.p.t); }
}`));
    const cj = await h.deploy(bc(J));
    const cs = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(cj, sel('set(address,uint96)') + clean + W(0xabcd));
    await h.call(cs, sel('set(address,uint96)') + clean + W(0xabcd));
    expect(await rd(cj, 0)).toBe(await rd(cs, 0)); // t (20 bytes) + n (u96) packed in slot 0
    expect((await h.call(cj, sel('gt()'))).returnHex).toBe((await h.call(cs, sel('gt()'))).returnHex);
    expect((await h.call(cj, sel('gn()'))).returnHex).toBe((await h.call(cs, sel('gn()'))).returnHex);
    expect(BigInt((await h.call(cj, sel('gt()'))).returnHex)).toBe(BigInt(impl.toString())); // non-vacuous
    expect((await h.call(cj, sel('enc()'))).returnHex).toBe((await h.call(cs, sel('enc()'))).returnHex);
    // partial overwrite of the packed neighbor must not disturb the contract-ref half
    await h.call(cj, sel('setn(uint96)') + W(0x1111));
    await h.call(cs, sel('setn(uint96)') + W(0x1111));
    expect(await rd(cj, 0)).toBe(await rd(cs, 0));
    expect((await h.call(cj, sel('gt()'))).returnHex).toBe((await h.call(cs, sel('gt()'))).returnHex);
  });

  it('dynamic array push / index / length / set / pop: raw element slots byte-identical to solc', async () => {
    const h = await Harness.create();
    const rd = async (a: Awaited<ReturnType<Harness['deploy']>>, slot: bigint) =>
      toHex(await h.evm.stateManager.getStorage(a, keyB(slot)));
    const i1 = await h.deploy(compileSolidity(SPDX + 'contract Impl { }', 'Impl').creation);
    const i2 = await h.deploy(compileSolidity(SPDX + 'contract I2 { }', 'I2').creation);
    const A1 = pad32(BigInt(i1.toString())).replace(/^0x/, '');
    const A2 = pad32(BigInt(i2.toString())).replace(/^0x/, '');

    const J = JT + `class C {
  xs: T[];
  add(x: T): External<void> { this.xs.push(x); }
  get len(): External<u256> { return this.xs.length; }
  get at(i: u256): External<address> { return address(this.xs[i]); }
  setat(i: u256, x: T): External<void> { this.xs[i] = x; }
  pop(): External<void> { this.xs.pop(); }
}`;
    const S = ST + `contract C {
  T[] xs;
  function add(T x) external { xs.push(x); }
  function len() external view returns(uint256){ return xs.length; }
  function at(uint256 i) external view returns(address){ return address(xs[i]); }
  function setat(uint256 i, T x) external { xs[i] = x; }
  function pop() external { xs.pop(); }
}`;
    expect(accepts(J)).toBe(true);
    expect(bc(J)).toBe(bc(`class C {
  xs: address[];
  add(x: address): External<void> { this.xs.push(x); }
  get len(): External<u256> { return this.xs.length; }
  get at(i: u256): External<address> { return this.xs[i]; }
  setat(i: u256, x: address): External<void> { this.xs[i] = x; }
  pop(): External<void> { this.xs.pop(); }
}`));
    const cj = await h.deploy(bc(J));
    const cs = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const A of [A1, A2]) { await h.call(cj, sel('add(address)') + A); await h.call(cs, sel('add(address)') + A); }
    expect((await h.call(cj, sel('len()'))).returnHex).toBe((await h.call(cs, sel('len()'))).returnHex);
    expect(await rd(cj, 0n)).toBe(await rd(cs, 0n)); // length slot
    const base = arrBase(0);
    expect(await rd(cj, base)).toBe(await rd(cs, base));
    expect(await rd(cj, base + 1n)).toBe(await rd(cs, base + 1n));
    expect(BigInt((await h.call(cj, sel('at(uint256)') + W(1))).returnHex)).toBe(BigInt(i2.toString())); // non-vacuous
    for (const i of [0, 1]) {
      expect((await h.call(cj, sel('at(uint256)') + W(i))).returnHex).toBe((await h.call(cs, sel('at(uint256)') + W(i))).returnHex);
    }
    await h.call(cj, sel('setat(uint256,address)') + W(0) + A2); await h.call(cs, sel('setat(uint256,address)') + W(0) + A2);
    expect(await rd(cj, base)).toBe(await rd(cs, base));
    await h.call(cj, sel('pop()')); await h.call(cs, sel('pop()'));
    expect((await h.call(cj, sel('len()'))).returnHex).toBe((await h.call(cs, sel('len()'))).returnHex);
    expect(await rd(cj, base + 1n)).toBe(await rd(cs, base + 1n)); // popped slot cleared identically
  });

  it('fixed Arr<T,2> and mapping<address,T>: raw slots / getters byte-identical to solc', async () => {
    const h = await Harness.create();
    const rd = async (a: Awaited<ReturnType<Harness['deploy']>>, slot: bigint) =>
      toHex(await h.evm.stateManager.getStorage(a, keyB(slot)));
    const i1 = await h.deploy(compileSolidity(SPDX + 'contract Impl { }', 'Impl').creation);
    const i2 = await h.deploy(compileSolidity(SPDX + 'contract I2 { }', 'I2').creation);
    const A1 = pad32(BigInt(i1.toString())).replace(/^0x/, '');
    const A2 = pad32(BigInt(i2.toString())).replace(/^0x/, '');

    const Jarr = JT + `class C { xs: Arr<T, 2>; setx(i: u256, x: T): External<void> { this.xs[i] = x; } get at(i: u256): External<address> { return address(this.xs[i]); } }`;
    const Sarr = ST + `contract C { T[2] xs; function setx(uint256 i, T x) external { xs[i] = x; } function at(uint256 i) external view returns(address){ return address(xs[i]); } }`;
    expect(accepts(Jarr)).toBe(true);
    expect(bc(Jarr)).toBe(bc(`class C { xs: Arr<address, 2>; setx(i: u256, x: address): External<void> { this.xs[i] = x; } get at(i: u256): External<address> { return this.xs[i]; } }`));
    const aj = await h.deploy(bc(Jarr));
    const as = await h.deploy(compileSolidity(SPDX + Sarr, 'C').creation);
    await h.call(aj, sel('setx(uint256,address)') + W(0) + A1); await h.call(as, sel('setx(uint256,address)') + W(0) + A1);
    await h.call(aj, sel('setx(uint256,address)') + W(1) + A2); await h.call(as, sel('setx(uint256,address)') + W(1) + A2);
    expect(await rd(aj, 0n)).toBe(await rd(as, 0n));
    expect(await rd(aj, 1n)).toBe(await rd(as, 1n));
    expect(BigInt(await rd(aj, 1n))).toBe(BigInt(i2.toString())); // non-vacuous: fixed elem occupies its own slot
    for (const i of [0, 1]) expect((await h.call(aj, sel('at(uint256)') + W(i))).returnHex).toBe((await h.call(as, sel('at(uint256)') + W(i))).returnHex);

    const Jmap = JT + `class C { m: mapping<address, T>; setm(k: address, x: T): External<void> { this.m[k] = x; } get getm(k: address): External<address> { return address(this.m[k]); } delm(k: address): External<void> { delete this.m[k]; } }`;
    const Smap = ST + `contract C { mapping(address => T) m; function setm(address k, T x) external { m[k] = x; } function getm(address k) external view returns(address){ return address(m[k]); } function delm(address k) external { delete m[k]; } }`;
    expect(accepts(Jmap)).toBe(true);
    expect(bc(Jmap)).toBe(bc(`class C { m: mapping<address, address>; setm(k: address, x: address): External<void> { this.m[k] = x; } get getm(k: address): External<address> { return this.m[k]; } delm(k: address): External<void> { delete this.m[k]; } }`));
    const mj = await h.deploy(bc(Jmap));
    const ms = await h.deploy(compileSolidity(SPDX + Smap, 'C').creation);
    const K = W(0x99);
    await h.call(mj, sel('setm(address,address)') + K + A1); await h.call(ms, sel('setm(address,address)') + K + A1);
    const mk = mapSlot(K, 0);
    expect(await rd(mj, mk)).toBe(await rd(ms, mk));
    expect(BigInt(await rd(mj, mk))).toBe(BigInt(i1.toString())); // non-vacuous
    expect((await h.call(mj, sel('getm(address)') + K)).returnHex).toBe((await h.call(ms, sel('getm(address)') + K)).returnHex);
    await h.call(mj, sel('delm(address)') + K); await h.call(ms, sel('delm(address)') + K);
    expect(await rd(mj, mk)).toBe(await rd(ms, mk)); // cleared identically
    expect((await h.call(mj, sel('getm(address)') + K)).returnHex).toBe((await h.call(ms, sel('getm(address)') + K)).returnHex);
  });

  it('nested aggregates (struct with a T[] field; mapping to a struct with a T field) byte-identical', async () => {
    const h = await Harness.create();
    const rd = async (a: Awaited<ReturnType<Harness['deploy']>>, slot: bigint) =>
      toHex(await h.evm.stateManager.getStorage(a, keyB(slot)));
    const i1 = await h.deploy(compileSolidity(SPDX + 'contract Impl { }', 'Impl').creation);
    const A1 = pad32(BigInt(i1.toString())).replace(/^0x/, '');

    const Jn = JT + `type P = { xs: T[]; n: u256 }
class C { p: P; addp(x: T): External<void> { this.p.xs.push(x); } get pat(i: u256): External<address> { return address(this.p.xs[i]); } get plen(): External<u256> { return this.p.xs.length; } }`;
    const Sn = ST + `contract C { struct P { T[] xs; uint256 n; } P p; function addp(T x) external { p.xs.push(x); } function pat(uint256 i) external view returns(address){ return address(p.xs[i]); } function plen() external view returns(uint256){ return p.xs.length; } }`;
    expect(accepts(Jn)).toBe(true);
    const nj = await h.deploy(bc(Jn));
    const ns = await h.deploy(compileSolidity(SPDX + Sn, 'C').creation);
    await h.call(nj, sel('addp(address)') + A1); await h.call(ns, sel('addp(address)') + A1);
    expect((await h.call(nj, sel('plen()'))).returnHex).toBe((await h.call(ns, sel('plen()'))).returnHex);
    expect((await h.call(nj, sel('pat(uint256)') + W(0))).returnHex).toBe((await h.call(ns, sel('pat(uint256)') + W(0))).returnHex);
    expect(BigInt((await h.call(nj, sel('pat(uint256)') + W(0))).returnHex)).toBe(BigInt(i1.toString()));
    expect(await rd(nj, 0n)).toBe(await rd(ns, 0n)); // p.xs length slot

    const Jm = JT + `type P = { t: T; n: u256 }
class C { m: mapping<u256, P>; setm(k: u256, x: T, n: u256): External<void> { this.m[k] = { t: x, n }; } get gt(k: u256): External<address> { return address(this.m[k].t); } get gn(k: u256): External<u256> { return this.m[k].n; } }`;
    const Sm = ST + `contract C { struct P { T t; uint256 n; } mapping(uint256 => P) m; function setm(uint256 k, T x, uint256 n) external { m[k] = P(x, n); } function gt(uint256 k) external view returns(address){ return address(m[k].t); } function gn(uint256 k) external view returns(uint256){ return m[k].n; } }`;
    expect(accepts(Jm)).toBe(true);
    const mj = await h.deploy(bc(Jm));
    const ms = await h.deploy(compileSolidity(SPDX + Sm, 'C').creation);
    await h.call(mj, sel('setm(uint256,address,uint256)') + W(3) + A1 + W(77));
    await h.call(ms, sel('setm(uint256,address,uint256)') + W(3) + A1 + W(77));
    const base = mapSlot(W(3), 0);
    expect(await rd(mj, base)).toBe(await rd(ms, base)); // P.t
    expect(await rd(mj, base + 1n)).toBe(await rd(ms, base + 1n)); // P.n
    expect((await h.call(mj, sel('gt(uint256)') + W(3))).returnHex).toBe((await h.call(ms, sel('gt(uint256)') + W(3))).returnHex);
    expect((await h.call(mj, sel('gn(uint256)') + W(3))).returnHex).toBe((await h.call(ms, sel('gn(uint256)') + W(3))).returnHex);
  });

  it('auto-getters of a T field / T[] / mapping<address,T> return address, byte-identical to solc', async () => {
    const h = await Harness.create();
    const i1 = await h.deploy(compileSolidity(SPDX + 'contract Impl { }', 'Impl').creation);
    const i2 = await h.deploy(compileSolidity(SPDX + 'contract I2 { }', 'I2').creation);
    const A1 = pad32(BigInt(i1.toString())).replace(/^0x/, '');
    const A2 = pad32(BigInt(i2.toString())).replace(/^0x/, '');

    const J = JT + `class C { t: Visible<T>; xs: Visible<T[]>; m: Visible<mapping<address, T>>; sett(x: T): External<void> { this.t = x; } add(x: T): External<void> { this.xs.push(x); } setm(k: address, x: T): External<void> { this.m[k] = x; } }`;
    const S = ST + `contract C { T public t; T[] public xs; mapping(address => T) public m; function sett(T x) external { t = x; } function add(T x) external { xs.push(x); } function setm(address k, T x) external { m[k] = x; } }`;
    expect(accepts(J)).toBe(true);
    const cj = await h.deploy(bc(J));
    const cs = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(cj, sel('sett(address)') + A1); await h.call(cs, sel('sett(address)') + A1);
    await h.call(cj, sel('add(address)') + A2); await h.call(cs, sel('add(address)') + A2);
    await h.call(cj, sel('setm(address,address)') + W(0x55) + A1); await h.call(cs, sel('setm(address,address)') + W(0x55) + A1);
    // the getters return `address` (the contract type erases): returndata equal + non-vacuous
    for (const [fn, args, want] of [
      ['t()', '', i1], ['xs(uint256)', W(0), i2], ['m(address)', W(0x55), i1],
    ] as const) {
      const rj = await h.call(cj, sel(fn) + args);
      const rs = await h.call(cs, sel(fn) + args);
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(BigInt(rj.returnHex)).toBe(BigInt((want as any).toString()));
    }
  });

  it('does NOT over-accept: a value read OUT OF an aggregate is still NOMINAL (fail-closed gates fire)', () => {
    // the raw address capability surface is not on a contract-ref value read from an array/mapping/struct.
    for (const [where, jsrc, ssrc, jpre, jpost, spre, spost] of [
      ['arr', 'this.xs[0n]', 'xs[0]', `class C { xs: T[]; `, ` }`, `contract C { T[] xs; `, ` }`],
      ['map', 'this.m[address(0)]', 'm[address(0)]', `class C { m: mapping<address,T>; `, ` }`, `contract C { mapping(address=>T) m; `, ` }`],
      ['struct', 'this.p.t', 'p.t', `type P = { t: T }\nclass C { p: P; `, ` }`, `contract C { struct P { T t; } P p; `, ` }`],
    ] as const) {
      for (const [m, jret, sret] of [
        ['balance', 'u256', 'uint256'], ['code', 'bytes', 'bytes memory'], ['codehash', 'bytes32', 'bytes32'],
      ] as const) {
        expect(bothReject(
          JT + jpre + `get f(): External<${jret}> { return ${jsrc}.${m}; }` + jpost,
          ST + spre + `function f() external view returns(${sret}){ return ${ssrc}.${m}; }` + spost,
        )).toBe(true);
      }
      // no uN()/bytesN()/payable() cast, and no implicit contract->address, on the aggregate-sourced value
      for (const [jc, sc] of [['u256', 'uint256'], ['u160', 'uint160'], ['bytes20', 'bytes20']] as const) {
        expect(bothReject(
          JT + jpre + `get f(): External<${jc}> { return ${jc}(${jsrc}); }` + jpost,
          ST + spre + `function f() external view returns(${sc}){ return ${sc}(${ssrc}); }` + spost,
        )).toBe(true);
      }
      expect(bothReject(
        JT + jpre + `get f(): External<address> { return payable(${jsrc}); }` + jpost,
        ST + spre + `function f() external view returns(address){ return payable(${ssrc}); }` + spost,
      )).toBe(true);
      expect(bothReject(
        JT + jpre + `get f(): External<address> { let a: address = ${jsrc}; return a; }` + jpost,
        ST + spre + `function f() external view returns(address){ address a = ${ssrc}; return a; }` + spost,
      )).toBe(true);
    }
    // a plain address is NOT assignable into a contract-typed element (no implicit address -> T)
    expect(bothReject(
      JT + `class C { xs: T[]; set(a: address): External<void> { this.xs.push(a); } }`,
      ST + `contract C { T[] xs; function set(address a) external { xs.push(a); } }`,
    )).toBe(true);
    // a cross-contract-type assignment out of an array element (T2 -> D) stays rejected
    expect(bothReject(
      `abstract class D {}\nabstract class T2 { @virtual v(): View<u256>; }\nclass C extends D { xs: T2[]; d: D; set(): External<void> { this.d = this.xs[0n]; } }`,
      `abstract contract T2 { function v() external view virtual returns(uint256); } abstract contract D {} contract C is D { T2[] xs; D d; function set() external { d = xs[0]; } }`,
    )).toBe(true);
    // a LIBRARY name is NOT a valid aggregate element type (solc: not a value type)
    expect(bothReject(
      `static class L { g(): u256 { return 1n; } }\nclass C { xs: L[]; get f(): External<u256> { return 0n; } }`,
      `library L { function g() internal pure returns(uint256){ return 1; } } contract C { L[] xs; }`,
    )).toBe(true);
  });
});
