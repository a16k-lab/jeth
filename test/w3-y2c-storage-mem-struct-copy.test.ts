// W3-Y2c: storage<->memory struct-copy + whole-field-assign lifts, byte-identical to solc 0.8.35.
//  - P1-10: a WHOLE dynamic VALUE-array field assigned through a storage struct-array element /
//    mapping value (this.vals[i].xs = b, this.m[k].xs = b, xs: u256[]), with overwrite-clearing.
//  - P1-10 sibling: a WHOLE static fixed-array field at depth (this.vals[i].fa = a, this.o.inner.fa = a).
//  - CRASH fix: a MEMORY struct-array element copied INTO a storage struct (this.p0 = ps[i], ps a
//    memory Arr<P,N> / P[]), for a static struct AND a dynamic-field struct (string / bytes[] field).
// Plus adjacent CLEAN-reject / BOTH-REJECT assertions (no over-acceptance, no miscompile).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { hexToBytes } from '@ethereumjs/util';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const M = 1n << 256n;
const W = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const pad = (v: bigint) => W(v);
const slotKeccak = (p: bigint) => BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(p)) as `0x${string}`))));

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};

// u256[] calldata (offset + len + elems)
function uarr(vals: number[]): string {
  let h = W(0x20n) + W(BigInt(vals.length));
  for (const v of vals) h += W(BigInt(v));
  return h;
}
// a bytes calldata (offset + len + right-padded payload)
function bts(hex: string): string {
  const b = hex.replace(/^0x/, '');
  const len = b.length / 2;
  const words = Math.ceil(len / 32);
  let pl = b;
  for (let i = len; i < words * 32; i++) pl += '00';
  return W(0x20n) + W(BigInt(len)) + pl;
}
// a bytes[] calldata
function barr(hexes: string[]): string {
  const n = hexes.length;
  let table = W(BigInt(n));
  let tails = '';
  let off = n * 32;
  const enc: { len: number; pl: string; size: number }[] = [];
  for (const h of hexes) {
    const b = h.replace(/^0x/, '');
    const len = b.length / 2;
    const words = Math.ceil(len / 32);
    let pl = b;
    for (let i = len; i < words * 32; i++) pl += '00';
    enc.push({ len, pl, size: 32 + words * 32 });
  }
  for (const e of enc) {
    table += W(BigInt(off));
    off += e.size;
  }
  for (const e of enc) tails += W(BigInt(e.len)) + e.pl;
  return W(0x20n) + table + tails;
}
const s = (str: string) => bts('0x' + Array.from(new TextEncoder().encode(str)).map((x) => x.toString(16).padStart(2, '0')).join(''));

describe('W3-Y2c storage<->memory struct-copy + whole-field-assign - byte-identical to solc 0.8.35', () => {
  async function deploy(J: string, S: string) {
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await hs.deploy(compileSolidity(SPDX + S, 'C').creation);
    return { hj, hs, aj, as };
  }
  async function diff(J: string, S: string, calls: [string, string?][]) {
    const { hj, hs, aj, as } = await deploy(J, S);
    for (const [sg, args] of calls) {
      const data = sel(sg) + (args ?? '');
      const rj = await hj.call(aj, data);
      const rs = await hs.call(as, data);
      expect(rj.success, `${sg} success`).toBe(rs.success);
      expect(rj.returnHex, `${sg} returndata`).toBe(rs.returnHex);
    }
    return { hj, hs, aj, as };
  }

  it('P1-10: whole u256[] field assign to a storage struct-array element (+ overwrite-clear, OOB, empty)', async () => {
    const J = `@struct class D { id: u256; xs: u256[]; }
    @contract class C { @state vals: D[]; @state sentinel: u256;
      @external seed() { this.vals.push(); this.vals[0n].id = 100n; this.vals[0n].xs.push(1n); this.vals[0n].xs.push(2n); this.vals[0n].xs.push(3n); this.vals.push(); this.vals[1n].id = 200n; this.sentinel = 0xcafen; }
      @external setxs(i: u256, b: u256[]) { this.vals[i].xs = b; }
      @external getid(i: u256): u256 { return this.vals[i].id; }
      @external getlen(i: u256): u256 { return this.vals[i].xs.length; }
      @external getxs(i: u256, j: u256): u256 { return this.vals[i].xs[j]; }
      @external getsent(): u256 { return this.sentinel; } }`;
    const S = `contract C { struct D { uint256 id; uint256[] xs; } D[] vals; uint256 sentinel;
      function seed() external { vals.push(); vals[0].id=100; vals[0].xs.push(1); vals[0].xs.push(2); vals[0].xs.push(3); vals.push(); vals[1].id=200; sentinel=0xcafe; }
      function setxs(uint256 i, uint256[] calldata b) external { vals[i].xs = b; }
      function getid(uint256 i) external view returns (uint256){ return vals[i].id; }
      function getlen(uint256 i) external view returns (uint256){ return vals[i].xs.length; }
      function getxs(uint256 i, uint256 j) external view returns (uint256){ return vals[i].xs[j]; }
      function getsent() external view returns (uint256){ return sentinel; } }`;
    const { hj, hs, aj, as } = await diff(J, S, [
      ['seed()'],
      ['setxs(uint256,uint256[])', W(0n) + uarr([7, 8, 9, 10, 11])],
      ['getlen(uint256)', W(0n)],
      ['getxs(uint256,uint256)', W(0n) + W(4n)],
      ['setxs(uint256,uint256[])', W(0n) + uarr([42])], // shorter -> tail clear
      ['getlen(uint256)', W(0n)],
      ['getxs(uint256,uint256)', W(0n) + W(1n)], // OOB Panic 0x32
      ['setxs(uint256,uint256[])', W(0n) + uarr([])], // empty
      ['getlen(uint256)', W(0n)],
      ['setxs(uint256,uint256[])', W(1n) + uarr([55, 66])],
      ['getxs(uint256,uint256)', W(1n) + W(1n)],
      ['getid(uint256)', W(0n)],
      ['getid(uint256)', W(1n)],
      ['getsent()'],
    ]);
    // raw storage slots byte-identical after a final known assign
    const data = sel('setxs(uint256,uint256[])') + W(0n) + uarr([123, 456]);
    await hj.call(aj, data);
    await hs.call(as, data);
    const xsLen = slotKeccak(0n) + 1n; // vals[0].xs length slot (vals data at keccak(0), stride 2)
    const xsData = slotKeccak(xsLen);
    for (const sl of [xsLen, xsData, xsData + 1n]) {
      expect(await readSlot(hj, aj, sl), `slot ${sl}`).toBe(await readSlot(hs, as, sl));
    }
  });

  it('P1-10: whole u256[] field assign to a mapping-value struct field (this.m[k].xs = b)', async () => {
    const J = `@struct class D { id: u256; xs: u256[]; }
    @contract class C { @state m: mapping<address, D>;
      @external setxs(k: address, b: u256[]) { this.m[k].xs = b; }
      @external getlen(k: address): u256 { return this.m[k].xs.length; }
      @external getxs(k: address, j: u256): u256 { return this.m[k].xs[j]; } }`;
    const S = `contract C { struct D { uint256 id; uint256[] xs; } mapping(address=>D) m;
      function setxs(address k, uint256[] calldata b) external { m[k].xs = b; }
      function getlen(address k) external view returns (uint256){ return m[k].xs.length; }
      function getxs(address k, uint256 j) external view returns (uint256){ return m[k].xs[j]; } }`;
    const K = W(BigInt('0x' + '11'.repeat(20)));
    await diff(J, S, [
      ['setxs(address,uint256[])', K + uarr([3, 1, 4, 1, 5])],
      ['getlen(address)', K],
      ['getxs(address,uint256)', K + W(2n)],
      ['setxs(address,uint256[])', K + uarr([9])],
      ['getlen(address)', K],
    ]);
  });

  it('P1-10 sibling: whole static fixed-array field assign at depth (this.vals[i].fa, this.o.inner.fa)', async () => {
    const J = `@struct class D { id: u256; fa: Arr<u256,2>; }
    @struct class In { a: u256; fa: Arr<u256,2>; }
    @struct class O { x: u256; inner: In; }
    @contract class C { @state vals: D[]; @state o: O;
      @external seed() { this.vals.push(); this.vals[0n].id = 7n; }
      @external setElem(i: u256, a: Arr<u256,2>) { this.vals[i].fa = a; }
      @external setNested(a: Arr<u256,2>) { this.o.inner.fa = a; }
      @external gElem(i: u256, j: u256): u256 { return this.vals[i].fa[j]; }
      @external gId(i: u256): u256 { return this.vals[i].id; }
      @external gNested(j: u256): u256 { return this.o.inner.fa[j]; } }`;
    const S = `contract C { struct D { uint256 id; uint256[2] fa; } struct In { uint256 a; uint256[2] fa; } struct O { uint256 x; In inner; }
      D[] vals; O o;
      function seed() external { vals.push(); vals[0].id=7; }
      function setElem(uint256 i, uint256[2] calldata a) external { vals[i].fa = a; }
      function setNested(uint256[2] calldata a) external { o.inner.fa = a; }
      function gElem(uint256 i, uint256 j) external view returns(uint256){ return vals[i].fa[j]; }
      function gId(uint256 i) external view returns(uint256){ return vals[i].id; }
      function gNested(uint256 j) external view returns(uint256){ return o.inner.fa[j]; } }`;
    await diff(J, S, [
      ['seed()'],
      ['setElem(uint256,uint256[2])', W(0n) + W(11n) + W(22n)],
      ['gElem(uint256,uint256)', W(0n) + W(0n)],
      ['gElem(uint256,uint256)', W(0n) + W(1n)],
      ['gId(uint256)', W(0n)],
      ['setNested(uint256[2])', W(5n) + W(6n)],
      ['gNested(uint256)', W(0n)],
      ['gNested(uint256)', W(1n)],
    ]);
  });

  it('CRASH fix: a memory static-struct array element copied into a storage struct (Arr<P,N> + P[])', async () => {
    const J = `@struct class P { n: u256; m: u256; }
    @contract class C { @state p0: P; @state sent: u256;
      @external fromFixed() { let ps: Arr<P,2> = [P(11n,22n), P(33n,44n)]; this.p0 = ps[1n]; this.sent = 0x99n; }
      @external fromDyn() { let ps: P[] = [P(7n,8n), P(9n,10n)]; this.p0 = ps[0n]; }
      @external gn(): u256 { return this.p0.n; }
      @external gm(): u256 { return this.p0.m; }
      @external gs(): u256 { return this.sent; } }`;
    const S = `contract C { struct P { uint256 n; uint256 m; } P p0; uint256 sent;
      function fromFixed() external { P[2] memory ps = [P(11,22), P(33,44)]; p0 = ps[1]; sent = 0x99; }
      function fromDyn() external { P[] memory ps = new P[](2); ps[0]=P(7,8); ps[1]=P(9,10); p0 = ps[0]; }
      function gn() external view returns(uint256){ return p0.n; }
      function gm() external view returns(uint256){ return p0.m; }
      function gs() external view returns(uint256){ return sent; } }`;
    const { hj, hs, aj, as } = await diff(J, S, [['fromFixed()'], ['gn()'], ['gm()'], ['gs()'], ['fromDyn()'], ['gn()'], ['gm()']]);
    // p0 storage slots (slot 0 = n, slot 1 = m) byte-identical
    expect(await readSlot(hj, aj, 0n)).toBe(await readSlot(hs, as, 0n));
    expect(await readSlot(hj, aj, 1n)).toBe(await readSlot(hs, as, 1n));
  });

  it('CRASH fix: a memory dynamic-field-struct array element (string field) copied into storage (+ overwrite-clear)', async () => {
    const J = `@struct class P { n: u256; str: string; }
    @contract class C { @state p0: P;
      @external setLong(a: string) { this.p0.str = a; this.p0.n = 5n; }
      @external fromElem(a: string) { let ps: P[] = [P(1n,a), P(2n,a)]; this.p0 = ps[1n]; }
      @external gn(): u256 { return this.p0.n; }
      @external gs(): string { return this.p0.str; } }`;
    const S = `contract C { struct P { uint256 n; string str; } P p0;
      function setLong(string calldata a) external { p0.str = a; p0.n = 5; }
      function fromElem(string calldata a) external { P[] memory ps = new P[](2); ps[0]=P(1,a); ps[1]=P(2,a); p0 = ps[1]; }
      function gn() external view returns(uint256){ return p0.n; }
      function gs() external view returns(string memory){ return p0.str; } }`;
    await diff(J, S, [
      ['setLong(string)', s('a very long initial string that spans multiple storage slots for certain!!')],
      ['gs()'],
      ['fromElem(string)', s('short')], // long -> short: exercises overwrite-clear of the storage bytes tail
      ['gn()'],
      ['gs()'],
    ]);
  });

  it('CRASH fix: a memory dyn-struct array element with a bytes[] field copied into storage', async () => {
    const J = `@struct class P { n: u256; bs: bytes[]; }
    @contract class C { @state p0: P;
      @external fromElem(a: bytes[]) { let ps: P[] = [P(7n,a), P(8n,a)]; this.p0 = ps[0n]; }
      @external gn(): u256 { return this.p0.n; }
      @external gl(): u256 { return this.p0.bs.length; }
      @external gb(i: u256): bytes { return this.p0.bs[i]; } }`;
    const S = `contract C { struct P { uint256 n; bytes[] bs; } P p0;
      function fromElem(bytes[] calldata a) external { P[] memory ps = new P[](2); ps[0].n=7; ps[0].bs=a; ps[1].n=8; ps[1].bs=a; p0 = ps[0]; }
      function gn() external view returns(uint256){ return p0.n; }
      function gl() external view returns(uint256){ return p0.bs.length; }
      function gb(uint256 i) external view returns(bytes memory){ return p0.bs[i]; } }`;
    const arg = barr(['0x1122', '0x33445566778899aabbccddeeff00112233445566778899aabbccddeeff001122']);
    await diff(J, S, [['fromElem(bytes[])', arg], ['gn()'], ['gl()'], ['gb(uint256)', W(0n)], ['gb(uint256)', W(1n)]]);
  });

  it('adjacent clean-rejects / BOTH-REJECT (no over-acceptance)', () => {
    // a bytes[] field whole-assign to a storage struct-array element: solc ITSELF rejects (nested calldata
    // dynamic array to storage is unimplemented in the old codegen), JETH matches with a clean reject.
    expect(
      codes('@struct class D { id: u256; bs: bytes[]; } @contract class C { @state vals: D[]; @external w(b: bytes[]) { this.vals[0n].bs = b; } }'),
    ).not.toEqual([]);
    // a struct-element array field P[] whole-assign to a storage struct-array element: both reject.
    expect(
      codes('@struct class Q { n: u256; } @struct class D { id: u256; ps: Q[]; } @contract class C { @state vals: D[]; @external w(b: Q[]) { this.vals[0n].ps = b; } }'),
    ).not.toEqual([]);
    // a whole fixed-array ELEMENT of a nested array at depth (index last step) was LIFTED by W5A
    // (byte-identical to solc, see store-at-depth-nested-chain.test.ts): it now compiles cleanly.
    expect(
      codes('@contract class C { @state g3: Arr<u256,2>[]; @external w(i: u256, a: Arr<u256,2>) { this.g3[i][0n] = a[0n]; this.g3[i] = a; } }'),
    ).toEqual([]);
  });
});
