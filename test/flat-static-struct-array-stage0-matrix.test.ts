// Stage-0 differential matrix for the proposed FLAT Arr<In,N> (static struct) memory representation
// (docs/flat-static-struct-array-spec.md). This is the sacred-bar TRIPWIRE: every row is run+decoded
// with DISTINCT non-zero values and asserted byte-identical to solc 0.8.35 on the CURRENT
// (pointer-headed) representation.
//
// KEY RESULT documented and enforced here (the DECISIVE re-point row): solc lays `In[N] memory`
// POINTER-HEADED with element RE-POINT aliasing - `m[i] = m[j]` makes m[i] alias m[j] (a later
// mutation of one shows through the other). A FLAT contiguous image cannot reproduce this (it
// value-copies m[j] into m[i]'s fixed slot, so a later `m[j].a = 7` does NOT show through m[i].a).
// Therefore the flat flip proposed in the spec CANNOT be byte-identical end-to-end: it would
// MISCOMPILE the element-to-element assignment surface (see the `reptTri` case: solc 7,7 vs a flat
// image's stale 11,11). This test freezes the constraint so any future flat-flip stage that regresses
// element aliasing fails loudly. Regression rows (In[] / Arr<DynIn,N> / Arr<u256,N>) and controls
// (JETH465 / JETH470) are pinned too.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));

async function diff(J: string, S: string, calls: [string, string][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, args] of calls) {
    const data = sel(sg) + (args || '');
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
  }
}

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};

const IN = `@struct class In { a: u256; b: u256; }`;
const SIN = `struct In { uint256 a; uint256 b; }`;

describe('Stage-0 flat Arr<In,N> matrix - byte-identical to solc 0.8.35 (pointer-headed, the current representation)', () => {
  it('literal build + element read m[i] (const / runtime / OOB)', async () => {
    await diff(
      `${IN}
       @contract class C {
         @external @pure r(): u256 { let m: Arr<In,3> = [In(11n,12n), In(13n,14n), In(15n,16n)]; return m[0n].a + m[1n].b + m[2n].a; }
         @external @pure dyn(i: u256): u256 { let m: Arr<In,3> = [In(11n,12n), In(13n,14n), In(15n,16n)]; return m[i].a * 100n + m[i].b; } }`,
      `${SIN}
       contract C {
         function r() external pure returns(uint256){ In[3] memory m; m[0]=In(11,12);m[1]=In(13,14);m[2]=In(15,16); return m[0].a+m[1].b+m[2].a; }
         function dyn(uint256 i) external pure returns(uint256){ In[3] memory m; m[0]=In(11,12);m[1]=In(13,14);m[2]=In(15,16); return m[i].a*100+m[i].b; } }`,
      [['r()', ''], ['dyn(uint256)', W(0)], ['dyn(uint256)', W(2)], ['dyn(uint256)', W(9)]],
    );
  });

  it('m[i] = In(..) value write, m[i].f read+write', async () => {
    await diff(
      `${IN}
       @contract class C {
         @external @pure w(): u256 { let m: Arr<In,3> = [In(11n,12n), In(13n,14n), In(15n,16n)]; m[1n] = In(91n, 92n); return m[0n].a + m[1n].a + m[1n].b + m[2n].b; }
         @external @pure fw(): u256 { let m: Arr<In,2> = [In(11n,12n), In(13n,14n)]; m[0n].a = 77n; m[1n].b = 88n; return m[0n].a + m[0n].b + m[1n].a + m[1n].b; } }`,
      `${SIN}
       contract C {
         function w() external pure returns(uint256){ In[3] memory m; m[0]=In(11,12);m[1]=In(13,14);m[2]=In(15,16); m[1]=In(91,92); return m[0].a+m[1].a+m[1].b+m[2].b; }
         function fw() external pure returns(uint256){ In[2] memory m; m[0]=In(11,12);m[1]=In(13,14); m[0].a=77;m[1].b=88; return m[0].a+m[0].b+m[1].a+m[1].b; } }`,
      [['w()', ''], ['fw()', '']],
    );
  });

  it('DECISIVE: m[i]=m[j] element re-point aliasing (solc reference model; FLAT would MISCOMPILE this)', async () => {
    await diff(
      `${IN}
       @contract class C {
         @external @pure reptT1(): u256 { let m: Arr<In,3> = [In(11n,12n), In(88n,99n), In(50n,60n)]; m[1n] = m[0n]; m[0n].a = 7n; return m[1n].a; }
         @external @pure reptT2(): u256 { let m: Arr<In,3> = [In(11n,12n), In(88n,99n), In(50n,60n)]; m[1n] = m[0n]; m[1n].a = 77n; return m[0n].a; }
         @external @pure reptTri(): [u256,u256] { let m: Arr<In,3> = [In(11n,12n), In(88n,99n), In(50n,60n)]; m[2n]=m[0n]; m[1n]=m[0n]; m[0n].a=7n; return [m[1n].a, m[2n].a]; }
         @external @pure reptEnc(): bytes { let m: Arr<In,3> = [In(11n,12n), In(88n,99n), In(50n,60n)]; m[1n]=m[0n]; m[0n].a=7n; return abi.encode(m); } }`,
      `${SIN}
       contract C {
         function reptT1() external pure returns(uint256){ In[3] memory m; m[0]=In(11,12);m[1]=In(88,99);m[2]=In(50,60); m[1]=m[0]; m[0].a=7; return m[1].a; }
         function reptT2() external pure returns(uint256){ In[3] memory m; m[0]=In(11,12);m[1]=In(88,99);m[2]=In(50,60); m[1]=m[0]; m[1].a=77; return m[0].a; }
         function reptTri() external pure returns(uint256,uint256){ In[3] memory m; m[0]=In(11,12);m[1]=In(88,99);m[2]=In(50,60); m[2]=m[0]; m[1]=m[0]; m[0].a=7; return (m[1].a, m[2].a); }
         function reptEnc() external pure returns(bytes memory){ In[3] memory m; m[0]=In(11,12);m[1]=In(88,99);m[2]=In(50,60); m[1]=m[0]; m[0].a=7; return abi.encode(m); } }`,
      [['reptT1()', ''], ['reptT2()', ''], ['reptTri()', ''], ['reptEnc()', '']],
    );
  });

  it('let p = m[i] reference write-through (both directions)', async () => {
    await diff(
      `${IN}
       @contract class C {
         @external @pure al(): u256 { let m: Arr<In,2> = [In(11n,12n), In(13n,14n)]; let p: In = m[0n]; p.a = 99n; return m[0n].a * 1000n + p.a; }
         @external @pure al2(): u256 { let m: Arr<In,2> = [In(11n,12n), In(13n,14n)]; let p: In = m[0n]; m[0n].a = 55n; return p.a * 1000n + m[0n].a; } }`,
      `${SIN}
       contract C {
         function al() external pure returns(uint256){ In[2] memory m; m[0]=In(11,12);m[1]=In(13,14); In memory p=m[0]; p.a=99; return m[0].a*1000+p.a; }
         function al2() external pure returns(uint256){ In[2] memory m; m[0]=In(11,12);m[1]=In(13,14); In memory p=m[0]; m[0].a=55; return p.a*1000+m[0].a; } }`,
      [['al()', ''], ['al2()', '']],
    );
  });

  it('return m / abi.encode(m) / mixed with scalars / offset (preceding+following field)', async () => {
    await diff(
      `${IN}
       @contract class C {
         @external @pure ret(): Arr<In,3> { let m: Arr<In,3> = [In(11n,12n), In(13n,14n), In(15n,16n)]; return m; }
         @external @pure enc(): bytes { let m: Arr<In,3> = [In(11n,12n), In(13n,14n), In(15n,16n)]; return abi.encode(m); }
         @external @pure encmix(): bytes { let m: Arr<In,2> = [In(11n,12n), In(13n,14n)]; return abi.encode(m, m[1n].a, 999n); }
         @external @pure pre(): bytes { let x: u256 = 7n; let m: Arr<In,2> = [In(11n,12n), In(13n,14n)]; return abi.encode(x, m); }
         @external @pure post(): bytes { let m: Arr<In,2> = [In(11n,12n), In(13n,14n)]; let y: u256 = 9n; return abi.encode(m, y); } }`,
      `${SIN}
       contract C {
         function ret() external pure returns(In[3] memory){ In[3] memory m; m[0]=In(11,12);m[1]=In(13,14);m[2]=In(15,16); return m; }
         function enc() external pure returns(bytes memory){ In[3] memory m; m[0]=In(11,12);m[1]=In(13,14);m[2]=In(15,16); return abi.encode(m); }
         function encmix() external pure returns(bytes memory){ In[2] memory m; m[0]=In(11,12);m[1]=In(13,14); return abi.encode(m, m[1].a, uint256(999)); }
         function pre() external pure returns(bytes memory){ uint256 x=7; In[2] memory m; m[0]=In(11,12);m[1]=In(13,14); return abi.encode(x, m); }
         function post() external pure returns(bytes memory){ In[2] memory m; m[0]=In(11,12);m[1]=In(13,14); uint256 y=9; return abi.encode(m, y); } }`,
      [['ret()', ''], ['enc()', ''], ['encmix()', ''], ['pre()', ''], ['post()', '']],
    );
  });

  it('internal-call arg pick(m,i) + 2-hop', async () => {
    await diff(
      `${IN}
       @contract class C {
         @pure pick(m: Arr<In,3>, i: u256): u256 { return m[i].a * 10n + m[i].b; }
         @pure hop(m: Arr<In,3>): u256 { return this.pick(m, 2n); }
         @external @pure p(i: u256): u256 { let m: Arr<In,3> = [In(11n,12n), In(13n,14n), In(15n,16n)]; return this.pick(m, i); }
         @external @pure h(): u256 { let m: Arr<In,3> = [In(11n,12n), In(13n,14n), In(15n,16n)]; return this.hop(m); } }`,
      `${SIN}
       contract C {
         function pick(In[3] memory m, uint256 i) internal pure returns(uint256){ return m[i].a*10+m[i].b; }
         function hop(In[3] memory m) internal pure returns(uint256){ return pick(m,2); }
         function p(uint256 i) external pure returns(uint256){ In[3] memory m; m[0]=In(11,12);m[1]=In(13,14);m[2]=In(15,16); return pick(m,i); }
         function h() external pure returns(uint256){ In[3] memory m; m[0]=In(11,12);m[1]=In(13,14);m[2]=In(15,16); return hop(m); } }`,
      [['p(uint256)', W(0)], ['p(uint256)', W(1)], ['h()', '']],
    );
  });

  it('nested Arr<Arr<In,N>,M> read + encode', async () => {
    await diff(
      `${IN}
       @contract class C {
         @external @pure n(): u256 { let m: Arr<Arr<In,2>,2> = [[In(11n,12n), In(13n,14n)], [In(15n,16n), In(17n,18n)]]; return m[0n][1n].a * 1000n + m[1n][0n].b; }
         @external @pure ne(): bytes { let m: Arr<Arr<In,2>,2> = [[In(11n,12n), In(13n,14n)], [In(15n,16n), In(17n,18n)]]; return abi.encode(m); } }`,
      `${SIN}
       contract C {
         function n() external pure returns(uint256){ In[2][2] memory m; m[0][0]=In(11,12);m[0][1]=In(13,14);m[1][0]=In(15,16);m[1][1]=In(17,18); return m[0][1].a*1000+m[1][0].b; }
         function ne() external pure returns(bytes memory){ In[2][2] memory m; m[0][0]=In(11,12);m[0][1]=In(13,14);m[1][0]=In(15,16);m[1][1]=In(17,18); return abi.encode(m); } }`,
      [['n()', ''], ['ne()', '']],
    );
  });

  it('3-field / packed(u128) / struct-with-Arr<u256,2>-field elements', async () => {
    await diff(
      `@struct class In3 { a: u256; b: u256; c: u256; }
       @contract class C {
         @external @pure e(): bytes { let m: Arr<In3,2> = [In3(11n,12n,13n), In3(14n,15n,16n)]; return abi.encode(m, m[1n].c); } }`,
      `struct In3 { uint256 a; uint256 b; uint256 c; }
       contract C {
         function e() external pure returns(bytes memory){ In3[2] memory m; m[0]=In3(11,12,13);m[1]=In3(14,15,16); return abi.encode(m, m[1].c); } }`,
      [['e()', '']],
    );
    await diff(
      `@struct class Ip { a: u128; b: u128; }
       @contract class C {
         @external @pure e(): bytes { let m: Arr<Ip,2> = [Ip(11n,12n), Ip(13n,14n)]; return abi.encode(m, m[1n].a); }
         @external @pure r(i: u256): u256 { let m: Arr<Ip,2> = [Ip(11n,12n), Ip(13n,14n)]; return m[i].a * 100n + m[i].b; } }`,
      `struct Ip { uint128 a; uint128 b; }
       contract C {
         function e() external pure returns(bytes memory){ Ip[2] memory m; m[0]=Ip(11,12);m[1]=Ip(13,14); return abi.encode(m, m[1].a); }
         function r(uint256 i) external pure returns(uint256){ Ip[2] memory m; m[0]=Ip(11,12);m[1]=Ip(13,14); return m[i].a*100+m[i].b; } }`,
      [['e()', ''], ['r(uint256)', W(0)], ['r(uint256)', W(1)]],
    );
    await diff(
      `@struct class Q { a: u256; pre: Arr<u256,2>; }
       @contract class C {
         @external @pure e(): bytes { let m: Arr<Q,2> = [Q(5n,[6n,7n]), Q(8n,[9n,10n])]; return abi.encode(m, m[1n].pre[1n], m[0n].a); }
         @external @pure r(): u256 { let m: Arr<Q,2> = [Q(5n,[6n,7n]), Q(8n,[9n,10n])]; return m[0n].pre[0n] + m[1n].pre[1n] + m[1n].a; } }`,
      `struct Q { uint256 a; uint256[2] pre; }
       contract C {
         function e() external pure returns(bytes memory){ uint256[2] memory p0;p0[0]=6;p0[1]=7; uint256[2] memory p1;p1[0]=9;p1[1]=10; Q[2] memory m; m[0]=Q(5,p0);m[1]=Q(8,p1); return abi.encode(m, m[1].pre[1], m[0].a); }
         function r() external pure returns(uint256){ uint256[2] memory p0;p0[0]=6;p0[1]=7; uint256[2] memory p1;p1[0]=9;p1[1]=10; Q[2] memory m; m[0]=Q(5,p0);m[1]=Q(8,p1); return m[0].pre[0]+m[1].pre[1]+m[1].a; } }`,
      [['e()', ''], ['r()', '']],
    );
  });

  it('calldata-param read/encode/return + truncated/oversized revert flavor', async () => {
    await diff(
      `${IN}
       @contract class C {
         @external @pure rd(m: Arr<In,3>, i: u256): u256 { return m[i].a * 100n + m[i].b; }
         @external @pure en(m: Arr<In,3>): bytes { return abi.encode(m); }
         @external @pure rt(m: Arr<In,3>): Arr<In,3> { return m; } }`,
      `${SIN}
       contract C {
         function rd(In[3] calldata m, uint256 i) external pure returns(uint256){ return m[i].a*100+m[i].b; }
         function en(In[3] calldata m) external pure returns(bytes memory){ return abi.encode(m); }
         function rt(In[3] calldata m) external pure returns(In[3] memory){ return m; } }`,
      [
        ['rd((uint256,uint256)[3],uint256)', W(11) + W(12) + W(13) + W(14) + W(15) + W(16) + W(1)],
        ['en((uint256,uint256)[3])', W(11) + W(12) + W(13) + W(14) + W(15) + W(16)],
        ['rt((uint256,uint256)[3])', W(11) + W(12) + W(13) + W(14) + W(15) + W(16)],
      ],
    );
    await diff(
      `${IN}
       @contract class C {
         @external @pure rd(m: Arr<In,3>): u256 { return m[0n].a + m[2n].b; } }`,
      `${SIN}
       contract C {
         function rd(In[3] calldata m) external pure returns(uint256){ return m[0].a + m[2].b; } }`,
      [
        ['rd((uint256,uint256)[3])', W(11) + W(12) + W(13) + W(14) + W(15) + W(16)],
        ['rd((uint256,uint256)[3])', W(11) + W(12) + W(13)],
        ['rd((uint256,uint256)[3])', W(11) + W(12) + W(13) + W(14) + W(15) + W(16) + W(99)],
      ],
    );
  });

  it('storage @state Arr<In,N> read/encode + storage->mem copy independence', async () => {
    await diff(
      `${IN}
       @contract class C {
         @state s: Arr<In,3>;
         @external seed(): void { this.s[0n] = In(11n,12n); this.s[1n] = In(13n,14n); this.s[2n] = In(15n,16n); }
         @external @view rd(i: u256): u256 { return this.s[i].a * 100n + this.s[i].b; }
         @external @view en(): bytes { let m: Arr<In,3> = this.s; return abi.encode(m); } }`,
      `${SIN}
       contract C {
         In[3] s;
         function seed() external { s[0]=In(11,12); s[1]=In(13,14); s[2]=In(15,16); }
         function rd(uint256 i) external view returns(uint256){ return s[i].a*100+s[i].b; }
         function en() external view returns(bytes memory){ In[3] memory m=s; return abi.encode(m); } }`,
      [['seed()', ''], ['rd(uint256)', W(0)], ['rd(uint256)', W(2)], ['en()', '']],
    );
    await diff(
      `${IN}
       @contract class C {
         @state s: Arr<In,2>;
         @external seed(): void { this.s[0n] = In(11n,12n); this.s[1n] = In(13n,14n); }
         @external @view cp(): u256 { let m: Arr<In,2> = this.s; m[0n].a = 500n; return m[0n].a * 10000n + this.s[0n].a; } }`,
      `${SIN}
       contract C {
         In[2] s;
         function seed() external { s[0]=In(11,12); s[1]=In(13,14); }
         function cp() external view returns(uint256){ In[2] memory m=s; m[0].a=500; return m[0].a*10000+s[0].a; } }`,
      [['seed()', ''], ['cp()', '']],
    );
  });

  // ---------- REGRESSION rows: must stay pointer-headed + byte-identical ----------

  it('REG: DYNAMIC-outer In[] stays pointer-headed (build/read/return/alias)', async () => {
    await diff(
      `${IN}
       @contract class C {
         @external @pure lit(): bytes { let xs: In[] = [In(11n,12n), In(13n,14n), In(15n,16n)]; return abi.encode(xs); }
         @external @pure rd(): u256 { let xs: In[] = [In(11n,12n), In(13n,14n)]; return xs[1n].a + xs[0n].b + xs.length; }
         @external @pure ret(): In[] { let xs: In[] = [In(71n,72n), In(73n,74n)]; return xs; }
         @external @pure aliasw(): u256 { let xs: In[] = [In(11n,12n), In(88n,99n)]; xs[1n] = xs[0n]; xs[0n].a = 7n; return xs[1n].a; } }`,
      `${SIN}
       contract C {
         function lit() external pure returns(bytes memory){ In[] memory xs=new In[](3); xs[0]=In(11,12);xs[1]=In(13,14);xs[2]=In(15,16); return abi.encode(xs); }
         function rd() external pure returns(uint256){ In[] memory xs=new In[](2); xs[0]=In(11,12);xs[1]=In(13,14); return xs[1].a+xs[0].b+xs.length; }
         function ret() external pure returns(In[] memory){ In[] memory xs=new In[](2); xs[0]=In(71,72);xs[1]=In(73,74); return xs; }
         function aliasw() external pure returns(uint256){ In[] memory xs=new In[](2); xs[0]=In(11,12);xs[1]=In(88,99); xs[1]=xs[0]; xs[0].a=7; return xs[1].a; } }`,
      [['lit()', ''], ['rd()', ''], ['ret()', ''], ['aliasw()', '']],
    );
  });

  it('REG: Arr<DynIn,N> (dynamic-struct element) stays pointer-headed', async () => {
    await diff(
      `@struct class D { a: u256; s: string; }
       @contract class C {
         @external @pure lit(): bytes { let m: Arr<D,2> = [D(11n,"hi"), D(13n,"world")]; return abi.encode(m); }
         @external @pure rd(): u256 { let m: Arr<D,2> = [D(11n,"hi"), D(13n,"world")]; return m[0n].a + m[1n].a; }
         @external @pure ret(): Arr<D,2> { let m: Arr<D,2> = [D(71n,"aa"), D(73n,"bb")]; return m; } }`,
      `struct D { uint256 a; string s; }
       contract C {
         function lit() external pure returns(bytes memory){ D[2] memory m; m[0]=D(11,"hi");m[1]=D(13,"world"); return abi.encode(m); }
         function rd() external pure returns(uint256){ D[2] memory m; m[0]=D(11,"hi");m[1]=D(13,"world"); return m[0].a + m[1].a; }
         function ret() external pure returns(D[2] memory){ D[2] memory m; m[0]=D(71,"aa");m[1]=D(73,"bb"); return m; } }`,
      [['lit()', ''], ['rd()', ''], ['ret()', '']],
    );
  });

  it('REG: Arr<u256,N> value array unchanged (was always flat)', async () => {
    await diff(
      `@contract class C {
         @external @pure e(): bytes { let m: Arr<u256,3> = [11n, 12n, 13n]; return abi.encode(m, m[1n]); }
         @external @pure r(i: u256): u256 { let m: Arr<u256,3> = [11n, 12n, 13n]; m[i] = 99n; return m[0n] + m[1n] + m[2n]; }
         @external @pure ret(): Arr<u256,3> { let m: Arr<u256,3> = [71n, 72n, 73n]; return m; } }`,
      `contract C {
         function e() external pure returns(bytes memory){ uint256[3] memory m; m[0]=11;m[1]=12;m[2]=13; return abi.encode(m, m[1]); }
         function r(uint256 i) external pure returns(uint256){ uint256[3] memory m; m[0]=11;m[1]=12;m[2]=13; m[i]=99; return m[0]+m[1]+m[2]; }
         function ret() external pure returns(uint256[3] memory){ uint256[3] memory m; m[0]=71;m[1]=72;m[2]=73; return m; } }`,
      [['e()', ''], ['r(uint256)', W(1)], ['ret()', '']],
    );
  });

  // ---------- CONTROLS: must stay REJECT (a later stage may lift JETH465) ----------

  it('CONTROL: JETH465 inline-struct-ctor return of Arr<In,N> field STILL rejects', () => {
    expect(
      codes(`${IN}
        @struct class S { tag: u256; m: Arr<In,2>; }
        @contract class C {
          @external @pure f(): S { let m: Arr<In,2> = [In(11n,12n), In(13n,14n)]; return S(5n, m); } }`),
    ).toContain('JETH465');
  });

  it('CONTROL: JETH470 mem->storage struct-array copy STILL rejects', () => {
    expect(
      codes(`${IN}
        @contract class C {
          @state s: Arr<In,2>;
          @external f(): void { let m: Arr<In,2> = [In(11n,12n), In(13n,14n)]; this.s = m; } }`),
    ).toContain('JETH470');
  });
});
