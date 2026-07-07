// Round-4 coverage-proof findings (the storage-parent aggFieldRead row + the ternary aliasing gate).
// FIX-1 (a byte-identical LIFT): a whole Arr<In,N> field reached through a MULTI-HOP storage chain
// (this.ps[i].pre on @state P[], this.pa[i].pre on Arr<P,2>, this.w.p.pre on a nested struct chain -
// kind placeRead of array type) had NO case in aggArgToMemPtr and fell to the lowerExpr tail,
// producing zero-payload copies / raw-0x80-pointer leaks / runtime reverts through the internal-arg,
// internal-return, 2-hop, and element-write channels (7 witnesses). solc's storage->memory conversion
// COPIES, so the transcode is semantics-preserving: placeRead-of-array now routes through
// abiDecFromStorageToImage (pointer-headed twin) for reference-element / static-struct-leaf arrays,
// the flat abiEncFromStorage copy for value-element arrays - mirroring the arrayValue storage branch
// that already made single-hop this.one.pre work.
// FIX-2 (a clean reject): a MEMORY-parent aggFieldRead (xs[i].pre) as a TERNARY branch - the RC-2
// transcode substitutes a fresh copy where solc passes a live reference (mutation loss), so the
// analyzer's ternary ptrHeaded gate now includes aggFieldRead (JETH074).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));

const D = `@struct class In { x: u256; y: u256 }
@struct class P { pre: Arr<In,2>; n: u256 }
@struct class Wr { p: P; m: u256 }`;
const SD = `struct In { uint256 x; uint256 y; } struct P { In[2] pre; uint256 n; } struct Wr { P p; uint256 m; }`;

const J = `${D} @contract class C {
  @state ps: P[]; @state pa: Arr<P,2>; @state w: Wr; @state one: P;
  @external seed(): void {
    this.ps.push(); this.ps.push();
    this.ps[0n].pre[0n].x=11n; this.ps[0n].pre[0n].y=12n; this.ps[0n].pre[1n].x=13n; this.ps[0n].pre[1n].y=14n; this.ps[0n].n=5n;
    this.ps[1n].pre[0n].x=21n; this.ps[1n].pre[0n].y=22n; this.ps[1n].pre[1n].x=23n; this.ps[1n].pre[1n].y=24n; this.ps[1n].n=6n;
    this.pa[1n].pre[0n].x=41n; this.pa[1n].pre[0n].y=42n; this.pa[1n].pre[1n].x=43n; this.pa[1n].pre[1n].y=44n;
    this.w.p.pre[0n].x=61n; this.w.p.pre[0n].y=62n; this.w.p.pre[1n].x=63n; this.w.p.pre[1n].y=64n;
    this.one.pre[0n].x=71n; this.one.pre[0n].y=72n; this.one.pre[1n].x=73n; this.one.pre[1n].y=74n; }
  take(a: Arr<In,2>): u256 { return a[0n].x + 1000n*a[1n].y; }
  hop(a: Arr<In,2>): u256 { return this.take(a); }
  getPre(): Arr<In,2> { return this.ps[1n].pre; }
  @external @view mc1(): u256 { return this.take(this.ps[0n].pre); }
  @external @view mc1h(): u256 { return this.hop(this.ps[1n].pre); }
  @external @view mc2(): u256 { const a: Arr<In,2> = this.getPre(); return a[0n].x + 1000n*a[1n].y; }
  @external @view mc3(): u256 { let o: Arr<In,2>[] = new Array<Arr<In,2>>(1n); o[0n] = this.ps[0n].pre; return o[0n][1n].y; }
  @external @view mc4a(): u256 { return this.take(this.pa[1n].pre); }
  @external @view mc4w(): u256 { let o: Arr<In,2>[] = new Array<Arr<In,2>>(1n); o[0n] = this.pa[1n].pre; return o[0n][0n].x + o[0n][1n].y; }
  @external @view mc5a(): u256 { return this.take(this.w.p.pre); }
  @external @view mc5w(): u256 { let o: Arr<In,2>[] = new Array<Arr<In,2>>(1n); o[0n] = this.w.p.pre; return o[0n][0n].y + o[0n][1n].x; }
  @external @view ctlOne(): u256 { return this.take(this.one.pre); }
  @external @view ctlLeaf(): u256 { return this.ps[0n].pre[0n].x + 1000n*this.ps[0n].pre[1n].y; }
  @external @view ctlRet(): Arr<In,2> { return this.ps[1n].pre; }
  @external @view ctlEnc(): bytes { return abi.encode(this.w.p.pre); }
  @external @view ctlTern(c: bool): u256 { return this.take(c ? this.ps[0n].pre : this.ps[1n].pre); } }`;

const S = `${SD} contract C {
  P[] ps; P[2] pa; Wr w; P one;
  function seed() external {
    ps.push(); ps.push();
    ps[0].pre[0].x=11; ps[0].pre[0].y=12; ps[0].pre[1].x=13; ps[0].pre[1].y=14; ps[0].n=5;
    ps[1].pre[0].x=21; ps[1].pre[0].y=22; ps[1].pre[1].x=23; ps[1].pre[1].y=24; ps[1].n=6;
    pa[1].pre[0].x=41; pa[1].pre[0].y=42; pa[1].pre[1].x=43; pa[1].pre[1].y=44;
    w.p.pre[0].x=61; w.p.pre[0].y=62; w.p.pre[1].x=63; w.p.pre[1].y=64;
    one.pre[0].x=71; one.pre[0].y=72; one.pre[1].x=73; one.pre[1].y=74; }
  function take(In[2] memory a) internal pure returns(uint256){ return a[0].x + 1000*a[1].y; }
  function hop(In[2] memory a) internal pure returns(uint256){ return take(a); }
  function getPre() internal view returns(In[2] memory){ return ps[1].pre; }
  function mc1() external view returns(uint256){ return take(ps[0].pre); }
  function mc1h() external view returns(uint256){ return hop(ps[1].pre); }
  function mc2() external view returns(uint256){ In[2] memory a = getPre(); return a[0].x + 1000*a[1].y; }
  function mc3() external view returns(uint256){ In[2][] memory o = new In[2][](1); o[0] = ps[0].pre; return o[0][1].y; }
  function mc4a() external view returns(uint256){ return take(pa[1].pre); }
  function mc4w() external view returns(uint256){ In[2][] memory o = new In[2][](1); o[0] = pa[1].pre; return o[0][0].x + o[0][1].y; }
  function mc5a() external view returns(uint256){ return take(w.p.pre); }
  function mc5w() external view returns(uint256){ In[2][] memory o = new In[2][](1); o[0] = w.p.pre; return o[0][0].y + o[0][1].x; }
  function ctlOne() external view returns(uint256){ return take(one.pre); }
  function ctlLeaf() external view returns(uint256){ return ps[0].pre[0].x + 1000*ps[0].pre[1].y; }
  function ctlRet() external view returns(In[2] memory){ return ps[1].pre; }
  function ctlEnc() external view returns(bytes memory){ return abi.encode(w.p.pre); }
  function ctlTern(bool c) external view returns(uint256){ return take(c ? ps[0].pre : ps[1].pre); } }`;

describe('storage multi-hop Arr<In,N> field through the pointer-headed channels (Round-4 FIX-1 lift)', () => {
  it('byte-identical to solc across dyn/fixed/nested-chain parents, all channels, and controls', async () => {
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    for (const [sg, args] of [
      ['seed()', ''], ['mc1()', ''], ['mc1h()', ''], ['mc2()', ''], ['mc3()', ''], ['mc4a()', ''], ['mc4w()', ''],
      ['mc5a()', ''], ['mc5w()', ''], ['ctlOne()', ''], ['ctlLeaf()', ''], ['ctlRet()', ''], ['ctlEnc()', ''],
      ['ctlTern(bool)', W(1)], ['ctlTern(bool)', W(0)],
    ] as const) {
      const jr = await h.call(ja, sel(sg) + args);
      const sr = await h.call(sa, sel(sg) + args);
      expect(jr.returnHex, sg).toBe(sr.returnHex);
      expect(jr.success, sg).toBe(sr.success);
    }
    // non-vacuity anchors: mc1 = 11 + 1000*14 = 14011; mc4a = 41 + 1000*44 = 44041; mc5a = 61 + 1000*64 = 64061.
    expect(BigInt((await h.call(ja, sel('mc1()'))).returnHex)).toBe(14011n);
    expect(BigInt((await h.call(ja, sel('mc4a()'))).returnHex)).toBe(44041n);
    expect(BigInt((await h.call(ja, sel('mc5a()'))).returnHex)).toBe(64061n);
  });

  it('a MEMORY-parent aggFieldRead as a ternary branch rejects (FIX-2, aliasing-loss gate)', () => {
    const codes = (src: string): string[] => {
      try {
        compile(src, { fileName: 'C.jeth' });
        return [];
      } catch (e: any) {
        return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
      }
    };
    expect(
      codes(`${D} @contract class C { take(a: Arr<In,2>): u256 { return a[0n].x; } @external @pure f(c: bool): u256 { const xs: P[] = [P([In(1n,2n),In(3n,4n)],5n), P([In(6n,7n),In(8n,9n)],10n)]; return this.take(c ? xs[0n].pre : xs[1n].pre); } }`),
    ).toContain('JETH074');
  });
});
