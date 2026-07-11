// Tier-1 lifts from docs/OR-CATALOGUE.md (12 catalogued shapes, 4 families), each verified
// byte-identical to solc 0.8.35:
// B-19  JETH470 over-fire: this.s = this.mp[k] whole s2s copy with a MAPPING RHS - isStorageAggSource
//       was missing the mapStorageValue kind (fixedArraySrcBase/structSrcSlot already resolved it).
// L3    cross-location binds: let m = a (whole static calldata param, B-11), this.use(q.pre) +
//       let m = q.pre (static cd-struct leaf, B-13), let m = this.ps[i].pre (multi-hop storage, B-14) -
//       okInit widened + aggArgToMemPtr's cdPlaceReadAgg deep-copy case (abiDecFromCdToImage /
//       abiDecFromStorageToImage; solc's to-memory COPY semantics, incl. mutation locality).
// L1    direct array producers in a tuple-return slot (all were JETH900 storage-fallback throws):
//       internal-call result (B-1), inline literal (B-2), abi.decode (B-3), accepted ternary (B-4),
//       fixed-outer calldata element a[i] = a cdPlaceReadAgg leaf (B-12) - a phase-1 at-position
//       materialization (prodPtr via aggArgToMemPtr) + an abiEncFromMem write branch (inline for
//       ABI-static, offset+tail for dynamic).
// L5    storage struct-field array element ops: return this.st.f[i] whole element (B-16, incl. a
//       runtime index + OOB Panic), this.st.f[i] = In(..) / this.gx[i][j] = In(..) whole-element
//       writes (B-17), this.st.f.length constant fold (B-18) - resolveAccess now CLAIMS a struct
//       element of a FIXED array reached through a field/index chain (only pure-mapping-rooted
//       chains stay with structArrayElem), and .length of a fixed array folds to N on panic-free
//       place chains.
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
const run = async (J: string, S: string, calls: ReadonlyArray<readonly [string, string]>) => {
  const h = await Harness.create();
  await h.fund(me, 10n ** 20n);
  const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
  const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
  for (const [sg, args] of calls) {
    const jr = await h.call(ja, sel(sg) + args);
    const sr = await h.call(sa, sel(sg) + args);
    expect(jr.returnHex, `${sg} ${args.slice(0, 12)}`).toBe(sr.returnHex);
    expect(jr.success, sg).toBe(sr.success);
  }
  return { h, ja };
};
const D = `type In = { x: u256; y: u256 };`;
const SD = `struct In { uint256 x; uint256 y; }`;

describe('Tier-1 OR lifts (B-19, L3, L1, L5) byte-identical to solc 0.8.35', () => {
  it('B-19: s2s copy with a mapping RHS (fixed-array + struct values)', async () => {
    const J = `${D} class C {
  mp: mapping<u256, Arr<In,2>>; s: Arr<In,2>; mps: mapping<u256, In>; one: In;
  seed(): External<void> { this.mp[5n][0n].x = 95n; this.mp[5n][0n].y = 96n; this.mp[5n][1n].x = 97n; this.mp[5n][1n].y = 98n; this.mps[7n] = In(71n,72n); }
  cpA(): External<void> { this.s = this.mp[5n]; }
  cpS(): External<void> { this.one = this.mps[7n]; }
  get rd(): External<u256> { return this.s[0n].x + 1000n*this.s[1n].y; }
  get rdS(): External<u256> { return this.one.x + 1000n*this.one.y; } }`;
    const S = `${SD} contract C {
  mapping(uint256 => In[2]) mp; In[2] s; mapping(uint256 => In) mps; In one;
  function seed() external { mp[5][0].x = 95; mp[5][0].y = 96; mp[5][1].x = 97; mp[5][1].y = 98; mps[7] = In(71,72); }
  function cpA() external { s = mp[5]; }
  function cpS() external { one = mps[7]; }
  function rd() external view returns(uint256){ return s[0].x + 1000*s[1].y; }
  function rdS() external view returns(uint256){ return one.x + 1000*one.y; } }`;
    await run(J, S, [['seed()', ''], ['cpA()', ''], ['cpS()', ''], ['rd()', ''], ['rdS()', '']] as const);
  });

  it('L3: cross-location binds with copy locality (calldata param, cd leaf, storage multi-hop)', async () => {
    const J = `${D} type P = { pre: Arr<In,2>; n: u256 }; type Q = { pre: Arr<In,2>; z: u256 };
class C {
  ps: P[];
  seed(): External<void> { this.ps.push(); this.ps[0n].pre[0n].x=81n; this.ps[0n].pre[0n].y=82n; this.ps[0n].pre[1n].x=83n; this.ps[0n].pre[1n].y=84n; }
  take(a: Arr<In,2>): u256 { return a[0n].x + 1000n*a[1n].y; }
  get b11(a: Arr<In,2>): External<u256> { let m: Arr<In,2> = a; m[0n].x = m[0n].x + 1n; return m[0n].x + 1000n*m[1n].y; }
  get b13(q: Q): External<u256> { return this.take(q.pre); }
  get b13b(q: Q): External<u256> { let m: Arr<In,2> = q.pre; return m[0n].x + 1000n*m[1n].y; }
  get b14(): External<u256> { let m: Arr<In,2> = this.ps[0n].pre; m[1n].y = m[1n].y + 5n; return m[0n].x + 1000n*m[1n].y; }
  get b14chk(): External<u256> { return this.ps[0n].pre[1n].y; } }`;
    const S = `${SD} struct P { In[2] pre; uint256 n; } struct Q { In[2] pre; uint256 z; }
contract C {
  P[] ps;
  function seed() external { ps.push(); ps[0].pre[0].x=81; ps[0].pre[0].y=82; ps[0].pre[1].x=83; ps[0].pre[1].y=84; }
  function take(In[2] memory a) internal pure returns(uint256){ return a[0].x + 1000*a[1].y; }
  function b11(In[2] calldata a) external pure returns(uint256){ In[2] memory m = a; m[0].x = m[0].x + 1; return m[0].x + 1000*m[1].y; }
  function b13(Q calldata q) external pure returns(uint256){ return take(q.pre); }
  function b13b(Q calldata q) external pure returns(uint256){ In[2] memory m = q.pre; return m[0].x + 1000*m[1].y; }
  function b14() external view returns(uint256){ In[2] memory m = ps[0].pre; m[1].y = m[1].y + 5; return m[0].x + 1000*m[1].y; }
  function b14chk() external view returns(uint256){ return ps[0].pre[1].y; } }`;
    const a4 = W(51) + W(52) + W(53) + W(54);
    const q5 = W(61) + W(62) + W(63) + W(64) + W(9);
    await run(J, S, [
      ['seed()', ''], ['b11((uint256,uint256)[2])', a4], ['b13(((uint256,uint256)[2],uint256))', q5],
      ['b13b(((uint256,uint256)[2],uint256))', q5], ['b14()', ''], ['b14chk()', ''],
    ] as const);
  });

  it('L1: direct array producers in a tuple-return slot (call/literal/decode/ternary/cd-element)', async () => {
    const J = `${D} class C {
  sx: Arr<In,2>; sy: Arr<In,2>;
  seed(): External<void> { this.sx[0n].x=11n; this.sx[0n].y=12n; this.sx[1n].x=13n; this.sx[1n].y=14n; this.sy[0n].x=21n; this.sy[0n].y=22n; this.sy[1n].x=23n; this.sy[1n].y=24n; }
  mk2(): Arr<In,2> { return [In(111n,112n),In(113n,114n)]; }
  mkU(): u256[] { return [7n,8n,9n]; }
  get b1(): External<[u256, Arr<In,2>]> { return [7n, this.mk2()]; }
  get b1d(): External<[u256, u256[]]> { return [7n, this.mkU()]; }
  get b2(): External<[u256, Arr<In,2>]> { return [7n, [In(21n,22n),In(23n,24n)]]; }
  get b2f(): External<[Arr<In,2>, u256]> { return [[In(31n,32n),In(33n,34n)], 8n]; }
  get b3(b: bytes): External<[u256, Arr<In,2>]> { return [7n, abi.decode(b, Arr<In,2>)]; }
  get b4(c: bool): External<[u256, Arr<In,2>]> { return [7n, c ? this.sx : this.sy]; }
  get b12(a: Arr<Arr<In,2>,2>, i: u256): External<[u256, Arr<In,2>]> { return [206n, a[i]]; }
  get mixed(b: bytes): External<[u256, Arr<In,2>, string]> { return [7n, abi.decode(b, Arr<In,2>), "hello"]; } }`;
    const S = `${SD} contract C {
  In[2] sx; In[2] sy;
  function seed() external { sx[0].x=11; sx[0].y=12; sx[1].x=13; sx[1].y=14; sy[0].x=21; sy[0].y=22; sy[1].x=23; sy[1].y=24; }
  function mk2() internal pure returns(In[2] memory){ In[2] memory a=[In(111,112),In(113,114)]; return a; }
  function mkU() internal pure returns(uint256[] memory){ uint256[] memory u=new uint256[](3); u[0]=7;u[1]=8;u[2]=9; return u; }
  function b1() external pure returns(uint256, In[2] memory){ return (7, mk2()); }
  function b1d() external pure returns(uint256, uint256[] memory){ return (7, mkU()); }
  function b2() external pure returns(uint256, In[2] memory){ return (7, [In(21,22),In(23,24)]); }
  function b2f() external pure returns(In[2] memory, uint256){ return ([In(31,32),In(33,34)], 8); }
  function b3(bytes calldata b) external pure returns(uint256, In[2] memory){ return (7, abi.decode(b,(In[2]))); }
  function b4(bool c) external view returns(uint256, In[2] memory){ return (7, c ? sx : sy); }
  function b12(In[2][2] calldata a, uint256 i) external pure returns(uint256, In[2] memory){ return (206, a[i]); }
  function mixed(bytes calldata b) external pure returns(uint256, In[2] memory, string memory){ return (7, abi.decode(b,(In[2])), "hello"); } }`;
    const blob = W(0x20) + W(128) + W(51) + W(52) + W(53) + W(54);
    const a8 = W(61) + W(62) + W(63) + W(64) + W(65) + W(66) + W(67) + W(68);
    await run(J, S, [
      ['seed()', ''], ['b1()', ''], ['b1d()', ''], ['b2()', ''], ['b2f()', ''], ['b3(bytes)', blob],
      ['b4(bool)', W(1)], ['b4(bool)', W(0)],
      ['b12((uint256,uint256)[2][2],uint256)', a8 + W(1)],
      ['b12((uint256,uint256)[2][2],uint256)', a8 + W(2)], // OOB -> Panic 0x32 parity
      ['mixed(bytes)', blob],
    ] as const);
  });

  it('L5: storage struct-field array element read/write/length (incl runtime index + OOB + nested)', async () => {
    const J = `${D} type S = { f: Arr<In,2>; tag: u256 };
class C {
  st: S; gx: Arr<Arr<In,2>,2>;
  seed(): External<void> { this.st.f[0n] = In(91n,92n); this.st.f[1n] = In(83n,84n); this.st.tag = 5n;
    this.gx[0n][0n] = In(95n,96n); this.gx[1n][1n] = In(97n,98n); }
  wrt(i: u256): External<void> { this.st.f[i] = In(71n,72n); }
  get b16(): External<In> { return this.st.f[1n]; }
  get b16r(i: u256): External<In> { return this.st.f[i]; }
  get rdG(): External<u256> { return this.gx[0n][0n].x + 1000n*this.gx[1n][1n].y; }
  get b18(): External<u256> { return this.st.f.length; }
  get chk(): External<u256> { return this.st.f[0n].x + 1000n*this.st.f[1n].y + this.st.tag; }
  get enc(): External<bytes> { return abi.encode(this.st.f[0n]); } }`;
    const S2 = `${SD} struct S { In[2] f; uint256 tag; }
contract C {
  S st; In[2][2] gx;
  function seed() external { st.f[0] = In(91,92); st.f[1] = In(83,84); st.tag = 5;
    gx[0][0] = In(95,96); gx[1][1] = In(97,98); }
  function wrt(uint256 i) external { st.f[i] = In(71,72); }
  function b16() external view returns(In memory){ return st.f[1]; }
  function b16r(uint256 i) external view returns(In memory){ return st.f[i]; }
  function rdG() external view returns(uint256){ return gx[0][0].x + 1000*gx[1][1].y; }
  function b18() external view returns(uint256){ return st.f.length; }
  function chk() external view returns(uint256){ return st.f[0].x + 1000*st.f[1].y + st.tag; }
  function enc() external view returns(bytes memory){ return abi.encode(st.f[0]); } }`;
    const { h, ja } = await run(J, S2, [
      ['seed()', ''], ['b16()', ''], ['b16r(uint256)', W(0)],
      ['b16r(uint256)', W(5)], // OOB -> Panic parity
      ['rdG()', ''], ['b18()', ''], ['chk()', ''], ['enc()', ''],
      ['wrt(uint256)', W(0)], ['chk()', ''],
      ['wrt(uint256)', W(9)], // OOB write -> Panic parity
      ['b16()', ''],
    ] as const);
    // non-vacuity anchors: b18 == 2; post-wrt(0) chk = 71 + 1000*84 + 5 = 84076.
    expect(BigInt((await h.call(ja, sel('b18()'))).returnHex)).toBe(2n);
    expect(BigInt((await h.call(ja, sel('chk()'))).returnHex)).toBe(84076n);
  });
});
