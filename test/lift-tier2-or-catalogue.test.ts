// Tier-2 lifts from docs/OR-CATALOGUE.md (10 catalogued shapes + the NEW mapping-rooted family),
// each verified byte-identical to solc 0.8.35:
// L12   fixed-array STATE INITIALIZERS (@state a: Arr<u256,3> = [11n, 22n]): folded to packed slot
//       words at analyze time (full + SHORT literals - solc partial-fills, tail keeps the zero
//       default - packed u8/bool lanes, bytesN right-alignment rule); a LONGER literal still rejects.
// NEW   mapping-rooted FIXED-array whole-struct element ops (this.mp[k][i] read/write, JETH152):
//       resolveAccess now claims every fixed-index struct leaf; dynamic-index leaves keep their
//       verified structArrayElem owner.
// B-15  s2s assign + push of a multi-hop field (this.tgt = this.ps[0n].pre, this.stk.push(...)):
//       fixedArraySrcBase gained the placeRead slot resolution.
// L8    field-alias binds (let ys: u256[][] = m.g): a CALLDATA dyn-struct field deep-copies
//       (cdDynArrayField -> abiDecFromCdToImage); a MEMORY dyn-struct field ALIASES (pointer copy,
//       mutations visible both ways) - solc reference semantics.
// B-8   let m: Arr<In,2> = c ? this.sx : this.sy (ternary bind): a fresh pointer-headed copy via
//       aggArgToMemPtr's RC-2 transcode; mutation locality preserved.
// B-10  abi.encode(c ? [lit] : this.sx) both orders: the ternary checker infers an array-literal
//       branch's type from the non-literal branch when no outer expected type exists.
// B-9/C-7 access chains bottoming at a ternary ((c?A:B).length / [i].x / .a): desugared by pushing
//       the access into the branches (evaluation-order identical: cond once, access once on the
//       selected branch) - fires only where the existing machinery rejected, value-typed results only.
// L7(b) whole s.f (Arr<In,N> field of a memory struct) through the FLAT consumers (return /
//       abi.encode / tuple slot / indexed topic): reads as aggFieldRead (the flat sub-image kind);
//       the pointer channels (internal-arg / element-write) STAY rejected (R3 aliasing guard).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import type { LogEntry } from '../src/evm.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const run = async (J: string, S: string, calls: ReadonlyArray<readonly [string, string]>, compareLogs = false) => {
  const jh = await Harness.create();
  const sh = await Harness.create();
  await jh.fund(me, 10n ** 20n);
  await sh.fund(me, 10n ** 20n);
  const ja = await jh.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
  const sa = await sh.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
  for (const [sg, args] of calls) {
    const jr = await jh.call(ja, sel(sg) + args);
    const sr = await sh.call(sa, sel(sg) + args);
    expect(jr.returnHex, `${sg} ${args.slice(0, 12)}`).toBe(sr.returnHex);
    expect(jr.success, sg).toBe(sr.success);
    if (compareLogs) {
      const norm = (ls: LogEntry[]) => ls.map((l) => ({ t: l.topics, d: l.data }));
      expect(norm(jr.logs), sg).toEqual(norm(sr.logs));
    }
  }
  return { jh, ja };
};
const rejects = (src: string): boolean => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
};
const D = `type In = { x: u256; y: u256 };`;
const SD = `struct In { uint256 x; uint256 y; }`;

describe('Tier-2 OR lifts byte-identical to solc 0.8.35', () => {
  it('L12: fixed-array state initializers (full/short/packed/bool + tail zeros + longer-literal reject)', async () => {
    const J = `class C {
  arr: Arr<u256,3> = [11n, 22n];
  packed: Arr<u8,5> = [1n, 2n, 3n];
  bools: Arr<bool,3> = [true, false, true];
  aft: u256 = 42n;
  get g(i: u256): External<u256> { return this.arr[i]; }
  get gp(i: u256): External<u8> { return this.packed[i]; }
  get gb(i: u256): External<bool> { return this.bools[i]; }
  get ga(): External<u256> { return this.aft; } }`;
    const S = `contract C {
  uint256[3] arr = [uint256(11), 22];
  uint8[5] packed = [1, 2, 3];
  bool[3] bools = [true, false, true];
  uint256 aft = 42;
  function g(uint256 i) external view returns(uint256){ return arr[i]; }
  function gp(uint256 i) external view returns(uint8){ return packed[i]; }
  function gb(uint256 i) external view returns(bool){ return bools[i]; }
  function ga() external view returns(uint256){ return aft; } }`;
    const calls: [string, string][] = [];
    for (let i = 0; i < 3; i++) calls.push(['g(uint256)', W(i)], ['gb(uint256)', W(i)]);
    for (let i = 0; i < 5; i++) calls.push(['gp(uint256)', W(i)]);
    calls.push(['ga()', ''], ['g(uint256)', W(9)]);
    const { jh, ja } = await run(J, S, calls);
    expect(BigInt((await jh.call(ja, sel('g(uint256)') + W(2))).returnHex)).toBe(0n); // partial-fill tail
    expect(rejects(`class C { a: Arr<u256,2> = [1n,2n,3n]; get g(): External<u256> { return this.a[0n]; } }`)).toBe(true);
  });

  it('NEW-JETH152: mapping-rooted fixed-array whole-element read/write (+ nested map, dyn control)', async () => {
    const J = `${D} class C {
  mp: mapping<u256, Arr<In,2>>; nm: mapping<u256, mapping<u256, Arr<In,2>>>; md: mapping<u256, In[]>;
  seed(): External<void> { this.mp[5n][0n] = In(11n,12n); this.mp[5n][1n] = In(13n,14n); this.nm[1n][2n][1n] = In(31n,32n);
    this.md[9n].push(In(41n,42n)); this.md[9n].push(In(43n,44n)); }
  wr(k: u256, i: u256): External<void> { this.mp[k][i] = In(71n,72n); }
  get rd(k: u256, i: u256): External<In> { return this.mp[k][i]; }
  get rdn(): External<In> { return this.nm[1n][2n][1n]; }
  get chk(): External<u256> { return this.mp[5n][0n].x + 1000n*this.mp[5n][1n].y; }
  get ctlDyn(i: u256): External<In> { return this.md[9n][i]; } }`;
    const S = `${SD} contract C {
  mapping(uint256 => In[2]) mp; mapping(uint256 => mapping(uint256 => In[2])) nm; mapping(uint256 => In[]) md;
  function seed() external { mp[5][0] = In(11,12); mp[5][1] = In(13,14); nm[1][2][1] = In(31,32);
    md[9].push(In(41,42)); md[9].push(In(43,44)); }
  function wr(uint256 k, uint256 i) external { mp[k][i] = In(71,72); }
  function rd(uint256 k, uint256 i) external view returns(In memory){ return mp[k][i]; }
  function rdn() external view returns(In memory){ return nm[1][2][1]; }
  function chk() external view returns(uint256){ return mp[5][0].x + 1000*mp[5][1].y; }
  function ctlDyn(uint256 i) external view returns(In memory){ return md[9][i]; } }`;
    await run(J, S, [
      ['seed()', ''], ['rd(uint256,uint256)', W(5) + W(0)], ['rd(uint256,uint256)', W(5) + W(7)], ['rdn()', ''],
      ['chk()', ''], ['wr(uint256,uint256)', W(5) + W(1)], ['chk()', ''], ['wr(uint256,uint256)', W(5) + W(9)],
      ['ctlDyn(uint256)', W(0)], ['ctlDyn(uint256)', W(5)],
    ] as const);
  });

  it('B-15: s2s assign + push of a multi-hop storage field (dyn + nested-struct parents)', async () => {
    const J = `${D} type P = { pre: Arr<In,2>; n: u256 }; type Wr = { p: P; m: u256 };
class C {
  ps: P[]; w: Wr; tgt: Arr<In,2>; stk: Arr<In,2>[];
  seed(): External<void> { this.ps.push(); this.ps[0n].pre[0n] = In(11n,12n); this.ps[0n].pre[1n] = In(13n,14n);
    this.w.p.pre[0n] = In(61n,62n); this.w.p.pre[1n] = In(63n,64n); }
  asg(): External<void> { this.tgt = this.ps[0n].pre; }
  psh(): External<void> { this.stk.push(this.ps[0n].pre); this.stk.push(this.w.p.pre); }
  get rd(): External<u256> { return this.tgt[0n].x + 1000n*this.tgt[1n].y; }
  get rs(i: u256): External<u256> { return this.stk[i][0n].x + 1000n*this.stk[i][1n].y; } }`;
    const S = `${SD} struct P { In[2] pre; uint256 n; } struct Wr { P p; uint256 m; }
contract C {
  P[] ps; Wr w; In[2] tgt; In[2][] stk;
  function seed() external { ps.push(); ps[0].pre[0] = In(11,12); ps[0].pre[1] = In(13,14);
    w.p.pre[0] = In(61,62); w.p.pre[1] = In(63,64); }
  function asg() external { tgt = ps[0].pre; }
  function psh() external { stk.push(ps[0].pre); stk.push(w.p.pre); }
  function rd() external view returns(uint256){ return tgt[0].x + 1000*tgt[1].y; }
  function rs(uint256 i) external view returns(uint256){ return stk[i][0].x + 1000*stk[i][1].y; } }`;
    await run(J, S, [['seed()', ''], ['asg()', ''], ['rd()', ''], ['psh()', ''], ['rs(uint256)', W(0)], ['rs(uint256)', W(1)], ['rs(uint256)', W(9)]] as const);
  });

  it('L8: field-alias binds - calldata deep copy + memory alias (mutations visible both ways)', async () => {
    const J = `type Mm = { g: u256[][]; t: u256 };
class C {
  get f(m: Mm, i: u256, j: u256): External<u256> { let ys: u256[][] = m.g; return ys[i][j]; }
  get a1(m: Mm): External<u256> { let d: Mm = m; let ys: u256[][] = d.g; ys[0n][1n] = 77n; return d.g[0n][1n]; }
  get a2(m: Mm): External<u256> { let d: Mm = m; let ys: u256[][] = d.g; d.g[1n][0n] = 88n; return ys[1n][0n]; } }`;
    const S = `struct Mm { uint256[][] g; uint256 t; }
contract C {
  function f(Mm calldata m, uint256 i, uint256 j) external pure returns(uint256){ uint256[][] memory ys = m.g; return ys[i][j]; }
  function a1(Mm calldata m) external pure returns(uint256){ Mm memory d = m; uint256[][] memory ys = d.g; ys[0][1] = 77; return d.g[0][1]; }
  function a2(Mm calldata m) external pure returns(uint256){ Mm memory d = m; uint256[][] memory ys = d.g; d.g[1][0] = 88; return ys[1][0]; } }`;
    const g = W(2) + W(0x40) + W(0xa0) + W(2) + W(41) + W(42) + W(1) + W(43);
    const m = W(0x40) + W(9) + g;
    await run(J, S, [
      ['f((uint256[][],uint256),uint256,uint256)', W(0x60) + W(0) + W(1) + m],
      ['f((uint256[][],uint256),uint256,uint256)', W(0x60) + W(1) + W(5) + m],
      ['a1((uint256[][],uint256))', W(0x20) + m],
      ['a2((uint256[][],uint256))', W(0x20) + m],
    ] as const);
  });

  it('B-8/B-10: ternary bind (copy locality) + literal-branch ternary encode both orders', async () => {
    const J = `${D} class C {
  sx: Arr<In,2>; sy: Arr<In,2>;
  seed(): External<void> { this.sx[0n]=In(11n,12n); this.sx[1n]=In(13n,14n); this.sy[0n]=In(21n,22n); this.sy[1n]=In(23n,24n); }
  get b8(c: bool): External<u256> { let m: Arr<In,2> = c ? this.sx : this.sy; return m[0n].x + 1000n*m[1n].y; }
  get b8loc(c: bool): External<u256> { let m: Arr<In,2> = c ? this.sx : this.sy; m[0n].x = 99n; return this.sx[0n].x + this.sy[0n].x; }
  get b10(c: bool): External<bytes> { return abi.encode(c ? [In(41n,42n),In(43n,44n)] : this.sx); }
  get b10r(c: bool): External<bytes> { return abi.encode(c ? this.sx : [In(51n,52n),In(53n,54n)]); } }`;
    const S = `${SD} contract C {
  In[2] sx; In[2] sy;
  function seed() external { sx[0]=In(11,12); sx[1]=In(13,14); sy[0]=In(21,22); sy[1]=In(23,24); }
  function b8(bool c) external view returns(uint256){ In[2] memory m = c ? sx : sy; return m[0].x + 1000*m[1].y; }
  function b8loc(bool c) external view returns(uint256){ In[2] memory m = c ? sx : sy; m[0].x = 99; return sx[0].x + sy[0].x; }
  function b10(bool c) external view returns(bytes memory){ In[2] memory L = [In(41,42),In(43,44)]; return abi.encode(c ? L : sx); }
  function b10r(bool c) external view returns(bytes memory){ In[2] memory L = [In(51,52),In(53,54)]; return abi.encode(c ? sx : L); } }`;
    await run(J, S, [
      ['seed()', ''], ['b8(bool)', W(1)], ['b8(bool)', W(0)], ['b8loc(bool)', W(1)],
      ['b10(bool)', W(1)], ['b10(bool)', W(0)], ['b10r(bool)', W(1)], ['b10r(bool)', W(0)],
    ] as const);
  });

  it('B-9/C-7: access chains on a ternary (.length / [i].x / .a) incl side-effect-count parity', async () => {
    const J = `${D} type Sd = { a: u256; t: bytes };
class C {
  sx: Arr<In,2>; sy: Arr<In,2>; s1: Sd; s2: Sd; hits: u256;
  seed(): External<void> { this.sx[0n]=In(11n,12n); this.sx[1n]=In(13n,14n); this.sy[0n]=In(21n,22n); this.sy[1n]=In(23n,24n);
    this.s1 = Sd(31n, bytes("aa")); this.s2 = Sd(41n, bytes("bbb")); }
  eff(): bool { this.hits = this.hits + 1n; return this.hits > 1n; }
  get b9len(c: bool): External<u256> { return (c ? this.sx : this.sy).length; }
  get b9elem(c: bool, i: u256): External<u256> { return (c ? this.sx : this.sy)[i].y; }
  get c7(c: bool): External<u256> { return (c ? this.s1 : this.s2).a; }
  effOrder(): External<u256> { return (this.eff() ? this.sx : this.sy)[0n].x + 100000n*this.hits; } }`;
    const S = `${SD} struct Sd { uint256 a; bytes t; }
contract C {
  In[2] sx; In[2] sy; Sd s1; Sd s2; uint256 hits;
  function seed() external { sx[0]=In(11,12); sx[1]=In(13,14); sy[0]=In(21,22); sy[1]=In(23,24);
    s1 = Sd(31, hex"6161"); s2 = Sd(41, hex"626262"); }
  function eff() internal returns(bool){ hits = hits + 1; return hits > 1; }
  function b9len(bool c) external view returns(uint256){ return (c ? sx : sy).length; }
  function b9elem(bool c, uint256 i) external view returns(uint256){ return (c ? sx : sy)[i].y; }
  function c7(bool c) external view returns(uint256){ return (c ? s1 : s2).a; }
  function effOrder() external returns(uint256){ return (eff() ? sx : sy)[0].x + 100000*hits; } }`;
    await run(J, S, [
      ['seed()', ''], ['b9len(bool)', W(1)], ['b9len(bool)', W(0)],
      ['b9elem(bool,uint256)', W(1) + W(1)], ['b9elem(bool,uint256)', W(0) + W(5)],
      ['c7(bool)', W(1)], ['c7(bool)', W(0)], ['effOrder()', ''], ['effOrder()', ''],
    ] as const);
  });

  it('L7(b): whole s.f through the FLAT consumers (return/encode/tuple/topic); pointer channels stay rejected', async () => {
    const J = `${D} type S1 = { f: Arr<In,2>; n: u256 };
class C {
  E: event<{ v: indexed<Arr<In,2>>; t: u256 }>;
  get g(): External<Arr<In,2>> { const s: S1 = S1([In(1n,2n),In(3n,4n)], 5n); return s.f; }
  get ge(): External<bytes> { const s: S1 = S1([In(1n,2n),In(3n,4n)], 5n); return abi.encode(s.f); }
  get gt(): External<[u256, Arr<In,2>]> { const s: S1 = S1([In(6n,7n),In(8n,9n)], 5n); return [77n, s.f]; }
  em(): External<void> { const s: S1 = S1([In(11n,12n),In(13n,14n)], 5n); emit(E(s.f, 9n)); }
  get leaf(): External<u256> { const s: S1 = S1([In(1n,2n),In(3n,4n)], 5n); return s.f[1n].y + s.n; } }`;
    const S = `${SD} struct S1 { In[2] f; uint256 n; }
contract C {
  event E(In[2] indexed v, uint256 t);
  function g() external pure returns(In[2] memory){ S1 memory s = S1([In(1,2),In(3,4)], 5); return s.f; }
  function ge() external pure returns(bytes memory){ S1 memory s = S1([In(1,2),In(3,4)], 5); return abi.encode(s.f); }
  function gt() external pure returns(uint256, In[2] memory){ S1 memory s = S1([In(6,7),In(8,9)], 5); return (77, s.f); }
  function em() external { S1 memory s = S1([In(11,12),In(13,14)], 5); emit E(s.f, 9); }
  function leaf() external pure returns(uint256){ S1 memory s = S1([In(1,2),In(3,4)], 5); return s.f[1].y + s.n; } }`;
    await run(J, S, [['g()', ''], ['ge()', ''], ['gt()', ''], ['em()', ''], ['leaf()', '']] as const, true);
    const DD = `${D} type S1 = { f: Arr<In,2>; n: u256 };`;
    expect(rejects(`${DD} class C { take(a: Arr<In,2>): u256 { return a[0n].x; } get f(): External<u256> { const s: S1 = S1([In(1n,2n),In(3n,4n)], 5n); return this.take(s.f); } }`)).toBe(true);
    expect(rejects(`${DD} class C { get f(): External<u256> { const s: S1 = S1([In(1n,2n),In(3n,4n)], 5n); let o: Arr<In,2>[] = new Array<Arr<In,2>>(1n); o[0n] = s.f; return o[0n][0n].x; } }`)).toBe(true);
  });

  it('L7(b) extra shapes: nested Arr<Arr<In,2>,2> field + single-field-ctor struct (old S3 controls)', async () => {
    const J = `${D} type Q = { arr: Arr<In,2> }; type N2 = { g: Arr<Arr<In,2>,2>; n: u256 };
class C {
  get f(): External<Arr<In,2>> { let q: Q = Q([In(1n,2n),In(3n,4n)]); return q.arr; }
  get fe(): External<bytes> { let q: Q = Q([In(1n,2n),In(3n,4n)]); return abi.encode(q.arr); }
  get gn(): External<bytes> { let s: N2 = N2([[In(11n,12n),In(13n,14n)],[In(15n,16n),In(17n,18n)]], 9n); return abi.encode(s.g); }
  get gr(): External<Arr<Arr<In,2>,2>> { let s: N2 = N2([[In(11n,12n),In(13n,14n)],[In(15n,16n),In(17n,18n)]], 9n); return s.g; } }`;
    const S = `${SD} struct Q { In[2] arr; } struct N2 { In[2][2] g; uint256 n; }
contract C {
  function f() external pure returns(In[2] memory){ Q memory q = Q([In(1,2),In(3,4)]); return q.arr; }
  function fe() external pure returns(bytes memory){ Q memory q = Q([In(1,2),In(3,4)]); return abi.encode(q.arr); }
  function gn() external pure returns(bytes memory){ N2 memory s = N2([[In(11,12),In(13,14)],[In(15,16),In(17,18)]], 9); return abi.encode(s.g); }
  function gr() external pure returns(In[2][2] memory){ N2 memory s = N2([[In(11,12),In(13,14)],[In(15,16),In(17,18)]], 9); return s.g; } }`;
    await run(J, S, [['f()', ''], ['fe()', ''], ['gn()', ''], ['gr()', '']] as const);
  });

  it('desugar guard: cd|cd indexed ternary lifted with DIRTY-u8 validate parity; st|cd stays rejected', async () => {
    expect(rejects(`class C { s: u256[]; get f(c: bool, x: u256[], i: u256): External<u256> { return (c ? this.s : x)[i]; } }`)).toBe(true);
    const J = `class C { get f(c: bool, x: u8[], y: u8[], i: u256): External<u256> { return (c ? x : y)[i]; } }`;
    const S = `contract C { function f(bool c, uint8[] calldata x, uint8[] calldata y, uint256 i) external pure returns(uint256){ return uint256((c ? x : y)[i]); } }`;
    const sig = 'f(bool,uint8[],uint8[],uint256)';
    const arr = (vals: (number | string)[]) => W(vals.length) + vals.map((v) => (typeof v === 'string' ? v : W(v))).join('');
    const dirty = '00000000000000000000000000000000000000000000000000000000000001ff';
    const enc = (c: number, i: number, xv: (number | string)[], yv: (number | string)[]) =>
      W(c) + W(0xa0) + W(0xa0 + 32 * (1 + xv.length)) + W(i) + arr(xv) + arr(yv);
    await run(J, S, [
      [sig, enc(1, 0, [7, 8], [9])], [sig, enc(0, 0, [7, 8], [9])], [sig, enc(1, 5, [7, 8], [9])],
      [sig, enc(1, 1, [7, dirty], [9])], [sig, enc(0, 0, [7, dirty], [9])],
    ] as const);
  });
});
