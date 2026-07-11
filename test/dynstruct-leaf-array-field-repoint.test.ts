// NF-2 lift: re-pointing a dynamic-struct LEAF-array field whose element is itself DYNAMIC -
// string[] / bytes[] / T[][] (isDynStructLeafArrayField) - from a MEMORY source, through a storage
// struct-array element (this.ps[i].names = s), a mapping value (this.m[k].names = s), a nested struct
// field (this.o.inner.names = s), and a bare storage struct field (this.p.names = s). Previously JETH067
// (indexed/mapping/nested targets) or JETH226 (bare struct field). The `place` target the analyzer now
// produces routes through copyArrayValueIntoStorage -> copyMemAggArrayIntoStorage (the pointer-headed B4
// image deep-copy that this.vals.push(D(...)) / writeStruct already use), overwrite-clearing freed element
// slots + freed keccak long-data on a long->short re-point. Byte-identical to solc 0.8.35, verified BOTH by
// getter read-back AND by direct storage-slot comparison (base struct slot, the field [len] slot, each
// element string header, and the freed slots after a shrink). A CALLDATA leaf-array source stays a clean
// reject (solc rejects that copy too); a STORAGE source is admitted (copyArray deep-copies storage->storage).
import { describe, it, expect } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => n.toString(16).padStart(64, '0');
const pad = (v: bigint) => v.toString(16).padStart(64, '0');
const slotKeccak = (p: bigint) => BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(p)) as `0x${string}`))));
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function deployBoth(jeth: string, sol: string) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { hj, hs, aj, as };
}

async function eqCalls(
  ctx: { hj: Harness; hs: Harness; aj: Address; as: Address },
  calls: [string, string][],
) {
  for (const [sig, args] of calls) {
    const rj = await ctx.hj.call(ctx.aj, sel(sig) + args);
    const rs = await ctx.hs.call(ctx.as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

async function eqSlots(
  ctx: { hj: Harness; hs: Harness; aj: Address; as: Address },
  slots: [string, bigint][],
) {
  for (const [name, slot] of slots) {
    const sj = await readSlot(ctx.hj, ctx.aj, slot);
    const ss = await readSlot(ctx.hs, ctx.as, slot);
    expect(sj, `slot ${name} @0x${slot.toString(16)}`).toBe(ss);
  }
}

describe('dyn-struct leaf-array field re-point (string[]/bytes[]/T[][]) - byte-identical to solc 0.8.35', () => {
  it('struct-array element field: this.ps[i].names = <memory string[]> (PRIMARY, JETH067)', async () => {
    const J = `type P = { a: u256; names: string[] };
class C { ps: P[];
  run(): External<void> {
    let e0: string[] = new Array<string>(0n);
    this.ps.push(P(11n, e0)); this.ps.push(P(22n, e0));
    let s: string[] = new Array<string>(2n); s[0n] = "hello"; s[1n] = "worldy";
    this.ps[0n].names = s;
    this.ps[0n].a = 7n;
  }
  get a(i: u256): External<u256> { return this.ps[i].a; }
  get n(i: u256, j: u256): External<string> { return this.ps[i].names[j]; }
  get len(i: u256): External<u256> { return this.ps[i].names.length; } }`;
    const S = `contract C { struct P { uint256 a; string[] names; } P[] ps;
  function run() external {
    string[] memory e0 = new string[](0);
    ps.push(P(11, e0)); ps.push(P(22, e0));
    string[] memory s = new string[](2); s[0] = "hello"; s[1] = "worldy";
    ps[0].names = s;
    ps[0].a = 7;
  }
  function a(uint256 i) external view returns (uint256) { return ps[i].a; }
  function n(uint256 i, uint256 j) external view returns (string memory) { return ps[i].names[j]; }
  function len(uint256 i) external view returns (uint256) { return ps[i].names.length; } }`;
    const ctx = await deployBoth(J, S);
    await eqCalls(ctx, [['run()', '']]);
    // read-back
    await eqCalls(ctx, [
      ['a(uint256)', W(0n)], ['a(uint256)', W(1n)],
      ['n(uint256,uint256)', W(0n) + W(0n)], ['n(uint256,uint256)', W(0n) + W(1n)],
      ['len(uint256)', W(0n)], ['len(uint256)', W(1n)],
    ]);
    // slot-level: ps@0 (stride 2). elem0 base = keccak(0); a@base, names.len@base+1.
    const base0 = slotKeccak(0n);
    const namesLen0 = base0 + 1n;
    const namesElem = (j: bigint) => slotKeccak(namesLen0) + j;
    await eqSlots(ctx, [
      ['ps.length', 0n],
      ['ps[0].a', base0],
      ['ps[0].names.len', namesLen0],
      ['ps[0].names[0] hdr', namesElem(0n)],
      ['ps[0].names[1] hdr', namesElem(1n)],
      ['ps[1].a', base0 + 2n],
      ['ps[1].names.len', base0 + 3n],
    ]);
  });

  it('long->short re-point OVERWRITE zeroes freed element slots + freed keccak long-data', async () => {
    const long0 = 'LONG string zero exceeding thirty two bytes absolutely for sure ok yes';
    const long1 = 'LONG string one also exceeding the thirty-two byte inline boundary ok!!';
    const long2 = 'LONG string two exceeding thirty-two bytes as well definitely yes okok!';
    const J = `type P = { a: u256; names: string[] };
class C { ps: P[];
  run(): External<void> {
    let e0: string[] = new Array<string>(0n);
    this.ps.push(P(77n, e0)); this.ps.push(P(88n, e0));
    let big: string[] = new Array<string>(3n);
    big[0n] = "${long0}"; big[1n] = "${long1}"; big[2n] = "${long2}";
    this.ps[0n].names = big;
    let small: string[] = new Array<string>(1n); small[0n] = "z";
    this.ps[0n].names = small;
  }
  get len(i: u256): External<u256> { return this.ps[i].names.length; }
  get n(i: u256, j: u256): External<string> { return this.ps[i].names[j]; } }`;
    const S = `contract C { struct P { uint256 a; string[] names; } P[] ps;
  function run() external {
    string[] memory e0 = new string[](0);
    ps.push(P(77, e0)); ps.push(P(88, e0));
    string[] memory big = new string[](3);
    big[0] = "${long0}"; big[1] = "${long1}"; big[2] = "${long2}";
    ps[0].names = big;
    string[] memory small = new string[](1); small[0] = "z";
    ps[0].names = small;
  }
  function len(uint256 i) external view returns (uint256) { return ps[i].names.length; }
  function n(uint256 i, uint256 j) external view returns (string memory) { return ps[i].names[j]; } }`;
    const ctx = await deployBoth(J, S);
    await eqCalls(ctx, [['run()', ''], ['len(uint256)', W(0n)], ['n(uint256,uint256)', W(0n) + W(0n)]]);
    const base0 = slotKeccak(0n);
    const namesLen0 = base0 + 1n;
    const namesElem = (j: bigint) => slotKeccak(namesLen0) + j;
    await eqSlots(ctx, [
      ['ps[0].a', base0],
      ['ps[0].names.len', namesLen0],
      ['ps[0].names[0] hdr', namesElem(0n)],
      ['ps[0].names[1] hdr (freed)', namesElem(1n)],
      ['ps[0].names[2] hdr (freed)', namesElem(2n)],
      // freed keccak long-data of old elements 1 and 2 must be zeroed
      ['old names[1] data0 (freed)', slotKeccak(namesElem(1n))],
      ['old names[1] data1 (freed)', slotKeccak(namesElem(1n)) + 1n],
      ['old names[2] data0 (freed)', slotKeccak(namesElem(2n))],
      // neighbor ps[1] intact
      ['ps[1].a', base0 + 2n],
      ['ps[1].names.len', base0 + 3n],
    ]);
  });

  it('mapping value struct field: this.m[k].names = <memory string[]> (JETH067)', async () => {
    const J = `type P = { a: u256; names: string[] };
class C { m: mapping<u256, P>;
  run(): External<void> {
    let s: string[] = new Array<string>(2n); s[0n] = "alpha"; s[1n] = "beta";
    this.m[7n].names = s; this.m[7n].a = 99n;
  }
  get a(): External<u256> { return this.m[7n].a; }
  get n(j: u256): External<string> { return this.m[7n].names[j]; } }`;
    const S = `contract C { struct P { uint256 a; string[] names; } mapping(uint256 => P) m;
  function run() external {
    string[] memory s = new string[](2); s[0] = "alpha"; s[1] = "beta";
    m[7].names = s; m[7].a = 99;
  }
  function a() external view returns (uint256) { return m[7].a; }
  function n(uint256 j) external view returns (string memory) { return m[7].names[j]; } }`;
    const ctx = await deployBoth(J, S);
    await eqCalls(ctx, [['run()', ''], ['a()', ''], ['n(uint256)', W(0n)], ['n(uint256)', W(1n)]]);
  });

  it('nested struct field: this.o.inner.names = <memory string[]> (JETH067)', async () => {
    const J = `type Inner = { a: u256; names: string[] };
type Outer = { z: u256; inner: Inner };
class C { o: Outer;
  run(): External<void> {
    let s: string[] = new Array<string>(1n); s[0n] = "deep-and-fairly-long-value-over-thirty-two-bytes-yes";
    this.o.inner.names = s; this.o.z = 42n;
  }
  get z(): External<u256> { return this.o.z; }
  get n(j: u256): External<string> { return this.o.inner.names[j]; } }`;
    const S = `contract C { struct Inner { uint256 a; string[] names; } struct Outer { uint256 z; Inner inner; } Outer o;
  function run() external {
    string[] memory s = new string[](1); s[0] = "deep-and-fairly-long-value-over-thirty-two-bytes-yes";
    o.inner.names = s; o.z = 42;
  }
  function z() external view returns (uint256) { return o.z; }
  function n(uint256 j) external view returns (string memory) { return o.inner.names[j]; } }`;
    const ctx = await deployBoth(J, S);
    await eqCalls(ctx, [['run()', ''], ['z()', ''], ['n(uint256)', W(0n)]]);
    // o@0: z@0, inner@1 (a@1, names.len@2)
    const namesLen = 2n;
    await eqSlots(ctx, [
      ['o.z', 0n], ['o.inner.a', 1n], ['o.inner.names.len', namesLen],
      ['o.inner.names[0] hdr', slotKeccak(namesLen)],
      ['o.inner.names[0] data0', slotKeccak(slotKeccak(namesLen))],
    ]);
  });

  it('bare storage struct field: this.p.names = <memory string[]> (was JETH226)', async () => {
    const J = `type P = { a: u256; names: string[] };
class C { p: P;
  run(): External<void> {
    let s: string[] = new Array<string>(2n); s[0n] = "one"; s[1n] = "two";
    this.p.names = s; this.p.a = 5n;
  }
  get a(): External<u256> { return this.p.a; }
  get n(j: u256): External<string> { return this.p.names[j]; } }`;
    const S = `contract C { struct P { uint256 a; string[] names; } P p;
  function run() external {
    string[] memory s = new string[](2); s[0] = "one"; s[1] = "two";
    p.names = s; p.a = 5;
  }
  function a() external view returns (uint256) { return p.a; }
  function n(uint256 j) external view returns (string memory) { return p.names[j]; } }`;
    const ctx = await deployBoth(J, S);
    await eqCalls(ctx, [['run()', ''], ['a()', ''], ['n(uint256)', W(0n)], ['n(uint256)', W(1n)]]);
    // p@0: a@0, names.len@1
    await eqSlots(ctx, [
      ['p.a', 0n], ['p.names.len', 1n],
      ['p.names[0] hdr', slotKeccak(1n)], ['p.names[1] hdr', slotKeccak(1n) + 1n],
    ]);
  });

  it('bytes[] leaf field: this.ps[i].blobs = <memory bytes[]>', async () => {
    const J = `type P = { a: u256; blobs: bytes[] };
class C { ps: P[];
  run(): External<void> {
    let e0: bytes[] = new Array<bytes>(0n);
    this.ps.push(P(0n, e0));
    let s: bytes[] = new Array<bytes>(2n); s[0n] = bytes("hi"); s[1n] = bytes("world-and-a-long-tail-over-thirty-two-bytes!!");
    this.ps[0n].blobs = s;
  }
  get b(i: u256, j: u256): External<bytes> { return this.ps[i].blobs[j]; } }`;
    const S = `contract C { struct P { uint256 a; bytes[] blobs; } P[] ps;
  function run() external {
    bytes[] memory e0 = new bytes[](0);
    ps.push(P(0, e0));
    bytes[] memory s = new bytes[](2); s[0] = bytes("hi"); s[1] = bytes("world-and-a-long-tail-over-thirty-two-bytes!!");
    ps[0].blobs = s;
  }
  function b(uint256 i, uint256 j) external view returns (bytes memory) { return ps[i].blobs[j]; } }`;
    const ctx = await deployBoth(J, S);
    await eqCalls(ctx, [['run()', ''], ['b(uint256,uint256)', W(0n) + W(0n)], ['b(uint256,uint256)', W(0n) + W(1n)]]);
  });

  it('u256[][] leaf field: this.ps[i].grid = <memory u256[][]>', async () => {
    const J = `type P = { a: u256; grid: u256[][] };
class C { ps: P[];
  run(): External<void> {
    let e0: u256[][] = new Array<u256[]>(0n);
    this.ps.push(P(0n, e0));
    let r0: u256[] = new Array<u256>(2n); r0[0n]=1n; r0[1n]=2n;
    let r1: u256[] = new Array<u256>(1n); r1[0n]=9n;
    let s: u256[][] = new Array<u256[]>(2n); s[0n]=r0; s[1n]=r1;
    this.ps[0n].grid = s;
  }
  get g(i: u256, j: u256, k: u256): External<u256> { return this.ps[i].grid[j][k]; }
  get rl(i: u256, j: u256): External<u256> { return this.ps[i].grid[j].length; } }`;
    const S = `contract C { struct P { uint256 a; uint256[][] grid; } P[] ps;
  function run() external {
    uint256[][] memory e0 = new uint256[][](0);
    ps.push(P(0, e0));
    uint256[] memory r0 = new uint256[](2); r0[0]=1; r0[1]=2;
    uint256[] memory r1 = new uint256[](1); r1[0]=9;
    uint256[][] memory s = new uint256[][](2); s[0]=r0; s[1]=r1;
    ps[0].grid = s;
  }
  function g(uint256 i, uint256 j, uint256 k) external view returns (uint256) { return ps[i].grid[j][k]; }
  function rl(uint256 i, uint256 j) external view returns (uint256) { return ps[i].grid[j].length; } }`;
    const ctx = await deployBoth(J, S);
    await eqCalls(ctx, [
      ['run()', ''],
      ['g(uint256,uint256,uint256)', W(0n) + W(0n) + W(0n)],
      ['g(uint256,uint256,uint256)', W(0n) + W(0n) + W(1n)],
      ['g(uint256,uint256,uint256)', W(0n) + W(1n) + W(0n)],
      ['rl(uint256,uint256)', W(0n) + W(0n)],
      ['rl(uint256,uint256)', W(0n) + W(1n)],
    ]);
  });

  it('array-literal source: this.ps[i].names = ["aa","bb","cc"]', async () => {
    const J = `type P = { a: u256; names: string[] };
class C { ps: P[];
  run(): External<void> {
    let e0: string[] = new Array<string>(0n);
    this.ps.push(P(0n, e0));
    this.ps[0n].names = ["aa", "bb", "cc"];
  }
  get n(j: u256): External<string> { return this.ps[0n].names[j]; } }`;
    const S = `contract C { struct P { uint256 a; string[] names; } P[] ps;
  function run() external {
    string[] memory e0 = new string[](0);
    ps.push(P(0, e0));
    string[] memory s = new string[](3); s[0]="aa"; s[1]="bb"; s[2]="cc";
    ps[0].names = s;
  }
  function n(uint256 j) external view returns (string memory) { return ps[0].names[j]; } }`;
    const ctx = await deployBoth(J, S);
    await eqCalls(ctx, [['run()', ''], ['n(uint256)', W(0n)], ['n(uint256)', W(2n)]]);
  });

  it('storage source is admitted: this.ps[i].names = this.src (state string[])', async () => {
    const J = `type P = { a: u256; names: string[] };
class C { ps: P[]; src: string[];
  run(): External<void> {
    let e0: string[] = new Array<string>(0n);
    this.ps.push(P(0n, e0));
    this.src.push("aa"); this.src.push("bbbb-and-longer-than-thirty-two-bytes-for-real-yes");
    this.ps[0n].names = this.src;
  }
  get n(j: u256): External<string> { return this.ps[0n].names[j]; } }`;
    const S = `contract C { struct P { uint256 a; string[] names; } P[] ps; string[] src;
  function run() external {
    string[] memory e0 = new string[](0);
    ps.push(P(0, e0));
    src.push("aa"); src.push("bbbb-and-longer-than-thirty-two-bytes-for-real-yes");
    ps[0].names = src;
  }
  function n(uint256 j) external view returns (string memory) { return ps[0].names[j]; } }`;
    const ctx = await deployBoth(J, S);
    await eqCalls(ctx, [['run()', ''], ['n(uint256)', W(0n)], ['n(uint256)', W(1n)]]);
  });

  it('calldata leaf-array source stays a clean reject (JETH200; solc also rejects that copy)', () => {
    const J = `type P = { a: u256; names: string[] };
class C { ps: P[];
  run(s: string[]): External<void> {
    let e0: string[] = new Array<string>(0n);
    this.ps.push(P(0n, e0));
    this.ps[0n].names = s;
  } }`;
    let codes: string[] = [];
    try {
      compile(J, { fileName: 'C.jeth' });
    } catch (e: unknown) {
      codes = ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
    }
    expect(codes).toContain('JETH200');
  });
});
