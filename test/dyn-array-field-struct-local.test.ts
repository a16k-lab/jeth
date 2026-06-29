// JETH200 lift: a struct MEMORY LOCAL whose struct has a dynamic VALUE-element ARRAY field
// (`let p: S = S(a, ys, b)` / `= this.s`, where S { a: u256; xs: u256[]; b: u256; }). The local is a
// pointer-headed image: value fields inline, the array field a pointer to [len][elems] (like a
// bytes field). Supports construct (from a constructor / storage / another local), read (p.a / p.xs
// whole / p.xs.length / p.xs[i]), and whole-struct `return p`. Byte-identical to solc 0.8.35.
// Gated cleanly (JETH200): cd-source construct, storage construct, array-field write, string[]/T[][] fields.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
const cdArr = (xs: readonly bigint[]) => pad32(BigInt(xs.length)) + xs.map(pad32).join('');
function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}

describe('dynamic-array-field struct memory local (JETH200) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `@struct class S { a: u256; xs: u256[]; b: u256; }
@contract class C {
  @external @pure mk(ys: u256[], a: u256, b: u256): S { let p: S = S(a, ys, b); return p; }
  @external @pure rd(ys: u256[], i: u256): u256 { let p: S = S(7n, ys, 9n); return p.xs[i]; }
  @external @pure rlen(ys: u256[]): u256 { let p: S = S(7n, ys, 9n); return p.xs.length; }
  @external @pure rab(ys: u256[]): u256 { let p: S = S(7n, ys, 9n); return p.a + p.b; }
  @external @pure sumLocal(ys: u256[]): u256 { let p: S = S(1n, ys, 2n); let t: u256 = 0n; for (const v of p.xs) { t = t + v; } return t; }
  @state s: S;
  @external setSa(v: u256): void { this.s.a = v; }
  @external setSb(v: u256): void { this.s.b = v; }
  @external pushSx(v: u256): void { this.s.xs.push(v); }
  @external @view cpRet(): S { let p: S = this.s; return p; }
  @external @view cpIdx(i: u256): u256 { let p: S = this.s; return p.xs[i]; } }`;
  const So = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  struct S { uint256 a; uint256[] xs; uint256 b; }
  function mk(uint256[] calldata ys, uint256 a, uint256 b) external pure returns (S memory) { S memory p = S(a, ys, b); return p; }
  function rd(uint256[] calldata ys, uint256 i) external pure returns (uint256) { S memory p = S(7, ys, 9); return p.xs[i]; }
  function rlen(uint256[] calldata ys) external pure returns (uint256) { S memory p = S(7, ys, 9); return p.xs.length; }
  function rab(uint256[] calldata ys) external pure returns (uint256) { S memory p = S(7, ys, 9); return p.a + p.b; }
  function sumLocal(uint256[] calldata ys) external pure returns (uint256) { S memory p = S(1, ys, 2); uint256 t=0; for (uint256 i=0;i<p.xs.length;i++){t+=p.xs[i];} return t; }
  S s;
  function setSa(uint256 v) external { s.a = v; }
  function setSb(uint256 v) external { s.b = v; }
  function pushSx(uint256 v) external { s.xs.push(v); }
  function cpRet() external view returns (S memory) { S memory p = s; return p; }
  function cpIdx(uint256 i) external view returns (uint256) { S memory p = s; return p.xs[i]; } }`;

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(So, 'C').creation);
  });
  const cmp = async (data: string, label: string) => {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
  };

  it('construct + read (value fields, p.xs[i], p.xs.length, for-of) byte-identical', async () => {
    const ys = [10n, 20n, 30n];
    for (const [v, len] of [
      [[3n, 5n, 8n, 13n], 4],
      [[42n], 1],
      [[], 0],
    ] as const) {
      void len;
      const tail = pad32(BigInt(v.length)) + v.map(pad32).join('');
      await cmp('0x' + sel('rlen(uint256[])') + pad32(0x20n) + tail, `rlen(${v.length})`);
      await cmp('0x' + sel('rab(uint256[])') + pad32(0x20n) + tail, `rab(${v.length})`);
      await cmp('0x' + sel('sumLocal(uint256[])') + pad32(0x20n) + tail, `sumLocal(${v.length})`);
    }
    for (const i of [0n, 1n, 2n, 5n])
      await cmp('0x' + sel('rd(uint256[],uint256)') + pad32(0x40n) + pad32(i) + cdArr(ys), `rd[${i}]`);
  });
  it('whole-struct return (the array-field tail encoder) byte-identical', async () => {
    for (const ys of [[10n, 20n, 30n], [], [99n]] as const) {
      const data = '0x' + sel('mk(uint256[],uint256,uint256)') + pad32(0x60n) + pad32(7n) + pad32(9n) + cdArr(ys);
      await cmp(data, `mk(${ys.length})`);
    }
  });
  it('copy from storage -> read + whole return byte-identical (raw slots independent)', async () => {
    const run = async (d: string) => {
      await jeth.call(aj, d);
      await sol.call(as, d);
    };
    await run('0x' + sel('setSa(uint256)') + pad32(11n));
    await run('0x' + sel('setSb(uint256)') + pad32(99n));
    for (const v of [5n, 6n, 7n]) await run('0x' + sel('pushSx(uint256)') + pad32(v));
    await cmp('0x' + sel('cpRet()'), 'cpRet');
    for (const i of [0n, 1n, 2n]) await cmp('0x' + sel('cpIdx(uint256)') + pad32(i), `cpIdx[${i}]`);
  });
  it('clean gates: cd-construct, storage construct; array-field re-point now ACCEPTS', () => {
    const Sd = '@struct class S { a: u256; xs: u256[]; b: u256; }\n';
    // re-pointing a dynamic-array field of a memory struct (p.xs = ys) is now SUPPORTED (Batch B,
    // byte-identical to solc - see dyn-struct-nested-aggregate-field.test.ts). A calldata source is
    // copied to memory, exactly like solc's calldata->memory assignment.
    expect(
      codes(
        Sd +
          '@contract class C { @external @pure f(ys: u256[]): u256 { let p: S = S(1n, ys, 2n); p.xs = ys; return p.a; } }',
      ),
    ).toEqual([]);
    // A string[] / bytes[] struct FIELD is now SUPPORTED (Cat C, byte-identical to solc - see
    // dyn-struct-nested-leaf-array-field.test.ts). The constructor takes a typed array value.
    expect(
      codes(
        '@struct class T { a: u256; ts: string[]; }\n@contract class C { @external @pure f(): u256 { let t: string[] = ["x"]; let p: T = T(1n, t); return p.a; } }',
      ),
    ).toEqual([]);
    // An array LITERAL as a struct-constructor arg still rejects (JETH226), exactly as solc rejects it
    // (solc requires a typed `new string[](0)`, not a `[]` literal, for a struct array field arg).
    expect(
      codes(
        '@struct class T { a: u256; ts: string[]; }\n@contract class C { @external @pure f(): u256 { let p: T = T(1n, []); return p.a; } }',
      ),
    ).toContain('JETH226');
  });
});

// B3: an ARRAY of dynamic-field structs as a MEMORY local (`let xs: P[]`, P with a bytes/string or
// dynamic value-array field). Each element is an absolute pointer to a pointer-headed dyn-struct image
// (the same image a single dyn-struct local uses), zero-init'd to empty sentinels by `new P[](n)`.
// Construct (new / literal), read (xs[i].a / xs[i].s / xs[i].arr[j] / .length / whole xs[i]), write
// (xs[i].a=v / xs[i].s=<bytes> / xs[i].arr=<u256[]> / xs[i].arr[j]=v / xs[i]=P(..)), return, encode,
// abi.decode. Byte-identical to solc 0.8.35; OOB -> Panic 0x32, new n>=2^64 -> Panic 0x41.
describe('B3: dynamic-field struct ARRAY memory local (P[]) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `@struct class P { a: u256; s: bytes; }
@struct class Q { a: u256; arr: u256[]; }
@contract class C {
  @external @pure mk(n: u256): P[] { let xs: P[] = new Array<P>(n); return xs; }
  @external @pure mkLen(n: u256): u256 { let xs: P[] = new Array<P>(n); return xs.length; }
  @external @pure zeroSLen(): u256 { let xs: P[] = new Array<P>(2n); return xs[1n].s.length; }
  @external @pure lit(a1: u256, s1: bytes, a2: u256, s2: bytes): P[] { let xs: P[] = [P(a1,s1), P(a2,s2)]; return xs; }
  @external @pure getA(a1: u256, s1: bytes, a2: u256, s2: bytes): u256 { let xs: P[] = [P(a1,s1), P(a2,s2)]; return xs[1n].a; }
  @external @pure getS(a1: u256, s1: bytes, a2: u256, s2: bytes): bytes { let xs: P[] = [P(a1,s1), P(a2,s2)]; return xs[0n].s; }
  @external @pure getElem(a1: u256, s1: bytes, a2: u256, s2: bytes): P { let xs: P[] = [P(a1,s1), P(a2,s2)]; return xs[0n]; }
  @external @pure oob(a1: u256, s1: bytes): u256 { let xs: P[] = [P(a1,s1)]; return xs[5n].a; }
  @external @pure huge(): P[] { let xs: P[] = new Array<P>(18446744073709551616n); return xs; }
  @external @pure enc(a1: u256, s1: bytes, a2: u256, s2: bytes): bytes { let xs: P[] = [P(a1,s1), P(a2,s2)]; return abi.encode(xs); }
  @external @pure setA(v: u256): P[] { let xs: P[] = new Array<P>(2n); xs[0n].a = v; xs[1n].a = v + 1n; return xs; }
  @external @pure setS(b: bytes): P[] { let xs: P[] = new Array<P>(2n); xs[0n].s = b; return xs; }
  @external @pure setElem(a1: u256, s1: bytes): P[] { let xs: P[] = new Array<P>(2n); xs[0n] = P(a1, s1); return xs; }
  @external @pure setArr(arr: u256[]): Q[] { let xs: Q[] = new Array<Q>(2n); xs[1n].arr = arr; xs[1n].a = 7n; return xs; }
  @external @pure setArrElem(): Q[] { let xs: Q[] = new Array<Q>(1n); xs[0n].arr = [1n,2n,3n]; xs[0n].arr[1n] = 99n; return xs; }
  @external @pure readBack(arr: u256[]): u256 { let xs: Q[] = new Array<Q>(2n); xs[1n].arr = arr; return xs[1n].arr[0n] + xs[1n].arr.length; }
  @external @pure oobW(v: u256): u256 { let xs: P[] = new Array<P>(1n); xs[5n].a = v; return xs[0n].a; }
  @external dec(data: bytes): bytes { let xs: P[] = abi.decode(data, P[]); return abi.encode(xs); } }`;
  const So = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  struct P { uint256 a; bytes s; }
  struct Q { uint256 a; uint256[] arr; }
  function mk(uint256 n) external pure returns (P[] memory) { P[] memory xs=new P[](n); return xs; }
  function mkLen(uint256 n) external pure returns (uint256) { P[] memory xs=new P[](n); return xs.length; }
  function zeroSLen() external pure returns (uint256) { P[] memory xs=new P[](2); return xs[1].s.length; }
  function lit(uint256 a1, bytes calldata s1, uint256 a2, bytes calldata s2) external pure returns (P[] memory) { P[] memory xs=new P[](2); xs[0]=P(a1,s1); xs[1]=P(a2,s2); return xs; }
  function getA(uint256 a1, bytes calldata s1, uint256 a2, bytes calldata s2) external pure returns (uint256) { P[] memory xs=new P[](2); xs[0]=P(a1,s1); xs[1]=P(a2,s2); return xs[1].a; }
  function getS(uint256 a1, bytes calldata s1, uint256 a2, bytes calldata s2) external pure returns (bytes memory) { P[] memory xs=new P[](2); xs[0]=P(a1,s1); xs[1]=P(a2,s2); return xs[0].s; }
  function getElem(uint256 a1, bytes calldata s1, uint256 a2, bytes calldata s2) external pure returns (P memory) { P[] memory xs=new P[](2); xs[0]=P(a1,s1); xs[1]=P(a2,s2); return xs[0]; }
  function oob(uint256 a1, bytes calldata s1) external pure returns (uint256) { P[] memory xs=new P[](1); xs[0]=P(a1,s1); return xs[5].a; }
  function huge() external pure returns (P[] memory) { P[] memory xs=new P[](18446744073709551616); return xs; }
  function enc(uint256 a1, bytes calldata s1, uint256 a2, bytes calldata s2) external pure returns (bytes memory) { P[] memory xs=new P[](2); xs[0]=P(a1,s1); xs[1]=P(a2,s2); return abi.encode(xs); }
  function setA(uint256 v) external pure returns (P[] memory) { P[] memory xs=new P[](2); xs[0].a=v; xs[1].a=v+1; return xs; }
  function setS(bytes calldata b) external pure returns (P[] memory) { P[] memory xs=new P[](2); xs[0].s=b; return xs; }
  function setElem(uint256 a1, bytes calldata s1) external pure returns (P[] memory) { P[] memory xs=new P[](2); xs[0]=P(a1,s1); return xs; }
  function setArr(uint256[] calldata arr) external pure returns (Q[] memory) { Q[] memory xs=new Q[](2); xs[1].arr=arr; xs[1].a=7; return xs; }
  function setArrElem() external pure returns (Q[] memory) { Q[] memory xs=new Q[](1); xs[0].arr=new uint256[](3); xs[0].arr[0]=1; xs[0].arr[1]=2; xs[0].arr[2]=3; xs[0].arr[1]=99; return xs; }
  function readBack(uint256[] calldata arr) external pure returns (uint256) { Q[] memory xs=new Q[](2); xs[1].arr=arr; return xs[1].arr[0]+xs[1].arr.length; }
  function oobW(uint256 v) external pure returns (uint256) { P[] memory xs=new P[](1); xs[5].a=v; return xs[0].a; }
  function dec(bytes calldata data) external pure returns (bytes memory) { P[] memory xs=abi.decode(data,(P[])); return abi.encode(xs); } }`;

  const eb = (h: string) => { const len = h.length / 2; return pad32(BigInt(len)) + h + '00'.repeat((32 - (len % 32)) % 32); };
  const bytesParam = (h: string) => pad32(0x20n) + eb(h);
  const args4 = (a1: bigint, s1: string, a2: bigint, s2: string) => {
    const b1 = eb(s1), b2 = eb(s2); const o1 = 4 * 32, o2 = o1 + b1.length / 2;
    return pad32(a1) + pad32(BigInt(o1)) + pad32(a2) + pad32(BigInt(o2)) + b1 + b2;
  };
  const u256arr = (vals: bigint[]) => pad32(0x20n) + pad32(BigInt(vals.length)) + vals.map(pad32).join('');

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(So, 'C').creation);
  });
  const cmp = async (data: string, label: string) => {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
  };

  it('new P[](n): zero-init (empty sentinels) + length + return + huge Panic 0x41', async () => {
    for (const n of [0n, 1n, 3n]) await cmp('0x' + sel('mk(uint256)') + pad32(n), `mk(${n})`);
    await cmp('0x' + sel('mkLen(uint256)') + pad32(4n), 'mkLen(4)');
    await cmp('0x' + sel('zeroSLen()'), 'zeroSLen');
    await cmp('0x' + sel('huge()'), 'huge');
  });
  it('literal construct + field reads (xs[i].a / xs[i].s) + whole element + encode/return', async () => {
    const a = args4(7n, 'aabbcc', 99n, 'deadbeef0102');
    await cmp('0x' + sel('lit(uint256,bytes,uint256,bytes)') + a, 'lit');
    await cmp('0x' + sel('getA(uint256,bytes,uint256,bytes)') + a, 'getA');
    await cmp('0x' + sel('getS(uint256,bytes,uint256,bytes)') + a, 'getS');
    await cmp('0x' + sel('getElem(uint256,bytes,uint256,bytes)') + a, 'getElem');
    await cmp('0x' + sel('enc(uint256,bytes,uint256,bytes)') + a, 'enc');
  });
  it('OOB element access -> Panic 0x32 (byte-identical)', async () => {
    await cmp('0x' + sel('oob(uint256,bytes)') + pad32(7n) + pad32(0x40n) + eb('aabbcc'), 'oob');
    await cmp('0x' + sel('oobW(uint256)') + pad32(1n), 'oobW');
  });
  it('writes: xs[i].a=v / xs[i].s=<bytes> / xs[i]=P(..) / xs[i].arr=<u256[]> / xs[i].arr[j]=v', async () => {
    await cmp('0x' + sel('setA(uint256)') + pad32(42n), 'setA');
    await cmp('0x' + sel('setS(bytes)') + bytesParam('cafebabe'), 'setS');
    await cmp('0x' + sel('setElem(uint256,bytes)') + pad32(5n) + pad32(0x40n) + eb('001122'), 'setElem');
    await cmp('0x' + sel('setArr(uint256[])') + u256arr([10n, 20n, 30n]), 'setArr');
    await cmp('0x' + sel('setArrElem()'), 'setArrElem');
    await cmp('0x' + sel('readBack(uint256[])') + u256arr([100n, 200n]), 'readBack');
  });
  it('abi.decode(data, P[]) -> re-encode: well-formed + malformed (byte-identical revert)', async () => {
    // canonical blob from solc enc, fed back as the `data` bytes param.
    const encData = '0x' + sel('enc(uint256,bytes,uint256,bytes)') + args4(7n, 'aabbcc', 99n, 'deadbeef0102');
    const sE = await sol.call(as, encData);
    const ret = sE.returnHex.slice(2);
    const len = parseInt(ret.slice(64, 128), 16);
    const blob = ret.slice(128, 128 + len * 2);
    await cmp('0x' + sel('dec(bytes)') + bytesParam(blob), 'dec well-formed');
    await cmp('0x' + sel('dec(bytes)') + bytesParam(blob.slice(0, blob.length - 64)), 'dec truncated');
    const corrupt = blob.slice(0, 128) + pad32(BigInt('0xffffffffffffffffffff')) + blob.slice(192);
    await cmp('0x' + sel('dec(bytes)') + bytesParam(corrupt), 'dec corrupt-offset');
  });
  it('R[][] (static-struct nested array) now ACCEPTS (pointer-headed); FIXED outer Arr<P,N> still rejects', () => {
    expect(codes(`@struct class R{a:u256;b:u256;} @contract class C { @external @pure f(): R[][] { let m: R[][] = [[R(1n,2n)]]; return m; } }`)).toEqual([]);
    expect(codes(`@struct class P{a:u256;s:bytes;} @contract class C { @external @pure f(): Arr<P,2> { let m: Arr<P,2> = [P(1n,bytes("x")),P(2n,bytes("y"))]; return m; } }`).length).toBeGreaterThan(0);
  });
});
