// B4: a NESTED array whose ultimate leaf is a DYNAMIC byte-sequence (bytes[][], string[][], and
// deeper bytes[][][]) as a MEMORY local. The image is pointer-headed at every dynamic level: the
// outer is [len][ptr0][ptr1]..; each ptr_i -> the inner array image ([len][blob-ptr..]); each leaf
// word -> a [len][data] blob. `new Array<bytes[]>(n)` zero-inits each element to a fresh empty inner
// array. Construct (new / literal), read (xs[i] inner / xs[i][j] leaf / .length at each level), write
// (xs[i] = <bytes[]> re-point / xs[i][j] = <bytes> re-point), return, abi.encode, abi.decode. Byte-
// identical to solc 0.8.35; OOB at any level -> Panic 0x32, new n>=2^64 -> Panic 0x41.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const eb = (h: string) => { const len = h.length / 2; return pad32(BigInt(len)) + h + '00'.repeat((32 - (len % 32)) % 32); };
const bytesParam = (h: string) => pad32(0x20n) + eb(h);
// head/tail of N dynamic (bytes) args, contiguous (the calldata of f(bytes,bytes,...)).
const dynArgs = (blobs: string[]) => {
  let head = ''; let off = blobs.length * 32;
  for (const b of blobs) { head += pad32(BigInt(off)); off += b.length / 2; }
  return head + blobs.join('');
};

const J = `@contract class B4 {
  @external @pure mk(n: u256): bytes[][] { let xs: bytes[][] = new Array<bytes[]>(n); return xs; }
  @external @pure mkLen(n: u256): u256 { let xs: bytes[][] = new Array<bytes[]>(n); return xs.length; }
  @external @pure innerLen0(): u256 { let xs: bytes[][] = new Array<bytes[]>(3n); return xs[1n].length; }
  @external @pure huge(): bytes[][] { let xs: bytes[][] = new Array<bytes[]>(18446744073709551616n); return xs; }
  @external @pure lit(a: bytes, b: bytes, c: bytes): bytes[][] { let xs: bytes[][] = [[a, b], [c]]; return xs; }
  @external @pure inner(a: bytes, b: bytes, c: bytes): bytes[] { let xs: bytes[][] = [[a, b], [c]]; return xs[0n]; }
  @external @pure leaf(a: bytes, b: bytes, c: bytes): bytes { let xs: bytes[][] = [[a, b], [c]]; return xs[0n][1n]; }
  @external @pure innerLen(a: bytes, b: bytes, c: bytes): u256 { let xs: bytes[][] = [[a, b], [c]]; return xs[0n].length; }
  @external @pure leafLen(a: bytes, b: bytes, c: bytes): u256 { let xs: bytes[][] = [[a, b], [c]]; return xs[0n][1n].length; }
  @external @pure oobOuter(a: bytes): bytes[] { let xs: bytes[][] = [[a]]; return xs[5n]; }
  @external @pure oobInner(a: bytes): bytes { let xs: bytes[][] = [[a]]; return xs[0n][5n]; }
  @external @pure enc(a: bytes, b: bytes, c: bytes): bytes { let xs: bytes[][] = [[a, b], [c]]; return abi.encode(xs); }
  @external @pure repointInner(a: bytes, b: bytes): bytes[][] {
    let xs: bytes[][] = new Array<bytes[]>(2n);
    let row: bytes[] = new Array<bytes>(2n); row[0n] = a; row[1n] = b;
    xs[0n] = row; return xs;
  }
  @external @pure repointLeaf(a: bytes, b: bytes, c: bytes): bytes[][] { let xs: bytes[][] = [[a, b], [c]]; xs[0n][1n] = c; return xs; }
  @external @pure strs(a: string, b: string): string[][] {
    let xs: string[][] = new Array<string[]>(1n);
    let row: string[] = new Array<string>(2n); row[0n] = a; row[1n] = b;
    xs[0n] = row; return xs;
  }
  @external @pure strLeaf(a: string, b: string): string { let xs: string[][] = [[a, b]]; return xs[0n][1n]; }
  @external dec(data: bytes): bytes { let xs: bytes[][] = abi.decode(data, bytes[][]); return abi.encode(xs); }
  // 3-deep
  @external @pure leaf3(a: bytes, b: bytes): bytes { let m: bytes[][][] = [[[a],[b]]]; return m[0n][1n][0n]; }
  @external @pure enc3(a: bytes, b: bytes): bytes { let m: bytes[][][] = [[[a],[b]]]; return abi.encode(m); }
}`;
const So = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract B4 {
  function mk(uint256 n) external pure returns (bytes[][] memory) { bytes[][] memory xs=new bytes[][](n); return xs; }
  function mkLen(uint256 n) external pure returns (uint256) { bytes[][] memory xs=new bytes[][](n); return xs.length; }
  function innerLen0() external pure returns (uint256) { bytes[][] memory xs=new bytes[][](3); return xs[1].length; }
  function huge() external pure returns (bytes[][] memory) { bytes[][] memory xs=new bytes[][](18446744073709551616); return xs; }
  function lit(bytes calldata a, bytes calldata b, bytes calldata c) external pure returns (bytes[][] memory) { bytes[][] memory xs=new bytes[][](2); xs[0]=new bytes[](2); xs[0][0]=a; xs[0][1]=b; xs[1]=new bytes[](1); xs[1][0]=c; return xs; }
  function inner(bytes calldata a, bytes calldata b, bytes calldata c) external pure returns (bytes[] memory) { bytes[][] memory xs=new bytes[][](2); xs[0]=new bytes[](2); xs[0][0]=a; xs[0][1]=b; xs[1]=new bytes[](1); xs[1][0]=c; return xs[0]; }
  function leaf(bytes calldata a, bytes calldata b, bytes calldata c) external pure returns (bytes memory) { bytes[][] memory xs=new bytes[][](2); xs[0]=new bytes[](2); xs[0][0]=a; xs[0][1]=b; xs[1]=new bytes[](1); xs[1][0]=c; return xs[0][1]; }
  function innerLen(bytes calldata a, bytes calldata b, bytes calldata c) external pure returns (uint256) { bytes[][] memory xs=new bytes[][](2); xs[0]=new bytes[](2); xs[0][0]=a; xs[0][1]=b; xs[1]=new bytes[](1); xs[1][0]=c; return xs[0].length; }
  function leafLen(bytes calldata a, bytes calldata b, bytes calldata c) external pure returns (uint256) { bytes[][] memory xs=new bytes[][](2); xs[0]=new bytes[](2); xs[0][0]=a; xs[0][1]=b; xs[1]=new bytes[](1); xs[1][0]=c; return xs[0][1].length; }
  function oobOuter(bytes calldata a) external pure returns (bytes[] memory) { bytes[][] memory xs=new bytes[][](1); xs[0]=new bytes[](1); xs[0][0]=a; return xs[5]; }
  function oobInner(bytes calldata a) external pure returns (bytes memory) { bytes[][] memory xs=new bytes[][](1); xs[0]=new bytes[](1); xs[0][0]=a; return xs[0][5]; }
  function enc(bytes calldata a, bytes calldata b, bytes calldata c) external pure returns (bytes memory) { bytes[][] memory xs=new bytes[][](2); xs[0]=new bytes[](2); xs[0][0]=a; xs[0][1]=b; xs[1]=new bytes[](1); xs[1][0]=c; return abi.encode(xs); }
  function repointInner(bytes calldata a, bytes calldata b) external pure returns (bytes[][] memory) { bytes[][] memory xs=new bytes[][](2); bytes[] memory row=new bytes[](2); row[0]=a; row[1]=b; xs[0]=row; return xs; }
  function repointLeaf(bytes calldata a, bytes calldata b, bytes calldata c) external pure returns (bytes[][] memory) { bytes[][] memory xs=new bytes[][](2); xs[0]=new bytes[](2); xs[0][0]=a; xs[0][1]=b; xs[1]=new bytes[](1); xs[1][0]=c; xs[0][1]=c; return xs; }
  function strs(string calldata a, string calldata b) external pure returns (string[][] memory) { string[][] memory xs=new string[][](1); string[] memory row=new string[](2); row[0]=a; row[1]=b; xs[0]=row; return xs; }
  function strLeaf(string calldata a, string calldata b) external pure returns (string memory) { string[][] memory xs=new string[][](1); xs[0]=new string[](2); xs[0][0]=a; xs[0][1]=b; return xs[0][1]; }
  function dec(bytes calldata data) external pure returns (bytes memory) { bytes[][] memory xs=abi.decode(data,(bytes[][])); return abi.encode(xs); }
  function leaf3(bytes calldata a, bytes calldata b) external pure returns (bytes memory) { bytes[][][] memory m=new bytes[][][](1); m[0]=new bytes[][](2); m[0][0]=new bytes[](1); m[0][0][0]=a; m[0][1]=new bytes[](1); m[0][1][0]=b; return m[0][1][0]; }
  function enc3(bytes calldata a, bytes calldata b) external pure returns (bytes memory) { bytes[][][] memory m=new bytes[][][](1); m[0]=new bytes[][](2); m[0][0]=new bytes[](1); m[0][0][0]=a; m[0][1]=new bytes[](1); m[0][1][0]=b; return abi.encode(m); }
}`;

describe('B4: nested-dynamic-leaf array memory local (bytes[][], string[][]) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'B4.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(So, 'B4').creation);
  });
  const cmp = async (data: string, label: string) => {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
  };
  const A = 'aabbcc', B = 'dd', C = '112233445566778899';
  const args3 = dynArgs([eb(A), eb(B), eb(C)]);
  const sig3 = '(bytes,bytes,bytes)';

  it('new bytes[][](n): zero-init (empty inner arrays) + length + return + huge Panic 0x41', async () => {
    for (const n of [0n, 3n]) await cmp('0x' + sel('mk(uint256)') + pad32(n), `mk(${n})`);
    await cmp('0x' + sel('mkLen(uint256)') + pad32(4n), 'mkLen(4)');
    await cmp('0x' + sel('innerLen0()'), 'innerLen0');
    await cmp('0x' + sel('huge()'), 'huge');
  });
  it('literal construct + reads (xs[i] inner / xs[i][j] leaf / .length at each level) + encode/return', async () => {
    for (const fn of ['lit', 'inner', 'leaf', 'innerLen', 'leafLen', 'enc'])
      await cmp('0x' + sel(`${fn}${sig3}`) + args3, fn);
  });
  it('OOB at outer and inner level -> Panic 0x32', async () => {
    await cmp('0x' + sel('oobOuter(bytes)') + bytesParam(A), 'oobOuter');
    await cmp('0x' + sel('oobInner(bytes)') + bytesParam(A), 'oobInner');
  });
  it('writes: xs[i] = <bytes[]> (re-point inner) / xs[i][j] = <bytes> (re-point leaf)', async () => {
    await cmp('0x' + sel('repointInner(bytes,bytes)') + dynArgs([eb(A), eb(B)]), 'repointInner');
    await cmp('0x' + sel(`repointLeaf${sig3}`) + args3, 'repointLeaf');
  });
  it('string[][]: construct + write + leaf read (one pass)', async () => {
    const sa = Buffer.from('hello').toString('hex'), sb = Buffer.from('world').toString('hex');
    await cmp('0x' + sel('strs(string,string)') + dynArgs([eb(sa), eb(sb)]), 'strs');
    await cmp('0x' + sel('strLeaf(string,string)') + dynArgs([eb(sa), eb(sb)]), 'strLeaf');
  });
  it('bytes[][][] (3-deep): leaf read + encode byte-identical', async () => {
    await cmp('0x' + sel('leaf3(bytes,bytes)') + dynArgs([eb(A), eb(B)]), 'leaf3');
    await cmp('0x' + sel('enc3(bytes,bytes)') + dynArgs([eb(A), eb(B)]), 'enc3');
  });
  it('abi.decode(data, bytes[][]) -> re-encode: well-formed + malformed (byte-identical revert)', async () => {
    const encData = '0x' + sel(`enc${sig3}`) + args3;
    const sE = await sol.call(as, encData);
    const ret = sE.returnHex.slice(2);
    const len = parseInt(ret.slice(64, 128), 16);
    const blob = ret.slice(128, 128 + len * 2);
    await cmp('0x' + sel('dec(bytes)') + bytesParam(blob), 'dec well-formed');
    await cmp('0x' + sel('dec(bytes)') + bytesParam(blob.slice(0, blob.length - 64)), 'dec truncated');
    const corrupt = blob.slice(0, 64) + pad32(BigInt('0xffffffffffffffff')) + blob.slice(128);
    await cmp('0x' + sel('dec(bytes)') + bytesParam(corrupt), 'dec corrupt-offset');
  });
});
