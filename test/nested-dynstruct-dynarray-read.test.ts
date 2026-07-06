// Regression: reading a dynamic-array leaf reached THROUGH a nested dynamic-struct FIELD of a memory
// local sourced from abi.decode. S3{ p: S2{ a, arr:u256[] }, n } decoded from bytes, then x.p.arr[i] /
// x.p.arr.length / whole x.p.arr / whole x.p read+encoded. This shape used to crash with an internal
// JETH900 ("dynamic struct param 'x' is not bound") on the buildDynStructFromCalldata read path; the
// nested-chain deref codec (memDynNestedField + the dyn-struct field codec) now resolves it byte-
// identically to solc 0.8.35. Scalar-only reads (x.p.a + x.n) always worked; the dyn-array leaf is the
// regression target here. Non-vacuous: hard-coded expected values + a differential check vs solc.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => BigInt(n).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

// b = abi.encode(S3{ p: S2{ a:7, arr }, n:99 }); then wrap as the f(bytes) calldata argument.
function s3Calldata(arr: number[]): string {
  const body = W(0x20) + W(0x40) + W(99) + W(7) + W(0x40) + W(arr.length) + arr.map((x) => W(x)).join('');
  return W(0x20) + W(body.length / 2) + body;
}

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  const out: { sig: string; success: boolean; returnHex: string }[] = [];
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
    out.push({ sig, success: rj.success, returnHex: rj.returnHex });
  }
  return out;
}

const JP = '@struct class S2 { a: u256; arr: u256[]; } @struct class S3 { p: S2; n: u256; } @contract class C { ';
const SP = 'struct S2 { uint256 a; uint256[] arr; } struct S3 { S2 p; uint256 n; } contract C { ';
const J = (body: string) => JP + body + ' }';
const S = (body: string) => SP + body + ' }';

describe('nested dyn-struct field -> dyn-array leaf read from abi.decode (was JETH900)', () => {
  it('x.p.arr.length / x.p.arr[i] / scalar control are byte-identical to solc', async () => {
    const A3 = s3Calldata([10, 20, 30]);
    const out = await eqCalls(
      J('@external @pure len(b: bytes): u256 { let x: S3 = abi.decode(b, S3); return x.p.arr.length; }' +
        ' @external @pure el(b: bytes): u256 { let x: S3 = abi.decode(b, S3); return x.p.arr[1n]; }' +
        ' @external @pure sc(b: bytes): u256 { let x: S3 = abi.decode(b, S3); return x.p.a + x.n; }'),
      S('function len(bytes calldata b) external pure returns(uint256){ S3 memory x=abi.decode(b,(S3)); return x.p.arr.length; }' +
        ' function el(bytes calldata b) external pure returns(uint256){ S3 memory x=abi.decode(b,(S3)); return x.p.arr[1]; }' +
        ' function sc(bytes calldata b) external pure returns(uint256){ S3 memory x=abi.decode(b,(S3)); return x.p.a + x.n; }'),
      [['len(bytes)', A3], ['el(bytes)', A3], ['sc(bytes)', A3]],
    );
    // non-vacuous absolute checks: length=3, arr[1]=20, a+n=7+99=106
    expect(out[0]!.returnHex).toBe('0x' + W(3));
    expect(out[1]!.returnHex).toBe('0x' + W(20));
    expect(out[2]!.returnHex).toBe('0x' + W(106));
  });

  it('empty array, 5-element access, and OOB -> Panic 0x32 match solc', async () => {
    await eqCalls(
      J('@external @pure len(b: bytes): u256 { let x: S3 = abi.decode(b, S3); return x.p.arr.length; }' +
        ' @external @pure el(b: bytes, i: u256): u256 { let x: S3 = abi.decode(b, S3); return x.p.arr[i]; }'),
      S('function len(bytes calldata b) external pure returns(uint256){ S3 memory x=abi.decode(b,(S3)); return x.p.arr.length; }' +
        ' function el(bytes calldata b, uint256 i) external pure returns(uint256){ S3 memory x=abi.decode(b,(S3)); return x.p.arr[i]; }'),
      [
        ['len(bytes)', s3Calldata([])],
        ['el(bytes,uint256)', s3Calldata([1, 2, 3, 4, 5]) + W(4)],
        ['el(bytes,uint256)', s3Calldata([10, 20, 30]) + W(9)], // OOB -> Panic 0x32
      ],
    );
  });

  it('write x.p.arr[i], loop-sum, whole-field abi.encode(x.p.arr) and abi.encode(x.p) match solc', async () => {
    const A3 = s3Calldata([10, 20, 30]);
    await eqCalls(
      J('@external @pure wr(b: bytes): u256 { let x: S3 = abi.decode(b, S3); x.p.arr[1n] = 555n; return x.p.arr[1n] + x.p.arr[0n]; }' +
        ' @external @pure sum(b: bytes): u256 { let x: S3 = abi.decode(b, S3); let s: u256 = 0n; for (let i: u256 = 0n; i < x.p.arr.length; i = i + 1n) { s = s + x.p.arr[i]; } return s; }' +
        ' @external @pure encArr(b: bytes): bytes { let x: S3 = abi.decode(b, S3); return abi.encode(x.p.arr); }' +
        ' @external @pure encP(b: bytes): bytes { let x: S3 = abi.decode(b, S3); return abi.encode(x.p); }'),
      S('function wr(bytes calldata b) external pure returns(uint256){ S3 memory x=abi.decode(b,(S3)); x.p.arr[1]=555; return x.p.arr[1]+x.p.arr[0]; }' +
        ' function sum(bytes calldata b) external pure returns(uint256){ S3 memory x=abi.decode(b,(S3)); uint256 s=0; for(uint256 i=0;i<x.p.arr.length;i++){ s+=x.p.arr[i]; } return s; }' +
        ' function encArr(bytes calldata b) external pure returns(bytes memory){ S3 memory x=abi.decode(b,(S3)); return abi.encode(x.p.arr); }' +
        ' function encP(bytes calldata b) external pure returns(bytes memory){ S3 memory x=abi.decode(b,(S3)); return abi.encode(x.p); }'),
      [['wr(bytes)', A3], ['sum(bytes)', A3], ['encArr(bytes)', A3], ['encP(bytes)', A3]],
    );
  });
});
