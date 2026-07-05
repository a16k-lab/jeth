// Edge D (over-rejection lifted byte-identical): a FIXED-outer array whose leaf is bytes/string -
// Arr<string,N> / Arr<bytes,N> (and nested Arr<Arr<string,N>,M>) - as a MEMORY LOCAL. Previously JETH200.
// Its memory image is N absolute-pointer words (no [len] header), each pointing to a [len][data] blob -
// the same pointer-headed image abiEncFromMem's fixed-outer-dynamic-element branch already builds/reads for
// the value-leaf twin Arr<u256[],N>. The lift is pure routing (isDynBytesFixedLeafArray added at the gate,
// resolveArrayExpr, the localDecl builder, and the return dispatch); abiEncFromMem needed no change.
// A latent element-WRITE miscompile was fixed at the same time: the strArrayElem memory-store assumed a
// dynamic [len] header (bound = mload(ptr), data at ptr+0x20); for a FIXED outer it now bounds against N
// and writes at ptr (no header), mirroring lowerArrayGet's fixedLen handling.
// Scope matches the Arr<u256[],N> value-leaf precedent: build-from-literal, element read/write, whole
// return, .length, byte-index. abi.encode(x) is now ALSO lifted byte-identical (the pointer-headed
// fixed-of-dynamic codec, P0-33). W3-Y2d then lifted the last @external-boundary + mem-copy shapes byte-
// identical: the @external calldata-param decode + return-encode (the tuple-return wrapper's outer [0x20]
// offset word matched to solc) and the memory whole-array ALIAS `let ys = xs` (a POINTER copy, matching
// solc memory-reference aliasing - mutating one shows in the other; the pointer-alias lowering already
// existed, only the analyzer localDecl gate needed the memAggregate-alias term, fixed-outer only). A
// calldata->memory whole-param COPY (`let ys = p`) and a dynamic-outer nested-value alias (u256[][]) stay
// clean over-rejections (distinct deep-copy / memArray paths); a clean reject is never a miscompile.
// Verified byte-identical to solc 0.8.35.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => BigInt(n).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};

describe('Edge D: Arr<string,N> / Arr<bytes,N> fixed-outer-dynamic-leaf memory local - byte-identical to solc 0.8.35', () => {
  it('build from a literal + return the whole array (empty / short / >31-byte elements)', async () => {
    await eqCalls(
      '@contract class C { @external @pure go(): Arr<string,3> { let xs: Arr<string,3> = ["", "short", "this-string-is-definitely-longer-than-thirty-one-bytes-yes"]; return xs; } }',
      'contract C { function go() external pure returns(string[3] memory){ string[3] memory xs=["", "short", "this-string-is-definitely-longer-than-thirty-one-bytes-yes"]; return xs; } }',
      [['go()', '']],
    );
    await eqCalls(
      '@contract class C { @external @pure go(): Arr<bytes,2> { let xs: Arr<bytes,2> = [bytes("ab"), bytes("cdef")]; return xs; } }',
      'contract C { function go() external pure returns(bytes[2] memory){ bytes[2] memory xs=[bytes("ab"), bytes("cdef")]; return xs; } }',
      [['go()', '']],
    );
  });

  it('element read xs[i] (constant + runtime index, OOB -> Panic 0x32)', async () => {
    await eqCalls(
      '@contract class C { @external @pure go(i: u256): string { let xs: Arr<string,2> = ["foo","bar"]; return xs[i]; } }',
      'contract C { function go(uint256 i) external pure returns(string memory){ string[2] memory xs=["foo","bar"]; return xs[i]; } }',
      [['go(uint256)', W(0)], ['go(uint256)', W(1)], ['go(uint256)', W(2)], ['go(uint256)', W(99)]],
    );
  });

  it('element write xs[i] = <string/bytes> (constant + runtime index, re-point), then read back', async () => {
    await eqCalls(
      '@contract class C { @external @pure go(): Arr<string,2> { let xs: Arr<string,2> = ["a","b"]; xs[0n] = "changed-to-a-much-longer-value!!"; xs[1n] = "z"; return xs; } }',
      'contract C { function go() external pure returns(string[2] memory){ string[2] memory xs=["a","b"]; xs[0]="changed-to-a-much-longer-value!!"; xs[1]="z"; return xs; } }',
      [['go()', '']],
    );
    await eqCalls(
      '@contract class C { @external @pure go(i: u256, s: string): string { let xs: Arr<string,2> = ["a","b"]; xs[i] = s; return xs[i]; } }',
      'contract C { function go(uint256 i, string calldata s) external pure returns(string memory){ string[2] memory xs=["a","b"]; xs[i]=s; return xs[i]; } }',
      [['go(uint256,string)', W(1) + W(0x40) + W(3) + '7a7a7a'.padEnd(64, '0')]],
    );
    await eqCalls(
      '@contract class C { @external @pure go(): bytes { let xs: Arr<bytes,2> = [bytes("a"),bytes("b")]; xs[0n] = bytes("xyz"); return xs[0n]; } }',
      'contract C { function go() external pure returns(bytes memory){ bytes[2] memory xs=[bytes("a"),bytes("b")]; xs[0]=bytes("xyz"); return xs[0]; } }',
      [['go()', '']],
    );
  });

  it('byte-index xs[i][j], string.concat of elements, .length via the element, multiple locals', async () => {
    await eqCalls(
      '@contract class C { @external @pure go(): bytes1 { let xs: Arr<bytes,2> = [bytes("abc"),bytes("XY")]; return xs[0n][1n]; } }',
      'contract C { function go() external pure returns(bytes1){ bytes[2] memory xs=[bytes("abc"),bytes("XY")]; return xs[0][1]; } }',
      [['go()', '']],
    );
    await eqCalls(
      '@contract class C { @external @pure go(): string { let a: Arr<string,2> = ["aa","bb"]; let b: Arr<string,2> = ["cc","dd"]; return string.concat(a[1n], b[0n]); } }',
      'contract C { function go() external pure returns(string memory){ string[2] memory a=["aa","bb"]; string[2] memory b=["cc","dd"]; return string.concat(a[1], b[0]); } }',
      [['go()', '']],
    );
  });

  it('nested Arr<Arr<string,2>,2> local: element read + whole return', async () => {
    await eqCalls(
      '@contract class C { @external @pure rd(): string { let xs: Arr<Arr<string,2>,2> = [["a","b"],["c","d"]]; return xs[1n][0n]; } @external @pure rr(): Arr<Arr<string,2>,2> { let xs: Arr<Arr<string,2>,2> = [["a","b"],["c","d"]]; return xs; } }',
      'contract C { function rd() external pure returns(string memory){ string[2][2] memory xs=[["a","b"],["c","d"]]; return xs[1][0]; } function rr() external pure returns(string[2][2] memory){ string[2][2] memory xs=[["a","b"],["c","d"]]; return xs; } }',
      [['rd()', ''], ['rr()', '']],
    );
  });

  it('the dynamic-outer string[] element write is unaffected by the fixedLen header fix', async () => {
    await eqCalls(
      '@contract class C { @external @pure go(): string[] { let xs: string[] = ["a","b","c"]; xs[1n] = "changed"; return xs; } }',
      'contract C { function go() external pure returns(string[] memory){ string[] memory xs=new string[](3); xs[0]="a";xs[1]="b";xs[2]="c"; xs[1]="changed"; return xs; } }',
      [['go()', '']],
    );
  });

  it('a compile-time-CONSTANT out-of-bounds index is rejected at compile time (JETH211), like solc', () => {
    // solc errors "Out of bounds array access" at compile time; JETH211 matches. The check is now wired to
    // the fixed-outer pointer-headed family (read, write, and the outer index of a nested fixed array) -
    // it was previously missing for this representation (a fail-safe runtime-Panic over-acceptance).
    expect(codes('@contract class C { @external @pure go(): string { let xs: Arr<string,3> = ["a","b","c"]; return xs[3n]; } }')).toContain('JETH211');
    expect(codes('@contract class C { @external go(): void { let xs: Arr<string,3> = ["a","b","c"]; xs[3n] = "z"; } }')).toContain('JETH211');
    expect(codes('@contract class C { @external @pure go(): string { let xs: Arr<Arr<string,2>,2> = [["a","b"],["c","d"]]; return xs[2n][0n]; } }')).toContain('JETH211');
    expect(codes('@contract class C { @external @pure go(): string { let xs: Arr<Arr<string,2>,2> = [["a","b"],["c","d"]]; return xs[0n][2n]; } }')).toContain('JETH211');
    // an IN-BOUNDS constant index is accepted (no over-rejection).
    expect(codes('@contract class C { @external @pure go(): string { let xs: Arr<string,3> = ["a","b","c"]; return xs[2n]; } }')).toEqual([]);
  });

  it('abi.encode(Arr<string,N>) is lifted byte-identical to solc (P0-33 fixed-of-dynamic codec)', async () => {
    // Previously a clean reject; the pointer-headed fixed-of-dynamic codec now encodes it byte-identically.
    await eqCalls(
      '@contract class C { @external @pure go(): bytes { let xs: Arr<string,2> = ["a","b"]; return abi.encode(xs); } }',
      'contract C { function go() external pure returns(bytes memory){ string[2] memory xs = ["a","b"]; return abi.encode(xs); } }',
      [['go()', '']],
    );
  });
  it('@external param decode + return encode of Arr<string,N>/Arr<bytes,N> are byte-identical (W3-Y2d)', async () => {
    // The @external ABI boundary now decodes a fixed-outer-dynamic-leaf calldata param (string[2]/bytes[2])
    // to the pointer-headed memory image and encodes such a return through the fixed-of-dynamic ABI encoder
    // (the tuple-return wrapper adds the outer [0x20] offset word - matched to solc's full returndata).
    // Round-trip (decode then re-return) + element read + .length + byte-index are all byte-identical.
    await eqCalls(
      '@contract class C { @external @pure go(p: Arr<bytes,2>): u256 { return p[0n].length; } }',
      'contract C { function go(bytes[2] calldata p) external pure returns(uint256){ return p[0].length; } }',
      // string[2]/bytes[2] calldata param: [0x20 tuple-offset][h0][h1][len0][data0][len1][data1]
      [['go(bytes[2])', W(0x20) + W(0x40) + W(0x40 + 0x40) + W(2) + '6162'.padEnd(64, '0') + W(4) + '63646566'.padEnd(64, '0')]],
    );
    await eqCalls(
      '@contract class C { @external @pure go(p: Arr<string,2>): Arr<string,2> { return p; } }',
      'contract C { function go(string[2] calldata p) external pure returns(string[2] memory){ return p; } }',
      [
        ['go(string[2])', W(0x20) + W(0x40) + W(0x40 + 0x40) + W(0) + W(5) + '73686f7274'.padEnd(64, '0')], // "", "short"
        ['go(string[2])', W(0x20) + W(0x40) + W(0x40 + 0x60) + W(40) + '746869732d737472696e672d69732d6c6f6e6765722d7468616e2d3332212121'.padEnd(64, '0') + '3131' + '0'.repeat(60) + W(0)],
      ],
    );
    // @external @pure return of a locally-built fixed-of-dynamic array (tuple wrapper + tail blob).
    await eqCalls(
      '@contract class C { @external @pure go(): Arr<string,2> { let xs: Arr<string,2> = ["a","b"]; return xs; } }',
      'contract C { function go() external pure returns(string[2] memory){ string[2] memory xs=["a","b"]; return xs; } }',
      [['go()', '']],
    );
  });

  it('memory whole-array ALIAS copy of Arr<string,N>/Arr<bytes,N>/Arr<u256[],N> is byte-identical (W3-Y2d)', async () => {
    // solc memory arrays are reference types: `let ys = xs` is a POINTER copy (ys aliases xs's image;
    // mutating one shows in the other). Previously JETH200. The fix routes a fixed-outer aggregate-leaf /
    // nested-value memory-local decl whose init is a memAggregate (another local) through the pointer-alias
    // lowering (lowerExpr returns the source pointer verbatim) - byte-identical to solc's aliasing.
    // whole-array return of the alias:
    await eqCalls(
      '@contract class C { @external @pure go(): Arr<string,3> { let xs: Arr<string,3> = ["", "short", "this-string-is-definitely-longer-than-thirty-one-bytes-yes"]; let ys: Arr<string,3> = xs; return ys; } }',
      'contract C { function go() external pure returns(string[3] memory){ string[3] memory xs=["", "short", "this-string-is-definitely-longer-than-thirty-one-bytes-yes"]; string[3] memory ys=xs; return ys; } }',
      [['go()', '']],
    );
    // aliasing is a reference (not a deep copy): mutating xs[0] AFTER the alias is visible through ys[0].
    await eqCalls(
      '@contract class C { @external @pure go(): string { let xs: Arr<string,2> = ["a","b"]; let ys: Arr<string,2> = xs; xs[0n] = "changed-to-a-much-longer-value!!!"; return ys[0n]; } }',
      'contract C { function go() external pure returns(string memory){ string[2] memory xs=["a","b"]; string[2] memory ys=xs; xs[0]="changed-to-a-much-longer-value!!!"; return ys[0]; } }',
      [['go()', '']],
    );
    // the reverse direction: mutating ys[1] is visible through xs[1].
    await eqCalls(
      '@contract class C { @external @pure go(): bytes { let xs: Arr<bytes,2> = [bytes("a"),bytes("b")]; let ys: Arr<bytes,2> = xs; ys[1n] = bytes("via-ys"); return xs[1n]; } }',
      'contract C { function go() external pure returns(bytes memory){ bytes[2] memory xs=[bytes("a"),bytes("b")]; bytes[2] memory ys=xs; ys[1]=bytes("via-ys"); return xs[1]; } }',
      [['go()', '']],
    );
    // value-leaf fixed-of-dynamic twin Arr<u256[],N>: alias + element mutation visibility.
    await eqCalls(
      '@contract class C { @external @pure go(): u256 { let xs: Arr<u256[],2> = [[1n,2n],[3n]]; let ys: Arr<u256[],2> = xs; xs[0n][1n] = 99n; return ys[0n][1n]; } }',
      'contract C { function go() external pure returns(uint256){ uint256[][2] memory xs; xs[0]=new uint256[](2);xs[0][0]=1;xs[0][1]=2;xs[1]=new uint256[](1);xs[1][0]=3; uint256[][2] memory ys=xs; xs[0][1]=99; return ys[0][1]; } }',
      [['go()', '']],
    );
    // nested Arr<Arr<string,2>,2> alias round-trips byte-identically.
    await eqCalls(
      '@contract class C { @external @pure go(): Arr<Arr<string,2>,2> { let xs: Arr<Arr<string,2>,2> = [["a","b"],["c","d"]]; let ys: Arr<Arr<string,2>,2> = xs; return ys; } }',
      'contract C { function go() external pure returns(string[2][2] memory){ string[2][2] memory xs=[["a","b"],["c","d"]]; string[2][2] memory ys=xs; return ys; } }',
      [['go()', '']],
    );
  });

  it('adjacent alias shapes stay correctly gated (no over-acceptance)', () => {
    // a fixed-outer alias with a MISMATCHED type still rejects (JETH085), not a silent wrong-length copy.
    expect(codes('@contract class C { @external @pure go(): u256 { let xs: Arr<string,2> = ["a","b"]; let ys: Arr<string,3> = xs; return 0n; } }')).toContain('JETH085');
    expect(codes('@contract class C { @external @pure go(): u256 { let xs: Arr<string,2> = ["a","b"]; let ys: Arr<bytes,2> = xs; return 0n; } }')).toContain('JETH085');
    // a DYNAMIC-outer nested-value alias (u256[][]) stays a clean reject (a distinct memArray lowering, not
    // wired here); a clean reject is never a miscompile.
    expect(codes('@contract class C { @external @pure go(): u256[][] { let xs: u256[][] = [[1n,2n],[3n]]; let ys: u256[][] = xs; return ys[0n][0n]; } }').length).toBeGreaterThan(0);
    // a whole calldata fixed-of-dynamic PARAM copied into a memory local (let ys = p) stays a clean reject
    // (a calldata->memory deep copy, a separate path from the mem-to-mem alias lifted here).
    expect(codes('@contract class C { @external @pure go(p: Arr<string,2>): Arr<string,2> { let ys: Arr<string,2> = p; return ys; } }').length).toBeGreaterThan(0);
  });
});
