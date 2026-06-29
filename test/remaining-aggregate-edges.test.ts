// Remaining sound-edge lifts, byte-identical to solc 0.8.35:
//  D: inner-element WRITE of a value-fixed-array nested array (Arr<T,N>[] m[i][j]=v) - the header-less
//     fixed inner is now addressed at base+j*0x20 (was a phantom-length Panic / a 1-word skew).
//  E: WRITES into a dyn-struct memory local's NESTED STATIC AGGREGATE field - p.inner.x=v, p.fa[j]=v
//     (const/runtime/OOB), and whole-field re-point p.inner=In(..) / p.fa=other.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
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

describe('D: value-fixed-array nested array inner-element write (Arr<T,N>[] m[i][j]=v) vs solc 0.8.35', () => {
  it('literal + new Array construction, inner write (element-0 zero and non-zero), runtime OOB', async () => {
    const J = `@contract class C {
      @external @pure lit(): u256 { let m: Arr<u256, 2>[] = [[1n, 2n], [3n, 4n]]; m[0n][1n] = 99n; return m[0n][1n] + m[1n][0n] + m[0n][0n]; }
      @external @pure zeroELem(): u256 { let m: Arr<u256, 2>[] = [[0n, 0n], [0n, 0n]]; m[0n][0n] = 5n; return m[0n][0n]; }
      @external @pure nw(): u256 { let m: Arr<u256, 2>[] = new Array<Arr<u256, 2>>(2n); m[0n][1n] = 99n; m[1n][0n] = 7n; return m[0n][1n] + m[1n][0n]; }
      @external @pure enc(): bytes { let m: Arr<u256, 3>[] = new Array<Arr<u256, 3>>(2n); m[0n][0n] = 11n; m[0n][2n] = 33n; m[1n][1n] = 50n; return abi.encode(m); }
      @external @pure oob(i: u256): u256 { let m: Arr<u256, 3>[] = new Array<Arr<u256, 3>>(2n); m[0n][i] = 42n; return m[0n][i]; } }`;
    const S = `contract C {
      function lit() external pure returns(uint256){ uint256[2][] memory m=new uint256[2][](2); m[0][0]=1;m[0][1]=2;m[1][0]=3;m[1][1]=4; m[0][1]=99; return m[0][1]+m[1][0]+m[0][0]; }
      function zeroELem() external pure returns(uint256){ uint256[2][] memory m=new uint256[2][](2); m[0][0]=5; return m[0][0]; }
      function nw() external pure returns(uint256){ uint256[2][] memory m=new uint256[2][](2); m[0][1]=99; m[1][0]=7; return m[0][1]+m[1][0]; }
      function enc() external pure returns(bytes memory){ uint256[3][] memory m=new uint256[3][](2); m[0][0]=11; m[0][2]=33; m[1][1]=50; return abi.encode(m); }
      function oob(uint256 i) external pure returns(uint256){ uint256[3][] memory m=new uint256[3][](2); m[0][i]=42; return m[0][i]; } }`;
    await diff(J, S, [['lit()', ''], ['zeroELem()', ''], ['nw()', ''], ['enc()', ''], ['oob(uint256)', pad32(1n)], ['oob(uint256)', pad32(5n)]]);
  });
});

describe('E: dyn-struct nested static-aggregate field WRITES vs solc 0.8.35', () => {
  it('p.inner.x=v (value leaf), p.fa[j]=v (const/runtime/OOB), p.inner=In()/p.fa=other re-point', async () => {
    const J = `@struct class In { x: u256; y: u256; }
    @struct class S { a: u256; inner: In; fa: Arr<u256, 3>; b: bytes; }
    @contract class C {
      @external @pure vleaf(): bytes { let pp: Arr<u256, 3> = [7n, 8n, 9n]; let s: S = S(1n, In(3n, 4n), pp, bytes("z")); s.inner.x = 90n; return abi.encode(s, s.inner.x, s.inner.y); }
      @external @pure felem(): bytes { let pp: Arr<u256, 3> = [7n, 8n, 9n]; let s: S = S(1n, In(3n, 4n), pp, bytes("z")); s.fa[1n] = 99n; return abi.encode(s, s.fa[1n], s.fa[0n]); }
      @external @pure fdyn(i: u256): u256 { let pp: Arr<u256, 3> = [7n, 8n, 9n]; let s: S = S(1n, In(3n, 4n), pp, bytes("z")); s.fa[i] = 77n; return s.fa[i]; }
      @external @pure repoint(): bytes { let pp: Arr<u256, 3> = [7n, 8n, 9n]; let s: S = S(1n, In(3n, 4n), pp, bytes("z")); s.inner = In(5n, 6n); let q: Arr<u256, 3> = [10n, 11n, 12n]; s.fa = q; return abi.encode(s); } }`;
    const Sol = `struct In { uint256 x; uint256 y; }
    struct S { uint256 a; In inner; uint256[3] fa; bytes b; }
    contract C {
      function vleaf() external pure returns(bytes memory){ uint256[3] memory pp;pp[0]=7;pp[1]=8;pp[2]=9; S memory s=S(1,In(3,4),pp,bytes("z")); s.inner.x=90; return abi.encode(s, s.inner.x, s.inner.y); }
      function felem() external pure returns(bytes memory){ uint256[3] memory pp;pp[0]=7;pp[1]=8;pp[2]=9; S memory s=S(1,In(3,4),pp,bytes("z")); s.fa[1]=99; return abi.encode(s, s.fa[1], s.fa[0]); }
      function fdyn(uint256 i) external pure returns(uint256){ uint256[3] memory pp;pp[0]=7;pp[1]=8;pp[2]=9; S memory s=S(1,In(3,4),pp,bytes("z")); s.fa[i]=77; return s.fa[i]; }
      function repoint() external pure returns(bytes memory){ uint256[3] memory pp;pp[0]=7;pp[1]=8;pp[2]=9; S memory s=S(1,In(3,4),pp,bytes("z")); s.inner=In(5,6); uint256[3] memory q;q[0]=10;q[1]=11;q[2]=12; s.fa=q; return abi.encode(s); } }`;
    await diff(J, Sol, [['vleaf()', ''], ['felem()', ''], ['fdyn(uint256)', pad32(2n)], ['fdyn(uint256)', pad32(9n)], ['repoint()', '']]);
  });
});
