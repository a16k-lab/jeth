// Lifting rare sound over-rejections to full solc parity. Each case was rejected by JETH (often a
// clean diagnostic, one a JETH900 crash) while solc 0.8.35 accepts it; the result is now verified
// byte-identical. Differential: a JETH contract and the solc equivalent are deployed and their
// (success, returnHex) compared for the same calldata.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);

async function rt(jeth: string, sol: string, sigs: string[]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const s of sigs) {
    const data = '0x' + sel(s);
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${s}: success`).toBe(rs.success);
    expect(rj.returnHex, `${s}: returndata`).toBe(rs.returnHex);
  }
}

describe('lifted over-rejections: byte-identical vs solc', () => {
  it('abi.encode of an internal call returning a value-element array [was JETH900]', async () => {
    const J = `@contract class C {
      mk(): u256[] { let a: u256[] = new Array<u256>(3n); a[0n] = 7n; a[1n] = 8n; a[2n] = 9n; return a; }
      @external @pure f(): bytes { return abi.encode(this.mk()); }
      @external @pure g(): bytes { return abi.encode(7n, this.mk(), 9n); }
      @external @pure p(): bytes { return abi.encodePacked(this.mk()); }
    }`;
    const S = `contract C {
      function mk() internal pure returns (uint256[] memory){ uint256[] memory a = new uint256[](3); a[0]=7; a[1]=8; a[2]=9; return a; }
      function f() external pure returns (bytes memory){ return abi.encode(mk()); }
      function g() external pure returns (bytes memory){ return abi.encode(uint256(7), mk(), uint256(9)); }
      function p() external pure returns (bytes memory){ return abi.encodePacked(mk()); }
    }`;
    await rt(J, S, ['f()', 'g()', 'p()']);
  });

  it('memory-array struct-element field writes xs[i].a=v / deep / compound [was JETH067]', async () => {
    const J = `@struct class P { a: u256; b: u8; }
    @struct class Q { m: u256; }
    @struct class R { q: Q; pre: Arr<u256, 2>; }
    @contract class C {
      @external @pure fa(i: u256): bytes { let xs: P[] = new Array<P>(3n); xs[i].a = 11n; xs[i].b = 222n; return abi.encode(xs[i].a, xs[i].b); }
      @external @pure fdeep(i: u256): bytes { let xs: R[] = new Array<R>(2n); xs[i].q.m = 7n; xs[i].pre[0n] = 8n; xs[i].pre[1n] = 9n; return abi.encode(xs[i].q.m, xs[i].pre[0n], xs[i].pre[1n]); }
      @external @pure fdirty(i: u256, v: u256): bytes { let xs: P[] = new Array<P>(2n); xs[i].b = u8(v); return abi.encode(xs[i].b); }
      @external @pure fcompound(i: u256): u256 { let xs: P[] = new Array<P>(3n); xs[i].a = 10n; xs[i].a += 5n; xs[i].a++; return xs[i].a; }
    }`;
    const S = `struct P { uint256 a; uint8 b; }
    struct Q { uint256 m; }
    struct R { Q q; uint256[2] pre; }
    contract C {
      function fa(uint256 i) external pure returns (bytes memory){ P[] memory xs = new P[](3); xs[i].a=11; xs[i].b=222; return abi.encode(xs[i].a, xs[i].b); }
      function fdeep(uint256 i) external pure returns (bytes memory){ R[] memory xs = new R[](2); xs[i].q.m=7; xs[i].pre[0]=8; xs[i].pre[1]=9; return abi.encode(xs[i].q.m, xs[i].pre[0], xs[i].pre[1]); }
      function fdirty(uint256 i, uint256 v) external pure returns (bytes memory){ P[] memory xs = new P[](2); xs[i].b=uint8(v); return abi.encode(xs[i].b); }
      function fcompound(uint256 i) external pure returns (uint256){ P[] memory xs = new P[](3); xs[i].a=10; xs[i].a+=5; xs[i].a++; return xs[i].a; }
    }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await hs.deploy(compileSolidity(SPDX + S, 'C').creation);
    const P = (await import('../src/evm.js')).pad32;
    const cases: [string, string][] = [
      ['fa(uint256)', P(1n)],
      ['fdeep(uint256)', P(1n)],
      ['fdirty(uint256,uint256)', P(0n) + P(0x1ffn)],
      ['fcompound(uint256)', P(1n)],
    ];
    for (const [sig, args] of cases) {
      const data = '0x' + sel(sig) + args;
      const rj = await hj.call(aj, data);
      const rs = await hs.call(as, data);
      expect(rj.success, sig).toBe(rs.success);
      expect(rj.returnHex, sig).toBe(rs.returnHex);
    }
  });
});
