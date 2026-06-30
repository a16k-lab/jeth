// Library/struct over-rejections found by the differential audit (JETH900 crashes on valid input;
// never a miscompile). Lifted byte-identical to solc 0.8.35.
//  OR8: a STORAGE struct passed to an internal function (@library or plain) - solc copies it
//       storage->memory (the param is `S memory`); JETH crashed (structValue in a non-reference
//       context). Now a fresh flat memory image is built via abiEncFromStorage.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => n.toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function pair(jeth: string, sol: string) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { hj, hs, aj, as };
}

describe('audit library/struct over-rejections lifted byte-identical', () => {
  async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
    const { hj, hs, aj, as } = await pair(jeth, sol);
    for (const [sig, args] of calls) {
      const rj = await hj.call(aj, sel(sig) + args);
      const rs = await hs.call(as, sel(sig) + args);
      expect(rj.success, `${sig} success`).toBe(rs.success);
      expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
    }
  }

  it('OR8: a @state storage struct passed to an internal @library function', async () => {
    await eqCalls(
      '@struct class S { a: u256; b: u256; } @library class L { sm(s: S): u256 { return s.a * 10n + s.b; } } @contract @using(L) class C { @state st: S; @external set(x: u256, y: u256): void { this.st.a = x; this.st.b = y; } @external @view go(): u256 { return L.sm(this.st); } }',
      'library L { } contract C { struct S { uint256 a; uint256 b; } S st; function sm(S memory s) internal pure returns(uint256){ return s.a*10+s.b; } function set(uint256 x, uint256 y) external { st.a=x; st.b=y; } function go() external view returns(uint256){ return sm(st); } }',
      [['set(uint256,uint256)', W(3n) + W(4n)], ['go()', '']],
    );
  });

  it('OR8: a storage struct to a plain internal fn (storage / mapping / array element sources)', async () => {
    await eqCalls(
      '@struct class S { a: u256; b: u256; } @contract class C { @state st: S; @state m: mapping<u256,S>; @state arr: S[]; g(s: S): u256 { return s.a * 10n + s.b; } @external seed(): void { this.st.a = 1n; this.st.b = 2n; this.m[5n].a = 3n; this.m[5n].b = 4n; this.arr.push(S(6n, 7n)); } @external @view gst(): u256 { return this.g(this.st); } @external @view gm(): u256 { return this.g(this.m[5n]); } @external @view ga(): u256 { return this.g(this.arr[0n]); } }',
      'contract C { struct S { uint256 a; uint256 b; } S st; mapping(uint256=>S) m; S[] arr; function g(S memory s) internal pure returns(uint256){ return s.a*10+s.b; } function seed() external { st.a=1; st.b=2; m[5].a=3; m[5].b=4; arr.push(S(6,7)); } function gst() external view returns(uint256){ return g(st); } function gm() external view returns(uint256){ return g(m[5]); } function ga() external view returns(uint256){ return g(arr[0]); } }',
      [['seed()', ''], ['gst()', ''], ['gm()', ''], ['ga()', '']],
    );
  });

  it('OR8: packed storage struct + copy semantics (callee write does not affect storage)', async () => {
    await eqCalls(
      '@struct class S { a: u128; b: u128; } @contract class C { @state st: S; mut(s: S): u256 { s.a = 999n; return u256(s.a) + u256(s.b); } @external set(x: u128, y: u128): void { this.st.a = x; this.st.b = y; } @external go(): u256 { return this.mut(this.st); } @external @view ra(): u128 { return this.st.a; } }',
      'contract C { struct S { uint128 a; uint128 b; } S st; function mut(S memory s) internal pure returns(uint256){ s.a=999; return uint256(s.a)+uint256(s.b); } function set(uint128 x, uint128 y) external { st.a=x; st.b=y; } function go() external returns(uint256){ return mut(st); } function ra() external view returns(uint128){ return st.a; } }',
      [['set(uint128,uint128)', W(12n) + W(34n)], ['go()', ''], ['ra()', '']],
    );
  });
});
