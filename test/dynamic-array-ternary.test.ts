// JETH074 lift: a ternary over a DYNAMIC value-element array, `c ? a : b`, where the branches are
// storage arrays (this.a/this.b), calldata params, memory locals, or literals. The taken branch is
// materialized to a memory [len][elems] pointer (storage/calldata copy, memory alias) and selected;
// routed through memArrayExpr so return / index / .length consume it uniformly. Short-circuit (only
// the taken branch materialized), byte-identical to solc 0.8.35.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const cdArr = (xs: readonly bigint[]) => pad32(BigInt(xs.length)) + xs.map(pad32).join('');

describe('ternary over a dynamic value-array (JETH074) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `@contract class C {
    @state a: u256[];
    @state b: u256[];
    @external pushA(v: u256): void { this.a.push(v); }
    @external pushB(v: u256): void { this.b.push(v); }
    @external @view ret(c: bool): u256[] { return c ? this.a : this.b; }
    @external @view idx(c: bool, i: u256): u256 { return (c ? this.a : this.b)[i]; }
    @external @view len(c: bool): u256 { return (c ? this.a : this.b).length; }
    @external @pure cdRet(c: bool, x: u256[], y: u256[]): u256[] { return c ? x : y; }
    @external @pure memMix(c: bool, x: u256[]): u256[] { let m: u256[] = [1n, 2n]; return c ? m : x; } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  uint256[] a; uint256[] b;
  function pushA(uint256 v) external { a.push(v); }
  function pushB(uint256 v) external { b.push(v); }
  function ret(bool c) external view returns (uint256[] memory) { return c ? a : b; }
  function idx(bool c, uint256 i) external view returns (uint256) { return (c ? a : b)[i]; }
  function len(bool c) external view returns (uint256) { return (c ? a : b).length; }
  function cdRet(bool c, uint256[] calldata x, uint256[] calldata y) external pure returns (uint256[] memory) { return c ? x : y; }
  function memMix(bool c, uint256[] calldata x) external pure returns (uint256[] memory) { uint256[] memory m=new uint256[](2); m[0]=1;m[1]=2; return c ? m : x; } }`;

  beforeAll(async () => {
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
    const both = async (d: string) => { await jeth.call(aj, d); await sol.call(as, d); };
    for (const v of [10n, 20n, 30n]) await both('0x' + sel('pushA(uint256)') + pad32(v));
    for (const v of [100n, 200n]) await both('0x' + sel('pushB(uint256)') + pad32(v));
  });
  const cmp = async (data: string, label: string) => {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
  };

  it('storage-source ternary: whole return, index, and length per branch', async () => {
    for (const c of [1n, 0n]) {
      await cmp('0x' + sel('ret(bool)') + pad32(c), `ret(${c})`);
      await cmp('0x' + sel('len(bool)') + pad32(c), `len(${c})`);
      for (const i of [0n, 1n, 2n, 5n]) await cmp('0x' + sel('idx(bool,uint256)') + pad32(c) + pad32(i), `idx(${c},${i})`); // i=5 OOB
    }
  });
  it('calldata-source ternary return', async () => {
    for (const c of [1n, 0n]) {
      const x = [7n, 8n], y = [9n, 10n, 11n];
      const offx = 0x60n, offy = offx + BigInt((1 + x.length) * 32);
      await cmp('0x' + sel('cdRet(bool,uint256[],uint256[])') + pad32(c) + pad32(offx) + pad32(offy) + cdArr(x) + cdArr(y), `cdRet(${c})`);
    }
  });
  it('mixed memory-local vs calldata branches', async () => {
    for (const c of [1n, 0n]) {
      const x = [42n, 43n];
      await cmp('0x' + sel('memMix(bool,uint256[])') + pad32(c) + pad32(0x40n) + cdArr(x), `memMix(${c})`);
    }
  });
});
