// AUDIT: ordering of OOB-panic vs dirty-revert vs short-calldata for aggregate params.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = (1n << 256n);
function pad(v: bigint): string { return (((v % M) + M) % M).toString(16).padStart(64, '0'); }
const W = (v: bigint) => pad(v);

const JETH = `
@struct class P { x: u128; y: u128; }
@contract
class A {
  @external @pure pick(a: Arr<u8, 4>, i: u256): u8 { return a[i]; }
  @external @pure spx(ps: Arr<P, 2>, i: u256): u128 { return ps[i].x; }
  @external @pure aax(a: Arr<Arr<P,2>,2>, i: u256, j: u256): u128 { return a[i][j].x; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct P { uint128 x; uint128 y; }
  function pick(uint8[4] calldata a, uint256 i) external pure returns (uint8){ return a[i]; }
  function spx(P[2] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].x; }
  function aax(P[2][2] calldata a, uint256 i, uint256 j) external pure returns (uint128){ return a[i][j].x; }
}`;

let jeth: Harness, sol: Harness, aj: Address, as: Address;
beforeAll(async () => {
  const jb = compile(JETH, { fileName: 'A.jeth' });
  const sb = compileSolidity(SOL, 'A');
  jeth = await Harness.create(); sol = await Harness.create();
  aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
});
async function eq(label: string, data: string) {
  const j = await jeth.call(aj, data); const s = await sol.call(as, data);
  expect(j.success, `${label}: jeth=${j.success}(${j.exceptionError}) sol=${s.success}`).toBe(s.success);
  expect(j.returnHex, `${label}: rd jeth=${j.returnHex} sol=${s.returnHex}`).toBe(s.returnHex);
  return { j, s };
}

describe('OOB vs dirty ordering', () => {
  it('pick: OOB index when a dirty element exists -> which wins?', async () => {
    const sel = functionSelector('pick(uint8[4],uint256)');
    // element 0 dirty (0x1ff) AND index OOB (i=4): solc panics 0x32 (bound first)
    await eq('pick dirty+OOB', '0x' + sel + [0x1ffn, 0n, 0n, 0n, 4n].map(W).join(''));
    // huge index 2^255
    await eq('pick huge idx', '0x' + sel + [0n, 0n, 0n, 0n, 1n << 255n].map(W).join(''));
  });
  it('aax: i OOB and j OOB at once', async () => {
    const sel = functionSelector('aax((uint128,uint128)[2][2],uint256,uint256)');
    const a = [0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n];
    await eq('aax i&j OOB', '0x' + sel + [...a, 2n, 2n].map(W).join(''));
    await eq('aax i OOB only', '0x' + sel + [...a, 5n, 0n].map(W).join(''));
    await eq('aax j OOB only', '0x' + sel + [...a, 0n, 9n].map(W).join(''));
  });
  it('spx: short calldata (head truncated) vs OOB index', async () => {
    const sel = functionSelector('spx((uint128,uint128)[2],uint256)');
    // full head = 5 words. Truncate to 4 words but index also OOB -> short revert wins.
    await eq('spx short head', '0x' + sel + [1n, 2n, 3n, 4n].map(W).join(''));
    // exactly enough head but index OOB
    await eq('spx OOB', '0x' + sel + [1n, 2n, 3n, 4n, 2n].map(W).join(''));
    // dirty p1.x with OOB i=2 -> panic should win (bound first)
    await eq('spx dirty+OOB', '0x' + sel + [1n, 2n, (1n << 200n) | 3n, 4n, 2n].map(W).join(''));
  });
});
