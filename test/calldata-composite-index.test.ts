// Tier-1 (JETH151/JETH210): element access a[i][j] on a MIXED calldata composite array param:
//   dynamic-of-fixed  uint256[2][]   (a[i] is a contiguous fixed sub-array)
//   fixed-of-dynamic  uint256[][2]   (a[i] is an inner dynamic array via the offset table)
// Plus a[i].length (210). Byte-identical to solc incl. OOB Panic(0x32) parity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `@contract class C {
  @external @pure dof(a: Arr<u256,2>[], i: u256, j: u256): u256 { return a[i][j]; }
  @external @pure fod(a: Arr<u256[],2>, i: u256, j: u256): u256 { return a[i][j]; }
  @external @pure fodLen(a: Arr<u256[],2>, i: u256): u256 { return a[i].length; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function dof(uint256[2][] calldata a, uint256 i, uint256 j) external pure returns (uint256) { return a[i][j]; }
  function fod(uint256[][2] calldata a, uint256 i, uint256 j) external pure returns (uint256) { return a[i][j]; }
  function fodLen(uint256[][2] calldata a, uint256 i) external pure returns (uint256) { return a[i].length; }
}`;

// dynamic-of-fixed: [len][e0w0][e0w1][e1w0][e1w1]...  (fixed[2] elements contiguous)
const encDof = (rows: bigint[][]) => pad(BigInt(rows.length)) + rows.map((r) => pad(r[0]!) + pad(r[1]!)).join('');
// fixed-of-dynamic uint256[][2]: [off0][off1][inner0][inner1], offsets relative to the array start
const encU256Arr = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');
const encFod = (rows: bigint[][]) => {
  const inners = rows.map(encU256Arr);
  let off = rows.length * 32; const offs: string[] = [];
  for (const e of inners) { offs.push(pad(BigInt(off))); off += e.length / 2; }
  return offs.join('') + inners.join('');
};

describe('calldata composite element access (JETH151/210) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('dynamic-of-fixed uint256[2][] a[i][j] (+ OOB)', async () => {
    const rows = [[1n, 2n], [3n, 4n], [5n, 6n], [M - 1n, 0n]];
    const head = (i: bigint, j: bigint) => '0x' + sel('dof(uint256[2][],uint256,uint256)') + pad(0x60n) + pad(i) + pad(j) + encDof(rows);
    for (let i = 0n; i < 4n; i++) for (let j = 0n; j < 2n; j++) await eq(`dof[${i}][${j}]`, head(i, j));
    await eq('dof i OOB', head(4n, 0n));
    await eq('dof j OOB', head(0n, 2n));
    await eq('dof both OOB', head(9n, 9n));
  });
  it('fixed-of-dynamic uint256[][2] a[i][j] + a[i].length (+ OOB)', async () => {
    const rows = [[1n, 2n, 3n], [4n, 5n]];
    // fod(a,i,j): head [off_a=0x60][i][j]; fodLen(a,i): head [off_a=0x40][i]
    const fod = (i: bigint, j: bigint) => '0x' + sel('fod(uint256[][2],uint256,uint256)') + pad(0x60n) + pad(i) + pad(j) + encFod(rows);
    const fodLen = (i: bigint) => '0x' + sel('fodLen(uint256[][2],uint256)') + pad(0x40n) + pad(i) + encFod(rows);
    for (const [i, n] of [[0n, 3n], [1n, 2n]] as const) {
      await eq(`fodLen[${i}]`, fodLen(i));
      for (let j = 0n; j < n; j++) await eq(`fod[${i}][${j}]`, fod(i, j));
      await eq(`fod[${i}] j OOB`, fod(i, n));
    }
    await eq('fod i OOB', fod(2n, 0n));
  });
});
