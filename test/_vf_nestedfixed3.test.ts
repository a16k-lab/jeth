// AREA: nestedfixed (part 3) - nested FIXED arrays as CALLDATA PARAMETERS (decode
// side). JETH supports index/field READS of an aggregate calldata param (Phase 4d),
// but gates a WHOLE-array param return (JETH230). So this probe exercises the SUPPORTED
// surface: a[i][j] / a[i][j][k] leaf reads from a nested fixed-array param, packed u8,
// signed i64, bytesN element reads, summation loops, dirty leaf words (solc input
// validation), OOB index Panic(0x32), truncated calldata. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `@contract class C {
  @external idx2(a: Arr<Arr<u256, 2>, 2>, i: u256, j: u256): u256 { return a[i][j]; }
  @external idx3(a: Arr<Arr<Arr<u256, 2>, 2>, 2>, i: u256, j: u256, k: u256): u256 { return a[i][j][k]; }
  @external idxP(a: Arr<Arr<u8, 3>, 2>, i: u256, j: u256): u8 { return a[i][j]; }
  @external idxS(a: Arr<Arr<i64, 2>, 2>, i: u256, j: u256): i64 { return a[i][j]; }
  @external idxB(a: Arr<Arr<bytes4, 2>, 2>, i: u256, j: u256): bytes4 { return a[i][j]; }
  @external sum2(a: Arr<Arr<u256, 2>, 2>): u256 {
    let s: u256 = 0n;
    for (let i: u256 = 0n; i < 2n; i = i + 1n) { for (let j: u256 = 0n; j < 2n; j = j + 1n) { s = s + a[i][j]; } }
    return s;
  }
  @external sumP(a: Arr<Arr<u8, 3>, 2>): u256 {
    let s: u256 = 0n;
    for (let i: u256 = 0n; i < 2n; i = i + 1n) { for (let j: u256 = 0n; j < 3n; j = j + 1n) { s = s + u256(a[i][j]); } }
    return s;
  }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function idx2(uint256[2][2] calldata a, uint256 i, uint256 j) external pure returns (uint256){ return a[i][j]; }
  function idx3(uint256[2][2][2] calldata a, uint256 i, uint256 j, uint256 k) external pure returns (uint256){ return a[i][j][k]; }
  function idxP(uint8[3][2] calldata a, uint256 i, uint256 j) external pure returns (uint8){ return a[i][j]; }
  function idxS(int64[2][2] calldata a, uint256 i, uint256 j) external pure returns (int64){ return a[i][j]; }
  function idxB(bytes4[2][2] calldata a, uint256 i, uint256 j) external pure returns (bytes4){ return a[i][j]; }
  function sum2(uint256[2][2] calldata a) external pure returns (uint256){
    uint256 s = 0;
    for (uint256 i = 0; i < 2; i++) { for (uint256 j = 0; j < 2; j++) { s += a[i][j]; } }
    return s;
  }
  function sumP(uint8[3][2] calldata a) external pure returns (uint256){
    uint256 s = 0;
    for (uint256 i = 0; i < 2; i++) { for (uint256 j = 0; j < 3; j++) { s += uint256(a[i][j]); } }
    return s;
  }
}`;

describe('nestedfixed probe part 3 (calldata params)', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(label + ': jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError + '} sol{ok=' + s.success + ',ret=' + s.returnHex + '}');
  }
  function call(sig: string, words: bigint[]): string {
    return '0x' + functionSelector(sig) + words.map(pad).join('');
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    // 2D u256: row-major a[0][0],a[0][1],a[1][0],a[1][1]
    const g2 = [0x11n, 0x22n, 0x33n, 0x44n];
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`idx2[${i}][${j}]`, call('idx2(uint256[2][2],uint256,uint256)', [...g2, i, j]));
    // boundary leaf values
    const g2b = [0n, M - 1n, 1n << 255n, (1n << 255n) - 1n];
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`idx2-bound[${i}][${j}]`, call('idx2(uint256[2][2],uint256,uint256)', [...g2b, i, j]));
    await eq('idx2-oob-i', call('idx2(uint256[2][2],uint256,uint256)', [...g2, 2n, 0n]));
    await eq('idx2-oob-j', call('idx2(uint256[2][2],uint256,uint256)', [...g2, 0n, 2n]));
    await eq('idx2-oob-huge', call('idx2(uint256[2][2],uint256,uint256)', [...g2, M - 1n, 0n]));
    await eq('sum2', call('sum2(uint256[2][2])', [10n, 20n, 30n, 40n]));
    await eq('sum2-overflow', call('sum2(uint256[2][2])', [M - 1n, 1n, 0n, 0n])); // checked add overflow -> Panic 0x11

    // 3D u256: 8 leaves row-major
    const g3 = [0x1n, 0x2n, 0x3n, 0x4n, 0x5n, 0x6n, 0x7n, 0x8n];
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++) for (let k = 0n; k < 2n; k++)
      await eq(`idx3[${i}][${j}][${k}]`, call('idx3(uint256[2][2][2],uint256,uint256,uint256)', [...g3, i, j, k]));
    await eq('idx3-oob-k', call('idx3(uint256[2][2][2],uint256,uint256,uint256)', [...g3, 0n, 0n, 2n]));
    await eq('idx3-oob-i', call('idx3(uint256[2][2][2],uint256,uint256,uint256)', [...g3, 2n, 0n, 0n]));

    // packed u8 param: each leaf word is its own ABI word; solc validates <256
    const p = [1n, 2n, 3n, 4n, 5n, 6n];
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 3n; j++)
      await eq(`idxP[${i}][${j}]`, call('idxP(uint8[3][2],uint256,uint256)', [...p, i, j]));
    await eq('idxP-dirty', call('idxP(uint8[3][2],uint256,uint256)', [0x100n, 2n, 3n, 4n, 5n, 6n, 0n, 0n]));
    await eq('idxP-dirty-unread', call('idxP(uint8[3][2],uint256,uint256)', [1n, 2n, 3n, 4n, 5n, 0x1ffn, 0n, 0n])); // dirty UNREAD leaf
    await eq('sumP', call('sumP(uint8[3][2])', p));
    await eq('sumP-dirty', call('sumP(uint8[3][2])', [0x100n, 2n, 3n, 4n, 5n, 6n])); // reads all -> revert

    // signed i64 param
    const s = [5n, M - 7n, (1n << 63n) - 1n, M - (1n << 63n)];
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`idxS[${i}][${j}]`, call('idxS(int64[2][2],uint256,uint256)', [...s, i, j]));
    await eq('idxS-dirty', call('idxS(int64[2][2],uint256,uint256)', [(1n << 64n) | 5n, M - 7n, 0n, 0n, 0n, 0n]));

    // bytesN param
    const b = [0xdeadbeefn << 224n, 0x11223344n << 224n, 0n, 0xffffffffn << 224n];
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`idxB[${i}][${j}]`, call('idxB(bytes4[2][2],uint256,uint256)', [...b, i, j]));
    await eq('idxB-dirty', call('idxB(bytes4[2][2],uint256,uint256)', [0xdeadbeefn, 0n, 0n, 0n, 0n, 0n])); // not left-aligned

    // truncated calldata (one leaf word short) -> both revert
    const short = '0x' + functionSelector('idx2(uint256[2][2],uint256,uint256)') + [0x11n, 0x22n, 0x33n].map(pad).join('');
    await eq('idx2-truncated', short);

    if (mism.length) { console.log('MISMATCHES ' + mism.length + '/' + count); for (const m of mism.slice(0, 40)) console.log(m); }
    else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
