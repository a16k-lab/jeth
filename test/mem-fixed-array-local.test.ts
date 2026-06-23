// G9: fixed-array MEMORY locals (let a: Arr<u256,3> = [...]). memAggregate (N words); a[i]
// read/write (bounds-checked -> Panic 0x32), compound/inc-dec, whole return, aliasing, and
// copy from a storage / calldata fixed array. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const call = (sig: string, words: bigint[]) => '0x' + sel(sig) + words.map(pad).join('');

const JETH = `@contract class C {
  @state g: Arr<u256, 3>;
  @external setG(i: u256, v: u256): void { this.g[i] = v; }
  // construct + element read/write/compound + whole return
  @external @pure build(x: u256, y: u256, z: u256): Arr<u256, 3> {
    let a: Arr<u256, 3> = [x, y, z];
    a[0n] = a[0n] + 1n; a[1n]++; a[2n] += 10n;
    return a;
  }
  @external @pure sum(x: u256, y: u256, z: u256): u256 { let a: Arr<u256, 3> = [x, y, z]; return a[0n] + a[1n] + a[2n]; }
  // bounds check
  @external @pure oob(x: u256, i: u256): u256 { let a: Arr<u256, 3> = [x, x, x]; return a[i]; }
  // aliasing: b = a; b[0]=99 changes a
  @external @pure aliasing(x: u256): Arr<u256, 3> { let a: Arr<u256, 3> = [x, x, x]; let b: Arr<u256, 3> = a; b[0n] = 99n; return a; }
  // narrow / signed elements
  @external @pure narrow(p: u8, q: u8): Arr<u8, 4> { let a: Arr<u8, 4> = [p, q, 255n, 0n]; a[1n] = 200n; return a; }
  @external @pure signed(p: i64, q: i64): Arr<i64, 3> { let a: Arr<i64, 3> = [p, q, -1n]; return a; }
  // copy from storage fixed array
  @external @view fromG(): Arr<u256, 3> { let a: Arr<u256, 3> = this.g; a[0n] = a[0n] + 1000n; return a; }
  @external @view getG(i: u256): u256 { return this.g[i]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[3] g;
  function setG(uint256 i, uint256 v) external { g[i] = v; }
  function build(uint256 x, uint256 y, uint256 z) external pure returns (uint256[3] memory){
    uint256[3] memory a = [x, y, z];
    a[0] = a[0] + 1; a[1]++; a[2] += 10;
    return a;
  }
  function sum(uint256 x, uint256 y, uint256 z) external pure returns (uint256){ uint256[3] memory a = [x, y, z]; return a[0] + a[1] + a[2]; }
  function oob(uint256 x, uint256 i) external pure returns (uint256){ uint256[3] memory a = [x, x, x]; return a[i]; }
  function aliasing(uint256 x) external pure returns (uint256[3] memory){ uint256[3] memory a = [x, x, x]; uint256[3] memory b = a; b[0] = 99; return a; }
  function narrow(uint8 p, uint8 q) external pure returns (uint8[4] memory){ uint8[4] memory a = [p, q, 255, 0]; a[1] = 200; return a; }
  function signed(int64 p, int64 q) external pure returns (int64[3] memory){ int64[3] memory a = [p, q, -1]; return a; }
  function fromG() external view returns (uint256[3] memory){ uint256[3] memory a = g; a[0] = a[0] + 1000; return a; }
  function getG(uint256 i) external view returns (uint256){ return g[i]; }
}`;

describe('fixed-array memory locals (G9) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${j.exceptionError}`).toBe(s.success);
  }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('construct / element RMW / return / sum / alias', async () => {
    for (const [x, y, z] of [
      [1n, 2n, 3n],
      [0n, 0n, 0n],
      [M - 1n, M - 2n, 5n],
    ] as [bigint, bigint, bigint][]) {
      await eq('build', call('build(uint256,uint256,uint256)', [x, y, z]));
      await eq('sum', call('sum(uint256,uint256,uint256)', [x, y, z]));
      await eq('aliasing', call('aliasing(uint256)', [x]));
    }
  });
  it('bounds check (a[i] OOB -> Panic 0x32)', async () => {
    for (const i of [0n, 2n, 3n, 100n]) await eq(`oob(${i})`, call('oob(uint256,uint256)', [42n, i]));
  });
  it('narrow / signed elements', async () => {
    await eq('narrow', call('narrow(uint8,uint8)', [7n, 9n]));
    for (const [p, q] of [
      [1n, -1n],
      [(1n << 63n) - 1n, M - (1n << 63n)],
    ] as [bigint, bigint][])
      await eq('signed', call('signed(int64,int64)', [p, q]));
  });
  it('copy from a storage fixed array', async () => {
    for (const v of [10n, 20n, 30n]) await send(call('setG(uint256,uint256)', [v / 10n - 1n, v]));
    await eq('fromG', call('fromG()', []));
    await eq('getG(0) unchanged by the memory copy', call('getG(uint256)', [0n]));
  });
});
