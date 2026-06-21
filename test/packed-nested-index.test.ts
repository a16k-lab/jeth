// #2: a packed (<256-bit) fixed-array element indexed via a struct-FIELD path with a
// runtime (and constant) index: this.q.pts[i] where pts is Arr<i64,3> / Arr<u64,4>.
// read + write, signed sign-extend + unsigned, packing within slots. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;

const JETH = `@struct class Q { tag: u256; pts: Arr<i64, 3>; us: Arr<u64, 4>; }
@contract class PN {
  @state q: Q;
  @external setPt(i: u256, v: i64): void { this.q.pts[i] = v; }
  @external setUs(i: u256, v: u64): void { this.q.us[i] = v; }
  @external setPt1(v: i64): void { this.q.pts[1n] = v; }
  @external @view getPt(i: u256): i64 { return this.q.pts[i]; }
  @external @view getUs(i: u256): u64 { return this.q.us[i]; }
  @external @view getPt2(): i64 { return this.q.pts[2n]; }
  @external @view tag(): u256 { return this.q.tag; }
  @external setTag(v: u256): void { this.q.tag = v; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PN {
  struct Q { uint256 tag; int64[3] pts; uint64[4] us; }
  Q q;
  function setPt(uint256 i, int64 v) external { q.pts[i] = v; }
  function setUs(uint256 i, uint64 v) external { q.us[i] = v; }
  function setPt1(int64 v) external { q.pts[1] = v; }
  function getPt(uint256 i) external view returns (int64){ return q.pts[i]; }
  function getUs(uint256 i) external view returns (uint64){ return q.us[i]; }
  function getPt2() external view returns (int64){ return q.pts[2]; }
  function tag() external view returns (uint256){ return q.tag; }
  function setTag(uint256 v) external { q.tag = v; }
}`;

describe('packed fixed-array element via struct field vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function send(data: string) { const j = await jeth.call(aj, data); const s = await sol.call(as, data); expect(j.success, `send ${j.exceptionError}`).toBe(s.success); }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'PN.jeth' });
    const sb = compileSolidity(SOL, 'PN');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('signed packed element runtime write/read incl negatives + sign-extend', async () => {
    await send(encodeCall(sel('setTag(uint256)'), [0xdeadn]));
    await send(encodeCall(sel('setPt(uint256,int64)'), [0n, 5n]));
    await send(encodeCall(sel('setPt(uint256,int64)'), [1n, M - 7n])); // -7
    await send(encodeCall(sel('setPt(uint256,int64)'), [2n, (1n << 63n) - 1n])); // i64 max
    for (const i of [0n, 1n, 2n]) await eq(`getPt[${i}]`, encodeCall(sel('getPt(uint256)'), [i]));
    await eq('getPt2 const', encodeCall(sel('getPt2()'), []));
    await eq('tag preserved', encodeCall(sel('tag()'), []));
  });
  it('unsigned packed element runtime write/read (4 per slot)', async () => {
    for (const [i, v] of [[0n, 11n], [1n, 22n], [2n, 33n], [3n, (1n << 64n) - 1n]] as [bigint, bigint][])
      await send(encodeCall(sel('setUs(uint256,uint64)'), [i, v]));
    for (const i of [0n, 1n, 2n, 3n]) await eq(`getUs[${i}]`, encodeCall(sel('getUs(uint256)'), [i]));
  });
  it('constant-index packed write', async () => {
    await send(encodeCall(sel('setPt1(int64)'), [M - 99n]));
    await eq('getPt[1] after const write', encodeCall(sel('getPt(uint256)'), [1n]));
  });
  it('OOB packed index reverts identically', async () => {
    const data = encodeCall(sel('getPt(uint256)'), [3n]);
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success).toBe(s.success);
  });
});
