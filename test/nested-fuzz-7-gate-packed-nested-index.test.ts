// Formerly a GATE test: a PACKED fixed-array element inside a nested storage chain
// (this.accts[k].hist[i] where hist is Arr<u32,4>, mapKey -> field -> packedIndex) is now
// SUPPORTED via a runtime byte offset in the place model. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const K = BigInt('0x' + 'ab'.repeat(20));

const JETH = `@struct class Acct { hist: Arr<u32, 4>; }
@contract class Packed {
  @state accts: mapping<address, Acct>;
  @external setHist(k: address, i: u256, v: u32): void { this.accts[k].hist[i] = v; }
  @external @view getHist(k: address, i: u256): u32 { return this.accts[k].hist[i]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Packed {
  struct Acct { uint32[4] hist; }
  mapping(address => Acct) accts;
  function setHist(address k, uint256 i, uint32 v) external { accts[k].hist[i] = v; }
  function getHist(address k, uint256 i) external view returns (uint32){ return accts[k].hist[i]; }
}`;

describe('packed element in a nested mapping/struct/index chain vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function send(data: string) { const j = await jeth.call(aj, data); const s = await sol.call(as, data); expect(j.success).toBe(s.success); }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'Packed.jeth' });
    const sb = compileSolidity(SOL, 'Packed');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('this.accts[k].hist[i] packed write/read byte-identical (8 u32 per slot)', async () => {
    for (const [i, v] of [[0n, 11n], [1n, 22n], [2n, 33n], [3n, (1n << 32n) - 1n]] as [bigint, bigint][])
      await send(encodeCall(sel('setHist(address,uint256,uint32)'), [K, i, v]));
    for (const i of [0n, 1n, 2n, 3n]) await eq(`getHist[${i}]`, encodeCall(sel('getHist(address,uint256)'), [K, i]));
    // OOB index parity
    const data = encodeCall(sel('getHist(address,uint256)'), [K, 4n]);
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success).toBe(s.success);
  });
});
