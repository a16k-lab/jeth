// Phase 4e-2b: mapping<K, T[]> (value and struct element), byte-identical to Solidity
// incl. runtime keccak slots: push/pop/.length, this.m[k][i] read+write, per-key
// isolation, OOB Panic(0x32), pop-empty Panic(0x31), sentinel untouched.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const K1 = BigInt('0x' + '11'.repeat(20));
const K2 = BigInt('0x' + '22'.repeat(20));

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
function kec(hex: string): bigint {
  return BigInt('0x' + toHex(keccak(hexToBytes(('0x' + hex) as `0x${string}`))));
}
const mapLenSlot = (k: bigint, base: bigint) => kec(pad32(k) + pad32(base));
const dataSlot = (lenSlot: bigint) => kec(pad32(lenSlot));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MapArray {
  struct Rec { uint64 id; uint128 amt; }
  mapping(address => uint256[]) nums;
  mapping(address => Rec[]) recs;
  uint256 sentinel;
  function pushNum(address k, uint256 v) external { nums[k].push(v); }
  function popNum(address k) external { nums[k].pop(); }
  function setNum(address k, uint256 i, uint256 v) external { nums[k][i] = v; }
  function numLen(address k) external view returns (uint256){ return nums[k].length; }
  function numAt(address k, uint256 i) external view returns (uint256){ return nums[k][i]; }
  function addRec(address k, uint64 id, uint128 amt) external { recs[k].push(Rec(id, amt)); }
  function popRec(address k) external { recs[k].pop(); }
  function setRecAmt(address k, uint256 i, uint128 v) external { recs[k][i].amt = v; }
  function recLen(address k) external view returns (uint256){ return recs[k].length; }
  function recId(address k, uint256 i) external view returns (uint64){ return recs[k][i].id; }
  function recAmt(address k, uint256 i) external view returns (uint128){ return recs[k][i].amt; }
}`;

describe('mapping<K, T[]> (value + struct element) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eqCall(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'MapArray.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'MapArray.jeth' });
    const sb = compileSolidity(SOL, 'MapArray');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('value mapped array: push/length/index/set + raw slots, per-key isolation', async () => {
    await eqCall('pushNum K1 #0', encodeCall(sel('pushNum(address,uint256)'), [K1, 111n]));
    await eqCall('pushNum K1 #1', encodeCall(sel('pushNum(address,uint256)'), [K1, 222n]));
    await eqCall('pushNum K2 #0', encodeCall(sel('pushNum(address,uint256)'), [K2, 999n]));
    let r = await eqCall('numLen K1', encodeCall(sel('numLen(address)'), [K1]));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    r = await eqCall('numLen K2', encodeCall(sel('numLen(address)'), [K2]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    // raw length slot + element slots for K1
    const lenK1 = mapLenSlot(K1, 0n);
    await eqSlot(lenK1, 'nums[K1].length slot');
    const d1 = dataSlot(lenK1);
    await eqSlot(d1, 'nums[K1][0]');
    await eqSlot(d1 + 1n, 'nums[K1][1]');
    r = await eqCall('numAt K1 1', encodeCall(sel('numAt(address,uint256)'), [K1, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(222n);
    // write element
    await eqCall('setNum K1 0', encodeCall(sel('setNum(address,uint256,uint256)'), [K1, 0n, 12345n]));
    await eqSlot(d1, 'nums[K1][0] after set');
    // OOB
    r = await eqCall('numAt K1 OOB', encodeCall(sel('numAt(address,uint256)'), [K1, 2n]));
    expect(r.j.success).toBe(false);
  });

  it('struct mapped array: push(Rec)/field RMW + raw slots, pop', async () => {
    await eqCall('addRec K1 #0', encodeCall(sel('addRec(address,uint64,uint128)'), [K1, 7n, 1000n]));
    await eqCall('addRec K1 #1', encodeCall(sel('addRec(address,uint64,uint128)'), [K1, 8n, 2000n]));
    let r = await eqCall('recLen K1', encodeCall(sel('recLen(address)'), [K1]));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    const lenK1 = mapLenSlot(K1, 1n);
    const d = dataSlot(lenK1); // Rec is 1 slot (id|amt packed)
    await eqSlot(d, 'recs[K1][0] (id|amt)');
    await eqSlot(d + 1n, 'recs[K1][1]');
    r = await eqCall('recId K1 1', encodeCall(sel('recId(address,uint256)'), [K1, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(8n);
    r = await eqCall('recAmt K1 0', encodeCall(sel('recAmt(address,uint256)'), [K1, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(1000n);
    // field RMW preserves sibling id
    await eqCall('setRecAmt K1 0', encodeCall(sel('setRecAmt(address,uint256,uint128)'), [K1, 0n, 5555n]));
    await eqSlot(d, 'recs[K1][0] after setRecAmt');
    r = await eqCall('recId K1 0 (preserved)', encodeCall(sel('recId(address,uint256)'), [K1, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(7n);
    // pop, length shrinks, slot zeroed
    await eqCall('popRec K1', encodeCall(sel('popRec(address)'), [K1]));
    r = await eqCall('recLen K1 after pop', encodeCall(sel('recLen(address)'), [K1]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    await eqSlot(d + 1n, 'recs[K1][1] zeroed after pop');
    // pop the last, then pop empty -> Panic(0x31)
    await eqCall('popRec K1 #2', encodeCall(sel('popRec(address)'), [K1]));
    const re = await eqCall('popRec K1 empty', encodeCall(sel('popRec(address)'), [K1]));
    expect(re.j.success).toBe(false);
  });

  it('sentinel slot 2 untouched', async () => {
    expect(decodeUint(await readSlot(jeth, aj, 2n))).toBe(0n);
  });
});
