// Phase 4e-2: storage dynamic array of struct, byte-identical to Solidity incl.
// raw packed slots: push(Rec(...)) / push() / pop, this.recs[i].field read+write,
// .length, OOB Panic(0x32), sentinel isolation.
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
const A1 = BigInt('0x' + '11'.repeat(20));
const A2 = BigInt('0x' + '22'.repeat(20));

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
// data slot of a dynamic array whose length is at slot p = keccak256(pad32(p)).
const DATA0 = BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad32(0n)) as `0x${string}`))));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract StorageStructArray {
  struct Rec { uint64 id; address owner; uint128 amount; bool active; }
  Rec[] recs;
  uint256 sentinel;
  function add(uint64 id, address owner, uint128 amount, bool active) external { recs.push(Rec(id, owner, amount, active)); }
  function pushEmpty() external { recs.push(); }
  function popRec() external { recs.pop(); }
  function setAmount(uint256 i, uint128 v) external { recs[i].amount = v; }
  function setActive(uint256 i, bool v) external { recs[i].active = v; }
  function len() external view returns (uint256){ return recs.length; }
  function getId(uint256 i) external view returns (uint64){ return recs[i].id; }
  function getOwner(uint256 i) external view returns (address){ return recs[i].owner; }
  function getAmount(uint256 i) external view returns (uint128){ return recs[i].amount; }
  function getActive(uint256 i) external view returns (bool){ return recs[i].active; }
}`;

describe('storage dynamic array of struct vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqCall(label: string, data: string) {
    const { j, s } = await both(data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'StorageStructArray.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'StorageStructArray.jeth' });
    const sb = compileSolidity(SOL, 'StorageStructArray');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('push(Rec(...)) grows length and packs fields identically (raw slots)', async () => {
    await eqCall('add#0', encodeCall(sel('add(uint64,address,uint128,bool)'), [10n, A1, 1000n, 1n]));
    await eqCall('add#1', encodeCall(sel('add(uint64,address,uint128,bool)'), [20n, A2, 2000n, 0n]));
    const r = await eqCall('len=2', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    // raw slots: element i at DATA0 + i*2 (slot0 id|owner, slot1 amount|active)
    for (let i = 0; i < 2; i++) {
      await eqSlot(DATA0 + BigInt(i) * 2n, `recs[${i}].slot0 (id|owner)`);
      await eqSlot(DATA0 + BigInt(i) * 2n + 1n, `recs[${i}].slot1 (amount|active)`);
    }
    // per-field getters byte-identical
    for (const i of [0n, 1n]) {
      for (const g of ['getId(uint256)', 'getOwner(uint256)', 'getAmount(uint256)', 'getActive(uint256)']) {
        await eqCall(`${g}@${i}`, encodeCall(sel(g), [i]));
      }
    }
  });

  it('this.recs[i].field write (RMW) preserves siblings, byte-identical', async () => {
    await eqCall('setAmount#1', encodeCall(sel('setAmount(uint256,uint128)'), [1n, 9999n]));
    await eqCall('setActive#0', encodeCall(sel('setActive(uint256,bool)'), [0n, 1n]));
    await eqSlot(DATA0 + 2n + 1n, 'recs[1].slot1 after setAmount');
    await eqSlot(DATA0 + 1n, 'recs[0].slot1 after setActive');
    // siblings preserved (id/owner unchanged)
    let r = await eqCall('getAmount@1', encodeCall(sel('getAmount(uint256)'), [1n]));
    expect(decodeUint(r.j.returnHex)).toBe(9999n);
    r = await eqCall('getId@1', encodeCall(sel('getId(uint256)'), [1n]));
    expect(decodeUint(r.j.returnHex)).toBe(20n);
    r = await eqCall('getActive@0', encodeCall(sel('getActive(uint256)'), [0n]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
  });

  it('OOB index Panics(0x32) identically', async () => {
    const r = await eqCall('getId OOB', encodeCall(sel('getId(uint256)'), [2n]));
    expect(r.j.success).toBe(false);
    const r2 = await eqCall('setAmount OOB', encodeCall(sel('setAmount(uint256,uint128)'), [5n, 1n]));
    expect(r2.j.success).toBe(false);
  });

  it('push() empty appends a zero record; pop() shrinks and zeroes', async () => {
    await eqCall('pushEmpty', encodeCall(sel('pushEmpty()'), []));
    let r = await eqCall('len=3', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    await eqSlot(DATA0 + 4n, 'recs[2].slot0 (zero record)');
    await eqSlot(DATA0 + 5n, 'recs[2].slot1 (zero record)');
    r = await eqCall('getAmount@2', encodeCall(sel('getAmount(uint256)'), [2n]));
    expect(decodeUint(r.j.returnHex)).toBe(0n);
    // pop twice
    await eqCall('pop#1', encodeCall(sel('popRec()'), []));
    await eqCall('pop#2', encodeCall(sel('popRec()'), []));
    r = await eqCall('len=1', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    // popped slots zeroed byte-identically
    await eqSlot(DATA0 + 2n, 'recs[1].slot0 after pop');
    await eqSlot(DATA0 + 2n + 1n, 'recs[1].slot1 after pop');
    await eqSlot(DATA0 + 4n, 'recs[2].slot0 after pop');
    // pop empty eventually -> Panic(0x31)
    await eqCall('pop#3', encodeCall(sel('popRec()'), []));
    const re = await eqCall('pop empty', encodeCall(sel('popRec()'), []));
    expect(re.j.success).toBe(false);
  });

  it('sentinel slot 1 stays untouched', async () => {
    expect(decodeUint(await readSlot(jeth, aj, 1n))).toBe(0n);
    await eqSlot(1n, 'sentinel');
  });
});
