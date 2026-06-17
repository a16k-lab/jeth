// Phase 4e-2 differential scenario "push-pop-slot-reuse":
// push/pop lifecycle correctness with slot reuse. Push 5 records w/ distinct
// values; pop 3; push 2 NEW records (reusing the popped+zeroed slots). Verify
// reused elements read back the NEW values (not stale), and raw slots are
// byte-identical to solc throughout. Then pop all + pop once more -> Panic(0x31).
// Also push() empty after non-empty pushes -> element reads zero, raw slots zero.
// Interleave length() checks. Solidity is the oracle: EVERY probe (returndata,
// success, raw slot via readSlot, panic bytes) must be byte-identical.
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
const A3 = BigInt('0x' + '33'.repeat(20));
const A4 = BigInt('0x' + '44'.repeat(20));
const A5 = BigInt('0x' + '55'.repeat(20));
const A6 = BigInt('0x' + '66'.repeat(20));
const A7 = BigInt('0x' + '77'.repeat(20));

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
// data slot of a dynamic array whose length lives at slot p = keccak256(pad32(p)).
const DATA0 = BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad32(0n)) as `0x${string}`))));
// Rec = { uint64 id; address owner; uint128 amount; bool active; } => 2 slots/elem.
// slot0 = id|owner (8+20=28 bytes), slot1 = amount|active (16+1 bytes).
const SLOTS_PER = 2n;
const elemSlot0 = (i: bigint) => DATA0 + i * SLOTS_PER;
const elemSlot1 = (i: bigint) => DATA0 + i * SLOTS_PER + 1n;

// Faithful Solidity mirror of examples/StorageStructArray.jeth (identical layout).
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

describe('push-pop-slot-reuse vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);

  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  // byte-identical: success + returndata.
  async function eqCall(label: string, data: string) {
    const { j, s } = await both(data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError}) j=${j.returnHex} s=${s.returnHex}`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }
  // byte-identical raw storage slot.
  async function eqSlot(slot: bigint, label: string) {
    const j = await readSlot(jeth, aj, slot);
    const s = await readSlot(sol, as, slot);
    expect(j, `${label} jeth=${j} sol=${s}`).toBe(s);
  }
  async function expectLen(label: string, n: bigint) {
    const r = await eqCall(label, encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex), `${label} len value`).toBe(n);
  }
  // assert a whole element (both raw slots) byte-identical, plus per-field getters.
  async function eqElem(i: bigint, label: string) {
    await eqSlot(elemSlot0(i), `${label} recs[${i}].slot0 (id|owner)`);
    await eqSlot(elemSlot1(i), `${label} recs[${i}].slot1 (amount|active)`);
    for (const g of ['getId(uint256)', 'getOwner(uint256)', 'getAmount(uint256)', 'getActive(uint256)']) {
      await eqCall(`${label} ${g}@${i}`, encodeCall(sel(g), [i]));
    }
  }
  const add = (id: bigint, owner: bigint, amt: bigint, active: bigint) =>
    encodeCall(sel('add(uint64,address,uint128,bool)'), [id, owner, amt, active]);

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'StorageStructArray.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'StorageStructArray.jeth' });
    const sb = compileSolidity(SOL, 'StorageStructArray');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('push 5 distinct records; raw slots + getters byte-identical; len checks', async () => {
    await expectLen('len=0 (initial)', 0n);
    await eqCall('add#0', add(10n, A1, 1000n, 1n));
    await eqCall('add#1', add(20n, A2, 2000n, 0n));
    await expectLen('len=2', 2n);
    await eqCall('add#2', add(30n, A3, 3000n, 1n));
    await eqCall('add#3', add(40n, A4, 4000n, 0n));
    await eqCall('add#4', add(50n, A5, 5000n, 1n));
    await expectLen('len=5', 5n);
    // length slot (slot 0) holds raw length, must match solc.
    await eqSlot(0n, 'array length slot after 5 pushes');
    for (let i = 0n; i < 5n; i++) await eqElem(i, `after 5 pushes`);
  });

  it('pop 3 -> len 2, popped+zeroed slots byte-identical', async () => {
    await eqCall('pop#0', encodeCall(sel('popRec()'), []));
    await expectLen('len=4 after pop#0', 4n);
    await eqCall('pop#1', encodeCall(sel('popRec()'), []));
    await eqCall('pop#2', encodeCall(sel('popRec()'), []));
    await expectLen('len=2 after 3 pops', 2n);
    await eqSlot(0n, 'length slot after 3 pops');
    // popped indices 2,3,4 must be fully zeroed (solc zeroes on pop). Compare raw.
    for (const i of [2n, 3n, 4n]) {
      await eqSlot(elemSlot0(i), `popped recs[${i}].slot0 zeroed`);
      await eqSlot(elemSlot1(i), `popped recs[${i}].slot1 zeroed`);
    }
    // survivors 0,1 untouched
    await eqElem(0n, 'survivor');
    await eqElem(1n, 'survivor');
    // reading popped index OOB -> Panic(0x32), identical bytes
    const r = await eqCall('getId@2 OOB after pop', encodeCall(sel('getId(uint256)'), [2n]));
    expect(r.j.success).toBe(false);
  });

  it('push 2 NEW records into reused slots; read NEW values (no stale), raw identical', async () => {
    // these land at indices 2,3 -> the very slots just popped+zeroed.
    await eqCall('add#5 (reuse idx2)', add(60n, A6, 6000n, 0n));
    await eqCall('add#6 (reuse idx3)', add(70n, A7, 7000n, 1n));
    await expectLen('len=4 after reuse pushes', 4n);
    await eqSlot(0n, 'length slot after reuse pushes');
    // reused elements must read back the NEW values, not stale (50/A5/5000 etc).
    await eqElem(2n, 'reused');
    await eqElem(3n, 'reused');
    // explicit value assertions to catch a "stale read" that happened to also be
    // wrong-but-equal across both impls (defensive; solc is still oracle above).
    let r = await eqCall('getId@2 new', encodeCall(sel('getId(uint256)'), [2n]));
    expect(decodeUint(r.j.returnHex), 'reused idx2 id is NEW 60').toBe(60n);
    r = await eqCall('getAmount@2 new', encodeCall(sel('getAmount(uint256)'), [2n]));
    expect(decodeUint(r.j.returnHex), 'reused idx2 amount NEW 6000').toBe(6000n);
    r = await eqCall('getOwner@3 new', encodeCall(sel('getOwner(uint256)'), [3n]));
    expect(decodeUint(r.j.returnHex), 'reused idx3 owner NEW A7').toBe(A7);
    r = await eqCall('getActive@3 new', encodeCall(sel('getActive(uint256)'), [3n]));
    expect(decodeUint(r.j.returnHex), 'reused idx3 active NEW 1').toBe(1n);
    // survivors still intact
    await eqElem(0n, 'survivor post-reuse');
    await eqElem(1n, 'survivor post-reuse');
  });

  it('RMW on reused element then re-read; byte-identical raw slots', async () => {
    await eqCall('setAmount@2', encodeCall(sel('setAmount(uint256,uint128)'), [2n, 12345n]));
    await eqCall('setActive@2', encodeCall(sel('setActive(uint256,bool)'), [2n, 1n]));
    await eqSlot(elemSlot1(2n), 'recs[2].slot1 after RMW');
    await eqSlot(elemSlot0(2n), 'recs[2].slot0 unchanged after RMW');
    const r = await eqCall('getAmount@2 RMW', encodeCall(sel('getAmount(uint256)'), [2n]));
    expect(decodeUint(r.j.returnHex)).toBe(12345n);
    // siblings preserved (id/owner still NEW 60/A6)
    const r2 = await eqCall('getId@2 post-RMW', encodeCall(sel('getId(uint256)'), [2n]));
    expect(decodeUint(r2.j.returnHex)).toBe(60n);
    await eqElem(2n, 'post-RMW');
  });

  it('push() empty after non-empty pushes -> element reads zero, raw slots zero', async () => {
    // len currently 4 -> push() empty lands at index 4 (a slot region never
    // written since deploy in this run, but pop earlier touched 4; solc semantics:
    // element is zero either way). Compare raw + getters.
    await eqCall('pushEmpty', encodeCall(sel('pushEmpty()'), []));
    await expectLen('len=5 after pushEmpty', 5n);
    await eqSlot(elemSlot0(4n), 'pushEmpty recs[4].slot0 zero');
    await eqSlot(elemSlot1(4n), 'pushEmpty recs[4].slot1 zero');
    const r0 = await eqCall('getAmount@4 zero', encodeCall(sel('getAmount(uint256)'), [4n]));
    expect(decodeUint(r0.j.returnHex)).toBe(0n);
    const r1 = await eqCall('getId@4 zero', encodeCall(sel('getId(uint256)'), [4n]));
    expect(decodeUint(r1.j.returnHex)).toBe(0n);
    const r2 = await eqCall('getOwner@4 zero', encodeCall(sel('getOwner(uint256)'), [4n]));
    expect(decodeUint(r2.j.returnHex)).toBe(0n);
    const r3 = await eqCall('getActive@4 zero', encodeCall(sel('getActive(uint256)'), [4n]));
    expect(decodeUint(r3.j.returnHex)).toBe(0n);
    await eqElem(4n, 'pushEmpty');
  });

  it('pop all + pop once more -> Panic(0x31); raw length + slots identical throughout', async () => {
    // current len = 5 (indices 0..4). Pop them one at a time, checking len + slots.
    for (let remaining = 5n; remaining > 0n; remaining--) {
      const idx = remaining - 1n; // index being popped
      await eqCall(`pop down (len ${remaining}->${remaining - 1n})`, encodeCall(sel('popRec()'), []));
      await expectLen(`len=${remaining - 1n} during drain`, remaining - 1n);
      await eqSlot(0n, `length slot during drain (len ${remaining - 1n})`);
      // just-popped slots zeroed, byte-identical
      await eqSlot(elemSlot0(idx), `drained recs[${idx}].slot0 zeroed`);
      await eqSlot(elemSlot1(idx), `drained recs[${idx}].slot1 zeroed`);
    }
    await expectLen('len=0 after draining all', 0n);
    // pop on empty -> Panic(0x31). encode the expected panic bytes and assert
    // both the JETH and solc returndata equal it exactly.
    const PANIC31 = '0x4e487b71' + pad32(0x31n);
    const re = await eqCall('pop empty -> Panic(0x31)', encodeCall(sel('popRec()'), []));
    expect(re.j.success, 'pop empty reverts in jeth').toBe(false);
    expect(re.s.success, 'pop empty reverts in solc').toBe(false);
    expect(re.j.returnHex.toLowerCase(), 'jeth panic bytes = Panic(0x31)').toBe(PANIC31);
    expect(re.s.returnHex.toLowerCase(), 'solc panic bytes = Panic(0x31)').toBe(PANIC31);
    // all element slots remain zero
    for (let i = 0n; i < 5n; i++) {
      await eqSlot(elemSlot0(i), `final zero recs[${i}].slot0`);
      await eqSlot(elemSlot1(i), `final zero recs[${i}].slot1`);
    }
  });

  it('sentinel slot 1 untouched throughout', async () => {
    expect(decodeUint(await readSlot(jeth, aj, 1n)), 'jeth sentinel zero').toBe(0n);
    await eqSlot(1n, 'sentinel');
  });
});
