// Phase 4e-2b scenario "struct-with-fixed-array-field":
// mapping<uint256, Rec[]> where Rec{ uint64 id; uint256[2] data }.
// Exercises push(Rec(id, [..])), read+write this.m[k][i].id and this.m[k][i].data[j]
// (mapKey + dynIndex + field + index), OOB on dynamic index i and on fixed index j
// -> Panic(0x32). storageSlotCount(Rec)=3, element i at dataStart + i*3,
// data[j] at element + 1 + j. Byte-identical to solc: returndata, success, raw
// storage slots (readSlot), and revert/panic form.
import { describe, it, expect, beforeAll } from 'vitest';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const K1 = 0x1111n;
const K2 = 0x2222n;
const MAP_BASE = 0n; // recs mapping is the first @state -> slot 0

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
function kec(hex: string): bigint {
  return BigInt('0x' + toHex(keccak(hexToBytes(('0x' + hex) as `0x${string}`))));
}
// per-key array length slot = keccak256(pad32(key) . pad32(mapBaseSlot))
const mapLenSlot = (k: bigint, base: bigint) => kec(pad32(k) + pad32(base));
// data start = keccak256(pad32(lenSlot))
const dataSlot = (lenSlot: bigint) => kec(pad32(lenSlot));
const SLOTS_PER_REC = 3n;

// JETH source: Rec{ id:u64; data: Arr<u256,2> }; storageSlotCount(Rec)=3
// (slot 0: id packed alone; slot 1: data[0]; slot 2: data[1]).
// NOTE: the positional constructor Rec(id, [d0,d1]) with a fixed-array field is
// not implemented yet (compiler emits JETH226 "struct field of a non-value type
// is not constructible yet"). So records are grown via push() (a zero Rec) and
// then populated through the field/index write paths this.m[k][i].id and
// this.m[k][i].data[j] -- which is exactly the surface this scenario targets.
const JETH = `// scenario struct-with-fixed-array-field
@struct class Rec { id: u64; data: Arr<u256, 2>; }

@contract
class StructFixedArrField {
  @state recs: mapping<u256, Rec[]>;   // slot 0
  @state sentinel: u256;               // slot 1

  // grow + populate: push a zero Rec, then write its fields (covers push + RMW)
  @external addRec(k: u256, id: u64, d0: u256, d1: u256): void {
    this.recs[k].push();
    let i: u256 = this.recs[k].length - 1n;
    this.recs[k][i].id = id;
    this.recs[k][i].data[0n] = d0;
    this.recs[k][i].data[1n] = d1;
  }
  @external pushEmpty(k: u256): void { this.recs[k].push(); }
  @external popRec(k: u256): void { this.recs[k].pop(); }

  @external setId(k: u256, i: u256, v: u64): void { this.recs[k][i].id = v; }
  @external setData(k: u256, i: u256, j: u256, v: u256): void { this.recs[k][i].data[j] = v; }

  @external @view recLen(k: u256): u256 { return this.recs[k].length; }
  @external @view getId(k: u256, i: u256): u64 { return this.recs[k][i].id; }
  @external @view getData(k: u256, i: u256, j: u256): u256 { return this.recs[k][i].data[j]; }
}
`;

// Faithful Solidity mirror: same layout (mapping at slot 0, sentinel at slot 1),
// Rec packs id alone (uint64) then uint256[2] -> 3 slots. addRec mirrors the JETH
// grow-then-populate sequence exactly so storage is byte-identical.
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract StructFixedArrField {
  struct Rec { uint64 id; uint256[2] data; }
  mapping(uint256 => Rec[]) recs;   // slot 0
  uint256 sentinel;                  // slot 1

  function addRec(uint256 k, uint64 id, uint256 d0, uint256 d1) external {
    recs[k].push();
    uint256 i = recs[k].length - 1;
    recs[k][i].id = id;
    recs[k][i].data[0] = d0;
    recs[k][i].data[1] = d1;
  }
  function pushEmpty(uint256 k) external { recs[k].push(); }
  function popRec(uint256 k) external { recs[k].pop(); }

  function setId(uint256 k, uint256 i, uint64 v) external { recs[k][i].id = v; }
  function setData(uint256 k, uint256 i, uint256 j, uint256 v) external { recs[k][i].data[j] = v; }

  function recLen(uint256 k) external view returns (uint256){ return recs[k].length; }
  function getId(uint256 k, uint256 i) external view returns (uint64){ return recs[k][i].id; }
  function getData(uint256 k, uint256 i, uint256 j) external view returns (uint256){ return recs[k][i].data[j]; }
}`;

describe('mapping<uint256, Rec[]> with fixed-array struct field vs Solidity', () => {
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
    const j = await readSlot(jeth, aj, slot);
    const s = await readSlot(sol, as, slot);
    expect(j, `${label} (slot ${slot.toString(16)})`).toBe(s);
    return j;
  }

  beforeAll(async () => {
    // self-contained: write the JETH source next to the test, then compile it.
    const srcPath = join(here, '_gen4e2b_struct-with-fixed-array-field.jeth');
    writeFileSync(srcPath, JETH);
    const jb = compile(JETH, { fileName: '_gen4e2b_struct-with-fixed-array-field.jeth' });
    const sb = compileSolidity(SOL, 'StructFixedArrField');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('push(Rec(id,[d0,d1])) packs id and data[] identically (raw slots), per-key', async () => {
    // K1: two records
    await eqCall('addRec K1 #0', encodeCall(sel('addRec(uint256,uint64,uint256,uint256)'), [K1, 7n, 0xAAn, 0xBBn]));
    await eqCall('addRec K1 #1', encodeCall(sel('addRec(uint256,uint64,uint256,uint256)'), [K1, 8n, 0xCCn, 0xDDn]));
    // K2: one record (isolation)
    await eqCall('addRec K2 #0', encodeCall(sel('addRec(uint256,uint64,uint256,uint256)'), [K2, 99n, 0x1234n, 0x5678n]));

    let r = await eqCall('recLen K1', encodeCall(sel('recLen(uint256)'), [K1]));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    r = await eqCall('recLen K2', encodeCall(sel('recLen(uint256)'), [K2]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);

    // raw slots for K1: length slot + data start + each Rec's 3 slots
    const lenK1 = mapLenSlot(K1, MAP_BASE);
    await eqSlot(lenK1, 'recs[K1].length');
    const d = dataSlot(lenK1);
    for (let i = 0n; i < 2n; i++) {
      const base = d + i * SLOTS_PER_REC;
      await eqSlot(base, `recs[K1][${i}].id (slot+0)`);
      await eqSlot(base + 1n, `recs[K1][${i}].data[0] (slot+1)`);
      await eqSlot(base + 2n, `recs[K1][${i}].data[1] (slot+2)`);
    }
    // K2 isolated slots
    const lenK2 = mapLenSlot(K2, MAP_BASE);
    await eqSlot(lenK2, 'recs[K2].length');
    const d2 = dataSlot(lenK2);
    await eqSlot(d2, 'recs[K2][0].id');
    await eqSlot(d2 + 1n, 'recs[K2][0].data[0]');
    await eqSlot(d2 + 2n, 'recs[K2][0].data[1]');

    // getters byte-identical
    r = await eqCall('getId K1 1', encodeCall(sel('getId(uint256,uint256)'), [K1, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(8n);
    r = await eqCall('getData K1 0 0', encodeCall(sel('getData(uint256,uint256,uint256)'), [K1, 0n, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xAAn);
    r = await eqCall('getData K1 0 1', encodeCall(sel('getData(uint256,uint256,uint256)'), [K1, 0n, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xBBn);
    r = await eqCall('getData K1 1 1', encodeCall(sel('getData(uint256,uint256,uint256)'), [K1, 1n, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xDDn);
  });

  it('write this.m[k][i].id and this.m[k][i].data[j] (RMW) byte-identical', async () => {
    const lenK1 = mapLenSlot(K1, MAP_BASE);
    const d = dataSlot(lenK1);

    // setId on record 0: must not clobber data[0]/data[1] (id is packed alone in slot+0)
    await eqCall('setId K1 0', encodeCall(sel('setId(uint256,uint256,uint64)'), [K1, 0n, 0x4242n]));
    await eqSlot(d, 'recs[K1][0].id after setId');
    await eqSlot(d + 1n, 'recs[K1][0].data[0] preserved');
    await eqSlot(d + 2n, 'recs[K1][0].data[1] preserved');

    // setData data[0] and data[1] on record 1
    await eqCall('setData K1 1 0', encodeCall(sel('setData(uint256,uint256,uint256,uint256)'), [K1, 1n, 0n, 0xFEEDn]));
    await eqCall('setData K1 1 1', encodeCall(sel('setData(uint256,uint256,uint256,uint256)'), [K1, 1n, 1n, 0xCAFEn]));
    const base1 = d + 1n * SLOTS_PER_REC;
    await eqSlot(base1, 'recs[K1][1].id preserved after setData');
    await eqSlot(base1 + 1n, 'recs[K1][1].data[0] after setData');
    await eqSlot(base1 + 2n, 'recs[K1][1].data[1] after setData');

    // verify via getters
    let r = await eqCall('getId K1 0', encodeCall(sel('getId(uint256,uint256)'), [K1, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(0x4242n);
    r = await eqCall('getData K1 1 0', encodeCall(sel('getData(uint256,uint256,uint256)'), [K1, 1n, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xFEEDn);
    r = await eqCall('getData K1 1 1', encodeCall(sel('getData(uint256,uint256,uint256)'), [K1, 1n, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xCAFEn);
    // record 1 id preserved
    r = await eqCall('getId K1 1 preserved', encodeCall(sel('getId(uint256,uint256)'), [K1, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(8n);
  });

  it('OOB on dynamic index i -> Panic(0x32) byte-identical', async () => {
    // K1 length is 2; index 2 is OOB on read and on write paths
    const r = await eqCall('getId K1 OOB i=2', encodeCall(sel('getId(uint256,uint256)'), [K1, 2n]));
    expect(r.j.success).toBe(false);
    const r2 = await eqCall('getData K1 OOB i=2', encodeCall(sel('getData(uint256,uint256,uint256)'), [K1, 2n, 0n]));
    expect(r2.j.success).toBe(false);
    const r3 = await eqCall('setId K1 OOB i=5', encodeCall(sel('setId(uint256,uint256,uint64)'), [K1, 5n, 1n]));
    expect(r3.j.success).toBe(false);
    const r4 = await eqCall('setData K1 OOB i=5', encodeCall(sel('setData(uint256,uint256,uint256,uint256)'), [K1, 5n, 0n, 1n]));
    expect(r4.j.success).toBe(false);
    // empty key: any index OOB
    const r5 = await eqCall('getId emptyKey OOB', encodeCall(sel('getId(uint256,uint256)'), [0xDEADn, 0n]));
    expect(r5.j.success).toBe(false);
    // both should carry Panic(0x32): selector 0x4e487b71 + word 0x32
    const PANIC32 = '0x4e487b71' + pad32(0x32n);
    expect(r.j.returnHex, 'jeth OOB i returndata is Panic(0x32)').toBe(PANIC32);
    expect(r.s.returnHex, 'sol  OOB i returndata is Panic(0x32)').toBe(PANIC32);
  });

  it('OOB on fixed index j -> Panic(0x32) byte-identical', async () => {
    // data is uint256[2]; j=2 is OOB on the fixed-array field
    const r = await eqCall('getData K1 0 OOB j=2', encodeCall(sel('getData(uint256,uint256,uint256)'), [K1, 0n, 2n]));
    expect(r.j.success).toBe(false);
    const r2 = await eqCall('setData K1 0 OOB j=7', encodeCall(sel('setData(uint256,uint256,uint256,uint256)'), [K1, 0n, 7n, 1n]));
    expect(r2.j.success).toBe(false);
    const PANIC32 = '0x4e487b71' + pad32(0x32n);
    expect(r.j.returnHex, 'jeth OOB j returndata is Panic(0x32)').toBe(PANIC32);
    expect(r.s.returnHex, 'sol  OOB j returndata is Panic(0x32)').toBe(PANIC32);
  });

  it('pushEmpty + pop preserve byte-identical slots and panic on pop-empty', async () => {
    // K2 has 1 element. push empty -> zero record, length 2.
    await eqCall('pushEmpty K2', encodeCall(sel('pushEmpty(uint256)'), [K2]));
    let r = await eqCall('recLen K2 = 2', encodeCall(sel('recLen(uint256)'), [K2]));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    const lenK2 = mapLenSlot(K2, MAP_BASE);
    const d2 = dataSlot(lenK2);
    const eBase = d2 + 1n * SLOTS_PER_REC;
    await eqSlot(eBase, 'recs[K2][1].id (zero record)');
    await eqSlot(eBase + 1n, 'recs[K2][1].data[0] (zero)');
    await eqSlot(eBase + 2n, 'recs[K2][1].data[1] (zero)');

    // pop both; popped slots zeroed identically
    await eqCall('popRec K2 #1', encodeCall(sel('popRec(uint256)'), [K2]));
    await eqCall('popRec K2 #2', encodeCall(sel('popRec(uint256)'), [K2]));
    r = await eqCall('recLen K2 = 0', encodeCall(sel('recLen(uint256)'), [K2]));
    expect(decodeUint(r.j.returnHex)).toBe(0n);
    await eqSlot(d2, 'recs[K2][0].id zeroed after pop');
    await eqSlot(d2 + 1n, 'recs[K2][0].data[0] zeroed after pop');
    await eqSlot(d2 + 2n, 'recs[K2][0].data[1] zeroed after pop');
    await eqSlot(eBase, 'recs[K2][1].id zeroed after pop');
    await eqSlot(lenK2, 'recs[K2].length = 0');

    // pop empty -> Panic(0x31)
    const re = await eqCall('popRec K2 empty', encodeCall(sel('popRec(uint256)'), [K2]));
    expect(re.j.success).toBe(false);
    const PANIC31 = '0x4e487b71' + pad32(0x31n);
    expect(re.j.returnHex, 'jeth pop-empty returndata is Panic(0x31)').toBe(PANIC31);
    expect(re.s.returnHex, 'sol  pop-empty returndata is Panic(0x31)').toBe(PANIC31);
  });

  it('sentinel slot 1 untouched', async () => {
    expect(decodeUint(await readSlot(jeth, aj, 1n))).toBe(0n);
    await eqSlot(1n, 'sentinel');
  });
});
