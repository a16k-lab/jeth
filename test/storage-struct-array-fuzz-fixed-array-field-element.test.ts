// Phase 4e-2 scenario "fixed-array-field-element": STORAGE dynamic array of struct
// whose element contains a FIXED ARRAY field. Rec{ uint64 id; uint256[3] data }.
// Probes this.recs[i].id and this.recs[i].data[j] (dynIndex + field + index) read &
// write; OOB on i -> Panic(0x32), OOB on j -> Panic(0x32). Byte-identical to solc:
// returndata, success, raw storage slots (readSlot), and panic bytes.
//
// Storage layout to mirror: length @ slot 0, data @ keccak(pad32(0)); element i at
// dataSlot + i*4 (slot0 = id, slots1..3 = data[0..2]); data[j] at element-base+1+j.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
// data slot of a dynamic array whose length is at slot p = keccak256(pad32(p)).
const DATA0 = BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad32(0n)) as `0x${string}`))));
const STRIDE = 4n; // storageSlotCount(Rec) = 1 (id slot) + 3 (uint256[3]) = 4

// element-base of element i, then data[j] at base + 1 + j (id occupies base+0).
const elemBase = (i: bigint) => DATA0 + i * STRIDE;
const idSlot = (i: bigint) => elemBase(i);
const dataSlot = (i: bigint, j: bigint) => elemBase(i) + 1n + j;

// NOTE on element construction: JETH deliberately defers the struct CONSTRUCTOR for
// a non-value field (Rec(id,[..]) -> diagnostic JETH226 "struct field 'data' of a
// non-value type is not constructible yet"; analyzer.ts:622). That constructor path
// is orthogonal to the feature under test here, which is the storage ACCESS PATH
// this.recs[i].id / this.recs[i].data[j] (dynIndex + field + index) read & write. To
// probe the access path byte-identically without tripping the unrelated deferral, we
// create elements with push() (zero element) and populate them through the access
// path itself (setId / setData). The Solidity mirror does exactly the same.
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FixedArrayFieldElement {
  struct Rec { uint64 id; uint256[3] data; }
  Rec[] recs;
  uint256 sentinel;
  function pushEmpty() external { recs.push(); }
  function popRec() external { recs.pop(); }
  function setId(uint256 i, uint64 v) external { recs[i].id = v; }
  function setData(uint256 i, uint256 j, uint256 v) external { recs[i].data[j] = v; }
  function len() external view returns (uint256){ return recs.length; }
  function getId(uint256 i) external view returns (uint64){ return recs[i].id; }
  function getData(uint256 i, uint256 j) external view returns (uint256){ return recs[i].data[j]; }
}`;

const JETH = `// scenario: fixed-array field inside a dynamic-array struct element.
@struct class Rec { id: u64; data: Arr<u256, 3>; }

@contract
class FixedArrayFieldElement {
  @state recs: Rec[];      // length @ slot 0, data @ keccak(0); each Rec = 4 slots
  @state sentinel: u256;   // slot 1

  @external pushEmpty(): void { this.recs.push(); }
  @external popRec(): void { this.recs.pop(); }
  @external setId(i: u256, v: u64): void { this.recs[i].id = v; }
  @external setData(i: u256, j: u256, v: u256): void { this.recs[i].data[j] = v; }

  @view len(): u256 { return this.recs.length; }
  @view getId(i: u256): u64 { return this.recs[i].id; }
  @view getData(i: u256, j: u256): u256 { return this.recs[i].data[j]; }
}`;

describe('fixed-array-field-element: storage dyn-array of struct w/ fixed-array field vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  let compileDiag: string | null = null;
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
    let jb;
    try {
      jb = compile(JETH, { fileName: 'FixedArrayFieldElement.jeth' });
    } catch (e) {
      if (e instanceof CompileError) {
        compileDiag = e.diagnostics.map((d: any) => `${d.code}: ${d.message}`).join('; ');
        return;
      }
      throw e;
    }
    const sb = compileSolidity(SOL, 'FixedArrayFieldElement');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('compiles (else capture diagnostic for deferral verdict)', () => {
    expect(compileDiag, `JETH rejected: ${compileDiag}`).toBeNull();
  });

  it('push() + access-path writes lay out id + uint256[3] identically (raw slots)', async () => {
    if (compileDiag) return;
    // create two zero elements, then populate via the access path under test.
    await eqCall('push#0', encodeCall(sel('pushEmpty()'), []));
    await eqCall('push#1', encodeCall(sel('pushEmpty()'), []));
    // element 0: id=10, data=[100,101,102]; element 1: id=20, data=[200,201,202]
    await eqCall('setId#0', encodeCall(sel('setId(uint256,uint64)'), [0n, 10n]));
    await eqCall('setId#1', encodeCall(sel('setId(uint256,uint64)'), [1n, 20n]));
    for (const i of [0n, 1n]) {
      for (const j of [0n, 1n, 2n]) {
        const v = (i === 0n ? 100n : 200n) + j;
        await eqCall(`setData#${i},${j}`, encodeCall(sel('setData(uint256,uint256,uint256)'), [i, j, v]));
      }
    }
    const r = await eqCall('len=2', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    // raw slots: element i at DATA0 + i*4 (id slot, then 3 data slots)
    for (const i of [0n, 1n]) {
      await eqSlot(idSlot(i), `recs[${i}].id slot`);
      for (const j of [0n, 1n, 2n]) {
        await eqSlot(dataSlot(i, j), `recs[${i}].data[${j}] slot`);
      }
    }
    // per-field / per-element getters byte-identical
    for (const i of [0n, 1n]) {
      const gi = await eqCall(`getId@${i}`, encodeCall(sel('getId(uint256)'), [i]));
      expect(decodeUint(gi.j.returnHex)).toBe(i === 0n ? 10n : 20n);
      for (const j of [0n, 1n, 2n]) {
        const g = await eqCall(`getData@${i},${j}`, encodeCall(sel('getData(uint256,uint256)'), [i, j]));
        expect(decodeUint(g.j.returnHex)).toBe((i === 0n ? 100n : 200n) + j);
      }
    }
  });

  it('this.recs[i].id and this.recs[i].data[j] writes (RMW) preserve siblings, byte-identical', async () => {
    if (compileDiag) return;
    // write id of element 1, and data[1] of element 0
    await eqCall('setId#1', encodeCall(sel('setId(uint256,uint64)'), [1n, 0xabcdn]));
    await eqCall('setData#0,1', encodeCall(sel('setData(uint256,uint256,uint256)'), [0n, 1n, 0xdeadbeefn]));
    // raw slots after write
    await eqSlot(idSlot(1n), 'recs[1].id after setId');
    await eqSlot(dataSlot(0n, 1n), 'recs[0].data[1] after setData');
    // siblings untouched: recs[0].id, recs[0].data[0], recs[0].data[2], recs[1].data*
    await eqSlot(idSlot(0n), 'recs[0].id (sibling)');
    await eqSlot(dataSlot(0n, 0n), 'recs[0].data[0] (sibling)');
    await eqSlot(dataSlot(0n, 2n), 'recs[0].data[2] (sibling)');
    for (const j of [0n, 1n, 2n]) await eqSlot(dataSlot(1n, j), `recs[1].data[${j}] (sibling)`);
    // getters confirm
    let r = await eqCall('getId@1', encodeCall(sel('getId(uint256)'), [1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xabcdn);
    r = await eqCall('getData@0,1', encodeCall(sel('getData(uint256,uint256)'), [0n, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xdeadbeefn);
    r = await eqCall('getData@0,0', encodeCall(sel('getData(uint256,uint256)'), [0n, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(100n);
    r = await eqCall('getId@0', encodeCall(sel('getId(uint256)'), [0n]));
    expect(decodeUint(r.j.returnHex)).toBe(10n);
  });

  it('OOB on dynamic index i Panics(0x32) identically (read & write)', async () => {
    if (compileDiag) return;
    // len == 2 here; index 2 is OOB
    const r = await eqCall('getId OOB i', encodeCall(sel('getId(uint256)'), [2n]));
    expect(r.j.success).toBe(false);
    const r2 = await eqCall('getData OOB i', encodeCall(sel('getData(uint256,uint256)'), [5n, 0n]));
    expect(r2.j.success).toBe(false);
    const r3 = await eqCall('setId OOB i', encodeCall(sel('setId(uint256,uint64)'), [9n, 1n]));
    expect(r3.j.success).toBe(false);
    const r4 = await eqCall('setData OOB i', encodeCall(sel('setData(uint256,uint256,uint256)'), [7n, 0n, 1n]));
    expect(r4.j.success).toBe(false);
    // panic bytes are exactly 0x4e487b71 + 0x32
    const PANIC32 = '0x4e487b71' + pad32(0x32n);
    expect(r.j.returnHex).toBe(PANIC32);
    expect(r2.j.returnHex).toBe(PANIC32);
    expect(r3.j.returnHex).toBe(PANIC32);
    expect(r4.j.returnHex).toBe(PANIC32);
  });

  it('OOB on fixed-array index j Panics(0x32) identically (read & write)', async () => {
    if (compileDiag) return;
    // valid i (0), j == 3 is OOB for uint256[3]
    const r = await eqCall('getData OOB j', encodeCall(sel('getData(uint256,uint256)'), [0n, 3n]));
    expect(r.j.success).toBe(false);
    const r2 = await eqCall('setData OOB j', encodeCall(sel('setData(uint256,uint256,uint256)'), [1n, 4n, 1n]));
    expect(r2.j.success).toBe(false);
    const PANIC32 = '0x4e487b71' + pad32(0x32n);
    expect(r.j.returnHex).toBe(PANIC32);
    expect(r2.j.returnHex).toBe(PANIC32);
  });

  it('push() empty appends a zero record (id + all data zero); pop() shrinks & zeroes', async () => {
    if (compileDiag) return;
    await eqCall('pushEmpty', encodeCall(sel('pushEmpty()'), []));
    let r = await eqCall('len=3', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    // element 2 is all-zero across its 4 slots
    await eqSlot(idSlot(2n), 'recs[2].id (zero record)');
    for (const j of [0n, 1n, 2n]) await eqSlot(dataSlot(2n, j), `recs[2].data[${j}] (zero record)`);
    r = await eqCall('getData@2,1', encodeCall(sel('getData(uint256,uint256)'), [2n, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0n);
    // pop two elements
    await eqCall('pop#1', encodeCall(sel('popRec()'), []));
    await eqCall('pop#2', encodeCall(sel('popRec()'), []));
    r = await eqCall('len=1', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    // popped element slots zeroed byte-identically (all 4 slots of elements 1 and 2)
    for (const i of [1n, 2n]) {
      await eqSlot(idSlot(i), `recs[${i}].id after pop`);
      for (const j of [0n, 1n, 2n]) await eqSlot(dataSlot(i, j), `recs[${i}].data[${j}] after pop`);
    }
    // pop down to empty, then pop empty -> Panic(0x31)
    await eqCall('pop#3', encodeCall(sel('popRec()'), []));
    const re = await eqCall('pop empty', encodeCall(sel('popRec()'), []));
    expect(re.j.success).toBe(false);
    expect(re.j.returnHex).toBe('0x4e487b71' + pad32(0x31n));
  });

  it('sentinel slot 1 stays untouched', async () => {
    if (compileDiag) return;
    expect(decodeUint(await readSlot(jeth, aj, 1n))).toBe(0n);
    await eqSlot(1n, 'sentinel');
  });
});
