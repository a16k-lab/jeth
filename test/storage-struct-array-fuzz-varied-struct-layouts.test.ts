// Phase 4e-2 differential scenario "varied-struct-layouts": storage dynamic array
// of struct across several element layouts, each its own contract. For each layout
// we push 3 records, then assert byte-identical (returndata, success, raw element
// slots via readSlot) against a faithful Solidity mirror, verify field-write RMW
// preserves siblings (raw slot identical), and OOB index -> Panic(0x32).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const A1 = BigInt('0x' + '11'.repeat(20));
const A2 = BigInt('0x' + '22'.repeat(20));
const A3 = BigInt('0x' + '33'.repeat(20));

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
// data slot of a dynamic array whose length lives at slot p = keccak256(pad32(p)).
function dataSlot(p: bigint): bigint {
  return BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad32(p)) as `0x${string}`))));
}
const DATA0 = dataSlot(0n); // every contract declares `recs` first (slot 0)

interface Pair {
  jeth: Harness;
  sol: Harness;
  aj: Address;
  as: Address;
}

async function buildPair(jethSrc: string, solSrc: string, name: string): Promise<Pair> {
  const jb = compile(jethSrc, { fileName: name + '.jeth' });
  const sb = compileSolidity(solSrc, name);
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  return { jeth, sol, aj, as };
}

function mk(p: Pair) {
  async function both(data: string) {
    return { j: await p.jeth.call(p.aj, data), s: await p.sol.call(p.as, data) };
  }
  async function eqCall(label: string, data: string) {
    const { j, s } = await both(data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(p.jeth, p.aj, slot), label).toBe(await readSlot(p.sol, p.as, slot));
  }
  return { both, eqCall, eqSlot };
}

// ---------------------------------------------------------------------------
// (a) single-slot { uint128 a; uint128 b }  -> storageSlotCount = 1
// ---------------------------------------------------------------------------
const A_JETH = `@struct class Rec { a: u128; b: u128; }
@contract
class LayoutA {
  @state recs: Rec[];
  @state sentinel: u256;
  @external add(a: u128, b: u128): void { this.recs.push(Rec(a, b)); }
  @external setA(i: u256, v: u128): void { this.recs[i].a = v; }
  @external setB(i: u256, v: u128): void { this.recs[i].b = v; }
  @external @view len(): u256 { return this.recs.length; }
  @external @view getA(i: u256): u128 { return this.recs[i].a; }
  @external @view getB(i: u256): u128 { return this.recs[i].b; }
}`;
const A_SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract LayoutA {
  struct Rec { uint128 a; uint128 b; }
  Rec[] recs; uint256 sentinel;
  function add(uint128 a, uint128 b) external { recs.push(Rec(a, b)); }
  function setA(uint256 i, uint128 v) external { recs[i].a = v; }
  function setB(uint256 i, uint128 v) external { recs[i].b = v; }
  function len() external view returns (uint256){ return recs.length; }
  function getA(uint256 i) external view returns (uint128){ return recs[i].a; }
  function getB(uint256 i) external view returns (uint128){ return recs[i].b; }
}`;

// ---------------------------------------------------------------------------
// (b) 3-slot { uint256 a; uint256 b; uint256 c }  -> storageSlotCount = 3
// ---------------------------------------------------------------------------
const B_JETH = `@struct class Rec { a: u256; b: u256; c: u256; }
@contract
class LayoutB {
  @state recs: Rec[];
  @state sentinel: u256;
  @external add(a: u256, b: u256, c: u256): void { this.recs.push(Rec(a, b, c)); }
  @external setA(i: u256, v: u256): void { this.recs[i].a = v; }
  @external setB(i: u256, v: u256): void { this.recs[i].b = v; }
  @external setC(i: u256, v: u256): void { this.recs[i].c = v; }
  @external @view len(): u256 { return this.recs.length; }
  @external @view getA(i: u256): u256 { return this.recs[i].a; }
  @external @view getB(i: u256): u256 { return this.recs[i].b; }
  @external @view getC(i: u256): u256 { return this.recs[i].c; }
}`;
const B_SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract LayoutB {
  struct Rec { uint256 a; uint256 b; uint256 c; }
  Rec[] recs; uint256 sentinel;
  function add(uint256 a, uint256 b, uint256 c) external { recs.push(Rec(a, b, c)); }
  function setA(uint256 i, uint256 v) external { recs[i].a = v; }
  function setB(uint256 i, uint256 v) external { recs[i].b = v; }
  function setC(uint256 i, uint256 v) external { recs[i].c = v; }
  function len() external view returns (uint256){ return recs.length; }
  function getA(uint256 i) external view returns (uint256){ return recs[i].a; }
  function getB(uint256 i) external view returns (uint256){ return recs[i].b; }
  function getC(uint256 i) external view returns (uint256){ return recs[i].c; }
}`;

// ---------------------------------------------------------------------------
// (c) tight-pack straddle { uint128 a; uint128 b; uint8 c }
//     a|b fill slot0 (16+16=32), c in slot1 -> storageSlotCount = 2
// ---------------------------------------------------------------------------
const C_JETH = `@struct class Rec { a: u128; b: u128; c: u8; }
@contract
class LayoutC {
  @state recs: Rec[];
  @state sentinel: u256;
  @external add(a: u128, b: u128, c: u8): void { this.recs.push(Rec(a, b, c)); }
  @external setA(i: u256, v: u128): void { this.recs[i].a = v; }
  @external setC(i: u256, v: u8): void { this.recs[i].c = v; }
  @external @view len(): u256 { return this.recs.length; }
  @external @view getA(i: u256): u128 { return this.recs[i].a; }
  @external @view getB(i: u256): u128 { return this.recs[i].b; }
  @external @view getC(i: u256): u8 { return this.recs[i].c; }
}`;
const C_SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract LayoutC {
  struct Rec { uint128 a; uint128 b; uint8 c; }
  Rec[] recs; uint256 sentinel;
  function add(uint128 a, uint128 b, uint8 c) external { recs.push(Rec(a, b, c)); }
  function setA(uint256 i, uint128 v) external { recs[i].a = v; }
  function setC(uint256 i, uint8 v) external { recs[i].c = v; }
  function len() external view returns (uint256){ return recs.length; }
  function getA(uint256 i) external view returns (uint128){ return recs[i].a; }
  function getB(uint256 i) external view returns (uint128){ return recs[i].b; }
  function getC(uint256 i) external view returns (uint8){ return recs[i].c; }
}`;

// ---------------------------------------------------------------------------
// (d) { bool a; uint8 b; uint16 c; uint64 d; address e }
//     1+1+2+8+20 = 32 -> all pack into one slot -> storageSlotCount = 1
// ---------------------------------------------------------------------------
const D_JETH = `@struct class Rec { a: bool; b: u8; c: u16; d: u64; e: address; }
@contract
class LayoutD {
  @state recs: Rec[];
  @state sentinel: u256;
  @external add(a: bool, b: u8, c: u16, d: u64, e: address): void { this.recs.push(Rec(a, b, c, d, e)); }
  @external setB(i: u256, v: u8): void { this.recs[i].b = v; }
  @external setE(i: u256, v: address): void { this.recs[i].e = v; }
  @external @view len(): u256 { return this.recs.length; }
  @external @view getA(i: u256): bool { return this.recs[i].a; }
  @external @view getB(i: u256): u8 { return this.recs[i].b; }
  @external @view getC(i: u256): u16 { return this.recs[i].c; }
  @external @view getD(i: u256): u64 { return this.recs[i].d; }
  @external @view getE(i: u256): address { return this.recs[i].e; }
}`;
const D_SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract LayoutD {
  struct Rec { bool a; uint8 b; uint16 c; uint64 d; address e; }
  Rec[] recs; uint256 sentinel;
  function add(bool a, uint8 b, uint16 c, uint64 d, address e) external { recs.push(Rec(a, b, c, d, e)); }
  function setB(uint256 i, uint8 v) external { recs[i].b = v; }
  function setE(uint256 i, address v) external { recs[i].e = v; }
  function len() external view returns (uint256){ return recs.length; }
  function getA(uint256 i) external view returns (bool){ return recs[i].a; }
  function getB(uint256 i) external view returns (uint8){ return recs[i].b; }
  function getC(uint256 i) external view returns (uint16){ return recs[i].c; }
  function getD(uint256 i) external view returns (uint64){ return recs[i].d; }
  function getE(uint256 i) external view returns (address){ return recs[i].e; }
}`;

describe('varied-struct-layouts: storage dyn-array element layouts vs Solidity', () => {
  let A: Pair, B: Pair, C: Pair, D: Pair;

  beforeAll(async () => {
    [A, B, C, D] = await Promise.all([
      buildPair(A_JETH, A_SOL, 'LayoutA'),
      buildPair(B_JETH, B_SOL, 'LayoutB'),
      buildPair(C_JETH, C_SOL, 'LayoutC'),
      buildPair(D_JETH, D_SOL, 'LayoutD'),
    ]);
  });

  // (a) storageSlotCount = 1: { uint128 a; uint128 b } packed in one slot.
  it('(a) single-slot {u128 a; u128 b}: 3 records, getters, raw slots, RMW, OOB', async () => {
    const { eqCall, eqSlot } = mk(A);
    const sc = 1n;
    const rows: [bigint, bigint][] = [[1n, 2n], [0xaaaan, 0xbbbbn], [0xdeadn, 0xbeefn]];
    for (let i = 0; i < rows.length; i++) {
      await eqCall(`A.add#${i}`, encodeCall(sel('add(uint128,uint128)'), rows[i]));
    }
    const r = await eqCall('A.len=3', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    for (let i = 0; i < 3; i++) {
      const base = DATA0 + BigInt(i) * sc;
      await eqSlot(base, `A.recs[${i}].slot0`);
      for (const g of ['getA(uint256)', 'getB(uint256)']) {
        await eqCall(`A.${g}@${i}`, encodeCall(sel(g), [BigInt(i)]));
      }
    }
    // RMW: write a, sibling b preserved (raw slot byte-identical).
    await eqCall('A.setA#1', encodeCall(sel('setA(uint256,uint128)'), [1n, 0x7777n]));
    await eqSlot(DATA0 + 1n * sc, 'A.recs[1].slot0 after setA (b preserved)');
    await eqCall('A.setB#2', encodeCall(sel('setB(uint256,uint128)'), [2n, 0x1234n]));
    await eqSlot(DATA0 + 2n * sc, 'A.recs[2].slot0 after setB (a preserved)');
    // OOB -> Panic(0x32)
    const oob = await eqCall('A.getA OOB', encodeCall(sel('getA(uint256)'), [3n]));
    expect(oob.j.success).toBe(false);
    const oobW = await eqCall('A.setA OOB', encodeCall(sel('setA(uint256,uint128)'), [9n, 1n]));
    expect(oobW.j.success).toBe(false);
  });

  // (b) storageSlotCount = 3: each uint256 occupies its own slot.
  it('(b) 3-slot {u256 a; u256 b; u256 c}: 3 records, getters, raw slots, RMW, OOB', async () => {
    const { eqCall, eqSlot } = mk(B);
    const sc = 3n;
    const rows: [bigint, bigint, bigint][] = [
      [1n, 2n, 3n],
      [1n << 200n, (1n << 255n) + 7n, 0xffffn],
      [(1n << 256n) - 1n, 0n, 42n],
    ];
    for (let i = 0; i < rows.length; i++) {
      await eqCall(`B.add#${i}`, encodeCall(sel('add(uint256,uint256,uint256)'), rows[i]));
    }
    const r = await eqCall('B.len=3', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    for (let i = 0; i < 3; i++) {
      const base = DATA0 + BigInt(i) * sc;
      for (let s = 0n; s < sc; s++) await eqSlot(base + s, `B.recs[${i}].slot${s}`);
      for (const g of ['getA(uint256)', 'getB(uint256)', 'getC(uint256)']) {
        await eqCall(`B.${g}@${i}`, encodeCall(sel(g), [BigInt(i)]));
      }
    }
    // RMW: each field is a full slot; writing b leaves a,c slots untouched.
    await eqCall('B.setB#1', encodeCall(sel('setB(uint256,uint256)'), [1n, 0xc0ffeen]));
    const base1 = DATA0 + 1n * sc;
    await eqSlot(base1 + 0n, 'B.recs[1].slot0 (a) after setB');
    await eqSlot(base1 + 1n, 'B.recs[1].slot1 (b) after setB');
    await eqSlot(base1 + 2n, 'B.recs[1].slot2 (c) after setB');
    // OOB -> Panic(0x32)
    const oob = await eqCall('B.getC OOB', encodeCall(sel('getC(uint256)'), [3n]));
    expect(oob.j.success).toBe(false);
    const oobW = await eqCall('B.setA OOB', encodeCall(sel('setA(uint256,uint256)'), [7n, 1n]));
    expect(oobW.j.success).toBe(false);
  });

  // (c) storageSlotCount = 2: a|b fill slot0 (16+16=32), c straddles into slot1.
  it('(c) straddle {u128 a; u128 b; u8 c}: 3 records, getters, raw slots, RMW, OOB', async () => {
    const { eqCall, eqSlot } = mk(C);
    const sc = 2n;
    const rows: [bigint, bigint, bigint][] = [
      [1n, 2n, 3n],
      [0xaaaan, 0xbbbbn, 0xffn],
      [(1n << 128n) - 1n, 0x12345678n, 0x7fn],
    ];
    for (let i = 0; i < rows.length; i++) {
      await eqCall(`C.add#${i}`, encodeCall(sel('add(uint128,uint128,uint8)'), rows[i]));
    }
    const r = await eqCall('C.len=3', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    for (let i = 0; i < 3; i++) {
      const base = DATA0 + BigInt(i) * sc;
      await eqSlot(base + 0n, `C.recs[${i}].slot0 (a|b)`);
      await eqSlot(base + 1n, `C.recs[${i}].slot1 (c)`);
      for (const g of ['getA(uint256)', 'getB(uint256)', 'getC(uint256)']) {
        await eqCall(`C.${g}@${i}`, encodeCall(sel(g), [BigInt(i)]));
      }
    }
    // RMW: writing a preserves sibling b in same slot0; writing c only touches slot1.
    await eqCall('C.setA#1', encodeCall(sel('setA(uint256,uint128)'), [1n, 0x9999n]));
    await eqSlot(DATA0 + 1n * sc + 0n, 'C.recs[1].slot0 after setA (b preserved)');
    await eqSlot(DATA0 + 1n * sc + 1n, 'C.recs[1].slot1 after setA (c untouched)');
    await eqCall('C.setC#2', encodeCall(sel('setC(uint256,uint8)'), [2n, 0x5an]));
    await eqSlot(DATA0 + 2n * sc + 0n, 'C.recs[2].slot0 after setC (a|b untouched)');
    await eqSlot(DATA0 + 2n * sc + 1n, 'C.recs[2].slot1 after setC');
    // OOB -> Panic(0x32)
    const oob = await eqCall('C.getC OOB', encodeCall(sel('getC(uint256)'), [3n]));
    expect(oob.j.success).toBe(false);
    const oobW = await eqCall('C.setC OOB', encodeCall(sel('setC(uint256,uint8)'), [4n, 1n]));
    expect(oobW.j.success).toBe(false);
  });

  // (d) storageSlotCount = 1: bool+u8+u16+u64+address = 1+1+2+8+20 = 32 bytes.
  it('(d) packed {bool a; u8 b; u16 c; u64 d; address e}: 3 records, getters, raw slot, RMW, OOB', async () => {
    const { eqCall, eqSlot } = mk(D);
    const sc = 1n;
    const rows: [bigint, bigint, bigint, bigint, bigint][] = [
      [1n, 0x12n, 0x3456n, 0x1122334455667788n, A1],
      [0n, 0xffn, 0xffffn, (1n << 64n) - 1n, A2],
      [1n, 0x7fn, 0x0001n, 0n, A3],
    ];
    for (let i = 0; i < rows.length; i++) {
      await eqCall(`D.add#${i}`, encodeCall(sel('add(bool,uint8,uint16,uint64,address)'), rows[i]));
    }
    const r = await eqCall('D.len=3', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    for (let i = 0; i < 3; i++) {
      const base = DATA0 + BigInt(i) * sc;
      await eqSlot(base, `D.recs[${i}].slot0 (a|b|c|d|e packed)`);
      for (const g of ['getA(uint256)', 'getB(uint256)', 'getC(uint256)', 'getD(uint256)', 'getE(uint256)']) {
        await eqCall(`D.${g}@${i}`, encodeCall(sel(g), [BigInt(i)]));
      }
    }
    // RMW: write the middle field b, all other packed siblings preserved (raw slot identical).
    await eqCall('D.setB#1', encodeCall(sel('setB(uint256,uint8)'), [1n, 0x77n]));
    await eqSlot(DATA0 + 1n * sc, 'D.recs[1].slot0 after setB (siblings preserved)');
    // write the top field e (address), low bytes preserved.
    await eqCall('D.setE#2', encodeCall(sel('setE(uint256,address)'), [2n, A1]));
    await eqSlot(DATA0 + 2n * sc, 'D.recs[2].slot0 after setE (siblings preserved)');
    // OOB -> Panic(0x32)
    const oob = await eqCall('D.getE OOB', encodeCall(sel('getE(uint256)'), [3n]));
    expect(oob.j.success).toBe(false);
    const oobW = await eqCall('D.setB OOB', encodeCall(sel('setB(uint256,uint8)'), [10n, 1n]));
    expect(oobW.j.success).toBe(false);
  });

  it('sentinel slot 1 stays zero and identical across all layouts', async () => {
    for (const [name, p] of [['A', A], ['B', B], ['C', C], ['D', D]] as const) {
      expect(decodeUint(await readSlot(p.jeth, p.aj, 1n)), `${name} sentinel`).toBe(0n);
      expect(await readSlot(p.jeth, p.aj, 1n), `${name} sentinel eq`).toBe(await readSlot(p.sol, p.as, 1n));
    }
  });
});
