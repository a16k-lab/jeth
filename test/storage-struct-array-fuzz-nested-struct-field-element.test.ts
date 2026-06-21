// Scenario nested-struct-field-element (Phase 4e-2): STORAGE dynamic array whose
// element is a struct containing a NESTED struct in the middle:
//   Outer { uint64 p; Inner inner; uint64 q }, Inner { uint128 x; uint128 y }
//   Outer[] recs;
// Exercises dynIndex + field + field chain (this.recs[i].inner.x / .inner.y) plus
// this.recs[i].p / .q, read AND write (RMW), byte-identical vs Solidity:
// returndata, success, raw storage slots (readSlot), and panic bytes.
//
// Solidity layout of each Outer element (3 slots, structs occupy whole slots):
//   element-slot 0: p   (uint64 @ offset 0; inner is a struct so it starts fresh)
//   element-slot 1: inner.x (uint128 @ off 0) | inner.y (uint128 @ off 16)
//   element-slot 2: q   (uint64 @ offset 0; new slot after the nested struct)
// recs: length @ slot 0, data @ keccak(pad32(0)); element i @ DATA0 + i*3.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
// data slot of the dynamic array whose length lives at slot 0.
const DATA0 = BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad32(0n)) as `0x${string}`))));
const STRIDE = 3n; // storage slots per Outer element

// Constant BigInt array indices in JETH must be BigInt literals (this.recs[0n]).
const JETH = `
@struct class Inner { x: u128; y: u128; }
@struct class Outer { p: u64; inner: Inner; q: u64; }

@contract
class NSFE {
  @state recs: Outer[];   // length @ slot 0, data @ keccak(0); each Outer = 3 slots
  @state sentinel: u256;  // slot 1

  @external pushEmpty(): void { this.recs.push(); }
  @external popRec(): void { this.recs.pop(); }

  @external setP(i: u256, v: u64): void { this.recs[i].p = v; }
  @external setQ(i: u256, v: u64): void { this.recs[i].q = v; }
  @external setX(i: u256, v: u128): void { this.recs[i].inner.x = v; }
  @external setY(i: u256, v: u128): void { this.recs[i].inner.y = v; }

  @external @view len(): u256 { return this.recs.length; }
  @external @view getP(i: u256): u64 { return this.recs[i].p; }
  @external @view getQ(i: u256): u64 { return this.recs[i].q; }
  @external @view getX(i: u256): u128 { return this.recs[i].inner.x; }
  @external @view getY(i: u256): u128 { return this.recs[i].inner.y; }
}
`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract NSFE {
  struct Inner { uint128 x; uint128 y; }
  struct Outer { uint64 p; Inner inner; uint64 q; }
  Outer[] recs;
  uint256 sentinel;
  function pushEmpty() external { recs.push(); }
  function popRec() external { recs.pop(); }
  function setP(uint256 i, uint64 v) external { recs[i].p = v; }
  function setQ(uint256 i, uint64 v) external { recs[i].q = v; }
  function setX(uint256 i, uint128 v) external { recs[i].inner.x = v; }
  function setY(uint256 i, uint128 v) external { recs[i].inner.y = v; }
  function len() external view returns (uint256){ return recs.length; }
  function getP(uint256 i) external view returns (uint64){ return recs[i].p; }
  function getQ(uint256 i) external view returns (uint64){ return recs[i].q; }
  function getX(uint256 i) external view returns (uint128){ return recs[i].inner.x; }
  function getY(uint256 i) external view returns (uint128){ return recs[i].inner.y; }
}`;

describe('nested-struct-field-element vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  let compileError: any = null;
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
      jb = compile(JETH, { fileName: 'NSFE.jeth' });
    } catch (e: any) {
      compileError = e;
      return; // record and let the gate test report; oracle compile still validates SOL
    }
    const sb = compileSolidity(SOL, 'NSFE');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('JETH accepts dynIndex + field + nested-struct-field chain', () => {
    if (compileError) {
      const codes = (compileError.diagnostics ?? []).map((d: any) => d.code);
      throw new Error(
        'JETH rejected this.recs[i].inner.x: ' +
          (compileError.message ?? String(compileError)) +
          ' codes=' + JSON.stringify(codes),
      );
    }
    expect(compileError).toBeNull();
  });

  it('push() two zero elements; length + zero raw slots byte-identical', async () => {
    if (compileError) return;
    await eqCall('pushEmpty#0', encodeCall(sel('pushEmpty()'), []));
    await eqCall('pushEmpty#1', encodeCall(sel('pushEmpty()'), []));
    const r = await eqCall('len=2', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    // recs.length raw slot (slot 0) and the 3 zeroed slots of each element
    await eqSlot(0n, 'recs.length slot');
    for (let i = 0n; i < 2n; i++) {
      for (let s = 0n; s < STRIDE; s++) {
        await eqSlot(DATA0 + i * STRIDE + s, `recs[${i}] element-slot ${s} (zero)`);
      }
    }
  });

  it('write p / q / inner.x / inner.y on recs[0]; RMW preserves siblings, raw slots match', async () => {
    if (compileError) return;
    // RMW each field; pack expectations: element-slot0=p, slot1=inner{x|y}, slot2=q
    await eqCall('setP@0', encodeCall(sel('setP(uint256,uint64)'), [0n, 0x1122334455667788n]));
    await eqCall('setX@0', encodeCall(sel('setX(uint256,uint128)'), [0n, 0xcafe00000000000000000000000000aan]));
    await eqCall('setY@0', encodeCall(sel('setY(uint256,uint128)'), [0n, 0xbeef000000000000000000000000bbn]));
    await eqCall('setQ@0', encodeCall(sel('setQ(uint256,uint64)'), [0n, 0x99aabbccddeeff00n]));

    await eqSlot(DATA0 + 0n, 'recs[0].p slot (element-slot 0)');
    await eqSlot(DATA0 + 1n, 'recs[0].inner slot (x|y packed, element-slot 1)');
    await eqSlot(DATA0 + 2n, 'recs[0].q slot (element-slot 2)');

    // getters byte-identical and values intact (no sibling clobber)
    let r = await eqCall('getP@0', encodeCall(sel('getP(uint256)'), [0n]));
    expect(decodeUint(r.j.returnHex)).toBe(0x1122334455667788n);
    r = await eqCall('getX@0', encodeCall(sel('getX(uint256)'), [0n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xcafe00000000000000000000000000aan);
    r = await eqCall('getY@0', encodeCall(sel('getY(uint256)'), [0n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xbeef000000000000000000000000bbn);
    r = await eqCall('getQ@0', encodeCall(sel('getQ(uint256)'), [0n]));
    expect(decodeUint(r.j.returnHex)).toBe(0x99aabbccddeeff00n);
  });

  it('write recs[1] independently; element isolation (recs[0] untouched), raw slots match', async () => {
    if (compileError) return;
    await eqCall('setP@1', encodeCall(sel('setP(uint256,uint64)'), [1n, 0xffffffffffffffffn]));
    await eqCall('setX@1', encodeCall(sel('setX(uint256,uint128)'), [1n, 0xffffffffffffffffffffffffffffffffn]));
    await eqCall('setY@1', encodeCall(sel('setY(uint256,uint128)'), [1n, 0x0000000000000000000000000000abcdn]));
    await eqCall('setQ@1', encodeCall(sel('setQ(uint256,uint64)'), [1n, 0x0102030405060708n]));

    for (let s = 0n; s < STRIDE; s++) {
      await eqSlot(DATA0 + 1n * STRIDE + s, `recs[1] element-slot ${s}`);
      await eqSlot(DATA0 + 0n * STRIDE + s, `recs[0] element-slot ${s} (must be unchanged)`);
    }
    for (const g of ['getP(uint256)', 'getX(uint256)', 'getY(uint256)', 'getQ(uint256)']) {
      await eqCall(`${g}@0 after recs[1] writes`, encodeCall(sel(g), [0n]));
      await eqCall(`${g}@1`, encodeCall(sel(g), [1n]));
    }
  });

  it('OOB index Panics(0x32) identically on nested read and write', async () => {
    if (compileError) return;
    // reads
    let r = await eqCall('getX OOB read', encodeCall(sel('getX(uint256)'), [2n]));
    expect(r.j.success).toBe(false);
    r = await eqCall('getY OOB read', encodeCall(sel('getY(uint256)'), [99n]));
    expect(r.j.success).toBe(false);
    r = await eqCall('getP OOB read', encodeCall(sel('getP(uint256)'), [2n]));
    expect(r.j.success).toBe(false);
    // writes (nested field write path must bounds-check too)
    r = await eqCall('setX OOB write', encodeCall(sel('setX(uint256,uint128)'), [2n, 1n]));
    expect(r.j.success).toBe(false);
    r = await eqCall('setQ OOB write', encodeCall(sel('setQ(uint256,uint64)'), [5n, 1n]));
    expect(r.j.success).toBe(false);
  });

  it('pop() zeroes all 3 element slots; pop empty -> Panic(0x31) identically', async () => {
    if (compileError) return;
    await eqCall('pop#1', encodeCall(sel('popRec()'), []));
    let r = await eqCall('len=1', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    // popped element (recs[1]) slots zeroed byte-identically
    for (let s = 0n; s < STRIDE; s++) {
      await eqSlot(DATA0 + 1n * STRIDE + s, `recs[1] element-slot ${s} after pop (zeroed)`);
    }
    await eqCall('pop#2', encodeCall(sel('popRec()'), []));
    r = await eqCall('len=0', encodeCall(sel('len()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0n);
    for (let s = 0n; s < STRIDE; s++) {
      await eqSlot(DATA0 + 0n * STRIDE + s, `recs[0] element-slot ${s} after pop (zeroed)`);
    }
    // pop empty -> Panic(0x31)
    const re = await eqCall('pop empty', encodeCall(sel('popRec()'), []));
    expect(re.j.success).toBe(false);
  });

  it('sentinel slot 1 stays untouched and matches', async () => {
    if (compileError) return;
    expect(decodeUint(await readSlot(jeth, aj, 1n))).toBe(0n);
    await eqSlot(1n, 'sentinel slot 1');
  });
});
