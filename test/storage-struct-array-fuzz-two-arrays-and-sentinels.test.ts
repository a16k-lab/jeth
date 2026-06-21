// Phase 4e-2 differential scenario "two-arrays-and-sentinels":
// TWO storage struct arrays plus interleaved scalar sentinels, plus a degenerate
// single-uint256-field struct array. Verifies vs Solidity oracle that:
//  - scalar sentinels x (slot 1) and y (slot 3) stay byte-identical to solc,
//  - both arrays' length + fields + raw packed slots match,
//  - the two arrays' data regions (keccak of their respective length slots) do
//    not collide,
//  - a 1-slot (single uint256 field) struct element works.
// PASS requires EVERY probe byte-identical: returndata, success, raw slots, panic.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const A1 = BigInt('0x' + '11'.repeat(20));
const A2 = BigInt('0x' + '22'.repeat(20));

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
// data slot of a dynamic array whose length is at slot p = keccak256(pad32(p)).
function dataSlot(p: bigint): bigint {
  return BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad32(p)) as `0x${string}`))));
}

// JETH state layout:
//   a: P[]   -> length slot 0, data keccak(0)
//   x: u256  -> slot 1
//   b: Q[]   -> length slot 2, data keccak(2)
//   y: u256  -> slot 3
//   c: S[]   -> length slot 4, data keccak(4)   (S has ONE uint256 field: 1 slot)
// P { id: u64; owner: address; flag: bool; }    -> 1 slot (8+20+1 = 29 bytes, packs in slot0)
// Q { amount: u128; tag: u64; live: bool; }     -> 1 slot, BUT we make Q 2 slots to
//   exercise multi-slot element: Q { big: u256; small: u128; mid: u128; }
const DATA_A = dataSlot(0n);
const DATA_B = dataSlot(2n);
const DATA_C = dataSlot(4n);

const JETH = `
@struct class P { id: u64; owner: address; flag: bool; }
@struct class Q { big: u256; small: u128; mid: u128; }
@struct class S { val: u256; }

@contract
class TwoArrays {
  @state a: P[];     // slot 0
  @state x: u256;    // slot 1
  @state b: Q[];     // slot 2
  @state y: u256;    // slot 3
  @state c: S[];     // slot 4

  @external setX(v: u256): void { this.x = v; }
  @external setY(v: u256): void { this.y = v; }
  @external @view getX(): u256 { return this.x; }
  @external @view getY(): u256 { return this.y; }

  @external pushA(id: u64, owner: address, flag: bool): void { this.a.push(P(id, owner, flag)); }
  @external pushAEmpty(): void { this.a.push(); }
  @external popA(): void { this.a.pop(); }
  @external setAFlag(i: u256, v: bool): void { this.a[i].flag = v; }
  @external setAId(i: u256, v: u64): void { this.a[i].id = v; }
  @external @view lenA(): u256 { return this.a.length; }
  @external @view getAId(i: u256): u64 { return this.a[i].id; }
  @external @view getAOwner(i: u256): address { return this.a[i].owner; }
  @external @view getAFlag(i: u256): bool { return this.a[i].flag; }

  @external pushB(big: u256, small: u128, mid: u128): void { this.b.push(Q(big, small, mid)); }
  @external pushBEmpty(): void { this.b.push(); }
  @external popB(): void { this.b.pop(); }
  @external setBSmall(i: u256, v: u128): void { this.b[i].small = v; }
  @external setBBig(i: u256, v: u256): void { this.b[i].big = v; }
  @external @view lenB(): u256 { return this.b.length; }
  @external @view getBBig(i: u256): u256 { return this.b[i].big; }
  @external @view getBSmall(i: u256): u128 { return this.b[i].small; }
  @external @view getBMid(i: u256): u128 { return this.b[i].mid; }

  @external pushC(val: u256): void { this.c.push(S(val)); }
  @external popC(): void { this.c.pop(); }
  @external setCVal(i: u256, v: u256): void { this.c[i].val = v; }
  @external @view lenC(): u256 { return this.c.length; }
  @external @view getCVal(i: u256): u256 { return this.c[i].val; }
}
`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TwoArrays {
  struct P { uint64 id; address owner; bool flag; }
  struct Q { uint256 big; uint128 small; uint128 mid; }
  struct S { uint256 val; }
  P[] a;          // slot 0
  uint256 x;      // slot 1
  Q[] b;          // slot 2
  uint256 y;      // slot 3
  S[] c;          // slot 4

  function setX(uint256 v) external { x = v; }
  function setY(uint256 v) external { y = v; }
  function getX() external view returns (uint256){ return x; }
  function getY() external view returns (uint256){ return y; }

  function pushA(uint64 id, address owner, bool flag) external { a.push(P(id, owner, flag)); }
  function pushAEmpty() external { a.push(); }
  function popA() external { a.pop(); }
  function setAFlag(uint256 i, bool v) external { a[i].flag = v; }
  function setAId(uint256 i, uint64 v) external { a[i].id = v; }
  function lenA() external view returns (uint256){ return a.length; }
  function getAId(uint256 i) external view returns (uint64){ return a[i].id; }
  function getAOwner(uint256 i) external view returns (address){ return a[i].owner; }
  function getAFlag(uint256 i) external view returns (bool){ return a[i].flag; }

  function pushB(uint256 big, uint128 small, uint128 mid) external { b.push(Q(big, small, mid)); }
  function pushBEmpty() external { b.push(); }
  function popB() external { b.pop(); }
  function setBSmall(uint256 i, uint128 v) external { b[i].small = v; }
  function setBBig(uint256 i, uint256 v) external { b[i].big = v; }
  function lenB() external view returns (uint256){ return b.length; }
  function getBBig(uint256 i) external view returns (uint256){ return b[i].big; }
  function getBSmall(uint256 i) external view returns (uint128){ return b[i].small; }
  function getBMid(uint256 i) external view returns (uint128){ return b[i].mid; }

  function pushC(uint256 val) external { c.push(S(val)); }
  function popC() external { c.pop(); }
  function setCVal(uint256 i, uint256 v) external { c[i].val = v; }
  function lenC() external view returns (uint256){ return c.length; }
  function getCVal(uint256 i) external view returns (uint256){ return c[i].val; }
}`;

describe('two-arrays-and-sentinels: two struct arrays + scalars + degenerate 1-slot element', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  let compileErr: any = null;
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
    let jb: { creationBytecode: string };
    try {
      jb = compile(JETH, { fileName: 'TwoArrays.jeth' });
    } catch (e: any) {
      compileErr = e;
      return;
    }
    const sb = compileSolidity(SOL, 'TwoArrays');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('JETH compiles the two-array + degenerate-struct contract', () => {
    if (compileErr) {
      throw new Error(
        'JETH compile failed: ' +
          (compileErr.diagnostics
            ? compileErr.diagnostics.map((d: any) => `${d.code}: ${d.message}`).join('; ')
            : String(compileErr)),
      );
    }
    expect(aj).toBeDefined();
  });

  it('data regions of arrays a, b, c are distinct (no collision)', () => {
    expect(DATA_A).not.toBe(DATA_B);
    expect(DATA_A).not.toBe(DATA_C);
    expect(DATA_B).not.toBe(DATA_C);
  });

  it('scalar sentinels x (slot1) and y (slot3) byte-identical', async () => {
    await eqCall('setX', encodeCall(sel('setX(uint256)'), [0xdeadbeefn]));
    await eqCall('setY', encodeCall(sel('setY(uint256)'), [0xfeedfacen]));
    await eqSlot(1n, 'x raw slot');
    await eqSlot(3n, 'y raw slot');
    const rx = await eqCall('getX', encodeCall(sel('getX()'), []));
    expect(decodeUint(rx.j.returnHex)).toBe(0xdeadbeefn);
    const ry = await eqCall('getY', encodeCall(sel('getY()'), []));
    expect(decodeUint(ry.j.returnHex)).toBe(0xfeedfacen);
  });

  it('array a: push(P(...)) packs id|owner|flag into 1 slot, raw-slot identical', async () => {
    await eqCall('pushA#0', encodeCall(sel('pushA(uint64,address,bool)'), [10n, A1, 1n]));
    await eqCall('pushA#1', encodeCall(sel('pushA(uint64,address,bool)'), [20n, A2, 0n]));
    const r = await eqCall('lenA=2', encodeCall(sel('lenA()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    // P is 1 slot per element: element i at DATA_A + i
    for (let i = 0; i < 2; i++) await eqSlot(DATA_A + BigInt(i), `a[${i}] packed slot`);
    for (const i of [0n, 1n]) {
      for (const g of ['getAId(uint256)', 'getAOwner(uint256)', 'getAFlag(uint256)']) {
        await eqCall(`${g}@${i}`, encodeCall(sel(g), [i]));
      }
    }
  });

  it('array b: push(Q(...)) uses 2 slots/element (big | small,mid), raw-slot identical', async () => {
    await eqCall('pushB#0', encodeCall(sel('pushB(uint256,uint128,uint128)'), [0x1111n, 0x22n, 0x33n]));
    await eqCall('pushB#1', encodeCall(sel('pushB(uint256,uint128,uint128)'), [0xaaaan, 0xbbn, 0xccn]));
    const r = await eqCall('lenB=2', encodeCall(sel('lenB()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    // Q is 2 slots: slot0 = big (full word), slot1 = small|mid packed (16+16 bytes)
    for (let i = 0; i < 2; i++) {
      await eqSlot(DATA_B + BigInt(i) * 2n, `b[${i}].slot0 (big)`);
      await eqSlot(DATA_B + BigInt(i) * 2n + 1n, `b[${i}].slot1 (small|mid)`);
    }
    for (const i of [0n, 1n]) {
      for (const g of ['getBBig(uint256)', 'getBSmall(uint256)', 'getBMid(uint256)']) {
        await eqCall(`${g}@${i}`, encodeCall(sel(g), [i]));
      }
    }
  });

  it('degenerate array c: single-uint256 element occupies exactly 1 slot, identical', async () => {
    await eqCall('pushC#0', encodeCall(sel('pushC(uint256)'), [0x123456n]));
    await eqCall('pushC#1', encodeCall(sel('pushC(uint256)'), [0x9999n]));
    const r = await eqCall('lenC=2', encodeCall(sel('lenC()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    for (let i = 0; i < 2; i++) await eqSlot(DATA_C + BigInt(i), `c[${i}] (single uint256)`);
    for (const i of [0n, 1n]) {
      await eqCall(`getCVal@${i}`, encodeCall(sel('getCVal(uint256)'), [i]));
    }
  });

  it('RMW field writes preserve packed siblings, byte-identical (both arrays)', async () => {
    // a: flip flag on a[1], change id on a[0]; owner must survive
    await eqCall('setAFlag#1', encodeCall(sel('setAFlag(uint256,bool)'), [1n, 1n]));
    await eqCall('setAId#0', encodeCall(sel('setAId(uint256,uint64)'), [0n, 0xffn]));
    await eqSlot(DATA_A + 1n, 'a[1] slot after setAFlag');
    await eqSlot(DATA_A + 0n, 'a[0] slot after setAId');
    let r = await eqCall('getAOwner@0', encodeCall(sel('getAOwner(uint256)'), [0n]));
    expect(decodeUint(r.j.returnHex)).toBe(A1);
    r = await eqCall('getAFlag@1', encodeCall(sel('getAFlag(uint256)'), [1n]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);

    // b: change small on b[0] (packed slot1) and big on b[1] (slot0); mid must survive
    await eqCall('setBSmall#0', encodeCall(sel('setBSmall(uint256,uint128)'), [0n, 0x7777n]));
    await eqCall('setBBig#1', encodeCall(sel('setBBig(uint256,uint256)'), [1n, 0xdeadn]));
    await eqSlot(DATA_B + 1n, 'b[0].slot1 after setBSmall');
    await eqSlot(DATA_B + 2n, 'b[1].slot0 after setBBig');
    r = await eqCall('getBMid@0', encodeCall(sel('getBMid(uint256)'), [0n]));
    expect(decodeUint(r.j.returnHex)).toBe(0x33n);
    r = await eqCall('getBSmall@0', encodeCall(sel('getBSmall(uint256)'), [0n]));
    expect(decodeUint(r.j.returnHex)).toBe(0x7777n);
  });

  it('OOB index on either array Panics(0x32) identically', async () => {
    const r1 = await eqCall('getAId OOB', encodeCall(sel('getAId(uint256)'), [2n]));
    expect(r1.j.success).toBe(false);
    expect(r1.j.returnHex.startsWith('0x4e487b71')).toBe(true);
    const r2 = await eqCall('getBBig OOB', encodeCall(sel('getBBig(uint256)'), [9n]));
    expect(r2.j.success).toBe(false);
    const r3 = await eqCall('setCVal OOB', encodeCall(sel('setCVal(uint256,uint256)'), [5n, 1n]));
    expect(r3.j.success).toBe(false);
    const r4 = await eqCall('getCVal OOB', encodeCall(sel('getCVal(uint256)'), [2n]));
    expect(r4.j.success).toBe(false);
  });

  it('push empty + pop: zeroing and Panic(0x31) on empty, sentinels untouched', async () => {
    // push empty onto a and b, then pop everything; check raw slots zero like solc
    await eqCall('pushAEmpty', encodeCall(sel('pushAEmpty()'), []));
    await eqCall('pushBEmpty', encodeCall(sel('pushBEmpty()'), []));
    let r = await eqCall('lenA=3', encodeCall(sel('lenA()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    await eqSlot(DATA_A + 2n, 'a[2] zero element');
    await eqSlot(DATA_B + 4n, 'b[2].slot0 zero element');
    await eqSlot(DATA_B + 5n, 'b[2].slot1 zero element');

    // pop a down to empty, verify each popped slot zeroes identically
    await eqCall('popA#1', encodeCall(sel('popA()'), []));
    await eqSlot(DATA_A + 2n, 'a[2] after pop (zeroed)');
    await eqCall('popA#2', encodeCall(sel('popA()'), []));
    await eqSlot(DATA_A + 1n, 'a[1] after pop (zeroed)');
    await eqCall('popA#3', encodeCall(sel('popA()'), []));
    await eqSlot(DATA_A + 0n, 'a[0] after pop (zeroed)');
    r = await eqCall('lenA=0', encodeCall(sel('lenA()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0n);
    // pop empty a -> Panic 0x31
    const re = await eqCall('popA empty', encodeCall(sel('popA()'), []));
    expect(re.j.success).toBe(false);
    expect(re.j.returnHex.startsWith('0x4e487b71')).toBe(true);

    // pop b's 2-slot elements: both slots of popped element must zero
    await eqCall('popB#1', encodeCall(sel('popB()'), []));
    await eqSlot(DATA_B + 4n, 'b[2].slot0 after pop');
    await eqSlot(DATA_B + 5n, 'b[2].slot1 after pop');
    await eqCall('popB#2', encodeCall(sel('popB()'), []));
    await eqCall('popB#3', encodeCall(sel('popB()'), []));
    const reB = await eqCall('popB empty', encodeCall(sel('popB()'), []));
    expect(reB.j.success).toBe(false);

    // pop c (degenerate)
    await eqCall('popC#1', encodeCall(sel('popC()'), []));
    await eqSlot(DATA_C + 1n, 'c[1] after pop');
    await eqCall('popC#2', encodeCall(sel('popC()'), []));
    const reC = await eqCall('popC empty', encodeCall(sel('popC()'), []));
    expect(reC.j.success).toBe(false);

    // sentinels x and y survived all array churn, byte-identical
    await eqSlot(1n, 'x sentinel after all ops');
    await eqSlot(3n, 'y sentinel after all ops');
    r = await eqCall('getX final', encodeCall(sel('getX()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0xdeadbeefn);
    r = await eqCall('getY final', encodeCall(sel('getY()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0xfeedfacen);
  });
});
