// Scenario s4-deep-nested-struct: three-level struct nesting with offset
// accumulation across 3 field steps, byte-identical to Solidity incl. raw slots.
//
//   C { p:u128; q:u128 }                 // 1 slot (p|q packed)
//   B { m:u64; c:C; n:u64 }              // m -> own slot, c -> fresh slot, n -> fresh
//   A { x:u64; b:B; y:u64 }              // x -> own slot, b -> fresh slot, y -> fresh
//   sentinel u256 @ slot 0, a: A @ slot 1
//
// Solidity rule: a nested struct member always starts at a fresh slot and the
// member following it also starts a fresh slot. So the layout is:
//   slot 0  sentinel
//   slot 1  a.x   (u64, offset 0)
//   slot 2  a.b.m (u64, offset 0)
//   slot 3  a.b.c.p (u128, offset 0) | a.b.c.q (u128, offset 16)
//   slot 4  a.b.n (u64, offset 0)
//   slot 5  a.y   (u64, offset 0)
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const JETH = `// three-level nesting with a leading sentinel
@struct class C { p: u128; q: u128; }
@struct class B { m: u64; c: C; n: u64; }
@struct class A { x: u64; b: B; y: u64; }

@contract
class Deep {
  @state sentinel: u256;   // slot 0
  @state a: A;             // slots 1-5

  @external setP(v: u128): void { this.a.b.c.p = v; }
  @external setQ(v: u128): void { this.a.b.c.q = v; }
  @external setM(v: u64): void  { this.a.b.m = v; }
  @external setX(v: u64): void  { this.a.x = v; }
  @external @view getP(): u128 { return this.a.b.c.p; }
  @external @view getQ(): u128 { return this.a.b.c.q; }
  @external @view getM(): u64  { return this.a.b.m; }
  @external @view getX(): u64  { return this.a.x; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Deep {
  struct C { uint128 p; uint128 q; }
  struct B { uint64 m; C c; uint64 n; }
  struct A { uint64 x; B b; uint64 y; }
  uint256 sentinel;
  A a;
  function setP(uint128 v) external { a.b.c.p = v; }
  function setQ(uint128 v) external { a.b.c.q = v; }
  function setM(uint64 v) external  { a.b.m = v; }
  function setX(uint64 v) external  { a.x = v; }
  function getP() external view returns (uint128){ return a.b.c.p; }
  function getQ() external view returns (uint128){ return a.b.c.q; }
  function getM() external view returns (uint64){ return a.b.m; }
  function getX() external view returns (uint64){ return a.x; }
}`;

describe('s4 deep nested struct vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'Deep.jeth' });
    const sb = compileSolidity(SOL, 'Deep');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('writes through 3-level path; raw slots match Solidity (offset accumulation)', async () => {
    // distinct sentinel values per field so a misrouted write is visible
    await both(encodeCall(sel('setP(uint128)'), [0x1111_2222_3333_4444n]));
    await both(encodeCall(sel('setQ(uint128)'), [0xaaaa_bbbb_cccc_ddddn]));
    await both(encodeCall(sel('setM(uint64)'), [0x0102_0304_0506_0708n]));
    await both(encodeCall(sel('setX(uint64)'), [0x1112_1314_1516_1718n]));

    // a.b.c lives at slot 3: p in low 16 bytes, q in high 16 bytes (packed)
    await eqSlot(3n, 'a.b.c slot (p|q packed) = slot 3');
    // a.b.m at slot 2, a.x at slot 1
    await eqSlot(2n, 'a.b.m slot = slot 2');
    await eqSlot(1n, 'a.x slot = slot 1');
    // a.b.n (slot 4) and a.y (slot 5) never written -> stay zero in both
    await eqSlot(4n, 'a.b.n slot = slot 4 (untouched)');
    await eqSlot(5n, 'a.y slot = slot 5 (untouched)');
    // sentinel at slot 0 untouched
    await eqSlot(0n, 'sentinel slot 0 (untouched)');

    // explicit packing check on the JETH side: slot3 = q<<128 | p
    const slot3 = decodeUint(await readSlot(jeth, aj, 3n));
    expect(slot3 & ((1n << 128n) - 1n)).toBe(0x1111_2222_3333_4444n); // p low
    expect(slot3 >> 128n).toBe(0xaaaa_bbbb_cccc_ddddn); // q high
  });

  it('getters return byte-identical returndata vs Solidity', async () => {
    for (const [g, want] of [
      ['getP()', 0x1111_2222_3333_4444n],
      ['getQ()', 0xaaaa_bbbb_cccc_ddddn],
      ['getM()', 0x0102_0304_0506_0708n],
      ['getX()', 0x1112_1314_1516_1718n],
    ] as const) {
      const r = await both(encodeCall(sel(g)));
      expect(r.j.success, g).toBe(true);
      expect(r.j.returnHex, g).toBe(r.s.returnHex);
      expect(decodeUint(r.j.returnHex), g).toBe(want);
    }
  });

  it('overwriting one packed half preserves the other (byte-identical)', async () => {
    // rewrite p, leave q; both halves must match Solidity exactly
    await both(encodeCall(sel('setP(uint128)'), [0xdead_beefn]));
    await eqSlot(3n, 'a.b.c slot after p-only rewrite');
    let r = await both(encodeCall(sel('getP()')));
    expect(r.j.returnHex).toBe(r.s.returnHex);
    expect(decodeUint(r.j.returnHex)).toBe(0xdead_beefn);
    r = await both(encodeCall(sel('getQ()')));
    expect(r.j.returnHex).toBe(r.s.returnHex);
    expect(decodeUint(r.j.returnHex)).toBe(0xaaaa_bbbb_cccc_ddddn); // q untouched
  });
});
