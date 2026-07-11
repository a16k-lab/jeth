// Scenario s6-arr-struct-with-struct-field: Arr<Item,3>, Item{id:u64; pt:Pt},
// Pt{x:u128; y:u128}. Exercises index + field + field-chain storage access:
// this.items[i].id, this.items[i].pt.x, this.items[i].pt.y. Byte-identical vs
// Solidity Item[3], raw slots match (Item = id-slot then Pt-slot), OOB Panics(0x32).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const JETH = `
type Pt = { x: u128; y: u128; };
type Item = { id: u64; pt: Pt; };

class S6 {
  items: Arr<Item, 3>;   // slots 0-5 (each Item: id-slot + pt-slot)
  sentinel: u256;        // slot 6

  setId(i: u256, v: u64): External<void> { this.items[i].id = v; }
  setX(i: u256, v: u128): External<void> { this.items[i].pt.x = v; }
  setY(i: u256, v: u128): External<void> { this.items[i].pt.y = v; }
  get getId(i: u256): External<u64> { return this.items[i].id; }
  get getX(i: u256): External<u128> { return this.items[i].pt.x; }
  get getY(i: u256): External<u128> { return this.items[i].pt.y; }
}
`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract S6 {
  struct Pt { uint128 x; uint128 y; }
  struct Item { uint64 id; Pt pt; }
  Item[3] items; // slots 0-5
  uint256 sentinel; // slot 6
  function setId(uint256 i, uint64 v) external { items[i].id = v; }
  function setX(uint256 i, uint128 v) external { items[i].pt.x = v; }
  function setY(uint256 i, uint128 v) external { items[i].pt.y = v; }
  function getId(uint256 i) external view returns (uint64){ return items[i].id; }
  function getX(uint256 i) external view returns (uint128){ return items[i].pt.x; }
  function getY(uint256 i) external view returns (uint128){ return items[i].pt.y; }
}`;

describe('s6-arr-struct-with-struct-field vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'S6.jeth' });
    const sb = compileSolidity(SOL, 'S6');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('index + field + field-chain: items[i].id/.pt.x/.pt.y raw slots + getters', async () => {
    // Item[1]: id-slot = 2*1 = 2, pt-slot = 2*1+1 = 3
    await both(encodeCall(sel('setId(uint256,uint64)'), [1n, 0x0123456789abcdefn]));
    await both(encodeCall(sel('setX(uint256,uint128)'), [1n, 0xcafen]));
    await both(encodeCall(sel('setY(uint256,uint128)'), [1n, 0xbeefn]));

    await eqSlot(2n, 'items[1].id slot');
    await eqSlot(3n, 'items[1].pt slot (x|y packed)');

    let r = await both(encodeCall(sel('getId(uint256)'), [1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0x0123456789abcdefn);
    expect(r.j.returnHex, 'getId returndata').toBe(r.s.returnHex);

    r = await both(encodeCall(sel('getX(uint256)'), [1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xcafen);
    expect(r.j.returnHex, 'getX returndata').toBe(r.s.returnHex);

    r = await both(encodeCall(sel('getY(uint256)'), [1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xbeefn);
    expect(r.j.returnHex, 'getY returndata').toBe(r.s.returnHex);
  });

  it('items[0] and items[2] raw slots + getters byte-identical', async () => {
    await both(encodeCall(sel('setId(uint256,uint64)'), [0n, 0xdeadn]));
    await both(encodeCall(sel('setX(uint256,uint128)'), [0n, 0x1111n]));
    await both(encodeCall(sel('setY(uint256,uint128)'), [0n, 0x2222n]));
    await both(encodeCall(sel('setId(uint256,uint64)'), [2n, 0xffffffffffffffffn]));
    await both(encodeCall(sel('setX(uint256,uint128)'), [2n, 0xffffffffffffffffffffffffffffffffn]));
    await both(encodeCall(sel('setY(uint256,uint128)'), [2n, 0x3333n]));

    // items[0]: slots 0,1 ; items[2]: slots 4,5
    await eqSlot(0n, 'items[0].id slot');
    await eqSlot(1n, 'items[0].pt slot');
    await eqSlot(4n, 'items[2].id slot');
    await eqSlot(5n, 'items[2].pt slot');

    for (const [g, i] of [
      ['getId(uint256)', 0n],
      ['getX(uint256)', 0n],
      ['getY(uint256)', 0n],
      ['getId(uint256)', 2n],
      ['getX(uint256)', 2n],
      ['getY(uint256)', 2n],
    ] as [string, bigint][]) {
      const r = await both(encodeCall(sel(g), [i]));
      expect(r.j.returnHex, `${g}[${i}]`).toBe(r.s.returnHex);
    }
  });

  it('OOB index Panics(0x32) identically on read and write', async () => {
    // read OOB
    let r = await both(encodeCall(sel('getId(uint256)'), [3n]));
    expect(r.j.success, 'getId(3) reverts').toBe(false);
    expect(r.s.success).toBe(false);
    expect(r.j.returnHex, 'getId(3) Panic data').toBe(r.s.returnHex);

    r = await both(encodeCall(sel('getX(uint256)'), [3n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex, 'getX(3) Panic data').toBe(r.s.returnHex);

    r = await both(encodeCall(sel('getY(uint256)'), [99n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex, 'getY(99) Panic data').toBe(r.s.returnHex);

    // write OOB
    r = await both(encodeCall(sel('setId(uint256,uint64)'), [3n, 1n]));
    expect(r.j.success, 'setId(3) reverts').toBe(false);
    expect(r.j.returnHex, 'setId(3) Panic data').toBe(r.s.returnHex);

    r = await both(encodeCall(sel('setX(uint256,uint128)'), [5n, 1n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex, 'setX(5) Panic data').toBe(r.s.returnHex);
  });

  it('sentinel slot 6 untouched in both implementations', async () => {
    expect(decodeUint(await readSlot(jeth, aj, 6n)), 'jeth sentinel').toBe(0n);
    await eqSlot(6n, 'sentinel slot 6 matches');
  });
});
