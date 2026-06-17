// Storage layout packing must match Solidity exactly (directive §2.3, §4.6).
import { describe, it, expect } from 'vitest';
import { planLayout } from '../src/layout.js';
import type { JethType } from '../src/types.js';

const u = (bits: number): JethType => ({ kind: 'uint', bits });
const addr: JethType = { kind: 'address', payable: false };
const boolean: JethType = { kind: 'bool' };
const map: JethType = { kind: 'mapping', key: addr, value: u(256) };

describe('storage layout', () => {
  it('assigns sequential slots to full-word vars', () => {
    const { vars, slotCount } = planLayout([
      { name: 'a', type: u(256) },
      { name: 'b', type: u(256) },
    ]);
    expect(vars.map((v) => [v.slot, v.offset])).toEqual([
      [0, 0],
      [1, 0],
    ]);
    expect(slotCount).toBe(2);
  });

  it('packs small types into one slot, low-order first', () => {
    // uint128 + uint64 + bool  -> all in slot 0 (16 + 8 + 1 = 25 bytes <= 32)
    const { vars, slotCount } = planLayout([
      { name: 'a', type: u(128) },
      { name: 'b', type: u(64) },
      { name: 'c', type: boolean },
    ]);
    expect(vars.map((v) => [v.slot, v.offset])).toEqual([
      [0, 0],
      [0, 16],
      [0, 24],
    ]);
    expect(slotCount).toBe(1);
  });

  it('starts a new slot when a var does not fit', () => {
    // uint128 (16) at slot0:0; uint128 (16) at slot0:16 fills the slot;
    // uint8 starts slot1.
    const { vars } = planLayout([
      { name: 'a', type: u(128) },
      { name: 'b', type: u(128) },
      { name: 'c', type: u(8) },
    ]);
    expect(vars.map((v) => [v.slot, v.offset])).toEqual([
      [0, 0],
      [0, 16],
      [1, 0],
    ]);
  });

  it('packs an address (20 bytes) with a uint96 (12 bytes) into one slot', () => {
    const { vars, slotCount } = planLayout([
      { name: 'owner', type: addr },
      { name: 'ts', type: u(96) },
    ]);
    expect(vars.map((v) => [v.slot, v.offset])).toEqual([
      [0, 0],
      [0, 20],
    ]);
    expect(slotCount).toBe(1);
  });

  it('never packs a mapping; it takes its own slot', () => {
    const { vars } = planLayout([
      { name: 'flag', type: boolean },
      { name: 'balances', type: map },
      { name: 'flag2', type: boolean },
    ]);
    // flag at 0:0; mapping finishes slot0 and takes slot1; flag2 at slot2
    expect(vars.map((v) => [v.slot, v.offset])).toEqual([
      [0, 0],
      [1, 0],
      [2, 0],
    ]);
  });
});
