// Storage-layout planner (directive §2.3, §4.6). Reproduces Solidity's slot
// assignment and packing exactly so JETH storage interoperates with Foundry,
// ethers/viem, and block explorers.
//
// Rules implemented here:
//  - sequential slots from 0, in declaration order;
//  - types < 32 bytes pack contiguously into a slot when they fit, packing from
//    the low-order byte; a var that doesn't fit starts a fresh slot;
//  - mappings, dynamic arrays, bytes/string and other whole-slot types are never
//    packed: they finish the current slot and take their own.
import type { JethType } from './types.js';
import { storageByteSize, storageSlotCount } from './types.js';
import type { StateVar } from './ir.js';

export interface RawStateVar {
  name: string;
  type: JethType;
  initialValue?: bigint | boolean;
}

export interface LayoutResult {
  vars: StateVar[];
  slotCount: number;
}

function occupiesWholeSlot(t: JethType): boolean {
  // Structs and fixed arrays occupy whole (possibly multiple) slots and never pack
  // alongside other vars; reference / dynamic types and full-word value types too.
  return t.kind === 'struct' || (t.kind === 'array' && t.length !== undefined) || storageByteSize(t) === 32;
}

export function planLayout(raw: RawStateVar[]): LayoutResult {
  const vars: StateVar[] = [];
  let slot = 0;
  let usedInSlot = 0; // bytes consumed in the current slot

  for (const v of raw) {
    const size = storageByteSize(v.type);

    if (occupiesWholeSlot(v.type)) {
      if (usedInSlot > 0) {
        slot += 1;
        usedInSlot = 0;
      }
      vars.push({ ...v, slot, offset: 0 });
      slot += storageSlotCount(v.type); // multi-slot for structs / fixed arrays
      usedInSlot = 0;
      continue;
    }

    // packable type
    if (usedInSlot + size > 32) {
      slot += 1;
      usedInSlot = 0;
    }
    vars.push({ ...v, slot, offset: usedInSlot });
    usedInSlot += size;
    if (usedInSlot === 32) {
      slot += 1;
      usedInSlot = 0;
    }
  }

  const slotCount = usedInSlot > 0 ? slot + 1 : slot;
  return { vars, slotCount };
}
