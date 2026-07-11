// Scenario s3-nested-3d-fixed-array: Arr<Arr<Arr<u256,2>,2>,2> cube with u256
// sentinels before and after. Asserts this.cube[a][b][c] set/get is byte-identical
// to Solidity uint256[2][2][2], raw slot = base + a*4 + b*2 + c matches, OOB on
// each of the three dimensions Panics(0x32) identically, and sentinels are untouched.
import { describe, it, expect, beforeAll } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import type { Address } from '@ethereumjs/util';

// Layout (Solidity uint256[2][2][2] == JETH Arr<Arr<Arr<u256,2>,2>,2>):
//   slot 0           : sentinelBefore (u256)
//   slots 1..8       : cube, row-major. cube[a][b][c] at base(=1) + a*4 + b*2 + c
//   slot 9           : sentinelAfter (u256)
const CUBE_BASE = 1n;
const SENT_BEFORE = 0n;
const SENT_AFTER = 9n;
function cubeSlot(a: bigint, b: bigint, c: bigint): bigint {
  return CUBE_BASE + a * 4n + b * 2n + c;
}

const JETH_SRC = `// 3D fixed array with sentinels before/after.
class Cube3D {
  sentinelBefore: u256;                      // slot 0
  cube: Arr<Arr<Arr<u256, 2>, 2>, 2>;        // slots 1-8
  sentinelAfter: u256;                        // slot 9

  setSent(before: u256, after: u256): External<void> {
    this.sentinelBefore = before;
    this.sentinelAfter = after;
  }
  setCube(a: u256, b: u256, c: u256, v: u256): External<void> {
    this.cube[a][b][c] = v;
  }
  get getCube(a: u256, b: u256, c: u256): External<u256> {
    return this.cube[a][b][c];
  }
  get getSentBefore(): External<u256> { return this.sentinelBefore; }
  get getSentAfter(): External<u256> { return this.sentinelAfter; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Cube3D {
  uint256 sentinelBefore;          // slot 0
  uint256[2][2][2] cube;           // slots 1-8
  uint256 sentinelAfter;           // slot 9
  function setSent(uint256 b4, uint256 aft) external {
    sentinelBefore = b4;
    sentinelAfter = aft;
  }
  function setCube(uint256 a, uint256 b, uint256 c, uint256 v) external {
    cube[a][b][c] = v;
  }
  function getCube(uint256 a, uint256 b, uint256 c) external view returns (uint256) {
    return cube[a][b][c];
  }
  function getSentBefore() external view returns (uint256) { return sentinelBefore; }
  function getSentAfter() external view returns (uint256) { return sentinelAfter; }
}`;

// Panic(0x32) ABI encoding: selector 0x4e487b71 + 0x32 word.
const PANIC32 = '0x4e487b71' + '0000000000000000000000000000000000000000000000000000000000000032';

describe('s3-nested-3d-fixed-array: cube[a][b][c] vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const jb = compile(JETH_SRC, { fileName: 'Cube3D.jeth' });
    const sb = compileSolidity(SOL, 'Cube3D');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('writes every cube cell; raw slot = base + a*4 + b*2 + c matches Solidity', async () => {
    // Distinct value per cell so an index/stride bug surfaces.
    let n = 0n;
    const vals = new Map<string, bigint>();
    for (let a = 0n; a < 2n; a++) {
      for (let b = 0n; b < 2n; b++) {
        for (let c = 0n; c < 2n; c++) {
          n += 1n;
          const v = (0xc0ffee00n << 8n) | n; // unique sentinel-ish value
          vals.set(`${a},${b},${c}`, v);
          const r = await both(encodeCall(sel('setCube(uint256,uint256,uint256,uint256)'), [a, b, c, v]));
          expect(r.j.success, `setCube(${a},${b},${c})`).toBe(true);
          expect(r.j.returnHex, `setCube returndata (${a},${b},${c})`).toBe(r.s.returnHex);
        }
      }
    }
    // Raw slot identity + correct mapping of (a,b,c) -> slot.
    for (let a = 0n; a < 2n; a++) {
      for (let b = 0n; b < 2n; b++) {
        for (let c = 0n; c < 2n; c++) {
          const slot = cubeSlot(a, b, c);
          await eqSlot(slot, `cube[${a}][${b}][${c}] raw slot ${slot}`);
          // And the slot actually holds the value we wrote (proves no aliasing).
          expect(decodeUint(await readSlot(jeth, aj, slot)), `cube[${a}][${b}][${c}] value`).toBe(
            vals.get(`${a},${b},${c}`),
          );
        }
      }
    }
  });

  it('getCube byte-identical to Solidity for every cell', async () => {
    for (let a = 0n; a < 2n; a++) {
      for (let b = 0n; b < 2n; b++) {
        for (let c = 0n; c < 2n; c++) {
          const r = await both(encodeCall(sel('getCube(uint256,uint256,uint256)'), [a, b, c]));
          expect(r.j.success, `getCube(${a},${b},${c}) success`).toBe(true);
          expect(r.j.returnHex, `getCube(${a},${b},${c}) returndata`).toBe(r.s.returnHex);
        }
      }
    }
  });

  it('OOB on outer dim a Panics(0x32) identically', async () => {
    const r = await both(encodeCall(sel('getCube(uint256,uint256,uint256)'), [2n, 0n, 0n]));
    expect(r.j.success).toBe(false);
    expect(r.s.success).toBe(false);
    expect(r.j.returnHex, 'JETH OOB-a returndata').toBe(r.s.returnHex);
    expect(r.j.returnHex.toLowerCase(), 'OOB-a is Panic(0x32)').toBe(PANIC32);
    // also on the write path
    const w = await both(encodeCall(sel('setCube(uint256,uint256,uint256,uint256)'), [2n, 0n, 0n, 1n]));
    expect(w.j.success).toBe(false);
    expect(w.j.returnHex, 'setCube OOB-a returndata').toBe(w.s.returnHex);
  });

  it('OOB on middle dim b Panics(0x32) identically', async () => {
    const r = await both(encodeCall(sel('getCube(uint256,uint256,uint256)'), [0n, 2n, 0n]));
    expect(r.j.success).toBe(false);
    expect(r.s.success).toBe(false);
    expect(r.j.returnHex, 'JETH OOB-b returndata').toBe(r.s.returnHex);
    expect(r.j.returnHex.toLowerCase(), 'OOB-b is Panic(0x32)').toBe(PANIC32);
  });

  it('OOB on inner dim c Panics(0x32) identically', async () => {
    const r = await both(encodeCall(sel('getCube(uint256,uint256,uint256)'), [0n, 0n, 2n]));
    expect(r.j.success).toBe(false);
    expect(r.s.success).toBe(false);
    expect(r.j.returnHex, 'JETH OOB-c returndata').toBe(r.s.returnHex);
    expect(r.j.returnHex.toLowerCase(), 'OOB-c is Panic(0x32)').toBe(PANIC32);
  });

  it('sentinels before/after the cube are untouched and byte-identical', async () => {
    // Set sentinels to recognizable nonzero values, then write the whole cube again.
    const B4 = 0xdeadbeefn;
    const AFT = 0xfeedface00n;
    await both(encodeCall(sel('setSent(uint256,uint256)'), [B4, AFT]));
    // overwrite a corner of the cube to provoke any over/underflow into sentinels
    await both(encodeCall(sel('setCube(uint256,uint256,uint256,uint256)'), [0n, 0n, 0n, 0x11n]));
    await both(encodeCall(sel('setCube(uint256,uint256,uint256,uint256)'), [1n, 1n, 1n, 0x22n]));

    await eqSlot(SENT_BEFORE, 'sentinelBefore raw slot');
    await eqSlot(SENT_AFTER, 'sentinelAfter raw slot');
    expect(decodeUint(await readSlot(jeth, aj, SENT_BEFORE)), 'sentinelBefore value').toBe(B4);
    expect(decodeUint(await readSlot(jeth, aj, SENT_AFTER)), 'sentinelAfter value').toBe(AFT);

    // getters byte-identical too
    const rb = await both(encodeCall(sel('getSentBefore()')));
    expect(rb.j.returnHex, 'getSentBefore returndata').toBe(rb.s.returnHex);
    const ra = await both(encodeCall(sel('getSentAfter()')));
    expect(ra.j.returnHex, 'getSentAfter returndata').toBe(ra.s.returnHex);

    // first cube slot is base(=1), immediately after sentinelBefore(=0);
    // last cube slot is base+7=8, immediately before sentinelAfter(=9).
    expect(cubeSlot(0n, 0n, 0n)).toBe(1n);
    expect(cubeSlot(1n, 1n, 1n)).toBe(8n);
  });
});
