// Scenario s1-arr-of-packed-struct: Arr<P,4> with P{a:u8;b:u16;c:u64;d:bool;e:address}.
// Multiple packed fields share a slot; address e fills bytes 12..31 of the same
// (single) slot per element (Solidity numberOfBytes == 32). For i in {0,2,3}: set
// then get each field, assert byte-identical getter returndata vs Solidity AND raw
// slot of pts[i] identical. Reading getX at OOB index 4 must Panic(0x32) identically.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PackedArr {
  struct P { uint8 a; uint16 b; uint64 c; bool d; address e; }
  P[4] pts;        // slots 0-3
  uint256 sentinel; // slot 4
  function setA(uint256 i, uint8 v) external { pts[i].a = v; }
  function setB(uint256 i, uint16 v) external { pts[i].b = v; }
  function setC(uint256 i, uint64 v) external { pts[i].c = v; }
  function setD(uint256 i, bool v) external { pts[i].d = v; }
  function setE(uint256 i, address v) external { pts[i].e = v; }
  function getA(uint256 i) external view returns (uint8){ return pts[i].a; }
  function getB(uint256 i) external view returns (uint16){ return pts[i].b; }
  function getC(uint256 i) external view returns (uint64){ return pts[i].c; }
  function getD(uint256 i) external view returns (bool){ return pts[i].d; }
  function getE(uint256 i) external view returns (address){ return pts[i].e; }
}`;

// Distinct per-index field values so a layout/stride bug surfaces immediately.
const VALS: Record<number, { a: bigint; b: bigint; c: bigint; d: bigint; e: bigint }> = {
  0: { a: 0x11n, b: 0x2233n, c: 0x445566778899aabbn, d: 1n, e: BigInt('0x' + 'a1'.repeat(20)) },
  2: { a: 0xffn, b: 0xfedcn, c: 0x0123456789abcdefn, d: 0n, e: BigInt('0x' + 'b2'.repeat(20)) },
  3: { a: 0x7fn, b: 0x8001n, c: 0xdeadbeefcafef00dn, d: 1n, e: BigInt('0x' + 'c3'.repeat(20)) },
};

describe('s1-arr-of-packed-struct vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);

  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', '_gen_PackedArr.jeth'), 'utf8');
    const jb = compile(src, { fileName: '_gen_PackedArr.jeth' });
    const sb = compileSolidity(SOL, 'PackedArr');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('compiles JETH source to creation bytecode', () => {
    // beforeAll would have thrown otherwise; explicit sanity assert.
    expect(aj).toBeDefined();
    expect(as).toBeDefined();
  });

  for (const i of [0, 2, 3]) {
    it(`index ${i}: set+get every packed field byte-identical + raw slot ${i}`, async () => {
      const v = VALS[i]!;
      // Set every field at this index on BOTH compilers.
      const setCalls: [string, bigint][] = [
        ['setA(uint256,uint8)', v.a],
        ['setB(uint256,uint16)', v.b],
        ['setC(uint256,uint64)', v.c],
        ['setD(uint256,bool)', v.d],
        ['setE(uint256,address)', v.e],
      ];
      for (const [s, val] of setCalls) {
        const r = await both(encodeCall(sel(s), [BigInt(i), val]));
        expect(r.j.success, `jeth ${s}@${i}`).toBe(true);
        expect(r.s.success, `sol ${s}@${i}`).toBe(true);
      }

      // Raw slot pts[i] (stride 1 slot/element): must be byte-identical, proving the
      // a|b|c|d|e packing inside the single slot matches Solidity exactly.
      await eqSlot(BigInt(i), `pts[${i}] packed slot`);

      // Every getter returndata byte-identical, and decoded values are what we set.
      const checks: [string, bigint][] = [
        ['getA(uint256)', v.a],
        ['getB(uint256)', v.b],
        ['getC(uint256)', v.c],
        ['getD(uint256)', v.d],
        ['getE(uint256)', v.e],
      ];
      for (const [g, expected] of checks) {
        const r = await both(encodeCall(sel(g), [BigInt(i)]));
        expect(r.j.success, `jeth ${g}@${i}`).toBe(true);
        expect(r.j.returnHex, `${g}@${i} returndata`).toBe(r.s.returnHex);
        expect(decodeUint(r.j.returnHex), `${g}@${i} value`).toBe(expected);
      }
    });
  }

  it('struct occupies exactly one slot: sentinel (slot 4) untouched on both', async () => {
    // If any element spilled into a second slot, sentinel at slot 4 would differ.
    await eqSlot(4n, 'sentinel slot 4');
    expect(decodeUint(await readSlot(jeth, aj, 4n))).toBe(0n);
  });

  it('cross-index isolation: setting index 0 left index 1 (slot 1) zero on both', async () => {
    await eqSlot(1n, 'pts[1] untouched slot');
    expect(decodeUint(await readSlot(jeth, aj, 1n))).toBe(0n);
  });

  it('OOB index 4: every getter Panic(0x32) byte-identical to Solidity', async () => {
    const PANIC32 = '0x4e487b71' + '0000000000000000000000000000000000000000000000000000000000000032';
    for (const g of ['getA(uint256)', 'getB(uint256)', 'getC(uint256)', 'getD(uint256)', 'getE(uint256)']) {
      const r = await both(encodeCall(sel(g), [4n]));
      expect(r.j.success, `jeth ${g}@4 should revert`).toBe(false);
      expect(r.s.success, `sol ${g}@4 should revert`).toBe(false);
      expect(r.j.returnHex, `${g}@4 panic returndata`).toBe(r.s.returnHex);
      expect(r.j.returnHex, `${g}@4 is Panic(0x32)`).toBe(PANIC32);
    }
  });
});
