// Phase 4c: structs byte-identical to Solidity — mixed-width field packing, field
// read/write, positional construction, whole-struct assignment (no trailing-space
// reuse), and struct (tuple) return. Raw slots compared via readSlot.
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
const U128_MAX = (1n << 128n) - 1n;
const DADDR = BigInt('0x' + 'aa'.repeat(20));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Structs {
  struct Mixed { uint128 a; uint64 b; bool c; address d; uint256 e; }
  Mixed s; uint256 after_;
  function setAll(uint128 a, uint64 b, bool c, address d, uint256 e) external { s = Mixed(a,b,c,d,e); after_ = 0x99; }
  function setA(uint128 v) external { s.a = v; }
  function getA() external view returns (uint128){ return s.a; }
  function getB() external view returns (uint64){ return s.b; }
  function getC() external view returns (bool){ return s.c; }
  function getD() external view returns (address){ return s.d; }
  function getE() external view returns (uint256){ return s.e; }
  function getAll() external view returns (Mixed memory){ return s; }
  function make(uint128 a, uint256 e) external pure returns (Mixed memory){ return Mixed(a, 0, true, address(0), e); }
}`;

describe('structs vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'Structs.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'Structs.jeth' });
    const sb = compileSolidity(SOL, 'Structs');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('packs mixed-width fields into the right slots (raw slots + after_ untouched)', async () => {
    await both(encodeCall(sel('setAll(uint128,uint64,bool,address,uint256)'), [U128_MAX, 0x1122334455667788n, 1n, DADDR, 0xdeadbeefn]));
    await eqSlot(0n, 'slot0 (a|b|c packed)');
    await eqSlot(1n, 'slot1 (d address)');
    await eqSlot(2n, 'slot2 (e)');
    await eqSlot(3n, 'slot3 (after_)');
    expect(decodeUint(await readSlot(jeth, aj, 3n))).toBe(0x99n);
  });

  it('reads each field byte-identically', async () => {
    for (const g of ['getA()', 'getB()', 'getC()', 'getD()', 'getE()']) {
      const r = await both(encodeCall(sel(g)));
      expect(r.j.returnHex, g).toBe(r.s.returnHex);
    }
  });

  it('writes a single field via RMW without disturbing siblings', async () => {
    await both(encodeCall(sel('setA(uint128)'), [42n]));
    await eqSlot(0n, 'slot0 after setA');
    const r = await both(encodeCall(sel('getB()')));
    expect(decodeUint(r.j.returnHex)).toBe(0x1122334455667788n); // b unchanged
    expect(r.j.returnHex).toBe(r.s.returnHex);
  });

  it('returns the whole struct as an ABI tuple, byte-identical', async () => {
    const r = await both(encodeCall(sel('getAll()')));
    expect(r.j.returnHex, 'getAll tuple').toBe(r.s.returnHex);
    // 5 head words
    expect((r.j.returnHex.length - 2) / 64).toBe(5);
  });

  it('constructs and returns a struct from a pure function, byte-identical', async () => {
    const r = await both(encodeCall(sel('make(uint128,uint256)'), [7n, 0xcafen]));
    expect(r.j.returnHex, 'make tuple').toBe(r.s.returnHex);
  });
});
