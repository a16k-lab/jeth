// Packed storage must be byte-identical to Solidity (directive §2.3, §4.6),
// including the left-aligned bytesN placement. Differentially compare raw slots
// and every getter against the reference compiler.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Packed {
  uint128 a; bytes4 b; int16 c; bool d; address e;
  function setA(uint128 x) external { a = x; }
  function setB(bytes4 x) external { b = x; }
  function setC(int16 x) external { c = x; }
  function setD(bool x) external { d = x; }
  function setE(address x) external { e = x; }
  function getA() external view returns (uint128){ return a; }
  function getB() external view returns (bytes4){ return b; }
  function getC() external view returns (int16){ return c; }
  function getD() external view returns (bool){ return d; }
  function getE() external view returns (address){ return e; }
}`;

// 32-byte words for the set calls. bytes4 is left-aligned; address right-aligned.
const A = 0x0123456789abcdefn;
const B_WORD = BigInt('0xaabbccdd' + '00'.repeat(28)); // bytes4 left-aligned
const C = -1234n; // int16
const ADDR = BigInt('0x' + 'ab'.repeat(20));

describe('packed storage vs Solidity', () => {
  let hj: Harness;
  let hs: Harness;
  let aj: any;
  let as: any;
  const sel = (s: string) => functionSelector(s);

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'Packed.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'Packed.jeth' });
    const sb = compileSolidity(SOL, 'Packed');
    hj = await Harness.create();
    hs = await Harness.create();
    aj = await hj.deploy(jb.creationBytecode);
    as = await hs.deploy(sb.creation);

    const calls: [string, bigint][] = [
      ['setA(uint128)', A],
      ['setB(bytes4)', B_WORD],
      ['setC(int16)', C],
      ['setD(bool)', 1n],
      ['setE(address)', ADDR],
    ];
    for (const [s, v] of calls) {
      const data = encodeCall(sel(s), [v]);
      expect((await hj.call(aj, data)).success, `jeth ${s}`).toBe(true);
      expect((await hs.call(as, data)).success, `sol ${s}`).toBe(true);
    }
  });

  it('produces byte-identical packed slot 0 and slot 1', async () => {
    expect(await readSlot(hj, aj, 0n)).toBe(await readSlot(hs, as, 0n));
    expect(await readSlot(hj, aj, 1n)).toBe(await readSlot(hs, as, 1n));
  });

  it('round-trips every packed field identically to Solidity', async () => {
    for (const g of ['getA()', 'getB()', 'getC()', 'getD()', 'getE()']) {
      const data = encodeCall(sel(g));
      const rj = await hj.call(aj, data);
      const rs = await hs.call(as, data);
      expect(rj.success, `jeth ${g}`).toBe(true);
      expect(rj.returnHex, `field ${g} mismatch`).toBe(rs.returnHex);
    }
  });

  it('returns the left-aligned bytesN value (not zero)', async () => {
    const rj = await hj.call(aj, encodeCall(sel('getB()')));
    expect(rj.returnHex).toBe('0x' + 'aabbccdd' + '00'.repeat(28));
  });
});
