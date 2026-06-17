import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const M = 1n << 256n;
const w = (v: bigint): string => (((v % M) + M) % M).toString(16).padStart(64, '0');
const sel = (s: string) => functionSelector(s);

const HI = 1n << 255n;
const WRAP = M - 0x20n;
const U64 = (1n << 64n) - 1n;
const U64m32 = (1n << 64n) - 32n;
const U64p1 = 1n << 64n;
const SB = 1n << 255n;
const SBm1 = (1n << 255n) - 1n;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AdversarialAbi {
  struct D { uint256 a; bytes s; }
  function dLen(D calldata d) external pure returns (uint256){ return d.s.length; }
  function dGet(D calldata d) external pure returns (bytes memory){ return d.s; }
  function mGet(uint256[][] calldata m, uint256 i, uint256 j) external pure returns (uint256){ return m[i][j]; }
  function innerLen(uint256[][] calldata m, uint256 i) external pure returns (uint256){ return m[i].length; }
  function saAt(string[] calldata a, uint256 i) external pure returns (string memory){ return a[i]; }
  function dEcho(D calldata d) external pure returns (D memory){ return d; }
  function saEcho(string[] calldata a) external pure returns (string[] memory){ return a; }
  function mEcho(uint256[][] calldata m) external pure returns (uint256[][] memory){ return m; }
}`;

describe('adv1: dyn-struct bytes-field offset/length sweep', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mismatches: string[] = [];

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'AdversarialAbi.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'AdversarialAbi.jeth' });
    const sb = compileSolidity(SOL, 'AdversarialAbi');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  async function same(label: string, sig: string, body: string) {
    const data = '0x' + sel(sig) + body;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    const ok = j.success === s.success && j.returnHex === s.returnHex;
    if (!ok) {
      mismatches.push(
        `MISMATCH [${label}] ${sig}\n  calldata: ${data}\n  jeth: success=${j.success} ret=${j.returnHex}\n  sol : success=${s.success} ret=${s.returnHex}`,
      );
    }
    return { j, s, ok };
  }

  it('runs the full sweep', async () => {
    const tail = w(5n) + Buffer.from('hello').toString('hex').padEnd(64, '0');

    // (A) dLen lazy off_s
    await same('A1 off_s=2^64-32', 'dLen((uint256,bytes))', w(0x20n) + w(7n) + w(U64m32));
    await same('A2 off_s=2^64', 'dLen((uint256,bytes))', w(0x20n) + w(7n) + w(U64p1));
    await same('A3 off_s=2^64-1', 'dLen((uint256,bytes))', w(0x20n) + w(7n) + w(U64));
    await same('A4 off_s=2^255-1', 'dLen((uint256,bytes))', w(0x20n) + w(7n) + w(SBm1));
    await same('A5 off_s=2^255', 'dLen((uint256,bytes))', w(0x20n) + w(7n) + w(SB));
    await same('A6 off_s=2^256-1', 'dLen((uint256,bytes))', w(0x20n) + w(7n) + w(M - 1n));
    await same('A1g off_s=2^64-32', 'dGet((uint256,bytes))', w(0x20n) + w(7n) + w(U64m32));
    await same('A5g off_s=2^255', 'dGet((uint256,bytes))', w(0x20n) + w(7n) + w(SB));
    await same('A6g off_s=2^256-1', 'dGet((uint256,bytes))', w(0x20n) + w(7n) + w(M - 1n));
    await same('A7g off_s=2^256-64', 'dGet((uint256,bytes))', w(0x20n) + w(7n) + w(M - 0x40n));

    await same('A8 off_s=0x40 honest', 'dLen((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + tail);
    await same('A9 off_s=0x41', 'dLen((uint256,bytes))', w(0x20n) + w(7n) + w(0x41n) + tail + w(0n));
    await same('A10 off_s=0x3f', 'dLen((uint256,bytes))', w(0x20n) + w(7n) + w(0x3fn) + tail + w(0n));
    await same('A11 off_s=0', 'dLen((uint256,bytes))', w(0x20n) + w(7n) + w(0n) + tail);
    await same('A12 off_s=0x20', 'dLen((uint256,bytes))', w(0x20n) + w(7n) + w(0x20n) + tail);

    await same('A13 topoff=2^64-1', 'dLen((uint256,bytes))', w(U64) + w(7n) + w(0x40n) + tail);
    await same('A14 topoff=2^255', 'dLen((uint256,bytes))', w(HI) + w(7n) + w(0x40n) + tail);
    await same('A15 topoff=2^256-32', 'dLen((uint256,bytes))', w(WRAP) + w(7n) + w(0x40n) + tail);
    await same('A16 topoff=0x21', 'dLen((uint256,bytes))', w(0x21n) + w(7n) + w(0x40n) + tail + w(0n));
    await same('A17 topoff=0', 'dLen((uint256,bytes))', w(0n) + w(7n) + w(0x40n) + tail);

    // (B) dEcho len + off_s
    await same('B1 echo len=2^63', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + w(1n << 63n));
    await same('B2 echo len=2^64-32', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + w(U64m32));
    await same('B3 echo len=2^64-1', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + w(U64));
    await same('B4 echo len=2^64', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + w(U64p1));
    await same('B5 echo len=2^255', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + w(SB));
    await same('B6 echo len=2^256-1', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + w(M - 1n));
    await same('B7 echo off_s=2^255', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(SB));
    await same('B8 echo off_s=2^256-32', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(WRAP));
    await same('B9 echo off_s=2^64-1', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(U64));
    await same('B10 echo off_s=2^64', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(U64p1));
    await same('B11 echo off_s=2^64-32', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(U64m32));
    await same('B12 echo len=33 trunc', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + w(33n) + w(0n));
    await same('B13 echo len=32 exact', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + w(32n) + w(0n));
    await same('B14 echo len=33 ok', 'dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + w(33n) + w(0n) + w(0n));
    await same('B15 echo topoff=2^256-32', 'dEcho((uint256,bytes))', w(WRAP) + w(7n) + w(0x40n) + w(5n) + w(0n));
    await same('B16 echo topoff=2^255', 'dEcho((uint256,bytes))', w(HI) + w(7n) + w(0x40n) + w(5n) + w(0n));

    if (mismatches.length) {
      console.log('\n' + mismatches.join('\n\n'));
    }
    expect(mismatches, `${mismatches.length} mismatches`).toEqual([]);
  });
});
