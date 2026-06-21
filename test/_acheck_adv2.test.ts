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

describe('adv2: T[][] and string[] offset/length sweep', () => {
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

  it('T[][] inner-offset sweep (lazy m[i][j], innerLen)', async () => {
    // calldata: [off_m=0x60][i=0][j=0] + region@0x64:[outer_len=1][inner_off0][...]
    // pointer base B = 0x84.
    const sigG = 'mGet(uint256[][],uint256,uint256)';
    const sigL = 'innerLen(uint256[][],uint256)';
    const pre = w(0x60n) + w(0n) + w(0n); // off_m,i,j for mGet
    const preL = w(0x40n) + w(0n);        // off_m,i for innerLen

    // inner_off near signed/64 boundaries
    for (const [lbl, off] of [
      ['ino=2^64-32', U64m32], ['ino=2^64', U64p1], ['ino=2^64-1', U64],
      ['ino=2^255-1', SBm1], ['ino=2^255', SB], ['ino=2^256-32', WRAP], ['ino=2^256-1', M - 1n],
    ] as [string, bigint][]) {
      await same(`mGet ${lbl}`, sigG, pre + w(1n) + w(off) + w(2n) + w(0x77n) + w(0x88n));
      await same(`innerLen ${lbl}`, sigL, preL + w(1n) + w(off));
    }
    // overlapping / self-referential / non-aligned inner offsets with real data
    // honest region with inner0 at 0x20: [outerLen=1][off0=0x20][innerLen=2][111][222]
    await same('mGet honest', sigG, pre + w(1n) + w(0x20n) + w(2n) + w(111n) + w(222n));
    await same('mGet ino=0x21 nonaligned', sigG, pre + w(1n) + w(0x21n) + w(2n) + w(111n) + w(222n) + w(0n));
    await same('mGet ino=0 selfref', sigG, pre + w(1n) + w(0n) + w(2n) + w(111n) + w(222n));
    await same('mGet ino=0x40 overlap', sigG, pre + w(1n) + w(0x40n) + w(2n) + w(111n) + w(222n));
    // outer off_m sweep
    for (const [lbl, off] of [
      ['offm=2^64-1', U64], ['offm=2^255', SB], ['offm=2^256-32', WRAP],
    ] as [string, bigint][]) {
      await same(`mGet ${lbl}`, sigG, w(off) + w(0n) + w(0n) + w(1n) + w(0x20n) + w(2n) + w(111n) + w(222n));
    }

    if (mismatches.length) console.log('\n' + mismatches.join('\n\n'));
    expect(mismatches, `${mismatches.length} mismatches`).toEqual([]);
  });

  it('T[][] echo sweep (mEcho)', async () => {
    mismatches.length = 0;
    const sig = 'mEcho(uint256[][])';
    // region:[outerLen=1][off0=0x20][innerLen][...]
    for (const [lbl, len] of [
      ['ilen=2^63', 1n << 63n], ['ilen=2^64-32', U64m32], ['ilen=2^64-1', U64],
      ['ilen=2^64', U64p1], ['ilen=2^255', SB], ['ilen=2^256-1', M - 1n],
    ] as [string, bigint][]) {
      await same(`mEcho ${lbl}`, sig, w(0x20n) + w(1n) + w(0x20n) + w(len));
    }
    // inner offset wrap/high-bit in echo (unsigned cap)
    for (const [lbl, off] of [
      ['ino=2^64-32', U64m32], ['ino=2^64', U64p1], ['ino=2^64-1', U64],
      ['ino=2^255', SB], ['ino=2^256-32', WRAP], ['ino=2^256-1', M - 1n],
    ] as [string, bigint][]) {
      await same(`mEcho ${lbl}`, sig, w(0x20n) + w(1n) + w(off));
    }
    // outer offset wrap in echo
    for (const [lbl, off] of [
      ['offm=2^64-1', U64], ['offm=2^255', SB], ['offm=2^256-32', WRAP],
    ] as [string, bigint][]) {
      await same(`mEcho ${lbl}`, sig, w(off) + w(1n) + w(0x20n) + w(2n) + w(1n) + w(2n));
    }
    // truncated: declares innerLen with payload exactly at / past end
    await same('mEcho innerLen=2 exact', sig, w(0x20n) + w(1n) + w(0x20n) + w(2n) + w(1n) + w(2n));
    await same('mEcho innerLen=2 short1', sig, w(0x20n) + w(1n) + w(0x20n) + w(2n) + w(1n));
    await same('mEcho outerLen=2 truncated table', sig, w(0x20n) + w(2n) + w(0x40n));
    // outerLen huge
    await same('mEcho outerLen=2^64', sig, w(0x20n) + w(U64p1));
    await same('mEcho outerLen=2^256-1', sig, w(0x20n) + w(M - 1n));

    if (mismatches.length) console.log('\n' + mismatches.join('\n\n'));
    expect(mismatches, `${mismatches.length} mismatches`).toEqual([]);
  });

  it('string[] element-offset sweep (lazy saAt + echo saEcho)', async () => {
    mismatches.length = 0;
    const sigA = 'saAt(string[],uint256)';
    const sigE = 'saEcho(string[])';
    // saAt: [off_a=0x40][i=0] + region@0x44:[L=1][el_off0][...] table base B=0x64
    const preA = w(0x40n) + w(0n);
    for (const [lbl, off] of [
      ['eo=2^64-32', U64m32], ['eo=2^64', U64p1], ['eo=2^64-1', U64],
      ['eo=2^255-1', SBm1], ['eo=2^255', SB], ['eo=2^256-32', WRAP], ['eo=2^256-1', M - 1n],
    ] as [string, bigint][]) {
      await same(`saAt ${lbl}`, sigA, preA + w(1n) + w(off) + w(2n) + w(0n));
    }
    // honest + overlapping/self-ref/nonaligned element offsets
    // region [L=1][off0=0x20][len=2]["ab"] : el data right after table
    const ab = w(2n) + Buffer.from('ab').toString('hex').padEnd(64, '0');
    await same('saAt honest', sigA, preA + w(1n) + w(0x20n) + ab);
    await same('saAt eo=0x21 nonaligned', sigA, preA + w(1n) + w(0x21n) + ab + w(0n));
    await same('saAt eo=0 selfref', sigA, preA + w(1n) + w(0n) + ab);
    await same('saAt eo=0x40 deeper', sigA, preA + w(2n) + w(0x40n) + w(0x60n) + ab + ab);

    // saEcho: [off_a=0x20] + region:[L=1][off0=0x20][len][...]
    for (const [lbl, len] of [
      ['elen=2^63', 1n << 63n], ['elen=2^64-32', U64m32], ['elen=2^64-1', U64],
      ['elen=2^64', U64p1], ['elen=2^255', SB], ['elen=2^256-1', M - 1n],
    ] as [string, bigint][]) {
      await same(`saEcho ${lbl}`, sigE, w(0x20n) + w(1n) + w(0x20n) + w(len));
    }
    for (const [lbl, off] of [
      ['eo=2^64-32', U64m32], ['eo=2^64', U64p1], ['eo=2^64-1', U64],
      ['eo=2^255', SB], ['eo=2^256-32', WRAP], ['eo=2^256-1', M - 1n],
    ] as [string, bigint][]) {
      await same(`saEcho ${lbl}`, sigE, w(0x20n) + w(1n) + w(off));
    }
    // L huge in echo
    await same('saEcho L=2^64', sigE, w(0x20n) + w(U64p1));
    await same('saEcho L=2^256-1', sigE, w(0x20n) + w(M - 1n));

    if (mismatches.length) console.log('\n' + mismatches.join('\n\n'));
    expect(mismatches, `${mismatches.length} mismatches`).toEqual([]);
  });
});
