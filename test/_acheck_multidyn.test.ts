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

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MultiDyn {
  struct T { uint256 a; bytes s; bytes b; }
  struct U { string name; uint256 x; bytes data; }
  function tLenS(T calldata t) external pure returns (uint256){ return t.s.length; }
  function tLenB(T calldata t) external pure returns (uint256){ return t.b.length; }
  function tGetS(T calldata t) external pure returns (bytes memory){ return t.s; }
  function tGetB(T calldata t) external pure returns (bytes memory){ return t.b; }
  function tEcho(T calldata t) external pure returns (T memory){ return t; }
  function uGetN(U calldata u) external pure returns (string memory){ return u.name; }
  function uGetD(U calldata u) external pure returns (bytes memory){ return u.data; }
  function uX(U calldata u) external pure returns (uint256){ return u.x; }
  function uEcho(U calldata u) external pure returns (U memory){ return u; }
}`;

const tSig = '(uint256,bytes,bytes)';
const uSig = '(string,uint256,bytes)';

describe('multi-dynamic-field struct adversarial parity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mismatches: string[] = [];

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'MultiDyn.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'MultiDyn.jeth' });
    const sb = compileSolidity(SOL, 'MultiDyn');
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

  it('T{a,s,b} two bytes fields - honest + adversarial offsets', async () => {
    // T head (3 words): [a][off_s][off_b]. tuple start B = byte 4 (top_off=0x20).
    // honest: a=7, off_s=0x60 -> s at B+0x60, off_b after s.
    // s="hi"(2), b="xyz"(3). s payload = [2][hi..], b payload = [3][xyz..]
    const sP = w(2n) + Buffer.from('hi').toString('hex').padEnd(64, '0'); // 0x40 bytes
    const bP = w(3n) + Buffer.from('xyz').toString('hex').padEnd(64, '0'); // 0x40 bytes
    const honest = w(7n) + w(0x60n) + w(0xa0n) + sP + bP; // off_s=0x60, off_b=0x60+0x40=0xa0
    const top = w(0x20n);
    for (const f of ['tLenS', 'tLenB', 'tGetS', 'tGetB', 'tEcho']) {
      await same(`${f} honest`, `${f}${tSig}`, top + honest);
    }
    // adversarial off_s (lazy): high-bit / wrap / 64-boundary
    for (const [lbl, off] of [
      ['off_s=2^64-32', U64m32],
      ['off_s=2^64', U64p1],
      ['off_s=2^64-1', U64],
      ['off_s=2^255', SB],
      ['off_s=2^256-32', WRAP],
      ['off_s=2^256-1', M - 1n],
    ] as [string, bigint][]) {
      await same(`tLenS ${lbl}`, `tLenS${tSig}`, top + w(7n) + w(off) + w(0xa0n) + sP + bP);
      await same(`tGetS ${lbl}`, `tGetS${tSig}`, top + w(7n) + w(off) + w(0xa0n) + sP + bP);
    }
    // adversarial off_b (second dynamic field)
    for (const [lbl, off] of [
      ['off_b=2^64-32', U64m32],
      ['off_b=2^64', U64p1],
      ['off_b=2^64-1', U64],
      ['off_b=2^255', SB],
      ['off_b=2^256-32', WRAP],
      ['off_b=2^256-1', M - 1n],
    ] as [string, bigint][]) {
      await same(`tLenB ${lbl}`, `tLenB${tSig}`, top + w(7n) + w(0x60n) + w(off) + sP + bP);
      await same(`tGetB ${lbl}`, `tGetB${tSig}`, top + w(7n) + w(0x60n) + w(off) + sP + bP);
    }
    // tEcho with adversarial off_s / off_b / lengths
    for (const [lbl, off] of [
      ['off_s=2^255', SB],
      ['off_s=2^256-32', WRAP],
      ['off_s=2^64-1', U64],
      ['off_s=2^64', U64p1],
    ] as [string, bigint][]) {
      await same(`tEcho ${lbl}`, `tEcho${tSig}`, top + w(7n) + w(off) + w(0xa0n) + sP + bP);
    }
    for (const [lbl, off] of [
      ['off_b=2^255', SB],
      ['off_b=2^256-32', WRAP],
      ['off_b=2^64-1', U64],
      ['off_b=2^64', U64p1],
    ] as [string, bigint][]) {
      await same(`tEcho ${lbl}`, `tEcho${tSig}`, top + w(7n) + w(0x60n) + w(off) + sP + bP);
    }
    // tEcho with adversarial s/b lengths (alloc panic boundary)
    for (const [lbl, len] of [
      ['slen=2^63', 1n << 63n],
      ['slen=2^64-1', U64],
      ['slen=2^64', U64p1],
      ['slen=2^256-1', M - 1n],
    ] as [string, bigint][]) {
      await same(`tEcho ${lbl}`, `tEcho${tSig}`, top + w(7n) + w(0x60n) + w(0xa0n) + w(len) + w(0n) + bP);
    }
    // overlapping: off_s = off_b (both point to same payload)
    await same('tEcho off_s=off_b=0x60', `tEcho${tSig}`, top + w(7n) + w(0x60n) + w(0x60n) + sP);
    await same('tLenB off_s=off_b=0x60', `tLenB${tSig}`, top + w(7n) + w(0x60n) + w(0x60n) + sP);

    if (mismatches.length) console.log('\n' + mismatches.join('\n\n'));
    expect(mismatches, `${mismatches.length} mismatches`).toEqual([]);
  });

  it('U{string,uint,bytes} string-first dynamic struct', async () => {
    mismatches.length = 0;
    // U head (3 words): [off_name][x][off_data]. tuple start B.
    const nP = w(4n) + Buffer.from('test').toString('hex').padEnd(64, '0'); // 0x40
    const dP = w(2n) + Buffer.from('zz').toString('hex').padEnd(64, '0'); // 0x40
    const top = w(0x20n);
    const honest = w(0x60n) + w(99n) + w(0xa0n) + nP + dP; // off_name=0x60, x=99, off_data=0xa0
    for (const f of ['uGetN', 'uGetD', 'uX', 'uEcho']) {
      await same(`${f} honest`, `${f}${uSig}`, top + honest);
    }
    // adversarial off_name and off_data
    for (const [lbl, off] of [
      ['off_name=2^255', SB],
      ['off_name=2^256-32', WRAP],
      ['off_name=2^64-1', U64],
      ['off_name=2^64', U64p1],
    ] as [string, bigint][]) {
      await same(`uGetN ${lbl}`, `uGetN${uSig}`, top + w(off) + w(99n) + w(0xa0n) + nP + dP);
      await same(`uEcho ${lbl}`, `uEcho${uSig}`, top + w(off) + w(99n) + w(0xa0n) + nP + dP);
    }
    for (const [lbl, off] of [
      ['off_data=2^255', SB],
      ['off_data=2^256-32', WRAP],
      ['off_data=2^64-1', U64],
      ['off_data=2^64', U64p1],
    ] as [string, bigint][]) {
      await same(`uGetD ${lbl}`, `uGetD${uSig}`, top + w(0x60n) + w(99n) + w(off) + nP + dP);
      await same(`uEcho ${lbl}`, `uEcho${uSig}`, top + w(0x60n) + w(99n) + w(off) + nP + dP);
    }
    // x read (static field after a dynamic field) - dirty value? x is full u256 so always valid.
    await same('uX honest', `uX${uSig}`, top + honest);

    if (mismatches.length) console.log('\n' + mismatches.join('\n\n'));
    expect(mismatches, `${mismatches.length} mismatches`).toEqual([]);
  });
});
