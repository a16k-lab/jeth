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
contract TopBytes {
  function bLen(bytes calldata s) external pure returns (uint256){ return s.length; }
  function bGet(bytes calldata s) external pure returns (bytes memory){ return s; }
  function bAt(bytes calldata s, uint256 i) external pure returns (bytes1){ return s[i]; }
}`;

describe('top-level bytes calldata param adversarial parity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mismatches: string[] = [];

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'TopBytes.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'TopBytes.jeth' });
    const sb = compileSolidity(SOL, 'TopBytes');
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

  it('bLen/bGet offset sweep', async () => {
    // calldata for bLen(bytes): [off][payload...]. off base = byte 4.
    const tail = w(5n) + Buffer.from('hello').toString('hex').padEnd(64, '0');
    for (const sig of ['bLen(bytes)', 'bGet(bytes)']) {
      await same(`${sig} honest`, sig, w(0x20n) + tail);
      for (const [lbl, off] of [
        ['off=2^64-32', U64m32], ['off=2^64', U64p1], ['off=2^64-1', U64],
        ['off=2^255-1', SBm1], ['off=2^255', SB], ['off=2^256-32', WRAP], ['off=2^256-1', M - 1n],
      ] as [string, bigint][]) {
        await same(`${sig} ${lbl}`, sig, w(off) + tail);
      }
      // wrap that lands lp at a readable word (off = 2^256-32 -> lp = byte 4 - 32 = -28 wraps far; but
      // for top-level base is byte 4). off = 2^256 - 4 -> lp = 0 ; off small negative variants:
      await same(`${sig} off=2^256-4`, sig, w(M - 4n) + tail);
      await same(`${sig} off=0`, sig, w(0n) + tail);
      await same(`${sig} off=0x21 nonaligned`, sig, w(0x21n) + tail + w(0n));
      // length sweep (offset honest, length adversarial)
      for (const [lbl, len] of [
        ['len=2^63', 1n << 63n], ['len=2^64-32', U64m32], ['len=2^64-1', U64],
        ['len=2^64', U64p1], ['len=2^255', SB], ['len=2^256-1', M - 1n],
      ] as [string, bigint][]) {
        await same(`${sig} ${lbl}`, sig, w(0x20n) + w(len) + w(0n));
      }
      // truncated payloads at boundaries
      await same(`${sig} len=33 trunc`, sig, w(0x20n) + w(33n) + w(0n));
      await same(`${sig} len=32 exact`, sig, w(0x20n) + w(32n) + w(0n));
      await same(`${sig} len=64 short`, sig, w(0x20n) + w(64n) + w(0n) + w(0n));
    }

    if (mismatches.length) console.log('\n' + mismatches.join('\n\n'));
    expect(mismatches, `${mismatches.length} mismatches`).toEqual([]);
  });

  it('bAt index/offset sweep', async () => {
    mismatches.length = 0;
    const sig = 'bAt(bytes,uint256)';
    // [off][i][payload]. honest off=0x40.
    const tail = w(5n) + Buffer.from('hello').toString('hex').padEnd(64, '0');
    await same('bAt honest i=0', sig, w(0x40n) + w(0n) + tail);
    await same('bAt honest i=4', sig, w(0x40n) + w(4n) + tail);
    await same('bAt oob i=5', sig, w(0x40n) + w(5n) + tail);
    for (const [lbl, off] of [
      ['off=2^255', SB], ['off=2^256-32', WRAP], ['off=2^64-1', U64],
    ] as [string, bigint][]) {
      await same(`bAt ${lbl}`, sig, w(off) + w(0n) + tail);
    }
    if (mismatches.length) console.log('\n' + mismatches.join('\n\n'));
    expect(mismatches, `${mismatches.length} mismatches`).toEqual([]);
  });
});
