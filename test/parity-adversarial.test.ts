// ADVERSARIAL PARITY (audit findings B2/B4/B6/B3): the calldata decoders and the
// decode-to-memory echo encoders must be BYTE-IDENTICAL to real Solidity on
// hand-crafted adversarial offsets/lengths, not just on honest input. Every case
// below feeds the SAME raw calldata to JETH-compiled and solc-compiled bytecode and
// asserts identical (success, returndata).
//
// The two solc code paths this pins down (empirically measured against solc 0.8):
//
//  (1) LAZY-ACCESS of a single calldata slice (d.s, d.s.length, a[i], m[i], m[i][j]):
//      solc's `access_calldata_tail` form -> SIGNED length-word-readable check
//      `slt(off, calldatasize - B - 31)` (a high-bit / wrapping offset PASSES and the
//      pointer wraps mod 2^256, reading 0 out of range), the byte/element length is
//      capped at 2^64-1, and a SIGNED payload-fits `sgt(ptr, calldatasize - (size +
//      0x20))`. Net effect: off = 2^255 -> reads 0 (empty / Panic 0x32 on a later
//      index); off = 2^256-0x20 -> wraps to B-0x20 and reads that word; off = 2^64-1
//      (and the whole (calldatasize, 2^255) band) -> EMPTY revert.
//
//  (2) DECODE-TO-FRESH-MEMORY ECHO of a whole aggregate (return d / return a / return
//      m): a wrapping/high-bit member offset is rejected by the UNSIGNED cap
//      `gt(off, 2^64-1)` (-> EMPTY), and an oversized payload allocation raises
//      Panic(0x41) (returndata 0x4e487b71..0041) BEFORE the payload-within-calldatasize
//      EMPTY check. Measured: echo string length 2^63 -> EMPTY (payload past end);
//      2^64-1 / 2^64 / 2^256-1 -> Panic(0x41).
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

const HI = 1n << 255n; // high bit set ("negative" signed)
const WRAP = M - 0x20n; // -32 mod 2^256
const U64 = (1n << 64n) - 1n; // 2^64-1
const PANIC = (code: bigint) => '0x4e487b71' + w(code);

// D uses a `bytes` field (not `string`) only so JETH can express `d.s.length`
// (Solidity's `string` has no .length); bytes and string share an identical ABI
// layout, so every hand-built calldata below is valid for both. The JETH source is
// examples/AdversarialAbi.jeth; the contract name there is AdversarialAbi.
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

describe('adversarial offset/length parity vs Solidity (byte-for-byte)', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'AdversarialAbi.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'AdversarialAbi.jeth' });
    const sb = compileSolidity(SOL, 'AdversarialAbi');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // Feed identical raw calldata to both; assert identical (success, returndata).
  // Optionally pin solc's expected output so the test also documents the truth.
  async function same(sig: string, body: string, expected?: { success: boolean; ret?: string }) {
    const data = '0x' + sel(sig) + body;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${sig} success (jeth=${j.success} sol=${s.success})`).toBe(s.success);
    expect(j.returnHex, `${sig} returndata`).toBe(s.returnHex);
    if (expected) {
      expect(s.success, `${sig} solc-success pin`).toBe(expected.success);
      if (expected.ret !== undefined) expect(s.returnHex, `${sig} solc-ret pin`).toBe(expected.ret);
    }
    return { j, s };
  }

  // ---------------------------------------------------------------------------
  // 1. Dynamic-struct string field offset (lazy access: d.s / d.s.length)
  //    calldata: [top_off=0x20][a=7][off_s]. tuple start B = byte 0x24.
  // ---------------------------------------------------------------------------
  it('dyn-struct string-field off_s = 2^255 -> wraps, reads 0 (len 0)', async () => {
    // off_s high-bit: signed slt passes, lp wraps far OOB, length read = 0.
    await same('dLen((uint256,bytes))', w(0x20n) + w(7n) + w(HI), { success: true, ret: '0x' + w(0n) });
  });

  it('dyn-struct string-field off_s = 2^256-32 -> wraps to B-0x20, reads the top offset word', async () => {
    // lp = B - 0x20 = byte 0x04 = the top-level offset word (value 0x20) read as the
    // string length; payload is the next words. dLen returns 0x20.
    await same('dLen((uint256,bytes))', w(0x20n) + w(7n) + w(WRAP), { success: true, ret: '0x' + w(0x20n) });
    // dGet echoes that wrapped 32-byte string back ([0x20][len=0x20][word 0x07]).
    await same('dGet((uint256,bytes))', w(0x20n) + w(7n) + w(WRAP), {
      success: true,
      ret: '0x' + w(0x20n) + w(0x20n) + w(7n),
    });
  });

  it('dyn-struct string-field off_s = 2^64-1 -> EMPTY (signed slt rejects huge positive)', async () => {
    await same('dLen((uint256,bytes))', w(0x20n) + w(7n) + w(U64), { success: false, ret: '0x' });
    // the whole band (2^64, 2^255) is also EMPTY:
    await same('dLen((uint256,bytes))', w(0x20n) + w(7n) + w(1n << 200n), { success: false, ret: '0x' });
    await same('dLen((uint256,bytes))', w(0x20n) + w(7n) + w(1n << 64n), { success: false, ret: '0x' });
  });

  // ---------------------------------------------------------------------------
  // 2. T[][] inner offset (lazy access: m[i][j])
  //    calldata: [off_m=0x60][i=0][j=0] + region@0x64: [outer_len=1][inner_off0][...]
  //    pointer-region base B = byte 0x84.
  // ---------------------------------------------------------------------------
  it('m[i][j] inner offset = 2^255 -> Panic(0x32) (wrapped len 0, j=0 OOB)', async () => {
    const body = w(0x60n) + w(0n) + w(0n) + w(1n) + w(HI) + w(2n) + w(0x77n) + w(0x88n);
    await same('mGet(uint256[][],uint256,uint256)', body, { success: false, ret: PANIC(0x32n) });
    // m[i].length over the same wrapped inner array -> innerLen read 0 (success).
    await same('innerLen(uint256[][],uint256)', w(0x40n) + w(0n) + w(1n) + w(HI), { success: true, ret: '0x' + w(0n) });
  });

  it('m[i][j] inner offset = 2^256-32 -> wraps, reads the wrapped element', async () => {
    // base B=0x84, inner_off0=-0x20 -> lenPtr = 0x64 = outer_len word (=1) -> innerLen 1;
    // dataOff = 0x84 = the inner_off0 word itself = 2^256-0x20; j=0 reads it.
    const body = w(0x60n) + w(0n) + w(0n) + w(1n) + w(WRAP);
    await same('mGet(uint256[][],uint256,uint256)', body, { success: true, ret: '0x' + w(WRAP) });
  });

  it('m[i][j] inner offset = 2^64-1 -> EMPTY (signed slt rejects)', async () => {
    const body = w(0x60n) + w(0n) + w(0n) + w(1n) + w(U64) + w(2n) + w(0x77n) + w(0x88n);
    await same('mGet(uint256[][],uint256,uint256)', body, { success: false, ret: '0x' });
  });

  // ---------------------------------------------------------------------------
  // 3. string[] element offset high-bit (lazy access: a[i])
  //    calldata: [off_a=0x40][i=0] + region@0x44: [L=1][el_off0][...]
  //    table base B = byte 0x64.
  // ---------------------------------------------------------------------------
  it('string[] element offset = 2^255 -> wraps, empty string', async () => {
    // a[i] echoes the wrapped-to-empty element: [0x20][len=0].
    await same('saAt(string[],uint256)', w(0x40n) + w(0n) + w(1n) + w(HI), {
      success: true,
      ret: '0x' + w(0x20n) + w(0n),
    });
  });

  it('string[] element offset = 2^256-32 -> wraps to B-0x20 (the array length word)', async () => {
    // B = 0x64; lp = 0x44 = the L word (=1) -> string length 1, payload = next word.
    const body = w(0x40n) + w(0n) + w(1n) + w(WRAP) + w(0xabn << 248n); // one payload word after table
    // solc defines the exact bytes; we just assert identity (and that it succeeds).
    const { s } = await same('saAt(string[],uint256)', body);
    expect(s.success).toBe(true);
  });

  it('string[] element offset = 2^64-1 -> EMPTY (signed slt rejects)', async () => {
    await same('saAt(string[],uint256)', w(0x40n) + w(0n) + w(1n) + w(U64), { success: false, ret: '0x' });
  });

  // ---------------------------------------------------------------------------
  // 4. Decode-to-memory ECHO alloc bound: Panic(0x41) vs EMPTY (rule 3)
  // ---------------------------------------------------------------------------
  it('dEcho string length 2^63 -> EMPTY (payload past end, no alloc panic yet)', async () => {
    await same('dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + w(1n << 63n), { success: false, ret: '0x' });
  });

  it('dEcho string length 2^64-1 / 2^64 / 2^256-1 -> Panic(0x41) (oversized alloc)', async () => {
    for (const len of [U64, 1n << 64n, M - 1n]) {
      await same('dEcho((uint256,bytes))', w(0x20n) + w(7n) + w(0x40n) + w(len), { success: false, ret: PANIC(0x41n) });
    }
  });

  it('saEcho element length 2^63 -> EMPTY ; 2^64-1 / 2^64 -> Panic(0x41)', async () => {
    // region: [L=1][off0=0x20][elemLen][...]
    await same('saEcho(string[])', w(0x20n) + w(1n) + w(0x20n) + w(1n << 63n), { success: false, ret: '0x' });
    for (const len of [U64, 1n << 64n]) {
      await same('saEcho(string[])', w(0x20n) + w(1n) + w(0x20n) + w(len), { success: false, ret: PANIC(0x41n) });
    }
  });

  it('mEcho inner length 2^63 / 2^64-1 -> Panic(0x41) ; wrapped inner offset -> EMPTY', async () => {
    // region: [outerLen=1][off0=0x20][innerLen][...]
    for (const len of [1n << 63n, U64]) {
      await same('mEcho(uint256[][])', w(0x20n) + w(1n) + w(0x20n) + w(len), { success: false, ret: PANIC(0x41n) });
    }
    // a wrapping/high-bit inner offset is rejected by the echo's UNSIGNED cap -> EMPTY,
    // unlike the lazy m[i][j] path (which wraps and succeeds).
    await same('mEcho(uint256[][])', w(0x20n) + w(1n) + w(WRAP), { success: false, ret: '0x' });
    await same('mEcho(uint256[][])', w(0x20n) + w(1n) + w(HI), { success: false, ret: '0x' });
  });

  // ---------------------------------------------------------------------------
  // 5. Happy-path controls: the honest layouts must STILL be byte-identical.
  // ---------------------------------------------------------------------------
  it('happy path: dLen / dGet / dEcho honest', async () => {
    // D{a:7, s:"hello"} : [0x20][7][off_s=0x40][len=5]["hello"...]
    const sHex = Buffer.from('hello').toString('hex').padEnd(64, '0');
    const body = w(0x20n) + w(7n) + w(0x40n) + w(5n) + sHex;
    await same('dLen((uint256,bytes))', body, { success: true, ret: '0x' + w(5n) });
    await same('dGet((uint256,bytes))', body, { success: true, ret: '0x' + w(0x20n) + w(5n) + sHex });
    await same('dEcho((uint256,bytes))', body, { success: true });
  });

  it('happy path: m[i][j] / mEcho honest (asymmetric inner lengths)', async () => {
    // m = [[1,2,3],[4],[5,6]] canonical encoding.
    const region =
      w(3n) + w(0x60n) + w(0xe0n) + w(0x120n) + w(3n) + w(1n) + w(2n) + w(3n) + w(1n) + w(4n) + w(2n) + w(5n) + w(6n);
    await same('mGet(uint256[][],uint256,uint256)', w(0x60n) + w(0n) + w(2n) + region, {
      success: true,
      ret: '0x' + w(3n),
    });
    await same('mEcho(uint256[][])', w(0x20n) + region, { success: true });
  });

  it('happy path: a[i] / saEcho honest', async () => {
    // a = ["ab","cdef"] canonical encoding.
    const region =
      w(2n) +
      w(0x40n) +
      w(0x80n) +
      w(2n) +
      Buffer.from('ab').toString('hex').padEnd(64, '0') +
      w(4n) +
      Buffer.from('cdef').toString('hex').padEnd(64, '0');
    await same('saAt(string[],uint256)', w(0x40n) + w(1n) + region, {
      success: true,
      ret: '0x' + w(0x20n) + w(4n) + Buffer.from('cdef').toString('hex').padEnd(64, '0'),
    });
    await same('saEcho(string[])', w(0x20n) + region, { success: true });
  });
});
