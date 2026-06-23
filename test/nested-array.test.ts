// Phase 4e-5: nested dynamic arrays T[][] (u256[][], u8[][]) as a calldata param and
// as a return, byte-identical to Solidity. Covers: echo of asymmetric-length values
// like [[1,2,3],[4],[5,6]] (byte-identical returndata), m[i][j] reads, m.length /
// m[i].length, OOB on the outer and inner dimension -> Panic(0x32), empty outer /
// empty inner, malformed inner offset / truncation -> EMPTY revert, u8 element
// validation (>255 -> EMPTY on read), and overlapping-offset acceptance.
//
// Layout (spec section 2): the inner-offset table base is the word immediately AFTER
// the outer length word (the pointer-region start). inner_off[k] points (relative to
// that base) to inner k's length word; the outer offset base is calldata byte 4.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const sel = (s: string) => functionSelector(s);

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract NestedArray {
  function echo(uint256[][] calldata m) external pure returns (uint256[][] memory){ return m; }
  function echo8(uint8[][] calldata m) external pure returns (uint8[][] memory){ return m; }
  function at(uint256[][] calldata m, uint256 i, uint256 j) external pure returns (uint256){ return m[i][j]; }
  function at8(uint8[][] calldata m, uint256 i, uint256 j) external pure returns (uint8){ return m[i][j]; }
  function outerLen(uint256[][] calldata m) external pure returns (uint256){ return m.length; }
  function innerLen(uint256[][] calldata m, uint256 i) external pure returns (uint256){ return m[i].length; }
}`;

// ABI-encode a T[][] DATA REGION (no outer offset): [outerLen][pointer table][inner
// tails]. Each inner tail is [innerLen][elem0]...; pointer offsets are relative to the
// pointer-region start (the word after outerLen), per spec section 2.1. Returns hex
// (no 0x).
function encodeNestedRegion(m: bigint[][]): string {
  const N = m.length;
  const tails = m.map((inner) => pad(BigInt(inner.length)) + inner.map((e) => pad(e)).join(''));
  // pointer offsets accumulate from the pointer-region start; the table is N words.
  let offBytes = N * 32; // first inner tail sits right after the table
  let table = '';
  for (const t of tails) {
    table += pad(BigInt(offBytes));
    offBytes += t.length / 2; // hex chars / 2 = byte length of this inner tail
  }
  return pad(BigInt(N)) + table + tails.join('');
}

// Full calldata for a sole T[][] param: selector + [outer off=0x20] + region.
function call1(selSig: string, m: bigint[][]): string {
  return '0x' + sel(selSig) + pad(0x20n) + encodeNestedRegion(m);
}
// Calldata for (T[][] m, uint256 i): selector + [outer off=0x40][i] + region.
function call2(selSig: string, m: bigint[][], i: bigint): string {
  return '0x' + sel(selSig) + pad(0x40n) + pad(i) + encodeNestedRegion(m);
}
// Calldata for (T[][] m, uint256 i, uint256 j): selector + [outer off=0x60][i][j] + region.
function call3(selSig: string, m: bigint[][], i: bigint, j: bigint): string {
  return '0x' + sel(selSig) + pad(0x60n) + pad(i) + pad(j) + encodeNestedRegion(m);
}

describe('nested dynamic array T[][] vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const sr = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(sr.success);
    expect(j.returnHex, `${label} returndata`).toBe(sr.returnHex);
    return { j, s: sr };
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'NestedArray.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'NestedArray.jeth' });
    const sb = compileSolidity(SOL, 'NestedArray');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('echoes u256[][] byte-identically (asymmetric inner lengths)', async () => {
    // The load-bearing case: asymmetric lengths (3,1,2) force non-uniform pointers,
    // so only the correct pointer-region base reproduces the whole returndata.
    await eq('echo [[1,2,3],[4],[5,6]]', call1('echo(uint256[][])', [[1n, 2n, 3n], [4n], [5n, 6n]]));
    // single inner, single element.
    await eq('echo [[7]]', call1('echo(uint256[][])', [[7n]]));
    // larger / mixed values incl. max word.
    await eq('echo big', call1('echo(uint256[][])', [[M - 1n, 0n], [0x1234n], [1n, 2n, 3n, 4n, 5n]]));
  });

  it('echoes empty outer / empty inner byte-identically', async () => {
    await eq('echo [] (empty outer)', call1('echo(uint256[][])', []));
    await eq('echo [[]] (one empty inner)', call1('echo(uint256[][])', [[]]));
    await eq('echo [[],[1],[]]', call1('echo(uint256[][])', [[], [1n], []]));
  });

  it('echoes u8[][] byte-identically (same layout as u256[][])', async () => {
    await eq('echo8 [[1,255,0],[42]]', call1('echo8(uint8[][])', [[1n, 255n, 0n], [42n]]));
    await eq('echo8 [] (empty outer)', call1('echo8(uint8[][])', []));
    await eq('echo8 [[],[7,8]]', call1('echo8(uint8[][])', [[], [7n, 8n]]));
  });

  it('reads m[i][j] (Panic 0x32 on outer or inner OOB)', async () => {
    const m = [[10n, 11n, 12n], [20n], [30n, 31n]];
    let r = await eq('at (0,0)', call3('at(uint256[][],uint256,uint256)', m, 0n, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(10n);
    r = await eq('at (0,2)', call3('at(uint256[][],uint256,uint256)', m, 0n, 2n));
    expect(decodeUint(r.j.returnHex)).toBe(12n);
    r = await eq('at (1,0)', call3('at(uint256[][],uint256,uint256)', m, 1n, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(20n);
    r = await eq('at (2,1)', call3('at(uint256[][],uint256,uint256)', m, 2n, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(31n);

    // outer OOB: i == outerLen (==3) -> Panic(0x32).
    r = await eq('at outer OOB i=3', call3('at(uint256[][],uint256,uint256)', m, 3n, 0n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
    await eq('at outer OOB i=99', call3('at(uint256[][],uint256,uint256)', m, 99n, 0n));

    // inner OOB: j == innerLen (m[1] has length 1, so j=1 is OOB) -> Panic(0x32).
    r = await eq('at inner OOB (1,1)', call3('at(uint256[][],uint256,uint256)', m, 1n, 1n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
    // inner OOB on an empty inner: m[0] of [[],...] -> any j Panics.
    await eq('at inner OOB empty (0,0)', call3('at(uint256[][],uint256,uint256)', [[], [1n]], 0n, 0n));
  });

  it('m.length and m[i].length', async () => {
    const m = [[1n, 2n, 3n], [4n], [5n, 6n]];
    let r = await eq('outerLen', call1('outerLen(uint256[][])', m));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    r = await eq('outerLen []', call1('outerLen(uint256[][])', []));
    expect(decodeUint(r.j.returnHex)).toBe(0n);

    r = await eq('innerLen i=0', call2('innerLen(uint256[][],uint256)', m, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    r = await eq('innerLen i=1', call2('innerLen(uint256[][],uint256)', m, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    r = await eq('innerLen i=2', call2('innerLen(uint256[][],uint256)', m, 2n));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    // m[i].length with i OOB -> Panic(0x32).
    r = await eq('innerLen OOB i=3', call2('innerLen(uint256[][],uint256)', m, 3n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
  });

  it('u8 element validation: > 255 -> EMPTY on read', async () => {
    // Build a u8[][] region whose inner element word is 256 (dirty for uint8). The
    // m[i][j] read must validate it -> EMPTY revert, matching solc.
    // region: [outerLen=1][off0=0x20][innerLen=1][elem=256]
    const region = pad(1n) + pad(0x20n) + pad(1n) + pad(256n);
    const data = '0x' + sel('at8(uint8[][],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(0n) + region;
    const r = await eq('at8 dirty elem 256 -> empty', data);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // exactly 255 is OK.
    const okRegion = pad(1n) + pad(0x20n) + pad(1n) + pad(255n);
    const okData = '0x' + sel('at8(uint8[][],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(0n) + okRegion;
    const ro = await eq('at8 elem 255 -> ok', okData);
    expect(decodeUint(ro.j.returnHex)).toBe(255n);
  });

  it('malformed: bad outer offset / bad inner offset / truncation -> EMPTY revert', async () => {
    // outer offset points past calldata.
    let r = await eq('outerLen bad outer offset', '0x' + sel('outerLen(uint256[][])') + pad(0x1000n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // declares outerLen=3 but only 1 pointer word present (truncated pointer table).
    const trunc = '0x' + sel('outerLen(uint256[][])') + pad(0x20n) + pad(3n) + pad(0x60n);
    r = await eq('outerLen truncated table', trunc);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // outerLen=1, inner pointer points past calldata -> EMPTY on the m[i][j] read.
    const badInnerOff =
      '0x' + sel('at(uint256[][],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(0n) + pad(1n) + pad(0x1000n);
    r = await eq('at bad inner offset', badInnerOff);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // outerLen=1, valid inner pointer (0x20) but innerLen implies elements past
    // calldatasize (declares innerLen=4 with no element words).
    const badPayload =
      '0x' + sel('at(uint256[][],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(0n) + pad(1n) + pad(0x20n) + pad(4n);
    r = await eq('at inner payload past end', badPayload);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // inner offsets relative to the WRONG base (calldata byte 0): a too-large pointer
    // -> length word OOB -> EMPTY.
    const wrongBase =
      '0x' + sel('at(uint256[][],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(0n) + pad(1n) + pad(0x100n);
    r = await eq('at wrong-base inner offset', wrongBase);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('overlapping inner offsets accepted (pure pointer arithmetic, no order checks)', async () => {
    // Two outer entries whose pointer words BOTH point at the same inner array (the
    // first). solc accepts overlapping/non-canonical pointers; both reads succeed.
    // region: [outerLen=2][offA][offB][innerLen=2][7][8]  with offA=offB=0x40.
    const region = pad(2n) + pad(0x40n) + pad(0x40n) + pad(2n) + pad(7n) + pad(8n);
    let r = await eq(
      'at overlap (1,0)->first',
      '0x' + sel('at(uint256[][],uint256,uint256)') + pad(0x60n) + pad(1n) + pad(0n) + region,
    );
    expect(decodeUint(r.j.returnHex)).toBe(7n);
    r = await eq(
      'at overlap (0,1)->first',
      '0x' + sel('at(uint256[][],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(1n) + region,
    );
    expect(decodeUint(r.j.returnHex)).toBe(8n);
    // echo of an overlapping/aliased value still matches solc byte-for-byte (solc
    // re-canonicalizes the layout on re-encode).
    await eq('echo overlap', '0x' + sel('echo(uint256[][])') + pad(0x20n) + region);
  });
});
