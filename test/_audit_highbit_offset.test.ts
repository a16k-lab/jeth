// AUDIT FINDING (now FIXED): member/inner offsets with the HIGH BIT set (>= 2^255).
// On the LAZY-ACCESS path (d.s, m[i][j], a[i]) solc bounds-checks an inner/member
// dynamic offset with a SIGNED comparison, so a high-bit ("negative") offset passes
// the check; the resulting pointer is huge mod 2^256, so calldataload returns 0 ->
// length/element read as zero (NO revert). JETH's lazy-access helpers now use that
// signed form, so these are byte-identical to solc; the tests assert equality.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}
const W = (v: bigint) => pad(v);
const HB = 1n << 255n; // high bit set

const JETH = `
type D = { a: u256; s: bytes; };
class A {
  get dLen(d: D): External<u256> { return d.s.length; }
  get dGet(d: D): External<bytes> { return d.s; }
  get dByte(d: D, i: u256): External<bytes1> { return d.s[i]; }
  get mGet(m: u256[][], i: u256, j: u256): External<u256> { return m[i][j]; }
  get sElem(a: string[], i: u256): External<string> { return a[i]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct D { uint256 a; bytes s; }
  function dLen(D calldata d) external pure returns (uint256){ return d.s.length; }
  function dGet(D calldata d) external pure returns (bytes memory){ return d.s; }
  function dByte(D calldata d, uint256 i) external pure returns (bytes1){ return d.s[i]; }
  function mGet(uint256[][] calldata m, uint256 i, uint256 j) external pure returns (uint256){ return m[i][j]; }
  function sElem(string[] calldata a, uint256 i) external pure returns (string memory){ return a[i]; }
}`;

let jeth: Harness, sol: Harness, aj: Address, as: Address;
beforeAll(async () => {
  const jb = compile(JETH, { fileName: 'A.jeth' });
  const sb = compileSolidity(SOL, 'A');
  jeth = await Harness.create();
  sol = await Harness.create();
  aj = await jeth.deploy(jb.creationBytecode);
  as = await sol.deploy(sb.creation);
});

// These tests now assert BYTE-IDENTITY: JETH must match solc on success + returndata.
async function pair(label: string, data: string) {
  const j = await jeth.call(aj, data);
  const s = await sol.call(as, data);
  expect(j.success, `${label} success`).toBe(s.success);
  expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  return { j, s, label };
}

describe('high-bit member/inner offset: JETH matches solc byte-for-byte', () => {
  it('dLen: off_s = 2^255 -> 0 (lazy signed-offset wrap reads 0)', async () => {
    const data = '0x' + functionSelector('dLen((uint256,bytes))') + [W(0n), W(HB), W(0n)].join('');
    const { s } = await pair('dLen', data);
    expect(s.success).toBe(true);
    expect(s.returnHex).toBe('0x' + '00'.repeat(32));
  });

  it('dGet: off_s = 2^255 -> empty bytes', async () => {
    const data = '0x' + functionSelector('dGet((uint256,bytes))') + [W(0n), W(HB), W(0n)].join('');
    const { s } = await pair('dGet', data);
    expect(s.success).toBe(true);
    expect(s.returnHex).toBe('0x' + W(0x20n) + W(0n)); // [offset][len=0]
  });

  it('dByte: off_s = 2^255 -> Panic(0x32) (len read 0, i=0 OOB)', async () => {
    const data = '0x' + functionSelector('dByte((uint256,bytes),uint256)') + [W(0x20n), W(0n), W(HB), W(0n)].join('');
    const { s } = await pair('dByte', data);
    expect(s.success).toBe(false);
    expect(s.returnHex).toBe('0x4e487b71' + W(0x32n)); // Panic(0x32)
  });

  it('mGet: inner_off = 2^255 -> Panic(0x32)', async () => {
    // head: off_m=0x60, i=0, j=0; region @0x60: [outer_len=1][inner_off0=HB]
    const data =
      '0x' + functionSelector('mGet(uint256[][],uint256,uint256)') + [W(0x60n), W(0n), W(0n), W(1n), W(HB)].join('');
    const { s } = await pair('mGet', data);
    expect(s.success).toBe(false);
    expect(s.returnHex).toBe('0x4e487b71' + W(0x32n));
  });

  it('sElem: element offset = 2^255 -> empty string', async () => {
    // head: off_a=0x40, i=0; region @0x40: [len=1][el_off0=HB]
    const data = '0x' + functionSelector('sElem(string[],uint256)') + [W(0x40n), W(0n), W(1n), W(HB)].join('');
    const { s } = await pair('sElem', data);
    expect(s.success).toBe(true);
    expect(s.returnHex).toBe('0x' + W(0x20n) + W(0n));
  });
});
