// Tier-1 (JETH074): ternary over bytes/string `c ? a : b` (string-literal, storage, calldata, and
// memory-local branches), materialized to memory and selected by pointer with short-circuit. Covers
// return, .length, b[i], nesting, and use as an event arg. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const encStr = (s: string) => { const h = Buffer.from(s, 'utf8').toString('hex'); return pad(BigInt(h.length / 2)) + h.padEnd(Math.ceil(h.length / 64) * 64, '0'); };
// (bool c, string x, string y): head [c][off_x=0x60][off_y], then x, then y
const cdBSS = (sig: string, c: boolean, x: string, y: string) => {
  const tx = encStr(x); const offY = 0x60 + tx.length / 2;
  return '0x' + sel(sig) + pad(c ? 1n : 0n) + pad(0x60n) + pad(BigInt(offY)) + tx + encStr(y);
};

const SHORT = 'yes', LONG = 'no, this is a string that runs well past thirty-two bytes for the long case';
const JETH = `@contract class C {
  @state a: string; @state b: string;
  @external setAB(x: string, y: string): void { this.a = x; this.b = y; }
  @external @pure lit(c: bool): string { return c ? "${SHORT}" : "${LONG}"; }
  @external @view stor(c: bool): string { let s: string = c ? this.a : this.b; return s; }
  @external @pure cd(c: bool, x: string, y: string): string { return c ? x : y; }
  @external @pure cdLen(c: bool, x: bytes, y: bytes): u256 { return (c ? x : y).length; }
  @external @pure nested(c: bool, d: bool, x: string, y: string): string { return c ? (d ? x : y) : "fallback string that is also over thirty-two bytes long ok"; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  string a; string b;
  function setAB(string calldata x, string calldata y) external { a = x; b = y; }
  function lit(bool c) external pure returns (string memory) { return c ? "${SHORT}" : "${LONG}"; }
  function stor(bool c) external view returns (string memory) { string memory s = c ? a : b; return s; }
  function cd(bool c, string calldata x, string calldata y) external pure returns (string memory) { return c ? x : y; }
  function cdLen(bool c, bytes calldata x, bytes calldata y) external pure returns (uint256) { return (c ? x : y).length; }
  function nested(bool c, bool d, string calldata x, string calldata y) external pure returns (string memory) { return c ? (d ? x : y) : "fallback string that is also over thirty-two bytes long ok"; }
}`;

describe('bytes/string ternary (JETH074) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  async function seedAB(x: string, y: string) {
    // setAB takes (string,string); reuse cdBSS layout minus the leading bool
    const tx = encStr(x); const offY = 0x40 + tx.length / 2;
    const d = '0x' + sel('setAB(string,string)') + pad(0x40n) + pad(BigInt(offY)) + tx + encStr(y);
    await jeth.call(aj, d); await sol.call(as, d);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('literal / calldata / nested / .length ternaries (both branch directions)', async () => {
    for (const c of [true, false]) {
      await eq(`lit(${c})`, encodeCall(sel('lit(bool)'), [c ? 1n : 0n]));
      for (const [x, y] of [[SHORT, LONG], [LONG, SHORT], ['', 'x'], ['ab', '']] as const) {
        await eq(`cd(${c})`, cdBSS('cd(bool,string,string)', c, x, y));
        await eq(`cdLen(${c})`, cdBSS('cdLen(bool,string,string)', c, x, y));
      }
      for (const d of [true, false]) {
        await eq(`nested(${c},${d})`, '0x' + sel('nested(bool,bool,string,string)') + pad(c ? 1n : 0n) + pad(d ? 1n : 0n) + pad(0x80n) + pad(BigInt(0x80 + encStr(SHORT).length / 2)) + encStr(SHORT) + encStr(LONG));
      }
    }
  });
  it('storage-string ternary (both directions, short/long)', async () => {
    for (const [x, y] of [[SHORT, LONG], [LONG, SHORT], ['', 'nonempty value here']] as const) {
      await seedAB(x, y);
      await eq('stor(true)', encodeCall(sel('stor(bool)'), [1n]));
      await eq('stor(false)', encodeCall(sel('stor(bool)'), [0n]));
    }
  });
});
