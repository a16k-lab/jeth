// C8: multi-value return `f(): [T1, T2, ...]` with `return [a, b]`. Value + bytes/string
// components (static head + dynamic head/tail, no outer wrapper). Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const A = BigInt('0x' + '11'.repeat(20));

const JETH = `@contract class MR {
  @external @pure two(a: u256, b: u256): [u256, u256] { return [a, b]; }
  @external @pure mixed(a: u256, b: address, c: bool): [u256, address, bool] { return [a, b, c]; }
  @external @pure swap(a: u256, b: u256): [u256, u256] { return [b, a]; }
  @external @pure withStr(n: u256, s: string): [u256, string] { return [n, s]; }
  @external @pure twoStr(a: string, b: string): [string, string] { return [a, b]; }
  @external @pure strBetween(a: string, n: u256, b: string): [string, u256, string] { return [a, n, b]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MR {
  function two(uint256 a, uint256 b) external pure returns (uint256, uint256){ return (a, b); }
  function mixed(uint256 a, address b, bool c) external pure returns (uint256, address, bool){ return (a, b, c); }
  function swap(uint256 a, uint256 b) external pure returns (uint256, uint256){ return (b, a); }
  function withStr(uint256 n, string calldata s) external pure returns (uint256, string memory){ return (n, s); }
  function twoStr(string calldata a, string calldata b) external pure returns (string memory, string memory){ return (a, b); }
  function strBetween(string calldata a, uint256 n, string calldata b) external pure returns (string memory, uint256, string memory){ return (a, n, b); }
}`;

const LONG = 'a definitely-longer-than-thirty-two-byte string for the multi-return tail test';

describe('multi-value return vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  function strArg(selSig: string, head: bigint[], strs: { at: number; s: string }[]): string {
    // build calldata: head words (with offsets for string positions), then string tails
    let h = '0x' + sel(selSig);
    h += head.map(pad).join('');
    // replace string-position head words with offsets, append tails
    const headArr = head.map(pad);
    let tailBuf = '';
    let off = head.length * 32;
    for (const { at, s } of strs) {
      headArr[at] = pad(BigInt(off));
      const b = Buffer.from(s, 'utf8');
      const nwords = Math.ceil(b.length / 32);
      let data = '';
      for (let i = 0; i < nwords; i++) data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)]).subarray(0, 32).toString('hex');
      tailBuf += pad(BigInt(b.length)) + data;
      off += 32 + nwords * 32;
    }
    return '0x' + sel(selSig) + headArr.join('') + tailBuf;
  }
  async function eqRaw(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'MR.jeth' });
    const sb = compileSolidity(SOL, 'MR');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('two value returns', async () => {
    await eqRaw('two', encodeCall(sel('two(uint256,uint256)'), [7n, 9n]));
    await eqRaw('swap', encodeCall(sel('swap(uint256,uint256)'), [7n, 9n]));
  });
  it('mixed value types (uint, address, bool)', async () => {
    await eqRaw('mixed', encodeCall(sel('mixed(uint256,address,bool)'), [42n, A, 1n]));
  });
  it('value + string (one dynamic tail)', async () => {
    await eqRaw('withStr short', strArg('withStr(uint256,string)', [5n, 0n], [{ at: 1, s: 'hi' }]));
    await eqRaw('withStr long', strArg('withStr(uint256,string)', [5n, 0n], [{ at: 1, s: LONG }]));
  });
  it('two strings (two dynamic tails)', async () => {
    await eqRaw('twoStr', strArg('twoStr(string,string)', [0n, 0n], [{ at: 0, s: 'aa' }, { at: 1, s: LONG }]));
  });
  it('string, value, string interleaved', async () => {
    await eqRaw('strBetween', strArg('strBetween(string,uint256,string)', [0n, 99n, 0n], [{ at: 0, s: LONG }, { at: 2, s: 'zz' }]));
  });
});
