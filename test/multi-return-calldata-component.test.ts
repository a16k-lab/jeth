// Tier-1 (JETH213): a whole DYNAMIC calldata param (calldata array / dynamic struct) as a
// component of a multi-value return — `return [xs, n]` / `return [d, n]` — echoed via the
// recursive calldata encoder (offset + tail, value arrays cleaned / others validated). Byte-
// identical to solc, including dirty-input revert parity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const encStr = (s: string) => { const h = Buffer.from(s, 'utf8').toString('hex'); return pad(BigInt(h.length / 2)) + h.padEnd(Math.ceil(h.length / 64) * 64, '0'); };
const encU256Arr = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');
const encStrArr = (ss: string[]) => {
  const elems = ss.map(encStr);
  let off = ss.length * 32; const offs: string[] = [];
  for (const e of elems) { offs.push(pad(BigInt(off))); off += e.length / 2; }
  return pad(BigInt(ss.length)) + offs.join('') + elems.join('');
};
const encD = (a: bigint, s: string) => pad(a) + pad(0x40n) + encStr(s);

const JETH = `@struct class D { a: u256; s: string; }
@contract class C {
  @external @pure arrFirst(xs: u256[]): [u256[], u256] { return [xs, 5n]; }
  @external @pure arrSecond(ss: string[]): [u256, string[]] { return [3n, ss]; }
  @external @pure structFirst(d: D): [D, u256] { return [d, 9n]; }
  @external @pure two(b: bytes, xs: u256[]): [bytes, u256[]] { return [b, xs]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct D { uint256 a; string s; }
  function arrFirst(uint256[] calldata xs) external pure returns (uint256[] memory, uint256) { return (xs, 5); }
  function arrSecond(string[] calldata ss) external pure returns (uint256, string[] memory) { return (3, ss); }
  function structFirst(D calldata d) external pure returns (D memory, uint256) { return (d, 9); }
  function two(bytes calldata b, uint256[] calldata xs) external pure returns (bytes memory, uint256[] memory) { return (b, xs); }
}`;

describe('calldata-aggregate component in multi-value return (JETH213) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('calldata array / dynamic-struct components (various sizes)', async () => {
    for (const xs of [[], [1n], [1n, 2n, 3n], [M - 1n, 0n, 42n]] as const) {
      await eq(`arrFirst([${xs.length}])`, '0x' + sel('arrFirst(uint256[])') + pad(0x20n) + encU256Arr([...xs]));
      await eq(`two([${xs.length}])`, '0x' + sel('two(bytes,uint256[])') + pad(0x40n) + pad(BigInt(0x40 + encStr('payload').length / 2)) + encStr('payload') + encU256Arr([...xs]));
    }
    for (const ss of [[], ['a'], ['short', 'a much longer string element exceeding thirty-two bytes here ok'], ['', '']] as const) {
      await eq(`arrSecond([${ss.length}])`, '0x' + sel('arrSecond(string[])') + pad(0x20n) + encStrArr([...ss]));
    }
    for (const [a, s] of [[7n, 'hi'], [M - 1n, 'a longer string field over thirty-two bytes for the struct'], [0n, '']] as const) {
      await eq(`structFirst`, '0x' + sel('structFirst((uint256,string))') + pad(0x20n) + encD(a, s));
    }
  });
});
