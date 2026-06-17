// G5: returning a whole STATIC struct / fixed-array calldata parameter unchanged
// (echo). Inline re-encode via the recursive calldata codec; dirty narrow leaves
// validate exactly like solc. Byte-identical. Static-aggregate calldata is just the
// selector followed by flat inline words, so we hand-craft it directly.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const w = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const call = (sig: string, words: bigint[]) => sel(sig) + words.map(w).join('');

const JETH = `@struct class P { a: u256; b: u8; c: address; }
@contract class C {
  @external @pure echo2(a: Arr<Arr<u256, 2>, 2>): Arr<Arr<u256, 2>, 2> { return a; }
  @external @pure echo3(a: Arr<Arr<Arr<u256, 2>, 2>, 2>): Arr<Arr<Arr<u256, 2>, 2>, 2> { return a; }
  @external @pure echoPacked(a: Arr<Arr<u8, 4>, 3>): Arr<Arr<u8, 4>, 3> { return a; }
  @external @pure echoStruct(p: P): P { return p; }
  @external @pure echoStructArr(a: Arr<P, 2>): Arr<P, 2> { return a; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; address c; }
  function echo2(uint256[2][2] calldata a) external pure returns (uint256[2][2] memory){ return a; }
  function echo3(uint256[2][2][2] calldata a) external pure returns (uint256[2][2][2] memory){ return a; }
  function echoPacked(uint8[4][3] calldata a) external pure returns (uint8[4][3] memory){ return a; }
  function echoStruct(P calldata p) external pure returns (P memory){ return p; }
  function echoStructArr(P[2] calldata a) external pure returns (P[2] memory){ return a; }
}`;

describe('whole static-aggregate calldata param echo (G5) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eqRaw(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('echo2 / echo3 (nested fixed value arrays)', async () => {
    await eqRaw('echo2', call('echo2(uint256[2][2])', [1n, 2n, 3n, 4n]));
    await eqRaw('echo3', call('echo3(uint256[2][2][2])', [10n, 11n, 12n, 13n, 20n, 21n, 22n, 23n]));
  });
  it('echoPacked (uint8[4][3], 12 inline words)', async () => {
    await eqRaw('echoPacked', call('echoPacked(uint8[4][3])', [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n]));
  });
  it('echoStruct / echoStructArr', async () => {
    await eqRaw('echoStruct', call('echoStruct((uint256,uint8,address))', [42n, 7n, 0x1234n]));
    await eqRaw('echoStructArr', call('echoStructArr((uint256,uint8,address)[2])', [1n, 2n, 0xaaaan, 3n, 4n, 0xbbbbn]));
  });
  it('dirty narrow leaf: non-canonical uint8 / address reverts like solc', async () => {
    const clean = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n];
    await eqRaw('echoPacked clean', call('echoPacked(uint8[4][3])', clean));
    const d0 = [...clean]; d0[0] = (1n << 255n) | 5n;
    await eqRaw('echoPacked dirty[0]', call('echoPacked(uint8[4][3])', d0));
    const d7 = [...clean]; d7[7] = (0xffn << 8n) | 9n;
    await eqRaw('echoPacked dirty[7]', call('echoPacked(uint8[4][3])', d7));
    // dirty address high bits on echoStruct.c (word 2, address is 160-bit)
    const ds = [42n, 7n, (1n << 200n) | 0x1234n];
    await eqRaw('echoStruct dirty addr', call('echoStruct((uint256,uint8,address))', ds));
    // dirty uint8 field b (word 1)
    const db = [42n, (1n << 9n) | 7n, 0x1234n];
    await eqRaw('echoStruct dirty b', call('echoStruct((uint256,uint8,address))', db));
  });
});
