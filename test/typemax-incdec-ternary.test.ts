// C5 type(T).max/.min, C6 x++/x--/++x/--x, C3 ternary c?a:b. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `class TC {
  count: u256;
  get umax(): External<u256> { return type(u256).max; }
  get u8max(): External<u8> { return type(u8).max; }
  get i8min(): External<i256> { return type(i8).min; }
  get i256max(): External<i256> { return type(i256).max; }
  inc(): External<u256> { this.count++; return this.count; }
  dec(): External<u256> { this.count--; return this.count; }
  preInc(): External<u256> { ++this.count; return this.count; }
  get localIncDec(a: u256): External<u256> { let x: u256 = a; x++; x++; x--; return x; }
  get tern(a: u256, b: u256): External<u256> { return a > b ? a : b; }
  get ternTypes(c: bool, a: u8, b: u256): External<u256> { return c ? a : b; }
  get ternShort(c: bool, a: u256): External<u256> { return c ? a + 1n : a; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TC {
  uint256 count;
  function umax() external pure returns (uint256){ return type(uint256).max; }
  function u8max() external pure returns (uint8){ return type(uint8).max; }
  function i8min() external pure returns (int256){ return type(int8).min; }
  function i256max() external pure returns (int256){ return type(int256).max; }
  function inc() external returns (uint256){ count++; return count; }
  function dec() external returns (uint256){ count--; return count; }
  function preInc() external returns (uint256){ ++count; return count; }
  function localIncDec(uint256 a) external pure returns (uint256){ uint256 x = a; x++; x++; x--; return x; }
  function tern(uint256 a, uint256 b) external pure returns (uint256){ return a > b ? a : b; }
  function ternTypes(bool c, uint8 a, uint256 b) external pure returns (uint256){ return c ? a : b; }
  function ternShort(bool c, uint256 a) external pure returns (uint256){ return c ? a + 1 : a; }
}`;

describe('type().max/min, ++/--, ternary vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, sig: string, args: bigint[] = []) {
    const data = '0x' + sel(sig) + args.map(pad).join('');
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'TC.jeth' });
    const sb = compileSolidity(SOL, 'TC');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('type(T).max/.min constants', async () => {
    await eq('umax', 'umax()');
    await eq('u8max', 'u8max()');
    await eq('i8min', 'i8min()');
    await eq('i256max', 'i256max()');
  });
  it('state ++ / -- / pre-++', async () => {
    await eq('inc', 'inc()');
    await eq('inc2', 'inc()');
    await eq('preInc', 'preInc()');
    await eq('dec', 'dec()');
  });
  it('local ++/--', async () => {
    await eq('localIncDec', 'localIncDec(uint256)', [10n]);
  });
  it('ternary value-select + mixed-width + short-circuit', async () => {
    await eq('tern 5,9', 'tern(uint256,uint256)', [5n, 9n]);
    await eq('tern 9,5', 'tern(uint256,uint256)', [9n, 5n]);
    await eq('ternTypes true', 'ternTypes(bool,uint8,uint256)', [1n, 200n, 99999n]);
    await eq('ternTypes false', 'ternTypes(bool,uint8,uint256)', [0n, 200n, 99999n]);
    await eq('ternShort true', 'ternShort(bool,uint256)', [1n, 41n]);
    await eq('ternShort overflow-branch-not-taken', 'ternShort(bool,uint256)', [0n, M - 1n]); // a+1 would overflow but not taken
  });
});
