// C2: exponentiation a ** b (checked, Panic 0x11 on overflow). C4: unchecked: { } block
// (wrapping + - * ** unary-). Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `@contract class EU {
  @external @pure powU(b: u256, e: u256): u256 { return b ** e; }
  @external @pure powU8(b: u8, e: u256): u8 { return b ** e; }
  @external @pure powI(b: i256, e: u256): i256 { return b ** e; }
  @external @pure uncheckedAdd(a: u8, b: u8): u8 { unchecked: { let r: u8 = a + b; return r; } }
  @external @pure uncheckedMul(a: u256, b: u256): u256 { unchecked: { let r: u256 = a * b; return r; } }
  @external @pure uncheckedPow(b: u8, e: u256): u8 { unchecked: { let r: u8 = b ** e; return r; } }
  @external @pure uncheckedNeg(a: i256): i256 { unchecked: { let r: i256 = -a; return r; } }
  @external @pure checkedAddReverts(a: u8, b: u8): u8 { return a + b; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract EU {
  function powU(uint256 b, uint256 e) external pure returns (uint256){ return b ** e; }
  function powU8(uint8 b, uint256 e) external pure returns (uint8){ return b ** e; }
  function powI(int256 b, uint256 e) external pure returns (int256){ return b ** e; }
  function uncheckedAdd(uint8 a, uint8 b) external pure returns (uint8){ unchecked { uint8 r = a + b; return r; } }
  function uncheckedMul(uint256 a, uint256 b) external pure returns (uint256){ unchecked { uint256 r = a * b; return r; } }
  function uncheckedPow(uint8 b, uint256 e) external pure returns (uint8){ unchecked { uint8 r = b ** e; return r; } }
  function uncheckedNeg(int256 a) external pure returns (int256){ unchecked { int256 r = -a; return r; } }
  function checkedAddReverts(uint8 a, uint8 b) external pure returns (uint8){ return a + b; }
}`;

describe('exponentiation + unchecked vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, sig: string, args: bigint[]) {
    const data = '0x' + sel(sig) + args.map(pad).join('');
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'EU.jeth' });
    const sb = compileSolidity(SOL, 'EU');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('uint ** : normal + overflow revert', async () => {
    await eq('2**10', 'powU(uint256,uint256)', [2n, 10n]);
    await eq('3**5', 'powU(uint256,uint256)', [3n, 5n]);
    await eq('0**0', 'powU(uint256,uint256)', [0n, 0n]);
    await eq('5**0', 'powU(uint256,uint256)', [5n, 0n]);
    await eq('2**256 overflow', 'powU(uint256,uint256)', [2n, 256n]);
  });
  it('u8 ** : in-range + overflow', async () => {
    await eq('2**7=128', 'powU8(uint8,uint256)', [2n, 7n]);
    await eq('2**8 overflow u8', 'powU8(uint8,uint256)', [2n, 8n]);
    await eq('3**5 overflow u8', 'powU8(uint8,uint256)', [3n, 5n]);
  });
  it('int ** : negative base', async () => {
    await eq('(-2)**3=-8', 'powI(int256,uint256)', [M - 2n, 3n]);
    await eq('(-2)**4=16', 'powI(int256,uint256)', [M - 2n, 4n]);
  });
  it('unchecked wraps where checked reverts', async () => {
    await eq('uncheckedAdd 200+100', 'uncheckedAdd(uint8,uint8)', [200n, 100n]); // wraps to 44
    await eq('checkedAdd 200+100 reverts', 'checkedAddReverts(uint8,uint8)', [200n, 100n]);
    await eq('uncheckedMul big', 'uncheckedMul(uint256,uint256)', [M - 1n, 2n]);
    await eq('uncheckedPow 2**8 wraps', 'uncheckedPow(uint8,uint256)', [2n, 8n]); // 256 -> 0
    await eq('uncheckedNeg INT_MIN', 'uncheckedNeg(int256)', [1n << 255n]);
  });
});
