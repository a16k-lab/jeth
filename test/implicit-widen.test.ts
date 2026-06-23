// B1: implicit widening conversions (uintN->uintM, intN->intM, bytesN->bytesM, M>=N) and
// mixed-width arithmetic/comparison, Solidity-identical. Narrowing / uint<->int still need
// an explicit cast (compile error here).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
function diags(src: string): string[] {
  try {
    compile(src, { fileName: 'W.jeth' });
    return [];
  } catch (e: any) {
    return (e.diagnostics ?? e.items ?? []).map((d: any) => d.code);
  }
}

const JETH = `@contract class W {
  @external @pure widenU(a: u8, b: u256): u256 { return a + b; }
  @external @pure widenAssign(a: u16): u256 { let x: u256 = a; return x; }
  @external @pure widenI(a: i8, b: i256): i256 { return a + b; }
  @external @pure cmpMixed(a: u8, b: u256): bool { return a < b; }
  @external @pure widenBytes(a: bytes4): bytes32 { return a; }
  @external @pure widenU8toU64(a: u8): u64 { return a; }
  @external @pure negWiden(a: i8): i256 { return a; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract W {
  function widenU(uint8 a, uint256 b) external pure returns (uint256){ return a + b; }
  function widenAssign(uint16 a) external pure returns (uint256){ uint256 x = a; return x; }
  function widenI(int8 a, int256 b) external pure returns (int256){ return int256(a) + b; }
  function cmpMixed(uint8 a, uint256 b) external pure returns (bool){ return a < b; }
  function widenBytes(bytes4 a) external pure returns (bytes32){ return a; }
  function widenU8toU64(uint8 a) external pure returns (uint64){ return a; }
  function negWiden(int8 a) external pure returns (int256){ return a; }
}`;

const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

describe('implicit widening vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'W.jeth' });
    const sb = compileSolidity(SOL, 'W');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('mixed-width uint add: a(u8) + b(u256)', async () => {
    await eq('widenU', '0x' + sel('widenU(uint8,uint256)') + pad(200n) + pad(1000n));
    await eq('widenU max', '0x' + sel('widenU(uint8,uint256)') + pad(255n) + pad(M - 1n)); // overflow -> both revert
  });
  it('widen on assignment u16 -> u256', async () => {
    await eq('widenAssign', '0x' + sel('widenAssign(uint16)') + pad(0xabcdn));
  });
  it('mixed-width int add: a(i8) + b(i256), negative', async () => {
    await eq('widenI -5 + 100', '0x' + sel('widenI(int8,int256)') + pad(M - 5n) + pad(100n));
    await eq('widenI -1 + -1', '0x' + sel('widenI(int8,int256)') + pad(M - 1n) + pad(M - 1n));
  });
  it('mixed-width comparison u8 < u256', async () => {
    await eq('cmp 5<1000', '0x' + sel('cmpMixed(uint8,uint256)') + pad(5n) + pad(1000n));
    await eq('cmp 200<10', '0x' + sel('cmpMixed(uint8,uint256)') + pad(200n) + pad(10n));
  });
  it('bytes widening bytes4 -> bytes32 (left-aligned)', async () => {
    await eq('widenBytes', '0x' + sel('widenBytes(bytes4)') + 'deadbeef'.padEnd(64, '0'));
  });
  it('uint widening u8 -> u64 and int sign-extend i8 -> i256', async () => {
    await eq('widenU8toU64', '0x' + sel('widenU8toU64(uint8)') + pad(0xffn));
    await eq('negWiden -1', '0x' + sel('negWiden(int8)') + pad(M - 1n));
  });

  it('narrowing and uint<->int mixes are still rejected (need explicit cast)', () => {
    expect(diags('@contract class W { @external @pure f(a: u256): u8 { return a; } }')).toContain('JETH085');
    expect(diags('@contract class W { @external @pure f(a: u8, b: i8): bool { return a < b; } }')).toContain('JETH083');
    expect(diags('@contract class W { @external @pure f(a: bytes32): bytes4 { return a; } }')).toContain('JETH085');
  });
});
