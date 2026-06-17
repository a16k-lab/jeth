// Internal/private/public function calls (G8): value + void returns, recursion, mutual
// recursion, nested calls, state read/write propagation, and arg evaluation order.
// Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

const JETH = `@contract class C {
  @state acc: u256;
  @state log: u256;
  @internal @pure add(a: u256, b: u256): u256 { return a + b; }
  @private @pure mul3(a: u256, b: u256, c: u256): u256 { return this.add(a, b) * c; }
  @external @pure sum3(a: u256, b: u256, c: u256): u256 { return this.add(this.add(a, b), c); }
  @external @pure poly(a: u256, b: u256, c: u256): u256 { return this.mul3(a, b, c) + this.add(a, c); }
  @internal @pure fib(n: u256): u256 { if (n < 2n) { return n; } return this.fib(n - 1n) + this.fib(n - 2n); }
  @external @pure fibE(n: u256): u256 { return this.fib(n); }
  @internal @pure isEven(n: u256): bool { if (n == 0n) { return true; } return this.isOdd(n - 1n); }
  @internal @pure isOdd(n: u256): bool { if (n == 0n) { return false; } return this.isEven(n - 1n); }
  @external @pure evenE(n: u256): bool { return this.isEven(n); }
  // void helper writing state -> caller is non-view (nonpayable)
  @internal bump(by: u256): void { this.acc = this.acc + by; }
  @external doBump(x: u256): void { this.bump(x); this.bump(x); }
  @view getAcc(): u256 { return this.acc; }
  // internal view reading state -> external view caller
  @view readAcc(): u256 { return this.acc; }
  @view doubleAcc(): u256 { return this.add(this.readAcc(), this.readAcc()); }
  // signed + narrow args/returns
  @internal @pure clampNeg(x: i64): i64 { if (x < 0n) { return 0n; } return x; }
  @external @pure clampE(x: i64): i64 { return this.clampNeg(x); }
  // arg with a side effect (left-to-right arg order)
  @external @pure argOrder(): u256 { let s: u256 = 0n; return this.sub2((s = s * 10n + 1n), (s = s * 10n + 2n)) * 1000n + s; }
  @internal @pure sub2(a: u256, b: u256): u256 { return a * 100n + b; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256 acc;
  uint256 log;
  function add(uint256 a, uint256 b) internal pure returns (uint256){ return a + b; }
  function mul3(uint256 a, uint256 b, uint256 c) private pure returns (uint256){ return add(a, b) * c; }
  function sum3(uint256 a, uint256 b, uint256 c) external pure returns (uint256){ return add(add(a, b), c); }
  function poly(uint256 a, uint256 b, uint256 c) external pure returns (uint256){ return mul3(a, b, c) + add(a, c); }
  function fib(uint256 n) internal pure returns (uint256){ if (n < 2) { return n; } return fib(n - 1) + fib(n - 2); }
  function fibE(uint256 n) external pure returns (uint256){ return fib(n); }
  function isEven(uint256 n) internal pure returns (bool){ if (n == 0) { return true; } return isOdd(n - 1); }
  function isOdd(uint256 n) internal pure returns (bool){ if (n == 0) { return false; } return isEven(n - 1); }
  function evenE(uint256 n) external pure returns (bool){ return isEven(n); }
  function bump(uint256 by) internal { acc = acc + by; }
  function doBump(uint256 x) external { bump(x); bump(x); }
  function getAcc() external view returns (uint256){ return acc; }
  function readAcc() internal view returns (uint256){ return acc; }
  function doubleAcc() external view returns (uint256){ return add(readAcc(), readAcc()); }
  function clampNeg(int64 x) internal pure returns (int64){ if (x < 0) { return 0; } return x; }
  function clampE(int64 x) external pure returns (int64){ return clampNeg(x); }
  function argOrder() external pure returns (uint256){ uint256 s = 0; return sub2((s = s * 10 + 1), (s = s * 10 + 2)) * 1000 + s; }
  function sub2(uint256 a, uint256 b) internal pure returns (uint256){ return a * 100 + b; }
}`;

describe('internal function calls vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function send(data: string) { const j = await jeth.call(aj, data); const s = await sol.call(as, data); expect(j.success, `${j.exceptionError}`).toBe(s.success); }
  async function eq(label: string, data: string) {
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

  it('value-returning helpers, nesting, recursion', async () => {
    for (const a of [0n, 1n, 7n, 1000n]) for (const b of [0n, 2n, 50n]) {
      await eq(`sum3(${a},${b},3)`, encodeCall(sel('sum3(uint256,uint256,uint256)'), [a, b, 3n]));
      await eq(`poly(${a},${b},4)`, encodeCall(sel('poly(uint256,uint256,uint256)'), [a, b, 4n]));
    }
    for (const n of [0n, 1n, 2n, 5n, 10n, 15n]) await eq(`fibE(${n})`, encodeCall(sel('fibE(uint256)'), [n]));
    for (const n of [0n, 1n, 2n, 7n, 20n]) await eq(`evenE(${n})`, encodeCall(sel('evenE(uint256)'), [n]));
  });
  it('signed clamp + arg order', async () => {
    for (const x of [-100n, -1n, 0n, 1n, 1000n]) await eq(`clampE(${x})`, encodeCall(sel('clampE(int64)'), [x]));
    await eq('argOrder', encodeCall(sel('argOrder()'), []));
  });
  it('state write/read propagation through internal calls', async () => {
    for (const x of [3n, 10n]) await send(encodeCall(sel('doBump(uint256)'), [x]));
    await eq('getAcc', encodeCall(sel('getAcc()'), []));
    await eq('doubleAcc', encodeCall(sel('doubleAcc()'), []));
  });
});
