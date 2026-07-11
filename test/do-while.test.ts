// do { } while (cond): body runs at least once; continue re-evaluates the condition;
// break exits; condition can be false on entry (still runs once). Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

const JETH = `class C {
  // runs body once even when cond is false on entry
  get runsOnce(n: u256): External<u256> { let c: u256 = 0n; do { c = c + 1n; } while (c < n); return c; }
  // sum 1..n via do-while
  get sumTo(n: u256): External<u256> { let s: u256 = 0n; let i: u256 = 0n; do { i = i + 1n; s = s + i; } while (i < n); return s; }
  // continue must jump to the condition check (skip rest of body, still re-test)
  get skipEvens(n: u256): External<u256> {
    let s: u256 = 0n; let i: u256 = 0n;
    do { i = i + 1n; if (i % 2n == 0n) { continue; } s = s + i; } while (i < n);
    return s;
  }
  // break exits immediately
  get breakAt(n: u256, lim: u256): External<u256> {
    let i: u256 = 0n;
    do { i = i + 1n; if (i == lim) { break; } } while (i < n);
    return i;
  }
  // nested do-while with break/continue in inner loop
  get grid(a: u256, b: u256): External<u256> {
    let total: u256 = 0n; let i: u256 = 0n;
    do {
      i = i + 1n; let j: u256 = 0n;
      do { j = j + 1n; if (j == 3n) { continue; } total = total + i * j; } while (j < b);
    } while (i < a);
    return total;
  }
  // a do-while that mutates state (condition reads state too)
  acc: u256;
  pump(steps: u256): External<void> { let k: u256 = 0n; do { this.acc = this.acc + k; k = k + 1n; } while (k < steps); }
  get getAcc(): External<u256> { return this.acc; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function runsOnce(uint256 n) external pure returns (uint256){ uint256 c = 0; do { c = c + 1; } while (c < n); return c; }
  function sumTo(uint256 n) external pure returns (uint256){ uint256 s = 0; uint256 i = 0; do { i = i + 1; s = s + i; } while (i < n); return s; }
  function skipEvens(uint256 n) external pure returns (uint256){
    uint256 s = 0; uint256 i = 0;
    do { i = i + 1; if (i % 2 == 0) { continue; } s = s + i; } while (i < n);
    return s;
  }
  function breakAt(uint256 n, uint256 lim) external pure returns (uint256){
    uint256 i = 0;
    do { i = i + 1; if (i == lim) { break; } } while (i < n);
    return i;
  }
  function grid(uint256 a, uint256 b) external pure returns (uint256){
    uint256 total = 0; uint256 i = 0;
    do {
      i = i + 1; uint256 j = 0;
      do { j = j + 1; if (j == 3) { continue; } total = total + i * j; } while (j < b);
    } while (i < a);
    return total;
  }
  uint256 acc;
  function pump(uint256 steps) external { uint256 k = 0; do { acc = acc + k; k = k + 1; } while (k < steps); }
  function getAcc() external view returns (uint256){ return acc; }
}`;

describe('do-while vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${j.exceptionError}`).toBe(s.success);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runsOnce / sumTo / skipEvens / breakAt over many n', async () => {
    for (const n of [0n, 1n, 2n, 3n, 5n, 8n, 13n, 20n]) {
      await eq(`runsOnce(${n})`, encodeCall(sel('runsOnce(uint256)'), [n]));
      await eq(`sumTo(${n})`, encodeCall(sel('sumTo(uint256)'), [n]));
      await eq(`skipEvens(${n})`, encodeCall(sel('skipEvens(uint256)'), [n]));
      for (const lim of [0n, 1n, 3n, 5n, 100n])
        await eq(`breakAt(${n},${lim})`, encodeCall(sel('breakAt(uint256,uint256)'), [n, lim]));
    }
  });
  it('nested grid', async () => {
    for (const a of [1n, 2n, 4n])
      for (const b of [1n, 2n, 3n, 5n]) await eq(`grid(${a},${b})`, encodeCall(sel('grid(uint256,uint256)'), [a, b]));
  });
  it('stateful pump', async () => {
    for (const s of [1n, 2n, 4n]) await send(encodeCall(sel('pump(uint256)'), [s]));
    await eq('getAcc', encodeCall(sel('getAcc()'), []));
  });
});
