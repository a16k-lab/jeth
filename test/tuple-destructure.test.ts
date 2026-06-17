// Tier-1: tuple destructuring (JETH062/067) + multi-value internal calls (JETH241/243).
//   let [a, , c] = this.f();   [a, b] = this.f();   let [a, b] = [x, y];   [a, b] = [b, a];
// Sources: a multi-value internal call (value return components) or a tuple literal; targets:
// new locals, existing value lvalues (incl. storage), or skipped. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

const JETH = `@contract class C {
  @state x: u256;
  @state y: u256;
  @internal @pure two(): [u256, u256] { return [11n, 22n]; }
  @internal @pure three(): [u256, u256, u256] { return [1n, 2n, 3n]; }
  @internal @pure mix(): [u256, bool, u8] { return [7n, true, 5n]; }
  @internal @pure addsub(a: u256, b: u256): [u256, u256] { return [a + b, a - b]; }
  @external @pure declCall(): u256 { let [a, b] = this.two(); return a * 1000n + b; }
  @external @pure assignCall(): u256 { let a: u256 = 0n; let b: u256 = 0n; [a, b] = this.two(); return a * 1000n + b; }
  @external @pure skipCall(): u256 { let [a, , c] = this.three(); return a * 1000n + c; }
  @external @pure mixed(): u256 { let [a, f, c] = this.mix(); return f ? (a * 1000n + u256(c)) : 0n; }
  @external @pure callArgs(p: u256, q: u256): u256 { let [s, d] = this.addsub(p, q); return s * 1000000n + d; }
  @external @pure declTuple(p: u256, q: u256): u256 { let [a, b] = [p, q]; return a * 1000000n + b; }
  @external @pure swapLocal(p: u256, q: u256): u256 { let a: u256 = p; let b: u256 = q; [a, b] = [b, a]; return a * 1000000n + b; }
  @external swapState(p: u256, q: u256): u256 { this.x = p; this.y = q; [this.x, this.y] = [this.y, this.x]; return this.x * 1000000n + this.y; }
  @external mixedTargets(): u256 { let b: u256 = 0n; [this.x, b] = this.two(); return this.x * 1000n + b; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256 x; uint256 y;
  function two() internal pure returns (uint256, uint256) { return (11, 22); }
  function three() internal pure returns (uint256, uint256, uint256) { return (1, 2, 3); }
  function mix() internal pure returns (uint256, bool, uint8) { return (7, true, 5); }
  function addsub(uint256 a, uint256 b) internal pure returns (uint256, uint256) { return (a + b, a - b); }
  function declCall() external pure returns (uint256) { (uint256 a, uint256 b) = two(); return a * 1000 + b; }
  function assignCall() external pure returns (uint256) { uint256 a = 0; uint256 b = 0; (a, b) = two(); return a * 1000 + b; }
  function skipCall() external pure returns (uint256) { (uint256 a, , uint256 c) = three(); return a * 1000 + c; }
  function mixed() external pure returns (uint256) { (uint256 a, bool f, uint8 c) = mix(); return f ? (a * 1000 + uint256(c)) : 0; }
  function callArgs(uint256 p, uint256 q) external pure returns (uint256) { (uint256 s, uint256 d) = addsub(p, q); return s * 1000000 + d; }
  function declTuple(uint256 p, uint256 q) external pure returns (uint256) { (uint256 a, uint256 b) = (p, q); return a * 1000000 + b; }
  function swapLocal(uint256 p, uint256 q) external pure returns (uint256) { uint256 a = p; uint256 b = q; (a, b) = (b, a); return a * 1000000 + b; }
  function swapState(uint256 p, uint256 q) external returns (uint256) { x = p; y = q; (x, y) = (y, x); return x * 1000000 + y; }
  function mixedTargets() external returns (uint256) { uint256 b = 0; (x, b) = two(); return x * 1000 + b; }
}`;

describe('tuple destructuring + multi-return internal calls vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
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

  it('destructure from a multi-value internal call (decl / assign / skip / mixed types / args)', async () => {
    await eq('declCall', encodeCall(sel('declCall()'), []));
    await eq('assignCall', encodeCall(sel('assignCall()'), []));
    await eq('skipCall', encodeCall(sel('skipCall()'), []));
    await eq('mixed', encodeCall(sel('mixed()'), []));
    for (const [p, q] of [[10n, 3n], [100n, 100n], [5n, 0n]] as const) {
      await eq(`callArgs(${p},${q})`, encodeCall(sel('callArgs(uint256,uint256)'), [p, q]));
    }
  });
  it('destructure from a tuple literal (decl / swap local / swap state / mixed targets)', async () => {
    for (const [p, q] of [[3n, 9n], [42n, 7n], [0n, 1n]] as const) {
      await eq(`declTuple(${p},${q})`, encodeCall(sel('declTuple(uint256,uint256)'), [p, q]));
      await eq(`swapLocal(${p},${q})`, encodeCall(sel('swapLocal(uint256,uint256)'), [p, q]));
      await eq(`swapState(${p},${q})`, encodeCall(sel('swapState(uint256,uint256)'), [p, q]));
    }
    await eq('mixedTargets', encodeCall(sel('mixedTargets()'), []));
  });
});
