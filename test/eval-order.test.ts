// Evaluation-order parity with solc for side-effecting subexpressions (incDec / assignExpr
// in value position). solc evaluates BINARY operands right-to-left, but argument lists
// (array literals, return tuples, event/error args) left-to-right. Byte-identical here.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

const JETH = `@contract class C {
  @event Ev(x: u256, y: u256, z: u256);
  @error Er(x: u256, y: u256);
  // binary operands: RIGHT before LEFT
  @external @pure incBin(): u256 { let x: u256 = 5n; let y: u256 = (++x) * 100n + (++x); return x * 100000n + y; }
  @external @pure compBin(a: u256): u256 { let x: u256 = a; x += 5n; let y: u256 = (x *= 2n) - (x -= 3n); return x * 1000n + y; }
  @external @pure leftMutRightRead(v: u256): u256 { let x: u256 = 0n; let r: u256 = (x = v) + x; return r; }
  @external @pure rightMutLeftRead(v: u256): u256 { let x: u256 = 0n; let r: u256 = x + (x = v); return r; }
  @external @pure nested(): u256 { let x: u256 = 0n; let r: u256 = (x = 1n) + (x = 2n) * 10n; return x * 1000n + r; }
  @external @pure postSub(): u256 { let x: u256 = 9n; unchecked: { let y: u256 = (x--) - (x--); return x * 100n + y; } }
  // argument lists: LEFT to RIGHT
  @external @pure arrLit(): u256 { let s: u256 = 0n; let xs: u256[] = [(s = s * 10n + 1n), (s = s * 10n + 2n)]; return s * 100n + xs[0n] * 10n + xs[1n]; }
  @external @pure retTuple(): [u256, u256, u256] { let s: u256 = 0n; return [(s = s * 10n + 1n), (s = s * 10n + 2n), s]; }
  @state seq: u256;
  @external emitOrd(): void { this.seq = 0n; emit(Ev((this.seq = this.seq * 10n + 1n), (this.seq = this.seq * 10n + 2n), (this.seq = this.seq * 10n + 3n))); }
  @external @view getSeq(): u256 { return this.seq; }
  @external @pure revertOrd(): void { let s: u256 = 0n; revert(Er((s = s * 10n + 1n), (s = s * 10n + 2n))); }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  event Ev(uint256 x, uint256 y, uint256 z);
  error Er(uint256 x, uint256 y);
  function incBin() external pure returns (uint256){ uint256 x = 5; uint256 y = (++x) * 100 + (++x); return x * 100000 + y; }
  function compBin(uint256 a) external pure returns (uint256){ uint256 x = a; x += 5; uint256 y = (x *= 2) - (x -= 3); return x * 1000 + y; }
  function leftMutRightRead(uint256 v) external pure returns (uint256){ uint256 x = 0; uint256 r = (x = v) + x; return r; }
  function rightMutLeftRead(uint256 v) external pure returns (uint256){ uint256 x = 0; uint256 r = x + (x = v); return r; }
  function nested() external pure returns (uint256){ uint256 x = 0; uint256 r = (x = 1) + (x = 2) * 10; return x * 1000 + r; }
  function postSub() external pure returns (uint256){ uint256 x = 9; unchecked { uint256 y = (x--) - (x--); return x * 100 + y; } }
  function arrLit() external pure returns (uint256){ uint256 s = 0; uint256[2] memory xs = [(s = s * 10 + 1), (s = s * 10 + 2)]; return s * 100 + xs[0] * 10 + xs[1]; }
  function retTuple() external pure returns (uint256, uint256, uint256){ uint256 s = 0; return ((s = s * 10 + 1), (s = s * 10 + 2), s); }
  uint256 seq;
  function emitOrd() external { seq = 0; emit Ev((seq = seq * 10 + 1), (seq = seq * 10 + 2), (seq = seq * 10 + 3)); }
  function getSeq() external view returns (uint256){ return seq; }
  function revertOrd() external pure { uint256 s = 0; revert Er((s = s * 10 + 1), (s = s * 10 + 2)); }
}`;

describe('evaluation order vs Solidity', () => {
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

  it('binary operand order (right before left)', async () => {
    await eq('incBin', encodeCall(sel('incBin()'), []));
    await eq('nested', encodeCall(sel('nested()'), []));
    await eq('postSub', encodeCall(sel('postSub()'), []));
    for (const v of [0n, 1n, 7n, 99n]) {
      await eq(`compBin(${v})`, encodeCall(sel('compBin(uint256)'), [v]));
      await eq(`leftMutRightRead(${v})`, encodeCall(sel('leftMutRightRead(uint256)'), [v]));
      await eq(`rightMutLeftRead(${v})`, encodeCall(sel('rightMutLeftRead(uint256)'), [v]));
    }
  });
  it('argument-list order (left to right)', async () => {
    await eq('arrLit', encodeCall(sel('arrLit()'), []));
    await eq('retTuple', encodeCall(sel('retTuple()'), []));
    await eq('revertOrd', encodeCall(sel('revertOrd()'), []));
    await eq('emitOrd', encodeCall(sel('emitOrd()'), []));
    await eq('getSeq', encodeCall(sel('getSeq()'), []));
  });
});
