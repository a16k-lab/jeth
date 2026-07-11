// Assignment used as a value-producing expression: (x = v), (x += v), chained x = y = a,
// assignment in arg / condition / return position, narrow-type masked yields, signed.
// The result of `x = v` is the assigned (LHS-typed) value. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

const JETH = `class C {
  // (x = v) yields v
  get plainEq(v: u256): External<u256> { let x: u256 = 0n; let y: u256 = (x = v) + 1n; return x * 1000n + y; }
  // (x += v) yields the new x
  get compound(a: u256, v: u256): External<u256> { let x: u256 = a; let y: u256 = (x += v) * 2n; return x * 1000000n + y; }
  // chained x = y = a (right associative): both become a, result a
  get chained(a: u256): External<u256> { let x: u256 = 0n; let y: u256 = 0n; x = y = a; return x * 1000n + y; }
  // assignment nested in a cast argument
  get asArg(v: u256): External<u256> { let x: u256 = 0n; let r: u256 = u256(u128(x = v)) + x; return r; }
  // assignment in a condition
  get inCond(v: u256): External<u256> { let x: u256 = 0n; if ((x = v) > 10n) { return x + 100n; } return x; }
  // assignment in a return
  get inReturn(v: u256): External<u256> { let x: u256 = 0n; return (x = v) + 7n; }
  // narrow-type masked yield: (x = ...) where x is u8 wraps via assignment? No - checked.
  get narrowYield(a: u8, b: u8): External<u16> { let x: u8 = a; let r: u16 = (x = b); return r; }
  // signed assignment yield
  get signedYield(v: i64): External<i256> { let x: i64 = 0n; let r: i256 = (x = v); return r; }
  // compound chain in one expression
  get multiCompound(a: u256): External<u256> { let x: u256 = a; x += 5n; let y: u256 = (x *= 2n) - (x -= 3n); return x * 1000n + y; }
  // state variable as the LHS of an expression-assignment
  s: u256;
  setVia(v: u256): External<u256> { let y: u256 = (this.s = v) + 1n; return y; }
  get getS(): External<u256> { return this.s; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function plainEq(uint256 v) external pure returns (uint256){ uint256 x = 0; uint256 y = (x = v) + 1; return x * 1000 + y; }
  function compound(uint256 a, uint256 v) external pure returns (uint256){ uint256 x = a; uint256 y = (x += v) * 2; return x * 1000000 + y; }
  function chained(uint256 a) external pure returns (uint256){ uint256 x = 0; uint256 y = 0; x = y = a; return x * 1000 + y; }
  function asArg(uint256 v) external pure returns (uint256){ uint256 x = 0; uint256 r = uint256(uint128(x = v)) + x; return r; }
  function inCond(uint256 v) external pure returns (uint256){ uint256 x = 0; if ((x = v) > 10) { return x + 100; } return x; }
  function inReturn(uint256 v) external pure returns (uint256){ uint256 x = 0; return (x = v) + 7; }
  function narrowYield(uint8 a, uint8 b) external pure returns (uint16){ uint8 x = a; uint16 r = (x = b); return r; }
  function signedYield(int64 v) external pure returns (int256){ int64 x = 0; int256 r = (x = v); return r; }
  function multiCompound(uint256 a) external pure returns (uint256){ uint256 x = a; x += 5; uint256 y = (x *= 2) - (x -= 3); return x * 1000 + y; }
  uint256 s;
  function setVia(uint256 v) external returns (uint256){ uint256 y = (s = v) + 1; return y; }
  function getS() external view returns (uint256){ return s; }
}`;

describe('assignment-as-expression vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('value/compound/chained/arg/cond/return positions', async () => {
    for (const v of [0n, 1n, 5n, 11n, 42n, 1000n]) {
      await eq(`plainEq(${v})`, encodeCall(sel('plainEq(uint256)'), [v]));
      await eq(`chained(${v})`, encodeCall(sel('chained(uint256)'), [v]));
      await eq(`asArg(${v})`, encodeCall(sel('asArg(uint256)'), [v]));
      await eq(`inCond(${v})`, encodeCall(sel('inCond(uint256)'), [v]));
      await eq(`inReturn(${v})`, encodeCall(sel('inReturn(uint256)'), [v]));
      await eq(`multiCompound(${v})`, encodeCall(sel('multiCompound(uint256)'), [v]));
      for (const a of [0n, 3n, 100n])
        await eq(`compound(${a},${v})`, encodeCall(sel('compound(uint256,uint256)'), [a, v]));
    }
  });
  it('narrow/signed masked yields', async () => {
    for (const a of [0n, 1n, 200n, 255n])
      for (const b of [0n, 7n, 128n, 255n])
        await eq(`narrowYield(${a},${b})`, encodeCall(sel('narrowYield(uint8,uint8)'), [a, b]));
    for (const v of [0n, 1n, -1n, (1n << 63n) - 1n, M - (1n << 63n), -42n])
      await eq(`signedYield(${v})`, encodeCall(sel('signedYield(int64)'), [v]));
  });
  it('state-variable expression-assignment', async () => {
    for (const v of [0n, 9n, 12345n]) {
      await eq(`setVia(${v})`, encodeCall(sel('setVia(uint256)'), [v]));
      await eq(`getS after ${v}`, encodeCall(sel('getS()'), []));
    }
  });
});
