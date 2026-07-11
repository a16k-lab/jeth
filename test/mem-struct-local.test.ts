// G9 (first increment): STATIC struct MEMORY locals. Construct (let p: P = P(...)), value-field
// read/write (p.x, p.x = v, p.x += v, p.x++), whole-struct return, and memory aliasing
// (let q = p; q.x = 1 mutates p). Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

const JETH = `type P = { a: u256; b: u8; c: i64; d: address; };
type Q = { x: u128; y: u128; };
class C {
  // construct + return a whole memory struct
  get mk(a: u256, b: u8, c: i64, d: address): External<P> { let p: P = P(a, b, c, d); return p; }
  // construct, mutate fields, return
  get mutate(a: u256, b: u8): External<P> {
    let p: P = P(a, b, 0n, address(0n));
    p.a = p.a + 1n; p.b = 255n; p.c = -7n; p.d = address(0x1234n);
    return p;
  }
  // compound + inc/dec on memory fields
  get ops(a: u256): External<u256> {
    let q: Q = Q(u128(a), 10n);
    q.x += 5n; q.y -= 3n; q.x++; let z: u128 = q.x--;
    return q.x * 1000000n + q.y * 1000n + z;
  }
  // read a single field
  get getB(a: u256, b: u8): External<u8> { let p: P = P(a, b, 1n, address(0n)); return p.b; }
  // memory aliasing: q = p; mutating q changes p
  get aliasing(a: u128): External<Q> { let p: Q = Q(a, a); let q: Q = p; q.x = 99n; return p; }
  // narrow/signed field cleanliness on construction + return
  get signs(c: i64): External<P> { let p: P = P(0n, 0n, c, address(0n)); return p; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; int64 c; address d; }
  struct Q { uint128 x; uint128 y; }
  function mk(uint256 a, uint8 b, int64 c, address d) external pure returns (P memory){ P memory p = P(a, b, c, d); return p; }
  function mutate(uint256 a, uint8 b) external pure returns (P memory){
    P memory p = P(a, b, 0, address(0));
    p.a = p.a + 1; p.b = 255; p.c = -7; p.d = address(0x1234);
    return p;
  }
  function ops(uint256 a) external pure returns (uint256){
    Q memory q = Q(uint128(a), 10);
    q.x += 5; q.y -= 3; q.x++; uint128 z = q.x--;
    return uint256(q.x) * 1000000 + uint256(q.y) * 1000 + uint256(z);
  }
  function getB(uint256 a, uint8 b) external pure returns (uint8){ P memory p = P(a, b, 1, address(0)); return p.b; }
  function aliasing(uint128 a) external pure returns (Q memory){ Q memory p = Q(a, a); Q memory q = p; q.x = 99; return p; }
  function signs(int64 c) external pure returns (P memory){ P memory p = P(0, 0, c, address(0)); return p; }
}`;

describe('static struct memory locals (G9) vs Solidity', () => {
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

  it('construct + return, field read', async () => {
    for (const [a, b, c, d] of [
      [1n, 2n, 3n, 0x55n],
      [M - 1n, 255n, M - 1n, 0xdeadn],
      [0n, 0n, 0n, 0n],
    ] as [bigint, bigint, bigint, bigint][]) {
      await eq(`mk(${a},${b})`, encodeCall(sel('mk(uint256,uint8,int64,address)'), [a, b, c, d]));
      await eq(`getB(${a},${b})`, encodeCall(sel('getB(uint256,uint8)'), [a, b]));
    }
  });
  it('mutate fields + signs', async () => {
    for (const a of [0n, 41n, M - 2n]) await eq(`mutate(${a})`, encodeCall(sel('mutate(uint256,uint8)'), [a, 7n]));
    for (const c of [0n, 1n, -1n, (1n << 63n) - 1n, M - (1n << 63n), -42n])
      await eq(`signs(${c})`, encodeCall(sel('signs(int64)'), [c]));
  });
  it('compound/inc-dec on memory fields', async () => {
    for (const a of [0n, 1n, 100n, 1n << 100n]) await eq(`ops(${a})`, encodeCall(sel('ops(uint256)'), [a]));
  });
  it('memory aliasing (q = p; q.x = 99 mutates p)', async () => {
    for (const a of [0n, 5n, 12345n]) await eq(`aliasing(${a})`, encodeCall(sel('aliasing(uint128)'), [a]));
  });
});
