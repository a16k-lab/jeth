// Tier-1 (JETH074): ternary over a STATIC struct / fixed array `c ? this.x : this.y`,
// materialized to a memory image and selected by pointer (short-circuit). Covers struct/array
// local + return + field read + a constructor branch. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

const JETH = `type P = { a: u256; b: u8; c: address; };
class C {
  x: P; y: P;
  ax: Arr<u256,3>; ay: Arr<u256,3>;
  seed(): External<void> {
    this.x = P(11n, 22n, address(0xa1n)); this.y = P(33n, 44n, address(0xb2n));
    this.ax[0n] = 1n; this.ax[1n] = 2n; this.ax[2n] = 3n;
    this.ay[0n] = 7n; this.ay[1n] = 8n; this.ay[2n] = 9n;
  }
  get pickField(c: bool): External<u256> { let p: P = c ? this.x : this.y; return p.a; }
  get pickStruct(c: bool): External<P> { return c ? this.x : this.y; }
  get pickStructLocal(c: bool): External<P> { let p: P = c ? this.x : this.y; return p; }
  get pickArr(c: bool): External<Arr<u256,3>> { return c ? this.ax : this.ay; }
  get pickArrLocal(c: bool): External<Arr<u256,3>> { let a: Arr<u256,3> = c ? this.ax : this.ay; return a; }
  get pickCtor(c: bool, v: u256): External<P> { let p: P = c ? this.x : P(v, 5n, address(0xc3n)); return p; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; address c; }
  P x; P y;
  uint256[3] ax; uint256[3] ay;
  function seed() external {
    x = P(11, 22, address(0xa1)); y = P(33, 44, address(0xb2));
    ax[0]=1; ax[1]=2; ax[2]=3; ay[0]=7; ay[1]=8; ay[2]=9;
  }
  function pickField(bool c) external view returns (uint256) { P memory p = c ? x : y; return p.a; }
  function pickStruct(bool c) external view returns (P memory) { return c ? x : y; }
  function pickStructLocal(bool c) external view returns (P memory) { P memory p = c ? x : y; return p; }
  function pickArr(bool c) external view returns (uint256[3] memory) { return c ? ax : ay; }
  function pickArrLocal(bool c) external view returns (uint256[3] memory) { uint256[3] memory a = c ? ax : ay; return a; }
  function pickCtor(bool c, uint256 v) external view returns (P memory) { P memory p = c ? x : P(v, 5, address(0xc3)); return p; }
}`;

describe('ternary over a static struct / fixed array (JETH074) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
    await jeth.call(aj, encodeCall(sel('seed()'), []));
    await sol.call(as, encodeCall(sel('seed()'), []));
  });

  it('struct / fixed-array ternary (both directions) + field read + ctor branch', async () => {
    for (const c of [1n, 0n]) {
      await eq(`pickField(${c})`, encodeCall(sel('pickField(bool)'), [c]));
      await eq(`pickStruct(${c})`, encodeCall(sel('pickStruct(bool)'), [c]));
      await eq(`pickStructLocal(${c})`, encodeCall(sel('pickStructLocal(bool)'), [c]));
      await eq(`pickArr(${c})`, encodeCall(sel('pickArr(bool)'), [c]));
      await eq(`pickArrLocal(${c})`, encodeCall(sel('pickArrLocal(bool)'), [c]));
      await eq(`pickCtor(${c})`, encodeCall(sel('pickCtor(bool,uint256)'), [c, 0x999n]));
    }
  });
});
