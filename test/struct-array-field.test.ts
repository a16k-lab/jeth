// A5: a @struct with a dynamic-array field (u256[] / string[]). STORAGE: field access
// (this.s.xs.push/.length/[i]), other fields, whole-struct return. CALLDATA: whole-struct
// echo (return s). Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `type S = { a: u256; xs: u256[]; b: u256; };
type E = { a: u256; xs: u256[]; };
class SF {
  s: S;
  setA(v: u256): External<void> { this.s.a = v; }
  setB(v: u256): External<void> { this.s.b = v; }
  pushX(v: u256): External<void> { this.s.xs.push(v); }
  popX(): External<void> { this.s.xs.pop(); }
  setX(i: u256, v: u256): External<void> { this.s.xs[i] = v; }
  get xlen(): External<u256> { return this.s.xs.length; }
  get xat(i: u256): External<u256> { return this.s.xs[i]; }
  get getA(): External<u256> { return this.s.a; }
  get getS(): External<S> { return this.s; }
  get echo(e: E): External<E> { return e; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SF {
  struct S { uint256 a; uint256[] xs; uint256 b; }
  struct E { uint256 a; uint256[] xs; }
  S s;
  function setA(uint256 v) external { s.a = v; }
  function setB(uint256 v) external { s.b = v; }
  function pushX(uint256 v) external { s.xs.push(v); }
  function popX() external { s.xs.pop(); }
  function setX(uint256 i, uint256 v) external { s.xs[i] = v; }
  function xlen() external view returns (uint256){ return s.xs.length; }
  function xat(uint256 i) external view returns (uint256){ return s.xs[i]; }
  function getA() external view returns (uint256){ return s.a; }
  function getS() external view returns (S memory){ return s; }
  function echo(E calldata e) external pure returns (E memory){ return e; }
}`;

describe('struct with a dynamic-array field vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `send success (jeth err=${j.exceptionError})`).toBe(s.success);
  }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'SF.jeth' });
    const sb = compileSolidity(SOL, 'SF');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('storage: field access + array field push/pop/index/length, siblings preserved', async () => {
    await send(encodeCall(sel('setA(uint256)'), [7n]));
    await send(encodeCall(sel('setB(uint256)'), [9n]));
    await send(encodeCall(sel('pushX(uint256)'), [11n]));
    await send(encodeCall(sel('pushX(uint256)'), [22n]));
    await send(encodeCall(sel('pushX(uint256)'), [33n]));
    await eq('xlen', encodeCall(sel('xlen()'), []));
    await eq('xat[1]', encodeCall(sel('xat(uint256)'), [1n]));
    await send(encodeCall(sel('setX(uint256,uint256)'), [1n, 99n]));
    await eq('xat[1] after set', encodeCall(sel('xat(uint256)'), [1n]));
    await eq('getA preserved', encodeCall(sel('getA()'), []));
    await eq('getS whole', encodeCall(sel('getS()'), []));
    await send(encodeCall(sel('popX()'), []));
    await eq('getS after pop', encodeCall(sel('getS()'), []));
  });

  it('calldata: echo(e) for a struct with a u256[] field', async () => {
    // E = { uint256 a; uint256[] xs } -> calldata: [0x20 off][a][xs off=0x40][xs len][elems]
    const xs = [5n, 6n, 7n];
    let data = '0x' + sel('echo((uint256,uint256[]))');
    data += pad(0x20n); // offset to tuple
    data += pad(42n); // a
    data += pad(0x40n); // offset to xs (rel tuple start)
    data += pad(BigInt(xs.length));
    for (const x of xs) data += pad(x);
    await eq('echo', data);
  });
});
