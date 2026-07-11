// #6: struct / array COMPONENTS in a multi-value return (storage-source). Static struct,
// dynamic struct, value array, mixed with value/string. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `type P = { x: u128; y: u128; };
type D = { a: u256; s: string; };
class MA {
  p: P;
  d: D;
  arr: u256[];
  setP(x: u128, y: u128): External<void> { this.p.x = x; this.p.y = y; }
  setDA(a: u256): External<void> { this.d.a = a; }
  setDS(s: string): External<void> { this.d.s = s; }
  pushArr(v: u256): External<void> { this.arr.push(v); }
  get withStatic(n: u256): External<[P, u256]> { return [this.p, n]; }
  get withDyn(n: u256): External<[D, u256]> { return [this.d, n]; }
  get withArr(n: u256): External<[u256[], u256]> { return [this.arr, n]; }
  get twoAgg(): External<[P, D]> { return [this.p, this.d]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MA {
  struct P { uint128 x; uint128 y; }
  struct D { uint256 a; string s; }
  P p; D d; uint256[] arr;
  function setP(uint128 x, uint128 y) external { p.x=x; p.y=y; }
  function setDA(uint256 a) external { d.a=a; }
  function setDS(string calldata s) external { d.s=s; }
  function pushArr(uint256 v) external { arr.push(v); }
  function withStatic(uint256 n) external view returns (P memory, uint256){ return (p, n); }
  function withDyn(uint256 n) external view returns (D memory, uint256){ return (d, n); }
  function withArr(uint256 n) external view returns (uint256[] memory, uint256){ return (arr, n); }
  function twoAgg() external view returns (P memory, D memory){ return (p, d); }
}`;

const LONG = 'a definitely-longer-than-thirty-two-byte string for the dynamic struct component';

describe('aggregate components in multi-value return vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  function strCall(sig: string, s: string): string {
    const b = Buffer.from(s, 'utf8');
    const nwords = Math.ceil(b.length / 32);
    let data = '';
    for (let i = 0; i < nwords; i++)
      data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)])
        .subarray(0, 32)
        .toString('hex');
    return '0x' + sel(sig) + pad(0x20n) + pad(BigInt(b.length)) + data;
  }
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success).toBe(s.success);
  }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'MA.jeth' });
    const sb = compileSolidity(SOL, 'MA');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('static struct + value', async () => {
    await send(encodeCall(sel('setP(uint128,uint128)'), [0xcafen, 0xbeefn]));
    await eq('withStatic', encodeCall(sel('withStatic(uint256)'), [42n]));
  });
  it('dynamic struct + value (short + long)', async () => {
    await send(encodeCall(sel('setDA(uint256)'), [99n]));
    await send(strCall('setDS(string)', 'hi'));
    await eq('withDyn short', encodeCall(sel('withDyn(uint256)'), [7n]));
    await send(strCall('setDS(string)', LONG));
    await eq('withDyn long', encodeCall(sel('withDyn(uint256)'), [7n]));
  });
  it('value array + value', async () => {
    await send(encodeCall(sel('pushArr(uint256)'), [10n]));
    await send(encodeCall(sel('pushArr(uint256)'), [20n]));
    await eq('withArr', encodeCall(sel('withArr(uint256)'), [3n]));
  });
  it('two aggregate components (static + dynamic struct)', async () => {
    await eq('twoAgg', encodeCall(sel('twoAgg()'), []));
  });
});
