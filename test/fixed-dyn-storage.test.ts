// A4: storage fixed arrays of DYNAMIC elements: Arr<string,N> and Arr<D,N> (D = dynamic
// struct). Element read/write/field-access + whole-array return. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
function strSet(sel: string, head: bigint[], s: string): string {
  const b = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(b.length / 32);
  let data = '';
  for (let i = 0; i < nwords; i++) data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)]).subarray(0, 32).toString('hex');
  let h = '0x' + functionSelector(sel);
  for (const w of head) h += pad(w);
  h += pad(BigInt((head.length + 1) * 32)) + pad(BigInt(b.length)) + data;
  return h;
}

const JETH = `@struct class D { a: u256; s: string; }
@contract class FD {
  @state ss: Arr<string, 3>;
  @state ds: Arr<D, 2>;
  @external setS(i: u256, v: string): void { this.ss[i] = v; }
  @external setDA(i: u256, a: u256): void { this.ds[i].a = a; }
  @external setDS(i: u256, s: string): void { this.ds[i].s = s; }
  @external setDWhole(i: u256, a: u256, s: string): void { this.ds[i] = D(a, s); }
  @external @view getS(i: u256): string { return this.ss[i]; }
  @external @view getDWhole(i: u256): D { return this.ds[i]; }
  @external @view getDA(i: u256): u256 { return this.ds[i].a; }
  @external @view getDS(i: u256): string { return this.ds[i].s; }
  @external @view getAllS(): Arr<string, 3> { return this.ss; }
  @external @view getAllD(): Arr<D, 2> { return this.ds; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FD {
  struct D { uint256 a; string s; }
  string[3] ss;
  D[2] ds;
  function setS(uint256 i, string calldata v) external { ss[i] = v; }
  function setDA(uint256 i, uint256 a) external { ds[i].a = a; }
  function setDS(uint256 i, string calldata s) external { ds[i].s = s; }
  function setDWhole(uint256 i, uint256 a, string calldata s) external { ds[i] = D(a, s); }
  function getS(uint256 i) external view returns (string memory){ return ss[i]; }
  function getDWhole(uint256 i) external view returns (D memory){ return ds[i]; }
  function getDA(uint256 i) external view returns (uint256){ return ds[i].a; }
  function getDS(uint256 i) external view returns (string memory){ return ds[i].s; }
  function getAllS() external view returns (string[3] memory){ return ss; }
  function getAllD() external view returns (D[2] memory){ return ds; }
}`;

const LONG = 'a definitely-longer-than-thirty-two-byte string for the fixed dynamic element';

describe('storage Arr<string,N> / Arr<D,N> vs Solidity', () => {
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
    const jb = compile(JETH, { fileName: 'FD.jeth' });
    const sb = compileSolidity(SOL, 'FD');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('Arr<string,3>: element write/read short+long, OOB', async () => {
    await send(strSet('setS(uint256,string)', [0n], 'hi'));
    await send(strSet('setS(uint256,string)', [2n], LONG));
    await eq('getS[0]', encodeCall(sel('getS(uint256)'), [0n]));
    await eq('getS[1] default', encodeCall(sel('getS(uint256)'), [1n]));
    await eq('getS[2] long', encodeCall(sel('getS(uint256)'), [2n]));
    {
      const data = strSet('setS(uint256,string)', [3n], 'oob');
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(j.success, 'setS OOB parity').toBe(s.success);
    }
  });

  it('Arr<string,3>: whole-array return', async () => {
    await eq('getAllS', encodeCall(sel('getAllS()'), []));
  });

  it('Arr<D,2>: field read/write + whole element', async () => {
    await send(encodeCall(sel('setDA(uint256,uint256)'), [0n, 42n]));
    await send(strSet('setDS(uint256,string)', [0n], LONG));
    await eq('getDA', encodeCall(sel('getDA(uint256)'), [0n]));
    await eq('getDS', encodeCall(sel('getDS(uint256)'), [0n]));
    await eq('getDWhole[0]', encodeCall(sel('getDWhole(uint256)'), [0n]));
    await send(strSet('setDWhole(uint256,uint256,string)', [1n, 7n], 'sh'));
    await eq('getDWhole[1]', encodeCall(sel('getDWhole(uint256)'), [1n]));
  });

  it('Arr<D,2>: whole-array return', async () => {
    await eq('getAllD', encodeCall(sel('getAllD()'), []));
  });
});
