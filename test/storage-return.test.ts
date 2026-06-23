// Phase 4: returning a whole STORAGE aggregate whose element/field is DYNAMIC, via
// the storage-source recursive encoder (closes the last caveat). Byte-identical to
// Solidity: return this.d (dynamic struct), this.ss (string[]), this.recs (D[]).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const enc = (s: string) => {
  const b = Buffer.from(s, 'utf8');
  const M = 1n << 256n;
  const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
  const nwords = Math.ceil(b.length / 32);
  let data = '';
  for (let i = 0; i < nwords; i++)
    data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)])
      .subarray(0, 32)
      .toString('hex');
  return { len: BigInt(b.length), data, pad };
};
function strArg(sel: string, headStatic: bigint[], s: string): string {
  const { len, data, pad } = enc(s);
  let h = '0x' + functionSelector(sel);
  for (const w of headStatic) h += pad(w);
  h += pad(BigInt((headStatic.length + 1) * 32)) + pad(len) + data;
  return h;
}

const JETH = `@struct class D { a: u256; s: string; }
@contract class SR {
  @state d: D;
  @state ss: string[];
  @state recs: D[];
  @external setDA(a: u256): void { this.d.a = a; }
  @external setDS(s: string): void { this.d.s = s; }
  @external pushSs(s: string): void { this.ss.push(s); }
  @external pushRec(a: u256, s: string): void { this.recs.push(D(a, s)); }
  @external @view getD(): D { return this.d; }
  @external @view getSs(): string[] { return this.ss; }
  @external @view getRecs(): D[] { return this.recs; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SR {
  struct D { uint256 a; string s; }
  D d;
  string[] ss;
  D[] recs;
  function setDA(uint256 a) external { d.a = a; }
  function setDS(string calldata s) external { d.s = s; }
  function pushSs(string calldata s) external { ss.push(s); }
  function pushRec(uint256 a, string calldata s) external { recs.push(D(a, s)); }
  function getD() external view returns (D memory){ return d; }
  function getSs() external view returns (string[] memory){ return ss; }
  function getRecs() external view returns (D[] memory){ return recs; }
}`;

const LONG = 'a string certainly longer than thirty-two bytes to exercise the long-storage path';

describe('returning a whole storage dynamic aggregate vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function send(data: string) {
    await jeth.call(aj, data);
    await sol.call(as, data);
  }
  async function eqGet(label: string, selSig: string) {
    const data = '0x' + sel(selSig);
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'SR.jeth' });
    const sb = compileSolidity(SOL, 'SR');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('return this.d (storage dynamic struct) byte-identical, short + long string', async () => {
    await send(encodeCall(sel('setDA(uint256)'), [42n]));
    await send(strArg('setDS(string)', [], 'hi'));
    await eqGet('getD short', 'getD()');
    await send(strArg('setDS(string)', [], LONG));
    await eqGet('getD long', 'getD()');
  });

  it('return this.ss (storage string[]) byte-identical incl empty + long elements', async () => {
    await eqGet('getSs empty', 'getSs()');
    await send(strArg('pushSs(string)', [], 'ab'));
    await send(strArg('pushSs(string)', [], LONG));
    await send(strArg('pushSs(string)', [], ''));
    await eqGet('getSs n=3', 'getSs()');
  });

  it('return this.recs (storage D[] of dynamic struct) byte-identical', async () => {
    await send(strArg('pushRec(uint256,string)', [7n], 'first'));
    await send(strArg('pushRec(uint256,string)', [8n], LONG));
    await eqGet('getRecs n=2', 'getRecs()');
  });
});
