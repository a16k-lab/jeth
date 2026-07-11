// Phase 4 bug #4: mapping<K, bytes> / mapping<K, string> scalar dynamic value.
// Read / return / write / .length / byte-index all flow through the dynamic-value
// machinery at the runtime keccak(key.base) mapping slot. Byte-identical to Solidity,
// short (inline) and long (keccak data slots) paths.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const K = BigInt('0x' + 'cd'.repeat(20));
// build calldata for f(address k, <bytes|string> v)
function bytesArg(sel: string, k: bigint, s: string): string {
  const b = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(b.length / 32) || 0;
  let data = '';
  for (let i = 0; i < nwords; i++)
    data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)])
      .subarray(0, 32)
      .toString('hex');
  let h = '0x' + functionSelector(sel);
  h += pad(k) + pad(0x40n) + pad(BigInt(b.length)) + data;
  return h;
}

const JETH = `class MB {
  mb: mapping<address, bytes>;
  ms: mapping<address, string>;
  setB(k: address, v: bytes): External<void> { this.mb[k] = v; }
  setS(k: address, v: string): External<void> { this.ms[k] = v; }
  get getB(k: address): External<bytes> { return this.mb[k]; }
  get getS(k: address): External<string> { return this.ms[k]; }
  get lenB(k: address): External<u256> { return this.mb[k].length; }
  get atB(k: address, i: u256): External<bytes1> { return this.mb[k][i]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MB {
  mapping(address => bytes) mb;
  mapping(address => string) ms;
  function setB(address k, bytes calldata v) external { mb[k] = v; }
  function setS(address k, string calldata v) external { ms[k] = v; }
  function getB(address k) external view returns (bytes memory){ return mb[k]; }
  function getS(address k) external view returns (string memory){ return ms[k]; }
  function lenB(address k) external view returns (uint256){ return mb[k].length; }
  function atB(address k, uint256 i) external view returns (bytes1){ return mb[k][i]; }
}`;

const SHORT = 'hi there';
const LONG = 'a value string definitely longer than thirty-two bytes for the long storage path test';

describe('mapping<K, bytes>/<K, string> vs Solidity', () => {
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
    const jb = compile(JETH, { fileName: 'MB.jeth' });
    const sb = compileSolidity(SOL, 'MB');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('empty value: getB / getS / lenB byte-identical', async () => {
    await eq('getB empty', encodeCall(sel('getB(address)'), [K]));
    await eq('getS empty', encodeCall(sel('getS(address)'), [K]));
    await eq('lenB empty', encodeCall(sel('lenB(address)'), [K]));
  });

  it('short bytes: set/get/len/index byte-identical', async () => {
    await send(bytesArg('setB(address,bytes)', K, SHORT));
    await eq('getB short', encodeCall(sel('getB(address)'), [K]));
    await eq('lenB short', encodeCall(sel('lenB(address)'), [K]));
    for (const i of [0n, 1n, 7n]) await eq(`atB short[${i}]`, encodeCall(sel('atB(address,uint256)'), [K, i]));
  });

  it('long bytes: set/get/len/index byte-identical', async () => {
    await send(bytesArg('setB(address,bytes)', K, LONG));
    await eq('getB long', encodeCall(sel('getB(address)'), [K]));
    await eq('lenB long', encodeCall(sel('lenB(address)'), [K]));
    for (const i of [0n, 31n, 32n, 50n]) await eq(`atB long[${i}]`, encodeCall(sel('atB(address,uint256)'), [K, i]));
  });

  it('byte-index OOB reverts identically (Panic 0x32)', async () => {
    await send(bytesArg('setB(address,bytes)', K, SHORT));
    await eq('atB OOB', encodeCall(sel('atB(address,uint256)'), [K, 8n]));
  });

  it('string: short then long set/get byte-identical', async () => {
    await send(bytesArg('setS(address,string)', K, SHORT));
    await eq('getS short', encodeCall(sel('getS(address)'), [K]));
    await send(bytesArg('setS(address,string)', K, LONG));
    await eq('getS long', encodeCall(sel('getS(address)'), [K]));
  });

  it('overwrite long with short clears tail (getB byte-identical)', async () => {
    await send(bytesArg('setB(address,bytes)', K, LONG));
    await send(bytesArg('setB(address,bytes)', K, SHORT));
    await eq('getB after shrink', encodeCall(sel('getB(address)'), [K]));
    await eq('lenB after shrink', encodeCall(sel('lenB(address)'), [K]));
  });
});
