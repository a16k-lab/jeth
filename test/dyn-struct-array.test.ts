// Phase 4e-1: dynamic array of static struct (Pt[], Acct[]) as a calldata param,
// byte-identical to Solidity: whole-array echo (head/tail decode+re-encode, dirty
// fields cleaned), element field reads ps[i].field (dirty -> revert), OOB Panic,
// length, short/malformed calldata.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract DynStructArray {
  struct Pt { uint128 x; uint128 y; }
  struct Acct { uint128 bal; uint64 nonce; bool active; }
  function echoPts(Pt[] calldata ps) external pure returns (Pt[] memory){ return ps; }
  function echoAccts(Acct[] calldata a) external pure returns (Acct[] memory){ return a; }
  function ptX(Pt[] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].x; }
  function ptY(Pt[] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].y; }
  function acctNonce(Acct[] calldata a, uint256 i) external pure returns (uint64){ return a[i].nonce; }
  function acctActive(Acct[] calldata a, uint256 i) external pure returns (bool){ return a[i].active; }
  function len(Pt[] calldata ps) external pure returns (uint256){ return ps.length; }
}`;

describe('dynamic array of static struct (calldata param) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }
  // sole dynamic-array param: head = [offset=0x20], then [len][flat words]
  const arr1 = (selSig: string, flat: bigint[], len: number) =>
    '0x' + sel(selSig) + pad(0x20n) + pad(BigInt(len)) + flat.map(pad).join('');
  // (dynamic-array, uint256 i): head = [offset=0x40][i], then [len][flat words]
  const arr2 = (selSig: string, flat: bigint[], len: number, i: bigint) =>
    '0x' + sel(selSig) + pad(0x40n) + pad(i) + pad(BigInt(len)) + flat.map(pad).join('');

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'DynStructArray.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'DynStructArray.jeth' });
    const sb = compileSolidity(SOL, 'DynStructArray');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('echoes Pt[] byte-identically (head/tail round-trip)', async () => {
    const pts = [1n, 2n, 3n, 4n, 5n, 6n]; // 3 Pts
    await eq('echoPts n=3', arr1('echoPts((uint128,uint128)[])', pts, 3));
    await eq('echoPts n=0', arr1('echoPts((uint128,uint128)[])', [], 0));
    await eq('echoPts n=1', arr1('echoPts((uint128,uint128)[])', [7n, 8n], 1));
  });

  it('echoes Acct[] and VALIDATES struct fields on whole-array copy (revert on dirty)', async () => {
    const ok = [100n, 7n, 1n, 200n, 9n, 0n]; // 2 Accts
    await eq('echoAccts clean', arr1('echoAccts((uint128,uint64,bool)[])', ok, 2));
    // unlike a VALUE-element array (which cleans, Bug A), a STRUCT-element copy reads
    // each field and so reverts EMPTY on any dirty field, matching solc.
    const dirty = [(1n << 200n) | 100n, 1n << 64n, 5n];
    const r = await eq('echoAccts dirty->revert', arr1('echoAccts((uint128,uint64,bool)[])', dirty, 1));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('reads ps[i].field with lazy dirty validation + OOB Panic', async () => {
    const pts = [0xaaan, 0xbbbn, 0xcccn, 0xdddn]; // Pt0={aaa,bbb}, Pt1={ccc,ddd}
    let r = await eq('ptX i=1', arr2('ptX((uint128,uint128)[],uint256)', pts, 2, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(0xcccn);
    r = await eq('ptY i=0', arr2('ptY((uint128,uint128)[],uint256)', pts, 2, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(0xbbbn);
    // OOB i=2 (len 2) -> Panic(0x32)
    r = await eq('ptX OOB', arr2('ptX((uint128,uint128)[],uint256)', pts, 2, 2n));
    expect(r.j.success).toBe(false);
    // Acct field reads
    const accts = [100n, 7n, 1n, 200n, 9n, 0n];
    r = await eq('acctNonce i=1', arr2('acctNonce((uint128,uint64,bool)[],uint256)', accts, 2, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(9n);
    await eq('acctActive i=0', arr2('acctActive((uint128,uint64,bool)[],uint256)', accts, 2, 0n));
    // dirty nonce single read -> revert empty
    const dn = [100n, 1n << 64n, 1n];
    r = await eq('acctNonce dirty', arr2('acctNonce((uint128,uint64,bool)[],uint256)', dn, 1, 0n));
    expect(r.j.success).toBe(false);
    // dirty active=2 single read -> revert empty
    const da = [100n, 7n, 2n];
    r = await eq('acctActive dirty', arr2('acctActive((uint128,uint64,bool)[],uint256)', da, 1, 0n));
    expect(r.j.success).toBe(false);
    // dirty UNREAD field (bal) while reading nonce -> OK (lazy)
    const du = [1n << 200n, 7n, 1n];
    r = await eq('acctNonce dirty-unread-bal', arr2('acctNonce((uint128,uint64,bool)[],uint256)', du, 1, 0n));
    expect(r.j.success).toBe(true);
  });

  it('length, short/malformed calldata', async () => {
    const r = await eq('len', arr1('len((uint128,uint128)[])', [1n, 2n, 3n, 4n], 2));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    // declares len=3 but only 1 Pt (2 words) of payload -> empty revert
    const bad = '0x' + sel('echoPts((uint128,uint128)[])') + pad(0x20n) + pad(3n) + pad(1n) + pad(2n);
    const rb = await eq('echoPts truncated payload', bad);
    expect(rb.j.success).toBe(false);
    // offset past calldata -> empty revert
    const off = '0x' + sel('len((uint128,uint128)[])') + pad(0x1000n);
    const ro = await eq('len bad offset', off);
    expect(ro.j.success).toBe(false);
  });
});
