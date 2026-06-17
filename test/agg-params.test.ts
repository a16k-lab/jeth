// Phase 4d: aggregate calldata params (fixed-array + struct, incl. nested and
// mixed with value params) byte-identical to Solidity: returndata, lazy dirty-read
// reverts (empty), and runtime OOB index Panic(0x32).
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

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AggParams {
  struct Pt { uint128 x; uint128 y; }
  struct Acct { uint128 bal; uint64 nonce; bool active; }
  struct Inner { uint128 a; uint128 b; }
  struct Outer { uint64 p; Inner inner; uint64 q; }
  struct WithArr { uint64 id; uint256[2] data; }
  function sumTriple(uint256[3] calldata a) external pure returns (uint256){ return a[0]+a[1]+a[2]; }
  function pick(uint8[4] calldata a, uint256 i) external pure returns (uint8){ return a[i]; }
  function pickAddr(address[3] calldata a, uint256 i) external pure returns (address){ return a[i]; }
  function lenOf(uint256[3] calldata a) external pure returns (uint256){ return a.length; }
  function ptX(Pt calldata p) external pure returns (uint128){ return p.x; }
  function ptY(Pt calldata p) external pure returns (uint128){ return p.y; }
  function acctNonce(Acct calldata a) external pure returns (uint64){ return a.nonce; }
  function acctActive(Acct calldata a) external pure returns (bool){ return a.active; }
  function outerInnerB(Outer calldata o) external pure returns (uint128){ return o.inner.b; }
  function outerQ(Outer calldata o) external pure returns (uint64){ return o.q; }
  function withId(WithArr calldata t) external pure returns (uint64){ return t.id; }
  function dataAt(WithArr calldata t, uint256 j) external pure returns (uint256){ return t.data[j]; }
  function ptsX(Pt[2] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].x; }
  function ptsY(Pt[2] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].y; }
  function afterAgg(uint256[3] calldata a, uint256 x) external pure returns (uint256){ return a[2]+x; }
}`;

const M = (1n << 256n);
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}

describe('aggregate calldata params vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  function raw(selSig: string, words: bigint[]): string {
    return '0x' + sel(selSig) + words.map(pad).join('');
  }
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  // assert JETH matches Solidity byte-for-byte (returndata + success).
  async function eq(label: string, data: string) {
    const { j, s } = await both(data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'AggParams.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'AggParams.jeth' });
    const sb = compileSolidity(SOL, 'AggParams');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('fixed-array value param: constant + runtime index, length', async () => {
    const r = await eq('sumTriple', raw('sumTriple(uint256[3])', [10n, 20n, 30n]));
    expect(decodeUint(r.j.returnHex)).toBe(60n);
    for (const i of [0n, 1n, 2n, 3n]) {
      await eq(`pick i=${i}`, raw('pick(uint8[4],uint256)', [10n, 20n, 30n, 40n, i])); // i=3 ok, addressing word 3
    }
    // runtime OOB index -> Panic(0x32) identically
    await eq('pick OOB i=4', raw('pick(uint8[4],uint256)', [1n, 2n, 3n, 4n, 4n]));
    await eq('lenOf', raw('lenOf(uint256[3])', [5n, 6n, 7n]));
  });

  it('lazy dirty-element validation: dirty read reverts empty, unread dirty ignored', async () => {
    // a[2] dirty (0x1ff for uint8), read i=2 -> both revert EMPTY
    let r = await eq('pick dirty read', raw('pick(uint8[4],uint256)', [1n, 2n, 0x1ffn, 4n, 2n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // same dirty element but read a CLEAN index i=0 -> both OK (lazy)
    r = await eq('pick dirty unread', raw('pick(uint8[4],uint256)', [1n, 2n, 0x1ffn, 4n, 0n]));
    expect(r.j.success).toBe(true);
  });

  it('address fixed-array param', async () => {
    const A = [BigInt('0x' + '11'.repeat(20)), BigInt('0x' + '22'.repeat(20)), BigInt('0x' + '33'.repeat(20))];
    for (const i of [0n, 1n, 2n]) {
      const r = await eq(`pickAddr i=${i}`, raw('pickAddr(address[3],uint256)', [...A, i]));
      expect(decodeUint(r.j.returnHex)).toBe(A[Number(i)]!);
    }
    // dirty address (high bits) read -> revert empty
    const r = await eq('pickAddr dirty', raw('pickAddr(address[3],uint256)', [(1n << 200n) | A[0]!, A[1]!, A[2]!, 0n]));
    expect(r.j.success).toBe(false);
  });

  it('static struct param (packed leaves are 1 word each)', async () => {
    const pt = [0xcafen, 0xbeefn]; // x, y
    expect(decodeUint((await eq('ptX', raw('ptX((uint128,uint128))', pt))).j.returnHex)).toBe(0xcafen);
    expect(decodeUint((await eq('ptY', raw('ptY((uint128,uint128))', pt))).j.returnHex)).toBe(0xbeefn);
    const acct = [1000n, 7n, 1n]; // bal, nonce, active
    expect(decodeUint((await eq('acctNonce', raw('acctNonce((uint128,uint64,bool))', acct))).j.returnHex)).toBe(7n);
    await eq('acctActive', raw('acctActive((uint128,uint64,bool))', acct));
    // dirty nonce (bit64 set) read -> revert empty
    let r = await eq('acctNonce dirty', raw('acctNonce((uint128,uint64,bool))', [1000n, 1n << 64n, 1n]));
    expect(r.j.success).toBe(false);
    // dirty active (2) read -> revert empty
    r = await eq('acctActive dirty', raw('acctActive((uint128,uint64,bool))', [1000n, 7n, 2n]));
    expect(r.j.success).toBe(false);
    // dirty bal (unread by acctNonce) -> OK (lazy)
    r = await eq('acctNonce dirty-unread-bal', raw('acctNonce((uint128,uint64,bool))', [1n << 200n, 7n, 1n]));
    expect(r.j.success).toBe(true);
  });

  it('nested struct param flattened inline', async () => {
    // Outer{p, inner{a,b}, q} -> 4 head words: p, a, b, q
    const o = [0x11n, 0xaaaan, 0xbbbbn, 0x22n];
    expect(decodeUint((await eq('outerInnerB', raw('outerInnerB((uint64,(uint128,uint128),uint64))', o))).j.returnHex)).toBe(0xbbbbn);
    expect(decodeUint((await eq('outerQ', raw('outerQ((uint64,(uint128,uint128),uint64))', o))).j.returnHex)).toBe(0x22n);
  });

  it('struct-with-array-field param', async () => {
    const t = [9n, 0x111n, 0x222n]; // id, data[0], data[1]
    expect(decodeUint((await eq('withId', raw('withId((uint64,uint256[2]))', t))).j.returnHex)).toBe(9n);
    expect(decodeUint((await eq('dataAt j=0', raw('dataAt((uint64,uint256[2]),uint256)', [...t, 0n]))).j.returnHex)).toBe(0x111n);
    expect(decodeUint((await eq('dataAt j=1', raw('dataAt((uint64,uint256[2]),uint256)', [...t, 1n]))).j.returnHex)).toBe(0x222n);
    // OOB j=2 -> Panic(0x32)
    const r = await eq('dataAt OOB', raw('dataAt((uint64,uint256[2]),uint256)', [...t, 2n]));
    expect(r.j.success).toBe(false);
  });

  it('fixed-array-of-struct param + OOB', async () => {
    // ps[0]={1,2}, ps[1]={3,4}
    const ps = [1n, 2n, 3n, 4n];
    expect(decodeUint((await eq('ptsX i=1', raw('ptsX((uint128,uint128)[2],uint256)', [...ps, 1n]))).j.returnHex)).toBe(3n);
    expect(decodeUint((await eq('ptsY i=0', raw('ptsY((uint128,uint128)[2],uint256)', [...ps, 0n]))).j.returnHex)).toBe(2n);
    const r = await eq('ptsX OOB', raw('ptsX((uint128,uint128)[2],uint256)', [...ps, 2n]));
    expect(r.j.success).toBe(false);
  });

  it('mixed aggregate + value: head cursor advances past the whole aggregate', async () => {
    const r = await eq('afterAgg', raw('afterAgg(uint256[3],uint256)', [1n, 2n, 3n, 100n]));
    expect(decodeUint(r.j.returnHex)).toBe(103n);
  });

  it('short calldata reverts empty identically', async () => {
    // sumTriple needs 3 head words (96 bytes); supply only 2.
    const short = '0x' + sel('sumTriple(uint256[3])') + pad(1n) + pad(2n);
    const r = await eq('sumTriple short', short);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // afterAgg needs 4 head words; supply 3.
    const short2 = '0x' + sel('afterAgg(uint256[3],uint256)') + [1n, 2n, 3n].map(pad).join('');
    const r2 = await eq('afterAgg short', short2);
    expect(r2.j.success).toBe(false);
  });
});
