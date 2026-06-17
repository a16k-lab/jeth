// Phase 4c-3: nested storage access (array-of-struct, mapping-of-struct, nested
// fixed arrays, nested structs) byte-identical to Solidity, incl. raw slots.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const K = BigInt('0x' + 'cc'.repeat(20));

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
function mapSlot(keyWord: bigint, baseSlot: bigint): bigint {
  const buf = new Uint8Array(64);
  buf.set(hexToBytes(('0x' + pad32(keyWord)) as `0x${string}`), 0);
  buf.set(hexToBytes(('0x' + pad32(baseSlot)) as `0x${string}`), 32);
  return BigInt('0x' + toHex(keccak(buf)));
}

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Nested {
  struct Pt { uint128 x; uint128 y; }
  struct Acct { uint128 bal; uint64 nonce; bool active; }
  struct Inner { uint128 a; uint128 b; }
  struct Outer { uint64 p; Inner inner; uint64 q; }
  Pt[3] pts; uint256 sentinel1;
  mapping(address => Acct) accts;
  uint256[2][3] mat; uint256 sentinel2;
  Outer outer;
  function setPtX(uint256 i, uint128 v) external { pts[i].x = v; }
  function setPtY(uint256 i, uint128 v) external { pts[i].y = v; }
  function getPtX(uint256 i) external view returns (uint128){ return pts[i].x; }
  function getPtY(uint256 i) external view returns (uint128){ return pts[i].y; }
  function setBal(address k, uint128 v) external { accts[k].bal = v; }
  function setNonce(address k, uint64 v) external { accts[k].nonce = v; }
  function setActive(address k, bool v) external { accts[k].active = v; }
  function getBal(address k) external view returns (uint128){ return accts[k].bal; }
  function getNonce(address k) external view returns (uint64){ return accts[k].nonce; }
  function getActive(address k) external view returns (bool){ return accts[k].active; }
  function setMat(uint256 r, uint256 c, uint256 v) external { mat[r][c] = v; }
  function getMat(uint256 r, uint256 c) external view returns (uint256){ return mat[r][c]; }
  function setInnerA(uint128 v) external { outer.inner.a = v; }
  function setOuterP(uint64 v) external { outer.p = v; }
  function getInnerA() external view returns (uint128){ return outer.inner.a; }
  function getOuterP() external view returns (uint64){ return outer.p; }
}`;

describe('nested storage access vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'Nested.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'Nested.jeth' });
    const sb = compileSolidity(SOL, 'Nested');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('array-of-struct: this.pts[i].x/.y raw slots + getters', async () => {
    await both(encodeCall(sel('setPtX(uint256,uint128)'), [2n, 0xcafen]));
    await both(encodeCall(sel('setPtY(uint256,uint128)'), [2n, 0xbeefn]));
    await eqSlot(2n, 'pts[2] slot (x|y packed)');
    let r = await both(encodeCall(sel('getPtX(uint256)'), [2n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xcafen);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    r = await both(encodeCall(sel('getPtY(uint256)'), [2n]));
    expect(r.j.returnHex).toBe(r.s.returnHex);
    // OOB nested index -> Panic 0x32
    r = await both(encodeCall(sel('getPtX(uint256)'), [3n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(r.s.returnHex);
  });

  it('mapping-of-struct: this.accts[k].field raw slot + getters', async () => {
    await both(encodeCall(sel('setBal(address,uint128)'), [K, 0xbeefn]));
    await both(encodeCall(sel('setNonce(address,uint64)'), [K, 7n]));
    await both(encodeCall(sel('setActive(address,bool)'), [K, 1n]));
    const base = mapSlot(K, 4n); // accts base = keccak(pad(k) . pad(4)); Acct{bal,nonce,active} all in base slot
    await eqSlot(base, 'accts[k] packed slot');
    for (const g of ['getBal(address)', 'getNonce(address)', 'getActive(address)']) {
      const r = await both(encodeCall(sel(g), [K]));
      expect(r.j.returnHex, g).toBe(r.s.returnHex);
    }
  });

  it('nested fixed arrays: this.mat[r][c] raw slot + getter', async () => {
    await both(encodeCall(sel('setMat(uint256,uint256,uint256)'), [1n, 1n, 0x1234n]));
    await eqSlot(8n, 'mat[1][1] (slot 5 + 1*2 + 1)'); // row-major
    let r = await both(encodeCall(sel('getMat(uint256,uint256)'), [1n, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0x1234n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    // OOB inner / outer -> Panic 0x32
    r = await both(encodeCall(sel('getMat(uint256,uint256)'), [3n, 0n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    r = await both(encodeCall(sel('getMat(uint256,uint256)'), [0n, 2n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(r.s.returnHex);
  });

  it('nested structs: this.outer.inner.a raw slot + getters', async () => {
    await both(encodeCall(sel('setInnerA(uint128)'), [0xabcdn]));
    await both(encodeCall(sel('setOuterP(uint64)'), [0x99n]));
    await eqSlot(13n, 'outer.inner slot (12 + 1)');
    await eqSlot(12n, 'outer.p slot');
    let r = await both(encodeCall(sel('getInnerA()')));
    expect(decodeUint(r.j.returnHex)).toBe(0xabcdn);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    r = await both(encodeCall(sel('getOuterP()')));
    expect(r.j.returnHex).toBe(r.s.returnHex);
  });

  it('leaves sentinels untouched', async () => {
    expect(decodeUint(await readSlot(jeth, aj, 3n))).toBe(0n);
    expect(decodeUint(await readSlot(jeth, aj, 11n))).toBe(0n);
  });
});
