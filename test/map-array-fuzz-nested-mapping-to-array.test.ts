// Phase 4e-2b scenario "nested-mapping-to-array": mapping<address, mapping<uint256, uint256[]>> g
// alongside mapping<address, Rec[]> recs and a scalar sentinel. Differential against Solidity:
// push/length/index read+write/pop on the two-key inner dynamic array, raw keccak slots,
// per-(a,b) isolation, sentinel untouched. Two-key length slot:
//   lenSlot = keccak(pad(b) . keccak(pad(a) . pad(gBase)))   (gBase = 0)
//   dataStart = keccak(pad(lenSlot)); element i at dataStart + i.
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

// distinct (a,b) pairs to prove isolation
const A1 = BigInt('0x' + '11'.repeat(20));
const A2 = BigInt('0x' + '22'.repeat(20));
const B1 = 7n;
const B2 = 9n;

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
function kec(hex: string): bigint {
  return BigInt('0x' + toHex(keccak(hexToBytes(('0x' + hex) as `0x${string}`))));
}
// inner-mapping slot for key a under base: keccak(pad(a) . pad(base))
const innerMapSlot = (a: bigint, base: bigint) => kec(pad32(a) + pad32(base));
// two-key array length slot: keccak(pad(b) . innerMapSlot(a, gBase))
const gLenSlot = (a: bigint, b: bigint, gBase: bigint) => kec(pad32(b) + pad32(innerMapSlot(a, gBase)));
// one-key mapped-array length slot: keccak(pad(a) . pad(base))
const recLenSlot = (a: bigint, base: bigint) => kec(pad32(a) + pad32(base));
// data start for a dynamic array whose length lives at lenSlot
const dataSlot = (lenSlot: bigint) => kec(pad32(lenSlot));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract NestedMapArray {
  struct Rec { uint64 id; uint128 amt; }
  mapping(address => mapping(uint256 => uint256[])) g;  // slot 0
  mapping(address => Rec[]) recs;                        // slot 1
  uint256 sentinel;                                      // slot 2
  function gpush(address a, uint256 b, uint256 v) external { g[a][b].push(v); }
  function gpop(address a, uint256 b) external { g[a][b].pop(); }
  function gset(address a, uint256 b, uint256 i, uint256 v) external { g[a][b][i] = v; }
  function glen(address a, uint256 b) external view returns (uint256){ return g[a][b].length; }
  function gat(address a, uint256 b, uint256 i) external view returns (uint256){ return g[a][b][i]; }
  function rpush(address a, uint64 id, uint128 amt) external { recs[a].push(Rec(id, amt)); }
  function rlen(address a) external view returns (uint256){ return recs[a].length; }
  function rid(address a, uint256 i) external view returns (uint64){ return recs[a][i].id; }
}`;

describe('nested-mapping-to-array: mapping<A, mapping<B, T[]>> vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);

  async function eqCall(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }
  async function eqSlot(slot: bigint, label: string) {
    const j = await readSlot(jeth, aj, slot);
    const s = await readSlot(sol, as, slot);
    expect(j, `${label} (jeth=${j} sol=${s})`).toBe(s);
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', '_gen4e2b_NestedMapArray.jeth'), 'utf8');
    const jb = compile(src, { fileName: '_gen4e2b_NestedMapArray.jeth' });
    const sb = compileSolidity(SOL, 'NestedMapArray');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('two-key push/length/index + raw keccak slots, (a,b)-pair isolation', async () => {
    // populate g[A1][B1] with two elements, g[A1][B2] and g[A2][B1] with one each
    await eqCall('gpush A1 B1 #0', encodeCall(sel('gpush(address,uint256,uint256)'), [A1, B1, 111n]));
    await eqCall('gpush A1 B1 #1', encodeCall(sel('gpush(address,uint256,uint256)'), [A1, B1, 222n]));
    await eqCall('gpush A1 B2 #0', encodeCall(sel('gpush(address,uint256,uint256)'), [A1, B2, 333n]));
    await eqCall('gpush A2 B1 #0', encodeCall(sel('gpush(address,uint256,uint256)'), [A2, B1, 444n]));

    // lengths byte-identical and correct per pair
    let r = await eqCall('glen A1 B1', encodeCall(sel('glen(address,uint256)'), [A1, B1]));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    r = await eqCall('glen A1 B2', encodeCall(sel('glen(address,uint256)'), [A1, B2]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    r = await eqCall('glen A2 B1', encodeCall(sel('glen(address,uint256)'), [A2, B1]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);

    // raw two-key length slots
    const lenA1B1 = gLenSlot(A1, B1, 0n);
    const lenA1B2 = gLenSlot(A1, B2, 0n);
    const lenA2B1 = gLenSlot(A2, B1, 0n);
    await eqSlot(lenA1B1, 'g[A1][B1].length slot');
    await eqSlot(lenA1B2, 'g[A1][B2].length slot');
    await eqSlot(lenA2B1, 'g[A2][B1].length slot');

    // raw element slots for g[A1][B1]
    const dA1B1 = dataSlot(lenA1B1);
    await eqSlot(dA1B1, 'g[A1][B1][0]');
    await eqSlot(dA1B1 + 1n, 'g[A1][B1][1]');
    await eqSlot(dataSlot(lenA1B2), 'g[A1][B2][0]');
    await eqSlot(dataSlot(lenA2B1), 'g[A2][B1][0]');

    // getters byte-identical, pairs isolated (no cross-talk)
    r = await eqCall('gat A1 B1 0', encodeCall(sel('gat(address,uint256,uint256)'), [A1, B1, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(111n);
    r = await eqCall('gat A1 B1 1', encodeCall(sel('gat(address,uint256,uint256)'), [A1, B1, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(222n);
    r = await eqCall('gat A1 B2 0', encodeCall(sel('gat(address,uint256,uint256)'), [A1, B2, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(333n);
    r = await eqCall('gat A2 B1 0', encodeCall(sel('gat(address,uint256,uint256)'), [A2, B1, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(444n);
  });

  it('two-key index write (gset) updates only the target element, byte-identical', async () => {
    await eqCall('gset A1 B1 0', encodeCall(sel('gset(address,uint256,uint256,uint256)'), [A1, B1, 0n, 98765n]));
    const lenA1B1 = gLenSlot(A1, B1, 0n);
    const dA1B1 = dataSlot(lenA1B1);
    await eqSlot(dA1B1, 'g[A1][B1][0] after gset');
    await eqSlot(dA1B1 + 1n, 'g[A1][B1][1] unchanged');
    // sibling pairs untouched
    await eqSlot(dataSlot(gLenSlot(A1, B2, 0n)), 'g[A1][B2][0] untouched by gset');
    await eqSlot(dataSlot(gLenSlot(A2, B1, 0n)), 'g[A2][B1][0] untouched by gset');
    let r = await eqCall('gat A1 B1 0 after set', encodeCall(sel('gat(address,uint256,uint256)'), [A1, B1, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(98765n);
    r = await eqCall('gat A1 B1 1 preserved', encodeCall(sel('gat(address,uint256,uint256)'), [A1, B1, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(222n);
  });

  it('two-key pop shrinks length and zeroes the slot byte-identically', async () => {
    const lenA1B1 = gLenSlot(A1, B1, 0n);
    const dA1B1 = dataSlot(lenA1B1);
    await eqCall('gpop A1 B1', encodeCall(sel('gpop(address,uint256)'), [A1, B1]));
    let r = await eqCall('glen A1 B1 after pop', encodeCall(sel('glen(address,uint256)'), [A1, B1]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    await eqSlot(lenA1B1, 'g[A1][B1].length slot after pop');
    await eqSlot(dA1B1 + 1n, 'g[A1][B1][1] zeroed after pop');
    await eqSlot(dA1B1, 'g[A1][B1][0] preserved after pop');
    // pop last, then pop empty -> Panic(0x31)
    await eqCall('gpop A1 B1 #2', encodeCall(sel('gpop(address,uint256)'), [A1, B1]));
    await eqSlot(lenA1B1, 'g[A1][B1].length slot zero after second pop');
    await eqSlot(dA1B1, 'g[A1][B1][0] zeroed after second pop');
    const re = await eqCall('gpop A1 B1 empty -> Panic(0x31)', encodeCall(sel('gpop(address,uint256)'), [A1, B1]));
    expect(re.j.success).toBe(false);
  });

  it('two-key OOB index Panics(0x32) byte-identically (read and write)', async () => {
    // g[A1][B2] has length 1; index 1 is OOB
    const r = await eqCall('gat A1 B2 OOB', encodeCall(sel('gat(address,uint256,uint256)'), [A1, B2, 1n]));
    expect(r.j.success).toBe(false);
    const r2 = await eqCall(
      'gset A1 B2 OOB',
      encodeCall(sel('gset(address,uint256,uint256,uint256)'), [A1, B2, 5n, 1n]),
    );
    expect(r2.j.success).toBe(false);
  });

  it('alongside one-key mapped struct array stays isolated and byte-identical', async () => {
    await eqCall('rpush A1 #0', encodeCall(sel('rpush(address,uint64,uint128)'), [A1, 7n, 1000n]));
    await eqCall('rpush A1 #1', encodeCall(sel('rpush(address,uint64,uint128)'), [A1, 8n, 2000n]));
    let r = await eqCall('rlen A1', encodeCall(sel('rlen(address)'), [A1]));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    const recLen = recLenSlot(A1, 1n);
    const dRec = dataSlot(recLen);
    await eqSlot(recLen, 'recs[A1].length slot');
    await eqSlot(dRec, 'recs[A1][0] (id|amt packed)');
    await eqSlot(dRec + 1n, 'recs[A1][1]');
    r = await eqCall('rid A1 1', encodeCall(sel('rid(address,uint256)'), [A1, 1n]));
    expect(decodeUint(r.j.returnHex)).toBe(8n);
    // g lengths for surviving pairs still byte-identical (recs push did not disturb g)
    await eqSlot(gLenSlot(A1, B2, 0n), 'g[A1][B2].length slot still identical after recs push');
    await eqSlot(gLenSlot(A2, B1, 0n), 'g[A2][B1].length slot still identical after recs push');
  });

  it('sentinel slot 2 untouched, byte-identical to Solidity', async () => {
    expect(decodeUint(await readSlot(jeth, aj, 2n))).toBe(0n);
    await eqSlot(2n, 'sentinel slot 2');
  });
});
