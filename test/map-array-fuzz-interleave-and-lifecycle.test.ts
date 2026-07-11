// Phase 4e-2b scenario "interleave-and-lifecycle": lifecycle + interleaving across
// a plain state array (direct: u256[]) and two keys of a mapped array
// (m: mapping<address,u256[]>), with a co-resident untouched scalar s. Verifies
// independent .length, raw slots, slot reuse reads NEW values, popped slots zeroed,
// data regions never collide, pop-to-empty then pop -> Panic(0x31). Solidity is oracle.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const K1 = BigInt('0x' + '11'.repeat(20));
const K2 = BigInt('0x' + '22'.repeat(20));

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
function kec(hex: string): bigint {
  return BigInt('0x' + toHex(keccak(hexToBytes(('0x' + hex) as `0x${string}`))));
}
// plain dynamic array at slot p: length lives at slot p, data starts at keccak(pad32(p)).
const plainData = (p: bigint) => kec(pad32(p));
// mapped array: per-key length slot = keccak(pad32(k) . pad32(base)); data = keccak(pad32(lenSlot)).
const mapLenSlot = (k: bigint, base: bigint) => kec(pad32(k) + pad32(base));
const dataSlot = (lenSlot: bigint) => kec(pad32(lenSlot));

const JETH = `// interleave-and-lifecycle
class Inter {
  direct: u256[];                    // slot 0
  m: mapping<address, u256[]>;       // slot 1
  s: u256;                           // slot 2

  pushDirect(v: u256): External<void> { this.direct.push(v); }
  popDirect(): External<void> { this.direct.pop(); }
  get lenDirect(): External<u256> { return this.direct.length; }
  get getDirect(i: u256): External<u256> { return this.direct[i]; }
  setDirect(i: u256, v: u256): External<void> { this.direct[i] = v; }

  pushM(k: address, v: u256): External<void> { this.m[k].push(v); }
  popM(k: address): External<void> { this.m[k].pop(); }
  get lenM(k: address): External<u256> { return this.m[k].length; }
  get getM(k: address, i: u256): External<u256> { return this.m[k][i]; }
  setM(k: address, i: u256, v: u256): External<void> { this.m[k][i] = v; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Inter {
  uint256[] direct;                       // slot 0
  mapping(address => uint256[]) m;        // slot 1
  uint256 s;                              // slot 2
  function pushDirect(uint256 v) external { direct.push(v); }
  function popDirect() external { direct.pop(); }
  function lenDirect() external view returns (uint256){ return direct.length; }
  function getDirect(uint256 i) external view returns (uint256){ return direct[i]; }
  function setDirect(uint256 i, uint256 v) external { direct[i] = v; }
  function pushM(address k, uint256 v) external { m[k].push(v); }
  function popM(address k) external { m[k].pop(); }
  function lenM(address k) external view returns (uint256){ return m[k].length; }
  function getM(address k, uint256 i) external view returns (uint256){ return m[k][i]; }
  function setM(address k, uint256 i, uint256 v) external { m[k][i] = v; }
}`;

describe('mapping<K,u256[]> interleave-and-lifecycle vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  const mismatches: { probe: string; jeth: string; solidity: string }[] = [];

  async function eqCall(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success)
      mismatches.push({
        probe: `${label} success`,
        jeth: String(j.success) + ` (err=${j.exceptionError})`,
        solidity: String(s.success),
      });
    if (j.returnHex !== s.returnHex)
      mismatches.push({ probe: `${label} returndata`, jeth: j.returnHex, solidity: s.returnHex });
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }
  async function eqSlot(slot: bigint, label: string) {
    const jv = await readSlot(jeth, aj, slot);
    const sv = await readSlot(sol, as, slot);
    if (jv !== sv) mismatches.push({ probe: `slot ${label}`, jeth: jv, solidity: sv });
    expect(jv, label).toBe(sv);
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'Inter.jeth' });
    const sb = compileSolidity(SOL, 'Inter');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  const dLen = 0n; // direct length slot
  const dData = plainData(0n); // direct data start
  const lenK1 = mapLenSlot(K1, 1n);
  const lenK2 = mapLenSlot(K2, 1n);
  const dK1 = dataSlot(lenK1);
  const dK2 = dataSlot(lenK2);

  it('interleaved push across direct, m[K1], m[K2]; independent lengths + raw slots; no collision', async () => {
    // Interleave pushes.
    await eqCall('pushDirect 100', encodeCall(sel('pushDirect(uint256)'), [100n]));
    await eqCall('pushM K1 11', encodeCall(sel('pushM(address,uint256)'), [K1, 11n]));
    await eqCall('pushDirect 200', encodeCall(sel('pushDirect(uint256)'), [200n]));
    await eqCall('pushM K2 21', encodeCall(sel('pushM(address,uint256)'), [K2, 21n]));
    await eqCall('pushM K1 12', encodeCall(sel('pushM(address,uint256)'), [K1, 12n]));
    await eqCall('pushDirect 300', encodeCall(sel('pushDirect(uint256)'), [300n]));
    await eqCall('pushM K2 22', encodeCall(sel('pushM(address,uint256)'), [K2, 22n]));
    await eqCall('pushM K2 23', encodeCall(sel('pushM(address,uint256)'), [K2, 23n]));

    // Independent lengths: direct=3, K1=2, K2=3.
    let r = await eqCall('lenDirect', encodeCall(sel('lenDirect()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    r = await eqCall('lenM K1', encodeCall(sel('lenM(address)'), [K1]));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    r = await eqCall('lenM K2', encodeCall(sel('lenM(address)'), [K2]));
    expect(decodeUint(r.j.returnHex)).toBe(3n);

    // Raw length slots.
    await eqSlot(dLen, 'direct.length');
    await eqSlot(lenK1, 'm[K1].length');
    await eqSlot(lenK2, 'm[K2].length');

    // Raw data slots for each region (must be disjoint and correct).
    await eqSlot(dData, 'direct[0]');
    await eqSlot(dData + 1n, 'direct[1]');
    await eqSlot(dData + 2n, 'direct[2]');
    await eqSlot(dK1, 'm[K1][0]');
    await eqSlot(dK1 + 1n, 'm[K1][1]');
    await eqSlot(dK2, 'm[K2][0]');
    await eqSlot(dK2 + 1n, 'm[K2][1]');
    await eqSlot(dK2 + 2n, 'm[K2][2]');

    // Sanity: the three data regions are distinct (no overlap in tested span).
    const span = (b: bigint, n: number) => Array.from({ length: n }, (_, i) => b + BigInt(i));
    const all = [...span(dData, 3), ...span(dK1, 2), ...span(dK2, 3)];
    expect(new Set(all.map(String)).size).toBe(all.length);

    // Element reads byte-identical.
    for (const [k, i, want] of [
      [K1, 0n, 11n],
      [K1, 1n, 12n],
      [K2, 0n, 21n],
      [K2, 1n, 22n],
      [K2, 2n, 23n],
    ] as const) {
      r = await eqCall(`getM ${k.toString(16).slice(0, 4)} ${i}`, encodeCall(sel('getM(address,uint256)'), [k, i]));
      expect(decodeUint(r.j.returnHex)).toBe(want);
    }
    for (const [i, want] of [
      [0n, 100n],
      [1n, 200n],
      [2n, 300n],
    ] as const) {
      r = await eqCall(`getDirect ${i}`, encodeCall(sel('getDirect(uint256)'), [i]));
      expect(decodeUint(r.j.returnHex)).toBe(want);
    }
  });

  it('pop some, then re-push: slot reuse reads NEW values; popped slots zeroed', async () => {
    // Pop tail of K2 (23 at index 2) and direct (300 at index 2).
    await eqCall('popM K2', encodeCall(sel('popM(address)'), [K2]));
    await eqCall('popDirect', encodeCall(sel('popDirect()'), []));

    let r = await eqCall('lenM K2 after pop', encodeCall(sel('lenM(address)'), [K2]));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    r = await eqCall('lenDirect after pop', encodeCall(sel('lenDirect()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(2n);

    // Popped slots must be zeroed (byte-identical to solc).
    await eqSlot(dK2 + 2n, 'm[K2][2] zeroed after pop');
    await eqSlot(dData + 2n, 'direct[2] zeroed after pop');

    // Re-push DIFFERENT values into the just-freed slots: must read the NEW value.
    await eqCall('repush M K2 77', encodeCall(sel('pushM(address,uint256)'), [K2, 77n]));
    await eqCall('repush Direct 777', encodeCall(sel('pushDirect(uint256)'), [777n]));

    await eqSlot(dK2 + 2n, 'm[K2][2] reused slot = 77');
    await eqSlot(dData + 2n, 'direct[2] reused slot = 777');

    r = await eqCall('getM K2 2 new', encodeCall(sel('getM(address,uint256)'), [K2, 2n]));
    expect(decodeUint(r.j.returnHex)).toBe(77n);
    r = await eqCall('getDirect 2 new', encodeCall(sel('getDirect(uint256)'), [2n]));
    expect(decodeUint(r.j.returnHex)).toBe(777n);

    // Untouched neighbors unchanged.
    r = await eqCall('getM K1 0 unchanged', encodeCall(sel('getM(address,uint256)'), [K1, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(11n);
  });

  it('overwrite via setM/setDirect then verify raw slot + isolation across keys', async () => {
    await eqCall('setM K1 1 -> 1212', encodeCall(sel('setM(address,uint256,uint256)'), [K1, 1n, 1212n]));
    await eqCall('setDirect 0 -> 1000', encodeCall(sel('setDirect(uint256,uint256)'), [0n, 1000n]));
    await eqSlot(dK1 + 1n, 'm[K1][1] after setM');
    await eqSlot(dData, 'direct[0] after setDirect');
    // K2 region untouched by K1 writes.
    await eqSlot(dK2, 'm[K2][0] still isolated');
    let r = await eqCall('getM K2 0', encodeCall(sel('getM(address,uint256)'), [K2, 0n]));
    expect(decodeUint(r.j.returnHex)).toBe(21n);
  });

  it('OOB index Panics(0x32) byte-identically', async () => {
    const r = await eqCall('getDirect OOB', encodeCall(sel('getDirect(uint256)'), [9n]));
    expect(r.j.success).toBe(false);
    const r2 = await eqCall('getM K1 OOB', encodeCall(sel('getM(address,uint256)'), [K1, 9n]));
    expect(r2.j.success).toBe(false);
    const r3 = await eqCall('setM K2 OOB', encodeCall(sel('setM(address,uint256,uint256)'), [K2, 9n, 1n]));
    expect(r3.j.success).toBe(false);
  });

  it('pop-to-empty then pop -> Panic(0x31) byte-identical, for m[K1] and direct', async () => {
    // Drain m[K1] (len 2) fully, then pop empty.
    await eqCall('popM K1 #1', encodeCall(sel('popM(address)'), [K1]));
    await eqCall('popM K1 #2', encodeCall(sel('popM(address)'), [K1]));
    let r = await eqCall('lenM K1 empty', encodeCall(sel('lenM(address)'), [K1]));
    expect(decodeUint(r.j.returnHex)).toBe(0n);
    const reM = await eqCall('popM K1 empty -> Panic', encodeCall(sel('popM(address)'), [K1]));
    expect(reM.j.success).toBe(false);

    // Drain direct fully (current len 3: original 3, popped 1, re-pushed 1), then pop empty.
    await eqCall('popDirect #1', encodeCall(sel('popDirect()'), []));
    await eqCall('popDirect #2', encodeCall(sel('popDirect()'), []));
    await eqCall('popDirect #3', encodeCall(sel('popDirect()'), []));
    r = await eqCall('lenDirect empty', encodeCall(sel('lenDirect()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0n);
    const reD = await eqCall('popDirect empty -> Panic', encodeCall(sel('popDirect()'), []));
    expect(reD.j.success).toBe(false);

    // K2 untouched by K1/direct drains.
    r = await eqCall('lenM K2 still 3', encodeCall(sel('lenM(address)'), [K2]));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
  });

  it('scalar s (slot 2) stayed untouched the entire run', async () => {
    expect(decodeUint(await readSlot(jeth, aj, 2n))).toBe(0n);
    await eqSlot(2n, 'scalar s');
    // Report any accumulated mismatches for visibility.
    expect(mismatches, JSON.stringify(mismatches, null, 2)).toEqual([]);
  });
});
