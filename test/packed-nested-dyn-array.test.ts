// JETH217 lift: a PACKED (<256-bit) element of a NESTED dynamic array reached through a struct field
// or a mapping value, e.g. `this.s.ps[i]` / `this.m[k].ps[i]` where `ps: u64[]`. The data lives at
// keccak(lenSlot) with packing (perSlot per slot, runtime byte offset) - the dynamic-array twin of the
// already-supported packed fixed-array-through-a-struct-field case. Byte-identical to solc 0.8.35 on
// raw storage slots + reads + OOB Panic 0x32, across element widths.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { keccak256 } from 'ethereum-cryptography/keccak.js';
import { hexToBytes, bytesToHex } from 'ethereum-cryptography/utils.js';

const sel = (s: string) => functionSelector(s);

describe('packed element of a nested dynamic array (JETH217) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  // u64[] (4 per slot) as a struct field AND as a mapping-of-struct value; plus a u16[] (16/slot) field.
  const J = `type S = { tag: u256; ps: u64[]; ws: u16[]; };
class C {
  s: S;
  m: mapping<u256, S>;
  pushP(v: u64): External<void> { this.s.ps.push(v); }
  pushW(v: u16): External<void> { this.s.ws.push(v); }
  setP(i: u256, v: u64): External<void> { this.s.ps[i] = v; }
  get getP(i: u256): External<u64> { return this.s.ps[i]; }
  get getW(i: u256): External<u16> { return this.s.ws[i]; }
  mPush(k: u256, v: u64): External<void> { this.m[k].ps.push(v); }
  mSet(k: u256, i: u256, v: u64): External<void> { this.m[k].ps[i] = v; }
  get mGet(k: u256, i: u256): External<u64> { return this.m[k].ps[i]; } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  struct S { uint256 tag; uint64[] ps; uint16[] ws; }
  S s;
  mapping(uint256 => S) m;
  function pushP(uint64 v) external { s.ps.push(v); }
  function pushW(uint16 v) external { s.ws.push(v); }
  function setP(uint256 i, uint64 v) external { s.ps[i] = v; }
  function getP(uint256 i) external view returns (uint64) { return s.ps[i]; }
  function getW(uint256 i) external view returns (uint16) { return s.ws[i]; }
  function mPush(uint256 k, uint64 v) external { m[k].ps.push(v); }
  function mSet(uint256 k, uint256 i, uint64 v) external { m[k].ps[i] = v; }
  function mGet(uint256 k, uint256 i) external view returns (uint64) { return m[k].ps[i]; } }`;

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });
  const both = async (data: string) => {
    await jeth.call(aj, data);
    await sol.call(as, data);
  };
  const eq = async (data: string, label: string) => {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
  };

  it('u64[] struct field: 6 packed elements across slots, write, read, OOB - raw slots match', async () => {
    for (const v of [10n, 20n, 30n, 40n, 50n, 60n]) await both('0x' + sel('pushP(uint64)') + pad32(v));
    await both('0x' + sel('setP(uint256,uint64)') + pad32(3n) + pad32(0xdeadn));
    for (let i = 0n; i < 6n; i++) await eq('0x' + sel('getP(uint256)') + pad32(i), `ps[${i}]`);
    await eq('0x' + sel('getP(uint256)') + pad32(6n), 'ps OOB'); // Panic 0x32
    // raw data slots: ps length at slot 1 (tag=0, ps=1, ws=2); data at keccak(1), 4 u64 per slot -> 2 slots
    const psData = BigInt('0x' + bytesToHex(keccak256(hexToBytes(pad32(1n)))));
    for (const k of [0n, 1n])
      expect(await readSlot(jeth, aj, psData + k), `ps data+${k}`).toBe(await readSlot(sol, as, psData + k));
    expect(await readSlot(jeth, aj, 1n)).toBe(await readSlot(sol, as, 1n)); // ps length
  });
  it('u16[] struct field (16 per slot): packing within one slot matches solc', async () => {
    for (const v of [1n, 2n, 3n, 4n, 65535n]) await both('0x' + sel('pushW(uint16)') + pad32(v));
    for (let i = 0n; i < 5n; i++) await eq('0x' + sel('getW(uint256)') + pad32(i), `ws[${i}]`);
    const wsData = BigInt('0x' + bytesToHex(keccak256(hexToBytes(pad32(2n)))));
    expect(await readSlot(jeth, aj, wsData)).toBe(await readSlot(sol, as, wsData)); // all 5 packed in slot 0
  });
  it('mapping<u256,S> packed dyn-array element: reads + write match solc', async () => {
    for (const [k, v] of [
      [1n, 11n],
      [1n, 22n],
      [1n, 33n],
      [2n, 99n],
    ] as const)
      await both('0x' + sel('mPush(uint256,uint64)') + pad32(k) + pad32(v));
    await both('0x' + sel('mSet(uint256,uint256,uint64)') + pad32(1n) + pad32(2n) + pad32(0xbeefn));
    for (const [k, i] of [
      [1n, 0n],
      [1n, 1n],
      [1n, 2n],
      [2n, 0n],
    ] as const)
      await eq('0x' + sel('mGet(uint256,uint256)') + pad32(k) + pad32(i), `m[${k}].ps[${i}]`);
    await eq('0x' + sel('mGet(uint256,uint256)') + pad32(2n) + pad32(5n), 'm OOB'); // Panic 0x32
  });
});
