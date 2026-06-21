// Scenario s9-map-of-fixed-array-then-struct:
//   mapping<u256, Arr<Slot,2>> where Slot { lo: u128; hi: u128; }
// Access chain is mapKey + index(whole-slot struct element) + field:
//   this.book[k][i].lo  and  this.book[k][i].hi   for k,i in {0,1}.
// Layout to mirror (book is the only state var -> base slot 0):
//   map base = keccak256(pad32(k) . pad32(0))
//   Slot is u128+u128 -> packs into ONE slot (lo offset 0, hi offset 16),
//   so Arr<Slot,2> element i is at base + i (stride 1).
// Assert: byte-identical returndata vs Solidity mapping(uint256 => Slot[2]),
//   raw slots (base+0 and base+1, lo|hi packed), and OOB index Panic(0x32).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

// Two distinct u256 keys to exercise k in {0,1} semantics (use non-trivial values).
const K0 = BigInt('0x' + 'a1'.repeat(32)); // full 256-bit key
const K1 = 7n;

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
function mapSlot(keyWord: bigint, baseSlot: bigint): bigint {
  const buf = new Uint8Array(64);
  buf.set(hexToBytes(('0x' + pad32(keyWord)) as `0x${string}`), 0);
  buf.set(hexToBytes(('0x' + pad32(baseSlot)) as `0x${string}`), 32);
  return BigInt('0x' + toHex(keccak(buf)));
}

// JETH source. book is the only state var -> base slot 0.
const JETH = `// s9: mapping<u256, Arr<Slot,2>> where Slot{lo:u128; hi:u128}
@struct class Slot { lo: u128; hi: u128; }

@contract
class M {
  @state book: mapping<u256, Arr<Slot, 2>>; // slot 0

  @external setLo(k: u256, i: u256, v: u128): void { this.book[k][i].lo = v; }
  @external setHi(k: u256, i: u256, v: u128): void { this.book[k][i].hi = v; }
  @external @view getLo(k: u256, i: u256): u128 { return this.book[k][i].lo; }
  @external @view getHi(k: u256, i: u256): u128 { return this.book[k][i].hi; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract M {
  struct Slot { uint128 lo; uint128 hi; }
  mapping(uint256 => Slot[2]) book; // slot 0
  function setLo(uint256 k, uint256 i, uint128 v) external { book[k][i].lo = v; }
  function setHi(uint256 k, uint256 i, uint128 v) external { book[k][i].hi = v; }
  function getLo(uint256 k, uint256 i) external view returns (uint128){ return book[k][i].lo; }
  function getHi(uint256 k, uint256 i) external view returns (uint128){ return book[k][i].hi; }
}`;

describe('s9-map-of-fixed-array-then-struct vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  // Distinct u128 values per (key, index, field) so a wrong slot/offset surfaces.
  // lo/hi must each fit in u128 (< 2^128).
  const LO = (k: number, i: number) => BigInt('0x' + (0x100 + k * 0x10 + i).toString(16)) | (1n << 100n);
  const HI = (k: number, i: number) => BigInt('0xfeed' + (k * 2 + i).toString(16).padStart(2, '0')) | (1n << 120n);

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 's9.jeth' });
    const sb = compileSolidity(SOL, 'M');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('set/get this.book[k][i].lo and .hi for k,i in {0,1}; raw slots packed lo|hi', async () => {
    const keys = [K0, K1];
    // Write all (k,i) lo and hi.
    for (let kk = 0; kk < 2; kk++) {
      for (let i = 0; i < 2; i++) {
        const rl = await both(encodeCall(sel('setLo(uint256,uint256,uint128)'), [keys[kk]!, BigInt(i), LO(kk, i)]));
        expect(rl.j.success, `setLo(k${kk},i${i}) jeth success`).toBe(true);
        expect(rl.j.success).toBe(rl.s.success);
        expect(rl.j.returnHex, `setLo(k${kk},i${i}) returndata`).toBe(rl.s.returnHex);
        const rh = await both(encodeCall(sel('setHi(uint256,uint256,uint128)'), [keys[kk]!, BigInt(i), HI(kk, i)]));
        expect(rh.j.success, `setHi(k${kk},i${i}) jeth success`).toBe(true);
        expect(rh.j.success).toBe(rh.s.success);
        expect(rh.j.returnHex, `setHi(k${kk},i${i}) returndata`).toBe(rh.s.returnHex);
      }
    }
    // Raw slots: for each key, element i lives at base(k)+i; lo at offset 0, hi at offset 16.
    for (let kk = 0; kk < 2; kk++) {
      const base = mapSlot(keys[kk]!, 0n);
      for (let i = 0; i < 2; i++) {
        await eqSlot(base + BigInt(i), `book[k${kk}][${i}] slot (base+${i}, lo|hi packed)`);
        // Verify the packing matches expectation: raw == lo | (hi << 128).
        const raw = BigInt(await readSlot(jeth, aj, base + BigInt(i)));
        const expected = LO(kk, i) | (HI(kk, i) << 128n);
        expect(raw, `book[k${kk}][${i}] packing lo|(hi<<128)`).toBe(expected);
      }
    }
    // Getters byte-identical for every (k,i) field.
    for (let kk = 0; kk < 2; kk++) {
      for (let i = 0; i < 2; i++) {
        const gl = await both(encodeCall(sel('getLo(uint256,uint256)'), [keys[kk]!, BigInt(i)]));
        expect(decodeUint(gl.j.returnHex), `lo(k${kk},i${i}) value`).toBe(LO(kk, i));
        expect(gl.j.returnHex, `getLo(k${kk},i${i}) returndata`).toBe(gl.s.returnHex);
        const gh = await both(encodeCall(sel('getHi(uint256,uint256)'), [keys[kk]!, BigInt(i)]));
        expect(decodeUint(gh.j.returnHex), `hi(k${kk},i${i}) value`).toBe(HI(kk, i));
        expect(gh.j.returnHex, `getHi(k${kk},i${i}) returndata`).toBe(gh.s.returnHex);
      }
    }
  });

  it('keys are independent: writing k1 does not clobber k0 slots', async () => {
    const base0 = mapSlot(K0, 0n);
    const base1 = mapSlot(K1, 0n);
    // base0 and base1 must differ.
    expect(base0).not.toBe(base1);
    for (let i = 0; i < 2; i++) {
      await eqSlot(base0 + BigInt(i), `k0 element ${i} still identical`);
      await eqSlot(base1 + BigInt(i), `k1 element ${i} still identical`);
    }
    // Cross-check getters again post all writes.
    const gl = await both(encodeCall(sel('getLo(uint256,uint256)'), [K0, 0n]));
    expect(gl.j.returnHex).toBe(gl.s.returnHex);
  });

  it('OOB index this.book[k][2].lo read Panics(0x32) identically', async () => {
    const r = await both(encodeCall(sel('getLo(uint256,uint256)'), [K0, 2n]));
    expect(r.j.success, 'jeth getLo OOB reverts').toBe(false);
    expect(r.s.success, 'sol getLo OOB reverts').toBe(false);
    const PANIC32 =
      '0x4e487b71' +
      '0000000000000000000000000000000000000000000000000000000000000032';
    expect(r.j.returnHex, 'jeth Panic(0x32) returndata').toBe(PANIC32);
    expect(r.j.returnHex, 'jeth==sol revert returndata').toBe(r.s.returnHex);
  });

  it('OOB index this.book[k][2].hi write Panics(0x32) identically', async () => {
    const r = await both(encodeCall(sel('setHi(uint256,uint256,uint128)'), [K1, 2n, 0x99n]));
    expect(r.j.success, 'jeth setHi OOB reverts').toBe(false);
    expect(r.s.success, 'sol setHi OOB reverts').toBe(false);
    expect(r.j.returnHex, 'write OOB jeth==sol returndata').toBe(r.s.returnHex);
  });
});
