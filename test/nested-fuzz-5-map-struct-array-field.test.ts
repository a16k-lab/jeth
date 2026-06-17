// Scenario s5-map-struct-array-field: mapping<address, Acct> where
// Acct { bal: u128; hist: Arr<u256,3> }. hist is a whole-slot-element fixed
// array struct field. Exercises this.accts[k].bal and this.accts[k].hist[i]
// (i in {0,1,2}) set/get, byte-identical vs Solidity, raw slots identical, and
// OOB this.accts[k].hist[3] read Panics(0x32) identically.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

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

// JETH source. accts is the only state var -> base slot 0.
// Within Acct: bal (u128) occupies offset 0 of the base slot; hist[0] is u256
// and needs a whole slot, so hist starts at +1: hist[i] at base+1+i.
const JETH = `// s5: mapping<address, Acct{ bal:u128; hist: Arr<u256,3> }>
@struct class Acct { bal: u128; hist: Arr<u256, 3>; }

@contract
class M {
  @state accts: mapping<address, Acct>; // slot 0

  @external setBal(k: address, v: u128): void { this.accts[k].bal = v; }
  @view getBal(k: address): u128 { return this.accts[k].bal; }

  @external setHist(k: address, i: u256, v: u256): void { this.accts[k].hist[i] = v; }
  @view getHist(k: address, i: u256): u256 { return this.accts[k].hist[i]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract M {
  struct Acct { uint128 bal; uint256[3] hist; }
  mapping(address => Acct) accts; // slot 0
  function setBal(address k, uint128 v) external { accts[k].bal = v; }
  function getBal(address k) external view returns (uint128){ return accts[k].bal; }
  function setHist(address k, uint256 i, uint256 v) external { accts[k].hist[i] = v; }
  function getHist(address k, uint256 i) external view returns (uint256){ return accts[k].hist[i]; }
}`;

describe('s5-map-struct-array-field vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 's5.jeth' });
    const sb = compileSolidity(SOL, 'M');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('bal: this.accts[k].bal set/get + raw base slot', async () => {
    const V = 0x0123456789abcdef0123n; // fits u128
    const r = await both(encodeCall(sel('setBal(address,uint128)'), [K, V]));
    expect(r.j.success, 'setBal jeth success').toBe(true);
    expect(r.j.success).toBe(r.s.success);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    const base = mapSlot(K, 0n); // accts base = keccak(pad(k) . pad(0))
    await eqSlot(base, 'accts[k] base slot (bal at offset 0)');
    const g = await both(encodeCall(sel('getBal(address)'), [K]));
    expect(decodeUint(g.j.returnHex)).toBe(V);
    expect(g.j.returnHex, 'getBal returndata').toBe(g.s.returnHex);
  });

  it('hist[i]: whole-slot fixed-array field set/get + raw slots base+1+i', async () => {
    const base = mapSlot(K, 0n);
    const vals = [
      (1n << 255n) | 0xdeadn, // hist[0]: high bit set, full word
      0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn, // hist[1]: all-ones
      0x42n, // hist[2]
    ];
    for (let i = 0; i < 3; i++) {
      const r = await both(
        encodeCall(sel('setHist(address,uint256,uint256)'), [K, BigInt(i), vals[i]!]),
      );
      expect(r.j.success, `setHist[${i}] jeth success`).toBe(true);
      expect(r.j.success).toBe(r.s.success);
      expect(r.j.returnHex).toBe(r.s.returnHex);
    }
    // Raw slots: hist[i] lives at base + 1 + i (bal consumed offset 0 of base).
    for (let i = 0; i < 3; i++) {
      await eqSlot(base + 1n + BigInt(i), `accts[k].hist[${i}] slot (base+1+${i})`);
    }
    // Getters byte-identical.
    for (let i = 0; i < 3; i++) {
      const g = await both(encodeCall(sel('getHist(address,uint256)'), [K, BigInt(i)]));
      expect(decodeUint(g.j.returnHex), `hist[${i}] value`).toBe(vals[i]);
      expect(g.j.returnHex, `getHist[${i}] returndata`).toBe(g.s.returnHex);
    }
  });

  it('bal stays packed in base slot; hist did not clobber it', async () => {
    const V = 0x0123456789abcdef0123n;
    const base = mapSlot(K, 0n);
    // base slot low 16 bytes == bal, high 16 bytes == 0 (hist is separate slots).
    const raw = BigInt(await readSlot(jeth, aj, base));
    expect(raw, 'base slot raw == bal (no high-bytes spill)').toBe(V);
    await eqSlot(base, 'base slot still identical after hist writes');
    // Re-read bal returndata equality.
    const g = await both(encodeCall(sel('getBal(address)'), [K]));
    expect(g.j.returnHex).toBe(g.s.returnHex);
  });

  it('OOB this.accts[k].hist[3] read Panics(0x32) identically', async () => {
    const r = await both(encodeCall(sel('getHist(address,uint256)'), [K, 3n]));
    expect(r.j.success, 'jeth getHist[3] reverts').toBe(false);
    expect(r.s.success, 'sol getHist[3] reverts').toBe(false);
    // Panic(0x32): selector 0x4e487b71 + abi.encode(uint256(0x32)).
    const PANIC32 =
      '0x4e487b71' +
      '0000000000000000000000000000000000000000000000000000000000000032';
    expect(r.j.returnHex, 'jeth Panic(0x32) returndata').toBe(PANIC32);
    expect(r.j.returnHex, 'jeth==sol revert returndata').toBe(r.s.returnHex);
  });

  it('OOB this.accts[k].hist[3] write Panics(0x32) identically (extra)', async () => {
    const r = await both(encodeCall(sel('setHist(address,uint256,uint256)'), [K, 3n, 7n]));
    expect(r.j.success).toBe(false);
    expect(r.s.success).toBe(false);
    expect(r.j.returnHex, 'write OOB jeth==sol').toBe(r.s.returnHex);
  });
});
