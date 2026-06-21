// Scenario s2-map-struct-multikey: two maps in one contract over a packed Acct
// struct, keyed by bytes32 and u256. Differential vs Solidity: byte-identical
// getters + raw mapped-slot equality for both maps.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
function mapSlot(keyWord: bigint, baseSlot: bigint): bigint {
  const buf = new Uint8Array(64);
  buf.set(hexToBytes(('0x' + pad32(keyWord)) as `0x${string}`), 0);
  buf.set(hexToBytes(('0x' + pad32(baseSlot)) as `0x${string}`), 32);
  return BigInt('0x' + toHex(keccak(buf)));
}

// Fixed keys.
const BKEY = BigInt('0x' + 'ab'.repeat(32)); // bytes32 key
const UKEY = 0xdeadbeefn;                     // u256 key

const JETH = `// s2-map-struct-multikey
@struct class Acct { bal: u128; nonce: u64; active: bool; }

@contract
class MultiKey {
  @state bm: mapping<bytes32, Acct>; // slot 0
  @state um: mapping<u256, Acct>;    // slot 1

  @external setBBal(k: bytes32, v: u128): void { this.bm[k].bal = v; }
  @external setBNonce(k: bytes32, v: u64): void { this.bm[k].nonce = v; }
  @external setBActive(k: bytes32, v: bool): void { this.bm[k].active = v; }
  @external @view getBBal(k: bytes32): u128 { return this.bm[k].bal; }
  @external @view getBNonce(k: bytes32): u64 { return this.bm[k].nonce; }
  @external @view getBActive(k: bytes32): bool { return this.bm[k].active; }

  @external setUBal(k: u256, v: u128): void { this.um[k].bal = v; }
  @external setUNonce(k: u256, v: u64): void { this.um[k].nonce = v; }
  @external setUActive(k: u256, v: bool): void { this.um[k].active = v; }
  @external @view getUBal(k: u256): u128 { return this.um[k].bal; }
  @external @view getUNonce(k: u256): u64 { return this.um[k].nonce; }
  @external @view getUActive(k: u256): bool { return this.um[k].active; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MultiKey {
  struct Acct { uint128 bal; uint64 nonce; bool active; }
  mapping(bytes32 => Acct) bm; // slot 0
  mapping(uint256 => Acct) um; // slot 1

  function setBBal(bytes32 k, uint128 v) external { bm[k].bal = v; }
  function setBNonce(bytes32 k, uint64 v) external { bm[k].nonce = v; }
  function setBActive(bytes32 k, bool v) external { bm[k].active = v; }
  function getBBal(bytes32 k) external view returns (uint128){ return bm[k].bal; }
  function getBNonce(bytes32 k) external view returns (uint64){ return bm[k].nonce; }
  function getBActive(bytes32 k) external view returns (bool){ return bm[k].active; }

  function setUBal(uint256 k, uint128 v) external { um[k].bal = v; }
  function setUNonce(uint256 k, uint64 v) external { um[k].nonce = v; }
  function setUActive(uint256 k, bool v) external { um[k].active = v; }
  function getUBal(uint256 k) external view returns (uint128){ return um[k].bal; }
  function getUNonce(uint256 k) external view returns (uint64){ return um[k].nonce; }
  function getUActive(uint256 k) external view returns (bool){ return um[k].active; }
}`;

describe('s2-map-struct-multikey: two maps of packed struct vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqSlot(slot: bigint, label: string) {
    const jv = await readSlot(jeth, aj, slot);
    const sv = await readSlot(sol, as, slot);
    expect(jv, label).toBe(sv);
    return { jv, sv };
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'MultiKey.jeth' });
    const sb = compileSolidity(SOL, 'MultiKey');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('bytes32 map: set/get every field, byte-identical + raw slot', async () => {
    await both(encodeCall(sel('setBBal(bytes32,uint128)'), [BKEY, 0x1111222233334444n]));
    await both(encodeCall(sel('setBNonce(bytes32,uint64)'), [BKEY, 0x55n]));
    await both(encodeCall(sel('setBActive(bytes32,bool)'), [BKEY, 1n]));

    // Raw packed slot for bm[BKEY]: keccak(pad32(key) . pad32(0)).
    const slot = mapSlot(BKEY, 0n);
    const { jv } = await eqSlot(slot, 'bm[BKEY] packed slot');
    // Sanity: the packed layout must reflect all three fields (non-zero, low 16
    // bytes = bal, next 8 = nonce, next byte = active).
    const word = BigInt(jv);
    expect(word & ((1n << 128n) - 1n)).toBe(0x1111222233334444n);            // bal
    expect((word >> 128n) & ((1n << 64n) - 1n)).toBe(0x55n);                  // nonce
    expect((word >> 192n) & 0xffn).toBe(1n);                                  // active

    for (const g of ['getBBal(bytes32)', 'getBNonce(bytes32)', 'getBActive(bytes32)']) {
      const r = await both(encodeCall(sel(g), [BKEY]));
      expect(r.j.success, g).toBe(true);
      expect(r.j.returnHex, g).toBe(r.s.returnHex);
    }
    // Spot-check decoded values too.
    let r = await both(encodeCall(sel('getBBal(bytes32)'), [BKEY]));
    expect(decodeUint(r.j.returnHex)).toBe(0x1111222233334444n);
    r = await both(encodeCall(sel('getBNonce(bytes32)'), [BKEY]));
    expect(decodeUint(r.j.returnHex)).toBe(0x55n);
    r = await both(encodeCall(sel('getBActive(bytes32)'), [BKEY]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
  });

  it('u256 map: set/get every field, byte-identical + raw slot', async () => {
    await both(encodeCall(sel('setUBal(uint256,uint128)'), [UKEY, 0xaaaabbbbccccddddn]));
    await both(encodeCall(sel('setUNonce(uint256,uint64)'), [UKEY, 0x99n]));
    await both(encodeCall(sel('setUActive(uint256,bool)'), [UKEY, 1n]));

    const slot = mapSlot(UKEY, 1n);
    const { jv } = await eqSlot(slot, 'um[UKEY] packed slot');
    const word = BigInt(jv);
    expect(word & ((1n << 128n) - 1n)).toBe(0xaaaabbbbccccddddn);
    expect((word >> 128n) & ((1n << 64n) - 1n)).toBe(0x99n);
    expect((word >> 192n) & 0xffn).toBe(1n);

    for (const g of ['getUBal(uint256)', 'getUNonce(uint256)', 'getUActive(uint256)']) {
      const r = await both(encodeCall(sel(g), [UKEY]));
      expect(r.j.success, g).toBe(true);
      expect(r.j.returnHex, g).toBe(r.s.returnHex);
    }
    let r = await both(encodeCall(sel('getUBal(uint256)'), [UKEY]));
    expect(decodeUint(r.j.returnHex)).toBe(0xaaaabbbbccccddddn);
    r = await both(encodeCall(sel('getUNonce(uint256)'), [UKEY]));
    expect(decodeUint(r.j.returnHex)).toBe(0x99n);
    r = await both(encodeCall(sel('getUActive(uint256)'), [UKEY]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
  });

  it('maps are independent: bm[k] and um[k] for same key word do not collide', async () => {
    // Same numeric key value in both maps must land in different slots and not
    // bleed values across. Use a key that is valid both as bytes32 and uint256.
    const SHARED = 0x42n;
    await both(encodeCall(sel('setBBal(bytes32,uint128)'), [SHARED, 0x7n]));
    await both(encodeCall(sel('setUBal(uint256,uint128)'), [SHARED, 0x8n]));

    const bSlot = mapSlot(SHARED, 0n);
    const uSlot = mapSlot(SHARED, 1n);
    expect(bSlot).not.toBe(uSlot);
    await eqSlot(bSlot, 'bm[SHARED] slot');
    await eqSlot(uSlot, 'um[SHARED] slot');

    let r = await both(encodeCall(sel('getBBal(bytes32)'), [SHARED]));
    expect(r.j.returnHex).toBe(r.s.returnHex);
    expect(decodeUint(r.j.returnHex)).toBe(0x7n);
    r = await both(encodeCall(sel('getUBal(uint256)'), [SHARED]));
    expect(r.j.returnHex).toBe(r.s.returnHex);
    expect(decodeUint(r.j.returnHex)).toBe(0x8n);
  });

  it('untouched key reads zero, byte-identical', async () => {
    const OTHER = BigInt('0x' + '11'.repeat(32));
    for (const g of ['getBBal(bytes32)', 'getBNonce(bytes32)', 'getBActive(bytes32)']) {
      const r = await both(encodeCall(sel(g), [OTHER]));
      expect(r.j.returnHex, g).toBe(r.s.returnHex);
      expect(decodeUint(r.j.returnHex)).toBe(0n);
    }
  });
});
