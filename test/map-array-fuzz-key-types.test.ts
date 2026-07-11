// Phase 4e-2b scenario "key-types": mapping<K, uint256[]> for
// K in {address, uint256, bytes32, uint64, int128}. For each key type we push
// several values across 2-3 distinct keys, verify .length, m[k][i] read, set
// m[k][i], pop, and assert byte-identical returndata / success / raw storage
// slots (per-key length slot keccak(pad(key).pad(base)) and data slot
// keccak(pad(lenSlot)) + element offsets) against solc. Also: per-key
// isolation (distinct keys don't collide), OOB Panic(0x32), pop-empty
// Panic(0x31). Solidity is the oracle; every probe must be byte-identical.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

// ---- key-derivation helpers (mirror Solidity exactly) ----
function pad32(v: bigint): string {
  // two's-complement 32-byte representation: negatives sign-extend like solc.
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
function kec(hex: string): bigint {
  return BigInt('0x' + toHex(keccak(hexToBytes(('0x' + hex) as `0x${string}`))));
}
const mapLenSlot = (k: bigint, base: bigint) => kec(pad32(k) + pad32(base));
const dataSlot = (lenSlot: bigint) => kec(pad32(lenSlot));

// ---- JETH source: one mapping<K, u256[]> per key type, distinct slots 0..4 ----
const JETH = `
class KeyTypes {
  ma: mapping<address, u256[]>;   // slot 0
  mu: mapping<u256, u256[]>;       // slot 1
  mb: mapping<bytes32, u256[]>;    // slot 2
  m6: mapping<u64, u256[]>;        // slot 3
  mi: mapping<i128, u256[]>;       // slot 4
  sentinel: u256;                   // slot 5

  pushA(k: address, v: u256): External<void> { this.ma[k].push(v); }
  popA(k: address): External<void> { this.ma[k].pop(); }
  setA(k: address, i: u256, v: u256): External<void> { this.ma[k][i] = v; }
  get lenA(k: address): External<u256> { return this.ma[k].length; }
  get atA(k: address, i: u256): External<u256> { return this.ma[k][i]; }

  pushU(k: u256, v: u256): External<void> { this.mu[k].push(v); }
  popU(k: u256): External<void> { this.mu[k].pop(); }
  setU(k: u256, i: u256, v: u256): External<void> { this.mu[k][i] = v; }
  get lenU(k: u256): External<u256> { return this.mu[k].length; }
  get atU(k: u256, i: u256): External<u256> { return this.mu[k][i]; }

  pushB(k: bytes32, v: u256): External<void> { this.mb[k].push(v); }
  popB(k: bytes32): External<void> { this.mb[k].pop(); }
  setB(k: bytes32, i: u256, v: u256): External<void> { this.mb[k][i] = v; }
  get lenB(k: bytes32): External<u256> { return this.mb[k].length; }
  get atB(k: bytes32, i: u256): External<u256> { return this.mb[k][i]; }

  push6(k: u64, v: u256): External<void> { this.m6[k].push(v); }
  pop6(k: u64): External<void> { this.m6[k].pop(); }
  set6(k: u64, i: u256, v: u256): External<void> { this.m6[k][i] = v; }
  get len6(k: u64): External<u256> { return this.m6[k].length; }
  get at6(k: u64, i: u256): External<u256> { return this.m6[k][i]; }

  pushI(k: i128, v: u256): External<void> { this.mi[k].push(v); }
  popI(k: i128): External<void> { this.mi[k].pop(); }
  setI(k: i128, i: u256, v: u256): External<void> { this.mi[k][i] = v; }
  get lenI(k: i128): External<u256> { return this.mi[k].length; }
  get atI(k: i128, i: u256): External<u256> { return this.mi[k][i]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract KeyTypes {
  mapping(address => uint256[]) ma;  // slot 0
  mapping(uint256 => uint256[]) mu;  // slot 1
  mapping(bytes32 => uint256[]) mb;  // slot 2
  mapping(uint64  => uint256[]) m6;  // slot 3
  mapping(int128  => uint256[]) mi;  // slot 4
  uint256 sentinel;                  // slot 5

  function pushA(address k, uint256 v) external { ma[k].push(v); }
  function popA(address k) external { ma[k].pop(); }
  function setA(address k, uint256 i, uint256 v) external { ma[k][i] = v; }
  function lenA(address k) external view returns (uint256){ return ma[k].length; }
  function atA(address k, uint256 i) external view returns (uint256){ return ma[k][i]; }

  function pushU(uint256 k, uint256 v) external { mu[k].push(v); }
  function popU(uint256 k) external { mu[k].pop(); }
  function setU(uint256 k, uint256 i, uint256 v) external { mu[k][i] = v; }
  function lenU(uint256 k) external view returns (uint256){ return mu[k].length; }
  function atU(uint256 k, uint256 i) external view returns (uint256){ return mu[k][i]; }

  function pushB(bytes32 k, uint256 v) external { mb[k].push(v); }
  function popB(bytes32 k) external { mb[k].pop(); }
  function setB(bytes32 k, uint256 i, uint256 v) external { mb[k][i] = v; }
  function lenB(bytes32 k) external view returns (uint256){ return mb[k].length; }
  function atB(bytes32 k, uint256 i) external view returns (uint256){ return mb[k][i]; }

  function push6(uint64 k, uint256 v) external { m6[k].push(v); }
  function pop6(uint64 k) external { m6[k].pop(); }
  function set6(uint64 k, uint256 i, uint256 v) external { m6[k][i] = v; }
  function len6(uint64 k) external view returns (uint256){ return m6[k].length; }
  function at6(uint64 k, uint256 i) external view returns (uint256){ return m6[k][i]; }

  function pushI(int128 k, uint256 v) external { mi[k].push(v); }
  function popI(int128 k) external { mi[k].pop(); }
  function setI(int128 k, uint256 i, uint256 v) external { mi[k][i] = v; }
  function lenI(int128 k) external view returns (uint256){ return mi[k].length; }
  function atI(int128 k, uint256 i) external view returns (uint256){ return mi[k][i]; }
}`;

// ABI selectors are identical between JETH (Solidity-canonical ABI) and solc,
// because every key type maps to its canonical ABI type:
//   address->address, u256->uint256, bytes32->bytes32, u64->uint64, i128->int128.
const SIG = {
  push: (t: string) => `push${t}(${ABI[t]},uint256)`,
  pop: (t: string) => `pop${t}(${ABI[t]})`,
  set: (t: string) => `set${t}(${ABI[t]},uint256,uint256)`,
  len: (t: string) => `len${t}(${ABI[t]})`,
  at: (t: string) => `at${t}(${ABI[t]},uint256)`,
};
const ABI: Record<string, string> = {
  A: 'address',
  U: 'uint256',
  B: 'bytes32',
  '6': 'uint64',
  I: 'int128',
};

// Per-key-type config: code-letter, base slot, and 2-3 distinct keys.
interface KT {
  name: string;
  code: string;
  base: bigint;
  keys: bigint[]; // canonical 32-byte-padded key values (negatives ok for i128)
}
const KTS: KT[] = [
  {
    name: 'address',
    code: 'A',
    base: 0n,
    keys: [BigInt('0x' + '11'.repeat(20)), BigInt('0x' + 'ab'.repeat(20)), BigInt('0x' + '00'.repeat(19) + '07')],
  },
  { name: 'uint256', code: 'U', base: 1n, keys: [0n, 1n, (1n << 256n) - 1n] },
  {
    name: 'bytes32',
    code: 'B',
    base: 2n,
    keys: [BigInt('0x' + 'de'.repeat(32)), BigInt('0x' + '00'.repeat(31) + '01'), (1n << 256n) - 5n],
  },
  { name: 'uint64', code: '6', base: 3n, keys: [0n, 42n, (1n << 64n) - 1n] },
  { name: 'int128', code: 'I', base: 4n, keys: [-1n, 7n, -(1n << 127n)] }, // exercise sign-extended keccak preimage
];

describe('mapping<K, uint256[]> key-types vs Solidity (byte-identical)', () => {
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
    if (jv !== sv) mismatches.push({ probe: `${label} (slot 0x${slot.toString(16)})`, jeth: jv, solidity: sv });
    expect(jv, label).toBe(sv);
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'KeyTypes.jeth' });
    const sb = compileSolidity(SOL, 'KeyTypes');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  for (const kt of KTS) {
    it(`key=${kt.name}: push/length/index/set/pop + raw slots, per-key isolation`, async () => {
      const c = kt.code;
      const k0 = kt.keys[0]!,
        k1 = kt.keys[1]!,
        k2 = kt.keys[2]!;

      // ---- push several values across distinct keys ----
      await eqCall(`${kt.name} push k0 #0`, encodeCall(sel(SIG.push(c)), [k0, 111n]));
      await eqCall(`${kt.name} push k0 #1`, encodeCall(sel(SIG.push(c)), [k0, 222n]));
      await eqCall(`${kt.name} push k0 #2`, encodeCall(sel(SIG.push(c)), [k0, 333n]));
      await eqCall(`${kt.name} push k1 #0`, encodeCall(sel(SIG.push(c)), [k1, 999n]));
      await eqCall(`${kt.name} push k1 #1`, encodeCall(sel(SIG.push(c)), [k1, 888n]));
      await eqCall(`${kt.name} push k2 #0`, encodeCall(sel(SIG.push(c)), [k2, 7n]));

      // ---- .length per key ----
      let r = await eqCall(`${kt.name} len k0`, encodeCall(sel(SIG.len(c)), [k0]));
      expect(decodeUint(r.j.returnHex)).toBe(3n);
      r = await eqCall(`${kt.name} len k1`, encodeCall(sel(SIG.len(c)), [k1]));
      expect(decodeUint(r.j.returnHex)).toBe(2n);
      r = await eqCall(`${kt.name} len k2`, encodeCall(sel(SIG.len(c)), [k2]));
      expect(decodeUint(r.j.returnHex)).toBe(1n);

      // ---- raw length slot + data slots match solc for every key ----
      for (const k of kt.keys) {
        await eqSlot(mapLenSlot(k, kt.base), `${kt.name} len-slot key=${k}`);
      }
      const ls0 = mapLenSlot(k0, kt.base);
      const d0 = dataSlot(ls0);
      await eqSlot(d0, `${kt.name} k0[0] data slot`);
      await eqSlot(d0 + 1n, `${kt.name} k0[1] data slot`);
      await eqSlot(d0 + 2n, `${kt.name} k0[2] data slot`);

      // ---- m[k][i] read ----
      r = await eqCall(`${kt.name} at k0 1`, encodeCall(sel(SIG.at(c)), [k0, 1n]));
      expect(decodeUint(r.j.returnHex)).toBe(222n);
      r = await eqCall(`${kt.name} at k1 0`, encodeCall(sel(SIG.at(c)), [k1, 0n]));
      expect(decodeUint(r.j.returnHex)).toBe(999n);

      // ---- set m[k][i] (write) + raw slot ----
      await eqCall(`${kt.name} set k0 0`, encodeCall(sel(SIG.set(c)), [k0, 0n, 12345n]));
      await eqSlot(d0, `${kt.name} k0[0] after set`);
      r = await eqCall(`${kt.name} at k0 0 (post-set)`, encodeCall(sel(SIG.at(c)), [k0, 0n]));
      expect(decodeUint(r.j.returnHex)).toBe(12345n);

      // ---- per-key isolation: k1/k2 untouched by k0 writes ----
      r = await eqCall(`${kt.name} at k1 1 (isolation)`, encodeCall(sel(SIG.at(c)), [k1, 1n]));
      expect(decodeUint(r.j.returnHex)).toBe(888n);
      r = await eqCall(`${kt.name} at k2 0 (isolation)`, encodeCall(sel(SIG.at(c)), [k2, 0n]));
      expect(decodeUint(r.j.returnHex)).toBe(7n);
      // k2's data slot must be distinct from k0/k1 (no collision) and equal to solc.
      const ls2 = mapLenSlot(k2, kt.base);
      await eqSlot(dataSlot(ls2), `${kt.name} k2[0] data slot (distinct)`);
      expect(dataSlot(ls2)).not.toBe(d0);

      // ---- pop: length shrinks, popped slot zeroed ----
      await eqCall(`${kt.name} pop k0`, encodeCall(sel(SIG.pop(c)), [k0]));
      r = await eqCall(`${kt.name} len k0 after pop`, encodeCall(sel(SIG.len(c)), [k0]));
      expect(decodeUint(r.j.returnHex)).toBe(2n);
      await eqSlot(d0 + 2n, `${kt.name} k0[2] zeroed after pop`);

      // ---- OOB index -> Panic(0x32) ----
      const oob = await eqCall(`${kt.name} at k0 OOB`, encodeCall(sel(SIG.at(c)), [k0, 5n]));
      expect(oob.j.success).toBe(false);
      // Panic(uint256) selector 0x4e487b71 with code 0x32
      expect(oob.j.returnHex).toBe('0x4e487b71' + '0000000000000000000000000000000000000000000000000000000000000032');

      // ---- pop down to empty, then pop empty -> Panic(0x31) ----
      await eqCall(`${kt.name} pop k0 b`, encodeCall(sel(SIG.pop(c)), [k0]));
      await eqCall(`${kt.name} pop k0 c`, encodeCall(sel(SIG.pop(c)), [k0]));
      r = await eqCall(`${kt.name} len k0 emptied`, encodeCall(sel(SIG.len(c)), [k0]));
      expect(decodeUint(r.j.returnHex)).toBe(0n);
      const pe = await eqCall(`${kt.name} pop k0 empty`, encodeCall(sel(SIG.pop(c)), [k0]));
      expect(pe.j.success).toBe(false);
      expect(pe.j.returnHex).toBe('0x4e487b71' + '0000000000000000000000000000000000000000000000000000000000000031');
    });
  }

  it('sentinel slot 5 untouched + no cross-mapping collisions; mismatch report empty', async () => {
    expect(decodeUint(await readSlot(jeth, aj, 5n))).toBe(0n);
    await eqSlot(5n, 'sentinel slot 5');
    if (mismatches.length) {
      // surface exact hex for any byte-level divergence
      console.error('MISMATCHES:', JSON.stringify(mismatches, null, 2));
    }
    expect(mismatches, 'all probes byte-identical to Solidity').toEqual([]);
  });
});
