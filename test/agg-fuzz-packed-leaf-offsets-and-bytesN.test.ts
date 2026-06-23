// Phase 4d scenario "packed-leaf-offsets-and-bytesN":
// Struct Mix{bool a; uint8 b; int16 c; address d; bytes4 e; uint64 f; bytes32 g; int128 h}
// whose leaves are many different widths. Confirm each leaf sits at its OWN
// consecutive 32-byte ABI head word (NOT storage-packed) and is byte-identical to
// Solidity. Probe a dirty value for each narrow leaf (EMPTY revert) and a clean read
// of a sibling while another leaf is dirty (OK, lazy).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

// --- JETH source: one getter per leaf so each access is isolated/lazy. ---
const JETH = `
@struct class Mix {
  a: bool;
  b: u8;
  c: i16;
  d: address;
  e: bytes4;
  f: u64;
  g: bytes32;
  h: i128;
}

@contract
class PackedLeaves {
  @external @pure mixA(m: Mix): bool    { return m.a; }
  @external @pure mixB(m: Mix): u8      { return m.b; }
  @external @pure mixC(m: Mix): i16     { return m.c; }
  @external @pure mixD(m: Mix): address { return m.d; }
  @external @pure mixE(m: Mix): bytes4  { return m.e; }
  @external @pure mixF(m: Mix): u64     { return m.f; }
  @external @pure mixG(m: Mix): bytes32 { return m.g; }
  @external @pure mixH(m: Mix): i128    { return m.h; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PackedLeaves {
  struct Mix {
    bool a;
    uint8 b;
    int16 c;
    address d;
    bytes4 e;
    uint64 f;
    bytes32 g;
    int128 h;
  }
  function mixA(Mix calldata m) external pure returns (bool)    { return m.a; }
  function mixB(Mix calldata m) external pure returns (uint8)   { return m.b; }
  function mixC(Mix calldata m) external pure returns (int16)   { return m.c; }
  function mixD(Mix calldata m) external pure returns (address) { return m.d; }
  function mixE(Mix calldata m) external pure returns (bytes4)  { return m.e; }
  function mixF(Mix calldata m) external pure returns (uint64)  { return m.f; }
  function mixG(Mix calldata m) external pure returns (bytes32) { return m.g; }
  function mixH(Mix calldata m) external pure returns (int128)  { return m.h; }
}`;

// The struct param expands to a tuple; as the sole arg it is wrapped in the
// function's own parens -> double parens. One head word per leaf.
const TUP = '((bool,uint8,int16,address,bytes4,uint64,bytes32,int128))';

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}

describe('packed-leaf-offsets-and-bytesN: ABI head is unpacked, one word per leaf', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  function raw(selSig: string, words: bigint[]): string {
    return '0x' + sel(selSig) + words.map(pad).join('');
  }
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eq(label: string, data: string) {
    const { j, s } = await both(data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  // Canonical leaf values (left-aligned for bytesN; sign/zero correct).
  const ADDR = BigInt('0x' + 'ab'.repeat(20)); // 160-bit address
  const B4 = BigInt('0xdeadbeef') << (256n - 32n); // bytes4 left-aligned
  const B32 = BigInt('0x' + 'ff'.repeat(16) + '00'.repeat(16)); // arbitrary full word
  // int16 = -5 -> sign-extended 256-bit; int128 = -123456789
  const I16 = ((-5n % M) + M) % M;
  const I128 = ((-123456789n % M) + M) % M;
  // canonical struct words, in head order a,b,c,d,e,f,g,h
  const OK = [1n, 0xa5n, I16, ADDR, B4, 0xdeadbeefcafebaben, B32, I128];

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'PackedLeaves.jeth' });
    const sb = compileSolidity(SOL, 'PackedLeaves');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('each leaf is at its own consecutive 32-byte head word, byte-identical to Solidity', async () => {
    // a=word0, b=word1, c=word2, d=word3, e=word4, f=word5, g=word6, h=word7
    const ra = await eq('mixA', raw('mixA' + TUP, OK));
    expect(ra.j.returnHex).toBe('0x' + pad(1n)); // bool true

    const rb = await eq('mixB', raw('mixB' + TUP, OK));
    expect(decodeUint(rb.j.returnHex)).toBe(0xa5n);

    const rc = await eq('mixC', raw('mixC' + TUP, OK));
    expect(rc.j.returnHex).toBe('0x' + pad(I16)); // -5 sign-extended

    const rd = await eq('mixD', raw('mixD' + TUP, OK));
    expect(decodeUint(rd.j.returnHex)).toBe(ADDR);

    const re = await eq('mixE', raw('mixE' + TUP, OK));
    expect(re.j.returnHex).toBe('0x' + pad(B4)); // bytes4 left-aligned

    const rf = await eq('mixF', raw('mixF' + TUP, OK));
    expect(decodeUint(rf.j.returnHex)).toBe(0xdeadbeefcafebaben);

    const rg = await eq('mixG', raw('mixG' + TUP, OK));
    expect(rg.j.returnHex).toBe('0x' + pad(B32));

    const rh = await eq('mixH', raw('mixH' + TUP, OK));
    expect(rh.j.returnHex).toBe('0x' + pad(I128)); // -123456789 sign-extended
  });

  it('proves head is UNPACKED: shifting a leaf into the next word changes only that leaf', async () => {
    // If the head were storage-packed (bool|uint8|int16 in one word) the compiler
    // would read b/c from byte offsets inside word0. Instead each leaf reads its own
    // word: writing distinct values at words 0..7 yields each independently.
    const w = [7n, 0x11n, 0x22n, ADDR, B4, 0x33n, B32, 0x44n];
    expect(decodeUint((await eq('uB', raw('mixB' + TUP, w))).j.returnHex)).toBe(0x11n);
    expect(decodeUint((await eq('uC', raw('mixC' + TUP, w))).j.returnHex)).toBe(0x22n);
    expect(decodeUint((await eq('uF', raw('mixF' + TUP, w))).j.returnHex)).toBe(0x33n);
    expect(decodeUint((await eq('uH', raw('mixH' + TUP, w))).j.returnHex)).toBe(0x44n);
    // bool word0 = 7 is NOT canonical -> dirty read reverts (also proves a is its own word).
    const ra = await eq('uA dirty(7)', raw('mixA' + TUP, w));
    expect(ra.j.success).toBe(false);
    expect(ra.j.returnHex).toBe('0x');
  });

  it('dirty narrow leaf reverts EMPTY on read (lazy per-access validation)', async () => {
    // bool a: 2 is non-canonical
    let r = await eq('dirty a=2', raw('mixA' + TUP, [2n, ...OK.slice(1)]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // uint8 b: high bit above byte 0 set
    r = await eq('dirty b', raw('mixB' + TUP, [OK[0]!, 1n << 8n, ...OK.slice(2)]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // int16 c: not sign-extended (low 16 bits = 0x8000 negative, but high bits 0 -> dirty)
    const cDirty = 0x8000n; // signextend(16) would set high bits; this has them 0
    r = await eq('dirty c', raw('mixC' + TUP, [OK[0]!, OK[1]!, cDirty, ...OK.slice(3)]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // address d: high 96 bits dirty
    r = await eq('dirty d', raw('mixD' + TUP, [...OK.slice(0, 3), (1n << 200n) | ADDR, ...OK.slice(4)]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // bytes4 e: low bit set (must be left-aligned, low 224 bits zero)
    r = await eq('dirty e', raw('mixE' + TUP, [...OK.slice(0, 4), B4 | 1n, ...OK.slice(5)]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // uint64 f: bit 64 set
    r = await eq('dirty f', raw('mixF' + TUP, [...OK.slice(0, 5), 1n << 64n, ...OK.slice(6)]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // int128 h: low 128 bits look negative but high bits 0 -> not sign-extended
    const hDirty = 1n << 127n;
    r = await eq('dirty h', raw('mixH' + TUP, [...OK.slice(0, 7), hDirty]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('lazy: a sibling clean read succeeds while ANOTHER leaf is dirty', async () => {
    // Make EVERY narrow leaf except the one being read dirty; the read must still
    // succeed because only the accessed leaf is validated.
    // Read b (clean) while a,c,d,e,f,h are all dirty:
    const dirtyAll = [
      2n, // a dirty
      0xa5n, // b CLEAN (read target)
      0x8000n, // c dirty
      1n << 200n, // d dirty
      B4 | 1n, // e dirty
      1n << 64n, // f dirty
      B32, // g (full word, never dirty)
      1n << 127n, // h dirty
    ];
    const r = await eq('clean b amid dirty siblings', raw('mixB' + TUP, dirtyAll));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0xa5n);

    // And read g (full word, always canonical) amid the same dirt:
    const rg = await eq('clean g amid dirty siblings', raw('mixG' + TUP, dirtyAll));
    expect(rg.j.success).toBe(true);
    expect(rg.j.returnHex).toBe('0x' + pad(B32));

    // Read a (the dirty leaf itself) -> revert empty, confirming the dirt is real.
    const ra = await eq('dirty a amid dirty siblings', raw('mixA' + TUP, dirtyAll));
    expect(ra.j.success).toBe(false);
    expect(ra.j.returnHex).toBe('0x');
  });

  it('short calldata (< 4 + 8*32 = 260 bytes) reverts EMPTY identically', async () => {
    // supply only 7 head words; reading any leaf needs the full 8-word head present
    const short = '0x' + sel('mixH' + TUP) + OK.slice(0, 7).map(pad).join('');
    const r = await eq('mixH short', short);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });
});
