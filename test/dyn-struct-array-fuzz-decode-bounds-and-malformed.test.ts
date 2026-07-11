// Phase 4e-1 differential scenario "decode-bounds-and-malformed":
// Exhaustive decode validity for a dynamic array of static struct Pt[] (stride 2
// words / 64 bytes per element). We hand-build calldata word-by-word so we can
// craft malformed head/tail layouts (truncated payload, huge declared length,
// out-of-range offsets, non-32-aligned-but-valid offset, len=0, trailing junk)
// and assert JETH is BYTE-IDENTICAL to solc on every probe: success flag,
// returndata, and revert form (0x empty vs Panic 0x4e487b71...0032).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const sel = (s: string) => functionSelector(s);

// JETH source: reuse the Phase 4e-1 surface (Pt[] dynamic array of static struct).
const JETH = `// scenario decode-bounds-and-malformed
type Pt = { x: u128; y: u128; };

class DBM {
  get echoPts(ps: Pt[]): External<Pt[]> { return ps; }
  get ptX(ps: Pt[], i: u256): External<u128> { return ps[i].x; }
  get len(ps: Pt[]): External<u256> { return ps.length; }
}`;

// Faithful Solidity mirror (the oracle).
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract DBM {
  struct Pt { uint128 x; uint128 y; }
  function echoPts(Pt[] calldata ps) external pure returns (Pt[] memory){ return ps; }
  function ptX(Pt[] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].x; }
  function len(Pt[] calldata ps) external pure returns (uint256){ return ps.length; }
}`;

const ECHO = 'echoPts((uint128,uint128)[])';
const PTX = 'ptX((uint128,uint128)[],uint256)';
const LEN = 'len((uint128,uint128)[])';

// Build raw calldata from selector + an explicit list of 32-byte words (as bigints).
// Some cases need sub-word (non-32-aligned) padding; those pass an extra `tailHex`.
const build = (selSig: string, words: bigint[], tailHex = '') => '0x' + sel(selSig) + words.map(pad).join('') + tailHex;

describe('decode-bounds-and-malformed: Pt[] decode validity vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;

  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata\n jeth=${j.returnHex}\n sol =${s.returnHex}`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'DBM.jeth' });
    const sb = compileSolidity(SOL, 'DBM');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // ---- (1) exact-fit payload vs one word short --------------------------------
  it('(1) exact-fit payload OK; one word short -> EMPTY revert', async () => {
    // len=2 -> 2 elements * 2 words = 4 payload words. Offset 0x20 (relative to byte 4).
    // Head: [offset=0x20]; Tail at +0x20: [len=2][x0,y0,x1,y1]. Ends exactly at calldatasize.
    const exact = build(ECHO, [0x20n, 2n, 1n, 2n, 3n, 4n]);
    const re = await eq('echoPts exact-fit n=2', exact);
    expect(re.j.success).toBe(true);

    // One word short: declare len=2 (needs 4 words) but supply only 3 payload words.
    // Up-front payload check (len*stride must fit) fails -> EMPTY revert, no returndata.
    const short = build(ECHO, [0x20n, 2n, 1n, 2n, 3n]);
    const rs = await eq('echoPts one-word-short', short);
    expect(rs.j.success).toBe(false);
    expect(rs.j.returnHex).toBe('0x');

    // Also exercise via len(): exact-fit returns the length; short reverts EMPTY.
    const lenExact = build(LEN, [0x20n, 2n, 1n, 2n, 3n, 4n]);
    const rl = await eq('len exact-fit', lenExact);
    expect(decodeUint(rl.j.returnHex)).toBe(2n);
    const lenShort = build(LEN, [0x20n, 2n, 1n, 2n, 3n]);
    const rls = await eq('len one-word-short', lenShort);
    expect(rls.j.success).toBe(false);
    expect(rls.j.returnHex).toBe('0x');
  });

  // ---- (2) declared length absurdly huge --------------------------------------
  it('(2) declared length huge (2^64, 2^256-1) -> EMPTY revert', async () => {
    const huge64 = 1n << 64n;
    const huge256 = M - 1n; // 2^256-1
    for (const [name, L] of [
      ['2^64', huge64],
      ['2^256-1', huge256],
    ] as const) {
      // echoPts: huge length -> payload-size check overflows/cannot fit -> EMPTY.
      const e = build(ECHO, [0x20n, L]);
      const re = await eq(`echoPts huge-len ${name}`, e);
      expect(re.j.success).toBe(false);
      expect(re.j.returnHex).toBe('0x');
      // len(): solc still validates the array payload up-front on calldata decode,
      // so a huge declared length reverts EMPTY even though the body only reads .length.
      const l = build(LEN, [0x20n, L]);
      const rl = await eq(`len huge-len ${name}`, l);
      expect(rl.j.success).toBe(false);
      expect(rl.j.returnHex).toBe('0x');
    }
  });

  // ---- (3) offset out of range ------------------------------------------------
  it('(3) offset out of range (0x1000, 2^255) -> EMPTY revert', async () => {
    for (const [name, off] of [
      ['0x1000', 0x1000n],
      ['2^255', 1n << 255n],
    ] as const) {
      // echoPts with a single head word = bogus offset, no tail. Offset points past
      // calldata -> EMPTY. (Even with a tail present, 2^255 is unreachable.)
      const e = build(ECHO, [off]);
      const re = await eq(`echoPts bad-offset ${name}`, e);
      expect(re.j.success).toBe(false);
      expect(re.j.returnHex).toBe('0x');
      const l = build(LEN, [off]);
      const rl = await eq(`len bad-offset ${name}`, l);
      expect(rl.j.success).toBe(false);
      expect(rl.j.returnHex).toBe('0x');
    }
  });

  // ---- (4) offset NOT 32-aligned but pointing at a valid in-range array --------
  it('(4) non-32-aligned offset to a valid array -> OK (solc tolerates)', async () => {
    // We place the array [len=2][x0,y0,x1,y1] starting at byte 0x28 (40) relative to
    // byte 4, i.e. 8 bytes (non-multiple-of-32) past the head word. Layout after
    // selector:
    //   word0 (0x00..0x20): offset = 0x28
    //   0x20..0x28        : 8 bytes of filler
    //   0x28..            : len, then 4 payload words
    // offset 0x28 is in range and the full payload fits -> solc decodes fine.
    const head = pad(0x28n);
    const filler = '00'.repeat(8); // 8 bytes, makes the array start non-32-aligned
    const tail = [2n, 1n, 2n, 3n, 4n].map(pad).join('');
    const data = '0x' + sel(ECHO) + head + filler + tail;
    const re = await eq('echoPts non-aligned-offset', data);
    expect(re.j.success).toBe(true);
    // sanity: the echoed array must round-trip to the canonical encoding
    // [offset=0x20][len=2][x0,y0,x1,y1].
    expect(re.j.returnHex).toBe('0x' + [0x20n, 2n, 1n, 2n, 3n, 4n].map(pad).join(''));

    // Same idea through len(): must read length 2.
    const lenData = '0x' + sel(LEN) + head + filler + tail;
    const rl = await eq('len non-aligned-offset', lenData);
    expect(decodeUint(rl.j.returnHex)).toBe(2n);

    // And through ptX(ps, i): head has TWO words [offset_to_array][i]. Put the array
    // 8 bytes past the 2-word head (offset 0x48 rel byte 4) and read ps[1].x.
    const head2 = pad(0x48n) + pad(1n); // offset=0x48, i=1
    const data2 = '0x' + sel(PTX) + head2 + filler + tail;
    const rp = await eq('ptX non-aligned-offset i=1', data2);
    expect(decodeUint(rp.j.returnHex)).toBe(3n); // x1
  });

  // ---- (5) empty array len=0 --------------------------------------------------
  it('(5) empty array len=0: echo returns empty, any index -> Panic(0x32)', async () => {
    // echoPts len=0 -> canonical empty dynamic array re-encode [offset=0x20][len=0].
    const e = build(ECHO, [0x20n, 0n]);
    const re = await eq('echoPts len=0', e);
    expect(re.j.success).toBe(true);
    expect(re.j.returnHex).toBe('0x' + pad(0x20n) + pad(0n));

    // len() of the empty array -> 0.
    const l = build(LEN, [0x20n, 0n]);
    const rl = await eq('len len=0', l);
    expect(decodeUint(rl.j.returnHex)).toBe(0n);

    // Any index into a 0-length array -> Panic(0x32) (array-OOB / division panic code).
    const PANIC32 = '0x' + sel('Panic(uint256)') + pad(0x32n);
    for (const i of [0n, 1n, 5n]) {
      const p = build(PTX, [0x40n, i, 0n]); // head [offset=0x40][i], tail [len=0]
      const rp = await eq(`ptX into-empty i=${i}`, p);
      expect(rp.j.success).toBe(false);
      expect(rp.j.returnHex).toBe(PANIC32);
    }
  });

  // ---- (6) trailing junk after a valid array ----------------------------------
  it('(6) trailing junk after a valid array -> ignored, OK', async () => {
    // Valid len=2 array, then append extra junk words past the consumed payload.
    // solc ignores trailing calldata; JETH must too.
    const junk = ['dead'.repeat(16), 'beef'.repeat(16)].map((h) => h.padStart(64, '0')).join('');
    const data = build(ECHO, [0x20n, 2n, 1n, 2n, 3n, 4n], junk);
    const re = await eq('echoPts trailing-junk', data);
    expect(re.j.success).toBe(true);
    // Echo ignores the junk: canonical re-encode of just the 2 elements.
    expect(re.j.returnHex).toBe('0x' + [0x20n, 2n, 1n, 2n, 3n, 4n].map(pad).join(''));

    // Trailing junk + a field read still works (junk past the array is irrelevant).
    const dataP = build(PTX, [0x40n, 1n, 2n, 1n, 2n, 3n, 4n], junk);
    const rp = await eq('ptX trailing-junk i=1', dataP);
    expect(decodeUint(rp.j.returnHex)).toBe(3n); // x1
  });
});
