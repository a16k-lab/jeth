// Phase 4e-1 scenario "all-field-types-struct":
// A dynamic array Big[] of a static struct with many field widths:
//   Big { uint8 a; int16 b; bool c; address d; bytes4 e; uint64 f; uint256 g; int128 h }
// Confirms the ABI head is UNPACKED (each leaf its own consecutive 32-byte word, NOT
// storage-packed): element stride = 8*32 = 256 bytes, leaf k of element i lives at
// tail word (i*8 + k). For each narrow leaf we probe via an element getter bigs[i].field:
//   - clean read -> byte-identical value to Solidity,
//   - dirty read -> EMPTY revert ('0x'), never masked,
//   - dirty-unread-while-reading-a-sibling -> OK (lazy per-access validation).
// Whole-array echo of this STRUCT array VALIDATES every field (reads all leaves), so a
// clean array round-trips byte-identically while ANY single dirty field -> EMPTY revert.
// Plus length, runtime OOB Panic(0x32), and short/malformed calldata. Solidity is the
// oracle: every probe (returndata, success, revert form 0x vs panic) must be byte-equal.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

// One element getter per leaf so each access is isolated/lazy; plus whole-array echo
// and length. Field order: a(u8) b(i16) c(bool) d(address) e(bytes4) f(u64) g(u256) h(i128).
const JETH = `
@struct class Big {
  a: u8;
  b: i16;
  c: bool;
  d: address;
  e: bytes4;
  f: u64;
  g: u256;
  h: i128;
}

@contract
class AllFieldTypes {
  @external @pure echo(bs: Big[]): Big[] { return bs; }
  @external @pure len(bs: Big[]): u256 { return bs.length; }
  @external @pure getA(bs: Big[], i: u256): u8      { return bs[i].a; }
  @external @pure getB(bs: Big[], i: u256): i16     { return bs[i].b; }
  @external @pure getC(bs: Big[], i: u256): bool    { return bs[i].c; }
  @external @pure getD(bs: Big[], i: u256): address { return bs[i].d; }
  @external @pure getE(bs: Big[], i: u256): bytes4  { return bs[i].e; }
  @external @pure getF(bs: Big[], i: u256): u64     { return bs[i].f; }
  @external @pure getG(bs: Big[], i: u256): u256    { return bs[i].g; }
  @external @pure getH(bs: Big[], i: u256): i128    { return bs[i].h; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AllFieldTypes {
  struct Big {
    uint8 a;
    int16 b;
    bool c;
    address d;
    bytes4 e;
    uint64 f;
    uint256 g;
    int128 h;
  }
  function echo(Big[] calldata bs) external pure returns (Big[] memory){ return bs; }
  function len(Big[] calldata bs) external pure returns (uint256){ return bs.length; }
  function getA(Big[] calldata bs, uint256 i) external pure returns (uint8)   { return bs[i].a; }
  function getB(Big[] calldata bs, uint256 i) external pure returns (int16)   { return bs[i].b; }
  function getC(Big[] calldata bs, uint256 i) external pure returns (bool)    { return bs[i].c; }
  function getD(Big[] calldata bs, uint256 i) external pure returns (address) { return bs[i].d; }
  function getE(Big[] calldata bs, uint256 i) external pure returns (bytes4)  { return bs[i].e; }
  function getF(Big[] calldata bs, uint256 i) external pure returns (uint64)  { return bs[i].f; }
  function getG(Big[] calldata bs, uint256 i) external pure returns (uint256) { return bs[i].g; }
  function getH(Big[] calldata bs, uint256 i) external pure returns (int128)  { return bs[i].h; }
}`;

// Tuple expansion of the struct for selector building. As the array element type the
// struct becomes a tuple: Big[] -> (uint8,int16,bool,address,bytes4,uint64,uint256,int128)[].
const TUP = '(uint8,int16,bool,address,bytes4,uint64,uint256,int128)';
const ECHO_SIG = `echo(${TUP}[])`;
const LEN_SIG = `len(${TUP}[])`;
const getSig = (fn: string) => `${fn}(${TUP}[],uint256)`;

const sel = (s: string) => functionSelector(s);

// Calldata builders. The dynamic-array param is encoded as: [offset to tail], then at
// the tail [length][flat element words]. Leaves are UNPACKED (one word each), so a flat
// of N elements has N*8 words in head order a,b,c,d,e,f,g,h per element.
// echo(bs): sole dynamic param -> head=[offset=0x20]; tail=[len][flat].
const echoData = (flat: bigint[], len: number) =>
  '0x' + sel(ECHO_SIG) + pad(0x20n) + pad(BigInt(len)) + flat.map(pad).join('');
// len(bs): same shape, just a different selector.
const lenData = (flat: bigint[], len: number) =>
  '0x' + sel(LEN_SIG) + pad(0x20n) + pad(BigInt(len)) + flat.map(pad).join('');
// getX(bs, i): (dynamic-array, uint256 i) -> head=[offset=0x40][i]; tail=[len][flat].
const getData = (fn: string, flat: bigint[], len: number, i: bigint) =>
  '0x' + sel(getSig(fn)) + pad(0x40n) + pad(i) + pad(BigInt(len)) + flat.map(pad).join('');

// Canonical leaf values (head order a,b,c,d,e,f,g,h).
const ADDR = BigInt('0x' + 'ab'.repeat(20));            // 160-bit address
const B4 = BigInt('0xdeadbeef') << (256n - 32n);        // bytes4 left-aligned
const I16 = ((-5n) % M + M) % M;                        // int16 = -5, sign-extended
const I128 = ((-123456789n) % M + M) % M;               // int128 negative, sign-extended
// one canonical Big element, in head order
const elem = (
  a: bigint, b: bigint, c: bigint, d: bigint, e: bigint, f: bigint, g: bigint, h: bigint,
) => [a, b, c, d, e, f, g, h];
const BIG0 = elem(0xa5n, I16, 1n, ADDR, B4, 0xdeadbeefcafebaben, 0x1122334455667788n, I128);
const BIG1 = elem(0x3cn, 7n, 0n, ADDR ^ 0xffn, B4 ^ (1n << 248n), 42n, M - 1n, 0x7fn);

// leaf index in head order for each field name
const LEAF: Record<string, number> = { a: 0, b: 1, c: 2, d: 3, e: 4, f: 5, g: 6, h: 7 };

describe('all-field-types-struct: Big[] dyn array of wide-leaf struct vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'AllFieldTypes.jeth' });
    const sb = compileSolidity(SOL, 'AllFieldTypes');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('each leaf sits at its own consecutive head word (ABI-unpacked, NOT storage-packed)', async () => {
    const flat = [...BIG0, ...BIG1]; // 2 elements, 16 tail words
    // distinct values per leaf via getter, read both elements
    const expectVal: [string, bigint, bigint][] = [
      ['getA', BIG0[0]!, BIG1[0]!],
      ['getB', BIG0[1]!, BIG1[1]!],
      ['getC', BIG0[2]!, BIG1[2]!],
      ['getD', BIG0[3]!, BIG1[3]!],
      ['getE', BIG0[4]!, BIG1[4]!],
      ['getF', BIG0[5]!, BIG1[5]!],
      ['getG', BIG0[6]!, BIG1[6]!],
      ['getH', BIG0[7]!, BIG1[7]!],
    ];
    for (const [fn, v0, v1] of expectVal) {
      const r0 = await eq(`${fn} i=0`, getData(fn, flat, 2, 0n));
      expect(r0.j.returnHex, `${fn} i=0 word`).toBe('0x' + pad(v0));
      const r1 = await eq(`${fn} i=1`, getData(fn, flat, 2, 1n));
      expect(r1.j.returnHex, `${fn} i=1 word`).toBe('0x' + pad(v1));
    }
  });

  it('length and runtime OOB index -> Panic(0x32)', async () => {
    const flat = [...BIG0, ...BIG1];
    const rl = await eq('len=2', lenData(flat, 2));
    expect(decodeUint(rl.j.returnHex)).toBe(2n);
    const rl0 = await eq('len=0', lenData([], 0));
    expect(decodeUint(rl0.j.returnHex)).toBe(0n);
    // OOB: len 2, read i=2 -> Panic(0x32)
    const oob = await eq('getA OOB i=2', getData('getA', flat, 2, 2n));
    expect(oob.j.success).toBe(false);
    expect(oob.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
    // OOB on a different field too, same panic
    const oobH = await eq('getH OOB i=5', getData('getH', flat, 2, 5n));
    expect(oobH.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
  });

  // dirty word per narrow leaf (non-canonical encoding). uint256 g has NO dirty form
  // (every 256-bit word is canonical), so it is excluded from dirty probes.
  const dirtyFor: Record<string, bigint> = {
    a: 1n << 8n,          // uint8: bit above byte 0 set
    b: 0x8000n,           // int16: low 16 bits negative (0x8000) but high bits 0 -> not sign-extended
    c: 2n,                // bool: not 0/1
    d: (1n << 200n) | ADDR, // address: high bits above 160 set
    e: B4 | 1n,           // bytes4: must be left-aligned, low 224 bits zero -> set a low bit
    f: 1n << 64n,         // uint64: bit 64 set
    h: 1n << 127n,        // int128: low 128 bits look negative, high bits 0 -> not sign-extended
  };

  it('dirty narrow leaf read -> EMPTY revert; reading a clean sibling -> OK (lazy)', async () => {
    for (const field of ['a', 'b', 'c', 'd', 'e', 'f', 'h']) {
      const k = LEAF[field]!;
      // build a single element whose leaf `field` is dirty, all others canonical (BIG0)
      const dirtyElem = [...BIG0];
      dirtyElem[k] = dirtyFor[field]!;
      const flat = dirtyElem; // 1 element
      // read the dirty field -> EMPTY revert, never masked
      const fnRead = 'get' + field.toUpperCase();
      const bad = await eq(`${fnRead} dirty read`, getData(fnRead, flat, 1, 0n));
      expect(bad.j.success, `${fnRead} dirty -> revert`).toBe(false);
      expect(bad.j.returnHex, `${fnRead} dirty -> empty`).toBe('0x');
      // read a CLEAN sibling field while this one stays dirty -> OK (lazy per-access)
      const sibling = field === 'g' ? 'a' : 'g'; // g (u256) is always clean; read it
      const fnSib = 'get' + sibling.toUpperCase();
      const ok = await eq(`${fnSib} clean (dirty ${field} unread)`, getData(fnSib, flat, 1, 0n));
      expect(ok.j.success, `${fnSib} clean amid dirty ${field}`).toBe(true);
      expect(ok.j.returnHex, `${fnSib} clean word`).toBe('0x' + pad(BIG0[LEAF[sibling]!]!));
    }
  });

  it('dirty leaf in a NON-indexed element is ignored when reading another index (lazy)', async () => {
    // element 0 clean (BIG0), element 1 has a dirty bool c; read element 0's c -> OK.
    const dirty1 = [...BIG1];
    dirty1[LEAF.c!] = 2n;
    const flat = [...BIG0, ...dirty1];
    const ok = await eq('getC i=0 (dirty c at i=1)', getData('getC', flat, 2, 0n));
    expect(ok.j.success).toBe(true);
    expect(ok.j.returnHex).toBe('0x' + pad(BIG0[LEAF.c!]!));
    // but reading element 1's c -> EMPTY revert
    const bad = await eq('getC i=1 (dirty)', getData('getC', flat, 2, 1n));
    expect(bad.j.success).toBe(false);
    expect(bad.j.returnHex).toBe('0x');
  });

  it('whole-array echo: clean round-trips byte-identically (validates every leaf)', async () => {
    // 0, 1, and 2 elements all clean -> identical returndata
    await eq('echo n=0', echoData([], 0));
    await eq('echo n=1', echoData([...BIG0], 1));
    await eq('echo n=2', echoData([...BIG0, ...BIG1], 2));
  });

  it('whole-array echo: ANY single dirty field -> EMPTY revert (struct echo reads all leaves)', async () => {
    // Unlike a value-element array (which cleans), a struct-element copy validates every
    // field, so dirtying any one narrow leaf in any element reverts EMPTY.
    for (const field of ['a', 'b', 'c', 'd', 'e', 'f', 'h']) {
      const k = LEAF[field]!;
      // dirty the field in element 1 of a 2-element array
      const d1 = [...BIG1];
      d1[k] = dirtyFor[field]!;
      const flat = [...BIG0, ...d1];
      const r = await eq(`echo dirty ${field}@1`, echoData(flat, 2));
      expect(r.j.success, `echo dirty ${field} -> revert`).toBe(false);
      expect(r.j.returnHex, `echo dirty ${field} -> empty`).toBe('0x');
    }
    // also dirty in element 0
    const d0 = [...BIG0];
    d0[LEAF.f!] = 1n << 64n;
    const rf = await eq('echo dirty f@0', echoData([...d0, ...BIG1], 2));
    expect(rf.j.success).toBe(false);
    expect(rf.j.returnHex).toBe('0x');
  });

  it('short / malformed calldata reverts EMPTY identically', async () => {
    // declares len=2 but supplies only 1 element (8 words) of payload -> empty revert
    const bad = '0x' + sel(ECHO_SIG) + pad(0x20n) + pad(2n) + BIG0.map(pad).join('');
    const rb = await eq('echo truncated payload', bad);
    expect(rb.j.success).toBe(false);
    expect(rb.j.returnHex).toBe('0x');
    // offset past calldata -> empty revert
    const off = '0x' + sel(LEN_SIG) + pad(0x1000n);
    const ro = await eq('len bad offset', off);
    expect(ro.j.success).toBe(false);
    expect(ro.j.returnHex).toBe('0x');
    // huge length that cannot fit payload -> empty revert (up-front payload check)
    const huge = '0x' + sel(ECHO_SIG) + pad(0x20n) + pad(1n << 64n) + BIG0.map(pad).join('');
    const rh = await eq('echo huge length', huge);
    expect(rh.j.success).toBe(false);
    expect(rh.j.returnHex).toBe('0x');
  });
});
