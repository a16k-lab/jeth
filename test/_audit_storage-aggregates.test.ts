// AUDIT (storage-aggregates): adversarial differential test vs solc (cancun, opt on).
//
// Targets the storage-aggregate attack surface: packed & nested structs, fixed &
// dynamic arrays, nested arrays, mappings (as struct field, nested, to array, to
// bytes), bytes/string. Operations: R/W/RMW, push/pop (multi-slot + dynamic
// elements + freed-tail raw verify), length, whole-aggregate assign/copy
// (struct / dynamic array / whole fixed array), delete (value/packed/struct/
// array/dynamic-bytes/mapping-value leaving mapping intact), packed-neighbor
// preservation, and slot reuse after pop/delete/shrink.
//
// Every mutation compares success + returndata AND a broad set of raw storage
// slots (direct + computed keccak data slots) byte-for-byte. Calldata is pushed
// adversarially: dirty high bits in narrow ints / bool / short bytesN, boundary
// values (0, max, signed min/max), OOB indices (Panic 0x32), and malformed
// dynamic offsets/lengths.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const mod = (v: bigint) => ((v % M) + M) % M;
const pad = (v: bigint) => mod(v).toString(16).padStart(64, '0');
const b32 = (v: bigint) => Buffer.from(pad(v), 'hex');
// keccak(slot) - data slot of a dynamic array / long string at `slot`.
const kec = (n: bigint) => BigInt('0x' + toHex(keccak(b32(n))));
// keccak(key . base) - mapping value slot for m[key] where m is at `base`.
const mapSlot = (key: bigint, base: bigint) => BigInt('0x' + toHex(keccak(Buffer.concat([b32(key), b32(base)]))));

// Build calldata: selector + 32-byte-padded static words (raw, no masking - dirty allowed).
function raw(selSig: string, words: bigint[] = []): string {
  return '0x' + sel(selSig) + words.map(pad).join('');
}
// Build calldata for a fn with a trailing dynamic string/bytes arg (after `head` static words).
function dynArg(selSig: string, head: bigint[], s: string): string {
  const b = Buffer.from(s, 'utf8');
  const padded = Buffer.concat([b, Buffer.alloc((32 - (b.length % 32)) % 32)]);
  let h = '0x' + sel(selSig);
  for (const w of head) h += pad(w);
  h += pad(BigInt((head.length + 1) * 32)) + pad(BigInt(b.length)) + padded.toString('hex');
  return h;
}

interface Pair {
  jeth: Harness;
  sol: Harness;
  aj: Address;
  as: Address;
}

async function build(jethSrc: string, solSrc: string, name = 'C'): Promise<Pair> {
  const jb = compile(jethSrc, { fileName: name + '.jeth' });
  const sb = compileSolidity(solSrc, name);
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  return { jeth, sol, aj, as };
}

// Run one piece of calldata on both, compare success + returndata + each raw slot.
async function step(p: Pair, label: string, data: string, slots: bigint[]) {
  const j = await p.jeth.call(p.aj, data);
  const s = await p.sol.call(p.as, data);
  expect(j.success, `${label}: success (jeth err=${j.exceptionError})`).toBe(s.success);
  expect(j.returnHex, `${label}: returndata`).toBe(s.returnHex);
  for (const slot of slots) {
    expect(await readSlot(p.jeth, p.aj, slot), `${label}: slot 0x${slot.toString(16)}`).toBe(
      await readSlot(p.sol, p.as, slot),
    );
  }
}

// Run a sequence of [label,data] calls, comparing slots after EACH call.
async function seq(p: Pair, slots: bigint[], steps: [string, string][]) {
  for (const [label, data] of steps) await step(p, label, data, slots);
}

const LONG = 'this string is definitely longer than thirty-two bytes so it spills to keccak data slots____';
const LONG2 = 'another distinct long payload that also exceeds the thirty-one byte short-string inline limit';
const SHORT = 'hi';
const MAXU = M - 1n;

// ===========================================================================
// 1. Packed struct: full-slot dirty fields, RMW, neighbor preservation.
// ===========================================================================
describe('storage-agg: packed struct mixed widths, dirty calldata', () => {
  const JETH = `type S = { a: u8; b: i16; c: bool; d: bytes3; e: u64; f: address; };
class C {
  pre: u256;       // slot 0 guard
  s: S;            // slot 1 (8+16+8+24+64+160 = 280 bits > 256 -> 2 slots)
  post: u256;      // guard
  setA(v: u8): External<void> { this.s.a = v; }
  setB(v: i16): External<void> { this.s.b = v; }
  setC(v: bool): External<void> { this.s.c = v; }
  setD(v: bytes3): External<void> { this.s.d = v; }
  setE(v: u64): External<void> { this.s.e = v; }
  setF(v: address): External<void> { this.s.f = v; }
  addB(v: i16): External<void> { this.s.b += v; }
  setPre(v: u256): External<void> { this.pre = v; }
  setPost(v: u256): External<void> { this.post = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint8 a; int16 b; bool c; bytes3 d; uint64 e; address f; }
  uint256 pre; S s; uint256 post;
  function setA(uint8 v) external { s.a = v; }
  function setB(int16 v) external { s.b = v; }
  function setC(bool v) external { s.c = v; }
  function setD(bytes3 v) external { s.d = v; }
  function setE(uint64 v) external { s.e = v; }
  function setF(address v) external { s.f = v; }
  function addB(int16 v) external { s.b += v; }
  function setPre(uint256 v) external { pre = v; }
  function setPost(uint256 v) external { post = v; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const slots = [0n, 1n, 2n, 3n];

  it('dirty narrow ints / bool / short bytesN must be masked identically', async () => {
    await seq(p, slots, [
      ['setPre', raw('setPre(uint256)', [MAXU])],
      ['setPost', raw('setPost(uint256)', [MAXU])],
      // a: u8 with garbage high bits -> must truncate to 0xff
      ['setA dirty', raw('setA(uint8)', [(MAXU << 8n) | 0xffn])],
      // b: i16 with garbage above 16 bits, value -1 worth
      ['setB dirty', raw('setB(int16)', [MAXU])],
      // c: bool with garbage (only LSB matters)
      ['setC dirty', raw('setC(bool)', [(0xdeadn << 8n) | 1n])],
      // d: bytes3 with garbage in low 29 bytes (only top 3 matter)
      ['setD dirty', raw('setD(bytes3)', [(0xaabbccn << 232n) | 0xffffffffffn])],
      // e: u64 dirty high
      ['setE dirty', raw('setE(uint64)', [(MAXU << 64n) | 0x1122334455667788n])],
      // f: address dirty high 96 bits
      ['setF dirty', raw('setF(address)', [(MAXU << 160n) | 0x1234567890abcdef1234567890abcdef12345678n])],
    ]);
  });

  it('RMW addB across overflow wrap on packed signed field', async () => {
    await seq(p, slots, [
      ['setB max', raw('setB(int16)', [0x7fffn])],
      ['addB +1 (overflow -> revert parity)', raw('addB(int16)', [1n])],
      ['setB to -1', raw('setB(int16)', [MAXU])],
      ['addB +2', raw('addB(int16)', [2n])],
    ]);
  });
});

// ===========================================================================
// 2. Nested struct (struct field is a struct), packed inner.
// ===========================================================================
describe('storage-agg: nested struct, packed inner fields', () => {
  const JETH = `type Inner = { x: u64; y: u64; flag: bool; };
type Outer = { tag: u128; inner: Inner; tail: u8; };
class C {
  o: Outer;     // tag@slot0(lo), inner.x/y/flag pack @slot1, tail@slot2
  setTag(v: u128): External<void> { this.o.tag = v; }
  setX(v: u64): External<void> { this.o.inner.x = v; }
  setY(v: u64): External<void> { this.o.inner.y = v; }
  setFlag(v: bool): External<void> { this.o.inner.flag = v; }
  setTail(v: u8): External<void> { this.o.tail = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Inner { uint64 x; uint64 y; bool flag; }
  struct Outer { uint128 tag; Inner inner; uint8 tail; }
  Outer o;
  function setTag(uint128 v) external { o.tag = v; }
  function setX(uint64 v) external { o.inner.x = v; }
  function setY(uint64 v) external { o.inner.y = v; }
  function setFlag(bool v) external { o.inner.flag = v; }
  function setTail(uint8 v) external { o.tail = v; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  it('writes land in the right slot/offset, neighbors preserved', async () => {
    await seq(
      p,
      [0n, 1n, 2n, 3n],
      [
        ['setTag', raw('setTag(uint128)', [(1n << 128n) - 1n])],
        ['setX dirty', raw('setX(uint64)', [(MAXU << 64n) | 0xaaaaaaaaaaaaaaaan])],
        ['setY', raw('setY(uint64)', [0xbbbbbbbbbbbbbbbbn])],
        ['setFlag dirty', raw('setFlag(bool)', [0xff00n | 1n])],
        ['setTail dirty', raw('setTail(uint8)', [(MAXU << 8n) | 0x5an])],
      ],
    );
  });
});

// ===========================================================================
// 3. uint64[] dynamic: push packs 4/slot, pop zeroes freed lane, OOB index Panic.
// ===========================================================================
describe('storage-agg: uint64[] packed push/pop/set, OOB Panic 0x32', () => {
  const JETH = `class C {
  a: u64[];
  push(v: u64): External<void> { this.a.push(v); }
  pop(): External<void> { this.a.pop(); }
  set(i: u256, v: u64): External<void> { this.a[i] = v; }
  get get(i: u256): External<u64> { return this.a[i]; }
  get len(): External<u256> { return this.a.length; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint64[] a;
  function push(uint64 v) external { a.push(v); }
  function pop() external { a.pop(); }
  function set(uint256 i, uint64 v) external { a[i] = v; }
  function get(uint256 i) external view returns (uint64) { return a[i]; }
  function len() external view returns (uint256) { return a.length; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const d = kec(0n);
  const slots = [0n, d, d + 1n, d + 2n];

  it('push 5, set with dirty value, pop twice clears freed lanes', async () => {
    await seq(p, slots, [
      ['push1', raw('push(uint64)', [0x1111111111111111n])],
      ['push2', raw('push(uint64)', [0x2222222222222222n])],
      ['push3', raw('push(uint64)', [0x3333333333333333n])],
      ['push4', raw('push(uint64)', [0x4444444444444444n])],
      ['push5 (new slot)', raw('push(uint64)', [0x5555555555555555n])],
      ['set dirty', raw('set(uint256,uint64)', [2n, (MAXU << 64n) | 0xfeedfacecafebeefn])],
      ['pop (slot1 had only elem4)', raw('pop()')],
      ['pop (elem3 lane in slot0)', raw('pop()')],
    ]);
  });
  it('OOB get / set / pop-on-empty all Panic identically', async () => {
    // length is 3 now (5 pushed, 2 popped). index 3 OOB.
    await step(p, 'get OOB', raw('get(uint256)', [3n]), []);
    await step(p, 'get huge OOB', raw('get(uint256)', [MAXU]), []);
    await step(p, 'set OOB', raw('set(uint256,uint64)', [99n, 1n]), slots);
    // drain to empty then pop -> Panic 0x31
    await step(p, 'pop', raw('pop()'), slots);
    await step(p, 'pop', raw('pop()'), slots);
    await step(p, 'pop', raw('pop()'), slots);
    await step(p, 'pop on empty Panic 0x31', raw('pop()'), slots);
  });
});

// ===========================================================================
// 4. Dynamic array of multi-slot struct: stride, push();-then-set, pop frees all.
// ===========================================================================
describe('storage-agg: Rec[] (3-slot stride) push/set/pop frees whole element', () => {
  const JETH = `type Rec = { a: u256; b: u128; c: u128; d: u256; };
class C {
  recs: Rec[];
  pushZ(): External<void> { this.recs.push(); }
  pushV(a: u256, b: u128, c: u128, d: u256): External<void> { this.recs.push(Rec(a, b, c, d)); }
  pop(): External<void> { this.recs.pop(); }
  setB(i: u256, v: u128): External<void> { this.recs[i].b = v; }
  setC(i: u256, v: u128): External<void> { this.recs[i].c = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Rec { uint256 a; uint128 b; uint128 c; uint256 d; }
  Rec[] recs;
  function pushZ() external { recs.push(); }
  function pushV(uint256 a, uint128 b, uint128 c, uint256 d) external { recs.push(Rec(a,b,c,d)); }
  function pop() external { recs.pop(); }
  function setB(uint256 i, uint128 v) external { recs[i].b = v; }
  function setC(uint256 i, uint128 v) external { recs[i].c = v; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const d = kec(0n);
  const slots = [0n];
  for (let i = 0; i < 9n; i++) slots.push(d + BigInt(i));

  it('push full + push empty + setB/C dirty + pop frees all 3 slots', async () => {
    await seq(p, slots, [
      ['pushV', raw('pushV(uint256,uint128,uint128,uint256)', [MAXU, (1n << 128n) - 1n, 0xabcn, MAXU - 5n])],
      ['pushZ', raw('pushZ()')],
      ['setB dirty', raw('setB(uint256,uint128)', [1n, (MAXU << 128n) | 0x1234n])],
      ['setC dirty', raw('setC(uint256,uint128)', [1n, (MAXU << 128n) | 0x5678n])],
      ['pushZ (3rd)', raw('pushZ()')],
      ['pop (frees elem2: 3 slots must zero)', raw('pop()')],
      ['pop (frees elem1)', raw('pop()')],
    ]);
  });
});

// ===========================================================================
// 5. bytes/string short<->long transitions + freed-tail clearing + OOB index.
// ===========================================================================
describe('storage-agg: bytes/string short/long transitions, dirty len, OOB', () => {
  // NOTE: indexing into string is not legal in Solidity; test bytes index instead.
  const JETH2 = `class C {
  pre: u256;
  s: string;     // slot 1
  bs: bytes;     // slot 2
  post: u256;
  setS(v: string): External<void> { this.s = v; }
  setBs(v: bytes): External<void> { this.bs = v; }
  get atBs(i: u256): External<bytes1> { return this.bs[i]; }
  get lenBs(): External<u256> { return this.bs.length; }
  setPre(v: u256): External<void> { this.pre = v; }
  setPost(v: u256): External<void> { this.post = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256 pre; string s; bytes bs; uint256 post;
  function setS(string calldata v) external { s = v; }
  function setBs(bytes calldata v) external { bs = v; }
  function atBs(uint256 i) external view returns (bytes1) { return bs[i]; }
  function lenBs() external view returns (uint256) { return bs.length; }
  function setPre(uint256 v) external { pre = v; }
  function setPost(uint256 v) external { post = v; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH2, SOL);
  });
  const ds = kec(1n),
    db = kec(2n);
  const slots = [0n, 1n, 2n, 3n, ds, ds + 1n, ds + 2n, ds + 3n, db, db + 1n, db + 2n, db + 3n];

  it('string long->short->empty->exact31->exact32 boundary clears tail', async () => {
    await seq(p, slots, [
      ['pre', raw('setPre(uint256)', [MAXU])],
      ['post', raw('setPost(uint256)', [MAXU])],
      ['setS long', dynArg('setS(string)', [], LONG)],
      ['setS short', dynArg('setS(string)', [], SHORT)], // long->short clears data slots
      ['setS long2', dynArg('setS(string)', [], LONG2)],
      ['setS empty', dynArg('setS(string)', [], '')], // long->empty clears data slots
      ['setS 31', dynArg('setS(string)', [], '0'.repeat(31))], // short (fits inline)
      ['setS 32', dynArg('setS(string)', [], '0'.repeat(32))], // long (boundary!)
      ['setS 31 again', dynArg('setS(string)', [], '1'.repeat(31))], // long->short
    ]);
  });
  it('bytes long->short transitions clear tail; len + OOB index parity', async () => {
    await seq(p, slots, [
      ['setBs long', dynArg('setBs(bytes)', [], LONG)],
      ['lenBs', raw('lenBs()')],
      ['atBs[0]', raw('atBs(uint256)', [0n])],
      ['atBs OOB', raw('atBs(uint256)', [BigInt(LONG.length)])],
      ['atBs huge OOB', raw('atBs(uint256)', [MAXU])],
      ['setBs short', dynArg('setBs(bytes)', [], 'ab')],
      ['atBs[0]', raw('atBs(uint256)', [0n])],
      ['atBs[1] OOB', raw('atBs(uint256)', [2n])],
    ]);
  });
});

// ===========================================================================
// 6. Whole dynamic-array copy with shrink (tail clearing) - value + string elems.
// ===========================================================================
describe('storage-agg: whole dynamic-array copy a=b with grow+shrink tail clear', () => {
  const JETH = `type D = { n: u256; s: string; };
class C {
  a: u256[];
  b: u256[];
  sa: string[];
  sb: string[];
  pushA(v: u256): External<void> { this.a.push(v); }
  pushB(v: u256): External<void> { this.b.push(v); }
  pushSA(s: string): External<void> { this.sa.push(s); }
  pushSB(s: string): External<void> { this.sb.push(s); }
  copyAB(): External<void> { this.a = this.b; }
  copySAB(): External<void> { this.sa = this.sb; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[] a; uint256[] b; string[] sa; string[] sb;
  function pushA(uint256 v) external { a.push(v); }
  function pushB(uint256 v) external { b.push(v); }
  function pushSA(string calldata s) external { sa.push(s); }
  function pushSB(string calldata s) external { sb.push(s); }
  function copyAB() external { a = b; }
  function copySAB() external { sa = sb; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const da = kec(0n),
    dsa = kec(2n);
  const slots = [
    0n,
    1n,
    2n,
    3n,
    da,
    da + 1n,
    da + 2n,
    da + 3n,
    da + 4n,
    dsa,
    dsa + 1n,
    dsa + 2n,
    kec(dsa),
    kec(dsa + 1n),
  ];

  it('copy a=b: grow then shrink-by-recopy must clear the freed tail', async () => {
    await seq(p, slots, [
      ['pushA1', raw('pushA(uint256)', [0x11n])],
      ['pushA2', raw('pushA(uint256)', [0x22n])],
      ['pushA3', raw('pushA(uint256)', [0x33n])],
      ['pushA4', raw('pushA(uint256)', [0x44n])],
      ['pushA5', raw('pushA(uint256)', [0x55n])], // a now len 5
      ['pushB1', raw('pushB(uint256)', [0xaan])],
      ['pushB2', raw('pushB(uint256)', [0xbbn])], // b len 2
      ['copyAB (shrink 5->2, clears tail)', raw('copyAB()')],
      ['pushB3', raw('pushB(uint256)', [0xccn])], // b len 3
      ['copyAB (grow 2->3)', raw('copyAB()')],
    ]);
  });
  it('copy sa=sb: string[] with long elems, shrink clears element headers+data', async () => {
    await seq(p, slots, [
      ['pushSA1', dynArg('pushSA(string)', [], LONG)],
      ['pushSA2', dynArg('pushSA(string)', [], LONG2)],
      ['pushSA3', dynArg('pushSA(string)', [], SHORT)], // sa len 3
      ['pushSB1', dynArg('pushSB(string)', [], 'x')], // sb len 1
      ['copySAB (shrink 3->1, clear headers+long data)', raw('copySAB()')],
    ]);
  });
});

// ===========================================================================
// 7. Whole fixed-array copy + whole struct copy.
// ===========================================================================
describe('storage-agg: whole fixed-array copy & whole struct copy', () => {
  const JETH = `type S = { a: u128; b: u64; c: bool; };
class C {
  fa: Arr<u256, 3>;   // slots 0..2
  fb: Arr<u256, 3>;   // slots 3..5
  s1: S;              // slot 6
  s2: S;              // slot 7
  setFb(i: u256, v: u256): External<void> { this.fb[i] = v; }
  setS2(a: u128, b: u64, c: bool): External<void> { this.s2 = S(a, b, c); }
  copyFA(): External<void> { this.fa = this.fb; }
  copyS(): External<void> { this.s1 = this.s2; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint128 a; uint64 b; bool c; }
  uint256[3] fa; uint256[3] fb; S s1; S s2;
  function setFb(uint256 i, uint256 v) external { fb[i] = v; }
  function setS2(uint128 a, uint64 b, bool c) external { s2 = S(a,b,c); }
  function copyFA() external { fa = fb; }
  function copyS() external { s1 = s2; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const slots = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n];
  it('fixed-array copy + struct copy land identically with dirty inputs', async () => {
    await seq(p, slots, [
      ['setFb0', raw('setFb(uint256,uint256)', [0n, MAXU])],
      ['setFb2', raw('setFb(uint256,uint256)', [2n, 0xdeadn])],
      ['copyFA', raw('copyFA()')],
      ['setS2 dirty', raw('setS2(uint128,uint64,bool)', [(1n << 128n) - 1n, (MAXU << 64n) | 0xffn, 0xff00n | 1n])],
      ['copyS', raw('copyS()')],
    ]);
  });
});

// ===========================================================================
// 8. Mapping to dynamic array: per-key isolation, push/pop, set OOB Panic.
// ===========================================================================
describe('storage-agg: mapping<u256,u256[]> per-key push/pop/set OOB', () => {
  const JETH = `class C {
  m: mapping<u256, u256[]>;
  push(k: u256, v: u256): External<void> { this.m[k].push(v); }
  pop(k: u256): External<void> { this.m[k].pop(); }
  set(k: u256, i: u256, v: u256): External<void> { this.m[k][i] = v; }
  get len(k: u256): External<u256> { return this.m[k].length; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  mapping(uint256 => uint256[]) m;
  function push(uint256 k, uint256 v) external { m[k].push(v); }
  function pop(uint256 k) external { m[k].pop(); }
  function set(uint256 k, uint256 i, uint256 v) external { m[k][i] = v; }
  function len(uint256 k) external view returns (uint256) { return m[k].length; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const K1 = 7n,
    K2 = MAXU; // adversarial key = max u256
  const len1 = mapSlot(K1, 0n),
    data1 = kec(len1);
  const len2 = mapSlot(K2, 0n),
    data2 = kec(len2);
  const slots = [0n, len1, data1, data1 + 1n, data1 + 2n, len2, data2, data2 + 1n];

  it('two keys stay isolated; pop frees tail; OOB set/pop Panic', async () => {
    await seq(p, slots, [
      ['push k1', raw('push(uint256,uint256)', [K1, 0x1111n])],
      ['push k1', raw('push(uint256,uint256)', [K1, 0x2222n])],
      ['push k1', raw('push(uint256,uint256)', [K1, 0x3333n])],
      ['push k2(max)', raw('push(uint256,uint256)', [K2, 0x9999n])],
      ['set k1[1]', raw('set(uint256,uint256,uint256)', [K1, 1n, 0xbeefn])],
      ['pop k1 (frees data1+2)', raw('pop(uint256)', [K1])],
      ['set k1 OOB Panic', raw('set(uint256,uint256,uint256)', [K1, 5n, 1n])],
      ['pop k2', raw('pop(uint256)', [K2])],
      ['pop k2 empty Panic', raw('pop(uint256)', [K2])],
    ]);
  });
});

// ===========================================================================
// 9. Nested mapping mapping<address,mapping<u256,V>> packed value + struct value.
// ===========================================================================
describe('storage-agg: nested mapping, packed value & struct value', () => {
  const JETH = `type S = { a: u64; b: u64; flag: bool; };
class C {
  mv: mapping<address, mapping<u256, u128>>;
  ms: mapping<bytes32, S>;
  setV(a: address, k: u256, v: u128): External<void> { this.mv[a][k] = v; }
  setSa(k: bytes32, v: u64): External<void> { this.ms[k].a = v; }
  setSflag(k: bytes32, v: bool): External<void> { this.ms[k].flag = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint64 a; uint64 b; bool flag; }
  mapping(address => mapping(uint256 => uint128)) mv;
  mapping(bytes32 => S) ms;
  function setV(address a, uint256 k, uint128 v) external { mv[a][k] = v; }
  function setSa(bytes32 k, uint64 v) external { ms[k].a = v; }
  function setSflag(bytes32 k, bool v) external { ms[k].flag = v; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const A = 0x1234567890abcdef1234567890abcdef12345678n;
  const inner = mapSlot(A, 0n);
  const valSlot = mapSlot(42n, inner);
  const K = (1n << 200n) | 0xabcdn;
  const sBase = mapSlot(K, 1n);
  const slots = [valSlot, sBase, sBase + 1n];

  it('nested mapping value slot + packed struct value with dirty calldata', async () => {
    await seq(p, slots, [
      // address key dirty top 96 bits
      ['setV dirty addr', raw('setV(address,uint256,uint128)', [(MAXU << 160n) | A, 42n, (MAXU << 128n) | 0xcafen])],
      ['setSa dirty', raw('setSa(bytes32,uint64)', [K, (MAXU << 64n) | 0x1111n])],
      ['setSflag dirty', raw('setSflag(bytes32,bool)', [K, 0xdeadn | 1n])],
    ]);
  });
});

// ===========================================================================
// 10. Mapping as struct field (struct contains mapping); delete leaves mapping.
// ===========================================================================
describe('storage-agg: struct with mapping field, delete keeps entries', () => {
  const JETH = `type S = { a: u256; m: mapping<address, u256>; b: u256; };
class C {
  s: S;          // a@0, m@1, b@2
  guard: u256;   // slot 3
  setA(v: u256): External<void> { this.s.a = v; }
  setB(v: u256): External<void> { this.s.b = v; }
  setM(k: address, v: u256): External<void> { this.s.m[k] = v; }
  setGuard(v: u256): External<void> { this.guard = v; }
  delS(): External<void> { delete this.s; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint256 a; mapping(address => uint256) m; uint256 b; }
  S s; uint256 guard;
  function setA(uint256 v) external { s.a = v; }
  function setB(uint256 v) external { s.b = v; }
  function setM(address k, uint256 v) external { s.m[k] = v; }
  function setGuard(uint256 v) external { guard = v; }
  function delS() external { delete s; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const A = 0xa11ce0000000000000000000000000000000n;
  const B = 0xb0b0000000000000000000000000000000000n;
  const mA = mapSlot(A, 1n),
    mB = mapSlot(B, 1n);
  const slots = [0n, 1n, 2n, 3n, mA, mB];
  it('delete struct zeroes value fields, keeps guard + mapping entries', async () => {
    await seq(p, slots, [
      ['setA', raw('setA(uint256)', [111n])],
      ['setB', raw('setB(uint256)', [222n])],
      ['setM A', raw('setM(address,uint256)', [A, 777n])],
      ['setM B', raw('setM(address,uint256)', [B, 888n])],
      ['setGuard', raw('setGuard(uint256)', [0xcafen])],
      ['delS (mapping survives)', raw('delS()')],
    ]);
    // explicit: mapping entries SURVIVE struct delete (both must agree, checked above,
    // and the value must literally remain the written one).
    expect(await readSlot(p.jeth, p.aj, mA)).toBe('0x' + pad(777n));
    expect(await readSlot(p.jeth, p.aj, mB)).toBe('0x' + pad(888n));
    expect(await readSlot(p.sol, p.as, mA)).toBe('0x' + pad(777n));
  });
  it('dirty address key (high 96 bits set) reverts identically (no write)', async () => {
    // solc 0.8.x ABI decoder validates address params; both must revert and store nothing.
    await step(p, 'setM dirty-addr revert', raw('setM(address,uint256)', [(MAXU << 160n) | A, 777n]), [
      mapSlot((MAXU << 160n) | A, 1n),
      mapSlot(A, 1n),
    ]);
  });
});

// ===========================================================================
// 11. Mapping to bytes/string short/long; delete clears, mapping intact.
// ===========================================================================
describe('storage-agg: mapping<address,bytes> short/long, delete value', () => {
  const JETH = `class C {
  mb: mapping<address, bytes>;
  setB(k: address, v: bytes): External<void> { this.mb[k] = v; }
  delB(k: address): External<void> { delete this.mb[k]; }
  get lenB(k: address): External<u256> { return this.mb[k].length; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  mapping(address => bytes) mb;
  function setB(address k, bytes calldata v) external { mb[k] = v; }
  function delB(address k) external { delete mb[k]; }
  function lenB(address k) external view returns (uint256) { return mb[k].length; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const A = 0xa11ce0000000000000000000000000000000n;
  const head = mapSlot(A, 0n),
    data = kec(head);
  const slots = [head, data, data + 1n, data + 2n];
  it('long->short->delete clears the long-data slots', async () => {
    await seq(p, slots, [
      ['setB long', dynArg('setB(address,bytes)', [A], LONG)],
      ['lenB', raw('lenB(address)', [A])],
      ['setB short', dynArg('setB(address,bytes)', [A], 'ab')],
      ['setB long2', dynArg('setB(address,bytes)', [A], LONG2)],
      ['delB (clear long data)', raw('delB(address)', [A])],
    ]);
  });
});

// ===========================================================================
// 12. delete: packed fixed array (whole + element), value, struct, dyn-array.
// ===========================================================================
describe('storage-agg: delete packed/value/struct/dyn-array, neighbor preserve', () => {
  const JETH = `type S = { a: u128; b: u64; c: bool; };
class C {
  a8: Arr<u8, 5>;     // slot 0 (5 bytes packed)
  guard: u256;        // slot 1
  xs: u256[];         // slot 2
  s: S;               // slot 3
  seed(): External<void> {
    this.a8[0n]=1n; this.a8[1n]=2n; this.a8[2n]=3n; this.a8[3n]=4n; this.a8[4n]=5n;
    this.guard=0x9999n;
    this.xs.push(0xaaaan); this.xs.push(0xbbbbn); this.xs.push(0xccccn);
    this.s = S(123n, 456n, true);
  }
  delA8(): External<void> { delete this.a8; }
  delA8e(): External<void> { delete this.a8[2n]; }
  delXs(): External<void> { delete this.xs; }
  delS(): External<void> { delete this.s; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint128 a; uint64 b; bool c; }
  uint8[5] a8; uint256 guard; uint256[] xs; S s;
  function seed() external {
    a8[0]=1; a8[1]=2; a8[2]=3; a8[3]=4; a8[4]=5;
    guard=0x9999;
    xs.push(0xaaaa); xs.push(0xbbbb); xs.push(0xcccc);
    s = S(123,456,true);
  }
  function delA8() external { delete a8; }
  function delA8e() external { delete a8[2]; }
  function delXs() external { delete xs; }
  function delS() external { delete s; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const dx = kec(2n);
  const slots = [0n, 1n, 2n, 3n, dx, dx + 1n, dx + 2n];
  async function reseed() {
    await p.jeth.call(p.aj, raw('seed()'));
    await p.sol.call(p.as, raw('seed()'));
  }
  it('delete whole packed array, single lane, dyn-array, struct', async () => {
    await reseed();
    await step(p, 'delA8', raw('delA8()'), slots);
    await reseed();
    await step(p, 'delA8e', raw('delA8e()'), slots);
    await reseed();
    await step(p, 'delXs', raw('delXs()'), slots);
    await reseed();
    await step(p, 'delS', raw('delS()'), slots);
  });
});

// ===========================================================================
// 13. Slot reuse after pop then re-push (stale data must be overwritten).
// ===========================================================================
describe('storage-agg: slot reuse after pop/delete, no stale bytes', () => {
  const JETH = `type R = { a: u128; b: u64; c: bool; d: bytes4; };
class C {
  recs: R[];
  s: string;
  pushV(a: u128, b: u64, c: bool, d: bytes4): External<void> { this.recs.push(R(a, b, c, d)); }
  pop(): External<void> { this.recs.pop(); }
  delAndReset(): External<void> { delete this.s; this.s = "${SHORT}"; }
  setS(v: string): External<void> { this.s = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct R { uint128 a; uint64 b; bool c; bytes4 d; }
  R[] recs; string s;
  function pushV(uint128 a, uint64 b, bool c, bytes4 d) external { recs.push(R(a,b,c,d)); }
  function pop() external { recs.pop(); }
  function delAndReset() external { delete s; s = "${SHORT}"; }
  function setS(string calldata v) external { s = v; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const d = kec(0n);
  const ds = kec(1n);
  const slots = [0n, 1n, d, d + 1n, ds, ds + 1n, ds + 2n];
  it('pop a fully-dirty element then push a smaller one: no stale high bytes', async () => {
    await seq(p, slots, [
      ['push full dirty', raw('pushV(uint128,uint64,bool,bytes4)', [(1n << 128n) - 1n, MAXU, 1n, MAXU])],
      ['push2', raw('pushV(uint128,uint64,bool,bytes4)', [0x1234n, 0x5678n, 0n, 0x11223344n << 224n])],
      ['pop', raw('pop()')],
      // re-push into the just-popped slot with mostly-zero values -> must fully overwrite
      ['push small (reuse popped slot)', raw('pushV(uint128,uint64,bool,bytes4)', [1n, 2n, 1n, 0x99000000n << 0n])],
    ]);
  });
  it('delete long string + reset short: long-data slots cleared on reuse', async () => {
    await seq(p, slots, [
      ['setS long', dynArg('setS(string)', [], LONG)],
      ['delAndReset', raw('delAndReset()')],
    ]);
  });
});

// ===========================================================================
// 14. Nested fixed array uint256[2][3] + array-of-array dynamic u256[][].
// ===========================================================================
describe('storage-agg: nested fixed array + nested dynamic array', () => {
  const JETH = `class C {
  ff: Arr<Arr<u256, 2>, 3>;   // slots 0..5 whole-slot
  dd: u256[][];               // slot 6
  setFF(i: u256, j: u256, v: u256): External<void> { this.ff[i][j] = v; }
  pushOuter(): External<void> { this.dd.push(); }
  pushInner(i: u256, v: u256): External<void> { this.dd[i].push(v); }
  setInner(i: u256, j: u256, v: u256): External<void> { this.dd[i][j] = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[2][3] ff;
  uint256[][] dd;
  function setFF(uint256 i, uint256 j, uint256 v) external { ff[i][j] = v; }
  function pushOuter() external { dd.push(); }
  function pushInner(uint256 i, uint256 v) external { dd[i].push(v); }
  function setInner(uint256 i, uint256 j, uint256 v) external { dd[i][j] = v; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  // dd at slot 6; outer data @ kec(6); dd[i] len @ kec(6)+i; dd[i] data @ kec(kec(6)+i).
  const o = kec(6n);
  const d0 = kec(o),
    d1 = kec(o + 1n);
  const slots = [0n, 1n, 2n, 3n, 4n, 5n, 6n, o, o + 1n, d0, d0 + 1n, d1];
  it('ff[i][j] lands in slot 2i+j; nested dyn dd[i][j] keccak chain matches', async () => {
    await seq(p, slots, [
      ['setFF 2,1', raw('setFF(uint256,uint256,uint256)', [2n, 1n, MAXU])],
      ['setFF 0,0', raw('setFF(uint256,uint256,uint256)', [0n, 0n, 0xa0n])],
      ['setFF OOB i Panic', raw('setFF(uint256,uint256,uint256)', [3n, 0n, 1n])],
      ['setFF OOB j Panic', raw('setFF(uint256,uint256,uint256)', [0n, 2n, 1n])],
      ['pushOuter', raw('pushOuter()')],
      ['pushOuter', raw('pushOuter()')],
      ['pushInner 0', raw('pushInner(uint256,uint256)', [0n, 0x11n])],
      ['pushInner 0', raw('pushInner(uint256,uint256)', [0n, 0x22n])],
      ['pushInner 1', raw('pushInner(uint256,uint256)', [1n, 0x33n])],
      ['setInner 0,1', raw('setInner(uint256,uint256,uint256)', [0n, 1n, 0xbeefn])],
      ['setInner OOB Panic', raw('setInner(uint256,uint256,uint256)', [0n, 9n, 1n])],
    ]);
  });
});

// ===========================================================================
// 15. Packed-neighbor preservation in array-of-packed-structs (dirty writes).
// ===========================================================================
describe('storage-agg: Pt[3] single-slot packed struct, neighbor preserve', () => {
  const JETH = `type Pt = { x: u128; y: u128; };
class C {
  a: Arr<Pt, 3>;   // each Pt 1 slot; slots 0,1,2
  guard: u256;     // slot 3
  setX(i: u256, v: u128): External<void> { this.a[i].x = v; }
  setY(i: u256, v: u128): External<void> { this.a[i].y = v; }
  setGuard(v: u256): External<void> { this.guard = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Pt { uint128 x; uint128 y; }
  Pt[3] a; uint256 guard;
  function setX(uint256 i, uint128 v) external { a[i].x = v; }
  function setY(uint256 i, uint128 v) external { a[i].y = v; }
  function setGuard(uint256 v) external { guard = v; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const slots = [0n, 1n, 2n, 3n];
  it('writing x must not disturb y in same slot; guard intact', async () => {
    await seq(p, slots, [
      ['setGuard', raw('setGuard(uint256)', [MAXU])],
      ['setY[0] dirty', raw('setY(uint256,uint128)', [0n, (MAXU << 128n) | ((1n << 128n) - 1n)])],
      ['setX[0]', raw('setX(uint256,uint128)', [0n, 0xaaaan])],
      ['setX[2] dirty', raw('setX(uint256,uint128)', [2n, (MAXU << 128n) | 0xccccn])],
      ['setY[2]', raw('setY(uint256,uint128)', [2n, 0xddddn])],
      ['setX OOB Panic', raw('setX(uint256,uint128)', [3n, 1n])],
    ]);
  });
});

// ===========================================================================
// 16. bytes32[] dynamic whole-slot + .length growth boundaries.
// ===========================================================================
describe('storage-agg: bytes32[] whole-slot push to slot boundary', () => {
  const JETH = `class C {
  a: bytes32[];
  push(v: bytes32): External<void> { this.a.push(v); }
  pop(): External<void> { this.a.pop(); }
  get len(): External<u256> { return this.a.length; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  bytes32[] a;
  function push(bytes32 v) external { a.push(v); }
  function pop() external { a.pop(); }
  function len() external view returns (uint256) { return a.length; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const d = kec(0n);
  const slots = [0n, d, d + 1n, d + 2n, d + 3n];
  it('push 4 / pop 2: length + data slots match (whole-slot elements)', async () => {
    await seq(p, slots, [
      ['push max', raw('push(bytes32)', [MAXU])],
      ['push', raw('push(bytes32)', [0x1n << 248n])],
      ['push', raw('push(bytes32)', [0xffn])],
      ['push', raw('push(bytes32)', [0xdeadbeefn << 224n])],
      ['pop', raw('pop()')],
      ['pop', raw('pop()')],
      ['len', raw('len()')],
    ]);
  });
});

// ===========================================================================
// 17. i128[] dynamic packed 2/slot with negatives (sign-ext) + RMW via re-set.
// ===========================================================================
describe('storage-agg: i128[] packed 2/slot negatives', () => {
  const JETH = `class C {
  a: i128[];
  push(v: i128): External<void> { this.a.push(v); }
  set(i: u256, v: i128): External<void> { this.a[i] = v; }
  get get(i: u256): External<i128> { return this.a[i]; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  int128[] a;
  function push(int128 v) external { a.push(v); }
  function set(uint256 i, int128 v) external { a[i] = v; }
  function get(uint256 i) external view returns (int128) { return a[i]; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const d = kec(0n);
  const slots = [0n, d, d + 1n];
  it('push/set negatives pack correctly; sign-ext on get', async () => {
    await seq(p, slots, [
      ['push -1', raw('push(int128)', [MAXU])], // -1 in 128 bits
      ['push min', raw('push(int128)', [-(1n << 127n)])],
      ['push max', raw('push(int128)', [(1n << 127n) - 1n])],
      ['set[0] dirty', raw('set(uint256,int128)', [0n, (MAXU << 128n) | 0x7fffffffffffffffffffffffffffffffn])],
      ['get[0]', raw('get(uint256)', [0n])],
      ['get[1]', raw('get(uint256)', [1n])],
      ['get[2]', raw('get(uint256)', [2n])],
    ]);
  });
});

// ===========================================================================
// 18. Struct with whole-slot fixed-array field + trailing packed (delete whole).
// ===========================================================================
describe('storage-agg: struct {u8 tag; u256[3] data; u8 flag} delete', () => {
  const JETH = `type T = { tag: u8; data: Arr<u256, 3>; flag: u8; };
class C {
  t: T;          // tag@slot0 lane, data@1..3, flag@4 lane
  seed(): External<void> { this.t.tag = 0x7fn; this.t.data[0n] = 0x11n; this.t.data[2n] = 0x55n; this.t.flag = 0x99n; }
  delT(): External<void> { delete this.t; }
  setData(i: u256, v: u256): External<void> { this.t.data[i] = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct T { uint8 tag; uint256[3] data; uint8 flag; }
  T t;
  function seed() external { t.tag = 0x7f; t.data[0] = 0x11; t.data[2] = 0x55; t.flag = 0x99; }
  function delT() external { delete t; }
  function setData(uint256 i, uint256 v) external { t.data[i] = v; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const slots = [0n, 1n, 2n, 3n, 4n];
  it('seed then delete clears all 5 slots; OOB data index Panic', async () => {
    await seq(p, slots, [
      ['seed', raw('seed()')],
      ['setData OOB Panic', raw('setData(uint256,uint256)', [3n, 1n])],
      ['delT', raw('delT()')],
    ]);
  });
});

// ===========================================================================
// 19. .length read after various mutations + grow array via length is NOT in
//     Solidity (a.length = n removed); ensure JETH parity (both reject) if tried.
// ===========================================================================
describe('storage-agg: length semantics & push return-of-ref parity', () => {
  it('JETH and solc both reject assigning to .length', () => {
    const j = `class C { a: u256[]; f(): External<void> { this.a.length = 3n; } }`;
    const s = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C { uint256[] a; function f() external { a.length = 3; } }`;
    let jThrew = false,
      sThrew = false;
    try {
      compile(j, { fileName: 'C.jeth' });
    } catch {
      jThrew = true;
    }
    try {
      compileSolidity(s, 'C');
    } catch {
      sThrew = true;
    }
    expect(sThrew, 'solc rejects .length=').toBe(true);
    expect(jThrew, 'jeth rejects .length=').toBe(true);
  });
});

// ===========================================================================
// 20. Dynamic array of dynamic-field struct D{n;s} push/pop frees header+long.
// ===========================================================================
describe('storage-agg: D[] {u256 n; string s} push/pop frees long-data', () => {
  const JETH = `type D = { n: u256; s: string; };
class C {
  recs: D[];   // slot 0; each D = 2 slots (n, s-header)
  pushV(n: u256, s: string): External<void> { this.recs.push(D(n, s)); }
  pop(): External<void> { this.recs.pop(); }
  get getS(i: u256): External<string> { return this.recs[i].s; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct D { uint256 n; string s; }
  D[] recs;
  function pushV(uint256 n, string calldata s) external { recs.push(D(n,s)); }
  function pop() external { recs.pop(); }
  function getS(uint256 i) external view returns (string memory) { return recs[i].s; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const d = kec(0n);
  // elem k: n @ d+2k, s-header @ d+2k+1, s-longdata @ kec(d+2k+1)
  const slots = [0n, d, d + 1n, d + 2n, d + 3n, kec(d + 1n), kec(d + 1n) + 1n, kec(d + 3n)];
  it('push long-string elems then pop: header + long-data zeroed', async () => {
    await seq(p, slots, [
      ['pushV long', dynArg('pushV(uint256,string)', [0xa1n], LONG)],
      ['pushV long2', dynArg('pushV(uint256,string)', [0xb2n], LONG2)],
      ['getS[0]', raw('getS(uint256)', [0n])],
      ['pop (frees elem1 header+longdata)', raw('pop()')],
      ['getS OOB Panic', raw('getS(uint256)', [1n])],
    ]);
  });
});

// ===========================================================================
// 21. Address-array & bool-array packed delete element vs whole.
// ===========================================================================
describe('storage-agg: address[3] & bool[10] delete element/whole', () => {
  const JETH = `class C {
  addrs: Arr<address, 3>;   // each whole-slot (20 bytes but no packing in arrays)
  flags: Arr<bool, 10>;     // 10 bytes packed in slot 3
  guard: u256;              // slot 4
  seed(): External<void> {
    this.addrs[0n] = address(0x1111111111111111111111111111111111111111n);
    this.addrs[1n] = address(0x2222222222222222222222222222222222222222n);
    this.addrs[2n] = address(0x3333333333333333333333333333333333333333n);
    this.flags[0n]=true; this.flags[3n]=true; this.flags[9n]=true;
    this.guard=0xfn;
  }
  delAddr(): External<void> { delete this.addrs; }
  delAddrE(): External<void> { delete this.addrs[1n]; }
  delFlags(): External<void> { delete this.flags; }
  delFlagE(): External<void> { delete this.flags[3n]; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  address[3] addrs; bool[10] flags; uint256 guard;
  function seed() external {
    addrs[0] = address(0x1111111111111111111111111111111111111111);
    addrs[1] = address(0x2222222222222222222222222222222222222222);
    addrs[2] = address(0x3333333333333333333333333333333333333333);
    flags[0]=true; flags[3]=true; flags[9]=true;
    guard=0xf;
  }
  function delAddr() external { delete addrs; }
  function delAddrE() external { delete addrs[1]; }
  function delFlags() external { delete flags; }
  function delFlagE() external { delete flags[3]; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const slots = [0n, 1n, 2n, 3n, 4n];
  async function reseed() {
    await p.jeth.call(p.aj, raw('seed()'));
    await p.sol.call(p.as, raw('seed()'));
  }
  it('delete whole / single element of address[] and bool[]', async () => {
    await reseed();
    await step(p, 'delAddr', raw('delAddr()'), slots);
    await reseed();
    await step(p, 'delAddrE', raw('delAddrE()'), slots);
    await reseed();
    await step(p, 'delFlags', raw('delFlags()'), slots);
    await reseed();
    await step(p, 'delFlagE', raw('delFlagE()'), slots);
  });
});

// ===========================================================================
// 22. Whole-struct return from storage (packed fields ABI re-expand).
// ===========================================================================
describe('storage-agg: return packed struct from storage (ABI re-expand)', () => {
  const JETH = `type S = { a: i64; b: u32; c: bytes4; d: bool; e: address; };
class C {
  s: S;
  setA(v: i64): External<void> { this.s.a = v; }
  setE(v: address): External<void> { this.s.e = v; }
  setAll(a: i64, b: u32, c: bytes4, d: bool, e: address): External<void> { this.s = S(a, b, c, d, e); }
  get get(): External<S> { return this.s; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { int64 a; uint32 b; bytes4 c; bool d; address e; }
  S s;
  function setA(int64 v) external { s.a = v; }
  function setE(address v) external { s.e = v; }
  function setAll(int64 a, uint32 b, bytes4 c, bool d, address e) external { s = S(a,b,c,d,e); }
  function get() external view returns (S memory) { return s; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const slots = [0n, 1n];
  it('store dirty, return ABI words match (sign-ext, left-align bytesN)', async () => {
    await seq(p, slots, [
      [
        'setAll dirty',
        raw('setAll(int64,uint32,bytes4,bool,address)', [
          MAXU,
          (MAXU << 32n) | 0xdeadbeefn,
          (0x11223344n << 224n) | 0xffffn,
          0xff00n | 1n,
          (MAXU << 160n) | 0x1234567890abcdef1234567890abcdef12345678n,
        ]),
      ],
      ['get', raw('get()')],
      ['setA -9999', raw('setA(int64)', [-9999n])],
      ['get', raw('get()')],
    ]);
  });
});

// ===========================================================================
// 23. Dynamic offset/length attacks on a fn that decodes a string into storage.
// ===========================================================================
describe('storage-agg: malformed dynamic offsets/lengths into storage write', () => {
  const JETH = `class C {
  s: string;
  setS(v: string): External<void> { this.s = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C { string s; function setS(string calldata v) external { s = v; } }`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const d = kec(0n);
  const slots = [0n, d, d + 1n, d + 2n, d + 3n];
  const selS = sel('setS(string)');
  it('high-bit / huge / aliased / past-end offsets all match (revert or ok)', async () => {
    const cases: [string, string][] = [
      // valid baseline
      ['valid', dynArg('setS(string)', [], LONG)],
      // offset = 2^255 (high bit)
      ['off 2^255', '0x' + selS + pad(1n << 255n)],
      // offset = 2^64 (Panic 0x41 region)
      ['off 2^64', '0x' + selS + pad(1n << 64n)],
      // offset points past calldatasize
      ['off past-end', '0x' + selS + pad(0x1000n)],
      // offset = 0 (points at itself, len decoded from selector area)
      ['off 0', '0x' + selS + pad(0n)],
      // valid offset, length = 2^64 (Panic 0x41)
      ['len 2^64', '0x' + selS + pad(0x20n) + pad(1n << 64n)],
      // valid offset, length huge (2^255)
      ['len 2^255', '0x' + selS + pad(0x20n) + pad(1n << 255n)],
      // valid offset, length = 0x21 but no data tail (truncated)
      ['len 33 truncated', '0x' + selS + pad(0x20n) + pad(0x21n)],
      // offset = 0x20 but length word missing entirely
      ['no length word', '0x' + selS + pad(0x20n)],
    ];
    for (const [label, data] of cases) await step(p, label, data, slots);
  });
});

// ===========================================================================
// 24. Mapping<bool,...> & mapping<i8,...> dirty-key normalization to slot.
// ===========================================================================
describe('storage-agg: mapping key normalization (bool, i8) dirty bits', () => {
  const JETH = `class C {
  mbool: mapping<bool, u256>;
  mi8: mapping<i8, u256>;
  setBool(k: bool, v: u256): External<void> { this.mbool[k] = v; }
  setI8(k: i8, v: u256): External<void> { this.mi8[k] = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  mapping(bool => uint256) mbool;
  mapping(int8 => uint256) mi8;
  function setBool(bool k, uint256 v) external { mbool[k] = v; }
  function setI8(int8 k, uint256 v) external { mi8[k] = v; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  // bool key true -> keccak(1 . 0). i8 key -1 -> keccak(padded-signext . 1).
  const boolTrue = mapSlot(1n, 0n);
  const i8neg1 = mapSlot(MAXU, 1n); // -1 sign-extended to 256 bits
  const slots = [boolTrue, i8neg1];
  it('dirty bool/i8 keys: revert-or-normalize parity with solc decoder', async () => {
    await seq(p, slots, [
      // bool key with garbage high bits (solc decoder reverts on non-0/1 bool)
      ['setBool dirty', raw('setBool(bool,uint256)', [(0xabcdn << 8n) | 1n, 111n])],
      // clean bool true
      ['setBool clean', raw('setBool(bool,uint256)', [1n, 111n])],
      // i8 key = -1 with garbage above 8 bits (solc decoder reverts on bad sign-ext)
      ['setI8 -1 dirty', raw('setI8(int8,uint256)', [(0x1234n << 8n) | 0xffn, 222n])],
      // clean i8 -1 (sign-extended) -> hashes to canonical slot
      ['setI8 -1 clean', raw('setI8(int8,uint256)', [MAXU, 222n])],
    ]);
  });
});

// ===========================================================================
// 25. Whole fixed-array-of-struct copy where dest held LONGER strings (tail clear).
// ===========================================================================
describe('storage-agg: Arr<D,2> copy with string fields, dest-longer tail clear', () => {
  const JETH = `type D = { n: u256; s: string; };
class C {
  dst: Arr<D, 2>;   // D[0]: n@0,s@1 ; D[1]: n@2,s@3
  src: Arr<D, 2>;   // D[0]: n@4,s@5 ; D[1]: n@6,s@7
  setDst(i: u256, n: u256, s: string): External<void> { this.dst[i] = D(n, s); }
  setSrc(i: u256, n: u256, s: string): External<void> { this.src[i] = D(n, s); }
  copy(): External<void> { this.dst = this.src; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct D { uint256 n; string s; }
  D[2] dst; D[2] src;
  function setDst(uint256 i, uint256 n, string calldata s) external { dst[i] = D(n, s); }
  function setSrc(uint256 i, uint256 n, string calldata s) external { src[i] = D(n, s); }
  function copy() external { dst = src; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  // dst headers at slots 1,3; their long-data at kec(1),kec(3). src at 5,7 -> kec(5),kec(7).
  const slots = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, kec(1n), kec(1n) + 1n, kec(3n), kec(5n), kec(5n) + 1n, kec(7n)];
  it('copy short src over long dst clears dst long-data slots', async () => {
    await seq(p, slots, [
      ['setDst0 long', dynArg('setDst(uint256,uint256,string)', [0n, 0xa0n], LONG)],
      ['setDst1 long2', dynArg('setDst(uint256,uint256,string)', [1n, 0xb0n], LONG2)],
      ['setSrc0 short', dynArg('setSrc(uint256,uint256,string)', [0n, 0xc0n], 'x')],
      ['setSrc1 short', dynArg('setSrc(uint256,uint256,string)', [1n, 0xd0n], 'yz')],
      ['copy (dst long-data must clear)', raw('copy()')],
    ]);
  });
  it('copy long src over short dst grows dst long-data slots', async () => {
    await seq(p, slots, [
      ['setSrc0 long', dynArg('setSrc(uint256,uint256,string)', [0n, 0xe0n], LONG)],
      ['setSrc1 long2', dynArg('setSrc(uint256,uint256,string)', [1n, 0xf0n], LONG2)],
      ['copy (grow)', raw('copy()')],
    ]);
  });
});

// ===========================================================================
// 26. bytes[] (array of dynamic bytes) push long elems, pop frees header+long.
// ===========================================================================
describe('storage-agg: bytes[] push/pop frees element headers + long-data', () => {
  const JETH = `class C {
  a: bytes[];
  push(v: bytes): External<void> { this.a.push(v); }
  pop(): External<void> { this.a.pop(); }
  get at(i: u256): External<bytes> { return this.a[i]; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  bytes[] a;
  function push(bytes calldata v) external { a.push(v); }
  function pop() external { a.pop(); }
  function at(uint256 i) external view returns (bytes memory) { return a[i]; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const d = kec(0n); // data base: element headers at d, d+1, ...
  const slots = [0n, d, d + 1n, d + 2n, kec(d), kec(d) + 1n, kec(d + 1n), kec(d + 1n) + 1n, kec(d + 2n)];
  it('push 3 (long,short,long2), pop 2: freed headers + long-data zeroed', async () => {
    await seq(p, slots, [
      ['push long', dynArg('push(bytes)', [], LONG)],
      ['push short', dynArg('push(bytes)', [], 'ab')],
      ['push long2', dynArg('push(bytes)', [], LONG2)],
      ['at[0]', raw('at(uint256)', [0n])],
      ['pop (frees long2 header+data)', raw('pop()')],
      ['pop (frees short header)', raw('pop()')],
      ['at OOB Panic', raw('at(uint256)', [1n])],
    ]);
  });
});

// ===========================================================================
// 27. Exactly 31/32-byte boundary for bytes (short/long flag) + freed-tail.
// ===========================================================================
describe('storage-agg: bytes 31/32-byte short/long flag boundary', () => {
  const JETH = `class C {
  bs: bytes;   // slot 0
  setBs(v: bytes): External<void> { this.bs = v; }
  get len(): External<u256> { return this.bs.length; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  bytes bs;
  function setBs(bytes calldata v) external { bs = v; }
  function len() external view returns (uint256) { return bs.length; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  const d = kec(0n);
  const slots = [0n, d, d + 1n, d + 2n];
  it('31 (short) -> 32 (long) -> 33 -> back to 31 clears long-data slot', async () => {
    await seq(p, slots, [
      ['setBs 31', dynArg('setBs(bytes)', [], 'p'.repeat(31))], // short: inline, low byte = 2*31
      ['len', raw('len()')],
      ['setBs 32', dynArg('setBs(bytes)', [], 'q'.repeat(32))], // long: slot0 = 2*32+1, data @ kec(0)
      ['len', raw('len()')],
      ['setBs 65', dynArg('setBs(bytes)', [], 'r'.repeat(65))], // long, 3 data slots
      ['setBs 31 again', dynArg('setBs(bytes)', [], 's'.repeat(31))], // long->short: must clear all data slots
    ]);
  });
});

// ===========================================================================
// 28. mapping to mapping-to-array (mapping<u256, mapping<u256, u256[]>>).
// ===========================================================================
describe('storage-agg: mapping<u256, mapping<u256, u256[]>> deep nesting', () => {
  const JETH = `class C {
  m: mapping<u256, mapping<u256, u256[]>>;
  push(k1: u256, k2: u256, v: u256): External<void> { this.m[k1][k2].push(v); }
  pop(k1: u256, k2: u256): External<void> { this.m[k1][k2].pop(); }
  set(k1: u256, k2: u256, i: u256, v: u256): External<void> { this.m[k1][k2][i] = v; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  mapping(uint256 => mapping(uint256 => uint256[])) m;
  function push(uint256 k1, uint256 k2, uint256 v) external { m[k1][k2].push(v); }
  function pop(uint256 k1, uint256 k2) external { m[k1][k2].pop(); }
  function set(uint256 k1, uint256 k2, uint256 i, uint256 v) external { m[k1][k2][i] = v; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await build(JETH, SOL);
  });
  // inner = keccak(k1 . 0); len = keccak(k2 . inner); data = keccak(len).
  const k1 = MAXU,
    k2 = 0n; // adversarial keys: max and zero
  const inner = mapSlot(k1, 0n);
  const len = mapSlot(k2, inner);
  const data = kec(len);
  const slots = [len, data, data + 1n, data + 2n];
  it('deep nested mapping-to-array push/pop/set OOB on adversarial keys', async () => {
    await seq(p, slots, [
      ['push', raw('push(uint256,uint256,uint256)', [k1, k2, 0x11n])],
      ['push', raw('push(uint256,uint256,uint256)', [k1, k2, 0x22n])],
      ['set', raw('set(uint256,uint256,uint256,uint256)', [k1, k2, 0n, 0xbeefn])],
      ['set OOB Panic', raw('set(uint256,uint256,uint256,uint256)', [k1, k2, 9n, 1n])],
      ['pop', raw('pop(uint256,uint256)', [k1, k2])],
      ['pop', raw('pop(uint256,uint256)', [k1, k2])],
      ['pop empty Panic', raw('pop(uint256,uint256)', [k1, k2])],
    ]);
  });
});
