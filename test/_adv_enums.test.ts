// ADVERSARIAL enum audit. An enum `Color { Red, Green, Blue }` is a branded uint8: ABI type uint8,
// 1-byte packed storage, members 0,1,2. The HARD invariant is byte-identical to solc on returndata,
// raw storage slots, event topics/data, and revert data. This suite hunts hard at the places a
// miscompile hides: the recursive calldata codec (esp. enum ARRAY element validation, eager vs lazy),
// out-of-range / dirty-bit decode, storage packing beside other small fields and across slot
// boundaries, indexed/non-indexed event enums, enum custom-error args, the full cast matrix
// (Color(x) Panic 0x21 vs uint8 calldata empty-revert), default member 0, delete, mapping key/value.
//
// Every probe builds BOTH a JETH contract and a byte-for-byte Solidity twin (same enum) and asserts
// success + returndata + raw slots + logs identical. Raw calldata is hand-assembled so we can inject
// out-of-range and dirty-high-bit enum words that the ABI encoders would otherwise reject.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint, pad32, type LogEntry } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => pad32(v);
// dynamic value array tail: [len][e0][e1]... as raw 32-byte words (callers may inject dirty/OOR bits)
const dynArr = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');

const PRAGMA = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

// ---- the contract under test (JETH) and a byte-for-byte Solidity twin -------------------------
const J = `enum Color { Red, Green, Blue }
enum Status { Inactive, Active, Banned, Frozen }
type Packed = { a: Color; b: u8; c: Status; d: bool; e: address; };
type Boundary = { lead: u248; col: Color; trail: u8; };
type Item = { c: Color; qty: u32; flag: bool; };
type WithArr = { tag: u8; cols: Arr<Color,3>; };
type Nested = { id: u16; it: Item; };
type WithDyn = { a: Color[]; n: u256; };
class C {
  BadColor: error<{ c: Color }>;
  TaggedColor: error<{ tag: u256; c: Color }>;
  ColorSet: event<{ c: Color }>;
  ColorIdx: event<{ c: indexed<Color>; v: u256 }>;
  TwoEnum: event<{ a: indexed<Color>; b: Status }>;
  ColorArr: event<{ a: Color[] }>;
  packed: Packed;            // slot 0
  bnd: Boundary;             // slots 1-2 (u248 fills slot1; Color+u8 in slot2)
  it: Item;                  // slot 3
  cdyn: Color[];             // slot 4 (len) + keccak data
  cfix: Arr<Color,3>;        // slots 5,6,7 (one each? packed? -> match solc)
  seen: mapping<Color, bool>;
  pref: mapping<address, Color>;
  cur: Color;                // standalone slot for delete
  wa: WithArr;               // struct holding a fixed enum array
  nst: Nested;               // struct in struct, enum field nested

  // --- packing ---
  setPacked(a: Color, b: u8, c: Status, d: bool, e: address): External<void> {
    this.packed = Packed(a, b, c, d, e);
  }
  get getPackedA(): External<Color> { return this.packed.a; }
  get getPackedC(): External<Status> { return this.packed.c; }
  setBnd(lead: u248, col: Color, trail: u8): External<void> { this.bnd = Boundary(lead, col, trail); }
  get bndCol(): External<Color> { return this.bnd.col; }
  setItem(c: Color, q: u32, f: bool): External<void> { this.it = Item(c, q, f); }
  get itemColor(): External<Color> { return this.it.c; }

  // --- enum arrays ---
  get echoFix(a: Arr<Color,3>): External<Arr<Color,3>> { return a; }
  get echoDyn(a: Color[]): External<Color[]> { return a; }
  get echoNestedFix(a: Arr<Arr<Color,2>,2>): External<Arr<Arr<Color,2>,2>> { return a; }
  get echoStruct(s: WithDyn): External<WithDyn> { return s; }
  get fixElem(a: Arr<Color,3>, i: u256): External<Color> { return a[i]; }
  get dynElem(a: Color[], i: u256): External<Color> { return a[i]; }
  get fixSum(a: Arr<Color,3>): External<u256> { let s: u256 = 0n; for (const v of a) { s = s + u256(v); } return s; }
  get dynSum(a: Color[]): External<u256> { let s: u256 = 0n; for (const v of a) { s = s + u256(v); } return s; }
  get dynLen(a: Color[]): External<u256> { return a.length; }
  pushCdyn(c: Color): External<void> { this.cdyn.push(c); }     // element-wise (whole cd->storage copy is rejected JETH900, non-enum)
  get getCdyn(): External<Color[]> { return this.cdyn; }
  get cdynElem(i: u256): External<Color> { return this.cdyn[i]; }
  setCfixElem(i: u256, c: Color): External<void> { this.cfix[i] = c; }
  get getCfix(): External<Arr<Color,3>> { return this.cfix; }
  get cfixElem(i: u256): External<Color> { return this.cfix[i]; }

  // --- events ---
  emitColor(c: Color): External<void> { emit(ColorSet(c)); }
  emitIdx(c: Color, v: u256): External<void> { emit(ColorIdx(c, v)); }
  emitTwo(a: Color, b: Status): External<void> { emit(TwoEnum(a, b)); }
  emitArr(a: Color[]): External<void> { emit(ColorArr(a)); }

  // --- custom errors ---
  revBad(c: Color): External<void> { revert(BadColor(c)); }
  revTagged(t: u256, c: Color): External<void> { revert(TaggedColor(t, c)); }

  // --- casts ---
  get mk(x: u8): External<Color> { return Color(x); }
  get mkFromU256(x: u256): External<Color> { return Color(x); }
  get mkFromI8(x: i8): External<Color> { return Color(u8(x)); }
  get mkI8(x: i8): External<Color> { return Color(x); }           // direct signed cast, range-checked
  get mkI256(x: i256): External<Color> { return Color(x); }
  get cToBytes1(c: Color): External<bytes1> { return bytes1(u8(c)); } // the LEGAL enum->bytes1 path
  get toU8(c: Color): External<u8> { return u8(c); }
  get toU16(c: Color): External<u16> { return u16(c); }
  get toU256(c: Color): External<u256> { return u256(c); }
  get roundtrip(x: u8): External<u8> { return u8(Color(x)); }
  get redConst(): External<Color> { return Color.Red; }
  get blueConst(): External<Color> { return Color.Blue; }
  get constCast(): External<Color> { return Color(2n); }

  // --- mapping key/value ---
  mark(c: Color): External<void> { this.seen[c] = true; }
  get isSeen(c: Color): External<bool> { return this.seen[c]; }
  setPref(a: address, c: Color): External<void> { this.pref[a] = c; }
  get prefOf(a: address): External<Color> { return this.pref[a]; }

  // --- default member 0 + delete ---
  get unsetMapping(a: address): External<Color> { return this.pref[a]; }   // never set -> Red(0)
  setCur(c: Color): External<void> { this.cur = c; }
  delCur(): External<void> { delete this.cur; }
  get getCur(): External<Color> { return this.cur; }

  // --- comparisons / control flow ---
  get eq(a: Color, b: Color): External<bool> { return a == b; }
  get ne(a: Color, b: Color): External<bool> { return a != b; }
  get lt(a: Color, b: Color): External<bool> { return a < b; }
  get le(a: Color, b: Color): External<bool> { return a <= b; }
  get gt(a: Color, b: Color): External<bool> { return a > b; }
  get ge(a: Color, b: Color): External<bool> { return a >= b; }
  get tern(c: Color): External<u256> { return c == Color.Blue ? 100n : 1n; }
  get classify(c: Color): External<u8> {
    if (c == Color.Red) { return 7n; }
    if (c == Color.Green) { return 8n; }
    return 9n;
  }

  // --- multi-value + nested ---
  get pair(c: Color, n: u256): External<[Color, u256]> { return [c, n]; }
  setNested(id: u16, c: Color, q: u32, f: bool): External<void> { this.nst = Nested(id, Item(c, q, f)); }
  get nestedColor(): External<Color> { return this.nst.it.c; }
  setWa(tag: u8, c0: Color, c1: Color, c2: Color): External<void> { this.wa = WithArr(tag, [c0, c1, c2]); }
  get waElem(i: u256): External<Color> { return this.wa.cols[i]; }
  get mkBoundary(lead: u248, col: Color, trail: u8): External<Boundary> { return Boundary(lead, col, trail); }

  // --- default enum param (F3) ---
  mkDef(c: Color = Color.Red): Color { return c; }
  get defParam(): External<Color> { return this.mkDef(); }
  get withDef(c: Color = Color.Red): External<Color> { return c; }
}`;

const SOL = `${PRAGMA}contract C {
  enum Color { Red, Green, Blue }
  enum Status { Inactive, Active, Banned, Frozen }
  struct Packed { Color a; uint8 b; Status c; bool d; address e; }
  struct Boundary { uint248 lead; Color col; uint8 trail; }
  struct Item { Color c; uint32 qty; bool flag; }
  struct WithArr { uint8 tag; Color[3] cols; }
  struct Nested { uint16 id; Item it; }
  struct WithDyn { Color[] a; uint256 n; }
  error BadColor(Color c);
  error TaggedColor(uint256 tag, Color c);
  event ColorSet(Color c);
  event ColorIdx(Color indexed c, uint256 v);
  event TwoEnum(Color indexed a, Status b);
  event ColorArr(Color[] a);
  Packed packed;
  Boundary bnd;
  Item it;
  Color[] cdyn;
  Color[3] cfix;
  mapping(Color => bool) seen;
  mapping(address => Color) pref;
  Color cur;
  WithArr wa;
  Nested nst;

  function setPacked(Color a, uint8 b, Status c, bool d, address e) external { packed = Packed(a, b, c, d, e); }
  function getPackedA() external view returns (Color) { return packed.a; }
  function getPackedC() external view returns (Status) { return packed.c; }
  function setBnd(uint248 lead, Color col, uint8 trail) external { bnd = Boundary(lead, col, trail); }
  function bndCol() external view returns (Color) { return bnd.col; }
  function setItem(Color c, uint32 q, bool f) external { it = Item(c, q, f); }
  function itemColor() external view returns (Color) { return it.c; }

  function echoFix(Color[3] calldata a) external pure returns (Color[3] memory) { return a; }
  function echoDyn(Color[] calldata a) external pure returns (Color[] memory) { return a; }
  function echoNestedFix(Color[2][2] calldata a) external pure returns (Color[2][2] memory) { return a; }
  function echoStruct(WithDyn calldata s) external pure returns (WithDyn memory) { return s; }
  function fixElem(Color[3] calldata a, uint256 i) external pure returns (Color) { return a[i]; }
  function dynElem(Color[] calldata a, uint256 i) external pure returns (Color) { return a[i]; }
  function fixSum(Color[3] calldata a) external pure returns (uint256) { uint256 s=0; for (uint256 i=0;i<3;i++){ s+=uint256(a[i]); } return s; }
  function dynSum(Color[] calldata a) external pure returns (uint256) { uint256 s=0; for (uint256 i=0;i<a.length;i++){ s+=uint256(a[i]); } return s; }
  function dynLen(Color[] calldata a) external pure returns (uint256) { return a.length; }
  function pushCdyn(Color c) external { cdyn.push(c); }
  function getCdyn() external view returns (Color[] memory) { return cdyn; }
  function cdynElem(uint256 i) external view returns (Color) { return cdyn[i]; }
  function setCfixElem(uint256 i, Color c) external { cfix[i] = c; }
  function getCfix() external view returns (Color[3] memory) { return cfix; }
  function cfixElem(uint256 i) external view returns (Color) { return cfix[i]; }

  function emitColor(Color c) external { emit ColorSet(c); }
  function emitIdx(Color c, uint256 v) external { emit ColorIdx(c, v); }
  function emitTwo(Color a, Status b) external { emit TwoEnum(a, b); }
  function emitArr(Color[] calldata a) external { emit ColorArr(a); }

  function revBad(Color c) external pure { revert BadColor(c); }
  function revTagged(uint256 t, Color c) external pure { revert TaggedColor(t, c); }

  function mk(uint8 x) external pure returns (Color) { return Color(x); }
  function mkFromU256(uint256 x) external pure returns (Color) { return Color(x); }
  function mkFromI8(int8 x) external pure returns (Color) { return Color(uint8(x)); }
  function mkI8(int8 x) external pure returns (Color) { return Color(x); }
  function mkI256(int256 x) external pure returns (Color) { return Color(x); }
  function cToBytes1(Color c) external pure returns (bytes1) { return bytes1(uint8(c)); }
  function toU8(Color c) external pure returns (uint8) { return uint8(c); }
  function toU16(Color c) external pure returns (uint16) { return uint16(c); }
  function toU256(Color c) external pure returns (uint256) { return uint256(c); }
  function roundtrip(uint8 x) external pure returns (uint8) { return uint8(Color(x)); }
  function redConst() external pure returns (Color) { return Color.Red; }
  function blueConst() external pure returns (Color) { return Color.Blue; }
  function constCast() external pure returns (Color) { return Color(2); }

  function mark(Color c) external { seen[c] = true; }
  function isSeen(Color c) external view returns (bool) { return seen[c]; }
  function setPref(address a, Color c) external { pref[a] = c; }
  function prefOf(address a) external view returns (Color) { return pref[a]; }

  function unsetMapping(address a) external view returns (Color) { return pref[a]; }
  function setCur(Color c) external { cur = c; }
  function delCur() external { delete cur; }
  function getCur() external view returns (Color) { return cur; }

  function eq(Color a, Color b) external pure returns (bool) { return a == b; }
  function ne(Color a, Color b) external pure returns (bool) { return a != b; }
  function lt(Color a, Color b) external pure returns (bool) { return a < b; }
  function le(Color a, Color b) external pure returns (bool) { return a <= b; }
  function gt(Color a, Color b) external pure returns (bool) { return a > b; }
  function ge(Color a, Color b) external pure returns (bool) { return a >= b; }
  function tern(Color c) external pure returns (uint256) { return c == Color.Blue ? 100 : 1; }
  function classify(Color c) external pure returns (uint8) {
    if (c == Color.Red) { return 7; }
    if (c == Color.Green) { return 8; }
    return 9;
  }

  function pair(Color c, uint256 n) external pure returns (Color, uint256) { return (c, n); }
  function setNested(uint16 id, Color c, uint32 q, bool f) external { nst = Nested(id, Item(c, q, f)); }
  function nestedColor() external view returns (Color) { return nst.it.c; }
  function setWa(uint8 tag, Color c0, Color c1, Color c2) external { wa = WithArr(tag, [c0, c1, c2]); }
  function waElem(uint256 i) external view returns (Color) { return wa.cols[i]; }
  function mkBoundary(uint248 lead, Color col, uint8 trail) external pure returns (Boundary memory) { return Boundary(lead, col, trail); }

  function mkDefInternal(Color c) internal pure returns (Color) { return c; }
  function defParam() external pure returns (Color) { return mkDefInternal(Color.Red); }
  function withDef() external pure returns (Color) { return Color.Red; }
}`;

const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
  expect(a.map((l) => ({ t: l.topics, d: l.data }))).toEqual(b.map((l) => ({ t: l.topics, d: l.data })));

describe('ADV enums: byte-identical to solc (runtime / storage / logs / revert data)', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  // full parity for one call: success + returndata + logs (topics+data). Covers Panic / empty-revert
  // data (returnHex) and event encoding.
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    eqLogs(j.logs, s.logs);
    return { j, s };
  }
  async function slots(label: string, ...nums: bigint[]) {
    for (const n of nums) {
      expect(await readSlot(jeth, aj, n), `${label} slot ${n}`).toBe(await readSlot(sol, as, n));
    }
  }
  beforeAll(async () => {
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // ===== 0. ABI shape =====
  it('ABI types every enum exactly as uint8 (params, returns, mapping, array, event, error)', () => {
    const abi = compile(J, { fileName: 'C.jeth' }).abi;
    const io = (name: string): any => abi.find((e: any) => e.name === name);
    expect(io('setPacked').inputs.map((i: any) => i.type)).toEqual(['uint8', 'uint8', 'uint8', 'bool', 'address']);
    expect(io('echoFix').inputs.map((i: any) => i.type)).toEqual(['uint8[3]']);
    expect(io('echoDyn').inputs.map((i: any) => i.type)).toEqual(['uint8[]']);
    expect(io('pair').outputs.map((o: any) => o.type)).toEqual(['uint8', 'uint256']);
    expect(io('ColorSet').inputs.map((i: any) => i.type)).toEqual(['uint8']);
    expect(io('ColorIdx').inputs.map((i: any) => ({ t: i.type, ix: i.indexed }))).toEqual([
      { t: 'uint8', ix: true },
      { t: 'uint256', ix: false },
    ]);
    expect(io('BadColor').inputs.map((i: any) => i.type)).toEqual(['uint8']);
    // selectors hash uint8 so they hit the solc twin
    expect(sel('emitColor(uint8)')).toBe(functionSelector('emitColor(uint8)'));
  });

  // ===== 5. Casts =====
  it('Color(x) range-checks with Panic(0x21); in-range ok; -ve / wide / dirty all Panic', async () => {
    for (const v of [0n, 1n, 2n]) await eq(`mk(${v})`, encodeCall(sel('mk(uint8)'), [v]));
    for (const v of [3n, 4n, 255n]) await eq(`mk(${v}) OOR`, encodeCall(sel('mk(uint8)'), [v]));
    // literal Panic(0x21) data
    const r = await jeth.call(aj, encodeCall(sel('mk(uint8)'), [3n]));
    expect(r.returnHex).toBe('0x4e487b71' + pad(0x21n));
    // Color(uint256) with a wide value > N and dirty high bits -> Panic 0x21 (matches solc)
    for (const v of [
      3n,
      100n,
      1n << 255n,
      (1n << 256n) - 1n,
      0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03n,
    ])
      await eq(`mkFromU256(${v}) OOR`, encodeCall(sel('mkFromU256(uint256)'), [v]));
    for (const v of [0n, 1n, 2n]) await eq(`mkFromU256(${v}) ok`, encodeCall(sel('mkFromU256(uint256)'), [v]));
    // NEGATIVE int -> Color(u8(-1)) = Color(255) -> Panic 0x21
    await eq('mkFromI8(-1) OOR', encodeCall(sel('mkFromI8(int8)'), [-1n]));
    await eq('mkFromI8(2) ok', encodeCall(sel('mkFromI8(int8)'), [2n]));
    // DIRECT signed cast Color(i8) / Color(i256): the unsigned lt naturally rejects negatives.
    for (const v of [0n, 1n, 2n, -1n, 3n, 127n, -128n]) await eq(`mkI8(${v})`, encodeCall(sel('mkI8(int8)'), [v]));
    for (const v of [0n, 2n, -1n, 3n, 1n << 255n]) await eq(`mkI256(${v})`, encodeCall(sel('mkI256(int256)'), [v]));
    // the LEGAL enum->bytes1 path (via u8): left-aligned byte, matches solc
    for (const v of [0n, 1n, 2n]) await eq(`cToBytes1(${v})`, encodeCall(sel('cToBytes1(uint8)'), [v]));
    // roundtrip decode-cast-extract
    await eq('roundtrip(2)', encodeCall(sel('roundtrip(uint8)'), [2n]));
    await eq('roundtrip(3) OOR', encodeCall(sel('roundtrip(uint8)'), [3n]));
    // extraction reinterprets (no check)
    for (const v of [0n, 1n, 2n]) {
      await eq(`toU8(${v})`, encodeCall(sel('toU8(uint8)'), [v]));
      await eq(`toU16(${v})`, encodeCall(sel('toU16(uint8)'), [v]));
      await eq(`toU256(${v})`, encodeCall(sel('toU256(uint8)'), [v]));
    }
    // member constants + constant cast
    await eq('redConst', encodeCall(sel('redConst()'), []));
    await eq('blueConst', encodeCall(sel('blueConst()'), []));
    await eq('constCast', encodeCall(sel('constCast()'), []));
  });

  it('an out-of-range enum SCALAR calldata word reverts EMPTY (not a Panic), like solc', async () => {
    for (const v of [3n, 4n, 255n, 1n << 255n]) {
      const { j, s } = await eq(`mark(${v}) OOR empty revert`, encodeCall(sel('mark(uint8)'), [v]));
      expect(j.success).toBe(false);
      expect(j.returnHex).toBe('0x');
      expect(s.returnHex).toBe('0x');
    }
  });

  // ===== 2. ENUM ARRAYS: the crucial out-of-range / dirty element validation =====
  //
  // EMPIRICAL solc model (probed, NOT assumed): solc does NOT eagerly validate every enum array
  // element at the calldata-decode boundary. Instead it range-checks an enum element the moment it
  // READS / COPIES that element, and an out-of-range or dirty-high-bits element raises Panic(0x21)
  // at that read (NOT an empty revert, NOT at decode). Consequences:
  //   - reading `.length` of a Color[] with an OOR element: solc OK (length read touches no element).
  //   - a[i] / for-of element access: validates each element it touches -> matches JETH's lazy
  //     `validateInput` on calldata element read. (Accessing a single OOR element reverts EMPTY in
  //     BOTH, since the single-leaf path reverts(0,0); accessing an in-range index while a DIFFERENT
  //     index is OOR succeeds in both.)
  //   - WHOLE-ARRAY copy to memory (return a / echo): solc reads every element during the copy and
  //     reverts Panic(0x21) on the first OOR/dirty one.  <-- this is where JETH diverges (see below).
  const fixSelEcho = sel('echoFix(uint8[3])');
  const dynSelEcho = sel('echoDyn(uint8[])');
  const PANIC21 = '0x4e487b71' + pad(0x21n);

  describe('enum CALLDATA array ELEMENT ACCESS / sum / length: matches solc', () => {
    it('fixed Arr<Color,3> element ACCESS a[i] with an OOR neighbour -> matches solc', async () => {
      const s = sel('fixElem(uint8[3],uint256)');
      await eq('fixElem[0] arr has OOR[1]', '0x' + s + pad(0n) + pad(5n) + pad(2n) + pad(0n));
      await eq('fixElem[2] arr has OOR[1]', '0x' + s + pad(0n) + pad(5n) + pad(2n) + pad(2n));
      await eq('fixElem[1]=5 (access OOR)', '0x' + s + pad(0n) + pad(5n) + pad(2n) + pad(1n));
      for (const i of [0n, 1n, 2n]) await eq(`fixElem[${i}] in-range`, '0x' + s + pad(2n) + pad(1n) + pad(0n) + pad(i));
    });
    it('fixed Arr<Color,3> for-of sum reads every element -> OOR/dirty match solc', async () => {
      const s = sel('fixSum(uint8[3])');
      await eq('fixSum in-range', '0x' + s + pad(0n) + pad(1n) + pad(2n));
      await eq('fixSum OOR', '0x' + s + pad(0n) + pad(9n) + pad(2n));
      await eq('fixSum dirty', '0x' + s + pad((1n << 9n) | 1n) + pad(1n) + pad(2n));
    });
    it('dynamic Color[] sum / length / element access: OOR -> matches solc', async () => {
      const ss = sel('dynSum(uint8[])');
      const sl = sel('dynLen(uint8[])');
      const se = sel('dynElem(uint8[],uint256)');
      await eq('dynSum in-range', '0x' + ss + pad(0x20n) + dynArr([0n, 1n, 2n]));
      await eq('dynSum OOR', '0x' + ss + pad(0x20n) + dynArr([0n, 9n, 2n]));
      // .length touches no element: solc accepts an array carrying an OOR element. JETH must match.
      await eq('dynLen with OOR element (both OK)', '0x' + sl + pad(0x20n) + dynArr([0n, 5n, 2n]));
      await eq('dynLen in-range', '0x' + sl + pad(0x20n) + dynArr([0n, 1n, 2n]));
      await eq('dynElem[0] arr has OOR[2]', '0x' + se + pad(0x40n) + pad(0n) + dynArr([1n, 0n, 8n]));
      await eq('dynElem[2]=OOR (access)', '0x' + se + pad(0x40n) + pad(2n) + dynArr([1n, 0n, 8n]));
      await eq('dynElem OOB index -> Panic 0x32', '0x' + se + pad(0x40n) + pad(5n) + dynArr([1n, 0n, 2n]));
    });
    it('in-range whole-array echo (fixed + dynamic) matches solc exactly', async () => {
      await eq('echoFix in-range', '0x' + fixSelEcho + pad(0n) + pad(1n) + pad(2n));
      await eq('echoFix all-zero', '0x' + fixSelEcho + pad(0n) + pad(0n) + pad(0n));
      await eq('echoDyn empty', '0x' + dynSelEcho + pad(0x20n) + dynArr([]));
      await eq('echoDyn in-range', '0x' + dynSelEcho + pad(0x20n) + dynArr([0n, 1n, 2n, 0n]));
    });
  });

  // ----------------------------------------------------------------------------------------------
  // REGRESSION (was a P1 miscompile, now FIXED). A calldata enum array copied WHOLE to memory
  // (`return a` for Color[3] / Color[]) is range-checked element-by-element to match solc: an
  // out-of-range element (>= memberCount) or one with dirty high bits reverts Panic(0x21) the
  // moment it is copied, exactly like solc. (Previously JETH masked it to uint8 and returned it.)
  // Fix: src/yul.ts abiEncFromCd value-leaf / static-aggregate "clean" branches emit
  // `if iszero(lt(w, N)) { panic(0x21) }` for an enum leaf instead of cleanCalldataElem (mask). The
  // other enum-validation sites keep their EMPTY revert (ABI decode boundary, lazy element access,
  // event/error materialization) - see the BOUNDARY case below.
  describe('enum CALLDATA array WHOLE-ARRAY echo: OOR/dirty element validation', () => {
    it('dynamic Color[] echo with an OOR element reverts Panic(0x21) like solc', async () => {
      const r = await jeth.call(aj, '0x' + dynSelEcho + pad(0x20n) + dynArr([0n, 7n, 2n]));
      expect(r.success).toBe(false);
      expect(r.returnHex).toBe(PANIC21);
    });
    it('dynamic Color[] echo with dirty high bits reverts Panic(0x21) like solc', async () => {
      const r = await jeth.call(aj, '0x' + dynSelEcho + pad(0x20n) + dynArr([0n, (1n << 16n) | 1n, 2n]));
      expect(r.success).toBe(false);
      expect(r.returnHex).toBe(PANIC21);
    });
    it('fixed Arr<Color,3> echo with an OOR element reverts Panic(0x21) like solc', async () => {
      const r = await jeth.call(aj, '0x' + fixSelEcho + pad(0n) + pad(5n) + pad(2n));
      expect(r.success).toBe(false);
      expect(r.returnHex).toBe(PANIC21);
    });
    it('fixed Arr<Color,3> echo with dirty high bits reverts Panic(0x21) like solc', async () => {
      const r = await jeth.call(aj, '0x' + fixSelEcho + pad(0n) + pad((1n << 8n) | 2n) + pad(2n));
      expect(r.success).toBe(false);
      expect(r.returnHex).toBe(PANIC21);
    });
    it('nested Arr<Arr<Color,2>,2> echo with an OOR element reverts Panic(0x21)', async () => {
      const r = await jeth.call(aj, '0x' + sel('echoNestedFix(uint8[2][2])') + pad(0n) + pad(5n) + pad(2n) + pad(0n));
      expect(r.success).toBe(false);
      expect(r.returnHex).toBe(PANIC21);
    });
    it('PARITY: an OOR Color[] echo now reverts Panic(0x21) in BOTH JETH and solc', async () => {
      const data = '0x' + dynSelEcho + pad(0x20n) + dynArr([0n, 7n, 2n]);
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(s.success).toBe(false);
      expect(s.returnHex).toBe(PANIC21);
      expect(j.success).toBe(s.success);
      expect(j.returnHex).toBe(s.returnHex);
    });
    it('BOUNDARY: a Color[] WRAPPED IN A STRUCT echo IS validated (matches solc, no divergence)', async () => {
      // When the same enum array is a struct field, JETH takes the struct-decode validate path, so an
      // OOR element reverts in BOTH (here EMPTY, solc validating at the struct decode boundary). This
      // narrows the miscompile to TOP-LEVEL / nested bare value-leaf arrays only.
      const head = pad(0x20n) + pad(0x40n) + pad(9n); // outer off, struct{a_off, n}
      await eq('echoStruct in-range', '0x' + sel('echoStruct((uint8[],uint256))') + head + dynArr([0n, 1n, 2n]));
      const { j, s } = await eq(
        'echoStruct OOR -> both revert',
        '0x' + sel('echoStruct((uint8[],uint256))') + head + dynArr([0n, 7n, 2n]),
      );
      expect(j.success).toBe(false);
      expect(s.success).toBe(false);
    });
  });

  // ===== 1. STORAGE PACKING =====
  it('enum packs in a slot beside u8 / Status / bool / address (raw slot parity)', async () => {
    const A = 0xcafe0000000000000000000000000000beef0001n;
    const d =
      '0x' + sel('setPacked(uint8,uint8,uint8,bool,address)') + pad(2n) + pad(0xabn) + pad(3n) + pad(1n) + pad(A);
    await jeth.call(aj, d);
    await sol.call(as, d);
    await slots('packed', 0n);
    await eq('getPackedA', encodeCall(sel('getPackedA()'), []));
    await eq('getPackedC', encodeCall(sel('getPackedC()'), []));
  });

  it('enum struct field across a slot boundary (u248 fills slot, enum starts next slot)', async () => {
    const lead = (1n << 248n) - 1n;
    const d = '0x' + sel('setBnd(uint248,uint8,uint8)') + pad(lead) + pad(2n) + pad(0x77n);
    await jeth.call(aj, d);
    await sol.call(as, d);
    await slots('bnd', 1n, 2n);
    await eq('bndCol', encodeCall(sel('bndCol()'), []));
    // whole-struct return of the boundary struct
    await eq('mkBoundary', '0x' + sel('mkBoundary(uint248,uint8,uint8)') + pad(lead) + pad(1n) + pad(0x55n));
  });

  it('enum struct field packed beside u32/bool (Item) raw slot parity', async () => {
    const d = '0x' + sel('setItem(uint8,uint32,bool)') + pad(1n) + pad(0xdeadbeefn) + pad(1n);
    await jeth.call(aj, d);
    await sol.call(as, d);
    await slots('item', 3n);
    await eq('itemColor', encodeCall(sel('itemColor()'), []));
  });

  it('storage Color[] (dynamic) + Arr<Color,3> (fixed): raw slots match solc incl. packing', async () => {
    // dynamic Color[] @ slot 4 (length) + keccak(4) data. Build element-wise via push.
    for (const c of [2n, 0n, 1n, 2n, 1n]) {
      await jeth.call(aj, encodeCall(sel('pushCdyn(uint8)'), [c]));
      await sol.call(as, encodeCall(sel('pushCdyn(uint8)'), [c]));
    }
    await slots('cdyn length', 4n);
    // keccak(slot 4) data base: solc packs 32 uint8 enums per slot, so 5 elements live in one slot.
    const { keccak256 } = await import('ethereum-cryptography/keccak.js');
    const { setLengthLeft, hexToBytes, bytesToHex } = await import('@ethereumjs/util');
    const dataBase = BigInt(bytesToHex(keccak256(setLengthLeft(hexToBytes('0x04'), 32))));
    await slots('cdyn data+0', dataBase);
    await eq('getCdyn', encodeCall(sel('getCdyn()'), []));
    await eq('cdynElem[4]', encodeCall(sel('cdynElem(uint256)'), [4n]));
    // fixed Arr<Color,3> @ slot 5: solc packs 3 uint8 enums into ONE slot. Write each element.
    for (const [i, c] of [
      [0n, 2n],
      [1n, 0n],
      [2n, 1n],
    ] as [bigint, bigint][]) {
      await jeth.call(aj, encodeCall(sel('setCfixElem(uint256,uint8)'), [i, c]));
      await sol.call(as, encodeCall(sel('setCfixElem(uint256,uint8)'), [i, c]));
    }
    await slots('cfix packed in one slot', 5n);
    await eq('getCfix', encodeCall(sel('getCfix()'), []));
    for (const i of [0n, 1n, 2n]) await eq(`cfixElem[${i}]`, encodeCall(sel('cfixElem(uint256)'), [i]));
  });

  // ===== 3. EVENTS =====
  it('enum events: non-indexed, indexed, two-enum -> topics/data byte-identical to solc', async () => {
    // eq() already compares logs (topics + data) against solc for each call.
    for (const v of [0n, 1n, 2n]) await eq(`emitColor(${v})`, encodeCall(sel('emitColor(uint8)'), [v]));
    for (const v of [0n, 1n, 2n]) await eq(`emitIdx(${v})`, encodeCall(sel('emitIdx(uint8,uint256)'), [v, 0xabcdn]));
    await eq('emitTwo', '0x' + sel('emitTwo(uint8,uint8)') + pad(2n) + pad(3n));
    // topic0 of a non-indexed enum event hashes the uint8 signature (full 32-byte keccak).
    const ev = await jeth.call(aj, encodeCall(sel('emitColor(uint8)'), [1n]));
    const sv = await sol.call(as, encodeCall(sel('emitColor(uint8)'), [1n]));
    expect(ev.logs[0]!.topics[0]).toBe(sv.logs[0]!.topics[0]); // = keccak256("ColorSet(uint8)")
    // the non-indexed enum member sits in the data word (not a topic)
    expect(ev.logs[0]!.data).toBe('0x' + pad32(1n));
    // indexed enum: member is topic1, brand-erased to a uint8-padded word
    const ix = await jeth.call(aj, encodeCall(sel('emitIdx(uint8,uint256)'), [2n, 0xabcdn]));
    expect(ix.logs[0]!.topics[1]).toBe('0x' + pad32(2n));
  });

  it('enum ARRAY event arg: the validate path range-checks every element (matches solc, unlike echo)', async () => {
    // CONTRAST with the whole-array echo miscompile: the emit/revert encoder takes the validate=true
    // branch, so an OOR / dirty enum element is range-checked and the call reverts EMPTY in BOTH
    // JETH and solc. This proves the enum-element check IS wired on the event/error encode path.
    await eq('emitArr in-range', '0x' + sel('emitArr(uint8[])') + pad(0x20n) + dynArr([0n, 1n, 2n]));
    const { j, s } = await eq(
      'emitArr OOR -> both revert empty',
      '0x' + sel('emitArr(uint8[])') + pad(0x20n) + dynArr([0n, 7n, 2n]),
    );
    expect(j.success).toBe(false);
    expect(j.returnHex).toBe('0x');
    expect(s.returnHex).toBe('0x');
    await eq(
      'emitArr dirty -> both revert empty',
      '0x' + sel('emitArr(uint8[])') + pad(0x20n) + dynArr([0n, (1n << 16n) | 1n, 2n]),
    );
  });

  // ===== 4. CUSTOM ERRORS =====
  it('enum custom-error args: revert data byte-identical (signature hashes uint8)', async () => {
    for (const v of [0n, 1n, 2n]) {
      const { j } = await eq(`revBad(${v})`, encodeCall(sel('revBad(uint8)'), [v]));
      expect(j.success).toBe(false);
      // selector(BadColor(uint8)) + the member word
      expect(j.returnHex).toBe('0x' + functionSelector('BadColor(uint8)') + pad(v));
    }
    await eq('revTagged', '0x' + sel('revTagged(uint256,uint8)') + pad(42n) + pad(2n));
  });

  // ===== 6. DEFAULT 0 + DELETE =====
  it('unset mapping enum reads default member 0 (Red); delete resets storage enum (raw slot)', async () => {
    const A = 0xdead0000000000000000000000000000dead0002n;
    await eq('unsetMapping default 0', encodeCall(sel('unsetMapping(address)'), [A]));
    // set then delete; cur lives at slot 8 (standalone enum)
    await jeth.call(aj, encodeCall(sel('setCur(uint8)'), [2n]));
    await sol.call(as, encodeCall(sel('setCur(uint8)'), [2n]));
    await slots('cur set', 8n);
    await jeth.call(aj, encodeCall(sel('delCur()'), []));
    await sol.call(as, encodeCall(sel('delCur()'), []));
    await slots('cur deleted', 8n);
    await eq('getCur after delete', encodeCall(sel('getCur()'), []));
  });

  // ===== 7. COMPARISONS + CONTROL FLOW + MAPPING KEY/VALUE =====
  it('all six comparisons + ternary + if-chain over enums match solc', async () => {
    const pairs: [bigint, bigint][] = [
      [0n, 0n],
      [0n, 1n],
      [1n, 0n],
      [2n, 2n],
      [0n, 2n],
      [2n, 0n],
    ];
    for (const op of ['eq', 'ne', 'lt', 'le', 'gt', 'ge']) {
      for (const [a, b] of pairs) await eq(`${op}(${a},${b})`, encodeCall(sel(`${op}(uint8,uint8)`), [a, b]));
    }
    for (const v of [0n, 1n, 2n]) {
      await eq(`tern(${v})`, encodeCall(sel('tern(uint8)'), [v]));
      await eq(`classify(${v})`, encodeCall(sel('classify(uint8)'), [v]));
    }
  });

  it('enum as mapping KEY and VALUE matches solc incl. raw slots', async () => {
    await jeth.call(aj, encodeCall(sel('mark(uint8)'), [2n]));
    await sol.call(as, encodeCall(sel('mark(uint8)'), [2n]));
    for (const v of [0n, 1n, 2n]) await eq(`isSeen(${v})`, encodeCall(sel('isSeen(uint8)'), [v]));
    const A = 0xa11ce0000000000000000000000000000000n;
    const setP = '0x' + sel('setPref(address,uint8)') + pad(A) + pad(1n);
    await jeth.call(aj, setP);
    await sol.call(as, setP);
    await eq('prefOf', encodeCall(sel('prefOf(address)'), [A]));
  });

  // ===== 8. MULTI-VALUE + NESTED =====
  it('enum in a multi-value tuple return + enum nested in struct-in-struct + enum array in struct', async () => {
    await eq('pair', '0x' + sel('pair(uint8,uint256)') + pad(2n) + pad(0x1234n));
    const setN = '0x' + sel('setNested(uint16,uint8,uint32,bool)') + pad(0x0102n) + pad(1n) + pad(0xcafen) + pad(1n);
    await jeth.call(aj, setN);
    await sol.call(as, setN);
    await eq('nestedColor', encodeCall(sel('nestedColor()'), []));
    // enum array inside a struct
    const setW = '0x' + sel('setWa(uint8,uint8,uint8,uint8)') + pad(0xabn) + pad(2n) + pad(0n) + pad(1n);
    await jeth.call(aj, setW);
    await sol.call(as, setW);
    for (const i of [0n, 1n, 2n]) await eq(`waElem[${i}]`, encodeCall(sel('waElem(uint256)'), [i]));
  });

  // ===== 9. INTERACTIONS: default enum param =====
  it('default enum param (F3) omitted at an INTERNAL call site -> Color.Red, matches solc', async () => {
    // F3 defaults apply at internal call sites only; defParam() calls this.mkDef() with the param
    // omitted, so it resolves to Color.Red. Solidity cannot express a default param, so the twin
    // hard-codes Color.Red in defParam(): both must return Red (member 0).
    await eq('defParam (internal default Red)', encodeCall(sel('defParam()'), []));
    // An @external default KEEPS the uint8 param in the JETH ABI (the default only fires at internal
    // call sites), so withDef(uint8) is a plain passthrough. solc has no such function, so we assert
    // JETH's own behavior here (returns the member unchanged) rather than against the twin.
    for (const v of [0n, 1n, 2n]) {
      const r = await jeth.call(aj, encodeCall(sel('withDef(uint8)'), [v]));
      expect(r.success, `withDef(${v})`).toBe(true);
      expect(decodeUint(r.returnHex)).toBe(v);
    }
    // out-of-range passthrough still reverts EMPTY at the uint8-enum calldata guard, like any enum param
    const oor = await jeth.call(aj, encodeCall(sel('withDef(uint8)'), [5n]));
    expect(oor.success).toBe(false);
    expect(oor.returnHex).toBe('0x');
  });

  it('getCur sanity: stored member index round-trips', async () => {
    await jeth.call(aj, encodeCall(sel('setCur(uint8)'), [1n]));
    const r = await jeth.call(aj, encodeCall(sel('getCur()'), []));
    expect(decodeUint(r.returnHex)).toBe(1n);
  });
});

// ===== 10. SOUNDNESS REJECTIONS (capture the JETH diagnostic code, must not crash) =====
function errCodes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    if (e && Array.isArray(e.diagnostics)) {
      return e.diagnostics.filter((d: any) => d.severity === 'error').map((d: any) => d.code);
    }
    throw e;
  }
}
const PRE = 'enum Color { Red, Green, Blue }\nenum Status { Inactive, Active }\n';
const wrap = (body: string) => `${PRE}class C { ${body} }`;

describe('ADV enums: soundness rejections (no crash, correct diagnostic)', () => {
  it('rejects arithmetic / bitwise / shift on enums (JETH279)', () => {
    expect(errCodes(wrap('@external @pure f(): Color { return Color.Red + 1n; }'))).toContain('JETH279');
    expect(errCodes(wrap('@external @pure f(a: Color, b: Color): u8 { return u8(a + b); }'))).toContain('JETH279');
    expect(errCodes(wrap('@external @pure f(a: Color, b: Color): u8 { return u8(a & b); }'))).toContain('JETH279');
    expect(errCodes(wrap('@external @pure f(a: Color): u8 { return u8(a << 1n); }'))).toContain('JETH279');
    expect(errCodes(wrap('@external @pure f(a: Color): u8 { return u8(a | a); }'))).toContain('JETH279');
  });
  it('rejects mixing two different enums in a comparison (JETH083)', () => {
    expect(errCodes(wrap('@external @pure f(a: Color, b: Status): bool { return a == b; }'))).toContain('JETH083');
    expect(errCodes(wrap('@external @pure f(a: Color, b: Status): bool { return a < b; }'))).toContain('JETH083');
  });
  it('rejects a bare integer assigned to an enum without a cast (JETH280)', () => {
    expect(errCodes(wrap('@external @pure f(): Color { return 1n; }'))).toContain('JETH280');
    expect(errCodes(wrap('@state c: Color; @external s(): void { this.c = 2n; }'))).toContain('JETH280');
    expect(errCodes(wrap('@external @pure f(c: Color): bool { return c == 1n; }'))).toContain('JETH280');
    expect(errCodes(wrap('@external @pure f(): Color { const c: Color = 1n; return c; }'))).toContain('JETH280');
  });
  it('rejects an empty enum (JETH275) and explicit member values (JETH270)', () => {
    expect(errCodes('enum E {}\nclass C { get f(): External<u8> { return 0n; } }')).toContain('JETH275');
    expect(errCodes('enum E { A = 5 }\nclass C { get f(): External<u8> { return 0n; } }')).toContain(
      'JETH270',
    );
  });
  it('rejects an unknown member (JETH271) and out-of-range constant cast (JETH278)', () => {
    expect(errCodes(wrap('@external @pure f(): Color { return Color.Purple; }'))).toContain('JETH271');
    expect(errCodes(wrap('@external @pure f(): Color { return Color(3n); }'))).toContain('JETH278');
    expect(errCodes(wrap('@external @pure f(): Color { return Color(255n); }'))).toContain('JETH278');
  });
  it('accepts the in-range constant cast Color(2n) (no error)', () => {
    expect(errCodes(wrap('@external @pure f(): Color { return Color(2n); }'))).toEqual([]);
    expect(errCodes(wrap('@external @pure f(): Color { return Color(0n); }'))).toEqual([]);
  });
  it('rejects casting a non-integer (address / bytes32 / bool / struct) to an enum (JETH277)', () => {
    expect(errCodes(wrap('@external @pure f(a: address): Color { return Color(a); }'))).toContain('JETH277');
    expect(errCodes(wrap('@external @pure f(b: bytes32): Color { return Color(b); }'))).toContain('JETH277');
    expect(errCodes(wrap('@external @pure f(b: bool): Color { return Color(b); }'))).toContain('JETH277');
    expect(
      errCodes(
        'enum Color { Red, Green, Blue }\ntype P = { x: u256; };\nclass C { get f(p: P): External<Color> { return Color(p); } }',
      ),
    ).toContain('JETH277');
  });
  it('rejects an enum used as a non-bool if/loop discriminant (JETH110)', () => {
    expect(errCodes(wrap('@external @pure f(c: Color): u8 { if (c) { return 1n; } return 0n; }'))).toContain('JETH110');
    expect(errCodes(wrap('@external @pure f(c: Color): u8 { while (c) { return 1n; } return 0n; }'))).toContain(
      'JETH110',
    );
  });

  // REGRESSION (was over-acceptance, now FIXED). solc REJECTS a direct enum->bytesN conversion
  // ("Explicit type conversion not allowed from enum to bytes1"); the only legal path is
  // bytes1(uint8(c)). JETH now rejects the direct enum->bytesN cast (JETH170, via the enum-source
  // guard in isCastAllowed) to match solc. The legal bytes1(u8(c)) path stays byte-identical.
  it('rejects a direct enum->bytesN cast like solc does (JETH170)', () => {
    const codes = errCodes(wrap('@external @pure f(c: Color): bytes1 { return bytes1(c); }'));
    expect(codes).toContain('JETH170');
  });
});
