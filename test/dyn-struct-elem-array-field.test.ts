// Lift #S: a DYNAMIC-outer struct-ELEMENT array field of a memory dyn-struct local. Two SEPARABLE
// element kinds: (A) a STATIC-struct element `Poly{id; pts:Pt[]}` (each element flat-inline in the array
// image), and (B) a DYNAMIC-struct element `Order{id; lines:Line[]}` (Line has a string field, so each
// element is pointer-headed). The field's ONE head word holds an absolute pointer to the array image
// [len][per-element block] - the SAME [len]-headed image a BARE Pt[]/Line[] memory local already builds
// (buildNestedMemArrayLit) and reads (resolveMemDynStructArrayField). Byte-identical to solc 0.8.35 across:
// element field read p.pts[i].y / o.lines[i].note/.qty (const + runtime index), .id, .pts.length,
// abi.encode(whole struct), return whole struct, abi.encode(field array) / return field array (o.lines),
// empty/single/3-element field arrays, a >32-byte string element, an element struct with a u256[] field,
// a nested outer with TWO struct-element-array fields, and a nested-dyn-struct field carrying one. OOB is a
// runtime Panic 0x32 (the field is a DYNAMIC array; the bounds-checked dyn-array element access reverts,
// NOT a compile-time JETH211 reject). CONTROL: the value-element dyn-array field Order2{id; ns:u256[]} is a
// separate pre-existing path and stays byte-identical; the literal-direct-to-field form `Poly(9,[Pt,Pt])`
// stays a clean JETH226 reject (solc rejects the Pt[2]->Pt[] implicit conversion too).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}
function decodeString(hex: string): string {
  const b = Buffer.from(hex.replace(/^0x/, ''), 'hex');
  const len = Number(BigInt('0x' + b.subarray(0x20, 0x40).toString('hex')));
  return b.subarray(0x40, 0x40 + len).toString('utf8');
}
function decodeU256(hex: string): bigint {
  return BigInt('0x' + hex.replace(/^0x/, '').slice(0, 64));
}
const PANIC32 = '0x4e487b71' + pad32(0x32n);

describe('dynamic-outer struct-element array field of a memory dyn-struct local (Lift #S) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  // KIND A: static-struct element Pt[]. KIND B: dynamic-struct element Line[] (string field).
  // S5-A: O{xs:St[]; k}. Deep: element carries a u256[]. Nested: TWO fields. NestedDyn: field behind a
  // nested dyn struct. Field arrays are built via a local (solc rejects the Pt[2]->Pt[] literal conversion).
  const J = `type Pt = { x: u256; y: u256 };
type Poly = { id: u256; pts: Pt[] };
type Line = { note: string; qty: u256 };
type Order = { id: u256; lines: Line[] };
type St = { s: string; v: u256 };
type O = { xs: St[]; k: u256 };
type Item = { tags: u256[]; qty: u256 };
type Bag = { id: u256; items: Item[] };
type Both = { pts: Pt[]; lines: Line[] };
type Inner = { name: string; lines: Line[] };
type Outer = { tag: u256; inner: Inner };
class C {
  get aReadY(i: u256): External<u256> { let a: Pt[] = [Pt(3n,4n),Pt(5n,6n)]; let p: Poly = Poly(9n, a); return p.pts[i].y; }
  get aReadX0(): External<u256> { let a: Pt[] = [Pt(3n,4n),Pt(5n,6n)]; let p: Poly = Poly(9n, a); return p.pts[0n].x; }
  get aId(): External<u256> { let a: Pt[] = [Pt(3n,4n),Pt(5n,6n)]; let p: Poly = Poly(9n, a); return p.id; }
  get aLen(): External<u256> { let a: Pt[] = [Pt(3n,4n),Pt(5n,6n)]; let p: Poly = Poly(9n, a); return p.pts.length; }
  get aEnc(): External<bytes> { let a: Pt[] = [Pt(3n,4n),Pt(5n,6n)]; let p: Poly = Poly(9n, a); return abi.encode(p); }
  get aWhole(): External<Poly> { let a: Pt[] = [Pt(3n,4n),Pt(5n,6n)]; let p: Poly = Poly(9n, a); return p; }
  get aEmptyLen(): External<u256> { let a: Pt[] = []; let p: Poly = Poly(9n, a); return p.pts.length; }
  get aEmptyEnc(): External<bytes> { let a: Pt[] = []; let p: Poly = Poly(9n, a); return abi.encode(p); }
  get aSingle(): External<u256> { let a: Pt[] = [Pt(7n,8n)]; let p: Poly = Poly(9n, a); return p.pts[0n].y; }
  get aOOB(): External<u256> { let a: Pt[] = [Pt(3n,4n),Pt(5n,6n)]; let p: Poly = Poly(9n, a); return p.pts[5n].y; }

  get bNote(i: u256): External<string> { let a: Line[] = [Line("hello",42n),Line("world",7n)]; let o: Order = Order(3n, a); return o.lines[i].note; }
  get bQty(i: u256): External<u256> { let a: Line[] = [Line("hello",42n),Line("world",7n)]; let o: Order = Order(3n, a); return o.lines[i].qty; }
  get bId(): External<u256> { let a: Line[] = [Line("hello",42n),Line("world",7n)]; let o: Order = Order(3n, a); return o.id; }
  get bLen(): External<u256> { let a: Line[] = [Line("hello",42n),Line("world",7n)]; let o: Order = Order(3n, a); return o.lines.length; }
  get bEncO(): External<bytes> { let a: Line[] = [Line("hello",42n),Line("world",7n)]; let o: Order = Order(3n, a); return abi.encode(o); }
  get bRetO(): External<Order> { let a: Line[] = [Line("hello",42n),Line("world",7n)]; let o: Order = Order(3n, a); return o; }
  get bEncLines(): External<bytes> { let a: Line[] = [Line("hello",42n),Line("world",7n)]; let o: Order = Order(3n, a); return abi.encode(o.lines); }
  get bRetLines(): External<Line[]> { let a: Line[] = [Line("hello",42n),Line("world",7n)]; let o: Order = Order(3n, a); return o.lines; }
  get bBig(): External<bytes> { let a: Line[] = [Line("this-is-a-note-longer-than-thirty-two-bytes-for-sure",1n),Line("y",2n)]; let o: Order = Order(3n, a); return abi.encode(o); }
  get bThree(): External<bytes> { let a: Line[] = [Line("aa",1n),Line("bb",2n),Line("cc",3n)]; let o: Order = Order(3n, a); return abi.encode(o); }
  get bEmptyEnc(): External<bytes> { let a: Line[] = []; let o: Order = Order(3n, a); return abi.encode(o); }
  get bEmptyLines(): External<Line[]> { let a: Line[] = []; let o: Order = Order(3n, a); return o.lines; }
  get bOOB(): External<u256> { let a: Line[] = [Line("hi",1n),Line("yo",2n)]; let o: Order = Order(3n, a); return o.lines[5n].qty; }

  get s5RetXs(): External<St[]> { let a: St[] = [St("p",1n),St("q",2n)]; let o: O = O(a, 99n); return o.xs; }
  get s5EncXs(): External<bytes> { let a: St[] = [St("p",1n),St("q",2n)]; let o: O = O(a, 99n); return abi.encode(o.xs); }
  get s5EncO(): External<bytes> { let a: St[] = [St("p",1n),St("q",2n)]; let o: O = O(a, 99n); return abi.encode(o); }
  get s5K(): External<u256> { let a: St[] = [St("p",1n),St("q",2n)]; let o: O = O(a, 99n); return o.k; }

  get dpEnc(): External<bytes> { let t0: u256[] = [1n,2n]; let t1: u256[] = [9n]; let a: Item[] = [Item(t0,5n),Item(t1,6n)]; let b: Bag = Bag(7n, a); return abi.encode(b); }
  get dpTag(): External<u256> { let t0: u256[] = [1n,2n]; let t1: u256[] = [9n]; let a: Item[] = [Item(t0,5n),Item(t1,6n)]; let b: Bag = Bag(7n, a); return b.items[0n].tags[1n]; }

  get ntEnc(): External<bytes> { let ap: Pt[] = [Pt(1n,2n),Pt(3n,4n)]; let al: Line[] = [Line("x",5n)]; let b: Both = Both(ap, al); return abi.encode(b); }
  get ntPt(): External<u256> { let ap: Pt[] = [Pt(1n,2n),Pt(3n,4n)]; let al: Line[] = [Line("x",5n)]; let b: Both = Both(ap, al); return b.pts[1n].y; }
  get ntLn(): External<string> { let ap: Pt[] = [Pt(1n,2n),Pt(3n,4n)]; let al: Line[] = [Line("x",5n)]; let b: Both = Both(ap, al); return b.lines[0n].note; }

  get ndEnc(): External<bytes> { let al: Line[] = [Line("a",1n),Line("b",2n)]; let inr: Inner = Inner("nm", al); let o: Outer = Outer(7n, inr); return abi.encode(o); }
  get ndNote(): External<string> { let al: Line[] = [Line("a",1n),Line("b",2n)]; let inr: Inner = Inner("nm", al); let o: Outer = Outer(7n, inr); return o.inner.lines[1n].note; }

  get vElem(): External<u256> { let a: u256[] = [10n,20n,30n]; let o2: Order2 = Order2(9n, a); return o2.ns[1n]; }
}
type Order2 = { id: u256; ns: u256[] };`;
  const So = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  struct Pt { uint256 x; uint256 y; }
  struct Poly { uint256 id; Pt[] pts; }
  struct Line { string note; uint256 qty; }
  struct Order { uint256 id; Line[] lines; }
  struct St { string s; uint256 v; }
  struct O { St[] xs; uint256 k; }
  struct Item { uint256[] tags; uint256 qty; }
  struct Bag { uint256 id; Item[] items; }
  struct Both { Pt[] pts; Line[] lines; }
  struct Inner { string name; Line[] lines; }
  struct Outer { uint256 tag; Inner inner; }
  struct Order2 { uint256 id; uint256[] ns; }
  function mkPoly() internal pure returns (Poly memory p){ Pt[] memory a=new Pt[](2); a[0]=Pt(3,4);a[1]=Pt(5,6); p=Poly(9,a); }
  function aReadY(uint256 i) external pure returns (uint256){ return mkPoly().pts[i].y; }
  function aReadX0() external pure returns (uint256){ return mkPoly().pts[0].x; }
  function aId() external pure returns (uint256){ return mkPoly().id; }
  function aLen() external pure returns (uint256){ return mkPoly().pts.length; }
  function aEnc() external pure returns (bytes memory){ return abi.encode(mkPoly()); }
  function aWhole() external pure returns (Poly memory){ return mkPoly(); }
  function aEmptyLen() external pure returns (uint256){ Pt[] memory a=new Pt[](0); return Poly(9,a).pts.length; }
  function aEmptyEnc() external pure returns (bytes memory){ Pt[] memory a=new Pt[](0); return abi.encode(Poly(9,a)); }
  function aSingle() external pure returns (uint256){ Pt[] memory a=new Pt[](1); a[0]=Pt(7,8); return Poly(9,a).pts[0].y; }
  function aOOB() external pure returns (uint256){ return mkPoly().pts[5].y; }

  function mkOrder() internal pure returns (Order memory o){ Line[] memory a=new Line[](2); a[0]=Line("hello",42);a[1]=Line("world",7); o=Order(3,a); }
  function bNote(uint256 i) external pure returns (string memory){ return mkOrder().lines[i].note; }
  function bQty(uint256 i) external pure returns (uint256){ return mkOrder().lines[i].qty; }
  function bId() external pure returns (uint256){ return mkOrder().id; }
  function bLen() external pure returns (uint256){ return mkOrder().lines.length; }
  function bEncO() external pure returns (bytes memory){ return abi.encode(mkOrder()); }
  function bRetO() external pure returns (Order memory){ return mkOrder(); }
  function bEncLines() external pure returns (bytes memory){ return abi.encode(mkOrder().lines); }
  function bRetLines() external pure returns (Line[] memory){ return mkOrder().lines; }
  function bBig() external pure returns (bytes memory){ Line[] memory a=new Line[](2); a[0]=Line("this-is-a-note-longer-than-thirty-two-bytes-for-sure",1);a[1]=Line("y",2); return abi.encode(Order(3,a)); }
  function bThree() external pure returns (bytes memory){ Line[] memory a=new Line[](3); a[0]=Line("aa",1);a[1]=Line("bb",2);a[2]=Line("cc",3); return abi.encode(Order(3,a)); }
  function bEmptyEnc() external pure returns (bytes memory){ Line[] memory a=new Line[](0); return abi.encode(Order(3,a)); }
  function bEmptyLines() external pure returns (Line[] memory){ Line[] memory a=new Line[](0); return Order(3,a).lines; }
  function bOOB() external pure returns (uint256){ Line[] memory a=new Line[](2); a[0]=Line("hi",1);a[1]=Line("yo",2); return Order(3,a).lines[5].qty; }

  function mkO() internal pure returns (O memory o){ St[] memory a=new St[](2); a[0]=St("p",1);a[1]=St("q",2); o=O(a,99); }
  function s5RetXs() external pure returns (St[] memory){ return mkO().xs; }
  function s5EncXs() external pure returns (bytes memory){ return abi.encode(mkO().xs); }
  function s5EncO() external pure returns (bytes memory){ return abi.encode(mkO()); }
  function s5K() external pure returns (uint256){ return mkO().k; }

  function mkBag() internal pure returns (Bag memory b){ uint256[] memory t0=new uint256[](2); t0[0]=1;t0[1]=2; uint256[] memory t1=new uint256[](1); t1[0]=9; Item[] memory a=new Item[](2); a[0]=Item(t0,5);a[1]=Item(t1,6); b=Bag(7,a); }
  function dpEnc() external pure returns (bytes memory){ return abi.encode(mkBag()); }
  function dpTag() external pure returns (uint256){ return mkBag().items[0].tags[1]; }

  function mkBoth() internal pure returns (Both memory b){ Pt[] memory ap=new Pt[](2); ap[0]=Pt(1,2);ap[1]=Pt(3,4); Line[] memory al=new Line[](1); al[0]=Line("x",5); b=Both(ap,al); }
  function ntEnc() external pure returns (bytes memory){ return abi.encode(mkBoth()); }
  function ntPt() external pure returns (uint256){ return mkBoth().pts[1].y; }
  function ntLn() external pure returns (string memory){ return mkBoth().lines[0].note; }

  function mkOuter() internal pure returns (Outer memory o){ Line[] memory al=new Line[](2); al[0]=Line("a",1);al[1]=Line("b",2); Inner memory inr=Inner("nm", al); o=Outer(7, inr); }
  function ndEnc() external pure returns (bytes memory){ return abi.encode(mkOuter()); }
  function ndNote() external pure returns (string memory){ return mkOuter().inner.lines[1].note; }

  function vElem() external pure returns (uint256){ uint256[] memory a=new uint256[](3); a[0]=10;a[1]=20;a[2]=30; return Order2(9,a).ns[1]; }
}`;

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(So, 'C').creation);
  });
  const cmp = async (data: string, label: string) => {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
    return j;
  };

  it('KIND A static-struct element: field read (const + runtime idx), id, length, byte-identical + values', async () => {
    const r1 = await cmp('0x' + sel('aReadY(uint256)') + pad32(1n), 'aReadY[1]');
    expect(decodeU256(r1.returnHex)).toBe(6n);
    const r0 = await cmp('0x' + sel('aReadY(uint256)') + pad32(0n), 'aReadY[0]');
    expect(decodeU256(r0.returnHex)).toBe(4n);
    const rx = await cmp('0x' + sel('aReadX0()'), 'aReadX0');
    expect(decodeU256(rx.returnHex)).toBe(3n);
    const id = await cmp('0x' + sel('aId()'), 'aId');
    expect(decodeU256(id.returnHex)).toBe(9n);
    const len = await cmp('0x' + sel('aLen()'), 'aLen');
    expect(decodeU256(len.returnHex)).toBe(2n);
  });
  it('KIND A abi.encode(whole) + return whole + empty + single byte-identical', async () => {
    await cmp('0x' + sel('aEnc()'), 'aEnc');
    await cmp('0x' + sel('aWhole()'), 'aWhole');
    const el = await cmp('0x' + sel('aEmptyLen()'), 'aEmptyLen');
    expect(decodeU256(el.returnHex)).toBe(0n);
    await cmp('0x' + sel('aEmptyEnc()'), 'aEmptyEnc');
    const s1 = await cmp('0x' + sel('aSingle()'), 'aSingle');
    expect(decodeU256(s1.returnHex)).toBe(8n);
  });
  it('KIND A const-OOB p.pts[5].y is a runtime Panic 0x32 (both)', async () => {
    const r = await cmp('0x' + sel('aOOB()'), 'aOOB');
    expect(r.success).toBe(false);
    expect(r.returnHex).toBe(PANIC32);
  });

  it('KIND B dynamic-struct element: note/qty (const + runtime idx), id, length byte-identical + values', async () => {
    const n1 = await cmp('0x' + sel('bNote(uint256)') + pad32(1n), 'bNote[1]');
    expect(decodeString(n1.returnHex)).toBe('world');
    const n0 = await cmp('0x' + sel('bNote(uint256)') + pad32(0n), 'bNote[0]');
    expect(decodeString(n0.returnHex)).toBe('hello');
    const q1 = await cmp('0x' + sel('bQty(uint256)') + pad32(1n), 'bQty[1]');
    expect(decodeU256(q1.returnHex)).toBe(7n);
    const id = await cmp('0x' + sel('bId()'), 'bId');
    expect(decodeU256(id.returnHex)).toBe(3n);
    const len = await cmp('0x' + sel('bLen()'), 'bLen');
    expect(decodeU256(len.returnHex)).toBe(2n);
  });
  it('KIND B abi.encode(o) + return o + abi.encode(o.lines) + return o.lines byte-identical', async () => {
    await cmp('0x' + sel('bEncO()'), 'bEncO');
    await cmp('0x' + sel('bRetO()'), 'bRetO');
    const el = await cmp('0x' + sel('bEncLines()'), 'bEncLines');
    // abi.encode(Line[]) sole-return: [0x20][len=2][off0][off1] then element tuples
    expect(decodeU256('0x' + el.returnHex.slice(2, 66))).toBe(0x20n);
    await cmp('0x' + sel('bRetLines()'), 'bRetLines');
  });
  it('KIND B >32-byte note + 3 elements + empty field byte-identical', async () => {
    await cmp('0x' + sel('bBig()'), 'bBig');
    await cmp('0x' + sel('bThree()'), 'bThree');
    await cmp('0x' + sel('bEmptyEnc()'), 'bEmptyEnc');
    await cmp('0x' + sel('bEmptyLines()'), 'bEmptyLines');
  });
  it('KIND B const-OOB o.lines[5].qty is a runtime Panic 0x32 (both)', async () => {
    const r = await cmp('0x' + sel('bOOB()'), 'bOOB');
    expect(r.success).toBe(false);
    expect(r.returnHex).toBe(PANIC32);
  });

  it('S5-A form O{xs:St[];k}: return o.xs / abi.encode(o.xs) / whole / o.k byte-identical', async () => {
    await cmp('0x' + sel('s5RetXs()'), 's5RetXs');
    await cmp('0x' + sel('s5EncXs()'), 's5EncXs');
    await cmp('0x' + sel('s5EncO()'), 's5EncO');
    const k = await cmp('0x' + sel('s5K()'), 's5K');
    expect(decodeU256(k.returnHex)).toBe(99n);
  });
  it('element struct with a u256[] field (Bag{items:Item[]}, Item{tags:u256[];qty}) byte-identical', async () => {
    await cmp('0x' + sel('dpEnc()'), 'dpEnc');
    const t = await cmp('0x' + sel('dpTag()'), 'dpTag');
    expect(decodeU256(t.returnHex)).toBe(2n);
  });
  it('nested outer with TWO struct-element-array fields (Both{pts:Pt[];lines:Line[]}) byte-identical', async () => {
    await cmp('0x' + sel('ntEnc()'), 'ntEnc');
    const p = await cmp('0x' + sel('ntPt()'), 'ntPt');
    expect(decodeU256(p.returnHex)).toBe(4n);
    const l = await cmp('0x' + sel('ntLn()'), 'ntLn');
    expect(decodeString(l.returnHex)).toBe('x');
  });
  it('nested dyn-struct field carrying a struct-element array (Outer{inner:Inner{lines:Line[]}}) byte-identical', async () => {
    await cmp('0x' + sel('ndEnc()'), 'ndEnc');
    const n = await cmp('0x' + sel('ndNote()'), 'ndNote');
    expect(decodeString(n.returnHex)).toBe('b');
  });

  it('CONTROL: value-element dyn-array field Order2{ns:u256[]} stays byte-identical (pre-existing path)', async () => {
    const r = await cmp('0x' + sel('vElem()'), 'vElem');
    expect(decodeU256(r.returnHex)).toBe(20n);
  });
  it('CONTROL: literal-direct-to-field Poly(9,[Pt,Pt]) is a clean JETH226 reject (solc rejects Pt[2]->Pt[])', () => {
    const src = `type Pt = { x: u256; y: u256 };
type Poly = { id: u256; pts: Pt[] };
class C { get f(): External<u256> { let p: Poly = Poly(9n, [Pt(3n,4n),Pt(5n,6n)]); return p.pts[1n].y; } }`;
    expect(codes(src)).toContain('JETH226');
  });
});
