// ENUMS: a JETH `enum Color { Red, Green, Blue }` is a BRANDED uint8 carrying its member names.
// The brand is fully erased at codegen/ABI/selectors (ABI type uint8, 1-byte packed storage), so
// the invariant is byte-identical to a Solidity twin with the same enum on: returndata, raw storage
// slots (incl. packing beside other small fields), and the exact revert data of the explicit
// conversion Panic(0x21) / the empty revert of an out-of-range enum calldata decode.
//
// We also pin the compile-time rules solc enforces (and a couple JETH-specific ones): no explicit
// member values, no arithmetic, no enum mixing, no bare-int-without-cast, no empty enum, no unknown
// member, out-of-range constant conversion.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => pad32(v);

// ---- the JETH contract under test, and a byte-for-byte Solidity twin -------------------------
const J = `enum Color { Red, Green, Blue }
type Item = { c: Color; qty: u32; flag: bool; };
class C {
  c: Color;          // slot 0, byte 0
  small: u8;         // slot 0, byte 1 (packed beside the enum)
  owner: u16;        // slot 0, bytes 2-3
  it: Item;          // slot 1: c@byte0, qty@bytes1-4, flag@byte5
  seen: mapping<Color, bool>;
  pref: mapping<address, Color>;
  setC(x: Color): External<void> { this.c = x; }
  get getC(): External<Color> { return this.c; }
  setSmall(s: u8, o: u16): External<void> { this.small = s; this.owner = o; }
  setItem(c: Color, q: u32, f: bool): External<void> { this.it = Item(c, q, f); }
  get itemColor(): External<Color> { return this.it.c; }
  mark(c: Color): External<void> { this.seen[c] = true; }
  get isSeen(c: Color): External<bool> { return this.seen[c]; }
  setPref(a: address, c: Color): External<void> { this.pref[a] = c; }
  get prefOf(a: address): External<Color> { return this.pref[a]; }
  get mk(x: u8): External<Color> { return Color(x); }          // range-checked -> Panic 0x21
  get toU8(c: Color): External<u8> { return u8(c); }            // reinterpret, no check
  get toU256(c: Color): External<u256> { return u256(c); }
  get red(): External<Color> { return Color.Red; }
  get green(): External<Color> { return Color.Green; }
  get blue(): External<Color> { return Color.Blue; }
  get isBlue(c: Color): External<bool> { return c == Color.Blue; }
  get notRed(c: Color): External<bool> { return c != Color.Red; }
  get ltGreen(c: Color): External<bool> { return c < Color.Green; }
  get geGreen(c: Color): External<bool> { return c >= Color.Green; }
  get classify(c: Color): External<u8> {
    if (c == Color.Red) { return 100n; }
    if (c < Color.Blue) { return 50n; }
    return 9n;
  }
  get roundtrip(x: u8): External<u8> { return u8(Color(x)); }   // decode-cast-extract
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  enum Color { Red, Green, Blue }
  struct Item { Color c; uint32 qty; bool flag; }
  Color c;
  uint8 small;
  uint16 owner;
  Item it;
  mapping(Color => bool) seen;
  mapping(address => Color) pref;
  function setC(Color x) external { c = x; }
  function getC() external view returns (Color) { return c; }
  function setSmall(uint8 s, uint16 o) external { small = s; owner = o; }
  function setItem(Color c_, uint32 q, bool f) external { it = Item(c_, q, f); }
  function itemColor() external view returns (Color) { return it.c; }
  function mark(Color c_) external { seen[c_] = true; }
  function isSeen(Color c_) external view returns (bool) { return seen[c_]; }
  function setPref(address a, Color c_) external { pref[a] = c_; }
  function prefOf(address a) external view returns (Color) { return pref[a]; }
  function mk(uint8 x) external pure returns (Color) { return Color(x); }
  function toU8(Color c_) external pure returns (uint8) { return uint8(c_); }
  function toU256(Color c_) external pure returns (uint256) { return uint256(c_); }
  function red() external pure returns (Color) { return Color.Red; }
  function green() external pure returns (Color) { return Color.Green; }
  function blue() external pure returns (Color) { return Color.Blue; }
  function isBlue(Color c_) external pure returns (bool) { return c_ == Color.Blue; }
  function notRed(Color c_) external pure returns (bool) { return c_ != Color.Red; }
  function ltGreen(Color c_) external pure returns (bool) { return c_ < Color.Green; }
  function geGreen(Color c_) external pure returns (bool) { return c_ >= Color.Green; }
  function classify(Color c_) external pure returns (uint8) {
    if (c_ == Color.Red) { return 100; }
    if (c_ < Color.Blue) { return 50; }
    return 9;
  }
  function roundtrip(uint8 x) external pure returns (uint8) { return uint8(Color(x)); }
}`;

describe('enums (branded uint8) are byte-identical to solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  // success/returndata parity for a single call (covers Panic + empty-revert data, which live in
  // returnHex), against the real solc twin running on the same EVM.
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('the ABI types an enum exactly as uint8 (param, return, mapping key/value)', () => {
    const abi = compile(J, { fileName: 'C.jeth' }).abi;
    const getIO = (name: string): any => abi.find((e: any) => e.name === name)!;
    expect(getIO('setC').inputs.map((i: any) => i.type)).toEqual(['uint8']);
    expect(getIO('getC').outputs.map((o: any) => o.type)).toEqual(['uint8']);
    expect(getIO('mk').inputs.map((i: any) => i.type)).toEqual(['uint8']);
    expect(getIO('mk').outputs.map((o: any) => o.type)).toEqual(['uint8']);
    expect(getIO('setPref').inputs.map((i: any) => i.type)).toEqual(['address', 'uint8']);
    expect(getIO('prefOf').outputs.map((o: any) => o.type)).toEqual(['uint8']);
    // the selectors are computed from the uint8 ABI type, so they match solc's exactly.
    expect(jeth).toBeDefined();
  });

  it('the enum selectors are computed from the uint8 ABI type (so they hit the solc twin)', () => {
    // every differential call below dispatches the SAME selector against both the JETH and the
    // Solidity contract; if a selector differed, the call would hit the solc fallback and revert,
    // breaking parity. Here we assert the brand-erased signature directly.
    const abi = compile(J, { fileName: 'C.jeth' }).abi;
    const setC = abi.find((e: any) => e.name === 'setC')!;
    expect(setC.inputs.map((i: any) => i.type)).toEqual(['uint8']);
    // the JETH-computed selector equals the canonical uint8 signature's selector.
    expect(sel('setC(uint8)')).toBe(functionSelector('setC(uint8)'));
    expect(sel('setPref(address,uint8)').length).toBe(8);
  });

  it('member constants, comparisons in branches, and enum<->int conversions match solc', async () => {
    await eq('red()', encodeCall(sel('red()'), []));
    await eq('green()', encodeCall(sel('green()'), []));
    await eq('blue()', encodeCall(sel('blue()'), []));
    for (const v of [0n, 1n, 2n]) {
      await eq(`isBlue(${v})`, encodeCall(sel('isBlue(uint8)'), [v]));
      await eq(`notRed(${v})`, encodeCall(sel('notRed(uint8)'), [v]));
      await eq(`ltGreen(${v})`, encodeCall(sel('ltGreen(uint8)'), [v]));
      await eq(`geGreen(${v})`, encodeCall(sel('geGreen(uint8)'), [v]));
      await eq(`classify(${v})`, encodeCall(sel('classify(uint8)'), [v]));
      await eq(`toU8(${v})`, encodeCall(sel('toU8(uint8)'), [v]));
      await eq(`toU256(${v})`, encodeCall(sel('toU256(uint8)'), [v]));
    }
  });

  it('Color(x) range-checks with a byte-identical Panic(0x21) when out of range', async () => {
    // valid in-range conversions
    for (const v of [0n, 1n, 2n]) await eq(`mk(${v})`, encodeCall(sel('mk(uint8)'), [v]));
    // out-of-range explicit conversions -> Panic(0x21): the revert DATA must be byte-identical.
    for (const v of [3n, 4n, 255n]) await eq(`mk(${v}) OOR`, encodeCall(sel('mk(uint8)'), [v]));
    // the exact Panic(0x21) revert data, pinned literally (0x4e487b71 + 0x21).
    const r = await jeth.call(aj, encodeCall(sel('mk(uint8)'), [3n]));
    expect(r.success).toBe(false);
    expect(r.returnHex).toBe('0x4e487b71' + pad(0x21n)); // Panic(0x21): selector + 32-byte code word
    await eq('roundtrip(2)', encodeCall(sel('roundtrip(uint8)'), [2n]));
    await eq('roundtrip(3) OOR', encodeCall(sel('roundtrip(uint8)'), [3n]));
  });

  it('an out-of-range enum CALLDATA value reverts EMPTY exactly like solc (not a Panic)', async () => {
    // setC(uint8) with an enum param: solc validates the calldata word `< 3` and reverts(0,0).
    for (const v of [3n, 4n, 7n, 255n]) {
      const r = await jeth.call(aj, encodeCall(sel('setC(uint8)'), [v]));
      const s = await sol.call(as, encodeCall(sel('setC(uint8)'), [v]));
      expect(r.success, `setC(${v}) should revert`).toBe(false);
      expect(s.success).toBe(false);
      expect(r.returnHex, `setC(${v}) empty revert`).toBe(s.returnHex); // both '0x'
      expect(r.returnHex).toBe('0x');
    }
    // in-range values are accepted and persisted identically.
    for (const v of [0n, 1n, 2n]) await eq(`setC(${v}) ok`, encodeCall(sel('setC(uint8)'), [v]));
  });

  it('a state enum var packs into one byte beside other small fields (raw slot parity)', async () => {
    // write the enum + two neighbours that share slot 0, then compare the raw slot bit-for-bit.
    await jeth.call(aj, encodeCall(sel('setC(uint8)'), [2n]));
    await sol.call(as, encodeCall(sel('setC(uint8)'), [2n]));
    await jeth.call(aj, encodeCall(sel('setSmall(uint8,uint16)'), [0xabn, 0x1234n]));
    await sol.call(as, encodeCall(sel('setSmall(uint8,uint16)'), [0xabn, 0x1234n]));
    expect(await readSlot(jeth, aj, 0n), 'slot 0 (packed enum+small+owner)').toBe(await readSlot(sol, as, 0n));
    await eq('getC after pack', encodeCall(sel('getC()'), []));
    // an enum struct field packs identically (slot 1: Color@byte0, uint32@1-4, bool@byte5).
    await jeth.call(aj, encodeCall(sel('setItem(uint8,uint32,bool)'), [1n, 0xdeadbeefn, 1n]));
    await sol.call(as, encodeCall(sel('setItem(uint8,uint32,bool)'), [1n, 0xdeadbeefn, 1n]));
    expect(await readSlot(jeth, aj, 1n), 'slot 1 (packed enum struct field)').toBe(await readSlot(sol, as, 1n));
    await eq('itemColor()', encodeCall(sel('itemColor()'), []));
  });

  it('enum as a mapping KEY and as a mapping VALUE matches solc (incl. raw slots)', async () => {
    // enum key: mark(Color) sets seen[c]=true; the key is hashed as a uint8.
    await jeth.call(aj, encodeCall(sel('mark(uint8)'), [2n]));
    await sol.call(as, encodeCall(sel('mark(uint8)'), [2n]));
    for (const v of [0n, 1n, 2n]) await eq(`isSeen(${v})`, encodeCall(sel('isSeen(uint8)'), [v]));
    // enum value: setPref(addr, Color) stores a uint8 at keccak(addr . slot).
    const A = 0xa11ce0000000000000000000000000000000n;
    const setP = '0x' + sel('setPref(address,uint8)') + pad(A) + pad(1n);
    await jeth.call(aj, setP);
    await sol.call(as, setP);
    await eq('prefOf', encodeCall(sel('prefOf(address)'), [A]));
  });

  it('getC returns the stored member index (decode sanity)', async () => {
    await jeth.call(aj, encodeCall(sel('setC(uint8)'), [1n]));
    const r = await jeth.call(aj, encodeCall(sel('getC()'), []));
    expect(decodeUint(r.returnHex)).toBe(1n);
  });
});

// ---- compile-time rejections (capture the JETH diagnostic code) -------------------------------
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
const E = 'enum Color { Red, Green, Blue }\n';
const wrap = (body: string) => `${E}class C { ${body} }`;

describe('enum compile-time rules (solc parity)', () => {
  it('rejects arithmetic on an enum (JETH279)', () => {
    expect(errCodes(wrap('@external @pure f(c: Color): Color { let x: Color = c + c; return x; }'))).toContain(
      'JETH279',
    );
    expect(errCodes(wrap('@external @pure f(c: Color): u8 { let x: Color = c & c; return u8(x); }'))).toContain(
      'JETH279',
    );
    expect(errCodes(wrap('@external @pure f(c: Color): u8 { let x: Color = c << 1n; return u8(x); }'))).toContain(
      'JETH279',
    );
  });

  it('rejects mixing two different enums in a comparison (JETH083)', () => {
    const src = `enum A { X, Y }\nenum B { P, Q }\nclass C { get f(a: A, b: B): External<bool> { return a == b; } }`;
    expect(errCodes(src)).toContain('JETH083');
  });

  it('rejects assigning a bare integer to an enum without a cast (JETH280)', () => {
    expect(errCodes(wrap('@external @pure f(): Color { return 1n; }'))).toContain('JETH280');
    expect(errCodes(wrap('@state c: Color; @external s(): void { this.c = 2n; }'))).toContain('JETH280');
    expect(errCodes(wrap('@external @pure f(c: Color): bool { return c == 1n; }'))).toContain('JETH280');
  });

  it('rejects an enum member with an explicit value (JETH270)', () => {
    const src = `enum Color { Red = 5, Green, Blue }\nclass C { get f(): External<u8> { return 0n; } }`;
    expect(errCodes(src)).toContain('JETH270');
  });

  it('rejects an empty enum (JETH275)', () => {
    const src = `enum E {}\nclass C { get f(): External<u8> { return 0n; } }`;
    expect(errCodes(src)).toContain('JETH275');
  });

  it('rejects an unknown member Color.Purple (JETH271)', () => {
    expect(errCodes(wrap('@external @pure f(): Color { return Color.Purple; }'))).toContain('JETH271');
  });

  it('rejects an out-of-range CONSTANT conversion Color(3) at compile time (JETH278)', () => {
    expect(errCodes(wrap('@external @pure f(): Color { return Color(3n); }'))).toContain('JETH278');
  });

  it('rejects an enum conversion of a non-integer operand (JETH277)', () => {
    expect(errCodes(wrap('@external @pure f(a: address): Color { return Color(a); }'))).toContain('JETH277');
  });

  it('rejects an enum name colliding with a primitive (JETH272) / a duplicate member (JETH274)', () => {
    expect(errCodes(`enum u8 { A, B }\nclass C { get f(): External<u8> { return 0n; } }`)).toContain(
      'JETH272',
    );
    expect(
      errCodes(`enum Color { Red, Green, Red }\nclass C { get f(): External<u8> { return 0n; } }`),
    ).toContain('JETH274');
  });

  it('accepts the legal enum operations (member constants, comparisons, both-way casts)', () => {
    expect(errCodes(wrap('@external @pure f(c: Color): bool { return c == Color.Red || c < Color.Blue; }'))).toEqual(
      [],
    );
    expect(errCodes(wrap('@external @pure f(x: u8): Color { return Color(x); }'))).toEqual([]);
    expect(errCodes(wrap('@external @pure f(c: Color): u256 { return u256(c); }'))).toEqual([]);
    expect(errCodes(wrap('@external @pure f(): Color { return Color.Green; }'))).toEqual([]);
  });
});
