// Four small OR lifts from the 2026-07-12 catalogue live audit (top cluster):
//   BYTES-CONST        - a `bytes`-typed @constant (JETH050 whitelist + constByteString folding)
//   PAREN-CALLEE       - a parenthesized DIRECT callee `(this.f)(v)` / `(C.f)(v)` / `(L.f)(v)`
//   DEFAULT-ARG-CONST  - a value-type @constant as an internal-fn default param `b: u256 = C.K`
//   GET-PROPERTY-READ  - an argless `get x()` accessor read as a property `this.x` == the call `this.x()`
// Each is verified byte-identical to solc 0.8.35 (or to its own call/literal twin where solc has no
// spelling), and the safety negatives (a state var / immutable default, a param-getter property-read,
// a struct constant) still reject.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e;
  }
};

describe('BYTES-CONST: a bytes-typed @constant', () => {
  it('the string-literal and bytes("...") spellings compile and read byte-identically to solc', async () => {
    for (const init of ['"hello world"', 'bytes("hello world")', 'abi.encodePacked("hello", " ", "world")']) {
      const j = `class C { static B: bytes = ${init}; get f(): External<bytes> { return C.B; } }`;
      expect(codes(j)).toEqual([]);
      const h = await Harness.create();
      const aj = await h.deploy(bc(j));
      const as = await h.deploy(compileSolidity(SPDX + `contract C { bytes constant B = "hello world"; function f() external pure returns(bytes memory){ return B; } }`, 'C').creation);
      const rj = await h.call(aj, sel('f()')), rs = await h.call(as, sel('f()'));
      expect(rj.success).toBe(true);
      expect(rj.returnHex).toBe(rs.returnHex);
    }
  });
  it('a bytes constant hashes byte-identically to solc; empty bytes compiles', async () => {
    const j = `class C { static SALT: bytes = "SALT"; get h(): External<bytes32> { return keccak256(C.SALT); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(bc(j));
    const as = await h.deploy(compileSolidity(SPDX + `contract C { bytes constant SALT = "SALT"; function h() external pure returns(bytes32){ return keccak256(SALT); } }`, 'C').creation);
    expect((await h.call(aj, sel('h()'))).returnHex).toBe((await h.call(as, sel('h()'))).returnHex);
    expect(codes(`class C { static B: bytes = ""; get f(): External<bytes> { return C.B; } }`)).toEqual([]);
  });
  it('NEGATIVES: a non-literal init rejects; a struct/array constant stays JETH050', () => {
    expect(codes(`class C { s: bytes; static B: bytes = this.s; get f(): External<bytes> { return C.B; } }`)).toContain('JETH048');
    expect(codes(`type P = { a: u256 };\nclass C { static B: P = P(1n); get f(): External<u256> { return C.B.a; } }`)).toContain('JETH050');
  });
});

describe('PAREN-CALLEE: a parenthesized direct callee', () => {
  it('(this.f)(v) / (C.f)(v) / (L.f)(v) / ((this.f))(v) all compile and run byte-identical to solc', async () => {
    const j = `class C { dbl(x: u256): u256 { return x + x; } get f(): External<u256> { return (this.dbl)(4n); } }`;
    const s = `contract C { function dbl(uint256 x) internal pure returns(uint256){ return x+x; } function f() external pure returns(uint256){ return (dbl)(4); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(bc(j));
    const as = await h.deploy(compileSolidity(SPDX + s, 'C').creation);
    expect((await h.call(aj, sel('f()'))).returnHex).toBe((await h.call(as, sel('f()'))).returnHex);
    expect(codes(`class C { static dbl(x: u256): u256 { return x + x; } get f(): External<u256> { return (C.dbl)(4n); } }`)).toEqual([]);
    expect(codes(`static class L { dbl(x: u256): u256 { return x + x; } }\nclass C { get f(): External<u256> { return (L.dbl)(4n); } }`)).toEqual([]);
    expect(codes(`class C { dbl(x: u256): u256 { return x + x; } get f(): External<u256> { return ((this.dbl))(4n); } }`)).toEqual([]);
  });
  it('NEGATIVES (solc rejects these): an OVERLOADED parenthesized callee and (payable)(x) stay JETH074', () => {
    // parenthesizing an overloaded name forces a value lookup with no unique function type - solc:
    // "No matching declaration found after variable lookup" / "Member not unique". The peel must NOT fire.
    expect(codes(`class C { g(x: u256): u256 { return x; } g(x: u256, y: u256): u256 { return x+y; } get f(): External<u256> { return (this.g)(5n); } }`)).toContain('JETH074');
    expect(codes(`class C { static g(x: u256): u256 { return x; } static g(x: u256, y: u256): u256 { return x+y; } get f(): External<u256> { return (C.g)(5n); } }`)).toContain('JETH074');
    expect(codes(`static class L { g(x: u256): u256 { return x; } g(x: u256, y: u256): u256 { return x+y; } }\nclass C { get f(): External<u256> { return (L.g)(5n); } }`)).toContain('JETH074');
    expect(codes(`class C { g(x: u256): u256 { return x; } g(x: u256, y: u256): u256 { return x+y; } get f(): External<u256> { return ((this.g))(5n); } }`)).toContain('JETH074');
    // `payable` is a mutability keyword, not a parenthesizable production (solc: ParserError).
    expect(codes(`class C { get f(x: address): External<address> { return (payable)(x); } }`)).toContain('JETH074');
    // an elementary-type cast in parens IS pure grouping - solc accepts it, byte-identical to the bare cast.
    expect(bc(`class C { get f(x: u256): External<u8> { return (u8)(x); } }`)).toBe(bc(`class C { get f(x: u256): External<u8> { return u8(x); } }`));
  });
  it('a funcref-ternary callee through parens still dispatches correctly (not swallowed by the peel)', async () => {
    const j = `class C { inc(x: u256): u256 { return x+1n; } dec(x: u256): u256 { return x-1n; } get f(cnd: bool): External<u256> { return (cnd ? this.inc : this.dec)(10n); } }`;
    const s = `contract C { function inc(uint256 x) internal pure returns(uint256){return x+1;} function dec(uint256 x) internal pure returns(uint256){return x-1;} function f(bool cnd) external pure returns(uint256){ return (cnd ? inc : dec)(10); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(bc(j));
    const as = await h.deploy(compileSolidity(SPDX + s, 'C').creation);
    for (const c of [1, 0]) expect((await h.call(aj, sel('f(bool)') + W(c))).returnHex).toBe((await h.call(as, sel('f(bool)') + W(c))).returnHex);
  });
});

describe('DEFAULT-ARG-CONST: a value-type constant as a default param', () => {
  it('b: u256 = C.K is byte-identical to the literal-default twin and fills/overrides like solc', async () => {
    const j = `class C {
      static K: u256 = 7n;
      add(a: u256, b: u256 = C.K): u256 { return a + b; }
      get useDefault(): External<u256> { return this.add(10n); }
      get useProvided(): External<u256> { return this.add(10n, 100n); }
    }`;
    expect(bc(j)).toBe(bc(j.replace('b: u256 = C.K', 'b: u256 = 7n')));
    const h = await Harness.create();
    const aj = await h.deploy(bc(j));
    const as = await h.deploy(compileSolidity(SPDX + `contract C { uint256 constant K = 7; function add(uint256 a, uint256 b) internal pure returns(uint256){ return a+b; } function useDefault() external pure returns(uint256){ return add(10, K); } function useProvided() external pure returns(uint256){ return add(10, 100); } }`, 'C').creation);
    for (const g of ['useDefault()', 'useProvided()']) expect((await h.call(aj, sel(g))).returnHex).toBe((await h.call(as, sel(g))).returnHex);
  });
  it('address/bytesN/bool/enum constant defaults compile; a state var or immutable default still rejects', () => {
    expect(codes(`class C { static A: address = address(7n); f(x: address = C.A): address { return x; } get g(): External<address> { return this.f(); } }`)).toEqual([]);
    expect(codes(`class C { static B: bytes4 = bytes4(0x11223344n); f(x: bytes4 = C.B): bytes4 { return x; } get g(): External<bytes4> { return this.f(); } }`)).toEqual([]);
    expect(codes(`enum Color { Red, Blue }\nclass C { static D: Color = Color.Blue; f(x: Color = C.D): Color { return x; } get g(): External<Color> { return this.f(); } }`)).toEqual([]);
    // a STATE var default would be a caller-scope SLOAD - must stay JETH250 (a default must be a constant)
    expect(codes(`class C { s: u256; f(a: u256, b: u256 = this.s): u256 { return a+b; } get g(): External<u256> { return this.f(1n); } }`)).toContain('JETH250');
    // an immutable is a code read, not a slot-free constant - stays JETH250
    expect(codes(`class C { static M: u256; constructor(){ this.M = 5n; } f(a: u256, b: u256 = C.M): u256 { return a+b; } get g(): External<u256> { return this.f(1n); } }`)).toContain('JETH250');
  });
});

describe('GET-PROPERTY-READ: an argless get accessor read as a property', () => {
  it('this.x (property) is byte-identical to this.x() (call), same-class and inherited', async () => {
    const prop = `class C { s: u256; setX(v: u256): External<void> { this.s = v; } get val(): u256 { return this.s + 1n; } get f(): External<u256> { return this.val; } }`;
    const call = prop.replace('return this.val;', 'return this.val();');
    expect(bc(prop)).toBe(bc(call));
    const h = await Harness.create();
    const a = await h.deploy(bc(prop));
    await h.call(a, sel('setX(uint256)') + W(41));
    expect(BigInt((await h.call(a, sel('f()'))).returnHex)).toBe(42n);
    // inherited getter read as a property from the derived contract
    const inh = `abstract class B { s: u256; get val(): u256 { return this.s; } }\nclass C extends B { setY(v: u256): External<void> { this.s = v; } get f(): External<u256> { return this.val + 5n; } }`;
    const a2 = await h.deploy(bc(inh));
    await h.call(a2, sel('setY(uint256)') + W(100));
    expect(BigInt((await h.call(a2, sel('f()'))).returnHex)).toBe(105n);
  });
  it('NEGATIVES: a getter WITH params, a plain method, and an unknown name all stay JETH065', () => {
    expect(codes(`class C { m: mapping<address,u256>; get bal(o: address): u256 { return this.m[o]; } get f(): External<u256> { return this.bal; } }`)).toContain('JETH065');
    expect(codes(`class C { helper(): u256 { return 7n; } get f(): External<u256> { return this.helper; } }`)).toContain('JETH065');
    expect(codes(`class C { get f(): External<u256> { return this.nope; } }`)).toContain('JETH065');
  });
});
