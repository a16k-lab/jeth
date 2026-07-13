// The 2026-07-14 "lift all liftable ORs" campaign. Each row is byte-identical to solc 0.8.35 (or to its
// ctor/call twin where solc has no direct spelling) with the negatives that must still reject pinned.
// The interface-chain rows (IFACE-CHAIN-REDECLARE / IFACE-CHAIN-TIGHTEN) live in
// native-interface-extends-interface.test.ts + native-interface-overloads.test.ts.
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

describe('STRUCT-FIELD-LENGTH: a struct field named length shadows .length (solc parity)', () => {
  it('reads the field, byte-identical to solc; the real .length builtin is unaffected', async () => {
    const h = await Harness.create();
    const j = `type P = { length: u256; other: u256 };\nclass C { get f(): External<u256> { let p: P = P(7n, 9n); return p.length; } }`;
    expect(codes(j)).toEqual([]);
    const aj = await h.deploy(bc(j));
    const as = await h.deploy(compileSolidity(SPDX + `contract C { struct P { uint256 length; uint256 other; } function f() external pure returns(uint256){ P memory p = P(7,9); return p.length; } }`, 'C').creation);
    expect((await h.call(aj, sel('f()'))).returnHex).toBe((await h.call(as, sel('f()'))).returnHex);
    expect(codes(`class C { xs: u256[]; get f(): External<u256> { return this.xs.length; } }`)).toEqual([]); // real array .length
    expect(codes(`type P = { length: u256 };\nclass C { p: P; setp(a: u256): External<void> { this.p = P(a); } get f(): External<u256> { return this.p.length; } }`)).toEqual([]); // storage
  });
});

describe('LIB-EVENT-QUALIFIED: emit(L.E(a)) from a contract', () => {
  it('emits the library event byte-identically; shadow/unknown reject', async () => {
    const j = `static class L { E: event<{ a: u256 }>; }\nclass C { fire(a: u256): External<void> { emit(L.E(a)); } }`;
    expect(codes(j)).toEqual([]);
    const h = await Harness.create();
    const aj = await h.deploy(bc(j));
    const as = await h.deploy(compileSolidity(SPDX + `library L { event E(uint256 a); }\ncontract C { function fire(uint256 a) external { emit L.E(a); } }`, 'C').creation);
    const [ej, es] = [await h.call(aj, sel('fire(uint256)') + W(7)), await h.call(as, sel('fire(uint256)') + W(7))];
    expect(JSON.stringify(ej.logs)).toBe(JSON.stringify(es.logs));
    expect(codes(`static class L { E: event<{ a: u256 }>; }\nclass C { fire(L: u256): External<void> { emit(L.E(L)); } }`).length).toBeGreaterThan(0); // shadowed L
    expect(codes(`static class L { m(): u256 { return 1n; } }\nclass C { fire(a: u256): External<void> { emit(L.E(a)); } }`).length).toBeGreaterThan(0); // unknown event
  });
});

describe('FIELD-INIT-EXPR / FIELD-INIT-NS: non-literal + namespaced string/bytes field initializers', () => {
  it('a non-this string/bytes initializer (template, cast) and a @storage(ns) literal init are byte-identical', () => {
    const tmpl = 'class C { s: string = `x${"y"}z`; get f(): External<string> { return this.s; } }';
    const tmplTwin = 'class C { s: string; constructor() { this.s = `x${"y"}z`; } get f(): External<string> { return this.s; } }';
    expect(codes(tmpl)).toEqual([]);
    expect(bc(tmpl)).toBe(bc(tmplTwin));
    expect(codes(`class C { b: bytes = bytes("a"); get f(): External<bytes> { return this.b; } }`)).toEqual([]);
    const ns = `@storage('my.ns')\nclass C { s: string = "x"; get f(): External<string> { return this.s; } }`;
    expect(codes(ns)).toEqual([]);
    expect(bc(ns)).toBe(bc(`@storage('my.ns')\nclass C { s: string; constructor() { this.s = "x"; } get f(): External<string> { return this.s; } }`));
  });
  it('RESIDUALS stay JETH048: a this-reading init, a value-type non-fold init, a state-var-reading init', () => {
    expect(codes(`class C { a: u256; s: string = this.a == 0n ? "x" : "y"; get f(): External<string> { return this.s; } }`)).toContain('JETH048');
    expect(codes(`class C { x: u256 = block.timestamp; get f(): External<u256> { return this.x; } }`)).toContain('JETH048');
    expect(codes(`class C { a: u256 = 5n; b: u256 = this.a + 1n; get f(): External<u256> { return this.b; } }`)).toContain('JETH048');
  });
});

describe('RECEIVE-INTERNAL-CALL: receive()/fallback() may call internal helpers', () => {
  it('receive calling a state-writing helper is byte-identical to solc; unknown fn still rejects', async () => {
    const j = `class C { total: u256; add(x: u256): u256 { return this.total + x; } receive() { this.total = this.add(msg.value); } get read(): External<u256> { return this.total; } }`;
    expect(codes(j)).toEqual([]);
    const h = await Harness.create();
    const aj = await h.deploy(bc(j));
    const as = await h.deploy(compileSolidity(SPDX + `contract C { uint256 total; function add(uint256 x) internal view returns(uint256){ return total + x; } receive() external payable { total = add(msg.value); } function read() external view returns(uint256){ return total; } }`, 'C').creation);
    await h.call(aj, '0x', { value: 5n }); await h.call(as, '0x', { value: 5n });
    expect((await h.call(aj, sel('read()'))).returnHex).toBe((await h.call(as, sel('read()'))).returnHex);
    // fallback -> helper, a receive->a->b chain, and a fallback(bytes) -> helper-returning-bytes all compile
    expect(codes(`class C { n: u256; bump(): u256 { this.n = this.n + 1n; return this.n; } fallback() { this.bump(); } get read(): External<u256> { return this.n; } }`)).toEqual([]);
    expect(codes(`class C { n: u256; b(x: u256): u256 { return x + 1n; } a(x: u256): u256 { return this.b(x) + 1n; } receive() { this.n = this.a(msg.value); } get read(): External<u256> { return this.n; } }`)).toEqual([]);
    expect(codes(`class C { wrap(b: bytes): bytes { return b; } fallback(input: bytes): bytes { return this.wrap(input); } }`)).toEqual([]);
    expect(codes(`class C { receive() { this.nope(); } }`)).toContain('JETH074'); // unknown fn still rejects
  });
});

describe('JETH434-DISAMBIGUABLE: named-arg emit of an overloaded event', () => {
  it('a unique key set selects the overload (byte-identical); ambiguity + value-mismatch reject', async () => {
    const j = `class C { E: event<{a: u256}>; E: event<{b: address; c: u256}>; f(): External<void> { emit(this.E({a: 5n})); } g(w: address): External<void> { emit(this.E({c: 7n, b: w})); } }`;
    expect(codes(j)).toEqual([]);
    const h = await Harness.create();
    const aj = await h.deploy(bc(j));
    const as = await h.deploy(compileSolidity(SPDX + `contract C { event E(uint256 a); event E(address b, uint256 c); function f() external { emit E({a: 5}); } function g(address w) external { emit E({c: 7, b: w}); } }`, 'C').creation);
    expect(JSON.stringify((await h.call(aj, sel('f()'))).logs)).toBe(JSON.stringify((await h.call(as, sel('f()'))).logs));
    const w = W(BigInt('0x2222222222222222222222222222222222222222'));
    expect(JSON.stringify((await h.call(aj, sel('g(address)') + w)).logs)).toBe(JSON.stringify((await h.call(as, sel('g(address)') + w)).logs));
    // same key set across two overloads -> JETH434; a value that does not fit the chosen overload rejects
    expect(codes(`class C { E: event<{a: u256; b: address}>; E: event<{a: address; b: u256}>; f(w: address): External<void> { emit(this.E({a: 1n, b: w})); } }`)).toContain('JETH434');
    expect(codes(`class C { E: event<{a: address; b: u256}>; E: event<{c: u256; d: address}>; f(w: address): External<void> { emit(this.E({a: 5n, b: w})); } }`).length).toBeGreaterThan(0);
  });
});

describe('GET-EXTLIB-VIEW: a get accessor may call a pure/view external-lib fn', () => {
  it('a get over a pure ext-lib fn accepts; a get over an emit-writer ext-lib fn stays JETH043', () => {
    expect(codes(`static class L { sq(a: u256): External<u256> { return a * a; } }\nclass C { get f(a: u256): External<u256> { return L.sq(a); } }`)).toEqual([]);
    expect(codes(`static class L { E: event<{a: u256}>; go(a: u256): External<u256> { emit(E(a)); return a; } }\nclass C { get f(a: u256): External<u256> { return L.go(a); } }`)).toContain('JETH043');
  });
});
