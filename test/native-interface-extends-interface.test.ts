// IFACE-EXTENDS-IFACE lift: `interface B extends A` is the native spelling of solc's
// `interface B is A`. B's callable surface is the UNION of the chain - an inherited method keeps its
// ORIGINAL declaration's canonical signature/selector and its STATICCALL-vs-CALL mutability marker -
// and a `class C extends B` owes the FULL union (JETH385 anchored on the original declaring
// interface). InterfaceDecl.methods stays OWN-methods-only (solc's resolution set for
// type(I).interfaceId and qualified I.m.selector, both of which EXCLUDE inherited methods -
// witnessed), while call-site lookup walks the parent chain and the C3 linearizer follows interface
// heritage (so `class C extends B, A` hits the same "linearization impossible" wall as solc).
// ORACLES:
//   1) BYTE-IDENTITY: every accepted chain shape compiles byte-identical to its REDECLARE workaround
//      (B declaring all of A's methods inline) - the in-compiler oracle;
//   2) solc 0.8.35 runtime differentials (run + decode, distinct seeds) on chain mirrors;
//   3) REJECT parity, each cell witnessed vs solc 0.8.35: forward-ref/cycle/non-interface parents
//      (JETH349), redeclare cells (JETH342/386/387), the distinct-declarer diamond (JETH430),
//      duplicate parent (JETH456), base order (JETH371), @override list membership/completeness
//      through chains (JETH415/381), and the pre-existing own-only selector surface (JETH074).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const A = (h: string | { toString(): string }) => pad32(BigInt(h.toString()));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

const CHAIN = `interface A { f(): View<u256>; }
  interface B extends A { g(): View<u256>; }`;
const FLAT = `interface A { f(): View<u256>; }
  interface B { f(): View<u256>; g(): View<u256>; }`;

describe('interface extends interface: byte-identity vs the redeclare workaround', () => {
  it('CONTROL: the pinned pre-fix shape (JETH349) now compiles - and only invalid parents still reject JETH349', () => {
    // pre-fix pin: this exact shape rejected ["JETH349", ...] at base 750d262.
    expect(codes(`${CHAIN} class C { get useB(t: address): External<u256> { return B(t).g(); } }`)).toEqual([]);
    expect(codes(`${CHAIN} class C { get useB(t: address): External<u256> { return B(t).f(); } }`)).toEqual([]);
    // JETH349 is retained for invalid parents only (all witnessed solc rejects).
    expect(codes(`interface B extends A { g(): View<u256>; } interface A { f(): View<u256>; }
      class C { get u(t: address): External<u256> { return B(t).g(); } }`)).toContain('JETH349'); // base below derived (solc: base must precede)
    expect(codes(`interface A extends B { f(): View<u256>; } interface B extends A { g(): View<u256>; }
      class C { get u(t: address): External<u256> { return B(t).g(); } }`)).toContain('JETH349'); // cycle (always has a forward edge)
    expect(codes(`abstract class K { } interface B extends K { g(): View<u256>; }
      class C { get u(t: address): External<u256> { return B(t).g(); } }`)).toContain('JETH349'); // class parent
    expect(codes(`type S = { a: u256 }; interface B extends S { g(): View<u256>; }
      class C { get u(t: address): External<u256> { return B(t).g(); } }`)).toContain('JETH349'); // struct-type parent
    expect(codes(`interface A { f(): View<u256>; } interface B extends A<u256> { g(): View<u256>; }
      class C { get u(t: address): External<u256> { return B(t).g(); } }`)).toContain('JETH349'); // type arguments
  });

  it('2-level chain: inherited-only and mixed inherited+own calls == the redeclare workaround', () => {
    expect(bc(`${CHAIN} class C { get u(t: address): External<u256> { return B(t).f(); } }`))
      .toBe(bc(`${FLAT} class C { get u(t: address): External<u256> { return B(t).f(); } }`));
    expect(bc(`${CHAIN} class C { get u(t: address): External<u256> { return B(t).f() + B(t).g(); } }`))
      .toBe(bc(`${FLAT} class C { get u(t: address): External<u256> { return B(t).f() + B(t).g(); } }`));
  });

  it('3-level chain and multi-parent == the redeclare workaround', () => {
    expect(bc(`interface A { f(): View<u256>; }
      interface B extends A { g(): View<u256>; }
      interface D extends B { h(): View<u256>; }
      class C { get u(t: address): External<u256> { return D(t).f() + D(t).g() + D(t).h(); } }`))
      .toBe(bc(`interface A { f(): View<u256>; }
      interface B extends A { g(): View<u256>; }
      interface D { f(): View<u256>; g(): View<u256>; h(): View<u256>; }
      class C { get u(t: address): External<u256> { return D(t).f() + D(t).g() + D(t).h(); } }`));
    expect(bc(`interface A { f(): View<u256>; }
      interface B { g(x: u256): u256; }
      interface D extends A, B { h(): Pure<u256>; }
      class C { get u(t: address): External<u256> { return D(t).f() + D(t).h(); } w(t: address, x: u256): External<u256> { return D(t).g(x); } }`))
      .toBe(bc(`interface A { f(): View<u256>; }
      interface B { g(x: u256): u256; }
      interface D { f(): View<u256>; g(x: u256): u256; h(): Pure<u256>; }
      class C { get u(t: address): External<u256> { return D(t).f() + D(t).h(); } w(t: address, x: u256): External<u256> { return D(t).g(x); } }`));
  });

  it('common-grandparent diamond (ONE declarer via two paths) accepts == workaround; distinct declarers reject JETH430', () => {
    expect(bc(`interface G { f(): View<u256>; }
      interface A extends G { a(): View<u256>; }
      interface B extends G { b(): View<u256>; }
      interface D extends A, B { h(): View<u256>; }
      class C { get u(t: address): External<u256> { return D(t).f() + D(t).a() + D(t).b() + D(t).h(); } }`))
      .toBe(bc(`interface G { f(): View<u256>; }
      interface A extends G { a(): View<u256>; }
      interface B extends G { b(): View<u256>; }
      interface D { f(): View<u256>; a(): View<u256>; b(): View<u256>; h(): View<u256>; }
      class C { get u(t: address): External<u256> { return D(t).f() + D(t).a() + D(t).b() + D(t).h(); } }`));
    // solc: "Derived contract must override function f" - and the required override(A, B) redeclare
    // is unspellable on a TS interface method, so the whole diamond-distinct-declarers cell rejects.
    expect(codes(`interface A { f(): View<u256>; } interface B { f(): View<u256>; }
      interface D extends A, B { h(): View<u256>; }
      class C { get u(t: address): External<u256> { return D(t).h(); } }`)).toContain('JETH430');
  });

  it('class-implements-union (extends-base consumer) == workaround; a missing inherited member is JETH385; base order matches solc C3', () => {
    expect(bc(`${CHAIN} class C extends B { s: u256; get f(): External<u256> { return this.s; } get g(): External<u256> { return this.s + 1n; } bump(): External<void> { this.s = this.s + 1n; } }`))
      .toBe(bc(`${FLAT} class C extends B { s: u256; get f(): External<u256> { return this.s; } get g(): External<u256> { return this.s + 1n; } bump(): External<void> { this.s = this.s + 1n; } }`));
    // abstract mid-class defers part of the union to the leaf (solc W26 accept)
    expect(bc(`interface A { f(): View<u256>; }
      interface B extends A { g(): u256; }
      abstract class Z extends B { s: u256; get f(): External<u256> { return this.s; } }
      class C extends Z { g(): External<u256> { this.s = this.s + 1n; return this.s; } }`))
      .toBe(bc(`interface A { f(): View<u256>; }
      interface B { f(): View<u256>; g(): u256; }
      abstract class Z extends B { s: u256; get f(): External<u256> { return this.s; } }
      class C extends Z { g(): External<u256> { this.s = this.s + 1n; return this.s; } }`));
    // the obligation travels the chain: implementing only B's own layer leaves A.f open -> JETH385
    expect(codes(`${CHAIN} class C extends B { get g(): External<u256> { return 2n; } }`)).toContain('JETH385');
    // C3 base order: extends A, B is legal (base first); extends B, A is solc's "Linearization impossible"
    expect(codes(`${CHAIN} class C extends A, B { get f(): External<u256> { return 1n; } get g(): External<u256> { return 2n; } }`)).toEqual([]);
    expect(codes(`${CHAIN} class C extends B, A { get f(): External<u256> { return 1n; } get g(): External<u256> { return 2n; } }`)).toContain('JETH371');
  });

  it('payable {value} and try/catch through the chain == workaround; empty child accepted', () => {
    expect(bc(`interface A { dep(): Payable<u256>; }
      interface B extends A { g(): View<u256>; }
      class C { u(t: address): Payable<u256> { return B(t, { value: msg.value }).dep(); } }`))
      .toBe(bc(`interface A { dep(): Payable<u256>; }
      interface B { dep(): Payable<u256>; g(): View<u256>; }
      class C { u(t: address): Payable<u256> { return B(t, { value: msg.value }).dep(); } }`));
    expect(bc(`${CHAIN} class C { get u(t: address): External<u256> { try { let r: u256 = B(t).f(); return r; } catch { return 999n; } } }`))
      .toBe(bc(`${FLAT} class C { get u(t: address): External<u256> { try { let r: u256 = B(t).f(); return r; } catch { return 999n; } } }`));
    expect(codes(`interface A { f(): View<u256>; } interface B extends A {}
      class C { get u(t: address): External<u256> { return B(t).f(); } }`)).toEqual([]);
  });

  it('type(I).interfaceId is OWN-methods-only through the chain (solc-witnessed) and B.f.selector stays own-only', () => {
    // the flat twin for interfaceId is an interface with ONLY the own layer (inherited f excluded)
    expect(bc(`${CHAIN} class C { get idB(): External<bytes4> { return type(B).interfaceId; } get idA(): External<bytes4> { return type(A).interfaceId; } }`))
      .toBe(bc(`interface A { f(): View<u256>; } interface Bx { g(): View<u256>; }
      class C { get idB(): External<bytes4> { return type(Bx).interfaceId; } get idA(): External<bytes4> { return type(A).interfaceId; } }`));
    // qualified selector: inherited f is NOT a member of type(B) (solc: "Member f not found") -> JETH074
    expect(codes(`${CHAIN} class C { get u(): External<bytes4> { return B.f.selector; } }`)).toContain('JETH074');
    expect(codes(`${CHAIN} class C { get u(): External<bytes4> { return B.g.selector; } }`)).toEqual([]);
  });

  it('redeclare/overload collision cells reject with exact codes (each witnessed vs solc)', () => {
    const CALL = `class C { get u(t: address): External<u256> { return 1n; } }`;
    // same params, different return: solc rejects ("Overriding function return types differ")
    expect(codes(`interface A { f(): View<u256>; } interface B extends A { f(): View<address>; } ${CALL}`)).toContain('JETH386');
    // same params, mutability change: LOOSEN (view -> nonpayable) rejects JETH387 (solc parity); TIGHTEN
    // (nonpayable -> view) is LIFTED (IFACE-CHAIN-TIGHTEN, solc accepts)
    expect(codes(`interface A { f(): View<u256>; } interface B extends A { f(): u256; } ${CALL}`)).toContain('JETH387');
    expect(codes(`interface A { f(): u256; } interface B extends A { f(): View<u256>; } ${CALL}`)).toEqual([]);
    // identical redeclare: LIFTED (IFACE-CHAIN-REDECLARE, solc accepts a redundant redeclare in a chain)
    expect(codes(`interface A { f(): View<u256>; } interface B extends A { f(): View<u256>; } ${CALL}`)).toEqual([]);
    // cross-chain overload: LIFTED (IFACE-OVERLOADS, 2026-07-12) - solc treats the chain as an
    // overload set, so a different-params redeclare now MERGES (see native-interface-overloads.test.ts)
    expect(codes(`interface A { f(): View<u256>; } interface B extends A { f(x: u256): View<u256>; } ${CALL}`)).toEqual([]);
    // duplicate parent (solc: linearization impossible) and unknown member through the chain
    expect(codes(`interface A { f(): View<u256>; } interface D extends A, A { h(): View<u256>; }
      class C { get u(t: address): External<u256> { return D(t).h(); } }`)).toContain('JETH456');
    expect(codes(`${CHAIN} class C { get u(t: address): External<u256> { return B(t).nope(); } }`)).toContain('JETH351');
  });

  it('@override interplay through the chain matches solc (bare/indirect-declarer/non-declaring/two-head list)', () => {
    const IMPL = `get f(): External<u256> { return 1n; } get g(): External<u256> { return 2n; }`;
    expect(codes(`${CHAIN} class C extends B { @override ${IMPL} }`)).toEqual([]); // W20c accept
    expect(codes(`${CHAIN} class C extends B { @override(A) ${IMPL} }`)).toEqual([]); // W20a accept (declaring interface, indirect)
    expect(codes(`${CHAIN} class C extends B { @override(B) ${IMPL} }`)).toContain('JETH415'); // W20b reject (B does not declare f)
    expect(codes(`interface A { f(): View<u256>; } interface B extends A { g(): View<u256>; } interface D extends B { h(): View<u256>; }
      class C extends D { @override(A) ${IMPL} get h(): External<u256> { return 3n; } }`)).toEqual([]); // W33 accept (3-level root)
    const TWO = `interface A { f(): View<u256>; } interface B extends A { g(): View<u256>; } interface K { f(): View<u256>; }`;
    expect(codes(`${TWO} class C extends B, K { ${IMPL} }`)).toContain('JETH381'); // W32a: needs (A, K)
    expect(codes(`${TWO} class C extends B, K { @override(A, K) ${IMPL} }`)).toEqual([]); // W32b accept
    expect(codes(`${TWO} class C extends B, K { @override(B, K) ${IMPL} }`)).toContain('JETH415'); // W32c reject
    // getter var implementing the inherited method through the chain (solc W17 accept)
    expect(codes(`${CHAIN} class C extends B { f: Visible<u256>; get g(): External<u256> { return this.f + 1n; } }`)).toEqual([]);
  });

  it('runtime differential vs solc `interface B is A` mirrors: chain calls through a two-layer target (distinct seeds)', async () => {
    const TGT = `contract T { uint256 v; constructor(uint256 s) { v = s; }
      function f() external view returns (uint256) { return v + 7; }
      function g() external view returns (uint256) { return v * 2; }
      function w(uint256 x) external returns (uint256) { v = v + x; return v; } }`;
    const J = `interface A { f(): View<u256>; w(x: u256): u256; }
      interface B extends A { g(): View<u256>; }
      class C {
        get r(t: address): External<u256> { return B(t).f() + B(t).g(); }
        wr(t: address, x: u256): External<u256> { return B(t).w(x); } }`;
    const S = `interface A { function f() external view returns (uint256); function w(uint256 x) external returns (uint256); }
      interface B is A { function g() external view returns (uint256); }
      contract C {
        function r(address t) external view returns (uint256) { return B(t).f() + B(t).g(); }
        function wr(address t, uint256 x) external returns (uint256) { return B(t).w(x); } }`;
    const h = await Harness.create();
    const seed = 31337n;
    const tj = await h.deploy(compileSolidity(SPDX + TGT, 'T').creation + W(seed));
    const ts = await h.deploy(compileSolidity(SPDX + TGT, 'T').creation + W(seed));
    const jc = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sc = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const cells: [string, (t: unknown) => string][] = [
      ['r(address)', (t) => A(String(t))],
      ['wr(address,uint256)', (t) => A(String(t)) + W(555)],
      ['r(address)', (t) => A(String(t))], // re-read after the write (proves the CALL mutated state)
    ];
    let sawValue = false;
    for (const [sg, args] of cells) {
      const rj = await h.call(jc, sel(sg) + args(tj));
      const rs = await h.call(sc, sel(sg) + args(ts));
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
      if (rj.returnHex === '0x' + W(seed + 555n + 7n + (seed + 555n) * 2n)) sawValue = true; // non-vacuity: post-write read decodes the seeded math
    }
    expect(sawValue).toBe(true);
  });

  it('runtime differential: class-implements-union deployed contract behaves identically to solc `contract C is B`', async () => {
    const J = `interface A { f(): View<u256>; }
      interface B extends A { g(): View<u256>; }
      class C extends B { s: u256; constructor() { this.s = 8181n; }
        get f(): External<u256> { return this.s; }
        get g(): External<u256> { return this.s + 9n; }
        bump(d: u256): External<u256> { this.s = this.s + d; return this.s; } }`;
    const S = `interface A { function f() external view returns (uint256); }
      interface B is A { function g() external view returns (uint256); }
      contract C is B { uint256 s; constructor() { s = 8181; }
        function f() external view returns (uint256) { return s; }
        function g() external view returns (uint256) { return s + 9; }
        function bump(uint256 d) external returns (uint256) { s = s + d; return s; } }`;
    const h = await Harness.create();
    const jc = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sc = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['f()', ''], ['g()', ''], ['bump(uint256)', W(19)], ['f()', '']] as [string, string][]) {
      const rj = await h.call(jc, sel(sg) + args);
      const rs = await h.call(sc, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
    // non-vacuity: the final read must decode the seeded value + the bump
    expect((await h.call(jc, sel('f()'))).returnHex).toBe('0x' + W(8181n + 19n));
  });

  it('runtime differential: type(I).interfaceId equals solc through 2-level and empty-derived chains', async () => {
    const J = `interface A { f(): View<u256>; }
      interface B extends A { g(): View<u256>; }
      interface E extends B {}
      class C { get idB(): External<bytes4> { return type(B).interfaceId; } get idA(): External<bytes4> { return type(A).interfaceId; } get idE(): External<bytes4> { return type(E).interfaceId; } }`;
    const S = `interface A { function f() external view returns (uint256); }
      interface B is A { function g() external view returns (uint256); }
      interface E is B {}
      contract C { function idB() external pure returns (bytes4) { return type(B).interfaceId; } function idA() external pure returns (bytes4) { return type(A).interfaceId; } function idE() external pure returns (bytes4) { return type(E).interfaceId; } }`;
    const h = await Harness.create();
    const jc = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sc = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const sg of ['idB()', 'idA()', 'idE()']) {
      const rj = await h.call(jc, sel(sg));
      const rs = await h.call(sc, sel(sg));
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
    // non-vacuity: idB is g()'s selector alone (inherited f EXCLUDED), idE is zero (no own methods)
    expect((await h.call(jc, sel('idB()'))).returnHex.slice(0, 10)).toBe(sel('g()'));
    expect((await h.call(jc, sel('idE()'))).returnHex.slice(0, 10)).toBe('0x' + '0'.repeat(8));
  });
});
