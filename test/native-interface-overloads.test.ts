// IFACE-OVERLOADS lift (2026-07-12) + PURE-GET-OBLIGATION resolution pins.
//
// ROW A - IFACE-OVERLOADS: a native `interface I` may declare the same method NAME with different
// parameter types (solc accepts overloads in interfaces). Every overload keeps its own canonical
// signature/selector and is its OWN per-signature implementation obligation. There is NO
// distinct-names bytecode twin (the selectors differ by construction), so THE ORACLE here is:
//   1) solc 0.8.35 runtime differentials (run + decode, distinct seeds, callee-state readback);
//   2) REJECT PARITY on every collision/ambiguity cell (each solc-witnessed):
//      - same NAME + same PARAMS (return ignored) -> JETH342 (solc: "defined twice");
//      - a concrete contract missing ONE overload -> JETH385 / non-abstract middle -> JETH483
//        (solc: 'Contract "X" should be marked as abstract.');
//      - bare member reference to an overloaded name (I.f.selector, abi.encodeCall(I.f, ...)) ->
//        JETH074/JETH434 (solc: 'Member "f" not unique after argument-dependent lookup');
//      - a call fitting 2+ overloads (bare literal, or a u8 arg that widens into both) -> JETH434;
//      - SELECTOR HASH COLLISION between two different signatures in the callable union -> JETH044
//        (solc: "Function signature hash collision") - closing a PRE-EXISTING over-acceptance: the
//        pre-lift base ACCEPTED colliding different-name methods (both encoding 0x00000000).
// The chain rows IFACE-CHAIN-REDECLARE (JETH342) / IFACE-CHAIN-TIGHTEN (JETH387) / same-signature
// diamond (JETH430) stay catalogued rejects; the IFACE-CHAIN-OVERLOAD row is LIFTED (a chain is an
// overload union, witnessed).
//
// ROW B - PURE-GET-OBLIGATION: the recorded pin (`p(): Pure<u256>` obligation + `get p(): Pure<u256>`
// impl rejects) was STALE - GET-MUT-HEADROOM (9a77971) already resolved it. Pinned here: the accept
// (runtime vs the solc mirror) + the solc mutability ladder (pure impl of view obligation accepts;
// state-reading/view impl of a pure obligation rejects JETH387 - solc: 'Overriding function changes
// state mutability from "pure" to "view"').
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const A = (h: string | { toString(): string }) => pad32(BigInt(h.toString()));
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};
/** Deploy the JETH source and its solc mirror, run the calls on both, expect equal (success, bytes). */
const runDiff = async (J: string, S: string, calls: [string, string?][]) => {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, args] of calls) {
    const rj = await h.call(aj, sel(sg) + (args ?? ''));
    const rs = await h.call(as, sel(sg) + (args ?? ''));
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
  }
};

describe('interface overloads: runtime differential vs solc 0.8.35', () => {
  it('an overloaded interface + full impl: both selectors dispatch, per-overload state writes read back', async () => {
    await runDiff(
      `interface I { f(x: u256): u256; f(x: u256, y: u256): u256; }
       class C extends I { s: u256;
         f(x: u256): External<u256> { this.s = x * 3n; return x + 1n; }
         f(x: u256, y: u256): External<u256> { this.s = y * 7n; return x + y; }
         get r(): External<u256> { return this.s; } }`,
      `interface I { function f(uint256 x) external returns (uint256); function f(uint256 x, uint256 y) external returns (uint256); }
       contract C is I { uint256 s;
         function f(uint256 x) external override returns (uint256) { s = x * 3; return x + 1; }
         function f(uint256 x, uint256 y) external override returns (uint256) { s = y * 7; return x + y; }
         function r() external view returns (uint256) { return s; } }`,
      [['f(uint256)', W(5)], ['r()'], ['f(uint256,uint256)', W(3) + W(4)], ['r()'], ['f(uint256)', W(11)], ['r()']],
    );
  });

  it('extends-chain overload union (B adds an overload of A.f) and a two-parent diamond of different sigs', async () => {
    await runDiff(
      `interface A0 { f(x: u256): u256; }
       interface B0 extends A0 { f(x: u256, y: u256): u256; }
       class C extends B0 { s: u256;
         f(x: u256): External<u256> { this.s = x; return x + 1n; }
         f(x: u256, y: u256): External<u256> { this.s = x * y; return x + y; }
         get r(): External<u256> { return this.s; } }`,
      `interface A0 { function f(uint256 x) external returns (uint256); }
       interface B0 is A0 { function f(uint256 x, uint256 y) external returns (uint256); }
       contract C is B0 { uint256 s;
         function f(uint256 x) external override returns (uint256) { s = x; return x + 1; }
         function f(uint256 x, uint256 y) external override returns (uint256) { s = x * y; return x + y; }
         function r() external view returns (uint256) { return s; } }`,
      [['f(uint256)', W(9)], ['r()'], ['f(uint256,uint256)', W(6) + W(7)], ['r()']],
    );
    await runDiff(
      `interface A1 { f(x: u256): u256; }
       interface B1 { f(x: u256, y: u256): u256; }
       interface D1 extends A1, B1 {}
       class C extends D1 { s: u256;
         f(x: u256): External<u256> { this.s = x + 100n; return x + 1n; }
         f(x: u256, y: u256): External<u256> { this.s = x + y + 200n; return x + y; }
         get r(): External<u256> { return this.s; } }`,
      `interface A1 { function f(uint256 x) external returns (uint256); }
       interface B1 { function f(uint256 x, uint256 y) external returns (uint256); }
       interface D1 is A1, B1 {}
       contract C is D1 { uint256 s;
         function f(uint256 x) external override returns (uint256) { s = x + 100; return x + 1; }
         function f(uint256 x, uint256 y) external override returns (uint256) { s = x + y + 200; return x + y; }
         function r() external view returns (uint256) { return s; } }`,
      [['f(uint256)', W(4)], ['r()'], ['f(uint256,uint256)', W(8) + W(9)], ['r()']],
    );
  });

  it('call-site dispatch through I(addr): arity picks the overload, a typed u256 arg picks past a u8 overload', async () => {
    // callee is solc-AUTHORED on both sides (ground truth for which selector each call hit),
    // plus a v() readback proving the last dispatch really landed (non-vacuous).
    const TGT = `contract T { uint256 public v;
      function f(uint256 x) external returns (uint256) { v = x; return x + 1; }
      function f(uint256 x, uint256 y) external returns (uint256) { v = x * 1000 + y; return x + y; }
      function g(uint8 x) external pure returns (uint256) { return 800 + x; }
      function g(uint256 x) external pure returns (uint256) { return 256000 + x; } }`;
    const J = `interface IT { f(x: u256): u256; f(x: u256, y: u256): u256; g(x: u8): Pure<u256>; g(x: u256): Pure<u256>; }
      class C { s: u256;
        one(t: address, x: u256): External<u256> { this.s = IT(t).f(x); return this.s; }
        two(t: address, x: u256, y: u256): External<u256> { this.s = IT(t).f(x, y); return this.s; }
        get g256(t: address, v: u256): External<u256> { return IT(t).g(v); } }`;
    const S = `interface IT { function f(uint256 x) external returns (uint256); function f(uint256 x, uint256 y) external returns (uint256); function g(uint8 x) external pure returns (uint256); function g(uint256 x) external pure returns (uint256); }
      contract C { uint256 s;
        function one(address t, uint256 x) external returns (uint256) { s = IT(t).f(x); return s; }
        function two(address t, uint256 x, uint256 y) external returns (uint256) { s = IT(t).f(x, y); return s; }
        function g256(address t, uint256 v) external view returns (uint256) { return IT(t).g(v); } }`;
    const h = await Harness.create();
    const tj = await h.deploy(compileSolidity(SPDX + TGT, 'T').creation);
    const ts = await h.deploy(compileSolidity(SPDX + TGT, 'T').creation);
    const jc = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sc = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const cells: [string, string][] = [
      ['one(address,uint256)', W(41)],
      ['two(address,uint256,uint256)', W(6) + W(9)],
      ['g256(address,uint256)', W(19)],
      ['one(address,uint256)', W(77)],
    ];
    for (const [sg, args] of cells) {
      const rj = await h.call(jc, sel(sg) + A(tj) + args);
      const rs = await h.call(sc, sel(sg) + A(ts) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
    const vj = await h.call(tj, sel('v()'));
    const vs = await h.call(ts, sel('v()'));
    expect(vj.returnHex).toBe(W(77).replace(/^/, '0x')); // the last one(77) really hit f(uint256)
    expect(vj.returnHex).toBe(vs.returnHex);
  });

  it('type(I).interfaceId XORs EVERY overload selector; mixed per-overload mutability runs equal', async () => {
    await runDiff(
      `interface I { f(x: u256): u256; f(x: u256, y: u256): u256; g(): View<bool>; }
       class C { get id(): External<bytes4> { return type(I).interfaceId; } }`,
      `interface I { function f(uint256 x) external returns (uint256); function f(uint256 x, uint256 y) external returns (uint256); function g() external view returns (bool); }
       contract C { function id() external pure returns (bytes4) { return type(I).interfaceId; } }`,
      [['id()']],
    );
    await runDiff(
      `interface I { f(x: u256): View<u256>; f(x: u256, y: u256): u256; }
       class C extends I { s: u256;
         get f(x: u256): External<u256> { return x + this.s; }
         f(x: u256, y: u256): External<u256> { this.s = y; return x + y; }
         get r(): External<u256> { return this.s; } }`,
      `interface I { function f(uint256 x) external view returns (uint256); function f(uint256 x, uint256 y) external returns (uint256); }
       contract C is I { uint256 s;
         function f(uint256 x) external view override returns (uint256) { return x + s; }
         function f(uint256 x, uint256 y) external override returns (uint256) { s = y; return x + y; }
         function r() external view returns (uint256) { return s; } }`,
      [['f(uint256,uint256)', W(2) + W(30)], ['f(uint256)', W(5)], ['r()']],
    );
  });

  it('a Visible CONSTANT satisfies its own zero-arg pure obligation next to an overloaded name (statics rule intact)', async () => {
    await runDiff(
      `interface I { k(): Pure<u256>; f(x: u256): u256; f(x: u256, y: u256): u256; }
       class C extends I { s: u256; static k: Visible<u256> = 42n;
         f(x: u256): External<u256> { this.s = x; return x + 1n; }
         f(x: u256, y: u256): External<u256> { this.s = x + y; return x * y; }
         get r(): External<u256> { return this.s; } }`,
      `interface I { function k() external pure returns (uint256); function f(uint256 x) external returns (uint256); function f(uint256 x, uint256 y) external returns (uint256); }
       contract C is I { uint256 s; uint256 public constant k = 42;
         function f(uint256 x) external override returns (uint256) { s = x; return x + 1; }
         function f(uint256 x, uint256 y) external override returns (uint256) { s = x + y; return x * y; }
         function r() external view returns (uint256) { return s; } }`,
      [['k()'], ['f(uint256)', W(13)], ['r()'], ['f(uint256,uint256)', W(3) + W(5)], ['r()']],
    );
  });
});

describe('interface overloads: reject parity (every cell solc-witnessed)', () => {
  const CALL = `class C { s: u256; go(a: address): External<void> { this.s = I(a).f(1n); } }`;
  it('same name + same params is "defined twice" (return type ignored) - JETH342 stays', () => {
    expect(codes(`interface I { f(x: u256): u256; f(y: u256): u256; } ${CALL}`)).toContain('JETH342');
    expect(codes(`interface I { f(x: u256): u256; f(x: u256): bool; } ${CALL}`)).toContain('JETH342');
  });

  it('a concrete contract missing ONE overload rejects: JETH385 at the leaf, JETH483 at a non-abstract middle', () => {
    expect(codes(`interface I { f(x: u256): u256; f(x: u256, y: u256): u256; }
      class C extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x + 1n; } }`)).toContain('JETH385');
    // the missing overload declared in the BASE of the chain is still owed
    expect(codes(`interface A0 { f(x: u256): u256; } interface B0 extends A0 { f(x: u256, y: u256): u256; }
      class C extends B0 { s: u256; f(x: u256, y: u256): External<u256> { this.s = y; return x + y; } }`)).toContain('JETH385');
    expect(codes(`interface I { f(x: u256): u256; f(x: u256, y: u256): u256; }
      class M extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x; } }
      class C extends M { f(x: u256, y: u256): External<u256> { this.s = y; return x + y; } }`)).toContain('JETH483');
    // a wrong-return / non-external impl of one overload keeps the per-signature rules
    expect(codes(`interface I { f(x: u256): u256; f(x: u256, y: u256): bool; }
      class C extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x; } f(x: u256, y: u256): External<u256> { this.s = y; return x + y; } }`)).toContain('JETH386');
    expect(codes(`interface I { f(x: u256): u256; f(x: u256, y: u256): u256; }
      class C extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x; } f(x: u256, y: u256): u256 { return x + y; } }`)).toContain('JETH388');
  });

  it('a bare member reference to an overloaded name is ambiguous: .selector -> JETH074, abi.encodeCall -> JETH434', () => {
    const I2 = `interface I { f(x: u256): u256; f(x: u256, y: u256): u256; }`;
    expect(codes(`${I2} class C { get g(): External<bytes4> { return I.f.selector; } }`)).toContain('JETH074');
    expect(codes(`${I2} class C { get g(): External<bytes> { return abi.encodeCall(I.f, [1n]); } }`)).toContain('JETH434');
    // single-overload references keep working
    expect(codes(`interface I { f(x: u256): u256; } class C { get g(): External<bytes4> { return I.f.selector; } }`)).toEqual([]);
  });

  it('argument-dependent lookup: ambiguous fits reject JETH434, no arity fit rejects JETH354, no type fit rejects JETH355', () => {
    const I8 = `interface I { f(x: u8): u256; f(x: u256): u256; }`;
    // a bare literal fits both (solc: 'Member "f" not unique after argument-dependent lookup')
    expect(codes(`${I8} ${CALL}`)).toContain('JETH434');
    // a u8-typed arg ALSO fits both (u8 widens into u256 - witnessed ambiguous in solc too)
    expect(codes(`${I8} class C { s: u256; go(a: address): External<void> { this.s = I(a).f(u8(7n)); } }`)).toContain('JETH434');
    // a u256-typed arg fits exactly one -> accepted
    expect(codes(`${I8} class C { s: u256; go(a: address, v: u256): External<void> { this.s = I(a).f(v); } }`)).toEqual([]);
    expect(codes(`interface I { f(x: u256): u256; f(x: u256, y: u256): u256; }
      class C { s: u256; go(a: address): External<void> { this.s = I(a).f(); } }`)).toContain('JETH354');
    // SAME-arity overloads that both fail the type trial -> JETH355 (solc: member "not found ... after
    // argument-dependent lookup"); an arity-UNIQUE candidate skips the trial and reports the ordinary
    // precise per-argument error instead (same shortcut as the internal resolveOverload).
    expect(codes(`interface I { f(x: bool): u256; f(x: address): u256; }
      class C { s: u256; go(a: address): External<void> { this.s = I(a).f(1n); } }`)).toContain('JETH355');
    expect(codes(`interface I { f(x: u256): u256; f(x: bool, y: bool): u256; }
      class C { s: u256; go(a: address): External<void> { this.s = I(a).f(1n, 2n); } }`)).toContain('JETH084');
  });

  it('selector hash collisions in the callable union reject JETH044 (pre-fix: silently ACCEPTED the cross-name pair)', () => {
    // same-name overloads whose signatures collide (mined pair, selector e697e3d6)
    expect(codes(`interface I { f(a: u48, b: u48, c: u136): u256; f(a: u192, b: bytes2, c: u72): u256; }
      class C { s: u256; go(x: address): External<void> { this.s = I(x).f(1n, 2n, 3n); } }`)).toContain('JETH044');
    // different-name collision in ONE body (both 0x00000000) - the closed over-acceptance
    expect(codes(`interface I { blockHashAskewLimitary(x: u256): u256; blockHashAddendsInexpansible(x: u256): u256; }
      class C { s: u256; go(a: address): External<void> { this.s = I(a).blockHashAskewLimitary(1n); } }`)).toContain('JETH044');
    // and ACROSS an extends chain (the union is one callable surface, like solc's derived interface)
    expect(codes(`interface A0 { blockHashAskewLimitary(x: u256): u256; }
      interface B0 extends A0 { blockHashAddendsInexpansible(x: u256): u256; }
      class C { s: u256; go(a: address): External<void> { this.s = B0(a).blockHashAskewLimitary(1n); } }`)).toContain('JETH044');
  });

  it('chain rows: same-sig diamond stays JETH430; identical redeclare + mutability-tighten are LIFTED', () => {
    // a REAL diamond (two distinct parents, same signature) still rejects JETH430 - unexpressible override list
    expect(codes(`interface A1 { f(x: u256): u256; } interface B1 { f(x: u256): u256; } interface D1 extends A1, B1 {}
      class C { s: u256; go(a: address): External<void> { this.s = D1(a).f(1n); } }`)).toContain('JETH430');
    // IFACE-CHAIN-REDECLARE: an EXACT same-signature redeclare in a linear chain now ACCEPTS (solc parity)
    expect(codes(`interface A0 { f(x: u256): u256; } interface B0 extends A0 { f(x: u256): u256; }
      class C { s: u256; go(a: address): External<void> { this.s = B0(a).f(1n); } }`)).toEqual([]);
    // IFACE-CHAIN-TIGHTEN: a mutability TIGHTEN (nonpayable -> view) now ACCEPTS; a LOOSEN stays JETH387
    expect(codes(`interface A0 { f(x: u256): u256; } interface B0 extends A0 { f(x: u256): View<u256>; }
      class C { s: u256; go(a: address): External<void> { this.s = B0(a).f(1n); } }`)).toEqual([]);
    expect(codes(`interface A0 { f(x: u256): View<u256>; } interface B0 extends A0 { f(x: u256): u256; }
      class C { s: u256; go(a: address): External<void> { this.s = B0(a).f(1n); } }`)).toContain('JETH387');
  });

  it('a value option must target the payable OVERLOAD (per-overload mutability): JETH353 on the non-payable one', () => {
    expect(codes(`interface I { f(x: u256): Payable<u256>; f(x: u256, y: u256): u256; }
      class C { s: u256; go(a: address): External<void> { this.s = I(a, { value: 1n }).f(1n, 2n); } }`)).toContain('JETH353');
    expect(codes(`interface I { f(x: u256): Payable<u256>; f(x: u256, y: u256): u256; }
      class C { s: u256; go(a: address): External<void> { this.s = I(a, { value: 1n }).f(1n); } }`)).toEqual([]);
  });
});

describe('PURE-GET-OBLIGATION (Row B): resolved pin + the mutability ladder', () => {
  it('a Pure obligation implemented by a declared-Pure get runs equal to the solc mirror (the recorded pin, now resolved)', async () => {
    await runDiff(
      `interface I { p(): Pure<u256>; } class C extends I { get p(): Pure<u256> { return 5n; } }`,
      `interface I { function p() external pure returns (uint256); } contract C is I { function p() external pure override returns (uint256) { return 5; } }`,
      [['p()']],
    );
  });

  it('ladder: pure impl of a View obligation accepts (runtime-equal); a pure obligation with an arg accepts', async () => {
    await runDiff(
      `interface I { p(): View<u256>; } class C extends I { get p(): Pure<u256> { return 5n; } }`,
      `interface I { function p() external view returns (uint256); } contract C is I { function p() external pure override returns (uint256) { return 5; } }`,
      [['p()']],
    );
    expect(codes(`interface I { p(a: u256): Pure<u256>; } class C extends I { get p(a: u256): Pure<u256> { return a * 2n; } }`)).toEqual([]);
  });

  it('ladder rejects (solc parity): a view/state-reading impl cannot satisfy a pure obligation', () => {
    // solc: 'Overriding function changes state mutability from "pure" to "view".'
    expect(codes(`interface I { p(): Pure<u256>; } class C extends I { s: u256; get p(): External<u256> { return this.s; } }`)).toContain('JETH387');
    expect(codes(`interface I { p(): Pure<u256>; } class C extends I { get p(): View<u256> { return 5n; } }`)).toContain('JETH387');
  });
});
