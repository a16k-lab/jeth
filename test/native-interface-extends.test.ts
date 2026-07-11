// P0a: a native TS `interface I` is an EXTENDABLE base (`class C extends I`), the native spelling of
// the `@interface class I` implements-path (solc `contract C is I`). The heritage path routes through
// the SAME InterfaceDecl machinery as the decorator form, so THE ORACLE here is twofold:
//   1) TWIN-BYTECODE EQUALITY: every accepted shape compiles byte-identical to its decorator twin
//      (same compiler, both spellings) - the in-compiler oracle;
//   2) solc 0.8.35 runtime differentials (run + decode with distinct seeds) on representative shapes;
//   3) REJECT PARITY: every obligation/ladder/override rule fires with the SAME code on both spellings
//      (JETH385/386/387/388/381/384/456/369), and the pre-existing gates are unchanged (JETH370 for a
//      non-interface non-contract base, JETH391 for `implements`, legacy mode untouched).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string, sources?: Record<string, string>) =>
  compile(src, { fileName: 'C.jeth', ...(sources ? { sources } : {}) }).creationBytecode;
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};
/** Both spellings must reject with the same code. */
const bothReject = (native: string, twin: string, code: string) => {
  expect(codes(native), `native must reject ${code}`).toContain(code);
  expect(codes(twin), `twin must reject ${code}`).toContain(code);
};

describe('native interface as an extendable base (P0a): twin-bytecode equality', () => {
  it('single method + view getter impl == the interface twin', () => {
    expect(bc(`interface I { f(x: u256): u256; g(): View<u256>; }
      class C extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x + 1n; } get g(): External<u256> { return this.s; } }`))
      .toBe(bc(`interface I { f(x: u256): u256; g(): View<u256>; }
      class C extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x + 1n; } get g(): External<u256> { return this.s; } }`));
  });

  it('multi-method: all four mutability marker cells (bare/View/Pure/Payable) == twin', () => {
    expect(bc(`interface I { w(x: u256): u256; v(): View<u256>; p(a: u256): Pure<u256>; pay(): Payable<u256>; }
      class C extends I {
        s: u256;
        w(x: u256): External<u256> { this.s = x; return this.s; }
        get v(): External<u256> { return this.s; }
        get p(a: u256): External<u256> { return a * 3n; }
        pay(): Payable<u256> { return msg.value; }
      }`))
      .toBe(bc(`interface I { w(x: u256): u256; v(): View<u256>; p(a: u256): Pure<u256>; pay(): Payable<u256>; }
      class C extends I {
        s: u256;
        w(x: u256): External<u256> { this.s = x; return this.s; }
        get v(): External<u256> { return this.s; }
        get p(a: u256): External<u256> { return a * 3n; }
        pay(): Payable<u256> { return msg.value; }
      }`));
  });

  it('STRICTER-impl ladder cells accept: pure impl of a View method; view impl of a bare method', () => {
    expect(bc(`interface I { g(): View<u256>; }
      class C extends I { get g(): External<u256> { return 5n; } }`))
      .toBe(bc(`interface I { g(): View<u256>; }
      class C extends I { get g(): External<u256> { return 5n; } }`));
    expect(bc(`interface I { g(): u256; }
      class C extends I { s: u256; get g(): External<u256> { return this.s; } bump(): External<void> { this.s = this.s + 1n; } }`))
      .toBe(bc(`interface I { g(): u256; }
      class C extends I { s: u256; get g(): External<u256> { return this.s; } bump(): External<void> { this.s = this.s + 1n; } }`));
  });

  it('C3 mix (extends an abstract base AND an interface) == twin; obligation travels through a base', () => {
    expect(bc(`interface I { total(): View<u256>; }
      abstract class B { s: u256; constructor() { this.s = 7n; } add(d: u256): External<void> { this.s = this.s + d; } }
      class C extends B, I { get total(): External<u256> { return this.s; } }`))
      .toBe(bc(`interface I { total(): View<u256>; }
      abstract class B { s: u256; constructor() { this.s = 7n; } add(d: u256): External<void> { this.s = this.s + d; } }
      class C extends B, I { get total(): External<u256> { return this.s; } }`));
    // abstract B extends I and defers; the concrete leaf implements
    expect(bc(`interface I { g(): View<u256>; h(): u256; }
      abstract class B extends I { s: u256; get g(): External<u256> { return this.s; } }
      class C extends B { h(): External<u256> { this.s = this.s + 1n; return this.s; } }`))
      .toBe(bc(`interface I { g(): View<u256>; h(): u256; }
      abstract class B extends I { s: u256; get g(): External<u256> { return this.s; } }
      class C extends B { h(): External<u256> { this.s = this.s + 1n; return this.s; } }`));
  });

  it('struct + array params (expanded-tuple ABI) == twin', () => {
    expect(bc(`type P = { a: u256; b: u256 };
      interface I { sum(p: P): View<u256>; agg(xs: u256[]): View<u256>; }
      class C extends I {
        get sum(p: P): External<u256> { return p.a + p.b; }
        get agg(xs: u256[]): External<u256> { let t: u256 = 0n; for (let i: u256 = 0n; i < xs.length; i = i + 1n) { t = t + xs[i]; } return t; }
      }`))
      .toBe(bc(`type P = { a: u256; b: u256 };
      interface I { sum(p: P): View<u256>; agg(xs: u256[]): View<u256>; }
      class C extends I {
        get sum(p: P): External<u256> { return p.a + p.b; }
        get agg(xs: u256[]): External<u256> { let t: u256 = 0n; for (let i: u256 = 0n; i < xs.length; i = i + 1n) { t = t + xs[i]; } return t; }
      }`));
  });

  it('@override interplay: optional bare @override and required @override(I, J) == twin', () => {
    expect(bc(`interface I { f(x: u256): u256; }
      class C extends I { s: u256; @override f(x: u256): External<u256> { this.s = x; return x + 1n; } }`))
      .toBe(bc(`interface I { f(x: u256): u256; }
      class C extends I { s: u256; @override f(x: u256): External<u256> { this.s = x; return x + 1n; } }`));
    expect(bc(`interface I { f(): View<u256>; }
      interface J { f(): View<u256>; }
      class C extends I, J { @override(I, J) get f(): External<u256> { return 1n; } }`))
      .toBe(bc(`interface I { f(): View<u256>; }
      interface J { f(): View<u256>; }
      class C extends I, J { @override(I, J) get f(): External<u256> { return 1n; } }`));
  });

  it('extending one interface while CALLING another (call-target usage unchanged) == twin', () => {
    expect(bc(`interface I { relay(t: address): u256; }
      interface IT { get(): View<u256>; }
      class C extends I { relay(t: address): External<u256> { this.s = IT(t).get(); return this.s; } s: u256; }`))
      .toBe(bc(`interface I { relay(t: address): u256; }
      interface IT { get(): View<u256>; }
      class C extends I { relay(t: address): External<u256> { this.s = IT(t).get(); return this.s; } s: u256; }`));
  });

  it('multi-file: the interface lives in a dep, imported + extended == twin', () => {
    const nat = bc(
      `import { I } from "./dep.jeth";
       class C extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x + 1n; } get g(): External<u256> { return this.s; } }`,
      { 'dep.jeth': `export interface I { f(x: u256): u256; g(): View<u256>; }\n` },
    );
    const twin = bc(
      `import { I } from "./dep.jeth";
       @contract class C extends I { @state s: u256; @external f(x: u256): u256 { this.s = x; return x + 1n; } @external @view g(): u256 { return this.s; } }`,
      { 'dep.jeth': `export @interface class I { @external f(x: u256): u256; @external @view g(): u256; }\n` },
    );
    expect(nat).toBe(twin);
  });

  it('C3 ordering parity: `extends B, I` where B already implements I rejects (JETH371) both spellings; `extends I, B` accepts twin-equal', () => {
    bothReject(
      `interface I { g(): View<u256>; }
       abstract class B extends I { s: u256; get g(): External<u256> { return this.s; } }
       class C extends B, I { h(): External<void> { this.s = 1n; } }`,
      `interface I { g(): View<u256>; }
       abstract class B extends I { s: u256; g(): External<u256> { return this.s; } }
       class C extends B, I { h(): External<void> { this.s = 1n; } }`,
      'JETH371',
    );
    expect(bc(`interface I { g(): View<u256>; }
      abstract class B extends I { s: u256; get g(): External<u256> { return this.s; } }
      class C extends I, B { h(): External<void> { this.s = 1n; } }`))
      .toBe(bc(`interface I { g(): View<u256>; }
      abstract class B extends I { s: u256; get g(): External<u256> { return this.s; } }
      class C extends I, B { h(): External<void> { this.s = 1n; } }`));
  });
});

describe('native interface extends: solc 0.8.35 runtime differentials', () => {
  it('single-method + getter impl runs byte-identical to solc (distinct seeds, decoded)', async () => {
    const J = `interface I { f(x: u256): u256; g(): View<u256>; }
      class C extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x + 1n; } get g(): External<u256> { return this.s; } }`;
    const S = `interface I { function f(uint256 x) external returns(uint256); function g() external view returns(uint256); }
      contract C is I { uint256 s; function f(uint256 x) external override returns(uint256){ s = x; return x + 1; } function g() external view override returns(uint256){ return s; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['f(uint256)', W(41)], ['g()', ''], ['f(uint256)', W(999)], ['g()', '']] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
    // non-vacuity: the second g() must observe the second seed
    const rg = await h.call(aj, sel('g()'));
    expect(rg.returnHex).toBe('0x' + W(999));
  });

  it('the payable marker cell receives value byte-identical to solc', async () => {
    const J = `interface I { pay(): Payable<u256>; v(): View<u256>; }
      class C extends I { s: u256; pay(): Payable<u256> { this.s = msg.value; return msg.value; } get v(): External<u256> { return this.s; } }`;
    const S = `interface I { function pay() external payable returns(uint256); function v() external view returns(uint256); }
      contract C is I { uint256 s; function pay() external payable override returns(uint256){ s = msg.value; return msg.value; } function v() external view override returns(uint256){ return s; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const rj = await h.call(aj, sel('pay()'), { value: 12345n });
    const rs = await h.call(as, sel('pay()'), { value: 12345n });
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(rj.returnHex).toBe('0x' + W(12345));
    const vj = await h.call(aj, sel('v()'));
    const vs = await h.call(as, sel('v()'));
    expect(vj.returnHex).toBe(vs.returnHex);
    expect(vj.returnHex).toBe('0x' + W(12345));
  });

  it('C3 mix (abstract base + interface) with a base constructor runs byte-identical to solc', async () => {
    const J = `interface I { total(): View<u256>; }
      abstract class B { s: u256; constructor() { this.s = 7n; } add(d: u256): External<void> { this.s = this.s + d; } }
      class C extends B, I { get total(): External<u256> { return this.s; } }`;
    const S = `interface I { function total() external view returns(uint256); }
      abstract contract B { uint256 s; constructor() { s = 7; } function add(uint256 d) external { s = s + d; } }
      contract C is B, I { function total() external view override returns(uint256){ return s; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['total()', ''], ['add(uint256)', W(5)], ['total()', '']] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
    const rt = await h.call(aj, sel('total()'));
    expect(rt.returnHex).toBe('0x' + W(12)); // 7 (ctor) + 5 (add)
  });

  it('struct + dynamic-array interface params run byte-identical to solc', async () => {
    const J = `type P = { a: u256; b: u256 };
      interface I { sum(p: P): View<u256>; agg(xs: u256[]): View<u256>; }
      class C extends I {
        get sum(p: P): External<u256> { return p.a + p.b; }
        get agg(xs: u256[]): External<u256> { let t: u256 = 0n; for (let i: u256 = 0n; i < xs.length; i = i + 1n) { t = t + xs[i]; } return t; }
      }`;
    const S = `struct P { uint256 a; uint256 b; }
      interface I { function sum(P calldata p) external view returns(uint256); function agg(uint256[] calldata xs) external view returns(uint256); }
      contract C is I {
        function sum(P calldata p) external view override returns(uint256){ return p.a + p.b; }
        function agg(uint256[] calldata xs) external view override returns(uint256){ uint256 t = 0; for (uint256 i = 0; i < xs.length; i++) { t = t + xs[i]; } return t; }
      }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const calls: [string, string][] = [
      ['sum((uint256,uint256))', W(3) + W(4)],
      ['agg(uint256[])', W(32) + W(3) + W(10) + W(20) + W(30)],
    ];
    for (const [sg, args] of calls) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
    expect((await h.call(aj, sel('agg(uint256[])') + W(32) + W(3) + W(10) + W(20) + W(30))).returnHex).toBe('0x' + W(60));
  });
});

describe('native interface extends: reject parity (same code, both spellings)', () => {
  it('unimplemented interface method -> JETH385 (direct and via an abstract base)', () => {
    bothReject(
      `interface I { f(x: u256): u256; g(): View<u256>; }
       class C extends I { f(x: u256): External<u256> { this.s = x; return x + 1n; } s: u256; }`,
      `interface I { f(x: u256): u256; g(): View<u256>; }
       class C extends I { f(x: u256): External<u256> { this.s = x; return x + 1n; } s: u256; }`,
      'JETH385',
    );
    bothReject(
      `interface I { g(): View<u256>; }
       abstract class B extends I { s: u256; poke(): External<void> { this.s = this.s + 1n; } }
       class C extends B { }`,
      `interface I { g(): View<u256>; }
       abstract class B extends I { s: u256; poke(): External<void> { this.s = this.s + 1n; } }
       class C extends B { }`,
      'JETH385',
    );
    // a PARAM-TYPE mismatch is an unimplemented method too, not a silent overload
    bothReject(
      `interface I { f(x: u256): u256; }
       class C extends I { f(x: bool): External<u256> { this.s = 1n; return this.s; } s: u256; }`,
      `interface I { f(x: u256): u256; }
       class C extends I { f(x: bool): External<u256> { this.s = 1n; return this.s; } s: u256; }`,
      'JETH385',
    );
  });

  it('return-type mismatch -> JETH386; mutability loosening -> JETH387 (view->writer, payable<->nonpayable)', () => {
    bothReject(
      `interface I { f(): u256; }
       class C extends I { f(): External<bool> { this.s = 1n; return true; } s: u256; }`,
      `interface I { f(): u256; }
       class C extends I { f(): External<bool> { this.s = 1n; return true; } s: u256; }`,
      'JETH386',
    );
    bothReject(
      `interface I { g(): View<u256>; }
       class C extends I { s: u256; g(): External<u256> { this.s = this.s + 1n; return this.s; } }`,
      `interface I { g(): View<u256>; }
       class C extends I { s: u256; g(): External<u256> { this.s = this.s + 1n; return this.s; } }`,
      'JETH387',
    );
    bothReject(
      `interface I { pay(): Payable<u256>; }
       class C extends I { s: u256; pay(): External<u256> { this.s = this.s + 1n; return this.s; } }`,
      `interface I { pay(): Payable<u256>; }
       class C extends I { s: u256; pay(): External<u256> { this.s = this.s + 1n; return this.s; } }`,
      'JETH387',
    );
    bothReject(
      `interface I { f(): u256; }
       class C extends I { f(): Payable<u256> { return msg.value; } }`,
      `interface I { f(): u256; }
       class C extends I { f(): Payable<u256> { return msg.value; } }`,
      'JETH387',
    );
  });

  it('non-external impl -> JETH388; two same-sig interfaces without @override(I, J) -> JETH381', () => {
    bothReject(
      `interface I { f(): u256; }
       class C extends I { f(): u256 { this.s = 1n; return this.s; } s: u256; kick(): External<void> { this.f(); } }`,
      `interface I { f(): u256; }
       class C extends I { f(): u256 { this.s = 1n; return this.s; } s: u256; kick(): External<void> { this.f(); } }`,
      'JETH388',
    );
    bothReject(
      `interface I { f(): View<u256>; }
       interface J { f(): View<u256>; }
       class C extends I, J { get f(): External<u256> { return 1n; } }`,
      `interface I { f(): View<u256>; }
       interface J { f(): View<u256>; }
       class C extends I, J { get f(): External<u256> { return 1n; } }`,
      'JETH381',
    );
  });

  it('heritage-shape gates: ctor args on an interface -> JETH384; duplicate base -> JETH456; @override of nothing -> JETH369', () => {
    bothReject(
      `interface I { f(): u256; }
       class C extends I(7n) { f(): External<u256> { this.s = 1n; return this.s; } s: u256; }`,
      `interface I { f(): u256; }
       class C extends I(7n) { f(): External<u256> { this.s = 1n; return this.s; } s: u256; }`,
      'JETH384',
    );
    bothReject(
      `interface I { f(): u256; }
       class C extends I, I { f(): External<u256> { this.s = 1n; return this.s; } s: u256; }`,
      `interface I { f(): u256; }
       class C extends I, I { f(): External<u256> { this.s = 1n; return this.s; } s: u256; }`,
      'JETH456',
    );
    bothReject(
      `interface I { f(): u256; }
       class C extends I { f(): External<u256> { this.s = 1n; return this.s; } s: u256; @override h(): External<void> { this.s = 2n; } }`,
      `interface I { f(): u256; }
       class C extends I { f(): External<u256> { this.s = 1n; return this.s; } s: u256; @override h(): External<void> { this.s = 2n; } }`,
      'JETH369',
    );
  });

  it('pre-existing gates unchanged: JETH370 for a non-interface base, JETH391 for implements, JETH349 for interface-extends-interface, legacy mode untouched', () => {
    // extending a struct type alias is still JETH370
    expect(codes(`type P = { a: u256 };
      class C extends P { f(): External<u256> { this.x = 1n; return 1n; } x: u256; }`)).toContain('JETH370');
    // `implements` stays a loud reject
    expect(codes(`interface I { f(x: u256): u256; }
      class C implements I { f(x: u256): External<u256> { this.s = x; return x; } s: u256; }`)).toContain('JETH391');
    // a native interface still cannot extend another interface
    expect(codes(`interface I0 { f(): u256; }
      interface I extends I0 { g(): u256; }
      class C extends I { f(): External<u256> { this.s = 1n; return this.s; } g(): External<u256> { this.s = 2n; return this.s; } s: u256; }`)).toContain('JETH349');
    // LEGACY mode: a TS `interface` is not collected, so extending it is still JETH370
    expect(codes(`// use @decorators
interface I { f(x: u256): u256; }
@contract class C extends I { @external f(x: u256): u256 { return x; } }`)).toContain('JETH370');
  });
});
