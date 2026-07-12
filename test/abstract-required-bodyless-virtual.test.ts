// OA-ABSTRACT (JETH483): solc 0.8.35 requires the `abstract` keyword on ANY contract that declares a
// bodyless function ('Contract "B" should be marked as abstract.'), EVEN IF the deployed leaf
// implements every such member - and likewise on any NON-abstract contract that, in ITS OWN view of
// the inheritance chain, leaves an inherited bodyless function unimplemented (a non-abstract MIDDLE
// class). JETH previously enforced this only for the DEPLOYED contract (JETH380), so a non-abstract
// BASE with a bodyless @virtual member whose leaf implemented it was silently ACCEPTED: an
// over-acceptance, witnessed against solc for a plain method, a `get` accessor, the receive/fallback
// special entries, the middle-chain, and the diamond-sibling shapes.
//
// PRE-FIX CONTROL (non-vacuity): the pinned repro below ACCEPTED at parent 750d262 (proven by a
// parent-compile via the main checkout during the fix); every abstract twin in this file was proven
// BYTE-IDENTICAL to its parent-750d262 compile at fix time and is runtime-differentially compared to
// its solc mirror here with distinct seeds.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    const err = e as { diagnostics?: { code: string }[] };
    if (err.diagnostics) return err.diagnostics.map((d) => d.code);
    throw e;
  }
};
const solcRejects = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};

/** Deploy the JETH source and its solc mirror side by side, run `calls` on both, assert exact
 *  success + returnHex parity per call, and return the JETH results (for value assertions). */
async function runBoth(
  J: string,
  S: string,
  calls: { data: string; value?: bigint }[],
): Promise<{ success: boolean; returnHex: string }[]> {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  const out: { success: boolean; returnHex: string }[] = [];
  for (const c of calls) {
    const opts = c.value !== undefined ? { value: c.value } : {};
    const rj = await h.call(aj, '0x' + c.data, opts);
    const rs = await h.call(as, '0x' + c.data, opts);
    expect(rj.success, `success parity for ${c.data || '<empty>'}`).toBe(rs.success);
    expect(rj.returnHex, `return parity for ${c.data || '<empty>'}`).toBe(rs.returnHex);
    out.push({ success: rj.success, returnHex: rj.returnHex });
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// The pinned repro: a NON-abstract base declaring a bodyless @virtual method, leaf implements.
// Pre-fix this ACCEPTED (over-acceptance); solc rejects 'Contract "B" should be marked as abstract.'
// ---------------------------------------------------------------------------------------------
describe('JETH483: a non-abstract class declaring a bodyless @virtual member rejects (solc parity)', () => {
  it('the pinned repro (plain method, leaf implements) -> exactly JETH483; solc mirror rejects', () => {
    expect(
      codes(
        `class B { @virtual f(): External<u256>; x: u256; } class C extends B { @override f(): External<u256> { this.x = 7n; return this.x; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `contract B { function f() external virtual returns (uint256); uint256 x; } contract C is B { function f() external override returns (uint256) { x = 7; return x; } }`,
      ),
    ).toBe(true);
  });

  it('get-flavored bodyless member in a non-abstract base -> exactly JETH483; solc mirror rejects', () => {
    expect(
      codes(`class B { @virtual get f(): External<u256>; } class C extends B { @override get f(): External<u256> { return 5n; } }`),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `contract B { function f() external virtual returns (uint256); } contract C is B { function f() external view override returns (uint256) { return 5; } }`,
      ),
    ).toBe(true);
  });

  it('bodyless receive entry in a non-abstract base -> exactly JETH483; solc mirror rejects', () => {
    expect(
      codes(
        `class B { @virtual receive(): void; } class C extends B { count: u256; @override receive(): void { this.count = 42n; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `contract B { receive() external payable virtual; } contract C is B { uint256 count; receive() external payable override { count = 42; } }`,
      ),
    ).toBe(true);
  });

  it('bodyless fallback entry in a non-abstract base -> exactly JETH483; solc mirror rejects', () => {
    expect(
      codes(
        `class B { @virtual fallback(): void; } class C extends B { count: u256; @override fallback(): void { this.count = 42n; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `contract B { fallback() external virtual; } contract C is B { uint256 count; fallback() external override { count = 42; } }`,
      ),
    ).toBe(true);
  });

  it('the never-extended variant (deploy candidate declares bodyless) fires JETH483 alongside JETH380', () => {
    const got = codes(`class C { @virtual f(): External<u256>; }`);
    expect(got).toContain('JETH483');
    expect(got).toContain('JETH380'); // the pre-existing deployed-leaf gate is unregressed
    expect(solcRejects(`contract C { function f() external virtual returns (uint256); }`)).toBe(true);
  });

  it('diamond siblings: only the non-abstract declaring base fires -> exactly JETH483', () => {
    expect(
      codes(
        `abstract class A { @virtual f(): External<u256>; } class K { @virtual h(): External<u256>; } class C extends A, K { x: u256; @override f(): External<u256> { this.x = 1n; return this.x; } @override h(): External<u256> { this.x = 2n; return this.x; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `abstract contract A { function f() external virtual returns (uint256); } contract K { function h() external virtual returns (uint256); } contract C is A, K { uint256 x; function f() external override returns (uint256) { x = 1; return x; } function h() external override returns (uint256) { x = 2; return x; } }`,
      ),
    ).toBe(true);
  });

  it('a non-abstract base with a bodyless member AND implemented members still fires -> exactly JETH483', () => {
    expect(
      codes(
        `class B { @virtual f(): External<u256>; w: u256; k(): External<u256> { this.w = 9n; return this.w; } } class C extends B { @override f(): External<u256> { this.w = 7n; return this.w; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `contract B { function f() external virtual returns (uint256); uint256 w; function k() external returns (uint256) { w = 9; return w; } } contract C is B { function f() external override returns (uint256) { w = 7; return w; } }`,
      ),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------
// The INHERITED rule: a non-abstract MIDDLE class that leaves an inherited bodyless member
// unimplemented must be abstract too (solc: 'Contract "M" should be marked as abstract.').
// ---------------------------------------------------------------------------------------------
describe('JETH483: a non-abstract middle class inheriting an unimplemented bodyless member rejects', () => {
  it('abstract base -> non-abstract middle (no impl) -> implementing leaf -> exactly JETH483', () => {
    expect(
      codes(
        `abstract class A { @virtual f(): External<u256>; } class M extends A { x: u256; g(): External<u256> { this.x = 1n; return this.x; } } class C extends M { @override f(): External<u256> { this.x = 2n; return this.x; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `abstract contract A { function f() external virtual returns (uint256); } contract M is A { uint256 x; function g() external returns (uint256) { x = 1; return x; } } contract C is M { function f() external override returns (uint256) { x = 2; return x; } }`,
      ),
    ).toBe(true);
  });

  it('two non-abstract middles in a deep chain each fire JETH483 (one per class, solc parity)', () => {
    const got = codes(
      `abstract class A { @virtual f(): External<u256>; } class M1 extends A { x: u256; g(): External<u256> { this.x = 1n; return this.x; } } class M2 extends M1 { h(): External<u256> { this.x = 2n; return this.x; } } class C extends M2 { @override f(): External<u256> { this.x = 3n; return this.x; } }`,
    );
    expect(got.filter((c) => c === 'JETH483')).toEqual(['JETH483', 'JETH483']);
    expect(
      solcRejects(
        `abstract contract A { function f() external virtual returns (uint256); } contract M1 is A { uint256 x; function g() external returns (uint256) { x = 1; return x; } } contract M2 is M1 { function h() external returns (uint256) { x = 2; return x; } } contract C is M2 { function f() external override returns (uint256) { x = 3; return x; } }`,
      ),
    ).toBe(true);
  });

  it('special-entry flavor: bodyless receive inherited by a non-abstract middle -> exactly JETH483', () => {
    expect(
      codes(
        `abstract class A { @virtual receive(): void; } class M extends A { y: u256; g(): External<u256> { this.y = 1n; return this.y; } } class C extends M { count: u256; @override receive(): void { this.count = 42n; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `abstract contract A { receive() external payable virtual; } contract M is A { uint256 y; function g() external returns (uint256) { y = 1; return y; } } contract C is M { uint256 count; receive() external payable override { count = 42; } }`,
      ),
    ).toBe(true);
  });

  it('a getter-var override in the LEAF does not satisfy the non-abstract MIDDLE -> JETH483 (solc parity)', () => {
    expect(
      codes(
        `abstract class A { @virtual x(): External<u256>; } class M extends A { g(): External<u256> { return 1n; } } class C extends M { @override x: Visible<u256>; }`,
      ),
    ).toContain('JETH483');
    expect(
      solcRejects(
        `abstract contract A { function x() external virtual returns (uint256); } contract M is A { function g() external returns (uint256) { return 1; } } contract C is M { uint256 public override x; }`,
      ),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------
// The LEGAL abstract idiom is untouched: abstract declarer + implementing leaf ACCEPTS, and runs
// byte-for-byte equal to the solc mirror on distinct seeds. (Each twin was additionally proven
// byte-identical to its parent-750d262 compile at fix time.)
// ---------------------------------------------------------------------------------------------
describe('JETH483 controls: the legal abstract idiom stays accepted and solc-runtime-equal', () => {
  it('abstract twin of the pinned repro accepts and matches solc on distinct seeds', async () => {
    const J = `abstract class B { @virtual f(x: u256): External<u256>; v: u256; } class C extends B { @override f(x: u256): External<u256> { this.v = x + 3n; return this.v; } }`;
    const S = `abstract contract B { function f(uint256 x) external virtual returns (uint256); uint256 v; } contract C is B { function f(uint256 x) external override returns (uint256) { v = x + 3; return v; } }`;
    const r = await runBoth(J, S, [
      { data: sel('f(uint256)') + W(11n) },
      { data: sel('f(uint256)') + W(94582n) },
    ]);
    expect(r[0]).toEqual({ success: true, returnHex: '0x' + W(14n) });
    expect(r[1]).toEqual({ success: true, returnHex: '0x' + W(94585n) });
  });

  it('abstract twin of the get-flavored cell accepts and matches solc', async () => {
    const J = `abstract class B { @virtual get f(): External<u256>; } class C extends B { s: u256; constructor() { this.s = 777n; } @override get f(): External<u256> { return this.s; } }`;
    const S = `abstract contract B { function f() external view virtual returns (uint256); } contract C is B { uint256 s; constructor() { s = 777; } function f() external view override returns (uint256) { return s; } }`;
    const r = await runBoth(J, S, [{ data: sel('f()') }]);
    expect(r[0]).toEqual({ success: true, returnHex: '0x' + W(777n) });
  });

  it('abstract twin of the receive cell accepts and matches solc (transfer then read)', async () => {
    const J = `abstract class B { @virtual receive(): void; } class C extends B { count: u256; @override receive(): void { this.count = msg.value + 40n; } get g(): External<u256> { return this.count; } }`;
    const S = `abstract contract B { receive() external payable virtual; } contract C is B { uint256 count; receive() external payable override { count = msg.value + 40; } function g() external view returns (uint256) { return count; } }`;
    const r = await runBoth(J, S, [{ data: '', value: 2n }, { data: sel('g()') }]);
    expect(r[1]).toEqual({ success: true, returnHex: '0x' + W(42n) });
  });

  it('abstract MIDDLE inheriting the unimplemented member stays accepted and matches solc', async () => {
    const J = `abstract class A { @virtual f(): External<u256>; } abstract class M extends A { y: u256; g(): External<u256> { this.y = 1n; return this.y; } } class C extends M { @override f(): External<u256> { this.y = this.y + 5n; return this.y; } }`;
    const S = `abstract contract A { function f() external virtual returns (uint256); } abstract contract M is A { uint256 y; function g() external returns (uint256) { y = 1; return y; } } contract C is M { function f() external override returns (uint256) { y = y + 5; return y; } }`;
    const r = await runBoth(J, S, [
      { data: sel('g()') },
      { data: sel('f()') },
      { data: sel('f()') },
    ]);
    expect(r[2]).toEqual({ success: true, returnHex: '0x' + W(11n) });
  });

  it('a getter-var override in the MIDDLE satisfies it (solc-legal) and stays accepted', () => {
    expect(
      codes(
        `abstract class A { @virtual x(): External<u256>; } class M extends A { @override x: Visible<u256>; } class C extends M { y: u256; g(): External<u256> { this.y = 3n; return this.y; } }`,
      ),
    ).toEqual([]);
    expect(
      solcRejects(
        `abstract contract A { function x() external virtual returns (uint256); } contract M is A { uint256 public override x; } contract C is M { uint256 y; function g() external returns (uint256) { y = 3; return y; } }`,
      ),
    ).toBe(false);
  });

  it('a non-abstract middle that IMPLEMENTS the member is legal (solc parity) and stays accepted', () => {
    expect(
      codes(
        `abstract class A { @virtual f(): External<u256>; } class M extends A { y: u256; @virtual @override f(): External<u256> { this.y = 1n; return this.y; } } class C extends M { @override f(): External<u256> { this.y = 3n; return this.y; } }`,
      ),
    ).toEqual([]);
    expect(
      solcRejects(
        `abstract contract A { function f() external virtual returns (uint256); } contract M is A { uint256 y; function f() external virtual override returns (uint256) { y = 1; return y; } } contract C is M { function f() external override returns (uint256) { y = 3; return y; } }`,
      ),
    ).toBe(false);
  });

  it('pre-existing gates are unregressed: the leaf that fails to implement still fires JETH380', () => {
    const got = codes(
      `abstract class B { @virtual f(): External<u256>; } class C extends B { x: u256; g(): External<u256> { this.x = 3n; return this.x; } }`,
    );
    expect(got).toContain('JETH380');
    expect(got).not.toContain('JETH483'); // the abstract declarer and the leaf are innocent of 483
  });
});

// ---------------------------------------------------------------------------------------------
// The INTERFACE flavor of the inherited rule (JETH483-IFACE-MIDDLE): a non-abstract MIDDLE class
// over a NATIVE INTERFACE base whose own view of the chain leaves an interface-declared obligation
// unimplemented must be abstract, even when the deployed LEAF implements it. Pre-fix the interface
// obligation (JETH385) fired only at the deployed leaf, so an implementing leaf MASKED the
// non-abstract middle (over-acceptance; solc 0.8.35 rejects 'Contract "M" should be marked as
// abstract.' - witnessed for the method flavor, the View-getter flavor, an `interface B extends A`
// union obligation, a multi-interface heritage, a diamond sibling, and a public-getter-var impl
// declared only at the leaf). Both pinned repros ACCEPTED at parent 6d94558 (proven by a
// base-compile in the fix worktree); every accept control below was proven BYTE-IDENTICAL to its
// parent-6d94558 compile at fix time.
// ---------------------------------------------------------------------------------------------
describe('JETH483 interface flavor: a non-abstract middle over an unimplemented interface obligation rejects', () => {
  it('pinned repro 1 (method flavor, leaf implements) -> exactly JETH483; solc mirror rejects', () => {
    expect(
      codes(
        `interface I { f(x: u256): u256; } class M extends I { w: u256; h(x: u256): External<u256> { this.w = x; return this.w; } } class C extends M { f(x: u256): External<u256> { this.w = x + 1n; return this.w; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `interface I { function f(uint256 x) external returns (uint256); } contract M is I { uint256 w; function h(uint256 x) external returns (uint256) { w = x; return w; } } contract C is M { function f(uint256 x) external override returns (uint256) { w = x + 1; return w; } }`,
      ),
    ).toBe(true);
  });

  it('pinned repro 2 (View-getter flavor, leaf implements via get) -> exactly JETH483; solc mirror rejects', () => {
    expect(
      codes(
        `interface I { g(): View<u256>; } class M extends I { w: u256; h(x: u256): External<u256> { this.w = x; return this.w; } } class C extends M { get g(): External<u256> { return this.w; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `interface I { function g() external view returns (uint256); } contract M is I { uint256 w; function h(uint256 x) external returns (uint256) { w = x; return w; } } contract C is M { function g() external view override returns (uint256) { return w; } }`,
      ),
    ).toBe(true);
  });

  it('iface-extends-iface UNION: the middle implements only the parent-interface part -> exactly JETH483', () => {
    expect(
      codes(
        `interface A { f(x: u256): u256; } interface B extends A { g(x: u256): u256; } class M extends B { s: u256; f(x: u256): External<u256> { this.s = x; return x; } } class C extends M { g(x: u256): External<u256> { this.s = x + 1n; return this.s; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `interface A { function f(uint256 x) external returns (uint256); } interface B is A { function g(uint256 x) external returns (uint256); } contract M is B { uint256 s; function f(uint256 x) external override returns (uint256) { s = x; return x; } } contract C is M { function g(uint256 x) external override returns (uint256) { s = x + 1; return s; } }`,
      ),
    ).toBe(true);
  });

  it('multi-interface heritage: the middle implements one of two -> exactly JETH483', () => {
    expect(
      codes(
        `interface A { f(x: u256): u256; } interface B { g(x: u256): u256; } class M extends A, B { s: u256; f(x: u256): External<u256> { this.s = x; return x; } } class C extends M { g(x: u256): External<u256> { this.s = x + 1n; return this.s; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `interface A { function f(uint256 x) external returns (uint256); } interface B { function g(uint256 x) external returns (uint256); } contract M is A, B { uint256 s; function f(uint256 x) external override returns (uint256) { s = x; return x; } } contract C is M { function g(uint256 x) external override returns (uint256) { s = x + 1; return s; } }`,
      ),
    ).toBe(true);
  });

  it('a Visible<T> getter var declared only at the LEAF does not satisfy the middle -> exactly JETH483', () => {
    expect(
      codes(
        `interface I { x(): View<u256>; } class M extends I { w: u256; h(v: u256): External<u256> { this.w = v; return this.w; } } class C extends M { x: Visible<u256>; }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `interface I { function x() external view returns (uint256); } contract M is I { uint256 w; function h(uint256 v) external returns (uint256) { w = v; return w; } } contract C is M { uint256 public x; }`,
      ),
    ).toBe(true);
  });

  it('diamond siblings over one interface: only the non-implementing sibling fires -> exactly JETH483', () => {
    expect(
      codes(
        `interface I { f(x: u256): u256; } class M extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x; } } class M2 extends I { s2: u256; } class C extends M, M2 { k(x: u256): External<u256> { this.s = x; return x; } }`,
      ),
    ).toEqual(['JETH483']);
    expect(
      solcRejects(
        `interface I { function f(uint256 x) external returns (uint256); } contract M is I { uint256 s; function f(uint256 x) external override returns (uint256) { s = x; return x; } } contract M2 is I { uint256 s2; } contract C is M, M2 { function k(uint256 x) external returns (uint256) { s = x; return x; } }`,
      ),
    ).toBe(true);
  });

  it('a deep chain: BOTH non-abstract middles above the implementing leaf fire (one JETH483 each)', () => {
    expect(
      codes(
        `interface I { f(x: u256): u256; } class M extends I { s: u256; h(x: u256): External<u256> { this.s = x; return this.s; } } class D extends M { s2: u256; } class C extends D { f(x: u256): External<u256> { this.s = x; return this.s; } }`,
      ),
    ).toEqual(['JETH483', 'JETH483']);
    expect(
      solcRejects(
        `interface I { function f(uint256 x) external returns (uint256); } contract M is I { uint256 s; function h(uint256 x) external returns (uint256) { s = x; return s; } } contract D is M { uint256 s2; } contract C is D { function f(uint256 x) external override returns (uint256) { s = x; return s; } }`,
      ),
    ).toBe(true);
  });

  it('pre-existing leaf gates unregressed: abstract middle + missing leaf stays JETH385; nobody-implements adds JETH483 for the middle', () => {
    expect(
      codes(
        `interface I { f(x: u256): u256; } abstract class M extends I { w: u256; } class C extends M { h(x: u256): External<u256> { this.w = x; return this.w; } }`,
      ),
    ).toEqual(['JETH385']);
    expect(
      codes(
        `interface I { f(x: u256): u256; } class M extends I { w: u256; } class C extends M { h(x: u256): External<u256> { this.w = x; return this.w; } }`,
      ),
    ).toEqual(['JETH385', 'JETH483']);
  });

  it('JETH481 guard: the legacy @abstract / @interface decorator spellings of these shapes stay banned', () => {
    expect(
      codes(
        `interface I { f(x: u256): u256; } @abstract class M extends I { w: u256; } class C extends M { f(x: u256): External<u256> { this.w = x; return this.w; } }`,
      ),
    ).toEqual(['JETH481']);
    expect(
      codes(
        `@interface class I { f(x: u256): u256; } class C extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x; } }`,
      ),
    ).toEqual(['JETH481']);
  });
});

describe('JETH483 interface-flavor controls: every legal shape stays accepted (and solc-runtime-equal)', () => {
  it('abstract middle + implementing leaf accepts and matches solc on distinct seeds', async () => {
    const J = `interface I { f(x: u256): u256; } abstract class M extends I { w: u256; h(x: u256): External<u256> { this.w = x; return this.w; } } class C extends M { f(x: u256): External<u256> { this.w = x + 1n; return this.w; } }`;
    const S = `interface I { function f(uint256 x) external returns (uint256); } abstract contract M is I { uint256 w; function h(uint256 x) external returns (uint256) { w = x; return w; } } contract C is M { function f(uint256 x) external override returns (uint256) { w = x + 1; return w; } }`;
    const r = await runBoth(J, S, [
      { data: sel('f(uint256)') + W(41n) },
      { data: sel('h(uint256)') + W(9n) },
    ]);
    expect(r[0]).toEqual({ success: true, returnHex: '0x' + W(42n) });
    expect(r[1]).toEqual({ success: true, returnHex: '0x' + W(9n) });
  });

  it('the P0a direct-implementation surface is untouched: class extends I + full impl accepts', () => {
    expect(
      codes(
        `interface I { f(x: u256): u256; } class C extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x + 1n; } }`,
      ),
    ).toEqual([]);
  });

  it('a non-abstract middle that implements ALL interface obligations itself accepts (solc parity)', () => {
    expect(
      codes(
        `interface I { f(x: u256): u256; } class M extends I { s: u256; f(x: u256): External<u256> { this.s = x; return x; } } class C extends M { h(x: u256): External<u256> { this.s = x; return 3n; } }`,
      ),
    ).toEqual([]);
    expect(
      solcRejects(
        `interface I { function f(uint256 x) external returns (uint256); } contract M is I { uint256 s; function f(uint256 x) external override returns (uint256) { s = x; return x; } } contract C is M { function h(uint256 x) external returns (uint256) { s = x; return 3; } }`,
      ),
    ).toBe(false);
  });

  it('a middle implementing a View obligation via `get` accepts; abstract-abstract deep chain accepts', () => {
    expect(
      codes(
        `interface I { g(): View<u256>; } class M extends I { w: u256; get g(): External<u256> { return this.w; } } class C extends M { h(x: u256): External<u256> { this.w = x; return this.w; } }`,
      ),
    ).toEqual([]);
    expect(
      codes(
        `interface I { f(x: u256): u256; } abstract class M extends I { s: u256; } abstract class D extends M { s2: u256; } class C extends D { f(x: u256): External<u256> { this.s = x; return this.s; } }`,
      ),
    ).toEqual([]);
  });

  it('iface-extends-iface: a middle implementing the WHOLE union accepts and matches solc', async () => {
    const J = `interface A { f(x: u256): u256; } interface B extends A { g(x: u256): u256; } class M extends B { s: u256; f(x: u256): External<u256> { this.s = x; return x; } g(x: u256): External<u256> { this.s = x + 1n; return this.s; } } class C extends M { k(x: u256): External<u256> { this.s = x; return 9n; } }`;
    const S = `interface A { function f(uint256 x) external returns (uint256); } interface B is A { function g(uint256 x) external returns (uint256); } contract M is B { uint256 s; function f(uint256 x) external override returns (uint256) { s = x; return x; } function g(uint256 x) external override returns (uint256) { s = x + 1; return s; } } contract C is M { function k(uint256 x) external returns (uint256) { s = x; return 9; } }`;
    const r = await runBoth(J, S, [
      { data: sel('f(uint256)') + W(5n) },
      { data: sel('g(uint256)') + W(6n) },
      { data: sel('k(uint256)') + W(7n) },
    ]);
    expect(r[1]).toEqual({ success: true, returnHex: '0x' + W(7n) });
  });

  it('a middle overridden by the leaf still satisfies the middle (its own impl counts)', () => {
    expect(
      codes(
        `interface I { f(x: u256): u256; } class M extends I { s: u256; @virtual f(x: u256): External<u256> { this.s = x; return x; } } class C extends M { @override f(x: u256): External<u256> { this.s = x; return x + 2n; } }`,
      ),
    ).toEqual([]);
  });

  it('getter-var satisfaction at the MIDDLE: @override Visible<T> and plain Visible<T> both accept (solc parity)', () => {
    expect(
      codes(
        `interface I { x(): View<u256>; } class M extends I { @override x: Visible<u256>; h(v: u256): External<void> { this.x = v; } } class C extends M { k(v: u256): External<void> { this.x = v + 1n; } }`,
      ),
    ).toEqual([]);
    expect(
      codes(
        `interface I { x(): View<u256>; } class M extends I { x: Visible<u256>; h(v: u256): External<void> { this.x = v; } } class C extends M { k(v: u256): External<void> { this.x = v + 1n; } }`,
      ),
    ).toEqual([]);
    expect(
      solcRejects(
        `interface I { function x() external view returns (uint256); } contract M is I { uint256 public x; function h(uint256 v) external { x = v; } } contract C is M { function k(uint256 v) external { x = v + 1; } }`,
      ),
    ).toBe(false);
  });
});
