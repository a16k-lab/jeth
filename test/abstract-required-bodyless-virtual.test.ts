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
