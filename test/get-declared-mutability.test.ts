// GET-MUT-HEADROOM: `View<T>` / `Pure<T>` as the return marker of a CONTRACT `get` accessor DECLARE its
// mutability, exactly solc's explicit `view`/`pure` keywords. The DECLARED value (not the body inference)
// anchors the override ladder (JETH378) and the ABI stateMutability, so a base `@virtual get f(): View<u256>`
// with a pure body keeps view HEADROOM for a state-reading override - solc accepts a view override of a
// declared-view virtual, where the inferred-pure base rejects it. The body may be STRICTER than declared
// (a pure body under View<T> is fine, ABI says view - solc parity); a LOOSER body rejects via the
// declared-mutability checks (JETH054 view-writes / JETH055+JETH164 pure-reads), matching solc's
// "declared view/pure but this expression ..." TypeErrors. The markers stay GET-ONLY: a plain method,
// field, special entry, or library keeps its existing reject, and the interface marker surface is untouched.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const mut = (src: string): Record<string, string> => {
  const abi = compile(src, { fileName: 'C.jeth' }).abi as { type: string; name?: string; stateMutability?: string }[];
  return Object.fromEntries(abi.filter((e) => e.type === 'function').map((f) => [f.name!, f.stateMutability!]));
};
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};
const runBoth = async (J: string, S: string, calls: [string, string][]): Promise<void> => {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, args] of calls) {
    const rj = await h.call(aj, sel(sg) + args);
    const rs = await h.call(as, sel(sg) + args);
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
  }
};

describe('declared-mutability get accessors (GET-MUT-HEADROOM)', () => {
  it('HEADROOM: a declared-View virtual base with a pure body accepts a state-reading override (solc parity)', async () => {
    const J = `
      class B { @virtual get f(): View<u256> { return 1n; } }
      class C extends B {
        x: u256 = 7n;
        set(v: u256): External<void> { this.x = v; }
        @override get f(): External<u256> { return this.x; }
      }`;
    const S = `
      contract B { function f() external view virtual returns (uint256) { return 1; } }
      contract C is B {
        uint256 x = 7;
        function set(uint256 v) external { x = v; }
        function f() external view override returns (uint256) { return x; }
      }`;
    // distinct seeds: the initializer (7), then a written 4242 - the getter must decode BOTH
    await runBoth(J, S, [['f()', ''], ['set(uint256)', W(4242)], ['f()', '']]);
  });

  it('CONTROL (non-vacuity): the SAME shape with an inferred-pure base (External<T>) still rejects JETH378', () => {
    // pre-fix, the headroom was inexpressible: the ONLY base spelling inferred pure and the ladder
    // rejected the view override. The lift opens it exclusively via the DECLARED marker.
    expect(codes(`
      class B { @virtual get f(): External<u256> { return 1n; } }
      class C extends B { x: u256 = 7n; @override get f(): External<u256> { return this.x; } }`)).toContain('JETH378');
    // and the declared spelling compiles clean (the pre-fix behavior - JETH013 unknown type - flipped)
    expect(codes(`
      class B { @virtual get f(): View<u256> { return 1n; } }
      class C extends B { x: u256 = 7n; @override get f(): External<u256> { return this.x; } }`)).toEqual([]);
  });

  it('NEUTRALITY: declared == inferred -> byte-identical to the External<T> spelling (view and pure)', () => {
    // declared view + view body === inferred view
    expect(bc(`class C { x: u256 = 7n; get f(): View<u256> { return this.x; } }`))
      .toBe(bc(`class C { x: u256 = 7n; get f(): External<u256> { return this.x; } }`));
    // declared pure + pure body === inferred pure
    expect(bc(`class C { get f(): Pure<u256> { return 41n + 1n; } }`))
      .toBe(bc(`class C { get f(): External<u256> { return 41n + 1n; } }`));
    // declared view + PURE body (stricter body is fine) === same bytes (mutability is codegen-neutral)
    expect(bc(`class C { get f(): View<u256> { return 42n; } }`))
      .toBe(bc(`class C { get f(): External<u256> { return 42n; } }`));
  });

  it('ABI: the DECLARED mutability is the stateMutability - a pure body under View<T> says view (solc parity)', () => {
    expect(mut(`class C { get f(): View<u256> { return 42n; } }`)).toEqual({ f: 'view' });
    expect(mut(`class C { get f(): Pure<u256> { return 42n; } }`)).toEqual({ f: 'pure' });
    expect(mut(`class C { x: u256 = 7n; get f(): View<u256> { return this.x; } }`)).toEqual({ f: 'view' });
  });

  it('runs byte-equal to solc: parameterized declared-view get (mapping) + tuple-return declared-view get', async () => {
    await runBoth(
      `class C {
        m: mapping<u256, u256>;
        set(k: u256, v: u256): External<void> { this.m[k] = v; }
        get at(k: u256): View<u256> { return this.m[k]; }
      }`,
      `contract C {
        mapping(uint256 => uint256) m;
        function set(uint256 k, uint256 v) external { m[k] = v; }
        function at(uint256 k) external view returns (uint256) { return m[k]; }
      }`,
      [['set(uint256,uint256)', W(3) + W(1234)], ['at(uint256)', W(3)], ['at(uint256)', W(4)]],
    );
    await runBoth(
      `class C { x: u256 = 5n; get pair(): View<[u256, bool]> { return [this.x, true]; } }`,
      `contract C { uint256 x = 5; function pair() external view returns (uint256, bool) { return (x, true); } }`,
      [['pair()', '']],
    );
  });
});

describe('the override ladder anchors on the DECLARED mutability (witnessed vs solc 0.8.35)', () => {
  const baseView = `class B { @virtual get f(): View<u256> { return 1n; } }`;
  const basePure = `class B { @virtual get f(): Pure<u256> { return 1n; } }`;

  it('declared-View base + {declared-View, inferred-pure, declared-Pure} overrides accept and run vs solc', async () => {
    // declared-View override (solc: view virtual + view override)
    await runBoth(
      baseView + ` class C extends B { x: u256 = 9n; @override get f(): View<u256> { return this.x; } }`,
      `contract B { function f() external view virtual returns (uint256) { return 1; } }
       contract C is B { uint256 x = 9; function f() external view override returns (uint256) { return x; } }`,
      [['f()', '']],
    );
    // inferred-pure override tightens (solc: view virtual + pure override)
    await runBoth(
      baseView + ` class C extends B { @override get f(): External<u256> { return 5n; } }`,
      `contract B { function f() external view virtual returns (uint256) { return 1; } }
       contract C is B { function f() external pure override returns (uint256) { return 5; } }`,
      [['f()', '']],
    );
    // declared-Pure override tightens too
    expect(codes(baseView + ` class C extends B { @override get f(): Pure<u256> { return 5n; } }`)).toEqual([]);
  });

  it('a WRITER override of a declared-View base rejects JETH378 (solc: "view" -> "nonpayable" TypeError)', () => {
    expect(codes(baseView + ` class C extends B { x: u256; @override f(): External<u256> { this.x = 2n; return this.x; } }`))
      .toContain('JETH378');
  });

  it('a declared-Pure base rejects a view override - inferred OR declared (solc: "pure" -> "view" TypeError)', () => {
    expect(codes(basePure + ` class C extends B { x: u256 = 7n; @override get f(): External<u256> { return this.x; } }`))
      .toContain('JETH378');
    expect(codes(basePure + ` class C extends B { x: u256 = 7n; @override get f(): View<u256> { return this.x; } }`))
      .toContain('JETH378');
    // pure-on-pure stays accepted
    expect(codes(basePure + ` class C extends B { @override get f(): External<u256> { return 5n; } }`)).toEqual([]);
  });

  it('a BODYLESS @virtual declared-View get in an abstract base takes a view implementation (solc parity)', async () => {
    await runBoth(
      `abstract class B { @virtual get f(): View<u256>; }
       class C extends B { x: u256 = 7n; @override get f(): External<u256> { return this.x; } }`,
      `abstract contract B { function f() external view virtual returns (uint256); }
       contract C is B { uint256 x = 7; function f() external view override returns (uint256) { return x; } }`,
      [['f()', '']],
    );
  });

  it('interface ladder: a declared-View impl of a Pure interface method rejects JETH387; declared-Pure impl of a View method tightens', () => {
    expect(codes(`interface I { f(): Pure<u256>; }
      class C extends I { x: u256 = 7n; get f(): View<u256> { return this.x; } }`)).toContain('JETH387');
    expect(codes(`interface I { f(): View<u256>; }
      class C extends I { get f(): Pure<u256> { return 5n; } }`)).toEqual([]);
  });

  it('getter-var interplay: a Visible<T> field overrides a declared-View virtual get (solc: public var override) but never a declared-Pure one', () => {
    expect(codes(`abstract class B { @virtual get f(): View<u256>; }
      class C extends B { @override f: Visible<u256> = 7n; }`)).toEqual([]);
    expect(codes(`abstract class B { @virtual get f(): Pure<u256>; }
      class C extends B { @override f: Visible<u256> = 7n; }`)).toContain('JETH433');
  });
});

describe('a LOOSER body than declared rejects (solc "declared view/pure but ..." TypeErrors)', () => {
  it('View<T> + a WRITING body rejects JETH054 (a declared-view get is read-only by construction)', () => {
    expect(codes(`class C { x: u256; get f(): View<u256> { this.x = 1n; return this.x; } }`)).toContain('JETH054');
  });
  it('Pure<T> + a state-READING body rejects JETH055; + an env read rejects JETH164', () => {
    expect(codes(`class C { x: u256 = 7n; get f(): Pure<u256> { return this.x; } }`)).toContain('JETH055');
    expect(codes(`class C { get f(): Pure<address> { return msg.sender; } }`)).toContain('JETH164');
  });
});

describe('the markers stay GET-ONLY (scope guards)', () => {
  it('a plain (non-get) method with View<T>/Pure<T> keeps the existing unknown-type reject (JETH013)', () => {
    expect(codes(`class C { f(): View<u256> { return 1n; } }`)).toContain('JETH013');
    expect(codes(`class C { f(): Pure<u256> { return 1n; } }`)).toContain('JETH013');
  });
  it('a field with View<T>/Pure<T> keeps JETH482 (Visible<T> owns fields)', () => {
    expect(codes(`class C { x: View<u256>; }`)).toContain('JETH482');
    expect(codes(`class C { x: Pure<u256>; }`)).toContain('JETH482');
  });
  it('a #-private get with a declared marker is the External<T> contradiction (JETH352)', () => {
    expect(codes(`class C { get #f(): View<u256> { return 1n; } }`)).toContain('JETH352');
    expect(codes(`class C { get #f(): Pure<u256> { return 1n; } }`)).toContain('JETH352');
  });
  it('@nonReentrant on a declared get rejects at collection (JETH260): the guard TSTOREs while the ABI claims view/pure', () => {
    expect(codes(`class C { x: u256 = 7n; @nonReentrant get f(): View<u256> { return this.x; } }`)).toContain('JETH260');
    expect(codes(`class C { @nonReentrant get f(): Pure<u256> { return 1n; } }`)).toContain('JETH260');
  });
  it('marker arity is enforced like External<T> (JETH352)', () => {
    expect(codes(`class C { get f(): View { return 1n; } }`)).toContain('JETH352');
    expect(codes(`class C { get f(): View<u256, u256> { return 1n; } }`)).toContain('JETH352');
  });
  it('a Payable<T> get stays the read-only contradiction (JETH352); special entries and interfaces are untouched', () => {
    expect(codes(`class C { get f(): Payable<u256> { return 1n; } }`)).toContain('JETH352');
    // receive/fallback special entries never take the declared markers
    expect(codes(`class C { receive(): View<void> {} }`)).toContain('JETH384');
    // the interface marker surface still works (per-method mutability markers, not the get form)
    expect(codes(`interface I { f(): View<u256>; }
      class C extends I { x: u256 = 1n; get f(): External<u256> { return this.x; } }`)).toEqual([]);
  });
});
