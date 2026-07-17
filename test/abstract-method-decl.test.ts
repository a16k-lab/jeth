// ABSTRACT-METHOD-DECL (JETH374/375 catalogue row, lifted): the TS-native `abstract` member modifier
// on a method / `get` accessor inside an `abstract class` is a first-class native spelling of the
// bodyless @virtual declaration - `abstract f(v: u256): External<T>;` == `@virtual f(v: u256): External<T>;`.
// It feeds the SAME isVirtual flag and flows through the identical override machinery: @override
// required in the leaf (JETH374), abstract required on the declarer and on middles (JETH483),
// unimplemented-in-concrete-leaf (JETH380), the return/mutability/visibility ladders, the diamond
// @override(A, B) completeness, the getter-var (Visible<T>) override, and the receive/fallback
// special entries. Both spellings coexist (@virtual is KEEP-list and stays byte-identical).
//
// PRE-FIX CONTROL (non-vacuity): at base 8171315 every abstract-spelling accept below REJECTED with
// exactly one extra JETH375 over its @virtual twin ("overrides 'B.f', which is not @virtual" - the
// abstract modifier was consumed as a plain bodyless member, never as virtual); the get flavor came
// from a synthesis that DROPPED the modifier entirely. The JETH486 misuse family (an abstract member
// with a body / static / constructor / field / interface member) previously either accepted SILENTLY
// (ctor, field-as-state-var, interface member - each invalid TS whose grammar error lives in the
// checker, invisible to parseDiagnostics) or rejected only with incidental codes.
//
// solc 0.8.35 witnesses (re-run at fix time): bodyless virtual + leaf override ACCEPT; leaf missing
// `override` REJECT; bodyless NON-virtual REJECT ("Trying to override non-virtual function");
// concrete middle REJECT ('Contract "M" should be marked as abstract.'); diamond override(A,B)
// ACCEPT; unimplemented concrete leaf REJECT; declared-view get ACCEPT; bodyless virtual receive
// ACCEPT; public-state-var override of a bodyless virtual getter ACCEPT.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

const bc = (src: string): string => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    const err = e as { diagnostics?: { code: string }[] };
    if (err.diagnostics) return [...new Set(err.diagnostics.map((d) => d.code))];
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

/** Deploy the JETH source and its solc mirror, run `calls` on both, assert exact parity. */
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

/** Build the same source under both spellings: mk receives a wrapper that renders a member
 *  signature as either `abstract <sig>;` or `@virtual <sig>;`. */
type Spelled = (sig: string) => string;
const ABS: Spelled = (sig) => `abstract ${sig};`;
const VIRT: Spelled = (sig) => `@virtual ${sig};`;
const identical = (mk: (d: Spelled) => string): void => {
  expect(bc(mk(ABS)), 'abstract spelling must be byte-identical to the @virtual twin').toBe(bc(mk(VIRT)));
};

describe('ABSTRACT-METHOD-DECL: `abstract` member == bodyless @virtual, byte-identical twins', () => {
  it('method flavor: External<u256> / External<void> / Payable<u256> / string / internal bare', () => {
    identical((d) => `
      abstract class B { ${d('f(v: u256): External<u256>')} }
      class C extends B { x: u256; @override f(v: u256): External<u256> { this.x = v; return this.x + 1n; } }`);
    identical((d) => `
      abstract class B { ${d('f(v: u256): External<void>')} }
      class C extends B { x: u256; @override f(v: u256): External<void> { this.x = v * 3n; } }`);
    identical((d) => `
      abstract class B { ${d('f(v: u256): Payable<u256>')} }
      class C extends B { x: u256; @override f(v: u256): Payable<u256> { this.x = v + msg.value; return this.x; } }`);
    identical((d) => `
      abstract class B { ${d('f(s: string): External<string>')} }
      class C extends B { t: string; @override f(s: string): External<string> { this.t = s; return this.t; } }`);
    // internal virtual (bare return type): solc's `function f(...) internal virtual returns (...);`
    identical((d) => `
      abstract class B { ${d('f(v: u256): u256')} }
      class C extends B { x: u256; @override f(v: u256): u256 { return v * 2n; } h(v: u256): External<u256> { this.x = this.f(v); return this.x; } }`);
  });

  it('get flavor: External<u256> / declared View<u256> headroom / declared Pure<u256>', () => {
    identical((d) => `
      abstract class B { ${d('get g(): External<u256>')} }
      class C extends B { x: u256; h(v: u256): External<void> { this.x = v; } @override get g(): External<u256> { return this.x; } }`);
    identical((d) => `
      abstract class B { ${d('get g(): External<u256>')} }
      class C extends B { x: u256; h(v: u256): External<void> { this.x = v; } @override get g(): External<u256> { return this.x; } }`);
    identical((d) => `
      abstract class B { ${d('get g(): External<u256>')} }
      class C extends B { @override get g(): External<u256> { return 41n + 1n; } x: u256; h(v: u256): External<void> { this.x = v; } }`);
  });

  it('chain shapes: abstract middle, bodyless-over-bodyless redeclare, diamond @override(A,B)', () => {
    identical((d) => `
      abstract class A { ${d('f(v: u256): External<u256>')} }
      abstract class M extends A { }
      class C extends M { x: u256; @override f(v: u256): External<u256> { this.x = v; return this.x + 7n; } }`);
    identical((d) => `
      abstract class A { ${d('f(v: u256): External<u256>')} }
      abstract class M extends A { @override ${d('f(v: u256): External<u256>')} }
      class C extends M { x: u256; @override f(v: u256): External<u256> { this.x = v; return this.x + 9n; } }`);
    identical((d) => `
      abstract class A { ${d('f(v: u256): External<u256>')} }
      abstract class B { ${d('f(v: u256): External<u256>')} }
      class C extends A, B { x: u256; @override(A, B) f(v: u256): External<u256> { this.x = v; return this.x + 3n; } }`);
  });

  it('getter-var (Visible<T>) override of an abstract get + receive/fallback special entries', () => {
    identical((d) => `
      abstract class B { ${d('get g(): External<u256>')} }
      class C extends B { @override g: Visible<u256>; h(v: u256): External<void> { this.g = v; } }`);
    identical((d) => `
      abstract class B { ${d('receive(): void')} }
      class C extends B { count: u256; @override receive(): void { this.count = msg.value + 40n; } get g(): External<u256> { return this.count; } }`);
    identical((d) => `
      abstract class B { ${d('fallback(): void')} }
      class C extends B { count: u256; @override fallback(): void { this.count = 55n; } get g(): External<u256> { return this.count; } }`);
  });

  it('both spellings coexist across one chain (abstract base + @virtual @override middle w/ body)', () => {
    identical((d) => `
      abstract class A { ${d('f(v: u256): External<u256>')} }
      abstract class M extends A { y: u256; @virtual @override f(v: u256): External<u256> { this.y = v; return this.y + 1n; } }
      class C extends M { x: u256; @override f(v: u256): External<u256> { this.x = v; return this.x + 2n; } }`);
  });
});

describe('ABSTRACT-METHOD-DECL: runtime differential vs the solc mirror (distinct seeds, run+decode)', () => {
  it('abstract method: leaf override runs byte-equal to solc', async () => {
    const rs = await runBoth(
      `abstract class B { abstract f(v: u256): External<u256>; }
       class C extends B { x: u256; @override f(v: u256): External<u256> { this.x = v; return this.x + 1n; } }`,
      `abstract contract B { function f(uint256 v) external virtual returns (uint256); }
       contract C is B { uint256 x; function f(uint256 v) external override returns (uint256) { x = v; return x + 1; } }`,
      [
        { data: sel('f(uint256)') + W(41n) },
        { data: sel('f(uint256)') + W(1000003n) },
      ],
    );
    expect(rs[0]!.returnHex).toBe('0x' + W(42n)); // non-vacuous: seeded value read back
    expect(rs[1]!.returnHex).toBe('0x' + W(1000004n));
  });

  it('abstract get with declared View<T>: seeded state read back equal to solc', async () => {
    const rs = await runBoth(
      `abstract class B { abstract get g(): External<u256>; }
       class C extends B { x: u256; h(v: u256): External<void> { this.x = v; } @override get g(): External<u256> { return this.x; } }`,
      `abstract contract B { function g() external view virtual returns (uint256); }
       contract C is B { uint256 x; function h(uint256 v) external { x = v; } function g() external view override returns (uint256) { return x; } }`,
      [
        { data: sel('g()') },
        { data: sel('h(uint256)') + W(777n) },
        { data: sel('g()') },
      ],
    );
    expect(rs[0]!.returnHex).toBe('0x' + W(0n));
    expect(rs[2]!.returnHex).toBe('0x' + W(777n)); // non-vacuous
  });

  it('diamond: two abstract declarers + @override(A, B) leaf, equal to solc', async () => {
    const rs = await runBoth(
      `abstract class A { abstract f(v: u256): External<u256>; }
       abstract class B { abstract f(v: u256): External<u256>; }
       class C extends A, B { x: u256; @override(A, B) f(v: u256): External<u256> { this.x = v; return this.x + 3n; } }`,
      `abstract contract A { function f(uint256 v) external virtual returns (uint256); }
       abstract contract B { function f(uint256 v) external virtual returns (uint256); }
       contract C is A, B { uint256 x; function f(uint256 v) external override(A, B) returns (uint256) { x = v; return x + 3; } }`,
      [
        { data: sel('f(uint256)') + W(5n) },
        { data: sel('f(uint256)') + W(123456789n) },
      ],
    );
    expect(rs[0]!.returnHex).toBe('0x' + W(8n));
    expect(rs[1]!.returnHex).toBe('0x' + W(123456792n));
  });

  it('abstract receive: value-carrying plain transfer lands in the leaf override, equal to solc', async () => {
    const J = `abstract class B { abstract receive(): void; }
      class C extends B { count: u256; @override receive(): void { this.count = msg.value + 40n; } get g(): External<u256> { return this.count; } }`;
    const S = `abstract contract B { receive() external payable virtual; }
      contract C is B { uint256 count; receive() external payable override { count = msg.value + 40; } function g() external view returns (uint256) { return count; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const rj = await h.call(aj, '0x', { value: 2n });
    const rs = await h.call(as, '0x', { value: 2n });
    expect(rj.success).toBe(rs.success);
    const gj = await h.call(aj, '0x' + sel('g()'));
    const gs = await h.call(as, '0x' + sel('g()'));
    expect(gj.returnHex).toBe(gs.returnHex);
    expect(gj.returnHex).toBe('0x' + W(42n)); // non-vacuous: msg.value + 40
  });
});

describe('ABSTRACT-METHOD-DECL: override machinery applies to the abstract spelling (exact codes)', () => {
  it('leaf missing @override -> exactly JETH374 (same as the @virtual twin); solc mirror rejects', () => {
    const mk = (d: Spelled) => `
      abstract class B { ${d('f(v: u256): External<u256>')} }
      class C extends B { x: u256; f(v: u256): External<u256> { this.x = v; return this.x + 1n; } }`;
    expect(codes(mk(ABS))).toEqual(['JETH374']);
    expect(codes(mk(ABS))).toEqual(codes(mk(VIRT)));
    expect(
      solcRejects(
        `abstract contract B { function f(uint256 v) external virtual returns (uint256); }
         contract C is B { uint256 x; function f(uint256 v) external returns (uint256) { x = v; return x + 1; } }`,
      ),
    ).toBe(true);
  });

  it('abstract member in a NON-abstract class -> JETH483 (declarer rule), twin-equal', () => {
    const mk = (d: Spelled) => `
      class B { ${d('f(v: u256): External<u256>')} }
      class C extends B { x: u256; @override f(v: u256): External<u256> { this.x = v; return this.x + 1n; } }`;
    expect(codes(mk(ABS))).toEqual(['JETH483']);
    expect(codes(mk(ABS))).toEqual(codes(mk(VIRT)));
  });

  it('concrete MIDDLE inheriting an unimplemented abstract -> JETH483, twin-equal; solc rejects', () => {
    const mk = (d: Spelled) => `
      abstract class A { ${d('f(v: u256): External<u256>')} }
      class M extends A { }
      class C extends M { x: u256; @override f(v: u256): External<u256> { this.x = v; return this.x + 1n; } }`;
    expect(codes(mk(ABS))).toEqual(['JETH483']);
    expect(codes(mk(ABS))).toEqual(codes(mk(VIRT)));
    expect(
      solcRejects(
        `abstract contract A { function f(uint256 v) external virtual returns (uint256); }
         contract M is A { }
         contract C is M { uint256 x; function f(uint256 v) external override returns (uint256) { x = v; return x + 1; } }`,
      ),
    ).toBe(true);
  });

  it('unimplemented abstract + concrete leaf -> JETH380 (twin-equal); solc rejects', () => {
    const mk = (d: Spelled) => `
      abstract class B { ${d('f(v: u256): External<u256>')} }
      class C extends B { y: u256; h(v: u256): External<void> { this.y = v; } }`;
    expect(codes(mk(ABS))).toContain('JETH380');
    expect(codes(mk(ABS))).toEqual(codes(mk(VIRT)));
    expect(
      solcRejects(
        `abstract contract B { function f(uint256 v) external virtual returns (uint256); }
         contract C is B { uint256 y; function h(uint256 v) external { y = v; } }`,
      ),
    ).toBe(true);
  });

  it('override changing the return type -> JETH377, twin-equal', () => {
    const mk = (d: Spelled) => `
      abstract class B { ${d('f(v: u256): External<u256>')} }
      class C extends B { x: u256; @override f(v: u256): External<void> { this.x = v; } }`;
    expect(codes(mk(ABS))).toEqual(['JETH377']);
    expect(codes(mk(ABS))).toEqual(codes(mk(VIRT)));
  });

  it('PRE-FIX PIN (non-vacuity): a bodyless NON-virtual member still rejects JETH375 - the code the abstract spelling used to trip', () => {
    // At base 8171315 the abstract spelling itself rejected with this exact extra code; post-lift
    // only the genuinely non-virtual bodyless member does. solc mirror: "Trying to override
    // non-virtual function."
    expect(
      codes(`
      abstract class B { f(v: u256): External<u256>; }
      class C extends B { x: u256; @override f(v: u256): External<u256> { this.x = v; return this.x + 1n; } }`),
    ).toEqual(['JETH375']);
    expect(
      solcRejects(
        `abstract contract B { function f(uint256 v) external returns (uint256); }
         contract C is B { uint256 x; function f(uint256 v) external override returns (uint256) { x = v; return x + 1; } }`,
      ),
    ).toBe(true);
  });
});

describe('JETH486: `abstract` misuse rejects loudly (each shape is invalid TS with no parse diagnostic)', () => {
  it('an abstract member WITH a body -> JETH486 (was an incidental-codes reject pre-fix)', () => {
    expect(
      codes(`
      abstract class B { abstract f(v: u256): External<u256> { return 1n; } }
      class C extends B { x: u256; @override f(v: u256): External<u256> { this.x = v; return this.x + 1n; } }`),
    ).toContain('JETH486');
    // the get flavor with a body
    expect(
      codes(`
      abstract class B { abstract get g(): External<u256> { return 1n; } }
      class C extends B { @override get g(): External<u256> { return 2n; } x: u256; h(v: u256): External<void> { this.x = v; } }`),
    ).toContain('JETH486');
  });

  it('static abstract -> JETH486 (TS forbids the combination)', () => {
    expect(codes(`abstract class B { static abstract f(): u256; } class C extends B { x: u256; h(v: u256): External<void> { this.x = v; } }`)).toContain('JETH486');
  });

  it('abstract constructor -> JETH486 (pre-fix: accepted SILENTLY)', () => {
    expect(
      codes(`abstract class B { abstract constructor(); } class C extends B { x: u256; f(v: u256): External<void> { this.x = v; } }`),
    ).toEqual(['JETH486']);
  });

  it('abstract FIELD -> JETH486 (pre-fix: silently became a plain state variable)', () => {
    expect(
      codes(`abstract class B { abstract x: u256; } class C extends B { y: u256; f(v: u256): External<void> { this.y = v; } }`),
    ).toEqual(['JETH486']);
  });

  it('abstract on an interface member -> JETH486 (pre-fix: the modifier was silently eaten)', () => {
    expect(
      codes(`interface I { abstract f(v: u256): u256; } class C extends I { x: u256; @override f(v: u256): External<u256> { this.x = v; return v; } }`),
    ).toEqual(['JETH486']);
  });

  it('guards stay intact: abstract async -> JETH020; stray const/declare members keep JETH485', () => {
    expect(
      codes(`abstract class B { abstract async f(v: u256): External<void>; } class C extends B { x: u256; @override f(v: u256): External<void> { this.x = v; } }`),
    ).toContain('JETH020');
    expect(codes(`class C { declare x: u256; f(v: u256): External<void> { this.x = v; } }`)).toContain('JETH485');
  });
});
