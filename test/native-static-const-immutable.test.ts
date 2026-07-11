// Item #7: in NATIVE mode a `static` contract field is the native spelling of a compile-time @constant
// (when it carries an initializer) or a constructor-set @immutable (when it does not). It routes through the
// exact same collectConstant/collectImmutable path, so it is byte-identical to the decorated form and to
// solc's `constant`/`immutable` (no storage slot; a const read is pure, an immutable read is view).
// Idiomatic TS reads a static member as `ClassName.K`; a pre-pass (compile.ts rewriteStaticFieldAccess)
// rewrites `C.K` -> `this.K`, so both `C.K` (IDE-clean) and `this.K` work.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const compiled = (src: string) => compile(src, { fileName: 'C.jeth' });
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

describe('static = constant / immutable (item #7)', () => {
  it('a static const is byte-identical to @constant (pure read, no slot); static immutable to @immutable', () => {
    expect(bc(`class C { static K: u256 = 5n; get calc(a: u256): External<u256> { return a + C.K; } }`))
      .toBe(bc(`class C { static K: u256 = 5n; get calc(a: u256): External<u256> { return a + this.K; } }`));
    expect(bc(`class C { static M: u256; constructor(){ this.M = 7n; } get getM(): External<u256> { return C.M; } }`))
      .toBe(bc(`class C { static M: u256; constructor(){ this.M = 7n; } get getM(): External<u256> { return this.M; } }`));
    // no storage slot for either; a const read infers pure, an immutable read infers view.
    const rC = compiled(`class C { static K: u256 = 5n; get readK(): External<u256> { return C.K; } }`);
    expect(rC.storageLayout).toEqual([]);
    expect(rC.abi.filter((f: any) => f.type === 'function').map((f: any) => f.stateMutability)).toEqual(['pure']);
    const rM = compiled(`class C { static M: u256; constructor(){ this.M = 7n; } get readM(): External<u256> { return C.M; } }`);
    expect(rM.storageLayout).toEqual([]);
    expect(rM.abi.filter((f: any) => f.type === 'function').map((f: any) => f.stateMutability)).toEqual(['view']);
  });

  it('`C.K` and `this.K` both resolve to the constant, byte-identically', () => {
    expect(bc(`class C { static K: u256 = 5n; get f(a: u256): External<u256> { return a + C.K; } }`))
      .toBe(bc(`class C { static K: u256 = 5n; get f(a: u256): External<u256> { return a + this.K; } }`));
  });

  it('a static const + immutable contract runs byte-identical to solc (via idiomatic `C.K`)', async () => {
    const J = `class C {
      static K: u256 = 100n;
      static M: u256;
      constructor(){ this.M = 42n; }
      get kk(): External<u256> { return C.K; }
      get mm(): External<u256> { return C.M; }
      get calc(a: u256): External<u256> { return a + C.K + C.M; } }`;
    const S = `contract C {
      uint256 constant K = 100;
      uint256 immutable M;
      constructor(){ M = 42; }
      function kk() external pure returns(uint256){ return K; }
      function mm() external view returns(uint256){ return M; }
      function calc(uint256 a) external view returns(uint256){ return a + K + M; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['kk()', ''], ['mm()', ''], ['calc(uint256)', pad32(5n)]] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('`@external` on a static const exposes the public-constant getter, like @external @constant', () => {
    expect(bc(`class C { static K: Visible<u256> = 5n; }`)).toBe(bc(`class C { static K: Visible<u256> = 5n; }`));
    expect(compiled(`class C { static K: Visible<u256> = 5n; }`).abi.filter((f: any) => f.type === 'function').map((f: any) => f.name)).toEqual(['K']);
  });

  it('rejects: a static field with no type annotation; the decorator pragma is banned', () => {
    expect(codes(`class C { static K = 5n; get f(): External<u256> { return C.K; } }`)).toContain('JETH045'); // needs a type
    // decorator mode was removed in stage 2; a `// use @decorators` file now hard-rejects (JETH480).
    expect(codes(`// use @decorators\nclass C { static K: u256 = 5n; get f(): External<u256> { return 1n; } }`)).toContain('JETH480');
  });

  it('the C.K rewrite is scope-safe: a local/param shadowing the contract reads the LOCAL field, not the constant', async () => {
    // sweep finding (silent miscompile): a param/local named like the contract must win over the static const.
    const J = `type P = { K: u256 }; class C { static K: u256 = 999n; get f(C: P): External<u256> { return C.K; } }`;
    const h = await Harness.create();
    const a = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const r = await h.call(a, sel('f((uint256))') + pad32(7n));
    expect(BigInt(r.returnHex)).toBe(7n); // the param's field, NOT the constant 999
  });

  it('a member access on a non-contract `type` does not hijack a same-named contract member', () => {
    // sweep finding: harvesting static names from non-contract classes poisoned the rewrite map. Natively a
    // `type` struct has no statics to harvest, so `S.count` cannot bind the contract's own `count` field -
    // it rejects (JETH074) instead of silently reading the contract's slot.
    expect(codes(`type S = { count: u256; x: u256 }; class C { count: u256; get foo(): External<u256> { return S.count; } }`)).toContain('JETH074');
  });
});

// Static METHODS: a `static` method / `get` is a CLASS-level function - no `this` (enforced), called as
// `ClassName.f(args)`, composing with the get/#/External axes like any method. Mutability is inferred as
// usual (no `this` -> typically pure; an env read still makes it view - static is no-instance, not
// blanket-pure). Byte-identical to the equivalent internal/external function + solc.
describe('static methods (class-level functions)', () => {
  it('the full matrix: static method / static get / static #method / static get External<T>', () => {
    // internal class fn, called C.f(...)
    expect(codes(`class C { static dbl(a: u256): u256 { return a * 2n; } get d(): External<u256> { return C.dbl(21n); } }`)).toEqual([]);
    // internal read-only class fn (static get)
    expect(codes(`class C { static get two(): u256 { return 2n; } get d(): External<u256> { return C.two(); } }`)).toEqual([]);
    // PRIVATE class fn (static #f)
    expect(codes(`class C { static #half(a: u256): u256 { return a / 2n; } get d(): External<u256> { return C.#half(84n); } }`)).toEqual([]);
    // EXTERNAL pure accessor (static get f(): External<T>) - in the ABI
    const abi = compile(`class C { static get two(): External<u256> { return 2n; } }`, { fileName: 'C.jeth' }).abi as any[];
    expect(abi.filter((f) => f.type === 'function').map((f) => f.name + ':' + f.stateMutability)).toEqual(['two:pure']);
  });

  it('no `this` in a static body (JETH354); statics chain via ClassName.x; env reads infer view', () => {
    expect(codes(`class C { x: u256; static bad(): u256 { return this.x; } get d(): External<u256> { return C.bad(); } }`)).toContain('JETH354');
    // a static may call another static and read a static const via ClassName.x
    expect(codes(`class C { static K: u256 = 10n; static f(a: u256): u256 { return C.g(a) + C.K; } static g(a: u256): u256 { return a * 2n; } get d(): External<u256> { return C.f(5n); } }`)).toEqual([]);
    // static = no-instance, NOT blanket-pure: an env read makes it view.
    const abi = compile(`class C { static who(): address { return msg.sender; } get w(): External<address> { return C.who(); } }`, { fileName: 'C.jeth' }).abi as any[];
    expect(abi.filter((f) => f.type === 'function').map((f) => f.stateMutability)).toEqual(['view']);
    // the immutable ctor-staging `this.M = ...` is a CONSTRUCTOR (not static) - unaffected.
    expect(codes(`class C { static M: u256; constructor(){ this.M = 7n; } get m(): External<u256> { return C.M; } }`)).toEqual([]);
  });

  it('a static helper contract runs byte-identical to solc (constant + internal pure fn)', async () => {
    const J = `class C { static FEE: u256 = 100n; static feeOn(amt: u256): u256 { return amt * C.FEE / 10000n; } get quote(a: u256): External<u256> { return C.feeOn(a); } }`;
    const S = `contract C { uint256 constant FEE = 100; function feeOn(uint256 amt) internal pure returns(uint256){ return amt * FEE / 10000; } function quote(uint256 a) external pure returns(uint256){ return feeOn(a); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const rj = await h.call(aj, sel('quote(uint256)') + pad32(50000n));
    const rs = await h.call(as, sel('quote(uint256)') + pad32(50000n));
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
  });
});

// The ClassName.K rewrite is SITE-AWARE: `C.K` rewrites to `this.K` only when C is the access site's own
// class or one of its transitive extends ancestors AND K is a static of C's chain. Previously the rewrite
// unioned every contract-shaped class file-wide, so `B.K` on an UNRELATED class silently bound the site
// chain's same-named K (wrong value, 1 instead of a reject); solc rejects the twin ('Member "K" not found
// or not visible ... in type(contract B)'). Surfaced by the v3 multi-file sweep, but single-file too.
describe('static qualifier chain-scoping (the B.K wrong-binding fix)', () => {
  const codes2 = (src: string): string[] => {
    try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e.diagnostics.map((d: any) => d.code); }
  };
  it('an out-of-chain qualifier rejects instead of binding the chain K (solc parity)', () => {
    expect(codes2(`abstract class A { static K: u256 = 1n; }\nabstract class B { static K: u256 = 2n; }\nclass V extends A { get f(): External<u256> { return B.K; } }`).length).toBeGreaterThan(0);
    // the v3 shape that surfaced it: two same-named dep bases, the non-extended one's K must not leak.
    const d = (src: string, sources: Record<string, string>) => {
      try { compile(src, { fileName: 'v.jeth', sources }); return []; } catch (e: any) { return e.diagnostics.map((x: any) => x.code); }
    };
    expect(d(`import { Base as B1 } from "./a.jeth";\nimport { Base as B2 } from "./b.jeth";\nclass V extends B1 { get f(): External<u256> { return B2.K; } }`,
      { 'a.jeth': `export abstract class Base { static K: u256 = 1n; }`, 'b.jeth': `export abstract class Base { static K: u256 = 2n; }` }).length).toBeGreaterThan(0);
  });
  it('every in-chain spelling keeps working: own, ancestor, inherited-through-derived, static init', async () => {
    const r = compiled(`abstract class Base { static K: u256 = 40n; static two(): u256 { return 2n; } }\nclass C extends Base { static OWN: u256 = 100n; get f(): External<u256> { return Base.K + C.OWN + C.K + Base.two(); } }`);
    const h = await Harness.create();
    const a = await h.deploy(r.creationBytecode);
    expect(BigInt((await h.call(a, sel('f()'))).returnHex)).toBe(182n);
    const r2 = compiled(`class C { static A: u256 = 5n; static B: u256 = C.A + 1n; get f(): External<u256> { return C.B; } }`);
    const a2 = await h.deploy(r2.creationBytecode);
    expect(BigInt((await h.call(a2, sel('f()'))).returnHex)).toBe(6n);
  });
});
