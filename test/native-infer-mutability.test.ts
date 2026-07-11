// Item #8: in NATIVE mode a function's Solidity mutability is INFERRED from its body when no explicit
// @view/@pure/@payable is written - writes -> nonpayable, reads-only (state or env / STATICCALL) -> view,
// neither -> pure. Inference is codegen-neutral (view/pure/nonpayable emit identical bytecode; only
// @payable differs), so it only sets the ABI stateMutability - to match an idiomatic solc contract that
// DECLARES the tightest mutability. A TS `get foo(): T { ... }` is an argless external read-only accessor
// (un-bans getters), byte-identical to `@external @view foo(): T { ... }`; a writing getter rejects.
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

describe('native mutability inference (item #8)', () => {
  it('infers view / pure / nonpayable from the body (incl. transitively through internal calls)', () => {
    expect(mut(`class C {
      x: u256;
      get readsX(): External<u256> { return this.x; }
      get pureFn(a: u256): External<u256> { return a + 1n; }
      writesX(v: u256): External<void> { this.x = v; }
      get readsEnv(): External<address> { return msg.sender; }
      get viaHelper(): External<u256> { return this.helper(); }
      helper(): u256 { return this.x; } }`))
      .toEqual({ readsX: 'view', pureFn: 'pure', writesX: 'nonpayable', readsEnv: 'view', viaHelper: 'view' });
  });

  it('inferred == explicit @view/@pure bytecode; explicit @payable / @view untouched', () => {
    expect(bc(`class C { x: u256; get f(): External<u256> { return this.x; } }`))
      .toBe(bc(`class C { x: u256; get f(): External<u256> { return this.x; } }`));
    expect(bc(`class C { get g(a: u256): External<u256> { return a + 1n; } }`))
      .toBe(bc(`class C { get g(a: u256): External<u256> { return a + 1n; } }`));
    expect(mut(`class C { x: u256; pay(): Payable<void> {} get v(): External<u256> { return this.x; } }`))
      .toEqual({ pay: 'payable', v: 'view' });
  });

  it('the inferred contract runs byte-identical to solc with explicit mutability', async () => {
    const J = `class C {
      x: u256;
      set(v: u256): External<void> { this.x = v; }
      get get(): External<u256> { return this.x; }
      get calc(a: u256): External<u256> { return a * 2n; } }`;
    const S = `contract C {
      uint256 x;
      function set(uint256 v) external { x = v; }
      function get() external view returns(uint256){ return x; }
      function calc(uint256 a) external pure returns(uint256){ return a * 2; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['set(uint256)', W(42)], ['get()', ''], ['calc(uint256)', W(9)]] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('decorator mode is unchanged: a no-decorator function stays nonpayable', () => {
    expect(mut(`// use @decorators\n@contract class C { @state x: u256; @external readsX(): u256 { return this.x; } }`))
      .toEqual({ readsX: 'nonpayable' });
  });
});

describe('`get` accessors (item #8; `get` = read-only at ANY visibility, External<T> = the ABI form)', () => {
  it('an EXTERNAL `get` (get f(): External<T>) is byte-identical to @external @view; a bare get is internal', () => {
    expect(bc(`class C { x: u256; get val(): External<u256> { return this.x; } }`))
      .toBe(bc(`class C { x: u256; get val(): External<u256> { return this.x; } }`));
    expect(mut(`class C { x: u256; get val(): External<u256> { return this.x; } set(v: u256): External<void> { this.x = v; } }`))
      .toEqual({ val: 'view', set: 'nonpayable' });
    // a BARE get is an INTERNAL read-only helper: not in the ABI, callable as this.f().
    expect(mut(`class C { x: u256; get bal(): u256 { return this.x; } get pub(): External<u256> { return this.bal(); } }`))
      .toEqual({ pub: 'view' });
  });

  it('a `get` over a `#`-private field runs byte-identical to solc', async () => {
    const J = `class C { #s: u256; stash(v: u256): External<void> { this.#s = v; } get secret(): External<u256> { return this.#s; } }`;
    const S = `contract C { uint256 private s; function stash(uint256 v) external { s = v; } function secret() external view returns(uint256){ return s; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, sel('stash(uint256)') + W(88));
    await h.call(as, sel('stash(uint256)') + W(88));
    const rj = await h.call(aj, sel('secret()'));
    const rs = await h.call(as, sel('secret()'));
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(rj.returnHex).toBe('0x' + W(88));
  });

  it('rejects a writing `get`, a setter, and `get` in decorator mode', () => {
    expect(codes(`class C { x: u256; get bad(): u256 { this.x = 1n; return this.x; } }`)).toContain('JETH043');
    expect(codes(`class C { x: u256; set val(v: u256) { this.x = v; } }`)).toContain('JETH043');
    expect(codes(`// use @decorators\n@contract class C { @state x: u256; get val(): u256 { return this.x; } }`)).toContain('JETH043');
  });
});

// Mutability-compatibility fixes surfaced by the #8 adversarial sweep (3 clusters of over-acceptances).
describe('mutability compatibility (item #8 sweep fixes)', () => {
  it('cluster 3: a caller of a @view helper infers view (not pure); @pure calling @view rejects', () => {
    // an explicit @view helper is at-least-view by declaration, so its callers are at-least-view.
    expect(mut(`class C { h(a: u256): u256 { return a + 1n; } get f(a: u256): External<u256> { return this.h(a); } }`)).toEqual({ f: 'view' });
    expect(mut(`class C { h(a: u256): u256 { return a + 1n; } get x(): External<u256> { return this.h(1n); } }`)).toEqual({ x: 'view' });
    expect(codes(`@contract class C { @view h(a: u256): u256 { return a + 1n; } @external @pure p(a: u256): u256 { return this.h(a); } }`)).toContain('JETH055');
  });

  it('cluster 1: the override mutability ladder is checked with the RESOLVED (inferred) mutability', () => {
    const base = (m: string) => `@abstract class A { @state x: u256; @virtual @external ${m} f(): u256 { return this.x; } }`;
    // view base + WRITING override (inferred nonpayable) -> loosen -> reject
    expect(codes(`${base('@view')} class C extends A { @override f(): External<u256> { this.x = 1n; return this.x; } }`)).toContain('JETH378');
    // view base (inferred) + writing override -> reject
    expect(codes(`abstract class A { x: u256; @virtual get f(): External<u256> { return this.x; } } class C extends A { @override f(): External<u256> { this.x = 1n; return this.x; } }`)).toContain('JETH378');
    // explicit view base + native read-only override (inferred view) -> ACCEPT (was spuriously rejected pre-fix)
    expect(codes(`${base('@view')} class C extends A { @override f(): External<u256> { return this.x + 1n; } }`)).toEqual([]);
  });

  it('cluster 2: an `implements` clause is rejected (JETH391); interfaces are implemented via `extends`', () => {
    expect(codes(`interface I { f(): Pure<u256>; } class C implements I { get f(): External<u256> { return 0n; } }`)).toContain('JETH391');
    expect(codes(`interface I { m(): View<u256>; } class C implements I { x: u256; m(): External<u256> { this.x = 1n; return this.x; } }`)).toContain('JETH391');
    // extends still enforces the interface mutability ladder (JETH387) for a loosening impl.
    expect(codes(`@interface class I { @external @pure f(): u256; } @contract class C extends I { @external @view f(): u256 { return 0n; } }`)).toContain('JETH387');
  });
});
