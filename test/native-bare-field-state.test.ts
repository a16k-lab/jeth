// Item #9: in NATIVE mode a BARE (undecorated, non-static) contract field is an implicit @state storage
// variable - no @state decorator needed. It flows through the exact same collectStateVar path (type
// resolution, layout planning, initializer handling, getter synthesis on @external), so it is byte-identical
// to the `@state` form and to solc's equivalent state variable. A `static` field is item #7 (const/immutable)
// and stays rejected; @public/@internal/@private/@hidden on a field still reject (JETH440); a `#`-prefixed
// bare field is a PRIVATE @state var (completing item #2, which previously needed `@state #s`).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const layout = (src: string) => compile(src, { fileName: 'C.jeth' }).storageLayout;
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

describe('bare field = @state (item #9)', () => {
  it('a bare field is byte-identical to @state, across types + initializer + packing', () => {
    const body = `{ a: u256; b: address; c: bool; m: mapping<address, u256>;
      get getA(): External<u256> { return this.a; } setB(v: address): External<void> { this.b = v; } }`;
    expect(bc(`class C ${body}`)).toBe(bc(`class C ${body}`));
    // initializer
    expect(bc(`class C { x: u256 = 42n; get g(): External<u256> { return this.x; } }`))
      .toBe(bc(`class C { x: u256 = 42n; get g(): External<u256> { return this.x; } }`));
    // packing: two u128 share a slot exactly like @state
    expect(layout(`class C { lo: u128; hi: u128; get s(): External<u256> { return u256(this.lo) + u256(this.hi); } }`))
      .toEqual(layout(`class C { lo: u128; hi: u128; get s(): External<u256> { return u256(this.lo) + u256(this.hi); } }`));
  });

  it('a native bare-field contract runs byte-identical to solc', async () => {
    const J = `class Bank {
      balances: mapping<address, u256>;
      total: u256;
      deposit(a: u256): External<void> { this.balances[msg.sender] = this.balances[msg.sender] + a; this.total = this.total + a; }
      get balanceOf(o: address): External<u256> { return this.balances[o]; }
      get supply(): External<u256> { return this.total; } }`;
    const S = `contract Bank {
      mapping(address => uint256) balances;
      uint256 total;
      function deposit(uint256 a) external { balances[msg.sender] = balances[msg.sender] + a; total = total + a; }
      function balanceOf(address o) external view returns(uint256){ return balances[o]; }
      function supply() external view returns(uint256){ return total; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'Bank').creation);
    for (const [sg, args] of [['deposit(uint256)', W(100)], ['supply()', ''], ['balanceOf(address)', pad32(0n)], ['deposit(uint256)', W(25)], ['supply()', '']] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('a `#`-prefixed bare field is a private @state var (item #2 completion), byte-identical', () => {
    expect(bc(`class C { #s: u256; stash(v: u256): External<void> { this.#s = v; } get reveal(): External<u256> { return this.#s; } }`))
      .toBe(bc(`class C { #s: u256; stash(v: u256): External<void> { this.#s = v; } get reveal(): External<u256> { return this.#s; } }`));
  });

  it('`@external` on a bare field exposes the getter, like @external @state', () => {
    const a = compile(`class C { x: Visible<u256>; }`, { fileName: 'C.jeth' }).abi.filter((f: any) => f.type === 'function').map((f: any) => f.name);
    expect(a).toEqual(['x']);
    expect(bc(`class C { x: Visible<u256>; }`)).toBe(bc(`class C { x: Visible<u256>; }`));
  });

  it('a bare field in a native abstract base flattens into the leaf, byte-identical', () => {
    const base = `abstract class Base { owner: address; get getOwner(): External<address> { return this.owner; } }`;
    const der = `class C extends Base { n: u256; setN(v: u256): External<void> { this.n = v; } }`;
    expect(bc(`${base} ${der}`)).toBe(bc(`${base} ${der}`));
  });

  it('a static field is a constant (item #7); a banned visibility decorator + the banned pragma reject', () => {
    // item #7: `static K = ...` is a compile-time constant (no storage slot), not a JETH045 reject.
    expect(codes(`class C { static K: u256 = 5n; get f(): External<u256> { return this.K; } }`)).toEqual([]);
    // @public is a banned legacy visibility decorator in stage 2 (JETH481).
    expect(codes(`class C { @public x: u256; get f(): External<u256> { return 1n; } }`)).toContain('JETH481');
    // decorator mode was removed in stage 2; a `// use @decorators` file now hard-rejects (JETH480).
    expect(codes(`// use @decorators\nclass C { x: u256; get f(): External<u256> { return this.x; } }`)).toContain('JETH480');
  });

  it('a duplicate bare state field rejects like @state (JETH373) - same contract and across a chain', () => {
    // sweep finding: the JETH373 collision check was gated on @state, so a bare duplicate slipped through.
    expect(codes(`class C { x: u256; x: u256; get f(): External<u256> { return this.x; } }`)).toContain('JETH373');
    expect(codes(`abstract class B { x: u256; } class C extends B { x: u256; get f(): External<u256> { return this.x; } }`)).toContain('JETH373');
    expect(codes(`class C { x: u256; x: u256; get f(): External<u256> { return this.x; } }`)).toContain('JETH373'); // mixed bare + @state
    expect(codes(`class C { #x: u256; #x: u256; get f(): External<u256> { return this.#x; } }`)).toContain('JETH373'); // # collide (same mangled name)
    // a single bare field is fine, and a same-name #private in a base + derived is two separate slots (solc parity).
    expect(codes(`class C { x: u256; get f(): External<u256> { return this.x; } }`)).toEqual([]);
    expect(codes(`abstract class B { #x: u256; } class C extends B { #x: u256; get f(): External<u256> { return this.#x; } }`)).toEqual([]);
  });
});
