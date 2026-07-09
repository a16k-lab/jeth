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
    const body = (kw: string) => `{ ${kw} a: u256; ${kw} b: address; ${kw} c: bool; ${kw} m: mapping<address, u256>;
      @external @view getA(): u256 { return this.a; } @external setB(v: address): void { this.b = v; } }`;
    expect(bc(`class C ${body('')}`)).toBe(bc(`@contract class C ${body('@state ')}`));
    // initializer
    expect(bc(`class C { x: u256 = 42n; @external @view g(): u256 { return this.x; } }`))
      .toBe(bc(`@contract class C { @state x: u256 = 42n; @external @view g(): u256 { return this.x; } }`));
    // packing: two u128 share a slot exactly like @state
    expect(layout(`class C { lo: u128; hi: u128; @external @view s(): u256 { return u256(this.lo) + u256(this.hi); } }`))
      .toEqual(layout(`@contract class C { @state lo: u128; @state hi: u128; @external @view s(): u256 { return u256(this.lo) + u256(this.hi); } }`));
  });

  it('a native bare-field contract runs byte-identical to solc', async () => {
    const J = `class Bank {
      balances: mapping<address, u256>;
      total: u256;
      @external deposit(a: u256): void { this.balances[msg.sender] = this.balances[msg.sender] + a; this.total = this.total + a; }
      @external @view balanceOf(o: address): u256 { return this.balances[o]; }
      @external @view supply(): u256 { return this.total; } }`;
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
    expect(bc(`class C { #s: u256; @external stash(v: u256): void { this.#s = v; } @external @view reveal(): u256 { return this.#s; } }`))
      .toBe(bc(`@contract class C { @state #s: u256; @external stash(v: u256): void { this.#s = v; } @external @view reveal(): u256 { return this.#s; } }`));
  });

  it('`@external` on a bare field exposes the getter, like @external @state', () => {
    const a = compile(`class C { @external x: u256; }`, { fileName: 'C.jeth' }).abi.filter((f: any) => f.type === 'function').map((f: any) => f.name);
    expect(a).toEqual(['x']);
    expect(bc(`class C { @external x: u256; }`)).toBe(bc(`@contract class C { @external @state x: u256; }`));
  });

  it('a bare field in a native abstract base flattens into the leaf, byte-identical', () => {
    const base = (kw: string) => `${kw} class Base { owner: address; @external @view getOwner(): address { return this.owner; } }`;
    const der = `class C extends Base { n: u256; @external setN(v: u256): void { this.n = v; } }`;
    expect(bc(`${base('abstract')} ${der}`)).toBe(bc(`@abstract class Base { @state owner: address; @external @view getOwner(): address { return this.owner; } } @contract class C extends Base { @state n: u256; @external setN(v: u256): void { this.n = v; } }`));
  });

  it('rejects: static field (item #7), a field visibility decorator, and a bare field in decorator mode', () => {
    expect(codes(`class C { static K: u256 = 5n; @external @view f(): u256 { return 1n; } }`)).toContain('JETH045');
    expect(codes(`class C { @public x: u256; @external @view f(): u256 { return 1n; } }`)).toContain('JETH440');
    expect(codes(`// use @decorators\n@contract class C { x: u256; @external @view f(): u256 { return this.x; } }`)).toContain('JETH045');
  });

  it('a duplicate bare state field rejects like @state (JETH373) - same contract and across a chain', () => {
    // sweep finding: the JETH373 collision check was gated on @state, so a bare duplicate slipped through.
    expect(codes(`class C { x: u256; x: u256; @external @view f(): u256 { return this.x; } }`)).toContain('JETH373');
    expect(codes(`abstract class B { x: u256; } class C extends B { x: u256; @external @view f(): u256 { return this.x; } }`)).toContain('JETH373');
    expect(codes(`class C { x: u256; @state x: u256; @external @view f(): u256 { return this.x; } }`)).toContain('JETH373'); // mixed bare + @state
    expect(codes(`class C { #x: u256; #x: u256; @external @view f(): u256 { return this.#x; } }`)).toContain('JETH373'); // # collide (same mangled name)
    // a single bare field is fine, and a same-name #private in a base + derived is two separate slots (solc parity).
    expect(codes(`class C { x: u256; @external @view f(): u256 { return this.x; } }`)).toEqual([]);
    expect(codes(`abstract class B { #x: u256; } class C extends B { #x: u256; @external @view f(): u256 { return this.#x; } }`)).toEqual([]);
  });
});
