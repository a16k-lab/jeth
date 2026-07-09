// Native visibility markers + error/event field declarations (the marker-type design language).
//
// PART A (#10's mechanism): on a contract/abstract method, a marker RETURN type declares visibility -
//   f(): External<T>  = @external f (mutability inferred),   deposit(): Payable<void> = @external @payable
//   (payable IMPLIES external). Bare = internal. The marker is stripped before the return type resolves
//   and never enters the selector - exactly the interface View/Pure/Payable treatment.
// PART B: a field typed with a lowercase marker generic declares a custom error / event:
//   Insufficient: error<{ need: u256; have: u256 }>;          = @error Insufficient(need, have);
//   Transfer: event<{ from: indexed<address>; amount: u256 }>; = @event Transfer(@indexed from, amount);
// raised/emitted with NAMED arguments (order-independent, reordered to the declared parameter order):
//   throw this.Insufficient({ need: a, have: b })  |  revert(this.Insufficient({ ... }))
//   emit(this.Transfer({ from: x, amount: a }))
// Both route through the SAME collectors/checkers as the decorated forms (synthesized decorated members /
// desugared bare-name calls), so they are byte-identical to the decorator forms and to solc.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

describe('Part A: External<T> / Payable<T> visibility markers on contract methods', () => {
  it('External<T> == @external and Payable<T> == @external @payable, byte-identically', () => {
    expect(bc(`class C { x: u256; balanceOf(o: address): External<u256> { return this.x; } set(v: u256): External<void> { this.x = v; } }`))
      .toBe(bc(`class C { x: u256; @external balanceOf(o: address): u256 { return this.x; } @external set(v: u256): void { this.x = v; } }`));
    expect(bc(`class C { x: u256; deposit(): Payable<void> { this.x = msg.value; } }`))
      .toBe(bc(`class C { x: u256; @external @payable deposit(): void { this.x = msg.value; } }`));
  });

  it('mutability is inferred through the marker; bare methods stay internal', () => {
    const abi = compile(`class C { x: u256; reads(): External<u256> { return this.x; } calc(a: u256): External<u256> { return a + 1n; } writes(v: u256): External<void> { this.x = v; } pays(): Payable<void> { this.x = msg.value; } helper(): u256 { return this.x; } }`, { fileName: 'C.jeth' }).abi as any[];
    const m = Object.fromEntries(abi.filter((f) => f.type === 'function').map((f) => [f.name, f.stateMutability]));
    expect(m).toEqual({ reads: 'view', calc: 'pure', writes: 'nonpayable', pays: 'payable' }); // no `helper`
  });

  it('a fully-native contract (markers + inference) runs byte-identical to solc', async () => {
    const J = `class C { x: u256;
      set(v: u256): External<void> { this.x = v; }
      get2(): External<u256> { return this.x; }
      pay(): Payable<u256> { this.x = this.x + msg.value; return this.x; } }`;
    const S = `contract C { uint256 x;
      function set(uint256 v) external { x = v; }
      function get2() external view returns(uint256){ return x; }
      function pay() external payable returns(uint256){ x = x + msg.value; return x; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args, value] of [['set(uint256)', W(5), 0n], ['get2()', '', 0n], ['pay()', '', 30n], ['get2()', '', 0n]] as [string, string, bigint][]) {
      const rj = await h.call(aj, sel(sg) + args, { value });
      const rs = await h.call(as, sel(sg) + args, { value });
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('marker misuse rejects: bad arity, on a getter, with a conflicting mutability, in decorator mode', () => {
    expect(codes(`class C { f(): External { return 1n; } }`)).toContain('JETH352');
    expect(codes(`class C { x: u256; get v(): External<u256> { return this.x; } }`)).toContain('JETH352');
    expect(codes(`class C { @view f(): Payable<u256> { return 1n; } }`)).toContain('JETH052');
    expect(codes(`// use @decorators\n@contract class C { f(): External<u256> { return 1n; } }`)).toContain('JETH013');
  });
});

describe('Part B: error<{...}> / event<{...}> / indexed<T> field declarations', () => {
  it('an error field + this-raise is byte-identical to @error + positional revert (throw == revert too)', () => {
    const NATIVE = `class C { Insufficient: error<{ need: u256; have: u256 }>; pay(a: u256, bal: u256): External<void> { if (bal < a) { revert(this.Insufficient({ need: a, have: bal })); } } }`;
    expect(bc(NATIVE)).toBe(bc(`class C { @error Insufficient(need: u256, have: u256); pay(a: u256, bal: u256): External<void> { if (bal < a) { revert(Insufficient(a, bal)); } } }`));
    // throw form and named-arg ORDER are byte-identical (named args reorder to the declared order).
    expect(bc(`class C { Insufficient: error<{ need: u256; have: u256 }>; pay(a: u256, bal: u256): External<void> { if (bal < a) { throw this.Insufficient({ need: a, have: bal }); } } }`)).toBe(bc(NATIVE));
    expect(bc(`class C { Insufficient: error<{ need: u256; have: u256 }>; pay(a: u256, bal: u256): External<void> { if (bal < a) { revert(this.Insufficient({ have: bal, need: a })); } } }`)).toBe(bc(NATIVE));
  });

  it('an event field (with indexed<>) + this-emit is byte-identical to @event @indexed + positional emit', () => {
    expect(bc(`class C { Transfer: event<{ from: indexed<address>; to: indexed<address>; amount: u256 }>; send(to: address, a: u256): External<void> { emit(this.Transfer({ from: msg.sender, to: to, amount: a })); } }`))
      .toBe(bc(`class C { @event Transfer(@indexed from: address, @indexed to: address, amount: u256); send(to: address, a: u256): External<void> { emit(Transfer(msg.sender, to, a)); } }`));
  });

  it('throw/revert revert-data and emit logs are byte-identical to solc', async () => {
    const J = `class C {
      Insufficient: error<{ need: u256; have: u256 }>;
      Transfer: event<{ from: indexed<address>; amount: u256 }>;
      pay(a: u256, bal: u256): External<void> { if (bal < a) { throw this.Insufficient({ need: a, have: bal }); } emit(this.Transfer({ from: msg.sender, amount: a })); } }`;
    const S = `contract C {
      error Insufficient(uint256 need, uint256 have);
      event Transfer(address indexed from, uint256 amount);
      function pay(uint256 a, uint256 bal) external { if (bal < a) { revert Insufficient(a, bal); } emit Transfer(msg.sender, a); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    // revert path: identical custom-error revert data.
    const rj = await h.call(aj, sel('pay(uint256,uint256)') + W(100) + W(5));
    const rs = await h.call(as, sel('pay(uint256,uint256)') + W(100) + W(5));
    expect(rj.success).toBe(false);
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
    // emit path: identical logs (topics + data).
    const ej = await h.call(aj, sel('pay(uint256,uint256)') + W(5) + W(100));
    const es = await h.call(as, sel('pay(uint256,uint256)') + W(5) + W(100));
    expect(ej.success).toBe(es.success);
    expect(JSON.stringify(ej.logs)).toBe(JSON.stringify(es.logs));
  });

  it('rejects: bad named args, banned throw shapes, a decorated/#/static/initialized field, decorator mode', () => {
    const E = `E: error<{ a: u256; b: u256 }>;`;
    expect(codes(`class C { ${E} f(): External<void> { revert(this.E({ a: 1n })); } }`)).toContain('JETH130');            // missing key
    expect(codes(`class C { ${E} f(): External<void> { revert(this.E({ a: 1n, b: 2n, z: 3n })); } }`)).toContain('JETH130'); // extra key
    expect(codes(`class C { f(): External<void> { throw "bad"; } }`)).toContain('JETH025');
    expect(codes(`class C { f(): External<void> { throw new Error("x"); } }`)).toContain('JETH025');
    expect(codes(`class C { f(): External<void> { throw this.Nope({ a: 1n }); } }`)).toContain('JETH025');                // unknown error
    expect(codes(`class C { E: error<{ a: u256 }> = 1n; f(): External<void> { } }`)).toContain('JETH353');                 // initializer
    expect(codes(`class C { #E: error<{ a: u256 }>; f(): External<void> { } }`)).toContain('JETH353');                     // #-private
    expect(codes(`class C { static E: error<{ a: u256 }>; f(): External<void> { } }`)).toContain('JETH353');               // static
    expect(codes(`// use @decorators\n@contract class C { E: error<{ a: u256 }>; @external f(): void { } }`)).toContain('JETH045'); // decorator mode
  });
});

// Hardening from the adversarial sweep (784 cases): the 4 bar-violations it confirmed, now closed.
describe('marker + raise hardening (verification sweep)', () => {
  it('a generic function cannot take an External<T>/Payable<T> marker (JETH290, like @external)', () => {
    expect(codes(`class C { f<T>(): External<T> { return 1n; } g(): External<u256> { return 1n; } }`)).toContain('JETH290');
  });

  it('named-args emit of an OVERLOADED event rejects (ambiguous); positional + single-decl named still work', () => {
    // the unsound key-set first-match could reorder per one overload and type-resolve to another (a
    // silent wrong-data emit); an overloaded event must be raised positionally.
    expect(codes(`class C { T: event<{ a: u256; b: u256 }>; @event T(b: address, a: address); f(p: address, q: address): External<void> { emit(this.T({ a: p, b: q })); } }`)).toContain('JETH434');
    expect(codes(`class C { T: event<{ a: u256; b: u256 }>; @event T(b: address, a: address); f(p: address, q: address): External<void> { emit(this.T(p, q)); } }`)).toEqual([]);
    expect(codes(`class C { T: event<{ a: u256; b: address }>; f(v: u256, w: address): External<void> { emit(this.T({ b: w, a: v })); } }`)).toEqual([]);
  });

  it('a duplicate error field reports only the error-duplicate (no spurious state-var collision)', () => {
    expect(codes(`class C { E: error<{ a: u256 }>; E: error<{ a: u256 }>; f(): External<void> { } }`)).toEqual(['JETH128']);
  });

  it('a visibility marker on a @library method rejects at the declaration (use @external)', () => {
    expect(codes(`@library class L { f(a: u256): External<u256> { return a + 1n; } } class C { g(a: u256): External<u256> { return L.f(a); } }`)).toContain('JETH390');
  });
});
