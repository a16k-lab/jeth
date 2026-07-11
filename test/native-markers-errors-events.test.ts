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

describe('Part A: two orthogonal axes - `get` = read-only (any visibility); External/Payable = the ABI', () => {
  it('an EXTERNAL `get` (parameterized) == @external @view; External<T> writer == @external; Payable == @external @payable', () => {
    expect(bc(`class C { balances: mapping<address, u256>; get balanceOf(o: address): External<u256> { return this.balances[o]; } deposit(a: u256): External<void> { this.balances[msg.sender] = a; } }`))
      .toBe(bc(`class C { balances: mapping<address, u256>; get balanceOf(o: address): External<u256> { return this.balances[o]; } deposit(a: u256): External<void> { this.balances[msg.sender] = a; } }`));
    expect(bc(`class C { x: u256; deposit(): Payable<void> { this.x = msg.value; } }`))
      .toBe(bc(`class C { x: u256; deposit(): Payable<void> { this.x = msg.value; } }`));
  });

  it('`get` works at ALL THREE visibilities: internal (bare), private (#), external (External<T>)', () => {
    // internal + private gets are NOT in the ABI and are callable in-contract; only the External get is.
    const abi = compile(`class C { x: u256;
      get #raw(): u256 { return this.x; }
      get bal(): u256 { return this.#raw(); }
      get balance(): External<u256> { return this.bal(); } }`, { fileName: 'C.jeth' }).abi as any[];
    expect(abi.filter((f) => f.type === 'function').map((f) => f.name)).toEqual(['balance']);
    // a derived contract cannot reach a base's #-private get (private stays private).
    expect(codes(`abstract class B { x: u256; get #raw(): u256 { return this.x; } } class C extends B { get p(): External<u256> { return this.#raw(); } }`).length).toBeGreaterThan(0);
  });

  it('mutability is inferred (get -> view/pure by body; External writers nonpayable); bare stays internal', () => {
    const abi = compile(`class C { x: u256; get reads(): External<u256> { return this.x; } get calc(a: u256): External<u256> { return a + 1n; } writes(v: u256): External<void> { this.x = v; } pays(): Payable<void> { this.x = msg.value; } helper(): u256 { return this.x; } }`, { fileName: 'C.jeth' }).abi as any[];
    const m = Object.fromEntries(abi.filter((f) => f.type === 'function').map((f) => [f.name, f.stateMutability]));
    expect(m).toEqual({ reads: 'view', calc: 'pure', writes: 'nonpayable', pays: 'payable' }); // no `helper`
  });

  it('a fully-native contract (get + markers + inference) runs byte-identical to solc', async () => {
    const J = `class C { x: u256;
      set(v: u256): External<void> { this.x = v; }
      get value(): External<u256> { return this.x; }
      pay(): Payable<u256> { this.x = this.x + msg.value; return this.x; } }`;
    const S = `contract C { uint256 x;
      function set(uint256 v) external { x = v; }
      function value() external view returns(uint256){ return x; }
      function pay() external payable returns(uint256){ x = x + msg.value; return x; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args, value] of [['set(uint256)', W(5), 0n], ['value()', '', 0n], ['pay()', '', 30n], ['value()', '', 0n]] as [string, string, bigint][]) {
      const rj = await h.call(aj, sel(sg) + args, { value });
      const rs = await h.call(as, sel(sg) + args, { value });
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('GET IS A MUST: a read-only value-returning External<T> method rejects; void assert-style stays External<void>', () => {
    // a read-only external returning a value must be spelled `get f(): External<T>`.
    expect(codes(`class C { x: u256; balanceOf(): External<u256> { return this.x; } }`)).toContain('JETH352');
    expect(codes(`class C { calc(a: u256): External<u256> { return a + 1n; } }`)).toContain('JETH352');
    expect(codes(`class C { x: u256; f(): External<u256> { return this.x; } }`)).toContain('JETH352');
    // a VOID read-only external (assert-style: the body only checks/reverts) is exempt.
    expect(codes(`class C { x: u256; check(a: u256): External<void> { require(a > this.x, "too small"); } }`)).toEqual([]);
    // a writing getter rejects at EVERY visibility (a get is read-only).
    expect(codes(`class C { x: u256; get bad(v: u256): u256 { this.x = v; return v; } }`)).toContain('JETH043');
    expect(codes(`class C { x: u256; get bad(): External<u256> { this.x = 1n; return this.x; } }`)).toContain('JETH043');
  });

  it('virtual idioms: a @virtual get chain works; override HEADROOM is a bodyless @virtual External<T>', () => {
    // a virtual EXTERNAL reader chain: @virtual get + @override get (byte-identical to the decorated form).
    expect(bc(`abstract class B { x: u256; @virtual get v(): External<u256> { return this.x; } } class C extends B { @override get v(): External<u256> { return this.x + 1n; } }`))
      .toBe(bc(`abstract class B { x: u256; @virtual get v(): External<u256> { return this.x; } } class C extends B { @override get v(): External<u256> { return this.x + 1n; } }`));
    // headroom: a BODYLESS @virtual External<T> stays nonpayable, so a writing override is legal (solc's
    // abstract-virtual idiom); a BODIED @virtual External reader rejects (spell it get, or make it bodyless).
    expect(codes(`abstract class B { x: u256; @virtual f(): External<u256>; } class C extends B { @override f(): External<u256> { this.x = this.x + 1n; return this.x; } }`)).toEqual([]);
    expect(codes(`abstract class B { x: u256; @virtual f(): External<u256> { return this.x; } } class C extends B { @override f(): External<u256> { this.x = this.x + 1n; return this.x; } }`)).toContain('JETH352');
  });

  it('a #-private member cannot be @external (the mangled-ABI leak, both methods and fields)', () => {
    // @external #f previously EXPOSED $p$C$f as an externally callable ABI entry - a "private" method that
    // was public under an obfuscated selector; the field form leaked the same way via the auto-getter.
    expect(codes(`class C { #f(): External<u256> { return 42n; } get g(): External<u256> { return 1n; } }`)).toContain('JETH352');
    expect(codes(`class C { #x: Visible<u256>; get g(): External<u256> { return 1n; } }`)).toContain('JETH352');
  });

  it('the marker names are reserved: a declaration named External/Payable/View/Pure/error/event/indexed rejects', () => {
    // a user struct named `External` shadowed the marker in return positions with a MISLEADING arity error.
    expect(codes(`type External = { a: u256 }; class C { get f(): External<u256> { return 1n; } }`)).toContain('JETH038');
    expect(codes(`static class View { f(): u256 { return 1n; } } class C { get g(): External<u256> { return View.f(); } }`)).toContain('JETH038');
    expect(codes(`type error = { a: u256 }; class C { get f(): External<u256> { return 1n; } }`)).toContain('JETH038');
  });

  it('marker misuse rejects: bad arity, a Payable get, a conflicting mutability, decorator mode', () => {
    expect(codes(`class C { f(): External { return 1n; } }`)).toContain('JETH352');
    expect(codes(`class C { get f(): Payable<u256> { return 1n; } }`)).toContain('JETH352'); // a get is read-only; payable is a writer property
    expect(codes(`class C { @view f(): Payable<u256> { return 1n; } }`)).toContain('JETH052');
    expect(codes(`// use @decorators\n@contract class C { f(): External<u256> { return 1n; } }`)).toContain('JETH013');
  });

  it('a #-private method cannot carry External/Payable (it would expose the mangled name in the ABI)', () => {
    // matrix-audit finding: #f(): External<void> / Payable<void> silently exposed `$p$C$f` as an
    // externally callable (even payable) ABI entry - private and external contradict.
    expect(codes(`class C { x: u256; #f(v: u256): External<void> { this.x = v; } g(v: u256): External<void> { this.#f(v); } }`)).toContain('JETH352');
    expect(codes(`class C { x: u256; #f(): Payable<void> { this.x = msg.value; } }`)).toContain('JETH352');
    expect(codes(`class C { static #f(a: u256): External<u256> { return a; } get g(): External<u256> { return C.#f(1n); } }`)).toContain('JETH352');
    // a static Payable is rejected (user ruling): a payable fn RECEIVES ether, and a static has no `this`
    // to account for it - received money with nowhere to record it, and no solc counterpart to anchor it.
    expect(codes(`class C { static f(): Payable<u256> { return msg.value; } }`)).toContain('JETH352');
    // a static External writer/assert stays fine; the payable entry belongs on an instance method.
    expect(codes(`class C { total: u256; deposit(): Payable<void> { this.total = this.total + msg.value; } static check(a: u256): External<void> { require(a > 0n, "x"); } }`)).toEqual([]);
  });
});

describe('Part B: error<{...}> / event<{...}> / indexed<T> field declarations', () => {
  it('an error field + this-raise is byte-identical to @error + positional revert (throw == revert too)', () => {
    const NATIVE = `class C { Insufficient: error<{ need: u256; have: u256 }>; pay(a: u256, bal: u256): External<void> { if (bal < a) { revert(this.Insufficient({ need: a, have: bal })); } } }`;
    expect(bc(NATIVE)).toBe(bc(`class C { Insufficient: error<{ need: u256; have: u256 }>; pay(a: u256, bal: u256): External<void> { if (bal < a) { revert(Insufficient(a, bal)); } } }`));
    // throw form and named-arg ORDER are byte-identical (named args reorder to the declared order).
    expect(bc(`class C { Insufficient: error<{ need: u256; have: u256 }>; pay(a: u256, bal: u256): External<void> { if (bal < a) { throw this.Insufficient({ need: a, have: bal }); } } }`)).toBe(bc(NATIVE));
    expect(bc(`class C { Insufficient: error<{ need: u256; have: u256 }>; pay(a: u256, bal: u256): External<void> { if (bal < a) { revert(this.Insufficient({ have: bal, need: a })); } } }`)).toBe(bc(NATIVE));
  });

  it('an event field (with indexed<>) + this-emit is byte-identical to @event @indexed + positional emit', () => {
    expect(bc(`class C { Transfer: event<{ from: indexed<address>; to: indexed<address>; amount: u256 }>; send(to: address, a: u256): External<void> { emit(this.Transfer({ from: msg.sender, to: to, amount: a })); } }`))
      .toBe(bc(`class C { Transfer: event<{ from: indexed<address>; to: indexed<address>; amount: u256 }>; send(to: address, a: u256): External<void> { emit(Transfer(msg.sender, to, a)); } }`));
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

// FILE-LEVEL error/event declarations: `type X = error<{...}>` / `type X = event<{...}>` at the top level
// are the native spellings of solc's file-level `error X(...)` (0.8.4+) and `event X(...)` (0.8.22+).
// They route through the SAME synthesis as the member-field form (identical selector/topic0), are raised
// BARE and positionally (`revert(X(...))` / `emit(X(...))` - exactly solc's spelling; named-args stay
// exclusive to the member `this.X({...})` form since bare object-literals already mean struct literals),
// and export/import like any type alias.
describe('file-level error/event declarations (type X = error<{...}>)', () => {
  const J = `type Insufficient = error<{ need: u256; have: u256 }>;
type Moved = event<{ who: indexed<address>; amount: u256 }>;
class C { f(a: u256): External<void> { if (a == 0n) { revert(Insufficient(1n, a)); } emit(Moved(msg.sender, a)); } }`;

  it('revert data + event logs are byte-identical to solc file-level error/event', async () => {
    const S = `error Insufficient(uint256 need, uint256 have);
event Moved(address indexed who, uint256 amount);
contract C { function f(uint256 a) external { if (a == 0) revert Insufficient(1, a); emit Moved(msg.sender, a); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const rj = await h.call(aj, sel('f(uint256)') + W(0));
    const rs = await h.call(as, sel('f(uint256)') + W(0));
    expect(rj.success).toBe(false);
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex); // the custom-error selector + args
    const ej = await h.call(aj, sel('f(uint256)') + W(5));
    const es = await h.call(as, sel('f(uint256)') + W(5));
    expect(JSON.stringify(ej.logs)).toBe(JSON.stringify(es.logs)); // topic0 + indexed topics + data
  });

  it('a file-level declaration is byte-identical to the member-field form', () => {
    expect(bc(J)).toBe(bc(`class C { Insufficient: error<{ need: u256; have: u256 }>; Moved: event<{ who: indexed<address>; amount: u256 }>; f(a: u256): External<void> { if (a == 0n) { revert(this.Insufficient({ need: 1n, have: a })); } emit(this.Moved({ who: msg.sender, amount: a })); } }`));
  });

  it('exports/imports like any type alias; the v2 import edge is enforced; guards hold', () => {
    const diag = (src: string, sources: Record<string, string>): string[] => {
      try { compile(src, { fileName: 'vault.jeth', sources }); return []; } catch (e: any) { return e.diagnostics.map((d: any) => `${d.code}@${d.file}:${d.line}`); }
    };
    const DEP = `export type Insufficient = error<{ need: u256; have: u256 }>;\nexport type Whoops = error<{ code: u256 }>;`;
    expect(diag(`import { Insufficient } from "./errs.jeth";\nclass V { x: u256; f(a: u256): External<void> { if (a == 0n) { revert(Insufficient(1n, a)); } this.x = a; } }`, { 'errs.jeth': DEP })).toEqual([]);
    expect(diag(`import { Insufficient } from "./errs.jeth";\nclass V { x: u256; f(a: u256): External<void> { if (a == 0n) { revert(Whoops(1n)); } this.x = a; } }`, { 'errs.jeth': DEP })).toEqual(['JETH039@vault.jeth:2']);
    // this.X is the MEMBER spelling - a file-level declaration is raised bare.
    expect(codes(`type E = error<{ a: u256 }>;\nclass C { f(): External<void> { throw this.E({ a: 1n }); } }`)).toContain('JETH353');
    // duplicate (file-level + member) hits the normal duplicate check; decorator mode is unchanged.
    expect(codes(`type E = error<{ a: u256 }>;\nclass C { E: error<{ a: u256 }>; f(): External<void> { revert(E(1n)); } }`)).toContain('JETH128');
    expect(codes(`// use @decorators\ntype E = error<{ a: u256 }>;\n@contract class C { @external f(): void { } }`)).toContain('JETH015');
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
    expect(codes(`class C { T: event<{ a: u256; b: u256 }>; T: event<{ b: address; a: address }>; f(p: address, q: address): External<void> { emit(this.T({ a: p, b: q })); } }`)).toContain('JETH434');
    expect(codes(`class C { T: event<{ a: u256; b: u256 }>; T: event<{ b: address; a: address }>; f(p: address, q: address): External<void> { emit(this.T(p, q)); } }`)).toEqual([]);
    expect(codes(`class C { T: event<{ a: u256; b: address }>; f(v: u256, w: address): External<void> { emit(this.T({ b: w, a: v })); } }`)).toEqual([]);
  });

  it('a duplicate error field reports only the error-duplicate (no spurious state-var collision)', () => {
    expect(codes(`class C { E: error<{ a: u256 }>; E: error<{ a: u256 }>; f(): External<void> { } }`)).toEqual(['JETH128']);
  });

  it('External<T> on a library method = @external (a delegatecall library fn); Payable<T> rejects', () => {
    // originally rejected as a half-state; now properly wired: the marker makes the library deployable +
    // linked, exactly like the @external decorator (and solc's library-with-an-external-fn).
    const M = `static class L { f(a: u256): External<u256> { return a + 1n; } } class C { x: u256; s(a: u256): External<void> { this.x = L.f(a); } }`;
    const D = `static class L { f(a: u256): External<u256> { return a + 1n; } } class C { x: u256; s(a: u256): External<void> { this.x = L.f(a); } }`;
    expect(compile(M, { fileName: 'C.jeth' }).creationBytecode).toBe(compile(D, { fileName: 'C.jeth' }).creationBytecode);
    expect(codes(`static class L { f(): Payable<void> { } } class C { g(): External<u256> { this.x = 1n; return 1n; } x: u256; }`)).toContain('JETH390');
  });
});
