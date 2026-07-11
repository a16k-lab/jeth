// P0b - the `Visible<T>` FIELD marker: the native spelling of the @external field decorator
// (solc's `public` state variable / constant / immutable with an auto-generated getter).
// Fields are PUBLIC (an auto-getter), methods are EXTERNAL - hence the field marker is Visible<T>
// while External<T>/Payable<T> stay method-only.
//   x: Visible<u256>                     = @external @state x: u256          (state getter)
//   balances: Visible<mapping<K, V>>     = @external @state balances         (parameterized getter)
//   static K: Visible<u256> = 5n;        = @external @constant K / @external static K   (constant getter)
//   static M: Visible<address>;          = @external @immutable M / @external static M  (view getter)
// The marker unwraps to the inner type BEFORE field classification and routes through the EXACT
// machinery the decorator uses (publicStateNames / publicConstantNames / publicImmutableNames), so the
// ORACLE is twin-bytecode equality: for every shape both spellings must produce byte-identical
// creationBytecode (which also pins getter selectors + ABI - the capture-diff migration depends on it).
// A runtime differential vs solc re-proves the getter surface, reject controls pin the misuse space
// (including the wrong-marker pointers: External<T> on a field, Visible<T> on a method), and
// non-vacuity pairs prove the marker actually synthesizes a getter (bare field stays internal).
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
const messages = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => `${d.code}: ${d.message}`) ?? ['THROW']; }
};
async function eqCalls(J: string, S: string, calls: [string, string][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, args] of calls) {
    const rj = await h.call(aj, sel(sg) + args);
    const rs = await h.call(as, sel(sg) + args);
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
  }
}

const P = `type P = { a: u256; b: address };`;

describe('Visible<T> field marker == @external decorator twin (creationBytecode equality)', () => {
  const twins: [string, string, string][] = [
    ['u256 state', `class C { x: Visible<u256> = 7n; }`, `class C { x: Visible<u256> = 7n; }`],
    ['address state', `class C { a: Visible<address>; f(v: address): External<void> { this.a = v; } }`,
      `class C { a: Visible<address>; f(v: address): External<void> { this.a = v; } }`],
    ['bool state', `class C { flag: Visible<bool> = true; }`, `class C { flag: Visible<bool> = true; }`],
    ['bytes8 state', `class C { h: Visible<bytes8>; set(v: bytes8): External<void> { this.h = v; } }`,
      `class C { h: Visible<bytes8>; set(v: bytes8): External<void> { this.h = v; } }`],
    ['string state', `class C { name: Visible<string>; set(v: string): External<void> { this.name = v; } }`,
      `class C { name: Visible<string>; set(v: string): External<void> { this.name = v; } }`],
    ['bytes state', `class C { blob: Visible<bytes>; set(v: bytes): External<void> { this.blob = v; } }`,
      `class C { blob: Visible<bytes>; set(v: bytes): External<void> { this.blob = v; } }`],
    ['mapping 1-key', `class C { balances: Visible<mapping<address, u256>>; set(k: address, v: u256): External<void> { this.balances[k] = v; } }`,
      `class C { balances: Visible<mapping<address, u256>>; set(k: address, v: u256): External<void> { this.balances[k] = v; } }`],
    ['mapping 2-key nested', `class C { allow: Visible<mapping<address, mapping<address, u256>>>; set(a: address, b: address, v: u256): External<void> { this.allow[a][b] = v; } }`,
      `class C { allow: Visible<mapping<address, mapping<address, u256>>>; set(a: address, b: address, v: u256): External<void> { this.allow[a][b] = v; } }`],
    ['dyn array', `class C { xs: Visible<u256[]>; push(v: u256): External<void> { this.xs.push(v); } }`,
      `class C { xs: Visible<u256[]>; push(v: u256): External<void> { this.xs.push(v); } }`],
    ['fixed array', `class C { fa: Visible<Arr<u256, 3>>; set(i: u256, v: u256): External<void> { this.fa[i] = v; } }`,
      `class C { fa: Visible<Arr<u256, 3>>; set(i: u256, v: u256): External<void> { this.fa[i] = v; } }`],
    ['struct field (flattened getter)', `${P} class C { p: Visible<P>; set(a: u256, b: address): External<void> { this.p.a = a; this.p.b = b; } }`,
      `${P} class C { p: Visible<P>; set(a: u256, b: address): External<void> { this.p.a = a; this.p.b = b; } }`],
    ['mapping to struct', `${P} class C { m: Visible<mapping<u256, P>>; set(k: u256, a: u256, b: address): External<void> { this.m[k].a = a; this.m[k].b = b; } }`,
      `${P} class C { m: Visible<mapping<u256, P>>; set(k: u256, a: u256, b: address): External<void> { this.m[k].a = a; this.m[k].b = b; } }`],
    ['enum state', `enum Color { Red, Green, Blue } class C { c: Visible<Color> = Color.Blue; }`,
      `enum Color { Red, Green, Blue } class C { c: Visible<Color> = Color.Blue; }`],
    ['i256 state', `class C { s: Visible<i256> = -5n; }`, `class C { s: Visible<i256> = -5n; }`],
    ['static constant vs @external static', `class C { static K: Visible<u256> = 5n; }`, `class C { static K: Visible<u256> = 5n; }`],
    ['static constant vs @external @constant', `class C { static K: Visible<u256> = 5n; }`, `class C { static K: Visible<u256> = 5n; }`],
    ['string constant', `class C { static NAME: Visible<string> = "JETH"; }`, `class C { static NAME: Visible<string> = "JETH"; }`],
    ['bytes4 constant', `class C { static MAGIC: Visible<bytes4> = bytes4(0x01020304n); }`, `class C { static MAGIC: Visible<bytes4> = bytes4(0x01020304n); }`],
    ['immutable vs @external static', `class C { static M: Visible<address>; constructor() { this.M = msg.sender; } }`,
      `class C { static M: Visible<address>; constructor() { this.M = msg.sender; } }`],
    ['immutable vs @external @immutable', `class C { static M: Visible<address>; constructor() { this.M = msg.sender; } }`,
      `class C { static M: Visible<address>; constructor() { this.M = msg.sender; } }`],
    ['immutable from ctor arg', `class C { static N: Visible<u64>; constructor(n: u64) { this.N = n; } }`,
      `class C { static N: Visible<u64>; constructor(n: u64) { this.N = n; } }`],
    ['public field in an abstract base', `abstract class Base { total: Visible<u256>; bump(v: u256): External<void> { this.total = this.total + v; } } class C extends Base { }`,
      `abstract class Base { total: Visible<u256>; bump(v: u256): External<void> { this.total = this.total + v; } } class C extends Base { }`],
    ['marker and decorator mixed per-field (cross)', `class C { x: Visible<u256> = 3n; y: Visible<u256> = 4n; z: u256 = 5n; }`,
      `class C { x: Visible<u256> = 3n; y: Visible<u256> = 4n; z: u256 = 5n; }`],
    ['marker beside an internal state field', `class C { hidden1: u256 = 1n; x: Visible<u256> = 2n; }`,
      `class C { hidden1: u256 = 1n; x: Visible<u256> = 2n; }`],
    ['explicit @state plus marker', `class C { x: Visible<u256> = 7n; }`, `class C { x: Visible<u256> = 7n; }`],
    ['slot packing preserved', `class C { a: Visible<u64> = 1n; b: Visible<u64> = 2n; c2: Visible<u128> = 3n; }`,
      `class C { a: Visible<u64> = 1n; b: Visible<u64> = 2n; c2: Visible<u128> = 3n; }`],
    ['@storage namespace field', `class C { @storage('app') x: Visible<u256>; set(v: u256): External<void> { this.x = v; } }`,
      `class C { @storage('app') x: Visible<u256>; set(v: u256): External<void> { this.x = v; } }`],
    ['@override getter var (P1-4)', `abstract class A { @virtual x(): External<u256>; } class C extends A { @override x: Visible<u256>; set(v: u256): External<void> { this.x = v; } }`,
      `abstract class A { @virtual x(): External<u256>; } class C extends A { @override x: Visible<u256>; set(v: u256): External<void> { this.x = v; } }`],
    ['interface obligation satisfied by the marker getter', `interface I { x(): View<u256>; } class C extends I { x: Visible<u256>; set(v: u256): External<void> { this.x = v; } }`,
      `interface I { x(): View<u256>; } class C extends I { x: Visible<u256>; set(v: u256): External<void> { this.x = v; } }`],
  ];
  for (const [label, native, twin] of twins) {
    it(`twin: ${label}`, () => {
      expect(bc(native)).toBe(bc(twin));
    });
  }
});

describe('Visible<T> field getters run byte-identical to solc (incl. parameterized getters)', () => {
  const A1 = W(0x1111), A2 = W(0x2222);
  it('u256 state getter after writes', async () => {
    await eqCalls(
      `class C { x: Visible<u256> = 7n; bump(v: u256): External<void> { this.x = this.x + v; } }`,
      `contract C { uint256 public x = 7; function bump(uint256 v) external { x += v; } }`,
      [['bump(uint256)', W(35)], ['x()', '']],
    );
  });
  it('mapping getter is parameterized: balances(address)', async () => {
    await eqCalls(
      `class C { balances: Visible<mapping<address, u256>>; set(k: address, v: u256): External<void> { this.balances[k] = v; } }`,
      `contract C { mapping(address => uint256) public balances; function set(address k, uint256 v) external { balances[k] = v; } }`,
      [['set(address,uint256)', A1 + W(1234)], ['balances(address)', A1], ['balances(address)', A2]],
    );
  });
  it('2-key nested mapping getter: allow(address,address)', async () => {
    await eqCalls(
      `class C { allow: Visible<mapping<address, mapping<address, u256>>>; set(a: address, b: address, v: u256): External<void> { this.allow[a][b] = v; } }`,
      `contract C { mapping(address => mapping(address => uint256)) public allow; function set(address a, address b, uint256 v) external { allow[a][b] = v; } }`,
      [['set(address,address,uint256)', A1 + A2 + W(777)], ['allow(address,address)', A1 + A2], ['allow(address,address)', A2 + A1]],
    );
  });
  it('dynamic array indexed getter incl. out-of-bounds revert', async () => {
    await eqCalls(
      `class C { xs: Visible<u256[]>; push(v: u256): External<void> { this.xs.push(v); } }`,
      `contract C { uint256[] public xs; function push(uint256 v) external { xs.push(v); } }`,
      [['push(uint256)', W(11)], ['push(uint256)', W(22)], ['xs(uint256)', W(0)], ['xs(uint256)', W(1)], ['xs(uint256)', W(2)]],
    );
  });
  it('struct getter returns the flattened tuple', async () => {
    await eqCalls(
      `${P} class C { p: Visible<P>; set(a: u256, b: address): External<void> { this.p.a = a; this.p.b = b; } }`,
      `contract C { struct P { uint256 a; address b; } P public p; function set(uint256 a, address b) external { p.a = a; p.b = b; } }`,
      [['set(uint256,address)', W(55) + A1], ['p()', '']],
    );
  });
  it('constant getter (value + string) and immutable getter', async () => {
    await eqCalls(
      `class C { static K: Visible<u256> = 5n; }`,
      `contract C { uint256 public constant K = 5; }`,
      [['K()', '']],
    );
    await eqCalls(
      `class C { static NAME: Visible<string> = "JETH"; }`,
      `contract C { string public constant NAME = "JETH"; }`,
      [['NAME()', '']],
    );
    await eqCalls(
      `class C { static M: Visible<u64>; constructor() { this.M = 4242n; } }`,
      `contract C { uint64 public immutable M; constructor() { M = 4242; } }`,
      [['M()', '']],
    );
  });
  it('public field in an abstract base is inherited into the deployed getter surface', async () => {
    await eqCalls(
      `abstract class Base { total: Visible<u256>; bump(v: u256): External<void> { this.total = this.total + v; } } class C extends Base { }`,
      `abstract contract Base { uint256 public total; function bump(uint256 v) external { total += v; } } contract C is Base { }`,
      [['bump(uint256)', W(9)], ['total()', '']],
    );
  });
  it('@override marker getter var implementing a base @virtual function', async () => {
    await eqCalls(
      `abstract class A { @virtual x(): External<u256>; } class C extends A { @override x: Visible<u256>; set(v: u256): External<void> { this.x = v; } }`,
      `abstract contract A { function x() external view virtual returns (uint256); } contract C is A { uint256 public override x; function set(uint256 v) external { x = v; } }`,
      [['set(uint256)', W(42)], ['x()', ''], ['set(uint256)', W(9)], ['x()', '']],
    );
  });
});

describe('Visible<T> field marker rejects (misuse stays loud, nothing silently accepted)', () => {
  it('a #-private field cannot be Visible<T> (contradiction, JETH352)', () => {
    expect(codes(`class C { #x: Visible<u256> = 7n; }`)).toContain('JETH352');
    expect(codes(`class C { static #K: Visible<u256> = 5n; }`)).toContain('JETH352');
    expect(messages(`class C { #x: Visible<u256> = 7n; }`).join(' ')).toContain('cannot be Visible<T>');
  });
  it('Visible<T> arity: zero / two type args reject (JETH482)', () => {
    expect(codes(`class C { x: Visible = 7n; }`)).toContain('JETH482');
    expect(codes(`class C { x: Visible<u256, u256> = 7n; }`)).toContain('JETH482');
  });
  it('a nested marker / declaration head inside Visible<...> rejects (JETH482)', () => {
    expect(codes(`class C { x: Visible<Visible<u256>>; }`)).toContain('JETH482');
    expect(codes(`class C { x: Visible<External<u256>>; }`)).toContain('JETH482');
    expect(codes(`class C { X: Visible<error<{ a: u256 }>>; }`)).toContain('JETH482');
    expect(codes(`class C { X: Visible<event<{ a: u256 }>>; }`)).toContain('JETH482');
  });
  it('External<T> on a FIELD rejects with the Visible<T> pointer (JETH482)', () => {
    for (const src of [
      `class C { x: External<u256> = 7n; }`,
      `class C { static K: External<u256> = 5n; }`,
      `class C { static M: External<address>; constructor() { this.M = msg.sender; } }`,
      `class C { balances: External<mapping<address, u256>>; }`,
    ]) {
      expect(codes(src), src).toContain('JETH482');
      expect(messages(src).join(' '), src).toContain('on a field the visibility marker is Visible<T>');
    }
  });
  it('the FUNCTION markers have no meaning on a field (JETH482)', () => {
    expect(codes(`class C { x: Payable<u256> = 7n; }`)).toContain('JETH482');
    expect(codes(`class C { x: View<u256> = 7n; }`)).toContain('JETH482');
    expect(codes(`class C { x: Pure<u256> = 7n; }`)).toContain('JETH482');
    expect(messages(`class C { x: View<u256> = 7n; }`).join(' ')).toContain('a public field is spelled Visible<T>');
  });
  it('Visible<T> on a METHOD return rejects with the External<T> pointer (JETH482)', () => {
    for (const src of [
      `class C { x: u256; f(v: u256): Visible<void> { this.x = v; } }`,
      `class C { f(): Visible<u256> { return 1n; } }`,
      `class C { x: u256 = 3n; get f(): Visible<u256> { return this.x; } }`,
      `class C { static f(): Visible<u256> { return 1n; } }`,
      `abstract class B { f(): Visible<void>; } class C extends B { f(): External<void> { } }`,
      `static class L { f(): Visible<u256> { return 1n; } } class C { x: u256; g(v: u256): External<void> { this.x = v; } }`,
    ]) {
      expect(codes(src), src).toContain('JETH482');
      expect(messages(src).join(' '), src).toContain('Visible<T> marks a public FIELD');
    }
  });
  it('Visible<T> in the remaining non-field positions stays a loud reject (JETH013/JETH384 family)', () => {
    expect(codes(`class C { x: u256; f(): External<u256> { const v: Visible<u256> = 7n; return v; } }`)).toContain('JETH013');
    expect(codes(`class C { f(v: Visible<u256>): External<void> { } }`)).toContain('JETH013');
    expect(codes(`class C { constructor(v: Visible<u256>) { } }`)).toContain('JETH013');
    expect(codes(`type Q = { x: Visible<u256>; }; class C { p: Q; }`)).toContain('JETH013');
    expect(codes(`interface I { f(): Visible<u256>; } class C { i: I; g(v: address): External<void> { this.i = I(v); } }`)).toContain('JETH013');
    // special entries: a receive/fallback return type is gated before marker resolution (JETH384)
    expect(codes(`class C { receive(): Visible<void> { } }`)).toContain('JETH384');
    expect(codes(`class C { fallback(): Visible<void> { } }`)).toContain('JETH384');
  });
  it('the retired `// use @decorators` pragma is a hard reject (native is the only syntax now) -> JETH480', () => {
    // native adjudication: this cell used to prove the Visible<T> marker was native-ONLY (an unknown type
    // JETH013 under the legacy decorator pragma). Stage-2 removed the dual-mode pragma entirely, so the
    // `// use @decorators` line is now retired (JETH480) and short-circuits before any marker resolution.
    expect(codes(`// use @decorators\n@contract class C { @state x: Visible<u256>; }`)).toContain('JETH480');
  });
  it('the RESERVED_MARKERS gate: a declaration cannot be named Visible or External (JETH038)', () => {
    expect(codes(`class Visible { } class C { x: u256; }`)).toContain('JETH038');
    expect(codes(`type Visible = { a: u256 }; class C { x: u256; }`)).toContain('JETH038');
    expect(codes(`interface Visible { f(): View<u256>; } class C { x: u256; }`)).toContain('JETH038');
    expect(codes(`class External { } class C { x: u256; }`).length).toBeGreaterThan(0);
  });
  it('non-constant initializer on a marker state field rejects like the twin (JETH048)', () => {
    expect(codes(`class C { x: Visible<u256> = msg.value; }`)).toContain('JETH048');
    expect(codes(`class C { x: Visible<u256> = msg.value; }`)).toContain('JETH048');
  });
  it('duplicate names with a marker field stay clean rejects', () => {
    expect(codes(`class C { x: Visible<u256>; x: u256; }`)).toContain('JETH373');
    expect(codes(`abstract class B { x: Visible<u256>; } class C extends B { x: u256; }`)).toContain('JETH373');
  });
});

describe('non-vacuity: the marker actually synthesizes the getter', () => {
  it('a BARE field stays internal (no getter): marker vs bare bytecode DIFFERS', () => {
    expect(bc(`class C { x: Visible<u256> = 7n; }`)).not.toBe(bc(`class C { x: u256 = 7n; }`));
  });
  it('a static without the marker stays a non-public constant / immutable', () => {
    expect(bc(`class C { static K: Visible<u256> = 5n; get f(): External<u256> { return C.K; } }`))
      .not.toBe(bc(`class C { static K: u256 = 5n; get f(): External<u256> { return C.K; } }`));
    expect(bc(`class C { static M: Visible<u64>; constructor() { this.M = 4n; } get f(): External<u64> { return this.M; } }`))
      .not.toBe(bc(`class C { static M: u64; constructor() { this.M = 4n; } get f(): External<u64> { return this.M; } }`));
  });
  it('the getter selector answers on the marker contract and reverts on the bare one', async () => {
    const h = await Harness.create();
    const withGetter = await h.deploy(bc(`class C { x: Visible<u256> = 7n; }`));
    const bare = await h.deploy(bc(`class C { x: u256 = 7n; }`));
    const rg = await h.call(withGetter, sel('x()'));
    expect(rg.success).toBe(true);
    expect(rg.returnHex).toBe('0x' + W(7));
    const rb = await h.call(bare, sel('x()'));
    expect(rb.success).toBe(false);
  });
});
