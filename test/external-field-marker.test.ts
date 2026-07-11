// P0b - the `External<T>` FIELD marker: the native spelling of the @external field decorator
// (solc's `public` state variable / constant / immutable with an auto-generated getter).
//   x: External<u256>                    = @external @state x: u256          (state getter)
//   balances: External<mapping<K, V>>    = @external @state balances         (parameterized getter)
//   static K: External<u256> = 5n;       = @external @constant K / @external static K   (constant getter)
//   static M: External<address>;         = @external @immutable M / @external static M  (view getter)
// The marker unwraps to the inner type BEFORE field classification and routes through the EXACT
// machinery the decorator uses (publicStateNames / publicConstantNames / publicImmutableNames), so the
// ORACLE is twin-bytecode equality: for every shape both spellings must produce byte-identical
// creationBytecode (which also pins getter selectors + ABI - the capture-diff migration depends on it).
// A runtime differential vs solc re-proves the getter surface, reject controls pin the misuse space,
// and non-vacuity pairs prove the marker actually synthesizes a getter (bare field stays internal).
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

describe('External<T> field marker == @external decorator twin (creationBytecode equality)', () => {
  const twins: [string, string, string][] = [
    ['u256 state', `class C { x: External<u256> = 7n; }`, `class C { @external @state x: u256 = 7n; }`],
    ['address state', `class C { a: External<address>; f(v: address): External<void> { this.a = v; } }`,
      `class C { @external @state a: address; f(v: address): External<void> { this.a = v; } }`],
    ['bool state', `class C { flag: External<bool> = true; }`, `class C { @external @state flag: bool = true; }`],
    ['bytes8 state', `class C { h: External<bytes8>; set(v: bytes8): External<void> { this.h = v; } }`,
      `class C { @external @state h: bytes8; set(v: bytes8): External<void> { this.h = v; } }`],
    ['string state', `class C { name: External<string>; set(v: string): External<void> { this.name = v; } }`,
      `class C { @external @state name: string; set(v: string): External<void> { this.name = v; } }`],
    ['bytes state', `class C { blob: External<bytes>; set(v: bytes): External<void> { this.blob = v; } }`,
      `class C { @external @state blob: bytes; set(v: bytes): External<void> { this.blob = v; } }`],
    ['mapping 1-key', `class C { balances: External<mapping<address, u256>>; set(k: address, v: u256): External<void> { this.balances[k] = v; } }`,
      `class C { @external @state balances: mapping<address, u256>; set(k: address, v: u256): External<void> { this.balances[k] = v; } }`],
    ['mapping 2-key nested', `class C { allow: External<mapping<address, mapping<address, u256>>>; set(a: address, b: address, v: u256): External<void> { this.allow[a][b] = v; } }`,
      `class C { @external @state allow: mapping<address, mapping<address, u256>>; set(a: address, b: address, v: u256): External<void> { this.allow[a][b] = v; } }`],
    ['dyn array', `class C { xs: External<u256[]>; push(v: u256): External<void> { this.xs.push(v); } }`,
      `class C { @external @state xs: u256[]; push(v: u256): External<void> { this.xs.push(v); } }`],
    ['fixed array', `class C { fa: External<Arr<u256, 3>>; set(i: u256, v: u256): External<void> { this.fa[i] = v; } }`,
      `class C { @external @state fa: Arr<u256, 3>; set(i: u256, v: u256): External<void> { this.fa[i] = v; } }`],
    ['struct field (flattened getter)', `${P} class C { p: External<P>; set(a: u256, b: address): External<void> { this.p.a = a; this.p.b = b; } }`,
      `${P} class C { @external @state p: P; set(a: u256, b: address): External<void> { this.p.a = a; this.p.b = b; } }`],
    ['mapping to struct', `${P} class C { m: External<mapping<u256, P>>; set(k: u256, a: u256, b: address): External<void> { this.m[k].a = a; this.m[k].b = b; } }`,
      `${P} class C { @external @state m: mapping<u256, P>; set(k: u256, a: u256, b: address): External<void> { this.m[k].a = a; this.m[k].b = b; } }`],
    ['enum state', `enum Color { Red, Green, Blue } class C { c: External<Color> = Color.Blue; }`,
      `enum Color { Red, Green, Blue } class C { @external @state c: Color = Color.Blue; }`],
    ['i256 state', `class C { s: External<i256> = -5n; }`, `class C { @external @state s: i256 = -5n; }`],
    ['static constant vs @external static', `class C { static K: External<u256> = 5n; }`, `class C { @external static K: u256 = 5n; }`],
    ['static constant vs @external @constant', `class C { static K: External<u256> = 5n; }`, `class C { @external @constant K: u256 = 5n; }`],
    ['string constant', `class C { static NAME: External<string> = "JETH"; }`, `class C { @external @constant NAME: string = "JETH"; }`],
    ['bytes4 constant', `class C { static MAGIC: External<bytes4> = bytes4(0x01020304n); }`, `class C { @external static MAGIC: bytes4 = bytes4(0x01020304n); }`],
    ['immutable vs @external static', `class C { static M: External<address>; constructor() { this.M = msg.sender; } }`,
      `class C { @external static M: address; constructor() { this.M = msg.sender; } }`],
    ['immutable vs @external @immutable', `class C { static M: External<address>; constructor() { this.M = msg.sender; } }`,
      `class C { @external @immutable M: address; constructor() { this.M = msg.sender; } }`],
    ['immutable from ctor arg', `class C { static N: External<u64>; constructor(n: u64) { this.N = n; } }`,
      `class C { @external @immutable N: u64; constructor(n: u64) { this.N = n; } }`],
    ['public field in an abstract base', `abstract class Base { total: External<u256>; bump(v: u256): External<void> { this.total = this.total + v; } } class C extends Base { }`,
      `abstract class Base { @external @state total: u256; bump(v: u256): External<void> { this.total = this.total + v; } } class C extends Base { }`],
    ['marker and decorator mixed per-field (cross)', `class C { x: External<u256> = 3n; @external @state y: u256 = 4n; z: u256 = 5n; }`,
      `class C { @external @state x: u256 = 3n; y: External<u256> = 4n; z: u256 = 5n; }`],
    ['marker beside an internal state field', `class C { hidden1: u256 = 1n; x: External<u256> = 2n; }`,
      `class C { hidden1: u256 = 1n; @external @state x: u256 = 2n; }`],
    ['explicit @state plus marker', `class C { @state x: External<u256> = 7n; }`, `class C { @external @state x: u256 = 7n; }`],
    ['slot packing preserved', `class C { a: External<u64> = 1n; b: External<u64> = 2n; c2: External<u128> = 3n; }`,
      `class C { @external @state a: u64 = 1n; @external @state b: u64 = 2n; @external @state c2: u128 = 3n; }`],
    ['@storage namespace field', `class C { @storage('app') x: External<u256>; set(v: u256): External<void> { this.x = v; } }`,
      `class C { @external @storage('app') x: u256; set(v: u256): External<void> { this.x = v; } }`],
    ['@override getter var (P1-4)', `abstract class A { @virtual @external x(): u256; } class C extends A { @override x: External<u256>; set(v: u256): External<void> { this.x = v; } }`,
      `abstract class A { @virtual @external x(): u256; } class C extends A { @override @external @state x: u256; set(v: u256): External<void> { this.x = v; } }`],
    ['interface obligation satisfied by the marker getter', `@interface class I { @external @view x(): u256; } class C extends I { x: External<u256>; set(v: u256): External<void> { this.x = v; } }`,
      `@interface class I { @external @view x(): u256; } class C extends I { @external @state x: u256; set(v: u256): External<void> { this.x = v; } }`],
  ];
  for (const [label, native, twin] of twins) {
    it(`twin: ${label}`, () => {
      expect(bc(native)).toBe(bc(twin));
    });
  }
});

describe('External<T> field getters run byte-identical to solc (incl. parameterized getters)', () => {
  const A1 = W(0x1111), A2 = W(0x2222);
  it('u256 state getter after writes', async () => {
    await eqCalls(
      `class C { x: External<u256> = 7n; bump(v: u256): External<void> { this.x = this.x + v; } }`,
      `contract C { uint256 public x = 7; function bump(uint256 v) external { x += v; } }`,
      [['bump(uint256)', W(35)], ['x()', '']],
    );
  });
  it('mapping getter is parameterized: balances(address)', async () => {
    await eqCalls(
      `class C { balances: External<mapping<address, u256>>; set(k: address, v: u256): External<void> { this.balances[k] = v; } }`,
      `contract C { mapping(address => uint256) public balances; function set(address k, uint256 v) external { balances[k] = v; } }`,
      [['set(address,uint256)', A1 + W(1234)], ['balances(address)', A1], ['balances(address)', A2]],
    );
  });
  it('2-key nested mapping getter: allow(address,address)', async () => {
    await eqCalls(
      `class C { allow: External<mapping<address, mapping<address, u256>>>; set(a: address, b: address, v: u256): External<void> { this.allow[a][b] = v; } }`,
      `contract C { mapping(address => mapping(address => uint256)) public allow; function set(address a, address b, uint256 v) external { allow[a][b] = v; } }`,
      [['set(address,address,uint256)', A1 + A2 + W(777)], ['allow(address,address)', A1 + A2], ['allow(address,address)', A2 + A1]],
    );
  });
  it('dynamic array indexed getter incl. out-of-bounds revert', async () => {
    await eqCalls(
      `class C { xs: External<u256[]>; push(v: u256): External<void> { this.xs.push(v); } }`,
      `contract C { uint256[] public xs; function push(uint256 v) external { xs.push(v); } }`,
      [['push(uint256)', W(11)], ['push(uint256)', W(22)], ['xs(uint256)', W(0)], ['xs(uint256)', W(1)], ['xs(uint256)', W(2)]],
    );
  });
  it('struct getter returns the flattened tuple', async () => {
    await eqCalls(
      `${P} class C { p: External<P>; set(a: u256, b: address): External<void> { this.p.a = a; this.p.b = b; } }`,
      `contract C { struct P { uint256 a; address b; } P public p; function set(uint256 a, address b) external { p.a = a; p.b = b; } }`,
      [['set(uint256,address)', W(55) + A1], ['p()', '']],
    );
  });
  it('constant getter (value + string) and immutable getter', async () => {
    await eqCalls(
      `class C { static K: External<u256> = 5n; }`,
      `contract C { uint256 public constant K = 5; }`,
      [['K()', '']],
    );
    await eqCalls(
      `class C { static NAME: External<string> = "JETH"; }`,
      `contract C { string public constant NAME = "JETH"; }`,
      [['NAME()', '']],
    );
    await eqCalls(
      `class C { static M: External<u64>; constructor() { this.M = 4242n; } }`,
      `contract C { uint64 public immutable M; constructor() { M = 4242; } }`,
      [['M()', '']],
    );
  });
  it('public field in an abstract base is inherited into the deployed getter surface', async () => {
    await eqCalls(
      `abstract class Base { total: External<u256>; bump(v: u256): External<void> { this.total = this.total + v; } } class C extends Base { }`,
      `abstract contract Base { uint256 public total; function bump(uint256 v) external { total += v; } } contract C is Base { }`,
      [['bump(uint256)', W(9)], ['total()', '']],
    );
  });
  it('@override marker getter var implementing a base @virtual function', async () => {
    await eqCalls(
      `abstract class A { @virtual @external x(): u256; } class C extends A { @override x: External<u256>; set(v: u256): External<void> { this.x = v; } }`,
      `abstract contract A { function x() external view virtual returns (uint256); } contract C is A { uint256 public override x; function set(uint256 v) external { x = v; } }`,
      [['set(uint256)', W(42)], ['x()', ''], ['set(uint256)', W(9)], ['x()', '']],
    );
  });
});

describe('External<T> field marker rejects (misuse stays loud, nothing silently accepted)', () => {
  it('a #-private field cannot be External<T> (contradiction, JETH352)', () => {
    expect(codes(`class C { #x: External<u256> = 7n; }`)).toContain('JETH352');
    expect(codes(`class C { static #K: External<u256> = 5n; }`)).toContain('JETH352');
  });
  it('External<T> arity: zero / two type args reject (JETH482)', () => {
    expect(codes(`class C { x: External = 7n; }`)).toContain('JETH482');
    expect(codes(`class C { x: External<u256, u256> = 7n; }`)).toContain('JETH482');
  });
  it('a nested marker / declaration head inside External<...> rejects (JETH482)', () => {
    expect(codes(`class C { x: External<External<u256>>; }`)).toContain('JETH482');
    expect(codes(`class C { X: External<error<{ a: u256 }>>; }`)).toContain('JETH482');
    expect(codes(`class C { X: External<event<{ a: u256 }>>; }`)).toContain('JETH482');
  });
  it('the FUNCTION markers have no meaning on a field (JETH482)', () => {
    expect(codes(`class C { x: Payable<u256> = 7n; }`)).toContain('JETH482');
    expect(codes(`class C { x: View<u256> = 7n; }`)).toContain('JETH482');
    expect(codes(`class C { x: Pure<u256> = 7n; }`)).toContain('JETH482');
  });
  it('marker misuse positions reject: local, param, struct field (unknown type, JETH013)', () => {
    expect(codes(`class C { f(): External<u256> { const v: External<u256> = 7n; return v; } }`)).toContain('JETH013');
    expect(codes(`class C { f(v: External<u256>): External<void> { } }`)).toContain('JETH013');
    expect(codes(`type Q = { x: External<u256>; }; class C { p: Q; }`)).toContain('JETH013');
  });
  it('decorator mode: the marker stays an unknown type (native-gated, JETH013)', () => {
    expect(codes(`// use @decorators\n@contract class C { @state x: External<u256>; }`)).toContain('JETH013');
  });
  it('the RESERVED_MARKERS gate is unchanged: a declaration cannot be named External', () => {
    expect(codes(`class External { } class C { x: u256; }`).length).toBeGreaterThan(0);
  });
  it('non-constant initializer on a marker state field rejects like the twin (JETH048)', () => {
    expect(codes(`class C { x: External<u256> = msg.value; }`)).toContain('JETH048');
    expect(codes(`class C { @external @state x: u256 = msg.value; }`)).toContain('JETH048');
  });
  it('duplicate names with a marker field stay clean rejects', () => {
    expect(codes(`class C { x: External<u256>; x: u256; }`)).toContain('JETH373');
    expect(codes(`abstract class B { x: External<u256>; } class C extends B { x: u256; }`)).toContain('JETH373');
  });
});

describe('non-vacuity: the marker actually synthesizes the getter', () => {
  it('a BARE field stays internal (no getter): marker vs bare bytecode DIFFERS', () => {
    expect(bc(`class C { x: External<u256> = 7n; }`)).not.toBe(bc(`class C { x: u256 = 7n; }`));
  });
  it('a static without the marker stays a non-public constant / immutable', () => {
    expect(bc(`class C { static K: External<u256> = 5n; get f(): External<u256> { return C.K; } }`))
      .not.toBe(bc(`class C { static K: u256 = 5n; get f(): External<u256> { return C.K; } }`));
    expect(bc(`class C { static M: External<u64>; constructor() { this.M = 4n; } get f(): External<u64> { return this.M; } }`))
      .not.toBe(bc(`class C { static M: u64; constructor() { this.M = 4n; } get f(): External<u64> { return this.M; } }`));
  });
  it('the getter selector answers on the marker contract and reverts on the bare one', async () => {
    const h = await Harness.create();
    const withGetter = await h.deploy(bc(`class C { x: External<u256> = 7n; }`));
    const bare = await h.deploy(bc(`class C { x: u256 = 7n; }`));
    const rg = await h.call(withGetter, sel('x()'));
    expect(rg.success).toBe(true);
    expect(rg.returnHex).toBe('0x' + W(7));
    const rb = await h.call(bare, sel('x()'));
    expect(rb.success).toBe(false);
  });
});
