// W3-A4: call / interface / getter over-rejection lifts, byte-identical to solc 0.8.35.
//  P1-12: `this.f({ value, gas })` payable/gas self-call options (solc `this.f{value:e}()`).
//  P1-8 : calldata VALUE-element array slicing `a.slice(start[, end])` (solc `a[start:end]`).
//  P1-11: `let [a, b] = L.mm(x)` tuple destructure of an @external (delegatecall) @library call.
//  P1-4 : a `@external @state` getter var carrying `@override` implementing a base @virtual /
//         @interface function (solc `uint256 public override x;`).
// Each lift: MATCH byte-identical across a value spread, adjacent shapes solc REJECTS still reject
// (no over-acceptance), and the invalid-override guards reject a loosened getter.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, compileSolidityLinked, deploySolLinked } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n)).toString();
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

function codesOf(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    return ((e as { diagnostics?: { code: string }[] }).diagnostics ?? []).map((d) => d.code);
  }
}
const accepts = (src: string) => codesOf(src).length === 0;
const solcAccepts = (src: string) => {
  try {
    compileSolidity(SPDX + src, 'C');
    return true;
  } catch {
    return false;
  }
};

async function eqCalls(jeth: string, sol: string, calls: [string, string][], opts: { value?: bigint } = {}) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  const callOpt = opts.value !== undefined ? { value: opts.value } : {};
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + (args ?? ''), callOpt);
    const rs = await hs.call(as, sel(sig) + (args ?? ''), callOpt);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

async function eqCallsLinked(jeth: string, sol: string, calls: [string, string][], libs = ['L']) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = (await hj.deployLinked(compile(jeth, { fileName: 'C.jeth' }))).address;
  const as = await deploySolLinked(hs, compileSolidityLinked(SPDX + sol, 'C', libs));
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + (args ?? ''));
    const rs = await hs.call(as, sel(sig) + (args ?? ''));
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

// =====================================================================================
describe('P1-12: this.f({ value, gas }) payable/gas self-call options', () => {
  it('value forwarded on a payable self-call (observed via msg.value), across a spread', async () => {
    await eqCalls(
      `@contract class C {
        @external @payable pay(): u256 { return msg.value; }
        @external @payable fwd(e: u256): u256 { return this.pay({ value: e }); }
      }`,
      `contract C {
        function pay() external payable returns (uint256) { return msg.value; }
        function fwd(uint256 e) external payable returns (uint256) { return this.pay{value: e}(); }
      }`,
      [['fwd(uint256)', W(0)], ['fwd(uint256)', W(3)], ['fwd(uint256)', W(10)]],
      { value: 10n },
    );
  });

  it('value + positional args self-call', async () => {
    await eqCalls(
      `@contract class C {
        @external @payable pay(a: u256, b: u256): u256 { return msg.value + a + b; }
        @external @payable fwd(e: u256): u256 { return this.pay(2n, 5n, { value: e }); }
      }`,
      `contract C {
        function pay(uint256 a, uint256 b) external payable returns (uint256) { return msg.value + a + b; }
        function fwd(uint256 e) external payable returns (uint256) { return this.pay{value: e}(2, 5); }
      }`,
      [['fwd(uint256)', W(4)]],
      { value: 10n },
    );
  });

  it('gas option only, and value+gas together', async () => {
    await eqCalls(
      `@contract class C {
        @external echo(x: u256): u256 { return x; }
        @external run(): u256 { return this.echo(11n, { gas: 60000n }); }
      }`,
      `contract C {
        function echo(uint256 x) external returns (uint256) { return x; }
        function run() external returns (uint256) { return this.echo{gas: 60000}(11); }
      }`,
      [['run()', '']],
    );
    await eqCalls(
      `@contract class C {
        @external @payable pay(): u256 { return msg.value; }
        @external @payable fwd(e: u256): u256 { return this.pay({ value: e, gas: 90000n }); }
      }`,
      `contract C {
        function pay() external payable returns (uint256) { return msg.value; }
        function fwd(uint256 e) external payable returns (uint256) { return this.pay{value: e, gas: 90000}(); }
      }`,
      [['fwd(uint256)', W(7)]],
      { value: 20n },
    );
  });

  it('plain this.f() with no options still works', async () => {
    await eqCalls(
      `@contract class C {
        @external @payable pay(): u256 { return msg.value; }
        @external @payable fwd(): u256 { return this.pay(); }
      }`,
      `contract C {
        function pay() external payable returns (uint256) { return msg.value; }
        function fwd() external payable returns (uint256) { return this.pay(); }
      }`,
      [['fwd()', '']],
      { value: 50n },
    );
  });

  it('DISAMBIGUATION: this.pay({value:5}) where pay has a param named `value` is a NAMED ARG (msg.value stays 0)', async () => {
    await eqCalls(
      `@contract class C {
        @external @payable pay(value: u256): [u256, u256] { return [value, msg.value]; }
        @external @payable fwd(): [u256, u256] { return this.pay({ value: 5n }); }
      }`,
      `contract C {
        function pay(uint256 value) external payable returns (uint256, uint256) { return (value, msg.value); }
        function fwd() external payable returns (uint256, uint256) { return this.pay({value: 5}); }
      }`,
      [['fwd()', '']],
      { value: 40n },
    );
  });

  it('REJECT: value option on a non-payable / internal target, unknown option key, non-int value', () => {
    // value on a non-payable self-call
    expect(accepts(`@contract class C { @external np(): u256 { return 1n; } @external @payable f(e: u256): u256 { return this.np({ value: e }); } }`)).toBe(false);
    // options on an internal (non-external) target
    expect(codesOf(`@contract class C { priv(): u256 { return 1n; } @external @payable f(e: u256): u256 { return this.priv({ value: e }); } }`)).toContain('JETH432');
    // non-integer value
    expect(accepts(`@contract class C { @external @payable pay(): u256 { return msg.value; } @external @payable f(t: address): u256 { return this.pay({ value: t }); } }`)).toBe(false);
  });
});

// =====================================================================================
describe('P1-8: calldata value-element array slicing a.slice(start[, end])', () => {
  const arr = (...xs: number[]) => W(0x20) + W(xs.length) + xs.map((x) => W(x)).join('');

  it('element read a.slice(1)[i] across indices', async () => {
    await eqCalls(
      `@contract class C { @external @view f(a: u256[], i: u256): u256 { return a.slice(1n)[i]; } }`,
      `contract C { function f(uint256[] calldata a, uint256 i) external pure returns (uint256) { return a[1:][i]; } }`,
      [['f(uint256[],uint256)', arr(11, 22, 33, 44, 55) + W(0)], ['f(uint256[],uint256)', arr(11, 22, 33, 44, 55) + W(3)]],
    );
  });

  it('bound-local .length across start; direct return of 2-arg slice incl. empty', async () => {
    await eqCalls(
      `@contract class C { @external @view f(a: u256[], s: u256): u256 { let b: u256[] = a.slice(s); return b.length; } }`,
      `contract C { function f(uint256[] calldata a, uint256 s) external pure returns (uint256) { uint256[] calldata b = a[s:]; return b.length; } }`,
      [['f(uint256[],uint256)', arr(11, 22, 33, 44, 55) + W(0)], ['f(uint256[],uint256)', arr(11, 22, 33, 44, 55) + W(5)]],
    );
    await eqCalls(
      `@contract class C { @external @view f(a: u256[], s: u256, e: u256): u256[] { return a.slice(s, e); } }`,
      `contract C { function f(uint256[] calldata a, uint256 s, uint256 e) external pure returns (uint256[] memory) { return a[s:e]; } }`,
      [
        ['f(uint256[],uint256,uint256)', arr(11, 22, 33, 44, 55) + W(1) + W(4)],
        ['f(uint256[],uint256,uint256)', arr(11, 22, 33, 44, 55) + W(2) + W(2)],
        ['f(uint256[],uint256,uint256)', arr(11, 22, 33, 44, 55) + W(0) + W(5)],
      ],
    );
  });

  it('REVERT cases byte-identical: start>end, end>len, and element OOB Panic(0x32)', async () => {
    await eqCalls(
      `@contract class C { @external @view f(a: u256[], s: u256, e: u256): u256[] { return a.slice(s, e); } }`,
      `contract C { function f(uint256[] calldata a, uint256 s, uint256 e) external pure returns (uint256[] memory) { return a[s:e]; } }`,
      [
        ['f(uint256[],uint256,uint256)', arr(11, 22, 33, 44, 55) + W(3) + W(1)], // start>end
        ['f(uint256[],uint256,uint256)', arr(11, 22, 33, 44, 55) + W(0) + W(6)], // end>len
        ['f(uint256[],uint256,uint256)', arr(11, 22, 33, 44, 55) + W(5) + W(10)], // both OOB
      ],
    );
    await eqCalls(
      `@contract class C { @external @view f(a: u256[], i: u256): u256 { return a.slice(2n)[i]; } }`,
      `contract C { function f(uint256[] calldata a, uint256 i) external pure returns (uint256) { return a[2:][i]; } }`,
      [['f(uint256[],uint256)', arr(11, 22, 33, 44, 55) + W(3)], ['f(uint256[],uint256)', arr(11, 22, 33, 44, 55) + W(2)]],
    );
  });

  it('other value element types with dirty-bit masking (address / bool / uint32 / int64)', async () => {
    const enc = (words: string[]) => W(0x20) + W(words.length) + words.join('');
    await eqCalls(
      `@contract class C { @external @view f(a: address[]): address[] { let b: address[] = a.slice(0n); return b; } }`,
      `contract C { function f(address[] calldata a) external pure returns (address[] memory) { address[] memory b = a[0:]; return b; } }`,
      [['f(address[])', enc(['ff'.repeat(12) + 'aa'.repeat(20)])]], // dirty upper bits masked
    );
    await eqCalls(
      `@contract class C { @external @view f(a: bool[]): bool[] { return a.slice(1n); } }`,
      `contract C { function f(bool[] calldata a) external pure returns (bool[] memory) { return a[1:]; } }`,
      [['f(bool[])', enc([W(1), W(5), W(255)])]], // dirty bool masked to 1
    );
    await eqCalls(
      `@contract class C { @external @view f(a: u32[]): u32[] { return a.slice(0n); } }`,
      `contract C { function f(uint32[] calldata a) external pure returns (uint32[] memory) { return a[0:]; } }`,
      [['f(uint32[])', enc(['ff'.repeat(28) + '000000ff', W(0xdeadbeef)])]],
    );
    await eqCalls(
      `@contract class C { @external @view f(a: i64[], i: u256): i64 { return a.slice(1n)[i]; } }`,
      `contract C { function f(int64[] calldata a, uint256 i) external pure returns (int64) { return a[1:][i]; } }`,
      [['f(int64[],uint256)', enc([W(7), 'ff'.repeat(32), W(3)]) + W(0)]],
    );
  });

  it('slice-of-slice element read + bound length', async () => {
    const enc = W(0x20) + W(5) + [10, 20, 30, 40, 50].map((x) => W(x)).join('');
    await eqCalls(
      `@contract class C { @external @view f(a: u256[], i: u256): u256 { return a.slice(1n).slice(1n)[i]; } }`,
      `contract C { function f(uint256[] calldata a, uint256 i) external pure returns (uint256) { return a[1:][1:][i]; } }`,
      [['f(uint256[],uint256)', enc + W(0)]],
    );
  });

  it('REJECT: .length on an unbound slice expression; struct/dynamic-element/non-calldata slices', () => {
    // solc: "Member length not found ... in uint256[] calldata slice" -> reject the unbound-slice .length
    expect(accepts(`@contract class C { @external @view f(a: u256[]): u256 { return a.slice(1n).length; } }`)).toBe(false);
    expect(solcAccepts(`contract C { function f(uint256[] calldata a) external pure returns (uint256) { return a[1:].length; } }`)).toBe(false);
    // static-struct element slice: left rejected (element field-read codec not wired) - no miscompile
    expect(accepts(`@struct class P { x: u256; y: u256; } @contract class C { @external @view f(a: P[], i: u256): u256 { return a.slice(1n)[i].y; } }`)).toBe(false);
    // dynamic-element slices left rejected
    expect(accepts(`@contract class C { @external @view f(a: bytes[]): bytes { return a.slice(1n)[0n]; } }`)).toBe(false);
    expect(accepts(`@contract class C { @external @view f(a: u256[][]): u256 { return a.slice(1n)[0n][0n]; } }`)).toBe(false);
  });
});

// =====================================================================================
describe('P1-11: tuple destructure of an @external (delegatecall) library call', () => {
  it('2-tuple and 3-tuple value returns across a spread', async () => {
    await eqCallsLinked(
      `@library class L { @external @pure mm(x: u256): [u256, u256] { return [x + 1n, x + 2n]; } }
       @contract class C { @external @pure go(x: u256): u256 { let [a, b] = L.mm(x); return a * 100n + b; } }`,
      `library L { function mm(uint256 x) external pure returns (uint256, uint256) { return (x + 1, x + 2); } }
       contract C { function go(uint256 x) external pure returns (uint256) { (uint256 a, uint256 b) = L.mm(x); return a * 100 + b; } }`,
      [['go(uint256)', W(0)], ['go(uint256)', W(5)], ['go(uint256)', W(255)]],
    );
    await eqCallsLinked(
      `@library class L { @external @pure mm(x: u256): [u256, u256, u256] { return [x, x + 1n, x + 2n]; } }
       @contract class C { @external @pure go(x: u256): u256 { let [a, b, c] = L.mm(x); return a + b * 10n + c * 100n; } }`,
      `library L { function mm(uint256 x) external pure returns (uint256, uint256, uint256) { return (x, x + 1, x + 2); } }
       contract C { function go(uint256 x) external pure returns (uint256) { (uint256 a, uint256 b, uint256 c) = L.mm(x); return a + b * 10 + c * 100; } }`,
      [['go(uint256)', W(7)]],
    );
  });

  it('mixed-type and dynamic (bytes / u256[]) tuple components', async () => {
    await eqCallsLinked(
      `@library class L { @external @pure mm(x: u256): [address, bool, u256] { return [address(u160(x)), x > 0n, x * 2n]; } }
       @contract class C { @external @pure go(x: u256): u256 { let [a, f, n] = L.mm(x); return (f ? n : 0n) + u256(u160(a)); } }`,
      `library L { function mm(uint256 x) external pure returns (address, bool, uint256) { return (address(uint160(x)), x > 0, x * 2); } }
       contract C { function go(uint256 x) external pure returns (uint256) { (address a, bool f, uint256 n) = L.mm(x); return (f ? n : 0) + uint256(uint160(a)); } }`,
      [['go(uint256)', W(0)], ['go(uint256)', W(100)]],
    );
    await eqCallsLinked(
      `@library class L { @external @pure mm(x: u256): [u256, u256[]] { let xs: u256[] = [x, x + 1n]; return [x, xs]; } }
       @contract class C { @external @pure go(x: u256): u256 { let [a, xs] = L.mm(x); return a + xs[0n] + xs[1n]; } }`,
      `library L { function mm(uint256 x) external pure returns (uint256, uint256[] memory) { uint256[] memory xs = new uint256[](2); xs[0]=x; xs[1]=x+1; return (x, xs); } }
       contract C { function go(uint256 x) external pure returns (uint256) { (uint256 a, uint256[] memory xs) = L.mm(x); return a + xs[0] + xs[1]; } }`,
      [['go(uint256)', W(4)], ['go(uint256)', W(10)]],
    );
  });

  it('INTERNAL library tuple destructure still works (regression)', async () => {
    await eqCallsLinked(
      `@library class L { mm(x: u256): [u256, u256] { return [x, x + 1n]; } }
       @contract class C { @external @pure go(x: u256): u256 { let [a, b] = L.mm(x); return a * 10n + b; } }`,
      `library L { function mm(uint256 x) internal pure returns (uint256, uint256) { return (x, x + 1); } }
       contract C { function go(uint256 x) external pure returns (uint256) { (uint256 a, uint256 b) = L.mm(x); return a * 10 + b; } }`,
      [['go(uint256)', W(9)]],
      [],
    );
  });

  it('REJECT: wrong-arity / single-return (dyn-struct component now LIFTED, W5D-3)', () => {
    expect(accepts(`@library class L { @external @pure mm(x: u256): [u256, u256] { return [x, x]; } } @contract class C { @external @pure go(x: u256): u256 { let [a, b, c] = L.mm(x); return a; } }`)).toBe(false);
    expect(accepts(`@library class L { @external @pure mm(x: u256): u256 { return x; } } @contract class C { @external @pure go(x: u256): u256 { let [a, b] = L.mm(x); return a; } }`)).toBe(false);
    // W5D-3: a DYNAMIC-struct tuple component decodes through the same abiDecode source the interface
    // tuple path uses (buildDynStructFromMemBlob), so this shape is now accepted (behavior verified
    // byte-identical in library-tuple-dyn-struct.test.ts).
    expect(accepts(`@struct class D { xs: u256[]; } @library class L { @external @pure mm(): [u256, D] { let xs: u256[] = [1n]; return [1n, D(xs)]; } } @contract class C { @external @pure go(): u256 { let [a, d] = L.mm(); return a; } }`)).toBe(true);
  });
});

// =====================================================================================
describe('P1-4: getter var overriding/implementing a base virtual / interface function', () => {
  it('getter override of a view / nonpayable / concrete base returns the stored value', async () => {
    await eqCalls(
      `@abstract class A { @virtual @external x(): u256; }
       @contract class C extends A { @override @external @state x: u256; @external set(v: u256): void { this.x = v; } }`,
      `abstract contract A { function x() external view virtual returns (uint256); }
       contract C is A { uint256 public override x; function set(uint256 v) external { x = v; } }`,
      [['set(uint256)', W(0)], ['x()', ''], ['set(uint256)', W(42)], ['x()', '']],
    );
    // nonpayable base (a view getter may override it), and a concrete-body base:
    await eqCalls(
      `@abstract class A { @virtual @external x(): u256; }
       @contract class C extends A { @override @external @state x: u256; @external set(v: u256): void { this.x = v; } }`,
      `abstract contract A { function x() external virtual returns (uint256); }
       contract C is A { uint256 public override x; function set(uint256 v) external { x = v; } }`,
      [['set(uint256)', W(7)], ['x()', '']],
    );
    await eqCalls(
      `@abstract class A { @virtual @external x(): u256 { return 111n; } }
       @contract class C extends A { @override @external @state x: u256; @external set(v: u256): void { this.x = v; } }`,
      `abstract contract A { function x() external view virtual returns (uint256) { return 111; } }
       contract C is A { uint256 public override x; function set(uint256 v) external { x = v; } }`,
      [['set(uint256)', W(9)], ['x()', '']],
    );
  });

  it('interface-implementing getter, mapping getter, address getter', async () => {
    await eqCalls(
      `@interface class I { @external x(): u256; }
       @contract class C extends I { @override @external @state x: u256; @external set(v: u256): void { this.x = v; } }`,
      `interface I { function x() external view returns (uint256); }
       contract C is I { uint256 public override x; function set(uint256 v) external { x = v; } }`,
      [['set(uint256)', W(99)], ['x()', '']],
    );
    const kw = '00'.repeat(12) + '11'.repeat(20);
    await eqCalls(
      `@abstract class A { @virtual @external m(k: address): u256; }
       @contract class C extends A { @override @external @state m: mapping<address,u256>; @external set(k: address, v: u256): void { this.m[k] = v; } }`,
      `abstract contract A { function m(address) external view virtual returns (uint256); }
       contract C is A { mapping(address=>uint256) public override m; function set(address k, uint256 v) external { m[k] = v; } }`,
      [['set(address,uint256)', kw + W(5)], ['m(address)', kw]],
    );
    const aw = '00'.repeat(12) + 'ab'.repeat(20);
    await eqCalls(
      `@abstract class A { @virtual @external o(): address; }
       @contract class C extends A { @override @external @state o: address; @external set(v: address): void { this.o = v; } }`,
      `abstract contract A { function o() external view virtual returns (address); }
       contract C is A { address public override o; function set(address v) external { o = v; } }`,
      [['set(address)', aw], ['o()', '']],
    );
  });

  it('getter override coexisting with a same-name overload dispatches correctly', async () => {
    await eqCalls(
      `@abstract class A { @virtual @external x(): u256; }
       @contract class C extends A { @override @external @state x: u256; @external @view x2(a: u256): u256 { return a * 3n; } @external set(v: u256): void { this.x = v; } }`,
      `abstract contract A { function x() external view virtual returns (uint256); }
       contract C is A { uint256 public override x; function x2(uint256 a) external view returns (uint256) { return a * 3; } function set(uint256 v) external { x = v; } }`,
      [['set(uint256)', W(50)], ['x()', ''], ['x2(uint256)', W(7)]],
    );
  });

  it('REJECT (no over-acceptance): loosened mutability / wrong return type / param mismatch / non-virtual / override-nothing', () => {
    // base pure -> getter (view) loosens
    expect(accepts(`@abstract class A { @virtual @external @pure x(): u256; } @contract class C extends A { @override @external @state x: u256; }`)).toBe(false);
    // base payable
    expect(accepts(`@abstract class A { @virtual @external @payable x(): u256; } @contract class C extends A { @override @external @state x: u256; }`)).toBe(false);
    // return type mismatch (u128 base, u256 getter)
    expect(accepts(`@abstract class A { @virtual @external x(): u128; } @contract class C extends A { @override @external @state x: u256; }`)).toBe(false);
    // return type mismatch (u256 base, address getter)
    expect(accepts(`@abstract class A { @virtual @external x(): u256; } @contract class C extends A { @override @external @state x: address; }`)).toBe(false);
    // param mismatch (base has a param, plain-var getter has none)
    expect(accepts(`@abstract class A { @virtual @external x(a: u256): u256; } @contract class C extends A { @override @external @state x: u256; }`)).toBe(false);
    // base not virtual
    expect(accepts(`@abstract class A { @external x(): u256 { return 1n; } } @contract class C extends A { @override @external @state x: u256; }`)).toBe(false);
    // @override but no base function of that name
    expect(codesOf(`@contract class C { @override @external @state x: u256; }`)).toContain('JETH433');
    // mapping key-type mismatch
    expect(accepts(`@abstract class A { @virtual @external m(k: u256): u256; } @contract class C extends A { @override @external @state m: mapping<address,u256>; }`)).toBe(false);
  });
});
