// Phase 5 - FULL MODIFIER PARITY: the last four @modifier over-rejections (JETH320 multiple `_`
// placeholders; JETH322 aggregate modifier parameter; JETH323 post-code on an aggregate-param / multi-
// value-return / aggregate-return function; JETH325 a bare `return;` in a modifier body) are now LIFTED.
// Each is verified BYTE-IDENTICAL to solc 0.8.35 (returndata + raw storage slots + revert) by deploying
// a JETH contract and a solc mirror with the same modifier shape and diffing observable output. The kept
// rejects (a value-return modifier, a constructor with a post-code modifier) are confirmed to still fire.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const owner = new Address(Buffer.from('1111111111111111111111111111111111111111', 'hex'));
const sel = (s: string) => functionSelector(s);
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
async function depJ(src: string, caller = owner) {
  const h = await Harness.create();
  await h.fund(caller, 10n ** 20n);
  return { h, a: await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode, { caller }) };
}
async function depS(src: string, caller = owner) {
  const h = await Harness.create();
  await h.fund(caller, 10n ** 20n);
  return { h, a: await h.deploy(compileSolidity(SPDX + src, 'C').creation, { caller }) };
}
/** Deploy J + the solc mirror S, run the same calldata against both, and assert byte-identical
 *  success + returndata + every requested raw storage slot. */
async function diff(J: string, S: string, calldata: string, slots: bigint[] = [], caller = owner) {
  const j = await depJ(J),
    s = await depS(S);
  const rj = await j.h.call(j.a, calldata, { caller });
  const rs = await s.h.call(s.a, calldata, { caller });
  expect(rj.success, 'success').toBe(rs.success);
  expect(rj.returnHex, 'returndata').toBe(rs.returnHex);
  for (const slot of slots) {
    expect(await readSlot(j.h, j.a, slot), `slot ${slot}`).toBe(await readSlot(s.h, s.a, slot));
  }
  return { j, s, rj, rs };
}

describe('Full modifier parity vs solc 0.8.35 (JETH320 / JETH322 / JETH323 / JETH325)', () => {
  // ---------------------------------------------------------------------------
  // JETH320: MULTIPLE `_` placeholders. The wrapped body runs once per placeholder; a value-return
  // yields the LAST run's value, and intervening pre/mid/post code runs in declaration order.
  // ---------------------------------------------------------------------------
  it('JETH320: `m(){ _; _; }` on a state-writing g() runs the body TWICE (raw slot byte-identical)', async () => {
    const J = `class C { n: u256; @modifier twice() { _; _; } @twice bump(): External<void> { this.n = this.n + 1n; } }`;
    const S = `contract C { uint256 n; modifier twice(){ _; _; } function bump() external twice { n = n + 1; } }`;
    const { j } = await diff(J, S, '0x' + sel('bump()'), [0n]);
    // sanity: the body really ran twice
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(2n);
  });

  it('JETH320: `m(){ _; _; }` on a value-return f() returns the LAST run value (byte-identical)', async () => {
    // each run increments n then returns it: two runs => returns 2.
    const J = `class C { n: u256; @modifier twice() { _; _; } @twice f(): External<u256> { this.n = this.n + 1n; return this.n; } }`;
    const S = `contract C { uint256 n; modifier twice(){ _; _; } function f() external twice returns(uint256){ n = n + 1; return n; } }`;
    const { rj } = await diff(J, S, '0x' + sel('f()'), [0n]);
    expect(BigInt(rj.returnHex)).toBe(2n);
  });

  it('JETH320: `pre; _; mid; _; post;` interleaves modifier code and two body runs in order', async () => {
    // n starts 0; pre +1 => 1; body *2 => 2; mid +10 => 12; body *2 => 24; post +100 => 124.
    const J = `class C { n: u256; @modifier weave() { this.n = this.n + 1n; _; this.n = this.n + 10n; _; this.n = this.n + 100n; } @weave run(): External<void> { this.n = this.n * 2n; } }`;
    const S = `contract C { uint256 n; modifier weave(){ n = n + 1; _; n = n + 10; _; n = n + 100; } function run() external weave { n = n * 2; } }`;
    const { j } = await diff(J, S, '0x' + sel('run()'), [0n]);
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(124n);
  });

  // ---------------------------------------------------------------------------
  // JETH322: AGGREGATE modifier parameter. The arg materializes once; the guard reads its length.
  // ---------------------------------------------------------------------------
  it('JETH322: `chk(xs: u256[]){ require(xs.length>0); _; }` fires on empty + passes on non-empty', async () => {
    const J = `class C { n: u256; @modifier chk(xs: u256[]) { require(xs.length > 0n, "empty"); _; } @chk(([])) e(): External<void> { this.n = 1n; } @chk(([7n,8n])) ne(): External<void> { this.n = this.n + 9n; } }`;
    const S = `contract C { uint256 n; modifier chk(uint256[] memory xs){ require(xs.length>0,"empty"); _; } function e() external chk(new uint256[](0)) { n = 1; } function ne() external chk(_two()) { n = n + 9; } function _two() internal pure returns(uint256[] memory r){ r = new uint256[](2); r[0]=7; r[1]=8; } }`;
    // the empty-array branch reverts on BOTH (require fires)
    await diff(J, S, '0x' + sel('e()'), [0n]);
    // the non-empty branch passes on BOTH and writes n
    const { j } = await diff(J, S, '0x' + sel('ne()'), [0n]);
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(9n);
  });

  it('JETH322: a fixed-array modifier param Arr<u256,2> reads an element in the guard', async () => {
    const J = `class C { n: u256; @modifier minHead(a: Arr<u256,2>) { require(a[0n] >= 10n, "lo"); _; } @minHead(([5n,6n])) lo(): External<void> { this.n = 1n; } @minHead(([15n,6n])) hi(): External<void> { this.n = 2n; } }`;
    const S = `contract C { uint256 n; modifier minHead(uint256[2] memory a){ require(a[0]>=10,"lo"); _; } function lo() external minHead([uint256(5),6]) { n = 1; } function hi() external minHead([uint256(15),6]) { n = 2; } }`;
    await diff(J, S, '0x' + sel('lo()'), [0n]); // reverts on both
    const { j } = await diff(J, S, '0x' + sel('hi()'), [0n]); // passes on both
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(2n);
  });

  // ---------------------------------------------------------------------------
  // JETH323: POST-code modifier on a function with an aggregate PARAM, a MULTI-VALUE return, or an
  // aggregate RETURN. The post-code runs AFTER the body and the result is ABI-encoded ONCE.
  // ---------------------------------------------------------------------------
  it('JETH323: post-code modifier on a fn taking u256[] (aggregate param) - byte-identical', async () => {
    const J = `class C { n: u256; @modifier track() { _; this.n = this.n + 1n; } @track sum(xs: u256[]): External<u256> { let t: u256 = 0n; for (let i: u256 = 0n; i < xs.length; i = i + 1n) { t = t + xs[i]; } return t; } }`;
    const S = `contract C { uint256 n; modifier track(){ _; n = n + 1; } function sum(uint256[] memory xs) external track returns(uint256){ uint256 t=0; for (uint256 i=0;i<xs.length;i++){ t += xs[i]; } return t; } }`;
    // calldata: sum([3,4,5]) -> head offset 0x20, len 3, elems
    const cd =
      '0x' +
      sel('sum(uint256[])') +
      pad32(0x20n) +
      pad32(3n) +
      pad32(3n) +
      pad32(4n) +
      pad32(5n);
    const { rj } = await diff(J, S, cd, [0n]);
    expect(BigInt(rj.returnHex)).toBe(12n); // 3+4+5
  });

  it('JETH323: post-code modifier on a MULTI-VALUE return (u256,u256) - byte-identical', async () => {
    const J = `class C { n: u256; @modifier track() { _; this.n = this.n + 1n; } @track pair(x: u256): External<[u256, u256]> { return [x, x + 1n]; } }`;
    const S = `contract C { uint256 n; modifier track(){ _; n = n + 1; } function pair(uint256 x) external track returns(uint256,uint256){ return (x, x+1); } }`;
    const { rj } = await diff(J, S, '0x' + sel('pair(uint256)') + pad32(41n), [0n]);
    expect(rj.returnHex).toBe('0x' + pad32(41n) + pad32(42n));
  });

  it('JETH323: post-code modifier returning a value-element dynamic array u256[] - byte-identical', async () => {
    const J = `class C { n: u256; @modifier track() { _; this.n = this.n + 1n; } @track mk(x: u256): External<u256[]> { return [x, x + 1n, x + 2n]; } }`;
    const S = `contract C { uint256 n; modifier track(){ _; n = n + 1; } function mk(uint256 x) external track returns(uint256[] memory){ uint256[] memory r = new uint256[](3); r[0]=x; r[1]=x+1; r[2]=x+2; return r; } }`;
    const { rj } = await diff(J, S, '0x' + sel('mk(uint256)') + pad32(7n), [0n]);
    // ABI: [0x20][len=3][7][8][9]
    expect(rj.returnHex).toBe('0x' + pad32(0x20n) + pad32(3n) + pad32(7n) + pad32(8n) + pad32(9n));
  });

  it('JETH323: post-code modifier returning a STATIC struct P{x,y} - byte-identical', async () => {
    const J = `type P = { x: u256; y: u256; }; class C { n: u256; @modifier track() { _; this.n = this.n + 1n; } @track mkP(a: u256): External<P> { return P(a, a + 5n); } }`;
    const S = `contract C { struct P { uint256 x; uint256 y; } uint256 n; modifier track(){ _; n = n + 1; } function mkP(uint256 a) external track returns(P memory){ return P(a, a+5); } }`;
    const { rj } = await diff(J, S, '0x' + sel('mkP(uint256)') + pad32(3n), [0n]);
    expect(rj.returnHex).toBe('0x' + pad32(3n) + pad32(8n));
  });

  // ---------------------------------------------------------------------------
  // JETH325: a bare `return;` in a modifier body early-exits the wrapped function with the CURRENT
  // (zero) return values; otherwise the body runs and produces its value.
  // ---------------------------------------------------------------------------
  it('JETH325: `m(){ if (c) return; _; }` early-out returns the ZERO value, else runs the body', async () => {
    const J = `class C { gate: bool; n: u256; @modifier guard() { if (this.gate) { return; } _; } setGate(g: bool): External<void> { this.gate = g; } @guard f(): External<u256> { this.n = this.n + 1n; return 99n; } }`;
    const S = `contract C { bool gate; uint256 n; modifier guard(){ if (gate) { return; } _; } function setGate(bool g) external { gate = g; } function f() external guard returns(uint256){ n = n + 1; return 99; } }`;
    // gate=false: body runs, returns 99, n becomes 1
    {
      const { rj } = await diff(J, S, '0x' + sel('f()'), [1n]);
      expect(BigInt(rj.returnHex)).toBe(99n);
    }
    // gate=true: early `return;` returns the zero value, body skipped (n stays 0)
    {
      const j = await depJ(J),
        s = await depS(S);
      await j.h.call(j.a, '0x' + sel('setGate(bool)') + pad32(1n));
      await s.h.call(s.a, '0x' + sel('setGate(bool)') + pad32(1n));
      const rj = await j.h.call(j.a, '0x' + sel('f()'));
      const rs = await s.h.call(s.a, '0x' + sel('f()'));
      expect(rj.success).toBe(rs.success);
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(BigInt(rj.returnHex)).toBe(0n); // zero value
      expect(await readSlot(j.h, j.a, 1n)).toBe(await readSlot(s.h, s.a, 1n));
      expect(BigInt(await readSlot(j.h, j.a, 1n))).toBe(0n); // body skipped
    }
  });

  it('JETH325: `m(){ _; return; }` (post-placeholder bare return) is a no-op tail, byte-identical', async () => {
    const J = `class C { n: u256; @modifier m() { _; return; } @m f(): External<u256> { this.n = 1n; return 7n; } }`;
    const S = `contract C { uint256 n; modifier m(){ _; return; } function f() external m returns(uint256){ n = 1; return 7; } }`;
    const { rj } = await diff(J, S, '0x' + sel('f()'), [0n]);
    expect(BigInt(rj.returnHex)).toBe(7n);
  });

  // ---------------------------------------------------------------------------
  // KEPT REJECTS: shapes solc ACCEPTS but JETH still rejects must NOT regress, and shapes BOTH reject.
  // ---------------------------------------------------------------------------
  it('a value-return modifier `m(){ return 5n; }` still rejects (JETH324: solc rejects it too)', () => {
    expect(
      codes(`class C { @modifier m() { return 5n; _; } @m get f(): External<u256> { return 1n; } }`),
    ).toContain('JETH324');
    // solc also rejects a value-return inside a modifier
    expect(() =>
      compileSolidity(SPDX + `contract C { modifier m(){ return 5; _; } function f() external m returns(uint256){ return 1; } }`, 'C'),
    ).toThrow();
  });

  it('P1-20: a constructor with a post-code modifier is LIFTED, byte-identical (slot 0 == 11)', async () => {
    const J = `class C { n: u256; @modifier m() { _; this.n = this.n + 1n; } @m constructor(){ this.n = 10n; } }`;
    const S = `contract C { uint256 n; modifier m() { _; n = n + 1; } constructor() m { n = 10; } }`;
    const j = await depJ(J),
      s = await depS(S);
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(11n);
  });

  it('P1-20: a multi-placeholder (@twice) modifier on a constructor runs the body twice, byte-identical', async () => {
    const J = `class C { n: u256; @modifier twice() { _; _; } @twice constructor(){ this.n = this.n + 1n; } }`;
    const S = `contract C { uint256 n; modifier twice() { _; _; } constructor() twice { n = n + 1; } }`;
    const j = await depJ(J),
      s = await depS(S);
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(2n);
  });

  it('P1-20: a conditional-placeholder modifier on a constructor (0-or-N-times), byte-identical', async () => {
    for (const [flag, expected] of [
      ['true', 7n],
      ['false', 0n],
    ] as const) {
      const J = `class C { n: u256; @modifier m(c: bool) { if (c) { _; } } @m(${flag}) constructor(){ this.n = this.n + 7n; } }`;
      const S = `contract C { uint256 n; modifier m(bool c) { if (c) { _; } } constructor() m(${flag}) { n = n + 7; } }`;
      const j = await depJ(J),
        s = await depS(S);
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
      expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(expected);
    }
  });

  it('W5D-1: a bare-return modifier on a constructor is now LIFTED (level-exit outlining)', () => {
    // behavior verified byte-identical vs solc in test/ctor-modifier-return.test.ts
    expect(
      codes(
        `class C { n: u256; @modifier m(c: bool) { if (c) { return; } _; } @m(false) constructor(){ this.n = 10n; } }`,
      ),
    ).toEqual([]);
  });
});
