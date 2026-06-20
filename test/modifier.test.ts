// Phase 5 - USER-DEFINED MODIFIERS (@modifier). A Solidity-style modifier wraps a function body at a
// `_;` placeholder. Increment 1 supports PRE-ONLY modifiers (the placeholder is the LAST statement,
// i.e. pre-condition guards like `require(...); _;`), which covers onlyOwner / whenNotPaused /
// minValue, etc. The pre-code is inlined before the function body, so returns work normally (no
// post-placeholder code -> no buffered-return machinery). Multiple modifiers nest leftmost-outermost;
// the same modifier may apply twice; args are evaluated EXACTLY ONCE. Verified byte-identical to solc
// 0.8.35 on raw storage slots + returndata + accept/reject; post-code and conditional placeholders
// are cleanly gated.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const owner = new Address(Buffer.from('1111111111111111111111111111111111111111', 'hex'));
const other = new Address(Buffer.from('2222222222222222222222222222222222222222', 'hex'));
const sel = (s: string) => functionSelector(s);
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; }
  catch (e) { if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e; }
};
const solcRejects = (src: string): boolean => { try { compileSolidity(SPDX + src, 'C'); return false; } catch { return true; } };
async function depJ(src: string, caller = owner) {
  const h = await Harness.create(); await h.fund(caller, 10n ** 20n);
  return { h, a: await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode, { caller }) };
}
async function depS(src: string, caller = owner) {
  const h = await Harness.create(); await h.fund(caller, 10n ** 20n);
  return { h, a: await h.deploy(compileSolidity(SPDX + src, 'C').creation, { caller }) };
}

describe('Phase 5 user-defined modifiers (@modifier) vs solc 0.8.35', () => {
  it('onlyOwner guard: owner succeeds, other reverts, byte-identical (incl. raw slot)', async () => {
    const J = `@contract class C { @state owner: address; @state n: u256; @modifier onlyOwner() { require(msg.sender == this.owner, "not owner"); _; } constructor(){ this.owner = msg.sender; } @external @onlyOwner bump(): void { this.n = this.n + 1n; } }`;
    const S = `contract C { address owner; uint256 n; modifier onlyOwner(){ require(msg.sender==owner,"not owner"); _; } constructor(){ owner=msg.sender; } function bump() external onlyOwner { n=n+1; } }`;
    for (const who of [owner, other]) {
      const j = await depJ(J), s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('bump()'), { caller: who });
      const rs = await s.h.call(s.a, '0x' + sel('bump()'), { caller: who });
      expect(rj.success).toBe(rs.success);
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(await readSlot(j.h, j.a, 1n)).toBe(await readSlot(s.h, s.a, 1n));
    }
  });

  it('a modifier with an argument (atLeast(10)) guards on a state read', async () => {
    const J = `@contract class C { @state n: u256; @modifier atLeast(lo: u256) { require(this.n >= lo, "lo"); _; } @external setN(v: u256): void { this.n = v; } @external @atLeast(10n) doit(): void { this.n = this.n + 1n; } }`;
    const S = `contract C { uint256 n; modifier atLeast(uint256 lo){ require(n>=lo,"lo"); _; } function setN(uint256 v) external { n=v; } function doit() external atLeast(10) { n=n+1; } }`;
    for (const v of [5n, 20n]) {
      const j = await depJ(J), s = await depS(S);
      await j.h.call(j.a, '0x' + sel('setN(uint256)') + pad32(v));
      await s.h.call(s.a, '0x' + sel('setN(uint256)') + pad32(v));
      const rj = await j.h.call(j.a, '0x' + sel('doit()'));
      const rs = await s.h.call(s.a, '0x' + sel('doit()'));
      expect(rj.success).toBe(rs.success);
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    }
  });

  it('a function body return value passes through a modifier (-> 42)', async () => {
    const J = `@contract class C { @modifier g2() { require(true, "g2"); _; } @external @pure @g2 plain(x: u256): u256 { return x * 2n; } }`;
    const S = `contract C { modifier g2(){ require(true,"g2"); _; } function plain(uint256 x) external pure g2 returns(uint256){ return x*2; } }`;
    const j = await depJ(J), s = await depS(S);
    const rj = await j.h.call(j.a, '0x' + sel('plain(uint256)') + pad32(21n));
    const rs = await s.h.call(s.a, '0x' + sel('plain(uint256)') + pad32(21n));
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(BigInt(rj.returnHex)).toBe(42n);
  });

  it('multiple modifiers nest leftmost-outermost (a, b, body -> 129)', async () => {
    const J = `@contract class C { @state log: u256; @modifier a() { this.log = this.log * 10n + 1n; _; } @modifier b() { this.log = this.log * 10n + 2n; _; } @external @a @b run(): void { this.log = this.log * 10n + 9n; } }`;
    const S = `contract C { uint256 log; modifier a(){ log=log*10+1; _; } modifier b(){ log=log*10+2; _; } function run() external a b { log=log*10+9; } }`;
    const j = await depJ(J), s = await depS(S);
    await j.h.call(j.a, '0x' + sel('run()'));
    await s.h.call(s.a, '0x' + sel('run()'));
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(129n);
  });

  it('the same modifier applied twice runs its pre-code twice (-> 102)', async () => {
    const J = `@contract class C { @state n: u256; @modifier inc() { this.n = this.n + 1n; _; } @external @inc @inc run(): void { this.n = this.n + 100n; } }`;
    const S = `contract C { uint256 n; modifier inc(){ n=n+1; _; } function run() external inc inc { n=n+100; } }`;
    const j = await depJ(J), s = await depS(S);
    await j.h.call(j.a, '0x' + sel('run()'));
    await s.h.call(s.a, '0x' + sel('run()'));
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(102n);
  });

  it('a modifier argument is evaluated EXACTLY ONCE (side-effecting arg -> calls == 1)', async () => {
    const J = `@contract class C { @state calls: u256; @state sum: u256; @modifier use(v: u256) { this.sum = this.sum + v; _; } @internal bump(): u256 { this.calls = this.calls + 1n; return 7n; } @external @use(this.bump()) f(): void {} }`;
    const S = `contract C { uint256 calls; uint256 sum; modifier use(uint256 v){ sum=sum+v; _; } function bump() internal returns(uint256){ calls=calls+1; return 7; } function f() external use(bump()) {} }`;
    const j = await depJ(J), s = await depS(S);
    await j.h.call(j.a, '0x' + sel('f()'));
    await s.h.call(s.a, '0x' + sel('f()'));
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n)); // calls
    expect(await readSlot(j.h, j.a, 1n)).toBe(await readSlot(s.h, s.a, 1n)); // sum
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(1n);
  });

  it('composes with the built-in @nonReentrant (guard + owner check both apply)', async () => {
    const J = `@contract class C { @state owner: address; @state n: u256; @modifier onlyOwner() { require(msg.sender == this.owner, "no"); _; } constructor(){ this.owner = msg.sender; } @external @nonReentrant @onlyOwner bump(): void { this.n = this.n + 1n; } }`;
    const j = await depJ(J);
    const r1 = await j.h.call(j.a, '0x' + sel('bump()'), { caller: owner });
    const r2 = await j.h.call(j.a, '0x' + sel('bump()'), { caller: other });
    expect(r1.success).toBe(true);
    expect(r2.success).toBe(false);
    expect(BigInt(await readSlot(j.h, j.a, 1n))).toBe(1n);
  });

  describe('purity / mutability propagation through inlined modifier effects (accept/reject parity)', () => {
    const parity = (J: string, S: string, expectReject: boolean) => {
      expect(codes(J).length > 0).toBe(expectReject);
      expect(solcRejects(S)).toBe(expectReject);
    };
    it('@pure + an env-reading (msg.sender) modifier -> both reject', () =>
      parity(
        `@contract class C { @modifier g() { require(msg.sender != address(0n), "z"); _; } @external @pure @g f(x: u256): u256 { return x; } }`,
        `contract C { modifier g(){ require(msg.sender!=address(0),"z"); _; } function f(uint256 x) external pure g returns(uint256){ return x; } }`, true));
    it('@view + a state-reading modifier -> both accept', () =>
      parity(
        `@contract class C { @state n: u256; @modifier g() { require(this.n > 0n, "z"); _; } @external @view @g f(): u256 { return this.n; } }`,
        `contract C { uint256 n; modifier g(){ require(n>0,"z"); _; } function f() external view g returns(uint256){ return n; } }`, false));
    it('@view + a state-WRITING modifier -> both reject', () =>
      parity(
        `@contract class C { @state n: u256; @modifier g() { this.n = this.n + 1n; _; } @external @view @g f(): u256 { return this.n; } }`,
        `contract C { uint256 n; modifier g(){ n=n+1; _; } function f() external view g returns(uint256){ return n; } }`, true));
  });

  describe('clean gates', () => {
    it('post-placeholder code -> JETH321', () =>
      expect(codes(`@contract class C { @state n: u256; @modifier m() { _; this.n = 1n; } @external @m f(): void {} }`)).toContain('JETH321'));
    it('a placeholder inside a conditional -> JETH321', () =>
      expect(codes(`@contract class C { @state n: u256; @modifier m() { if (this.n > 0n) { _; } } @external @m f(): void {} }`)).toContain('JETH321'));
    it('more than one placeholder -> JETH320', () =>
      expect(codes(`@contract class C { @modifier m() { _; _; } @external @m f(): void {} }`)).toContain('JETH320'));
    it('zero placeholders -> JETH328', () =>
      expect(codes(`@contract class C { @modifier m() { let x: u256 = 1n; } @external @m f(): void {} }`)).toContain('JETH328'));
    it('`return expr` in a modifier -> JETH324 (parity: solc also rejects)', () =>
      expect(codes(`@contract class C { @modifier m() { return 5n; _; } @external @m f(): u256 { return 1n; } }`)).toContain('JETH324'));
    it('bare `return;` in a modifier -> JETH325', () =>
      expect(codes(`@contract class C { @state n: u256; @modifier m() { if (this.n > 0n) { return; } _; } @external @m f(): void {} }`)).toContain('JETH325'));
    it('an unknown applied modifier -> JETH329', () =>
      expect(codes(`@contract class C { @external @nope f(): void {} }`)).toContain('JETH329'));
    it('a modifier arg-count mismatch -> JETH329', () =>
      expect(codes(`@contract class C { @modifier m(x: u256) { _; } @external @m f(): void {} }`)).toContain('JETH329'));
    it('an aggregate modifier parameter -> JETH322', () =>
      expect(codes(`@contract class C { @modifier m(a: Arr<u256,2>) { _; } @external @m(([1n,2n])) f(): void {} }`)).toContain('JETH322'));
    it('a visibility/mutability decorator on the modifier itself -> JETH330', () =>
      expect(codes(`@contract class C { @view @modifier m() { _; } @external @m f(): void {} }`)).toContain('JETH330'));
    it('a modifier on a multi-value-return function -> JETH323', () =>
      expect(codes(`@contract class C { @modifier m() { _; } @external @m f(): [u256, u256] { return [1n, 2n]; } }`)).toContain('JETH323'));
  });
});
