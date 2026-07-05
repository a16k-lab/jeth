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
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
const solcRejects = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
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

describe('Phase 5 user-defined modifiers (@modifier) vs solc 0.8.35', () => {
  it('onlyOwner guard: owner succeeds, other reverts, byte-identical (incl. raw slot)', async () => {
    const J = `@contract class C { @state owner: address; @state n: u256; @modifier onlyOwner() { require(msg.sender == this.owner, "not owner"); _; } constructor(){ this.owner = msg.sender; } @external @onlyOwner bump(): void { this.n = this.n + 1n; } }`;
    const S = `contract C { address owner; uint256 n; modifier onlyOwner(){ require(msg.sender==owner,"not owner"); _; } constructor(){ owner=msg.sender; } function bump() external onlyOwner { n=n+1; } }`;
    for (const who of [owner, other]) {
      const j = await depJ(J),
        s = await depS(S);
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
      const j = await depJ(J),
        s = await depS(S);
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
    const j = await depJ(J),
      s = await depS(S);
    const rj = await j.h.call(j.a, '0x' + sel('plain(uint256)') + pad32(21n));
    const rs = await s.h.call(s.a, '0x' + sel('plain(uint256)') + pad32(21n));
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(BigInt(rj.returnHex)).toBe(42n);
  });

  it('multiple modifiers nest leftmost-outermost (a, b, body -> 129)', async () => {
    const J = `@contract class C { @state log: u256; @modifier a() { this.log = this.log * 10n + 1n; _; } @modifier b() { this.log = this.log * 10n + 2n; _; } @external @a @b run(): void { this.log = this.log * 10n + 9n; } }`;
    const S = `contract C { uint256 log; modifier a(){ log=log*10+1; _; } modifier b(){ log=log*10+2; _; } function run() external a b { log=log*10+9; } }`;
    const j = await depJ(J),
      s = await depS(S);
    await j.h.call(j.a, '0x' + sel('run()'));
    await s.h.call(s.a, '0x' + sel('run()'));
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(129n);
  });

  it('the same modifier applied twice runs its pre-code twice (-> 102)', async () => {
    const J = `@contract class C { @state n: u256; @modifier inc() { this.n = this.n + 1n; _; } @external @inc @inc run(): void { this.n = this.n + 100n; } }`;
    const S = `contract C { uint256 n; modifier inc(){ n=n+1; _; } function run() external inc inc { n=n+100; } }`;
    const j = await depJ(J),
      s = await depS(S);
    await j.h.call(j.a, '0x' + sel('run()'));
    await s.h.call(s.a, '0x' + sel('run()'));
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(102n);
  });

  it('a modifier argument is evaluated EXACTLY ONCE (side-effecting arg -> calls == 1)', async () => {
    const J = `@contract class C { @state calls: u256; @state sum: u256; @modifier use(v: u256) { this.sum = this.sum + v; _; } bump(): u256 { this.calls = this.calls + 1n; return 7n; } @external @use(this.bump()) f(): void {} }`;
    const S = `contract C { uint256 calls; uint256 sum; modifier use(uint256 v){ sum=sum+v; _; } function bump() internal returns(uint256){ calls=calls+1; return 7; } function f() external use(bump()) {} }`;
    const j = await depJ(J),
      s = await depS(S);
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
        `contract C { modifier g(){ require(msg.sender!=address(0),"z"); _; } function f(uint256 x) external pure g returns(uint256){ return x; } }`,
        true,
      ));
    it('@view + a state-reading modifier -> both accept', () =>
      parity(
        `@contract class C { @state n: u256; @modifier g() { require(this.n > 0n, "z"); _; } @external @view @g f(): u256 { return this.n; } }`,
        `contract C { uint256 n; modifier g(){ require(n>0,"z"); _; } function f() external view g returns(uint256){ return n; } }`,
        false,
      ));
    it('@view + a state-WRITING modifier -> both reject', () =>
      parity(
        `@contract class C { @state n: u256; @modifier g() { this.n = this.n + 1n; _; } @external @view @g f(): u256 { return this.n; } }`,
        `contract C { uint256 n; modifier g(){ n=n+1; _; } function f() external view g returns(uint256){ return n; } }`,
        true,
      ));
  });

  describe('clean gates', () => {
    it('post-placeholder code is now SUPPORTED (full modifiers) -> no diagnostics', () =>
      expect(
        codes(`@contract class C { @state n: u256; @modifier m() { _; this.n = 1n; } @external @m f(): void {} }`),
      ).toEqual([]));
    it('a placeholder inside a conditional (0-or-N-times) is now SUPPORTED -> no diagnostics', () =>
      expect(
        codes(
          `@contract class C { @state n: u256; @modifier m() { if (this.n > 0n) { _; } } @external @m f(): void {} }`,
        ),
      ).toEqual([]));
    it('more than one placeholder is now supported (JETH320 lifted: the body runs N times)', () =>
      expect(codes(`@contract class C { @modifier m() { _; _; } @external @m f(): void {} }`)).toEqual([]));
    it('zero placeholders -> JETH328', () =>
      expect(codes(`@contract class C { @modifier m() { let x: u256 = 1n; } @external @m f(): void {} }`)).toContain(
        'JETH328',
      ));
    it('`return expr` in a modifier -> JETH324 (parity: solc also rejects)', () =>
      expect(
        codes(`@contract class C { @modifier m() { return 5n; _; } @external @m f(): u256 { return 1n; } }`),
      ).toContain('JETH324'));
    it('bare `return;` in a modifier is now supported (JETH325 lifted: early-out returns the current values)', () =>
      expect(
        codes(
          `@contract class C { @state n: u256; @modifier m() { if (this.n > 0n) { return; } _; } @external @m f(): void {} }`,
        ),
      ).toEqual([]));
    it('an unknown applied modifier -> JETH329', () =>
      expect(codes(`@contract class C { @external @nope f(): void {} }`)).toContain('JETH329'));
    it('a modifier arg-count mismatch -> JETH329', () =>
      expect(codes(`@contract class C { @modifier m(x: u256) { _; } @external @m f(): void {} }`)).toContain(
        'JETH329',
      ));
    it('an aggregate modifier parameter is now supported (JETH322 lifted)', () =>
      expect(
        codes(`@contract class C { @modifier m(a: Arr<u256,2>) { _; } @external @m(([1n,2n])) f(): void {} }`),
      ).toEqual([]));
    it('a mapping modifier parameter still rejects (JETH247: mappings are storage-only)', () =>
      expect(
        codes(`@contract class C { @modifier m(a: mapping<u256, u256>) { _; } @external @m f(): void {} }`),
      ).toContain('JETH247'));
    it('a visibility/mutability decorator on the modifier itself -> JETH330', () =>
      expect(codes(`@contract class C { @view @modifier m() { _; } @external @m f(): void {} }`)).toContain('JETH330'));
    it('a (pre-only) modifier on a multi-value-return function is supported', () =>
      expect(
        codes(`@contract class C { @modifier m() { _; } @external @m f(): [u256, u256] { return [1n, 2n]; } }`),
      ).toEqual([]));
  });

  // Regression: a modifier param/local sharing a NAME with a function param must NOT shadow it in the
  // body (the body reads the FUNCTION param, not the modifier's value). Caught by the Phase 5
  // adversarial sweep as a silent miscompile (wrong returndata + wrong raw storage slot).
  describe('modifier param name-shadowing the function param (no leak into the body)', () => {
    it('returndata reads the function param, not the modifier arg', async () => {
      const J = `@contract class C { @modifier g(v: u256) { require(v < 1000n, "g"); _; } @external @pure @g(99n) f(v: u256): u256 { return v; } }`;
      const S = `contract C { modifier g(uint256 v){ require(v<1000,"g"); _; } function f(uint256 v) external pure g(99) returns(uint256){ return v; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('f(uint256)') + pad32(7n));
      const rs = await s.h.call(s.a, '0x' + sel('f(uint256)') + pad32(7n));
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(BigInt(rj.returnHex)).toBe(7n);
    });
    it('raw storage slot uses the function param (withdraw(amount) with @maxOut(100))', async () => {
      const J = `@contract class C { @state bal: u256; @modifier maxOut(amount: u256) { require(amount <= 100n, "cap"); _; } constructor(){ this.bal = 1000n; } @external @maxOut(100n) withdraw(amount: u256): void { this.bal = this.bal - amount; } }`;
      const S = `contract C { uint256 bal; modifier maxOut(uint256 amount){ require(amount<=100,"cap"); _; } constructor(){ bal=1000; } function withdraw(uint256 amount) external maxOut(100) { bal = bal - amount; } }`;
      const j = await depJ(J),
        s = await depS(S);
      await j.h.call(j.a, '0x' + sel('withdraw(uint256)') + pad32(30n));
      await s.h.call(s.a, '0x' + sel('withdraw(uint256)') + pad32(30n));
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
      expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(970n);
    });
  });

  // A constructor may carry a modifier (the canonical base-init guard), inlined like a function
  // modifier; byte-identical to solc (deploy succeeds/reverts per the guard).
  it('a @modifier on the constructor runs its guard at deploy', async () => {
    const J = `@contract class C { @state n: u256; @modifier pos(x: u256) { require(x > 0n, "pos"); _; } @external @view getN(): u256 { return this.n; } @pos(v) constructor(v: u256) { this.n = v; } }`;
    const S = `contract C { uint256 n; modifier pos(uint256 x){ require(x>0,"pos"); _; } function getN() external view returns(uint256){return n;} constructor(uint256 v) pos(v) { n = v; } }`;
    for (const v of [9n, 0n]) {
      let jr = false,
        sr = false,
        sj = '',
        ss = '';
      const hj = await Harness.create();
      await hj.fund(owner, 10n ** 20n);
      const hs = await Harness.create();
      await hs.fund(owner, 10n ** 20n);
      try {
        const a = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode + pad32(v), { caller: owner });
        sj = await readSlot(hj, a, 0n);
      } catch {
        jr = true;
      }
      try {
        const a = await hs.deploy(compileSolidity(SPDX + S, 'C').creation + pad32(v), { caller: owner });
        ss = await readSlot(hs, a, 0n);
      } catch {
        sr = true;
      }
      expect({ jr, sj }).toEqual({ jr: sr, sj: ss });
    }
  });

  describe("the reserved identifier '_' (JETH034)", () => {
    const par = (J: string, S: string) => {
      expect(codes(J)).toContain('JETH034');
      expect(solcRejects(S)).toBe(true);
    };
    it('rejects a local named _', () =>
      par(
        `@contract class C { @external @pure f(): u256 { let _: u256 = 3n; return _; } }`,
        `contract C { function f() external pure returns(uint256){ uint256 _ = 3; return _; } }`,
      ));
    it('rejects a parameter named _', () =>
      par(
        `@contract class C { @external @pure f(_: u256): u256 { return _; } }`,
        `contract C { function f(uint256 _) external pure returns(uint256){ return _; } }`,
      ));
    it('rejects a @state field named _', () =>
      par(
        `@contract class C { @state _: u256; @external @view g(): u256 { return this._; } }`,
        `contract C { uint256 _; function g() external view returns(uint256){ return _; } }`,
      ));
    it('rejects a modifier parameter named _', () =>
      par(
        `@contract class C { @state s: u256; @modifier m(_: u256) { require(_ > 0n); _; } @external @m(1n) f(): void { this.s = 1n; } }`,
        `contract C { uint256 s; modifier m(uint256 _){ require(_>0); _; } function f() external m(1) { s=1; } }`,
      ));
    it('the _ placeholder itself still works', () =>
      expect(
        codes(
          `@contract class C { @state s: u256; @modifier m() { require(true); _; } @external @m f(): void { this.s = 1n; } }`,
        ),
      ).toEqual([]));
  });

  // FULL MODIFIERS: post-placeholder code (the statements after `_;`) runs AFTER the wrapped body. The
  // body is lowered as a synthesized Yul function so a `return` in it runs the enclosing post-code (the
  // RETURN TRAP) before the value is ABI-encoded ONCE. Multiple modifiers: pre outer-first, post
  // inner-first. Verified byte-identical to solc 0.8.35 on raw storage slots + returndata + logs +
  // revert data. Out-of-scope shapes (aggregate/dynamic param, multi-value/aggregate return, internal
  // function, constructor) are cleanly gated JETH323; a conditional placeholder is now SUPPORTED.
  describe('post-placeholder code (full modifiers) vs solc 0.8.35', () => {
    it('1. post-code state write after the body commits (read back), byte-identical slots', async () => {
      const J = `@contract class C { @state n: u256; @state post: u256; @modifier track() { this.n = this.n + 1n; _; this.post = this.n * 100n; } @external @track go(): void { this.n = this.n + 10n; } @external @view readPost(): u256 { return this.post; } }`;
      const S = `contract C { uint256 n; uint256 post; modifier track(){ n=n+1; _; post=n*100; } function go() external track { n=n+10; } function readPost() external view returns(uint256){ return post; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('go()'));
      const rs = await s.h.call(s.a, '0x' + sel('go()'));
      expect(rj.success).toBe(rs.success);
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
      expect(await readSlot(j.h, j.a, 1n)).toBe(await readSlot(s.h, s.a, 1n));
      const pj = await j.h.call(j.a, '0x' + sel('readPost()'));
      const ps = await s.h.call(s.a, '0x' + sel('readPost()'));
      expect(pj.returnHex).toBe(ps.returnHex);
    });

    it('2. a post-condition require AFTER the body reverts the WHOLE call (identical revert data)', async () => {
      const J = `@contract class C { @state n: u256; @modifier cap() { _; require(this.n <= 5n, "too big"); } @external @cap add(v: u256): void { this.n = this.n + v; } }`;
      const S = `contract C { uint256 n; modifier cap(){ _; require(n<=5,"too big"); } function add(uint256 v) external cap { n=n+v; } }`;
      for (const v of [3n, 99n]) {
        const j = await depJ(J),
          s = await depS(S);
        const rj = await j.h.call(j.a, '0x' + sel('add(uint256)') + pad32(v));
        const rs = await s.h.call(s.a, '0x' + sel('add(uint256)') + pad32(v));
        expect(rj.success).toBe(rs.success);
        expect(rj.returnHex).toBe(rs.returnHex);
        expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
      }
    });

    it('2c. a post-code custom-error revert AFTER the body (identical revert data)', async () => {
      const J = `@contract class C { @error TooBig(have: u256); @state n: u256; @modifier cap() { _; if (this.n > 5n) { revert(TooBig(this.n)); } } @external @cap add(v: u256): void { this.n = this.n + v; } }`;
      const S = `contract C { error TooBig(uint256 have); uint256 n; modifier cap(){ _; if(n>5){ revert TooBig(n);} } function add(uint256 v) external cap { n=n+v; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('add(uint256)') + pad32(99n));
      const rs = await s.h.call(s.a, '0x' + sel('add(uint256)') + pad32(99n));
      expect(rj.success).toBe(false);
      expect(rj.success).toBe(rs.success);
      expect(rj.returnHex).toBe(rs.returnHex);
    });

    it('3. an early return inside an if in the body runs all posts (inner-first), returns the value', async () => {
      const J = `@contract class C { @state log: u256; @modifier a() { this.log = this.log * 10n + 1n; _; this.log = this.log * 10n + 8n; } @modifier b() { this.log = this.log * 10n + 2n; _; this.log = this.log * 10n + 7n; } @external @a @b pick(x: u256): u256 { if (x > 0n) { return x * 2n; } return 999n; } }`;
      const S = `contract C { uint256 log; modifier a(){ log=log*10+1; _; log=log*10+8; } modifier b(){ log=log*10+2; _; log=log*10+7; } function pick(uint256 x) external a b returns(uint256){ if(x>0){ return x*2; } return 999; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('pick(uint256)') + pad32(21n));
      const rs = await s.h.call(s.a, '0x' + sel('pick(uint256)') + pad32(21n));
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(BigInt(rj.returnHex)).toBe(42n);
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n)); // posts ran b(7) then a(8)
    });

    it('4. a return inside a for AND a while loop in the body still runs the posts (leave-from-loop)', async () => {
      const Jf = `@contract class C { @state post: u256; @modifier m() { _; this.post = 777n; } @external @m find(target: u256): u256 { for (let i: u256 = 0n; i < 100n; i = i + 1n) { if (i == target) { return i * 3n; } } return 0n; } }`;
      const Sf = `contract C { uint256 post; modifier m(){ _; post=777; } function find(uint256 target) external m returns(uint256){ for(uint256 i=0;i<100;i=i+1){ if(i==target){ return i*3; } } return 0; } }`;
      const jf = await depJ(Jf),
        sf = await depS(Sf);
      const rjf = await jf.h.call(jf.a, '0x' + sel('find(uint256)') + pad32(7n));
      const rsf = await sf.h.call(sf.a, '0x' + sel('find(uint256)') + pad32(7n));
      expect(rjf.returnHex).toBe(rsf.returnHex);
      expect(BigInt(rjf.returnHex)).toBe(21n);
      expect(await readSlot(jf.h, jf.a, 0n)).toBe(await readSlot(sf.h, sf.a, 0n));
      const Jw = `@contract class C { @state post: u256; @modifier m() { _; this.post = 555n; } @external @m findw(target: u256): u256 { let i: u256 = 0n; while (i < 100n) { if (i == target) { return i + 1000n; } i = i + 1n; } return 0n; } }`;
      const Sw = `contract C { uint256 post; modifier m(){ _; post=555; } function findw(uint256 target) external m returns(uint256){ uint256 i=0; while(i<100){ if(i==target){ return i+1000; } i=i+1; } return 0; } }`;
      const jw = await depJ(Jw),
        sw = await depS(Sw);
      const rjw = await jw.h.call(jw.a, '0x' + sel('findw(uint256)') + pad32(9n));
      const rsw = await sw.h.call(sw.a, '0x' + sel('findw(uint256)') + pad32(9n));
      expect(rjw.returnHex).toBe(rsw.returnHex);
      expect(BigInt(rjw.returnHex)).toBe(1009n);
      expect(await readSlot(jw.h, jw.a, 0n)).toBe(await readSlot(sw.h, sw.a, 0n));
    });

    it('5. multiple modifiers: pre outer-first, post inner-first (logs + state counter pin the order)', async () => {
      const J = `@contract class C { @event Step(label: u256); @state seq: u256; @modifier outer() { this.seq = this.seq * 10n + 1n; emit(Step(1n)); _; this.seq = this.seq * 10n + 4n; emit(Step(4n)); } @modifier inner() { this.seq = this.seq * 10n + 2n; emit(Step(2n)); _; this.seq = this.seq * 10n + 3n; emit(Step(3n)); } @external @outer @inner run(): void { this.seq = this.seq * 10n + 9n; emit(Step(9n)); } }`;
      const S = `contract C { event Step(uint256 label); uint256 seq; modifier outer(){ seq=seq*10+1; emit Step(1); _; seq=seq*10+4; emit Step(4); } modifier inner(){ seq=seq*10+2; emit Step(2); _; seq=seq*10+3; emit Step(3); } function run() external outer inner { seq=seq*10+9; emit Step(9); } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('run()'));
      const rs = await s.h.call(s.a, '0x' + sel('run()'));
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
      expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(12934n); // pre 1,2 (outer-first), post 3,4 (inner-first)
      expect(JSON.stringify(rj.logs)).toBe(JSON.stringify(rs.logs));
    });

    it('6. the same modifier applied twice with post-code', async () => {
      const J = `@contract class C { @state n: u256; @modifier step() { this.n = this.n + 1n; _; this.n = this.n + 100n; } @external @step @step run(): void { this.n = this.n + 1000n; } }`;
      const S = `contract C { uint256 n; modifier step(){ n=n+1; _; n=n+100; } function run() external step step { n=n+1000; } }`;
      const j = await depJ(J),
        s = await depS(S);
      await j.h.call(j.a, '0x' + sel('run()'));
      await s.h.call(s.a, '0x' + sel('run()'));
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
      expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(1202n);
    });

    it('7. a pre+post guard on a value-returning function returns the body value with both posts run', async () => {
      const J = `@contract class C { @state log: u256; @modifier g() { this.log = this.log + 1n; _; this.log = this.log + 10n; } @external @g calc(x: u256): u256 { return x * x; } }`;
      const S = `contract C { uint256 log; modifier g(){ log=log+1; _; log=log+10; } function calc(uint256 x) external g returns(uint256){ return x*x; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('calc(uint256)') + pad32(9n));
      const rs = await s.h.call(s.a, '0x' + sel('calc(uint256)') + pad32(9n));
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(BigInt(rj.returnHex)).toBe(81n);
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
      expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(11n);
    });

    it('8. compose post-code with @nonReentrant (a normal call succeeds, post runs)', async () => {
      const J = `@contract class C { @state n: u256; @modifier track() { this.n = this.n + 1n; _; this.n = this.n + 100n; } @external @nonReentrant @track go(): void { this.n = this.n + 10n; } }`;
      const j = await depJ(J);
      const rj = await j.h.call(j.a, '0x' + sel('go()'));
      expect(rj.success).toBe(true);
      expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(111n); // pre +1, body +10, post +100
    });

    it('9. a post-code modifier with a side-effecting arg evaluates the arg EXACTLY ONCE', async () => {
      const J = `@contract class C { @state calls: u256; @state sum: u256; @modifier use(v: u256) { this.sum = this.sum + v; _; this.sum = this.sum + v; } bump(): u256 { this.calls = this.calls + 1n; return 7n; } @external @use(this.bump()) f(): void {} }`;
      const S = `contract C { uint256 calls; uint256 sum; modifier use(uint256 v){ sum=sum+v; _; sum=sum+v; } function bump() internal returns(uint256){ calls=calls+1; return 7; } function f() external use(bump()) {} }`;
      const j = await depJ(J),
        s = await depS(S);
      await j.h.call(j.a, '0x' + sel('f()'));
      await s.h.call(s.a, '0x' + sel('f()'));
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n)); // calls == 1
      expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(1n);
      expect(await readSlot(j.h, j.a, 1n)).toBe(await readSlot(s.h, s.a, 1n)); // sum == 14 (v added twice)
      expect(BigInt(await readSlot(j.h, j.a, 1n))).toBe(14n);
    });

    it('10. a void function with post-code (no ret var)', async () => {
      const J = `@contract class C { @state n: u256; @modifier m() { _; this.n = this.n + 5n; } @external @m go(): void { this.n = this.n + 1n; } }`;
      const S = `contract C { uint256 n; modifier m(){ _; n=n+5; } function go() external m { n=n+1; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('go()'));
      const rs = await s.h.call(s.a, '0x' + sel('go()'));
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
      expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(6n);
    });

    it('11. a bytes/string single return with post-code (buffered through the ret reg)', async () => {
      const J = `@contract class C { @state n: u256; @modifier m() { _; this.n = this.n + 1n; } @external @m greet(x: u256): string { if (x > 0n) { return "big"; } return "small"; } }`;
      const S = `contract C { uint256 n; modifier m(){ _; n=n+1; } function greet(uint256 x) external m returns(string memory){ if(x>0){ return "big"; } return "small"; } }`;
      const j = await depJ(J),
        s = await depS(S);
      for (const x of [5n, 0n]) {
        const rj = await j.h.call(j.a, '0x' + sel('greet(uint256)') + pad32(x));
        const rs = await s.h.call(s.a, '0x' + sel('greet(uint256)') + pad32(x));
        expect(rj.returnHex).toBe(rs.returnHex);
      }
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    });
  });

  // JETH323 LIFTED for FUNCTION shapes: a post-code modifier on a function with an aggregate/dynamic
  // PARAM, a MULTI-VALUE return, or a supported aggregate RETURN (static struct/fixed-array, value-element
  // dynamic array, bytes/string) is now SUPPORTED (the body is a normal internal userfn). The genuine
  // remaining rejects stay JETH323: a non-@external function, a constructor (no userfn body in creation
  // code), and a return shape with no buffered memory-pointer encoder (string[], D[], T[][], Arr<dyn,N>,
  // or a multi-value tuple with an aggregate component). A return in a modifier stays JETH324/JETH325.
  describe('post-code gates (clean over-rejections vs solc)', () => {
    it('aggregate/dynamic param + post-modifier is now supported (JETH323 lifted)', () => {
      expect(
        codes(
          `@contract class C { @state n: u256; @modifier m() { _; this.n = this.n + 1n; } @external @m f(xs: Arr<u256,2>): u256 { return xs[0n]; } }`,
        ),
      ).toEqual([]);
      expect(
        codes(
          `@contract class C { @state n: u256; @modifier m() { _; this.n = this.n + 1n; } @external @m f(b: bytes): u256 { return b.length; } }`,
        ),
      ).toEqual([]);
    });
    it('multi-value (value-component) return + post-modifier is now supported (JETH323 lifted)', () =>
      expect(
        codes(
          `@contract class C { @state n: u256; @modifier m() { _; this.n = this.n + 1n; } @external @m f(): [u256, u256] { return [1n, 2n]; } }`,
        ),
      ).toEqual([]));
    it('aggregate (static struct) return + post-modifier is now supported (JETH323 lifted)', () =>
      expect(
        codes(
          `@struct class P { x: u256; y: u256; } @contract class C { @state n: u256; @modifier m() { _; this.n = this.n + 1n; } @external @m f(): P { return P(1n, 2n); } }`,
        ),
      ).toEqual([]));
    it('a value-element dynamic-array return + post-modifier is now supported (JETH323 lifted)', () =>
      expect(
        codes(
          `@contract class C { @state n: u256; @modifier m() { _; this.n = this.n + 1n; } @external @m f(): u256[] { return [1n, 2n, 3n]; } }`,
        ),
      ).toEqual([]));
    it('a nested-dynamic-element array return (string[]) + post-modifier still rejects (JETH323: no buffered encoder)', () =>
      expect(
        codes(
          `@contract class C { @state ss: string[]; @modifier m() { _; this.ss.push('x'); } @external @m f(): string[] { return this.ss; } }`,
        ),
      ).toContain('JETH323'));
    it('a multi-value return with an aggregate component + post-modifier still rejects (JETH323)', () =>
      expect(
        codes(
          `@contract class C { @state n: u256; @modifier m() { _; this.n = this.n + 1n; } @external @m f(): [u256[], u256] { return [[1n], 2n]; } }`,
        ),
      ).toContain('JETH323'));
    it('post-modifier on a non-@external (internal) function -> JETH323', () =>
      expect(
        codes(
          `@contract class C { @state n: u256; @modifier m() { _; this.n = this.n + 1n; } @m helper(): u256 { return 5n; } @external go(): u256 { return this.helper(); } }`,
        ),
      ).toContain('JETH323'));
    it('P1-20: a post-code modifier on a constructor is LIFTED and byte-identical to solc', async () => {
      // The ctor body runs (n=10), then the modifier post-code (n=n+1) -> 11. A ctor has no return
      // value, so the whole modifier body is inlined with `_;` replaced by the ctor body.
      const J = `@contract class C { @state n: u256; @modifier m() { _; this.n = this.n + 1n; } @m constructor(){ this.n = 10n; } @external @view gn(): u256 { return this.n; } }`;
      const S = `contract C { uint256 n; modifier m() { _; n = n + 1; } constructor() m { n = 10; } function gn() external view returns(uint256){ return n; } }`;
      const j = await depJ(J),
        s = await depS(S);
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
      const rj = await j.h.call(j.a, '0x' + sel('gn()'));
      const rs = await s.h.call(s.a, '0x' + sel('gn()'));
      expect(rj.returnHex).toBe(rs.returnHex);
    });
    it('W5D-1: a bare-return modifier on a constructor is now LIFTED (level-exit outlining)', () =>
      // behavior verified byte-identical vs solc in test/ctor-modifier-return.test.ts
      expect(
        codes(
          `@contract class C { @state n: u256; @modifier m(c: bool) { if (c) { return; } _; } @m(false) constructor(){ this.n = 10n; } }`,
        ),
      ).toEqual([]));
    it('a value param + value return post-modifier is supported -> no diagnostics', () =>
      expect(
        codes(
          `@contract class C { @state n: u256; @modifier m() { _; this.n = this.n + 1n; } @external @m f(x: u256): u256 { return x * 2n; } }`,
        ),
      ).toEqual([]));
  });

  // A @virtual @modifier in a base contract may be replaced by an @override @modifier of the same name
  // in a derived contract (plain replacement: the derived body wins). This mirrors solc's function
  // override discipline applied to modifiers; the same virtual/override pairing is enforced.
  describe('@override on a @modifier (virtual/override modifier discipline)', () => {
    it('a @virtual base modifier is replaced by a derived @override modifier (derived body wins)', async () => {
      // base require(false) would always revert; derived require(true) relaxes it, so f() succeeds.
      const J = `@abstract class A { @virtual @modifier g() { require(false, "base"); _; } } @contract class C extends A { @override @modifier g() { require(true); _; } @state n: u256; @external @g f(): u256 { this.n = this.n + 1n; return this.n; } }`;
      const S = `abstract contract A { modifier g() virtual { require(false,"base"); _; } } contract C is A { modifier g() override { require(true); _; } uint256 n; function f() external g returns (uint256) { n=n+1; return n; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('f()'));
      const rs = await s.h.call(s.a, '0x' + sel('f()'));
      expect(rj.success).toBe(true);
      expect(rj.success).toBe(rs.success);
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    });

    it('the derived override modifier can TIGHTEN the guard (base true -> derived false reverts f())', async () => {
      const J = `@abstract class A { @virtual @modifier g() { require(true); _; } } @contract class C extends A { @override @modifier g() { require(false, "der"); _; } @state n: u256; @external @g f(): u256 { this.n = 1n; return this.n; } }`;
      const S = `abstract contract A { modifier g() virtual { require(true); _; } } contract C is A { modifier g() override { require(false,"der"); _; } uint256 n; function f() external g returns (uint256) { n=1; return n; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('f()'));
      const rs = await s.h.call(s.a, '0x' + sel('f()'));
      expect(rj.success).toBe(false);
      expect(rj.success).toBe(rs.success);
      expect(rj.returnHex).toBe(rs.returnHex);
    });

    it('a parameterised @virtual/@override modifier pair is byte-identical', async () => {
      const J = `@abstract class A { @virtual @modifier g(x: u256) { require(x > 0n, "a"); _; } } @contract class C extends A { @override @modifier g(x: u256) { require(x > 5n, "c"); _; } @state n: u256; @external @g(3n) f(): u256 { this.n = this.n + 1n; return this.n; } }`;
      const S = `abstract contract A { modifier g(uint256 x) virtual { require(x>0,"a"); _; } } contract C is A { modifier g(uint256 x) override { require(x>5,"c"); _; } uint256 n; function f() external g(3) returns (uint256) { n=n+1; return n; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('f()'));
      const rs = await s.h.call(s.a, '0x' + sel('f()'));
      expect(rj.success).toBe(false); // derived requires x>5, called with 3
      expect(rj.success).toBe(rs.success);
      expect(rj.returnHex).toBe(rs.returnHex);
    });

    it('a valid diamond @override(A, B) modifier is accepted and byte-identical', async () => {
      const J = `@abstract class A { @virtual @modifier g() { require(true); _; } } @abstract class B { @virtual @modifier g() { require(true); _; } } @contract class C extends A, B { @override(A, B) @modifier g() { require(false, "won"); _; } @state n: u256; @external @g f(): u256 { this.n = 1n; return this.n; } }`;
      const S = `abstract contract A { modifier g() virtual { require(true); _; } } abstract contract B { modifier g() virtual { require(true); _; } } contract C is A, B { modifier g() override(A,B) { require(false,"won"); _; } uint256 n; function f() external g returns (uint256) { n=1; return n; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('f()'));
      const rs = await s.h.call(s.a, '0x' + sel('f()'));
      expect(rj.success).toBe(false);
      expect(rj.returnHex).toBe(rs.returnHex);
    });

    it('a genuine same-contract duplicate @modifier still rejects (JETH046, solc also rejects)', () => {
      const J = `@contract class C { @modifier g() { require(true); _; } @modifier g() { require(false); _; } @state n: u256; @external @g f(): void { this.n = 1n; } }`;
      const S = `contract C { modifier g(){ require(true); _; } modifier g(){ require(false); _; } uint256 n; function f() external g { n=1; } }`;
      expect(codes(J)).toContain('JETH046');
      expect(solcRejects(S)).toBe(true);
    });

    it('an @override modifier overriding a NON-@virtual base rejects (JETH375, solc also rejects)', () => {
      const J = `@abstract class A { @modifier g() { require(true); _; } } @contract class C extends A { @override @modifier g() { require(true); _; } @state n: u256; @external @g f(): void { this.n = 1n; } }`;
      const S = `abstract contract A { modifier g(){ require(true); _; } } contract C is A { modifier g() override { require(true); _; } uint256 n; function f() external g { n=1; } }`;
      expect(codes(J)).toContain('JETH375');
      expect(solcRejects(S)).toBe(true);
    });

    it('a derived modifier redefining a @virtual base WITHOUT @override rejects (JETH374, solc also rejects)', () => {
      const J = `@abstract class A { @virtual @modifier g() { require(true); _; } } @contract class C extends A { @modifier g() { require(true); _; } @state n: u256; @external @g f(): void { this.n = 1n; } }`;
      const S = `abstract contract A { modifier g() virtual { require(true); _; } } contract C is A { modifier g(){ require(true); _; } uint256 n; function f() external g { n=1; } }`;
      expect(codes(J)).toContain('JETH374');
      expect(solcRejects(S)).toBe(true);
    });

    it('an @override modifier with no base of that name rejects (JETH369, solc also rejects)', () => {
      const J = `@contract class C { @override @modifier g() { require(true); _; } @state n: u256; @external @g f(): void { this.n = 1n; } }`;
      const S = `contract C { modifier g() override { require(true); _; } uint256 n; function f() external g { n=1; } }`;
      expect(codes(J)).toContain('JETH369');
      expect(solcRejects(S)).toBe(true);
    });

    it('an override that changes the modifier parameter signature rejects (JETH377, solc also rejects)', () => {
      const J = `@abstract class A { @virtual @modifier g(x: u256) { require(x > 0n); _; } } @contract class C extends A { @override @modifier g(x: address) { require(x != address(0n)); _; } @state n: u256; @external @g(address(0n)) f(): void { this.n = 1n; } }`;
      const S = `abstract contract A { modifier g(uint256 x) virtual { require(x>0); _; } } contract C is A { modifier g(address x) override { require(x!=address(0)); _; } uint256 n; function f() external g(address(0)) { n=1; } }`;
      expect(codes(J)).toContain('JETH377');
      expect(solcRejects(S)).toBe(true);
    });

    it('a bare @override on a diamond modifier (2 base branches) requires the full list (JETH381, solc also rejects)', () => {
      const J = `@abstract class A { @virtual @modifier g() { require(true); _; } } @abstract class B { @virtual @modifier g() { require(true); _; } } @contract class C extends A, B { @override @modifier g() { require(true); _; } @state n: u256; @external @g f(): void { this.n = 1n; } }`;
      const S = `abstract contract A { modifier g() virtual { require(true); _; } } abstract contract B { modifier g() virtual { require(true); _; } } contract C is A, B { modifier g() override { require(true); _; } uint256 n; function f() external g { n=1; } }`;
      expect(codes(J)).toContain('JETH381');
      expect(solcRejects(S)).toBe(true);
    });
  });
});
