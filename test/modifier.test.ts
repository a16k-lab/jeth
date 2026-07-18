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
    const J = `class C { owner: address; n: u256; @modifier onlyOwner() { require(msg.sender == this.owner, "not owner"); _; } constructor(){ this.owner = msg.sender; } @onlyOwner bump(): External<void> { this.n = this.n + 1n; } }`;
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
    const J = `class C { n: u256; @modifier atLeast(lo: u256) { require(this.n >= lo, "lo"); _; } setN(v: u256): External<void> { this.n = v; } @atLeast(10n) doit(): External<void> { this.n = this.n + 1n; } }`;
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
    const J = `class C { @modifier g2() { require(true, "g2"); _; } @g2 get plain(x: u256): External<u256> { return x * 2n; } }`;
    const S = `contract C { modifier g2(){ require(true,"g2"); _; } function plain(uint256 x) external pure g2 returns(uint256){ return x*2; } }`;
    const j = await depJ(J),
      s = await depS(S);
    const rj = await j.h.call(j.a, '0x' + sel('plain(uint256)') + pad32(21n));
    const rs = await s.h.call(s.a, '0x' + sel('plain(uint256)') + pad32(21n));
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(BigInt(rj.returnHex)).toBe(42n);
  });

  it('multiple modifiers nest leftmost-outermost (a, b, body -> 129)', async () => {
    const J = `class C { log: u256; @modifier a() { this.log = this.log * 10n + 1n; _; } @modifier b() { this.log = this.log * 10n + 2n; _; } @a @b run(): External<void> { this.log = this.log * 10n + 9n; } }`;
    const S = `contract C { uint256 log; modifier a(){ log=log*10+1; _; } modifier b(){ log=log*10+2; _; } function run() external a b { log=log*10+9; } }`;
    const j = await depJ(J),
      s = await depS(S);
    await j.h.call(j.a, '0x' + sel('run()'));
    await s.h.call(s.a, '0x' + sel('run()'));
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(129n);
  });

  it('the same modifier applied twice runs its pre-code twice (-> 102)', async () => {
    const J = `class C { n: u256; @modifier inc() { this.n = this.n + 1n; _; } @inc @inc run(): External<void> { this.n = this.n + 100n; } }`;
    const S = `contract C { uint256 n; modifier inc(){ n=n+1; _; } function run() external inc inc { n=n+100; } }`;
    const j = await depJ(J),
      s = await depS(S);
    await j.h.call(j.a, '0x' + sel('run()'));
    await s.h.call(s.a, '0x' + sel('run()'));
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(102n);
  });

  it('a modifier argument is evaluated EXACTLY ONCE (side-effecting arg -> calls == 1)', async () => {
    const J = `class C { calls: u256; sum: u256; @modifier use(v: u256) { this.sum = this.sum + v; _; } bump(): u256 { this.calls = this.calls + 1n; return 7n; } @use(this.bump()) f(): External<void> {} }`;
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
    const J = `class C { owner: address; n: u256; @modifier onlyOwner() { require(msg.sender == this.owner, "no"); _; } constructor(){ this.owner = msg.sender; } @nonReentrant @onlyOwner bump(): External<void> { this.n = this.n + 1n; } }`;
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
    it('@pure + an env-reading (msg.sender) modifier -> both reject (native: no @pure to violate, so the banned decorator is JETH481; solc rejects the explicit-pure mirror)', () =>
      // Unlike the state-writing-modifier case, an env-reading modifier on a read-only fn is inferred `view`
      // natively (legal), so there is no native reject; the legacy @pure spelling is a banned decorator (JETH481).
      parity(
        `@contract class C { @modifier g() { require(msg.sender != address(0n), "z"); _; } @external @pure @g f(x: u256): u256 { return x; } }`,
        `contract C { modifier g(){ require(msg.sender!=address(0),"z"); _; } function f(uint256 x) external pure g returns(uint256){ return x; } }`,
        true,
      ));
    it('@view + a state-reading modifier -> both accept', () =>
      parity(
        `class C { n: u256; @modifier g() { require(this.n > 0n, "z"); _; } @g get f(): External<u256> { return this.n; } }`,
        `contract C { uint256 n; modifier g(){ require(n>0,"z"); _; } function f() external view g returns(uint256){ return n; } }`,
        false,
      ));
    it('a read-only get + a state-WRITING modifier -> both reject', () =>
      // Native: a `get` is read-only; a modifier that writes state makes it transitively mutating -> JETH043
      // (the native twin of the legacy @view + state-writing-modifier reject). solc rejects the mirror.
      parity(
        `class C { n: u256; @modifier g() { this.n = this.n + 1n; _; } @g get f(): External<u256> { return this.n; } }`,
        `contract C { uint256 n; modifier g(){ n=n+1; _; } function f() external view g returns(uint256){ return n; } }`,
        true,
      ));
  });

  describe('clean gates', () => {
    it('post-placeholder code is now SUPPORTED (full modifiers) -> no diagnostics', () =>
      expect(
        codes(`class C { n: u256; @modifier m() { _; this.n = 1n; } @m f(): External<void> {} }`),
      ).toEqual([]));
    it('a placeholder inside a conditional (0-or-N-times) is now SUPPORTED -> no diagnostics', () =>
      expect(
        codes(
          `class C { n: u256; @modifier m() { if (this.n > 0n) { _; } } @m f(): External<void> {} }`,
        ),
      ).toEqual([]));
    it('more than one placeholder is now supported (JETH320 lifted: the body runs N times)', () =>
      expect(codes(`class C { @modifier m() { _; _; } @m f(): External<void> {} }`)).toEqual([]));
    it('zero placeholders -> JETH328', () =>
      expect(codes(`class C { @modifier m() { let x: u256 = 1n; } @m f(): External<void> {} }`)).toContain(
        'JETH328',
      ));
    it('`return expr` in a modifier -> JETH324 (parity: solc also rejects)', () =>
      expect(
        codes(`class C { @modifier m() { return 5n; _; } @m get f(): External<u256> { return 1n; } }`),
      ).toContain('JETH324'));
    it('bare `return;` in a modifier is now supported (JETH325 lifted: early-out returns the current values)', () =>
      expect(
        codes(
          `class C { n: u256; @modifier m() { if (this.n > 0n) { return; } _; } @m f(): External<void> {} }`,
        ),
      ).toEqual([]));
    it('an unknown applied modifier -> JETH329', () =>
      expect(codes(`class C { @nope f(): External<void> {} }`)).toContain('JETH329'));
    it('a modifier arg-count mismatch -> JETH329', () =>
      expect(codes(`class C { @modifier m(x: u256) { _; } @m f(): External<void> {} }`)).toContain(
        'JETH329',
      ));
    it('an aggregate modifier parameter is now supported (JETH322 lifted)', () =>
      expect(
        codes(`class C { @modifier m(a: Arr<u256,2>) { _; } @m(([u256(1n),2n])) f(): External<void> {} }`),
      ).toEqual([]));
    it('a mapping modifier parameter still rejects (JETH247: mappings are storage-only)', () =>
      expect(
        codes(`class C { @modifier m(a: mapping<u256, u256>) { _; } @m f(): External<void> {} }`),
      ).toContain('JETH247'));
    it('a visibility/mutability marker on the modifier itself -> JETH330', () =>
      expect(codes(`class C { @modifier m(): View<void> { _; } @m f(): External<void> {} }`)).toContain('JETH330'));
    it('a (pre-only) modifier on a multi-value-return function is supported', () =>
      expect(
        codes(`class C { @modifier m() { _; } @m get f(): External<[u256, u256]> { return [1n, 2n]; } }`),
      ).toEqual([]));
  });

  // Regression: a modifier param/local sharing a NAME with a function param must NOT shadow it in the
  // body (the body reads the FUNCTION param, not the modifier's value). Caught by the Phase 5
  // adversarial sweep as a silent miscompile (wrong returndata + wrong raw storage slot).
  describe('modifier param name-shadowing the function param (no leak into the body)', () => {
    it('returndata reads the function param, not the modifier arg', async () => {
      const J = `class C { @modifier g(v: u256) { require(v < 1000n, "g"); _; } @g(99n) get f(v: u256): External<u256> { return v; } }`;
      const S = `contract C { modifier g(uint256 v){ require(v<1000,"g"); _; } function f(uint256 v) external pure g(99) returns(uint256){ return v; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('f(uint256)') + pad32(7n));
      const rs = await s.h.call(s.a, '0x' + sel('f(uint256)') + pad32(7n));
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(BigInt(rj.returnHex)).toBe(7n);
    });
    it('raw storage slot uses the function param (withdraw(amount) with @maxOut(100))', async () => {
      const J = `class C { bal: u256; @modifier maxOut(amount: u256) { require(amount <= 100n, "cap"); _; } constructor(){ this.bal = 1000n; } @maxOut(100n) withdraw(amount: u256): External<void> { this.bal = this.bal - amount; } }`;
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
    const J = `class C { n: u256; @modifier pos(x: u256) { require(x > 0n, "pos"); _; } get getN(): External<u256> { return this.n; } @pos(v) constructor(v: u256) { this.n = v; } }`;
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
        `class C { get f(): External<u256> { let _: u256 = 3n; return _; } }`,
        `contract C { function f() external pure returns(uint256){ uint256 _ = 3; return _; } }`,
      ));
    it('rejects a parameter named _', () =>
      par(
        `class C { get f(_: u256): External<u256> { return _; } }`,
        `contract C { function f(uint256 _) external pure returns(uint256){ return _; } }`,
      ));
    it('rejects a @state field named _', () =>
      par(
        `class C { _: u256; get g(): External<u256> { return this._; } }`,
        `contract C { uint256 _; function g() external view returns(uint256){ return _; } }`,
      ));
    it('rejects a modifier parameter named _', () =>
      par(
        `class C { s: u256; @modifier m(_: u256) { require(_ > 0n); _; } @m(1n) f(): External<void> { this.s = 1n; } }`,
        `contract C { uint256 s; modifier m(uint256 _){ require(_>0); _; } function f() external m(1) { s=1; } }`,
      ));
    it('the _ placeholder itself still works', () =>
      expect(
        codes(
          `class C { s: u256; @modifier m() { require(true); _; } @m f(): External<void> { this.s = 1n; } }`,
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
      const J = `class C { n: u256; post: u256; @modifier track() { this.n = this.n + 1n; _; this.post = this.n * 100n; } @track go(): External<void> { this.n = this.n + 10n; } get readPost(): External<u256> { return this.post; } }`;
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
      const J = `class C { n: u256; @modifier cap() { _; require(this.n <= 5n, "too big"); } @cap add(v: u256): External<void> { this.n = this.n + v; } }`;
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
      const J = `class C { TooBig: error<{ have: u256 }>; n: u256; @modifier cap() { _; if (this.n > 5n) { revert(TooBig(this.n)); } } @cap add(v: u256): External<void> { this.n = this.n + v; } }`;
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
      const J = `class C { log: u256; @modifier a() { this.log = this.log * 10n + 1n; _; this.log = this.log * 10n + 8n; } @modifier b() { this.log = this.log * 10n + 2n; _; this.log = this.log * 10n + 7n; } @a @b pick(x: u256): External<u256> { if (x > 0n) { return x * 2n; } return 999n; } }`;
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
      const Jf = `class C { post: u256; @modifier m() { _; this.post = 777n; } @m find(target: u256): External<u256> { for (let i: u256 = 0n; i < 100n; i = i + 1n) { if (i == target) { return i * 3n; } } return 0n; } }`;
      const Sf = `contract C { uint256 post; modifier m(){ _; post=777; } function find(uint256 target) external m returns(uint256){ for(uint256 i=0;i<100;i=i+1){ if(i==target){ return i*3; } } return 0; } }`;
      const jf = await depJ(Jf),
        sf = await depS(Sf);
      const rjf = await jf.h.call(jf.a, '0x' + sel('find(uint256)') + pad32(7n));
      const rsf = await sf.h.call(sf.a, '0x' + sel('find(uint256)') + pad32(7n));
      expect(rjf.returnHex).toBe(rsf.returnHex);
      expect(BigInt(rjf.returnHex)).toBe(21n);
      expect(await readSlot(jf.h, jf.a, 0n)).toBe(await readSlot(sf.h, sf.a, 0n));
      const Jw = `class C { post: u256; @modifier m() { _; this.post = 555n; } @m findw(target: u256): External<u256> { let i: u256 = 0n; while (i < 100n) { if (i == target) { return i + 1000n; } i = i + 1n; } return 0n; } }`;
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
      const J = `class C { Step: event<{ label: u256 }>; seq: u256; @modifier outer() { this.seq = this.seq * 10n + 1n; emit(Step(1n)); _; this.seq = this.seq * 10n + 4n; emit(Step(4n)); } @modifier inner() { this.seq = this.seq * 10n + 2n; emit(Step(2n)); _; this.seq = this.seq * 10n + 3n; emit(Step(3n)); } @outer @inner run(): External<void> { this.seq = this.seq * 10n + 9n; emit(Step(9n)); } }`;
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
      const J = `class C { n: u256; @modifier step() { this.n = this.n + 1n; _; this.n = this.n + 100n; } @step @step run(): External<void> { this.n = this.n + 1000n; } }`;
      const S = `contract C { uint256 n; modifier step(){ n=n+1; _; n=n+100; } function run() external step step { n=n+1000; } }`;
      const j = await depJ(J),
        s = await depS(S);
      await j.h.call(j.a, '0x' + sel('run()'));
      await s.h.call(s.a, '0x' + sel('run()'));
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
      expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(1202n);
    });

    it('7. a pre+post guard on a value-returning function returns the body value with both posts run', async () => {
      const J = `class C { log: u256; @modifier g() { this.log = this.log + 1n; _; this.log = this.log + 10n; } @g calc(x: u256): External<u256> { return x * x; } }`;
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
      const J = `class C { n: u256; @modifier track() { this.n = this.n + 1n; _; this.n = this.n + 100n; } @nonReentrant @track go(): External<void> { this.n = this.n + 10n; } }`;
      const j = await depJ(J);
      const rj = await j.h.call(j.a, '0x' + sel('go()'));
      expect(rj.success).toBe(true);
      expect(BigInt(await readSlot(j.h, j.a, 0n))).toBe(111n); // pre +1, body +10, post +100
    });

    it('9. a post-code modifier with a side-effecting arg evaluates the arg EXACTLY ONCE', async () => {
      const J = `class C { calls: u256; sum: u256; @modifier use(v: u256) { this.sum = this.sum + v; _; this.sum = this.sum + v; } bump(): u256 { this.calls = this.calls + 1n; return 7n; } @use(this.bump()) f(): External<void> {} }`;
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
      const J = `class C { n: u256; @modifier m() { _; this.n = this.n + 5n; } @m go(): External<void> { this.n = this.n + 1n; } }`;
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
      const J = `class C { n: u256; @modifier m() { _; this.n = this.n + 1n; } @m greet(x: u256): External<string> { if (x > 0n) { return "big"; } return "small"; } }`;
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
          `class C { n: u256; @modifier m() { _; this.n = this.n + 1n; } @m f(xs: Arr<u256,2>): External<u256> { return xs[0n]; } }`,
        ),
      ).toEqual([]);
      expect(
        codes(
          `class C { n: u256; @modifier m() { _; this.n = this.n + 1n; } @m f(b: bytes): External<u256> { return b.length; } }`,
        ),
      ).toEqual([]);
    });
    it('multi-value (value-component) return + post-modifier is now supported (JETH323 lifted)', () =>
      expect(
        codes(
          `class C { n: u256; @modifier m() { _; this.n = this.n + 1n; } @m f(): External<[u256, u256]> { return [1n, 2n]; } }`,
        ),
      ).toEqual([]));
    it('aggregate (static struct) return + post-modifier is now supported (JETH323 lifted)', () =>
      expect(
        codes(
          `type P = { x: u256; y: u256; }; class C { n: u256; @modifier m() { _; this.n = this.n + 1n; } @m f(): External<P> { return P(1n, 2n); } }`,
        ),
      ).toEqual([]));
    it('a value-element dynamic-array return + post-modifier is now supported (JETH323 lifted)', () =>
      expect(
        codes(
          `class C { n: u256; @modifier m() { _; this.n = this.n + 1n; } @m f(): External<u256[]> { return [1n, 2n, 3n]; } }`,
        ),
      ).toEqual([]));
    it('a nested-dynamic-element array return (string[]) + post-modifier still rejects (JETH323: no buffered encoder)', () =>
      expect(
        codes(
          `class C { ss: string[]; @modifier m() { _; this.ss.push('x'); } @m get f(): External<string[]> { return this.ss; } }`,
        ),
      ).toContain('JETH323'));
    it('a multi-value return with an aggregate component + post-modifier still rejects (JETH323)', () =>
      expect(
        codes(
          `class C { n: u256; @modifier m() { _; this.n = this.n + 1n; } @m get f(): External<[u256[], u256]> { return [[1n], 2n]; } }`,
        ),
      ).toContain('JETH323'));
    it('post-modifier on a non-@external (internal) function -> JETH323', () =>
      expect(
        codes(
          `class C { n: u256; @modifier m() { _; this.n = this.n + 1n; } @m helper(): u256 { return 5n; } get go(): External<u256> { return this.helper(); } }`,
        ),
      ).toContain('JETH323'));
    it('P1-20: a post-code modifier on a constructor is LIFTED and byte-identical to solc', async () => {
      // The ctor body runs (n=10), then the modifier post-code (n=n+1) -> 11. A ctor has no return
      // value, so the whole modifier body is inlined with `_;` replaced by the ctor body.
      const J = `class C { n: u256; @modifier m() { _; this.n = this.n + 1n; } @m constructor(){ this.n = 10n; } get gn(): External<u256> { return this.n; } }`;
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
          `class C { n: u256; @modifier m(c: bool) { if (c) { return; } _; } @m(false) constructor(){ this.n = 10n; } }`,
        ),
      ).toEqual([]));
    it('a value param + value return post-modifier is supported -> no diagnostics', () =>
      expect(
        codes(
          `class C { n: u256; @modifier m() { _; this.n = this.n + 1n; } @m f(x: u256): External<u256> { return x * 2n; } }`,
        ),
      ).toEqual([]));
  });

  // A @virtual @modifier in a base contract may be replaced by an @override @modifier of the same name
  // in a derived contract (plain replacement: the derived body wins). This mirrors solc's function
  // override discipline applied to modifiers; the same virtual/override pairing is enforced.
  describe('@override on a @modifier (virtual/override modifier discipline)', () => {
    it('a @virtual base modifier is replaced by a derived @override modifier (derived body wins)', async () => {
      // base require(false) would always revert; derived require(true) relaxes it, so f() succeeds.
      const J = `abstract class A { @virtual @modifier g() { require(false, "base"); _; } } class C extends A { @override @modifier g() { require(true); _; } n: u256; @g f(): External<u256> { this.n = this.n + 1n; return this.n; } }`;
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
      const J = `abstract class A { @virtual @modifier g() { require(true); _; } } class C extends A { @override @modifier g() { require(false, "der"); _; } n: u256; @g f(): External<u256> { this.n = 1n; return this.n; } }`;
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
      const J = `abstract class A { @virtual @modifier g(x: u256) { require(x > 0n, "a"); _; } } class C extends A { @override @modifier g(x: u256) { require(x > 5n, "c"); _; } n: u256; @g(3n) f(): External<u256> { this.n = this.n + 1n; return this.n; } }`;
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
      const J = `abstract class A { @virtual @modifier g() { require(true); _; } } abstract class B { @virtual @modifier g() { require(true); _; } } class C extends A, B { @override(A, B) @modifier g() { require(false, "won"); _; } n: u256; @g f(): External<u256> { this.n = 1n; return this.n; } }`;
      const S = `abstract contract A { modifier g() virtual { require(true); _; } } abstract contract B { modifier g() virtual { require(true); _; } } contract C is A, B { modifier g() override(A,B) { require(false,"won"); _; } uint256 n; function f() external g returns (uint256) { n=1; return n; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('f()'));
      const rs = await s.h.call(s.a, '0x' + sel('f()'));
      expect(rj.success).toBe(false);
      expect(rj.returnHex).toBe(rs.returnHex);
    });

    it('a genuine same-contract duplicate @modifier still rejects (JETH046, solc also rejects)', () => {
      const J = `class C { @modifier g() { require(true); _; } @modifier g() { require(false); _; } n: u256; @g f(): External<void> { this.n = 1n; } }`;
      const S = `contract C { modifier g(){ require(true); _; } modifier g(){ require(false); _; } uint256 n; function f() external g { n=1; } }`;
      expect(codes(J)).toContain('JETH046');
      expect(solcRejects(S)).toBe(true);
    });

    it('an @override modifier overriding a NON-@virtual base rejects (JETH375, solc also rejects)', () => {
      const J = `abstract class A { @modifier g() { require(true); _; } } class C extends A { @override @modifier g() { require(true); _; } n: u256; @g f(): External<void> { this.n = 1n; } }`;
      const S = `abstract contract A { modifier g(){ require(true); _; } } contract C is A { modifier g() override { require(true); _; } uint256 n; function f() external g { n=1; } }`;
      expect(codes(J)).toContain('JETH375');
      expect(solcRejects(S)).toBe(true);
    });

    it('a derived modifier redefining a @virtual base WITHOUT @override rejects (JETH374, solc also rejects)', () => {
      const J = `abstract class A { @virtual @modifier g() { require(true); _; } } class C extends A { @modifier g() { require(true); _; } n: u256; @g f(): External<void> { this.n = 1n; } }`;
      const S = `abstract contract A { modifier g() virtual { require(true); _; } } contract C is A { modifier g(){ require(true); _; } uint256 n; function f() external g { n=1; } }`;
      expect(codes(J)).toContain('JETH374');
      expect(solcRejects(S)).toBe(true);
    });

    it('an @override modifier with no base of that name rejects (JETH369, solc also rejects)', () => {
      const J = `class C { @override @modifier g() { require(true); _; } n: u256; @g f(): External<void> { this.n = 1n; } }`;
      const S = `contract C { modifier g() override { require(true); _; } uint256 n; function f() external g { n=1; } }`;
      expect(codes(J)).toContain('JETH369');
      expect(solcRejects(S)).toBe(true);
    });

    it('an override that changes the modifier parameter signature rejects (JETH377, solc also rejects)', () => {
      const J = `abstract class A { @virtual @modifier g(x: u256) { require(x > 0n); _; } } class C extends A { @override @modifier g(x: address) { require(x != address(0n)); _; } n: u256; @g(address(0n)) f(): External<void> { this.n = 1n; } }`;
      const S = `abstract contract A { modifier g(uint256 x) virtual { require(x>0); _; } } contract C is A { modifier g(address x) override { require(x!=address(0)); _; } uint256 n; function f() external g(address(0)) { n=1; } }`;
      expect(codes(J)).toContain('JETH377');
      expect(solcRejects(S)).toBe(true);
    });

    it('a bare @override on a diamond modifier (2 base branches) requires the full list (JETH381, solc also rejects)', () => {
      const J = `abstract class A { @virtual @modifier g() { require(true); _; } } abstract class B { @virtual @modifier g() { require(true); _; } } class C extends A, B { @override @modifier g() { require(true); _; } n: u256; @g f(): External<void> { this.n = 1n; } }`;
      const S = `abstract contract A { modifier g() virtual { require(true); _; } } abstract contract B { modifier g() virtual { require(true); _; } } contract C is A, B { modifier g() override { require(true); _; } uint256 n; function f() external g { n=1; } }`;
      expect(codes(J)).toContain('JETH381');
      expect(solcRejects(S)).toBe(true);
    });
  });

  // UNUSED-MODIFIER-BODY OA: JETH only type-checked a @modifier body by INLINING it at an application
  // site, so a DECLARED-but-UNAPPLIED modifier's body escaped the checker (a broken unused body was
  // silently ACCEPTED while solc rejects the file). analyzeContract now type-checks every declared
  // modifier body once, standalone, in its declaring-class scope with its params + `_;` legal. These pins
  // lock the close (broken unused body now rejects, matching solc) and the no-over-rejection controls
  // (a valid unused body still accepts + does not change bytecode).
  describe('an unapplied @modifier body is still type-checked (OA close vs solc)', () => {
    it('undeclared identifier in an UNUSED body -> JETH072 (solc also rejects; was an over-acceptance)', () => {
      const J = `class C { @modifier only() { require(q, "x"); _; } get f(): External<u256> { return 1n; } }`;
      const S = `contract C { modifier only() { require(q, "x"); _; } function f() external pure returns (uint256){ return 1; } }`;
      expect(codes(J)).toContain('JETH072');
      expect(solcRejects(S)).toBe(true);
    });
    it('the SAME broken body already both-rejected when APPLIED (unchanged control)', () => {
      const J = `class C { @modifier only() { require(q, "x"); _; } @only get f(): External<u256> { return 1n; } }`;
      const S = `contract C { modifier only() { require(q, "x"); _; } function f() external only pure returns (uint256){ return 1; } }`;
      expect(codes(J)).toContain('JETH072');
      expect(solcRejects(S)).toBe(true);
    });
    it('bad-type assignment in an UNUSED body rejects (solc also rejects)', () => {
      const J = `class C { x: u256; @modifier only() { this.x = true; _; } get f(): External<u256> { return 1n; } }`;
      const S = `contract C { uint256 x; modifier only() { x = true; _; } function f() external view returns (uint256){ return 1; } }`;
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });
    it('a call to a non-existent method in an UNUSED body rejects (solc also rejects)', () => {
      const J = `class C { @modifier only() { this.nope(); _; } get f(): External<u256> { return 1n; } }`;
      const S = `contract C { modifier only() { nope(); _; } function f() external pure returns (uint256){ return 1; } }`;
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });
    it('a broken UNUSED body with PARAMS rejects (solc also rejects)', () => {
      const J = `class C { @modifier only(v: u256) { require(v > z, "x"); _; } get f(): External<u256> { return 1n; } }`;
      const S = `contract C { modifier only(uint256 v) { require(v > z, "x"); _; } function f() external pure returns (uint256){ return 1; } }`;
      expect(codes(J)).toContain('JETH072');
      expect(solcRejects(S)).toBe(true);
    });
    it('an UNUSED body reading a non-existent field rejects (solc also rejects)', () => {
      const J = `class C { @modifier only() { require(this.ghost > 0n, "x"); _; } get f(): External<u256> { return 1n; } }`;
      const S = `contract C { modifier only() { require(ghost > 0, "x"); _; } function f() external pure returns (uint256){ return 1; } }`;
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });
    it('two UNUSED modifiers, one broken -> the file rejects (solc also rejects)', () => {
      const J = `class C { x: u256; @modifier ok() { require(this.x > 0n, "x"); _; } @modifier bad() { require(q, "x"); _; } get f(): External<u256> { return 1n; } }`;
      const S = `contract C { uint256 x; modifier ok() { require(x > 0, "x"); _; } modifier bad() { require(q, "x"); _; } function f() external view returns (uint256){ return 1; } }`;
      expect(codes(J)).toContain('JETH072');
      expect(solcRejects(S)).toBe(true);
    });
    it('an override-LOSER base body (broken) is still checked even when unapplied (solc also rejects)', () => {
      const J = `class B { z: u256; @virtual @modifier m() { require(qqq, "b"); _; } } class C extends B { @override @modifier m() { require(this.z > 0n, "c"); _; } get f(): External<u256> { return 1n; } }`;
      const S = `contract B { uint256 z; modifier m() virtual { require(qqq, "b"); _; } } contract C is B { modifier m() override { require(z > 0, "c"); _; } function f() external view returns (uint256){ return 1; } }`;
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });

    // --- NO NEW OVER-REJECTION: a VALID unused modifier still accepts + is byte-identical ---
    it('a VALID unused modifier (reads this.<field>, has `_;`) still accepts (solc accepts)', () => {
      const J = `class C { x: u256; @modifier only() { require(this.x > 0n, "x"); _; } get f(): External<u256> { return 1n; } }`;
      const S = `contract C { uint256 x; modifier only() { require(x > 0, "x"); _; } function f() external view returns (uint256){ return 1; } }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
    });
    it('a VALID unused modifier using its PARAMS still accepts', () =>
      expect(codes(`class C { @modifier only(v: u256) { require(v > 0n, "x"); _; } get f(): External<u256> { return 1n; } }`)).toEqual([]));
    it('a VALID unused modifier that writes state / emits / reads msg.value still accepts', () => {
      expect(codes(`class C { x: u256; @modifier only() { this.x = 7n; _; } get f(): External<u256> { return 1n; } }`)).toEqual([]);
      expect(codes(`class C { @modifier only() { require(msg.value >= 0n, "x"); _; } get f(): External<u256> { return 1n; } }`)).toEqual([]);
      expect(codes(`class C { E: event<{ a: u256 }>; @modifier only() { emit(this.E(1n)); _; } get f(): External<u256> { return 1n; } }`)).toEqual([]);
    });
    it('a VALID unused library modifier is unaffected (still dead code, both accept)', () =>
      expect(codes(`static class L { @modifier only() { require(true, "x"); _; } add(a: u256, b: u256): u256 { return a + b; } }\nclass C { get f(): External<u256> { return L.add(5n, 6n); } }`)).toEqual([]));
    it('adding a VALID unused modifier does NOT change creation or runtime bytecode', () => {
      const base = `class C { x: u256; g(v: u256): External<void> { this.x = v; } get f(): External<u256> { return this.x; } }`;
      const plus = `class C { x: u256; @modifier only() { require(this.x >= 0n, "x"); _; } g(v: u256): External<void> { this.x = v; } get f(): External<u256> { return this.x; } }`;
      const b = compile(base, { fileName: 'C.jeth' });
      const p = compile(plus, { fileName: 'C.jeth' });
      expect(p.creationBytecode).toBe(b.creationBytecode);
      expect(p.runtimeBytecode).toBe(b.runtimeBytecode);
    });
    it('a VALID unused modifier whose body calls an internal fn + writes state stays byte-identical', () => {
      const base = `class C { x: u256; chk(): bool { return this.x > 0n; } g(v: u256): External<void> { this.x = v; } }`;
      const plus = `class C { x: u256; chk(): bool { return this.x > 0n; } @modifier only() { require(this.chk(), "x"); this.x = this.x; _; } g(v: u256): External<void> { this.x = v; } }`;
      const b = compile(base, { fileName: 'C.jeth' });
      const p = compile(plus, { fileName: 'C.jeth' });
      expect(p.creationBytecode).toBe(b.creationBytecode);
      expect(p.runtimeBytecode).toBe(b.runtimeBytecode);
    });
    it('the built-in @nonReentrant and a modifier-free contract are unaffected', () => {
      expect(codes(`class C { x: u256; @nonReentrant g(v: u256): External<void> { this.x = v; } }`)).toEqual([]);
      expect(codes(`class C { x: u256; g(v: u256): External<void> { this.x = v; } get f(): External<u256> { return this.x; } }`)).toEqual([]);
    });
  });

  // MEM-ARRAY-MODIFIER-PARAM push/pop OA close: `push`/`pop` are STORAGE-array-only; a modifier array
  // PARAM is a MEMORY reference, so solc rejects `v.push(...)`/`v.pop()` in the body ("Member push/pop is
  // not available in <T> memory outside of storage"). In a NORMAL function a memory-array push rode
  // through analysis and was only rejected at CODEGEN (the generic JETH900 in yul.ts), reached solely when
  // the body is actually lowered - but a DECLARED-but-UNAPPLIED @modifier body is type-checked into a
  // discarded sink and NEVER lowered, so codegen never ran and `v.push(1n)` was OVER-ACCEPTED. The fix is
  // an analysis-time gate in checkArrayMutator: a memArray/memArrayExpr base (any memory array) rejects
  // push/pop with JETH210 (the same "requires a storage array" code the bytes/string memory push already
  // emits), the memory analog of the calldata (JETH214) / fixed (JETH218) rejects. Since the generic
  // checker checks each probe monomorphization through the SAME body path, the generic + chimera cases
  // close for free. STORAGE push/pop and every VALID memory-array-param access (v[i]/v.length/return
  // v/abi.encode(v)/pass-to-internal/struct-field) are untouched.
  describe('push/pop on a MEMORY array modifier param is a clean reject (OA close vs solc)', () => {
    // ---- FULL-AXIS CLOSE: each was an over-acceptance; each must now REJECT (solc rejects the mirror) ----
    const oa = (name: string, J: string, S: string) =>
      it(name, () => {
        expect(codes(J).length).toBeGreaterThan(0);
        expect(solcRejects(S)).toBe(true);
      });
    oa('push on an u256[] param (UNAPPLIED, non-generic)',
      `class C { x: u256; @modifier m(v: u256[]) { v.push(1n); _; } get z(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier m(uint256[] memory v){ v.push(1); _; } function z() external view returns(uint256){ return x; } }`);
    oa('pop on an u256[] param (UNAPPLIED, non-generic)',
      `class C { x: u256; @modifier m(v: u256[]) { v.pop(); _; } get z(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier m(uint256[] memory v){ v.pop(); _; } function z() external view returns(uint256){ return x; } }`);
    oa('push on a bytes param',
      `class C { x: u256; @modifier m(v: bytes) { v.push(1n); _; } get z(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier m(bytes memory v){ v.push(1); _; } function z() external view returns(uint256){ return x; } }`);
    oa('pop on a bytes param',
      `class C { x: u256; @modifier m(v: bytes) { v.pop(); _; } get z(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier m(bytes memory v){ v.pop(); _; } function z() external view returns(uint256){ return x; } }`);
    oa('push on a string param',
      `class C { x: u256; @modifier m(v: string) { v.push("a"); _; } get z(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier m(string memory v){ v.push(0x61); _; } function z() external view returns(uint256){ return x; } }`);
    oa('push on a struct P[] param',
      `type P = { a: u256 }; class C { x: u256; @modifier m(v: P[]) { v.push({a:1n}); _; } get z(): External<u256> { return this.x; } }`,
      `struct P{uint256 a;} contract C { uint256 x; modifier m(P[] memory v){ v.push(P(1)); _; } function z() external view returns(uint256){ return x; } }`);
    oa('push on a dynamic-struct D[] param',
      `type D = { s: string }; class C { x: u256; @modifier m(v: D[]) { v.push({s:"a"}); _; } get z(): External<u256> { return this.x; } }`,
      `struct D{string s;} contract C { uint256 x; modifier m(D[] memory v){ v.push(D("a")); _; } function z() external view returns(uint256){ return x; } }`);
    oa('push on an Arr<u256,3> param',
      `class C { x: u256; @modifier m(v: Arr<u256,3>) { v.push(1n); _; } get z(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier m(uint256[3] memory v){ v.push(1); _; } function z() external view returns(uint256){ return x; } }`);
    oa('GENERIC push (every monomorphization rejects)',
      `class C { x: u256; @modifier m<T>(v: T) { v.push(1n); _; } get z(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier m(uint256[] memory v){ v.push(1); _; } function z() external view returns(uint256){ return x; } }`);
    oa('GENERIC pop (every monomorphization rejects)',
      `class C { x: u256; @modifier m<T>(v: T) { v.pop(); _; } get z(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier m(uint256[] memory v){ v.pop(); _; } function z() external view returns(uint256){ return x; } }`);
    oa('CHIMERA push + memory reassign (no location permits both)',
      `class C { x: u256; @modifier m(v: u256[]) { v.push(1n); v = new Array<u256>(3n); _; } get z(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier m(uint256[] memory v){ v.push(1); v = new uint256[](3); _; } function z() external view returns(uint256){ return x; } }`);
    oa('GENERIC chimera push + memory reassign',
      `class C { x: u256; @modifier m<T>(v: T) { v.push(1n); v = new Array<u256>(3n); _; } get z(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier m(uint256[] memory v){ v.push(1); v = new uint256[](3); _; } function z() external view returns(uint256){ return x; } }`);
    oa('CHIMERA pop + memory reassign',
      `class C { x: u256; @modifier m(v: u256[]) { v.pop(); v = new Array<u256>(3n); _; } get z(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier m(uint256[] memory v){ v.pop(); v = new uint256[](3); _; } function z() external view returns(uint256){ return x; } }`);

    it('the base OA case rejects with JETH210 specifically (memory array has no push/pop)', () =>
      expect(codes(`class C { x: u256; @modifier m(v: u256[]) { v.push(1n); _; } get z(): External<u256> { return this.x; } }`)).toContain('JETH210'));

    // ---- CONTROL: the same reject already applied to a NORMAL function's memory-array local (ground truth,
    //      previously the codegen JETH900; now the same analysis-time JETH210). Still a clean reject. ----
    it('a NORMAL function memory-array-local push/pop still rejects (solc also rejects)', () => {
      expect(codes(`class C { f(): External<void> { let a: u256[] = [1n,2n]; a.push(3n); } }`).length).toBeGreaterThan(0);
      expect(codes(`class C { f(): External<void> { let a: u256[] = [1n,2n]; a.pop(); } }`).length).toBeGreaterThan(0);
      expect(solcRejects(`contract C { function f() external { uint256[] memory a=new uint256[](2); a[0]=1;a[1]=2; a.push(3); } }`)).toBe(true);
    });

    // ---- NO NEW OVER-REJECTION: every VALID memory-array-param access still ACCEPTS (solc accepts) ----
    const acc = (name: string, J: string) => it(name, () => expect(codes(J)).toEqual([]));
    acc('valid require(v.length) body', `class C { x: u256; @modifier m(v: u256[]) { require(v.length > 0n, "e"); _; } get z(): External<u256> { return this.x; } }`);
    acc('valid v[0] read body', `class C { x: u256; @modifier m(v: u256[]) { require(v[0n] >= 0n, "e"); _; } get z(): External<u256> { return this.x; } }`);
    acc('valid abi.encode(v) body', `class C { x: u256; @modifier m(v: u256[]) { let b: bytes = abi.encode(v); require(b.length > 0n, "e"); _; } get z(): External<u256> { return this.x; } }`);
    acc('valid pass v to an internal fn body', `class C { x: u256; sum(w: u256[]): u256 { return w.length; } @modifier m(v: u256[]) { require(this.sum(v) >= 0n, "e"); _; } get z(): External<u256> { return this.x; } }`);
    acc('valid struct-field read body', `type P = { a: u256 }; class C { x: u256; @modifier m(v: P) { require(v.a > 0n, "e"); _; } get z(): External<u256> { return this.x; } }`);
    acc('valid GENERIC v.length body (valid at bytes)', `class C { x: u256; @modifier m<T>(v: T) { require(v.length >= 0n, "e"); _; } get z(): External<u256> { return this.x; } }`);
    acc('valid GENERIC let y:T=v body', `class C { x: u256; @modifier m<T>(v: T) { let y: T = v; _; } get z(): External<u256> { return this.x; } }`);
    acc('a STORAGE array push/pop in a NORMAL function still accepts', `class C { arr: u256[]; f(x: u256): External<void> { this.arr.push(x); } g(): External<void> { this.arr.pop(); } }`);

    // ---- STORAGE push STILL WORKS: deploy + run + read raw slots byte-identical to solc ----
    it('this.arr.push / .pop remain byte-identical to solc (raw slots + returndata)', async () => {
      const J = `class C { arr: u256[]; push1(x: u256): External<void> { this.arr.push(x); } popIt(): External<void> { this.arr.pop(); } get len(): External<u256> { return this.arr.length; } get at(i: u256): External<u256> { return this.arr[i]; } }`;
      const S = `contract C { uint256[] arr; function push1(uint256 x) external { arr.push(x); } function popIt() external { arr.pop(); } function len() external view returns(uint256){ return arr.length; } function at(uint256 i) external view returns(uint256){ return arr[i]; } }`;
      const j = await depJ(J), s = await depS(S);
      for (const v of [11n, 22n, 33n]) {
        await j.h.call(j.a, '0x' + sel('push1(uint256)') + pad32(v));
        await s.h.call(s.a, '0x' + sel('push1(uint256)') + pad32(v));
      }
      const rjl = await j.h.call(j.a, '0x' + sel('len()')), rsl = await s.h.call(s.a, '0x' + sel('len()'));
      expect(rjl.returnHex).toBe(rsl.returnHex);
      const rja = await j.h.call(j.a, '0x' + sel('at(uint256)') + pad32(1n)), rsa = await s.h.call(s.a, '0x' + sel('at(uint256)') + pad32(1n));
      expect(rja.returnHex).toBe(rsa.returnHex);
      await j.h.call(j.a, '0x' + sel('popIt()')); await s.h.call(s.a, '0x' + sel('popIt()'));
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    });

    // ---- an APPLIED modifier with a VALID array-param body runs byte-identically (the fix is diag-only) ----
    it('an APPLIED modifier reading v.length / v[i] runs byte-identical to solc', async () => {
      const J = `class C { n: u256; @modifier m(v: u256[]) { require(v.length > 0n && v[0n] == 5n, "e"); _; } @m([5n,6n]) bump(): External<void> { this.n = this.n + 7n; } }`;
      const S = `contract C { uint256 n; modifier m(uint256[] memory v){ require(v.length>0 && v[0]==5,"e"); _; } function f_mk() internal pure returns(uint256[] memory){ uint256[] memory a=new uint256[](2); a[0]=5;a[1]=6; return a; } function bump() external m(f_mk()) { n = n + 7; } }`;
      const j = await depJ(J), s = await depS(S);
      await j.h.call(j.a, '0x' + sel('bump()')); await s.h.call(s.a, '0x' + sel('bump()'));
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    });

    // ---- BYTE-IDENTITY: adding a VALID unapplied array-param modifier changes NO bytecode ----
    it('adding a valid unapplied array-param modifier does NOT change creation or runtime bytecode', () => {
      const base = `class C { s: u256 = 0n; setS(v: u256): External<void> { this.s = v; } get getS(): External<u256> { return this.s; } }`;
      const plus = `class C { s: u256 = 0n; @modifier m(v: u256[]) { require(v.length >= 0n, "x"); _; } setS(v: u256): External<void> { this.s = v; } get getS(): External<u256> { return this.s; } }`;
      const b = compile(base, { fileName: 'C.jeth' });
      const p = compile(plus, { fileName: 'C.jeth' });
      expect(p.creationBytecode).toBe(b.creationBytecode);
      expect(p.runtimeBytecode).toBe(b.runtimeBytecode);
    });
  });

  // LIB-MODIFIER unapplied-body OA close: a @modifier declared in a `static class L` (library) is registered
  // under a qualified `L.name` key in a SEPARATE list from contract modifiers, so the contract-modifier
  // unapplied-body pass never reached it - a DECLARED-but-UNAPPLIED library modifier body escaped the
  // checker entirely (solc type-checks every library modifier body regardless of use). The pass now also
  // type-checks each unapplied library modifier body once, standalone, in the LIBRARY's scope (currentLibrary=L,
  // no contract state/instance - its own params / constants / functions / `_;` only). These pins lock the
  // close (a broken unused library modifier now rejects, matching solc) and the no-over-rejection controls.
  describe('an unapplied library @modifier body is still type-checked (LIB-MODIFIER OA close vs solc)', () => {
    it('EXACT OA: undeclared identifier in an UNAPPLIED library modifier -> JETH072 (solc also rejects)', () => {
      const J = `static class L { @modifier only() { require(q, "x"); _; } add(a: u256, b: u256): u256 { return a + b; } } class C { get z(): External<u256> { return L.add(1n, 2n); } }`;
      const S = `library L { modifier only() { require(q,"x"); _; } function add(uint256 a, uint256 b) internal pure returns(uint256){ return a+b; } } contract C { function z() external pure returns(uint256){ return L.add(1,2); } }`;
      expect(codes(J)).toContain('JETH072');
      expect(solcRejects(S)).toBe(true);
    });
    it('bad-type assignment (string literal into a u256 local) in an UNAPPLIED library modifier rejects', () => {
      const J = `static class L { @modifier m(v: u256) { let s: u256 = "hello"; _; } add(a: u256): u256 { return a; } } class C { get z(): External<u256> { return L.add(1n); } }`;
      const S = `library L { modifier m(uint256 v) { uint256 s = "hello"; _; } function add(uint256 a) internal pure returns(uint256){ return a; } } contract C { function z() external pure returns(uint256){ return L.add(1); } }`;
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });
    it('a call to a non-existent library function in an UNAPPLIED library modifier rejects', () => {
      const J = `static class L { @modifier m(v: u256) { require(L.missing(v) > 0n, "x"); _; } add(a: u256): u256 { return a; } } class C { get z(): External<u256> { return L.add(1n); } }`;
      const S = `library L { modifier m(uint256 v) { require(L.missing(v) > 0, "x"); _; } function add(uint256 a) internal pure returns(uint256){ return a; } } contract C { function z() external pure returns(uint256){ return L.add(1); } }`;
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });
    it('a type error in require (non-bool condition) in an UNAPPLIED library modifier rejects', () => {
      const J = `static class L { @modifier m(v: u256) { require(v + 1n, "x"); _; } add(a: u256): u256 { return a; } } class C { get z(): External<u256> { return L.add(1n); } }`;
      const S = `library L { modifier m(uint256 v) { require(v + 1, "x"); _; } function add(uint256 a) internal pure returns(uint256){ return a; } } contract C { function z() external pure returns(uint256){ return L.add(1); } }`;
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });
    it('a broken expression using the params (u256 > bool) in an UNAPPLIED library modifier rejects', () => {
      const J = `static class L { @modifier m(v: u256) { require(v > true, "x"); _; } add(a: u256): u256 { return a; } } class C { get z(): External<u256> { return L.add(1n); } }`;
      const S = `library L { modifier m(uint256 v) { require(v > true, "x"); _; } function add(uint256 a) internal pure returns(uint256){ return a; } } contract C { function z() external pure returns(uint256){ return L.add(1); } }`;
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });
    it('MIXED: one APPLIED valid + one UNAPPLIED broken library modifier - the file rejects (solc also rejects)', () => {
      const J = `static class L { @modifier ok(v: u256) { require(v > 0n, "ok"); _; } @modifier bad(v: u256) { require(ghost, "b"); _; } @ok(v) inc(v: u256): u256 { return v + 1n; } } class C { get z(v: u256): External<u256> { return L.inc(v); } }`;
      const S = `library L { modifier ok(uint256 v) { require(v > 0, "ok"); _; } modifier bad(uint256 v) { require(ghost, "b"); _; } function inc(uint256 v) internal pure ok(v) returns(uint256){ return v + 1; } } contract C { function z(uint256 v) external pure returns(uint256){ return L.inc(v); } }`;
      expect(codes(J)).toContain('JETH072');
      expect(solcRejects(S)).toBe(true);
    });
    it('a generic library modifier with a broken body stays rejected at collect time (JETH390, pre-existing)', () => {
      const J = `static class L { @modifier lim<T>(v: T) { require(ghostXYZ, "e"); _; } add(a: u256): u256 { return a; } } class C { get z(): External<u256> { return L.add(1n); } }`;
      expect(codes(J)).toContain('JETH390');
    });
    it('a library modifier reading contract state `this.<field>` rejects - UNAPPLIED (JETH394; solc rejects)', () => {
      // A library has no contract instance/state; `this.x` is meaningless (exactly like a library function).
      const J = `static class L { @modifier m() { require(this.x > 0n, "x"); _; } add(a: u256): u256 { return a; } } class C { x: u256; get z(): External<u256> { return L.add(1n); } }`;
      const S = `library L { modifier m() { require(x > 0, "x"); _; } function add(uint256 a) internal pure returns(uint256){ return a; } } contract C { uint256 x; function z() external view returns(uint256){ return L.add(1); } }`;
      expect(codes(J)).toContain('JETH394');
      expect(solcRejects(S)).toBe(true);
    });
    it('a library modifier reading contract state `this.<field>` rejects - APPLIED too (JETH394; solc rejects)', () => {
      const J = `static class L { @modifier m() { require(this.x > 0n, "x"); _; } @m inc(a: u256): u256 { return a; } } class C { x: u256; get z(): External<u256> { return L.inc(1n); } }`;
      const S = `library L { modifier m() { require(x > 0, "x"); _; } function inc(uint256 a) internal view m returns(uint256){ return a; } } contract C { uint256 x; function z() external view returns(uint256){ return L.inc(1); } }`;
      expect(codes(J)).toContain('JETH394');
      expect(solcRejects(S)).toBe(true);
    });

    // --- NO NEW OVER-REJECTION: a VALID unused library modifier still accepts + is byte-identical ---
    it('a VALID unused library modifier reading the caller ENV (msg.*, address(this)) still accepts (both)', () => {
      // These read the CALLER's message/context (legal in a library body), not contract state - must accept.
      expect(codes(`static class L { @modifier m(v: u256) { require(msg.value >= 0n, "x"); _; } add(a: u256): u256 { return a; } } class C { get z(): External<u256> { return L.add(1n); } }`)).toEqual([]);
      expect(codes(`static class L { @modifier m() { require(msg.sender != address(0), "x"); _; } add(a: u256): u256 { return a; } } class C { get z(): External<u256> { return L.add(1n); } }`)).toEqual([]);
      expect(codes(`static class L { @modifier m() { require(address(this) != address(0), "x"); _; } add(a: u256): u256 { return a; } } class C { get z(): External<u256> { return L.add(1n); } }`)).toEqual([]);
    });
    it('a VALID unused library modifier referencing its params still accepts (solc accepts)', () => {
      const J = `static class L { @modifier okv(v: u256) { require(v >= 0n, "x"); _; } add(a: u256): u256 { return a; } } class C { get z(): External<u256> { return L.add(1n); } }`;
      const S = `library L { modifier okv(uint256 v) { require(v >= 0, "x"); _; } function add(uint256 a) internal pure returns(uint256){ return a; } } contract C { function z() external pure returns(uint256){ return L.add(1); } }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
    });
    it('a VALID unused library modifier referencing a library CONSTANT still accepts', () => {
      const J = `static class L { static MIN: u256 = 10n; @modifier okc(v: u256) { require(v >= MIN, "x"); _; } add(a: u256): u256 { return a; } } class C { get z(): External<u256> { return L.add(1n); } }`;
      const S = `library L { uint256 constant MIN = 10; modifier okc(uint256 v) { require(v >= MIN, "x"); _; } function add(uint256 a) internal pure returns(uint256){ return a; } } contract C { function z() external pure returns(uint256){ return L.add(1); } }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
    });
    it('a VALID unused library modifier calling another library FUNCTION still accepts', () => {
      const J = `static class L { helper(x: u256): u256 { return x + 1n; } @modifier okf(v: u256) { require(L.helper(v) > 0n, "x"); _; } add(a: u256): u256 { return a; } } class C { get z(): External<u256> { return L.add(1n); } }`;
      const S = `library L { function helper(uint256 x) internal pure returns(uint256){ return x + 1; } modifier okf(uint256 v) { require(L.helper(v) > 0, "x"); _; } function add(uint256 a) internal pure returns(uint256){ return a; } } contract C { function z() external pure returns(uint256){ return L.add(1); } }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
    });
    it('an APPLIED library modifier is unchanged (still both-accept)', () =>
      expect(codes(`static class L { @modifier onlyPos(v: u256) { require(v > 0n, "np"); _; } @onlyPos(v) inc(v: u256): u256 { return v + 1n; } } class C { get g(v: u256): External<u256> { return L.inc(v); } }`)).toEqual([]));
    it('adding a VALID unused library modifier does NOT change the consuming contract creation or runtime bytecode', () => {
      const base = `static class L { add(a: u256, b: u256): u256 { return a + b; } } class C { get z(): External<u256> { return L.add(1n, 2n); } }`;
      const plus = `static class L { @modifier onlyValid(v: u256) { require(v >= 0n, "x"); _; } add(a: u256, b: u256): u256 { return a + b; } } class C { get z(): External<u256> { return L.add(1n, 2n); } }`;
      const b = compile(base, { fileName: 'C.jeth' });
      const p = compile(plus, { fileName: 'C.jeth' });
      expect(p.creationBytecode).toBe(b.creationBytecode);
      expect(p.runtimeBytecode).toBe(b.runtimeBytecode);
    });
  });

  // UNUSED-MODIFIER-BODY (generic twin): solc type-checks every declared modifier body regardless of use.
  // A GENERIC @modifier is a TEMPLATE that JETH only monomorphizes + checks at an APPLICATION site, so a
  // DECLARED-but-NEVER-APPLIED generic modifier's body escaped the checker entirely - a type-parameter-
  // INDEPENDENT break (undeclared identifier / missing function / wrong arity / concrete bad-type / value-
  // return) was silently ACCEPTED while solc's monomorphized mirror rejects it (an over-acceptance). The
  // template body is now checked standalone under a DIVERSE probe set of concrete bindings; only an error
  // that fires under EVERY probe (i.e. type-parameter-INDEPENDENT) is reported, so a body that is valid at
  // SOME type (an applied generic, or an unapplied one valid for any type param) stays byte-identical.
  describe('unapplied GENERIC @modifier body type-checking (solc parity)', () => {
    // ---- FULL-AXIS CLOSE: each must now REJECT (solc's monomorphized mirror also rejects; non-vacuous) ----
    it('OA close: undeclared identifier in an unapplied generic modifier body', () => {
      const J = `class C { @modifier m<U>() { g; _; } get z(): External<u256> { return 7n; } }`;
      const S = `contract C { modifier m() { g; _; } function z() external pure returns(uint256){ return 7; } }`;
      expect(codes(J)).toContain('JETH072');
      expect(solcRejects(S)).toBe(true);
    });
    it('OA close: concrete bad-type assignment (let x: u256 = true)', () => {
      const J = `class C { @modifier m<U>() { let x: u256 = true; _; } get z(): External<u256> { return 7n; } }`;
      const S = `contract C { modifier m() { uint256 x = true; _; } function z() external pure returns(uint256){ return 7; } }`;
      expect(codes(J)).toContain('JETH085');
      expect(solcRejects(S)).toBe(true);
    });
    // MULTI-SITE conflict: broken for EVERY type param but at DIFFERENT source spans per probe, so the
    // span-key intersection was empty and the body slipped. Now rejected: every probe errors -> no
    // instantiation type-checks. solc rejects the monomorphized mirror at every concrete type.
    it('OA close: multi-site type-param-independent conflict (bool vs u256 sinks)', () => {
      const J = `class C { x: u256; @modifier m<T>(v: T) { let p: bool = v; let q: u256 = v; _; } get z(): External<u256> { return this.x; } }`;
      const S = `contract C { uint256 x; modifier m(uint256 v) { bool p = v; uint256 q = v; _; } function z() external view returns(uint256){ return x; } }`;
      expect(codes(J)).toContain('JETH085');
      expect(solcRejects(S)).toBe(true);
    });
    it('OA close: multi-site conflict, address vs u256 sinks', () => {
      const J = `class C { x: u256; @modifier m<T>(v: T) { let p: address = v; let q: u256 = v; _; } get z(): External<u256> { return this.x; } }`;
      const S = `contract C { uint256 x; modifier m(uint256 v) { address p = v; uint256 q = v; _; } function z() external view returns(uint256){ return x; } }`;
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });
    it('no over-rejection: a body valid at SOME type param stays accepted despite the multi-site guard', () => {
      // `let y: T = v` is valid at every T (a probe accepts) -> not "all probes errored" -> accept.
      expect(codes(`class C { x: u256; @modifier m<T>(v: T) { let y: T = v; _; } get z(): External<u256> { return this.x; } }`)).toEqual([]);
      // v.length is valid at bytes (the bytes probe accepts).
      expect(codes(`class C { x: u256; @modifier m<T>(v: T) { require(v.length > 0n, "x"); _; } get z(): External<u256> { return this.x; } }`)).toEqual([]);
    });
    // MULTI-TYPE-PARAM: the "all probes errored" guard uses the CROSS-PRODUCT of probes over the type params,
    // so a valid HETEROGENEOUS-param body (a: uint, b: bool) is NOT over-rejected (a mixed binding type-checks),
    // while a genuine conflict on one param (no valid instantiation) still rejects.
    it('no over-rejection: multi-type-param heterogeneous body stays accepted (cross-product binding)', () => {
      const J = `class C { x: u256; @modifier m<A,B>(a: A, b: B) { require(a > 0n, "x"); require(b && true, "y"); _; } get z(): External<u256> { return this.x; } }`;
      const S = `contract C { uint256 x; modifier m(uint256 a, bool b) { require(a > 0, "x"); require(b && true, "y"); _; } function z() external view returns(uint256){ return x; } }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
    });
    it('OA close: multi-type-param conflict on one param still rejects (no valid instantiation)', () => {
      const J = `class C { x: u256; @modifier m<A,B>(a: A, b: B) { let p: bool = a; let q: u256 = a; _; } get z(): External<u256> { return this.x; } }`;
      const S = `contract C { uint256 x; modifier m(uint256 a, bool b) { bool p = a; uint256 q = a; _; } function z() external view returns(uint256){ return x; } }`;
      expect(codes(J)).toContain('JETH085');
      expect(solcRejects(S)).toBe(true);
    });
    it('OA close: call to a non-existent function', () => {
      const J = `class C { @modifier m<U>() { nope(); _; } get z(): External<u256> { return 7n; } }`;
      const S = `contract C { modifier m() { nope(); _; } function z() external pure returns(uint256){ return 7; } }`;
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });
    it('OA close: wrong-argument-count call', () => {
      const J = `class C { g(a: u256): u256 { return a; } @modifier m<U>() { this.g(1n, 2n); _; } get z(): External<u256> { return 7n; } }`;
      const S = `contract C { function g(uint256 a) internal pure returns(uint256){return a;} modifier m() { g(1, 2); _; } function z() external pure returns(uint256){ return 7; } }`;
      expect(codes(J)).toContain('JETH148');
      expect(solcRejects(S)).toBe(true);
    });
    it('OA close: return-with-value (a modifier cannot return a value)', () => {
      const J = `class C { @modifier m<U>() { return 7n; _; } get z(): External<u256> { return 7n; } }`;
      const S = `contract C { modifier m() { return 7; _; } function z() external pure returns(uint256){ return 7; } }`;
      expect(codes(J)).toContain('JETH324');
      expect(solcRejects(S)).toBe(true);
    });
    it('OA close: MULTI-type-param generic modifier with a type-independent break', () => {
      const J = `class C { @modifier m<A, B>() { g; _; } get z(): External<u256> { return 7n; } }`;
      const S = `contract C { modifier m() { g; _; } function z() external pure returns(uint256){ return 7; } }`;
      expect(codes(J)).toContain('JETH072');
      expect(solcRejects(S)).toBe(true);
    });
    it('OA close: an unapplied generic modifier declared in a BASE class (derived route)', () => {
      const J = `abstract class B { @modifier m<U>() { g; _; } } class C extends B { get z(): External<u256> { return 7n; } }`;
      const S = `abstract contract B { modifier m(){ g; _; } } contract C is B { function z() external pure returns(uint256){ return 7; } }`;
      expect(codes(J)).toContain('JETH072');
      expect(solcRejects(S)).toBe(true);
    });
    it('OA close: a type-independent break in a whole-body (post-placeholder) generic modifier', () => {
      const J = `class C { log: u256; @modifier m<U>() { this.log = 1n; _; g; } get z(): External<u256> { return 7n; } }`;
      const S = `contract C { uint256 log; modifier m(){ log=1; _; g; } function z() external view returns(uint256){ return 7; } }`;
      expect(codes(J)).toContain('JETH072');
      expect(solcRejects(S)).toBe(true);
    });

    // ---- NO NEW OVER-REJECTION: each must still ACCEPT (a body VALID for any type param) ----
    it('accept: valid unapplied generic modifier (require(true); _;)', () => {
      const J = `class C { @modifier m<U>() { require(true, "x"); _; } get z(): External<u256> { return 7n; } }`;
      const S = `contract C { modifier m() { require(true, "x"); _; } function z() external pure returns(uint256){ return 7; } }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
    });
    it('accept: unapplied generic modifier consistently using its own param (let y: U = v)', () =>
      expect(codes(`class C { @modifier m<U>(v: U) { let y: U = v; _; } get z(): External<u256> { return 7n; } }`)).toEqual([]));
    it('accept: unapplied generic modifier reading this.<state>', () => {
      const J = `class C { owner: address; @modifier m<U>() { require(msg.sender == this.owner, "x"); _; } get z(): External<u256> { return 7n; } }`;
      const S = `contract C { address owner; modifier m(){ require(msg.sender==owner,"x"); _; } function z() external view returns(uint256){ return 7; } }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
    });
    it('accept: unapplied generic body valid only at bytes (v.length) is NOT over-rejected (type-param-dependent)', () =>
      expect(codes(`class C { @modifier m<U>(v: U) { let n: u256 = v.length; _; } get z(): External<u256> { return 7n; } }`)).toEqual([]));
    it('accept: unapplied generic body reading a STRUCT FIELD via its type param is NOT over-rejected (synthesized-struct probe)', () => {
      const J = `type P = { foo: u256 }; class C { @modifier m<U>(v: U) { let x: u256 = v.foo; _; } get z(): External<u256> { return 7n; } }`;
      const S = `contract C { struct P { uint256 foo; } modifier m(P memory v){ uint256 x = v.foo; _; } function z() external pure returns(uint256){ return 7; } }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
    });
    it('accept: generic modifier APPLIED on one method but not another (applied instance is checked at its site)', () => {
      const J = `class C { s: u256 = 0n; @modifier g<U>(v: U) { require(true); _; } @g<u256>(1n) a(): External<void> { this.s = 1n; } b(): External<void> { this.s = 2n; } }`;
      const S = `contract C { uint256 s; modifier g(uint256 v){ require(true); _; } function a() external g(1) { s=1; } function b() external { s=2; } }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
    });
    it('accept: a non-generic modifier and a contract with no modifiers are unchanged', () => {
      expect(codes(`class C { @modifier m() { require(true); _; } get z(): External<u256> { return 7n; } }`)).toEqual([]);
      expect(codes(`class C { get z(): External<u256> { return 7n; } }`)).toEqual([]);
    });

    // ---- BYTE-IDENTITY: adding a VALID unapplied generic modifier changes NO creation/runtime bytecode ----
    it('adding a valid unapplied SINGLE-type-param generic modifier does NOT change creation or runtime bytecode', () => {
      const base = `class C { s: u256 = 0n; setS(v: u256): External<void> { this.s = v; } get getS(): External<u256> { return this.s; } }`;
      const plus = `class C { s: u256 = 0n; @modifier gm<U>(v: U) { let y: U = v; require(true, "x"); _; } setS(v: u256): External<void> { this.s = v; } get getS(): External<u256> { return this.s; } }`;
      const b = compile(base, { fileName: 'C.jeth' });
      const p = compile(plus, { fileName: 'C.jeth' });
      expect(p.creationBytecode).toBe(b.creationBytecode);
      expect(p.runtimeBytecode).toBe(b.runtimeBytecode);
    });
    it('adding a valid unapplied MULTI-type-param generic modifier does NOT change creation or runtime bytecode', () => {
      const base = `class C { s: u256 = 0n; setS(v: u256): External<void> { this.s = v; } get getS(): External<u256> { return this.s; } }`;
      const plus = `class C { s: u256 = 0n; @modifier gm<A, B>() { require(1n > 0n); _; } setS(v: u256): External<void> { this.s = v; } get getS(): External<u256> { return this.s; } }`;
      const b = compile(base, { fileName: 'C.jeth' });
      const p = compile(plus, { fileName: 'C.jeth' });
      expect(p.creationBytecode).toBe(b.creationBytecode);
      expect(p.runtimeBytecode).toBe(b.runtimeBytecode);
    });
  });

  // OR LIFT: a U-typed body LOCAL / annotation (`let y: U = v`) inside an APPLIED generic @modifier body was
  // over-rejected JETH013 ("unknown JETH type 'U'"): collectModifier stores the body's RAW TS statements and
  // they were re-checked at the application site OUTSIDE the monomorphization binding, so U did not resolve.
  // Now RawModifier carries the concrete binding and withModifierTypeBinding restores it around body lowering
  // at every application site (buildModifierWrap / inlineModifier / inlineModifierBodyIntoCtor), so U resolves
  // to the concrete instantiation - byte-identical to solc's monomorphized modifier body. The binding is
  // restored ONLY around the modifier body (not the caller-scope application args), so it does not leak. This
  // introduces zero miscompiles / over-acceptances (a body broken AT the concrete type still rejects) and zero
  // new over-rejections (adversarially verified deploy+run+decode across instantiation types and body shapes).
  describe('APPLIED generic @modifier with a U-typed body local resolves to the instantiation (OR lift, solc parity)', () => {
    it('OR CLOSED: the exact witness now accepts (solc monomorph accepts)', () => {
      const J = `class C { s: u256 = 0n; @modifier lim<U>(v: U) { let y: U = v; _; } @lim<u256>(3n) f(x: u256): External<void> { this.s = x; } }`;
      const S = `contract C { uint256 s; modifier lim(uint256 v){ uint256 y = v; _; } function f(uint256 x) external lim(3) { s = x; } }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
    });
    // ---- no new over-rejection: valid U-typed-local bodies ACCEPT across instantiation types + body shapes ----
    it('accept: U-typed local at value types (u256/address/bool) and multi-type-param', () => {
      expect(codes(`class C { s: u256 = 0n; @modifier m<U>(v: U){ let y: U = v; this.s = 1n; _; } @m<u256>(7n) f(): External<void> {} }`)).toEqual([]);
      expect(codes(`class C { a: address; @modifier m<U>(v: U){ let y: U = v; this.a = y; _; } @m<address>(address(0xabn)) f(): External<void> {} }`)).toEqual([]);
      expect(codes(`class C { s: u256 = 0n; @modifier m<U>(v: U){ let y: U = v; if (y) { this.s = 1n; } _; } @m<bool>(true) f(): External<void> {} }`)).toEqual([]);
      expect(codes(`class C { s: u256 = 0n; t: u256 = 0n; @modifier m<A,B>(p: A, q: B){ let x: A = p; let y: B = q; this.s = x; this.t = y; _; } @m<u256,u256>(5n,9n) f(): External<void> {} }`)).toEqual([]);
    });
    it('accept: U-typed local at a struct instantiation (field read), function site', () => {
      const J = `type P = { a: u256; b: u256 }; class C { s: u256 = 0n; @modifier m<U>(v: U){ let y: U = v; this.s = y.a; _; } @m<P>(P(8n,3n)) f(): External<void> {} }`;
      const S = `struct P { uint256 a; uint256 b; } contract C { uint256 s; modifier m(P memory v){ P memory y = v; s = y.a; _; } function f() external m(P(8,3)) {} }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
    });
    it('accept: U-typed local in post-placeholder and conditional-placeholder shapes', () => {
      expect(codes(`class C { s: u256 = 0n; @modifier m<U>(v: U){ _; let y: U = v; this.s = y; } @m<u256>(7n) f(x: u256): External<void> { this.s = x; } }`)).toEqual([]);
      expect(codes(`class C { s: u256 = 0n; @modifier m<U>(v: U){ let y: U = v; if (true) { _; } this.s = y; } @m<u256>(7n) f(x: u256): External<void> { this.s = x; } }`)).toEqual([]);
    });
    // ---- no new over-acceptance: a body broken AT THE CONCRETE TYPE still rejects (solc parity) ----
    it('OA guard: a U-typed local misused at the concrete instantiation still rejects on both sides', () => {
      const bad: [string, string][] = [
        [`class C { s: u256 = 0n; @modifier m<U>(v: U){ let y: U = (1n > 0n); _; } @m<u256>(3n) f(): External<void> { this.s = 1n; } }`,
         `contract C { uint256 s; modifier m(uint256 v){ uint256 y = (1>0); _; } function f() external m(3) { s=1; } }`],
        [`class C { s: u256 = 0n; @modifier m<U>(v: U){ let y: U = v.foo; _; } @m<u256>(3n) f(): External<void> { this.s = 1n; } }`,
         `contract C { uint256 s; modifier m(uint256 v){ uint256 y = v.foo; _; } function f() external m(3) { s=1; } }`],
        [`class C { s: u256 = 0n; @modifier m<U>(v: U){ v.push(1n); _; } @m<u256>(3n) f(): External<void> { this.s = 1n; } }`,
         `contract C { uint256 s; modifier m(uint256 v){ v.push(1); _; } function f() external m(3) { s=1; } }`],
      ];
      for (const [J, S] of bad) {
        expect(codes(J).length).toBeGreaterThan(0);
        expect(solcRejects(S)).toBe(true);
      }
    });
    it('OA guard: a genuinely unknown type in the body still rejects JETH013 (binding is not a blanket suppressor)', () => {
      const J = `class C { s: u256 = 0n; @modifier m<U>(v: U){ let y: NoSuch = v; _; } @m<u256>(3n) f(): External<void> { this.s = 1n; } }`;
      const S = `contract C { uint256 s; modifier m(uint256 v){ NoSuch y = v; _; } function f() external m(3) { s=1; } }`;
      expect(codes(J)).toContain('JETH013');
      expect(solcRejects(S)).toBe(true);
    });
    it('no leak: the type parameter U is NOT visible in the wrapped function body (still JETH013)', () => {
      const J = `class C { s: u256 = 0n; @modifier m<U>(v: U){ let y: U = v; _; } @m<u256>(3n) f(): External<void> { let z: U = 1n; this.s = 1n; } }`;
      const S = `contract C { uint256 s; modifier m(uint256 v){ uint256 y = v; _; } function f() external m(3) { U z = 1; s=1; } }`;
      expect(codes(J)).toContain('JETH013');
      expect(solcRejects(S)).toBe(true);
    });
    // ---- deploy+run+decode byte-identity (the runtime lock) ----
    it('byte-identical run: a U-typed local carries the value into storage (u256)', async () => {
      const J = `class C { s: u256 = 0n; @modifier lim<U>(v: U){ let y: U = v; this.s = y; _; } @lim<u256>(7n) f(): External<u256> { return this.s; } }`;
      const S = `contract C { uint256 s; modifier lim(uint256 v){ uint256 y = v; s = y; _; } function f() external lim(7) returns(uint256){ return s; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('f()'));
      const rs = await s.h.call(s.a, '0x' + sel('f()'));
      expect(rj.success).toBe(rs.success);
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(BigInt(rj.returnHex)).toBe(7n);
      expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    });
    it('byte-identical run: post-placeholder U-typed local and a multi-type-param body', async () => {
      const J1 = `class C { s: u256 = 0n; @modifier lim<U>(v: U){ _; let y: U = v; this.s = y; } @lim<u256>(7n) f(x: u256): External<void> { this.s = x; } }`;
      const S1 = `contract C { uint256 s; modifier lim(uint256 v){ _; uint256 y = v; s = y; } function f(uint256 x) external lim(7) { s = x; } }`;
      const j1 = await depJ(J1),
        s1 = await depS(S1);
      await j1.h.call(j1.a, '0x' + sel('f(uint256)') + pad32(3n));
      await s1.h.call(s1.a, '0x' + sel('f(uint256)') + pad32(3n));
      expect(await readSlot(j1.h, j1.a, 0n)).toBe(await readSlot(s1.h, s1.a, 0n));
      expect(BigInt(await readSlot(j1.h, j1.a, 0n))).toBe(7n);
      const J2 = `class C { s: u256 = 0n; t: u256 = 0n; @modifier two<A,B>(p: A, q: B){ let x: A = p; let y: B = q; this.s = x; this.t = y; _; } @two<u256,u256>(5n,9n) f(): External<u256> { return this.s + this.t; } }`;
      const S2 = `contract C { uint256 s; uint256 t; modifier two(uint256 p, uint256 q){ uint256 x = p; uint256 y = q; s = x; t = y; _; } function f() external two(5,9) returns(uint256){ return s + t; } }`;
      const j2 = await depJ(J2),
        s2 = await depS(S2);
      const rj = await j2.h.call(j2.a, '0x' + sel('f()'));
      const rs = await s2.h.call(s2.a, '0x' + sel('f()'));
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(BigInt(rj.returnHex)).toBe(14n);
    });
  });

  // OR LIFT: a generic @modifier applied to a CONSTRUCTOR using a POINTER-HEADED aggregate type argument
  // (struct / dynamic-field struct / fixed array Arr<T,N>) as a WHOLE VALUE (`this.sp = v`, a body local
  // `let y: T = v; this.sp = y`, an internal-fn arg, an emit arg) was over-rejected JETH085 "cannot assign
  // u256 to P". ROOT CAUSE (an analysis-ordering bug, NOT codegen): the standalone unapplied-generic-body
  // pass probes a generic modifier body under a FINITE type set (u256/i256/bool/.../synthesized-struct); a
  // CONSTRUCTOR-applied generic was not marked applied before that pass ran (ctor lowering runs later than
  // function lowering), so a body valid ONLY at the real non-probe instantiation type - a user struct P -
  // errored under every probe and was wrongly rejected as uninstantiable. FIX: pre-scan the route's ctor
  // chain and mark ctor-applied generic templates applied before the pass, excluding them from it (mirroring
  // how a function application already suppresses it). The real monomorph is still checked at the ctor inline
  // site, so a broken ctor-applied body is still caught. Codegen-neutral; verified byte-identical deploy+run+
  // decode across aggregate shapes/consumers/inheritance, zero MC/OA/new-over-rejection.
  describe('generic @modifier on a CONSTRUCTOR with an aggregate whole-value use (OR lift, solc parity)', () => {
    it('OR CLOSED: ctor generic modifier whole-assigns a struct type arg (byte-identical, reads a AND b)', async () => {
      const J = `type P = { a: u256; b: u256 }; class C { sp: P; @modifier m<T>(v: T) { this.sp = v; _; } @m(P(8n,3n)) constructor() {} get pa(): External<u256> { return this.sp.a; } get pb(): External<u256> { return this.sp.b; } }`;
      const S = `struct P { uint256 a; uint256 b; } contract C { P sp; modifier m(P memory v){ sp = v; _; } constructor() m(P(8,3)) {} function pa() external view returns(uint256){ return sp.a; } function pb() external view returns(uint256){ return sp.b; } }`;
      expect(codes(J)).toEqual([]);
      expect(solcRejects(S)).toBe(false);
      const j = await depJ(J),
        s = await depS(S);
      for (const g of ['pa()', 'pb()']) {
        const rj = await j.h.call(j.a, '0x' + sel(g));
        const rs = await s.h.call(s.a, '0x' + sel(g));
        expect(rj.returnHex).toBe(rs.returnHex);
      }
      expect(BigInt((await j.h.call(j.a, '0x' + sel('pa()'))).returnHex)).toBe(8n);
      expect(BigInt((await j.h.call(j.a, '0x' + sel('pb()'))).returnHex)).toBe(3n);
    });
    it('accept: ctor generic modifier at fixed-array / dyn-field-struct / body-local / internal-arg / emit shapes', () => {
      expect(codes(`class C { fx: Arr<u256,3>; @modifier m<T>(v: T) { this.fx = v; _; } @m<Arr<u256,3>>([u256(4n),5n,6n]) constructor() {} get f0(): External<u256> { return this.fx[0n]; } }`)).toEqual([]);
      expect(codes(`type D = { a: u256; b: bytes }; class C { sd: D; @modifier m<T>(v: T) { this.sd = v; _; } @m(D(7n, bytes("qz"))) constructor() {} get da(): External<u256> { return this.sd.a; } }`)).toEqual([]);
      expect(codes(`type P = { a: u256; b: u256 }; class C { sp: P; @modifier m<T>(v: T) { let y: T = v; this.sp = y; _; } @m(P(8n,3n)) constructor() {} get pa(): External<u256> { return this.sp.a; } }`)).toEqual([]);
      expect(codes(`type P = { a: u256; b: u256 }; class C { n: u256; sum(p: P): u256 { return p.a + p.b; } @modifier m<T>(v: T) { let y: T = v; this.n = this.sum(y); _; } @m(P(8n,3n)) constructor() {} get gn(): External<u256> { return this.n; } }`)).toEqual([]);
      expect(codes(`type P = { a: u256; b: u256 }; class C { Ev: event<{ p: P }>; n: u256 = 0n; @modifier m<T>(v: T) { emit(this.Ev(v)); _; } @m(P(8n,3n)) constructor() { this.n = 1n; } get gn(): External<u256> { return this.n; } }`)).toEqual([]);
    });
    it('byte-identical run: ctor generic modifier whole-assigns a fixed array (reads all 3 elements)', async () => {
      const J = `class C { fx: Arr<u256,3>; @modifier m<T>(v: T) { this.fx = v; _; } @m<Arr<u256,3>>([u256(4n),5n,6n]) constructor() {} get f0(): External<u256> { return this.fx[0n]; } get f1(): External<u256> { return this.fx[1n]; } get f2(): External<u256> { return this.fx[2n]; } }`;
      const S = `contract C { uint256[3] fx; modifier m(uint256[3] memory v){ fx = v; _; } constructor() m([uint256(4),5,6]) {} function f0() external view returns(uint256){ return fx[0]; } function f1() external view returns(uint256){ return fx[1]; } function f2() external view returns(uint256){ return fx[2]; } }`;
      const j = await depJ(J),
        s = await depS(S);
      for (const [g, want] of [['f0()', 4n], ['f1()', 5n], ['f2()', 6n]] as [string, bigint][]) {
        const rj = await j.h.call(j.a, '0x' + sel(g));
        const rs = await s.h.call(s.a, '0x' + sel(g));
        expect(rj.returnHex).toBe(rs.returnHex);
        expect(BigInt(rj.returnHex)).toBe(want);
      }
    });
    it('byte-identical run: ctor generic modifier passes the aggregate to an internal function', async () => {
      const J = `type P = { a: u256; b: u256 }; class C { n: u256; sum(p: P): u256 { return p.a + p.b; } @modifier m<T>(v: T) { let y: T = v; this.n = this.sum(y); _; } @m(P(8n,3n)) constructor() {} get gn(): External<u256> { return this.n; } }`;
      const S = `struct P { uint256 a; uint256 b; } contract C { uint256 n; function sum(P memory p) internal pure returns(uint256){ return p.a+p.b; } modifier m(P memory v){ P memory y = v; n = sum(y); _; } constructor() m(P(8,3)) {} function gn() external view returns(uint256){ return n; } }`;
      const j = await depJ(J),
        s = await depS(S);
      const rj = await j.h.call(j.a, '0x' + sel('gn()'));
      const rs = await s.h.call(s.a, '0x' + sel('gn()'));
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(BigInt(rj.returnHex)).toBe(11n);
    });
    it('byte-identical run: a BASE constructor applies the generic modifier, the DERIVED contract deploys', async () => {
      const J = `type P = { a: u256; b: u256 }; abstract class B { sp: P; @modifier m<T>(v: T) { this.sp = v; _; } @m(P(8n,3n)) constructor() {} } class C extends B { get pa(): External<u256> { return this.sp.a; } get pb(): External<u256> { return this.sp.b; } }`;
      const S = `struct P { uint256 a; uint256 b; } abstract contract B { P sp; modifier m(P memory v){ sp = v; _; } constructor() m(P(8,3)) {} } contract C is B { function pa() external view returns(uint256){ return sp.a; } function pb() external view returns(uint256){ return sp.b; } }`;
      expect(codes(J)).toEqual([]);
      const j = await depJ(J),
        s = await depS(S);
      expect((await j.h.call(j.a, '0x' + sel('pa()'))).returnHex).toBe((await s.h.call(s.a, '0x' + sel('pa()'))).returnHex);
      expect(BigInt((await j.h.call(j.a, '0x' + sel('pb()'))).returnHex)).toBe(3n);
    });
    // ---- no over-acceptance: a broken ctor-applied generic body is still caught at the ctor inline site ----
    it('OA guard: a broken ctor-applied generic body still rejects on both sides', () => {
      const bad: [string, string][] = [
        [`type P = { a: u256; b: u256 }; class C { sp: P; @modifier m<T>(v: T) { nope; this.sp = v; _; } @m(P(8n,3n)) constructor() {} get pa(): External<u256> { return this.sp.a; } }`,
         `struct P { uint256 a; uint256 b; } contract C { P sp; modifier m(P memory v){ nope; sp = v; _; } constructor() m(P(8,3)) {} function pa() external view returns(uint256){ return sp.a; } }`],
        [`type P = { a: u256; b: u256 }; class C { sp: P; flag: bool; @modifier m<T>(v: T) { this.flag = v; this.sp = v; _; } @m(P(8n,3n)) constructor() {} get pa(): External<u256> { return this.sp.a; } }`,
         `struct P { uint256 a; uint256 b; } contract C { P sp; bool flag; modifier m(P memory v){ flag = v; sp = v; _; } constructor() m(P(8,3)) {} function pa() external view returns(uint256){ return sp.a; } }`],
      ];
      for (const [J, S] of bad) {
        expect(codes(J).length).toBeGreaterThan(0);
        expect(solcRejects(S)).toBe(true);
      }
    });
    it('no over-suppression: a SIBLING never-applied broken generic modifier is still checked and rejects', () => {
      // The pre-scan marks ONLY the ctor-applied name (good), not the unrelated unapplied `bad`.
      const J = `type P = { a: u256; b: u256 }; class C { sp: P; @modifier good<T>(v: T) { this.sp = v; _; } @modifier bad<U>() { undefinedThing; _; } @good(P(8n,3n)) constructor() {} get pa(): External<u256> { return this.sp.a; } }`;
      expect(codes(J)).toContain('JETH072');
    });
  });
});
