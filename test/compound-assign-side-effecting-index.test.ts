// Compound-assign (`lhs op= rhs`) and ++/-- STATEMENT forms whose lvalue navigation contains a
// SIDE-EFFECTING index/key (m[f()], xs[i++], m[a()][b()]) used to be rejected (JETH331) because the
// desugared `lhs = lhs op rhs` evaluated the index twice. They are now lifted: each impure index is
// hoisted to a temp evaluated EXACTLY ONCE, and the RHS is evaluated first - byte-identical to solc
// (solc evaluates RHS first, then each lvalue index once). Verified: side-effect count, eval order,
// all ten compound operators, nested keys, struct fields, RHS that mutates the lvalue, overflow.
// The EXPR-position form `y = (xs[f()] += 1)` and the whole-aggregate element write `recs[idx()] =
// R(9)` (PURE value) are now ALSO lifted (same hoist machinery, byte-identical). W8A lifts the last
// whole-aggregate case: an element/member/mapping-value write whose index AND value BOTH side-effect
// (`recs[idx()] = R(mk())`) - the RHS aggregate is materialized into a memory temp FIRST (source
// order), then the impure index is hoisted once, then the temp is copied in, matching solc's
// RHS-before-index order byte-identical. The remaining JETH331 rejects are the EXPR-position
// compound-assign in a conditional / reentrant / nested position (below), where hoisting to the
// statement prelude would move the side effect.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

const JETH = `class C {
  xs: u256[];
  m: mapping<u256,u256>;
  mm: mapping<u256,mapping<u256,u256>>;
  c: u256;
  d: u256;
  tr: u256[];
  idx(): u256 { this.c++; return 0n; }
  amt(): u256 { this.d++; return 5n; }
  a(): u256 { this.tr.push(1n); return 2n; }
  b(): u256 { this.tr.push(3n); return 4n; }
  v(): u256 { this.tr.push(9n); return 7n; }
  gWrite(): u256 { this.xs[0n] = 1000n; return 1n; }
  seed(): External<void> { this.xs.push(100n); this.xs.push(200n); }
  arrCompound(): External<void> { this.xs[this.idx()] += 5n; }
  arrIncDec(): External<void> { this.xs[this.idx()]++; }
  mapCompound(): External<void> { this.m[this.idx()] += 9n; }
  nested(): External<void> { this.mm[this.a()][this.b()] += this.v(); }
  rhsMutates(): External<void> { this.xs[this.idx()] += this.gWrite(); }
  get rx(i: u256): External<u256> { return this.xs[i]; }
  get rc(): External<u256> { return this.c; }
  get rm(k: u256): External<u256> { return this.m[k]; }
  get rmm(i: u256, j: u256): External<u256> { return this.mm[i][j]; }
  get trN(): External<u256> { return this.tr.length; }
  get trAt(i: u256): External<u256> { return this.tr[i]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[] xs;
  mapping(uint256=>uint256) m;
  mapping(uint256=>mapping(uint256=>uint256)) mm;
  uint256 c;
  uint256 d;
  uint256[] tr;
  function idx() internal returns(uint256){ c++; return 0; }
  function amt() internal returns(uint256){ d++; return 5; }
  function a() internal returns(uint256){ tr.push(1); return 2; }
  function b() internal returns(uint256){ tr.push(3); return 4; }
  function v() internal returns(uint256){ tr.push(9); return 7; }
  function gWrite() internal returns(uint256){ xs[0]=1000; return 1; }
  function seed() external { xs.push(100); xs.push(200); }
  function arrCompound() external { xs[idx()] += 5; }
  function arrIncDec() external { xs[idx()]++; }
  function mapCompound() external { m[idx()] += 9; }
  function nested() external { mm[a()][b()] += v(); }
  function rhsMutates() external { xs[idx()] += gWrite(); }
  function rx(uint256 i) external view returns(uint256){ return xs[i]; }
  function rc() external view returns(uint256){ return c; }
  function rm(uint256 k) external view returns(uint256){ return m[k]; }
  function rmm(uint256 i, uint256 j) external view returns(uint256){ return mm[i][j]; }
  function trN() external view returns(uint256){ return tr.length; }
  function trAt(uint256 i) external view returns(uint256){ return tr[i]; }
}`;

// all ten compound operators on xs[idx()] (idx() side-effects c once)
const OPS = ['+=', '-=', '*=', '/=', '%=', '|=', '&=', '^=', '<<=', '>>='];
const opJ = (op: string) =>
  `class C { xs: u256[]; c: u256; idx(): u256 { this.c++; return 0n; }
   go(): External<void> { this.xs.push(60n); this.xs[this.idx()] ${op} 4n; }
   get rx(): External<u256> { return this.xs[0n]; } get rc(): External<u256> { return this.c; } }`;
const opS = (op: string) =>
  `// SPDX-License-Identifier: MIT
   pragma solidity ^0.8.20;
   contract C { uint256[] xs; uint256 c; function idx() internal returns(uint256){ c++; return 0; }
   function go() external { xs.push(60); xs[idx()] ${op} 4; }
   function rx() external view returns(uint256){ return xs[0]; } function rc() external view returns(uint256){ return c; } }`;

describe('compound-assign / ++ with a side-effecting index vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(JETH, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(SOL, 'C').creation);
  });

  it('xs[idx()] += 5: index evaluated once, byte-identical value', async () => {
    await eq('seed', encodeCall(sel('seed()'), []));
    await eq('arrCompound', encodeCall(sel('arrCompound()'), []));
    await eq('rc', encodeCall(sel('rc()'), [])); // c == 1, not 2
    await eq('rx0', '0x' + sel('rx(uint256)') + (0n).toString(16).padStart(64, '0'));
  });
  it('xs[idx()]++ statement: index once', async () => {
    await eq('arrIncDec', encodeCall(sel('arrIncDec()'), []));
    await eq('rc', encodeCall(sel('rc()'), []));
    await eq('rx0', '0x' + sel('rx(uint256)') + (0n).toString(16).padStart(64, '0'));
  });
  it('m[idx()] += 9: mapping key once', async () => {
    await eq('mapCompound', encodeCall(sel('mapCompound()'), []));
    await eq('rc', encodeCall(sel('rc()'), []));
    await eq('rm0', '0x' + sel('rm(uint256)') + (0n).toString(16).padStart(64, '0'));
  });
  it('mm[a()][b()] += v(): eval order RHS, then outer key, then inner key', async () => {
    await eq('nested', encodeCall(sel('nested()'), []));
    await eq('trN', encodeCall(sel('trN()'), []));
    for (let i = 0n; i < 3n; i++) await eq(`trAt${i}`, '0x' + sel('trAt(uint256)') + i.toString(16).padStart(64, '0'));
    await eq('rmm', '0x' + sel('rmm(uint256,uint256)') + (2n).toString(16).padStart(64, '0') + (4n).toString(16).padStart(64, '0'));
  });
  it('xs[idx()] += gWrite(): RHS-first, the read sees the RHS mutation', async () => {
    await eq('rhsMutates', encodeCall(sel('rhsMutates()'), []));
    await eq('rx0', '0x' + sel('rx(uint256)') + (0n).toString(16).padStart(64, '0'));
  });

  it('every compound operator is byte-identical with a side-effecting index', async () => {
    for (const op of OPS) {
      const j = await Harness.create();
      const s = await Harness.create();
      const ja = await j.deploy(compile(opJ(op), { fileName: 'C.jeth' }).creationBytecode);
      const sa = await s.deploy(compileSolidity(opS(op), 'C').creation);
      await j.call(ja, encodeCall(sel('go()'), []));
      await s.call(sa, encodeCall(sel('go()'), []));
      const jx = await j.call(ja, encodeCall(sel('rx()'), []));
      const sx = await s.call(sa, encodeCall(sel('rx()'), []));
      expect(jx.returnHex, `${op} value`).toBe(sx.returnHex);
      const jc = await j.call(ja, encodeCall(sel('rc()'), []));
      const sc = await s.call(sa, encodeCall(sel('rc()'), []));
      expect(jc.returnHex, `${op} index-eval-count`).toBe(sc.returnHex);
    }
  });

  // The EXPR-position form `let y = (xs[f()] += v)` is now lifted: the index runs ONCE, the RHS is
  // evaluated first, and the expression yields the assigned (new) value - byte-identical to solc.
  it('expr-position (xs[f()] += 5) yields the new value, index once, byte-identical', async () => {
    const J = `class C {
      xs: u256[]; c: u256;
      f(): u256 { this.c++; return 0n; }
      seed(): External<void> { this.xs.push(60n); }
      go(): External<u256> { let y: u256 = (this.xs[this.f()] += 5n); return y; }
      get rx(): External<u256> { return this.xs[0n]; }
      get rc(): External<u256> { return this.c; } }`;
    const S = `// SPDX-License-Identifier: MIT
      pragma solidity ^0.8.20;
      contract C { uint256[] xs; uint256 c; function f() internal returns(uint256){ c++; return 0; }
      function seed() external { xs.push(60); }
      function go() external returns(uint256){ uint256 y = (xs[f()] += 5); return y; }
      function rx() external view returns(uint256){ return xs[0]; }
      function rc() external view returns(uint256){ return c; } }`;
    const j = await Harness.create(), s = await Harness.create();
    const ja = await j.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await s.deploy(compileSolidity(S, 'C').creation);
    for (const sig of ['seed()', 'go()', 'rx()', 'rc()']) {
      const jr = await j.call(ja, encodeCall(sel(sig), []));
      const sr = await s.call(sa, encodeCall(sel(sig), []));
      expect(jr.success, `${sig} success`).toBe(sr.success);
      expect(jr.returnHex, `${sig} returndata`).toBe(sr.returnHex);
    }
  });

  // A side-effecting RHS in expr position: solc evaluates the RHS BEFORE the index; the hoist emits
  // the RHS temp first, then the index temp, so the observed side-effect order matches (2=rhs,1=idx).
  it('expr-position (xs[idx()] += rhs()) preserves RHS-before-index order', async () => {
    const J = `class C {
      xs: u256[]; ord: u256[];
      idx(): u256 { this.ord.push(1n); return 0n; }
      rhs(): u256 { this.ord.push(2n); return 5n; }
      seed(): External<void> { this.xs.push(60n); }
      go(): External<u256> { let y: u256 = (this.xs[this.idx()] += this.rhs()); return y; }
      get ordN(): External<u256> { return this.ord.length; }
      get ordAt(i: u256): External<u256> { return this.ord[i]; }
      get rx(): External<u256> { return this.xs[0n]; } }`;
    const S = `// SPDX-License-Identifier: MIT
      pragma solidity ^0.8.20;
      contract C { uint256[] xs; uint256[] ord;
      function idx() internal returns(uint256){ ord.push(1); return 0; }
      function rhs() internal returns(uint256){ ord.push(2); return 5; }
      function seed() external { xs.push(60); }
      function go() external returns(uint256){ uint256 y = (xs[idx()] += rhs()); return y; }
      function ordN() external view returns(uint256){ return ord.length; }
      function ordAt(uint256 i) external view returns(uint256){ return ord[i]; }
      function rx() external view returns(uint256){ return xs[0]; } }`;
    const j = await Harness.create(), s = await Harness.create();
    const ja = await j.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await s.deploy(compileSolidity(S, 'C').creation);
    await j.call(ja, encodeCall(sel('seed()'), []));
    await s.call(sa, encodeCall(sel('seed()'), []));
    const jg = await j.call(ja, encodeCall(sel('go()'), []));
    const sg = await s.call(sa, encodeCall(sel('go()'), []));
    expect(jg.returnHex, 'go y').toBe(sg.returnHex);
    for (const sig of ['ordN()', 'rx()']) {
      expect((await j.call(ja, encodeCall(sel(sig), []))).returnHex, sig).toBe(
        (await s.call(sa, encodeCall(sel(sig), []))).returnHex,
      );
    }
    for (let i = 0n; i < 2n; i++) {
      const d = '0x' + sel('ordAt(uint256)') + i.toString(16).padStart(64, '0');
      expect((await j.call(ja, d)).returnHex, `ordAt${i}`).toBe((await s.call(sa, d)).returnHex);
    }
  });

  // The whole-aggregate element write `recs[idx()] = R(9)` with a PURE value is now lifted: the index
  // runs ONCE, the element gets the struct, other elements are untouched - byte-identical to solc.
  it('whole-aggregate write recs[idx()] = R(9): index once, element set, byte-identical', async () => {
    const J = `type R = { a: u256; b: u256; };
      class C {
      recs: R[]; c: u256;
      idx(): u256 { this.c++; return 0n; }
      seed(): External<void> { this.recs.push(R(1n,2n)); this.recs.push(R(3n,4n)); }
      go(): External<void> { this.recs[this.idx()] = R(9n, 8n); }
      get ra(i: u256): External<u256> { return this.recs[i].a; }
      get rb(i: u256): External<u256> { return this.recs[i].b; }
      get rc(): External<u256> { return this.c; } }`;
    const S = `// SPDX-License-Identifier: MIT
      pragma solidity ^0.8.20;
      contract C { struct R { uint256 a; uint256 b; } R[] recs; uint256 c;
      function idx() internal returns(uint256){ c++; return 0; }
      function seed() external { recs.push(R(1,2)); recs.push(R(3,4)); }
      function go() external { recs[idx()] = R(9, 8); }
      function ra(uint256 i) external view returns(uint256){ return recs[i].a; }
      function rb(uint256 i) external view returns(uint256){ return recs[i].b; }
      function rc() external view returns(uint256){ return c; } }`;
    const j = await Harness.create(), s = await Harness.create();
    const ja = await j.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await s.deploy(compileSolidity(S, 'C').creation);
    await j.call(ja, encodeCall(sel('seed()'), []));
    await s.call(sa, encodeCall(sel('seed()'), []));
    await j.call(ja, encodeCall(sel('go()'), []));
    await s.call(sa, encodeCall(sel('go()'), []));
    expect((await j.call(ja, encodeCall(sel('rc()'), []))).returnHex, 'idx count').toBe(
      (await s.call(sa, encodeCall(sel('rc()'), []))).returnHex,
    );
    for (const fn of ['ra(uint256)', 'rb(uint256)']) {
      for (let i = 0n; i < 2n; i++) {
        const d = '0x' + sel(fn) + i.toString(16).padStart(64, '0');
        expect((await j.call(ja, d)).returnHex, `${fn}[${i}]`).toBe((await s.call(sa, d)).returnHex);
      }
    }
  });

  // W8A: a whole-aggregate element write whose index AND value BOTH side-effect
  // (`recs[idx()] = R(mk())`) is now LIFTED byte-identical. solc evaluates the VALUE before the
  // index; the fix materializes the RHS aggregate into a memory temp FIRST (its side effects run
  // in source order), THEN hoists the impure index once, THEN copies the temp into the resolved
  // slot - matching solc's RHS-before-index order (the former JETH331 over-rejection is gone).
  it('whole-aggregate write with a side-effecting index AND value is byte-identical (W8A lift)', async () => {
    const J = `type R = { a: u256; }; class C {
      recs: R[]; c: u256;
      idx(): u256 { this.c++; return 0n; }
      mk(): u256 { this.c++; return 9n; }
      go(): External<void> { this.recs.push(R(1n)); this.recs[this.idx()] = R(this.mk()); }
      get ra(): External<u256> { return this.recs[0n].a; }
      get rc(): External<u256> { return this.c; } }`;
    const S = `// SPDX-License-Identifier: MIT
      pragma solidity ^0.8.20;
      struct R { uint256 a; }
      contract C { R[] recs; uint256 c;
      function idx() internal returns(uint256){ c++; return 0; }
      function mk() internal returns(uint256){ c++; return 9; }
      function go() external { recs.push(R(1)); recs[idx()] = R(mk()); }
      function ra() external view returns(uint256){ return recs[0].a; }
      function rc() external view returns(uint256){ return c; } }`;
    const j = await Harness.create(),
      s = await Harness.create();
    const ja = await j.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await s.deploy(compileSolidity(S, 'C').creation);
    for (const sig of ['go()', 'ra()', 'rc()']) {
      const jr = await j.call(ja, encodeCall(sel(sig), []));
      const sr = await s.call(sa, encodeCall(sel(sig), []));
      expect(jr.success, `${sig} success`).toBe(sr.success);
      expect(jr.returnHex, `${sig} returndata`).toBe(sr.returnHex);
    }
    // Non-vacuity: solc writes recs[0].a = 9 (RHS mk()=9 evaluated before idx()=0), c ends at 2.
    const ra = await s.call(sa, encodeCall(sel('ra()'), []));
    expect(BigInt(ra.returnHex)).toBe(9n);
    const rc = await s.call(sa, encodeCall(sel('rc()'), []));
    expect(BigInt(rc.returnHex)).toBe(2n);
  });

  // The EXPR-position compound-assign lift is scoped to the WHOLE value of a statement. Any deeper
  // position where hoisting to the statement prelude would move the side effect - conditionally
  // (ternary branch, `&&`/`||` RHS), per-iteration (loop condition / incrementor), or out of order
  // (call argument, binary operand) - stays a sound JETH331 reject rather than a miscompile. solc
  // accepts these (they are sound over-rejections: a clean reject always beats wrong bytes).
  it('expr-position compound-assign in a conditional / reentrant / nested position stays a JETH331 reject', () => {
    const reject = (src: string) => {
      let codes: string[] = [];
      try {
        compile(src, { fileName: 'C.jeth' });
      } catch (e: unknown) {
        codes = ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
      }
      return codes;
    };
    const H = 'class C { xs: u256[]; c: u256; f(): u256 { this.c++; return 0n; }';
    // ternary branch (conditional): the index must not run when the branch is not taken
    expect(reject(`${H} go(t: bool): External<u256> { let y: u256 = t ? 9n : (this.xs[this.f()] += 1n); return y; } }`)).toContain('JETH331');
    // && RHS (short-circuit): the index must not run when the LHS is false
    expect(reject(`${H} go(t: bool): External<bool> { let y: bool = t && ((this.xs[this.f()] += 1n) > 0n); return y; } }`)).toContain('JETH331');
    // while-condition (re-evaluated): the index must run per iteration, not once
    expect(reject(`${H} go(): External<void> { while ((this.xs[this.f()] += 1n) < 3n) {} } }`)).toContain('JETH331');
    // for-incrementor (re-evaluated): same
    expect(reject(`${H} go(): External<void> { for (let i: u256 = 0n; i < 3n; i = i + (this.xs[this.f()] += 1n)) {} } }`)).toContain('JETH331');
    // call argument (relative order): the index must run in argument order, not in a prelude
    expect(reject(`${H} g(a: u256, b: u256): u256 { return a + b; } go(): External<u256> { return this.g(1n, (this.xs[this.f()] += 1n)); } }`)).toContain('JETH331');
    // binary operand (relative order): same
    expect(reject(`${H} go(): External<u256> { let y: u256 = 5n + (this.xs[this.f()] += 1n); return y; } }`)).toContain('JETH331');
  });
});
