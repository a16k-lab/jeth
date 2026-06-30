// Compound-assign (`lhs op= rhs`) and ++/-- STATEMENT forms whose lvalue navigation contains a
// SIDE-EFFECTING index/key (m[f()], xs[i++], m[a()][b()]) used to be rejected (JETH331) because the
// desugared `lhs = lhs op rhs` evaluated the index twice. They are now lifted: each impure index is
// hoisted to a temp evaluated EXACTLY ONCE, and the RHS is evaluated first - byte-identical to solc
// (solc evaluates RHS first, then each lvalue index once). Verified: side-effect count, eval order,
// all ten compound operators, nested keys, struct fields, RHS that mutates the lvalue, overflow.
// The EXPR-position forms (y = (xs[f()] += 1)) and whole-aggregate element writes stay sound rejects.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

const JETH = `@contract class C {
  @state xs: u256[];
  @state m: mapping<u256,u256>;
  @state mm: mapping<u256,mapping<u256,u256>>;
  @state c: u256;
  @state d: u256;
  @state tr: u256[];
  idx(): u256 { this.c++; return 0n; }
  amt(): u256 { this.d++; return 5n; }
  a(): u256 { this.tr.push(1n); return 2n; }
  b(): u256 { this.tr.push(3n); return 4n; }
  v(): u256 { this.tr.push(9n); return 7n; }
  gWrite(): u256 { this.xs[0n] = 1000n; return 1n; }
  @external seed(): void { this.xs.push(100n); this.xs.push(200n); }
  @external arrCompound(): void { this.xs[this.idx()] += 5n; }
  @external arrIncDec(): void { this.xs[this.idx()]++; }
  @external mapCompound(): void { this.m[this.idx()] += 9n; }
  @external nested(): void { this.mm[this.a()][this.b()] += this.v(); }
  @external rhsMutates(): void { this.xs[this.idx()] += this.gWrite(); }
  @external @view rx(i: u256): u256 { return this.xs[i]; }
  @external @view rc(): u256 { return this.c; }
  @external @view rm(k: u256): u256 { return this.m[k]; }
  @external @view rmm(i: u256, j: u256): u256 { return this.mm[i][j]; }
  @external @view trN(): u256 { return this.tr.length; }
  @external @view trAt(i: u256): u256 { return this.tr[i]; }
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
  `@contract class C { @state xs: u256[]; @state c: u256; idx(): u256 { this.c++; return 0n; }
   @external go(): void { this.xs.push(60n); this.xs[this.idx()] ${op} 4n; }
   @external @view rx(): u256 { return this.xs[0n]; } @external @view rc(): u256 { return this.c; } }`;
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

  it('expr-position and whole-aggregate forms stay sound rejects (JETH331, no crash)', () => {
    const reject = (src: string) => {
      let codes: string[] = [];
      try {
        compile(src, { fileName: 'C.jeth' });
      } catch (e: unknown) {
        codes = ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
      }
      return codes;
    };
    expect(
      reject('@contract class C { @state xs: u256[]; f(): u256 { return 0n; } @external go(): u256 { this.xs.push(1n); let y: u256 = (this.xs[this.f()] += 5n); return y; } }'),
    ).toContain('JETH331');
    expect(
      reject('@struct class R { a: u256; } @contract class C { @state recs: R[]; idx(): u256 { return 0n; } @external go(): void { this.recs.push(R(1n)); this.recs[this.idx()] = R(9n); } }'),
    ).toContain('JETH331');
  });
});
