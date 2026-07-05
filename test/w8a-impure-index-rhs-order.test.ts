// W8A (RHS-value-before-index): a whole-AGGREGATE store into an element / member / mapping-value
// whose INDEX/KEY is impure and MUTATES state the (side-effect-free) RHS then READS. solc evaluates
// the RHS VALUE first, then the index/key; JETH previously hoisted the index temp first (its side
// effect ran), then built the RHS against POST-mutation state - a slot-level MISCOMPILE. The fix
// materializes the RHS aggregate into a memory temp FIRST (source order), then hoists the impure
// index once, then copies the temp into the resolved slot - byte-identical to solc for the four
// whole-aggregate target shapes AND the former JETH331 side-effecting-RHS case. Verified via
// returndata + raw storage slots + side-effect count parity.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);

async function rt(
  jeth: string,
  sol: string,
  calls: string[],
  slots: bigint[] = [],
): Promise<void> {
  const jb = compile(jeth, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jb.creationBytecode);
  const as = await hs.deploy(sb.creation);
  for (const sig of calls) {
    const data = '0x' + sel(sig);
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${sig}: returndata`).toBe(rs.returnHex);
  }
  for (const s of slots) {
    expect(await readSlot(hj, aj, s), `slot ${s}`).toBe(await readSlot(hs, as, s));
  }
}

describe('W8A: whole-aggregate store with an impure index that mutates RHS-read state (byte-identical)', () => {
  it('struct-array element ps[bump()] = P(ctr, ctr+50): RHS reads PRE-bump ctr', async () => {
    await rt(
      `@struct class P { x: u256; y: u256 } @contract class C {
        @state ctr: u256; @state ps: P[];
        bump(): u256 { this.ctr = this.ctr + 1n; return 0n; }
        @external run(): void { this.ps.push(P(0n,0n)); this.ps[this.bump()] = P(this.ctr, this.ctr + 50n); }
        @external @view gx(): u256 { return this.ps[0n].x; }
        @external @view gy(): u256 { return this.ps[0n].y; }
        @external @view gc(): u256 { return this.ctr; } }`,
      `struct P { uint256 x; uint256 y; } contract C {
        uint256 ctr; P[] ps;
        function bump() internal returns(uint256){ ctr = ctr + 1; return 0; }
        function run() external { ps.push(P(0,0)); ps[bump()] = P(ctr, ctr + 50); }
        function gx() external view returns(uint256){ return ps[0].x; }
        function gy() external view returns(uint256){ return ps[0].y; }
        function gc() external view returns(uint256){ return ctr; } }`,
      ['run()', 'gx()', 'gy()', 'gc()'],
      [0n],
    );
  });

  it('fixed-array element dd[bump()] = [ctr, ctr+50] (Arr<u256,2>[])', async () => {
    await rt(
      `@contract class C {
        @state ctr: u256; @state dd: Arr<u256,2>[];
        bump(): u256 { this.ctr = this.ctr + 1n; return 0n; }
        @external run(): void { this.dd.push([0n,0n]); this.dd[this.bump()] = [this.ctr, this.ctr + 50n]; }
        @external @view g0(): u256 { return this.dd[0n][0n]; }
        @external @view g1(): u256 { return this.dd[0n][1n]; } }`,
      `contract C {
        uint256 ctr; uint256[2][] dd;
        function bump() internal returns(uint256){ ctr = ctr + 1; return 0; }
        function run() external { dd.push([uint256(0),0]); dd[bump()] = [ctr, ctr + 50]; }
        function g0() external view returns(uint256){ return dd[0][0]; }
        function g1() external view returns(uint256){ return dd[0][1]; } }`,
      ['run()', 'g0()', 'g1()'],
      [0n],
    );
  });

  it('struct-member field xs[bump()].inner = P(ctr, ctr+50)', async () => {
    await rt(
      `@struct class P { x: u256; y: u256 } @struct class Q { inner: P } @contract class C {
        @state ctr: u256; @state xs: Q[];
        bump(): u256 { this.ctr = this.ctr + 1n; return 0n; }
        @external run(): void { this.xs.push(Q(P(0n,0n))); this.xs[this.bump()].inner = P(this.ctr, this.ctr + 50n); }
        @external @view gx(): u256 { return this.xs[0n].inner.x; }
        @external @view gy(): u256 { return this.xs[0n].inner.y; } }`,
      `struct P { uint256 x; uint256 y; } struct Q { P inner; } contract C {
        uint256 ctr; Q[] xs;
        function bump() internal returns(uint256){ ctr = ctr + 1; return 0; }
        function run() external { xs.push(Q(P(0,0))); xs[bump()].inner = P(ctr, ctr + 50); }
        function gx() external view returns(uint256){ return xs[0].inner.x; }
        function gy() external view returns(uint256){ return xs[0].inner.y; } }`,
      ['run()', 'gx()', 'gy()'],
      [0n],
    );
  });

  it('mapping-to-struct m[bump()] = P(ctr, ctr+50)', async () => {
    await rt(
      `@struct class P { x: u256; y: u256 } @contract class C {
        @state ctr: u256; @state m: mapping<u256,P>;
        bump(): u256 { this.ctr = this.ctr + 1n; return 0n; }
        @external run(): void { this.m[this.bump()] = P(this.ctr, this.ctr + 50n); }
        @external @view gx(): u256 { return this.m[0n].x; }
        @external @view gy(): u256 { return this.m[0n].y; } }`,
      `struct P { uint256 x; uint256 y; } contract C {
        uint256 ctr; mapping(uint256=>P) m;
        function bump() internal returns(uint256){ ctr = ctr + 1; return 0; }
        function run() external { m[bump()] = P(ctr, ctr + 50); }
        function gx() external view returns(uint256){ return m[0].x; }
        function gy() external view returns(uint256){ return m[0].y; } }`,
      ['run()', 'gx()', 'gy()'],
      [0n],
    );
  });

  it('side-effect count parity: bump() runs EXACTLY once (disjoint nc counter)', async () => {
    await rt(
      `@struct class P { x: u256; y: u256 } @contract class C {
        @state ctr: u256; @state nc: u256; @state ps: P[];
        bump(): u256 { this.nc = this.nc + 1n; this.ctr = this.ctr + 1n; return 0n; }
        @external run(): void { this.ps.push(P(0n,0n)); this.ps[this.bump()] = P(this.ctr, this.ctr + 50n); }
        @external @view gx(): u256 { return this.ps[0n].x; }
        @external @view gnc(): u256 { return this.nc; }
        @external @view gctr(): u256 { return this.ctr; } }`,
      `struct P { uint256 x; uint256 y; } contract C {
        uint256 ctr; uint256 nc; P[] ps;
        function bump() internal returns(uint256){ nc = nc + 1; ctr = ctr + 1; return 0; }
        function run() external { ps.push(P(0,0)); ps[bump()] = P(ctr, ctr + 50); }
        function gx() external view returns(uint256){ return ps[0].x; }
        function gnc() external view returns(uint256){ return nc; }
        function gctr() external view returns(uint256){ return ctr; } }`,
      ['run()', 'gx()', 'gnc()', 'gctr()'],
      [0n, 1n],
    );
  });

  it('side-effecting KEY on a mapping runs exactly once', async () => {
    await rt(
      `@struct class P { x: u256; y: u256 } @contract class C {
        @state ctr: u256; @state nc: u256; @state m: mapping<u256,P>;
        key(): u256 { this.nc = this.nc + 1n; this.ctr = this.ctr + 7n; return 3n; }
        @external run(): void { this.m[this.key()] = P(this.ctr, this.ctr + 1n); }
        @external @view gx(): u256 { return this.m[3n].x; }
        @external @view gnc(): u256 { return this.nc; } }`,
      `struct P { uint256 x; uint256 y; } contract C {
        uint256 ctr; uint256 nc; mapping(uint256=>P) m;
        function key() internal returns(uint256){ nc = nc + 1; ctr = ctr + 7; return 3; }
        function run() external { m[key()] = P(ctr, ctr + 1); }
        function gx() external view returns(uint256){ return m[3].x; }
        function gnc() external view returns(uint256){ return nc; } }`,
      ['run()', 'gx()', 'gnc()'],
      [0n, 1n],
    );
  });

  it('side-effecting index AND side-effecting RHS (former JETH331) is byte-identical', async () => {
    // solc evaluates the RHS (mk() side effects) BEFORE the index (bump()).
    await rt(
      `@struct class P { x: u256; y: u256 } @contract class C {
        @state ctr: u256; @state ps: P[];
        bump(): u256 { this.ctr = this.ctr + 1n; return 0n; }
        mk(): u256 { this.ctr = this.ctr + 100n; return this.ctr; }
        @external run(): void { this.ps.push(P(0n,0n)); this.ps[this.bump()] = P(this.mk(), this.mk()); }
        @external @view gx(): u256 { return this.ps[0n].x; }
        @external @view gy(): u256 { return this.ps[0n].y; }
        @external @view gc(): u256 { return this.ctr; } }`,
      `struct P { uint256 x; uint256 y; } contract C {
        uint256 ctr; P[] ps;
        function bump() internal returns(uint256){ ctr = ctr + 1; return 0; }
        function mk() internal returns(uint256){ ctr = ctr + 100; return ctr; }
        function run() external { ps.push(P(0,0)); ps[bump()] = P(mk(), mk()); }
        function gx() external view returns(uint256){ return ps[0].x; }
        function gy() external view returns(uint256){ return ps[0].y; }
        function gc() external view returns(uint256){ return ctr; } }`,
      ['run()', 'gx()', 'gy()', 'gc()'],
      [0n],
    );
  });

  it('memory-reference RHS with an impure index (storage deep-copy) is byte-identical', async () => {
    await rt(
      `@struct class P { x: u256; y: u256 } @contract class C {
        @state ctr: u256; @state ps: P[];
        bump(): u256 { this.ctr = this.ctr + 1n; return 0n; }
        @external run(): void { this.ps.push(P(0n,0n)); let src: P = P(this.ctr, this.ctr + 5n); this.ps[this.bump()] = src; }
        @external @view gx(): u256 { return this.ps[0n].x; }
        @external @view gy(): u256 { return this.ps[0n].y; } }`,
      `struct P { uint256 x; uint256 y; } contract C {
        uint256 ctr; P[] ps;
        function bump() internal returns(uint256){ ctr = ctr + 1; return 0; }
        function run() external { ps.push(P(0,0)); P memory src = P(ctr, ctr + 5); ps[bump()] = src; }
        function gx() external view returns(uint256){ return ps[0].x; }
        function gy() external view returns(uint256){ return ps[0].y; } }`,
      ['run()', 'gx()', 'gy()'],
      [0n],
    );
  });

  it('controls: value-leaf write + pure-index side-effecting-RHS stay byte-identical', async () => {
    // value-leaf ps[bump()].x = ctr (already correct; must stay)
    await rt(
      `@struct class P { x: u256; y: u256 } @contract class C {
        @state ctr: u256; @state ps: P[];
        bump(): u256 { this.ctr = this.ctr + 1n; return 0n; }
        @external run(): void { this.ps.push(P(0n,0n)); this.ps[this.bump()].x = this.ctr; }
        @external @view gx(): u256 { return this.ps[0n].x; } }`,
      `struct P { uint256 x; uint256 y; } contract C {
        uint256 ctr; P[] ps;
        function bump() internal returns(uint256){ ctr = ctr + 1; return 0; }
        function run() external { ps.push(P(0,0)); ps[bump()].x = ctr; }
        function gx() external view returns(uint256){ return ps[0].x; } }`,
      ['run()', 'gx()'],
      [0n],
    );
    // pure index, side-effecting RHS ps[0] = P(bump(), bump()) (already correct; must stay)
    await rt(
      `@struct class P { x: u256; y: u256 } @contract class C {
        @state ctr: u256; @state ps: P[];
        bump(): u256 { this.ctr = this.ctr + 1n; return this.ctr; }
        @external run(): void { this.ps.push(P(0n,0n)); this.ps[0n] = P(this.bump(), this.bump()); }
        @external @view gx(): u256 { return this.ps[0n].x; }
        @external @view gy(): u256 { return this.ps[0n].y; } }`,
      `struct P { uint256 x; uint256 y; } contract C {
        uint256 ctr; P[] ps;
        function bump() internal returns(uint256){ ctr = ctr + 1; return ctr; }
        function run() external { ps.push(P(0,0)); ps[0] = P(bump(), bump()); }
        function gx() external view returns(uint256){ return ps[0].x; }
        function gy() external view returns(uint256){ return ps[0].y; } }`,
      ['run()', 'gx()', 'gy()'],
      [0n],
    );
  });
});
