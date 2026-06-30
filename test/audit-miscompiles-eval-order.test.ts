// Two silent miscompiles found by the full differential audit (both sides succeed, but persisted
// state / emitted log bytes differed), now fixed byte-identical to solc 0.8.35:
//  M0: require(cond, <side-effecting dynamic string expr>) must evaluate the message expression
//      EAGERLY (solc runs it even when cond is true); JETH had deferred it into the failure branch,
//      silently dropping the message's side effects on the success path.
//  M1: emit argument evaluation order - solc evaluates INDEXED args first in REVERSE source order,
//      then NON-INDEXED args in forward source order; JETH had evaluated strictly source-order LTR,
//      so a mixed-indexed event with side-effecting args produced different topic/data bytes.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function pair(jeth: string, sol: string) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { hj, hs, aj, as };
}
const logsOf = (r: { logs?: { topics: string[]; data: string }[] }) =>
  JSON.stringify(r.logs?.map((l) => ({ t: l.topics, d: l.data })) ?? []);

describe('audit miscompiles: require eager-eval + emit eval-order vs solc', () => {
  it('M0: require(true, sideEffectingMsg()) evaluates the message eagerly (state persists)', async () => {
    const { hj, hs, aj, as } = await pair(
      "@contract class C { @state m: u256; ev(): string { this.m = 42n; return 'x'; } @external go(): u256 { require(true, this.ev()); return 1n; } @external getM(): u256 { return this.m; } }",
      'contract C { uint256 m; function ev() internal returns(string memory){ m=42; return "x"; } function go() external returns(uint256){ require(true, ev()); return 1; } function getM() external view returns(uint256){ return m; } }',
    );
    const gj = await hj.call(aj, sel('go()'));
    const gs = await hs.call(as, sel('go()'));
    expect(gj.success).toBe(gs.success);
    expect(gj.returnHex).toBe(gs.returnHex);
    expect((await hj.call(aj, sel('getM()'))).returnHex).toBe((await hs.call(as, sel('getM()'))).returnHex);
  });

  it('M0: require(false, ...) still reverts with the message and runs its side effects', async () => {
    const { hj, hs, aj, as } = await pair(
      "@contract class C { @state c: u256; tag(): string { this.c = this.c + 1n; return 'E'; } @external go(ok: bool): void { require(ok, string.concat(this.tag(), '!')); } @external rc(): u256 { return this.c; } }",
      'contract C { uint256 c; function tag() internal returns(string memory){ c=c+1; return "E"; } function go(bool ok) external { require(ok, string.concat(tag(), "!")); } function rc() external view returns(uint256){ return c; } }',
    );
    const W = (n: bigint) => n.toString(16).padStart(64, '0');
    for (const v of [1n, 0n]) {
      const j = await hj.call(aj, sel('go(bool)') + W(v));
      const s = await hs.call(as, sel('go(bool)') + W(v));
      expect(j.success, `ok=${v}`).toBe(s.success);
      expect(j.returnHex, `ok=${v} ret`).toBe(s.returnHex);
    }
    expect((await hj.call(aj, sel('rc()'))).returnHex).toBe((await hs.call(as, sel('rc()'))).returnHex);
  });

  it('M1: emit Ev(a, indexed b) with side-effecting args matches solc topic/data', async () => {
    const { hj, hs, aj, as } = await pair(
      '@contract class C { @state s: u256; @event Ev(a: u256, @indexed b: u256); @external go(): void { this.s = 0n; emit(Ev((this.s = this.s*10n+1n), (this.s = this.s*10n+2n))); } }',
      'contract C { uint256 s; event Ev(uint256 a, uint256 indexed b); function go() external { s = 0; emit Ev((s = s*10+1), (s = s*10+2)); } }',
    );
    expect(logsOf(await hj.call(aj, sel('go()')))).toBe(logsOf(await hs.call(as, sel('go()'))));
  });

  it('M1: interleaved (a, @b, c, @d) side-effecting args - indexed reverse then non-indexed forward', async () => {
    const { hj, hs, aj, as } = await pair(
      '@contract class C { @state s: u256; @event Ev(a: u256, @indexed b: u256, c: u256, @indexed d: u256); @external go(): void { this.s = 0n; emit(Ev((this.s=this.s*10n+1n),(this.s=this.s*10n+2n),(this.s=this.s*10n+3n),(this.s=this.s*10n+4n))); } }',
      'contract C { uint256 s; event Ev(uint256 a, uint256 indexed b, uint256 c, uint256 indexed d); function go() external { s = 0; emit Ev((s=s*10+1),(s=s*10+2),(s=s*10+3),(s=s*10+4)); } }',
    );
    expect(logsOf(await hj.call(aj, sel('go()')))).toBe(logsOf(await hs.call(as, sel('go()'))));
  });

  it('M1 regression: ordinary non-side-effecting events stay byte-identical', async () => {
    const W = (n: bigint) => n.toString(16).padStart(64, '0');
    const { hj, hs, aj, as } = await pair(
      '@contract class C { @event T(@indexed f: address, @indexed t: address, v: u256); @external go(a: address, b: address, v: u256): void { emit(T(a, b, v)); } }',
      'contract C { event T(address indexed f, address indexed t, uint256 v); function go(address a, address b, uint256 v) external { emit T(a, b, v); } }',
    );
    const args = W(0x1111n) + W(0x2222n) + W(100n);
    expect(logsOf(await hj.call(aj, sel('go(address,address,uint256)') + args))).toBe(
      logsOf(await hs.call(as, sel('go(address,address,uint256)') + args)),
    );
  });
});
