// W3-Y2a (over-rejections lifted byte-identical to solc 0.8.35): nested-struct-chain reads/writes rooted
// at a dynamic-field struct MEMORY local, where the chain crosses >=1 DYNAMIC hop and then either:
//   P0-35a  m.i.xs[k]         - indexes a dynamic value-array LEAF reached through a nested dyn-struct chain
//                               (base m.i is itself a nested dyn-struct field; the leaf head word derefs to
//                               the [len][elems] image). Read, .length, whole-field read, element read.
//   P1-24   m.i.xs[0n] = 9n   - element WRITE into that same nested dyn-array leaf (const + runtime index).
//   P1-23   v.t.inner.x       - a nested STATIC-struct hop UNDER a dynamic hop: `inner` is stored INLINE in
//                               the dyn hop's image, so its word offset folds into an inline accumulator
//                               rather than a deref. Read + write of a value leaf, arbitrarily deep static
//                               chains, and a static-hop then a further dynamic hop.
//
// Previously these surfaced as JETH900/JETH151/JETH214/JETH226 (a misleading "calldata parameter is
// read-only" / "mapping access" / an ICE) on valid input. resolveMemDynNestedStructRef now folds static
// hops into an inline word-offset accumulator (deref only on dynamic hops), and resolveCdDynStruct skips a
// memory dyn-struct local so it never mis-claims one as a calldata param. Genuinely-invalid chains still
// reject cleanly; a calldata dyn-struct PARAM chain is unchanged.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => n.toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const cdArr = (xs: readonly bigint[]) => W(BigInt(xs.length)) + xs.map((x) => W(x)).join('');
// calldata for a single u256[] param: [offset=0x20][len][elems...]
const argYs = (xs: readonly bigint[]) => W(32n) + cdArr(xs);
// calldata for (uint256 k, uint256[] ys): [k][offset_to_ys=0x40][len][elems...]
const argKYs = (k: bigint, xs: readonly bigint[]) => W(k) + W(64n) + cdArr(xs);

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig}(${args}) success`).toBe(rs.success);
    expect(rj.returnHex, `${sig}(${args}) return`).toBe(rs.returnHex);
  }
}

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};

describe('W3-Y2a nested-struct-chain reads/writes - byte-identical to solc 0.8.35', () => {
  it('P0-35a: m.i.xs[k] read (value spread + OOB Panic) + .length + whole read', async () => {
    await eqCalls(
      '@struct class I { xs: u256[]; n: u256 } @struct class M { a: u256; i: I } @contract class C { @external @pure go(k: u256, ys: u256[]): u256 { let m: M = M(1n, I(ys, 7n)); return m.i.xs[k]; } @external @pure ln(ys: u256[]): u256 { let m: M = M(1n, I(ys, 7n)); return m.i.xs.length; } @external @pure whole(ys: u256[]): u256[] { let m: M = M(1n, I(ys, 7n)); return m.i.xs; } }',
      'struct I { uint256[] xs; uint256 n; } struct M { uint256 a; I i; } contract C { function go(uint256 k, uint256[] calldata ys) external pure returns(uint256){ M memory m=M(1,I(ys,7)); return m.i.xs[k]; } function ln(uint256[] calldata ys) external pure returns(uint256){ M memory m=M(1,I(ys,7)); return m.i.xs.length; } function whole(uint256[] calldata ys) external pure returns(uint256[] memory){ M memory m=M(1,I(ys,7)); return m.i.xs; } }',
      [
        ['go(uint256,uint256[])', argKYs(0n, [10n, 20n, 30n])],
        ['go(uint256,uint256[])', argKYs(1n, [10n, 20n, 30n])],
        ['go(uint256,uint256[])', argKYs(2n, [10n, 20n, 30n])],
        ['go(uint256,uint256[])', argKYs(3n, [10n, 20n, 30n])], // OOB -> Panic 0x32
        ['ln(uint256[])', argYs([10n, 20n, 30n])],
        ['whole(uint256[])', argYs([10n, 20n, 30n])],
      ],
    );
  });

  it('P1-24: m.i.xs[i] write (const + runtime index) with read-back; no sibling corruption', async () => {
    await eqCalls(
      '@struct class I { xs: u256[]; n: u256 } @struct class M { a: u256; i: I } @contract class C { @external @pure go(ys: u256[]): u256 { let m: M = M(1n, I(ys, 4242n)); m.i.xs[0n] = 99n; m.i.xs[2n] = 77n; return m.i.xs[0n] + m.i.xs[1n] + m.i.xs[2n] + m.i.n + m.a; } @external @pure wr(k: u256, ys: u256[]): u256 { let m: M = M(1n, I(ys, 7n)); m.i.xs[k] = 999n; return m.i.xs[k]; } }',
      'struct I { uint256[] xs; uint256 n; } struct M { uint256 a; I i; } contract C { function go(uint256[] calldata ys) external pure returns(uint256){ M memory m=M(1,I(ys,4242)); m.i.xs[0]=99; m.i.xs[2]=77; return m.i.xs[0]+m.i.xs[1]+m.i.xs[2]+m.i.n+m.a; } function wr(uint256 k, uint256[] calldata ys) external pure returns(uint256){ M memory m=M(1,I(ys,7)); m.i.xs[k]=999; return m.i.xs[k]; } }',
      [
        ['go(uint256[])', argYs([10n, 20n, 30n])],
        ['wr(uint256,uint256[])', argKYs(0n, [10n, 20n, 30n])],
        ['wr(uint256,uint256[])', argKYs(2n, [10n, 20n, 30n])],
        ['wr(uint256,uint256[])', argKYs(3n, [10n, 20n, 30n])], // OOB -> Panic 0x32
      ],
    );
  });

  it('P1-23: v.t.inner.x static hop under a dynamic hop - value read + write', async () => {
    await eqCalls(
      '@struct class In { x: u256; y: u256 } @struct class T { s: string; inner: In } @struct class S { a: u256; t: T } @contract class C { @external @pure rd(): u256 { let v: S = S(1n, T("hi", In(5n, 6n))); return v.t.inner.x + v.t.inner.y + v.a; } @external @pure wr(): u256 { let v: S = S(1n, T("hi", In(5n, 6n))); v.t.inner.x = 50n; v.t.inner.y = 60n; return v.t.inner.x + v.t.inner.y; } }',
      'struct In { uint256 x; uint256 y; } struct T { string s; In inner; } struct S { uint256 a; T t; } contract C { function rd() external pure returns(uint256){ S memory v=S(1,T("hi",In(5,6))); return v.t.inner.x+v.t.inner.y+v.a; } function wr() external pure returns(uint256){ S memory v=S(1,T("hi",In(5,6))); v.t.inner.x=50; v.t.inner.y=60; return v.t.inner.x+v.t.inner.y; } }',
      [['rd()', ''], ['wr()', '']],
    );
  });

  it('P1-23: deep static hops (v.t.inner.i2.p) + a static hop then a further dynamic hop (v.t.inner.u.x)', async () => {
    await eqCalls(
      '@struct class In2 { p: u256; q: u256 } @struct class In { z: u256; i2: In2 } @struct class T { s: string; inner: In } @struct class S { a: u256; t: T } @contract class C { @external @pure rd(): u256 { let v: S = S(1n, T("hi", In(9n, In2(3n,4n)))); return v.t.inner.i2.p + v.t.inner.i2.q + v.t.inner.z; } @external @pure wr(): u256 { let v: S = S(1n, T("hi", In(9n, In2(3n,4n)))); v.t.inner.i2.p = 100n; v.t.inner.z = 200n; return v.t.inner.i2.p + v.t.inner.i2.q + v.t.inner.z; } }',
      'struct In2 { uint256 p; uint256 q; } struct In { uint256 z; In2 i2; } struct T { string s; In inner; } struct S { uint256 a; T t; } contract C { function rd() external pure returns(uint256){ S memory v=S(1,T("hi",In(9,In2(3,4)))); return v.t.inner.i2.p+v.t.inner.i2.q+v.t.inner.z; } function wr() external pure returns(uint256){ S memory v=S(1,T("hi",In(9,In2(3,4)))); v.t.inner.i2.p=100; v.t.inner.z=200; return v.t.inner.i2.p+v.t.inner.i2.q+v.t.inner.z; } }',
      [['rd()', ''], ['wr()', '']],
    );
    await eqCalls(
      '@struct class U { s: string; x: u256 } @struct class In { z: u256; u: U } @struct class T { s: string; inner: In } @struct class S { a: u256; t: T } @contract class C { @external @pure rd(): u256 { let v: S = S(1n, T("hi", In(9n, U("yo", 55n)))); return v.t.inner.u.x + v.t.inner.z; } @external @pure wr(): u256 { let v: S = S(1n, T("hi", In(9n, U("yo", 55n)))); v.t.inner.u.x = 88n; return v.t.inner.u.x; } }',
      'struct U { string s; uint256 x; } struct In { uint256 z; U u; } struct T { string s; In inner; } struct S { uint256 a; T t; } contract C { function rd() external pure returns(uint256){ S memory v=S(1,T("hi",In(9,U("yo",55)))); return v.t.inner.u.x+v.t.inner.z; } function wr() external pure returns(uint256){ S memory v=S(1,T("hi",In(9,U("yo",55)))); v.t.inner.u.x=88; return v.t.inner.u.x; } }',
      [['rd()', ''], ['wr()', '']],
    );
  });

  it('P1-23: writing v.t.inner.x does not corrupt a sibling string (v.t.s after inner)', async () => {
    await eqCalls(
      '@struct class In { x: u256; y: u256 } @struct class T { inner: In; s: string } @struct class S { a: u256; t: T } @contract class C { @external @pure go(): string { let v: S = S(1n, T(In(5n, 6n), "keepme")); v.t.inner.x = 999n; v.t.inner.y = 888n; return v.t.s; } }',
      'struct In { uint256 x; uint256 y; } struct T { In inner; string s; } struct S { uint256 a; T t; } contract C { function go() external pure returns(string memory){ S memory v=S(1,T(In(5,6),"keepme")); v.t.inner.x=999; v.t.inner.y=888; return v.t.s; } }',
      [['go()', '']],
    );
  });

  it('internal (default-visibility) dyn-struct MEMORY param: nested chains through resolveCdDynStruct-skip', async () => {
    // an internal param is registered in memDynStructLocals; the resolveCdDynStruct guard must route these
    // through the memory resolvers, not mis-claim them as calldata params.
    await eqCalls(
      '@struct class In { x: u256; y: u256 } @struct class T { s: string; inner: In } @struct class S { a: u256; t: T } @contract class C { @pure rd(v: S): u256 { return v.t.inner.x + v.t.inner.y + v.a; } @external @pure go(): u256 { let v: S = S(10n, T("hi", In(5n, 6n))); return rd(v); } }',
      'struct In { uint256 x; uint256 y; } struct T { string s; In inner; } struct S { uint256 a; T t; } contract C { function rd(S memory v) internal pure returns(uint256){ return v.t.inner.x+v.t.inner.y+v.a; } function go() external pure returns(uint256){ S memory v=S(10,T("hi",In(5,6))); return rd(v); } }',
      [['go()', '']],
    );
    await eqCalls(
      '@struct class I { xs: u256[]; n: u256 } @struct class M { a: u256; i: I } @contract class C { @pure rd(m: M, k: u256): u256 { return m.i.xs[k] + m.i.n; } @external @pure go(k: u256, ys: u256[]): u256 { let m: M = M(1n, I(ys, 42n)); return rd(m, k); } }',
      'struct I { uint256[] xs; uint256 n; } struct M { uint256 a; I i; } contract C { function rd(M memory m, uint256 k) internal pure returns(uint256){ return m.i.xs[k]+m.i.n; } function go(uint256 k, uint256[] calldata ys) external pure returns(uint256){ M memory m=M(1,I(ys,42)); return rd(m,k); } }',
      [['go(uint256,uint256[])', argKYs(1n, [10n, 20n, 30n])]],
    );
  });

  it('a calldata dyn-struct PARAM chain is unchanged (resolveCdDynStruct still fires)', async () => {
    // an @external dynamic-struct param stays a calldata read (NOT a memory local); this must keep working.
    const sBlob = W(2n) + '6869'.padEnd(64, '0'); // "hi"
    const tTuple = W(64n) + W(7n) + sBlob; // [off_to_s=0x40][n=7][s]
    const vTuple = W(100n) + W(64n) + tTuple; // [a=100][off_to_t=0x40][t]
    const arg = W(32n) + vTuple; // [off_to_v=0x20][v]
    await eqCalls(
      '@struct class T { s: string; n: u256 } @struct class S { a: u256; t: T } @contract class C { @external @pure go(v: S): u256 { return v.a + v.t.n; } }',
      'struct T { string s; uint256 n; } struct S { uint256 a; T t; } contract C { function go(S calldata v) external pure returns(uint256){ return v.a + v.t.n; } }',
      [['go((uint256,(string,uint256)))', arg]],
    );
  });

  it('genuinely-invalid nested chains still reject cleanly (no misleading calldata / mapping diagnostic)', () => {
    // an unknown field on a nested static hop
    expect(
      codes(
        '@struct class In { x: u256 } @struct class T { s: string; inner: In } @struct class S { a: u256; t: T } @contract class C { @external @pure go(): u256 { let v: S = S(1n, T("hi", In(5n))); return v.t.inner.nope; } }',
      ),
    ).toContain('JETH210');
    // a member access on a VALUE array element (m.i.xs[0].x)
    const c = codes(
      '@struct class I { xs: u256[]; n: u256 } @struct class M { a: u256; i: I } @contract class C { @external @pure go(ys: u256[]): u256 { let m: M = M(1n, I(ys, 7n)); return m.i.xs[0n].x; } }',
    );
    expect(c.length).toBeGreaterThan(0);
    expect(c).not.toContain('JETH151'); // not the misleading "mapping access" diagnostic
    expect(c).not.toContain('JETH214'); // not the misleading "calldata read-only" diagnostic
  });
});
