// USING-ON-LIBRARY (lift): `@using(M)` on a static-class (library) body IS consumed for that library's
// OWN bodies - solc scopes `using M for T` lexically to the DECLARING scope, and a library counts, so
// `x.f()` inside library L under `@using(M)` desugars to `M.f(x, ...)` exactly like inside a contract.
// @using is a pure RESOLUTION layer: the emitted call is identical to writing `M.f(x)` directly (proven
// byte-identical JETH-vs-JETH below), and `M.f(x)` is already byte-identical to solc, so the attached
// form is too. Every accept cell is verified run+decode byte-identical to solc 0.8.35 under non-trivial
// state; every reject cell is a both-reject (solc rejects the mirror). GUARDS: the lexical boundary holds
// (a contract's @using does not leak into a library body; one library's @using does not leak into another),
// @using naming a non-library rejects (JETH391), and a method not attached rejects (JETH074).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, compileSolidityLinked, deploySolLinked, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; }
  catch (e) { if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e; }
};
const solcRejects = (src: string): boolean => { try { compileSolidity(SPDX + src, 'C'); return false; } catch { return true; } };
async function dJ(s: string) { const h = await Harness.create(); return { h, a: await h.deploy(compile(s, { fileName: 'C.jeth' }).creationBytecode) }; }
async function dS(s: string) { const h = await Harness.create(); return { h, a: await h.deploy(compileSolidity(SPDX + s, 'C').creation) }; }

/** Deploy J + S; assert each call's success + returndata byte-identical, plus the first `nslots` raw
 *  storage slots. Calls run in order on BOTH sides (state carries). */
async function same(J: string, S: string, calls: { sig: string; arg?: string }[], nslots = 0) {
  const j = await dJ(J), s = await dS(S);
  for (const c of calls) {
    const d = '0x' + sel(c.sig) + (c.arg ?? '');
    const rj = await j.h.call(j.a, d), rs = await s.h.call(s.a, d);
    expect(rj.success, `${c.sig} success`).toBe(rs.success);
    expect(rj.returnHex, c.sig).toBe(rs.returnHex);
  }
  const js: string[] = [], ss: string[] = [];
  for (let i = 0; i < nslots; i++) { js.push(await readSlot(j.h, j.a, BigInt(i))); ss.push(await readSlot(s.h, s.a, BigInt(i))); }
  expect(js).toEqual(ss);
}

/** Assert JETH and solc BOTH reject `J`/`S`, and JETH's codes include `code`. */
function bothReject(J: string, S: string, code: string) {
  const c = codes(J);
  expect(c, 'JETH must reject').not.toEqual([]);
  expect(c).toContain(code);
  expect(solcRejects(S), 'solc must reject the mirror').toBe(true);
}

describe('USING-ON-LIBRARY: @using(M) inside a static-class library body', () => {
  it('u256 receiver, multi-method M, chained x.a().b().c()', async () => {
    await same(
      `static class M { dbl(x: u256): u256 { return x*2n; } inc(x: u256): u256 { return x+1n; } }
       @using(M) static class L { f(x: u256): u256 { return x.dbl().inc().dbl(); } }
       class C { get g(a: u256): External<u256> { return L.f(a); } }`,
      `library M { function dbl(uint256 x) internal pure returns(uint256){return x*2;} function inc(uint256 x) internal pure returns(uint256){return x+1;} }
       library L { using M for uint256; function f(uint256 x) internal pure returns(uint256){return x.dbl().inc().dbl();} }
       contract C { function g(uint256 a) external pure returns(uint256){ return L.f(a); } }`,
      [{ sig: 'g(uint256)', arg: W(3) }, { sig: 'g(uint256)', arg: W(0) }, { sig: 'g(uint256)', arg: W(1000) }],
    );
  });

  it('struct receiver, state written then read back through the attached call (raw slots)', async () => {
    await same(
      `type S = { a: u256; b: u256; };
       static class M { sum(s: S): u256 { return s.a + s.b; } }
       @using(M) static class L { total(s: S): u256 { return s.sum() * 10n; } }
       class C { st: S; set(x: u256, y: u256): External<void> { this.st.a = x; this.st.b = y; } get go(): External<u256> { return L.total(this.st); } }`,
      `struct S { uint256 a; uint256 b; }
       library M { function sum(S memory s) internal pure returns(uint256){return s.a+s.b;} }
       library L { using M for S; function total(S memory s) internal pure returns(uint256){return s.sum()*10;} }
       contract C { S st; function set(uint256 x,uint256 y) external { st.a=x; st.b=y; } function go() external view returns(uint256){ return L.total(st); } }`,
      [{ sig: 'set(uint256,uint256)', arg: W(7) + W(5) }, { sig: 'go()' }],
      2,
    );
  });

  it('bytesN and address receivers', async () => {
    await same(
      `static class M { hi(b: bytes32): bytes32 { return b; } }
       @using(M) static class L { echo(b: bytes32): bytes32 { return b.hi(); } }
       class C { get g(b: bytes32): External<bytes32> { return L.echo(b); } }`,
      `library M { function hi(bytes32 b) internal pure returns(bytes32){return b;} }
       library L { using M for bytes32; function echo(bytes32 b) internal pure returns(bytes32){return b.hi();} }
       contract C { function g(bytes32 b) external pure returns(bytes32){ return L.echo(b); } }`,
      [{ sig: 'g(bytes32)', arg: W(0xabc) }],
    );
    await same(
      `static class M { isZero(a: address): bool { return a == 0x0000000000000000000000000000000000000000; } }
       @using(M) static class L { chk(a: address): bool { return a.isZero(); } }
       class C { get g(a: address): External<bool> { return L.chk(a); } }`,
      `library M { function isZero(address a) internal pure returns(bool){return a==address(0);} }
       library L { using M for address; function chk(address a) internal pure returns(bool){return a.isZero();} }
       contract C { function g(address a) external pure returns(bool){ return L.chk(a); } }`,
      [{ sig: 'g(address)', arg: W(0) }, { sig: 'g(address)', arg: W(0x1234) }],
    );
  });

  it('self-convention and @using(M) attachments coexist in one library body', async () => {
    await same(
      `static class M { dbl(x: u256): u256 { return x*2n; } }
       static class N { half(self: u256): u256 { return self/2n; } }
       @using(M) static class L { f(x: u256): u256 { return x.dbl().half(); } }
       class C { get g(a: u256): External<u256> { return L.f(a); } }`,
      `library M { function dbl(uint256 x) internal pure returns(uint256){return x*2;} }
       library N { function half(uint256 x) internal pure returns(uint256){return x/2;} }
       library L { using M for uint256; using N for uint256; function f(uint256 x) internal pure returns(uint256){return x.dbl().half();} }
       contract C { function g(uint256 a) external pure returns(uint256){ return L.f(a); } }`,
      [{ sig: 'g(uint256)', arg: W(9) }, { sig: 'g(uint256)', arg: W(20) }],
    );
  });

  it('@using(M) inside an EXTERNAL (delegatecall) library, state-writing (linked)', async () => {
    const J = `static class M { bump(x: u256): u256 { return x + 100n; } }
      @using(M) static class L { grow(x: u256): External<u256> { return x.bump(); } }
      class C { v: u256; do(a: u256): External<void> { this.v = L.grow(a); } get val(): External<u256> { return this.v; } }`;
    const S = SPDX + `library M { function bump(uint256 x) internal pure returns(uint256){return x+100;} }
      library L { using M for uint256; function grow(uint256 x) external pure returns(uint256){return x.bump();} }
      contract C { uint256 v; function doo(uint256 a) external { v = L.grow(a); } function val() external view returns(uint256){ return v; } }`;
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidityLinked(S, 'C', ['L']);
    const jeth = await Harness.create(), sol = await Harness.create();
    const aj = (await jeth.deployLinked(jb)).address;
    const as = await deploySolLinked(sol, sb);
    await jeth.call(aj, '0x' + sel('do(uint256)') + W(42));
    await sol.call(as, '0x' + sel('doo(uint256)') + W(42));
    const jv = (await jeth.call(aj, '0x' + sel('val()'))).returnHex;
    const sv = (await sol.call(as, '0x' + sel('val()'))).returnHex;
    expect(jv).toBe(sv);
    expect(jv).toBe('0x' + W(142)); // 42 + 100, non-vacuous
    // raw storage: v landed in slot 0 on both sides
    expect(await readSlot(jeth, aj, 0n)).toBe(await readSlot(sol, as, 0n));
  });

  it('@using is a pure resolution layer: attached form is byte-identical to explicit M.f(x)', () => {
    const attached = compile(
      `static class M { dbl(x: u256): u256 { return x*2n; } }
       @using(M) static class L { td(x: u256): u256 { return x.dbl() + x; } }
       class C { get g(a: u256): External<u256> { return L.td(a); } }`,
      { fileName: 'C.jeth' },
    ).creationBytecode;
    const explicit = compile(
      `static class M { dbl(x: u256): u256 { return x*2n; } }
       static class L { td(x: u256): u256 { return M.dbl(x) + x; } }
       class C { get g(a: u256): External<u256> { return L.td(a); } }`,
      { fileName: 'C.jeth' },
    ).creationBytecode;
    expect(attached).toBe(explicit);
  });

  // ---- GUARDS: lexical boundaries + attachment validity (each a both-reject) ----

  it('lexical boundary: the deployed contract @using does NOT leak into a library body', () => {
    bothReject(
      `static class M { dbl(x: u256): u256 { return x*2n; } }
       static class L { f(x: u256): u256 { return x.dbl(); } }
       @using(M) class C { get g(a: u256): External<u256> { return L.f(a); } }`,
      `library M { function dbl(uint256 x) internal pure returns(uint256){return x*2;} }
       library L { function f(uint256 x) internal pure returns(uint256){return x.dbl();} }
       contract C { using M for uint256; function g(uint256 a) external pure returns(uint256){return L.f(a);} }`,
      'JETH074',
    );
  });

  it('lexical boundary: one library @using does NOT leak into another library body', () => {
    bothReject(
      `static class M { dbl(x: u256): u256 { return x*2n; } }
       @using(M) static class L1 { a(x: u256): u256 { return x.dbl(); } }
       static class L2 { b(x: u256): u256 { return x.dbl(); } }
       class C { get g(a: u256): External<u256> { return L2.b(a); } }`,
      `library M { function dbl(uint256 x) internal pure returns(uint256){return x*2;} }
       library L1 { using M for uint256; function a(uint256 x) internal pure returns(uint256){return x.dbl();} }
       library L2 { function b(uint256 x) internal pure returns(uint256){return x.dbl();} }
       contract C { function g(uint256 a) external pure returns(uint256){return L2.b(a);} }`,
      'JETH074',
    );
  });

  it('guard: @using naming a non-library rejects (JETH391)', () => {
    bothReject(
      `static class M { d(x: u256): u256 { return x; } } @using(Nope) static class L { f(x: u256): u256 { return x.d(); } } class C { get g(a: u256): External<u256> { return L.f(a); } }`,
      `library M{function d(uint256 x) internal pure returns(uint256){return x;}} library L{ using Nope for uint256; function f(uint256 x) internal pure returns(uint256){return x.d();} } contract C{function g(uint256 a) external pure returns(uint256){return L.f(a);}}`,
      'JETH391',
    );
  });

  it('guard: a method not in M rejects with the ordinary member-not-found (JETH074)', () => {
    bothReject(
      `static class M { d(x: u256): u256 { return x; } } @using(M) static class L { f(x: u256): u256 { return x.nope(); } } class C { get g(a: u256): External<u256> { return L.f(a); } }`,
      `library M{function d(uint256 x) internal pure returns(uint256){return x;}} library L{ using M for uint256; function f(uint256 x) internal pure returns(uint256){return x.nope();} } contract C{function g(uint256 a) external pure returns(uint256){return L.f(a);}}`,
      'JETH074',
    );
  });

  it('guard: a non-self first param with NO @using still rejects (no global attachment leak)', () => {
    bothReject(
      `static class M { dbl(x: u256): u256 { return x*2n; } } static class L { f(x: u256): u256 { return x.dbl(); } } class C { get g(a: u256): External<u256> { return L.f(a); } }`,
      `library M{function dbl(uint256 x) internal pure returns(uint256){return x*2;}} library L{ function f(uint256 x) internal pure returns(uint256){return x.dbl();} } contract C{function g(uint256 a) external pure returns(uint256){return L.f(a);}}`,
      'JETH074',
    );
  });
});
