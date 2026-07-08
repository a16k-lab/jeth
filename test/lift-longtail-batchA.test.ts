// Long-tail batch A lifts (docs/OR-CATALOGUE.md rows M-BYTES and T-LVALUE), byte-identical to
// solc 0.8.35:
// M1   direct plain-bytes-field byte WRITE on a memory dyn-struct local (q.b[2n] = 0x2an): a new
//      checkLValue branch keys on memDynStructFieldType (the chain roots at a MEMORY dyn-struct
//      local/param; storage roots at ThisKeyword and keeps its byteIndexStore RMW; calldata params
//      are never in memDynStructLocals) and emits the same in-place bounds-checked mstore8
//      (memByteIndexStore) the bytes-local / L13 bytes[]-element paths use.
// M2   2-hop nested field byte write/read (r.inner.b[1n]): the same gate resolves the field type
//      through resolveMemDynNestedStructRef; the read branch widened from identifier-only bases to
//      nested chains (claimed ONLY for bytes/string fields, so array-field element reads keep
//      their resolveArrayExpr paths).
// M3   byte READ rvalue through a bytes[] field chain (p.tags[1n][0n] as a VALUE): the Residual-B2
//      read gate now mirrors the L13 WRITE gate (a memArray local OR the field's memArrayExpr base).
// T1   ternary-chain whole-ELEMENT write (c ? this.A : this.B2)[i] = In(9n, 8n): the lvalue
//      desugar's final-type gate widened from static-value-only to bytes-like / struct / array
//      (every per-branch soundness gate re-runs via the synthetic checkAssignment calls).
// T2   compound assignment through the chain ((c ? A : B)[0].y += v, all ten ops) and ++/-- in
//      both statement and value position: solc's probed order (RHS, cond, index-once; ++/-- cond,
//      index-once) is preserved by the tmp-first branch-push / a short-circuit ternary of incDec.
// T3   nested ternary chains (c ? A : (d ? B : A))[i].y = v: the probe + emission recurse.
// GUARDS added with the lifts (all pre-existing bar violations fixed by this batch):
//  - branch-type unification: (c ? Arr<In,2> : Arr<In,3>) chains were OVER-ACCEPTED (solc
//    TypeError) on both the read and write desugars - ternBranchTypeQuiet now rejects the mix.
//  - location parity: (c ? this.A : m)[0].y = v (storage|memory) MISCOMPILED (solc writes into a
//    memory COPY of the storage branch; the branch-push wrote storage directly) - lvalueLoc parity
//    now keeps it a clean reject (a deliberate over-rejection: the copy-write semantics are not
//    reproducible by branch-pushing).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const run = async (J: string, S: string, calls: ReadonlyArray<readonly [string, string]>) => {
  const h = await Harness.create();
  await h.fund(me, 10n ** 20n);
  const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
  const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
  for (const [sg, args] of calls) {
    const jr = await h.call(ja, sel(sg) + args);
    const sr = await h.call(sa, sel(sg) + args);
    expect(jr.returnHex, `${sg} ${args.slice(0, 12)}`).toBe(sr.returnHex);
    expect(jr.success, sg).toBe(sr.success);
  }
};
const rejects = (src: string): boolean => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
};

describe('long-tail batch A: memory-struct byte access (M1-M3) byte-identical to solc 0.8.35', () => {
  it('M1/M2: plain + nested bytes-field byte write/read, runtime idx, OOB Panic, alias-through, storage/calldata controls', async () => {
    const J = `@struct class Q2 { b: bytes; n: u256 }
@struct class R2 { inner: Q2; m: u256 }
@contract class C {
  @state sq: Q2;
  @external seed(): void { this.sq.b = bytes("wxyz"); this.sq.n = 3n; }
  @external @pure m1(): bytes { let q: Q2 = Q2(bytes("wxyz"), 3n); q.b[2n] = 0x2an; return q.b; }
  @external @pure m2(i: u256): bytes { let q: Q2 = Q2(bytes("wxyz"), 3n); let s: R2 = R2(q, 7n); s.inner.b[i] = 0x5an; return s.inner.b; }
  @external @pure rd(i: u256): bytes1 { let q: Q2 = Q2(bytes("wxyz"), 3n); let s: R2 = R2(q, 7n); return s.inner.b[i]; }
  @external @pure al(): u256 { let q: Q2 = Q2(bytes("wxyz"), 3n); let t: bytes = q.b; q.b[2n] = 0x2an; return t[2n] == 0x2an ? 1n : 0n; }
  @external @pure alw(): u256 { let q: Q2 = Q2(bytes("wxyz"), 3n); let s: R2 = R2(q, 7n); s.inner.b[0n] = 0x42n; return q.b[0n] == 0x42n ? 1n : 0n; }
  poke(q: Q2): void { q.b[0n] = 0x42n; }
  @external @pure ia(): bytes { let q: Q2 = Q2(bytes("wxyz"), 3n); this.poke(q); return q.b; }
  @external ctlSt(): bytes { this.sq.b[1n] = 0x22n; return this.sq.b; } }`;
    const S = `contract C {
  struct Q2 { bytes b; uint256 n; }
  struct R2 { Q2 inner; uint256 m; }
  Q2 sq;
  function seed() external { sq.b = "wxyz"; sq.n = 3; }
  function m1() external pure returns (bytes memory) { Q2 memory q = Q2("wxyz", 3); q.b[2] = 0x2a; return q.b; }
  function m2(uint256 i) external pure returns (bytes memory) { Q2 memory q = Q2("wxyz", 3); R2 memory s = R2(q, 7); s.inner.b[i] = 0x5a; return s.inner.b; }
  function rd(uint256 i) external pure returns (bytes1) { Q2 memory q = Q2("wxyz", 3); R2 memory s = R2(q, 7); return s.inner.b[i]; }
  function al() external pure returns (uint256) { Q2 memory q = Q2("wxyz", 3); bytes memory t = q.b; q.b[2] = 0x2a; return t[2] == 0x2a ? 1 : 0; }
  function alw() external pure returns (uint256) { Q2 memory q = Q2("wxyz", 3); R2 memory s = R2(q, 7); s.inner.b[0] = 0x42; return q.b[0] == 0x42 ? 1 : 0; }
  function poke(Q2 memory q) internal pure { q.b[0] = 0x42; }
  function ia() external pure returns (bytes memory) { Q2 memory q = Q2("wxyz", 3); poke(q); return q.b; }
  function ctlSt() external returns (bytes memory) { sq.b[1] = 0x22; return sq.b; } }`;
    await run(J, S, [
      ['m1()', ''],
      ['m2(uint256)', W(1)],
      ['m2(uint256)', W(4)], // OOB write -> Panic 0x32 parity
      ['rd(uint256)', W(0)],
      ['rd(uint256)', W(9)], // OOB read -> Panic 0x32 parity
      ['al()', ''],
      ['alw()', ''],
      ['ia()', ''],
      ['seed()', ''],
      ['ctlSt()', ''], // storage base keeps the byteIndexStore RMW path
    ] as const);
    // a string field stays not-indexable (solc parity), a calldata dyn-struct param stays read-only.
    expect(
      rejects(`@struct class S2 { s: string; n: u256 } @contract class C { @external @pure f(): u256 { let q: S2 = S2("wxyz", 3n); q.s[0n] = 0x21n; return 1n; } }`),
    ).toBe(true);
    expect(
      rejects(`@struct class Q2 { b: bytes; n: u256 } @contract class C { @external f(q: Q2): u256 { q.b[0n] = 0x42n; return 1n; } }`),
    ).toBe(true);
  });

  it('M3: byte READ rvalue through a bytes[] field chain (+ ternary-base write cross stays lifted)', async () => {
    const J = `@struct class P2 { tags: bytes[]; n: u256 }
@contract class C {
  @external @pure r(i: u256, j: u256): bytes1 { let tg: bytes[] = [bytes("aabb"), bytes("cd")]; let p: P2 = P2(tg, 1n); return p.tags[i][j]; }
  @external @pure ar(): u256 { let tg: bytes[] = [bytes("aabb"), bytes("cd")]; let p: P2 = P2(tg, 1n); return p.tags[1n][0n] == 0x63n ? 1n : 0n; }
  @external @pure tb(c: bool): bytes { let t1: bytes[] = [bytes("aabb")]; let t2: bytes[] = [bytes("ccdd")]; let p: P2 = P2(t1, 1n); let q: P2 = P2(t2, 2n); (c ? p : q).tags[0n][1n] = 0x2an; return c ? p.tags[0n] : q.tags[0n]; } }`;
    const S = `contract C {
  struct P2 { bytes[] tags; uint256 n; }
  function r(uint256 i, uint256 j) external pure returns (bytes1) { bytes[] memory tg = new bytes[](2); tg[0] = "aabb"; tg[1] = "cd"; P2 memory p = P2(tg, 1); return p.tags[i][j]; }
  function ar() external pure returns (uint256) { bytes[] memory tg = new bytes[](2); tg[0] = "aabb"; tg[1] = "cd"; P2 memory p = P2(tg, 1); return p.tags[1][0] == 0x63 ? 1 : 0; }
  function tb(bool c) external pure returns (bytes memory) { bytes[] memory t1 = new bytes[](1); t1[0] = "aabb"; bytes[] memory t2 = new bytes[](1); t2[0] = "ccdd"; P2 memory p = P2(t1, 1); P2 memory q = P2(t2, 2); (c ? p : q).tags[0][1] = 0x2a; return c ? p.tags[0] : q.tags[0]; } }`;
    await run(J, S, [
      ['r(uint256,uint256)', W(1) + W(1)],
      ['r(uint256,uint256)', W(1) + W(2)], // OOB byte -> Panic 0x32
      ['r(uint256,uint256)', W(2) + W(0)], // OOB element -> Panic 0x32
      ['ar()', ''],
      ['tb(bool)', W(1)],
      ['tb(bool)', W(0)],
    ] as const);
  });
});

describe('long-tail batch A: ternary-chain lvalues (T1-T3) byte-identical to solc 0.8.35', () => {
  const IN = `@struct class In { x: u256; y: u256 }`;
  const SIN = `struct In { uint256 x; uint256 y; }`;

  it('T1: whole-element write (storage + memory branches), runtime idx + OOB, RHS/cond/idx order', async () => {
    const J = `${IN} @contract class C {
  @state A: Arr<In, 2>;
  @state B2: Arr<In, 2>;
  @state tr: u256[];
  cnd(): bool { this.tr.push(1n); return true; }
  idx(): u256 { this.tr.push(2n); return 0n; }
  rhs(): u256 { this.tr.push(3n); return 5n; }
  @external ord(): u256[] { (this.cnd() ? this.A : this.B2)[this.idx()] = In(this.rhs(), 8n); return this.tr; }
  @external w(c: bool, i: u256): u256 { (c ? this.A : this.B2)[i] = In(9n, 8n); return this.A[1n].y * 10n + this.B2[1n].y; }
  @external @pure wm(c: bool): u256 { let m1: Arr<In, 2> = [In(1n, 2n), In(3n, 4n)]; let m2: Arr<In, 2> = [In(5n, 6n), In(7n, 8n)]; (c ? m1 : m2)[0n] = In(9n, 8n); return m1[0n].y * 100n + m2[0n].y; } }`;
    const S = `contract C { ${SIN}
  In[2] A; In[2] B2;
  uint256[] tr;
  function cnd() internal returns (bool) { tr.push(1); return true; }
  function idx() internal returns (uint256) { tr.push(2); return 0; }
  function rhs() internal returns (uint256) { tr.push(3); return 5; }
  function ord() external returns (uint256[] memory) { (cnd() ? A : B2)[idx()] = In(rhs(), 8); return tr; }
  function w(bool c, uint256 i) external returns (uint256) { (c ? A : B2)[i] = In(9, 8); return A[1].y * 10 + B2[1].y; }
  function wm(bool c) external pure returns (uint256) { In[2] memory m1 = [In(1, 2), In(3, 4)]; In[2] memory m2 = [In(5, 6), In(7, 8)]; (c ? m1 : m2)[0] = In(9, 8); return m1[0].y * 100 + m2[0].y; } }`;
    await run(J, S, [
      ['ord()', ''], // solc-probed order [RHS, cond, idx]
      ['w(bool,uint256)', W(1) + W(1)],
      ['w(bool,uint256)', W(0) + W(1)],
      ['w(bool,uint256)', W(1) + W(2)], // OOB -> Panic 0x32 parity
      ['wm(bool)', W(1)],
      ['wm(bool)', W(0)],
    ] as const);
  });

  it('T2: compound ops + ++/-- (statement and value position) through the chain', async () => {
    const J = `${IN} @contract class C {
  @state A: Arr<In, 2>;
  @state B2: Arr<In, 2>;
  @state tr: u256[];
  cnd(): bool { this.tr.push(1n); return true; }
  idx(): u256 { this.tr.push(2n); return 0n; }
  rhs(): u256 { this.tr.push(3n); return 5n; }
  @external seed(): void { this.A[0n].y = 96n; this.B2[0n].y = 7n; }
  @external ord(): u256[] { (this.cnd() ? this.A : this.B2)[this.idx()].y += this.rhs(); return this.tr; }
  @external add(c: bool, v: u256): u256 { (c ? this.A : this.B2)[0n].y += v; return this.A[0n].y * 1000n + this.B2[0n].y; }
  @external dvd(c: bool, v: u256): u256 { (c ? this.A : this.B2)[0n].y /= v; return this.A[0n].y * 1000n + this.B2[0n].y; }
  @external xr(c: bool, v: u256): u256 { (c ? this.A : this.B2)[0n].y ^= v; return this.A[0n].y * 1000n + this.B2[0n].y; }
  @external shl(c: bool, v: u256): u256 { (c ? this.A : this.B2)[0n].y <<= v; return this.A[0n].y * 1000n + this.B2[0n].y; }
  @external st(c: bool): u256 { (c ? this.A : this.B2)[0n].y++; return this.A[0n].y * 100n + this.B2[0n].y; }
  @external ep(c: bool): u256 { let z: u256 = (c ? this.A : this.B2)[0n].y++; return z * 1000n + this.A[0n].y * 10n + this.B2[0n].y; }
  @external ef(c: bool): u256 { let z: u256 = --(c ? this.A : this.B2)[0n].y; return z * 1000n + this.A[0n].y * 10n + this.B2[0n].y; } }`;
    const S = `contract C { ${SIN}
  In[2] A; In[2] B2;
  uint256[] tr;
  function cnd() internal returns (bool) { tr.push(1); return true; }
  function idx() internal returns (uint256) { tr.push(2); return 0; }
  function rhs() internal returns (uint256) { tr.push(3); return 5; }
  function seed() external { A[0].y = 96; B2[0].y = 7; }
  function ord() external returns (uint256[] memory) { (cnd() ? A : B2)[idx()].y += rhs(); return tr; }
  function add(bool c, uint256 v) external returns (uint256) { (c ? A : B2)[0].y += v; return A[0].y * 1000 + B2[0].y; }
  function dvd(bool c, uint256 v) external returns (uint256) { (c ? A : B2)[0].y /= v; return A[0].y * 1000 + B2[0].y; }
  function xr(bool c, uint256 v) external returns (uint256) { (c ? A : B2)[0].y ^= v; return A[0].y * 1000 + B2[0].y; }
  function shl(bool c, uint256 v) external returns (uint256) { (c ? A : B2)[0].y <<= v; return A[0].y * 1000 + B2[0].y; }
  function st(bool c) external returns (uint256) { (c ? A : B2)[0].y++; return A[0].y * 100 + B2[0].y; }
  function ep(bool c) external returns (uint256) { uint256 z = (c ? A : B2)[0].y++; return z * 1000 + A[0].y * 10 + B2[0].y; }
  function ef(bool c) external returns (uint256) { uint256 z = --(c ? A : B2)[0].y; return z * 1000 + A[0].y * 10 + B2[0].y; } }`;
    await run(J, S, [
      ['seed()', ''],
      ['ord()', ''], // solc-probed compound order [RHS, cond, idx]
      ['add(bool,uint256)', W(1) + W(4)],
      ['dvd(bool,uint256)', W(0) + W(0)], // div-by-zero -> Panic 0x12 parity
      ['dvd(bool,uint256)', W(1) + W(4)],
      ['xr(bool,uint256)', W(0) + W(255)],
      ['shl(bool,uint256)', W(1) + W(2)],
      ['st(bool)', W(1)],
      ['st(bool)', W(0)],
      ['ep(bool)', W(1)],
      ['ep(bool)', W(0)],
      ['ef(bool)', W(1)],
      ['ef(bool)', W(0)],
    ] as const);
  });

  it('T3: nested ternary chains (3-level, ternary-in-cond, nested whole-element, nested compound)', async () => {
    const J = `${IN} @contract class C {
  @state A: Arr<In, 2>;
  @state B2: Arr<In, 2>;
  @state D: Arr<In, 2>;
  @external w3(c: bool, d: bool, e2: bool): u256 { (c ? this.A : (d ? this.B2 : (e2 ? this.D : this.A)))[1n].y = 42n; return this.A[1n].y * 10000n + this.B2[1n].y * 100n + this.D[1n].y; }
  @external wc(a: bool, b: bool): u256 { ((a ? b : !b) ? this.A : this.B2)[0n].y = 7n; return this.A[0n].y * 100n + this.B2[0n].y; }
  @external we(c: bool, d: bool): u256 { (c ? this.A : (d ? this.B2 : this.A))[0n] = In(3n, 4n); return this.A[0n].y * 100n + this.B2[0n].y; }
  @external wk(c: bool, d: bool): u256 { (c ? this.A : (d ? this.B2 : this.A))[0n].y += 5n; return this.A[0n].y * 100n + this.B2[0n].y; } }`;
    const S = `contract C { ${SIN}
  In[2] A; In[2] B2; In[2] D;
  function w3(bool c, bool d, bool e2) external returns (uint256) { (c ? A : (d ? B2 : (e2 ? D : A)))[1].y = 42; return A[1].y * 10000 + B2[1].y * 100 + D[1].y; }
  function wc(bool a, bool b) external returns (uint256) { ((a ? b : !b) ? A : B2)[0].y = 7; return A[0].y * 100 + B2[0].y; }
  function we(bool c, bool d) external returns (uint256) { (c ? A : (d ? B2 : A))[0] = In(3, 4); return A[0].y * 100 + B2[0].y; }
  function wk(bool c, bool d) external returns (uint256) { (c ? A : (d ? B2 : A))[0].y += 5; return A[0].y * 100 + B2[0].y; } }`;
    await run(J, S, [
      ['w3(bool,bool,bool)', W(0) + W(0) + W(1)],
      ['w3(bool,bool,bool)', W(0) + W(1) + W(0)],
      ['w3(bool,bool,bool)', W(0) + W(0) + W(0)],
      ['w3(bool,bool,bool)', W(1) + W(0) + W(0)],
      ['wc(bool,bool)', W(1) + W(0)],
      ['wc(bool,bool)', W(0) + W(0)],
      ['we(bool,bool)', W(0) + W(1)],
      ['we(bool,bool)', W(1) + W(0)],
      ['wk(bool,bool)', W(0) + W(1)],
      ['wk(bool,bool)', W(0) + W(0)],
    ] as const);
  });

  it('parity gates: mismatched branch types + storage|memory mixes stay rejected (solc rejects or copy-writes)', async () => {
    const IN2 = `@struct class In { x: u256; y: u256 }`;
    // branch types must unify: Arr<In,2> vs Arr<In,3> / fixed vs dynamic are solc TypeErrors
    // (these were OVER-ACCEPTED before this batch on both the write and read desugars).
    expect(
      rejects(`${IN2} @contract class C { @state A: Arr<In, 2>; @state C3: Arr<In, 3>; @external w(c: bool): u256 { (c ? this.A : this.C3)[0n].y = 9n; return 1n; } }`),
    ).toBe(true);
    expect(
      rejects(`${IN2} @contract class C { @state A: Arr<In, 2>; @state C3: Arr<In, 3>; @external @view r(c: bool): u256 { return (c ? this.A : this.C3)[0n].y; } }`),
    ).toBe(true);
    expect(
      rejects(`${IN2} @contract class C { @state A: Arr<In, 2>; @state D: In[]; @external w(c: bool): u256 { (c ? this.A : this.D)[0n].y = 9n; return 1n; } }`),
    ).toBe(true);
    // storage|memory mix: solc unifies the ternary to a MEMORY COPY - the storage branch's write is
    // lost in the discarded copy, the memory branch's write persists. OR cluster 1 (TERN-LV-MIX struct)
    // now LIFTS this byte-identical via the pointer-headed memArrayExpr path (a memory branch aliases, a
    // storage branch deep-copies), replacing the old deliberate reject (which existed only because the
    // former branch-push lowering would have written storage directly - a miscompile). Verify all three
    // forms (=, +=, ++) byte-identical incl the storage-write-discard witness.
    for (const [jstmt, sstmt] of [
      ['(c ? this.A : m)[0n].y = 9n;', '(c ? A : m)[0].y = 9;'],
      ['(c ? this.A : m)[0n].y += 3n;', '(c ? A : m)[0].y += 3;'],
      ['(c ? this.A : m)[0n].y++;', '(c ? A : m)[0].y++;'],
    ] as const) {
      await run(
        `${IN2} @contract class C { @state A: Arr<In, 2>;
  @external seed(): void { this.A[0n] = In(100n, 200n); this.A[1n] = In(300n, 400n); }
  @external w(c: bool): Arr<u256, 2> { let m: Arr<In, 2> = [In(1n, 2n), In(3n, 4n)]; ${jstmt} return [m[0n].y, this.A[0n].y]; } }`,
        `contract C { struct In { uint256 x; uint256 y; } In[2] A;
  function seed() external { A[0] = In(100, 200); A[1] = In(300, 400); }
  function w(bool c) external returns (uint256[2] memory) { In[2] memory m = [In(1, 2), In(3, 4)]; ${sstmt} return [m[0].y, A[0].y]; } }`,
        [['seed()', ''], ['w(bool)', W(1)], ['w(bool)', W(0)]] as const,
      );
    }
    // calldata|storage mix stays a both-reject (solc TypeError).
    expect(
      rejects(`${IN2} @contract class C { @state A: Arr<In, 2>; @external w(c: bool, p: Arr<In, 2>): u256 { (c ? this.A : p)[0n].y = 9n; return 1n; } }`),
    ).toBe(true);
  });
});
