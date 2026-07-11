// W5A (store-at-depth + nested-chain lifts), byte-identical to solc 0.8.35:
//  (1) whole-array store by INDEX-at-depth: `this.g3[i] = a` / `this.g3.push(a)` on Arr<T,N>[] state
//      arrays (string/bytes/u256/nested leaves; memory-local, literal, calldata-adjacent and storage
//      sources), previously JETH900. The element slot is keccak(base)+i*elemSlots; the store routes
//      through the SAME whole-array codecs (storeDynLeafFixedArrayFromMem / storeStaticAggFromMem),
//      overwrite-clearing each element's old tail (long->short verified by readback).
//  (2) fixed-array element through a nested-dyn-struct chain: `v.t.inner.fa[j]` read AND write
//      (const + runtime index, OOB Panic 0x32 / compile-time JETH211), previously JETH151.
//  (3) whole nested static-struct field read: `return v.t.inner`, `let w = v.t.inner` (an ALIAS,
//      like solc memory references), passing as an internal arg - previously JETH074.
// RHS-first order: a side-effecting/reverting array-literal RHS is materialized BEFORE the target's
// index bounds-check (revert data matches solc; was a latent both-revert-different-data divergence).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => n.toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const encStr = (s: string) => {
  const b = Buffer.from(s, 'utf8');
  return W(BigInt(b.length)) + (b.length ? b.toString('hex').padEnd(Math.ceil(b.length / 32) * 64, '0') : '');
};

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig}(${args.slice(0, 32)}) success`).toBe(rs.success);
    expect(rj.returnHex, `${sig}(${args.slice(0, 32)}) return`).toBe(rs.returnHex);
  }
}

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};

describe('W5A(1): whole fixed-array element store at depth (this.g3[i] = a / push(a))', () => {
  it('Arr<string,2>[] setAt/push from a memory local; long->short overwrite-clear; OOB Panic; pop', async () => {
    const LONG = 'a-string-definitely-longer-than-thirty-two-bytes-for-sure-1234567890';
    const setAt = (i: bigint, x: string, y: string) => {
      const hx = encStr(x);
      return W(i) + W(0x60n) + W(0x60n + BigInt(hx.length / 2)) + hx + encStr(y);
    };
    await eqCalls(
      `class C {
  g3: Arr<string,2>[];
  push0(): External<void> { this.g3.push(); }
  pushA(x: string, y: string): External<void> { let a: Arr<string,2> = [x, y]; this.g3.push(a); }
  setAt(i: u256, x: string, y: string): External<void> { let a: Arr<string,2> = [x, y]; this.g3[i] = a; }
  pop(): External<void> { this.g3.pop(); }
  get get(i: u256, j: u256): External<string> { return this.g3[i][j]; }
  get len(): External<u256> { return this.g3.length; }
}`,
      `contract C {
  string[2][] g3;
  function push0() external { g3.push(); }
  function pushA(string memory x, string memory y) external { string[2] memory a = [x, y]; g3.push(a); }
  function setAt(uint256 i, string memory x, string memory y) external { string[2] memory a = [x, y]; g3[i] = a; }
  function pop() external { g3.pop(); }
  function get(uint256 i, uint256 j) external view returns (string memory) { return g3[i][j]; }
  function len() external view returns (uint256) { return g3.length; }
}`,
      [
        ['push0()', ''],
        ['pushA(string,string)', W(0x40n) + W(0x40n + BigInt(encStr('hello').length / 2)) + encStr('hello') + encStr(LONG)],
        ['setAt(uint256,string,string)', setAt(0n, LONG, 'short')],
        ['get(uint256,uint256)', W(0n) + W(0n)],
        ['get(uint256,uint256)', W(0n) + W(1n)],
        ['setAt(uint256,string,string)', setAt(0n, '', 'x')], // long->short clears the old tail
        ['get(uint256,uint256)', W(0n) + W(0n)],
        ['get(uint256,uint256)', W(1n) + W(1n)],
        ['setAt(uint256,string,string)', setAt(5n, 'a', 'b')], // OOB -> Panic 0x32 both
        ['pop()', ''],
        ['len()', ''],
        ['get(uint256,uint256)', W(1n) + W(0n)], // now OOB
      ],
    );
  });

  it('Arr<u256,3>[] setAt/push (static leaf via storeStaticAggFromMem) and literal RHS-first order', async () => {
    await eqCalls(
      `class C {
  g3: Arr<u256,3>[];
  boom(): u256 { require(false, "BOOM"); return 1n; }
  push0(): External<void> { this.g3.push(); }
  setAt(i: u256, v: u256): External<void> { let a: Arr<u256,3> = [v, 0n, v * 2n]; this.g3[i] = a; }
  setLit(i: u256): External<void> { this.g3[i] = [this.boom(), 1n, 2n]; }
  get get(i: u256, j: u256): External<u256> { return this.g3[i][j]; }
}`,
      `contract C {
  uint256[3][] g3;
  function boom() internal pure returns (uint256) { require(false, "BOOM"); return 1; }
  function push0() external { g3.push(); }
  function setAt(uint256 i, uint256 v) external { uint256[3] memory a = [v, 0, v * 2]; g3[i] = a; }
  function setLit(uint256 i) external { g3[i] = [boom(), 1, 2]; }
  function get(uint256 i, uint256 j) external view returns (uint256) { return g3[i][j]; }
}`,
      [
        ['push0()', ''],
        ['setAt(uint256,uint256)', W(0n) + W(9n)],
        ['get(uint256,uint256)', W(0n) + W(2n)],
        // RHS-first: the reverting literal element runs BEFORE the OOB bounds-check, so the revert
        // data is require's "BOOM" (not Panic 0x32) - byte-identical to solc.
        ['setLit(uint256)', W(7n)],
        ['setAt(uint256,uint256)', W(3n) + W(1n)], // pure OOB -> Panic 0x32
      ],
    );
  });

  it('struct-array element field (this.vals[i].xs = xs) and mapping analogues', async () => {
    const setAt = (i: bigint, x: string, y: string) => {
      const hx = encStr(x);
      return W(i) + W(0x60n) + W(0x60n + BigInt(hx.length / 2)) + hx + encStr(y);
    };
    await eqCalls(
      `type D = { n: u256; xs: Arr<string,2> };
class C {
  vals: D[];
  m: mapping<u256, Arr<string,2>>;
  push0(): External<void> { this.vals.push(); }
  setXs(i: u256, x: string, y: string): External<void> { let xs: Arr<string,2> = [x, y]; this.vals[i].xs = xs; }
  get getXs(i: u256, j: u256): External<string> { return this.vals[i].xs[j]; }
  setM(k: u256, x: string, y: string): External<void> { let a: Arr<string,2> = [x, y]; this.m[k] = a; }
  get getM(k: u256, j: u256): External<string> { return this.m[k][j]; }
}`,
      `struct D { uint256 n; string[2] xs; }
contract C {
  D[] vals;
  mapping(uint256 => string[2]) m;
  function push0() external { vals.push(); }
  function setXs(uint256 i, string memory x, string memory y) external { string[2] memory xs = [x, y]; vals[i].xs = xs; }
  function getXs(uint256 i, uint256 j) external view returns (string memory) { return vals[i].xs[j]; }
  function setM(uint256 k, string memory x, string memory y) external { string[2] memory a = [x, y]; m[k] = a; }
  function getM(uint256 k, uint256 j) external view returns (string memory) { return m[k][j]; }
}`,
      [
        ['push0()', ''],
        ['setXs(uint256,string,string)', setAt(0n, 'long-enough-to-need-a-second-data-slot-yes!!', 'q')],
        ['getXs(uint256,uint256)', W(0n) + W(0n)],
        ['setXs(uint256,string,string)', setAt(0n, '', '')],
        ['getXs(uint256,uint256)', W(0n) + W(0n)],
        ['setM(uint256,string,string)', setAt(9n, 'mapval', 'w')],
        ['getM(uint256,uint256)', W(9n) + W(0n)],
        ['getM(uint256,uint256)', W(9n) + W(1n)],
      ],
    );
  });
});

describe('W5A(2): fixed-array element through a nested-dyn-struct chain (v.t.inner.fa[j])', () => {
  const J3 = `type I = { fa: Arr<u256,3>; m: u256 };
type T = { s: string; inner: I };
type S = { a: u256; t: T };
`;
  const S3 = `struct I { uint256[3] fa; uint256 m; }
struct T { string s; I inner; }
struct S { uint256 a; T t; }
`;

  it('read + write, const and runtime index, compound forms, runtime OOB Panic 0x32', async () => {
    await eqCalls(
      J3 +
        `class C {
  get go(j: u256): External<u256> {
    let v: S = S(1n, T("hi", I([10n,20n,30n], 4n)));
    v.t.inner.fa[j] = 99n;
    v.t.inner.fa[1n] += 5n;
    v.t.inner.fa[2n]++;
    return v.t.inner.fa[0n] + v.t.inner.fa[1n] + v.t.inner.fa[2n] + v.t.inner.m;
  }
}`,
      S3 +
        `contract C {
  function go(uint256 j) external pure returns (uint256) {
    S memory v = S(1, T("hi", I([uint256(10),20,30], 4)));
    v.t.inner.fa[j] = 99;
    v.t.inner.fa[1] += 5;
    v.t.inner.fa[2]++;
    return v.t.inner.fa[0] + v.t.inner.fa[1] + v.t.inner.fa[2] + v.t.inner.m;
  }
}`,
      [['go(uint256)', W(0n)], ['go(uint256)', W(2n)], ['go(uint256)', W(3n)]],
    );
  });

  it('struct-element array with a field hop after the index (v.t.inner.qs[j].y)', async () => {
    await eqCalls(
      `type Q = { x: u256; y: u256 };
type I = { qs: Arr<Q,2>; m: u256 };
type T = { s: string; inner: I };
type S = { a: u256; t: T };
class C {
  get go(j: u256): External<u256> {
    let v: S = S(1n, T("hi", I([Q(1n,2n), Q(3n,4n)], 9n)));
    v.t.inner.qs[j].y = 42n;
    return v.t.inner.qs[0n].x + v.t.inner.qs[1n].x + v.t.inner.qs[0n].y + v.t.inner.qs[1n].y;
  }
}`,
      `struct Q { uint256 x; uint256 y; }
struct I { Q[2] qs; uint256 m; }
struct T { string s; I inner; }
struct S { uint256 a; T t; }
contract C {
  function go(uint256 j) external pure returns (uint256) {
    S memory v = S(1, T("hi", I([Q(1,2), Q(3,4)], 9)));
    v.t.inner.qs[j].y = 42;
    return v.t.inner.qs[0].x + v.t.inner.qs[1].x + v.t.inner.qs[0].y + v.t.inner.qs[1].y;
  }
}`,
      [['go(uint256)', W(0n)], ['go(uint256)', W(1n)], ['go(uint256)', W(2n)]],
    );
  });

  it('const OOB index stays a compile-time reject (JETH211, solc TypeError)', () => {
    expect(
      codes(
        J3 +
          `class C { get go(): External<u256> { let v: S = S(1n, T("h", I([1n,2n,3n], 4n))); return v.t.inner.fa[3n]; } }`,
      ),
    ).toContain('JETH211');
  });
});

describe('W5A(3): whole nested static-struct field read (return / let-alias / internal arg)', () => {
  const J = `type I = { x: u256; y: u256 };
type T = { s: string; inner: I };
type S = { a: u256; t: T };
`;
  const SS = `struct I { uint256 x; uint256 y; }
struct T { string s; I inner; }
struct S { uint256 a; T t; }
`;

  it('return + abi.encode + let-ALIAS (write-through both directions) + internal-arg mutation', async () => {
    await eqCalls(
      J +
        `class C {
  bump(w: I): u256 { w.x += 100n; return w.x + w.y; }
  get ret(): External<I> { let v: S = S(1n, T("hi", I(7n, 8n))); return v.t.inner; }
  get enc(): External<bytes> { let v: S = S(1n, T("hi", I(7n, 8n))); return abi.encode(v.t.inner); }
  get lb(): External<u256> { let v: S = S(1n, T("hi", I(7n, 8n))); let w: I = v.t.inner; w.y = 50n; v.t.inner.x = 3n; return w.x + v.t.inner.y; }
  get arg(): External<u256> { let v: S = S(1n, T("hi", I(7n, 8n))); let r: u256 = this.bump(v.t.inner); return r + v.t.inner.x; }
}`,
      SS +
        `contract C {
  function bump(I memory w) internal pure returns (uint256) { w.x += 100; return w.x + w.y; }
  function ret() external pure returns (I memory) { S memory v = S(1, T("hi", I(7, 8))); return v.t.inner; }
  function enc() external pure returns (bytes memory) { S memory v = S(1, T("hi", I(7, 8))); return abi.encode(v.t.inner); }
  function lb() external pure returns (uint256) { S memory v = S(1, T("hi", I(7, 8))); I memory w = v.t.inner; w.y = 50; v.t.inner.x = 3; return w.x + v.t.inner.y; }
  function arg() external pure returns (uint256) { S memory v = S(1, T("hi", I(7, 8))); uint256 r = bump(v.t.inner); return r + v.t.inner.x; }
}`,
      [['ret()', ''], ['enc()', ''], ['lb()', ''], ['arg()', '']],
    );
  });

  it('packed fields + deeper chains (v.t.u.inner, v.t.u.inner.q) and a whole static fixed-array field', async () => {
    await eqCalls(
      `type Q = { m: u256; n: u256 };
type I = { p: u8; q: Q; fa: Arr<u256,2> };
type U = { z: string; inner: I };
type T = { s: string; u: U };
type S = { a: u256; t: T };
class C {
  get gq(): External<Q> { let v: S = S(1n, T("a", U("b", I(5n, Q(6n, 7n), [8n, 9n])))); return v.t.u.inner.q; }
  get gi(): External<I> { let v: S = S(1n, T("a", U("b", I(5n, Q(6n, 7n), [8n, 9n])))); return v.t.u.inner; }
  get gf(): External<Arr<u256,2>> { let v: S = S(1n, T("a", U("b", I(5n, Q(6n, 7n), [8n, 9n])))); return v.t.u.inner.fa; }
}`,
      `struct Q { uint256 m; uint256 n; }
struct I { uint8 p; Q q; uint256[2] fa; }
struct U { string z; I inner; }
struct T { string s; U u; }
struct S { uint256 a; T t; }
contract C {
  function gq() external pure returns (Q memory) { S memory v = S(1, T("a", U("b", I(5, Q(6, 7), [uint256(8), 9])))); return v.t.u.inner.q; }
  function gi() external pure returns (I memory) { S memory v = S(1, T("a", U("b", I(5, Q(6, 7), [uint256(8), 9])))); return v.t.u.inner; }
  function gf() external pure returns (uint256[2] memory) { S memory v = S(1, T("a", U("b", I(5, Q(6, 7), [uint256(8), 9])))); return v.t.u.inner.fa; }
}`,
      [['gq()', ''], ['gi()', ''], ['gf()', '']],
    );
  });

  it('adjacent shapes stay CLEAN rejects (no half-accept): storage store / emit / whole member write', () => {
    const store = codes(
      J + `class C { st: I; put(): External<void> { let v: S = S(1n, T("hi", I(7n, 8n))); this.st = v.t.inner; } }`,
    );
    expect(store.length).toBeGreaterThan(0); // JETH900 clean reject (solc accepts; a later lift)
    const emit = codes(
      J + `class C { Ev: event<{ i: I }>; go(): External<void> { let v: S = S(1n, T("hi", I(7n, 8n))); emit this.Ev(v.t.inner); } }`,
    );
    expect(emit.length).toBeGreaterThan(0);
    // whole nested member WRITE would deep-copy where solc re-points (aliasing would diverge) - JETH429.
    const write = codes(
      J + `class C { get go(): External<u256> { let v: S = S(1n, T("hi", I(7n, 8n))); v.t.inner = I(9n, 10n); return v.t.inner.x; } }`,
    );
    expect(write).toContain('JETH429');
  });

  it('Edge B unregressed: whole nested DYN struct field return / alias / v.t', async () => {
    await eqCalls(
      `type U = { q: string; n: u256 };
type T = { s: string; u: U };
type S = { a: u256; t: T };
class C {
  get ret(): External<U> { let v: S = S(1n, T("x", U("hello", 7n))); return v.t.u; }
  get lb(): External<u256> { let v: S = S(1n, T("x", U("hello", 7n))); let w: U = v.t.u; w.n = 9n; return v.t.u.n; }
  get retT(): External<T> { let v: S = S(1n, T("x", U("hello", 7n))); return v.t; }
}`,
      `struct U { string q; uint256 n; }
struct T { string s; U u; }
struct S { uint256 a; T t; }
contract C {
  function ret() external pure returns (U memory) { S memory v = S(1, T("x", U("hello", 7))); return v.t.u; }
  function lb() external pure returns (uint256) { S memory v = S(1, T("x", U("hello", 7))); U memory w = v.t.u; w.n = 9; return v.t.u.n; }
  function retT() external pure returns (T memory) { S memory v = S(1, T("x", U("hello", 7))); return v.t; }
}`,
      [['ret()', ''], ['lb()', ''], ['retT()', '']],
    );
  });
});
