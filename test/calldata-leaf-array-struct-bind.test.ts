// Lift (over-rejection): binding a WHOLE calldata struct with a LEAF-ARRAY field (string[] / bytes[] /
// T[][], isDynStructLeafArrayField) to a MEMORY local - `let m: S = p` where S has such a field.
// Previously JETH200 (+ JETH074/151/072 cascade) at the localDecl; now a byte-identical calldata->memory
// DEEP COPY. solc's `S memory m = p;` deep-copies every element into fresh memory.
//
// The codec was already fully in place (buildDynStructFromCalldataBase's Edge-F leaf-array branch, the
// same builder the direct-read paths p.a / p.tags[i] / abi.encode(p) use); the ONLY gate was a now-stale
// analyzer reject block on the cdDynStructValue source. Reads of the bound local (m.a, m.tags.length,
// m.tags[i], m.tags whole-field, whole abi.encode(m) / return m) are byte-identical; OOB index Panics
// 0x32; malformed calldata inherits the BIND-context flavor (huge inner/outer length -> Panic 0x41 via
// solc's allocation guard; truncated / OOB offset -> empty revert). Storage-source copy `let m: S = this.st`
// and memory-source alias `let m2: S = m` are also byte-identical.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const w = (n: bigint | number | string) => BigInt(n).toString(16).padStart(64, '0');

function encStr(str: string): string {
  const b = Buffer.from(str, 'utf8');
  const len = b.length;
  const padded = Math.ceil(len / 32) * 32;
  return w(len) + Buffer.concat([b, Buffer.alloc(padded - len)]).toString('hex');
}
function encStrArr(arr: string[]): string {
  const n = arr.length;
  const eh = arr.map(encStr);
  const offs: number[] = [];
  let base = n * 32;
  for (let i = 0; i < n; i++) {
    offs.push(base);
    base += eh[i]!.length / 2;
  }
  return w(n) + offs.map((o) => w(o)).join('') + eh.join('');
}
function encU256Arr(a: number[]): string {
  return w(a.length) + a.map((x) => w(x)).join('');
}
function encGrid(rows: number[][]): string {
  const n = rows.length;
  const eh = rows.map(encU256Arr);
  const offs: number[] = [];
  let base = n * 32;
  for (let i = 0; i < n; i++) {
    offs.push(base);
    base += eh[i]!.length / 2;
  }
  return w(n) + offs.map((o) => w(o)).join('') + eh.join('');
}
// S { uint256 a; <leafArray> L } as a single dynamic tuple param: outer offset 0x20, then head [a][off(L)=0x40].
const argStrS = (a: number, arr: string[]) => w(0x20) + w(a) + w(0x40) + encStrArr(arr);
const argGridS = (a: number, rows: number[][]) => w(0x20) + w(a) + w(0x40) + encGrid(rows);

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
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

describe('calldata leaf-array-field struct BIND to a memory local - byte-identical to solc 0.8.35', () => {
  const J = `
@struct class S { a: u256; tags: string[] }
@contract class C {
  @external @pure fa(p: S): u256 { let m: S = p; return m.a; }
  @external @pure flen(p: S): u256 { let m: S = p; return m.tags.length; }
  @external @pure fget(p: S, i: u256): string { let m: S = p; return m.tags[i]; }
  @external @pure fenc(p: S): bytes { let m: S = p; return abi.encode(m); }
  @external @pure fwhole(p: S): S { let m: S = p; return m; }
  @external @pure ffield(p: S): string[] { let m: S = p; return m.tags; }
}`;
  const S = `
struct S { uint256 a; string[] tags; }
contract C {
  function fa(S calldata p) external pure returns (uint256) { S memory m = p; return m.a; }
  function flen(S calldata p) external pure returns (uint256) { S memory m = p; return m.tags.length; }
  function fget(S calldata p, uint256 i) external pure returns (string memory) { S memory m = p; return m.tags[i]; }
  function fenc(S calldata p) external pure returns (bytes memory) { S memory m = p; return abi.encode(m); }
  function fwhole(S calldata p) external pure returns (S memory) { S memory m = p; return m; }
  function ffield(S calldata p) external pure returns (string[] memory) { S memory m = p; return m.tags; }
}`;
  // For fget/fa the leaf-array tuple is param 0 and i is param 1; both encoded with the outer offset.
  const argFget = (a: number, arr: string[], i: number) =>
    w(0x40) + w(i) + w(a) + w(0x40) + encStrArr(arr);

  it('primary: let m: S = p compiles (was JETH200)', () => {
    expect(codes(J)).toEqual([]);
  });

  it('m.a / m.tags.length / abi.encode(m) / return m / m.tags whole-field - empty, one, several, long', async () => {
    for (const arr of [[], ['hi'], ['a', 'bb', 'ccc'], ['short', 'x'.repeat(40), 'y'.repeat(64)]]) {
      const args = argStrS(7, arr);
      await eqCalls(J, S, [
        ['fa(S)', args],
        ['flen(S)', args],
        ['fenc(S)', args],
        ['fwhole(S)', args],
        ['ffield(S)', args],
      ]);
    }
  });

  it('m.tags[i] real values (non-vacuity) + OOB Panic 0x32', async () => {
    const arr = ['alpha', 'betabetabetabetabetabeta_over31', 'gamma'];
    await eqCalls(J, S, [
      ['fget(S,uint256)', argFget(3, arr, 0)],
      ['fget(S,uint256)', argFget(3, arr, 1)],
      ['fget(S,uint256)', argFget(3, arr, 2)],
      ['fget(S,uint256)', argFget(3, arr, 3)], // OOB -> Panic 0x32
      ['fget(S,uint256)', argFget(3, arr, 99)], // OOB -> Panic 0x32
    ]);
  });

  it('malformed calldata: BIND-context flavor (Panic 0x41 vs empty revert) matches solc', async () => {
    const good = argStrS(7, ['hi', 'yo']);
    const hugeCount = w(0x20) + w(7) + w(0x40) + w('0x1000000000000000') + w(0) + w(0);
    const hugeInner = w(0x20) + w(7) + w(0x40) + w(1) + w(0x20) + w('0x1000000000000000');
    const truncated = w(0x20) + w(7) + w(0x40) + w(3) + w(0x60) + w(0x80) + w(0xa0);
    const oobOff = w(0x20) + w(7) + w('0xffffffffffffffffffffffffffffffff');
    const innerOob = w(0x20) + w(7) + w(0x40) + w(1) + w('0xffffffffffffffff');
    const pOff = w('0xffffffffffffffffffffffffffffffff');
    const calls: [string, string][] = [];
    for (const args of [good, hugeCount, hugeInner, truncated, oobOff, innerOob, pOff]) {
      calls.push(['fa(S)', args], ['fenc(S)', args]);
    }
    await eqCalls(J, S, calls);
  });

  it('bytes[] leaf', async () => {
    const Jb = `
@struct class S { a: u256; blobs: bytes[] }
@contract class C {
  @external @pure f(p: S): bytes { let m: S = p; return m.blobs[0n]; }
  @external @pure fe(p: S): bytes { let m: S = p; return abi.encode(m); }
  @external @pure fl(p: S): u256 { let m: S = p; return m.blobs.length; }
}`;
    const Sb = `
struct S { uint256 a; bytes[] blobs; }
contract C {
  function f(S calldata p) external pure returns (bytes memory) { S memory m = p; return m.blobs[0]; }
  function fe(S calldata p) external pure returns (bytes memory) { S memory m = p; return abi.encode(m); }
  function fl(S calldata p) external pure returns (uint256) { S memory m = p; return m.blobs.length; }
}`;
    const args = argStrS(5, ['xy', 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz_over31']);
    await eqCalls(Jb, Sb, [['f(S)', args], ['fe(S)', args], ['fl(S)', args]]);
  });

  it('u256[][] leaf', async () => {
    const Ju = `
@struct class S { a: u256; grid: u256[][] }
@contract class C {
  @external @pure f(p: S): u256 { let m: S = p; return m.grid[1n][0n]; }
  @external @pure fe(p: S): bytes { let m: S = p; return abi.encode(m); }
  @external @pure fl(p: S): u256 { let m: S = p; return m.grid.length; }
}`;
    const Su = `
struct S { uint256 a; uint256[][] grid; }
contract C {
  function f(S calldata p) external pure returns (uint256) { S memory m = p; return m.grid[1][0]; }
  function fe(S calldata p) external pure returns (bytes memory) { S memory m = p; return abi.encode(m); }
  function fl(S calldata p) external pure returns (uint256) { S memory m = p; return m.grid.length; }
}`;
    const args = argGridS(3, [[1, 2, 3], [7, 8]]);
    await eqCalls(Ju, Su, [['f(S)', args], ['fe(S)', args], ['fl(S)', args]]);
  });

  it('mixed fields: a; s:string; tags:string[]; xs:u256[]', async () => {
    const Jm = `
@struct class S { a: u256; s: string; tags: string[]; xs: u256[] }
@contract class C {
  @external @pure fe(p: S): bytes { let m: S = p; return abi.encode(m); }
  @external @pure fs(p: S): string { let m: S = p; return m.s; }
  @external @pure ft(p: S): string { let m: S = p; return m.tags[0n]; }
  @external @pure fx(p: S): u256 { let m: S = p; return m.xs[1n]; }
}`;
    const Sm = `
struct S { uint256 a; string s; string[] tags; uint256[] xs; }
contract C {
  function fe(S calldata p) external pure returns (bytes memory) { S memory m = p; return abi.encode(m); }
  function fs(S calldata p) external pure returns (string memory) { S memory m = p; return m.s; }
  function ft(S calldata p) external pure returns (string memory) { S memory m = p; return m.tags[0]; }
  function fx(S calldata p) external pure returns (uint256) { S memory m = p; return m.xs[1]; }
}`;
    // head: a, off(s), off(tags), off(xs) = 4 words
    const sBody = encStr('hello world this is long enough to span two words');
    const tBody = encStrArr(['t1', 't2t2']);
    const xBody = encU256Arr([100, 200, 300]);
    let base = 4 * 32;
    const offS = base;
    base += sBody.length / 2;
    const offT = base;
    base += tBody.length / 2;
    const offX = base;
    const image = w(11) + w(offS) + w(offT) + w(offX) + sBody + tBody + xBody;
    const args = w(0x20) + image;
    await eqCalls(Jm, Sm, [['fe(S)', args], ['fs(S)', args], ['ft(S)', args], ['fx(S)', args]]);
  });

  it('memory-source alias: let m2: S = m', async () => {
    const Ja = `
@struct class S { a: u256; tags: string[] }
@contract class C {
  @external @pure f(p: S): bytes { let m: S = p; let m2: S = m; return abi.encode(m2); }
  @external @pure fg(p: S): string { let m: S = p; let m2: S = m; return m2.tags[1n]; }
}`;
    const Sa = `
struct S { uint256 a; string[] tags; }
contract C {
  function f(S calldata p) external pure returns (bytes memory) { S memory m = p; S memory m2 = m; return abi.encode(m2); }
  function fg(S calldata p) external pure returns (string memory) { S memory m = p; S memory m2 = m; return m2.tags[1]; }
}`;
    const args = argStrS(7, ['aa', 'bbbb', 'cccccc']);
    await eqCalls(Ja, Sa, [['f(S)', args], ['fg(S)', args]]);
  });

  it('storage-source copy: let m: S = this.st (deep copy) + readback + OOB', async () => {
    const Jb = `
@struct class S { a: u256; tags: string[] }
@contract class C {
  @state st: S;
  @external set(p: S): void { this.st = p; }
  @external @view getA(): u256 { let m: S = this.st; return m.a; }
  @external @view getT(idx: u256): string { let m: S = this.st; return m.tags[idx]; }
  @external @view getLen(): u256 { let m: S = this.st; return m.tags.length; }
  @external @view getEnc(): bytes { let m: S = this.st; return abi.encode(m); }
}`;
    const Sb = `
struct S { uint256 a; string[] tags; }
contract C {
  S st;
  function set(S calldata p) external { st = p; }
  function getA() external view returns (uint256) { S memory m = st; return m.a; }
  function getT(uint256 idx) external view returns (string memory) { S memory m = st; return m.tags[idx]; }
  function getLen() external view returns (uint256) { S memory m = st; return m.tags.length; }
  function getEnc() external view returns (bytes memory) { S memory m = st; return abi.encode(m); }
}`;
    const args = argStrS(7, ['aa', 'bbbb', 'cccccc']);
    await eqCalls(Jb, Sb, [
      ['set(S)', args],
      ['getA()', ''],
      ['getLen()', ''],
      ['getT(uint256)', w(0)],
      ['getT(uint256)', w(2)],
      ['getEnc()', ''],
      ['getT(uint256)', w(9)], // OOB Panic 0x32
    ]);
  });

  it('internal-arg pass of the bound leaf-array struct', async () => {
    const Ji = `
@struct class S { a: u256; tags: string[] }
@contract class C {
  @pure sumLen(m: S): u256 { return m.a + m.tags.length; }
  @pure firstTag(m: S): string { return m.tags[0n]; }
  @external @pure viaInternal(p: S): u256 { let m: S = p; return sumLen(m); }
  @external @pure viaInternal2(p: S): string { let m: S = p; return firstTag(m); }
}`;
    const Si = `
struct S { uint256 a; string[] tags; }
contract C {
  function sumLen(S memory m) internal pure returns (uint256) { return m.a + m.tags.length; }
  function firstTag(S memory m) internal pure returns (string memory) { return m.tags[0]; }
  function viaInternal(S calldata p) external pure returns (uint256) { S memory m = p; return sumLen(m); }
  function viaInternal2(S calldata p) external pure returns (string memory) { S memory m = p; return firstTag(m); }
}`;
    const args = argStrS(7, ['aa', 'bbbb', 'cccccc']);
    await eqCalls(Ji, Si, [['viaInternal(S)', args], ['viaInternal2(S)', args]]);
  });

  it('storage write of the bound local: this.st = m + readback', async () => {
    const Jw = `
@struct class S { a: u256; tags: string[] }
@contract class C {
  @state st: S;
  @external store(p: S): void { let m: S = p; this.st = m; }
  @external @view rd(idx: u256): string { let m: S = this.st; return m.tags[idx]; }
  @external @view ra(): u256 { let m: S = this.st; return m.a; }
}`;
    const Sw = `
struct S { uint256 a; string[] tags; }
contract C {
  S st;
  function store(S calldata p) external { S memory m = p; st = m; }
  function rd(uint256 idx) external view returns (string memory) { S memory m = st; return m.tags[idx]; }
  function ra() external view returns (uint256) { S memory m = st; return m.a; }
}`;
    const args = argStrS(42, ['one', 'twotwotwo', 'threethreethreethreethreethree_over31']);
    await eqCalls(Jw, Sw, [
      ['store(S)', args],
      ['ra()', ''],
      ['rd(uint256)', w(0)],
      ['rd(uint256)', w(1)],
      ['rd(uint256)', w(2)],
    ]);
  });

  it('REGRESSION: value-array (u256[]) field bind unregressed', async () => {
    const Jv = `
@struct class S { a: u256; xs: u256[] }
@contract class C {
  @external @pure f(p: S): u256 { let m: S = p; return m.xs[1n]; }
  @external @pure fe(p: S): bytes { let m: S = p; return abi.encode(m); }
}`;
    const Sv = `
struct S { uint256 a; uint256[] xs; }
contract C {
  function f(S calldata p) external pure returns (uint256) { S memory m = p; return m.xs[1]; }
  function fe(S calldata p) external pure returns (bytes memory) { S memory m = p; return abi.encode(m); }
}`;
    const args = w(0x20) + w(9) + w(0x40) + encU256Arr([11, 22, 33]);
    await eqCalls(Jv, Sv, [['f(S)', args], ['fe(S)', args]]);
  });

  it('REGRESSION: direct calldata-param reads (no bind) unregressed', async () => {
    const Jd = `
@struct class S { a: u256; tags: string[] }
@contract class C {
  @external @pure da(p: S): u256 { return p.a; }
  @external @pure dl(p: S): u256 { return p.tags.length; }
  @external @pure dg(p: S): string { return p.tags[0n]; }
  @external @pure de(p: S): bytes { return abi.encode(p); }
}`;
    const Sd = `
struct S { uint256 a; string[] tags; }
contract C {
  function da(S calldata p) external pure returns (uint256) { return p.a; }
  function dl(S calldata p) external pure returns (uint256) { return p.tags.length; }
  function dg(S calldata p) external pure returns (string memory) { return p.tags[0]; }
  function de(S calldata p) external pure returns (bytes memory) { return abi.encode(p); }
}`;
    const args = argStrS(7, ['hi', 'world!!']);
    await eqCalls(Jd, Sd, [['da(S)', args], ['dl(S)', args], ['dg(S)', args], ['de(S)', args]]);
  });

  it('REGRESSION: a DynStruct[] struct-element-array field still a clean JETH200 reject (not lifted)', () => {
    // isSupportedDynStructLocal excludes a struct-element array field, so the whole-struct bind stays rejected.
    const Jbad = `
@struct class Q { x: u256; s: string }
@struct class S { a: u256; qs: Q[] }
@contract class C {
  @external @pure f(p: S): u256 { let m: S = p; return m.a; }
}`;
    expect(codes(Jbad)).toContain('JETH200');
  });
});
