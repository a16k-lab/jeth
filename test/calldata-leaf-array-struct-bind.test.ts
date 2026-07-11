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
//
// NON-VACUITY: an external function taking a struct dispatches on the EXPANDED-tuple selector
// (fa((uint256,string[])), NOT fa(S)). Every differential call below uses the canonical expanded
// signature so it hits the real dispatcher; the guarded tests assert concrete decoded return values, so
// a selector miss (which would revert-empty) fails loudly instead of passing as a vacuous both-revert.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const w = (n: bigint | number | string) => BigInt(n).toString(16).padStart(64, '0');
// left-align raw bytes into a 32-byte word (for decoding short-string returndata content)
const asciiWord = (str: string) => Buffer.concat([Buffer.from(str, 'utf8'), Buffer.alloc(32)]).subarray(0, 32).toString('hex');

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

// Run each call on both, asserting success + returndata parity; RETURN jeth returndata for non-vacuity checks.
async function eqCalls(jeth: string, sol: string, calls: [string, string][]): Promise<{ success: boolean; returnHex: string }[]> {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  const out: { success: boolean; returnHex: string }[] = [];
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
    out.push({ success: rj.success, returnHex: rj.returnHex });
  }
  return out;
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
  const P = '(uint256,string[])'; // canonical tuple of S { uint256 a; string[] tags }
  const J = `
type S = { a: u256; tags: string[] };
class C {
  get fa(p: S): External<u256> { let m: S = p; return m.a; }
  get flen(p: S): External<u256> { let m: S = p; return m.tags.length; }
  get fget(p: S, i: u256): External<string> { let m: S = p; return m.tags[i]; }
  get fenc(p: S): External<bytes> { let m: S = p; return abi.encode(m); }
  get fwhole(p: S): External<S> { let m: S = p; return m; }
  get ffield(p: S): External<string[]> { let m: S = p; return m.tags; }
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
  // For fget the leaf-array tuple is param 0 and i is param 1; both encoded with the outer offset.
  const argFget = (a: number, arr: string[], i: number) =>
    w(0x40) + w(i) + w(a) + w(0x40) + encStrArr(arr);

  it('primary: let m: S = p compiles (was JETH200)', () => {
    expect(codes(J)).toEqual([]);
  });

  it('m.a / m.tags.length / abi.encode(m) / return m / m.tags whole-field - empty, one, several, long', async () => {
    // non-vacuity anchor: fa must return the real a value (7), not a revert.
    const anchor = await eqCalls(J, S, [[`fa(${P})`, argStrS(7, ['hi'])]]);
    expect(anchor[0]!.success).toBe(true);
    expect(anchor[0]!.returnHex).toBe('0x' + w(7));
    for (const arr of [[], ['hi'], ['a', 'bb', 'ccc'], ['short', 'x'.repeat(40), 'y'.repeat(64)]]) {
      const args = argStrS(7, arr);
      await eqCalls(J, S, [
        [`fa(${P})`, args],
        [`flen(${P})`, args],
        [`fenc(${P})`, args],
        [`fwhole(${P})`, args],
        [`ffield(${P})`, args],
      ]);
    }
  });

  it('m.tags[i] real values (non-vacuity) + OOB Panic 0x32', async () => {
    const arr = ['alpha', 'betabetabetabetabetabeta_over31', 'gamma'];
    const r = await eqCalls(J, S, [
      [`fget(${P},uint256)`, argFget(3, arr, 0)],
      [`fget(${P},uint256)`, argFget(3, arr, 1)],
      [`fget(${P},uint256)`, argFget(3, arr, 2)],
      [`fget(${P},uint256)`, argFget(3, arr, 3)], // OOB -> Panic 0x32
      [`fget(${P},uint256)`, argFget(3, arr, 99)], // OOB -> Panic 0x32
    ]);
    // non-vacuity: index 0 returns the string "alpha" (offset 0x20, len 5, "alpha" left-aligned); OOB reverts.
    expect(r[0]!.success).toBe(true);
    expect(r[0]!.returnHex).toBe('0x' + w(0x20) + w(5) + asciiWord('alpha'));
    expect(r[3]!.success).toBe(false); // OOB Panic 0x32
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
      calls.push([`fa(${P})`, args], [`fenc(${P})`, args]);
    }
    const r = await eqCalls(J, S, calls);
    expect(r[0]!.success).toBe(true); // non-vacuity: the good input actually decodes
    expect(r.slice(2).some((x) => !x.success)).toBe(true); // the malformed inputs actually revert
  });

  it('bytes[] leaf', async () => {
    const Pb = '(uint256,bytes[])';
    const Jb = `
type S = { a: u256; blobs: bytes[] };
class C {
  get f(p: S): External<bytes> { let m: S = p; return m.blobs[0n]; }
  get fe(p: S): External<bytes> { let m: S = p; return abi.encode(m); }
  get fl(p: S): External<u256> { let m: S = p; return m.blobs.length; }
}`;
    const Sb = `
struct S { uint256 a; bytes[] blobs; }
contract C {
  function f(S calldata p) external pure returns (bytes memory) { S memory m = p; return m.blobs[0]; }
  function fe(S calldata p) external pure returns (bytes memory) { S memory m = p; return abi.encode(m); }
  function fl(S calldata p) external pure returns (uint256) { S memory m = p; return m.blobs.length; }
}`;
    const args = argStrS(5, ['xy', 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz_over31']);
    const r = await eqCalls(Jb, Sb, [[`fl(${Pb})`, args], [`f(${Pb})`, args], [`fe(${Pb})`, args]]);
    expect(r[0]!.returnHex).toBe('0x' + w(2)); // non-vacuity: blobs.length == 2
  });

  it('u256[][] leaf', async () => {
    const Pu = '(uint256,uint256[][])';
    const Ju = `
type S = { a: u256; grid: u256[][] };
class C {
  get f(p: S): External<u256> { let m: S = p; return m.grid[1n][0n]; }
  get fe(p: S): External<bytes> { let m: S = p; return abi.encode(m); }
  get fl(p: S): External<u256> { let m: S = p; return m.grid.length; }
}`;
    const Su = `
struct S { uint256 a; uint256[][] grid; }
contract C {
  function f(S calldata p) external pure returns (uint256) { S memory m = p; return m.grid[1][0]; }
  function fe(S calldata p) external pure returns (bytes memory) { S memory m = p; return abi.encode(m); }
  function fl(S calldata p) external pure returns (uint256) { S memory m = p; return m.grid.length; }
}`;
    const args = argGridS(3, [[1, 2, 3], [7, 8]]);
    const r = await eqCalls(Ju, Su, [[`f(${Pu})`, args], [`fe(${Pu})`, args], [`fl(${Pu})`, args]]);
    expect(r[0]!.returnHex).toBe('0x' + w(7)); // non-vacuity: grid[1][0] == 7
  });

  it('mixed fields: a; s:string; tags:string[]; xs:u256[]', async () => {
    const Pm = '(uint256,string,string[],uint256[])';
    const Jm = `
type S = { a: u256; s: string; tags: string[]; xs: u256[] };
class C {
  get fe(p: S): External<bytes> { let m: S = p; return abi.encode(m); }
  get fs(p: S): External<string> { let m: S = p; return m.s; }
  get ft(p: S): External<string> { let m: S = p; return m.tags[0n]; }
  get fx(p: S): External<u256> { let m: S = p; return m.xs[1n]; }
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
    const r = await eqCalls(Jm, Sm, [[`fx(${Pm})`, args], [`fe(${Pm})`, args], [`fs(${Pm})`, args], [`ft(${Pm})`, args]]);
    expect(r[0]!.returnHex).toBe('0x' + w(200)); // non-vacuity: xs[1] == 200
  });

  it('memory-source alias: let m2: S = m', async () => {
    const Ja = `
type S = { a: u256; tags: string[] };
class C {
  get f(p: S): External<bytes> { let m: S = p; let m2: S = m; return abi.encode(m2); }
  get fg(p: S): External<string> { let m: S = p; let m2: S = m; return m2.tags[1n]; }
}`;
    const Sa = `
struct S { uint256 a; string[] tags; }
contract C {
  function f(S calldata p) external pure returns (bytes memory) { S memory m = p; S memory m2 = m; return abi.encode(m2); }
  function fg(S calldata p) external pure returns (string memory) { S memory m = p; S memory m2 = m; return m2.tags[1]; }
}`;
    const args = argStrS(7, ['aa', 'bbbb', 'cccccc']);
    const r = await eqCalls(Ja, Sa, [[`fg(${P})`, args], [`f(${P})`, args]]);
    expect(r[0]!.returnHex).toBe('0x' + w(0x20) + w(4) + asciiWord('bbbb')); // non-vacuity: m2.tags[1] == "bbbb"
  });

  it('storage-source copy: let m: S = this.st (deep copy) + readback + OOB', async () => {
    const Jb = `
type S = { a: u256; tags: string[] };
class C {
  st: S;
  set(p: S): External<void> { this.st = p; }
  get getA(): External<u256> { let m: S = this.st; return m.a; }
  get getT(idx: u256): External<string> { let m: S = this.st; return m.tags[idx]; }
  get getLen(): External<u256> { let m: S = this.st; return m.tags.length; }
  get getEnc(): External<bytes> { let m: S = this.st; return abi.encode(m); }
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
    const r = await eqCalls(Jb, Sb, [
      [`set(${P})`, args],
      ['getA()', ''],
      ['getLen()', ''],
      ['getT(uint256)', w(0)],
      ['getT(uint256)', w(2)],
      ['getEnc()', ''],
      ['getT(uint256)', w(9)], // OOB Panic 0x32
    ]);
    expect(r[1]!.returnHex).toBe('0x' + w(7)); // non-vacuity: getA() == 7 after set
    expect(r[2]!.returnHex).toBe('0x' + w(3)); // getLen() == 3
    expect(r[6]!.success).toBe(false); // OOB reverts
  });

  it('internal-arg pass of the bound leaf-array struct', async () => {
    const Ji = `
type S = { a: u256; tags: string[] };
class C {
  sumLen(m: S): u256 { return m.a + m.tags.length; }
  firstTag(m: S): string { return m.tags[0n]; }
  get viaInternal(p: S): External<u256> { let m: S = p; return sumLen(m); }
  get viaInternal2(p: S): External<string> { let m: S = p; return firstTag(m); }
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
    const r = await eqCalls(Ji, Si, [[`viaInternal(${P})`, args], [`viaInternal2(${P})`, args]]);
    expect(r[0]!.returnHex).toBe('0x' + w(10)); // non-vacuity: a(7) + tags.length(3) == 10
  });

  it('storage write of the bound local: this.st = m + readback', async () => {
    const Jw = `
type S = { a: u256; tags: string[] };
class C {
  st: S;
  store(p: S): External<void> { let m: S = p; this.st = m; }
  get rd(idx: u256): External<string> { let m: S = this.st; return m.tags[idx]; }
  get ra(): External<u256> { let m: S = this.st; return m.a; }
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
    const r = await eqCalls(Jw, Sw, [
      [`store(${P})`, args],
      ['ra()', ''],
      ['rd(uint256)', w(0)],
      ['rd(uint256)', w(1)],
      ['rd(uint256)', w(2)],
    ]);
    expect(r[1]!.returnHex).toBe('0x' + w(42)); // non-vacuity: ra() == 42 after store
  });

  it('REGRESSION: value-array (u256[]) field bind unregressed', async () => {
    const Pv = '(uint256,uint256[])';
    const Jv = `
type S = { a: u256; xs: u256[] };
class C {
  get f(p: S): External<u256> { let m: S = p; return m.xs[1n]; }
  get fe(p: S): External<bytes> { let m: S = p; return abi.encode(m); }
}`;
    const Sv = `
struct S { uint256 a; uint256[] xs; }
contract C {
  function f(S calldata p) external pure returns (uint256) { S memory m = p; return m.xs[1]; }
  function fe(S calldata p) external pure returns (bytes memory) { S memory m = p; return abi.encode(m); }
}`;
    const args = w(0x20) + w(9) + w(0x40) + encU256Arr([11, 22, 33]);
    const r = await eqCalls(Jv, Sv, [[`f(${Pv})`, args], [`fe(${Pv})`, args]]);
    expect(r[0]!.returnHex).toBe('0x' + w(22)); // non-vacuity: xs[1] == 22
  });

  it('REGRESSION: direct calldata-param reads (no bind) unregressed', async () => {
    const Jd = `
type S = { a: u256; tags: string[] };
class C {
  get da(p: S): External<u256> { return p.a; }
  get dl(p: S): External<u256> { return p.tags.length; }
  get dg(p: S): External<string> { return p.tags[0n]; }
  get de(p: S): External<bytes> { return abi.encode(p); }
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
    const r = await eqCalls(Jd, Sd, [[`da(${P})`, args], [`dl(${P})`, args], [`dg(${P})`, args], [`de(${P})`, args]]);
    expect(r[0]!.returnHex).toBe('0x' + w(7)); // non-vacuity: p.a == 7
  });

  it('LIFTED: a DynStruct[] struct-element-array field calldata->memory bind is byte-identical to solc', async () => {
    // Wave 2 (isDynStructElemArrayField) admits a struct-ELEMENT array field into isSupportedDynStructLocal,
    // so `let m: S = p` for S{ a; qs: Q[] } (Q dynamic) now DEEP-COPIES the calldata struct into memory
    // byte-identical to solc's `S memory m = p;`, instead of the old JETH200 reject.
    const Jg = `
type Q = { x: u256; s: string };
type S = { a: u256; qs: Q[] };
class C {
  get fa(p: S): External<u256> { let m: S = p; return m.a; }
  get fl(p: S): External<u256> { let m: S = p; return m.qs.length; }
  get fn(p: S): External<u256> { let m: S = p; return m.qs[1].x; }
  get fq(p: S): External<string> { let m: S = p; return m.qs[1].s; }
  get fe(p: S): External<bytes> { let m: S = p; return abi.encode(m); }
}`;
    const Sg = `
struct Q { uint256 x; string s; }
struct S { uint256 a; Q[] qs; }
contract C {
  function fa(S calldata p) external pure returns (uint256) { S memory m = p; return m.a; }
  function fl(S calldata p) external pure returns (uint256) { S memory m = p; return m.qs.length; }
  function fn(S calldata p) external pure returns (uint256) { S memory m = p; return m.qs[1].x; }
  function fq(S calldata p) external pure returns (string memory) { S memory m = p; return m.qs[1].s; }
  function fe(S calldata p) external pure returns (bytes memory) { S memory m = p; return abi.encode(m); }
}`;
    expect(codes(Jg)).toEqual([]); // Wave 2 lifted it: compiles clean
    // hand-encode one S{ a:7, qs:[Q{1,"hi"}, Q{2,"world!!"}] } as the sole (dynamic) calldata param.
    const PQ = '(uint256,(uint256,string)[])';
    const encQ = (x: number, s: string) => w(x) + w(0x40) + encStr(s); // Q = (uint256, string) dynamic
    const encQArr = (items: [number, string][]) => {
      const n = items.length;
      const eh = items.map(([x, s]) => encQ(x, s));
      const offs: number[] = [];
      let base = n * 32;
      for (let i = 0; i < n; i++) {
        offs.push(base);
        base += eh[i]!.length / 2;
      }
      return w(n) + offs.map((o) => w(o)).join('') + eh.join('');
    };
    const argS = (a: number, qs: [number, string][]) => w(0x20) + w(a) + w(0x40) + encQArr(qs);
    const args = argS(7, [[1, 'hi'], [2, 'world!!']]);
    const r = await eqCalls(Jg, Sg, [
      [`fa(${PQ})`, args], [`fl(${PQ})`, args], [`fn(${PQ})`, args], [`fq(${PQ})`, args], [`fe(${PQ})`, args],
    ]);
    // non-vacuity anchors (a selector miss or malformed calldata would revert-empty and fail these):
    expect(r[0]!.returnHex).toBe('0x' + w(7)); // m.a == 7
    expect(r[1]!.returnHex).toBe('0x' + w(2)); // m.qs.length == 2
    expect(r[2]!.returnHex).toBe('0x' + w(2)); // m.qs[1].x == 2
  });
});
