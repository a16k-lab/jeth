// G3: @error and @event with a non-indexed DYNAMIC-array argument (head/tail). Compares the
// error revert returndata AND the emitted event logs (topics + data) byte-for-byte vs solc.
// Array sources: calldata param and memory local; element types value/address/signed/nested.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, type LogEntry } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
  a.length === b.length && a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics));

// --- minimal ABI calldata encoder for the array/nested/string shapes (the test harness
// encodeCall only handles flat words). ---
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const encArr = (els: bigint[]) => pad(BigInt(els.length)) + els.map(pad).join(''); // uintN[]/intN[]/address[] tail
const encNest = (rows: bigint[][]) => {
  let off = rows.length * 32, table = '', tails = '';
  for (const row of rows) { table += pad(BigInt(off)); const t = encArr(row); tails += t; off += t.length / 2; }
  return pad(BigInt(rows.length)) + table + tails;
};
const encStr = (s: string) => {
  const hex = Buffer.from(s, 'utf8').toString('hex');
  return pad(BigInt(hex.length / 2)) + hex.padEnd(Math.ceil(hex.length / 64) * 64, '0');
};
type Comp = { dyn: false; word: string } | { dyn: true; tail: string };
const callData = (sig: string, comps: Comp[]) => {
  let off = comps.length * 32, head = '', tails = '';
  for (const c of comps) {
    if (!c.dyn) head += c.word;
    else { head += pad(BigInt(off)); tails += c.tail; off += c.tail.length / 2; }
  }
  return '0x' + sel(sig) + head + tails;
};
const A = (tail: string): Comp => ({ dyn: true, tail });
const V = (v: bigint): Comp => ({ dyn: false, word: pad(v) });

const JETH = `@contract class C {
  @error E1(a: u256[]);
  @error E2(tag: u256, a: u256[]);
  @error E3(a: u256[], s: string);
  @error EAddr(a: address[]);
  @error ESigned(a: i64[]);
  @error ENest(a: u256[][]);
  @event Ev1(a: u256[]);
  @event Ev2(@indexed tag: u256, a: u256[]);
  @event Ev3(a: u256[], s: string);
  @event EvAddr(a: address[]);
  // errors (calldata array source)
  @external @pure r1(a: u256[]): void { revert(E1(a)); }
  @external @pure r2(t: u256, a: u256[]): void { revert(E2(t, a)); }
  @external @pure r3(a: u256[], s: string): void { revert(E3(a, s)); }
  @external @pure rAddr(a: address[]): void { revert(EAddr(a)); }
  @external @pure rSigned(a: i64[]): void { revert(ESigned(a)); }
  @external @pure rNest(a: u256[][]): void { revert(ENest(a)); }
  // error with a MEMORY array source
  @external @pure rMem(x: u256, y: u256, z: u256): void { let xs: u256[] = [x, y, z]; revert(E1(xs)); }
  // events
  @external e1(a: u256[]): void { emit(Ev1(a)); }
  @external e2(t: u256, a: u256[]): void { emit(Ev2(t, a)); }
  @external e3(a: u256[], s: string): void { emit(Ev3(a, s)); }
  @external eAddr(a: address[]): void { emit(EvAddr(a)); }
  @external eMem(x: u256, y: u256): void { let xs: u256[] = [x, y]; emit(Ev1(xs)); }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  error E1(uint256[] a);
  error E2(uint256 tag, uint256[] a);
  error E3(uint256[] a, string s);
  error EAddr(address[] a);
  error ESigned(int64[] a);
  error ENest(uint256[][] a);
  event Ev1(uint256[] a);
  event Ev2(uint256 indexed tag, uint256[] a);
  event Ev3(uint256[] a, string s);
  event EvAddr(address[] a);
  function r1(uint256[] calldata a) external pure { revert E1(a); }
  function r2(uint256 t, uint256[] calldata a) external pure { revert E2(t, a); }
  function r3(uint256[] calldata a, string calldata s) external pure { revert E3(a, s); }
  function rAddr(address[] calldata a) external pure { revert EAddr(a); }
  function rSigned(int64[] calldata a) external pure { revert ESigned(a); }
  function rNest(uint256[][] calldata a) external pure { revert ENest(a); }
  function rMem(uint256 x, uint256 y, uint256 z) external pure { uint256[] memory xs = new uint256[](3); xs[0]=x;xs[1]=y;xs[2]=z; revert E1(xs); }
  function e1(uint256[] calldata a) external { emit Ev1(a); }
  function e2(uint256 t, uint256[] calldata a) external { emit Ev2(t, a); }
  function e3(uint256[] calldata a, string calldata s) external { emit Ev3(a, s); }
  function eAddr(address[] calldata a) external { emit EvAddr(a); }
  function eMem(uint256 x, uint256 y) external { uint256[] memory xs = new uint256[](2); xs[0]=x;xs[1]=y; emit Ev1(xs); }
}`;

describe('error/event with dynamic-array args (G3) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eqRevert(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, `${label} revertdata`).toBe(s.returnHex);
  }
  async function eqLog(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(eqLogs(j.logs, s.logs), `${label} logs\n jeth=${JSON.stringify(j.logs)}\n sol =${JSON.stringify(s.logs)}`).toBe(true);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  const arr = [1n, 2n, 3n, 0n, M - 1n];
  it('error revert data (calldata + memory array sources, mixed args)', async () => {
    await eqRevert('r1', callData('r1(uint256[])', [A(encArr(arr))]));
    await eqRevert('r1 empty', callData('r1(uint256[])', [A(encArr([]))]));
    await eqRevert('r2', callData('r2(uint256,uint256[])', [V(99n), A(encArr(arr))]));
    await eqRevert('r3', callData('r3(uint256[],string)', [A(encArr(arr)), A(encStr('hello world this is over thirty-two bytes long'))]));
    await eqRevert('rAddr', callData('rAddr(address[])', [A(encArr([0x1111n, 0xbeefn, 0n]))]));
    await eqRevert('rSigned', callData('rSigned(int64[])', [A(encArr([1n, M - 1n, (1n << 63n) - 1n, M - (1n << 63n)]))]));
    await eqRevert('rNest', callData('rNest(uint256[][])', [A(encNest([[1n, 2n], [3n], []]))]));
    await eqRevert('rMem', encodeCall(sel('rMem(uint256,uint256,uint256)'), [7n, 8n, 9n]));
  });
  it('event logs (topics + data) with array data', async () => {
    await eqLog('e1', callData('e1(uint256[])', [A(encArr(arr))]));
    await eqLog('e1 empty', callData('e1(uint256[])', [A(encArr([]))]));
    await eqLog('e2 (indexed tag + array data)', callData('e2(uint256,uint256[])', [V(42n), A(encArr(arr))]));
    await eqLog('e3 (array + string)', callData('e3(uint256[],string)', [A(encArr(arr)), A(encStr('abc'))]));
    await eqLog('eAddr', callData('eAddr(address[])', [A(encArr([0x1234n, 0n]))]));
    await eqLog('eMem', encodeCall(sel('eMem(uint256,uint256)'), [11n, 22n]));
  });
});
