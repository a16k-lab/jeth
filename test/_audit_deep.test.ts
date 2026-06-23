// AUDIT: deep nested static aggregate params (struct-with-fixed-array-of-struct,
// fixed-array-of-fixed-array-of-struct, struct-with-nested-struct-with-array).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}
const W = (v: bigint) => pad(v);

const JETH = `
@struct class P { x: u128; y: u128; }
@struct class S { id: u64; ps: Arr<P, 2>; }
@struct class Inner { a: u128; data: Arr<u256, 3>; }
@struct class Outer { id: u64; inner: Inner; tail: u16; }
@contract
class A {
  // struct with fixed-array-of-struct field, deep read s.ps[i].x / .y
  @external @pure spx(s: S, i: u256): u128 { return s.ps[i].x; }
  @external @pure spy(s: S, i: u256): u128 { return s.ps[i].y; }
  @external @pure sid(s: S): u64 { return s.id; }
  // nested struct-with-array, deep o.inner.data[j], o.inner.a, o.tail
  @external @pure odata(o: Outer, j: u256): u256 { return o.inner.data[j]; }
  @external @pure oinnerA(o: Outer): u128 { return o.inner.a; }
  @external @pure otail(o: Outer): u16 { return o.tail; }
  @external @pure oid(o: Outer): u64 { return o.id; }
  // fixed-array-of-fixed-array-of-struct param a[i][j].x
  @external @pure aax(a: Arr<Arr<P, 2>, 2>, i: u256, j: u256): u128 { return a[i][j].x; }
  @external @pure aay(a: Arr<Arr<P, 2>, 2>, i: u256, j: u256): u128 { return a[i][j].y; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct P { uint128 x; uint128 y; }
  struct S { uint64 id; P[2] ps; }
  struct Inner { uint128 a; uint256[3] data; }
  struct Outer { uint64 id; Inner inner; uint16 tail; }
  function spx(S calldata s, uint256 i) external pure returns (uint128){ return s.ps[i].x; }
  function spy(S calldata s, uint256 i) external pure returns (uint128){ return s.ps[i].y; }
  function sid(S calldata s) external pure returns (uint64){ return s.id; }
  function odata(Outer calldata o, uint256 j) external pure returns (uint256){ return o.inner.data[j]; }
  function oinnerA(Outer calldata o) external pure returns (uint128){ return o.inner.a; }
  function otail(Outer calldata o) external pure returns (uint16){ return o.tail; }
  function oid(Outer calldata o) external pure returns (uint64){ return o.id; }
  function aax(P[2][2] calldata a, uint256 i, uint256 j) external pure returns (uint128){ return a[i][j].x; }
  function aay(P[2][2] calldata a, uint256 i, uint256 j) external pure returns (uint128){ return a[i][j].y; }
}`;

let jeth: Harness, sol: Harness, aj: Address, as: Address;
beforeAll(async () => {
  const jb = compile(JETH, { fileName: 'A.jeth' });
  const sb = compileSolidity(SOL, 'A');
  jeth = await Harness.create();
  sol = await Harness.create();
  aj = await jeth.deploy(jb.creationBytecode);
  as = await sol.deploy(sb.creation);
});
async function eq(label: string, data: string) {
  const j = await jeth.call(aj, data);
  const s = await sol.call(as, data);
  expect(j.success, `${label}: jeth=${j.success}(${j.exceptionError}) sol=${s.success}`).toBe(s.success);
  expect(j.returnHex, `${label}: rd jeth=${j.returnHex} sol=${s.returnHex}`).toBe(s.returnHex);
  return { j, s };
}

describe('struct with fixed-array-of-struct field', () => {
  // S head: id(1) + ps(P[2] = 4 words: p0.x,p0.y,p1.x,p1.y) = 5 words
  const sWords = [W(0x99n), W(0x10n), W(0x11n), W(0x20n), W(0x21n)];
  it('s.ps[i].x / .y / s.id', async () => {
    await eq('sid', '0x' + functionSelector('sid((uint64,(uint128,uint128)[2]))') + sWords.join(''));
    for (const i of [0n, 1n]) {
      await eq(
        `spx i=${i}`,
        '0x' + functionSelector('spx((uint64,(uint128,uint128)[2]),uint256)') + [...sWords, W(i)].join(''),
      );
      await eq(
        `spy i=${i}`,
        '0x' + functionSelector('spy((uint64,(uint128,uint128)[2]),uint256)') + [...sWords, W(i)].join(''),
      );
    }
    await eq(
      'spx OOB',
      '0x' + functionSelector('spx((uint64,(uint128,uint128)[2]),uint256)') + [...sWords, W(2n)].join(''),
    );
    // dirty p1.x (read) -> revert; dirty p1.y unread when reading spx i=1
    const dirty = [...sWords];
    dirty[3] = W((1n << 200n) | 0x20n); // p1.x dirty (uint128)
    await eq(
      'spx i=1 dirty p1.x',
      '0x' + functionSelector('spx((uint64,(uint128,uint128)[2]),uint256)') + [...dirty, W(1n)].join(''),
    );
    await eq(
      'spy i=1 dirty p1.x unread',
      '0x' + functionSelector('spy((uint64,(uint128,uint128)[2]),uint256)') + [...dirty, W(1n)].join(''),
    );
  });
});

describe('nested struct-with-array field', () => {
  // Outer head: id(1) + inner(Inner: a(1) + data(3)) = 4 + tail(1) = 6 words.
  const oWords = [W(0xabn), W(0xa1n), W(0xd0n), W(0xd1n), W(0xd2n), W(0xeeen)];
  it('o.inner.data[j], o.inner.a, o.tail, o.id', async () => {
    const t = '(uint64,(uint128,uint256[3]),uint16)';
    await eq('oid', '0x' + functionSelector(`oid(${t})`) + oWords.join(''));
    await eq('oinnerA', '0x' + functionSelector(`oinnerA(${t})`) + oWords.join(''));
    await eq('otail', '0x' + functionSelector(`otail(${t})`) + oWords.join(''));
    for (const j of [0n, 1n, 2n]) {
      await eq(`odata j=${j}`, '0x' + functionSelector(`odata(${t},uint256)`) + [...oWords, W(j)].join(''));
    }
    await eq('odata OOB', '0x' + functionSelector(`odata(${t},uint256)`) + [...oWords, W(3n)].join(''));
  });
});

describe('fixed-array-of-fixed-array-of-struct', () => {
  // a P[2][2]: 8 words: a[0][0].x,.y, a[0][1].x,.y, a[1][0].x,.y, a[1][1].x,.y
  const aWords = [W(0x00n), W(0x01n), W(0x02n), W(0x03n), W(0x10n), W(0x11n), W(0x12n), W(0x13n)];
  it('a[i][j].x / .y all + OOB', async () => {
    const t = '(uint128,uint128)[2][2]';
    for (const i of [0n, 1n])
      for (const j of [0n, 1n]) {
        await eq(
          `aax ${i},${j}`,
          '0x' + functionSelector(`aax(${t},uint256,uint256)`) + [...aWords, W(i), W(j)].join(''),
        );
        await eq(
          `aay ${i},${j}`,
          '0x' + functionSelector(`aay(${t},uint256,uint256)`) + [...aWords, W(i), W(j)].join(''),
        );
      }
    await eq('aax OOB i', '0x' + functionSelector(`aax(${t},uint256,uint256)`) + [...aWords, W(2n), W(0n)].join(''));
    await eq('aax OOB j', '0x' + functionSelector(`aax(${t},uint256,uint256)`) + [...aWords, W(0n), W(2n)].join(''));
  });
});
