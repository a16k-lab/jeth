// JETH230 lift: element access + length + whole echo of a dynamic VALUE-array field of a calldata
// dynamic-struct param: `s.xs[i]`, `s.xs.length`, `return s.xs` where `s: S` and `S { a; xs: u256[]; }`.
// The array is decoded via the tuple tail offset (calldataDynAt) then read/encoded like any calldata
// array. Byte-identical to solc 0.8.35 incl. OOB Panic 0x32 and dirty-element validation.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
// build calldata for a function whose FIRST param is S{a: uint256, xs: uint256[]} (dynamic) and an
// optional trailing uint256. head = [off_s][trailing?]; s tuple at off_s = [a][off_xs=0x40][len][e..].
const buildS = (selStr: string, a: bigint, xs: readonly bigint[], trailing?: bigint, dirtyFirst = false): string => {
  const e0 = dirtyFirst && xs.length ? 'ff' + pad32(xs[0]!).slice(2) : xs.length ? pad32(xs[0]!) : '';
  const elems = xs.map((v, k) => (k === 0 ? e0 : pad32(v))).join('');
  const tuple = pad32(a) + pad32(0x40n) + pad32(BigInt(xs.length)) + elems;
  const offS = trailing === undefined ? 0x20n : 0x40n;
  const head = trailing === undefined ? pad32(offS) : pad32(offS) + pad32(trailing);
  return '0x' + sel(selStr) + head + tuple;
};

describe('calldata dyn-struct dynamic value-array field (JETH230) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `@struct class S { a: u256; xs: u256[]; }
@struct class N { a: u256; ns: u64[]; }
@contract class C {
  @external @pure idx(s: S, i: u256): u256 { return s.xs[i]; }
  @external @pure len(s: S): u256 { return s.xs.length; }
  @external @pure echo(s: S): u256[] { return s.xs; }
  @external @pure sum(s: S): u256 { let t: u256 = 0n; for (const v of s.xs) { t = t + v; } return t; }
  @external @pure nidx(n: N, i: u256): u64 { return n.ns[i]; } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  struct S { uint256 a; uint256[] xs; }
  struct N { uint256 a; uint64[] ns; }
  function idx(S calldata s, uint256 i) external pure returns (uint256) { return s.xs[i]; }
  function len(S calldata s) external pure returns (uint256) { return s.xs.length; }
  function echo(S calldata s) external pure returns (uint256[] memory) { return s.xs; }
  function sum(S calldata s) external pure returns (uint256) { uint256 t = 0; for (uint256 k = 0; k < s.xs.length; k++) { t += s.xs[k]; } return t; }
  function nidx(N calldata n, uint256 i) external pure returns (uint64) { return n.ns[i]; } }`;

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });
  const cmp = async (data: string, label: string) => {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
  };

  it('s.xs[i] reads every element + OOB Panic 0x32, byte-identical', async () => {
    for (const i of [0n, 1n, 2n, 3n, 99n])
      await cmp(buildS('idx((uint256,uint256[]),uint256)', 7n, [10n, 20n, 30n], i), `xs[${i}]`);
    await cmp(buildS('idx((uint256,uint256[]),uint256)', 7n, [], 0n), 'xs[0] empty (OOB)');
  });
  it('s.xs.length + return s.xs (whole echo) match solc, incl. empty', async () => {
    for (const xs of [[10n, 20n, 30n], [], [42n]] as const) {
      await cmp(buildS('len((uint256,uint256[]))', 7n, xs), `len(${xs.length})`);
      await cmp(buildS('echo((uint256,uint256[]))', 7n, xs), `echo(${xs.length})`);
    }
  });
  it('for-of over s.xs sums byte-identically', async () => {
    await cmp(buildS('sum((uint256,uint256[]))', 7n, [3n, 5n, 8n, 13n]), 'sum');
  });
  it('a NARROW element array (u64[]) validates dirty calldata bits like solc', async () => {
    await cmp(buildS('nidx((uint256,uint64[]),uint256)', 7n, [5n, 6n, 7n], 1n), 'nidx clean');
    // dirty high bits in the first u64 element: solc validates the read element and reverts
    await cmp(buildS('nidx((uint256,uint64[]),uint256)', 7n, [5n, 6n, 7n], 0n, true), 'nidx dirty[0] read');
  });
  it('MALFORMED calldata reverts byte-identically (array payload-fit + unsigned offset, not the bytes decode)', async () => {
    // The array field must be decoded with the ARRAY helper (len*stride payload-fit + unsigned offset
    // bound), NOT the bytes/string helper (len+0x20 + signed offset). solc EMPTY-reverts on all three.
    const SL = 'len((uint256,uint256[]))';
    // (1) truncated tail: declares len=5 but supplies only 2 element words
    await cmp(
      '0x' + sel(SL) + pad32(0x20n) + pad32(7n) + pad32(0x40n) + pad32(5n) + pad32(1n) + pad32(2n),
      'truncated tail',
    );
    // (2) offset wrap: off_xs = 2^256 - 32 (a wrapped/negative offset)
    await cmp(
      '0x' + sel(SL) + pad32(0x20n) + pad32(7n) + pad32((1n << 256n) - 32n) + pad32(2n) + pad32(1n) + pad32(2n),
      'offset wrap',
    );
    // (3) offset 0: the length word overlaps the leading scalar field (len = a = 7, no payload)
    await cmp('0x' + sel(SL) + pad32(0x20n) + pad32(7n) + pad32(0n) + pad32(1n) + pad32(2n), 'offset 0');
  });
});
