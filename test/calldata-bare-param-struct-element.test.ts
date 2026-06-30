// MISCOMPILE FIX: a whole STRUCT element of a calldata struct-array FIELD of a BARE dyn-struct PARAM
//   used as a VALUE - `return s.items[j]`, `abi.encode(s.items[j])`, and `let d:D = s.items[j]` where
//   s: S calldata (NOT an array element), S = { a:u256; items:D[] }, D = { v:u256; tag:string } (dynamic)
//   or { v:u256; w:u256 } (static).
// Before the fix this FELL THROUGH the cd-deep-reads block (which `return undefined`'d silently for a
// STRUCT element), dropping the return statement so the function fell off its end and returned default
// ZEROS (two zero words) with NO bounds check - a silent miscompile (wrong bytes + an OOB j returned
// success+zeros instead of Panic 0x32). The array-element analogue `xs[i].items[j]` was already byte-
// identical (commit 2106c8e); the bare-param form (a cdDynArrayField base with arrayRoot === undefined)
// is now routed through the SAME cdStructArrayElem / cdArrayElemBase codec, so all shapes match solc.
// Differential vs solc 0.8.35 for honest reads at multiple j (incl multi-word + empty tag + MAX value),
// OOB j (Panic 0x32), truncated calldata (empty revert), oversized inner length (return Panic 0x41 vs
// abi.encode empty revert), an out-of-range element offset, and the local-binding form.
import { describe, it, expect, beforeAll } from 'vitest';
import type { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const M = 1n << 256n;
const W = (v: bigint | number) => (((BigInt(v) % M) + M) % M).toString(16).padStart(64, '0');
const MAX = (1n << 256n) - 1n;

let h: Harness;
beforeAll(async () => {
  h = await Harness.create();
});

function arrTab(items: string[]) {
  let off = items.length * 32;
  const offs: number[] = [];
  for (const it of items) {
    offs.push(off);
    off += it.length / 2;
  }
  return W(items.length) + offs.map((o) => W(o)).join('') + items.join('');
}
function blob(s: string) {
  const hex = Buffer.from(s, 'utf8').toString('hex');
  const padded = hex.length ? hex.padEnd(Math.ceil(hex.length / 64) * 64, '0') : '';
  return W(s.length) + padded;
}
const dynD = (v: bigint, s: string) => W(v) + W(0x40) + blob(s);
// S = { a:u256; items:D[] } with a DYNAMIC D[]: head = [a][offset-to-items=0x40], then the items header.
const Sdyn = (av: bigint, ds: [bigint, string][]) => W(av) + W(0x40) + arrTab(ds.map(([v, s]) => dynD(v, s)));
const itemsStat = (ds: [bigint, bigint][]) => W(ds.length) + ds.map(([v, w]) => W(v) + W(w)).join('');
const Sstat = (av: bigint, ds: [bigint, bigint][]) => W(av) + W(0x40) + itemsStat(ds);

async function pair(jeth: string, sol: string) {
  const aj = await h.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { aj, as };
}
async function callOne(addr: Address, sig: string, cd: string) {
  const r = await h.call(addr, ('0x' + sel(sig) + cd) as `0x${string}`, {});
  return { success: r.success, ret: r.returnHex };
}
async function same(a: { aj: Address; as: Address }, label: string, sig: string, cd: string) {
  const j = await callOne(a.aj, sig, cd);
  const s = await callOne(a.as, sig, cd);
  expect(j, label).toEqual(s);
}

describe('calldata-bare-param-struct-element: dynamic D = {v:u256; tag:string}', () => {
  let a: { aj: Address; as: Address };
  const TYD = '(uint256,string)';
  const sigF = `f((uint256,${TYD}[]),uint256)`;
  const sigE = `e((uint256,${TYD}[]),uint256)`;
  const sigB = `b((uint256,${TYD}[]),uint256)`;
  // arg layout for f(S calldata s, uint256 j): [offset-to-s = 0x40][j][S region]
  const args = (s: string, j: bigint | number) => W(0x40) + W(j) + s;
  let s: string;
  beforeAll(async () => {
    a = await pair(
      `@struct class D{v:u256;tag:string;}
@struct class S{a:u256;items:D[];}
@contract class C{
  @external @pure f(s:S,j:u256):D{return s.items[j];}
  @external @pure e(s:S,j:u256):bytes{return abi.encode(s.items[j]);}
  @external @pure b(s:S,j:u256):D{let d:D = s.items[j]; return d;}
}`,
      `struct D{uint256 v;string tag;}
struct S{uint256 a;D[] items;}
contract C{
  function f(S calldata s,uint256 j)external pure returns(D memory){return s.items[j];}
  function e(S calldata s,uint256 j)external pure returns(bytes memory){return abi.encode(s.items[j]);}
  function b(S calldata s,uint256 j)external pure returns(D memory){D memory d = s.items[j]; return d;}
}`,
    );
    // items = [D(10,"hi"), D(MAX,"a string longer than thirty-two bytes for sure!!"), D(99,""), D(7,"x")]
    s = Sdyn(1n, [
      [10n, 'hi'],
      [MAX, 'a string longer than thirty-two bytes for sure!!'],
      [99n, ''],
      [7n, 'x'],
    ]);
  });

  it('return: honest reads at multiple j (multi-word, MAX value, empty tag)', async () => {
    await same(a, 'f[0]', sigF, args(s, 0));
    await same(a, 'f[1] multi-word + MAX', sigF, args(s, 1));
    await same(a, 'f[2] empty tag', sigF, args(s, 2));
    await same(a, 'f[3]', sigF, args(s, 3));
  });
  it('abi.encode: honest reads byte-identical', async () => {
    await same(a, 'e[0]', sigE, args(s, 0));
    await same(a, 'e[1]', sigE, args(s, 1));
    await same(a, 'e[2]', sigE, args(s, 2));
    await same(a, 'e[3]', sigE, args(s, 3));
  });
  it('local binding: let d:D = s.items[j]; return d', async () => {
    await same(a, 'b[0]', sigB, args(s, 0));
    await same(a, 'b[1]', sigB, args(s, 1));
    await same(a, 'b[2] empty tag', sigB, args(s, 2));
  });
  it('OOB j -> Panic 0x32 parity (return + encode + bind)', async () => {
    await same(a, 'f OOB j=4', sigF, args(s, 4));
    await same(a, 'f OOB j huge', sigF, args(s, 1n << 200n));
    await same(a, 'e OOB j=4', sigE, args(s, 4));
    await same(a, 'b OOB j=4', sigB, args(s, 4));
  });
  it('truncated calldata -> empty revert parity', async () => {
    const small = Sdyn(1n, [
      [10n, 'hi'],
      [20n, 'world'],
    ]);
    const full = args(small, 0);
    for (const chopBytes of [32, 64, 96, 128, 160, 192]) {
      await same(a, `f trunc -${chopBytes}B`, sigF, full.slice(0, full.length - chopBytes * 2));
      await same(a, `e trunc -${chopBytes}B`, sigE, full.slice(0, full.length - chopBytes * 2));
    }
  });
  it('oversized inner tag length: return Panic 0x41 vs abi.encode empty revert', async () => {
    // tag len within the 2^64 cap but payload way past calldata -> solc decode allocates huge -> Panic 0x41
    const dBad = W(7) + W(0x40) + W(1n << 64n);
    const sBad = W(1) + W(0x40) + (W(1) + W(0x20) + dBad);
    await same(a, 'f oversized tag len', sigF, args(sBad, 0));
    await same(a, 'e oversized tag len', sigE, args(sBad, 0));
    // tag len exceeding the 2^64 cap -> empty revert in both
    const dHuge = W(7) + W(0x40) + W(1n << 70n);
    const sHuge = W(1) + W(0x40) + (W(1) + W(0x20) + dHuge);
    await same(a, 'f tag len 2^70', sigF, args(sHuge, 0));
    await same(a, 'e tag len 2^70', sigE, args(sHuge, 0));
  });
  it('out-of-range element offset in the items table -> empty revert parity', async () => {
    const itemsBogus = W(1) + W(1n << 200n); // len=1, element-0 offset word huge
    const sBad = W(1) + W(0x40) + itemsBogus;
    await same(a, 'f bad elem offset', sigF, args(sBad, 0));
    await same(a, 'e bad elem offset', sigE, args(sBad, 0));
  });
});

describe('calldata-bare-param-struct-element: static D = {v:u256; w:u256}', () => {
  let a: { aj: Address; as: Address };
  const TYDb = '(uint256,uint256)';
  const sigF = `f((uint256,${TYDb}[]),uint256)`;
  const sigE = `e((uint256,${TYDb}[]),uint256)`;
  const sigB = `b((uint256,${TYDb}[]),uint256)`;
  const args = (s: string, j: bigint | number) => W(0x40) + W(j) + s;
  let s: string;
  beforeAll(async () => {
    a = await pair(
      `@struct class D{v:u256;w:u256;}
@struct class S{a:u256;items:D[];}
@contract class C{
  @external @pure f(s:S,j:u256):D{return s.items[j];}
  @external @pure e(s:S,j:u256):bytes{return abi.encode(s.items[j]);}
  @external @pure b(s:S,j:u256):D{let d:D = s.items[j]; return d;}
}`,
      `struct D{uint256 v;uint256 w;}
struct S{uint256 a;D[] items;}
contract C{
  function f(S calldata s,uint256 j)external pure returns(D memory){return s.items[j];}
  function e(S calldata s,uint256 j)external pure returns(bytes memory){return abi.encode(s.items[j]);}
  function b(S calldata s,uint256 j)external pure returns(D memory){D memory d = s.items[j]; return d;}
}`,
    );
    s = Sstat(1n, [
      [10n, 11n],
      [20n, 21n],
      [MAX, 5n],
    ]);
  });
  it('return: honest reads (incl MAX)', async () => {
    await same(a, 'f[0]', sigF, args(s, 0));
    await same(a, 'f[2] MAX', sigF, args(s, 2));
  });
  it('abi.encode: honest reads', async () => {
    await same(a, 'e[0]', sigE, args(s, 0));
    await same(a, 'e[2]', sigE, args(s, 2));
  });
  it('local binding: let d:D = s.items[j]; return d', async () => {
    await same(a, 'b[0]', sigB, args(s, 0));
    await same(a, 'b[2] MAX', sigB, args(s, 2));
  });
  it('OOB j -> Panic 0x32 parity', async () => {
    await same(a, 'f OOB j=3', sigF, args(s, 3));
    await same(a, 'e OOB j=3', sigE, args(s, 3));
    await same(a, 'b OOB j=3', sigB, args(s, 3));
  });
  it('truncated calldata + oversized declared items length -> empty revert parity', async () => {
    const full = args(s, 0);
    for (const chopBytes of [32, 64, 96, 160]) {
      await same(a, `f trunc -${chopBytes}B`, sigF, full.slice(0, full.length - chopBytes * 2));
    }
    const itemsBogus = W(1n << 200n) + W(10n) + W(11n); // declared len huge
    const sBad = W(1) + W(0x40) + itemsBogus;
    await same(a, 'f oversized items len', sigF, args(sBad, 0));
    await same(a, 'e oversized items len', sigE, args(sBad, 0));
  });
});
