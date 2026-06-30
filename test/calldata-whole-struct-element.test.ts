// LIFT: a whole STRUCT element of a calldata struct-array FIELD used as a VALUE -
//   `return xs[i].items[j]` and `abi.encode(xs[i].items[j])` where xs: S[] calldata,
//   S = { a:u256; items:D[] }, D = { v:u256; tag:string } (dynamic) or { v:u256; w:u256 } (static).
// Previously a clean JETH230 (and a PRIOR naive attempt mis-routed the cdDynArrayField-with-arrayRoot
// base producing wrong bytes + no OOB check - reverted). This lift resolves the element tuple base from
// the items[] field header (dynamic-element offset table / static-element contiguous run, stride-fixed in
// lowerArrayRef), bounds-checks (Panic 0x32) via cdArrayElemBase, then re-encodes the whole D with the
// recursive calldata codec. Differential vs solc 0.8.35 for honest reads at multiple i,j (incl multi-word
// + empty tag), OOB i AND j (Panic 0x32), truncated calldata (empty revert), oversized inner length
// (return Panic 0x41 vs abi.encode empty revert), and an out-of-range element offset.
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
const SelemDyn = (av: bigint, ds: [bigint, string][]) => W(av) + W(0x40) + arrTab(ds.map(([v, s]) => dynD(v, s)));
const itemsStat = (ds: [bigint, bigint][]) => W(ds.length) + ds.map(([v, w]) => W(v) + W(w)).join('');
const SelemStat = (av: bigint, ds: [bigint, bigint][]) => W(av) + W(0x40) + itemsStat(ds);

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

const MAX = (1n << 256n) - 1n;

describe('calldata-whole-struct-element: dynamic D = {v:u256; tag:string}', () => {
  let a: { aj: Address; as: Address };
  const TYD = '(uint256,string)';
  const sigF = `f((uint256,${TYD}[])[],uint256,uint256)`;
  const sigE = `e((uint256,${TYD}[])[],uint256,uint256)`;
  let xs: string;
  beforeAll(async () => {
    a = await pair(
      `@struct class D{v:u256;tag:string;}
@struct class S{a:u256;items:D[];}
@contract class C{
  @external @pure f(xs:S[],i:u256,j:u256):D{return xs[i].items[j];}
  @external @pure e(xs:S[],i:u256,j:u256):bytes{return abi.encode(xs[i].items[j]);}
}`,
      `struct D{uint256 v;string tag;}
struct S{uint256 a;D[] items;}
contract C{
  function f(S[] calldata xs,uint256 i,uint256 j)external pure returns(D memory){return xs[i].items[j];}
  function e(S[] calldata xs,uint256 i,uint256 j)external pure returns(bytes memory){return abi.encode(xs[i].items[j]);}
}`,
    );
    // element0.items = [D(10,"hi"), D(MAX,"a string longer than thirty-two bytes for sure!!")]
    // element1.items = [D(99,""), D(7,"x")]
    xs = arrTab([
      SelemDyn(1n, [[10n, 'hi'], [MAX, 'a string longer than thirty-two bytes for sure!!']]),
      SelemDyn(2n, [[99n, ''], [7n, 'x']]),
    ]);
  });

  it('return: honest reads at multiple i,j (multi-word, MAX value, empty tag)', async () => {
    await same(a, 'f[0][0]', sigF, W(0x60) + W(0) + W(0) + xs);
    await same(a, 'f[0][1] multi-word + MAX', sigF, W(0x60) + W(0) + W(1) + xs);
    await same(a, 'f[1][0] empty tag', sigF, W(0x60) + W(1) + W(0) + xs);
    await same(a, 'f[1][1]', sigF, W(0x60) + W(1) + W(1) + xs);
  });
  it('abi.encode: honest reads byte-identical', async () => {
    await same(a, 'e[0][0]', sigE, W(0x60) + W(0) + W(0) + xs);
    await same(a, 'e[0][1]', sigE, W(0x60) + W(0) + W(1) + xs);
    await same(a, 'e[1][0]', sigE, W(0x60) + W(1) + W(0) + xs);
  });
  it('OOB i and OOB j -> Panic 0x32 parity (return + encode)', async () => {
    await same(a, 'f OOB i=2', sigF, W(0x60) + W(2) + W(0) + xs);
    await same(a, 'f OOB j=2', sigF, W(0x60) + W(0) + W(2) + xs);
    await same(a, 'f OOB i huge', sigF, W(0x60) + W(1n << 200n) + W(0) + xs);
    await same(a, 'e OOB i=2', sigE, W(0x60) + W(2) + W(0) + xs);
    await same(a, 'e OOB j=2', sigE, W(0x60) + W(0) + W(2) + xs);
  });
  it('truncated calldata -> empty revert parity', async () => {
    const small = arrTab([SelemDyn(1n, [[10n, 'hi'], [20n, 'world']])]);
    const full = W(0x60) + W(0) + W(0) + small;
    for (const chopBytes of [32, 64, 96, 128, 160, 192]) {
      await same(a, `trunc -${chopBytes}B`, sigF, full.slice(0, full.length - chopBytes * 2));
    }
  });
  it('oversized inner tag length: return Panic 0x41 vs abi.encode empty revert', async () => {
    // tag len within the 2^64 cap but payload way past calldata -> solc decode allocates huge -> Panic 0x41
    const dBad = W(7) + W(0x40) + W(1n << 64n);
    const xsBad = arrTab([W(1) + W(0x40) + (W(1) + W(0x20) + dBad)]);
    await same(a, 'f oversized tag len', sigF, W(0x60) + W(0) + W(0) + xsBad);
    await same(a, 'e oversized tag len', sigE, W(0x60) + W(0) + W(0) + xsBad);
    // tag len exceeding 2^64 cap -> empty revert in both
    const dHuge = W(7) + W(0x40) + W(1n << 70n);
    const xsHuge = arrTab([W(1) + W(0x40) + (W(1) + W(0x20) + dHuge)]);
    await same(a, 'f tag len 2^70', sigF, W(0x60) + W(0) + W(0) + xsHuge);
    await same(a, 'e tag len 2^70', sigE, W(0x60) + W(0) + W(0) + xsHuge);
  });
  it('out-of-range element offset in the items table -> empty revert parity', async () => {
    const itemsBogus = W(1) + W(1n << 200n); // len=1, element-0 offset word huge
    const xsBad = arrTab([W(1) + W(0x40) + itemsBogus]);
    await same(a, 'f bad elem offset', sigF, W(0x60) + W(0) + W(0) + xsBad);
    await same(a, 'e bad elem offset', sigE, W(0x60) + W(0) + W(0) + xsBad);
  });
});

describe('calldata-whole-struct-element: static D = {v:u256; w:u256}', () => {
  let a: { aj: Address; as: Address };
  const TYDb = '(uint256,uint256)';
  const sigF = `f((uint256,${TYDb}[])[],uint256,uint256)`;
  const sigE = `e((uint256,${TYDb}[])[],uint256,uint256)`;
  let xs: string;
  beforeAll(async () => {
    a = await pair(
      `@struct class D{v:u256;w:u256;}
@struct class S{a:u256;items:D[];}
@contract class C{
  @external @pure f(xs:S[],i:u256,j:u256):D{return xs[i].items[j];}
  @external @pure e(xs:S[],i:u256,j:u256):bytes{return abi.encode(xs[i].items[j]);}
}`,
      `struct D{uint256 v;uint256 w;}
struct S{uint256 a;D[] items;}
contract C{
  function f(S[] calldata xs,uint256 i,uint256 j)external pure returns(D memory){return xs[i].items[j];}
  function e(S[] calldata xs,uint256 i,uint256 j)external pure returns(bytes memory){return abi.encode(xs[i].items[j]);}
}`,
    );
    xs = arrTab([SelemStat(1n, [[10n, 11n], [20n, 21n], [MAX, 5n]]), SelemStat(2n, [[100n, 101n]])]);
  });
  it('return: honest reads (incl MAX)', async () => {
    await same(a, 'f[0][0]', sigF, W(0x60) + W(0) + W(0) + xs);
    await same(a, 'f[0][2] MAX', sigF, W(0x60) + W(0) + W(2) + xs);
    await same(a, 'f[1][0]', sigF, W(0x60) + W(1) + W(0) + xs);
  });
  it('abi.encode: honest reads', async () => {
    await same(a, 'e[0][0]', sigE, W(0x60) + W(0) + W(0) + xs);
    await same(a, 'e[0][2]', sigE, W(0x60) + W(0) + W(2) + xs);
  });
  it('OOB i and OOB j -> Panic 0x32 parity', async () => {
    await same(a, 'f OOB i=2', sigF, W(0x60) + W(2) + W(0) + xs);
    await same(a, 'f OOB j=3', sigF, W(0x60) + W(0) + W(3) + xs);
    await same(a, 'f OOB j=1 (e1 has 1)', sigF, W(0x60) + W(1) + W(1) + xs);
    await same(a, 'e OOB i=2', sigE, W(0x60) + W(2) + W(0) + xs);
  });
  it('truncated calldata + oversized declared items length -> empty revert parity', async () => {
    const full = W(0x60) + W(0) + W(0) + xs;
    for (const chopBytes of [32, 64, 96, 160]) {
      await same(a, `trunc -${chopBytes}B`, sigF, full.slice(0, full.length - chopBytes * 2));
    }
    const itemsBogus = W(1n << 200n) + W(10n) + W(11n); // declared len huge
    const xsBad = arrTab([W(1) + W(0x40) + itemsBogus]);
    await same(a, 'f oversized items len', sigF, W(0x60) + W(0) + W(0) + xsBad);
    await same(a, 'e oversized items len', sigE, W(0x60) + W(0) + W(0) + xsBad);
  });
});
