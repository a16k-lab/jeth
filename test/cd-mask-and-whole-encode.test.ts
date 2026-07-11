// cd-mask-and-whole-encode: two calldata lifts, proven byte-identical to solc 0.8.35.
//   (A) FIX a fail-SAFE over-validation: `return xs[i]` where xs is a calldata array whose element is a
//       PACKED/sub-word VALUE-leaf sub-array (u8[][] -> u8[], bool[][] -> bool[], Arr<u8,N>[] -> Arr<u8,N>)
//       and a leaf has DIRTY high bits -> solc MASKS (and 1ifies a non-0/1 bool); JETH used to EMPTY-revert.
//   (B) LIFT whole-aggregate value re-encodes (return + abi.encode), previously JETH230 rejects:
//       - whole sub-aggregate element with a bytes/string / dyn-struct leaf: bytes[][]->bytes[],
//         string[][]->string[], D[][]->D[] (D dynamic).
//       - whole dynamic-array FIELD of a calldata dyn-struct array element: xs[i].grid (u256[][]),
//         xs[i].items (D[]), xs[i].grid[j] (whole inner u256[]).
//   STILL a clean reject (deferred, sound): whole STRUCT element of a struct-array field xs[i].items[j].
import { describe, it, expect, beforeAll } from 'vitest';
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
const valArr = (xs: (bigint | number)[]) => W(xs.length) + xs.map((x) => W(x)).join('');
const rawArr = (words: string[]) => W(words.length) + words.join('');
function blob(s: string) {
  const hex = Buffer.from(s, 'utf8').toString('hex');
  const padded = hex.length ? hex.padEnd(Math.ceil(hex.length / 64) * 64, '0') : '';
  return W(s.length) + padded;
}

async function pair(jeth: string, sol: string) {
  const aj = await h.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { aj, as };
}
async function callOne(addr: import('@ethereumjs/util').Address, sig: string, cd: string) {
  try {
    const r = await h.call(addr, '0x' + sel(sig) + cd, {});
    return { success: r.success, ret: r.returnHex };
  } catch {
    return { success: false, ret: 'THROW' };
  }
}
async function same(a: { aj: any; as: any }, sig: string, cd: string) {
  expect(await callOne(a.aj, sig, cd)).toEqual(await callOne(a.as, sig, cd));
}
function rejects(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return (e?.diagnostics ?? []).map((d: any) => d.code);
  }
}

describe('(A) value-leaf sub-aggregate element return masks dirty leaves (was an over-validation revert)', () => {
  it('u8[][] -> u8[]: dirty leaves masked, clean identical, OOB Panic 0x32', async () => {
    const a = await pair(
      `class C{ get f(xs:u8[][],i:u256):External<u8[]>{return xs[i];} }`,
      `contract C{ function f(uint8[][] calldata xs,uint256 i)external pure returns(uint8[] memory){return xs[i];} }`,
    );
    const inner0 = rawArr(['ff'.repeat(31) + '01', 'ab'.repeat(31) + 'ff']); // dirty high bits
    const inner1 = valArr([7]);
    const xs = arrTab([inner0, inner1]);
    await same(a, 'f(uint8[][],uint256)', W(0x40) + W(0) + xs);
    await same(a, 'f(uint8[][],uint256)', W(0x40) + W(1) + xs);
    await same(a, 'f(uint8[][],uint256)', W(0x40) + W(2) + xs); // OOB
  });
  it('bool[][] -> bool[]: dirty/non-0/1 bool 1ified', async () => {
    const a = await pair(
      `class C{ get f(xs:bool[][],i:u256):External<bool[]>{return xs[i];} }`,
      `contract C{ function f(bool[][] calldata xs,uint256 i)external pure returns(bool[] memory){return xs[i];} }`,
    );
    const inner = rawArr(['ff'.repeat(31) + '01', '00'.repeat(32), 'aa'.repeat(31) + '05']);
    await same(a, 'f(bool[][],uint256)', W(0x40) + W(0) + arrTab([inner]));
  });
  it('Arr<u8,2>[] -> Arr<u8,2>: dirty leaves masked, OOB Panic 0x32', async () => {
    const a = await pair(
      `class C{ get f(xs:Arr<u8,2>[],i:u256):External<Arr<u8,2>>{return xs[i];} }`,
      `contract C{ function f(uint8[2][] calldata xs,uint256 i)external pure returns(uint8[2] memory){return xs[i];} }`,
    );
    const xs = W(2) + ('ff'.repeat(31) + '01') + ('ab'.repeat(31) + '02') + W(3) + W(4);
    await same(a, 'f(uint8[2][],uint256)', W(0x40) + W(0) + xs);
    await same(a, 'f(uint8[2][],uint256)', W(0x40) + W(1) + xs);
    await same(a, 'f(uint8[2][],uint256)', W(0x40) + W(2) + xs);
  });
  it('P[][] -> P[] still VALIDATES a dirty struct field (clean reject of dirty bits, not mask)', async () => {
    const a = await pair(
      `type P = {a:u8;b:u8;}; class C{ get f(xs:P[][],i:u256):External<P[]>{return xs[i];} }`,
      `struct P{uint8 a;uint8 b;} contract C{ function f(P[][] calldata xs,uint256 i)external pure returns(P[] memory){return xs[i];} }`,
    );
    const dirty = W(1) + ('ff'.repeat(31) + '01') + W(2); // a dirty -> both revert
    await same(a, 'f((uint8,uint8)[][],uint256)', W(0x40) + W(0) + arrTab([dirty]));
    const clean = W(1) + W(3) + W(4);
    await same(a, 'f((uint8,uint8)[][],uint256)', W(0x40) + W(0) + arrTab([clean]));
  });
});

describe('(B1) whole sub-aggregate element with bytes/string/dyn-struct leaf', () => {
  it('bytes[][] -> bytes[]', async () => {
    const a = await pair(
      `class C{ get f(xs:bytes[][],i:u256):External<bytes[]>{return xs[i];} }`,
      `contract C{ function f(bytes[][] calldata xs,uint256 i)external pure returns(bytes[] memory){return xs[i];} }`,
    );
    const xs = arrTab([arrTab([blob('hi'), blob('a-string-longer-than-thirty-two-bytes-here')]), arrTab([])]);
    await same(a, 'f(bytes[][],uint256)', W(0x40) + W(0) + xs);
    await same(a, 'f(bytes[][],uint256)', W(0x40) + W(1) + xs);
    await same(a, 'f(bytes[][],uint256)', W(0x40) + W(2) + xs); // OOB
  });
  it('string[][] -> string[]', async () => {
    const a = await pair(
      `class C{ get f(xs:string[][],i:u256):External<string[]>{return xs[i];} }`,
      `contract C{ function f(string[][] calldata xs,uint256 i)external pure returns(string[] memory){return xs[i];} }`,
    );
    const xs = arrTab([arrTab([blob('x'), blob(''), blob('z')])]);
    await same(a, 'f(string[][],uint256)', W(0x40) + W(0) + xs);
  });
  it('D[][] -> D[] (D dynamic), incl truncated -> empty revert', async () => {
    const a = await pair(
      `type D = {v:u256;tag:string;}; class C{ get f(xs:D[][],i:u256):External<D[]>{return xs[i];} }`,
      `struct D{uint256 v;string tag;} contract C{ function f(D[][] calldata xs,uint256 i)external pure returns(D[] memory){return xs[i];} }`,
    );
    const dynD = (v: number, s: string) => W(v) + W(0x40) + blob(s);
    const xs = arrTab([arrTab([dynD(11, 'abc'), dynD(22, 'over-thirty-two-bytes-of-string-content!')]), arrTab([dynD(33, '')])]);
    const sig = 'f((uint256,string)[][],uint256)';
    await same(a, sig, W(0x40) + W(0) + xs);
    await same(a, sig, W(0x40) + W(1) + xs);
    await same(a, sig, W(0x40) + W(2) + xs); // OOB
    const full = W(0x40) + W(0) + xs;
    await same(a, sig, full.slice(0, full.length - 64)); // truncated tail
  });
});

describe('(B2) whole dynamic-array FIELD of a calldata dyn-struct array element', () => {
  const Jg = `type S = {a:u256;grid:u256[][];};
class C{
  get f(xs:S[],i:u256):External<u256[][]>{return xs[i].grid;}
  get j(xs:S[],i:u256,k:u256):External<u256[]>{return xs[i].grid[k];}
  get e(xs:S[],i:u256):External<bytes>{return abi.encode(xs[i].grid);}
}`;
  const Sg = `struct S{uint256 a;uint256[][] grid;}
contract C{
  function f(S[] calldata xs,uint256 i)external pure returns(uint256[][] memory){return xs[i].grid;}
  function j(S[] calldata xs,uint256 i,uint256 k)external pure returns(uint256[] memory){return xs[i].grid[k];}
  function e(S[] calldata xs,uint256 i)external pure returns(bytes memory){return abi.encode(xs[i].grid);}
}`;
  const SelemGrid = (a: number, grid2d: number[][]) => W(a) + W(0x40) + arrTab(grid2d.map(valArr));

  it('xs[i].grid (u256[][]) return + abi.encode + grid[j], incl OOB i/k Panic 0x32', async () => {
    const a = await pair(Jg, Sg);
    const xs = arrTab([SelemGrid(1, [[10, 20], [30]]), SelemGrid(2, [[7]])]);
    const sigF = 'f((uint256,uint256[][])[],uint256)';
    const sigJ = 'j((uint256,uint256[][])[],uint256,uint256)';
    const sigE = 'e((uint256,uint256[][])[],uint256)';
    await same(a, sigF, W(0x40) + W(0) + xs);
    await same(a, sigF, W(0x40) + W(1) + xs);
    await same(a, sigF, W(0x40) + W(2) + xs); // OOB i
    await same(a, sigJ, W(0x60) + W(0) + W(0) + xs);
    await same(a, sigJ, W(0x60) + W(0) + W(1) + xs);
    await same(a, sigJ, W(0x60) + W(0) + W(5) + xs); // OOB k
    await same(a, sigJ, W(0x60) + W(9) + W(0) + xs); // OOB i
    await same(a, sigE, W(0x40) + W(0) + xs);
  });

  it('xs[i].grid malformed: oversized inner len -> return Panic 0x41, abi.encode empty revert; truncated -> empty', async () => {
    const a = await pair(Jg, Sg);
    const SelemRaw = (av: number, gridBlob: string) => W(av) + W(0x40) + gridBlob;
    const oversized = arrTab([SelemRaw(1, W(1) + W(0x20) + W(1n << 64n))]);
    await same(a, 'f((uint256,uint256[][])[],uint256)', W(0x40) + W(0) + oversized);
    await same(a, 'e((uint256,uint256[][])[],uint256)', W(0x40) + W(0) + oversized);
    const truncated = arrTab([SelemRaw(1, W(1) + W(0x20) + W(5))]);
    await same(a, 'f((uint256,uint256[][])[],uint256)', W(0x40) + W(0) + truncated);
  });

  it('xs[i].items (D[] dyn struct) return + abi.encode + malformed', async () => {
    const a = await pair(
      `type D = {v:u256;tag:string;};
type S = {a:u256;items:D[];};
class C{
  get f(xs:S[],i:u256):External<D[]>{return xs[i].items;}
  get e(xs:S[],i:u256):External<bytes>{return abi.encode(xs[i].items);}
}`,
      `struct D{uint256 v;string tag;}
struct S{uint256 a;D[] items;}
contract C{
  function f(S[] calldata xs,uint256 i)external pure returns(D[] memory){return xs[i].items;}
  function e(S[] calldata xs,uint256 i)external pure returns(bytes memory){return abi.encode(xs[i].items);}
}`,
    );
    const dynD = (v: number, s: string) => W(v) + W(0x40) + blob(s);
    const SelemItems = (av: number, ds: [number, string][]) => W(av) + W(0x40) + arrTab(ds.map(([v, s]) => dynD(v, s)));
    const xs = arrTab([SelemItems(1, [[11, 'abc'], [22, 'a-string-larger-than-thirty-two-bytes!!']]), SelemItems(2, [[33, '']])]);
    const TYD = '(uint256,string)';
    const sigF = `f((uint256,${TYD}[])[],uint256)`;
    const sigE = `e((uint256,${TYD}[])[],uint256)`;
    await same(a, sigF, W(0x40) + W(0) + xs);
    await same(a, sigF, W(0x40) + W(1) + xs);
    await same(a, sigF, W(0x40) + W(2) + xs); // OOB
    await same(a, sigE, W(0x40) + W(0) + xs);
    // oversized inner string len: return Panic 0x41, abi.encode empty revert
    const dBad = W(7) + W(0x40) + W(1n << 64n);
    const xsBad = arrTab([W(1) + W(0x40) + (W(1) + W(0x20) + dBad)]);
    await same(a, sigF, W(0x40) + W(0) + xsBad);
    await same(a, sigE, W(0x40) + W(0) + xsBad);
  });
});

describe('whole STRUCT element of a struct-array field xs[i].items[j] (lifted byte-identical)', () => {
  it('dynamic D: return + abi.encode + OOB + malformed', async () => {
    const a = await pair(
      `type D = {v:u256;tag:string;};
type S = {a:u256;items:D[];};
class C{
  get f(xs:S[],i:u256,j:u256):External<D>{return xs[i].items[j];}
  get e(xs:S[],i:u256,j:u256):External<bytes>{return abi.encode(xs[i].items[j]);}
}`,
      `struct D{uint256 v;string tag;}
struct S{uint256 a;D[] items;}
contract C{
  function f(S[] calldata xs,uint256 i,uint256 j)external pure returns(D memory){return xs[i].items[j];}
  function e(S[] calldata xs,uint256 i,uint256 j)external pure returns(bytes memory){return abi.encode(xs[i].items[j]);}
}`,
    );
    const dynD = (v: number, s: string) => W(v) + W(0x40) + blob(s);
    const SelemItems = (av: number, ds: [number, string][]) => W(av) + W(0x40) + arrTab(ds.map(([v, s]) => dynD(v, s)));
    const xs = arrTab([SelemItems(1, [[11, 'abc'], [22, 'a-string-larger-than-thirty-two-bytes!!']]), SelemItems(2, [[33, '']])]);
    const TYD = '(uint256,string)';
    const sigF = `f((uint256,${TYD}[])[],uint256,uint256)`;
    const sigE = `e((uint256,${TYD}[])[],uint256,uint256)`;
    await same(a, sigF, W(0x60) + W(0) + W(0) + xs);
    await same(a, sigF, W(0x60) + W(0) + W(1) + xs); // multi-word tag
    await same(a, sigF, W(0x60) + W(1) + W(0) + xs); // empty tag
    await same(a, sigE, W(0x60) + W(0) + W(1) + xs);
    await same(a, sigF, W(0x60) + W(2) + W(0) + xs); // OOB i -> Panic 0x32
    await same(a, sigF, W(0x60) + W(0) + W(9) + xs); // OOB j -> Panic 0x32
    // oversized inner string len: return Panic 0x41, abi.encode empty revert
    const dBad = W(7) + W(0x40) + W(1n << 64n);
    const xsBad = arrTab([W(1) + W(0x40) + (W(1) + W(0x20) + dBad)]);
    await same(a, sigF, W(0x60) + W(0) + W(0) + xsBad);
    await same(a, sigE, W(0x60) + W(0) + W(0) + xsBad);
  });

  it('static D: return + abi.encode + OOB byte-identical', async () => {
    const a = await pair(
      `type D = {v:u256;w:u256;};
type S = {a:u256;items:D[];};
class C{
  get f(xs:S[],i:u256,j:u256):External<D>{return xs[i].items[j];}
  get e(xs:S[],i:u256,j:u256):External<bytes>{return abi.encode(xs[i].items[j]);}
}`,
      `struct D{uint256 v;uint256 w;}
struct S{uint256 a;D[] items;}
contract C{
  function f(S[] calldata xs,uint256 i,uint256 j)external pure returns(D memory){return xs[i].items[j];}
  function e(S[] calldata xs,uint256 i,uint256 j)external pure returns(bytes memory){return abi.encode(xs[i].items[j]);}
}`,
    );
    const itemsStat = (ds: [number, number][]) => W(ds.length) + ds.map(([v, w]) => W(v) + W(w)).join('');
    const Selem = (av: number, ds: [number, number][]) => W(av) + W(0x40) + itemsStat(ds);
    const xs = arrTab([Selem(1, [[10, 11], [20, 21]]), Selem(2, [[30, 31]])]);
    const TYDb = '(uint256,uint256)';
    const sigF = `f((uint256,${TYDb}[])[],uint256,uint256)`;
    const sigE = `e((uint256,${TYDb}[])[],uint256,uint256)`;
    await same(a, sigF, W(0x60) + W(0) + W(0) + xs);
    await same(a, sigF, W(0x60) + W(0) + W(1) + xs);
    await same(a, sigE, W(0x60) + W(1) + W(0) + xs);
    await same(a, sigF, W(0x60) + W(2) + W(0) + xs); // OOB i
    await same(a, sigF, W(0x60) + W(1) + W(1) + xs); // OOB j (e1 has 1 item)
  });
});
