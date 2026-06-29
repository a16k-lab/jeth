// Differential test: cd-nested-fields lift (LIFT #2 + #3).
//   #2 NESTED-ARRAY field of a calldata DYNAMIC-struct array element:
//        xs[i].grid[j][k]   where xs: S[], S = {a:u256; grid:u256[][]}
//      plus xs[i].grid[j].length, xs[i].grid.length, deeper u256[][][], bool dirty-bit validation.
//   #3 DYN-STRUCT-ARRAY field of a calldata DYNAMIC-struct array element:
//        xs[i].items[j].v   where xs: S[], S = {a:u256; items:D[]}, D = {v:u256; tag:string} (dynamic)
//      plus a STATIC D[] (contiguous), xs[i].items.length, a string leaf xs[i].items[j].tag.
//
// INVARIANT: byte-identical to solc 0.8.35 on returndata AND success/revert/Panic parity with RUNTIME
// indices at EVERY level (i,j,k). OOB at each level -> Panic(0x32); truncated calldata / out-of-range
// offsets -> EMPTY revert; a dirty packed bool leaf -> solc's lazy-validation EMPTY revert. The WHOLE
// field forms (xs[i].grid / xs[i].grid[j] / xs[i].items) stay CLEAN rejects (no whole-field codec).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

// ---- generic ABI builders ----
function arrOffsetTable(items: string[]): string {
  const n = items.length;
  let off = n * 32;
  const offs: number[] = [];
  for (const it of items) {
    offs.push(off);
    off += it.length / 2;
  }
  return pad(BigInt(n)) + offs.map((o) => pad(BigInt(o))).join('') + items.join('');
}
const valArr = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');

// ===================== #2 grid: u256[][] =====================
const J2 = `@struct class S{a:u256;grid:u256[][];}
@contract class C{
  @external @pure f(xs:S[],i:u256,j:u256,k:u256):u256{return xs[i].grid[j][k];}
  @external @pure innerLen(xs:S[],i:u256,j:u256):u256{return xs[i].grid[j].length;}
  @external @pure outerLen(xs:S[],i:u256):u256{return xs[i].grid.length;}
  @external @pure a(xs:S[],i:u256):u256{return xs[i].a;}
}`;
const S2 = `struct S{uint256 a;uint256[][] grid;}
contract C{
  function f(S[] calldata xs,uint256 i,uint256 j,uint256 k)external pure returns(uint256){return xs[i].grid[j][k];}
  function innerLen(S[] calldata xs,uint256 i,uint256 j)external pure returns(uint256){return xs[i].grid[j].length;}
  function outerLen(S[] calldata xs,uint256 i)external pure returns(uint256){return xs[i].grid.length;}
  function a(S[] calldata xs,uint256 i)external pure returns(uint256){return xs[i].a;}
}`;
const TY2 = '(uint256,uint256[][])';
const elemGrid = (a: bigint, grid: bigint[][]) => pad(a) + pad(0x40n) + arrOffsetTable(grid.map(valArr));

// ===================== #3 items: D[] (D dynamic) =====================
const J3 = `@struct class D{v:u256;tag:string;}
@struct class S{a:u256;items:D[];}
@contract class C{
  @external @pure f(xs:S[],i:u256,j:u256):u256{return xs[i].items[j].v;}
  @external @pure t(xs:S[],i:u256,j:u256):string{return xs[i].items[j].tag;}
  @external @pure ilen(xs:S[],i:u256):u256{return xs[i].items.length;}
}`;
const S3 = `struct D{uint256 v;string tag;}
struct S{uint256 a;D[] items;}
contract C{
  function f(S[] calldata xs,uint256 i,uint256 j)external pure returns(uint256){return xs[i].items[j].v;}
  function t(S[] calldata xs,uint256 i,uint256 j)external pure returns(string memory){return xs[i].items[j].tag;}
  function ilen(S[] calldata xs,uint256 i)external pure returns(uint256){return xs[i].items.length;}
}`;
const TYD = '(uint256,string)';
const TY3 = `(uint256,${TYD}[])`;
function strBlob(s: string): string {
  const b = Buffer.from(s, 'utf8').toString('hex');
  const w = Math.ceil((b.length || 1) / 64) * 64;
  return pad(BigInt(s.length)) + b.padEnd(w, '0');
}
const dynD = (v: bigint, s: string) => pad(v) + pad(0x40n) + strBlob(s);
// element S = {a; items:D[]}: head [a][off_items=0x40] then the already-built items array blob.
const elemItems = (a: bigint, itemsBlob: string) => pad(a) + pad(0x40n) + itemsBlob;

// ===================== #3b items: D[] (D static, contiguous) =====================
const J3b = `@struct class D{v:u256;w:u256;}
@struct class S{a:u256;items:D[];}
@contract class C{
  @external @pure f(xs:S[],i:u256,j:u256):u256{return xs[i].items[j].w;}
  @external @pure ilen(xs:S[],i:u256):u256{return xs[i].items.length;}
}`;
const S3b = `struct D{uint256 v;uint256 w;}
struct S{uint256 a;D[] items;}
contract C{
  function f(S[] calldata xs,uint256 i,uint256 j)external pure returns(uint256){return xs[i].items[j].w;}
  function ilen(S[] calldata xs,uint256 i)external pure returns(uint256){return xs[i].items.length;}
}`;
const TYDb = '(uint256,uint256)';
const TY3b = `(uint256,${TYDb}[])`;
const itemsStatic = (ds: [bigint, bigint][]) => pad(BigInt(ds.length)) + ds.map(([v, w]) => pad(v) + pad(w)).join('');

// ===================== deeper #2 cube: u256[][][] =====================
const Jc = `@struct class S{a:u256;cube:u256[][][];}
@contract class C{@external @pure f(xs:S[],i:u256,j:u256,k:u256,l:u256):u256{return xs[i].cube[j][k][l];}}`;
const Sc = `struct S{uint256 a;uint256[][][] cube;}
contract C{function f(S[] calldata xs,uint256 i,uint256 j,uint256 k,uint256 l)external pure returns(uint256){return xs[i].cube[j][k][l];}}`;
const TYc = '(uint256,uint256[][][])';

// ===================== bool dirty-bit =====================
const Jbool = `@struct class S{a:u256;flags:bool[][];}
@contract class C{@external @pure f(xs:S[],i:u256,j:u256,k:u256):bool{return xs[i].flags[j][k];}}`;
const Sbool = `struct S{uint256 a;bool[][] flags;}
contract C{function f(S[] calldata xs,uint256 i,uint256 j,uint256 k)external pure returns(bool){return xs[i].flags[j][k];}}`;
const TYbool = '(uint256,bool[][])';

async function pair(jSrc: string, sSrc: string): Promise<{ jeth: Harness; sol: Harness; aj: Address; as: Address }> {
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(compile(jSrc, { fileName: 'C.jeth' }).creationBytecode);
  const as = await sol.deploy(compileSolidity(SPDX + sSrc, 'C').creation);
  return { jeth, sol, aj, as };
}

describe('cd-nested-fields #2: xs[i].grid[j][k] on a calldata S[] (u256[][] field)', () => {
  let H: { jeth: Harness; sol: Harness; aj: Address; as: Address };
  async function eq(label: string, data: string) {
    const j = await H.jeth.call(H.aj, data);
    const s = await H.sol.call(H.as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  let xs: string;
  beforeAll(async () => {
    H = await pair(J2, S2);
    const e0 = elemGrid(11n, [[10n, 20n], [30n, 40n, 50n]]);
    const e1 = elemGrid(22n, [[1n], [2n, 3n], [(1n << 256n) - 1n]]);
    xs = arrOffsetTable([e0, e1]);
  });
  it('f reads grid[j][k] across runtime i,j,k (incl multi-word MAX)', async () => {
    const sig = `f(${TY2}[],uint256,uint256,uint256)`;
    await eq('xs[0].grid[0][1]=20', '0x' + sel(sig) + pad(0x80n) + pad(0n) + pad(0n) + pad(1n) + xs);
    await eq('xs[0].grid[1][2]=50', '0x' + sel(sig) + pad(0x80n) + pad(0n) + pad(1n) + pad(2n) + xs);
    await eq('xs[1].grid[2][0]=MAX', '0x' + sel(sig) + pad(0x80n) + pad(1n) + pad(2n) + pad(0n) + xs);
  });
  it('OOB at each level -> Panic(0x32) parity', async () => {
    const sig = `f(${TY2}[],uint256,uint256,uint256)`;
    await eq('i OOB', '0x' + sel(sig) + pad(0x80n) + pad(2n) + pad(0n) + pad(0n) + xs);
    await eq('j OOB', '0x' + sel(sig) + pad(0x80n) + pad(0n) + pad(5n) + pad(0n) + xs);
    await eq('k OOB', '0x' + sel(sig) + pad(0x80n) + pad(1n) + pad(0n) + pad(9n) + xs);
  });
  it('grid[j].length and grid.length and xs[i].a', async () => {
    await eq('inner', '0x' + sel(`innerLen(${TY2}[],uint256,uint256)`) + pad(0x60n) + pad(1n) + pad(1n) + xs);
    await eq('outer', '0x' + sel(`outerLen(${TY2}[],uint256)`) + pad(0x40n) + pad(1n) + xs);
    await eq('a', '0x' + sel(`a(${TY2}[],uint256)`) + pad(0x40n) + pad(0n) + xs);
  });
  it('truncated calldata -> EMPTY revert parity', async () => {
    const sig = `f(${TY2}[],uint256,uint256,uint256)`;
    const full = '0x' + sel(sig) + pad(0x80n) + pad(0n) + pad(0n) + pad(1n) + xs;
    await eq('trunc tail word', full.slice(0, full.length - 64));
  });
});

describe('cd-nested-fields #2: oversized/bad-offset + deeper cube + bool dirty', () => {
  it('huge inner length + bad offset -> parity', async () => {
    const H = await pair(J2, S2);
    const eq = async (label: string, data: string) => {
      const j = await H.jeth.call(H.aj, data);
      const s = await H.sol.call(H.as, data);
      expect(j.success, label).toBe(s.success);
      expect(j.returnHex, label).toBe(s.returnHex);
    };
    // grid=[ inner with HUGE claimed length ]
    const elemHuge = pad(0n) + pad(0x40n) + pad(1n) + pad(0x20n) + pad(1n << 64n);
    const xsHuge = arrOffsetTable([elemHuge]);
    const sig = `f(${TY2}[],uint256,uint256,uint256)`;
    await eq('huge len read k=0', '0x' + sel(sig) + pad(0x80n) + pad(0n) + pad(0n) + pad(0n) + xsHuge);
    await eq('huge len .length', '0x' + sel(`innerLen(${TY2}[],uint256,uint256)`) + pad(0x60n) + pad(0n) + pad(0n) + xsHuge);
    // grid offset word points past calldatasize
    const elemBad = pad(0n) + pad(0xffffffn) + pad(1n) + pad(0x20n) + pad(1n) + pad(5n);
    const xsBad = arrOffsetTable([elemBad]);
    await eq('bad grid offset', '0x' + sel(sig) + pad(0x80n) + pad(0n) + pad(0n) + pad(0n) + xsBad);
  });
  it('deeper cube u256[][][] reads + OOB', async () => {
    const H = await pair(Jc, Sc);
    const eq = async (label: string, data: string) => {
      const j = await H.jeth.call(H.aj, data);
      const s = await H.sol.call(H.as, data);
      expect(j.success, label).toBe(s.success);
      expect(j.returnHex, label).toBe(s.returnHex);
    };
    const inner = (xss: bigint[][]) => arrOffsetTable(xss.map(valArr));
    const cube = arrOffsetTable([inner([[1n, 2n], [3n]]), inner([[4n]])]);
    const xs = arrOffsetTable([pad(0n) + pad(0x40n) + cube]);
    const sig = `f(${TYc}[],uint256,uint256,uint256,uint256)`;
    await eq('cube[0][0][1]=2', '0x' + sel(sig) + pad(0xa0n) + pad(0n) + pad(0n) + pad(0n) + pad(1n) + xs);
    await eq('cube[0][1][0]=3', '0x' + sel(sig) + pad(0xa0n) + pad(0n) + pad(0n) + pad(1n) + pad(0n) + xs);
    await eq('cube[1][0][0]=4', '0x' + sel(sig) + pad(0xa0n) + pad(0n) + pad(1n) + pad(0n) + pad(0n) + xs);
    await eq('k OOB', '0x' + sel(sig) + pad(0xa0n) + pad(0n) + pad(1n) + pad(1n) + pad(0n) + xs);
  });
  it('bool[][] field: clean + dirty leaf parity', async () => {
    const H = await pair(Jbool, Sbool);
    const eq = async (label: string, data: string) => {
      const j = await H.jeth.call(H.aj, data);
      const s = await H.sol.call(H.as, data);
      expect(j.success, label).toBe(s.success);
      expect(j.returnHex, label).toBe(s.returnHex);
    };
    const xsClean = arrOffsetTable([elemGrid(0n, [[1n, 0n], [1n]])]);
    const xsDirty = arrOffsetTable([elemGrid(0n, [[2n]])]); // dirty bool (2)
    const sig = `f(${TYbool}[],uint256,uint256,uint256)`;
    await eq('true', '0x' + sel(sig) + pad(0x80n) + pad(0n) + pad(0n) + pad(0n) + xsClean);
    await eq('false', '0x' + sel(sig) + pad(0x80n) + pad(0n) + pad(0n) + pad(1n) + xsClean);
    await eq('dirty -> revert', '0x' + sel(sig) + pad(0x80n) + pad(0n) + pad(0n) + pad(0n) + xsDirty);
  });
});

describe('cd-nested-fields #3: xs[i].items[j].v on a calldata S[] (D[] field)', () => {
  it('dynamic D[] (D has string): value leaf, string leaf, length, OOB, truncated', async () => {
    const H = await pair(J3, S3);
    const eq = async (label: string, data: string) => {
      const j = await H.jeth.call(H.aj, data);
      const s = await H.sol.call(H.as, data);
      expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
      expect(j.returnHex, label).toBe(s.returnHex);
    };
    const it0 = arrOffsetTable([dynD(100n, 'ab'), dynD(200n, 'xyz')]);
    const it1 = arrOffsetTable([dynD(7n, '')]);
    const xsFixed = arrOffsetTable([elemItems(1n, it0), elemItems(2n, it1)]);
    const sigF = `f(${TY3}[],uint256,uint256)`;
    const sigT = `t(${TY3}[],uint256,uint256)`;
    const sigL = `ilen(${TY3}[],uint256)`;
    await eq('v 100', '0x' + sel(sigF) + pad(0x60n) + pad(0n) + pad(0n) + xsFixed);
    await eq('v 200', '0x' + sel(sigF) + pad(0x60n) + pad(0n) + pad(1n) + xsFixed);
    await eq('v 7', '0x' + sel(sigF) + pad(0x60n) + pad(1n) + pad(0n) + xsFixed);
    await eq('tag ab', '0x' + sel(sigT) + pad(0x60n) + pad(0n) + pad(0n) + xsFixed);
    await eq('tag xyz', '0x' + sel(sigT) + pad(0x60n) + pad(0n) + pad(1n) + xsFixed);
    await eq('tag empty', '0x' + sel(sigT) + pad(0x60n) + pad(1n) + pad(0n) + xsFixed);
    await eq('len 2', '0x' + sel(sigL) + pad(0x40n) + pad(0n) + xsFixed);
    await eq('len 1', '0x' + sel(sigL) + pad(0x40n) + pad(1n) + xsFixed);
    await eq('i OOB', '0x' + sel(sigF) + pad(0x60n) + pad(2n) + pad(0n) + xsFixed);
    await eq('j OOB', '0x' + sel(sigF) + pad(0x60n) + pad(0n) + pad(5n) + xsFixed);
    const full = '0x' + sel(sigF) + pad(0x60n) + pad(0n) + pad(0n) + xsFixed;
    await eq('truncated', full.slice(0, full.length - 128));
  });
  it('static D[] (contiguous): value leaf, length, OOB', async () => {
    const H = await pair(J3b, S3b);
    const eq = async (label: string, data: string) => {
      const j = await H.jeth.call(H.aj, data);
      const s = await H.sol.call(H.as, data);
      expect(j.success, label).toBe(s.success);
      expect(j.returnHex, label).toBe(s.returnHex);
    };
    const xs = arrOffsetTable([
      pad(9n) + pad(0x40n) + itemsStatic([[1n, 2n], [3n, 4n]]),
      pad(8n) + pad(0x40n) + itemsStatic([[5n, 6n]]),
    ]);
    const sigF = `f(${TY3b}[],uint256,uint256)`;
    const sigL = `ilen(${TY3b}[],uint256)`;
    await eq('w 2', '0x' + sel(sigF) + pad(0x60n) + pad(0n) + pad(0n) + xs);
    await eq('w 4', '0x' + sel(sigF) + pad(0x60n) + pad(0n) + pad(1n) + xs);
    await eq('w 6', '0x' + sel(sigF) + pad(0x60n) + pad(1n) + pad(0n) + xs);
    await eq('len 2', '0x' + sel(sigL) + pad(0x40n) + pad(0n) + xs);
    await eq('j OOB', '0x' + sel(sigF) + pad(0x60n) + pad(0n) + pad(9n) + xs);
  });
});

describe('cd-nested-fields: whole-field value forms stay CLEAN rejects (no whole-field codec)', () => {
  const rejects = (src: string) => {
    try {
      compile(src, { fileName: 'C.jeth' });
      return false;
    } catch {
      return true;
    }
  };
  it('xs[i].grid (whole u256[][]) rejected', () => {
    expect(rejects(`@struct class S{a:u256;grid:u256[][];}
@contract class C{@external @pure r(xs:S[],i:u256):u256[][]{return xs[i].grid;}}`)).toBe(true);
  });
  it('xs[i].grid[j] (whole u256[]) rejected', () => {
    expect(rejects(`@struct class S{a:u256;grid:u256[][];}
@contract class C{@external @pure r(xs:S[],i:u256,j:u256):u256[]{return xs[i].grid[j];}}`)).toBe(true);
  });
  it('xs[i].items (whole D[]) rejected', () => {
    expect(rejects(`@struct class D{v:u256;t:string;}
@struct class S{a:u256;items:D[];}
@contract class C{@external @pure r(xs:S[],i:u256):D[]{return xs[i].items;}}`)).toBe(true);
  });
});
