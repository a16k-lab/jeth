// Differential test: deep reads of a CALLDATA composite-struct array (cd-deep-reads cluster).
//   (A) xs[i][j].field   where xs: Arr<P,2>[] (P[2][])  - field after a DOUBLE index.
//   (C) xs[i].tags[j]    where xs: S[], S={a:u256; tags:string[]/bytes[]} - index a DYNAMIC-leaf
//       array FIELD of a dyn-struct array element (plus the whole-array echo return xs[i].tags).
//
// INVARIANT: byte-identical to solc 0.8.35 on returndata AND success/revert/Panic parity, with
// RUNTIME indices i,j (not literals). Dirty packed-field bits and truncated calldata are attacked
// to confirm solc's lazy-validation EMPTY-revert / Panic(0x32) parity.
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

// ---------- Case A: xs[i][j].field, xs: P[2][], P = {a,c:u8,b} (packed middle field) ----------
const JETH_A = `@struct class P{a:u256;c:u8;b:u256;}
@contract class C{
  @external @pure rdA(xs:Arr<P,3>[],i:u256,j:u256):u256{return xs[i][j].a;}
  @external @pure rdC(xs:Arr<P,3>[],i:u256,j:u256):u8{return xs[i][j].c;}
  @external @pure rdB(xs:Arr<P,3>[],i:u256,j:u256):u256{return xs[i][j].b;}
}`;
const SOL_A = `struct P{uint256 a;uint8 c;uint256 b;}
contract C{
  function rdA(P[3][] calldata xs,uint256 i,uint256 j)external pure returns(uint256){return xs[i][j].a;}
  function rdC(P[3][] calldata xs,uint256 i,uint256 j)external pure returns(uint8){return xs[i][j].c;}
  function rdB(P[3][] calldata xs,uint256 i,uint256 j)external pure returns(uint256){return xs[i][j].b;}
}`;

// ---------- Case C: xs[i].tags[j], xs: S[], S = {a:u256, tags:string[]} ----------
const JETH_C = `@struct class S{a:u256;tags:string[];}
@contract class C{
  @external @pure read(xs:S[],i:u256,j:u256):string{return xs[i].tags[j];}
  @external @pure echo(xs:S[],i:u256):string[]{return xs[i].tags;}
}`;
const SOL_C = `struct S{uint256 a;string[] tags;}
contract C{
  function read(S[] calldata xs,uint256 i,uint256 j)external pure returns(string memory){return xs[i].tags[j];}
  function echo(S[] calldata xs,uint256 i)external pure returns(string[] memory){return xs[i].tags;}
}`;

describe('cd-deep-reads (A): xs[i][j].field on a calldata Arr<P,N>[] composite', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(JETH_A, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(SPDX + SOL_A, 'C').creation);
  });

  // P[3][] = 2 outer rows, each row 3 P structs, each P = [a][c][b] (3 head words, c is u8 inline).
  // dirtyC: set the upper bits of the u8 field word so solc's lazy validation must EMPTY-revert.
  const rows = [
    [
      [1n, 7n, 2n],
      [3n, 8n, 4n],
      [5n, 9n, 6n],
    ],
    [
      [10n, 1n, 20n],
      [30n, 2n, 40n],
      [50n, 3n, 60n],
    ],
  ];
  const body = (dirtyC: boolean) => {
    let out = pad(BigInt(rows.length));
    for (const row of rows)
      for (const p of row) {
        out += pad(p[0]!);
        out += dirtyC ? 'ff'.repeat(31) + pad(p[1]!).slice(62) : pad(p[1]!);
        out += pad(p[2]!);
      }
    return out;
  };
  const data = (fn: string, i: bigint, j: bigint, dirtyC = false) =>
    '0x' + sel(`${fn}((uint256,uint8,uint256)[3][],uint256,uint256)`) + pad(0x60n) + pad(i) + pad(j) + body(dirtyC);

  it('reads each field across a runtime i,j grid (clean)', async () => {
    for (const fn of ['rdA', 'rdC', 'rdB'])
      for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 3n; j++) await eq(`${fn}[${i}][${j}]`, data(fn, i, j));
  });
  it('outer/inner OOB index -> Panic(0x32) parity', async () => {
    for (const fn of ['rdA', 'rdC', 'rdB']) {
      await eq(`${fn} i OOB`, data(fn, 2n, 0n));
      await eq(`${fn} j OOB`, data(fn, 0n, 3n));
      await eq(`${fn} both OOB`, data(fn, 9n, 9n));
    }
  });
  it('dirty packed u8-field word -> lazy-validation revert parity', async () => {
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 3n; j++) await eq(`rdC dirty[${i}][${j}]`, data('rdC', i, j, true));
  });
});

describe('cd-deep-reads (C): xs[i].tags[j] on a calldata S[] (string[] field)', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(JETH_C, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(SPDX + SOL_C, 'C').creation);
  });

  const strBlob = (s: string) => {
    const b = Buffer.from(s, 'utf8');
    const padN = (32 - (b.length % 32)) % 32;
    return pad(BigInt(b.length)) + Buffer.concat([b, Buffer.alloc(padN)]).toString('hex');
  };
  const tagsBlob = (tags: string[]) => {
    const offs: string[] = [];
    let payload = '';
    let cur = tags.length * 32;
    for (const t of tags) {
      offs.push(pad(BigInt(cur)));
      const bb = strBlob(t);
      payload += bb;
      cur += bb.length / 2;
    }
    return pad(BigInt(tags.length)) + offs.join('') + payload;
  };
  const elemBlob = (e: { a: bigint; tags: string[] }) => pad(e.a) + pad(64n) + tagsBlob(e.tags);
  const xs = [
    { a: 1n, tags: ['hello', 'world!!'] },
    { a: 2n, tags: ['', 'this-is-a-much-longer-string-well-over-thirty-two-bytes-yes-indeed'] },
  ];
  const xsData = () => {
    const ebs = xs.map(elemBlob);
    const offs: string[] = [];
    let cur = xs.length * 32;
    for (const eb of ebs) {
      offs.push(pad(BigInt(cur)));
      cur += eb.length / 2;
    }
    return pad(BigInt(xs.length)) + offs.join('') + ebs.join('');
  };
  const readData = (i: bigint, j: bigint) =>
    '0x' + sel('read((uint256,string[])[],uint256,uint256)') + pad(0x60n) + pad(i) + pad(j) + xsData();
  const echoData = (i: bigint) => '0x' + sel('echo((uint256,string[])[],uint256)') + pad(0x40n) + pad(i) + xsData();

  it('reads xs[i].tags[j] across a runtime i,j grid', async () => {
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++) await eq(`read[${i}].tags[${j}]`, readData(i, j));
  });
  it('outer/inner OOB -> Panic(0x32) parity', async () => {
    await eq('read i OOB', readData(2n, 0n));
    await eq('read j OOB', readData(0n, 2n));
    await eq('read both OOB', readData(5n, 5n));
  });
  it('truncated calldata -> EMPTY revert parity', async () => {
    const full = readData(0n, 0n);
    await eq('truncated', full.slice(0, full.length - 64));
  });
  it('echoes the whole xs[i].tags string[] array', async () => {
    for (let i = 0n; i < 2n; i++) await eq(`echo[${i}]`, echoData(i));
    await eq('echo OOB', echoData(2n));
  });
});

describe('cd-deep-reads: deferred sub-cases stay CLEAN rejects (no miscompile)', () => {
  function rejects(src: string): boolean {
    try {
      compile(src, { fileName: 'C.jeth' });
      return false;
    } catch {
      return true;
    }
  }
  it('(B) whole sub-aggregate element read xs[i] now COMPILES (lifted byte-identical, see _lift_cd_aggregate_copy.test.ts)', () => {
    // cd-whole-and-dynstruct-copy LIFT #1: `return xs[i]` for a calldata Arr<P,N>[] / P[][] now decodes the
    // inner sub-array to memory byte-identically to solc (the value/static-struct leaf forms). No longer rejected.
    expect(
      rejects(`@struct class P{a:u256;b:u256;}
@contract class C{@external @pure rd(xs:Arr<P,2>[],i:u256):Arr<P,2>{return xs[i];}}`),
    ).toBe(false);
  });
  // cd-mask-and-whole-encode LIFT: the whole DYNAMIC-ARRAY field value forms are now ACCEPTED byte-
  // identically (return + abi.encode), verified differentially in cd-whole-field-aggregate.test.ts.
  it('(C-deep) whole nested-array field xs[i].grid now COMPILES (lifted byte-identical)', () => {
    expect(
      rejects(`@struct class S{a:u256;grid:u256[][];}
@contract class C{@external @pure rd(xs:S[],i:u256):u256[][]{return xs[i].grid;}}`),
    ).toBe(false);
  });
  it('(C-deep) whole inner array xs[i].grid[j] (value) now COMPILES (lifted byte-identical)', () => {
    expect(
      rejects(`@struct class S{a:u256;grid:u256[][];}
@contract class C{@external @pure rd(xs:S[],i:u256,j:u256):u256[]{return xs[i].grid[j];}}`),
    ).toBe(false);
  });
  it('(C-deep) whole dyn-struct-array field xs[i].items now COMPILES (lifted byte-identical)', () => {
    expect(
      rejects(`@struct class D{v:u256;s:string;}
@struct class S{a:u256;items:D[];}
@contract class C{@external @pure rd(xs:S[],i:u256):D[]{return xs[i].items;}}`),
    ).toBe(false);
  });
  it('(C-deep) whole STRUCT ELEMENT of a struct-array field xs[i].items[j] STAYS a clean reject (deferred; mis-routed codec)', () => {
    // No byte-identical whole-struct-element re-encode codec from a struct-array FIELD element exists yet:
    // the cdStructArrayElem path mis-routes a cdDynArrayField-with-arrayRoot base (wrong bytes + no OOB
    // bounds check). Kept a SOUND clean reject rather than ship a miscompile.
    expect(
      rejects(`@struct class D{v:u256;s:string;}
@struct class S{a:u256;items:D[];}
@contract class C{@external @pure rd(xs:S[],i:u256,j:u256):D{return xs[i].items[j];}}`),
    ).toBe(true);
  });
});
