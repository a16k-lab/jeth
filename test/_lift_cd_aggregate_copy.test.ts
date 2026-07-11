// LIFT cd-whole-and-dynstruct-copy: two over-rejection lifts in the calldata -> memory aggregate
// decode family, proven byte-identical to solc 0.8.35 (honest + malformed calldata):
//   #1 a WHOLE sub-AGGREGATE element read of a calldata array-of-array (return xs[i] where
//      xs: Arr<P,N>[] / P[][] / u256[][] / Arr<u256,N>[]). The element sub-array is re-encoded from
//      its calldata head into a fresh ABI return blob via the recursive calldata codec.
//   #5 a DYNAMIC-STRUCT-element calldata array deep copy (let row: D[] = a; return row[i].<field>)
//      where D has a bytes/string/dynamic-value-array/nested-dynamic-leaf-array field. Each element
//      is decoded into the pointer-headed dyn-struct image a memDynStruct local consumes.
import { describe, it, expect, beforeAll } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (v: bigint | number) => BigInt(v).toString(16).padStart(64, '0');

let h: Harness;
beforeAll(async () => {
  h = await Harness.create();
});

async function pair(jeth: string, sol: string) {
  const aj = await h.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { aj, as };
}
async function callOne(addr: import('@ethereumjs/util').Address, sig: string, cd: string) {
  try {
    const r = await h.call(addr, '0x' + sel(sig) + cd, {});
    return { s: r.success, r: r.returnHex };
  } catch {
    return { s: false, r: 'THROW' };
  }
}
async function expectSame(a: { aj: any; as: any }, sig: string, cd: string) {
  const j = await callOne(a.aj, sig, cd);
  const s = await callOne(a.as, sig, cd);
  expect({ success: j.s, ret: j.r }).toEqual({ success: s.s, ret: s.r });
}

describe('LIFT #1: whole sub-aggregate element of a calldata array-of-array (return xs[i])', () => {
  it('Arr<P,2>[] -> Arr<P,2> (static-struct fixed sub-array, inline)', async () => {
    const a = await pair(
      `type P = { a: u256; b: u256; };
       class C { get f(xs: Arr<P,2>[], i: u256): External<Arr<P,2>> { return xs[i]; } }`,
      `struct P { uint256 a; uint256 b; }
       contract C { function f(P[2][] calldata xs, uint256 i) external pure returns (P[2] memory) { return xs[i]; } }`,
    );
    const xs = W(2) + W(11) + W(12) + W(13) + W(14) + W(21) + W(22) + W(23) + W(24);
    const sig = 'f(P[2][],uint256)';
    for (const i of [0, 1]) await expectSame(a, sig, W(0x40) + W(i) + xs);
    await expectSame(a, sig, W(0x40) + W(5) + xs); // OOB index -> Panic 0x32
    await expectSame(a, sig, W(0x40) + W(0) + W(2) + W(11) + W(12) + W(13) + W(14)); // truncated tail
  });

  it('P[][] -> P[] (dynamic static-struct sub-array, [0x20] wrapper)', async () => {
    const a = await pair(
      `type P = { a: u256; b: u256; };
       class C { get f(xs: P[][], i: u256): External<P[]> { return xs[i]; } }`,
      `struct P { uint256 a; uint256 b; }
       contract C { function f(P[][] calldata xs, uint256 i) external pure returns (P[] memory) { return xs[i]; } }`,
    );
    const E0 = W(2) + W(11) + W(12) + W(13) + W(14);
    const E1 = W(1) + W(99) + W(98);
    const off0 = 0x40;
    const off1 = off0 + E0.length / 2;
    const xs = W(2) + W(off0) + W(off1) + E0 + E1;
    const sig = 'f(P[][],uint256)';
    for (const i of [0, 1]) await expectSame(a, sig, W(0x40) + W(i) + xs);
    await expectSame(a, sig, W(0x40) + W(9) + xs); // OOB
    const pad = W(0).repeat(40);
    await expectSame(a, sig, W(0x40) + W(0) + W(1) + W(0x20) + W(2n ** 64n) + pad); // oversized inner len -> empty revert
    await expectSame(a, sig, W(0x40) + W(0) + W(1) + W(0xfffff)); // inner offset OOB -> empty revert
  });

  it('u256[][] -> u256[] (value-leaf), oversized inner len empty-reverts (not Panic 0x41)', async () => {
    const a = await pair(
      `class C { get f(xs: u256[][], i: u256): External<u256[]> { return xs[i]; } }`,
      `contract C { function f(uint256[][] calldata xs, uint256 i) external pure returns (uint256[] memory) { return xs[i]; } }`,
    );
    const E0 = W(3) + W(1) + W(2) + W(3);
    const E1 = W(2) + W(7) + W(8);
    const off0 = 0x40;
    const off1 = off0 + E0.length / 2;
    const xs = W(2) + W(off0) + W(off1) + E0 + E1;
    const sig = 'f(uint256[][],uint256)';
    for (const i of [0, 1]) await expectSame(a, sig, W(0x40) + W(i) + xs);
    const pad = W(0).repeat(40);
    await expectSame(a, sig, W(0x40) + W(0) + W(1) + W(0x20) + W(2n ** 64n) + pad); // empty revert
  });

  it('Arr<u256,3>[] -> Arr<u256,3> (value-fixed leaf, inline)', async () => {
    const a = await pair(
      `class C { get f(xs: Arr<u256,3>[], i: u256): External<Arr<u256,3>> { return xs[i]; } }`,
      `contract C { function f(uint256[3][] calldata xs, uint256 i) external pure returns (uint256[3] memory) { return xs[i]; } }`,
    );
    const xs = W(2) + W(1) + W(2) + W(3) + W(4) + W(5) + W(6);
    const sig = 'f(uint256[3][],uint256)';
    for (const i of [0, 1]) await expectSame(a, sig, W(0x40) + W(i) + xs);
    await expectSame(a, sig, W(0x40) + W(4) + xs); // OOB
  });

  it('deeper nesting: u256[][][] and P[][][] return xs[i]', async () => {
    const av = await pair(
      `class C { get f(xs: u256[][][], i: u256): External<u256[][]> { return xs[i]; } }`,
      `contract C { function f(uint256[][][] calldata xs, uint256 i) external pure returns (uint256[][] memory) { return xs[i]; } }`,
    );
    {
      const A = W(2) + W(7) + W(8);
      const B = W(1) + W(42);
      const offA = 0x40;
      const offB = offA + A.length / 2;
      const E0 = W(2) + W(offA) + W(offB) + A + B;
      await expectSame(av, 'f(uint256[][][],uint256)', W(0x40) + W(0) + W(1) + W(0x20) + E0);
    }
    const ap = await pair(
      `type P = { a: u256; b: u256; };
       class C { get f(xs: P[][][], i: u256): External<P[][]> { return xs[i]; } }`,
      `struct P { uint256 a; uint256 b; }
       contract C { function f(P[][][] calldata xs, uint256 i) external pure returns (P[][] memory) { return xs[i]; } }`,
    );
    {
      const A = W(2) + W(1) + W(2) + W(3) + W(4);
      const B = W(1) + W(9) + W(8);
      const offA = 0x40;
      const offB = offA + A.length / 2;
      const E0 = W(2) + W(offA) + W(offB) + A + B;
      await expectSame(ap, 'f(P[][][],uint256)', W(0x40) + W(0) + W(1) + W(0x20) + E0);
    }
  });

  it('whole bytes[][] element (return xs[i] -> bytes[]) is byte-identical', async () => {
    const ap = await pair(
      `class C { get f(xs: bytes[][], i: u256): External<bytes[]> { return xs[i]; } }`,
      `contract C { function f(bytes[][] calldata xs, uint256 i) external pure returns (bytes[] memory) { return xs[i]; } }`,
    );
    // outer offset table for 2 inner bytes[]; inner0 = ["hi", 40-byte], inner1 = []
    const blob = (s: string) => {
      const hex = Buffer.from(s, 'utf8').toString('hex');
      const padded = hex.length ? hex.padEnd(Math.ceil(hex.length / 64) * 64, '0') : '';
      return W(s.length) + padded;
    };
    const arrTab = (items: string[]) => {
      let off = items.length * 32;
      const offs: number[] = [];
      for (const it of items) {
        offs.push(off);
        off += it.length / 2;
      }
      return W(items.length) + offs.map((o) => W(o)).join('') + items.join('');
    };
    const inner0 = arrTab([blob('hi'), blob('this-string-is-definitely-longer-than-32b')]);
    const inner1 = arrTab([]);
    const xs = arrTab([inner0, inner1]);
    await expectSame(ap, 'f(bytes[][],uint256)', W(0x40) + W(0) + xs);
    await expectSame(ap, 'f(bytes[][],uint256)', W(0x40) + W(1) + xs);
    await expectSame(ap, 'f(bytes[][],uint256)', W(0x40) + W(2) + xs); // OOB -> Panic 0x32
  });

  it('whole D[][] element (return xs[i] -> D[], D dynamic) is byte-identical', async () => {
    const ap = await pair(
      `type D = {a:u256;b:bytes;}; class C { get f(xs: D[][], i: u256): External<D[]> { return xs[i]; } }`,
      `struct D{uint256 a;bytes b;} contract C { function f(D[][] calldata xs, uint256 i) external pure returns (D[] memory) { return xs[i]; } }`,
    );
    const dynD = (a: number, s: string) => {
      const hex = Buffer.from(s, 'utf8').toString('hex');
      const padded = hex.length ? hex.padEnd(Math.ceil(hex.length / 64) * 64, '0') : '';
      return W(a) + W(0x40) + W(s.length) + padded;
    };
    const arrTab = (items: string[]) => {
      let off = items.length * 32;
      const offs: number[] = [];
      for (const it of items) {
        offs.push(off);
        off += it.length / 2;
      }
      return W(items.length) + offs.map((o) => W(o)).join('') + items.join('');
    };
    const inner0 = arrTab([dynD(1, 'abc'), dynD(2, 'a-string-that-spans-more-than-thirty-two-bytes')]);
    const inner1 = arrTab([dynD(3, '')]);
    const xs = arrTab([inner0, inner1]);
    await expectSame(ap, 'f((uint256,bytes)[][],uint256)', W(0x40) + W(0) + xs);
    await expectSame(ap, 'f((uint256,bytes)[][],uint256)', W(0x40) + W(1) + xs);
    await expectSame(ap, 'f((uint256,bytes)[][],uint256)', W(0x40) + W(2) + xs); // OOB -> Panic 0x32
  });
});

describe('LIFT #5: dynamic-struct-element calldata array deep copy (let row: D[] = a)', () => {
  // D{a:u256; xs:u256[]; b:bytes}: a value field, a dynamic value-array field, a bytes field.
  const J = `type D = { a:u256; xs:u256[]; b:bytes; };
    class C{
      get f1(a:D[], i:u256):External<u256>{ let row:D[]=a; return row[i].a; }
      get f2(a:D[], i:u256, j:u256):External<u256>{ let row:D[]=a; return row[i].xs[j]; }
      get f3(a:D[], i:u256):External<bytes>{ let row:D[]=a; return row[i].b; }
    }`;
  const S = `struct D{ uint256 a; uint256[] xs; bytes b; }
    contract C{
      function f1(D[] calldata a, uint256 i) external pure returns(uint256){ D[] memory row=a; return row[i].a; }
      function f2(D[] calldata a, uint256 i, uint256 j) external pure returns(uint256){ D[] memory row=a; return row[i].xs[j]; }
      function f3(D[] calldata a, uint256 i) external pure returns(bytes memory){ D[] memory row=a; return row[i].b; }
    }`;

  function encBytes(hex: string) {
    const b = hex.length / 2;
    const p = Math.ceil(b / 32) * 32;
    return W(b) + hex.padEnd(p * 2, '0');
  }
  function encD(a: number, xs: number[], bhex: string) {
    const xsTail = W(xs.length) + xs.map((v) => W(v)).join('');
    const bTail = encBytes(bhex);
    return W(a) + W(3 * 32) + W(3 * 32 + xsTail.length / 2) + xsTail + bTail;
  }
  function buildA(elems: { a: number; xs: number[]; b: string }[], head: string) {
    const blobs = elems.map((e) => encD(e.a, e.xs, e.b));
    let table = '';
    let cur = elems.length * 32;
    for (const b of blobs) {
      table += W(cur);
      cur += b.length / 2;
    }
    return head + W(elems.length) + table + blobs.join('');
  }
  const elems = [
    { a: 5, xs: [10, 20, 30], b: 'aabb' },
    { a: 7, xs: [99], b: 'ccddeeff' },
  ];

  it('honest reads of every field shape + runtime index', async () => {
    const a = await pair(J, S);
    for (const i of [0, 1]) await expectSame(a, 'f1(D[],uint256)', buildA(elems, W(0x40) + W(i)));
    for (const [i, j] of [
      [0, 0],
      [0, 2],
      [1, 0],
    ] as [number, number][])
      await expectSame(a, 'f2(D[],uint256,uint256)', buildA(elems, W(0x60) + W(i) + W(j)));
    for (const i of [0, 1]) await expectSame(a, 'f3(D[],uint256)', buildA(elems, W(0x40) + W(i)));
  });

  it('OOB element + OOB inner index revert byte-identically', async () => {
    const a = await pair(J, S);
    await expectSame(a, 'f1(D[],uint256)', buildA(elems, W(0x40) + W(9)));
    await expectSame(a, 'f2(D[],uint256,uint256)', buildA(elems, W(0x60) + W(0) + W(9)));
  });

  it('malformed calldata: oversized inner length -> Panic 0x41; truncated/OOB -> empty revert', async () => {
    const a = await pair(
      `type D = {a:u256;b:bytes;}; class C{ get f(a:D[], i:u256):External<u256>{ let row:D[]=a; return row[i].a; } }`,
      `struct D{uint256 a;bytes b;} contract C{ function f(D[] calldata a, uint256 i) external pure returns(uint256){ D[] memory row=a; return row[i].a; } }`,
    );
    const sig = 'f(D[],uint256)';
    // oversized bytes length inside an element -> Panic 0x41 (calldata->memory copy alloc cap)
    await expectSame(a, sig, W(0x40) + W(0) + W(1) + W(0x20) + W(7) + W(0x40) + W(2n ** 64n) + W(0));
    // truncated tail (field offset beyond calldatasize) -> empty revert
    await expectSame(a, sig, W(0x40) + W(0) + W(1) + W(0x20) + W(7) + W(0xfffff));
    // oversized array length -> Panic 0x41
    await expectSame(a, sig, W(0x40) + W(0) + W(2n ** 64n) + W(0x20));
    // element offset OOB -> empty revert
    await expectSame(a, sig, W(0x40) + W(0) + W(1) + W(0xffffff));
  });

  it('dyn-struct with a bytes[] leaf-array field (Cat-C field codec)', async () => {
    const a = await pair(
      `type D = { a:u256; tags:bytes[]; };
       class C{ get f(a:D[], i:u256, j:u256):External<bytes>{ let row:D[]=a; return row[i].tags[j]; }
         get g(a:D[], i:u256):External<u256>{ let row:D[]=a; return row[i].a; } }`,
      `struct D{ uint256 a; bytes[] tags; }
       contract C{ function f(D[] calldata a, uint256 i, uint256 j) external pure returns(bytes memory){ D[] memory row=a; return row[i].tags[j]; }
         function g(D[] calldata a, uint256 i) external pure returns(uint256){ D[] memory row=a; return row[i].a; } }`,
    );
    function encBytesArr(arr: string[]) {
      const blobs = arr.map(encBytes);
      let table = '';
      let cur = arr.length * 32;
      for (const b of blobs) {
        table += W(cur);
        cur += b.length / 2;
      }
      return W(arr.length) + table + blobs.join('');
    }
    function encD2(av: number, tags: string[]) {
      return W(av) + W(0x40) + encBytesArr(tags);
    }
    function buildA2(es: { a: number; tags: string[] }[], head: string) {
      const blobs = es.map((e) => encD2(e.a, e.tags));
      let table = '';
      let cur = es.length * 32;
      for (const b of blobs) {
        table += W(cur);
        cur += b.length / 2;
      }
      return head + W(es.length) + table + blobs.join('');
    }
    const es = [
      { a: 1, tags: ['aa', 'bbbb'] },
      { a: 2, tags: ['cc'] },
    ];
    for (const [i, j] of [
      [0, 0],
      [0, 1],
      [1, 0],
    ] as [number, number][])
      await expectSame(a, 'f(D[],uint256,uint256)', buildA2(es, W(0x60) + W(i) + W(j)));
    for (const i of [0, 1]) await expectSame(a, 'g(D[],uint256)', buildA2(es, W(0x40) + W(i)));
  });
});
