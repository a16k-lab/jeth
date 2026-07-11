// Cluster of 3 STORAGE dynamic-struct-ARRAY over-rejections, lifted byte-identical to solc 0.8.35.
// D = { id: u256; tags: bytes[] } (a dyn-field struct whose field is a NESTED-DYNAMIC-LEAF array).
//   #1 WHOLE-ARRAY COPY storage->memory: let row: D[] = this.vals; row[i].id / row.length / return row /
//      abi.encode(row). Deep copy via abiDecFromStorageToImage (the storage twin); mutating row does NOT
//      write through to storage (non-aliasing), matching solc.
//   #3 DEEP ELEMENT-FIELD READS: this.vals[i].tags (whole bytes[]), this.vals[i].tags[j] (a bytes elem),
//      this.vals[i].tags.length. Materialize the element image (buildDynStructFromStorage on the element
//      slot), read .tags off it. OOB -> Panic 0x32.
//   #4 WHOLE-ELEMENT INDEX-ASSIGN: this.vals[i] = D(9n, t2). Deep-copy the RHS image into the element slot
//      (the same writeDynStructFromMem deep-copy push() uses). Re-read + later push see fresh data; OOB
//      -> Panic 0x32.
// Also exercises string[] and u256[][] leaf-field variants. Regression guards confirm static P[],
// single-bytes-field D[], single struct, and the whole-array return/encode (commit 19aa9a1) are unchanged.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => pad32(n).replace(/^0x/, '');
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};

async function diff(J: string, S: string, calls: [string, string?][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, args] of calls) {
    const data = sel(sg) + (args ?? '');
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sg + ' success').toBe(rs.success);
    expect(rj.returnHex, sg + ' returnHex').toBe(rs.returnHex);
  }
}

describe('storage dyn-struct-array cluster (#1 copy / #3 deep field read / #4 element assign) byte-identical', () => {
  it('#1 whole-array copy storage->memory (read back, length, return, abi.encode) + NON-ALIASING', async () => {
    const J = `type D = { id: u256; tags: bytes[]; };
    class C { vals: D[];
      seed(): External<void> { let a: bytes[] = [bytes("aa"), bytes("bb")]; this.vals.push(D(1n, a)); let b: bytes[] = [bytes("ccc")]; this.vals.push(D(2n, b)); }
      get rowId(i: u256): External<u256> { let row: D[] = this.vals; return row[i].id; }
      get rowLen(): External<u256> { let row: D[] = this.vals; return row.length; }
      get rowTag(i: u256, j: u256): External<bytes> { let row: D[] = this.vals; return row[i].tags[j]; }
      get retRow(): External<D[]> { let row: D[] = this.vals; return row; }
      get encRow(): External<bytes> { let row: D[] = this.vals; return abi.encode(row); }
      get mutate(): External<u256> { let row: D[] = this.vals; row[0n].id = 999n; return this.vals[0n].id; } }`;
    const S = `struct D { uint256 id; bytes[] tags; }
    contract C { D[] vals;
      function seed() external { bytes[] memory a=new bytes[](2); a[0]="aa"; a[1]="bb"; vals.push(D(1,a)); bytes[] memory b=new bytes[](1); b[0]="ccc"; vals.push(D(2,b)); }
      function rowId(uint256 i) external view returns (uint256) { D[] memory row=vals; return row[i].id; }
      function rowLen() external view returns (uint256) { D[] memory row=vals; return row.length; }
      function rowTag(uint256 i, uint256 j) external view returns (bytes memory) { D[] memory row=vals; return row[i].tags[j]; }
      function retRow() external view returns (D[] memory) { D[] memory row=vals; return row; }
      function encRow() external view returns (bytes memory) { D[] memory row=vals; return abi.encode(row); }
      function mutate() external returns (uint256) { D[] memory row=vals; row[0].id=999; return vals[0].id; } }`;
    await diff(J, S, [
      ['seed()'],
      ['rowId(uint256)', W(0n)],
      ['rowId(uint256)', W(1n)],
      ['rowLen()'],
      ['rowTag(uint256,uint256)', W(0n) + W(1n)],
      ['retRow()'],
      ['encRow()'],
      ['mutate()'], // non-aliasing: storage[0].id stays 1, not 999
      ['rowId(uint256)', W(0n)],
    ]);
  });

  it('#3 deep element-field reads: vals[i].tags / vals[i].tags[j] / vals[i].tags.length + OOB Panic', async () => {
    const J = `type D = { id: u256; tags: bytes[]; };
    class C { vals: D[];
      seed(): External<void> { let a: bytes[] = [bytes("aa"), bytes("a-leaf-well-past-thirty-two-bytes-boundary!!")]; this.vals.push(D(1n, a)); let b: bytes[] = [bytes("z")]; this.vals.push(D(2n, b)); }
      get whole(i: u256): External<bytes[]> { return this.vals[i].tags; }
      get one(i: u256, j: u256): External<bytes> { return this.vals[i].tags[j]; }
      get len(i: u256): External<u256> { return this.vals[i].tags.length; } }`;
    const S = `struct D { uint256 id; bytes[] tags; }
    contract C { D[] vals;
      function seed() external { bytes[] memory a=new bytes[](2); a[0]="aa"; a[1]="a-leaf-well-past-thirty-two-bytes-boundary!!"; vals.push(D(1,a)); bytes[] memory b=new bytes[](1); b[0]="z"; vals.push(D(2,b)); }
      function whole(uint256 i) external view returns (bytes[] memory) { return vals[i].tags; }
      function one(uint256 i, uint256 j) external view returns (bytes memory) { return vals[i].tags[j]; }
      function len(uint256 i) external view returns (uint256) { return vals[i].tags.length; } }`;
    await diff(J, S, [
      ['seed()'],
      ['whole(uint256)', W(0n)],
      ['whole(uint256)', W(1n)],
      ['one(uint256,uint256)', W(0n) + W(0n)],
      ['one(uint256,uint256)', W(0n) + W(1n)],
      ['len(uint256)', W(0n)],
      ['len(uint256)', W(1n)],
      // OOB on outer i (Panic 0x32)
      ['whole(uint256)', W(5n)],
      ['len(uint256)', W(9n)],
      ['one(uint256,uint256)', W(5n) + W(0n)],
      // OOB on inner j (Panic 0x32)
      ['one(uint256,uint256)', W(0n) + W(7n)],
      ['one(uint256,uint256)', W(1n) + W(3n)],
    ]);
  });

  it('#4 whole-element index-assign this.vals[i]=D(9n,t2): re-read + later push + OOB Panic', async () => {
    const J = `type D = { id: u256; tags: bytes[]; };
    class C { vals: D[];
      seed(): External<void> { let a: bytes[] = [bytes("aa"), bytes("bb")]; this.vals.push(D(1n, a)); let b: bytes[] = [bytes("ccc")]; this.vals.push(D(2n, b)); }
      put(i: u256): External<void> { let t: bytes[] = [bytes("NEW-overwrites-the-old-element-data-here!!"), bytes("x")]; this.vals[i] = D(9n, t); }
      push3(): External<void> { let c: bytes[] = [bytes("third")]; this.vals.push(D(3n, c)); }
      get getAll(): External<D[]> { return this.vals; }
      get getOne(i: u256): External<D> { return this.vals[i]; } }`;
    const S = `struct D { uint256 id; bytes[] tags; }
    contract C { D[] vals;
      function seed() external { bytes[] memory a=new bytes[](2); a[0]="aa"; a[1]="bb"; vals.push(D(1,a)); bytes[] memory b=new bytes[](1); b[0]="ccc"; vals.push(D(2,b)); }
      function put(uint256 i) external { bytes[] memory t=new bytes[](2); t[0]="NEW-overwrites-the-old-element-data-here!!"; t[1]="x"; vals[i]=D(9,t); }
      function push3() external { bytes[] memory c=new bytes[](1); c[0]="third"; vals.push(D(3,c)); }
      function getAll() external view returns (D[] memory) { return vals; }
      function getOne(uint256 i) external view returns (D memory) { return vals[i]; } }`;
    await diff(J, S, [
      ['seed()'],
      ['put(uint256)', W(0n)],
      ['getOne(uint256)', W(0n)],
      ['getOne(uint256)', W(1n)], // unchanged
      ['push3()'], // a later push sees no stale data
      ['getAll()'],
      ['put(uint256)', W(1n)],
      ['getAll()'],
      // OOB index-assign -> Panic 0x32
      ['put(uint256)', W(9n)],
    ]);
  });

  it('string[] + u256[][] leaf-field variants for #1/#3/#4', async () => {
    const J = `type D = { id: u256; names: string[]; grid: u256[][]; };
    class C { vals: D[];
      seed(): External<void> {
        let n: string[] = ["hi", "world-longer-than-thirty-two-bytes-for-sure!"]; let r0: u256[] = [1n, 2n]; let r1: u256[] = [3n]; let g: u256[][] = [r0, r1];
        this.vals.push(D(1n, n, g));
      }
      get rowNames(i: u256): External<string[]> { let row: D[] = this.vals; return row[i].names; }
      get eltGrid(i: u256): External<u256[][]> { return this.vals[i].grid; }
      get eltName(i: u256, j: u256): External<string> { return this.vals[i].names[j]; }
      put(i: u256): External<void> { let n2: string[] = ["replaced"]; let g2: u256[][] = []; this.vals[i] = D(7n, n2, g2); }
      get getOne(i: u256): External<D> { return this.vals[i]; } }`;
    const S = `struct D { uint256 id; string[] names; uint256[][] grid; }
    contract C { D[] vals;
      function seed() external {
        string[] memory n=new string[](2); n[0]="hi"; n[1]="world-longer-than-thirty-two-bytes-for-sure!"; uint256[][] memory g=new uint256[][](2); g[0]=new uint256[](2); g[0][0]=1; g[0][1]=2; g[1]=new uint256[](1); g[1][0]=3;
        vals.push(D(1,n,g));
      }
      function rowNames(uint256 i) external view returns (string[] memory) { D[] memory row=vals; return row[i].names; }
      function eltGrid(uint256 i) external view returns (uint256[][] memory) { return vals[i].grid; }
      function eltName(uint256 i, uint256 j) external view returns (string memory) { return vals[i].names[j]; }
      function put(uint256 i) external { string[] memory n2=new string[](1); n2[0]="replaced"; uint256[][] memory g2=new uint256[][](0); vals[i]=D(7,n2,g2); }
      function getOne(uint256 i) external view returns (D memory) { return vals[i]; } }`;
    await diff(J, S, [
      ['seed()'],
      ['rowNames(uint256)', W(0n)],
      ['eltGrid(uint256)', W(0n)],
      ['eltName(uint256,uint256)', W(0n) + W(1n)],
      ['put(uint256)', W(0n)],
      ['getOne(uint256)', W(0n)],
    ]);
  });

  it('REGRESSION GUARD: static P[], single-bytes-field D[], single struct, whole-array return/encode unchanged', async () => {
    await diff(
      `type P = { a: u256; b: u256; };
       class C { vals: P[];
         seed(): External<void> { this.vals.push(P(1n, 2n)); this.vals.push(P(3n, 4n)); }
         get getAll(): External<P[]> { return this.vals; }
         get cpy(): External<P[]> { let r: P[] = this.vals; return r; } }`,
      `struct P { uint256 a; uint256 b; }
       contract C { P[] vals;
         function seed() external { vals.push(P(1,2)); vals.push(P(3,4)); }
         function getAll() external view returns (P[] memory) { return vals; }
         function cpy() external view returns (P[] memory) { P[] memory r=vals; return r; } }`,
      [['seed()'], ['getAll()'], ['cpy()']],
    );
    await diff(
      `type D = { id: u256; s: bytes; };
       class C { vals: D[];
         seed(): External<void> { this.vals.push(D(1n, bytes("hi"))); this.vals.push(D(2n, bytes("world!"))); }
         get getAll(): External<D[]> { return this.vals; }
         get cpy(): External<D[]> { let r: D[] = this.vals; return r; }
         get encV(): External<bytes> { return abi.encode(this.vals); } }`,
      `struct D { uint256 id; bytes s; }
       contract C { D[] vals;
         function seed() external { vals.push(D(1,"hi")); vals.push(D(2,"world!")); }
         function getAll() external view returns (D[] memory) { return vals; }
         function cpy() external view returns (D[] memory) { D[] memory r=vals; return r; }
         function encV() external view returns (bytes memory) { return abi.encode(vals); } }`,
      [['seed()'], ['getAll()'], ['cpy()'], ['encV()']],
    );
  });

  it('#4 element-assign with a STORAGE leaf-array source (this.vals[i]=D(9n,this.tpl)) byte-identical', async () => {
    const J = `type D = { id: u256; tags: bytes[]; };
    class C { vals: D[]; tpl: bytes[];
      seed(): External<void> { let a: bytes[] = [bytes("aa"), bytes("bb")]; this.vals.push(D(1n, a)); this.tpl.push(bytes("TEMPLATE-leaf-bytes-longer-than-32-here!!")); this.tpl.push(bytes("q")); }
      put(i: u256): External<void> { this.vals[i] = D(9n, this.tpl); }
      get getOne(i: u256): External<D> { return this.vals[i]; } }`;
    const S = `struct D { uint256 id; bytes[] tags; }
    contract C { D[] vals; bytes[] tpl;
      function seed() external { bytes[] memory a=new bytes[](2); a[0]="aa"; a[1]="bb"; vals.push(D(1,a)); tpl.push("TEMPLATE-leaf-bytes-longer-than-32-here!!"); tpl.push("q"); }
      function put(uint256 i) external { vals[i]=D(9,tpl); }
      function getOne(uint256 i) external view returns (D memory) { return vals[i]; } }`;
    await diff(J, S, [['seed()'], ['put(uint256)', W(0n)], ['getOne(uint256)', W(0n)]]);
  });

  it('SOUNDNESS: a CALLDATA leaf-array source for the element constructor cleanly rejects (no crash)', () => {
    // this.vals[i] = D(9n, t) where t is a CALLDATA bytes[] would FLATTEN the leaf field (wrong bytes), so
    // it stays a clean reject (JETH900), exactly like vals.push(D(9n, <calldata bytes[]>)).
    const src = `type D = { id: u256; tags: bytes[]; };
      class C { vals: D[]; set(i: u256, t: bytes[]): External<void> { this.vals[i] = D(9n, t); } }`;
    expect(codes(src)).toContain('JETH900');
    // a struct-element (D[]) field of an outer struct constructed whole into storage still cleanly rejects.
    const src2 = `type D = { id: u256; tags: bytes[]; };
      type Outer = { tag: u256; ds: D[]; };
      class C { vals: Outer[]; set(i: u256): External<void> { this.vals[i] = Outer(1n, this.vals[0n].ds); } }`;
    expect(codes(src2).length).toBeGreaterThan(0);
  });
});
