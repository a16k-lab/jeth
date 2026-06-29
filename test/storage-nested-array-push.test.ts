// Storage push of a WHOLE array whose element is itself a DYNAMIC array:
//   (A) string[][].push(string[]) / bytes[][].push(bytes[])  - push a string[]/bytes[] element.
//   (B) u256[][][].push(u256[][])                            - push a value-array-of-arrays element.
// solc materializes the pushed value as a pointer-headed memory image then deep-copies it element by
// element into the freshly-grown storage element, recursing for each inner dynamic array (each inner
// array gets its own keccak-located storage data region). JETH now does the same recursive memory-
// image -> storage deep copy (copyMemAggArrayIntoStorage). Covers the array-literal push, the local-
// variable push, a 2nd push, and pop + reuse (stale slot, no resurfacing). Byte-identical to solc
// 0.8.35: every storage value is read back via JETH and compared to solc's own getters.
import { describe, it, expect, beforeAll } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);

// Deploy a JETH program and the matching solc program, run a shared call script against both, and
// assert every call agrees on {success, returnHex}. Mutating calls (set/reuse) seed identical state.
async function bothMatch(jeth: string, solc: string, calls: [string, string?][]): Promise<void> {
  const jbc = compile(jeth, { fileName: 'C.jeth' }).creationBytecode;
  const scr = compileSolidity(SPDX + solc, 'C').creation;
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jbc);
  const as = await hs.deploy(scr);
  for (const [sig, args] of calls) {
    const data = '0x' + sel(sig) + (args ?? '');
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `success ${sig} ${args ?? ''}`).toBe(rs.success);
    expect(rj.returnHex, `return ${sig} ${args ?? ''}`).toBe(rs.returnHex);
  }
}

describe('storage push of a whole nested-dynamic-array element', () => {
  it('A: string[][].push(string[]) - local push + literal push + read back', async () => {
    const J = `@contract class C {
      @state a: string[][];
      @external set(): void {
        let row: string[] = ["hello", "world"];
        this.a.push(row);
        this.a.push(["x", "yy", "this-is-a-fairly-long-string-exceeding-thirty-two-bytes-ok"]);
      }
      @external outer(): u256 { return this.a.length; }
      @external leni(i: u256): u256 { return this.a[i].length; }
      @external get(i: u256, j: u256): string { return this.a[i][j]; }
    }`;
    const S = `contract C {
      string[][] a;
      function set() external {
        string[] memory row = new string[](2); row[0]="hello"; row[1]="world";
        a.push(row);
        string[] memory r2 = new string[](3); r2[0]="x"; r2[1]="yy"; r2[2]="this-is-a-fairly-long-string-exceeding-thirty-two-bytes-ok";
        a.push(r2);
      }
      function outer() external view returns(uint){ return a.length; }
      function leni(uint i) external view returns(uint){ return a[i].length; }
      function get(uint i, uint j) external view returns(string memory){ return a[i][j]; }
    }`;
    await bothMatch(J, S, [
      ['set()'], ['outer()'],
      ['leni(uint256)', pad32(0n)], ['leni(uint256)', pad32(1n)],
      ['get(uint256,uint256)', pad32(0n) + pad32(0n)], ['get(uint256,uint256)', pad32(0n) + pad32(1n)],
      ['get(uint256,uint256)', pad32(1n) + pad32(0n)], ['get(uint256,uint256)', pad32(1n) + pad32(1n)],
      ['get(uint256,uint256)', pad32(1n) + pad32(2n)],
    ]);
  });

  it('B: bytes[][].push(bytes[]) + pop + reuse (stale slot, shorter inner)', async () => {
    const J = `@contract class C {
      @state a: bytes[][];
      @external set(): void {
        let row: bytes[] = [bytes("aaaa"), bytes("this-long-bytes-blob-is-clearly-over-thirty-two-bytes-yes")];
        this.a.push(row);
      }
      @external reuse(): void { this.a.pop(); this.a.push([bytes("z")]); }
      @external outer(): u256 { return this.a.length; }
      @external leni(i: u256): u256 { return this.a[i].length; }
      @external get(i: u256, j: u256): bytes { return this.a[i][j]; }
    }`;
    const S = `contract C {
      bytes[][] a;
      function set() external {
        bytes[] memory row = new bytes[](2);
        row[0]=bytes("aaaa"); row[1]=bytes("this-long-bytes-blob-is-clearly-over-thirty-two-bytes-yes");
        a.push(row);
      }
      function reuse() external { a.pop(); bytes[] memory r=new bytes[](1); r[0]=bytes("z"); a.push(r); }
      function outer() external view returns(uint){ return a.length; }
      function leni(uint i) external view returns(uint){ return a[i].length; }
      function get(uint i, uint j) external view returns(bytes memory){ return a[i][j]; }
    }`;
    await bothMatch(J, S, [
      ['set()'], ['outer()'], ['leni(uint256)', pad32(0n)],
      ['get(uint256,uint256)', pad32(0n) + pad32(0n)], ['get(uint256,uint256)', pad32(0n) + pad32(1n)],
      ['reuse()'], ['outer()'], ['leni(uint256)', pad32(0n)],
      ['get(uint256,uint256)', pad32(0n) + pad32(0n)],
    ]);
  });

  it('C: u256[][][].push(u256[][]) - local push + literal push', async () => {
    const J = `@contract class C {
      @state a: u256[][][];
      @external set(): void {
        let m: u256[][] = [[1n, 2n], [3n, 4n, 5n]];
        this.a.push(m);
        this.a.push([[9n]]);
      }
      @external outer(): u256 { return this.a.length; }
      @external lenj(i: u256): u256 { return this.a[i].length; }
      @external lenk(i: u256, j: u256): u256 { return this.a[i][j].length; }
      @external get(i: u256, j: u256, k: u256): u256 { return this.a[i][j][k]; }
    }`;
    const S = `contract C {
      uint256[][][] a;
      function set() external {
        uint256[][] memory m = new uint256[][](2);
        m[0]=new uint256[](2); m[0][0]=1; m[0][1]=2;
        m[1]=new uint256[](3); m[1][0]=3; m[1][1]=4; m[1][2]=5;
        a.push(m);
        uint256[][] memory n = new uint256[][](1); n[0]=new uint256[](1); n[0][0]=9;
        a.push(n);
      }
      function outer() external view returns(uint){ return a.length; }
      function lenj(uint i) external view returns(uint){ return a[i].length; }
      function lenk(uint i, uint j) external view returns(uint){ return a[i][j].length; }
      function get(uint i, uint j, uint k) external view returns(uint){ return a[i][j][k]; }
    }`;
    await bothMatch(J, S, [
      ['set()'], ['outer()'], ['lenj(uint256)', pad32(0n)], ['lenj(uint256)', pad32(1n)],
      ['lenk(uint256,uint256)', pad32(0n) + pad32(0n)], ['lenk(uint256,uint256)', pad32(0n) + pad32(1n)],
      ['lenk(uint256,uint256)', pad32(1n) + pad32(0n)],
      ['get(uint256,uint256,uint256)', pad32(0n) + pad32(0n) + pad32(0n)],
      ['get(uint256,uint256,uint256)', pad32(0n) + pad32(1n) + pad32(2n)],
      ['get(uint256,uint256,uint256)', pad32(1n) + pad32(0n) + pad32(0n)],
    ]);
  });

  it('D: u256[][][] pop + reuse with shorter element (deep stale clear)', async () => {
    const J = `@contract class C {
      @state a: u256[][][];
      @external seedBig(): void { this.a.push([[111n, 222n, 333n], [444n, 555n]]); }
      @external reuse(): void { this.a.pop(); this.a.push([[7n]]); }
      @external outer(): u256 { return this.a.length; }
      @external lenj(i: u256): u256 { return this.a[i].length; }
      @external lenk(i: u256, j: u256): u256 { return this.a[i][j].length; }
      @external get(i: u256, j: u256, k: u256): u256 { return this.a[i][j][k]; }
    }`;
    const S = `contract C {
      uint256[][][] a;
      function seedBig() external {
        uint256[][] memory m=new uint256[][](2);
        m[0]=new uint256[](3); m[0][0]=111; m[0][1]=222; m[0][2]=333;
        m[1]=new uint256[](2); m[1][0]=444; m[1][1]=555;
        a.push(m);
      }
      function reuse() external { a.pop(); uint256[][] memory n=new uint256[][](1); n[0]=new uint256[](1); n[0][0]=7; a.push(n); }
      function outer() external view returns(uint){ return a.length; }
      function lenj(uint i) external view returns(uint){ return a[i].length; }
      function lenk(uint i, uint j) external view returns(uint){ return a[i][j].length; }
      function get(uint i, uint j, uint k) external view returns(uint){ return a[i][j][k]; }
    }`;
    await bothMatch(J, S, [
      ['seedBig()'], ['reuse()'], ['outer()'], ['lenj(uint256)', pad32(0n)],
      ['lenk(uint256,uint256)', pad32(0n) + pad32(0n)],
      ['get(uint256,uint256,uint256)', pad32(0n) + pad32(0n) + pad32(0n)],
    ]);
  });

  it('E: string[][].push of an empty inner array (via new Array<string>(0n))', async () => {
    // NOTE: a BARE empty array literal push `this.a.push([])` is now correctly REJECTED (solc rejects it too -
    // it cannot deduce the empty literal's type in push-arg position; see _push_empty_literal.test.ts). The
    // valid way to push an empty inner array is `new Array<string>(0n)` (== solc `new string[](0)`), tested here.
    const J = `@contract class C {
      @state a: string[][];
      @external set(): void { let e: string[] = new Array<string>(0n); this.a.push(e); this.a.push(["only"]); }
      @external outer(): u256 { return this.a.length; }
      @external leni(i: u256): u256 { return this.a[i].length; }
      @external get(i: u256, j: u256): string { return this.a[i][j]; }
    }`;
    const S = `contract C {
      string[][] a;
      function set() external { string[] memory e=new string[](0); a.push(e); string[] memory o=new string[](1); o[0]="only"; a.push(o); }
      function outer() external view returns(uint){ return a.length; }
      function leni(uint i) external view returns(uint){ return a[i].length; }
      function get(uint i, uint j) external view returns(string memory){ return a[i][j]; }
    }`;
    await bothMatch(J, S, [
      ['set()'], ['outer()'], ['leni(uint256)', pad32(0n)], ['leni(uint256)', pad32(1n)],
      ['get(uint256,uint256)', pad32(1n) + pad32(0n)],
    ]);
  });

  it('F: whole-array assignment string[][] = memory image (overwrites longer existing data)', async () => {
    const J = `@contract class C {
      @state a: string[][];
      @external seed(): void { this.a.push(["long-existing-value-that-spans-more-than-thirty-two-bytes-clearly"]); this.a.push(["q", "ww"]); }
      @external set(): void { let v: string[][] = [["a"], ["bb", "ccc", "dddd"]]; this.a = v; }
      @external outer(): u256 { return this.a.length; }
      @external leni(i: u256): u256 { return this.a[i].length; }
      @external get(i: u256, j: u256): string { return this.a[i][j]; }
    }`;
    const S = `contract C {
      string[][] a;
      function seed() external {
        string[] memory x=new string[](1); x[0]="long-existing-value-that-spans-more-than-thirty-two-bytes-clearly"; a.push(x);
        string[] memory y=new string[](2); y[0]="q"; y[1]="ww"; a.push(y);
      }
      function set() external {
        string[][] memory v=new string[][](2);
        v[0]=new string[](1); v[0][0]="a";
        v[1]=new string[](3); v[1][0]="bb"; v[1][1]="ccc"; v[1][2]="dddd";
        a=v;
      }
      function outer() external view returns(uint){ return a.length; }
      function leni(uint i) external view returns(uint){ return a[i].length; }
      function get(uint i, uint j) external view returns(string memory){ return a[i][j]; }
    }`;
    await bothMatch(J, S, [
      ['seed()'], ['set()'], ['outer()'],
      ['leni(uint256)', pad32(0n)], ['leni(uint256)', pad32(1n)],
      ['get(uint256,uint256)', pad32(0n) + pad32(0n)], ['get(uint256,uint256)', pad32(1n) + pad32(2n)],
    ]);
  });
});
