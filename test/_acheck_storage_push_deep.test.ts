// LIFT #6 (storage-push-deep): storage push of a string/bytes-LEAF nested array at depth >= 3.
//   @state a: string[][][]; this.a.push([["x"]])   (the element is string[][])
// The codegen already supported this (copyMemAggArrayIntoStorage recurses to the bytes/string base
// case at any nesting depth); these tests LOCK IN byte-identity to solc 0.8.35 across literal +
// local sources, multi-word strings, the deep stale-slot clear on pop()+push-shorter, a second push,
// the depth-4 form (string[][][][]), and a bytes leaf (bytes[][][]). The auto-getter shape is read
// back via an explicit getter g(i,j,k) returning the leaf, plus length getters at every level.
//
// Note: solc cannot deduce a RAGGED nested array literal's common type, so the solc side builds the
// ragged value via memory locals (new T[](n) + element assigns) - the same value JETH builds from a
// ragged literal. Where the literal is uniform (single inner) both use a literal.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint | number) => (((BigInt(v) % M) + M) % M).toString(16).padStart(64, '0');
const sel = (s: string) => functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

const LONG = 'this is a multi-word string longer than thirty-two bytes total here';

// ---------- string[][][] ----------
const J3 = `
class C {
  a: string[][][];
  build(): External<void> {
    this.a.push([["alpha"], ["beta", "gamma"]]);
    this.a.push([["${LONG}"]]);
  }
  pushLocal(): External<void> {
    let row: string[][] = [["loc1", "loc2"]];
    this.a.push(row);
  }
  popThenShorter(): External<void> {
    this.a.pop();
    this.a.push([["short"]]);
  }
  push2(): External<void> {
    this.a.push([["p2a"], ["p2b"]]);
  }
  get g(i: u256, j: u256, k: u256): External<string> { return this.a[i][j][k]; }
  get outerLen(): External<u256> { return u256(this.a.length); }
  get midLen(i: u256): External<u256> { return u256(this.a[i].length); }
  get innLen(i: u256, j: u256): External<u256> { return u256(this.a[i][j].length); }
}`;
const S3 = `${SPDX}contract C {
  string[][][] a;
  function build() external {
    string[][] memory e0 = new string[][](2);
    string[] memory e0a = new string[](1); e0a[0]="alpha"; e0[0]=e0a;
    string[] memory e0b = new string[](2); e0b[0]="beta"; e0b[1]="gamma"; e0[1]=e0b;
    a.push(e0);
    string[][] memory e1 = new string[][](1);
    string[] memory e1a = new string[](1); e1a[0]="${LONG}"; e1[0]=e1a;
    a.push(e1);
  }
  function pushLocal() external {
    string[][] memory row = new string[][](1);
    string[] memory r0 = new string[](2);
    r0[0]="loc1"; r0[1]="loc2"; row[0]=r0;
    a.push(row);
  }
  function popThenShorter() external { a.pop(); a.push([["short"]]); }
  function push2() external { a.push([["p2a"], ["p2b"]]); }
  function g(uint i, uint j, uint k) external view returns (string memory) { return a[i][j][k]; }
  function outerLen() external view returns (uint) { return a.length; }
  function midLen(uint i) external view returns (uint) { return a[i].length; }
  function innLen(uint i, uint j) external view returns (uint) { return a[i][j].length; }
}`;

// ---------- bytes[][][] ----------
const Jb = `
class C {
  a: bytes[][][];
  build(): External<void> {
    let inner: bytes[] = [bytes("hello"), bytes("a multi-word bytes value longer than thirty-two bytes here ok")];
    let mid: bytes[][] = [inner];
    this.a.push(mid);
  }
  popShorter(): External<void> {
    this.a.pop();
    let s: bytes[][] = [[bytes("z")]];
    this.a.push(s);
  }
  get g(i: u256, j: u256, k: u256): External<bytes> { return this.a[i][j][k]; }
  get outerLen(): External<u256> { return u256(this.a.length); }
}`;
const Sb = `${SPDX}contract C {
  bytes[][][] a;
  function build() external {
    bytes[] memory inner = new bytes[](2);
    inner[0] = bytes("hello");
    inner[1] = bytes("a multi-word bytes value longer than thirty-two bytes here ok");
    bytes[][] memory mid = new bytes[][](1); mid[0] = inner;
    a.push(mid);
  }
  function popShorter() external {
    a.pop();
    bytes[] memory z = new bytes[](1); z[0] = bytes("z");
    bytes[][] memory s = new bytes[][](1); s[0] = z;
    a.push(s);
  }
  function g(uint i, uint j, uint k) external view returns (bytes memory) { return a[i][j][k]; }
  function outerLen() external view returns (uint) { return a.length; }
}`;

// ---------- string[][][][] (depth 4) ----------
const J4 = `
class C {
  a: string[][][][];
  build(): External<void> { this.a.push([[["deep four level value here longer than thirty two bytes total xx"]]]); }
  get g(i: u256, j: u256, k: u256, l: u256): External<string> { return this.a[i][j][k][l]; }
  get outerLen(): External<u256> { return u256(this.a.length); }
}`;
const S4 = `${SPDX}contract C {
  string[][][][] a;
  function build() external { a.push([[["deep four level value here longer than thirty two bytes total xx"]]]); }
  function g(uint i, uint j, uint k, uint l) external view returns (string memory) { return a[i][j][k][l]; }
  function outerLen() external view returns (uint) { return a.length; }
}`;

async function pair(J: string, S: string): Promise<{ jeth: Harness; sol: Harness; aj: Address; as: Address }> {
  const jb = compile(J, { fileName: 'C.jeth' });
  const sb = compileSolidity(S, 'C');
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  return { jeth, sol, aj, as };
}

describe('storage-push-deep: string/bytes-leaf nested array push at depth >= 3 (LIFT #6)', () => {
  describe('string[][][]', () => {
    let P: { jeth: Harness; sol: Harness; aj: Address; as: Address };
    beforeAll(async () => {
      P = await pair(J3, S3);
    });
    async function eq(label: string, data: string) {
      const j = await P.jeth.call(P.aj, data);
      const sr = await P.sol.call(P.as, data);
      expect(j.success, `${label} success`).toBe(sr.success);
      expect(j.returnHex, `${label} returndata`).toBe(sr.returnHex);
    }
    it('build (ragged literal + multi-word leaf)', async () => {
      await eq('build', '0x' + sel('build()'));
    });
    it('lengths at every level', async () => {
      await eq('outerLen', '0x' + sel('outerLen()'));
      await eq('midLen0', '0x' + sel('midLen(uint256)') + pad(0));
      await eq('midLen1', '0x' + sel('midLen(uint256)') + pad(1));
      await eq('innLen00', '0x' + sel('innLen(uint256,uint256)') + pad(0) + pad(0));
      await eq('innLen01', '0x' + sel('innLen(uint256,uint256)') + pad(0) + pad(1));
    });
    it('leaf reads', async () => {
      await eq('g000', '0x' + sel('g(uint256,uint256,uint256)') + pad(0) + pad(0) + pad(0));
      await eq('g010', '0x' + sel('g(uint256,uint256,uint256)') + pad(0) + pad(1) + pad(0));
      await eq('g011', '0x' + sel('g(uint256,uint256,uint256)') + pad(0) + pad(1) + pad(1));
      await eq('g100', '0x' + sel('g(uint256,uint256,uint256)') + pad(1) + pad(0) + pad(0));
    });
    it('push from a memory local', async () => {
      await eq('pushLocal', '0x' + sel('pushLocal()'));
      await eq('outerLen', '0x' + sel('outerLen()'));
      await eq('g200', '0x' + sel('g(uint256,uint256,uint256)') + pad(2) + pad(0) + pad(0));
      await eq('g201', '0x' + sel('g(uint256,uint256,uint256)') + pad(2) + pad(0) + pad(1));
    });
    it('pop() then push shorter (deep stale-slot clear)', async () => {
      await eq('popThenShorter', '0x' + sel('popThenShorter()'));
      await eq('outerLen', '0x' + sel('outerLen()'));
      await eq('g200', '0x' + sel('g(uint256,uint256,uint256)') + pad(2) + pad(0) + pad(0));
      await eq('innLen20', '0x' + sel('innLen(uint256,uint256)') + pad(2) + pad(0));
    });
    it('a second push', async () => {
      await eq('push2', '0x' + sel('push2()'));
      await eq('outerLen', '0x' + sel('outerLen()'));
      await eq('g300', '0x' + sel('g(uint256,uint256,uint256)') + pad(3) + pad(0) + pad(0));
      await eq('g310', '0x' + sel('g(uint256,uint256,uint256)') + pad(3) + pad(1) + pad(0));
    });
  });

  describe('bytes[][][]', () => {
    let P: { jeth: Harness; sol: Harness; aj: Address; as: Address };
    beforeAll(async () => {
      P = await pair(Jb, Sb);
    });
    async function eq(label: string, data: string) {
      const j = await P.jeth.call(P.aj, data);
      const sr = await P.sol.call(P.as, data);
      expect(j.success, `${label} success`).toBe(sr.success);
      expect(j.returnHex, `${label} returndata`).toBe(sr.returnHex);
    }
    it('build + reads + pop-shorter', async () => {
      await eq('build', '0x' + sel('build()'));
      await eq('outerLen', '0x' + sel('outerLen()'));
      await eq('g000', '0x' + sel('g(uint256,uint256,uint256)') + pad(0) + pad(0) + pad(0));
      await eq('g001', '0x' + sel('g(uint256,uint256,uint256)') + pad(0) + pad(0) + pad(1));
      await eq('popShorter', '0x' + sel('popShorter()'));
      await eq('outerLen2', '0x' + sel('outerLen()'));
      await eq('g000b', '0x' + sel('g(uint256,uint256,uint256)') + pad(0) + pad(0) + pad(0));
    });
  });

  describe('string[][][][] (depth 4)', () => {
    let P: { jeth: Harness; sol: Harness; aj: Address; as: Address };
    beforeAll(async () => {
      P = await pair(J4, S4);
    });
    async function eq(label: string, data: string) {
      const j = await P.jeth.call(P.aj, data);
      const sr = await P.sol.call(P.as, data);
      expect(j.success, `${label} success`).toBe(sr.success);
      expect(j.returnHex, `${label} returndata`).toBe(sr.returnHex);
    }
    it('build + read', async () => {
      await eq('build', '0x' + sel('build()'));
      await eq('outerLen', '0x' + sel('outerLen()'));
      await eq('g0000', '0x' + sel('g(uint256,uint256,uint256,uint256)') + pad(0) + pad(0) + pad(0) + pad(0));
    });
  });
});
