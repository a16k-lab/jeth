// Differential test: deep-copy a STORAGE reference-element array into a MEMORY local
//   (`let row: bytes[] = this.blobs`). The storage twin of the calldata-to-mem copy: a storage ->
//   pointer-headed-memory transcode (abiDecFromStorageToImage) that a memArray local binds. Storage
//   is canonical (no malformed-input revert / Panic), so this is byte-identical to solc's storage->
//   memory deep copy.
//
// Shapes: bytes[] / string[] / u256[][] / P[] (static struct) / P[][] / bytes[][] / a bytes[] FIELD
// of a storage struct (placeArray) / a dyn-struct array D[] (B3 storage analogue). Operations: element
// read, .length, return the row, abi.encode(row), and a DEEP-COPY check (mutating the memory copy must
// NOT change storage). The VALUE-element source (u256[]) is verified as a non-regression.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint | number) => (((BigInt(v) % M) + M) % M).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

type Case = { name: string; jeth: string; sol: string; calls: [string, string][] };

const cases: Case[] = [
  {
    name: 'bytes[] storage source: read + len + return + encode',
    jeth: `@contract class C {
  @state blobs: bytes[];
  @external seed(a: bytes, b: bytes): void { this.blobs.push(a); this.blobs.push(b); }
  @external readLen(): u256 { let row: bytes[] = this.blobs; return u256(row.length); }
  @external elemLen(i: u256): u256 { let row: bytes[] = this.blobs; return u256(row[i].length); }
  @external retRow(): bytes[] { let row: bytes[] = this.blobs; return row; }
  @external encRow(): bytes { let row: bytes[] = this.blobs; return abi.encode(row); }
}`,
    sol: `contract C {
  bytes[] blobs;
  function seed(bytes calldata a, bytes calldata b) external { blobs.push(a); blobs.push(b); }
  function readLen() external view returns (uint256) { bytes[] memory row = blobs; return row.length; }
  function elemLen(uint256 i) external view returns (uint256) { bytes[] memory row = blobs; return row[i].length; }
  function retRow() external view returns (bytes[] memory) { bytes[] memory row = blobs; return row; }
  function encRow() external view returns (bytes memory) { bytes[] memory row = blobs; return abi.encode(row); }
}`,
    calls: [
      ['seed(bytes,bytes)', pad(0x40) + pad(0x80) + pad(2) + 'aabb'.padEnd(64, '0') + pad(5) + '1122334455'.padEnd(64, '0')],
      ['readLen()', ''],
      ['elemLen(uint256)', pad(0)],
      ['elemLen(uint256)', pad(1)],
      ['retRow()', ''],
      ['encRow()', ''],
    ],
  },
  {
    name: 'string[] storage source: len + return + encode',
    jeth: `@contract class C {
  @state ss: string[];
  @external seed(a: string, b: string): void { this.ss.push(a); this.ss.push(b); }
  @external len(): u256 { let row: string[] = this.ss; return u256(row.length); }
  @external retRow(): string[] { let row: string[] = this.ss; return row; }
  @external encRow(): bytes { let row: string[] = this.ss; return abi.encode(row); }
}`,
    sol: `contract C {
  string[] ss;
  function seed(string calldata a, string calldata b) external { ss.push(a); ss.push(b); }
  function len() external view returns (uint256) { string[] memory row = ss; return row.length; }
  function retRow() external view returns (string[] memory) { string[] memory row = ss; return row; }
  function encRow() external view returns (bytes memory) { string[] memory row = ss; return abi.encode(row); }
}`,
    calls: [
      ['seed(string,string)', pad(0x40) + pad(0x80) + pad(3) + '616263'.padEnd(64, '0') + pad(4) + '64656667'.padEnd(64, '0')],
      ['len()', ''],
      ['retRow()', ''],
      ['encRow()', ''],
    ],
  },
  {
    name: 'u256[][] storage source: inner read + return + encode',
    jeth: `@contract class C {
  @state g: u256[][];
  @external seed(): void {
    let r0: u256[] = new Array<u256>(2n); r0[0n]=11n; r0[1n]=22n; this.g.push(r0);
    let r1: u256[] = new Array<u256>(3n); r1[0n]=33n; r1[1n]=44n; r1[2n]=55n; this.g.push(r1);
  }
  @external outerLen(): u256 { let row: u256[][] = this.g; return u256(row.length); }
  @external get(i: u256, j: u256): u256 { let row: u256[][] = this.g; return row[i][j]; }
  @external retRow(): u256[][] { let row: u256[][] = this.g; return row; }
  @external encRow(): bytes { let row: u256[][] = this.g; return abi.encode(row); }
}`,
    sol: `contract C {
  uint256[][] g;
  function seed() external {
    uint256[] memory r0 = new uint256[](2); r0[0]=11; r0[1]=22; g.push(r0);
    uint256[] memory r1 = new uint256[](3); r1[0]=33; r1[1]=44; r1[2]=55; g.push(r1);
  }
  function outerLen() external view returns (uint256) { uint256[][] memory row = g; return row.length; }
  function get(uint256 i, uint256 j) external view returns (uint256) { uint256[][] memory row = g; return row[i][j]; }
  function retRow() external view returns (uint256[][] memory) { uint256[][] memory row = g; return row; }
  function encRow() external view returns (bytes memory) { uint256[][] memory row = g; return abi.encode(row); }
}`,
    calls: [
      ['seed()', ''],
      ['outerLen()', ''],
      ['get(uint256,uint256)', pad(0) + pad(1)],
      ['get(uint256,uint256)', pad(1) + pad(2)],
      ['retRow()', ''],
      ['encRow()', ''],
    ],
  },
  {
    name: 'u256[][] deep copy: mutate memory copy, storage intact',
    jeth: `@contract class C {
  @state g: u256[][];
  @external seed(): void { let r0: u256[] = new Array<u256>(2n); r0[0n]=11n; r0[1n]=22n; this.g.push(r0); }
  @external mutateCopyThenRead(): u256 { let row: u256[][] = this.g; row[0n][0n] = 999n; return this.g[0n][0n]; }
}`,
    sol: `contract C {
  uint256[][] g;
  function seed() external { uint256[] memory r0 = new uint256[](2); r0[0]=11; r0[1]=22; g.push(r0); }
  function mutateCopyThenRead() external returns (uint256) { uint256[][] memory row = g; row[0][0] = 999; return g[0][0]; }
}`,
    calls: [['seed()', ''], ['mutateCopyThenRead()', '']],
  },
  {
    name: 'empty bytes[] storage source',
    jeth: `@contract class C {
  @state blobs: bytes[];
  @external len(): u256 { let row: bytes[] = this.blobs; return u256(row.length); }
  @external ret(): bytes[] { let row: bytes[] = this.blobs; return row; }
}`,
    sol: `contract C {
  bytes[] blobs;
  function len() external view returns (uint256) { bytes[] memory row = blobs; return row.length; }
  function ret() external view returns (bytes[] memory) { bytes[] memory row = blobs; return row; }
}`,
    calls: [['len()', ''], ['ret()', '']],
  },
  {
    name: 'P[] static struct storage source: read + return + encode + deep-copy',
    jeth: `@struct class P { a: u256; b: u256; }
@contract class C {
  @state ps: P[];
  @external seed(): void { this.ps.push(P(1n,2n)); this.ps.push(P(3n,4n)); }
  @external sum(): u256 { let row: P[] = this.ps; return row[0n].a + row[0n].b + row[1n].a + row[1n].b; }
  @external retRow(): P[] { let row: P[] = this.ps; return row; }
  @external encRow(): bytes { let row: P[] = this.ps; return abi.encode(row); }
  @external mutNoStore(): u256 { let row: P[] = this.ps; row[0n].a = 99n; return this.ps[0n].a; }
}`,
    sol: `struct P { uint256 a; uint256 b; }
contract C {
  P[] ps;
  function seed() external { ps.push(P(1,2)); ps.push(P(3,4)); }
  function sum() external view returns (uint256) { P[] memory row = ps; return row[0].a+row[0].b+row[1].a+row[1].b; }
  function retRow() external view returns (P[] memory) { P[] memory row = ps; return row; }
  function encRow() external view returns (bytes memory) { P[] memory row = ps; return abi.encode(row); }
  function mutNoStore() external returns (uint256) { P[] memory row = ps; row[0].a = 99; return ps[0].a; }
}`,
    calls: [['seed()', ''], ['sum()', ''], ['retRow()', ''], ['encRow()', ''], ['mutNoStore()', '']],
  },
  {
    name: 'P[][] static struct nested storage source (storage-seeded)',
    jeth: `@struct class P { a: u256; b: u256; }
@contract class C {
  @state gg: P[][];
  @external seed(): void { this.gg.push(); this.gg[0n].push(P(1n,2n)); this.gg[0n].push(P(3n,4n)); }
  @external get(i: u256, j: u256): u256 { let row: P[][] = this.gg; return row[i][j].a + row[i][j].b; }
  @external ret(): P[][] { let row: P[][] = this.gg; return row; }
}`,
    sol: `struct P { uint256 a; uint256 b; }
contract C {
  P[][] gg;
  function seed() external { gg.push(); gg[0].push(P(1,2)); gg[0].push(P(3,4)); }
  function get(uint256 i, uint256 j) external view returns (uint256) { P[][] memory row = gg; return row[i][j].a + row[i][j].b; }
  function ret() external view returns (P[][] memory) { P[][] memory row = gg; return row; }
}`,
    calls: [['seed()', ''], ['get(uint256,uint256)', pad(0) + pad(1)], ['ret()', '']],
  },
  {
    name: 'bytes[][] storage source',
    jeth: `@contract class C {
  @state gg: bytes[][];
  @external seed(a: bytes): void { let r: bytes[] = new Array<bytes>(1n); r[0n]=a; this.gg.push(r); }
  @external get(i: u256, j: u256): u256 { let row: bytes[][] = this.gg; return u256(row[i][j].length); }
  @external ret(): bytes[][] { let row: bytes[][] = this.gg; return row; }
}`,
    sol: `contract C {
  bytes[][] gg;
  function seed(bytes calldata a) external { bytes[] memory r = new bytes[](1); r[0]=a; gg.push(r); }
  function get(uint256 i, uint256 j) external view returns (uint256) { bytes[][] memory row = gg; return row[i][j].length; }
  function ret() external view returns (bytes[][] memory) { bytes[][] memory row = gg; return row; }
}`,
    calls: [['seed(bytes)', pad(0x20) + pad(4) + 'deadbeef'.padEnd(64, '0')], ['get(uint256,uint256)', pad(0) + pad(0)], ['ret()', '']],
  },
  {
    name: 'storage struct FIELD bytes[] (placeArray source)',
    jeth: `@struct class S { tag: u256; xs: bytes[]; }
@contract class C {
  @state s: S;
  @external seed(a: bytes): void { this.s.tag = 9n; this.s.xs.push(a); }
  @external len(): u256 { let row: bytes[] = this.s.xs; return u256(row.length); }
  @external elem0Len(): u256 { let row: bytes[] = this.s.xs; return u256(row[0n].length); }
  @external ret(): bytes[] { let row: bytes[] = this.s.xs; return row; }
}`,
    sol: `struct S { uint256 tag; bytes[] xs; }
contract C {
  S s;
  function seed(bytes calldata a) external { s.tag = 9; s.xs.push(a); }
  function len() external view returns (uint256) { bytes[] memory row = s.xs; return row.length; }
  function elem0Len() external view returns (uint256) { bytes[] memory row = s.xs; return row[0].length; }
  function ret() external view returns (bytes[] memory) { bytes[] memory row = s.xs; return row; }
}`,
    calls: [['seed(bytes)', pad(0x20) + pad(3) + 'aabbcc'.padEnd(64, '0')], ['len()', ''], ['elem0Len()', ''], ['ret()', '']],
  },
  {
    name: 'D[] dyn-struct (value + bytes field) storage source: B3 analogue',
    jeth: `@struct class D { tag: u256; name: bytes; }
@contract class C {
  @state ds: D[];
  @external seed(a: bytes): void { this.ds.push(D(7n, a)); }
  @external retRow(): D[] { let row: D[] = this.ds; return row; }
  @external enc(): bytes { let row: D[] = this.ds; return abi.encode(row); }
  @external nameLen(): u256 { let row: D[] = this.ds; return u256(row[0n].name.length); }
}`,
    sol: `struct D { uint256 tag; bytes name; }
contract C {
  D[] ds;
  function seed(bytes calldata a) external { ds.push(D(7, a)); }
  function retRow() external view returns (D[] memory) { D[] memory row = ds; return row; }
  function enc() external view returns (bytes memory) { D[] memory row = ds; return abi.encode(row); }
  function nameLen() external view returns (uint256) { D[] memory row = ds; return row[0].name.length; }
}`,
    calls: [['seed(bytes)', pad(0x20) + pad(3) + 'abcdef'.padEnd(64, '0')], ['retRow()', ''], ['enc()', ''], ['nameLen()', '']],
  },
  {
    name: 'u256[] VALUE-element storage source (non-regression)',
    jeth: `@contract class C {
  @state v: u256[];
  @external seed(): void { this.v.push(10n); this.v.push(20n); }
  @external sum(): u256 { let row: u256[] = this.v; return row[0n]+row[1n]; }
  @external ret(): u256[] { let row: u256[] = this.v; return row; }
}`,
    sol: `contract C {
  uint256[] v;
  function seed() external { v.push(10); v.push(20); }
  function sum() external view returns (uint256) { uint256[] memory row = v; return row[0]+row[1]; }
  function ret() external view returns (uint256[] memory) { uint256[] memory row = v; return row; }
}`,
    calls: [['seed()', ''], ['sum()', ''], ['ret()', '']],
  },
];

describe('storage-to-mem-copy: deep-copy a storage reference-element array into a memory local', () => {
  for (const c of cases) {
    describe(c.name, () => {
      let jeth: Harness, sol: Harness, aj: Address, as: Address;
      beforeAll(async () => {
        jeth = await Harness.create();
        sol = await Harness.create();
        aj = await jeth.deploy(compile(c.jeth, { fileName: 'C.jeth' }).creationBytecode);
        as = await sol.deploy(compileSolidity(SPDX + c.sol, 'C').creation);
      });
      for (let i = 0; i < c.calls.length; i++) {
        const [sig, args] = c.calls[i]!;
        it(`call #${i}: ${sig}`, async () => {
          const data = '0x' + sel(sig) + args;
          const j = await jeth.call(aj, data);
          const s = await sol.call(as, data);
          expect(j.success, `${sig} success (jeth err=${j.exceptionError})`).toBe(s.success);
          expect(j.returnHex, `${sig} returndata`).toBe(s.returnHex);
        });
      }
    });
  }
});

// A dyn-struct array element with a NESTED-DYNAMIC-LEAF array field (D = {tag; xs: bytes[]}) is NOT yet
// wired from storage -> memory (buildDynStructFromStorage does not transcode that field). It MUST stay a
// clean analyzer reject (JETH200), not a codegen crash, per the zero-miscompile bar.
describe('storage-to-mem-copy: deferred dyn-struct-leaf-array-field element is a clean reject', () => {
  it('let row: D[] = this.ds, D has a bytes[] field -> JETH200', () => {
    const src = `@struct class D { tag: u256; xs: bytes[]; }
@contract class C {
  @state ds: D[];
  @external ret(): D[] { let row: D[] = this.ds; return row; }
}`;
    let codes: string[] = [];
    try {
      compile(src, { fileName: 'C.jeth' });
      throw new Error('expected a clean reject, but compilation succeeded');
    } catch (e: any) {
      codes = (e?.diagnostics ?? []).map((d: any) => d.code);
    }
    expect(codes.length, 'must reject with a diagnostic (no crash)').toBeGreaterThan(0);
    expect(codes).toContain('JETH200');
  });
});
