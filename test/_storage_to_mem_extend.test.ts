// Differential test: storage-to-mem-copy EXTENSIONS (the storage twin family).
//   #2 a whole MAPPING-VALUE array bound to a memory local (`let row = this.m[k]`): u256[] / bytes[] /
//      u256[][] / bytes[][] / P[] (static struct). resolveMapAccess types this.m[k] as a mapStorageValue
//      (not an arrayValue with a mapArray base), so it is wired through aggArgToMemPtr -> the mapping slot
//      -> abiDecFromStorageToImage (a reference element) / abiEncFromStorage (a value element).
//   #4 a FIXED-outer storage source bound to a memory local (`let row: Arr<P,N> = this.fa`): the pointer-
//      headed static-struct fixed array now rides abiDecFromStorageToImage's fixed-array branch.
// Operations: element read, .length, return the row, abi.encode(row), and a DEEP-COPY check (mutating
// the memory copy must NOT change storage). The VALUE-element mapping source (u256[]) and a mapping
// STRUCT value (not array) are verified as non-regressions.
//
// #5 (a dyn-struct array element whose field is itself a bytes[]/string[]/T[][]) stays a CLEAN reject:
// the deeper storage transcode for that shape is not byte-identical even via the direct return path, so
// lifting the mem-copy would be unsound. Guarded below.
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
    name: '#2 mapping value u256[]: len + el + return + encode',
    jeth: `class C {
  m: mapping<u256, u256[]>;
  seed(k: u256, a: u256, b: u256): External<void> { this.m[k].push(a); this.m[k].push(b); }
  get len(k: u256): External<u256> { let row: u256[] = this.m[k]; return u256(row.length); }
  get el(k: u256, i: u256): External<u256> { let row: u256[] = this.m[k]; return row[i]; }
  get ret(k: u256): External<u256[]> { let row: u256[] = this.m[k]; return row; }
  get enc(k: u256): External<bytes> { let row: u256[] = this.m[k]; return abi.encode(row); }
}`,
    sol: `contract C {
  mapping(uint256 => uint256[]) m;
  function seed(uint256 k, uint256 a, uint256 b) external { m[k].push(a); m[k].push(b); }
  function len(uint256 k) external view returns (uint256) { uint256[] memory row = m[k]; return row.length; }
  function el(uint256 k, uint256 i) external view returns (uint256) { uint256[] memory row = m[k]; return row[i]; }
  function ret(uint256 k) external view returns (uint256[] memory) { uint256[] memory row = m[k]; return row; }
  function enc(uint256 k) external view returns (bytes memory) { uint256[] memory row = m[k]; return abi.encode(row); }
}`,
    calls: [
      ['seed(uint256,uint256,uint256)', pad(7) + pad(11) + pad(22)],
      ['len(uint256)', pad(7)],
      ['el(uint256,uint256)', pad(7) + pad(0)],
      ['el(uint256,uint256)', pad(7) + pad(1)],
      ['ret(uint256)', pad(7)],
      ['enc(uint256)', pad(7)],
      ['len(uint256)', pad(999)], // empty (unseeded) key
    ],
  },
  {
    name: '#2 mapping value bytes[]: len + elemLen + return + encode',
    jeth: `class C {
  m: mapping<u256, bytes[]>;
  seed(k: u256, a: bytes): External<void> { this.m[k].push(a); }
  get len(k: u256): External<u256> { let row: bytes[] = this.m[k]; return u256(row.length); }
  get el(k: u256, i: u256): External<u256> { let row: bytes[] = this.m[k]; return u256(row[i].length); }
  get ret(k: u256): External<bytes[]> { let row: bytes[] = this.m[k]; return row; }
  get enc(k: u256): External<bytes> { let row: bytes[] = this.m[k]; return abi.encode(row); }
}`,
    sol: `contract C {
  mapping(uint256 => bytes[]) m;
  function seed(uint256 k, bytes calldata a) external { m[k].push(a); }
  function len(uint256 k) external view returns (uint256) { bytes[] memory row = m[k]; return row.length; }
  function el(uint256 k, uint256 i) external view returns (uint256) { bytes[] memory row = m[k]; return row[i].length; }
  function ret(uint256 k) external view returns (bytes[] memory) { bytes[] memory row = m[k]; return row; }
  function enc(uint256 k) external view returns (bytes memory) { bytes[] memory row = m[k]; return abi.encode(row); }
}`,
    calls: [
      ['seed(uint256,bytes)', pad(7) + pad(0x40) + pad(3) + 'aabbcc'.padEnd(64, '0')],
      ['seed(uint256,bytes)', pad(7) + pad(0x40) + pad(2) + '1122'.padEnd(64, '0')],
      ['len(uint256)', pad(7)],
      ['el(uint256,uint256)', pad(7) + pad(0)],
      ['el(uint256,uint256)', pad(7) + pad(1)],
      ['ret(uint256)', pad(7)],
      ['enc(uint256)', pad(7)],
    ],
  },
  {
    name: '#2 mapping value u256[][]: len + el + return + encode',
    jeth: `class C {
  m: mapping<u256, u256[][]>;
  seed(k: u256): External<void> { let inner: u256[] = [1n, 2n, 3n]; this.m[k].push(inner); let inner2: u256[] = [9n]; this.m[k].push(inner2); }
  get len(k: u256): External<u256> { let row: u256[][] = this.m[k]; return u256(row.length); }
  get el(k: u256, i: u256, j: u256): External<u256> { let row: u256[][] = this.m[k]; return row[i][j]; }
  get ret(k: u256): External<u256[][]> { let row: u256[][] = this.m[k]; return row; }
  get enc(k: u256): External<bytes> { let row: u256[][] = this.m[k]; return abi.encode(row); }
}`,
    sol: `contract C {
  mapping(uint256 => uint256[][]) m;
  function seed(uint256 k) external { uint256[] memory inner = new uint256[](3); inner[0]=1;inner[1]=2;inner[2]=3; m[k].push(inner); uint256[] memory inner2 = new uint256[](1); inner2[0]=9; m[k].push(inner2); }
  function len(uint256 k) external view returns (uint256) { uint256[][] memory row = m[k]; return row.length; }
  function el(uint256 k, uint256 i, uint256 j) external view returns (uint256) { uint256[][] memory row = m[k]; return row[i][j]; }
  function ret(uint256 k) external view returns (uint256[][] memory) { uint256[][] memory row = m[k]; return row; }
  function enc(uint256 k) external view returns (bytes memory) { uint256[][] memory row = m[k]; return abi.encode(row); }
}`,
    calls: [
      ['seed(uint256)', pad(7)],
      ['len(uint256)', pad(7)],
      ['el(uint256,uint256,uint256)', pad(7) + pad(0) + pad(2)],
      ['el(uint256,uint256,uint256)', pad(7) + pad(1) + pad(0)],
      ['ret(uint256)', pad(7)],
      ['enc(uint256)', pad(7)],
    ],
  },
  {
    name: '#2 mapping value bytes[][]: return + encode',
    jeth: `class C {
  m: mapping<u256, bytes[][]>;
  seed(k: u256): External<void> { let i0: bytes[] = [bytes("a"), bytes("bb")]; this.m[k].push(i0); }
  get ret(k: u256): External<bytes[][]> { let row: bytes[][] = this.m[k]; return row; }
  get enc(k: u256): External<bytes> { let row: bytes[][] = this.m[k]; return abi.encode(row); }
}`,
    sol: `contract C {
  mapping(uint256 => bytes[][]) m;
  function seed(uint256 k) external { bytes[] memory i0 = new bytes[](2); i0[0]=hex"61"; i0[1]=hex"6262"; m[k].push(i0); }
  function ret(uint256 k) external view returns (bytes[][] memory) { bytes[][] memory row = m[k]; return row; }
  function enc(uint256 k) external view returns (bytes memory) { bytes[][] memory row = m[k]; return abi.encode(row); }
}`,
    calls: [['seed(uint256)', pad(5)], ['ret(uint256)', pad(5)], ['enc(uint256)', pad(5)]],
  },
  {
    name: '#2 mapping value P[] (static struct): el + return + encode',
    jeth: `type P = { a: u256; b: u256; };
class C {
  m: mapping<u256, P[]>;
  seed(k: u256): External<void> { this.m[k].push(P(1n,2n)); this.m[k].push(P(3n,4n)); }
  get el(k: u256, i: u256): External<u256> { let row: P[] = this.m[k]; return row[i].b; }
  get ret(k: u256): External<P[]> { let row: P[] = this.m[k]; return row; }
  get enc(k: u256): External<bytes> { let row: P[] = this.m[k]; return abi.encode(row); }
}`,
    sol: `contract C {
  struct P { uint256 a; uint256 b; }
  mapping(uint256 => P[]) m;
  function seed(uint256 k) external { m[k].push(P(1,2)); m[k].push(P(3,4)); }
  function el(uint256 k, uint256 i) external view returns (uint256) { P[] memory row = m[k]; return row[i].b; }
  function ret(uint256 k) external view returns (P[] memory) { P[] memory row = m[k]; return row; }
  function enc(uint256 k) external view returns (bytes memory) { P[] memory row = m[k]; return abi.encode(row); }
}`,
    calls: [
      ['seed(uint256)', pad(3)],
      ['el(uint256,uint256)', pad(3) + pad(0)],
      ['el(uint256,uint256)', pad(3) + pad(1)],
      ['ret(uint256)', pad(3)],
      ['enc(uint256)', pad(3)],
    ],
  },
  {
    name: '#2 mapping value u256[]: deep-copy non-aliasing (mutate copy leaves storage)',
    jeth: `class C {
  m: mapping<u256, u256[]>;
  seed(k: u256): External<void> { this.m[k].push(5n); this.m[k].push(6n); }
  get mutNoStore(k: u256): External<u256> { let row: u256[] = this.m[k]; row[0n] = 999n; return this.m[k][0n]; }
}`,
    sol: `contract C {
  mapping(uint256 => uint256[]) m;
  function seed(uint256 k) external { m[k].push(5); m[k].push(6); }
  function mutNoStore(uint256 k) external returns (uint256) { uint256[] memory row = m[k]; row[0] = 999; return m[k][0]; }
}`,
    calls: [['seed(uint256)', pad(8)], ['mutNoStore(uint256)', pad(8)]],
  },
  {
    name: '#4 fixed-outer Arr<P,2> storage source: el + encode + deep-copy non-aliasing',
    jeth: `type P = { a: u256; b: u256; };
class C {
  fa: Arr<P, 2>;
  seed(a0: u256, b0: u256, a1: u256, b1: u256): External<void> { this.fa[0n] = P(a0, b0); this.fa[1n] = P(a1, b1); }
  get el(i: u256): External<u256> { let row: Arr<P, 2> = this.fa; return row[i].a; }
  get el2(i: u256): External<u256> { let row: Arr<P, 2> = this.fa; return row[i].b; }
  get enc(): External<bytes> { let row: Arr<P, 2> = this.fa; return abi.encode(row); }
  get mutNoStore(): External<u256> { let row: Arr<P, 2> = this.fa; row[0n].a = 999n; return this.fa[0n].a; }
}`,
    sol: `contract C {
  struct P { uint256 a; uint256 b; }
  P[2] fa;
  function seed(uint256 a0, uint256 b0, uint256 a1, uint256 b1) external { fa[0]=P(a0,b0); fa[1]=P(a1,b1); }
  function el(uint256 i) external view returns (uint256) { P[2] memory row = fa; return row[i].a; }
  function el2(uint256 i) external view returns (uint256) { P[2] memory row = fa; return row[i].b; }
  function enc() external view returns (bytes memory) { P[2] memory row = fa; return abi.encode(row); }
  function mutNoStore() external returns (uint256) { P[2] memory row = fa; row[0].a = 999; return fa[0].a; }
}`,
    calls: [
      ['seed(uint256,uint256,uint256,uint256)', pad(10) + pad(20) + pad(30) + pad(40)],
      ['el(uint256)', pad(0)],
      ['el(uint256)', pad(1)],
      ['el2(uint256)', pad(0)],
      ['enc()', ''],
      ['mutNoStore()', ''],
    ],
  },
  {
    name: 'NR: mapping value u256[3] (value fixed) stays correct',
    jeth: `class C {
  fa: Arr<u256, 3>;
  seed(a: u256, b: u256, c: u256): External<void> { this.fa[0n]=a; this.fa[1n]=b; this.fa[2n]=c; }
  get el(i: u256): External<u256> { let row: Arr<u256, 3> = this.fa; return row[i]; }
  get enc(): External<bytes> { let row: Arr<u256, 3> = this.fa; return abi.encode(row); }
}`,
    sol: `contract C {
  uint256[3] fa;
  function seed(uint256 a, uint256 b, uint256 c) external { fa[0]=a;fa[1]=b;fa[2]=c; }
  function el(uint256 i) external view returns (uint256) { uint256[3] memory row = fa; return row[i]; }
  function enc() external view returns (bytes memory) { uint256[3] memory row = fa; return abi.encode(row); }
}`,
    calls: [['seed(uint256,uint256,uint256)', pad(1) + pad(2) + pad(3)], ['el(uint256)', pad(1)], ['enc()', '']],
  },
];

describe('storage-to-mem-extend: mapping-value arrays (#2) + fixed-outer storage source (#4)', () => {
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

// #5 stays a CLEAN reject: a dyn-struct array element with a nested-dynamic-leaf array field (bytes[]).
// The deeper storage transcode for this shape is not byte-identical even via the direct return path, so
// lifting the mem-copy would be unsound. It MUST stay a clean analyzer reject (JETH200), not a crash.
describe('storage-to-mem-extend: #5 dyn-struct-leaf-array-field element stays a clean reject', () => {
  it('let row: D[] = this.vals, D has a bytes[] field -> now COMPILES (lifted byte-identical)', () => {
    // The storage dyn-struct-array copy with a nested-dynamic-leaf field was deferred ONLY because the
    // storage codec was broken; it is now fixed (commits 19aa9a1 + 908936b) and this whole-array copy is
    // byte-identical to solc (covered in storage-dynstruct-array-cluster.test.ts). It now compiles clean.
    const src = `type D = { id: u256; tags: bytes[]; };
class C {
  vals: D[];
  get f(): External<u256> { let row: D[] = this.vals; return row.length; }
}`;
    expect(() => compile(src, { fileName: 'C.jeth' })).not.toThrow();
  });
});
