// Lift probe: calldata-field-array binding (#5a), multi-return field component (#5b), and
// tuple-assign to a pre-declared dynamic target (#6). Each shape is differential vs solc 0.8.35:
// SUCCESS paths compared by {success, returnHex}; OOB / malformed paths compared by revert KIND.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const w = (n: bigint | number): string => BigInt(n).toString(16).padStart(64, '0');

// ---- ABI encoders for S[] where S = (uint256 a, uint256[][] grid) ----
function encU256Arr(a: bigint[]): string {
  return w(a.length) + a.map(w).join('');
}
function encU256ArrArr(rows: bigint[][]): string {
  const tails = rows.map(encU256Arr);
  let head = w(rows.length);
  let off = rows.length * 32;
  for (const t of tails) {
    head += w(off);
    off += t.length / 2;
  }
  return head + tails.join('');
}
function encGridS(s: { a: bigint; grid: bigint[][] }): string {
  return w(s.a) + w(0x40) + encU256ArrArr(s.grid);
}
// ---- ABI encoders for S = (uint256 a, bytes[] tags) ----
function encBytes(hex: string): string {
  const len = hex.length / 2;
  return w(len) + hex + '0'.repeat((64 - (hex.length % 64)) % 64);
}
function encBytesArr(arr: string[]): string {
  const tails = arr.map(encBytes);
  let head = w(arr.length);
  let off = arr.length * 32;
  for (const t of tails) {
    head += w(off);
    off += t.length / 2;
  }
  return head + tails.join('');
}
function encTagS(s: { a: bigint; tags: string[] }): string {
  return w(s.a) + w(0x40) + encBytesArr(s.tags);
}
// dynamic array of dynamic structs S[]: [len][off..][S0][S1]... (offsets after the len word)
function encDynStructArr<T>(arr: T[], encOne: (x: T) => string): string {
  const tails = arr.map(encOne);
  let head = w(arr.length);
  let off = arr.length * 32;
  for (const t of tails) {
    head += w(off);
    off += t.length / 2;
  }
  return head + tails.join('');
}
// top-level args: one dynamic S[] arg + trailing static uint args
function encArgs<T>(arr: T[], encOne: (x: T) => string, statics: bigint[]): string {
  const blk = encDynStructArr(arr, encOne);
  let head = w((1 + statics.length) * 32);
  for (const s of statics) head += w(s);
  return head + blk;
}

const GRID_TUP = '(uint256,uint256[][])[]';
const TAG_TUP = '(uint256,bytes[])[]';

async function deployPair(jeth: string, sol: string): Promise<{ hj: Harness; aj: Address; hs: Harness; as: Address }> {
  const jr = compile(jeth);
  const sr = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const aj = await hj.deploy(jr.creationBytecode);
  const hs = await Harness.create();
  const as = await hs.deploy(sr.creation);
  return { hj, aj, hs, as };
}

describe('lift: calldata field-array binding (#5a) - u256[][] grid', () => {
  const JETH = `
type S = { a: u256; grid: u256[][]; };
class C {
  get rowread(xs: S[], i: u256, j: u256, k: u256): External<u256> { let row: u256[][] = xs[i].grid; return row[j][k]; }
  get rowlen(xs: S[], i: u256): External<u256> { let row: u256[][] = xs[i].grid; return u256(row.length); }
  get innerlen(xs: S[], i: u256, j: u256): External<u256> { let row: u256[][] = xs[i].grid; return u256(row[j].length); }
  get echo(xs: S[], i: u256): External<u256[][]> { let row: u256[][] = xs[i].grid; return row; }
  get innerread(xs: S[], i: u256, j: u256, k: u256): External<u256> { let inner: u256[] = xs[i].grid[j]; return inner[k]; }
}`;
  const SOL = `
struct S { uint256 a; uint256[][] grid; }
contract C {
  function rowread(S[] calldata xs, uint256 i, uint256 j, uint256 k) external pure returns (uint256) { uint256[][] memory row = xs[i].grid; return row[j][k]; }
  function rowlen(S[] calldata xs, uint256 i) external pure returns (uint256) { uint256[][] memory row = xs[i].grid; return row.length; }
  function innerlen(S[] calldata xs, uint256 i, uint256 j) external pure returns (uint256) { uint256[][] memory row = xs[i].grid; return row[j].length; }
  function echo(S[] calldata xs, uint256 i) external pure returns (uint256[][] memory) { uint256[][] memory row = xs[i].grid; return row; }
  function innerread(S[] calldata xs, uint256 i, uint256 j, uint256 k) external pure returns (uint256) { uint256[] memory inner = xs[i].grid[j]; return inner[k]; }
}`;
  const XS = [
    { a: 1n, grid: [[10n, 11n], [12n]] },
    { a: 2n, grid: [[20n]] },
  ];
  let H: Awaited<ReturnType<typeof deployPair>>;
  beforeAll(async () => {
    H = await deployPair(JETH, SOL);
  });
  async function eq(label: string, sig: string, statics: bigint[]) {
    const cd = '0x' + functionSelector(sig) + encArgs(XS, encGridS, statics);
    const j = await H.hj.call(H.aj, cd);
    const s = await H.hs.call(H.as, cd);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }
  it('reads + length + echo of a whole grid field bound to a local', async () => {
    await eq('rowread(0,0,1)', `rowread(${GRID_TUP},uint256,uint256,uint256)`, [0n, 0n, 1n]);
    await eq('rowread(1,0,0)', `rowread(${GRID_TUP},uint256,uint256,uint256)`, [1n, 0n, 0n]);
    await eq('rowlen(0)', `rowlen(${GRID_TUP},uint256)`, [0n]);
    await eq('innerlen(0,0)', `innerlen(${GRID_TUP},uint256,uint256)`, [0n, 0n]);
    await eq('echo(0)', `echo(${GRID_TUP},uint256)`, [0n]);
    await eq('echo(1)', `echo(${GRID_TUP},uint256)`, [1n]);
  });
  it('binds an inner grid[j] field (u256[]) to a local', async () => {
    await eq('innerread(0,0,1)', `innerread(${GRID_TUP},uint256,uint256,uint256)`, [0n, 0n, 1n]);
    await eq('innerread(1,0,0)', `innerread(${GRID_TUP},uint256,uint256,uint256)`, [1n, 0n, 0n]);
  });
  it('OOB index reverts with the same Panic kind as solc', async () => {
    const r1 = await eq('rowread OOB k', `rowread(${GRID_TUP},uint256,uint256,uint256)`, [0n, 0n, 5n]);
    expect(r1.j.success).toBe(false);
    await eq('rowread OOB i', `rowread(${GRID_TUP},uint256,uint256,uint256)`, [9n, 0n, 0n]);
    await eq('rowread OOB j', `rowread(${GRID_TUP},uint256,uint256,uint256)`, [0n, 7n, 0n]);
    await eq('innerread OOB k', `innerread(${GRID_TUP},uint256,uint256,uint256)`, [0n, 0n, 9n]);
  });
});

describe('lift: calldata field-array binding (#5a) - bytes[] tags', () => {
  const JETH = `
type S = { a: u256; tags: bytes[]; };
class C {
  get tagread(xs: S[], i: u256, j: u256): External<bytes> { let row: bytes[] = xs[i].tags; return row[j]; }
  get taglen(xs: S[], i: u256): External<u256> { let row: bytes[] = xs[i].tags; return u256(row.length); }
  get echo(xs: S[], i: u256): External<bytes[]> { let row: bytes[] = xs[i].tags; return row; }
}`;
  const SOL = `
struct S { uint256 a; bytes[] tags; }
contract C {
  function tagread(S[] calldata xs, uint256 i, uint256 j) external pure returns (bytes memory) { bytes[] memory row = xs[i].tags; return row[j]; }
  function taglen(S[] calldata xs, uint256 i) external pure returns (uint256) { bytes[] memory row = xs[i].tags; return row.length; }
  function echo(S[] calldata xs, uint256 i) external pure returns (bytes[] memory) { bytes[] memory row = xs[i].tags; return row; }
}`;
  const XS = [
    { a: 1n, tags: ['aabb', 'ccddee', ''] },
    { a: 2n, tags: ['ff'] },
  ];
  let H: Awaited<ReturnType<typeof deployPair>>;
  beforeAll(async () => {
    H = await deployPair(JETH, SOL);
  });
  async function eq(label: string, sig: string, statics: bigint[]) {
    const cd = '0x' + functionSelector(sig) + encArgs(XS, encTagS, statics);
    const j = await H.hj.call(H.aj, cd);
    const s = await H.hs.call(H.as, cd);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  it('reads + length + echo of a whole bytes[] field bound to a local', async () => {
    await eq('tagread(0,0)', `tagread(${TAG_TUP},uint256,uint256)`, [0n, 0n]);
    await eq('tagread(0,1)', `tagread(${TAG_TUP},uint256,uint256)`, [0n, 1n]);
    await eq('tagread(0,2) empty', `tagread(${TAG_TUP},uint256,uint256)`, [0n, 2n]);
    await eq('tagread(1,0)', `tagread(${TAG_TUP},uint256,uint256)`, [1n, 0n]);
    await eq('taglen(0)', `taglen(${TAG_TUP},uint256)`, [0n]);
    await eq('echo(0)', `echo(${TAG_TUP},uint256)`, [0n]);
    await eq('echo(1)', `echo(${TAG_TUP},uint256)`, [1n]);
  });
  it('OOB reverts identically', async () => {
    await eq('tagread OOB j', `tagread(${TAG_TUP},uint256,uint256)`, [0n, 9n]);
    await eq('tagread OOB i', `tagread(${TAG_TUP},uint256,uint256)`, [9n, 0n]);
  });
});

describe('lift: multi-return field component (#5b)', () => {
  const JETH = `
type S = { a: u256; grid: u256[][]; };
class C {
  get pair(xs: S[], i: u256): External<[u256[][], u256]> { return [xs[i].grid, xs[i].a]; }
  get innerpair(xs: S[], i: u256, j: u256): External<[u256[], u256]> { return [xs[i].grid[j], xs[i].a]; }
}`;
  const SOL = `
struct S { uint256 a; uint256[][] grid; }
contract C {
  function pair(S[] calldata xs, uint256 i) external pure returns (uint256[][] memory, uint256) { return (xs[i].grid, xs[i].a); }
  function innerpair(S[] calldata xs, uint256 i, uint256 j) external pure returns (uint256[] memory, uint256) { return (xs[i].grid[j], xs[i].a); }
}`;
  const XS = [
    { a: 1n, grid: [[10n, 11n], [12n]] },
    { a: 2n, grid: [[20n]] },
  ];
  let H: Awaited<ReturnType<typeof deployPair>>;
  beforeAll(async () => {
    H = await deployPair(JETH, SOL);
  });
  async function eq(label: string, sig: string, statics: bigint[]) {
    const cd = '0x' + functionSelector(sig) + encArgs(XS, encGridS, statics);
    const j = await H.hj.call(H.aj, cd);
    const s = await H.hs.call(H.as, cd);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  it('encodes a whole grid field + a value field in the return tuple', async () => {
    await eq('pair(0)', `pair(${GRID_TUP},uint256)`, [0n]);
    await eq('pair(1)', `pair(${GRID_TUP},uint256)`, [1n]);
    await eq('innerpair(0,0)', `innerpair(${GRID_TUP},uint256,uint256)`, [0n, 0n]);
    await eq('innerpair(0,1)', `innerpair(${GRID_TUP},uint256,uint256)`, [0n, 1n]);
  });
  it('OOB reverts identically', async () => {
    await eq('pair OOB i', `pair(${GRID_TUP},uint256)`, [9n]);
  });
});

describe('lift: tuple-assign to a pre-declared dynamic target (#6)', () => {
  it('self-call source: [a,b] = this.pair() (bytes,u256) and (u256[],u256)', async () => {
    const JETH = `
@contract class C {
  @external @view pair(): [bytes, u256] { return [bytes("hello"), 42n]; }
  @external @view mk(): [u256[], u256] { return [[7n,8n,9n], 3n]; }
  @external @view run(): [bytes, u256] {
    let a: bytes = bytes("");
    let b: u256 = 0n;
    [a, b] = this.pair();
    return [a, b];
  }
  @external @view arrpair(): [u256[], u256] {
    let xs: u256[] = [1n];
    let n: u256 = 0n;
    [xs, n] = this.mk();
    return [xs, n];
  }
}`;
    const SOL = `
contract C {
  function pair() public pure returns (bytes memory, uint256) { return (bytes("hello"), 42); }
  function mk() public pure returns (uint256[] memory, uint256) { uint256[] memory t = new uint256[](3); t[0]=7;t[1]=8;t[2]=9; return (t, 3); }
  function run() external view returns (bytes memory, uint256) { bytes memory a = bytes(""); uint256 b = 0; (a, b) = this.pair(); return (a, b); }
  function arrpair() external view returns (uint256[] memory, uint256) { uint256[] memory xs = new uint256[](1); xs[0]=1; uint256 n = 0; (xs, n) = this.mk(); return (xs, n); }
}`;
    const H = await deployPair(JETH, SOL);
    for (const sig of ['run()', 'arrpair()']) {
      const cd = '0x' + functionSelector(sig);
      const j = await H.hj.call(H.aj, cd);
      const s = await H.hs.call(H.as, cd);
      expect(j.success, `${sig} success`).toBe(s.success);
      expect(j.returnHex, `${sig} returndata`).toBe(s.returnHex);
      expect(j.success).toBe(true);
    }
  });

  it('abi.decode source: [a,b] = abi.decode(data, [bytes, u256])', async () => {
    const JETH = `
class C {
  get run(data: bytes): External<[bytes, u256]> {
    let a: bytes = bytes("");
    let b: u256 = 0n;
    [a, b] = abi.decode(data, [bytes, u256]);
    return [a, b];
  }
}`;
    const SOL = `
contract C {
  function run(bytes calldata data) external pure returns (bytes memory, uint256) {
    bytes memory a = bytes(""); uint256 b = 0;
    (a, b) = abi.decode(data, (bytes, uint256));
    return (a, b);
  }
}`;
    const H = await deployPair(JETH, SOL);
    // data = abi.encode(bytes "aabbccdd", 99) = [off=0x40][99][len=4][aabbccdd padded]
    const content = w(0x40) + w(99) + w(4) + ('aabbccdd' + '0'.repeat(64 - 8));
    const cpad = content + '0'.repeat((64 - (content.length % 64)) % 64);
    const args = w(0x20) + w(content.length / 2) + cpad;
    const cd = '0x' + functionSelector('run(bytes)') + args;
    const j = await H.hj.call(H.aj, cd);
    const s = await H.hs.call(H.as, cd);
    expect(j.success).toBe(s.success);
    expect(j.returnHex).toBe(s.returnHex);
    expect(j.success).toBe(true);
  });

  it('interface-call source: [a,b] = ITwo(t).pair()', async () => {
    const JETH_P = `class P { get pair(): External<[bytes, u256]> { return [bytes("yo"), 9n]; } }`;
    const JETH_C = `
interface ITwo { pair(): [bytes, u256]; }
class C {
  run(t: address): External<[bytes, u256]> {
    let a: bytes = bytes("");
    let b: u256 = 0n;
    [a, b] = ITwo(t).pair();
    return [a, b];
  }
}`;
    const SOL = `
interface ITwo { function pair() external view returns (bytes memory, uint256); }
contract P { function pair() external pure returns (bytes memory, uint256) { return (bytes("yo"), 9); } }
contract C {
  function run(address t) external returns (bytes memory, uint256) {
    bytes memory a = bytes(""); uint256 b = 0;
    (a, b) = ITwo(t).pair();
    return (a, b);
  }
}`;
    const jrP = compile(JETH_P);
    const jrC = compile(JETH_C);
    const srP = compileSolidity(SPDX + SOL, 'P');
    const srC = compileSolidity(SPDX + SOL, 'C');
    const hj = await Harness.create();
    const pj = await hj.deploy(jrP.creationBytecode);
    const cj = await hj.deploy(jrC.creationBytecode);
    const hs = await Harness.create();
    const ps = await hs.deploy(srP.creation);
    const cs = await hs.deploy(srC.creation);
    const addrArg = (a: Address) => Buffer.from(a.bytes).toString('hex').padStart(64, '0');
    const cdJ = '0x' + functionSelector('run(address)') + addrArg(pj);
    const cdS = '0x' + functionSelector('run(address)') + addrArg(ps);
    const j = await hj.call(cj, cdJ);
    const s = await hs.call(cs, cdS);
    expect(j.success).toBe(s.success);
    expect(j.returnHex).toBe(s.returnHex);
    expect(j.success).toBe(true);
  });

  it('rejects a non-re-pointable target (struct local / storage)', () => {
    const structTarget = `
type P = { x: u256; y: u256; };
class C {
  get pair(): External<[P, u256]> { return [P(3n,4n), 5n]; }
  get run(): External<u256> { let p: P = P(1n,2n); let b: u256 = 0n; [p, b] = this.pair(); return b; }
}`;
    expect(() => compile(structTarget)).toThrow();
    const storageTarget = `
class C {
  s: bytes;
  get pair(): External<[bytes, u256]> { return [bytes("x"), 1n]; }
  run(): External<void> { let b: u256 = 0n; [this.s, b] = this.pair(); }
}`;
    expect(() => compile(storageTarget)).toThrow();
  });
});
