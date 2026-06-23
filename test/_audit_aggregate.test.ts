// AUDIT: aggregate-params-and-nesting. Differential vs solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}

const JETH = `
@struct class Pt { x: u128; y: u128; }
@struct class Acct { bal: u128; nonce: u64; active: bool; }
@struct class Inner { a: u128; b: u128; }
@struct class Outer { p: u64; inner: Inner; q: u64; }
@struct class WithArr { id: u64; data: Arr<u256, 2>; }
@struct class Deep { tag: u32; mat: Arr<Arr<u64, 2>, 2>; tail: u16; }
@struct class Mixed3 { a: address; b: bytes4; c: i64; }

@contract
class A {
  @external @pure sumTriple(a: Arr<u256, 3>): u256 { return a[0n] + a[1n] + a[2n]; }
  @external @pure pick(a: Arr<u8, 4>, i: u256): u8 { return a[i]; }
  @external @pure pickI(a: Arr<i64, 4>, i: u256): i64 { return a[i]; }
  @external @pure pickB(a: Arr<bytes4, 4>, i: u256): bytes4 { return a[i]; }
  @external @pure pickBool(a: Arr<bool, 4>, i: u256): bool { return a[i]; }
  @external @pure ptX(p: Pt): u128 { return p.x; }
  @external @pure ptY(p: Pt): u128 { return p.y; }
  @external @pure acctNonce(a: Acct): u64 { return a.nonce; }
  @external @pure acctActive(a: Acct): bool { return a.active; }
  @external @pure acctBal(a: Acct): u128 { return a.bal; }
  @external @pure outerInnerA(o: Outer): u128 { return o.inner.a; }
  @external @pure outerInnerB(o: Outer): u128 { return o.inner.b; }
  @external @pure outerP(o: Outer): u64 { return o.p; }
  @external @pure outerQ(o: Outer): u64 { return o.q; }
  @external @pure withId(t: WithArr): u64 { return t.id; }
  @external @pure dataAt(t: WithArr, j: u256): u256 { return t.data[j]; }
  @external @pure ptsX(ps: Arr<Pt, 2>, i: u256): u128 { return ps[i].x; }
  @external @pure ptsY(ps: Arr<Pt, 2>, i: u256): u128 { return ps[i].y; }
  @external @pure afterAgg(a: Arr<u256, 3>, x: u256): u256 { return a[2n] + x; }
  @external @pure deepMat(d: Deep, i: u256, j: u256): u64 { return d.mat[i][j]; }
  @external @pure deepTail(d: Deep): u16 { return d.tail; }
  @external @pure deepTag(d: Deep): u32 { return d.tag; }
  @external @pure mixA(m: Mixed3): address { return m.a; }
  @external @pure mixB(m: Mixed3): bytes4 { return m.b; }
  @external @pure mixC(m: Mixed3): i64 { return m.c; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct Pt { uint128 x; uint128 y; }
  struct Acct { uint128 bal; uint64 nonce; bool active; }
  struct Inner { uint128 a; uint128 b; }
  struct Outer { uint64 p; Inner inner; uint64 q; }
  struct WithArr { uint64 id; uint256[2] data; }
  struct Deep { uint32 tag; uint64[2][2] mat; uint16 tail; }
  struct Mixed3 { address a; bytes4 b; int64 c; }
  function sumTriple(uint256[3] calldata a) external pure returns (uint256){ return a[0]+a[1]+a[2]; }
  function pick(uint8[4] calldata a, uint256 i) external pure returns (uint8){ return a[i]; }
  function pickI(int64[4] calldata a, uint256 i) external pure returns (int64){ return a[i]; }
  function pickB(bytes4[4] calldata a, uint256 i) external pure returns (bytes4){ return a[i]; }
  function pickBool(bool[4] calldata a, uint256 i) external pure returns (bool){ return a[i]; }
  function ptX(Pt calldata p) external pure returns (uint128){ return p.x; }
  function ptY(Pt calldata p) external pure returns (uint128){ return p.y; }
  function acctNonce(Acct calldata a) external pure returns (uint64){ return a.nonce; }
  function acctActive(Acct calldata a) external pure returns (bool){ return a.active; }
  function acctBal(Acct calldata a) external pure returns (uint128){ return a.bal; }
  function outerInnerA(Outer calldata o) external pure returns (uint128){ return o.inner.a; }
  function outerInnerB(Outer calldata o) external pure returns (uint128){ return o.inner.b; }
  function outerP(Outer calldata o) external pure returns (uint64){ return o.p; }
  function outerQ(Outer calldata o) external pure returns (uint64){ return o.q; }
  function withId(WithArr calldata t) external pure returns (uint64){ return t.id; }
  function dataAt(WithArr calldata t, uint256 j) external pure returns (uint256){ return t.data[j]; }
  function ptsX(Pt[2] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].x; }
  function ptsY(Pt[2] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].y; }
  function afterAgg(uint256[3] calldata a, uint256 x) external pure returns (uint256){ return a[2]+x; }
  function deepMat(Deep calldata d, uint256 i, uint256 j) external pure returns (uint64){ return d.mat[i][j]; }
  function deepTail(Deep calldata d) external pure returns (uint16){ return d.tail; }
  function deepTag(Deep calldata d) external pure returns (uint32){ return d.tag; }
  function mixA(Mixed3 calldata m) external pure returns (address){ return m.a; }
  function mixB(Mixed3 calldata m) external pure returns (bytes4){ return m.b; }
  function mixC(Mixed3 calldata m) external pure returns (int64){ return m.c; }
}`;

let jeth: Harness, sol: Harness, aj: Address, as: Address;

beforeAll(async () => {
  const jb = compile(JETH, { fileName: 'A.jeth' });
  const sb = compileSolidity(SOL, 'A');
  jeth = await Harness.create();
  sol = await Harness.create();
  aj = await jeth.deploy(jb.creationBytecode);
  as = await sol.deploy(sb.creation);
});

async function eq(label: string, data: string) {
  const j = await jeth.call(aj, data);
  const s = await sol.call(as, data);
  expect(j.success, `${label} success jeth=${j.success}/${j.exceptionError} sol=${s.success}`).toBe(s.success);
  expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  return { j, s };
}

function raw(sig: string, words: bigint[]): string {
  return '0x' + functionSelector(sig) + words.map(pad).join('');
}

describe('audit aggregate-params: signed/bytesN/bool/address leaves', () => {
  it('intN element + sign-extension via fixed array', async () => {
    // negative int64 element: high bytes should sign-extend on read
    // Provide a clean -5 (full sign extension)
    const cleanNeg = ((-5n % M) + M) % M;
    for (const i of [0n, 1n, 2n, 3n]) {
      await eq(`pickI clean i=${i}`, raw('pickI(int64[4],uint256)', [cleanNeg, 7n, M - 1n, 0n, i]));
    }
    // a DIRTY int64 element (low 8 bytes not equal sign-extension): solc reverts EMPTY on read
    const dirty = (1n << 100n) | 5n; // high bits set, not a sign-extension
    await eq('pickI dirty read i=0', raw('pickI(int64[4],uint256)', [dirty, 0n, 0n, 0n, 0n]));
    await eq('pickI dirty unread i=1', raw('pickI(int64[4],uint256)', [dirty, 9n, 0n, 0n, 1n]));
  });

  it('bytes4 element validation', async () => {
    const b = BigInt('0xdeadbeef') << BigInt((32 - 4) * 8); // left-aligned bytes4
    await eq('pickB clean i=0', raw('pickB(bytes4[4],uint256)', [b, 0n, 0n, 0n, 0n]));
    // dirty bytes4 (low bytes nonzero)
    const dirtyB = b | 1n;
    await eq('pickB dirty i=0', raw('pickB(bytes4[4],uint256)', [dirtyB, 0n, 0n, 0n, 0n]));
    await eq('pickB dirty unread i=1', raw('pickB(bytes4[4],uint256)', [dirtyB, b, 0n, 0n, 1n]));
  });

  it('bool element validation', async () => {
    await eq('pickBool true', raw('pickBool(bool[4],uint256)', [1n, 0n, 1n, 0n, 0n]));
    await eq('pickBool dirty=2', raw('pickBool(bool[4],uint256)', [2n, 0n, 0n, 0n, 0n]));
    await eq('pickBool dirty unread', raw('pickBool(bool[4],uint256)', [2n, 1n, 0n, 0n, 1n]));
  });

  it('mixed struct fields: address, bytes4, int64 alignment + validation', async () => {
    const addr = BigInt('0x' + 'ab'.repeat(20));
    const b4 = BigInt('0xcafebabe') << BigInt((32 - 4) * 8);
    const c = ((-1000n % M) + M) % M;
    await eq('mixA', raw('mixA((address,bytes4,int64))', [addr, b4, c]));
    await eq('mixB', raw('mixB((address,bytes4,int64))', [addr, b4, c]));
    await eq('mixC', raw('mixC((address,bytes4,int64))', [addr, b4, c]));
    // dirty address
    await eq('mixA dirty addr', raw('mixA((address,bytes4,int64))', [(1n << 200n) | addr, b4, c]));
    // dirty bytes4
    await eq('mixB dirty b4', raw('mixB((address,bytes4,int64))', [addr, b4 | 5n, c]));
    // dirty int64
    await eq('mixC dirty c', raw('mixC((address,bytes4,int64))', [addr, b4, (1n << 200n) | 5n]));
    // unread-dirty: read mixA while c dirty -> lazy, OK
    await eq('mixA dirty-unread-c', raw('mixA((address,bytes4,int64))', [addr, b4, (1n << 200n) | 5n]));
  });
});

describe('audit aggregate-params: deep nested struct with matrix field', () => {
  // Deep { uint32 tag; uint64[2][2] mat; uint16 tail; }
  // ABI head: tag(1) + mat(4 words: m00,m01,m10,m11) + tail(1) = 6 words
  function deepWords(tag: bigint, mat: bigint[][], tail: bigint): bigint[] {
    return [tag, mat[0]![0]!, mat[0]![1]!, mat[1]![0]!, mat[1]![1]!, tail];
  }
  it('deepMat all i,j + tag + tail', async () => {
    const mat = [
      [100n, 101n],
      [110n, 111n],
    ];
    const base = deepWords(7n, mat, 0x9999n);
    await eq('deepTag', raw('deepTag((uint32,uint64[2][2],uint16))', base));
    await eq('deepTail', raw('deepTail((uint32,uint64[2][2],uint16))', base));
    for (const i of [0n, 1n])
      for (const j of [0n, 1n]) {
        await eq(`deepMat ${i},${j}`, raw('deepMat((uint32,uint64[2][2],uint16),uint256,uint256)', [...base, i, j]));
      }
    // OOB i and j
    await eq('deepMat OOB i', raw('deepMat((uint32,uint64[2][2],uint16),uint256,uint256)', [...base, 2n, 0n]));
    await eq('deepMat OOB j', raw('deepMat((uint32,uint64[2][2],uint16),uint256,uint256)', [...base, 0n, 2n]));
    // dirty mat element
    const dirtyMat = [...base];
    dirtyMat[3] = (1n << 100n) | 5n; // m10 dirty uint64
    await eq(
      'deepMat dirty read 1,0',
      raw('deepMat((uint32,uint64[2][2],uint16),uint256,uint256)', [...dirtyMat, 1n, 0n]),
    );
    await eq(
      'deepMat dirty unread 0,0',
      raw('deepMat((uint32,uint64[2][2],uint16),uint256,uint256)', [...dirtyMat, 0n, 0n]),
    );
    // dirty tag/tail read
    const dt = [...base];
    dt[0] = (1n << 100n) | 7n;
    await eq('deepTag dirty', raw('deepTag((uint32,uint64[2][2],uint16),uint256,uint256)', dt));
  });
});
