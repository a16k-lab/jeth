// Phase 4d scenario "aggregate-plus-dynamic-sibling" — INDEPENDENT differential
// harness (unique file name to avoid collision with parallel agents).
//
// A static aggregate param (fixed array / struct) sits next to a DYNAMIC sibling
// (u256[] / bytes). The ABI head is FLAT + UNPACKED: the aggregate's leaves are
// inline (one word each), the dynamic param contributes ONE offset word, and the
// dynamic tail base is byte 4 (right after the selector). Solidity (solc, cancun,
// optimized) is the oracle; every probe must be byte-identical (success +
// returndata + revert form).
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AggDynSibling {
  struct Pt { uint128 x; uint128 y; }
  function sumAt(uint256[3] calldata a, uint256[] calldata b, uint256 i) external pure returns (uint256){ return a[i] + b[i]; }
  function aAt(uint256[3] calldata a, uint256[] calldata b, uint256 i) external pure returns (uint256){ return a[i]; }
  function bAt(uint256[3] calldata a, uint256[] calldata b, uint256 i) external pure returns (uint256){ return b[i]; }
  function bLen(uint256[3] calldata a, uint256[] calldata b, uint256 i) external pure returns (uint256){ return b.length; }
  function ptXof(Pt calldata p, bytes calldata data) external pure returns (uint128){ return p.x; }
  function ptYof(Pt calldata p, bytes calldata data) external pure returns (uint128){ return p.y; }
  function dataLen(Pt calldata p, bytes calldata data) external pure returns (uint256){ return data.length; }
  function dataAt(Pt calldata p, bytes calldata data, uint256 k) external pure returns (bytes1){ return data[k]; }
}`;

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}
const PANIC32 = '0x4e487b71' + pad(0x32n);
const sel = (s: string) => functionSelector(s);

describe('aggregate + dynamic sibling vs Solidity (independent)', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;

  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  // Byte-for-byte equality of success + returndata between JETH and solc.
  async function eq(label: string, data: string) {
    const { j, s } = await both(data);
    expect(
      j.success,
      `${label} success (jeth err=${j.exceptionError}; jeth ret=${j.returnHex}; sol ret=${s.returnHex})`,
    ).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', '_gen4d_AggDynSibling.jeth'), 'utf8');
    const jb = compile(src, { fileName: '_gen4d_AggDynSibling.jeth' });
    const sb = compileSolidity(SOL, 'AggDynSibling');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // ===== Part 1: f(uint256[3] a, uint256[] b, uint256 i) =====
  // Head = a0,a1,a2, offset(b), i  => 5 words (160 bytes). Tail base = byte 4.
  // With b's tail placed immediately after the head, offset(b) = 160 = 0xa0.
  function p1(selSig: string, a: bigint[], b: bigint[], i: bigint, offB = 0xa0n): string {
    const head = [a[0]!, a[1]!, a[2]!, offB, i];
    const tail = [BigInt(b.length), ...b];
    return '0x' + sel(selSig) + [...head, ...tail].map(pad).join('');
  }

  it('valid reads: a[i]+b[i], a[i], b[i], b.length over a clean tail', async () => {
    const a = [10n, 20n, 30n];
    const b = [100n, 200n, 300n, 400n];
    for (const i of [0n, 1n, 2n]) {
      const r = await eq(`sumAt i=${i}`, p1('sumAt(uint256[3],uint256[],uint256)', a, b, i));
      expect(decodeUint(r.j.returnHex)).toBe(a[Number(i)]! + b[Number(i)]!);
    }
    expect(decodeUint((await eq('aAt i=2', p1('aAt(uint256[3],uint256[],uint256)', a, b, 2n))).j.returnHex)).toBe(30n);
    expect(decodeUint((await eq('bAt i=3', p1('bAt(uint256[3],uint256[],uint256)', a, b, 3n))).j.returnHex)).toBe(400n);
    expect(decodeUint((await eq('bLen', p1('bLen(uint256[3],uint256[],uint256)', a, b, 0n))).j.returnHex)).toBe(4n);
  });

  it('b tail placed AFTER the i word (offset 0xc0) still resolves identically', async () => {
    // Put a one-word gap (the i word lives at 0x80) then the tail at 0xa0..; but
    // here we deliberately move the tail one extra word out to test offset!=0xa0.
    const a = [1n, 2n, 3n];
    const b = [77n, 88n];
    const head = [a[0]!, a[1]!, a[2]!, 0xc0n, 0n]; // offset(b)=0xc0, i=0
    const gap = [0xdeadn]; // junk word at 0xa0 (ignored)
    const tail = [BigInt(b.length), ...b]; // length+elems at 0xc0
    const data = '0x' + sel('bAt(uint256[3],uint256[],uint256)') + [...head, ...gap, ...tail].map(pad).join('');
    expect(decodeUint((await eq('bAt offset=0xc0', data)).j.returnHex)).toBe(77n);
  });

  it('runtime OOB on dynamic sibling b -> Panic(0x32) identically', async () => {
    const r = await eq('bAt OOB i=2', p1('bAt(uint256[3],uint256[],uint256)', [1n, 2n, 3n], [7n, 8n], 2n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(PANIC32);
  });

  it('runtime OOB on static fixed array a -> Panic(0x32) identically', async () => {
    const r = await eq('aAt OOB i=3', p1('aAt(uint256[3],uint256[],uint256)', [1n, 2n, 3n], [7n, 8n, 9n, 10n], 3n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(PANIC32);
  });

  it('malformed b offset (huge, length word OOB) -> EMPTY revert identically', async () => {
    const r = await eq(
      'bAt bad-offset huge',
      p1('bAt(uint256[3],uint256[],uint256)', [1n, 2n, 3n], [7n, 8n], 0n, 1n << 64n),
    );
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('b offset points at the i word claiming a huge length; element read OOB -> EMPTY', async () => {
    // offset -> the i word (0x80), which solc reads as the array length. With a
    // huge "length", reading element 0 lands past calldatasize -> EMPTY revert.
    const head = [1n, 2n, 3n, 0x80n, 1n << 200n];
    const data = '0x' + sel('bAt(uint256[3],uint256[],uint256)') + head.map(pad).join('');
    const r = await eq('bAt offset->huge-len', data);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('b offset == calldatasize (length word itself is OOB) -> EMPTY revert', async () => {
    // Head is 5 words = 160 bytes => calldatasize without tail = 4 + 160 = 164.
    // offset measured from byte 4; an offset of exactly 160 puts the length word
    // at bytes [164,196) which does not exist -> reading length is OOB -> EMPTY.
    const head = [1n, 2n, 3n, 0xa0n, 0n]; // offset(b)=0xa0=160, NO tail appended
    const data = '0x' + sel('bAt(uint256[3],uint256[],uint256)') + head.map(pad).join('');
    const r = await eq('bAt offset==size', data);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('short calldata (< static head) reverts EMPTY identically', async () => {
    const short = '0x' + sel('sumAt(uint256[3],uint256[],uint256)') + [1n, 2n, 3n, 0xa0n].map(pad).join('');
    const r = await eq('sumAt short', short);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('extra trailing bytes after a valid tail are ignored identically', async () => {
    const a = [5n, 6n, 7n];
    const b = [9n];
    const base = p1('bAt(uint256[3],uint256[],uint256)', a, b, 0n); // valid, returns 9
    const withJunk = base + 'ab'.repeat(48); // 96 stray bytes, not word-aligned count
    const r = await eq('bAt trailing junk', withJunk);
    expect(decodeUint(r.j.returnHex)).toBe(9n);
  });

  // ===== Part 2: g(Pt p, bytes data[, uint256 k]) =====
  // Head = p.x, p.y, offset(data) [, k] => 3 (or 4) words. Tail base = byte 4.
  function p2(selSig: string, x: bigint, y: bigint, data: Uint8Array, offD = 0x60n, extraHead: bigint[] = []): string {
    const head = [x, y, offD, ...extraHead];
    const len = BigInt(data.length);
    const tail: bigint[] = [len];
    for (let o = 0; o < data.length; o += 32) {
      const chunk = new Uint8Array(32);
      chunk.set(data.subarray(o, o + 32), 0); // left-aligned, right-padded
      tail.push(BigInt('0x' + Buffer.from(chunk).toString('hex')));
    }
    return '0x' + sel(selSig) + [...head, ...tail].map(pad).join('');
  }

  it('struct inline + bytes tail: p.x, p.y, data.length', async () => {
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01]);
    expect(
      decodeUint((await eq('ptXof', p2('ptXof((uint128,uint128),bytes)', 0xcafen, 0xbeefn, data))).j.returnHex),
    ).toBe(0xcafen);
    expect(
      decodeUint((await eq('ptYof', p2('ptYof((uint128,uint128),bytes)', 0xcafen, 0xbeefn, data))).j.returnHex),
    ).toBe(0xbeefn);
    expect(
      decodeUint((await eq('dataLen', p2('dataLen((uint128,uint128),bytes)', 0xcafen, 0xbeefn, data))).j.returnHex),
    ).toBe(5n);
  });

  it('bytes data[k]: valid k (left-aligned bytes1) and OOB k -> Panic(0x32)', async () => {
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01]);
    // dataAt has a 4th head word k; with a 4-word head, offset(data)=0x80.
    const p2k = (k: bigint) => p2('dataAt((uint128,uint128),bytes,uint256)', 0xcafen, 0xbeefn, data, 0x80n, [k]);
    for (let k = 0n; k < 5n; k++) {
      const r = await eq(`dataAt k=${k}`, p2k(k));
      expect(r.j.returnHex.slice(0, 4)).toBe('0x' + data[Number(k)]!.toString(16).padStart(2, '0'));
    }
    const r = await eq('dataAt OOB k=5', p2k(5n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(PANIC32);
  });

  it('lazy dirty struct leaves: read dirty leaf reverts EMPTY, read clean sibling OK', async () => {
    const data = new Uint8Array([0x11]);
    // dirty p.x (bit128 set): reading p.x reverts EMPTY...
    let r = await eq('ptXof dirty-x read', p2('ptXof((uint128,uint128),bytes)', (1n << 128n) | 0x1n, 0x2n, data));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // ...but reading p.y (clean) with the same dirty x is fine (lazy per-access).
    r = await eq('ptYof dirty-x unread', p2('ptYof((uint128,uint128),bytes)', (1n << 128n) | 0x1n, 0x2n, data));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0x2n);
    // symmetric: dirty p.y read reverts EMPTY; reading p.x (clean) is fine.
    r = await eq('ptYof dirty-y read', p2('ptYof((uint128,uint128),bytes)', 0x3n, (1n << 200n) | 0x4n, data));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    r = await eq('ptXof dirty-y unread', p2('ptXof((uint128,uint128),bytes)', 0x3n, (1n << 200n) | 0x4n, data));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0x3n);
  });

  it('struct + bytes short calldata (< static head) reverts EMPTY identically', async () => {
    const short = '0x' + sel('ptXof((uint128,uint128),bytes)') + [0xcafen, 0xbeefn].map(pad).join('');
    const r = await eq('ptXof short', short);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('bytes data offset pointing past calldata -> EMPTY revert identically', async () => {
    const data = new Uint8Array([0x11, 0x22]);
    const r = await eq('dataLen bad-offset', p2('dataLen((uint128,uint128),bytes)', 1n, 2n, data, 1n << 64n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  // ===== Part 3: compile-time gates (JETH must mirror solc's static rejections) =====
  it('returning a whole STATIC struct / fixed-array param now compiles (G5, matches solc)', () => {
    // Formerly a JETH-only JETH230 rejection; solc always accepted these, and G5 now does too
    // (byte-identical echo, verified in test/calldata-agg-return.test.ts).
    for (const src of [
      `type Pt = { x: u128; y: u128; };
class G { get retP(p: Pt): External<Pt> { return p; } }`,
      `class G { get retA(a: Arr<u256,3>): External<Arr<u256,3>> { return a; } }`,
    ]) {
      let codes: string[] | null = null;
      try {
        compile(src, { fileName: 'Gate.jeth' });
      } catch (e: any) {
        codes = (e.diagnostics ?? []).map((d: any) => d.code);
      }
      expect(codes, `expected clean compile for: ${src.slice(0, 40)}`).toBeNull();
    }
  });

  it('GATE: constant OOB index a[3n] on Arr<u256,3> is a COMPILE error (mirrors solc)', () => {
    const src = `class G { get oob(a: Arr<u256,3>, b: u256[]): External<u256> { return a[3n]; } }`;
    let threw = false;
    try {
      compile(src, { fileName: 'Gate.jeth' });
    } catch {
      threw = true;
    }
    expect(threw, 'constant OOB index must be a compile error, never a runtime Panic').toBe(true);
  });
});
