// Phase 4d scenario "multi-aggregate-head-cursor": head-cursor correctness with
// multiple/mixed params. Verifies that the ABI head cursor advances by
// abiHeadWords (NOT 1) past each static aggregate, so every leaf read lands at the
// right offset. Differential vs solc oracle, byte-for-byte.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

// JETH source. Per-leaf readers because whole-aggregate return is rejected (JETH230).
// (1) f: uint256[2] a, Pt b, uint8[3] c, uint256 x  -> head words: a0 a1 | bx by | c0 c1 c2 | x  (8 words)
// (2) g: Pt a, Pt b                                  -> head words: ax ay | bx by              (4 words)
// (3) h: uint256 x, uint256[3] a, uint256 y          -> head words: x | a0 a1 a2 | y            (5 words)
const JETH = `// scenario multi-aggregate-head-cursor
type Pt = { x: u128; y: u128; };

class MultiAgg {
  // (1) f(uint256[2] a, Pt b, uint8[3] c, uint256 x) reading each leaf at its offset
  get fA(a: Arr<u256, 2>, b: Pt, c: Arr<u8, 3>, x: u256, i: u256): External<u256> { return a[i]; }
  get fBx(a: Arr<u256, 2>, b: Pt, c: Arr<u8, 3>, x: u256): External<u128> { return b.x; }
  get fBy(a: Arr<u256, 2>, b: Pt, c: Arr<u8, 3>, x: u256): External<u128> { return b.y; }
  get fC(a: Arr<u256, 2>, b: Pt, c: Arr<u8, 3>, x: u256, i: u256): External<u8> { return c[i]; }
  get fX(a: Arr<u256, 2>, b: Pt, c: Arr<u8, 3>, x: u256): External<u256> { return x; }

  // (2) g(Pt a, Pt b) reading a.y and b.x
  get gAy(a: Pt, b: Pt): External<u128> { return a.y; }
  get gBx(a: Pt, b: Pt): External<u128> { return b.x; }
  get gAx(a: Pt, b: Pt): External<u128> { return a.x; }
  get gBy(a: Pt, b: Pt): External<u128> { return b.y; }

  // (3) h(uint256 x, uint256[3] a, uint256 y) value-aggregate-value
  get hX(x: u256, a: Arr<u256, 3>, y: u256): External<u256> { return x; }
  get hA(x: u256, a: Arr<u256, 3>, y: u256, i: u256): External<u256> { return a[i]; }
  get hY(x: u256, a: Arr<u256, 3>, y: u256): External<u256> { return y; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MultiAgg {
  struct Pt { uint128 x; uint128 y; }
  function fA(uint256[2] calldata a, Pt calldata b, uint8[3] calldata c, uint256 x, uint256 i) external pure returns (uint256){ return a[i]; }
  function fBx(uint256[2] calldata a, Pt calldata b, uint8[3] calldata c, uint256 x) external pure returns (uint128){ return b.x; }
  function fBy(uint256[2] calldata a, Pt calldata b, uint8[3] calldata c, uint256 x) external pure returns (uint128){ return b.y; }
  function fC(uint256[2] calldata a, Pt calldata b, uint8[3] calldata c, uint256 x, uint256 i) external pure returns (uint8){ return c[i]; }
  function fX(uint256[2] calldata a, Pt calldata b, uint8[3] calldata c, uint256 x) external pure returns (uint256){ return x; }
  function gAy(Pt calldata a, Pt calldata b) external pure returns (uint128){ return a.y; }
  function gBx(Pt calldata a, Pt calldata b) external pure returns (uint128){ return b.x; }
  function gAx(Pt calldata a, Pt calldata b) external pure returns (uint128){ return a.x; }
  function gBy(Pt calldata a, Pt calldata b) external pure returns (uint128){ return b.y; }
  function hX(uint256 x, uint256[3] calldata a, uint256 y) external pure returns (uint256){ return x; }
  function hA(uint256 x, uint256[3] calldata a, uint256 y, uint256 i) external pure returns (uint256){ return a[i]; }
  function hY(uint256 x, uint256[3] calldata a, uint256 y) external pure returns (uint256){ return y; }
}`;

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}

describe('multi-aggregate-head-cursor vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  function raw(selSig: string, words: bigint[]): string {
    return '0x' + sel(selSig) + words.map(pad).join('');
  }
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  // assert JETH matches Solidity byte-for-byte (success + returndata).
  async function eq(label: string, data: string) {
    const { j, s } = await both(data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError}, jhex=${j.returnHex}, shex=${s.returnHex})`).toBe(
      s.success,
    );
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'MultiAgg.jeth' });
    const sb = compileSolidity(SOL, 'MultiAgg');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // (1) f(uint256[2] a, Pt b, uint8[3] c, uint256 x): 8 static head words.
  // Layout: word0=a[0] word1=a[1] | word2=b.x word3=b.y | word4=c[0] word5=c[1] word6=c[2] | word7=x
  it('f: mixed array+struct+array+value, every leaf at the right offset', async () => {
    const fSigA = 'fA(uint256[2],(uint128,uint128),uint8[3],uint256,uint256)';
    const fSigC = 'fC(uint256[2],(uint128,uint128),uint8[3],uint256,uint256)';
    const fSig4 = (n: string) => `${n}(uint256[2],(uint128,uint128),uint8[3],uint256)`;
    // distinct sentinel values so a wrong cursor (e.g. +1 per aggregate) would read a neighbor
    const a = [0xa0a0n, 0xa1a1n];
    const b = [0xbbb0n, 0xbbb1n]; // x, y  (uint128, in-range)
    const c = [0x10n, 0x20n, 0x30n]; // uint8, in-range
    const x = 0xdeadn;
    const head = [...a, ...b, ...c, x];

    // a[0], a[1]
    expect(decodeUint((await eq('fA i=0', raw(fSigA, [...head, 0n]))).j.returnHex)).toBe(a[0]!);
    expect(decodeUint((await eq('fA i=1', raw(fSigA, [...head, 1n]))).j.returnHex)).toBe(a[1]!);
    // b.x at word2, b.y at word3 (cursor must have advanced +2 past a, not +1)
    expect(decodeUint((await eq('fBx', raw(fSig4('fBx'), head))).j.returnHex)).toBe(b[0]!);
    expect(decodeUint((await eq('fBy', raw(fSig4('fBy'), head))).j.returnHex)).toBe(b[1]!);
    // c[0..2] at words 4,5,6 (cursor must have advanced +2 past a AND +2 past b = +4)
    for (const i of [0n, 1n, 2n]) {
      expect(decodeUint((await eq(`fC i=${i}`, raw(fSigC, [...head, i]))).j.returnHex)).toBe(c[Number(i)]!);
    }
    // x at word7 (cursor +2 +2 +3 = +7)
    expect(decodeUint((await eq('fX', raw(fSig4('fX'), head))).j.returnHex)).toBe(x);
    // runtime OOB on a (len 2) -> Panic(0x32)
    const oob = await eq('fA OOB i=2', raw(fSigA, [...head, 2n]));
    expect(oob.j.success).toBe(false);
    expect(oob.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
    // runtime OOB on c (len 3) -> Panic(0x32)
    const oobc = await eq('fC OOB i=3', raw(fSigC, [...head, 3n]));
    expect(oobc.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
  });

  // (2) g(Pt a, Pt b): 4 static head words. a.x a.y | b.x b.y
  it('g: two struct params, b.x lands at word2 not word1', async () => {
    const sig = (n: string) => `${n}((uint128,uint128),(uint128,uint128))`;
    const head = [0x1111n, 0x2222n, 0x3333n, 0x4444n]; // a.x a.y b.x b.y
    expect(decodeUint((await eq('gAx', raw(sig('gAx'), head))).j.returnHex)).toBe(0x1111n);
    expect(decodeUint((await eq('gAy', raw(sig('gAy'), head))).j.returnHex)).toBe(0x2222n);
    // b.x at word2: if cursor wrongly advanced +1 past struct a it would read 0x2222
    expect(decodeUint((await eq('gBx', raw(sig('gBx'), head))).j.returnHex)).toBe(0x3333n);
    expect(decodeUint((await eq('gBy', raw(sig('gBy'), head))).j.returnHex)).toBe(0x4444n);
  });

  // (3) h(uint256 x, uint256[3] a, uint256 y): value-aggregate-value, 5 head words.
  // x | a0 a1 a2 | y
  it('h: value-aggregate-value, trailing y past the array', async () => {
    const sig5 = 'hA(uint256,uint256[3],uint256,uint256)';
    const sig4 = (n: string) => `${n}(uint256,uint256[3],uint256)`;
    const x = 0x77n,
      a = [0xa0n, 0xa1n, 0xa2n],
      y = 0x99n;
    const head = [x, ...a, y];
    expect(decodeUint((await eq('hX', raw(sig4('hX'), head))).j.returnHex)).toBe(x);
    for (const i of [0n, 1n, 2n]) {
      expect(decodeUint((await eq(`hA i=${i}`, raw(sig5, [...head, i]))).j.returnHex)).toBe(a[Number(i)]!);
    }
    // y at word4 (cursor +1 +3 = +4)
    expect(decodeUint((await eq('hY', raw(sig4('hY'), head))).j.returnHex)).toBe(y);
    // runtime OOB on a -> Panic(0x32)
    const oob = await eq('hA OOB i=3', raw(sig5, [...head, 3n]));
    expect(oob.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
  });

  // short-calldata boundary: f needs 8 static head words (256 bytes) + selector.
  // fX takes 4 params (no runtime i), so staticHeadWords = 8. calldatasize must be
  // >= 4 + 32*8 = 260. Supply exactly 7 head words -> EMPTY revert identically.
  it('short calldata boundary (f, one short of the static head) reverts empty', async () => {
    const fSig4 = 'fX(uint256[2],(uint128,uint128),uint8[3],uint256)';
    // 7 words = 224 bytes -> 1 word short of the 8-word static head
    const head7 = [0xa0a0n, 0xa1a1n, 0xbbb0n, 0xbbb1n, 0x10n, 0x20n, 0x30n];
    const short = '0x' + sel(fSig4) + head7.map(pad).join('');
    const r = await eq('fX short (7/8 words)', short);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // exactly 8 words = the boundary -> succeeds
    const ok = await eq('fX exact (8/8 words)', '0x' + sel(fSig4) + [...head7, 0xdeadn].map(pad).join(''));
    expect(ok.j.success).toBe(true);
    expect(decodeUint(ok.j.returnHex)).toBe(0xdeadn);
    // h short: hX needs 5 static head words; supply 4.
    const hSig4 = 'hX(uint256,uint256[3],uint256)';
    const hshort = '0x' + sel(hSig4) + [0x77n, 0xa0n, 0xa1n, 0xa2n].map(pad).join('');
    const rh = await eq('hX short (4/5 words)', hshort);
    expect(rh.j.success).toBe(false);
    expect(rh.j.returnHex).toBe('0x');
  });

  // adversarial cross-check: a dirty narrow leaf that IS read reverts empty, but an
  // unread dirty leaf is ignored (lazy) -- confirms the cursor isn't over-validating.
  it('lazy dirty validation across the multi-param head', async () => {
    const fSig4 = (n: string) => `${n}(uint256[2],(uint128,uint128),uint8[3],uint256)`;
    const fSig5 = 'fC(uint256[2],(uint128,uint128),uint8[3],uint256,uint256)';
    // dirty b.x (high bits of uint128 set) read by fBx -> revert empty
    const dirtyBx = [0xa0a0n, 0xa1a1n, (1n << 200n) | 0xbbb0n, 0xbbb1n, 0x10n, 0x20n, 0x30n, 0xdeadn];
    const rbx = await eq('fBx dirty', raw(fSig4('fBx'), dirtyBx));
    expect(rbx.j.success).toBe(false);
    expect(rbx.j.returnHex).toBe('0x');
    // same dirty b.x, but fX reads only x -> OK (lazy, b.x unread)
    const rx = await eq('fX dirty-unread-bx', raw(fSig4('fX'), dirtyBx));
    expect(rx.j.success).toBe(true);
    expect(decodeUint(rx.j.returnHex)).toBe(0xdeadn);
    // dirty c[1] (uint8 high bits) read -> revert empty; reading clean c[0] -> OK
    const dirtyC = [0xa0a0n, 0xa1a1n, 0xbbb0n, 0xbbb1n, 0x10n, 0x1ffn, 0x30n, 0xdeadn];
    const rc1 = await eq('fC dirty i=1', raw(fSig5, [...dirtyC, 1n]));
    expect(rc1.j.success).toBe(false);
    expect(rc1.j.returnHex).toBe('0x');
    const rc0 = await eq('fC clean i=0', raw(fSig5, [...dirtyC, 0n]));
    expect(rc0.j.success).toBe(true);
    expect(decodeUint(rc0.j.returnHex)).toBe(0x10n);
  });
});
