// AUDIT: mixed static-aggregate + multiple dynamic params, head cursor + tail base.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = (1n << 256n);
function pad(v: bigint): string { return (((v % M) + M) % M).toString(16).padStart(64, '0'); }

const JETH = `
@struct class Pt { x: u128; y: u128; }
@contract
class A {
  // static aggregate BEFORE a dynamic array param
  @external @pure aggThenArr(a: Arr<u256, 3>, b: u256[], i: u256): u256 { return a[2n] + b[i]; }
  // static struct then bytes then dyn array
  @external @pure structThenDyn(p: Pt, s: bytes, b: u256[], i: u256): u256 { return b[i]; }
  @external @pure structThenDynY(p: Pt, s: bytes, b: u256[], i: u256): u128 { return p.y; }
  // dyn array, static aggregate, dyn array (aggregate in the MIDDLE)
  @external @pure arrAggArr(b: u256[], a: Arr<u256, 2>, c: u256[], i: u256): u256 { return b[i] + a[1n] + c[0n]; }
  // two dynamic arrays + a value
  @external @pure twoArr(b: u256[], c: u256[], i: u256, j: u256): u256 { return b[i] + c[j]; }
  // fixed-array-of-struct then dyn array
  @external @pure fasThenArr(ps: Arr<Pt, 2>, b: u256[], i: u256): u128 { return ps[1n].x; }
  @external @pure fasThenArrB(ps: Arr<Pt, 2>, b: u256[], i: u256): u256 { return b[i]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct Pt { uint128 x; uint128 y; }
  function aggThenArr(uint256[3] calldata a, uint256[] calldata b, uint256 i) external pure returns (uint256){ return a[2]+b[i]; }
  function structThenDyn(Pt calldata p, bytes calldata s, uint256[] calldata b, uint256 i) external pure returns (uint256){ return b[i]; }
  function structThenDynY(Pt calldata p, bytes calldata s, uint256[] calldata b, uint256 i) external pure returns (uint128){ return p.y; }
  function arrAggArr(uint256[] calldata b, uint256[2] calldata a, uint256[] calldata c, uint256 i) external pure returns (uint256){ return b[i]+a[1]+c[0]; }
  function twoArr(uint256[] calldata b, uint256[] calldata c, uint256 i, uint256 j) external pure returns (uint256){ return b[i]+c[j]; }
  function fasThenArr(Pt[2] calldata ps, uint256[] calldata b, uint256 i) external pure returns (uint128){ return ps[1].x; }
  function fasThenArrB(Pt[2] calldata ps, uint256[] calldata b, uint256 i) external pure returns (uint256){ return b[i]; }
}`;

let jeth: Harness, sol: Harness, aj: Address, as: Address;
beforeAll(async () => {
  const jb = compile(JETH, { fileName: 'A.jeth' });
  const sb = compileSolidity(SOL, 'A');
  jeth = await Harness.create(); sol = await Harness.create();
  aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
});
async function eq(label: string, data: string) {
  const j = await jeth.call(aj, data); const s = await sol.call(as, data);
  expect(j.success, `${label} success jeth=${j.success}/${j.exceptionError} sol=${s.success}`).toBe(s.success);
  expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  return { j, s };
}
const W = (v: bigint) => pad(v);

describe('mixed aggregate + multiple dynamic params', () => {
  it('aggThenArr: static[3] then dyn array; canonical tail', async () => {
    // head: a (3 words inline), off_b, i  => 5 head words. off_b base = byte4.
    // head bytes = 5*32 = 0xA0. b tail at 0xA0.
    const sel = functionSelector('aggThenArr(uint256[3],uint256[],uint256)');
    const head = [W(10n), W(20n), W(30n), W(0xa0n), W(1n)].join(''); // a, off_b=0xA0, i=1
    const tail = [W(3n), W(0xb0n), W(0xb1n), W(0xb2n)].join('');     // b.len=3, elems
    await eq('aggThenArr canon', '0x' + sel + head + tail);
    // OOB i=3
    const head2 = [W(10n), W(20n), W(30n), W(0xa0n), W(3n)].join('');
    await eq('aggThenArr OOB', '0x' + sel + head2 + tail);
  });

  it('arrAggArr: dyn, static[2], dyn (aggregate in middle shifts head)', async () => {
    // head: off_b, a(2 inline), off_c, i => 5 head words = 0xA0.
    const sel = functionSelector('arrAggArr(uint256[],uint256[2],uint256[],uint256)');
    // b at 0xA0 (len2), c after b. b uses 1+2 words = 0x60 bytes. c at 0xA0+0x60=0x100.
    const head = [W(0xa0n), W(100n), W(200n), W(0x100n), W(0n)].join('');
    const tailB = [W(2n), W(7n), W(8n)].join('');
    const tailC = [W(1n), W(9n)].join('');
    await eq('arrAggArr canon', '0x' + sel + head + tailB + tailC);
  });

  it('twoArr: two dyn arrays + values, swapped offsets', async () => {
    const sel = functionSelector('twoArr(uint256[],uint256[],uint256,uint256)');
    // head: off_b, off_c, i, j = 4 words = 0x80. b at 0x80(len1), c at 0xC0(len1).
    const head = [W(0x80n), W(0xc0n), W(0n), W(0n)].join('');
    const tailB = [W(1n), W(0xaan)].join('');
    const tailC = [W(1n), W(0xbbn)].join('');
    await eq('twoArr canon', '0x' + sel + head + tailB + tailC);
    // swapped offsets: off_b->c's tail, off_c->b's tail (solc accepts pure ptr arith)
    const headSwap = [W(0xc0n), W(0x80n), W(0n), W(0n)].join('');
    await eq('twoArr swapped', '0x' + sel + headSwap + tailB + tailC);
    // overlapping (both point to same tail)
    const headOv = [W(0x80n), W(0x80n), W(0n), W(0n)].join('');
    await eq('twoArr overlap', '0x' + sel + headOv + tailB);
  });

  it('structThenDyn: static struct + bytes + dyn array', async () => {
    const sel = functionSelector('structThenDyn((uint128,uint128),bytes,uint256[],uint256)');
    // head: p(2 inline), off_s, off_b, i = 5 words = 0xA0.
    // s = bytes "hi" (len2). s tail at 0xA0: [len2][payload]. = 0x40 bytes. b at 0xE0.
    const head = [W(0xcafen), W(0xbeefn), W(0xa0n), W(0xe0n), W(0n)].join('');
    const sTail = [W(2n), pad(BigInt('0x6869') << BigInt(30 * 8))].join('');
    const bTail = [W(1n), W(0x42n)].join('');
    await eq('structThenDyn canon', '0x' + sel + head + sTail + bTail);
    const selY = functionSelector('structThenDynY((uint128,uint128),bytes,uint256[],uint256)');
    await eq('structThenDynY canon', '0x' + selY + head + sTail + bTail);
  });

  it('non-canonical tail gaps (injected padding) decode by pointer arithmetic', async () => {
    const sel = functionSelector('aggThenArr(uint256[3],uint256[],uint256)');
    // inject a 32-byte gap before b's tail: off_b = 0xC0 (head 0xA0 + 0x20 gap).
    const head = [W(10n), W(20n), W(30n), W(0xc0n), W(2n)].join('');
    const gap = W(0xdeadn);
    const tail = [W(3n), W(0xb0n), W(0xb1n), W(0xb2n)].join('');
    await eq('aggThenArr gap', '0x' + sel + head + gap + tail);
  });
});
