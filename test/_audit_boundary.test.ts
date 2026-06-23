// AUDIT: boundary truncation + offset/length range checks, byte-exact vs solc.
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
@contract
class A {
  @external @pure sumTriple(a: Arr<u256, 3>): u256 { return a[0n] + a[1n] + a[2n]; }
  @external @pure ptX(p: Pt): u128 { return p.x; }
  @external @pure ptY(p: Pt): u128 { return p.y; }
  @external @pure arrAt(b: u256[], i: u256): u256 { return b[i]; }
  @external @pure bytesAt(s: bytes, i: u256): bytes1 { return s[i]; }
  @external @pure aggThenArr(a: Arr<u256, 3>, b: u256[], i: u256): u256 { return b[i]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct Pt { uint128 x; uint128 y; }
  function sumTriple(uint256[3] calldata a) external pure returns (uint256){ return a[0]+a[1]+a[2]; }
  function ptX(Pt calldata p) external pure returns (uint128){ return p.x; }
  function ptY(Pt calldata p) external pure returns (uint128){ return p.y; }
  function arrAt(uint256[] calldata b, uint256 i) external pure returns (uint256){ return b[i]; }
  function bytesAt(bytes calldata s, uint256 i) external pure returns (bytes1){ return s[i]; }
  function aggThenArr(uint256[3] calldata a, uint256[] calldata b, uint256 i) external pure returns (uint256){ return b[i]; }
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
const W = (v: bigint) => pad(v);

describe('truncated head boundaries (static aggregates count as multiple words)', () => {
  it('sumTriple: every truncation length 0..96 bytes', async () => {
    const sel = functionSelector('sumTriple(uint256[3])');
    const full = [W(1n), W(2n), W(3n)].join('');
    for (let nbytes = 0; nbytes <= 96; nbytes++) {
      const data = '0x' + sel + full.slice(0, nbytes * 2);
      await eq(`sumTriple trunc ${nbytes}B`, data);
    }
    // 1 byte short of a word in the last head word
    await eq('sumTriple 95B', '0x' + sel + full.slice(0, 95 * 2));
    await eq('sumTriple 96B', '0x' + sel + full.slice(0, 96 * 2));
    // extra trailing bytes (solc ignores)
    await eq('sumTriple 96B+pad', '0x' + sel + full + 'ff'.repeat(7));
  });

  it('Pt struct: truncation at 0,32,63,64 bytes', async () => {
    const sel = functionSelector('ptY((uint128,uint128))');
    const full = [W(0xcafen), W(0xbeefn)].join('');
    for (const n of [0, 31, 32, 63, 64]) {
      await eq(`ptY trunc ${n}B`, '0x' + sel + full.slice(0, n * 2));
    }
  });
});

describe('offset/length inclusive boundaries on a dyn array param', () => {
  it('arrAt: offset and payload exactly at calldatasize', async () => {
    const sel = functionSelector('arrAt(uint256[],uint256)');
    // canonical: off=0x40, i=0, len=1, elem. total = 4+ (2 head + 2 tail)*32.
    const head = [W(0x40n), W(0n)].join('');
    const tail = [W(1n), W(0x77n)].join('');
    await eq('arrAt canon', '0x' + sel + head + tail);
    // payload one byte short: drop last byte of element -> EMPTY both
    const dataShort = '0x' + sel + head + tail.slice(0, tail.length - 2);
    await eq('arrAt payload 1B short', dataShort);
    // off points so that length word ends exactly at calldatasize but no payload
    // len declared 1 but no element -> EMPTY
    const head2 = [W(0x40n), W(0n)].join('');
    await eq('arrAt len1 no elem', '0x' + sel + head2 + W(1n));
    // len declared 0 at the boundary -> empty array, i=0 -> Panic(0x32)
    await eq('arrAt len0 i0', '0x' + sel + head2 + W(0n));
    // huge offset
    await eq('arrAt huge off', '0x' + sel + [W(1n << 200n), W(0n)].join('') + tail);
    // off = exactly calldatasize-4-0x20 region edge
  });

  it('bytesAt: payload inclusive boundary + index', async () => {
    const sel = functionSelector('bytesAt(bytes,uint256)');
    // s len=3 "abc". head: off=0x40, i. tail [3]["abc"00..].
    const head = [W(0x40n), W(0n)].join('');
    const payload = pad(BigInt('0x616263') << BigInt(29 * 8));
    const tail = [W(3n), payload].join('');
    await eq('bytesAt i0', '0x' + sel + head + tail);
    await eq('bytesAt i2', '0x' + sel + [W(0x40n), W(2n)].join('') + tail);
    await eq('bytesAt OOB i3', '0x' + sel + [W(0x40n), W(3n)].join('') + tail);
    // truncate payload word entirely (len=3 but no payload word) -> EMPTY
    await eq('bytesAt no payload', '0x' + sel + head + W(3n));
  });
});

describe('static aggregate before dyn array: head-cursor truncation', () => {
  it('aggThenArr: head needs 5 words; truncate at each word boundary', async () => {
    const sel = functionSelector('aggThenArr(uint256[3],uint256[],uint256)');
    const head = [W(10n), W(20n), W(30n), W(0xa0n), W(0n)].join('');
    const tail = [W(1n), W(0x99n)].join('');
    for (const n of [0, 32, 64, 96, 128, 159, 160]) {
      await eq(`aggThenArr head trunc ${n}B`, '0x' + sel + (head + tail).slice(0, n * 2));
    }
    await eq('aggThenArr full', '0x' + sel + head + tail);
  });
});
