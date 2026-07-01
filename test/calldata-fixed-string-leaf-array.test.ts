// A DYNAMIC-outer array whose element is a FIXED array of a dynamic leaf: Arr<string,2>[] (solc
// `string[2][] calldata`). The outer is a dynamic `[len][elem offsets][elem blocks]`; each element is a
// fixed string[2] block of `[2 head offsets][2 string tails]`, offsets relative to that block's start.
// Reading a leaf xs[i][j] follows the outer offset to the element block, then the block's j-th head
// offset to the string tail. Byte-identical to solc 0.8.35 (length, in-bounds leaf reads, OOB Panic).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => BigInt(n).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

// ---- ABI encoder for string[2][] (no 0x) ----------------------------------
const encStr = (s: string): string => {
  const h = Buffer.from(s, 'utf8').toString('hex');
  const len = h.length / 2;
  const words = Math.ceil(len / 32);
  return W(len) + h.padEnd(words * 64, '0');
};
// a fixed string[2] block: [off(a), off(b)] then the two string tails (offsets relative to block start).
const fixedPair = (a: string, b: string): string => {
  const t1 = encStr(a);
  const t2 = encStr(b);
  return W(64) + W(64 + t1.length / 2) + t1 + t2;
};
// the dynamic outer string[2][]: [len][elem offsets][elem blocks], offsets relative to the outer start.
const dynOuter = (pairs: [string, string][]): string => {
  const blocks = pairs.map(([a, b]) => fixedPair(a, b));
  let cur = pairs.length * 32; // offsets start after the offset table
  const offs: string[] = [];
  for (const b of blocks) {
    offs.push(W(cur));
    cur += b.length / 2;
  }
  return W(pairs.length) + offs.join('') + blocks.join('');
};
// a single dynamic param: outer offset (0x20) then the outer array region.
const arg = (pairs: [string, string][]) => W(0x20) + dynOuter(pairs);
// two params (string[2][] xs, uint256 i): head is [offset-to-xs=0x40][i], then the xs region at 0x40.
const arg2 = (pairs: [string, string][], i: number | bigint) => W(0x40) + W(i) + dynOuter(pairs);

const PAYLOAD: [string, string][] = [
  ['ab', 'cd'],
  ['ef', 'this-leaf-is-definitely-longer-than-thirty-one-bytes-yes-sir'],
];

describe('Arr<string,2>[] (solc string[2][] calldata): dynamic-outer fixed-string-leaf, byte-identical to solc 0.8.35', () => {
  it('.length of the dynamic outer array', async () => {
    await eqCalls(
      '@contract class C { @external @pure f(xs: Arr<string,2>[]): u256 { return xs.length; } }',
      'contract C { function f(string[2][] calldata xs) external pure returns(uint256){ return xs.length; } }',
      [['f(string[2][])', arg(PAYLOAD)]],
    );
  });

  it('leaf read xs[i][j] for every in-bounds (i,j), including a >31-byte leaf', async () => {
    await eqCalls(
      '@contract class C { @external @pure f(xs: Arr<string,2>[]): string { return xs[0n][0n]; } }',
      'contract C { function f(string[2][] calldata xs) external pure returns(string memory){ return xs[0][0]; } }',
      [['f(string[2][])', arg(PAYLOAD)]],
    );
    await eqCalls(
      '@contract class C { @external @pure f(xs: Arr<string,2>[]): string { return xs[0n][1n]; } }',
      'contract C { function f(string[2][] calldata xs) external pure returns(string memory){ return xs[0][1]; } }',
      [['f(string[2][])', arg(PAYLOAD)]],
    );
    await eqCalls(
      '@contract class C { @external @pure f(xs: Arr<string,2>[]): string { return xs[1n][1n]; } }',
      'contract C { function f(string[2][] calldata xs) external pure returns(string memory){ return xs[1][1]; } }',
      [['f(string[2][])', arg(PAYLOAD)]],
    );
  });

  it('runtime index xs[i][0] - in-bounds matches, OUT-OF-BOUNDS outer index Panics identically (0x32)', async () => {
    await eqCalls(
      '@contract class C { @external @pure f(xs: Arr<string,2>[], i: u256): string { return xs[i][0n]; } }',
      'contract C { function f(string[2][] calldata xs, uint256 i) external pure returns(string memory){ return xs[i][0]; } }',
      [
        ['f(string[2][],uint256)', arg2(PAYLOAD, 0)], // in-bounds
        ['f(string[2][],uint256)', arg2(PAYLOAD, 1)], // in-bounds
        ['f(string[2][],uint256)', arg2(PAYLOAD, 2)], // OOB -> Panic(0x32)
        ['f(string[2][],uint256)', arg2(PAYLOAD, 99)], // OOB -> Panic(0x32)
      ],
    );
  });
});
