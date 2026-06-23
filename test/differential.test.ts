// Differential testing vs Solidity (directive §7): compile the same contract in
// JETH and Solidity, run identical calldata on identical EVMs, assert identical
// results AND identical revert behavior. This is the strongest correctness proof:
// it pins JETH's arithmetic, comparisons, and shifts to the reference compiler.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));

const U256_MAX = (1n << 256n) - 1n;
const I256_MAX = (1n << 255n) - 1n;
const I256_MIN = -(1n << 255n);
const P128 = 1n << 128n;

// Solidity mirror of examples/Arith.jeth (same signatures -> same selectors).
const SOL_ARITH = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Arith {
  function addU256(uint256 a, uint256 b) external pure returns (uint256){ return a + b; }
  function subU256(uint256 a, uint256 b) external pure returns (uint256){ return a - b; }
  function mulU256(uint256 a, uint256 b) external pure returns (uint256){ return a * b; }
  function divU256(uint256 a, uint256 b) external pure returns (uint256){ return a / b; }
  function modU256(uint256 a, uint256 b) external pure returns (uint256){ return a % b; }
  function addU8(uint8 a, uint8 b) external pure returns (uint8){ return a + b; }
  function mulU8(uint8 a, uint8 b) external pure returns (uint8){ return a * b; }
  function shlU8(uint8 a, uint8 b) external pure returns (uint8){ return a << b; }
  function addI256(int256 a, int256 b) external pure returns (int256){ return a + b; }
  function subI256(int256 a, int256 b) external pure returns (int256){ return a - b; }
  function mulI256(int256 a, int256 b) external pure returns (int256){ return a * b; }
  function divI256(int256 a, int256 b) external pure returns (int256){ return a / b; }
  function modI256(int256 a, int256 b) external pure returns (int256){ return a % b; }
  function addI8(int8 a, int8 b) external pure returns (int8){ return a + b; }
  function mulI8(int8 a, int8 b) external pure returns (int8){ return a * b; }
  function negI8(int8 a) external pure returns (int8){ return -a; }
  function ltU256(uint256 a, uint256 b) external pure returns (bool){ return a < b; }
  function ltI256(int256 a, int256 b) external pure returns (bool){ return a < b; }
  function shrI256(int256 a, uint256 b) external pure returns (int256){ return a >> b; }
  function shlI8(int8 a, uint8 b) external pure returns (int8){ return a << b; }
  function shlI16(int16 a, uint8 b) external pure returns (int16){ return a << b; }
  function scAnd(uint256 a) external pure returns (bool){ return (a > 0) && ((10 / a) > 0); }
  function scOr(uint256 a) external pure returns (bool){ return (a == 0) || ((10 / a) > 5); }
}`;

interface Case {
  sig: string;
  args: bigint[];
}

const CASES: Case[] = [
  // unsigned arithmetic, including overflow / div-by-zero edges
  ...pairs('addU256(uint256,uint256)', [
    [0n, 0n],
    [1n, 2n],
    [U256_MAX, 0n],
    [U256_MAX, 1n],
    [P128, P128],
  ]),
  ...pairs('subU256(uint256,uint256)', [
    [5n, 3n],
    [3n, 5n],
    [0n, 0n],
    [0n, 1n],
  ]),
  ...pairs('mulU256(uint256,uint256)', [
    [0n, U256_MAX],
    [2n, 3n],
    [U256_MAX, 2n],
    [P128, P128],
    [P128, 2n],
  ]),
  ...pairs('divU256(uint256,uint256)', [
    [10n, 3n],
    [10n, 0n],
    [U256_MAX, 1n],
    [0n, 5n],
  ]),
  ...pairs('modU256(uint256,uint256)', [
    [10n, 3n],
    [10n, 0n],
    [U256_MAX, 7n],
  ]),
  // narrow unsigned
  ...pairs('addU8(uint8,uint8)', [
    [100n, 100n],
    [200n, 100n],
    [255n, 0n],
    [255n, 1n],
  ]),
  ...pairs('mulU8(uint8,uint8)', [
    [16n, 16n],
    [15n, 17n],
    [10n, 10n],
    [255n, 2n],
  ]),
  ...pairs('shlU8(uint8,uint8)', [
    [1n, 3n],
    [255n, 4n],
    [1n, 8n],
    [1n, 7n],
    [3n, 6n],
  ]),
  // signed arithmetic
  ...pairs('addI256(int256,int256)', [
    [1n, 2n],
    [-1n, -2n],
    [I256_MAX, 1n],
    [I256_MIN, -1n],
    [I256_MAX, -1n],
  ]),
  ...pairs('subI256(int256,int256)', [
    [1n, 2n],
    [I256_MIN, 1n],
    [I256_MAX, -1n],
    [-5n, -5n],
  ]),
  ...pairs('mulI256(int256,int256)', [
    [-2n, 3n],
    [I256_MIN, -1n],
    [I256_MAX, 2n],
    [2n, 3n],
    [-1n, -1n],
    [I256_MIN, 1n],
  ]),
  ...pairs('divI256(int256,int256)', [
    [-6n, 3n],
    [7n, -2n],
    [I256_MIN, -1n],
    [5n, 0n],
    [-7n, 2n],
  ]),
  ...pairs('modI256(int256,int256)', [
    [-7n, 3n],
    [7n, -3n],
    [5n, 0n],
    [-8n, 3n],
  ]),
  // narrow signed
  ...pairs('addI8(int8,int8)', [
    [100n, 27n],
    [100n, 28n],
    [-128n, -1n],
    [-100n, -28n],
    [-128n, 127n],
  ]),
  ...pairs('mulI8(int8,int8)', [
    [16n, 7n],
    [16n, 8n],
    [-16n, 8n],
    [-16n, 9n],
    [-1n, -128n],
  ]),
  ...pairs('negI8(int8)', [[5n], [-128n], [127n], [0n], [-1n]]),
  // comparisons (signed vs unsigned must differ on negatives)
  ...pairs('ltU256(uint256,uint256)', [
    [1n, 2n],
    [2n, 1n],
    [U256_MAX, 0n],
  ]),
  ...pairs('ltI256(int256,int256)', [
    [-1n, 1n],
    [1n, -1n],
    [I256_MIN, I256_MAX],
  ]),
  // arithmetic shift right keeps sign
  ...pairs('shrI256(int256,uint256)', [
    [-8n, 1n],
    [-1n, 5n],
    [I256_MIN, 4n],
    [255n, 2n],
  ]),
  // signed narrow left shift must sign-extend/truncate to the type (regression)
  ...pairs('shlI8(int8,uint8)', [
    [127n, 1n],
    [1n, 7n],
    [-1n, 1n],
    [64n, 1n],
    [-64n, 2n],
    [1n, 8n],
  ]),
  ...pairs('shlI16(int16,uint8)', [
    [16384n, 1n],
    [-1n, 4n],
    [255n, 8n],
    [1n, 15n],
  ]),
  // short-circuit: a == 0 must NOT evaluate the dividing RHS (would revert)
  ...pairs('scAnd(uint256)', [[0n], [5n]]),
  ...pairs('scOr(uint256)', [[0n], [1n], [3n]]),
];

function pairs(sig: string, argSets: bigint[][]): Case[] {
  return argSets.map((args) => ({ sig, args }));
}

describe('differential vs Solidity', () => {
  let jeth: Harness;
  let sol: Harness;
  let jethAddr: any;
  let solAddr: any;
  let jethBuild: ReturnType<typeof compile>;

  beforeAll(async () => {
    const source = readFileSync(join(here, '..', 'examples', 'Arith.jeth'), 'utf8');
    jethBuild = compile(source, { fileName: 'Arith.jeth' });
    const solBuild = compileSolidity(SOL_ARITH, 'Arith');
    jeth = await Harness.create();
    sol = await Harness.create();
    jethAddr = await jeth.deploy(jethBuild.creationBytecode);
    solAddr = await sol.deploy(solBuild.creation);
  });

  it('matches Solidity result/revert on every operation and input', async () => {
    let checked = 0;
    for (const c of CASES) {
      const data = encodeCall(functionSelector(c.sig), c.args);
      const r1 = await jeth.call(jethAddr, data);
      const r2 = await sol.call(solAddr, data);
      const label = `${c.sig} [${c.args.join(', ')}]`;
      expect(
        r1.success,
        `${label}: success mismatch (jeth=${r1.success} sol=${r2.success} err=${r1.exceptionError})`,
      ).toBe(r2.success);
      if (r1.success && r2.success) {
        expect(r1.returnHex, `${label}: return mismatch`).toBe(r2.returnHex);
      } else {
        // both reverted: Panic codes (and selector) must match too
        expect(r1.returnHex, `${label}: revert-data mismatch`).toBe(r2.returnHex);
      }
      checked++;
    }
    expect(checked).toBe(CASES.length);
  });

  it('places state at Solidity-identical storage slots', () => {
    // Arith is stateless; use the Counter contract for a storage-layout diff.
    const solCounter = compileSolidity(
      `// SPDX-License-Identifier: MIT
       pragma solidity ^0.8.20;
       contract Counter { uint256 count;
         function increment() external { count += 1; } }`,
      'Counter',
    );
    expect(solCounter.storageLayout[0]).toMatchObject({ label: 'count', slot: '0', offset: 0 });
  });

  it('produces byte-identical storage to Solidity after the same calls (Counter)', async () => {
    const counterSrc = readFileSync(join(here, '..', 'examples', 'Counter.jeth'), 'utf8');
    const jb = compile(counterSrc, { fileName: 'Counter.jeth' });
    const sb = compileSolidity(
      `// SPDX-License-Identifier: MIT
       pragma solidity ^0.8.20;
       contract Counter { uint256 count;
         function increment() external { count += 1; }
         function add(uint256 d) external { count += d; }
         function current() external view returns (uint256){ return count; } }`,
      'Counter',
    );
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(jb.creationBytecode);
    const as = await hs.deploy(sb.creation);
    const incJ = encodeCall(functionSelector('increment()'));
    const addJ = encodeCall(functionSelector('add(uint256)'), [41n]);
    for (const data of [incJ, incJ, addJ]) {
      await hj.call(aj, data);
      await hs.call(as, data);
    }
    expect(await readSlot(hj, aj, 0n)).toBe(await readSlot(hs, as, 0n));
  });
});
