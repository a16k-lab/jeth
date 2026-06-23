// Phase 4d scenario "boundary-and-trailing": exhaustive calldata-length boundaries
// for aggregate (struct + fixed-array) params, byte-identical to Solidity.
// For each function with static head N bytes:
//   - exactly N arg bytes  -> OK, correct value
//   - N-1 arg bytes        -> EMPTY revert (returndata 0x)
//   - selector-only        -> EMPTY revert (returndata 0x)
//   - N+40 trailing junk   -> OK, correct value (extra bytes ignored)
// Every probe must be byte-identical between JETH and Solidity (the oracle).
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

// Faithful Solidity mirror of the four functions under test (same shapes as the
// JETH examples/AggParams.jeth source).
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AggParams {
  struct Pt { uint128 x; uint128 y; }
  struct WithArr { uint64 id; uint256[2] data; }
  function sumTriple(uint256[3] calldata a) external pure returns (uint256){ return a[0]+a[1]+a[2]; }
  function afterAgg(uint256[3] calldata a, uint256 x) external pure returns (uint256){ return a[2]+x; }
  function ptsX(Pt[2] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].x; }
  function withId(WithArr calldata t) external pure returns (uint64){ return t.id; }
}`;

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}

describe('boundary-and-trailing: aggregate-param calldata length boundaries vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);

  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  // Assert JETH matches Solidity byte-for-byte (success flag + returndata).
  async function eq(label: string, data: string) {
    const { j, s } = await both(data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'AggParams.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'AggParams.jeth' });
    const sb = compileSolidity(SOL, 'AggParams');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // selSig: full canonical signature for the selector.
  // argHex: exact-need argument bytes (no 0x), expected.length == 2*needBytes.
  // expectVal: the uint value both contracts must return on a valid call.
  async function boundary(name: string, selSig: string, needBytes: number, argHex: string, expectVal: bigint) {
    const selHex = sel(selSig);
    expect(argHex.length, `${name} argHex must be exactly need bytes`).toBe(2 * needBytes);

    // (1) exactly need bytes -> OK and correct value, byte-identical.
    const exact = '0x' + selHex + argHex;
    const rExact = await eq(`${name} exact-need`, exact);
    expect(rExact.s.success, `${name} solc exact must succeed`).toBe(true);
    expect(decodeUint(rExact.j.returnHex), `${name} exact value`).toBe(expectVal);
    expect(decodeUint(rExact.s.returnHex), `${name} solc exact value`).toBe(expectVal);

    // (2) need-1 bytes -> EMPTY revert (drop the final hex byte = 2 hex chars).
    const minus1 = '0x' + selHex + argHex.slice(0, argHex.length - 2);
    const rM1 = await eq(`${name} need-1`, minus1);
    expect(rM1.j.success, `${name} need-1 must revert`).toBe(false);
    expect(rM1.s.success, `${name} need-1 solc must revert`).toBe(false);
    expect(rM1.j.returnHex, `${name} need-1 empty returndata`).toBe('0x');
    expect(rM1.s.returnHex, `${name} need-1 solc empty returndata`).toBe('0x');

    // (3) selector-only (0 arg bytes) -> EMPTY revert.
    const selOnly = '0x' + selHex;
    const rSel = await eq(`${name} selector-only`, selOnly);
    expect(rSel.j.success, `${name} selector-only must revert`).toBe(false);
    expect(rSel.s.success, `${name} selector-only solc must revert`).toBe(false);
    expect(rSel.j.returnHex, `${name} selector-only empty returndata`).toBe('0x');
    expect(rSel.s.returnHex, `${name} selector-only solc empty returndata`).toBe('0x');

    // (4) need+40 trailing junk -> OK and correct value (extra bytes ignored).
    const junk = 'ab'.repeat(40); // 40 trailing junk bytes
    const trailing = '0x' + selHex + argHex + junk;
    const rT = await eq(`${name} need+40 trailing`, trailing);
    expect(rT.j.success, `${name} trailing must succeed`).toBe(true);
    expect(rT.s.success, `${name} trailing solc must succeed`).toBe(true);
    expect(decodeUint(rT.j.returnHex), `${name} trailing value`).toBe(expectVal);
    expect(decodeUint(rT.s.returnHex), `${name} trailing solc value`).toBe(expectVal);
  }

  it('sumTriple(uint256[3]) needs 96 arg bytes', async () => {
    // a = [10, 20, 30] -> sum 60
    const argHex = [10n, 20n, 30n].map(pad).join('');
    await boundary('sumTriple', 'sumTriple(uint256[3])', 96, argHex, 60n);
  });

  it('afterAgg(uint256[3],uint256) needs 128 arg bytes', async () => {
    // a = [1, 2, 3], x = 100 -> a[2] + x = 103
    const argHex = [1n, 2n, 3n, 100n].map(pad).join('');
    await boundary('afterAgg', 'afterAgg(uint256[3],uint256)', 128, argHex, 103n);
  });

  it('ptsX((uint128,uint128)[2],uint256) needs 160 arg bytes', async () => {
    // ps[0]={1,2}, ps[1]={3,4}, i=1 -> ps[1].x = 3
    const argHex = [1n, 2n, 3n, 4n, 1n].map(pad).join('');
    await boundary('ptsX', 'ptsX((uint128,uint128)[2],uint256)', 160, argHex, 3n);
  });

  it('withId((uint64,uint256[2])) needs 96 arg bytes', async () => {
    // t = { id: 9, data: [0x111, 0x222] } -> id = 9
    const argHex = [9n, 0x111n, 0x222n].map(pad).join('');
    await boundary('withId', 'withId((uint64,uint256[2]))', 96, argHex, 9n);
  });
});
