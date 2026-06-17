// AUDIT: odd-width int/uint/bytesN leaves in aggregate params (validation masks).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = (1n << 256n);
function pad(v: bigint): string { return (((v % M) + M) % M).toString(16).padStart(64, '0'); }
const W = (v: bigint) => pad(v);

const JETH = `
@struct class Odd { a: u24; b: i40; c: bytes7; d: i8; e: u200; }
@contract
class A {
  @external @pure oa(o: Odd): u24 { return o.a; }
  @external @pure ob(o: Odd): i40 { return o.b; }
  @external @pure oc(o: Odd): bytes7 { return o.c; }
  @external @pure od(o: Odd): i8 { return o.d; }
  @external @pure oe(o: Odd): u200 { return o.e; }
  // fixed array of odd-width ints
  @external @pure pi(a: Arr<i24, 3>, i: u256): i24 { return a[i]; }
  @external @pure pu(a: Arr<u40, 3>, i: u256): u40 { return a[i]; }
  @external @pure pb(a: Arr<bytes3, 3>, i: u256): bytes3 { return a[i]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct Odd { uint24 a; int40 b; bytes7 c; int8 d; uint200 e; }
  function oa(Odd calldata o) external pure returns (uint24){ return o.a; }
  function ob(Odd calldata o) external pure returns (int40){ return o.b; }
  function oc(Odd calldata o) external pure returns (bytes7){ return o.c; }
  function od(Odd calldata o) external pure returns (int8){ return o.d; }
  function oe(Odd calldata o) external pure returns (uint200){ return o.e; }
  function pi(int24[3] calldata a, uint256 i) external pure returns (int24){ return a[i]; }
  function pu(uint40[3] calldata a, uint256 i) external pure returns (uint40){ return a[i]; }
  function pb(bytes3[3] calldata a, uint256 i) external pure returns (bytes3){ return a[i]; }
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
  expect(j.success, `${label}: jeth=${j.success}(${j.exceptionError}) sol=${s.success}`).toBe(s.success);
  expect(j.returnHex, `${label}: rd jeth=${j.returnHex} sol=${s.returnHex}`).toBe(s.returnHex);
  return { j, s };
}

const OddT = '(uint24,int40,bytes7,int8,uint200)';
// clean values
function oddClean() {
  const a = 0x123456n;                         // u24
  const b = ((-7n) % M + M) % M;               // i40 clean (full sign-extend)
  const c = BigInt('0x' + 'aa'.repeat(7)) << BigInt((32 - 7) * 8); // bytes7 left-aligned
  const d = ((-1n) % M + M) % M;               // i8 = 0xff...ff
  const e = (1n << 199n) - 1n;                 // u200 in range
  return [a, b, c, d, e];
}

describe('odd-width struct field leaves', () => {
  it('clean reads each field', async () => {
    const w = oddClean();
    await eq('oa', '0x' + functionSelector(`oa(${OddT})`) + w.map(W).join(''));
    await eq('ob', '0x' + functionSelector(`ob(${OddT})`) + w.map(W).join(''));
    await eq('oc', '0x' + functionSelector(`oc(${OddT})`) + w.map(W).join(''));
    await eq('od', '0x' + functionSelector(`od(${OddT})`) + w.map(W).join(''));
    await eq('oe', '0x' + functionSelector(`oe(${OddT})`) + w.map(W).join(''));
  });
  it('dirty each field read -> matches solc', async () => {
    const base = oddClean();
    // dirty u24 (bit24 set)
    let w = [...base]; w[0] = base[0]! | (1n << 24n);
    await eq('oa dirty', '0x' + functionSelector(`oa(${OddT})`) + w.map(W).join(''));
    // dirty i40 (not sign-extended)
    w = [...base]; w[1] = (1n << 100n) | 5n;
    await eq('ob dirty', '0x' + functionSelector(`ob(${OddT})`) + w.map(W).join(''));
    // dirty bytes7 (low bytes nonzero)
    w = [...base]; w[2] = base[2]! | 1n;
    await eq('oc dirty', '0x' + functionSelector(`oc(${OddT})`) + w.map(W).join(''));
    // dirty i8 (e.g. 0x7f...ff bit pattern not sign-extension of low byte)
    w = [...base]; w[3] = (1n << 100n) | 0x7fn;
    await eq('od dirty', '0x' + functionSelector(`od(${OddT})`) + w.map(W).join(''));
    // dirty u200 (bit200 set)
    w = [...base]; w[4] = base[4]! | (1n << 200n);
    await eq('oe dirty', '0x' + functionSelector(`oe(${OddT})`) + w.map(W).join(''));
  });
});

describe('odd-width fixed-array element validation', () => {
  it('int24 sign-ext, uint40, bytes3 each index', async () => {
    const iVals = [((-3n) % M + M) % M, 0x7fffffn, 0n];
    const uVals = [0xffffffffffn, 1n, 0n];
    const bVals = [BigInt('0xabcdef') << BigInt((32 - 3) * 8), 0n, 0n];
    for (const i of [0n, 1n, 2n]) {
      await eq(`pi ${i}`, '0x' + functionSelector('pi(int24[3],uint256)') + [...iVals, i].map(W).join(''));
      await eq(`pu ${i}`, '0x' + functionSelector('pu(uint40[3],uint256)') + [...uVals, i].map(W).join(''));
      await eq(`pb ${i}`, '0x' + functionSelector('pb(bytes3[3],uint256)') + [...bVals, i].map(W).join(''));
    }
    // dirty reads
    await eq('pi dirty', '0x' + functionSelector('pi(int24[3],uint256)') + [(1n << 100n) | 5n, 0n, 0n, 0n].map(W).join(''));
    await eq('pu dirty', '0x' + functionSelector('pu(uint40[3],uint256)') + [(1n << 40n) | 5n, 0n, 0n, 0n].map(W).join(''));
    await eq('pb dirty', '0x' + functionSelector('pb(bytes3[3],uint256)') + [(BigInt('0xabcdef') << BigInt((32 - 3) * 8)) | 1n, 0n, 0n, 0n].map(W).join(''));
  });
});
