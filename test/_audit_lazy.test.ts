// AUDIT: lazy vs eager validation of aggregate params (does solc validate unread leaves?)
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
@struct class Acct { bal: u128; nonce: u64; active: bool; }
@struct class Pt { x: u128; y: u128; }
@contract
class A {
  // reads NOTHING from the struct param -> does solc still validate it?
  @external @pure ignore(a: Acct): u256 { return 1n; }
  @external @pure ignoreArr(a: Arr<u8, 4>): u256 { return 1n; }
  @external @pure ignoreFas(ps: Arr<Pt, 2>): u256 { return 1n; }
  // reads only one field
  @external @pure onlyBal(a: Acct): u128 { return a.bal; }
  // a param mixed with another that is dirty
  @external @pure twoStructs(a: Acct, b: Acct): u128 { return a.bal; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct Acct { uint128 bal; uint64 nonce; bool active; }
  struct Pt { uint128 x; uint128 y; }
  function ignore(Acct calldata a) external pure returns (uint256){ return 1; }
  function ignoreArr(uint8[4] calldata a) external pure returns (uint256){ return 1; }
  function ignoreFas(Pt[2] calldata ps) external pure returns (uint256){ return 1; }
  function onlyBal(Acct calldata a) external pure returns (uint128){ return a.bal; }
  function twoStructs(Acct calldata a, Acct calldata b) external pure returns (uint128){ return a.bal; }
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
  expect(j.success, `${label}: jeth.success=${j.success}(${j.exceptionError}) sol.success=${s.success}`).toBe(s.success);
  expect(j.returnHex, `${label}: returndata jeth=${j.returnHex} sol=${s.returnHex}`).toBe(s.returnHex);
  return { j, s };
}

describe('lazy-vs-eager validation of UNREAD aggregate leaves', () => {
  it('ignore(Acct): dirty nonce/active never read', async () => {
    const sel = functionSelector('ignore((uint128,uint64,bool))');
    // dirty nonce (bit 64 set)
    await eq('ignore dirty nonce', '0x' + sel + [W(5n), W(1n << 64n), W(0n)].join(''));
    // dirty active (=2)
    await eq('ignore dirty active', '0x' + sel + [W(5n), W(3n), W(2n)].join(''));
    // dirty bal (high bits) -- bal is uint128
    await eq('ignore dirty bal', '0x' + sel + [W(1n << 200n), W(3n), W(1n)].join(''));
    // all dirty
    await eq('ignore all dirty', '0x' + sel + [W(M - 1n), W(M - 1n), W(M - 1n)].join(''));
  });

  it('ignoreArr(uint8[4]): dirty elements never read', async () => {
    const sel = functionSelector('ignoreArr(uint8[4])');
    await eq('ignoreArr dirty', '0x' + sel + [W(0x1ffn), W(0x200n), W(M - 1n), W(0n)].join(''));
  });

  it('ignoreFas(Pt[2]): dirty struct-array elements never read', async () => {
    const sel = functionSelector('ignoreFas((uint128,uint128)[2])');
    await eq('ignoreFas dirty', '0x' + sel + [W(1n << 200n), W(1n << 130n), W(0n), W(0n)].join(''));
  });

  it('onlyBal(Acct): dirty nonce/active unread, bal clean -> OK', async () => {
    const sel = functionSelector('onlyBal((uint128,uint64,bool))');
    await eq('onlyBal dirty-others', '0x' + sel + [W(99n), W(1n << 64n), W(2n)].join(''));
    // bal itself dirty -> read -> revert
    await eq('onlyBal dirty-bal', '0x' + sel + [W(1n << 200n), W(0n), W(0n)].join(''));
  });

  it('twoStructs: only a read; b entirely dirty', async () => {
    const sel = functionSelector('twoStructs((uint128,uint64,bool),(uint128,uint64,bool))');
    const a = [W(7n), W(0n), W(0n)].join('');
    const bDirty = [W(M - 1n), W(M - 1n), W(M - 1n)].join('');
    await eq('twoStructs b dirty', '0x' + sel + a + bDirty);
  });
});
