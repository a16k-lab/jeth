// Phase 6: the @receive / @fallback special entry points, dispatch byte-identical to solc 0.8.35.
//  - @receive recv() { ... }  -> Solidity `receive() external payable` (payable is implied): runs on
//    empty calldata (with or without value).
//  - @fallback fb() { ... }   -> Solidity `fallback() external`: runs on a non-matching selector, and
//    on empty calldata when there is no @receive. Non-payable here, so empty/bad-selector calls that
//    carry value revert.
//
// Each case triggers the entry point, then reads back a state var via a normal getter and diffs the
// stored value (and the call's success) against the equivalent solc contract.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const GET = functionSelector('get()');

const JETH = `@contract class C {
  @state count: u256;
  @receive recv() { this.count = 11n; }
  @fallback fb() { this.count = 22n; }
  @external @view get(): u256 { return this.count; }
}`;
const SOL = `contract C {
  uint256 stored;
  receive() external payable { stored = 11; }
  fallback() external { stored = 22; }
  function get() external view returns(uint256){ return stored; }
}`;

async function deployJeth() {
  const h = await Harness.create();
  return { h, a: await h.deploy(compile(JETH, { fileName: 'C.jeth' }).creationBytecode) };
}
async function deploySol() {
  const h = await Harness.create();
  return { h, a: await h.deploy(compileSolidity(SPDX + SOL, 'C').creation) };
}

/** Send `calldata` (with `value`) to both contracts, then read back the stored counter and diff
 *  the triggering call's success and the resulting state. */
async function dispatch(calldata: string, value: bigint) {
  const j = await deployJeth();
  const s = await deploySol();
  const rj = await j.h.call(j.a, '0x' + calldata, { value });
  const rs = await s.h.call(s.a, '0x' + calldata, { value });
  expect(rj.success, 'trigger success parity').toBe(rs.success);
  const gj = await j.h.call(j.a, '0x' + GET);
  const gs = await s.h.call(s.a, '0x' + GET);
  expect(gj.returnHex, 'stored state parity').toBe(gs.returnHex);
  return { triggered: rj.success, stored: BigInt(gj.returnHex) };
}

describe('@receive / @fallback dispatch', () => {
  it('empty calldata + value -> receive', async () => {
    const r = await dispatch('', 1n);
    expect(r).toEqual({ triggered: true, stored: 11n });
  });
  it('empty calldata, no value -> receive', async () => {
    const r = await dispatch('', 0n);
    expect(r).toEqual({ triggered: true, stored: 11n });
  });
  it('non-matching selector -> fallback', async () => {
    const r = await dispatch('deadbeef', 0n);
    expect(r).toEqual({ triggered: true, stored: 22n });
  });
  it('non-matching selector + value -> revert (non-payable fallback)', async () => {
    const r = await dispatch('deadbeef', 1n);
    expect(r.triggered).toBe(false);
    expect(r.stored).toBe(0n);
  });
});
