// F3: default + named function arguments at internal call sites. Both desugar to a positional
// internal call, so the externally observable result must equal a Solidity contract whose internal
// helper is called with the arguments written out in full.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

// JETH uses defaults + named args at the call sites; Solidity (no such feature) spells every
// argument out. If F3 desugars correctly, the two contracts are observationally identical.
const J = `class C {
  fee(amount: u256, bps: u256 = 30n, floor: u256 = 1n): u256 {
    let f: u256 = (amount * bps) / 10000n;
    if (f < floor) { f = floor; }
    return f;
  }
  get feeDefault(a: u256): External<u256> { return this.fee(a); }                 // bps=30, floor=1
  get feeBps(a: u256, b: u256): External<u256> { return this.fee(a, b); }         // floor=1
  get feeAll(a: u256, b: u256, fl: u256): External<u256> { return this.fee(a, b, fl); }
  get feeNamed(a: u256): External<u256> { return this.fee({ amount: a, bps: 50n }); } // named, floor default
  get feeNamedReorder(a: u256, b: u256): External<u256> { return this.fee({ bps: b, amount: a }); }
  capped(x: u256, cap: u256 = type(u256).max): u256 { return x < cap ? x : cap; }
  get capDefault(x: u256): External<u256> { return this.capped(x); }
  get capNamed(x: u256, c: u256): External<u256> { return this.capped({ cap: c, x: x }); }
  flag(on: bool = true): u256 { return on ? 1n : 0n; }
  get flagDefault(): External<u256> { return this.flag(); }
  get flagSet(): External<u256> { return this.flag(false); }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function fee(uint256 amount, uint256 bps, uint256 floor) internal pure returns (uint256) {
    uint256 f = (amount * bps) / 10000;
    if (f < floor) { f = floor; }
    return f;
  }
  function feeDefault(uint256 a) external pure returns (uint256) { return fee(a, 30, 1); }
  function feeBps(uint256 a, uint256 b) external pure returns (uint256) { return fee(a, b, 1); }
  function feeAll(uint256 a, uint256 b, uint256 fl) external pure returns (uint256) { return fee(a, b, fl); }
  function feeNamed(uint256 a) external pure returns (uint256) { return fee(a, 50, 1); }
  function feeNamedReorder(uint256 a, uint256 b) external pure returns (uint256) { return fee(a, b, 1); }
  function capped(uint256 x, uint256 cap) internal pure returns (uint256) { return x < cap ? x : cap; }
  function capDefault(uint256 x) external pure returns (uint256) { return capped(x, type(uint256).max); }
  function capNamed(uint256 x, uint256 c) external pure returns (uint256) { return capped(x, c); }
  function flag(bool on) internal pure returns (uint256) { return on ? 1 : 0; }
  function flagDefault() external pure returns (uint256) { return flag(true); }
  function flagSet() external pure returns (uint256) { return flag(false); }
}`;

describe('F3 default + named arguments', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} jeth=${j.exceptionError}`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('defaults and named calls match the fully-spelled-out Solidity equivalents', async () => {
    await eq('feeDefault(1e6)', encodeCall(sel('feeDefault(uint256)'), [1_000_000n]));
    await eq('feeDefault small', encodeCall(sel('feeDefault(uint256)'), [100n])); // floor kicks in
    await eq('feeBps', encodeCall(sel('feeBps(uint256,uint256)'), [1_000_000n, 75n]));
    await eq('feeAll', encodeCall(sel('feeAll(uint256,uint256,uint256)'), [1_000_000n, 75n, 500n]));
    await eq('feeNamed', encodeCall(sel('feeNamed(uint256)'), [1_000_000n]));
    await eq('feeNamedReorder', encodeCall(sel('feeNamedReorder(uint256,uint256)'), [2_000_000n, 40n]));
    await eq('capDefault', encodeCall(sel('capDefault(uint256)'), [42n]));
    await eq('capNamed under', encodeCall(sel('capNamed(uint256,uint256)'), [42n, 100n]));
    await eq('capNamed over', encodeCall(sel('capNamed(uint256,uint256)'), [999n, 100n]));
    await eq('flagDefault', encodeCall(sel('flagDefault()'), []));
    await eq('flagSet', encodeCall(sel('flagSet()'), []));
  });

  it('the ABI shows only externally-callable functions (defaults are call-site only)', () => {
    const abi = compile(J, { fileName: 'C.jeth' }).abi;
    // the helpers (fee/capped/flag) carry defaults but must not surface in the ABI...
    expect(abi.find((e: any) => e.name === 'fee')).toBeUndefined();
    expect(abi.find((e: any) => e.name === 'capped')).toBeUndefined();
    // ...and an exposed function's inputs never carry a default (the ABI lists every parameter).
    const fd = abi.find((e: any) => e.name === 'feeBps');
    expect(fd!.inputs.map((i: any) => i.type)).toEqual(['uint256', 'uint256']);
  });
});
