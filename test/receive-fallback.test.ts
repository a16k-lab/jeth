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

// P1-21: @virtual / @override are permitted on @receive / @fallback (solc allows them; they are
// structural override markers only, dispatch is byte-identical). The special-entry override
// relationship is validated exactly like a function override.
describe('P1-21: @virtual / @override on @receive / @fallback', () => {
  const codes = (src: string): string[] => {
    try {
      compile(src, { fileName: 'C.jeth' });
      return [];
    } catch (e) {
      const err = e as { diagnostics?: { code: string }[] };
      if (err.diagnostics) return err.diagnostics.map((d) => d.code);
      throw e;
    }
  };
  const solcRejects = (src: string): boolean => {
    try {
      compileSolidity(SPDX + src, 'C');
      return false;
    } catch {
      return true;
    }
  };

  it('@override @receive over a @virtual base receive runs the derived body, byte-identical', async () => {
    const J = `@abstract class A { @virtual @receive r(): void {} } @contract class C extends A { @state count: u256; @override @receive r(): void { this.count = 42n; } @external @view get(): u256 { return this.count; } }`;
    const S = `abstract contract A { receive() external payable virtual {} } contract C is A { uint256 count; receive() external payable override { count = 42; } function get() external view returns(uint256){ return count; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, '0x', { value: 1n });
    await h.call(as, '0x', { value: 1n });
    const gj = await h.call(aj, '0x' + GET);
    const gs = await h.call(as, '0x' + GET);
    expect(gj.returnHex).toBe(gs.returnHex);
    expect(BigInt(gj.returnHex)).toBe(42n);
  });

  it('@virtual @fallback compiles (structural marker only)', () => {
    expect(codes(`@contract class C { @virtual @fallback fb(): void {} }`)).toEqual([]);
  });

  // Accept/reject parity with solc for the special-entry override matrix.
  it('@override with no base receive -> both reject (overrides nothing)', () => {
    expect(codes(`@contract class C { @override @receive r(): void {} }`)).toContain('JETH386');
    expect(solcRejects(`contract C { receive() external payable override {} }`)).toBe(true);
  });
  it('@override receive over a NON-virtual base -> both reject', () => {
    expect(
      codes(`@abstract class A { @receive r(): void {} } @contract class C extends A { @override @receive r(): void {} }`),
    ).toContain('JETH386');
    expect(
      solcRejects(`abstract contract A { receive() external payable {} } contract C is A { receive() external payable override {} }`),
    ).toBe(true);
  });
  it('redeclaring a @virtual base receive WITHOUT @override -> both reject', () => {
    expect(
      codes(`@abstract class A { @virtual @receive r(): void {} } @contract class C extends A { @receive r(): void {} }`),
    ).toContain('JETH386');
    expect(
      solcRejects(`abstract contract A { receive() external payable virtual {} } contract C is A { receive() external payable {} }`),
    ).toBe(true);
  });
  it('a @view / @modifier-carrying special entry still rejects (JETH386)', () => {
    expect(codes(`@contract class C { @read @receive r(): void {} }`)).toContain('JETH386');
  });
});
