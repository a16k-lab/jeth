// @constant: a slot-free compile-time constant (solc's `type constant NAME = value`). The folded
// literal is inlined at each read site (no SLOAD), it consumes NO storage slot (so it must NOT shift
// the slot of a following @state var), and it is absent from the ABI. Verified byte-identical to solc
// 0.8.35 on returndata AND raw storage slots.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}

describe('@constant slot-free inlined constant', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  // A @constant is declared BEFORE the @state vars on purpose: in solc the constant has no slot, so
  // x must be slot 0 and y slot 1. If JETH wrongly gave the constant a slot, x/y would shift.
  const J = `@contract class C {
    @constant FEE: u256 = 100n;
    @constant SCALE: u256 = 10n ** 18n;
    @constant ON: bool = true;
    @state x: u256 = 0n;
    @state y: u256 = 0n;
    @external set(a: u256, b: u256): void { this.x = a; this.y = b; }
    @external @pure fee(): u256 { return this.FEE; }
    @external @pure scale(): u256 { return this.SCALE; }
    @external @pure on(): bool { return this.ON; }
    @external @pure calc(v: u256): u256 { return v * this.FEE + this.SCALE; }
    @external @view xv(): u256 { return this.x; } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  uint256 constant FEE = 100;
  uint256 constant SCALE = 10**18;
  bool constant ON = true;
  uint256 x;
  uint256 y;
  function set(uint256 a, uint256 b) external { x = a; y = b; }
  function fee() external pure returns (uint256) { return FEE; }
  function scale() external pure returns (uint256) { return SCALE; }
  function on() external pure returns (bool) { return ON; }
  function calc(uint256 v) external pure returns (uint256) { return v * FEE + SCALE; }
  function xv() external view returns (uint256) { return x; } }`;

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });

  it('reads the inlined constant value, byte-identical to solc', async () => {
    for (const fn of ['fee', 'scale', 'on'] as const) {
      const data = '0x' + sel(`${fn}()`);
      expect((await jeth.call(aj, data)).returnHex, fn).toBe((await sol.call(as, data)).returnHex);
    }
  });
  it('uses the constant in an expression, byte-identical to solc', async () => {
    for (const v of [0n, 1n, 5n, 123456n]) {
      const data = '0x' + sel('calc(uint256)') + pad32(v);
      expect((await jeth.call(aj, data)).returnHex, `calc(${v})`).toBe((await sol.call(as, data)).returnHex);
    }
  });
  it('the constant consumes NO storage slot: x=slot0, y=slot1 (raw slots match solc)', async () => {
    const data = '0x' + sel('set(uint256,uint256)') + pad32(7n) + pad32(9n);
    await jeth.call(aj, data);
    await sol.call(as, data);
    for (const slot of [0n, 1n, 2n]) {
      expect(await readSlot(jeth, aj, slot), `slot ${slot}`).toBe(await readSlot(sol, as, slot));
    }
    // x reads back 7 (slot 0), proving the constant did not occupy slot 0
    expect((await jeth.call(aj, '0x' + sel('xv()'))).returnHex).toBe('0x' + pad32(7n));
  });
  it('compile-time behavior: assigning to a @constant rejects; reading works', () => {
    expect(codes('@contract class C { @constant K: u256 = 1n; @external f(): void { this.K = 2n; } }')).toContain(
      'JETH441',
    );
    expect(codes('@contract class C { @constant K: u256 = 1n; @external @pure f(): u256 { return this.K; } }')).toEqual(
      [],
    );
    // a @constant requires a foldable initializer
    expect(codes('@contract class C { @constant K: u256; @external @pure f(): u256 { return this.K; } }')).toContain(
      'JETH048',
    );
    // a @constant + @state with the same shape compiles; @constant is excluded from the ABI (no getter)
    const o = compile(J, { fileName: 'C.jeth' });
    expect(o.abi.some((it: any) => it.name === 'FEE')).toBe(false);
  });
});
