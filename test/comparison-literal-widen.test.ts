// Conformance fix #7: solc compares an integer variable to an OUT-OF-RANGE literal by widening both
// to the smallest common type of the SAME signedness that holds the literal (a legal, usually
// degenerate comparison: e.g. `uint8 == 256` compares in uint16). A signedness mismatch (the
// literal's mobile type differs from the variable's) is still rejected. JETH used to reject the
// whole family (forcing the literal into the variable's type). Now matched to solc, byte-identical.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}
const f = (p: string, e: string) => `class C { get f(a: ${p}): External<bool> { return ${e}; } }`;

describe('comparison of an integer variable to an out-of-range literal (#7)', () => {
  it('accepts when the literal widens to a same-signedness common type (like solc)', () => {
    for (const [p, e] of [
      ['u8', 'a == 256n'],
      ['u8', 'a < 256n'],
      ['u8', 'a >= 256n'],
      ['u8', 'a != 300n'],
      ['u16', 'a == 70000n'],
      ['i8', 'a == -200n'],
      ['i8', 'a == -129n'],
    ] as const) {
      expect(codes(f(p, e)), `${p}: ${e}`).toEqual([]);
    }
  });
  it('rejects a signedness mismatch, like solc (uint vs negative, int vs out-of-range positive)', () => {
    expect(codes(f('u8', 'a == -1n')), 'uint8 == -1').not.toEqual([]); // negative literal's mobile type is int
    expect(codes(f('i8', 'a == 200n')), 'int8 == 200').not.toEqual([]); // 200's mobile type is uint8
    expect(codes(f('i8', 'a < 200n')), 'int8 < 200').not.toEqual([]);
  });
  it('normal in-range comparisons are unchanged', () => {
    expect(codes(f('u8', 'a == 5n'))).toEqual([]);
    expect(codes(f('i8', 'a == 100n'))).toEqual([]);
    expect(codes(f('i8', 'a == -128n'))).toEqual([]);
  });

  describe('runtime byte-identical to solc', () => {
    let jeth: Harness, sol: Harness, aj: Address, as: Address;
    const J = `class C {
      get eq(a: u8): External<bool> { return a == 256n; }
      get lt(a: u8): External<bool> { return a < 256n; }
      get ne(a: u8): External<bool> { return a != 300n; }
      get norm(a: u8, b: u8): External<bool> { return a < b; } }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  function eq(uint8 a) external pure returns (bool) { return a == 256; }
  function lt(uint8 a) external pure returns (bool) { return a < 256; }
  function ne(uint8 a) external pure returns (bool) { return a != 300; }
  function norm(uint8 a, uint8 b) external pure returns (bool) { return a < b; } }`;
    beforeAll(async () => {
      jeth = await Harness.create();
      sol = await Harness.create();
      aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
      as = await sol.deploy(compileSolidity(S, 'C').creation);
    });
    it('widened (always false/true) and normal comparisons match', async () => {
      for (const a of [0n, 1n, 200n, 255n]) {
        for (const fn of ['eq', 'lt', 'ne'] as const) {
          const data = '0x' + sel(`${fn}(uint8)`) + pad(a);
          expect((await jeth.call(aj, data)).returnHex, `${fn}(${a})`).toBe((await sol.call(as, data)).returnHex);
        }
      }
      for (const [a, b] of [
        [1n, 2n],
        [5n, 5n],
        [9n, 3n],
      ] as const) {
        const data = '0x' + sel('norm(uint8,uint8)') + pad(a) + pad(b);
        expect((await jeth.call(aj, data)).returnHex).toBe((await sol.call(as, data)).returnHex);
      }
    });
  });
});
