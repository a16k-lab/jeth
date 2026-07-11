// solc 0.8 rejects ordering operators (< > <= >=) on bool ("operator > cannot be applied to types
// bool and bool"); only == and != are valid on bool. JETH used to accept bool ordering (lowering to
// gt/lt); it now rejects it (JETH082), matching solc. Ordering on every OTHER value type
// (int/uint/address/bytesN/enum) stays allowed, as in solc. This locks the relational-operator type
// rules to solc's exactly.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => v.toString(16).padStart(64, '0');
function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}
const fn = (op: string, ty = 'bool') =>
  `@contract class C { @external @pure f(a: ${ty}, b: ${ty}): bool { return a ${op} b; } }`;

describe('relational operators on bool match solc', () => {
  it('< > <= >= on bool are rejected (JETH082)', () => {
    for (const op of ['>', '<', '>=', '<=']) {
      expect(codes(fn(op)), `'${op}' on bool`).toContain('JETH481');
    }
  });

  it('== and != on bool compile (only valid bool comparisons)', () => {
    expect(codes(fn('=='))).toEqual([]);
    expect(codes(fn('!='))).toEqual([]);
  });

  it('ordering on int/uint/address/bytesN and enum stays allowed (no over-rejection)', () => {
    for (const ty of ['u256', 'i128', 'address', 'bytes32', 'bytes4']) {
      for (const op of ['>', '<', '>=', '<=', '==', '!=']) {
        expect(codes(fn(op, ty)), `'${op}' on ${ty}`).toEqual([]);
      }
    }
    // enum ordering (compares the underlying uint8), as solc allows
    for (const op of ['>', '<', '>=', '<=', '==', '!=']) {
      expect(
        codes(`enum E { A, B, C } @contract class C { @external @pure f(a: E, b: E): bool { return a ${op} b; } }`),
        `'${op}' on enum`,
      ).toEqual([]);
    }
  });

  it('a bool ordering inside a larger expression is also rejected', () => {
    expect(
      codes(`class C { get f(a: bool, b: bool): External<bool> { return (a > b) || (a == b); } }`),
    ).toContain('JETH082');
  });

  describe('bool ==/!= runtime byte-identical to solc', () => {
    let jeth: Harness, sol: Harness, aj: Address, as: Address;
    const J = `class C { get eq(a: bool, b: bool): External<bool> { return a == b; } get ne(a: bool, b: bool): External<bool> { return a != b; } }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C { function eq(bool a, bool b) external pure returns (bool){ return a == b; } function ne(bool a, bool b) external pure returns (bool){ return a != b; } }`;
    beforeAll(async () => {
      jeth = await Harness.create();
      sol = await Harness.create();
      aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
      as = await sol.deploy(compileSolidity(S, 'C').creation);
    });
    it('all (a,b) combinations match', async () => {
      for (const [a, b] of [
        [0n, 0n],
        [0n, 1n],
        [1n, 0n],
        [1n, 1n],
      ] as const) {
        for (const f of ['eq', 'ne'] as const) {
          const data = '0x' + sel(`${f}(bool,bool)`) + pad(a) + pad(b);
          const j = await jeth.call(aj, data);
          const s = await sol.call(as, data);
          expect(j.returnHex, `${f}(${a},${b})`).toBe(s.returnHex);
        }
      }
    });
  });
});
