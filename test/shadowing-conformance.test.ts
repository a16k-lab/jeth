// Conformance fix #11/#12: variable shadowing. solc treats a function body (and every nested block)
// as a child scope of the enclosing one, so a local may SHADOW an outer variable (a parameter or an
// earlier local) - solc warns but compiles. A redeclaration in the SAME scope is a hard error. JETH
// used to reject ALL shadowing (stricter than solc, an accept/reject divergence). It now matches solc:
// cross-scope shadow accepted, same-scope redeclaration rejected (JETH068). Each declaration is given
// a unique Yul name, so shadowing is always sound (never miscompiles). The for-of / switch desugars
// additionally bump their synth temp past every visible user name, so a user variable spelled like an
// internal temp is never silently hijacked.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
function codes(src: string): string[] {
  try { compile(src, { fileName: 'C.jeth' }); return []; }
  catch (e) { if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e; }
}

describe('variable shadowing accept/reject parity with solc (#11/#12)', () => {
  it('accepts cross-scope shadowing exactly where solc does', () => {
    // a body-top-level local shadowing a parameter (solc: function body is a child scope of the params)
    expect(codes('@contract class C { @external @pure f(a: u256): u256 { let a: u256 = 1n; return a; } }')).toEqual([]);
    // a nested-block local shadowing the parameter
    expect(codes('@contract class C { @external @pure f(a: u256): u256 { let s: u256 = a; if (a > 0n) { let a: u256 = 100n; s = a; } return s; } }')).toEqual([]);
    // a nested-block local shadowing an earlier local
    expect(codes('@contract class C { @external @pure f(x: u256): u256 { let a: u256 = 1n; { let a: u256 = 2n; return a; } } }')).toEqual([]);
  });
  it('rejects same-scope redeclaration (JETH068), exactly where solc errors', () => {
    expect(codes('@contract class C { @external @pure f(x: u256): u256 { let a: u256 = 1n; let a: u256 = 2n; return a; } }')).toContain('JETH068');
    // two parameters with the same name is a same-scope collision too (caught earlier as JETH056)
    expect(codes('@contract class C { @external @pure f(a: u256, a: u256): u256 { return a; } }')).toContain('JETH056');
  });

  describe('runtime byte-identical to solc', () => {
    let jeth: Harness, sol: Harness, aj: Address, as: Address;
    const J = `@contract class C {
      @external @pure pshadow(a: u256): u256 { let a: u256 = 7n; return a; }
      @external @pure nested(a: u256): u256 { let s: u256 = a; if (a > 0n) { let a: u256 = 100n; s = s + a; } return s; }
      @external @pure earlier(x: u256): u256 { let a: u256 = x; { let a: u256 = x + 5n; return a; } } }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  function pshadow(uint256 a) external pure returns (uint256) { uint256 a = 7; return a; }
  function nested(uint256 a) external pure returns (uint256) { uint256 s = a; if (a > 0) { uint256 a = 100; s = s + a; } return s; }
  function earlier(uint256 x) external pure returns (uint256) { uint256 a = x; { uint256 a = x + 5; return a; } } }`;
    beforeAll(async () => {
      jeth = await Harness.create(); sol = await Harness.create();
      aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
      as = await sol.deploy(compileSolidity(S, 'C').creation);
    });
    it('every shadowing function returns the same word as solc', async () => {
      for (const fn of ['pshadow', 'nested', 'earlier'] as const) {
        for (const a of [0n, 1n, 7n, 100n, 12345n]) {
          const data = '0x' + sel(`${fn}(uint256)`) + pad32(a);
          const j = await jeth.call(aj, data); const s = await sol.call(as, data);
          expect(j.returnHex, `${fn}(${a})`).toBe(s.returnHex);
        }
      }
    });
  });
});
