// Tier-2 over-rejection lift (OR-b): a bytesN(bytesM(literal)) NESTED const cast folded in a runtime
// return position. The runtime path (bytesN(param) / bytesN(local)) already accepted this, but the
// const-fold cast path had no bytesN->bytesM branch, so bytes4(bytes4(0x..)) wrongly rejected JETH170
// ("explicit conversion not allowed"). solc accepts every bytesN<->bytesM reinterpret (widen = zero-pad
// on the right, narrow = keep the high N bytes); JETH now folds it byte-identically. This test RUNS +
// decodes the folded value (a compile-only accept/reject check would miss a wrong-value miscompile) and
// pins the reject controls that must NOT become over-acceptances.
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

const J = `@contract class C {
  @external @pure a(): bytes4 { return bytes4(bytes4(0xababababn)); }
  @external @pure w8(): bytes8 { return bytes8(bytes4(0xababababn)); }
  @external @pure w32(): bytes32 { return bytes32(bytes4(0xababababn)); }
  @external @pure n2(): bytes2 { return bytes2(bytes4(0xababababn)); }
  @external @pure n1(): bytes1 { return bytes1(bytes4(0xababababn)); }
  @external @pure s32(): bytes32 { return bytes32(bytes32(0x${'cd'.repeat(32)}n)); }
  @external @pure tri(): bytes2 { return bytes2(bytes4(bytes8(0x1122334455667788n))); }
  @external @pure inner(): bytes4 { return bytes4(0xababababn); }
  @external @pure viaLocal(): bytes4 { let b: bytes4 = bytes4(0xababababn); return bytes4(b); }
  @external @pure pw(b: bytes4): bytes8 { return bytes8(b); } }`;
const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  function a() external pure returns (bytes4) { return bytes4(bytes4(0xabababab)); }
  function w8() external pure returns (bytes8) { return bytes8(bytes4(0xabababab)); }
  function w32() external pure returns (bytes32) { return bytes32(bytes4(0xabababab)); }
  function n2() external pure returns (bytes2) { return bytes2(bytes4(0xabababab)); }
  function n1() external pure returns (bytes1) { return bytes1(bytes4(0xabababab)); }
  function s32() external pure returns (bytes32) { return bytes32(bytes32(0x${'cd'.repeat(32)})); }
  function tri() external pure returns (bytes2) { return bytes2(bytes4(bytes8(0x1122334455667788))); }
  function inner() external pure returns (bytes4) { return bytes4(0xabababab); }
  function viaLocal() external pure returns (bytes4) { bytes4 b = bytes4(0xabababab); return bytes4(b); }
  function pw(bytes4 b) external pure returns (bytes8) { return bytes8(b); } }`;

describe('nested bytesN(bytesM(literal)) const cast (OR-b) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });

  it('every nested/widening/narrowing/same-width fold is byte-identical AND matches the expected value', async () => {
    const abab = '0x' + 'abababab' + '00'.repeat(28);
    const cases: [string, string, string][] = [
      // [selector, argsHex, expected returnHex]
      ['a()', '', abab],
      ['w8()', '', abab], // bytes8 left-aligned: low bytes are zero anyway
      ['w32()', '', abab],
      ['n2()', '', '0x' + 'abab' + '00'.repeat(30)],
      ['n1()', '', '0x' + 'ab' + '00'.repeat(31)],
      ['s32()', '', '0x' + 'cd'.repeat(32)],
      ['tri()', '', '0x' + '1122' + '00'.repeat(30)],
      ['inner()', '', abab],
      ['viaLocal()', '', abab],
      ['pw(bytes4)', pad(0xababababn << 224n), abab],
    ];
    for (const [s, args, expected] of cases) {
      const data = '0x' + sel(s) + args;
      const j = await jeth.call(aj, data);
      const so = await sol.call(as, data);
      expect(j.success, s).toBe(true);
      expect(so.success, s).toBe(true);
      expect(j.returnHex, `${s} JETH vs solc`).toBe(so.returnHex);
      expect(so.returnHex, `${s} solc vs expected (non-vacuity)`).toBe(expected);
    }
  });

  it('reject controls stay rejecting (no over-acceptance introduced)', () => {
    // over-length bare-hex inner literal into bytesN: solc rejects, JETH must too
    expect(codes('@contract class C { @external @pure f(): bytes4 { return bytes4(0xabababababn); } }')).toContain('JETH170');
    // bytesN(uintM(x)) with a size mismatch (M != N*8): solc rejects, JETH must too
    expect(codes('@contract class C { @external @pure f(): bytes4 { return bytes4(u128(0xababababn)); } }')).toContain('JETH170');
    // a valid nested cast still compiles clean
    expect(codes('@contract class C { @external @pure f(): bytes4 { return bytes4(bytes4(0xababababn)); } }')).toEqual([]);
  });
});
