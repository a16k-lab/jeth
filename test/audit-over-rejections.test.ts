// Safe over-rejections found by the full differential audit (JETH rejected valid Solidity; never a
// miscompile). Lifted byte-identical to solc 0.8.35. This file grows as more are lifted.
//  OR0: @constant fold of bytesN(uintM(...)) / bytesN(bytesM(...)) casts (runtime already accepted).
//  OR2: @constant fold of address<->uint160 casts (u160(address(x)) / address(u160(x))).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function eqValue(jeth: string, sol: string, sig: string) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  const rj = await hj.call(aj, sel(sig));
  const rs = await hs.call(as, sel(sig));
  expect(rj.success).toBe(rs.success);
  expect(rj.returnHex).toBe(rs.returnHex);
}

describe('audit over-rejections lifted byte-identical', () => {
  it('OR0: @constant bytesN(uintM(x)) / bytesN(bytesM(x)) fold to solc values', async () => {
    await eqValue(
      '@contract class C { @constant K: bytes32 = bytes32(u256(0x1234n)); @external @pure get(): bytes32 { return this.K; } }',
      'contract C { bytes32 constant K = bytes32(uint256(0x1234)); function get() external pure returns (bytes32) { return K; } }',
      'get()',
    );
    await eqValue(
      '@contract class C { @constant K: bytes4 = bytes4(bytes2(0x1234n)); @external @pure get(): bytes4 { return this.K; } }',
      'contract C { bytes4 constant K = bytes4(bytes2(0x1234)); function get() external pure returns (bytes4) { return K; } }',
      'get()',
    );
    await eqValue(
      '@contract class C { @constant K: bytes2 = bytes2(bytes4(0x12345678n)); @external @pure get(): bytes2 { return this.K; } }',
      'contract C { bytes2 constant K = bytes2(bytes4(0x12345678)); function get() external pure returns (bytes2) { return K; } }',
      'get()',
    );
  });

  it('OR2: @constant address<->uint160 casts fold to solc values', async () => {
    await eqValue(
      '@contract class C { @constant K: u160 = u160(address(0x1234n)); @external @pure get(): u160 { return this.K; } }',
      'contract C { uint160 constant K = uint160(address(0x1234)); function get() external pure returns (uint160) { return K; } }',
      'get()',
    );
    await eqValue(
      '@contract class C { @constant K: address = address(u160(0x1234n)); @external @pure get(): address { return this.K; } }',
      'contract C { address constant K = address(uint160(0x1234)); function get() external pure returns (address) { return K; } }',
      'get()',
    );
  });

  it('still rejects illegal const casts (no over-acceptance regression)', () => {
    const rej = (s: string) => {
      try {
        compile(s, { fileName: 'C.jeth' });
        return false;
      } catch {
        return true;
      }
    };
    // wrong-size uintM -> bytesN is still rejected (solc rejects bytes4(uint256(x)))
    expect(rej('@contract class C { @constant K: bytes4 = bytes4(u256(0x12n)); @external @pure get(): bytes4 { return this.K; } }')).toBe(true);
  });
});
