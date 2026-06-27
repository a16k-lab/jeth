// Lifting rare sound over-rejections to full solc parity. Each case was rejected by JETH (often a
// clean diagnostic, one a JETH900 crash) while solc 0.8.35 accepts it; the result is now verified
// byte-identical. Differential: a JETH contract and the solc equivalent are deployed and their
// (success, returnHex) compared for the same calldata.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);

async function rt(jeth: string, sol: string, sigs: string[]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const s of sigs) {
    const data = '0x' + sel(s);
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${s}: success`).toBe(rs.success);
    expect(rj.returnHex, `${s}: returndata`).toBe(rs.returnHex);
  }
}

describe('lifted over-rejections: byte-identical vs solc', () => {
  it('abi.encode of an internal call returning a value-element array [was JETH900]', async () => {
    const J = `@contract class C {
      mk(): u256[] { let a: u256[] = new Array<u256>(3n); a[0n] = 7n; a[1n] = 8n; a[2n] = 9n; return a; }
      @external @pure f(): bytes { return abi.encode(this.mk()); }
      @external @pure g(): bytes { return abi.encode(7n, this.mk(), 9n); }
      @external @pure p(): bytes { return abi.encodePacked(this.mk()); }
    }`;
    const S = `contract C {
      function mk() internal pure returns (uint256[] memory){ uint256[] memory a = new uint256[](3); a[0]=7; a[1]=8; a[2]=9; return a; }
      function f() external pure returns (bytes memory){ return abi.encode(mk()); }
      function g() external pure returns (bytes memory){ return abi.encode(uint256(7), mk(), uint256(9)); }
      function p() external pure returns (bytes memory){ return abi.encodePacked(mk()); }
    }`;
    await rt(J, S, ['f()', 'g()', 'p()']);
  });
});
