// A memory value-array component in a multi-value return (return [xs, n]). Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `@contract class MM {
  @external @pure f(a: u256, b: u256): [u256[], u256] { let xs: u256[] = [a, b, a + b]; return [xs, a]; }
  @external @pure g(n: u256, a: u256, b: u256): [u256, u256[]] { let xs: u256[] = [a, b]; return [n, xs]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MM {
  function f(uint256 a, uint256 b) external pure returns (uint256[] memory, uint256) {
    uint256[] memory xs = new uint256[](3); xs[0]=a; xs[1]=b; xs[2]=a+b; return (xs, a);
  }
  function g(uint256 n, uint256 a, uint256 b) external pure returns (uint256, uint256[] memory) {
    uint256[] memory xs = new uint256[](2); xs[0]=a; xs[1]=b; return (n, xs);
  }
}`;

describe('memory-array multi-return component vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, sig: string, args: bigint[]) {
    const data = '0x' + sel(sig) + args.map(pad).join('');
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'MM.jeth' });
    const sb = compileSolidity(SOL, 'MM');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });
  it('[memArray, value] and [value, memArray]', async () => {
    await eq('f', 'f(uint256,uint256)', [10n, 20n]);
    await eq('g', 'g(uint256,uint256,uint256)', [99n, 5n, 6n]);
  });
});
