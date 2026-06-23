// Indexing a memory array produced by a ternary: (c ? xs : ys)[i]. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `@contract class TI {
  @external @pure pick(c: bool, x: u256, y: u256, i: u256): u256 {
    let xs: u256[] = [x, x + 1n];
    let ys: u256[] = [y, y + 1n, y + 2n];
    return (c ? xs : ys)[i];
  }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TI {
  function pick(bool c, uint256 x, uint256 y, uint256 i) external pure returns (uint256) {
    uint256[] memory xs = new uint256[](2); xs[0]=x; xs[1]=x+1;
    uint256[] memory ys = new uint256[](3); ys[0]=y; ys[1]=y+1; ys[2]=y+2;
    return (c ? xs : ys)[i];
  }
}`;

describe('ternary-result array index vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, args: bigint[]) {
    const data = '0x' + sel('pick(bool,uint256,uint256,uint256)') + args.map(pad).join('');
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'TI.jeth' });
    const sb = compileSolidity(SOL, 'TI');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('selects + indexes the right branch (incl OOB)', async () => {
    await eq('true [0]', [1n, 10n, 20n, 0n]);
    await eq('true [1]', [1n, 10n, 20n, 1n]);
    await eq('false [2]', [0n, 10n, 20n, 2n]);
    await eq('false [0]', [0n, 10n, 20n, 0n]);
    await eq('true OOB [2]', [1n, 10n, 20n, 2n]); // xs has len 2 -> Panic 0x32 on both
  });
});
