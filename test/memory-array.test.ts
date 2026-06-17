// C7: memory array locals (value element): let xs: u256[] = [a, b, c]; xs[i] read/write;
// xs.length; return xs. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `@contract class MA {
  @external @pure build(a: u256, b: u256, c: u256): u256[] {
    let xs: u256[] = [a, b, c];
    return xs;
  }
  @external @pure sum(a: u256, b: u256, c: u256): u256 {
    let xs: u256[] = [a, b, c];
    let s: u256 = 0n;
    let i: u256 = 0n;
    while (i < xs.length) { s = s + xs[i]; i = i + 1n; }
    return s;
  }
  @external @pure setThenGet(a: u256, b: u256): u256 {
    let xs: u256[] = [a, b];
    xs[0n] = xs[0n] + xs[1n];
    return xs[0n];
  }
  @external @pure lenOf(a: u256): u256 {
    let xs: u256[] = [a, a, a, a];
    return xs.length;
  }
  @external @pure oob(): u256 {
    let xs: u256[] = [1n, 2n];
    return xs[5n];
  }
  @external @pure addr(a: address, b: address): address[] {
    let xs: address[] = [a, b];
    return xs;
  }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MA {
  function build(uint256 a, uint256 b, uint256 c) external pure returns (uint256[] memory) {
    uint256[] memory xs = new uint256[](3); xs[0]=a; xs[1]=b; xs[2]=c; return xs;
  }
  function sum(uint256 a, uint256 b, uint256 c) external pure returns (uint256) {
    uint256[] memory xs = new uint256[](3); xs[0]=a; xs[1]=b; xs[2]=c;
    uint256 s = 0; for (uint256 i = 0; i < xs.length; i++) s += xs[i]; return s;
  }
  function setThenGet(uint256 a, uint256 b) external pure returns (uint256) {
    uint256[] memory xs = new uint256[](2); xs[0]=a; xs[1]=b;
    xs[0] = xs[0] + xs[1]; return xs[0];
  }
  function lenOf(uint256 a) external pure returns (uint256) {
    uint256[] memory xs = new uint256[](4); return xs.length;
  }
  function oob() external pure returns (uint256) {
    uint256[] memory xs = new uint256[](2); xs[0]=1; xs[1]=2; return xs[5];
  }
  function addr(address a, address b) external pure returns (address[] memory) {
    address[] memory xs = new address[](2); xs[0]=a; xs[1]=b; return xs;
  }
}`;

describe('memory array locals vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, sig: string, args: bigint[]) {
    const data = '0x' + sel(sig) + args.map(pad).join('');
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'MA.jeth' });
    const sb = compileSolidity(SOL, 'MA');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('build + return a memory array', async () => {
    await eq('build', 'build(uint256,uint256,uint256)', [11n, 22n, 33n]);
  });
  it('sum via index + length loop', async () => {
    await eq('sum', 'sum(uint256,uint256,uint256)', [5n, 6n, 7n]);
  });
  it('element write then read', async () => {
    await eq('setThenGet', 'setThenGet(uint256,uint256)', [40n, 2n]);
  });
  it('length', async () => {
    await eq('lenOf', 'lenOf(uint256)', [9n]);
  });
  it('OOB index reverts (Panic 0x32)', async () => {
    await eq('oob', 'oob()', []);
  });
  it('address[] memory', async () => {
    await eq('addr', 'addr(address,address)', [BigInt('0x' + '11'.repeat(20)), BigInt('0x' + '22'.repeat(20))]);
  });
});
