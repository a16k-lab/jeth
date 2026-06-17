// G6: ABI return / echo of a dynamic-array-of-fixed-array composite (uint256[2][]). Returning a
// storage one, and echoing a calldata param, byte-identical to solc. (Element access on a calldata
// composite param stays gated.)
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
// uint256[2][] calldata: selector + offset(0x20) + [len] + rows (each 2 inline words)
const cdComposite = (sig: string, rows: bigint[][]) =>
  '0x' + sel(sig) + pad(0x20n) + pad(BigInt(rows.length)) + rows.flat().map(pad).join('');

const JETH = `@contract class C {
  @state b: Arr<u256, 2>[];
  @external push(): void { this.b.push(); }
  @external setB(i: u256, j: u256, v: u256): void { this.b[i][j] = v; }
  @view all(): Arr<u256, 2>[] { return this.b; }
  @external @pure echo(x: Arr<u256, 2>[]): Arr<u256, 2>[] { return x; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[2][] b;
  function push() external { b.push(); }
  function setB(uint256 i, uint256 j, uint256 v) external { b[i][j] = v; }
  function all() external view returns (uint256[2][] memory){ return b; }
  function echo(uint256[2][] calldata x) external pure returns (uint256[2][] memory){ return x; }
}`;

describe('G6 composite-array ABI return/echo vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function send(data: string) { const j = await jeth.call(aj, data); const s = await sol.call(as, data); expect(j.success, `${j.exceptionError}`).toBe(s.success); }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('return a storage uint256[2][]', async () => {
    for (let i = 0; i < 3; i++) await send(encodeCall(sel('push()'), []));
    for (const [i, j, v] of [[0n, 0n, 1n], [0n, 1n, 2n], [1n, 0n, 3n], [2n, 1n, 9n]] as [bigint, bigint, bigint][])
      await send(encodeCall(sel('setB(uint256,uint256,uint256)'), [i, j, v]));
    await eq('all', encodeCall(sel('all()'), []));
  });
  it('echo a calldata uint256[2][] param', async () => {
    await eq('echo []', cdComposite('echo(uint256[2][])', []));
    await eq('echo [[1,2]]', cdComposite('echo(uint256[2][])', [[1n, 2n]]));
    await eq('echo [[1,2],[3,4],[M-1,0]]', cdComposite('echo(uint256[2][])', [[1n, 2n], [3n, 4n], [M - 1n, 0n]]));
  });
});
