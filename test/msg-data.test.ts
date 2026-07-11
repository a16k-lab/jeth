// msg.data: the complete calldata as `bytes` (selector included), so msg.data.length == calldatasize()
// and msg.data[0] is the first selector byte. Supported: `.length`, copy to a memory bytes / return, and
// byte-indexing (Panic 0x32 OOB). Allowed in @pure (calldata, like msg.sig). Byte-identical to solc 0.8.35.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}

describe('msg.data calldata bytes view', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `class C {
    get len(a: u256, b: u256): External<u256> { return msg.data.length; }
    get echo(a: u256): External<bytes> { return msg.data; }
    get copy(a: u256): External<bytes> { let d: bytes = msg.data; return d; }
    get at(i: u256, x: u256): External<bytes1> { return msg.data[i]; } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  function len(uint256 a, uint256 b) external pure returns (uint256) { return msg.data.length; }
  function echo(uint256 a) external pure returns (bytes memory) { return msg.data; }
  function copy(uint256 a) external pure returns (bytes memory) { bytes memory d = msg.data; return d; }
  function at(uint256 i, uint256 x) external pure returns (bytes1) { return msg.data[i]; } }`;

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });

  it('msg.data.length equals calldatasize (selector + args), byte-identical', async () => {
    const data = '0x' + sel('len(uint256,uint256)') + pad32(11n) + pad32(22n); // 4 + 64 = 68 bytes
    expect((await jeth.call(aj, data)).returnHex).toBe((await sol.call(as, data)).returnHex);
  });
  it('msg.data copy/return reproduces the whole calldata, byte-identical', async () => {
    for (const fn of ['echo', 'copy'] as const) {
      const data = '0x' + sel(`${fn}(uint256)`) + pad32(0xdeadbeefn);
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(j.success, fn).toBe(s.success);
      expect(j.returnHex, fn).toBe(s.returnHex);
    }
  });
  it('msg.data[i] byte-indexes the calldata incl. selector bytes, OOB Panic 0x32 matches solc', async () => {
    // calldata = selector(4) + pad32(i) + pad32(x) = 68 bytes; index every interesting byte + OOB
    for (const i of [0n, 1n, 3n, 4n, 35n, 36n, 67n, 68n, 100n]) {
      const data = '0x' + sel('at(uint256,uint256)') + pad32(i) + pad32(0xab12n);
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(j.success, `at(${i})`).toBe(s.success);
      expect(j.returnHex, `at(${i})`).toBe(s.returnHex);
    }
  });
  it('compile-time: msg.data is allowed in @pure; the stale JETH161 gate is gone', () => {
    expect(codes('class C { get f(): External<u256> { return msg.data.length; } }')).toEqual([]);
  });
});
