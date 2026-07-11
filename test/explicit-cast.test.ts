// C1: explicit numeric / bytes casts uintN(x)/intN(x)/bytesN(x): truncation, sign-extend,
// reinterpret, uint<->bytes same-size. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `class CC {
  get narrowU(a: u256): External<u8> { return u8(a); }
  get narrowU32(a: u256): External<u32> { return u32(a); }
  get u2i(a: u8): External<i8> { return i8(a); }
  get i2u(a: i8): External<u8> { return u8(a); }
  get narrowI(a: i256): External<i8> { return i8(a); }
  get ubytes(a: u256): External<bytes32> { return bytes32(a); }
  get bytesu(a: bytes32): External<u256> { return u256(a); }
  get u32b4(a: u32): External<bytes4> { return bytes4(a); }
  get b4u32(a: bytes4): External<u32> { return u32(a); }
  get narrowBytes(a: bytes32): External<bytes4> { return bytes4(a); }
  get chain(a: i256): External<u8> { return u8(u256(a)); }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CC {
  function narrowU(uint256 a) external pure returns (uint8){ return uint8(a); }
  function narrowU32(uint256 a) external pure returns (uint32){ return uint32(a); }
  function u2i(uint8 a) external pure returns (int8){ return int8(a); }
  function i2u(int8 a) external pure returns (uint8){ return uint8(a); }
  function narrowI(int256 a) external pure returns (int8){ return int8(a); }
  function ubytes(uint256 a) external pure returns (bytes32){ return bytes32(a); }
  function bytesu(bytes32 a) external pure returns (uint256){ return uint256(a); }
  function u32b4(uint32 a) external pure returns (bytes4){ return bytes4(a); }
  function b4u32(bytes4 a) external pure returns (uint32){ return uint32(a); }
  function narrowBytes(bytes32 a) external pure returns (bytes4){ return bytes4(a); }
  function chain(int256 a) external pure returns (uint8){ return uint8(uint256(a)); }
}`;

describe('explicit casts vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, sig: string, arg: bigint) {
    const data = '0x' + sel(sig) + pad(arg);
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'CC.jeth' });
    const sb = compileSolidity(SOL, 'CC');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('uint truncation u256 -> u8 / u32', async () => {
    for (const v of [0n, 255n, 256n, 0x1234n, M - 1n]) {
      await eq(`narrowU ${v}`, 'narrowU(uint256)', v);
      await eq(`narrowU32 ${v}`, 'narrowU32(uint256)', v);
    }
  });
  it('same-size sign reinterpret u8<->i8', async () => {
    for (const v of [0n, 127n, 128n, 200n, 255n]) await eq(`u2i ${v}`, 'u2i(uint8)', v);
    for (const v of [0n, 127n, M - 1n /*-1*/, M - 56n /*-56*/]) await eq(`i2u ${v}`, 'i2u(int8)', v);
  });
  it('int truncation i256 -> i8 (sign)', async () => {
    for (const v of [0n, 5n, M - 1n, 200n, M - 200n, 1n << 255n]) await eq(`narrowI ${v}`, 'narrowI(int256)', v);
  });
  it('uint<->bytes same-size: u256<->bytes32, u32<->bytes4', async () => {
    await eq('ubytes', 'ubytes(uint256)', BigInt('0x' + 'ab'.repeat(32)));
    await eq('bytesu', 'bytesu(bytes32)', BigInt('0x' + 'cd'.repeat(32)));
    await eq('u32b4', 'u32b4(uint32)', 0xdeadbeefn);
    await eq('b4u32', 'b4u32(bytes4)', BigInt('0xdeadbeef') << 224n);
  });
  it('bytes narrowing bytes32 -> bytes4', async () => {
    await eq('narrowBytes', 'narrowBytes(bytes32)', BigInt('0x' + 'a5'.repeat(32)));
  });
  it('two-step chain i256 -> u256 -> u8', async () => {
    await eq('chain -1', 'chain(int256)', M - 1n);
    await eq('chain 300', 'chain(int256)', 300n);
  });
});
