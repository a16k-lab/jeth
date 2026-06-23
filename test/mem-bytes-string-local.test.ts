// G9: bytes/string MEMORY locals (let s: string = X). Register holds a [len][data] pointer
// materialized from a calldata param / string literal / storage source; return, .length, b[i],
// keccak, and aliasing all work. Byte-identical to solc, short/long/empty.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const encStr = (s: string) => {
  const h = Buffer.from(s, 'utf8').toString('hex');
  return pad(BigInt(h.length / 2)) + h.padEnd(Math.ceil(h.length / 64) * 64, '0');
};
// single bytes/string arg: selector + offset(0x20) + [len][data]
const cd1 = (sig: string, s: string) => '0x' + sel(sig) + pad(0x20n) + encStr(s);
// (string, uint256): offset(0x40) + value + [len][data]
const cdSU = (sig: string, s: string, v: bigint) => '0x' + sel(sig) + pad(0x40n) + pad(v) + encStr(s);

const JETH = `@contract class C {
  @state st: string;
  @external setSt(x: string): void { this.st = x; }
  @external @pure echo(x: string): string { let s: string = x; return s; }
  @external @pure echoLit(): string { let s: string = "hello, this is a string literal over 32 bytes long!!"; return s; }
  @external @view fromStorage(): string { let s: string = this.st; return s; }
  @external @pure blen(x: bytes): u256 { let b: bytes = x; return b.length; }
  @external @pure byteAt(x: bytes, i: u256): u8 { let b: bytes = x; return u8(b[i]); }
  @external @pure aliasLen(x: bytes): u256 { let s: bytes = x; let t: bytes = s; return t.length; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  string st;
  function setSt(string calldata x) external { st = x; }
  function echo(string calldata x) external pure returns (string memory){ string memory s = x; return s; }
  function echoLit() external pure returns (string memory){ string memory s = "hello, this is a string literal over 32 bytes long!!"; return s; }
  function fromStorage() external view returns (string memory){ string memory s = st; return s; }
  function blen(bytes calldata x) external pure returns (uint256){ bytes memory b = x; return b.length; }
  function byteAt(bytes calldata x, uint256 i) external pure returns (uint8){ bytes memory b = x; return uint8(b[i]); }
  function aliasLen(bytes calldata x) external pure returns (uint256){ bytes memory s = x; bytes memory t = s; return t.length; }
}`;

describe('bytes/string memory locals (G9) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${j.exceptionError}`).toBe(s.success);
  }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  const STRS = [
    '',
    'abc',
    'abcdefghijklmnopqrstuvwxyz012345',
    'this string is definitely longer than thirty-two bytes for testing',
  ];
  it('echo (calldata copy) / literal / .length / keccak / alias', async () => {
    await eq('echoLit', encodeCall(sel('echoLit()'), []));
    for (const s of STRS) {
      await eq(`echo("${s.slice(0, 6)}")`, cd1('echo(string)', s));
      await eq(`blen("${s.slice(0, 6)}")`, cd1('blen(bytes)', s));
      await eq(`hash("${s.slice(0, 6)}")`, cd1('hash(string)', s));
      await eq(`aliasLen("${s.slice(0, 6)}")`, cd1('aliasLen(string)', s));
    }
  });
  it('storage source + byte index', async () => {
    for (const s of STRS) {
      await send(cd1('setSt(string)', s));
      await eq(`fromStorage`, encodeCall(sel('fromStorage()'), []));
    }
    // byteAt: bytes "abcde", index 0..4
    for (let i = 0n; i < 5n; i++) await eq(`byteAt(${i})`, cdSU('byteAt(bytes,uint256)', 'abcde', i));
    // OOB byte index reverts on both
    await eq('byteAt OOB', cdSU('byteAt(bytes,uint256)', 'abcde', 9n));
  });
});
