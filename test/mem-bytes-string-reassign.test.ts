// Whole-value REASSIGN (re-point) of a bytes/string MEMORY local, or an @internal/@private bytes/string
// param (both held as a [len][data] memory pointer): `d = bytes("x")` / `s = "x"`. The register is rebound
// at the new value, exactly like solc's `bytes memory` reference re-point. Previously this crashed with
// JETH900 ("reference value used in a non-reference context"). An @external bytes/string param is a
// read-only calldata view, so its reassign is a CLEAN reject (JETH214), not an internal crash.
// Byte-identical to solc 0.8.x: longer/shorter/empty, conditional, reassign-then-mutate, multiple, alias.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
// (bool) arg
const cdBool = (sig: string, b: boolean) => '0x' + sel(sig) + pad(b ? 1n : 0n);
// (bytes1) arg: a left-aligned single byte
const cdB1 = (sig: string, byte: number) => '0x' + sel(sig) + byte.toString(16).padStart(2, '0').padEnd(64, '0');

const JETH = `class C {
  get bLocal(): External<bytes> { let d: bytes = bytes("a"); d = bytes("hello"); return d; }
  get bLen(): External<u256> { let d: bytes = bytes("a"); d = bytes("hello"); return d.length; }
  get sLocal(): External<string> { let s: string = "a"; s = "world"; return s; }
  get sLen(): External<u256> { let s: string = "a"; s = "world!!"; return bytes(s).length; }
  get bParam(): External<bytes> { return this.g(bytes("a")); }
  g(d: bytes): bytes { d = bytes("changed"); return d; }
  get sParam(): External<string> { return this.h("a"); }
  h(d: string): string { d = "modified"; return d; }
  get longer(): External<bytes> { let d: bytes = bytes("ab"); d = bytes("abcdefghijklmnopqrstuvwxyz012345!!!"); return d; }
  get shorter(): External<bytes> { let d: bytes = bytes("abcdefghijklmnop"); d = bytes("x"); return d; }
  get empty(): External<bytes> { let d: bytes = bytes("abc"); d = bytes(""); return d; }
  get cond(c: bool): External<bytes> { let d: bytes = bytes("orig"); if (c) { d = bytes("changed!"); } return d; }
  get mutateAfter(b: bytes1): External<bytes> { let d: bytes = bytes("aa"); d = bytes("hello"); d[0n] = b; return d; }
  get multi(): External<bytes> { let d: bytes = bytes("a"); d = bytes("two"); d = bytes("three3"); d = bytes("final!!"); return d; }
  get fromLocal(): External<bytes> { let a: bytes = bytes("sourcevalue"); let d: bytes = bytes("x"); d = a; return d; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function bLocal() external pure returns (bytes memory){ bytes memory d = "a"; d = "hello"; return d; }
  function bLen() external pure returns (uint256){ bytes memory d = "a"; d = "hello"; return d.length; }
  function sLocal() external pure returns (string memory){ string memory s = "a"; s = "world"; return s; }
  function sLen() external pure returns (uint256){ string memory s = "a"; s = "world!!"; return bytes(s).length; }
  function bParam() external returns (bytes memory){ return g("a"); }
  function g(bytes memory d) internal pure returns (bytes memory){ d = "changed"; return d; }
  function sParam() external returns (string memory){ return h("a"); }
  function h(string memory d) internal pure returns (string memory){ d = "modified"; return d; }
  function longer() external pure returns (bytes memory){ bytes memory d = "ab"; d = "abcdefghijklmnopqrstuvwxyz012345!!!"; return d; }
  function shorter() external pure returns (bytes memory){ bytes memory d = "abcdefghijklmnop"; d = "x"; return d; }
  function empty() external pure returns (bytes memory){ bytes memory d = "abc"; d = ""; return d; }
  function cond(bool c) external pure returns (bytes memory){ bytes memory d = "orig"; if (c) { d = "changed!"; } return d; }
  function mutateAfter(bytes1 b) external pure returns (bytes memory){ bytes memory d = "aa"; d = "hello"; d[0] = b; return d; }
  function multi() external pure returns (bytes memory){ bytes memory d = "a"; d = "two"; d = "three3"; d = "final!!"; return d; }
  function fromLocal() external pure returns (bytes memory){ bytes memory a = "sourcevalue"; bytes memory d = "x"; d = a; return d; }
}`;

describe('bytes/string memory local + internal-param whole-value reassign vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
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

  it('bytes/string local + internal-param reassign, lengths, alias', async () => {
    for (const sig of ['bLocal()', 'bLen()', 'sLocal()', 'sLen()', 'bParam()', 'sParam()', 'fromLocal()']) {
      await eq(sig, encodeCall(sel(sig), []));
    }
  });
  it('longer / shorter / empty / multiple reassigns', async () => {
    for (const sig of ['longer()', 'shorter()', 'empty()', 'multi()']) {
      await eq(sig, encodeCall(sel(sig), []));
    }
  });
  it('conditional reassign (both branches)', async () => {
    await eq('cond(true)', cdBool('cond(bool)', true));
    await eq('cond(false)', cdBool('cond(bool)', false));
  });
  it('reassign then mutate d[i]', async () => {
    await eq('mutateAfter', cdB1('mutateAfter(bytes1)', 0x5a)); // 'Z'
  });

  it('an @external (calldata) bytes param reassign is a CLEAN reject (JETH214), not JETH900', () => {
    const src = `class C {
      get f(d: bytes): External<bytes> { d = bytes("x"); return d; }
    }`;
    let codes: string[] = [];
    try {
      compile(src, { fileName: 'C.jeth' });
      throw new Error('expected a diagnostic');
    } catch (e: unknown) {
      codes = ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
    }
    expect(codes).toContain('JETH214');
    expect(codes).not.toContain('JETH900');
  });
  it('an @external (calldata) string param reassign is a CLEAN reject too', () => {
    const src = `class C {
      get f(s: string): External<string> { s = "x"; return s; }
    }`;
    let codes: string[] = [];
    try {
      compile(src, { fileName: 'C.jeth' });
      throw new Error('expected a diagnostic');
    } catch (e: unknown) {
      codes = ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
    }
    expect(codes).toContain('JETH214');
    expect(codes).not.toContain('JETH900');
  });
});
