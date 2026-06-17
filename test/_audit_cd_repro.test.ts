// AUDIT: minimal reproducers for formerly-divergent JETH-vs-solc calldata decode,
// now CLOSED and asserted byte-identical.
// Class A: in-tuple dynamic-field offset in (2^255, 2^256) on the LAZY-ACCESS path:
//          solc accepts (signed slt + wrap), JETH's lazy helpers now match.
// Class B: huge (~2^64) length during a decode-to-memory ECHO: solc returns
//          Panic(0x41); JETH's echo encoders now apply the alloc Panic(0x41) too.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AuditCd {
  struct D { uint256 a; string s; }
  struct E { uint64 id; bytes name; }
  function dS(D calldata d) external pure returns (string memory) { return d.s; }
  function dEcho(D calldata d) external pure returns (D memory) { return d; }
  function eName(E calldata e) external pure returns (bytes memory) { return e.name; }
  function saEcho(string[] calldata a) external pure returns (string[] memory) { return a; }
  function mEcho(uint256[][] calldata m) external pure returns (uint256[][] memory) { return m; }
}`;

const JETH = `
@struct class D { a: u256; s: string; }
@struct class E { id: u64; name: bytes; }
@contract
class AuditCd {
  @external @pure dS(d: D): string { return d.s; }
  @external @pure dEcho(d: D): D { return d; }
  @external @pure eName(e: E): bytes { return e.name; }
  @external @pure saEcho(a: string[]): string[] { return a; }
  @external @pure mEcho(m: u256[][]): u256[][] { return m; }
}`;

const M = 1n << 256n;
function w(v: bigint): string { return (((v % M) + M) % M).toString(16).padStart(64, '0'); }

let jeth: Harness, sol: Harness, aj: Address, as_: Address;
function sel(s: string): string { return functionSelector(s); }
async function pair(sig: string, body: string) {
  const data = '0x' + sel(sig) + body;
  const j = await jeth.call(aj, data);
  const s = await sol.call(as_, data);
  return { data, j, s };
}

beforeAll(async () => {
  const jb = compile(JETH, { fileName: 'r.jeth' });
  const sb = compileSolidity(SOL, 'AuditCd');
  jeth = await Harness.create();
  sol = await Harness.create();
  aj = await jeth.deploy(jb.creationBytecode);
  as_ = await sol.deploy(sb.creation);
});

// byte-identity helper: JETH and solc must agree on success + returndata.
async function same(sig: string, body: string) {
  const { j, s } = await pair(sig, body);
  expect(j.success, `${sig} success`).toBe(s.success);
  expect(j.returnHex, `${sig} returndata`).toBe(s.returnHex);
  return { j, s };
}

describe('AUDIT cd confirmed reproducers (now byte-identical)', () => {
  // ---------- Class A: lazy-access in-tuple offset (signed slt + wrap) ----------
  it('A1: dS in-tuple string off_s=2^256-32 -> solc OK (wrapped read), JETH matches', async () => {
    const body = w(0x20n) + w(7n) + w(M - 32n) + w(0n) + w(0n) + w(0n) + w(0n);
    const { s } = await same('dS((uint256,string))', body);
    expect(s.success).toBe(true);
    expect(s.returnHex).toBe('0x' + w(0x20n) + w(0x20n) + w(7n)); // 32-byte string = word 0x07
  });

  it('A2: eName in-tuple bytes off=2^256-32 -> solc OK, JETH matches', async () => {
    const body = w(0x20n) + w(0x42n) + w(M - 32n) + w(0n) + w(0n) + w(0n) + w(0n);
    const { s } = await same('eName((uint64,bytes))', body);
    expect(s.success).toBe(true);
  });

  // ---------- Class B: huge length during decode-to-memory echo (Panic 0x41) ----------
  it('B1: dEcho in-tuple string len=2^64-1 -> Panic(0x41), JETH matches', async () => {
    const body = w(0x20n) + w(7n) + w(0x40n) + w((1n << 64n) - 1n);
    const { s } = await same('dEcho((uint256,string))', body);
    expect(s.success).toBe(false);
    expect(s.returnHex).toBe('0x4e487b71' + w(0x41n)); // Panic(0x41)
  });

  it('B2: saEcho string[] inner-element len=2^64-1 -> Panic(0x41), JETH matches', async () => {
    // saEcho(string[]) head=[off]. region: [L=2][off0=0x20][off1=2^64-1] ... triggers
    // the huge per-element allocation on echo -> Panic(0x41).
    const body = w(0x40n) + w(0n) + w(2n) + w(0x20n) + w((1n << 64n) - 1n) + w(0xffn) + w(1n) + w(0x1ffn);
    const { s } = await same('saEcho(string[])', body);
    expect(s.returnHex).toBe('0x4e487b71' + w(0x41n));
  });

  it('B3: mEcho uint256[][] inner-len=2^64-1 -> Panic(0x41), JETH matches', async () => {
    const body = w(0x40n) + w(0n) + w(2n) + w(0x20n) + w((1n << 64n) - 1n) + w(0xffn) + w(1n) + w(0x1ffn);
    const { s } = await same('mEcho(uint256[][])', body);
    expect(s.returnHex).toBe('0x4e487b71' + w(0x41n));
  });
});
