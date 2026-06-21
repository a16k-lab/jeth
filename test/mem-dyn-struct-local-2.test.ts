// Tier-1: dynamic-field struct memory local EXTENSIONS (beyond G10 construct/read/return):
// (1) bytes/string field WRITE `d.s = x` (re-point the head word at a fresh blob);
// (2) COPY-init from a storage struct (this.st / this.m[k] / this.recs[i]), a calldata struct
//     param, or another struct local (ALIAS); plus copy-then-mutate. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const encStr = (s: string) => { const h = Buffer.from(s, 'utf8').toString('hex'); return pad(BigInt(h.length / 2)) + h.padEnd(Math.ceil(h.length / 64) * 64, '0'); };
// seed(uint256 av, string s): head [av][off=0x40] then [len][data]
const cdUS = (sig: string, a: bigint, s: string) => '0x' + sel(sig) + pad(a) + pad(0x40n) + encStr(s);
// (uint256, string, string)
const cdUSS = (sig: string, a: bigint, s1: string, s2: string) => {
  const t1 = encStr(s1); const off2 = 0x60 + t1.length / 2;
  return '0x' + sel(sig) + pad(a) + pad(0x60n) + pad(BigInt(off2)) + t1 + encStr(s2);
};
// (uint256, string, string, uint256)
const cdUSSU = (sig: string, a: bigint, s1: string, s2: string, nv: bigint) => {
  const t1 = encStr(s1); const off2 = 0x80 + t1.length / 2;
  return '0x' + sel(sig) + pad(a) + pad(0x80n) + pad(BigInt(off2)) + pad(nv) + t1 + encStr(s2);
};
// fromCalldata(D x): D=(uint256,string) dynamic -> selector + off(0x20) + tuple[a, off_s=0x40, [len][data]]
const cdD = (sig: string, a: bigint, s: string) => '0x' + sel(sig) + pad(0x20n) + pad(a) + pad(0x40n) + encStr(s);

const JETH = `@struct class D { a: u256; s: string; }
@contract class C {
  @state st: D;
  @state m: mapping<address, D>;
  @state recs: D[];
  @external seedSt(av: u256, s: string): void { this.st = D(av, s); }
  @external seedMap(av: u256, s: string): void { this.m[address(0xbeefn)] = D(av, s); }
  @external seedRec(av: u256, s: string): void { this.recs.push(D(av, s)); }
  @external @view fromStorage(): D { let d: D = this.st; return d; }
  @external @view fromMap(): D { let d: D = this.m[address(0xbeefn)]; return d; }
  @external @view fromRec(): D { let d: D = this.recs[0n]; return d; }
  @external @view copyMut(nv: u256, ns: string): D { let d: D = this.st; d.a = nv; d.s = ns; return d; }
  @external @pure fromCalldata(x: D): D { let d: D = x; return d; }
  @external @pure copyCdMut(x: D, nv: u256): D { let d: D = x; d.a = nv; return d; }
  @external @pure writeBytes(av: u256, s: string, ns: string): D { let d: D = D(av, s); d.s = ns; return d; }
  @external @pure writeBoth(av: u256, s: string, ns: string, nv: u256): D { let d: D = D(av, s); d.s = ns; d.a = nv; return d; }
  @external @pure aliasMut(av: u256, s: string): D { let d: D = D(av, s); let e: D = d; e.a = 999n; return d; }
  @external @pure aliasBytes(av: u256, s: string, ns: string): D { let d: D = D(av, s); let e: D = d; e.s = ns; return d; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct D { uint256 a; string s; }
  D st;
  mapping(address => D) m;
  D[] recs;
  function seedSt(uint256 av, string calldata s) external { st = D(av, s); }
  function seedMap(uint256 av, string calldata s) external { m[address(0xbeef)] = D(av, s); }
  function seedRec(uint256 av, string calldata s) external { recs.push(D(av, s)); }
  function fromStorage() external view returns (D memory) { D memory d = st; return d; }
  function fromMap() external view returns (D memory) { D memory d = m[address(0xbeef)]; return d; }
  function fromRec() external view returns (D memory) { D memory d = recs[0]; return d; }
  function copyMut(uint256 nv, string calldata ns) external view returns (D memory) { D memory d = st; d.a = nv; d.s = ns; return d; }
  function fromCalldata(D calldata x) external pure returns (D memory) { D memory d = x; return d; }
  function copyCdMut(D calldata x, uint256 nv) external pure returns (D memory) { D memory d = x; d.a = nv; return d; }
  function writeBytes(uint256 av, string calldata s, string calldata ns) external pure returns (D memory) { D memory d = D(av, s); d.s = ns; return d; }
  function writeBoth(uint256 av, string calldata s, string calldata ns, uint256 nv) external pure returns (D memory) { D memory d = D(av, s); d.s = ns; d.a = nv; return d; }
  function aliasMut(uint256 av, string calldata s) external pure returns (D memory) { D memory d = D(av, s); D memory e = d; e.a = 999; return d; }
  function aliasBytes(uint256 av, string calldata s, string calldata ns) external pure returns (D memory) { D memory d = D(av, s); D memory e = d; e.s = ns; return d; }
}`;

describe('dyn-struct memory local: write + copy vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  async function seedBoth(data: string) { await jeth.call(aj, data); await sol.call(as, data); }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  const SHORT = 'hi', LONG = 'a string that is definitely longer than thirty-two bytes for the dynamic case';
  const NS = ['', 'x', 'a replacement string that exceeds thirty-two bytes so it needs a fresh blob'];

  it('bytes/string field write (short<->long<->empty) + write both fields', async () => {
    for (const s of [SHORT, LONG]) for (const ns of NS) {
      await eq(`writeBytes(${s.length},${ns.length})`, cdUSS('writeBytes(uint256,string,string)', 7n, s, ns));
      await eq(`writeBoth`, cdUSSU('writeBoth(uint256,string,string,uint256)', 7n, s, ns, 0xabcn));
    }
  });
  it('copy-init from storage struct / mapping / struct-array element', async () => {
    for (const [av, s] of [[1n, SHORT], [M - 1n, LONG], [0n, '']] as const) {
      await seedBoth(cdUS('seedSt(uint256,string)', av, s));
      await seedBoth(cdUS('seedMap(uint256,string)', av, s));
      await eq('fromStorage', encodeCall(sel('fromStorage()'), []));
      await eq('fromMap', encodeCall(sel('fromMap()'), []));
      await eq('copyMut', cdUS('copyMut(uint256,string)', 0x777n, s));
    }
    await seedBoth(cdUS('seedRec(uint256,string)', 42n, LONG));
    await eq('fromRec', encodeCall(sel('fromRec()'), []));
  });
  it('copy-init from a calldata struct param (+ mutate)', async () => {
    for (const [av, s] of [[5n, SHORT], [M - 1n, LONG], [0n, '']] as const) {
      await eq('fromCalldata', cdD('fromCalldata((uint256,string))', av, s));
      await eq('copyCdMut', '0x' + sel('copyCdMut((uint256,string),uint256)') + pad(0x40n) + pad(0x111n) + pad(av) + pad(0x40n) + encStr(s));
    }
  });
  it('another-local alias: mutation through the alias is visible in the original', async () => {
    for (const s of [SHORT, LONG]) {
      await eq('aliasMut', cdUS('aliasMut(uint256,string)', 1n, s));
      for (const ns of NS) await eq('aliasBytes', cdUSS('aliasBytes(uint256,string,string)', 1n, s, ns));
    }
  });
});
