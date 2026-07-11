// G4: an INDEXED bytes/string event parameter becomes a topic = keccak256(content bytes).
// Compares emitted log topics + data byte-for-byte vs solc. Short/long/empty, mixed indexed.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, type LogEntry } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const encStr = (s: string) => {
  const hex = Buffer.from(s, 'utf8').toString('hex');
  return pad(BigInt(hex.length / 2)) + hex.padEnd(Math.ceil(hex.length / 64) * 64, '0');
};
type Comp = { dyn: false; word: string } | { dyn: true; tail: string };
const callData = (sig: string, comps: Comp[]) => {
  let off = comps.length * 32,
    head = '',
    tails = '';
  for (const c of comps) {
    if (!c.dyn) head += c.word;
    else {
      head += pad(BigInt(off));
      tails += c.tail;
      off += c.tail.length / 2;
    }
  }
  return '0x' + sel(sig) + head + tails;
};
const S = (s: string): Comp => ({ dyn: true, tail: encStr(s) });
const V = (v: bigint): Comp => ({ dyn: false, word: pad(v) });
const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
  a.length === b.length &&
  a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics));

const JETH = `class C {
  Es: event<{ s: indexed<string>; v: u256 }>;
  Eb: event<{ b: indexed<bytes>; v: u256 }>;
  Emix: event<{ k: indexed<u256>; s: indexed<string>; v: u256 }>;
  Etwo: event<{ s1: indexed<string>; s2: indexed<string> }>;
  Eonly: event<{ s: indexed<string> }>;
  es(s: string, v: u256): External<void> { emit(Es(s, v)); }
  eb(b: bytes, v: u256): External<void> { emit(Eb(b, v)); }
  emix(k: u256, s: string, v: u256): External<void> { emit(Emix(k, s, v)); }
  etwo(s1: string, s2: string): External<void> { emit(Etwo(s1, s2)); }
  eonly(s: string): External<void> { emit(Eonly(s)); }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  event Es(string indexed s, uint256 v);
  event Eb(bytes indexed b, uint256 v);
  event Emix(uint256 indexed k, string indexed s, uint256 v);
  event Etwo(string indexed s1, string indexed s2);
  event Eonly(string indexed s);
  function es(string calldata s, uint256 v) external { emit Es(s, v); }
  function eb(bytes calldata b, uint256 v) external { emit Eb(b, v); }
  function emix(uint256 k, string calldata s, uint256 v) external { emit Emix(k, s, v); }
  function etwo(string calldata s1, string calldata s2) external { emit Etwo(s1, s2); }
  function eonly(string calldata s) external { emit Eonly(s); }
}`;

describe('indexed bytes/string event topic (G4) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eqLog(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(
      eqLogs(j.logs, s.logs),
      `${label} logs\n jeth=${JSON.stringify(j.logs)}\n sol =${JSON.stringify(s.logs)}`,
    ).toBe(true);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  const SHORT = 'abc';
  const EXACT = 'abcdefghijklmnopqrstuvwxyz012345'; // 32 bytes
  const LONG = 'this string is definitely longer than thirty-two bytes for the keccak topic test';
  const EMPTY = '';
  it('indexed string topic = keccak(content): short/exact32/long/empty', async () => {
    for (const s of [SHORT, EXACT, LONG, EMPTY]) {
      await eqLog(`es("${s.slice(0, 8)}")`, callData('es(string,uint256)', [S(s), V(7n)]));
      await eqLog(`eb("${s.slice(0, 8)}")`, callData('eb(bytes,uint256)', [S(s), V(9n)]));
      await eqLog(`eonly`, callData('eonly(string)', [S(s)]));
    }
  });
  it('mixed indexed (value + string) and two indexed strings', async () => {
    await eqLog('emix', callData('emix(uint256,string,uint256)', [V(42n), S(LONG), V(100n)]));
    await eqLog('etwo', callData('etwo(string,string)', [S(SHORT), S(LONG)]));
    await eqLog('etwo empty/long', callData('etwo(string,string)', [S(EMPTY), S(EXACT)]));
  });
});
