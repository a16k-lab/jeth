// JETH207 lift: an INDEXED static fixed-array / struct event parameter. solc hashes a reference-type
// indexed param to a keccak topic = keccak256(abi.encode(value)) (the padded leaf words). JETH already
// did this for indexed bytes/string and dynamic value-arrays; this extends it to STATIC fixed-arrays
// (incl. narrow elements) and static structs, from a @state source and a calldata-param source.
// Byte-identical LOG topics + data vs solc 0.8.35.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import type { LogEntry } from '../src/evm.js';

const sel = (s: string) => functionSelector(s);
const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
  expect(a.map((l) => ({ t: l.topics, d: l.data }))).toEqual(b.map((l) => ({ t: l.topics, d: l.data })));

describe('indexed static fixed-array / struct event param (JETH207) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `@struct class P { x: u256; y: u256; }
@contract class C {
  @event EF(@indexed a: Arr<u256,2>, v: u256);
  @event EN(@indexed a: Arr<u8,3>, v: u256);
  @event EP(@indexed p: P, v: u256);
  @state fa: Arr<u256,2>;
  @state na: Arr<u8,3>;
  @state ps: P;
  @external setFa(a: u256, b: u256): void { this.fa[0n] = a; this.fa[1n] = b; }
  @external setNa(a: u8, b: u8, c: u8): void { this.na[0n] = a; this.na[1n] = b; this.na[2n] = c; }
  @external setPs(x: u256, y: u256): void { this.ps.x = x; this.ps.y = y; }
  @external emitFaState(v: u256): void { emit(EF(this.fa, v)); }
  @external emitFaCd(a: Arr<u256,2>, v: u256): void { emit(EF(a, v)); }
  @external emitNaState(v: u256): void { emit(EN(this.na, v)); }
  @external emitPsState(v: u256): void { emit(EP(this.ps, v)); } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  struct P { uint256 x; uint256 y; }
  event EF(uint256[2] indexed a, uint256 v);
  event EN(uint8[3] indexed a, uint256 v);
  event EP(P indexed p, uint256 v);
  uint256[2] fa;
  uint8[3] na;
  P ps;
  function setFa(uint256 a, uint256 b) external { fa[0] = a; fa[1] = b; }
  function setNa(uint8 a, uint8 b, uint8 c) external { na[0] = a; na[1] = b; na[2] = c; }
  function setPs(uint256 x, uint256 y) external { ps.x = x; ps.y = y; }
  function emitFaState(uint256 v) external { emit EF(fa, v); }
  function emitFaCd(uint256[2] calldata a, uint256 v) external { emit EF(a, v); }
  function emitNaState(uint256 v) external { emit EN(na, v); }
  function emitPsState(uint256 v) external { emit EP(ps, v); } }`;

  beforeAll(async () => {
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
    const run = async (data: string) => { await jeth.call(aj, data); await sol.call(as, data); };
    await run('0x' + sel('setFa(uint256,uint256)') + pad32(111n) + pad32(222n));
    await run('0x' + sel('setNa(uint8,uint8,uint8)') + pad32(7n) + pad32(200n) + pad32(255n));
    await run('0x' + sel('setPs(uint256,uint256)') + pad32(42n) + pad32(99n));
  });

  it('indexed uint256[2] from a @state source: topic matches solc', async () => {
    const data = '0x' + sel('emitFaState(uint256)') + pad32(5n);
    eqLogs((await jeth.call(aj, data)).logs, (await sol.call(as, data)).logs);
  });
  it('indexed uint256[2] from a calldata-param source: topic matches solc', async () => {
    const data = '0x' + sel('emitFaCd(uint256[2],uint256)') + pad32(111n) + pad32(222n) + pad32(5n);
    eqLogs((await jeth.call(aj, data)).logs, (await sol.call(as, data)).logs);
  });
  it('indexed NARROW uint8[3] (padded-word keccak preimage): topic matches solc', async () => {
    const data = '0x' + sel('emitNaState(uint256)') + pad32(9n);
    eqLogs((await jeth.call(aj, data)).logs, (await sol.call(as, data)).logs);
  });
  it('indexed static struct: topic matches solc', async () => {
    const data = '0x' + sel('emitPsState(uint256)') + pad32(9n);
    eqLogs((await jeth.call(aj, data)).logs, (await sol.call(as, data)).logs);
  });
});
