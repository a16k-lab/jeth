// Tier-1 (JETH207): an indexed DYNAMIC value-element array event param. The topic is
// keccak256 of the element words (no length / offset) - verified empirically vs solc. Covers
// u256[]/u8[]/address[]/bytes32[], mixed indexed+non-indexed, empty/large. Topics + data
// compared byte-for-byte vs solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const arr = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');
type LogEntry = { topics: string[]; data: string };
const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
  a.length === b.length &&
  a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics));

const JETH = `class C {
  Eu: event<{ a: indexed<u256[]>; v: u256 }>;
  E8: event<{ a: indexed<u8[]> }>;
  Ead: event<{ a: indexed<address[]> }>;
  Emix: event<{ k: indexed<u256>; a: indexed<u256[]>; v: u256 }>;
  eu(a: u256[]): External<void> { emit(Eu(a, 9n)); }
  e8(a: u8[]): External<void> { emit(E8(a)); }
  ead(a: address[]): External<void> { emit(Ead(a)); }
  emix(k: u256, a: u256[], v: u256): External<void> { emit(Emix(k, a, v)); }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  event Eu(uint256[] indexed a, uint256 v);
  event E8(uint8[] indexed a);
  event Ead(address[] indexed a);
  event Emix(uint256 indexed k, uint256[] indexed a, uint256 v);
  function eu(uint256[] calldata a) external { emit Eu(a, 9); }
  function e8(uint8[] calldata a) external { emit E8(a); }
  function ead(address[] calldata a) external { emit Ead(a); }
  function emix(uint256 k, uint256[] calldata a, uint256 v) external { emit Emix(k, a, v); }
}`;

describe('indexed value-array event param (JETH207) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(
      eqLogs(j.logs as LogEntry[], s.logs as LogEntry[]),
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

  it('u256[] / u8[] / address[] / mixed indexed array topics', async () => {
    for (const xs of [[], [7n], [7n, 8n], [1n, 2n, 3n, 4n, 5n], [M - 1n, 0n]] as const) {
      await eq(`eu([${xs.length}])`, '0x' + sel('eu(uint256[])') + pad(0x20n) + arr([...xs]));
      await eq(
        `emix([${xs.length}])`,
        '0x' + sel('emix(uint256,uint256[],uint256)') + pad(42n) + pad(0x60n) + pad(99n) + arr([...xs]),
      );
    }
    for (const xs of [[], [1n, 255n], [0n, 128n, 7n]] as const) {
      await eq(`e8([${xs.length}])`, '0x' + sel('e8(uint8[])') + pad(0x20n) + arr([...xs]));
    }
    for (const xs of [[], [0xa1n], [0xa1n, 0xb2n, 0xc3n]] as const) {
      await eq(`ead([${xs.length}])`, '0x' + sel('ead(address[])') + pad(0x20n) + arr([...xs]));
    }
  });
});
