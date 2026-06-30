// Indexed and non-indexed @event params of dynamic-leaf arrays (string[], bytes[], u256[][],
// string[][], Arr<string,N>, Arr<u256[],N>) used to be rejected (JETH207 indexed / JETH142 the
// fixed-array-of-dynamic non-indexed forms). They are now lifted byte-identical to solc:
//   - NON-indexed: the value goes in the log DATA as a head offset + its abi.encode tail.
//   - INDEXED: topic = keccak256 of the packed-padded preimage - each leaf laid out with NO length
//     words and NO offset tables (a value leaf as its word; a bytes/string leaf as its content
//     right-padded to a 32-byte boundary; nested arrays concatenated). Verified across calldata,
//     memory, and storage sources, multi-word elements, empty arrays/strings, and mixed events.
// A STRUCT-leaf array (P[] / Arr<P,2> where P has a dynamic field) stays a sound reject (JETH207).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => BigInt(n).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

const cases: { name: string; jeth: string; sol: string; sig: string; args: string }[] = [
  {
    name: 'idx string[]',
    jeth: '@contract class C { @event E(@indexed a: string[]); @external go(xs: string[]): void { emit(E(xs)); } }',
    sol: 'contract C { event E(string[] indexed a); function go(string[] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[])',
    args: W(0x20) + W(2) + W(0x40) + W(0x80) + W(2) + '6161'.padEnd(64, '0') + W(2) + '6262'.padEnd(64, '0'),
  },
  {
    name: 'idx bytes[]',
    jeth: '@contract class C { @event E(@indexed a: bytes[]); @external go(xs: bytes[]): void { emit(E(xs)); } }',
    sol: 'contract C { event E(bytes[] indexed a); function go(bytes[] calldata xs) external { emit E(xs); } }',
    sig: 'go(bytes[])',
    args: W(0x20) + W(2) + W(0x40) + W(0x80) + W(2) + '6161'.padEnd(64, '0') + W(4) + '62626262'.padEnd(64, '0'),
  },
  {
    name: 'idx u256[][]',
    jeth: '@contract class C { @event E(@indexed a: u256[][]); @external go(xs: u256[][]): void { emit(E(xs)); } }',
    sol: 'contract C { event E(uint256[][] indexed a); function go(uint256[][] calldata xs) external { emit E(xs); } }',
    sig: 'go(uint256[][])',
    args: W(0x20) + W(2) + W(0x40) + W(0xa0) + W(2) + W(1) + W(2) + W(1) + W(3),
  },
  {
    name: 'idx Arr<string,2>',
    jeth: '@contract class C { @event E(@indexed a: Arr<string,2>); @external go(xs: Arr<string,2>): void { emit(E(xs)); } }',
    sol: 'contract C { event E(string[2] indexed a); function go(string[2] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[2])',
    args: W(0x20) + W(0x40) + W(0x80) + W(3) + '666f6f'.padEnd(64, '0') + W(3) + '626172'.padEnd(64, '0'),
  },
  {
    name: 'non-idx Arr<string,2>',
    jeth: '@contract class C { @event E(a: Arr<string,2>); @external go(xs: Arr<string,2>): void { emit(E(xs)); } }',
    sol: 'contract C { event E(string[2] a); function go(string[2] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[2])',
    args: W(0x20) + W(0x40) + W(0x80) + W(3) + '666f6f'.padEnd(64, '0') + W(3) + '626172'.padEnd(64, '0'),
  },
  {
    name: 'non-idx string[]',
    jeth: '@contract class C { @event E(a: string[]); @external go(xs: string[]): void { emit(E(xs)); } }',
    sol: 'contract C { event E(string[] a); function go(string[] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[])',
    args: W(0x20) + W(2) + W(0x40) + W(0x80) + W(2) + '6161'.padEnd(64, '0') + W(2) + '6262'.padEnd(64, '0'),
  },
  {
    name: 'idx string[][] (nested)',
    jeth: '@contract class C { @event E(@indexed a: string[][]); @external go(xs: string[][]): void { emit(E(xs)); } }',
    sol: 'contract C { event E(string[][] indexed a); function go(string[][] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[][])',
    args:
      W(0x20) + W(2) + W(0x40) + W(0x120) +
      W(2) + W(0x40) + W(0x80) + W(1) + '61'.padEnd(64, '0') + W(2) + '6262'.padEnd(64, '0') +
      W(1) + W(0x20) + W(3) + '636363'.padEnd(64, '0'),
  },
  {
    name: 'idx string[] empty',
    jeth: '@contract class C { @event E(@indexed a: string[]); @external go(xs: string[]): void { emit(E(xs)); } }',
    sol: 'contract C { event E(string[] indexed a); function go(string[] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[])',
    args: W(0x20) + W(0),
  },
  {
    name: 'mixed idx(u256)+idx(string[])+data',
    jeth: '@contract class C { @event E(@indexed n: u256, @indexed a: string[], m: u256); @external go(n: u256, xs: string[], m: u256): void { emit(E(n, xs, m)); } }',
    sol: 'contract C { event E(uint256 indexed n, string[] indexed a, uint256 m); function go(uint256 n, string[] calldata xs, uint256 m) external { emit E(n, xs, m); } }',
    sig: 'go(uint256,string[],uint256)',
    args: W(7) + W(0x80) + W(99) + W(2) + W(0x40) + W(0x80) + W(2) + '6161'.padEnd(64, '0') + W(2) + '6262'.padEnd(64, '0'),
  },
];

describe('dynamic-aggregate event params (indexed topic + non-indexed data) vs Solidity', () => {
  it('emits byte-identical logs for each shape', async () => {
    for (const c of cases) {
      const hj = await Harness.create();
      const hs = await Harness.create();
      const aj: Address = await hj.deploy(compile(c.jeth, { fileName: 'C.jeth' }).creationBytecode);
      const as: Address = await hs.deploy(compileSolidity(SPDX + c.sol, 'C').creation);
      const rj = await hj.call(aj, sel(c.sig) + c.args);
      const rs = await hs.call(as, sel(c.sig) + c.args);
      expect(rj.success, `${c.name} success`).toBe(rs.success);
      const lj = JSON.stringify(rj.logs?.map((l) => ({ t: l.topics, d: l.data })) ?? []);
      const ls = JSON.stringify(rs.logs?.map((l) => ({ t: l.topics, d: l.data })) ?? []);
      expect(lj, `${c.name} log`).toBe(ls);
    }
  });

  it('indexed string[] from a memory local and from storage match solc', async () => {
    const jeth = `@contract class C {
      @state xs: string[];
      @event E(@indexed a: string[]);
      @external fromMem(): void { let m: string[] = ["aa","bbbb"]; emit(E(m)); }
      @external seed(): void { this.xs.push("aa"); this.xs.push("bb"); }
      @external fromStore(): void { emit(E(this.xs)); }
    }`;
    const sol = `contract C {
      string[] xs;
      event E(string[] indexed a);
      function fromMem() external { string[] memory m = new string[](2); m[0]="aa"; m[1]="bbbb"; emit E(m); }
      function seed() external { xs.push("aa"); xs.push("bb"); }
      function fromStore() external { emit E(xs); }
    }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
    const as = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
    for (const s of ['fromMem()', 'seed()', 'fromStore()']) {
      const rj = await hj.call(aj, sel(s));
      const rs = await hs.call(as, sel(s));
      const lj = JSON.stringify(rj.logs?.map((l) => ({ t: l.topics, d: l.data })) ?? []);
      const ls = JSON.stringify(rs.logs?.map((l) => ({ t: l.topics, d: l.data })) ?? []);
      expect(lj, `${s} log`).toBe(ls);
    }
  });

  it('an indexed dynamic-struct-element array is now ACCEPTED (OR5, packed-padded struct topic)', () => {
    // Previously a sound reject; the topic codec now encodes each struct element's members
    // packed-padded (byte-identical to solc, verified in audit-over-rejections.test.ts). A struct
    // element with a deeper dynamic field (dyn array / nested dyn struct) stays a clean reject.
    const codes = (src: string) => {
      try {
        compile(src, { fileName: 'C.jeth' });
        return [];
      } catch (e: unknown) {
        return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
      }
    };
    expect(
      codes('@struct class P { a: u256; s: string } @contract class C { @event E(@indexed a: P[]); @external go(xs: P[]): void { emit(E(xs)); } }'),
    ).toEqual([]);
    expect(
      codes('@struct class P { a: u256; tags: u256[] } @contract class C { @event E(@indexed a: P[]); @external go(xs: P[]): void { emit(E(xs)); } }'),
    ).toContain('JETH207');
  });
});
