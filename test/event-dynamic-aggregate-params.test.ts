// Indexed and non-indexed @event params of dynamic-leaf arrays (string[], bytes[], u256[][],
// string[][], Arr<string,N>, Arr<u256[],N>) used to be rejected (JETH207 indexed / JETH142 the
// fixed-array-of-dynamic non-indexed forms). They are now lifted byte-identical to solc:
//   - NON-indexed: the value goes in the log DATA as a head offset + its abi.encode tail.
//   - INDEXED: topic = keccak256 of the packed-padded preimage - each leaf laid out with NO length
//     words and NO offset tables (a value leaf as its word; a bytes/string leaf as its content
//     right-padded to a 32-byte boundary; nested arrays concatenated). Verified across calldata,
//     memory, and storage sources, multi-word elements, empty arrays/strings, and mixed events.
// A STRUCT-leaf array (P[] / Arr<P,2> where P has a dynamic field) is supported too (OR5 + Edge C).
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
    jeth: 'class C { E: event<{ a: indexed<string[]> }>; go(xs: string[]): External<void> { emit(E(xs)); } }',
    sol: 'contract C { event E(string[] indexed a); function go(string[] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[])',
    args: W(0x20) + W(2) + W(0x40) + W(0x80) + W(2) + '6161'.padEnd(64, '0') + W(2) + '6262'.padEnd(64, '0'),
  },
  {
    name: 'idx bytes[]',
    jeth: 'class C { E: event<{ a: indexed<bytes[]> }>; go(xs: bytes[]): External<void> { emit(E(xs)); } }',
    sol: 'contract C { event E(bytes[] indexed a); function go(bytes[] calldata xs) external { emit E(xs); } }',
    sig: 'go(bytes[])',
    args: W(0x20) + W(2) + W(0x40) + W(0x80) + W(2) + '6161'.padEnd(64, '0') + W(4) + '62626262'.padEnd(64, '0'),
  },
  {
    name: 'idx u256[][]',
    jeth: 'class C { E: event<{ a: indexed<u256[][]> }>; go(xs: u256[][]): External<void> { emit(E(xs)); } }',
    sol: 'contract C { event E(uint256[][] indexed a); function go(uint256[][] calldata xs) external { emit E(xs); } }',
    sig: 'go(uint256[][])',
    args: W(0x20) + W(2) + W(0x40) + W(0xa0) + W(2) + W(1) + W(2) + W(1) + W(3),
  },
  {
    name: 'idx Arr<string,2>',
    jeth: 'class C { E: event<{ a: indexed<Arr<string,2>> }>; go(xs: Arr<string,2>): External<void> { emit(E(xs)); } }',
    sol: 'contract C { event E(string[2] indexed a); function go(string[2] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[2])',
    args: W(0x20) + W(0x40) + W(0x80) + W(3) + '666f6f'.padEnd(64, '0') + W(3) + '626172'.padEnd(64, '0'),
  },
  {
    name: 'non-idx Arr<string,2>',
    jeth: 'class C { E: event<{ a: Arr<string,2> }>; go(xs: Arr<string,2>): External<void> { emit(E(xs)); } }',
    sol: 'contract C { event E(string[2] a); function go(string[2] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[2])',
    args: W(0x20) + W(0x40) + W(0x80) + W(3) + '666f6f'.padEnd(64, '0') + W(3) + '626172'.padEnd(64, '0'),
  },
  {
    name: 'non-idx string[]',
    jeth: 'class C { E: event<{ a: string[] }>; go(xs: string[]): External<void> { emit(E(xs)); } }',
    sol: 'contract C { event E(string[] a); function go(string[] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[])',
    args: W(0x20) + W(2) + W(0x40) + W(0x80) + W(2) + '6161'.padEnd(64, '0') + W(2) + '6262'.padEnd(64, '0'),
  },
  {
    name: 'idx string[][] (nested)',
    jeth: 'class C { E: event<{ a: indexed<string[][]> }>; go(xs: string[][]): External<void> { emit(E(xs)); } }',
    sol: 'contract C { event E(string[][] indexed a); function go(string[][] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[][])',
    args:
      W(0x20) + W(2) + W(0x40) + W(0x120) +
      W(2) + W(0x40) + W(0x80) + W(1) + '61'.padEnd(64, '0') + W(2) + '6262'.padEnd(64, '0') +
      W(1) + W(0x20) + W(3) + '636363'.padEnd(64, '0'),
  },
  {
    name: 'idx string[] empty',
    jeth: 'class C { E: event<{ a: indexed<string[]> }>; go(xs: string[]): External<void> { emit(E(xs)); } }',
    sol: 'contract C { event E(string[] indexed a); function go(string[] calldata xs) external { emit E(xs); } }',
    sig: 'go(string[])',
    args: W(0x20) + W(0),
  },
  {
    name: 'mixed idx(u256)+idx(string[])+data',
    jeth: 'class C { E: event<{ n: indexed<u256>; a: indexed<string[]>; m: u256 }>; go(n: u256, xs: string[], m: u256): External<void> { emit(E(n, xs, m)); } }',
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
    const jeth = `class C {
      xs: string[];
      E: event<{ a: indexed<string[]> }>;
      fromMem(): External<void> { let m: string[] = ["aa","bbbb"]; emit(E(m)); }
      seed(): External<void> { this.xs.push("aa"); this.xs.push("bb"); }
      fromStore(): External<void> { emit(E(this.xs)); }
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

  it('a MEMORY-local FIXED-outer dynamic-leaf array (Arr<bytes,N>/Arr<string,N>/Arr<u256[],N>) as an indexed topic or non-indexed data matches solc', async () => {
    // Previously JETH900-crashed: materializeArrayArg rejects a fixed-outer-dynamic aggregate (Edge D),
    // but the analyzer accepts it as an @event param (solc does too). The topic is keccak256 of the
    // packed-padded preimage (each leaf padded to a word, no length/offset); the non-indexed data is the
    // fixed-outer abi.encode tail behind a head offset. Both are built from the memory image via
    // abiEncFromMem. Byte-identical to solc across bytes[2]/[3], string[2] with a >31-byte leaf,
    // uint256[][2], a nested bytes[2][2], an inline literal, and an anonymous event.
    const LONG = 'this leaf is definitely longer than thirty-two bytes for the topic test';
    const shapes: { name: string; jeth: string; sol: string }[] = [
      {
        name: 'idx Arr<bytes,2> local',
        jeth: 'class C { E: event<{ d: indexed<Arr<bytes,2>> }>; go(): External<void> { let a: Arr<bytes,2> = [bytes("ab"), bytes("cd")]; emit(E(a)); } }',
        sol: 'contract C { event E(bytes[2] indexed d); function go() external { bytes[2] memory a = [bytes("ab"), bytes("cd")]; emit E(a); } }',
      },
      {
        name: 'idx Arr<string,2> long-leaf local',
        jeth: `class C { E: event<{ d: indexed<Arr<string,2>> }>; go(): External<void> { let a: Arr<string,2> = ["ab", "${LONG}"]; emit(E(a)); } }`,
        sol: `contract C { event E(string[2] indexed d); function go() external { string[2] memory a = ["ab", "${LONG}"]; emit E(a); } }`,
      },
      {
        name: 'idx Arr<u256[],2> local',
        jeth: 'class C { E: event<{ d: indexed<Arr<u256[],2>> }>; go(): External<void> { let a: Arr<u256[],2> = [[1n,2n],[3n]]; emit(E(a)); } }',
        sol: 'contract C { event E(uint256[][2] indexed d); function go() external { uint256[] memory x = new uint256[](2); x[0]=1; x[1]=2; uint256[] memory y = new uint256[](1); y[0]=3; uint256[][2] memory a = [x, y]; emit E(a); } }',
      },
      {
        name: 'non-idx Arr<bytes,2> local',
        jeth: 'class C { E: event<{ d: Arr<bytes,2> }>; go(): External<void> { let a: Arr<bytes,2> = [bytes("ab"), bytes("cd")]; emit(E(a)); } }',
        sol: 'contract C { event E(bytes[2] d); function go() external { bytes[2] memory a = [bytes("ab"), bytes("cd")]; emit E(a); } }',
      },
      {
        name: 'idx inline Arr<bytes,2> literal',
        jeth: 'class C { E: event<{ d: indexed<Arr<bytes,2>> }>; go(): External<void> { emit(E([bytes("ab"), bytes("cd")])); } }',
        sol: 'contract C { event E(bytes[2] indexed d); function go() external { emit E([bytes("ab"), bytes("cd")]); } }',
      },
      {
        name: 'idx nested Arr<Arr<bytes,2>,2> local',
        jeth: 'class C { E: event<{ d: indexed<Arr<Arr<bytes,2>,2>> }>; go(): External<void> { let a: Arr<Arr<bytes,2>,2> = [[bytes("ab"),bytes("cd")],[bytes("ef"),bytes("gh")]]; emit(E(a)); } }',
        sol: 'contract C { event E(bytes[2][2] indexed d); function go() external { bytes[2][2] memory a = [[bytes("ab"),bytes("cd")],[bytes("ef"),bytes("gh")]]; emit E(a); } }',
      },
      {
        name: 'anonymous idx Arr<bytes,2> local',
        jeth: 'class C { @anonymous E: event<{ d: indexed<Arr<bytes,2>> }>; go(): External<void> { let a: Arr<bytes,2> = [bytes("ab"), bytes("cd")]; emit(E(a)); } }',
        sol: 'contract C { event E(bytes[2] indexed d) anonymous; function go() external { bytes[2] memory a = [bytes("ab"), bytes("cd")]; emit E(a); } }',
      },
    ];
    for (const c of shapes) {
      const hj = await Harness.create();
      const hs = await Harness.create();
      const aj: Address = await hj.deploy(compile(c.jeth, { fileName: 'C.jeth' }).creationBytecode);
      const as: Address = await hs.deploy(compileSolidity(SPDX + c.sol, 'C').creation);
      const rj = await hj.call(aj, sel('go()'));
      const rs = await hs.call(as, sel('go()'));
      expect(rj.success, `${c.name} success`).toBe(rs.success);
      const lj = JSON.stringify(rj.logs?.map((l) => ({ t: l.topics, d: l.data })) ?? []);
      const ls = JSON.stringify(rs.logs?.map((l) => ({ t: l.topics, d: l.data })) ?? []);
      expect(lj, `${c.name} log`).toBe(ls);
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
      codes('type P = { a: u256; s: string }; class C { E: event<{ a: indexed<P[]> }>; go(xs: P[]): External<void> { emit(E(xs)); } }'),
    ).toEqual([]);
    // Edge C: a struct element with a deeper dynamic field (dyn array / nested dyn struct) is now ACCEPTED
    // too (packTopicStructFromAbi recurses; byte-identical to solc - see event-indexed-dyn-struct-array).
    expect(
      codes('type P = { a: u256; tags: u256[] }; class C { E: event<{ a: indexed<P[]> }>; go(xs: P[]): External<void> { emit(E(xs)); } }'),
    ).toEqual([]);
  });
});
