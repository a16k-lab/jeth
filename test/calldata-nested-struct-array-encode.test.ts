// R3: a DIRECT (lazy, from-calldata) abi.encode(p) / keccak256(abi.encode(p)) / emit E(p) / revert Er(p)
// of a calldata NESTED struct S{ a; t: T } whose INNER struct T carries an ARRAY member used to crash
// with a JETH900 ICE on VALID input ("returning a calldata struct param with an array field is not
// supported yet"). solc 0.8.35 accepts and encodes it. The direct calldata encode path had no branch for
// a nested-struct FIELD whose own members include an array (value-array u256[], leaf-array string[] /
// bytes[] / u256[][], or a deeper nested struct with an array): the nested struct field recursed into the
// tuple encoder with a 'cd' source and the inner array member hit arrayFieldRef's crashing 'cd' branch.
//
// FIX: tupleSrc now detects a nested struct field whose subtree carries an array member and routes it
// through the SAME materialize-then-encode path a top-level value/leaf array field already uses
// (buildDynStructFromCalldata builds the whole pointer-headed memory image, then we encode from a 'mem'
// source) with the RE-ENCODE cap flavor (emptyCap = true): an oversized inner length EMPTY-reverts, a
// truncated / OOB source EMPTY-reverts, byte-identical to solc re-encoding a malformed calldata aggregate.
// This is the calldata twin of the memory codec the BIND path (`let m: S = p`) already uses; the BIND
// context keeps its Panic 0x41 flavor (verified below alongside the encode empty-revert).
//
// NON-VACUITY: every well-formed input decodes back to hard-coded expected values (a decode assertion on
// the abi.encode output) AND is compared byte-for-byte vs solc; emits compare log topics + data; reverts
// compare revert returndata. Malformed inputs (huge inner length 2^256-1 / 2^64, truncated, OOB inner /
// outer offset) match solc's empty revert.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const MAX = 2n ** 256n - 1n;
const HUGE64 = 1n << 64n;

const logStr = (logs: { topics: string[]; data: string }[]) =>
  logs.map((l) => `[${l.topics.join(',')}]:${l.data}`).join('|');

async function diff(J: string, S: string, calls: [string, string][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sig, args] of calls) {
    const data = sel(sig) + args;
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    const tag = sig.slice(0, 12) + ' ' + args.slice(0, 16);
    expect(rj.success, tag).toBe(rs.success);
    expect(rj.returnHex, tag).toBe(rs.returnHex);
    expect(logStr(rj.logs), tag + ' logs').toBe(logStr(rs.logs));
  }
}

// ---- well-formed calldata builders (a bare dynamic struct param -> [0x20][ tuple ]) ----
// S{ a; t:T{ xs:u256[]; n } }
const cdVal = (a: number, arr: number[], n: number) => {
  const t = W(0x40) + W(n) + W(arr.length) + arr.map(W).join('');
  return W(0x20) + W(a) + W(0x40) + t;
};
// S{ a; t:T{ ss:string[]/bs:bytes[]; n } } (string[] and bytes[] share this ABI layout)
const cdLeaf = (a: number, elems: string[], n: number) => {
  const k = elems.length;
  const bodies = elems.map((x) => {
    const b = Buffer.from(x, 'utf8');
    const padded = Math.ceil(b.length / 32) * 32;
    return W(b.length) + b.toString('hex').padEnd(padded * 2, '0');
  });
  const heads: string[] = [];
  let acc = k * 32;
  for (let i = 0; i < k; i++) {
    heads.push(W(acc));
    acc += bodies[i]!.length / 2;
  }
  const tail = W(k) + heads.join('') + bodies.join('');
  return W(0x20) + W(a) + W(0x40) + (W(0x40) + W(n) + tail);
};

describe('R3: direct calldata abi.encode of a nested struct with an inner array member (was JETH900)', () => {
  const vJ = '@struct class T { xs: u256[]; n: u256 } @struct class S { a: u256; t: T }';
  const vS = 'struct T { uint256[] xs; uint256 n; } struct S { uint256 a; T t; }';
  const vSig = '((uint256,(uint256[],uint256)))';

  it('non-vacuity: abi.encode output decodes to the exact seeded values', async () => {
    const h = await Harness.create();
    const J = `${vJ} @contract class C { @external @pure f(p: S): bytes { return abi.encode(p); } }`;
    const S = `${vS} contract C { function f(S calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`;
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const args = cdVal(0xaa, [11, 22, 33], 0x99);
    const rj = await h.call(aj, sel(`f${vSig}`) + args);
    const rs = await h.call(as, sel(`f${vSig}`) + args);
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    // decode the returned bytes and assert the values are correct (not a trivially-empty encode).
    const hex = rj.returnHex.slice(2);
    const words: bigint[] = [];
    for (let i = 0; i < hex.length; i += 64) words.push(BigInt('0x' + hex.slice(i, i + 64)));
    // words[0]=0x20 (bytes ptr), words[1]=len, words[2..]=inner abi.encode(S)
    const inner = words.slice(2);
    // inner[0]=0x20 (S ptr), inner[1]=a, inner[2]=off_t(rel to inner[1]); t at inner[1+off_t/32]
    expect(inner[1]).toBe(0xaan); // a
    const tbase = 1 + Number(inner[2]!) / 32;
    expect(inner[tbase + 1]).toBe(0x99n); // n
    const xsbase = tbase + Number(inner[tbase]!) / 32; // off_xs rel to t-tuple start
    expect(inner[xsbase]).toBe(3n); // xs.length
    expect(inner[xsbase + 1]).toBe(11n);
    expect(inner[xsbase + 2]).toBe(22n);
    expect(inner[xsbase + 3]).toBe(33n);
  });

  it('value-array member: abi.encode / keccak / emit / revert all byte-identical (wf + malformed)', async () => {
    const wf = cdVal(0xaa, [11, 22, 33], 0x99);
    const empty = cdVal(1, [], 2);
    const one = cdVal(7, [9], 7);
    const huge256 = W(0x20) + W(0xaa) + W(0x40) + W(0x40) + W(0x99) + W(MAX);
    const huge64 = W(0x20) + W(0xaa) + W(0x40) + W(0x40) + W(0x99) + W(HUGE64);
    const trunc = W(0x20) + W(0xaa) + W(0x40) + W(0x40) + W(0x99) + W(3); // len 3, no elems
    const oobInnerOff = W(0x20) + W(0xaa) + W(0x40) + W(2n ** 200n) + W(0x99);
    const oobOuterOff = W(0x20) + W(0xaa) + W(2n ** 200n) + W(0x99);
    const inputs = [wf, empty, one, huge256, huge64, trunc, oobInnerOff, oobOuterOff];

    await diff(
      `${vJ} @contract class C { @external @pure f(p: S): bytes { return abi.encode(p); } }`,
      `${vS} contract C { function f(S calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`,
      inputs.map((a) => [`f${vSig}`, a]),
    );
    await diff(
      `${vJ} @contract class C { @external @pure f(p: S): bytes32 { return keccak256(abi.encode(p)); } }`,
      `${vS} contract C { function f(S calldata p) external pure returns(bytes32){ return keccak256(abi.encode(p)); } }`,
      inputs.map((a) => [`f${vSig}`, a]),
    );
    await diff(
      `${vJ} @contract class C { @event Ev(p: S); @external g(p: S): void { emit(Ev(p)); } }`,
      `${vS} contract C { event Ev(S p); function g(S calldata p) external { emit Ev(p); } }`,
      inputs.map((a) => [`g${vSig}`, a]),
    );
    await diff(
      `${vJ} @contract class C { @error Er(p: S); @external g(p: S): void { revert(Er(p)); } }`,
      `${vS} contract C { error Er(S p); function g(S calldata p) external { revert Er(p); } }`,
      inputs.map((a) => [`g${vSig}`, a]),
    );
  });

  it('leaf-array member string[] / bytes[]: abi.encode + emit byte-identical (wf + malformed)', async () => {
    const lJ = '@struct class T { ss: string[]; n: u256 } @struct class S { a: u256; t: T }';
    const lS = 'struct T { string[] ss; uint256 n; } struct S { uint256 a; T t; }';
    const lSig = '((uint256,(string[],uint256)))';
    const lInputs = [
      cdLeaf(0xbb, ['hi', 'world'], 0x77),
      cdLeaf(1, [], 2),
      cdLeaf(2, [''], 9),
      cdLeaf(3, ['a', 'bb', 'ccc', 'dddd'], 5),
      W(0x20) + W(0xbb) + W(0x40) + W(0x40) + W(0x77) + W(MAX), // huge outer count -> EMPTY
      W(0x20) + W(0xbb) + W(0x40) + W(2n ** 200n) + W(0x77), // OOB inner offset -> EMPTY
    ];
    await diff(
      `${lJ} @contract class C { @external @pure f(p: S): bytes { return abi.encode(p); } }`,
      `${lS} contract C { function f(S calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`,
      lInputs.map((a) => [`f${lSig}`, a]),
    );
    await diff(
      `${lJ} @contract class C { @event Ev(p: S); @external g(p: S): void { emit(Ev(p)); } }`,
      `${lS} contract C { event Ev(S p); function g(S calldata p) external { emit Ev(p); } }`,
      lInputs.map((a) => [`g${lSig}`, a]),
    );

    const bJ = '@struct class T { bs: bytes[]; n: u256 } @struct class S { a: u256; t: T }';
    const bS = 'struct T { bytes[] bs; uint256 n; } struct S { uint256 a; T t; }';
    const bSig = '((uint256,(bytes[],uint256)))';
    const bInputs = [cdLeaf(5, ['deadbeef', 'cafe'], 7), cdLeaf(5, [], 7), cdLeaf(1, ['00'], 2)];
    await diff(
      `${bJ} @contract class C { @external @pure f(p: S): bytes { return abi.encode(p); } }`,
      `${bS} contract C { function f(S calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`,
      bInputs.map((a) => [`f${bSig}`, a]),
    );
    await diff(
      `${bJ} @contract class C { @error Er(p: S); @external g(p: S): void { revert(Er(p)); } }`,
      `${bS} contract C { error Er(S p); function g(S calldata p) external { revert Er(p); } }`,
      bInputs.map((a) => [`g${bSig}`, a]),
    );
  });

  it('u256[][] leaf-array member: abi.encode + keccak byte-identical', async () => {
    const aJ = '@struct class T { xs: u256[][]; n: u256 } @struct class S { a: u256; t: T }';
    const aS = 'struct T { uint256[][] xs; uint256 n; } struct S { uint256 a; T t; }';
    const aSig = '((uint256,(uint256[][],uint256)))';
    // T{ xs:u256[][]; n }: off_xs=0x40, then [outerlen][off0..offk][ each [len][elems] ]
    const cdAA = (a: number, aa: number[][], n: number) => {
      const k = aa.length;
      const bodies = aa.map((inner) => W(inner.length) + inner.map(W).join(''));
      const heads: string[] = [];
      let acc = k * 32;
      for (let i = 0; i < k; i++) {
        heads.push(W(acc));
        acc += bodies[i]!.length / 2;
      }
      const tail = W(k) + heads.join('') + bodies.join('');
      return W(0x20) + W(a) + W(0x40) + (W(0x40) + W(n) + tail);
    };
    const inputs = [cdAA(2, [[1, 2], [3]], 5), cdAA(2, [], 5), cdAA(2, [[], []], 5)];
    await diff(
      `${aJ} @contract class C { @external @pure f(p: S): bytes { return abi.encode(p); } }`,
      `${aS} contract C { function f(S calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`,
      inputs.map((a) => [`f${aSig}`, a]),
    );
    await diff(
      `${aJ} @contract class C { @external @pure f(p: S): bytes32 { return keccak256(abi.encode(p)); } }`,
      `${aS} contract C { function f(S calldata p) external pure returns(bytes32){ return keccak256(abi.encode(p)); } }`,
      inputs.map((a) => [`f${aSig}`, a]),
    );
  });

  it('multi-level nesting S{a; t:T{u:U{u256[]}; k}}: abi.encode + emit byte-identical', async () => {
    const mJ = '@struct class U { w: u256[] } @struct class T { u: U; k: u256 } @struct class S { a: u256; t: T }';
    const mS = 'struct U { uint256[] w; } struct T { U u; uint256 k; } struct S { uint256 a; T t; }';
    const mSig = '((uint256,((uint256[]),uint256)))';
    // S{a; t}: [a][off_t=0x40]; T{u; k}: [off_u=0x40][k]; U{w}: [off_w=0x20][arr]
    const cdU = (a: number, arr: number[], k: number) => {
      const U = W(0x20) + W(arr.length) + arr.map(W).join('');
      const T = W(0x40) + W(k) + U;
      return W(0x20) + W(a) + W(0x40) + T;
    };
    const inputs = [cdU(9, [1, 2, 3], 8), cdU(9, [], 8), cdU(0, [5], 0)];
    await diff(
      `${mJ} @contract class C { @external @pure f(p: S): bytes { return abi.encode(p); } }`,
      `${mS} contract C { function f(S calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`,
      inputs.map((a) => [`f${mSig}`, a]),
    );
    await diff(
      `${mJ} @contract class C { @event Ev(p: S); @external g(p: S): void { emit(Ev(p)); } }`,
      `${mS} contract C { event Ev(S p); function g(S calldata p) external { emit Ev(p); } }`,
      inputs.map((a) => [`g${mSig}`, a]),
    );
  });

  it('nested-struct field alongside scalar + dynamic siblings S{a; s:string; t:T{u256[];n}}', async () => {
    const sJ = '@struct class T { xs: u256[]; n: u256 } @struct class S { a: u256; s: string; t: T }';
    const sS = 'struct T { uint256[] xs; uint256 n; } struct S { uint256 a; string s; T t; }';
    const sSig = '((uint256,string,(uint256[],uint256)))';
    // S{a; s; t}: 3 head words [a][off_s][off_t]; off_s=0x60, off_t=0x60+sTail
    const cdSib = (a: number, s: string, arr: number[], n: number) => {
      const sb = Buffer.from(s, 'utf8');
      const padded = Math.ceil(sb.length / 32) * 32;
      const sTail = W(sb.length) + sb.toString('hex').padEnd(padded * 2, '0');
      const T = W(0x40) + W(n) + W(arr.length) + arr.map(W).join('');
      const offT = 0x60 + sTail.length / 2;
      return W(0x20) + W(a) + W(0x60) + W(offT) + sTail + T;
    };
    const inputs = [cdSib(1, 'hi', [4, 5, 6], 2), cdSib(1, '', [], 2), cdSib(9, 'padded-string-value', [7, 8], 3)];
    await diff(
      `${sJ} @contract class C { @external @pure f(p: S): bytes { return abi.encode(p); } }`,
      `${sS} contract C { function f(S calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`,
      inputs.map((a) => [`f${sSig}`, a]),
    );
    await diff(
      `${sJ} @contract class C { @error Er(p: S); @external g(p: S): void { revert(Er(p)); } }`,
      `${sS} contract C { error Er(S p); function g(S calldata p) external { revert Er(p); } }`,
      inputs.map((a) => [`g${sSig}`, a]),
    );
  });

  it('context split preserved: encode(p) EMPTY-reverts on huge inner len; BIND(let m=p) Panics 0x41', async () => {
    const huge = W(0x20) + W(0xaa) + W(0x40) + W(0x40) + W(0x99) + W(MAX);
    // RE-ENCODE context -> EMPTY revert (returndata "0x")
    await diff(
      `${vJ} @contract class C { @external @pure f(p: S): bytes { return abi.encode(p); } }`,
      `${vS} contract C { function f(S calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`,
      [[`f${vSig}`, huge]],
    );
    // BIND context -> Panic 0x41 (returndata 0x4e487b71...0041)
    await diff(
      `${vJ} @contract class C { @external @pure f(p: S): bytes { let m: S = p; return abi.encode(m); } }`,
      `${vS} contract C { function f(S calldata p) external pure returns(bytes memory){ S memory m = p; return abi.encode(m); } }`,
      [[`f${vSig}`, huge]],
    );
  });

  it('unregressed: scalar-only and single-leaf nested structs keep the direct calldata fast path', async () => {
    // scalar-only nested struct: no array member -> direct cd path (NOT materialized)
    await diff(
      '@struct class T { x: u256; y: u256 } @struct class S { a: u256; t: T } @contract class C { @external @pure f(p: S): bytes { return abi.encode(p); } }',
      'struct T { uint256 x; uint256 y; } struct S { uint256 a; T t; } contract C { function f(S calldata p) external pure returns(bytes memory){ return abi.encode(p); } }',
      [['f((uint256,(uint256,uint256)))', W(0xaa) + W(1) + W(2)]],
    );
    // single dynamic LEAF (string, not array) nested struct: direct cd path, well-formed round-trips
    const leafnest = (s: string, n: number, a: number) => {
      const sb = Buffer.from(s, 'utf8');
      const padded = Math.ceil(sb.length / 32) * 32;
      const sTail = W(sb.length) + sb.toString('hex').padEnd(padded * 2, '0');
      return W(0x20) + W(a) + W(0x40) + (W(0x40) + W(n) + sTail);
    };
    await diff(
      '@struct class T { s: string; n: u256 } @struct class S { a: u256; t: T } @contract class C { @external @pure f(p: S): bytes { return abi.encode(p); } }',
      'struct T { string s; uint256 n; } struct S { uint256 a; T t; } contract C { function f(S calldata p) external pure returns(bytes memory){ return abi.encode(p); } }',
      [
        ['f((uint256,(string,uint256)))', leafnest('hi', 9, 7)],
        ['f((uint256,(string,uint256)))', leafnest('', 0, 0)],
      ],
    );
  });
});
