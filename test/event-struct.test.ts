// Differential tests for NON-INDEXED static struct / fixed-array event params (Phase 6): the data
// tuple encodes a static aggregate INLINE in the head (no offset/tail). Byte-identical to solc
// (topic0 + log data), incl. mixed value/struct heads, a struct alongside a dynamic param, nested
// and packed structs.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n).slice(2);

async function diffLogs(jeth: string, sol: string, calls: { sig: string; args?: string }[]) {
  const jb = compile(jeth, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jb.creationBytecode);
  const as = await hs.deploy(sb.creation);
  for (const c of calls) {
    const data = '0x' + sel(c.sig) + (c.args ?? '');
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(JSON.stringify(rj.logs), `${c.sig}: logs (topics + data)`).toBe(JSON.stringify(rs.logs));
  }
}

describe('non-indexed struct / fixed-array event params vs Solidity', () => {
  it('a static struct param (inline in the data head)', async () => {
    await diffLogs(
      `@struct class P { a: u256; b: u256; } @contract class C { @event E(p: P); @external f(a: u256, b: u256): void { emit(E(P(a, b))); } }`,
      `struct P { uint256 a; uint256 b; } contract C { event E(P p); function f(uint256 a, uint256 b) external { emit E(P(a,b)); } }`,
      [{ sig: 'f(uint256,uint256)', args: W(11n) + W(22n) }],
    );
  });

  it('a value param before a struct (mixed head offsets) + a packed struct', async () => {
    await diffLogs(
      `@struct class P { a: u8; b: u16; c: bool; } @contract class C { @event E(n: u256, p: P); @external f(n: u256, a: u8, b: u16, c: bool): void { emit(E(n, P(a, b, c))); } }`,
      `struct P { uint8 a; uint16 b; bool c; } contract C { event E(uint256 n, P p); function f(uint256 n, uint8 a, uint16 b, bool c) external { emit E(n, P(a,b,c)); } }`,
      [{ sig: 'f(uint256,uint8,uint16,bool)', args: W(99n) + W(255n) + W(65535n) + W(1n) }],
    );
  });

  it('a struct param alongside a dynamic (bytes) param (struct inline, bytes in tail)', async () => {
    await diffLogs(
      `@struct class P { a: u256; b: u256; } @contract class C { @event E(p: P, data: bytes); @external f(a: u256, b: u256, d: bytes): void { emit(E(P(a, b), d)); } }`,
      `struct P { uint256 a; uint256 b; } contract C { event E(P p, bytes data); function f(uint256 a, uint256 b, bytes calldata d) external { emit E(P(a,b), d); } }`,
      [{ sig: 'f(uint256,uint256,bytes)', args: W(1n) + W(2n) + W(0x60n) + W(3n) + 'aabbcc'.padEnd(64, '0') }],
    );
  });

  it('a non-indexed DYNAMIC struct (bytes/string/array fields) param', async () => {
    await diffLogs(
      `@struct class D { a: u256; s: string; } @contract class C { @event E(n: u256, d: D); @external f(n: u256, a: u256, s: string): void { emit(E(n, D(a, s))); } }`,
      `struct D { uint256 a; string s; } contract C { event E(uint256 n, D d); function f(uint256 n, uint256 a, string calldata s) external { emit E(n, D(a,s)); } }`,
      [{ sig: 'f(uint256,uint256,string)', args: W(99n) + W(42n) + W(0x60n) + W(5n) + '68656c6c6f'.padEnd(64, '0') }],
    );
    await diffLogs(
      `@struct class D { a: u256; bs: bytes; xs: u256[]; } @contract class C { @event E(d: D); @external f(a: u256, bs: bytes, xs: u256[]): void { let m: D = D(a, bs, xs); emit(E(m)); } }`,
      `struct D { uint256 a; bytes bs; uint256[] xs; } contract C { event E(D d); function f(uint256 a, bytes calldata bs, uint256[] calldata xs) external { D memory m = D(a, bs, xs); emit E(m); } }`,
      [{ sig: 'f(uint256,bytes,uint256[])', args: W(1n) + W(0x60n) + W(0xa0n) + W(2n) + 'aabb'.padEnd(64, '0') + W(2n) + W(5n) + W(6n) }],
    );
  });

  it('a static fixed-array param and a nested static struct', async () => {
    await diffLogs(
      `@contract class C { @event E(xs: Arr<u256,3>); @external f(a: u256, b: u256, c: u256): void { emit(E([a, b, c])); } }`,
      `contract C { event E(uint256[3] xs); function f(uint256 a, uint256 b, uint256 c) external { emit E([a,b,c]); } }`,
      [{ sig: 'f(uint256,uint256,uint256)', args: W(7n) + W(8n) + W(9n) }],
    );
    await diffLogs(
      `@struct class I { x: u256; y: u256; } @struct class O { i: I; z: u256; } @contract class C { @event E(o: O); @external f(x: u256, y: u256, z: u256): void { emit(E(O(I(x, y), z))); } }`,
      `struct I { uint256 x; uint256 y; } struct O { I i; uint256 z; } contract C { event E(O o); function f(uint256 x, uint256 y, uint256 z) external { emit E(O(I(x,y), z)); } }`,
      [{ sig: 'f(uint256,uint256,uint256)', args: W(1n) + W(2n) + W(3n) }],
    );
  });
});
