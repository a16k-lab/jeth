// SOUNDNESS regression: emitting a memory Arr<P,N> (a fixed array whose element is a STATIC struct) as
// an event parameter. After the Cat-B / Batch-A pointer-headed static-struct memory redesign (commit
// 5431c5b), such a value's memory image is N absolute-pointer words, but lowerEmit still copied/hashed it
// as a flat ABI image - so the non-indexed log DATA leaked the pointer words (0x80/0xc0/...) instead of the
// element values, and the indexed TOPIC was keccak over the pointer header instead of the inline encoding.
// Both are silent wrong-bytes MISCOMPILES (the call succeeds). Fixed by transcoding the pointer-headed image
// to its flat inline ABI body via abiEncFromMem (the same path abi.encode uses) before mcopy/keccak.
// This test compares the EMITTED LOG (topics + data) byte-for-byte vs solc 0.8.35 - the ordinary returnHex
// harness would miss it because emit produces no return value.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);

async function logDiff(J: string, S: string, sig: string, args = '') {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  const data = sel(sig) + args;
  const rj = await h.call(aj, data);
  const rs = await h.call(as, data);
  const fmt = (r: any) =>
    r.success + ' ' + r.logs.map((l: any) => 'T[' + l.topics.join(',') + '] D=' + l.data).join(' | ');
  return { jeth: fmt(rj), solc: fmt(rs) };
}

describe('emit of a pointer-headed memory Arr<P,N> (static-struct fixed array) - byte-identical to solc 0.8.35', () => {
  it('non-indexed Arr<P,2> log data is the inline element words, not the pointer table', async () => {
    const r = await logDiff(
      `@struct class P { x: u256; y: u256; } @contract class C { @event E(a: Arr<P,2>); @external f(): void { let a: Arr<P,2> = [P(1n,2n), P(3n,4n)]; emit(E(a)); } }`,
      `contract C { struct P { uint256 x; uint256 y; } event E(P[2] a); function f() external { P[2] memory a=[P(1,2),P(3,4)]; emit E(a); } }`,
      'f()',
    );
    expect(r.jeth).toBe(r.solc);
  });

  it('indexed Arr<P,2> topic is keccak over the inline encoding, not the pointer header', async () => {
    const r = await logDiff(
      `@struct class P { x: u256; y: u256; } @contract class C { @event E(@indexed a: Arr<P,2>); @external f(): void { let a: Arr<P,2>=[P(1n,2n),P(3n,4n)]; emit(E(a)); } }`,
      `contract C { struct P { uint256 x; uint256 y; } event E(P[2] indexed a); function f() external { P[2] memory a=[P(1,2),P(3,4)]; emit E(a); } }`,
      'f()',
    );
    expect(r.jeth).toBe(r.solc);
  });

  it('packed (u8) fields, N=3, plus a trailing scalar - indexed and non-indexed', async () => {
    const nonIdx = await logDiff(
      `@struct class P { x: u256; y: u8; } @contract class C { @event E(a: Arr<P,3>, n: u256); @external f(): void { let a: Arr<P,3> = [P(1n,2n),P(3n,4n),P(5n,6n)]; emit(E(a, 9n)); } }`,
      `contract C { struct P { uint256 x; uint8 y; } event E(P[3] a, uint256 n); function f() external { P[3] memory a=[P(1,2),P(3,4),P(5,6)]; emit E(a,9); } }`,
      'f()',
    );
    expect(nonIdx.jeth).toBe(nonIdx.solc);
    const idx = await logDiff(
      `@struct class P { x: u256; y: u8; } @contract class C { @event E(@indexed a: Arr<P,3>); @external f(): void { let a: Arr<P,3> = [P(1n,2n),P(3n,4n),P(5n,6n)]; emit(E(a)); } }`,
      `contract C { struct P { uint256 x; uint8 y; } event E(P[3] indexed a); function f() external { P[3] memory a=[P(1,2),P(3,4),P(5,6)]; emit E(a); } }`,
      'f()',
    );
    expect(idx.jeth).toBe(idx.solc);
  });

  it('nested Arr<Arr<P,2>,2> (pointer-headed element is itself pointer-headed)', async () => {
    const r = await logDiff(
      `@struct class P { x: u256; y: u256; } @contract class C { @event E(a: Arr<Arr<P,2>,2>); @external f(): void { let a: Arr<Arr<P,2>,2> = [[P(1n,2n),P(3n,4n)],[P(5n,6n),P(7n,8n)]]; emit(E(a)); } }`,
      `contract C { struct P { uint256 x; uint256 y; } event E(P[2][2] a); function f() external { P[2][2] memory a=[[P(1,2),P(3,4)],[P(5,6),P(7,8)]]; emit E(a); } }`,
      'f()',
    );
    expect(r.jeth).toBe(r.solc);
  });

  it('control: a standalone static struct WITH an Arr<P,N> field stays flat (not transcoded) - indexed + non-indexed', async () => {
    const nonIdx = await logDiff(
      `@struct class P { x: u256; y: u256; } @struct class S { a: u256; ps: Arr<P,2>; } @contract class C { @event E(s: S); @external f(): void { let s: S = S(9n, [P(1n,2n),P(3n,4n)]); emit(E(s)); } }`,
      `contract C { struct P { uint256 x; uint256 y; } struct S { uint256 a; P[2] ps; } event E(S s); function f() external { S memory s=S(9,[P(1,2),P(3,4)]); emit E(s); } }`,
      'f()',
    );
    expect(nonIdx.jeth).toBe(nonIdx.solc);
    const idx = await logDiff(
      `@struct class P { x: u256; y: u256; } @struct class S { a: u256; ps: Arr<P,2>; } @contract class C { @event E(@indexed s: S); @external f(): void { let s: S = S(9n, [P(1n,2n),P(3n,4n)]); emit(E(s)); } }`,
      `contract C { struct P { uint256 x; uint256 y; } struct S { uint256 a; P[2] ps; } event E(S indexed s); function f() external { S memory s=S(9,[P(1,2),P(3,4)]); emit E(s); } }`,
      'f()',
    );
    expect(idx.jeth).toBe(idx.solc);
  });

  it('control: a value fixed array Arr<u256,3> stays inline (unaffected)', async () => {
    const r = await logDiff(
      `@contract class C { @event E(a: Arr<u256,3>); @external f(): void { let a: Arr<u256,3> = [7n,8n,9n]; emit(E(a)); } }`,
      `contract C { event E(uint256[3] a); function f() external { uint256[3] memory a=[uint256(7),8,9]; emit E(a); } }`,
      'f()',
    );
    expect(r.jeth).toBe(r.solc);
  });
});

// OR9 (FIX-ALL sweep): an indexed DYNAMIC array whose element is STATIC (a value u256[], or a static-struct
// P[] / static-fixed-array Arr<P,N>[]) now compiles - its topic is keccak over the inline element words,
// the same path as a value array. A DYNAMIC-element array (bytes[]/string[]/u256[][]/dyn-field P[]) has a
// different solc topic preimage and stays a clean reject (verified NOT a miscompile).
describe('OR9: indexed static-element dynamic array event topic - byte-identical to solc 0.8.35', () => {
  const codes = (src: string): string[] => {
    try {
      compile(src, { fileName: 'C.jeth' });
      return [];
    } catch (e: any) {
      return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
    }
  };
  it('indexed P[] (packed + all-u256) and Arr<P,2>[] topics match solc', async () => {
    const a = await logDiff(
      `@struct class P { x: u256; y: u8; } @contract class C { @event E(@indexed ps: P[], n: u256); @external f(): void { let ps: P[] = [P(1n,2n), P(3n,4n)]; emit(E(ps, 9n)); } }`,
      `contract C { struct P { uint256 x; uint8 y; } event E(P[] indexed ps, uint256 n); function f() external { P[] memory ps = new P[](2); ps[0]=P(1,2); ps[1]=P(3,4); emit E(ps, 9); } }`,
      'f()',
    );
    expect(a.jeth).toBe(a.solc);
    const b = await logDiff(
      `@struct class P { x: u256; y: u256; } @contract class C { @event E(@indexed ps: Arr<P,2>[]); @external f(): void { let ps: Arr<P,2>[] = [[P(1n,2n),P(3n,4n)],[P(5n,6n),P(7n,8n)]]; emit(E(ps)); } }`,
      `contract C { struct P { uint256 x; uint256 y; } event E(P[2][] indexed ps); function f() external { P[2][] memory ps = new P[2][](2); ps[0]=[P(1,2),P(3,4)]; ps[1]=[P(5,6),P(7,8)]; emit E(ps); } }`,
      'f()',
    );
    expect(b.jeth).toBe(b.solc);
  });
  it('indexed dynamic-element arrays (bytes[]/string[]/u256[][]/dyn-field P[]) stay a clean reject (NOT a miscompile)', () => {
    expect(codes(`@contract class C { @event E(@indexed a: bytes[]); @external f(): void { let a: bytes[]=[bytes("x")]; emit(E(a)); } }`)).toContain('JETH207');
    expect(codes(`@contract class C { @event E(@indexed a: u256[][]); @external f(): void { let a: u256[][]=[[1n]]; emit(E(a)); } }`)).toContain('JETH207');
    expect(codes(`@struct class P{a:u256;s:bytes;} @contract class C { @event E(@indexed ps: P[]); @external f(): void { let ps: P[]=[P(1n,bytes("x"))]; emit(E(ps)); } }`)).toContain('JETH207');
  });
});
