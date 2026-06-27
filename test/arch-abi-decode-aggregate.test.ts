// Arch over-rejection #3 (core): abi.decode into a STRUCT target (static + dynamic-field) and a TUPLE with
// a struct member, byte-identical to solc 0.8.35's abi.decode-from-memory semantics. The historical blocker
// (JETH's dynamic-struct memory image is pointer-headed, not ABI-offset) was solved by buildDynStructFromMemBlob
// (the constructor aggregate-param decoder, commit 9f704dc); lowerAbiDecode now routes a dynamic-field struct
// component through it, and decodeSupported admits a supported struct. A truncated/bad blob reverts the same
// way solc's memory decode does (the reuse of abiDecFromMem/buildDynStructFromMemBlob is what gives that parity).
// Residual (documented in SUPPORTED.md, clean over-rejections - never miscompiles): a struct ARRAY P[],
// bytes[]/string[], and a nested value array u256[][] as decode targets (each needs new array decode machinery;
// bytes[]/string[] additionally has no memory-local binding representation).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';
import { Address } from '@ethereumjs/util';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const W = (b: bigint) => pad32(b);
const BI = (h: string) => (!h || h === '0x' ? 0n : BigInt(h));
const sel = (s: string) => '0x' + functionSelector(s);
const ret = (r: any) => (r.returnHex.startsWith('0x') ? r.returnHex.slice(2) : r.returnHex);
const wrap = (blob: string) => W(0x20n) + W(BigInt(blob.length / 2)) + blob;

const J = `@struct class P { a: u256; b: u256; } @struct class Q { a: u256; tags: bytes; }
@contract class C {
  @external @pure ds(b: bytes): u256 { let p: P = abi.decode(b, P); return p.a + p.b; }
  @external @pure dq(b: bytes): u256 { let q: Q = abi.decode(b, Q); return q.a + q.tags.length; }
  @external @pure dt(b: bytes): u256 { let [n, p]: [u256, P] = abi.decode(b, [u256, P]); return n + p.a + p.b; } }`;
const S = `struct P { uint a; uint b; } struct Q { uint a; bytes tags; }
contract C {
  function ds(bytes calldata b) external pure returns(uint){ P memory p = abi.decode(b,(P)); return p.a+p.b; }
  function dq(bytes calldata b) external pure returns(uint){ Q memory q = abi.decode(b,(Q)); return q.a+q.tags.length; }
  function dt(bytes calldata b) external pure returns(uint){ (uint n, P memory p) = abi.decode(b,(uint,P)); return n+p.a+p.b; } }`;

describe('abi.decode into a struct / tuple-with-struct target (JETH322 core lifted)', () => {
  it('byte-identical to solc 0.8.35 (struct, dynamic-field struct, tuple, malformed revert parity)', async () => {
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    const bP = W(1n) + W(2n); // P{1,2} static, flat
    const bQ = W(0x20n) + W(5n) + W(0x40n) + W(2n) + ('aabb' + '00'.repeat(30)); // Q{5,0xaabb}
    const bT = W(10n) + W(1n) + W(2n); // [u256 10, P{1,2}]
    const cmp = async (data: string) => {
      const jr = await h.call(ja, data);
      const sr = await h.call(sa, data);
      expect(ret(jr)).toBe(ret(sr));
      expect(jr.success).toBe(sr.success);
      return jr;
    };
    expect(BI('0x' + ret(await cmp(sel('ds(bytes)') + wrap(bP))))).toBe(3n); // static struct
    expect(BI('0x' + ret(await cmp(sel('dq(bytes)') + wrap(bQ))))).toBe(7n); // dynamic-field struct
    expect(BI('0x' + ret(await cmp(sel('dt(bytes)') + wrap(bT))))).toBe(13n); // tuple with struct
    // malformed: blob length says 2 words but only 1 present -> both revert (memory-decode parity)
    const bad = await cmp(sel('ds(bytes)') + W(0x20n) + W(0x40n) + W(1n));
    expect(bad.success).toBe(false);
  });

  it('now ACCEPTS the Residual C array decode targets (P[], bytes[], u256[][]); compiles to bytecode', () => {
    // Residual C lifted P[] (static struct), bytes[]/string[], and u256[][] (nested value arrays) as
    // abi.decode targets (byte-identical decode verified in arch-residual-c-decode-array.test.ts). Here we
    // assert they now COMPILE (no longer JETH322/200). Genuinely-deferred targets stay rejecting below.
    const pre = `@struct class P { a: u256; b: u256; } @contract class C { @external @pure f(b: bytes): u256 {`;
    expect(() => compile(`${pre} let ps: P[] = abi.decode(b, P[]); return ps[0n].a; } }`, { fileName: 'C.jeth' })).not.toThrow();
    expect(() => compile(`${pre} let bs: bytes[] = abi.decode(b, bytes[]); return bs.length; } }`, { fileName: 'C.jeth' })).not.toThrow();
    expect(() => compile(`${pre} let m: u256[][] = abi.decode(b, u256[][]); return m[0n][0n]; } }`, { fileName: 'C.jeth' })).not.toThrow();
  });

  it('still rejects the genuinely-deferred array decode targets (clean over-rejections, not miscompiles)', () => {
    const codes = (src: string): string[] => {
      try {
        compile(src, { fileName: 'C.jeth' });
        return [];
      } catch (e: any) {
        return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
      }
    };
    // a DYNAMIC-field struct array (D has a bytes field): no memory-local representation / decoder yet.
    const preD = `@struct class D { a: u256; tags: bytes; } @contract class C { @external @pure f(b: bytes): u256 {`;
    expect(codes(`${preD} let ds: D[] = abi.decode(b, D[]); return ds.length; } }`).length).toBeGreaterThan(0);
    // nested-aggregate arrays (array of static-struct arrays / array of bytes arrays).
    const preP = `@struct class P { a: u256; b: u256; } @contract class C { @external @pure f(b: bytes): u256 {`;
    expect(codes(`${preP} let m: P[][] = abi.decode(b, P[][]); return m.length; } }`).length).toBeGreaterThan(0);
    const preC = `@contract class C { @external @pure f(b: bytes): u256 {`;
    expect(codes(`${preC} let m: bytes[][] = abi.decode(b, bytes[][]); return m.length; } }`).length).toBeGreaterThan(0);
  });
});
