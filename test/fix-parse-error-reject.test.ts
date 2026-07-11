// BYTE-SLICE-MC (pre-existing silent MISCOMPILE, found by the byte-access hunt): the non-JETH
// calldata colon-slice `x[s:e][j]` is not valid TypeScript. TS's parser error-recovers it into a
// truncated `x[s]` (dropping `:e][j]`), which JETH then silently compiled to the byte at the slice
// START for every j, with no bounds check (no OOB Panic). The byte-identical form is `.slice(s,e)[j]`.
//
// Root fix (general): JETH is a strict TS subset, so a TS SYNTACTIC parse error means malformed
// source. The analyzer now rejects a source that it would otherwise SILENTLY ACCEPT despite a
// (non-1011) parse diagnostic. Two deliberate error-recovery patterns are preserved: `abi.decode(b,
// T[])` (a bare array type in value position, TS code 1011, a valid feature) still compiles, and
// shapes the analyzer rejects semantically (e.g. `constructor() A(2n)` -> JETH379) keep their
// specific code (the check only fires when the analyzer produced no error of its own).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const rejects = (src: string): boolean => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
};
const codeOf = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return ['OK'];
  } catch (e: unknown) {
    const ds = (e as { diagnostics?: { code: string }[]; items?: { code: string }[] });
    return (ds.diagnostics ?? ds.items ?? []).map((d) => d.code);
  }
};

describe('parse-error rejection (BYTE-SLICE-MC + malformed-source robustness)', () => {
  it('the colon-slice byte-index x[s:e][j] rejects instead of silently compiling a truncated x[s]', () => {
    expect(rejects(`class C { get f(x: bytes, j: u256): External<bytes1> { return x[2n:5n][j]; } }`)).toBe(true);
    // the slice alone rejects too (colon-slice is not JETH syntax; use .slice()).
    expect(rejects(`class C { get f(x: bytes): External<bytes> { return x[2n:5n]; } }`)).toBe(true);
    // the byte-identical form (.slice) compiles.
    expect(rejects(`class C { get f(x: bytes, s: u256, e: u256): External<bytes> { return x.slice(s, e); } }`)).toBe(false);
    expect(
      rejects(`class C { get f(x: bytes, j: u256): External<bytes1> { let sl: bytes = x.slice(2n, 5n); return sl[j]; } }`),
    ).toBe(false);
  });

  it('other malformed sources reject instead of compiling an error-recovered AST', () => {
    expect(rejects(`class C { get f(): External<u256> { return 1n + ; } }`)).toBe(true);
    expect(rejects(`class C { get f(): External<u256> { let x = ; return 1n; } }`)).toBe(true);
  });

  it('deliberate TS error-recovery patterns are preserved', () => {
    // abi.decode(b, T[]) uses a bare array TYPE in value position (TS code 1011) - a valid feature.
    expect(
      rejects(`type D = { a: u256; tags: bytes }; class C { get f(b: bytes): External<u256> { let ds: D[] = abi.decode(b, D[]); return ds.length; } }`),
    ).toBe(false);
    expect(
      rejects(`class C { get f(b: bytes): External<u256> { let m: u256[][] = abi.decode(b, u256[][]); return m.length; } }`),
    ).toBe(false);
    // a shape the analyzer rejects semantically keeps its specific code (not the generic syntax code).
    expect(
      codeOf('abstract class A { a: u256; constructor(v: u256){ this.a = v; } } class C extends A(1n) { constructor() A(2n) { } }'),
    ).toContain('JETH379');
    // a valid ternary index (colon inside brackets, but with a `?`) still compiles.
    expect(
      rejects(`class C { get f(a: u256[], c: bool): External<u256> { return a[c ? 0n : 1n]; } }`),
    ).toBe(false);
  });
});
