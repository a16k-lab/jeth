// Soundness gate JETH088: `==` / `!=` (and ordered comparisons) are valid ONLY on value types.
// solc 0.8.35 rejects equality/comparison on structs, arrays (fixed/dynamic), bytes/string and mappings
// ("Built-in binary operator == cannot be applied to types struct ... memory and struct ... memory"), so
// JETH must too. Previously JETH ACCEPTED an aggregate comparison and emitted runtime bytecode for it -
// an over-acceptance that can never be byte-identical to solc (which compiles no program at all). This
// test pins the gate: structs / arrays / mappings reject JETH088; every value type still compares fine.
// EXCEPTION: `==` / `!=` on bytes/string is a JETH FEATURE (a keccak-idiom desugar, byte-identical to
// solc; see string-bytes-equality.test.ts); only ORDERED comparisons on bytes/string still reject here.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
const fn = (body: string, extra = '') => `${extra}class C { get f(): External<bool> { ${body} } }`;

describe('aggregate comparison gate (JETH088, solc parity)', () => {
  it('rejects == / != on a struct (solc rejects struct equality)', () => {
    const P = 'type P = { a: u256; b: u256; }; ';
    expect(codes(fn('let p: P = P(1n,2n); let q: P = P(1n,2n); return p == q;', P))).toContain('JETH088');
    expect(codes(fn('let p: P = P(1n,2n); let q: P = P(1n,2n); return p != q;', P))).toContain('JETH088');
  });

  it('rejects == on a dynamic array and a fixed array (solc rejects array equality)', () => {
    expect(codes(fn('let a: u256[] = [1n,2n]; let b: u256[] = [1n,2n]; return a == b;'))).toContain('JETH088');
    expect(codes(fn('let a: Arr<u256,2> = [u256(1n),2n]; let b: Arr<u256,2> = [u256(1n),2n]; return a == b;'))).toContain(
      'JETH088',
    );
    // NOTE: `==` / `!=` on `bytes` / `string` is now a FEATURE - it desugars to
    // `keccak256(bytes(a)) == keccak256(bytes(b))`, byte-identical to solc's idiom (see
    // string-bytes-equality.test.ts). Only ORDERED comparisons (< > <= >=) on bytes/string still reject.
    expect(codes(fn('let a: string = "x"; let b: string = "y"; return a == b;'))).toEqual([]); // lifted
    expect(codes(fn('let a: bytes = bytes(""); let b: bytes = bytes(""); return a != b;'))).toEqual([]); // lifted
    expect(codes(fn('let a: string = "x"; let b: string = "y"; return a < b;'))).toContain('JETH088'); // ordered: still rejects
  });

  it('still accepts == / != / ordered comparisons on every value type', () => {
    expect(codes(fn('let a: u256 = 1n; return a == 1n;'))).toEqual([]);
    expect(codes(fn('let a: u8 = 1n; let b: u256 = 1n; return a == b;'))).toEqual([]); // widened
    expect(codes(fn('let a: address = address(0n); return a == address(0n);'))).toEqual([]);
    expect(codes(fn('let a: bytes32 = bytes32(0n); return a != bytes32(0n);'))).toEqual([]);
    expect(codes(fn('let a: bool = true; return a == true;'))).toEqual([]);
    expect(codes(fn('let a: u256 = 1n; return a < 2n;'))).toEqual([]); // ordered
    expect(codes(fn('let c: Color = Color.Red; return c == Color.Red;', 'enum Color { Red, Blue } '))).toEqual([]);
  });
});
