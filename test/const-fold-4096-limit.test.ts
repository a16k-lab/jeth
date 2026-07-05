// Constant-fold 4096-bit int_const limit + constant-ref division-by-zero (solc parity).
//
// solc evaluates a fully-constant integer expression as a RationalNumberType limited to 4096 bits.
//   - `base ** exp` is a compile-time error when |base|>=2 and bitLength(|base|)*exp > 4096
//     (base 0/1/-1 fold to 0/1/±1, no limit). Boundary: 2**2048 accepts, 2**2049 rejects.
//   - `value << shift` is a compile-time error when value!=0 and bitLength(|value|)+shift > 4096.
//     Boundary: 1<<4095 accepts, 1<<4096 rejects. Right shift only shrinks, so it has no limit.
//   - `a / b` (or `%`) is "Division by zero" when the WHOLE expression is a pure int_const and the
//     divisor folds to 0. An integer @constant reference (bare name or this.NAME) folds as an int_const
//     (recursively through computed initializers), so `1 / this.Z` with `@constant Z = 0` rejects; but
//     `a / Z` (runtime dividend) and `u256(1) / Z` (typed dividend) stay accepted (runtime Panic 0x12).
//
// Before the fix, a huge power/shift (e.g. 2**(2**100)) threw a raw "Maximum BigInt size exceeded"
// with ZERO diagnostics; 2**2049 / 1<<4096 were silently over-accepted; and `1n / this.Z` (Z=0) was
// over-accepted (Panicked at runtime instead of a clean solc-matching compile reject).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';

function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e; // a raw throw (e.g. RangeError) is a bug: it must surface as a diagnostic, not a crash.
  }
}
const fn = (body: string, consts = '') =>
  `@contract class C {\n  ${consts}  @external f(a: u256): u256 { ${body} }\n}\n`;
const accepts = (body: string, consts = '') => expect(codes(fn(body, consts))).toEqual([]);
const rejects = (body: string, consts = '') => expect(codes(fn(body, consts)).length).toBeGreaterThan(0);

describe('constant ** / << 4096-bit fold limit (P0-36 crash, P0-37 boundary)', () => {
  it('does not raw-crash on an astronomically large power/shift (P0-36)', () => {
    // Must be a clean single JETH079, never a raw "Maximum BigInt size exceeded".
    expect(codes(fn('return (2n ** (2n ** 100n)) / 1n;'))).toEqual(['JETH079']);
    expect(codes(fn('return (1n << (2n ** 100n)) >> 1n;'))).toEqual(['JETH079']);
    rejects('return 2n ** 100000n;'); // representable but over the limit: clean reject, not a crash
  });

  it('** boundary is exact at bitLength(|base|)*exp == 4096 (P0-37)', () => {
    accepts('return (2n ** 2048n) / (2n ** 2048n);'); // 2*2048 = 4096
    rejects('return (2n ** 2049n) / (2n ** 2049n);'); // 2*2049 = 4098
    accepts('return (3n ** 2048n) / (3n ** 2048n);'); // bitLen(3)=2
    rejects('return (3n ** 2049n) / (3n ** 2049n);');
    accepts('return (4n ** 1365n) / (4n ** 1365n);'); // bitLen(4)=3, 3*1365=4095
    rejects('return (4n ** 1366n) / (4n ** 1366n);'); // 3*1366=4098
    accepts('return (256n ** 455n) / (256n ** 455n);'); // bitLen(256)=9, 9*455=4095
    rejects('return (256n ** 456n) / (256n ** 456n);'); // 9*456=4104
  });

  it('** base 0/1 have no limit (result is 0/1)', () => {
    accepts('return 0n ** 5000n;');
    accepts('return 1n ** 5000n;');
    accepts('return 1n ** (2n ** 100n);');
    accepts('return 0n ** (2n ** 100n);');
  });

  it('<< boundary is exact at bitLength(|value|)+shift == 4096 (P0-37)', () => {
    accepts('return (1n << 4095n) >> 4095n;'); // 1+4095 = 4096
    rejects('return (1n << 4096n) >> 4096n;'); // 1+4096 = 4097
    accepts('return (3n << 4094n) >> 4094n;'); // bitLen(3)=2, 2+4094=4096
    rejects('return (3n << 4095n) >> 4095n;'); // 2+4095=4097
    accepts('return (255n << 4088n) >> 4088n;'); // bitLen(255)=8, 8+4088=4096
    rejects('return (255n << 4089n) >> 4089n;');
  });

  it('value 0 << N and any >> N have no limit', () => {
    accepts('return 0n << 100000n;');
    accepts('return 0n << 4097n;');
    accepts('return 1n >> 100000n;');
    accepts('return (2n ** 2000n) >> 5000n;');
  });

  it('ordinary in-range fold and runtime arithmetic are unchanged', () => {
    accepts('return (10n / 4n) * 4n;'); // exact-rational: == 10
    accepts('return 2n ** 200n;');
    accepts('return 1n << 200n;');
    accepts('return a + 1n;'); // runtime
    accepts('return a << 3n;'); // runtime shift
    accepts('return a ** 2n;'); // runtime exponent
  });
});

describe('constant division/modulo by a zero @constant reference (P0-25)', () => {
  const Z0 = '@constant Z: u256 = 0n;\n';

  it('rejects a pure int_const divide/modulo by a zero @constant', () => {
    expect(codes(fn('return 1n / this.Z;', Z0))).toEqual(['JETH079']);
    expect(codes(fn('return 1n % this.Z;', Z0))).toEqual(['JETH079']);
    // still rejects when guarded behind a ternary (solc folds the constant subexpression regardless)
    expect(codes(fn('return a > 0n ? a : 1n / this.Z;', Z0))).toEqual(['JETH079']);
  });

  it('rejects when the zero divisor is a computed @constant (2n - 2n) or a folded ref expr', () => {
    rejects('return 1n / this.Z;', '@constant Z: u256 = 2n - 2n;\n');
    rejects('return 1n / this.Z;', '@constant Z: u256 = 10n - 10n;\n');
    rejects('return 1n / (this.Z - this.Z);', '@constant Z: u256 = 5n;\n');
  });

  it('KEEPS a runtime/typed dividend accepted (a Panic 0x12 at runtime, matching solc)', () => {
    accepts('return a / this.Z;', Z0); // runtime dividend
    accepts('return u256(1) / this.Z;', Z0); // typed-cast dividend -> runtime, not folded
    accepts('return a / this.Z;', '@constant Z: u256 = 5n;\n'); // nonzero divisor
    accepts('return a / a;'); // both runtime
  });

  it('KEEPS a nonzero pure-constant division accepted (exact fold)', () => {
    accepts('return 1n / this.Z;', '@constant Z: u256 = 1n;\n');
    accepts('return 6n / this.Z;', '@constant Z: u256 = 2n;\n');
  });
});
