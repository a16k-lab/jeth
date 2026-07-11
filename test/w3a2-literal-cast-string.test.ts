// W3-A2 literal / cast / string over-rejection lifts (byte-identical to solc 0.8.35), plus one
// cast-identity over-acceptance fix. Each valid shape flips to a byte-identical MATCH; adjacent shapes
// solc rejects still reject; the Wave-2 fold guards (octal/4096/enum) still fire.
//  P1-1  string literal -> fixed bytesN (return / local / @state / @constant / internal-arg / comparison
//        / explicit bytesN(str) cast); byte length <= N left-aligned, over-length rejected.
//  P1-17 bare-hex literal (no `n` suffix) -> bytesN in a @constant, incl. digit-separator underscores.
//  P1-16 / P0-26 prefix `-`/`~` over a CONSTANT binary folds with unbounded precision, then the FINAL
//        value is range-checked (`int8 = -(100 + 28)` == -128).
//  P1-14 fractional literal as a `rational_const` sub-term folds exactly (`4 * 0.5` == 2); a non-integer
//        FINAL value stays rejected; a bare fractional literal stays rejected.
//  P1-15 `\$` escape in a backtick template static part decodes to a literal `$` (backtick-context only).
//  OA    an explicit integer cast keeps its cast identity: `g(u256(5n))` for a `g(u8)` param now rejects
//        (u256 does not implicitly convert to u8), while legal casts (widen / exact / bare literal) accept.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

function accepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
function codesOf(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
}

let hj: Harness;
let hs: Harness;
beforeAll(async () => {
  hj = await Harness.create();
  hs = await Harness.create();
});

/** Deploy both, run each call, assert byte-identical returndata + success. */
async function eq(jeth: string, sol: string, calls: [string, string][]) {
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + (args ?? ''));
    const rs = await hs.call(as, sel(sig) + (args ?? ''));
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

describe('W3-A2: P1-1 string literal -> fixed bytesN', () => {
  it('return / local / @state / @constant / internal-arg across widths', async () => {
    await eq(
      'class C { get f(): External<bytes32> { return "abc"; } }',
      'contract C { function f() external pure returns (bytes32) { return "abc"; } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<bytes3> { return "abc"; } }',
      'contract C { function f() external pure returns (bytes3) { return "abc"; } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<bytes4> { return "abc"; } }',
      'contract C { function f() external pure returns (bytes4) { return "abc"; } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<bytes32> { return ""; } }',
      'contract C { function f() external pure returns (bytes32) { return ""; } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<bytes8> { let x: bytes8 = "hello"; return x; } }',
      'contract C { function f() external pure returns (bytes8) { bytes8 x = "hello"; return x; } }',
      [['f()', '']],
    );
    await eq(
      'class C { s: bytes4; constructor(){ this.s = "abcd"; } get f(): External<bytes4> { return this.s; } }',
      'contract C { bytes4 s; constructor(){ s = "abcd"; } function f() external view returns (bytes4) { return s; } }',
      [['f()', '']],
    );
    await eq(
      'class C { static B: bytes4 = "wxyz"; get f(): External<bytes4> { return this.B; } }',
      'contract C { bytes4 constant B = "wxyz"; function f() external pure returns (bytes4) { return B; } }',
      [['f()', '']],
    );
    await eq(
      'class C { g(v: bytes4): bytes4 { return v; } get f(): External<bytes4> { return this.g("ab"); } }',
      'contract C { function g(bytes4 v) internal pure returns (bytes4){ return v; } function f() external pure returns (bytes4) { return g("ab"); } }',
      [['f()', '']],
    );
    // unicode bytes counted raw
    await eq(
      'class C { get f(): External<bytes32> { return "é"; } }',
      'contract C { function f() external pure returns (bytes32) { return unicode"é"; } }',
      [['f()', '']],
    );
  });

  it('explicit bytesN(str) cast (byteLen <= N)', async () => {
    await eq(
      'class C { get f(): External<bytes4> { return bytes4("abc"); } }',
      'contract C { function f() external pure returns (bytes4) { return bytes4("abc"); } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<bytes4> { return bytes4("abcd"); } }',
      'contract C { function f() external pure returns (bytes4) { return bytes4("abcd"); } }',
      [['f()', '']],
    );
  });

  it('bytesN comparison with a string literal (asymmetric right-operand)', async () => {
    // exact width, short width, ordered, and !=
    await eq(
      'class C { get f(x: bytes4): External<bool> { return x == "abcd"; } }',
      'contract C { function f(bytes4 x) external pure returns (bool) { return x == "abcd"; } }',
      [
        ['f(bytes4)', '61626364'.padEnd(64, '0')],
        ['f(bytes4)', '61626300'.padEnd(64, '0')],
      ],
    );
    await eq(
      'class C { get f(x: bytes4): External<bool> { return x < "abcd"; } }',
      'contract C { function f(bytes4 x) external pure returns (bool) { return x < "abcd"; } }',
      [
        ['f(bytes4)', '61626300'.padEnd(64, '0')],
        ['f(bytes4)', '61626365'.padEnd(64, '0')],
      ],
    );
    await eq(
      'class C { get f(x: bytes4): External<bool> { return x == "ab"; } }',
      'contract C { function f(bytes4 x) external pure returns (bool) { return x == "ab"; } }',
      [['f(bytes4)', '61620000'.padEnd(64, '0')]],
    );
  });

  it('rejects an over-length string -> bytesN and the asymmetric left-literal comparison', () => {
    expect(accepts('class C { get f(): External<bytes2> { return "abc"; } }')).toBe(false);
    expect(accepts('class C { get f(): External<bytes1> { return "é"; } }')).toBe(false);
    expect(accepts('class C { get f(): External<bytes2> { return bytes2("abc"); } }')).toBe(false);
    // string literal on the LEFT of a comparison (solc types the literal by the LEFT operand, so a
    // literal LEFT vs a bytesN RIGHT is rejected).
    expect(accepts('class C { get f(x: bytes4): External<bool> { return "abcd" == x; } }')).toBe(false);
    // a string literal with NO expected type is still rejected.
    expect(codesOf('class C { get f(): External<u256> { let y: u256 = "abc"; return y; } }')).toContain('JETH074');
  });
});

describe('W3-A2: P1-17 bare-hex literal -> bytesN in a @constant', () => {
  it('bare hex (no `n`), incl. underscores, matches the suffixed form', async () => {
    await eq(
      'class C { static B: bytes4 = 0x12345678; get f(): External<bytes4> { return this.B; } }',
      'contract C { bytes4 constant B = 0x12345678; function f() external pure returns (bytes4) { return B; } }',
      [['f()', '']],
    );
    await eq(
      'class C { static B: bytes1 = 0xab; get f(): External<bytes1> { return this.B; } }',
      'contract C { bytes1 constant B = 0xab; function f() external pure returns (bytes1) { return B; } }',
      [['f()', '']],
    );
    await eq(
      'class C { static B: bytes4 = 0xdead_beef; get f(): External<bytes4> { return this.B; } }',
      'contract C { bytes4 constant B = 0xdeadbeef; function f() external pure returns (bytes4) { return B; } }',
      [['f()', '']],
    );
    await eq(
      'class C { static B: bytes4 = bytes4(0x12345678); get f(): External<bytes4> { return this.B; } }',
      'contract C { bytes4 constant B = bytes4(0x12345678); function f() external pure returns (bytes4) { return B; } }',
      [['f()', '']],
    );
  });

  it('rejects a wrong-width / odd-digit / decimal bare literal -> bytesN', () => {
    expect(accepts('class C { static B: bytes4 = 0x1234; get f(): External<bytes4> { return this.B; } }')).toBe(
      false,
    );
    expect(accepts('class C { static B: bytes4 = 0x12345; get f(): External<bytes4> { return this.B; } }')).toBe(
      false,
    );
    expect(
      accepts('class C { static B: bytes4 = 305419896; get f(): External<bytes4> { return this.B; } }'),
    ).toBe(false);
  });
});

describe('W3-A2: P1-16 / P0-26 prefix -/~ over a constant binary folds then range-checks the final value', () => {
  it('accepts a whole final value at the type boundary (incl. INT_MIN)', async () => {
    await eq(
      'class C { get f(): External<i8> { const x: i8 = -(100n + 28n); return x; } }',
      'contract C { function f() external pure returns (int8) { int8 x = -(100 + 28); return x; } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<i16> { const x: i16 = -(100n * 300n); return x; } }',
      'contract C { function f() external pure returns (int16) { int16 x = -(100 * 300); return x; } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<i8> { const x: i8 = ~(127n); return x; } }',
      'contract C { function f() external pure returns (int8) { int8 x = ~(127); return x; } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<i8> { const x: i8 = ~(100n + 27n); return x; } }',
      'contract C { function f() external pure returns (int8) { int8 x = ~(100 + 27); return x; } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<i256> { const x: i256 = -(2n ** 100n); return x; } }',
      'contract C { function f() external pure returns (int256) { int256 x = -(2 ** 100); return x; } }',
      [['f()', '']],
    );
  });

  it('rejects an out-of-range final value and the Wave-2 4096-bit guard still fires', () => {
    expect(codesOf('class C { get f(): External<i8> { const x: i8 = -(129n); return x; } }')).toContain('JETH070');
    expect(codesOf('class C { get f(): External<u8> { const x: u8 = ~(0n); return x; } }')).toContain('JETH070');
    expect(codesOf('class C { get f(): External<i8> { const x: i8 = -(-128n); return x; } }')).toContain('JETH070');
    // Wave-2 4096-bit ** limit through the unary path still rejects.
    expect(codesOf('class C { get f(): External<i256> { const x: i256 = -(2n ** 5000n); return x; } }')).toContain(
      'JETH079',
    );
  });
});

describe('W3-A2: P1-14 fractional literal exact-rational fold', () => {
  it('folds a whole final value; keeps a non-integer final value rejected', async () => {
    await eq(
      'class C { get f(): External<u256> { return 4n * 0.5; } }',
      'contract C { function f() external pure returns (uint256) { return 4 * 0.5; } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<u256> { return (1.5 + 0.5); } }',
      'contract C { function f() external pure returns (uint256) { return (1.5 + 0.5); } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<u256> { return 3n / 0.5; } }',
      'contract C { function f() external pure returns (uint256) { return 3 / 0.5; } }',
      [['f()', '']],
    );
    await eq(
      'class C { static K: u256 = 4n * 0.5; get f(): External<u256> { return this.K; } }',
      'contract C { uint256 constant K = 4 * 0.5; function f() external pure returns (uint256) { return K; } }',
      [['f()', '']],
    );
    // whole scientific / decimal literals still accepted (Wave-2 unchanged).
    await eq(
      'class C { get f(): External<u256> { return 1.5e18; } }',
      'contract C { function f() external pure returns (uint256) { return 1.5e18; } }',
      [['f()', '']],
    );
  });

  it('rejects a non-integer final value and a bare fractional literal', () => {
    expect(codesOf('class C { get f(): External<u256> { return 3n * 0.5; } }')).toContain('JETH079');
    expect(codesOf('class C { get f(): External<u256> { return 1n / 3n; } }')).toContain('JETH079');
    // a bare fractional literal (no arithmetic that can make it whole) still rejects JETH003.
    expect(codesOf('class C { get f(): External<u256> { let x: u256 = 0.5; return x; } }')).toContain('JETH003');
    expect(codesOf('class C { get f(): External<u256> { return 1.5; } }')).toContain('JETH003');
  });
});

describe('W3-A2: P1-15 `\\$` escape in a template static part', () => {
  it('decodes to a literal `$` in backtick context; stays rejected in a quoted string', async () => {
    await eq(
      'class C { get f(): External<string> { return `a\\${b}c`; } }',
      'contract C { function f() external pure returns (string memory) { return "a${b}c"; } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<string> { return `\\$100`; } }',
      'contract C { function f() external pure returns (string memory) { return "$100"; } }',
      [['f()', '']],
    );
    await eq(
      'class C { get f(): External<bytes> { return bytes(`\\$a`); } }',
      'contract C { function f() external pure returns (bytes memory) { return bytes("$a"); } }',
      [['f()', '']],
    );
    // `\$` in a DOUBLE-QUOTED string is an invalid escape (solc parser error) - stays rejected.
    expect(codesOf('class C { get f(): External<string> { return "a\\$b"; } }')).toContain('JETH420');
  });
});

describe('W3-A2: OA explicit-cast identity (close g(u256(5n))-for-g(u8) over-acceptance)', () => {
  it('rejects an explicit cast that does not implicitly convert to the param type', () => {
    // u256(5) does NOT implicitly convert to u8 (solc: invalid implicit conversion).
    expect(
      accepts(
        'class C { g(v: u8): u8 { return v; } get f(): External<u8> { return this.g(u256(5n)); } }',
      ),
    ).toBe(false);
    // narrowing in a local / return likewise rejects.
    expect(accepts('class C { get f(): External<u8> { let x: u8 = u256(5n); return x; } }')).toBe(false);
    expect(accepts('class C { get f(): External<u8> { return u256(5n); } }')).toBe(false);
    // arithmetic on a cast result stays uint256-typed and rejects for a u8 param.
    expect(
      accepts(
        'class C { g(v: u8): u8 { return v; } get f(): External<u8> { return this.g(u256(5n) + 1n); } }',
      ),
    ).toBe(false);
  });

  it('still accepts legal casts (bare literal narrows, exact match, implicit widen)', async () => {
    // a bare int literal narrows freely.
    await eq(
      'class C { g(v: u8): u8 { return v; } get f(): External<u8> { return this.g(5n); } }',
      'contract C { function g(uint8 v) internal pure returns (uint8){ return v; } function f() external pure returns (uint8) { return g(5); } }',
      [['f()', '']],
    );
    // an exact-type explicit cast.
    await eq(
      'class C { g(v: u8): u8 { return v; } get f(): External<u8> { return this.g(u8(5n)); } }',
      'contract C { function g(uint8 v) internal pure returns (uint8){ return v; } function f() external pure returns (uint8) { return g(uint8(5)); } }',
      [['f()', '']],
    );
    // an implicit-widening explicit cast (u16 -> u256).
    await eq(
      'class C { g(v: u256): u256 { return v; } get f(): External<u256> { return this.g(u16(5n)); } }',
      'contract C { function g(uint256 v) internal pure returns (uint256){ return v; } function f() external pure returns (uint256) { return g(uint16(5)); } }',
      [['f()', '']],
    );
    // exact target for the cast itself still works.
    await eq(
      'class C { get f(): External<u256> { let x: u256 = u256(5n); return x; } }',
      'contract C { function f() external pure returns (uint256) { uint256 x = uint256(5); return x; } }',
      [['f()', '']],
    );
  });
});

describe('W3-A2: Wave-2 hardening still fires (no regression)', () => {
  it('leading-zero octal / 4096-bit shift / enum-comparison rejects remain', () => {
    // leading-zero (octal-style) decimal literal.
    expect(accepts('class C { get f(): External<u256> { return 010; } }')).toBe(false);
    // 4096-bit << guard.
    expect(codesOf('class C { get f(): External<u256> { const x: u256 = 1n << 4096n; return x; } }')).toContain(
      'JETH079',
    );
    // `**=` compound assignment is NOT valid Solidity (solc parser error) - JETH keeps rejecting it.
    expect(accepts('class C { get f(): External<u256> { let x: u256 = 3n; x **= 4n; return x; } }')).toBe(false);
  });
});
