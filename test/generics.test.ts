// F6: compile-time generics (monomorphization). A generic internal function `f<T>(...)` is
// specialized per concrete type instantiation: each distinct type tuple synthesizes a mangled
// non-generic copy that flows through the EXISTING internal-function pipeline. Generics are a
// purely COMPILE-TIME feature (no runtime polymorphism, never in the ABI), so the observable
// behavior must be BYTE-IDENTICAL to solc with the equivalent hand-written non-generic helpers.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (v & ((1n << 256n) - 1n)).toString(16).padStart(64, '0');
const A1 = 0xa11ce0000000000000000000000000000000n;
const A2 = 0xb0b0000000000000000000000000000000000n;

// ---------------------------------------------------------------------------
// A contract using ONE generic max/min/clamp instantiated at MANY types, plus a
// state-mutating path, recursion, and a generic-calling-generic. The Solidity
// twin hand-writes the equivalent non-generic helpers (the generic is erased).
// ---------------------------------------------------------------------------
const JETH = `@contract class C {
  @state acc: u256;
  @state lastAddr: address;

  // a generic max/min/clamp over an ordered value type
  @hidden maxg<T>(a: T, b: T): T { return a > b ? a : b; }
  @hidden ming<T>(a: T, b: T): T { return a < b ? a : b; }
  @hidden clampg<T>(v: T, lo: T, hi: T): T { return this.maxg<T>(lo, this.ming<T>(v, hi)); }
  // a generic equality over any value type (incl. address)
  @hidden eqg<T>(a: T, b: T): bool { return a == b; }
  // a recursive generic with an accumulator: base ** exp (unchecked-free; small inputs)
  @hidden powg<T>(base: T, exp: u256, acc: T): T { return exp == 0n ? acc : this.powg<T>(base, exp - 1n, acc * base); }

  // u256 wrappers (inference)
  @external maxU(a: u256, b: u256): u256 { return this.maxg(a, b); }
  @external minU(a: u256, b: u256): u256 { return this.ming(a, b); }
  // u8 wrappers (explicit type args)
  @external maxU8(a: u8, b: u8): u8 { return this.maxg<u8>(a, b); }
  // i128 signed wrappers (inference) - signed comparison must match solc
  @external maxI(a: i128, b: i128): i128 { return this.maxg(a, b); }
  @external minI(a: i128, b: i128): i128 { return this.ming(a, b); }
  // clamp at two distinct types coexisting (u256 + i128)
  @external clampU(v: u256, lo: u256, hi: u256): u256 { return this.clampg<u256>(v, lo, hi); }
  @external clampI(v: i128, lo: i128, hi: i128): i128 { return this.clampg(v, lo, hi); }
  // address equality (a value type that is not ordered)
  @external addrEq(a: address, b: address): bool { return this.eqg(a, b); }
  // recursion: pow at u256 and u64 (two specializations of the same recursive generic)
  @external powU(b: u256, e: u256): u256 { return this.powg<u256>(b, e, 1n); }
  @external powU64(b: u64, e: u256): u64 { return this.powg<u64>(b, e, 1n); }

  // a state-mutating path computed through a generic (raw-slot comparison)
  @external setClamped(v: u256, lo: u256, hi: u256): void { this.acc = this.clampg<u256>(v, lo, hi); }
  @external setMaxAddr(a: address, b: address): void { this.lastAddr = this.maxgAddrSelect(a, b); }
  // address has no '>' in solc; select via eq to keep the twin honest
  @hidden maxgAddrSelect(a: address, b: address): address { return this.eqg<address>(a, b) ? a : b; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256 acc;
  address lastAddr;

  function _maxU(uint256 a, uint256 b) internal pure returns (uint256) { return a > b ? a : b; }
  function _minU(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; }
  function _clampU(uint256 v, uint256 lo, uint256 hi) internal pure returns (uint256) { return _maxU(lo, _minU(v, hi)); }
  function _maxU8(uint8 a, uint8 b) internal pure returns (uint8) { return a > b ? a : b; }
  function _maxI(int128 a, int128 b) internal pure returns (int128) { return a > b ? a : b; }
  function _minI(int128 a, int128 b) internal pure returns (int128) { return a < b ? a : b; }
  function _maxIc(int128 a, int128 b) internal pure returns (int128) { return a > b ? a : b; }
  function _minIc(int128 a, int128 b) internal pure returns (int128) { return a < b ? a : b; }
  function _clampI(int128 v, int128 lo, int128 hi) internal pure returns (int128) { return _maxIc(lo, _minIc(v, hi)); }
  function _eqA(address a, address b) internal pure returns (bool) { return a == b; }
  function _powU(uint256 base, uint256 exp, uint256 acc_) internal pure returns (uint256) { return exp == 0 ? acc_ : _powU(base, exp - 1, acc_ * base); }
  function _powU64(uint64 base, uint256 exp, uint64 acc_) internal pure returns (uint64) { return exp == 0 ? acc_ : _powU64(base, exp - 1, acc_ * base); }

  function maxU(uint256 a, uint256 b) external pure returns (uint256) { return _maxU(a, b); }
  function minU(uint256 a, uint256 b) external pure returns (uint256) { return _minU(a, b); }
  function maxU8(uint8 a, uint8 b) external pure returns (uint8) { return _maxU8(a, b); }
  function maxI(int128 a, int128 b) external pure returns (int128) { return _maxI(a, b); }
  function minI(int128 a, int128 b) external pure returns (int128) { return _minI(a, b); }
  function clampU(uint256 v, uint256 lo, uint256 hi) external pure returns (uint256) { return _clampU(v, lo, hi); }
  function clampI(int128 v, int128 lo, int128 hi) external pure returns (int128) { return _clampI(v, lo, hi); }
  function addrEq(address a, address b) external pure returns (bool) { return _eqA(a, b); }
  function powU(uint256 b, uint256 e) external pure returns (uint256) { return _powU(b, e, 1); }
  function powU64(uint64 b, uint256 e) external pure returns (uint64) { return _powU64(b, e, 1); }
  function setClamped(uint256 v, uint256 lo, uint256 hi) external { acc = _clampU(v, lo, hi); }
  function setMaxAddr(address a, address b) external { lastAddr = _eqA(a, b) ? a : b; }
}`;

describe('generics: monomorphization is byte-identical to solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('max/min at u256 (inferred) match solc', async () => {
    await eq('maxU(3,9)', encodeCall(sel('maxU(uint256,uint256)'), [3n, 9n]));
    await eq('maxU(9,3)', encodeCall(sel('maxU(uint256,uint256)'), [9n, 3n]));
    await eq('maxU(7,7)', encodeCall(sel('maxU(uint256,uint256)'), [7n, 7n]));
    await eq('minU(3,9)', encodeCall(sel('minU(uint256,uint256)'), [3n, 9n]));
    await eq('minU max-vals', encodeCall(sel('minU(uint256,uint256)'), [(1n << 256n) - 1n, 0n]));
  });

  it('max at u8 (explicit type arg) matches solc, incl. narrow-width masking', async () => {
    await eq('maxU8(200,17)', encodeCall(sel('maxU8(uint8,uint8)'), [200n, 17n]));
    await eq('maxU8(0,255)', encodeCall(sel('maxU8(uint8,uint8)'), [0n, 255n]));
  });

  it('signed max/min at i128 (signed comparison) match solc', async () => {
    const neg = (v: bigint) => v & ((1n << 256n) - 1n); // two's-complement word
    await eq('maxI(-5, 3)', encodeCall(sel('maxI(int128,int128)'), [neg(-5n), 3n]));
    await eq('maxI(-5,-9)', encodeCall(sel('maxI(int128,int128)'), [neg(-5n), neg(-9n)]));
    await eq('minI(-5, 3)', encodeCall(sel('minI(int128,int128)'), [neg(-5n), 3n]));
    const I128MIN = -(1n << 127n), I128MAX = (1n << 127n) - 1n;
    await eq('maxI(min,max)', encodeCall(sel('maxI(int128,int128)'), [neg(I128MIN), neg(I128MAX)]));
  });

  it('clamp at u256 and i128 (same generic, two specializations) match solc', async () => {
    await eq('clampU below', encodeCall(sel('clampU(uint256,uint256,uint256)'), [5n, 10n, 100n]));
    await eq('clampU inside', encodeCall(sel('clampU(uint256,uint256,uint256)'), [50n, 10n, 100n]));
    await eq('clampU above', encodeCall(sel('clampU(uint256,uint256,uint256)'), [500n, 10n, 100n]));
    const neg = (v: bigint) => v & ((1n << 256n) - 1n);
    await eq('clampI below', encodeCall(sel('clampI(int128,int128,int128)'), [neg(-50n), neg(-10n), 10n]));
    await eq('clampI inside', encodeCall(sel('clampI(int128,int128,int128)'), [0n, neg(-10n), 10n]));
    await eq('clampI above', encodeCall(sel('clampI(int128,int128,int128)'), [99n, neg(-10n), 10n]));
  });

  it('generic equality over address matches solc', async () => {
    await eq('addrEq same', encodeCall(sel('addrEq(address,address)'), [A1, A1]));
    await eq('addrEq diff', encodeCall(sel('addrEq(address,address)'), [A1, A2]));
  });

  it('recursive generic (pow accumulator) at u256 and u64 match solc', async () => {
    await eq('powU(2,10)', encodeCall(sel('powU(uint256,uint256)'), [2n, 10n]));
    await eq('powU(3,5)', encodeCall(sel('powU(uint256,uint256)'), [3n, 5n]));
    await eq('powU(7,0)', encodeCall(sel('powU(uint256,uint256)'), [7n, 0n]));
    await eq('powU64(2,10)', encodeCall(sel('powU64(uint64,uint256)'), [2n, 10n]));
    // u64 wrap on overflow must match solc's checked-arithmetic revert
    await eq('powU64(2,64) overflow', encodeCall(sel('powU64(uint64,uint256)'), [2n, 64n]));
  });

  it('a state write computed through a generic matches solc on raw storage slots', async () => {
    const setC = '0x' + sel('setClamped(uint256,uint256,uint256)') + pad(500n) + pad(10n) + pad(100n);
    await jeth.call(aj, setC);
    await sol.call(as, setC);
    expect(await readSlot(jeth, aj, 0n), 'acc slot 0').toBe(await readSlot(sol, as, 0n));

    const setA = '0x' + sel('setMaxAddr(address,address)') + pad(A1) + pad(A2);
    await jeth.call(aj, setA);
    await sol.call(as, setA);
    expect(await readSlot(jeth, aj, 1n), 'lastAddr slot 1').toBe(await readSlot(sol, as, 1n));
  });
});

// ---------------------------------------------------------------------------
// A bytes32 specialization and a loop-driven generic (a fold), to broaden the
// value-type coverage beyond the integer/address cases above.
// ---------------------------------------------------------------------------
const JETH2 = `@contract class C {
  @hidden eqg<T>(a: T, b: T): bool { return a == b; }
  @hidden selg<T>(c: bool, a: T, b: T): T { return c ? a : b; }
  // a loop-driven generic fold: sum 1..=n into an accumulator of type T
  @hidden sumLoop<T>(n: u256, seed: T): T {
    let s: T = seed;
    for (let i: u256 = 0n; i < n; i++) { s = s + seed; }
    return s;
  }
  @external eqB(a: bytes32, b: bytes32): bool { return this.eqg(a, b); }
  @external selB(c: bool, a: bytes32, b: bytes32): bytes32 { return this.selg(c, a, b); }
  @external foldU(n: u256, seed: u256): u256 { return this.sumLoop<u256>(n, seed); }
  @external foldU16(n: u256, seed: u16): u16 { return this.sumLoop<u16>(n, seed); }
}`;
const SOL2 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function _eqB(bytes32 a, bytes32 b) internal pure returns (bool) { return a == b; }
  function _selB(bool c, bytes32 a, bytes32 b) internal pure returns (bytes32) { return c ? a : b; }
  function _sumU(uint256 n, uint256 seed) internal pure returns (uint256) { uint256 s = seed; for (uint256 i = 0; i < n; i++) { s = s + seed; } return s; }
  function _sumU16(uint256 n, uint16 seed) internal pure returns (uint16) { uint16 s = seed; for (uint256 i = 0; i < n; i++) { s = s + seed; } return s; }
  function eqB(bytes32 a, bytes32 b) external pure returns (bool) { return _eqB(a, b); }
  function selB(bool c, bytes32 a, bytes32 b) external pure returns (bytes32) { return _selB(c, a, b); }
  function foldU(uint256 n, uint256 seed) external pure returns (uint256) { return _sumU(n, seed); }
  function foldU16(uint256 n, uint16 seed) external pure returns (uint16) { return _sumU16(n, seed); }
}`;

describe('generics: bytes32 + loop-driven specializations match solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH2, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL2, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('bytes32 equality + select match solc', async () => {
    const W = (h: string) => BigInt('0x' + h.padEnd(64, '0'));
    await eq('eqB same', encodeCall(sel('eqB(bytes32,bytes32)'), [W('dead'), W('dead')]));
    await eq('eqB diff', encodeCall(sel('eqB(bytes32,bytes32)'), [W('dead'), W('beef')]));
    await eq('selB true', encodeCall(sel('selB(bool,bytes32,bytes32)'), [1n, W('aa'), W('bb')]));
    await eq('selB false', encodeCall(sel('selB(bool,bytes32,bytes32)'), [0n, W('aa'), W('bb')]));
  });
  it('loop-driven generic fold at u256 and u16 (overflow) match solc', async () => {
    await eq('foldU(5,7)', encodeCall(sel('foldU(uint256,uint256)'), [5n, 7n]));
    await eq('foldU16(3,100)', encodeCall(sel('foldU16(uint256,uint16)'), [3n, 100n]));
    // u16 accumulation overflows -> checked revert; must match solc
    await eq('foldU16(1000,1000) overflow', encodeCall(sel('foldU16(uint256,uint16)'), [1000n, 1000n]));
  });
});

// ---------------------------------------------------------------------------
// Byte-identity: a generic instantiated at u256 produces the SAME bytecode as a
// hand-written u256 function (the specialized body is structurally identical).
// ---------------------------------------------------------------------------
describe('generics: a u256 specialization is byte-identical to a hand-written u256 helper', () => {
  const GEN = `@contract class C {
    @hidden maxg<T>(a: T, b: T): T { return a > b ? a : b; }
    @external m(a: u256, b: u256): u256 { return this.maxg(a, b); }
  }`;
  const HAND = `@contract class C {
    @hidden maxh(a: u256, b: u256): u256 { return a > b ? a : b; }
    @external m(a: u256, b: u256): u256 { return this.maxh(a, b); }
  }`;
  it('identical runtime AND creation bytecode (modulo helper name, which is internal)', () => {
    const g = compile(GEN, { fileName: 'C.jeth' });
    const h = compile(HAND, { fileName: 'C.jeth' });
    expect(g.runtimeBytecode).toBe(h.runtimeBytecode);
    expect(g.creationBytecode).toBe(h.creationBytecode);
    // the ABI never mentions the generic or its specialization (all internal)
    const names = g.abi.filter((x: any) => x.type === 'function').map((x: any) => x.name);
    expect(names).toEqual(['m']);
  });

  it('explicit type args and inference give the identical contract', () => {
    const inferred = `@contract class C { @hidden f<T>(a: T): T { return a; } @external g(x: u256): u256 { return this.f(x); } }`;
    const explicit = `@contract class C { @hidden f<T>(a: T): T { return a; } @external g(x: u256): u256 { return this.f<u256>(x); } }`;
    const a = compile(inferred, { fileName: 'C.jeth' });
    const b = compile(explicit, { fileName: 'C.jeth' });
    expect(a.creationBytecode).toBe(b.creationBytecode);
  });
});

// ---------------------------------------------------------------------------
// Dedup + worklist: the same instantiation across call sites collapses to ONE
// specialization; distinct types (incl. a brand vs its base) stay distinct.
// ---------------------------------------------------------------------------
describe('generics: specialization dedup, brand distinction, and the emit worklist', () => {
  const yulFns = (src: string): string[] =>
    [...compile(src, { fileName: 'C.jeth' }).yul.matchAll(/function (userfn_[A-Za-z0-9_$]+)\(/g)].map((m) => m[1]!);

  it('the same type instantiated at multiple call sites emits one specialization', () => {
    const src = `@contract class C {
      @hidden idf<T>(a: T): T { return a; }
      @external g(x: u256): u256 { return this.idf(x) + this.idf<u256>(x); }
    }`;
    expect(yulFns(src)).toEqual(['userfn_idf$uint256']);
  });

  it('the same generic at multiple types emits one specialization per type', () => {
    const src = `@contract class C {
      @hidden idf<T>(a: T): T { return a; }
      @external u(x: u256): u256 { return this.idf(x); }
      @external b(x: u8): u8 { return this.idf(x); }
      @external i(x: i128): i128 { return this.idf(x); }
    }`;
    expect(new Set(yulFns(src))).toEqual(new Set(['userfn_idf$uint256', 'userfn_idf$uint8', 'userfn_idf$int128']));
  });

  it('a branded newtype and its base are DISTINCT specializations (nominal identity)', () => {
    const src = `type Wei = Brand<u256>;
    @contract class C {
      @hidden idf<T>(a: T): T { return a; }
      @external w(a: Wei): Wei { return this.idf(a); }
      @external u(a: u256): u256 { return this.idf(a); }
    }`;
    const fns = yulFns(src);
    expect(new Set(fns)).toEqual(new Set(['userfn_idf$b_Wei_uint256', 'userfn_idf$uint256']));
  });

  it('a generic never called is dead and emits nothing', () => {
    const src = `@contract class C {
      @hidden unused<T>(a: T): T { return a; }
      @external g(x: u256): u256 { return x; }
    }`;
    expect(yulFns(src)).toEqual([]);
  });

  it('a generic calling another generic (and recursion) drains the worklist', () => {
    const src = `@contract class C {
      @hidden id<T>(a: T): T { return a; }
      @hidden dbl<T>(a: T): T { return this.id<T>(a) + this.id<T>(a); }
      @hidden sumTo<T>(n: T, acc: T): T { return n == 0n ? acc : this.sumTo<T>(n - 1n, acc + n); }
      @external d(x: u64): u64 { return this.dbl(x); }
      @external s(x: u32): u32 { return this.sumTo<u32>(x, 0n); }
    }`;
    const fns = new Set(yulFns(src));
    // dbl<u64> -> id<u64>; sumTo<u32> recurses into itself (one specialization)
    expect(fns).toEqual(new Set(['userfn_dbl$uint64', 'userfn_id$uint64', 'userfn_sumTo$uint32']));
  });
});

// ---------------------------------------------------------------------------
// Compile-time rejections: capture the precise JETH diagnostic code.
// ---------------------------------------------------------------------------
function errCodes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    if (e && Array.isArray(e.diagnostics)) {
      return e.diagnostics.filter((d: any) => d.severity === 'error').map((d: any) => d.code);
    }
    throw e;
  }
}

describe('generics: compile-time diagnostics', () => {
  it('JETH290: a generic @external/@public function (the ABI cannot be generic)', () => {
    expect(errCodes('@contract class C { @external f<T>(a: T): T { return a; } @external g(x:u256):u256 { return this.f(x); } }')).toContain('JETH290');
    expect(errCodes('@contract class C { @public f<T>(a: T): T { return a; } @external g(x:u256):u256 { return this.f(x); } }')).toContain('JETH290');
  });

  it('JETH291: a non-value type argument (array / struct / bytes)', () => {
    expect(errCodes('@contract class C { @hidden f<T>(a: u256): u256 { return a; } @external g(x:u256):u256 { return this.f<u256[]>(x); } }')).toContain('JETH291');
    expect(errCodes('@contract class C { @hidden f<T>(a: u256): u256 { return a; } @external g(x:u256):u256 { return this.f<bytes>(x); } }')).toContain('JETH291');
    const structSrc = `@struct class P { x: u256; y: u256; }
    @contract class C { @hidden f<T>(a: u256): u256 { return a; } @external g(x:u256):u256 { return this.f<P>(x); } }`;
    expect(errCodes(structSrc)).toContain('JETH291');
  });

  it('JETH292: a type parameter inferable only from the return type, with no explicit arg', () => {
    const src = `@contract class C { @hidden f<T>(a: u256): T { return T(a); } @external g(x:u256):u256 { return u256(this.f(x)); } }`;
    expect(errCodes(src)).toContain('JETH292');
  });

  it('JETH293: an inference conflict (same T inferred as two different types)', () => {
    const src = `@contract class C { @hidden f<T>(a: T, b: T): T { return a; } @external g(a:u256,b:u8):u256 { return this.f(a, b); } }`;
    expect(errCodes(src)).toContain('JETH293');
  });

  it('an instantiation whose body op is invalid for the type surfaces a diagnostic (no crash)', () => {
    // a + b on an address is not a valid arithmetic op; the specialization surfaces the normal
    // binary-op diagnostic at the call (instantiated at address).
    const src = `@contract class C { @hidden add<T>(a: T, b: T): T { return a + b; } @external g(a:address,b:address):address { return this.add(a, b); } }`;
    const codes = errCodes(src);
    expect(codes.length).toBeGreaterThan(0); // a precise diagnostic, not a crash
    // u256 instantiation of the SAME generic is independent and valid (no error)
    const okSrc = `@contract class C { @hidden add<T>(a: T, b: T): T { return a + b; } @external g(a:u256,b:u256):u256 { return this.add(a, b); } }`;
    expect(errCodes(okSrc)).toEqual([]);
  });

  it('JETH296: a user function whose name collides with a specialization mangled name', () => {
    const src = `@contract class C {
      @hidden idf<T>(a: T): T { return a; }
      @hidden idf$uint256(a: u256): u256 { return a; }
      @external g(x: u256): u256 { return this.idf(x) + this.idf$uint256(x); }
    }`;
    expect(errCodes(src)).toContain('JETH296');
  });

  it('two instantiations of one generic are independent: one valid, one invalid', () => {
    // `a + b` is valid at u256 but invalid at address; only the address instantiation errors.
    const src = `@contract class C {
      @hidden add<T>(a: T, b: T): T { return a + b; }
      @external ok(a: u256, b: u256): u256 { return this.add(a, b); }
      @external bad(a: address, b: address): address { return this.add(a, b); }
    }`;
    expect(errCodes(src).length).toBeGreaterThan(0);
  });
});
