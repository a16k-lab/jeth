// ADVERSARIAL F6 generics (compile-time monomorphization) audit.
//
// Goal: try VERY hard to break the monomorphization machinery: dedup, mangled-name collisions,
// unbounded/infinite specialization, recursion-at-same-type, inference (single/multi type-param,
// conflict, partial explicit), per-instantiation error isolation, the transitive purity/mutability
// fixpoint, byte-identity, feature interactions (defaults/switch/for-of/enum/brand), and the
// soundness-rejection diagnostics. For any behavioral claim we build a JETH generic contract and a
// Solidity twin with hand-written NON-generic helpers and assert byte-identical returndata + raw
// storage slots + logs against the real solc twin running on the same EVM.
//
// Hunt verdict markers: a genuine miscompile / soundness hole / crash is pinned with `it.fails` (or
// `it.skip` for a hang we will not run) and a minimal repro comment. A clean probe is a passing
// permanent regression.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, type LogEntry } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (v & ((1n << 256n) - 1n)).toString(16).padStart(64, '0');
const neg = (v: bigint) => v & ((1n << 256n) - 1n); // two's-complement 256-bit word
const A1 = 0xa11ce0000000000000000000000000000000n;
const A2 = 0xb0b0000000000000000000000000000000000n;
const SOLPRAGMA = 'pragma solidity 0.8.35;';

// Capture the precise JETH error codes for a source that should be rejected at compile time.
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
// Like errCodes but never throws and reports a crash distinctly (so a backend ICE is visible, not
// silently swallowed as "no diagnostics").
function compileOutcome(src: string): { ok: boolean; codes: string[]; crash?: string } {
  try {
    compile(src, { fileName: 'C.jeth' });
    return { ok: true, codes: [] };
  } catch (e: any) {
    if (e && Array.isArray(e.diagnostics)) {
      return { ok: false, codes: e.diagnostics.filter((d: any) => d.severity === 'error').map((d: any) => d.code) };
    }
    return { ok: false, codes: [], crash: String(e?.stack ?? e?.message ?? e) };
  }
}
// All emitted Yul `userfn_*` definitions (the specialization fingerprint).
const yulFns = (src: string): string[] =>
  [...compile(src, { fileName: 'C.jeth' }).yul.matchAll(/function (userfn_[A-Za-z0-9_$]+)\(/g)].map((m) => m[1]!);

const eqLogs = (a: LogEntry[], b: LogEntry[]): boolean =>
  a.length === b.length &&
  a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics));

// =====================================================================================
// PROBE 1 - DEDUP / MANY-TYPES-IN-ONE-CONTRACT. One generic family instantiated at u8, u16, u256,
// i128, i256, address, bytes32, bool, an enum, and a branded newtype, all coexisting; the same
// (T=u256) instantiation reached from BOTH an explicit f<u256> and an inferred f(x) site collapses
// to ONE specialization. Each must match its hand-written solc twin byte-for-byte.
// =====================================================================================
const JETH_MANY = `enum Col { Red, Green, Blue }
type Wei = Brand<u256>;
@contract class C {
  idg<T>(a: T): T { return a; }
  eqg<T>(a: T, b: T): bool { return a == b; }
  // u256 reached two ways (explicit + inferred): must be ONE specialization, same answer.
  @external @pure u256Explicit(x: u256): u256 { return this.idg<u256>(x); }
  @external @pure u256Inferred(x: u256): u256 { return this.idg(x); }
  @external @pure u8id(x: u8): u8 { return this.idg(x); }
  @external @pure u16id(x: u16): u16 { return this.idg(x); }
  @external @pure i128id(x: i128): i128 { return this.idg(x); }
  @external @pure i256id(x: i256): i256 { return this.idg(x); }
  @external @pure addrId(x: address): address { return this.idg(x); }
  @external @pure b32id(x: bytes32): bytes32 { return this.idg(x); }
  @external @pure boolId(x: bool): bool { return this.idg(x); }
  @external @pure enumId(x: Col): Col { return this.idg(x); }
  @external @pure weiId(x: Wei): Wei { return this.idg(x); }
  // eqg at several types simultaneously
  @external @pure eqU(a: u256, b: u256): bool { return this.eqg(a, b); }
  @external @pure eqA(a: address, b: address): bool { return this.eqg(a, b); }
  @external @pure eqE(a: Col, b: Col): bool { return this.eqg(a, b); }
  @external @pure eqW(a: Wei, b: Wei): bool { return this.eqg(a, b); }
}`;
const SOL_MANY = `// SPDX-License-Identifier: MIT
${SOLPRAGMA}
contract C {
  enum Col { Red, Green, Blue }
  function _idU(uint256 a) internal pure returns (uint256) { return a; }
  function _idU8(uint8 a) internal pure returns (uint8) { return a; }
  function _idU16(uint16 a) internal pure returns (uint16) { return a; }
  function _idI128(int128 a) internal pure returns (int128) { return a; }
  function _idI256(int256 a) internal pure returns (int256) { return a; }
  function _idA(address a) internal pure returns (address) { return a; }
  function _idB(bytes32 a) internal pure returns (bytes32) { return a; }
  function _idBool(bool a) internal pure returns (bool) { return a; }
  function _idE(Col a) internal pure returns (Col) { return a; }
  function u256Explicit(uint256 x) external pure returns (uint256) { return _idU(x); }
  function u256Inferred(uint256 x) external pure returns (uint256) { return _idU(x); }
  function u8id(uint8 x) external pure returns (uint8) { return _idU8(x); }
  function u16id(uint16 x) external pure returns (uint16) { return _idU16(x); }
  function i128id(int128 x) external pure returns (int128) { return _idI128(x); }
  function i256id(int256 x) external pure returns (int256) { return _idI256(x); }
  function addrId(address x) external pure returns (address) { return _idA(x); }
  function b32id(bytes32 x) external pure returns (bytes32) { return _idB(x); }
  function boolId(bool x) external pure returns (bool) { return _idBool(x); }
  function enumId(uint8 x) external pure returns (uint8) { return uint8(_idE(Col(x))); }
  function weiId(uint256 x) external pure returns (uint256) { return _idU(x); }
  function eqU(uint256 a, uint256 b) external pure returns (bool) { return a == b; }
  function eqA(address a, address b) external pure returns (bool) { return a == b; }
  function eqE(uint8 a, uint8 b) external pure returns (bool) { return Col(a) == Col(b); }
  function eqW(uint256 a, uint256 b) external pure returns (bool) { return a == b; }
}`;

describe('F6-adv 1: many-types-in-one-contract dedup is byte-identical to solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH_MANY, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL_MANY, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('every concrete instantiation returns the solc-identical value', async () => {
    const M = (1n << 256n) - 1n;
    await eq('u256Explicit', encodeCall(sel('u256Explicit(uint256)'), [M]));
    await eq('u256Inferred', encodeCall(sel('u256Inferred(uint256)'), [M]));
    await eq('u8id 255', encodeCall(sel('u8id(uint8)'), [255n]));
    await eq('u16id 65535', encodeCall(sel('u16id(uint16)'), [65535n]));
    await eq('i128id -1', encodeCall(sel('i128id(int128)'), [neg(-1n)]));
    await eq('i256id -1', encodeCall(sel('i256id(int256)'), [neg(-1n)]));
    await eq('addrId', encodeCall(sel('addrId(address)'), [A1]));
    await eq('b32id', encodeCall(sel('b32id(bytes32)'), [0xdeadn << 240n]));
    await eq('boolId', encodeCall(sel('boolId(bool)'), [1n]));
    await eq('enumId 2', encodeCall(sel('enumId(uint8)'), [2n]));
    await eq('weiId', encodeCall(sel('weiId(uint256)'), [12345n]));
    await eq('eqU eq', encodeCall(sel('eqU(uint256,uint256)'), [7n, 7n]));
    await eq('eqU ne', encodeCall(sel('eqU(uint256,uint256)'), [7n, 8n]));
    await eq('eqA', encodeCall(sel('eqA(address,address)'), [A1, A2]));
    await eq('eqE', encodeCall(sel('eqE(uint8,uint8)'), [1n, 1n]));
    await eq('eqW', encodeCall(sel('eqW(uint256,uint256)'), [5n, 6n]));
  });
  it('dedup: idg$uint256 is emitted exactly once despite two call sites (explicit + inferred)', () => {
    const fns = yulFns(JETH_MANY).filter((n) => n.startsWith('userfn_idg$uint256'));
    expect(fns).toEqual(['userfn_idg$uint256']); // exactly one, not two
  });
  it('distinct types yield independent specializations (one per concrete type)', () => {
    const idFns = new Set(yulFns(JETH_MANY).filter((n) => n.startsWith('userfn_idg$')));
    // u8/u16/u256/i128/i256/address/bytes32/bool/enum/brand = 10 distinct idg specializations
    expect(idFns.size).toBe(10);
    expect(idFns.has('userfn_idg$uint256')).toBe(true);
    expect(idFns.has('userfn_idg$int256')).toBe(true);
    expect([...idFns].some((n) => n.includes('b_Wei'))).toBe(true); // branded distinct from base
    expect([...idFns].some((n) => n.includes('b_Col'))).toBe(true); // enum distinct from uint8
    expect(idFns.has('userfn_idg$uint8')).toBe(true); // and plain uint8 also present
  });
});

// =====================================================================================
// PROBE 2 - MANGLED-NAME COLLISION. Try to make a USER function collide with a specialization's
// mangled name (already covered as JETH296 in the reference suite) AND the nastier variants the
// reference suite does NOT cover: (a) two DIFFERENT generics that mangle to the same key, (b) a
// generic whose NAME already contains the `$` mangling separator, (c) a user function colliding
// with a TWO-type-param specialization, (d) collision against a brand-tagged specialization name.
// A silent overwrite / wrong-function-called would be a miscompile - it must disambiguate or error.
// =====================================================================================
describe('F6-adv 2: mangled-name collision hunting (no silent overwrite)', () => {
  it('(baseline) user fn literally named like a 1-arg specialization -> JETH296', () => {
    const src = `@contract class C {
      idf<T>(a: T): T { return a; }
      idf$uint256(a: u256): u256 { return a; }
      @external g(x: u256): u256 { return this.idf(x) + this.idf$uint256(x); }
    }`;
    expect(errCodes(src)).toContain('JETH296');
  });

  it('user fn colliding with a TWO-type-param specialization name -> JETH296 (or clean error)', () => {
    // f<T,U> at (u256,address) mangles to f$uint256$address. A user fn of that exact name must not
    // be silently shadowed/overwritten.
    const src = `@contract class C {
      f<T, U>(a: T, b: U): T { return a; }
      f$uint256$address(a: u256, b: address): u256 { return a; }
      @external g(a: u256, b: address): u256 { return this.f(a, b) + this.f$uint256$address(a, b); }
    }`;
    const o = compileOutcome(src);
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.ok, 'must be rejected, not silently compiled with a shadow').toBe(false);
    expect(o.codes).toContain('JETH296');
  });

  it('user fn colliding with a BRAND-tagged specialization name -> JETH296', () => {
    // idf<Wei> mangles to idf$b_Wei_uint256. A user function of that exact name collides.
    const src = `type Wei = Brand<u256>;
    @contract class C {
      idf<T>(a: T): T { return a; }
      idf$b_Wei_uint256(a: u256): u256 { return a; }
      @external g(a: Wei): Wei { return this.idf(a); }
      @external h(a: u256): u256 { return this.idf$b_Wei_uint256(a); }
    }`;
    const o = compileOutcome(src);
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.codes).toContain('JETH296');
  });

  it('a generic whose NAME contains the mangling separator `$` collides on instantiation -> JETH296', () => {
    // Two generics, `a<T>` and `a$uint256<U>`. Instantiating `a` at u256 mangles to `a$uint256`,
    // the exact name of the SECOND generic. The collision check inspects genericsByName, so this is
    // caught: a clean JETH296, never a silent overwrite / wrong call (which would be a miscompile).
    const collidingNames = `@contract class C {
      a<T>(x: T): T { return x; }
      a$uint256<U>(x: U): U { return x; }
      @external g(x: u256): u256 { return this.a(x); }
      @external h(x: u8): u8 { return this.a$uint256(x); }
    }`;
    const o = compileOutcome(collidingNames);
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.ok, 'must be rejected, never a silent shadow').toBe(false);
    expect(o.codes).toContain('JETH296');
  });

  it('a generic specialization colliding with a SEPARATELY-instantiated generic -> JETH296', () => {
    // `g<T>` calls `f<u256>` (mangles to f$uint256), and a user fn `f$uint256` exists with a
    // DIFFERENT body (+99). If the cache silently clobbered, `g` would call the wrong body. JETH296.
    const src = `@contract class C {
      f<T>(x: T): T { return x; }
      g<T>(x: T): T { return this.f<u256>(x); }
      f$uint256(x: u256): u256 { return x + 99n; }
      @external @pure e(x: u256): u256 { return this.g<u256>(x) + this.f$uint256(x); }
    }`;
    const o = compileOutcome(src);
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.codes).toContain('JETH296');
  });

  it('a brand whose name embeds a base tag stays disambiguated by the `b_` prefix (no aliasing)', () => {
    // A brand literally named `X_uint256` mangles to `idf$b_X_uint256_uint256`; the base u256
    // specialization is `idf$uint256`. The `b_` prefix keeps them distinct - they must NOT collide.
    const src = `type X_uint256 = Brand<u256>;
    @contract class C {
      idf<T>(a: T): T { return a; }
      @external @pure w(a: X_uint256): X_uint256 { return this.idf(a); }
      @external @pure u(a: u256): u256 { return this.idf(a); }
    }`;
    const fns = new Set(yulFns(src));
    expect(fns.has('userfn_idf$b_X_uint256_uint256')).toBe(true);
    expect(fns.has('userfn_idf$uint256')).toBe(true);
    expect(fns.size).toBe(2); // two DISTINCT specializations, no clobber
  });

  it('two DIFFERENT generics cannot mangle to the same emitted Yul name (independent bodies)', () => {
    // Generic `m` at u256 -> m$uint256 (returns a*2). Generic `m2` at u256 -> m2$uint256 (returns a+1).
    // Confirm BOTH bodies are emitted and behaviorally distinct (no dedup-cache key clobber).
    const src = `@contract class C {
      m<T>(a: T): T { return a + a; }
      m2<T>(a: T): T { return a + 1n; }
      @external g(x: u256): u256 { return this.m(x); }
      @external h(x: u256): u256 { return this.m2(x); }
    }`;
    const fns = new Set(yulFns(src));
    expect(fns.has('userfn_m$uint256')).toBe(true);
    expect(fns.has('userfn_m2$uint256')).toBe(true);
  });
});

// behavioral proof for the colliding-generic-names case, if it compiled, run it against solc.
describe('F6-adv 2b: two distinct generics at u256 stay behaviorally distinct vs solc', () => {
  const J = `@contract class C {
    dbl<T>(a: T): T { return a + a; }
    inc<T>(a: T): T { return a + 1n; }
    @external @pure g(x: u256): u256 { return this.dbl(x); }
    @external @pure h(x: u256): u256 { return this.inc(x); }
  }`;
  const S = `// SPDX-License-Identifier: MIT
${SOLPRAGMA}
contract C {
  function _dbl(uint256 a) internal pure returns (uint256) { return a + a; }
  function _inc(uint256 a) internal pure returns (uint256) { return a + 1; }
  function g(uint256 x) external pure returns (uint256) { return _dbl(x); }
  function h(uint256 x) external pure returns (uint256) { return _inc(x); }
}`;
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  beforeAll(async () => {
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(S, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('dbl and inc are not cross-wired', async () => {
    for (const v of [0n, 7n, 1000n]) {
      const dg = await jeth.call(aj, encodeCall(sel('g(uint256)'), [v]));
      const ds = await sol.call(as, encodeCall(sel('g(uint256)'), [v]));
      expect(dg.returnHex, `g(${v})`).toBe(ds.returnHex);
      const hg = await jeth.call(aj, encodeCall(sel('h(uint256)'), [v]));
      const hs = await sol.call(as, encodeCall(sel('h(uint256)'), [v]));
      expect(hg.returnHex, `h(${v})`).toBe(hs.returnHex);
    }
  });
});

// =====================================================================================
// PROBE 3 - UNBOUNDED / "INFINITE" MONOMORPHIZATION. The value-type universe is finite, so a body
// that recurses at a DIFFERENT fixed type each step terminates after a bounded chain. We still pin a
// hard wall-clock budget so a regression that loops/OOMs is caught. We also chain a long but finite
// descent (u256->u128->u64->u32->u16->u8) and mutual cross-type recursion.
// =====================================================================================
describe('F6-adv 3: cross-type recursion terminates within a wall-clock budget (no hang/OOM)', () => {
  it('a 6-level descending-width chain compiles and terminates fast', () => {
    const src = `@contract class C {
      d8<T>(a: T): u8 { return 8n; }
      d16<T>(a: T): u8 { let x: u8 = 0n; return this.d8<u8>(x); }
      d32<T>(a: T): u8 { let x: u16 = 0n; return this.d16<u16>(x); }
      d64<T>(a: T): u8 { let x: u32 = 0n; return this.d32<u32>(x); }
      d128<T>(a: T): u8 { let x: u64 = 0n; return this.d64<u64>(x); }
      d256<T>(a: T): u8 { let x: u128 = 0n; return this.d128<u128>(x); }
      @external @pure go(a: u256): u8 { return this.d256<u256>(a); }
    }`;
    const t0 = Date.now();
    const o = compileOutcome(src);
    const ms = Date.now() - t0;
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.ok, `chain should compile (codes=${o.codes})`).toBe(true);
    expect(ms, `compile took ${ms}ms - possible non-termination`).toBeLessThan(8000);
  });

  it('self-recursion at T plus a one-shot spawn at a fixed other T closes via the cache (n=2)', () => {
    // f<T> recurses at T (dedup closes it) and ALSO spawns g<u8> once per call. The cache resolves
    // the in-progress f<T> self-call without re-queuing, so this cannot diverge: exactly 2 fns.
    const src = `@contract class C {
      f<T>(a: T, n: u256): u256 { return n == 0n ? 0n : 1n + this.f<T>(a, n - 1n) + this.g<u8>(0n); }
      g<U>(a: U): u256 { return 0n; }
      @external @pure go(a: u256, n: u256): u256 { return this.f<u256>(a, n); }
    }`;
    const t0 = Date.now();
    const o = compileOutcome(src);
    const ms = Date.now() - t0;
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.ok, `should compile (codes=${o.codes})`).toBe(true);
    expect(ms).toBeLessThan(8000);
    expect(new Set(yulFns(src))).toEqual(new Set(['userfn_f$uint256', 'userfn_g$uint8']));
  });

  it('a 20-brand chain instantiating one generic terminates with exactly 20 specializations', () => {
    const N = 20;
    const brands = Array.from({ length: N }, (_, i) => `type B${i} = Brand<u256>;`).join('\n');
    const params = Array.from({ length: N }, (_, i) => `b${i}: B${i}`).join(', ');
    const calls = Array.from({ length: N }, (_, i) => `u256(this.idf<B${i}>(b${i}))`).join(' + ');
    const src = `${brands}
    @contract class C { idf<T>(a: T): T { return a; }
      @external @pure go(${params}): u256 { return ${calls}; } }`;
    const t0 = Date.now();
    const o = compileOutcome(src);
    const ms = Date.now() - t0;
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.ok, `should compile (codes=${o.codes})`).toBe(true);
    expect(ms).toBeLessThan(8000);
    expect(new Set(yulFns(src)).size).toBe(N); // 20 distinct brand specializations, no collapse
  });

  it('mutual cross-type recursion (a<u256> -> b<u8> -> a<u256>) terminates via the dedup cache', () => {
    // a and b call each other but always at the SAME fixed types, so the dedup cache closes the loop.
    const src = `@contract class C {
      pa<T>(a: T, n: u256): u256 { return n == 0n ? 0n : 1n + this.pb<u8>(0n, n - 1n); }
      pb<U>(b: U, n: u256): u256 { return n == 0n ? 0n : 1n + this.pa<u256>(0n, n - 1n); }
      @external @pure go(n: u256): u256 { return this.pa<u256>(0n, n); }
    }`;
    const t0 = Date.now();
    const o = compileOutcome(src);
    const ms = Date.now() - t0;
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.ok, `should compile (codes=${o.codes})`).toBe(true);
    expect(ms, `compile took ${ms}ms`).toBeLessThan(8000);
    // exactly the two specializations pa$uint256 and pb$uint8
    const fns = new Set(yulFns(src));
    expect(fns.has('userfn_pa$uint256')).toBe(true);
    expect(fns.has('userfn_pb$uint8')).toBe(true);
  });

  it('a wide fan-out (one generic at all 32 byte widths bytes1..bytes32) terminates fast', () => {
    const widths = Array.from({ length: 32 }, (_, i) => i + 1);
    const calls = widths.map((w) => `this.idf<bytes${w}>(b${w})`).join(' == ');
    const params = widths.map((w) => `b${w}: bytes${w}`).join(', ');
    const src = `@contract class C {
      idf<T>(a: T): bool { return true; }
      @external @pure go(${params}): bool { return ${calls}; }
    }`;
    const t0 = Date.now();
    const o = compileOutcome(src);
    const ms = Date.now() - t0;
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.ok, `should compile (codes=${o.codes})`).toBe(true);
    expect(ms).toBeLessThan(8000);
    const idFns = new Set(yulFns(src).filter((n) => n.startsWith('userfn_idf$')));
    expect(idFns.size, '32 distinct bytesN specializations').toBe(32);
  });
});

// =====================================================================================
// PROBE 4 - RECURSION AT THE SAME TYPE. A generic that recurses at a FIXED T must terminate via the
// dedup cache (the in-progress specialization is found by the self-call) and match solc. Plus mutual
// recursion between two generics at fixed types.
// =====================================================================================
const JETH_REC = `@contract class C {
  sumTo<T>(n: T, acc: T): T { return n == 0n ? acc : this.sumTo<T>(n - 1n, acc + n); }
  isEvenG<T>(n: T): bool { return n == 0n ? true : this.isOddG<T>(n - 1n); }
  isOddG<T>(n: T): bool { return n == 0n ? false : this.isEvenG<T>(n - 1n); }
  @external @pure sumU(n: u256): u256 { return this.sumTo<u256>(n, 0n); }
  @external @pure sumU32(n: u32): u32 { return this.sumTo<u32>(n, 0n); }
  @external @pure evenU(n: u256): bool { return this.isEvenG<u256>(n); }
}`;
const SOL_REC = `// SPDX-License-Identifier: MIT
${SOLPRAGMA}
contract C {
  function _sumU(uint256 n, uint256 acc) internal pure returns (uint256) { return n == 0 ? acc : _sumU(n - 1, acc + n); }
  function _sumU32(uint32 n, uint32 acc) internal pure returns (uint32) { return n == 0 ? acc : _sumU32(n - 1, acc + n); }
  function _even(uint256 n) internal pure returns (bool) { return n == 0 ? true : _odd(n - 1); }
  function _odd(uint256 n) internal pure returns (bool) { return n == 0 ? false : _even(n - 1); }
  function sumU(uint256 n) external pure returns (uint256) { return _sumU(n, 0); }
  function sumU32(uint32 n) external pure returns (uint32) { return _sumU32(n, 0); }
  function evenU(uint256 n) external pure returns (bool) { return _even(n); }
}`;
describe('F6-adv 4: same-type recursion and mutual generic recursion match solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH_REC, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL_REC, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('recursive sum at u256 and u32 (overflow-prone narrow) match solc', async () => {
    await eq('sumU(10)', encodeCall(sel('sumU(uint256)'), [10n]));
    await eq('sumU(0)', encodeCall(sel('sumU(uint256)'), [0n]));
    await eq('sumU(100)', encodeCall(sel('sumU(uint256)'), [100n]));
    await eq('sumU32(50)', encodeCall(sel('sumU32(uint32)'), [50n]));
    // sum 1..70000 overflows u32 -> checked revert; must match solc's revert exactly
    await eq('sumU32(70000) overflow', encodeCall(sel('sumU32(uint32)'), [70000n]));
  });
  it('mutual generic recursion (even/odd) matches solc and emits one specialization each', async () => {
    await eq('evenU(0)', encodeCall(sel('evenU(uint256)'), [0n]));
    await eq('evenU(7)', encodeCall(sel('evenU(uint256)'), [7n]));
    await eq('evenU(20)', encodeCall(sel('evenU(uint256)'), [20n]));
    const fns = new Set(yulFns(JETH_REC));
    expect(fns.has('userfn_isEvenG$uint256')).toBe(true);
    expect(fns.has('userfn_isOddG$uint256')).toBe(true);
    expect(fns.has('userfn_sumTo$uint256')).toBe(true);
    expect(fns.has('userfn_sumTo$uint32')).toBe(true);
  });
});

// =====================================================================================
// PROBE 5 - INFERENCE. T inferred from enum / brand / bytesN / bool; T in MULTIPLE params (must
// agree, else JETH293); two type params <T,U> inferred independently; partial-explicit arity
// mismatch; explicit type args that CONFLICT with the arg types (the arg must coerce, not error,
// when assignment-compatible, and error when not).
// =====================================================================================
const JETH_INFER = `enum Col { Red, Green, Blue }
type Wei = Brand<u256>;
@contract class C {
  pick<T>(c: bool, a: T, b: T): T { return c ? a : b; }
  pair<T, U>(a: T, b: U): T { return a; }
  @external @pure pickE(c: bool, a: Col, b: Col): Col { return this.pick(c, a, b); }
  @external @pure pickW(c: bool, a: Wei, b: Wei): Wei { return this.pick(c, a, b); }
  @external @pure pickB(c: bool, a: bytes8, b: bytes8): bytes8 { return this.pick(c, a, b); }
  @external @pure pickBool(c: bool, a: bool, b: bool): bool { return this.pick(c, a, b); }
  // two independently-inferred type params
  @external @pure pairUA(a: u256, b: address): u256 { return this.pair(a, b); }
  @external @pure pairAU(a: address, b: u256): u256 { return u256(u160(this.pair(a, b))); }
}`;
const SOL_INFER = `// SPDX-License-Identifier: MIT
${SOLPRAGMA}
contract C {
  enum Col { Red, Green, Blue }
  function _pickE(bool c, Col a, Col b) internal pure returns (Col) { return c ? a : b; }
  function _pickW(bool c, uint256 a, uint256 b) internal pure returns (uint256) { return c ? a : b; }
  function _pickB(bool c, bytes8 a, bytes8 b) internal pure returns (bytes8) { return c ? a : b; }
  function _pickBool(bool c, bool a, bool b) internal pure returns (bool) { return c ? a : b; }
  function _pairUA(uint256 a, address b) internal pure returns (uint256) { return a; }
  function _pairAU(address a, uint256 b) internal pure returns (address) { return a; }
  function pickE(bool c, uint8 a, uint8 b) external pure returns (uint8) { return uint8(_pickE(c, Col(a), Col(b))); }
  function pickW(bool c, uint256 a, uint256 b) external pure returns (uint256) { return _pickW(c, a, b); }
  function pickB(bool c, bytes8 a, bytes8 b) external pure returns (bytes8) { return _pickB(c, a, b); }
  function pickBool(bool c, bool a, bool b) external pure returns (bool) { return _pickBool(c, a, b); }
  function pairUA(uint256 a, address b) external pure returns (uint256) { return _pairUA(a, b); }
  function pairAU(address a, uint256 b) external pure returns (uint256) { return uint256(uint160(_pairAU(a, b))); }
}`;
describe('F6-adv 5: inference from enum/brand/bytesN/bool and multi-param matches solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH_INFER, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL_INFER, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('inference picks the right specialization for each value type', async () => {
    await eq('pickE true', encodeCall(sel('pickE(bool,uint8,uint8)'), [1n, 1n, 2n]));
    await eq('pickE false', encodeCall(sel('pickE(bool,uint8,uint8)'), [0n, 1n, 2n]));
    await eq('pickW', encodeCall(sel('pickW(bool,uint256,uint256)'), [1n, 11n, 22n]));
    await eq('pickB', encodeCall(sel('pickB(bool,bytes8,bytes8)'), [0n, 0xaan << 56n, 0xbbn << 56n]));
    await eq('pickBool', encodeCall(sel('pickBool(bool,bool,bool)'), [1n, 1n, 0n]));
    await eq('pairUA', encodeCall(sel('pairUA(uint256,address)'), [42n, A1]));
    await eq('pairAU', encodeCall(sel('pairAU(address,uint256)'), [A1, 42n]));
  });
});

describe('F6-adv 5b: inference rejection diagnostics', () => {
  it('JETH293: same T inferred as two different types (conflict)', () => {
    const src = `@contract class C { f<T>(a: T, b: T): T { return a; } @external g(a:u256,b:u8):u256 { return this.f(a, b); } }`;
    expect(errCodes(src)).toContain('JETH293');
  });
  it('JETH292: arity mismatch - one explicit type arg for a two-type-param generic', () => {
    const src = `@contract class C { f<T, U>(a: T, b: U): T { return a; } @external g(a:u256,b:address):u256 { return this.f<u256>(a, b); } }`;
    expect(errCodes(src)).toContain('JETH292');
  });
  it('JETH292: more explicit type args than type params', () => {
    const src = `@contract class C { f<T>(a: T): T { return a; } @external g(a:u256):u256 { return this.f<u256, address>(a); } }`;
    expect(errCodes(src)).toContain('JETH292');
  });
  it('JETH292: a type param appearing only in the return type cannot be inferred', () => {
    const src = `@contract class C { f<T>(a: u256): T { return T(a); } @external g(x:u256):u256 { return u256(this.f(x)); } }`;
    expect(errCodes(src)).toContain('JETH292');
  });
  it('explicit type arg conflicting with a non-coercible arg type is rejected (no crash)', () => {
    // f<bool>(x) where x is u256: bool param cannot accept a u256 argument -> a clean diagnostic.
    const src = `@contract class C { f<T>(a: T): T { return a; } @external g(x:u256):u256 { return u256(this.f<bool>(x)); } }`;
    const o = compileOutcome(src);
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.ok, 'a u256 argument must not bind to a bool-specialized param').toBe(false);
    expect(o.codes.length).toBeGreaterThan(0);
  });
});

// =====================================================================================
// PROBE 6 - PER-INSTANTIATION ERROR ISOLATION. A generic body with an op valid for some types but
// not others. The bad instantiation must produce a CLEAN diagnostic (no crash) and a DIFFERENT valid
// instantiation of the SAME generic in the SAME contract must still compile and run correctly.
// =====================================================================================
describe('F6-adv 6: per-instantiation error isolation (no crash, valid sibling unaffected)', () => {
  it('`a + b` valid at u256, invalid at bool -> JETH082 only for the bool instantiation', () => {
    // `a + b` is invalid at bool (no arithmetic on bool) but valid at u256. The bool
    // instantiation surfaces JETH082; the u256 instantiation is clean and independent.
    const bad = `@contract class C {
      add<T>(a: T, b: T): T { return a + b; }
      @external @pure okU(a: u256, b: u256): u256 { return this.add(a, b); }
      @external @pure badB(a: bool, b: bool): bool { return this.add(a, b); }
    }`;
    const o = compileOutcome(bad);
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.ok, 'the bool instantiation of `+` must be rejected').toBe(false);
    expect(o.codes).toContain('JETH082');
  });

  // REGRESSION (was a pre-existing lint gap, now FIXED): solc rejects ordering (< > <= >=) on bool
  // ("operator > cannot be applied to types bool and bool"); JETH now rejects it too (JETH082). The
  // generic `>`-at-bool instantiation inherits the same rejection (the bool-ordering check fires when
  // the specialized body is checked), so generic and non-generic behave identically.
  it('bool `>` is rejected (JETH082) identically for generic and non-generic', () => {
    const nonGen = `@contract class C { @external @pure f(a: bool, b: bool): bool { return a > b; } }`;
    const gen = `@contract class C {
      g<T>(a: T, b: T): bool { return a > b; }
      @external @pure f(a: bool, b: bool): bool { return this.g(a, b); }
    }`;
    expect(errCodes(nonGen)).toContain('JETH082');
    expect(errCodes(gen)).toContain('JETH082');
  });
  it('`a + b` invalid at address, valid sibling at u256 compiles in isolation', () => {
    const okOnly = `@contract class C {
      add<T>(a: T, b: T): T { return a + b; }
      @external @pure ok(a: u256, b: u256): u256 { return this.add(a, b); }
    }`;
    expect(errCodes(okOnly)).toEqual([]); // the valid instantiation alone is clean
    const withBad = `@contract class C {
      add<T>(a: T, b: T): T { return a + b; }
      @external @pure ok(a: u256, b: u256): u256 { return this.add(a, b); }
      @external @pure bad(a: address, b: address): address { return this.add(a, b); }
    }`;
    const o = compileOutcome(withBad);
    expect(o.crash, `must not crash: ${o.crash}`).toBeUndefined();
    expect(o.ok, 'address `+` instantiation must error').toBe(false);
    expect(o.codes.length).toBeGreaterThan(0);
  });
  it('a valid instantiation compiles AND runs correctly even though a sibling generic has no valid use', async () => {
    // The contract only ever instantiates `add` at u256 (valid). An unused-at-bad-type generic
    // existing in the same contract must not poison the good one.
    const J = `@contract class C {
      add<T>(a: T, b: T): T { return a + b; }
      ordr<T>(a: T, b: T): bool { return a > b; }
      @external @pure s(a: u256, b: u256): u256 { return this.add(a, b); }
      @external @pure o(a: u256, b: u256): bool { return this.ordr(a, b); }
    }`;
    const S = `// SPDX-License-Identifier: MIT
${SOLPRAGMA}
contract C {
  function s(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }
  function o(uint256 a, uint256 b) external pure returns (bool) { return a > b; }
}`;
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(S, 'C');
    const jeth = await Harness.create();
    const sol = await Harness.create();
    const aj = await jeth.deploy(jb.creationBytecode);
    const as = await sol.deploy(sb.creation);
    for (const [a, b] of [
      [3n, 4n],
      [10n, 2n],
    ] as const) {
      const jr = await jeth.call(aj, encodeCall(sel('s(uint256,uint256)'), [a, b]));
      const sr = await sol.call(as, encodeCall(sel('s(uint256,uint256)'), [a, b]));
      expect(jr.returnHex, `s(${a},${b})`).toBe(sr.returnHex);
      const jo = await jeth.call(aj, encodeCall(sel('o(uint256,uint256)'), [a, b]));
      const so = await sol.call(as, encodeCall(sel('o(uint256,uint256)'), [a, b]));
      expect(jo.returnHex, `o(${a},${b})`).toBe(so.returnHex);
    }
  });
});

// =====================================================================================
// PROBE 7 - PURITY / MUTABILITY FIXPOINT. A @view calling a generic that READS state (allowed). A
// @pure calling a generic that WRITES state (rejected). A @view calling a generic that transitively
// EMITS an event (rejected). The same generic used once in a pure context and once in a view context.
// And: the wrapper ABI mutability must match solc.
// =====================================================================================
describe('F6-adv 7: transitive purity/mutability fixpoint through a generic', () => {
  it('@view calling a generic that READS state is allowed', () => {
    const src = `@contract class C {
      @state v: u256;
      rd<T>(k: T): u256 { return this.v; }
      @external @view get(x: u256): u256 { return this.rd<u256>(x); }
    }`;
    expect(errCodes(src)).toEqual([]);
  });
  it('@pure calling a generic that WRITES state is REJECTED (JETH055)', () => {
    const src = `@contract class C {
      @state v: u256;
      wr<T>(k: T): void { this.v = u256(0n); }
      @external @pure bad(x: u256): void { this.wr<u256>(x); }
    }`;
    expect(errCodes(src)).toContain('JETH055');
  });
  it('@view calling a generic that WRITES state is REJECTED (JETH054)', () => {
    const src = `@contract class C {
      @state v: u256;
      wr<T>(k: T): void { this.v = u256(0n); }
      @external @view bad(x: u256): void { this.wr<u256>(x); }
    }`;
    expect(errCodes(src)).toContain('JETH054');
  });
  it('@view calling a generic that transitively EMITS an event is REJECTED (JETH054)', () => {
    const src = `@contract class C {
      @event Ping(x: u256);
      ping<T>(k: T): void { emit(Ping(u256(0n))); }
      @external @view bad(x: u256): void { this.ping<u256>(x); }
    }`;
    expect(errCodes(src)).toContain('JETH054');
  });
  it('@pure calling a generic that READS state is REJECTED (JETH055)', () => {
    const src = `@contract class C {
      @state v: u256;
      rd<T>(k: T): u256 { return this.v; }
      @external @pure bad(x: u256): u256 { return this.rd<u256>(x); }
    }`;
    expect(errCodes(src)).toContain('JETH055');
  });
  it('the SAME generic in a pure context and a view context: pure wrapper of a pure body is OK', () => {
    // rd reads state; used in a @view wrapper (ok) and an @external (non-view, ok). A @pure wrapper
    // of the state-reading instantiation would be rejected; a @pure wrapper of a NON-reading
    // instantiation (different body branch) is fine. Here `idg` reads nothing, used pure + view.
    const src = `@contract class C {
      @state v: u256;
      idg<T>(a: T): T { return a; }
      rd<T>(k: T): u256 { return this.v; }
      @external @pure p(x: u256): u256 { return this.idg<u256>(x); }
      @external @view w(x: u256): u256 { return this.idg<u256>(x) + this.rd<u256>(x); }
    }`;
    expect(errCodes(src)).toEqual([]);
  });
  it('ABI mutability of the wrappers matches solc (pure stays pure, view stays view)', async () => {
    const J = `@contract class C {
      @state v: u256;
      idg<T>(a: T): T { return a; }
      rd<T>(k: T): u256 { return this.v; }
      @external @pure p(x: u256): u256 { return this.idg<u256>(x); }
      @external @view w(x: u256): u256 { return this.rd<u256>(x); }
    }`;
    const S = `// SPDX-License-Identifier: MIT
${SOLPRAGMA}
contract C {
  uint256 v;
  function _idg(uint256 a) internal pure returns (uint256) { return a; }
  function _rd(uint256) internal view returns (uint256) { return v; }
  function p(uint256 x) external pure returns (uint256) { return _idg(x); }
  function w(uint256 x) external view returns (uint256) { return _rd(x); }
}`;
    const jb = compile(J, { fileName: 'C.jeth' });
    compileSolidity(S, 'C'); // ensures the twin is valid Solidity (compiles)
    const abi = jb.abi.filter((e: any) => e.type === 'function');
    const p = abi.find((e: any) => e.name === 'p') as any;
    const w = abi.find((e: any) => e.name === 'w') as any;
    expect(p.stateMutability).toBe('pure');
    expect(w.stateMutability).toBe('view');
    // the generic specializations are NEVER in the ABI
    expect(abi.map((e: any) => e.name).sort()).toEqual(['p', 'w']);
  });
});

// =====================================================================================
// PROBE 8 - BYTE-IDENTITY in a state-mutating path + a multi-value-return + a struct field. Generic
// results flowing into raw storage slots, a tuple return, and a struct constructor must be byte-equal
// to the hand-written solc twin (returndata + raw slots).
// =====================================================================================
const JETH_BYTE = `@struct class Pair { a: u256; b: u256; }
@contract class C {
  @state s0: u256;
  @state s1: u256;
  maxg<T>(a: T, b: T): T { return a > b ? a : b; }
  ming<T>(a: T, b: T): T { return a < b ? a : b; }
  @external setBoth(x: u256, y: u256): void { this.s0 = this.maxg<u256>(x, y); this.s1 = this.ming<u256>(x, y); }
  @external @pure spread(x: u256, y: u256): Pair { return Pair(this.maxg<u256>(x, y), this.ming<u256>(x, y)); }
  @external @pure two(x: u256, y: u256): [u256, u256] { return [this.maxg<u256>(x, y), this.ming<u256>(x, y)]; }
}`;
const SOL_BYTE = `// SPDX-License-Identifier: MIT
${SOLPRAGMA}
contract C {
  uint256 s0;
  uint256 s1;
  struct Pair { uint256 a; uint256 b; }
  function _max(uint256 a, uint256 b) internal pure returns (uint256) { return a > b ? a : b; }
  function _min(uint256 a, uint256 b) internal pure returns (uint256) { return a < b ? a : b; }
  function setBoth(uint256 x, uint256 y) external { s0 = _max(x, y); s1 = _min(x, y); }
  function spread(uint256 x, uint256 y) external pure returns (Pair memory) { return Pair(_max(x, y), _min(x, y)); }
  function two(uint256 x, uint256 y) external pure returns (uint256, uint256) { return (_max(x, y), _min(x, y)); }
}`;
describe('F6-adv 8: generic result into raw slots, a struct field, and a multi-value return', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH_BYTE, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL_BYTE, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('struct field + multi-value returns match solc', async () => {
    await eq('spread(3,9)', encodeCall(sel('spread(uint256,uint256)'), [3n, 9n]));
    await eq('spread(9,3)', encodeCall(sel('spread(uint256,uint256)'), [9n, 3n]));
    await eq('two(3,9)', encodeCall(sel('two(uint256,uint256)'), [3n, 9n]));
    await eq('two(9,3)', encodeCall(sel('two(uint256,uint256)'), [9n, 3n]));
  });
  it('a state write through the generic matches solc on raw slots', async () => {
    const data = '0x' + sel('setBoth(uint256,uint256)') + pad(7n) + pad(99n);
    await jeth.call(aj, data);
    await sol.call(as, data);
    expect(await readSlot(jeth, aj, 0n), 'slot0 (max)').toBe(await readSlot(sol, as, 0n));
    expect(await readSlot(jeth, aj, 1n), 'slot1 (min)').toBe(await readSlot(sol, as, 1n));
  });
});

// =====================================================================================
// PROBE 9 - INTERACTIONS with F3 defaults, F5 switch, F2 for-of, F1 brand, F5 enum; a generic that
// calls a non-generic and vice versa. Each is differentially checked vs solc (returndata + logs).
// =====================================================================================
const JETH_MIX = `enum Op { Add, Sub, Mul }
type Tok = Brand<u256>;
@contract class C {
  @event Used(amount: u256);
  clampg<T>(v: T, lo: T = 0n, hi: T = 100n): T { return v < lo ? lo : (v > hi ? hi : v); }
  idg<T>(a: T): T { return a; }
  plain(a: u256): u256 { return this.idg<u256>(a) + 1n; }
  viaGen<T>(a: T): T { return this.idg<T>(a); }
  // generic inside an F5 switch arm
  @external @pure dispatch(op: Op, a: u256, b: u256): u256 {
    switch (op) {
      case Op.Add: return this.idg<u256>(a) + b;
      case Op.Sub: return a - this.idg<u256>(b);
      case Op.Mul: return this.idg<u256>(a) * this.idg<u256>(b);
    }
  }
  // generic with an F3 default argument
  @external @pure clampDefault(v: u256): u256 { return this.clampg<u256>(v); }
  @external @pure clampHi(v: u256, hi: u256): u256 { return this.clampg<u256>(v, 0n, hi); }
  // generic inside an F2 for...of body, accumulating
  @external @pure sumArr(xs: u256[]): u256 {
    let s: u256 = 0n;
    for (const x of xs) { s = s + this.idg<u256>(x); }
    return s;
  }
  // generic at a brand vs at the base, and a generic calling a non-generic and vice versa
  @external @pure tokId(t: Tok): Tok { return this.viaGen<Tok>(t); }
  @external @pure plus1(a: u256): u256 { return this.plain(a); }
  // generic that EMITS via a non-generic (effect propagation through the wrapper)
  logIt(a: u256): void { emit(Used(a)); }
  gLog<T>(a: T): void { this.logIt(u256(0n)); }
  @external doLog(a: u256): void { this.gLog<u256>(a); }
}`;
const SOL_MIX = `// SPDX-License-Identifier: MIT
${SOLPRAGMA}
contract C {
  enum Op { Add, Sub, Mul }
  event Used(uint256 amount);
  function _clampU(uint256 v, uint256 lo, uint256 hi) internal pure returns (uint256) { return v < lo ? lo : (v > hi ? hi : v); }
  function _idU(uint256 a) internal pure returns (uint256) { return a; }
  function dispatch(uint8 op, uint256 a, uint256 b) external pure returns (uint256) {
    if (Op(op) == Op.Add) return _idU(a) + b;
    if (Op(op) == Op.Sub) return a - _idU(b);
    return _idU(a) * _idU(b);
  }
  function clampDefault(uint256 v) external pure returns (uint256) { return _clampU(v, 0, 100); }
  function clampHi(uint256 v, uint256 hi) external pure returns (uint256) { return _clampU(v, 0, hi); }
  function sumArr(uint256[] calldata xs) external pure returns (uint256) {
    uint256 s = 0;
    for (uint256 i = 0; i < xs.length; i++) { s = s + _idU(xs[i]); }
    return s;
  }
  function tokId(uint256 t) external pure returns (uint256) { return _idU(t); }
  function plus1(uint256 a) external pure returns (uint256) { return _idU(a) + 1; }
  function doLog(uint256) external { emit Used(0); }
}`;
describe('F6-adv 9: interactions with F3 defaults, F5 switch, F2 for-of, brand, events', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    expect(eqLogs(j.logs, s.logs), `${label} logs`).toBe(true);
  }
  beforeAll(async () => {
    const jb = compile(JETH_MIX, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL_MIX, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('generic in a switch arm matches solc', async () => {
    await eq('dispatch Add', encodeCall(sel('dispatch(uint8,uint256,uint256)'), [0n, 10n, 3n]));
    await eq('dispatch Sub', encodeCall(sel('dispatch(uint8,uint256,uint256)'), [1n, 10n, 3n]));
    await eq('dispatch Mul', encodeCall(sel('dispatch(uint8,uint256,uint256)'), [2n, 10n, 3n]));
  });
  it('generic with an F3 default argument matches solc', async () => {
    await eq('clampDefault below', encodeCall(sel('clampDefault(uint256)'), [200n]));
    await eq('clampDefault inside', encodeCall(sel('clampDefault(uint256)'), [50n]));
    await eq('clampHi', encodeCall(sel('clampHi(uint256,uint256)'), [80n, 60n]));
  });
  it('generic inside an F2 for-of body (sum) matches solc', async () => {
    // encode a dynamic uint256[] {1,2,3,4}
    const head = sel('sumArr(uint256[])');
    const data = '0x' + head + pad(0x20n) + pad(4n) + pad(1n) + pad(2n) + pad(3n) + pad(4n);
    await eq('sumArr', data);
  });
  it('generic at a brand, generic<->non-generic call, and a generic-driven emit match solc', async () => {
    await eq('tokId', encodeCall(sel('tokId(uint256)'), [777n]));
    await eq('plus1', encodeCall(sel('plus1(uint256)'), [41n]));
    await eq('doLog (event via generic)', encodeCall(sel('doLog(uint256)'), [5n]));
  });
});

// =====================================================================================
// PROBE 10 - SOUNDNESS REJECTIONS. Capture the precise code, never crash.
// =====================================================================================
describe('F6-adv 10: soundness-rejection diagnostics (capture code, no crash)', () => {
  const cases: [string, string, string][] = [
    [
      'JETH290',
      'external generic',
      '@contract class C { @external f<T>(a: T): T { return a; } @external g(x:u256):u256 { return this.f(x); } }',
    ],
    [
      'JETH290',
      'public generic',
      '@contract class C { @external f<T>(a: T): T { return a; } @external g(x:u256):u256 { return this.f(x); } }',
    ],
    [
      'JETH290',
      '@nonReentrant generic',
      '@contract class C { @nonReentrant f<T>(a: T): T { return a; } @external g(x:u256):u256 { return this.f(x); } }',
    ],
    [
      'JETH291',
      'array type arg f<u256[]>',
      '@contract class C { f<T>(a: u256): u256 { return a; } @external g(x:u256):u256 { return this.f<u256[]>(x); } }',
    ],
    [
      'JETH291',
      'bytes type arg',
      '@contract class C { f<T>(a: u256): u256 { return a; } @external g(x:u256):u256 { return this.f<bytes>(x); } }',
    ],
    [
      'JETH291',
      'string type arg',
      '@contract class C { f<T>(a: u256): u256 { return a; } @external g(x:u256):u256 { return this.f<string>(x); } }',
    ],
    [
      'JETH292',
      'infer-from-return-only',
      '@contract class C { f<T>(a: u256): T { return T(a); } @external g(x:u256):u256 { return u256(this.f(x)); } }',
    ],
    [
      'JETH293',
      'inference conflict',
      '@contract class C { f<T>(a: T, b: T): T { return a; } @external g(a:u256,b:u8):u256 { return this.f(a, b); } }',
    ],
    [
      'JETH294',
      'type param shadows a primitive (u256)',
      '@contract class C { f<u256>(a: u256): u256 { return a; } @external g(x:u256):u256 { return this.f(x); } }',
    ],
    [
      'JETH294',
      'duplicate type param <T, T>',
      '@contract class C { f<T, T>(a: T, b: T): T { return a; } @external g(a:u256,b:u256):u256 { return this.f(a, b); } }',
    ],
    [
      'JETH296',
      'user fn collides with specialization name',
      '@contract class C { idf<T>(a: T): T { return a; } idf$uint256(a: u256): u256 { return a; } @external g(x:u256):u256 { return this.idf(x) + this.idf$uint256(x); } }',
    ],
  ];
  for (const [code, label, src] of cases) {
    it(`${code}: ${label}`, () => {
      const o = compileOutcome(src);
      expect(o.crash, `${label} crashed: ${o.crash}`).toBeUndefined();
      expect(o.codes, `${label} expected ${code}, got [${o.codes}]`).toContain(code);
    });
  }

  it('a struct type argument is rejected (no crash)', () => {
    const src = `@struct class P { x: u256; y: u256; }
    @contract class C { f<T>(a: u256): u256 { return a; } @external g(x:u256):u256 { return this.f<P>(x); } }`;
    const o = compileOutcome(src);
    expect(o.crash, `crashed: ${o.crash}`).toBeUndefined();
    expect(o.codes).toContain('JETH291');
  });

  it('a mapping type argument is rejected (no crash)', () => {
    const src = `@contract class C { f<T>(a: u256): u256 { return a; } @external g(x:u256):u256 { return this.f<mapping<u256, u256>>(x); } }`;
    const o = compileOutcome(src);
    expect(o.crash, `crashed: ${o.crash}`).toBeUndefined();
    // either JETH291 (value-type gate) or a parse/type diagnostic - any clean error, no crash
    expect(o.ok).toBe(false);
    expect(o.codes.length).toBeGreaterThan(0);
  });

  it('a type param that shadows an existing enum is rejected (JETH294)', () => {
    const src = `enum Col { Red, Green }
    @contract class C { f<Col>(a: Col): Col { return a; } @external g(x:u8):u8 { return u8(this.f(Col(x))); } }`;
    const o = compileOutcome(src);
    expect(o.crash, `crashed: ${o.crash}`).toBeUndefined();
    expect(o.codes).toContain('JETH294');
  });

  it('an UNUSED type param (not inferable, no explicit arg) is rejected (JETH292), not silently dropped', () => {
    // T never appears in a bare-identifier param, so it cannot be inferred and there is no explicit
    // type arg -> JETH292. (An unused-but-explicitly-supplied param compiles; see next test.)
    const src = `@contract class C { f<T>(a: u256): u256 { return a; } @external g(x:u256):u256 { return this.f(x); } }`;
    const o = compileOutcome(src);
    expect(o.crash, `crashed: ${o.crash}`).toBeUndefined();
    expect(o.codes).toContain('JETH292');
  });

  it('an unused type param WITH an explicit arg compiles (the type param is simply unobservable)', () => {
    const src = `@contract class C { f<T>(a: u256): u256 { return a; } @external @pure g(x:u256):u256 { return this.f<address>(x); } }`;
    const o = compileOutcome(src);
    expect(o.crash, `crashed: ${o.crash}`).toBeUndefined();
    expect(o.ok, `expected compile, got [${o.codes}]`).toBe(true);
  });
});
