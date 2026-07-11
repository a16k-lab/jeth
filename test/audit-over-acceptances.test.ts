// Over-acceptances found by the full differential audit: JETH compiled programs that solc 0.8.35
// rejects. Each is now rejected at compile time to match solc (none were miscompiles - they produced
// safe/correct or runtime-Panic code - but accepting them broke strict accept/reject parity).
//  OA0: @constant fold of a cross-signedness+width integer cast (u8(i16(-1))) - the runtime path
//       already rejected it; the const path skipped the legality check.
//  OA1: a constant out-of-bounds index on a fixed-size memory array with a struct / nested-fixed-array
//       element (xs[5].a where xs: Arr<P,2>) - value-element arrays already rejected it.
//  OA3: super.f() reaching an @external base virtual (external functions aren't in super dispatch).
//  OA4: @override on a function whose signature matches no base function (a botched override silently
//       treated as a new overload).
// NOT fixed (deliberate, sound): a @view/@pure function calling an inferred-pure internal helper - JETH
// infers purity (transitively, soundly) rather than enforcing solc's declared-mutability ceremony.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

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

describe('audit over-acceptances now reject like solc', () => {
  it('OA0: @constant cross-signedness+width cast u8(i16(-1)) is rejected', () => {
    expect(codesOf('class C { static K: u8 = u8(i16(0n - 1n)); get get(): External<u8> { return this.K; } }')).toContain('JETH070');
    // and the same illegal cast in a non-constant folded context
    expect(accepts('class C { get f(): External<u8> { return u8(i16(5n)); } }')).toBe(false);
    // valid const casts still accepted
    expect(accepts('class C { static K: u256 = u256(u8(5n)); get get(): External<u256> { return this.K; } }')).toBe(true);
    expect(accepts('class C { static K: u8 = u8(u16(7n)); get get(): External<u8> { return this.K; } }')).toBe(true);
    expect(accepts('class C { static K: i8 = i8(u8(200n)); get get(): External<i8> { return this.K; } }')).toBe(true);
  });

  it('OA1: constant OOB on a struct-element fixed memory array is rejected at compile time', () => {
    expect(codesOf('type P = {a:u256;b:u256;}; class C { get f(): External<u256> { let xs: Arr<P,2> = [P(1n,2n),P(3n,4n)]; return xs[5n].a; } }')).toContain('JETH211');
    // in-bounds access still accepted; a DYNAMIC outer array (unknown length) is NOT statically rejected
    expect(accepts('type P = {a:u256;b:u256;}; class C { get f(): External<u256> { let xs: Arr<P,2> = [P(1n,2n),P(3n,4n)]; return xs[1n].a; } }')).toBe(true);
    expect(accepts('type P = {a:u256;b:u256;}; class C { get f(ps: P[]): External<u256> { return ps[5n].a; } }')).toBe(true);
  });

  it('OA3: super.f() to an @external base virtual is rejected', () => {
    expect(codesOf('abstract class A { v: u256; @virtual f(): External<void> { this.v = this.v + 1n; } } class C extends A { @override f(): External<void> { super.f(); } }')).toContain('JETH240');
    // super to an INTERNAL base still works
    expect(accepts('abstract class A { v: u256; @virtual g(): u256 { this.v = this.v + 1n; return this.v; } } class C extends A { @override g(): u256 { return super.g() + 5n; } go(): External<u256> { return this.g(); } }')).toBe(true);
  });

  it('OA4: @override with a signature that overrides nothing is rejected (botched override)', () => {
    expect(codesOf('abstract class A { @virtual get f(x: u256): External<u256> { return x; } } class C extends A { @override get f(x: u128): External<u256> { return u256(x) + 1000n; } }')).toContain('JETH369');
    // a real override (same signature) and a real overload (no @override) still accepted
    expect(accepts('abstract class A { @virtual get f(x: u256): External<u256> { return x; } } class C extends A { @override get f(x: u256): External<u256> { return x + 1n; } }')).toBe(true);
    expect(accepts('abstract class A { @virtual get f(x: u256): External<u256> { return x; } } class C extends A { get f(x: u128): External<u256> { return u256(x); } @override get f(x: u256): External<u256> { return x; } }')).toBe(true);
  });
});
