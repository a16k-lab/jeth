// Cross-kind TOP-LEVEL name collision (JETH272 over ALL top-level classes): solc puts every file-level
// declaration - contract, abstract contract, library, interface, struct, enum, UDVT, file-level
// error/event - in ONE namespace and rejects every same-name pair as "Identifier already declared"
// (witnessed per kind pair on solc 0.8.35). JETH previously checked only the DEPLOYED contract's own
// name (the JETH272 gate in analyzeContract), so `interface I {} class I {} class C extends I {}`
// silently ACCEPTED - and linearize() resolves a base name via interfaceClassByName BEFORE classByName,
// so the interface shadowed the class, leaving `class I` dead code (an over-acceptance with wrong-base
// risk). checkClassTypeNameCollisions now runs the same check over ANY top-level class (deploy
// candidate, bases consumed or unconsumed, abstract contracts, libraries) without touching the
// linearize resolution order: the reject makes the shadowing unreachable.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

describe('cross-kind top-level name collisions (JETH272, solc "Identifier already declared" parity)', () => {
  it('(a) an interface sharing a CONSUMED base class name rejects (the pinned over-acceptance)', () => {
    // Pre-fix this ACCEPTED: class I was excluded from deploy candidates (extended base) and the
    // deployed-name-only gate never saw it; `extends I` silently bound to the interface.
    expect(codes(`interface I { f(): u256; } class I { g(): External<u256> { this.s = 41n; return this.s; } s: u256; } class C extends I { f(): External<u256> { this.t = 7n; return this.t; } t: u256; }`)).toContain('JETH272');
  });

  it('(b) an interface sharing an ABSTRACT base class name rejects', () => {
    // solc mirror: interface I + abstract contract I + contract C is I -> "Identifier already declared".
    expect(codes(`interface I { f(): u256; } abstract class I { abstract f(): External<u256>; } class C extends I { f(): External<u256> { this.t = 7n; return this.t; } t: u256; }`)).toContain('JETH272');
  });

  it('(c) a type-alias struct sharing a class name rejects, consumed and unconsumed', () => {
    // solc mirror: struct P + contract P (+ contract C [is P]) -> "Identifier already declared" (witnessed
    // for both the consumed and the unconsumed spelling).
    expect(codes(`type P = { a: u256 }; class P { s: u256; g(): External<u256> { this.s = 41n; return this.s; } } class C extends P { f(): External<u256> { return 7n; } }`)).toContain('JETH272');
    expect(codes(`type P = { a: u256 }; abstract class P { s: u256; } class C { f(): External<u256> { return 7n; } }`)).toContain('JETH272');
    expect(codes(`type P = { a: u256 }; class P { s: u256; } class C { f(): External<u256> { return 7n; } }`)).toContain('JETH272');
  });

  it('(d) an enum sharing a class name rejects', () => {
    // solc mirror: enum E + contract E -> "Identifier already declared" (witnessed consumed + unconsumed).
    expect(codes(`enum E { A, B } class E { s: u256; } class C extends E { f(): External<u256> { return 7n; } }`)).toContain('JETH272');
    expect(codes(`enum E { A, B } abstract class E { s: u256; } class C { f(): External<u256> { return 7n; } }`)).toContain('JETH272');
  });

  it('a file-level error/event sharing a class name rejects (solc file-level forms collide too)', () => {
    // solc mirror: file-level `error Boom(...)` / `event Ping(...)` + contract of the same name ->
    // "Identifier already declared" (witnessed both kinds).
    expect(codes(`type Boom = error<{ x: u256 }>; class Boom { s: u256; } class C extends Boom { f(): External<u256> { return 7n; } }`)).toContain('JETH272');
    expect(codes(`type Ping = event<{ x: u256 }>; class Ping { s: u256; } class C extends Ping { f(): External<u256> { return 7n; } }`)).toContain('JETH272');
  });

  it('a type sharing a LIBRARY name rejects (solc: library shares the file-level namespace)', () => {
    // solc mirror: struct L + library L / interface L + library L -> "Identifier already declared".
    expect(codes(`type L = { a: u256 }; static class L { static h(x: u256): u256 { return x + 1n; } } class C { f(): External<u256> { return L.h(6n); } }`)).toContain('JETH272');
    expect(codes(`interface L { f(): u256; } static class L { static h(x: u256): u256 { return x + 1n; } } class C { f(): External<u256> { return L.h(6n); } }`)).toContain('JETH272');
  });

  it('(e) the retired DECORATOR spelling is a JETH481 ban, not JETH272 (the pre-pass fires first)', () => {
    const dec = codes(`@interface class I { f(): u256; } @abstract class I2 { } @contract class C extends I { f(): External<u256> { return 7n; } }`);
    expect(dec).toContain('JETH481');
    expect(dec).not.toContain('JETH272');
  });

  it('(f) CONTROL: a non-colliding interface base still compiles clean', () => {
    expect(codes(`interface I { f(): u256; } class C extends I { f(): External<u256> { this.t = 7n; return this.t; } t: u256; }`)).toEqual([]);
  });

  it('(g) CONTROL: the deployed-name collision still rejects as a single JETH272', () => {
    const got = codes(`interface C { m(x: u256): View<u256>; } class C { get f(): External<u256> { return 1n; } }`);
    expect(got).toContain('JETH272');
    // the analyze()-level check and the analyzeContract gate emit the SAME code + message + node for the
    // deployed name; the DiagnosticBag exact-duplicate collapse must keep exactly one.
    expect(got.filter((c) => c === 'JETH272')).toHaveLength(1);
  });
});
