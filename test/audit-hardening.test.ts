// The 2026-07-14 whole-surface hard audit found 6 OVER-ACCEPTANCE bar violations (a program JETH accepted
// that solc rejects). Each is pinned here as a JETH reject; the sibling that must STILL compile is the
// control. (The one MISCOMPILE the audit found - funcref ==/!= of two byte-identical-body functions - is a
// separate design decision and is not addressed here.)
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';

const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e;
  }
};
const rejects = (src: string) => expect(codes(src).length).toBeGreaterThan(0);
const accepts = (src: string) => expect(codes(src)).toEqual([]);

describe('AUDIT OA-1: a different-size fixed-array alias in a local-decl init (solc: not convertible)', () => {
  it('rejects small->large and large->small; same-size alias and correct-size literal still accept', () => {
    // The alias would let an in-bounds index read/write PAST the source image (an OOB memory leak).
    rejects(`class C { get f(): External<u256> { let a: Arr<u256,2> = [1n,2n]; let b: Arr<u256,3> = a; return b[2]; } }`);
    rejects(`class C { get f(): External<u256> { let a: Arr<u256,3> = [1n,2n,3n]; let b: Arr<u256,2> = a; return b[0]; } }`);
    accepts(`class C { get f(): External<u256> { let a: Arr<u256,2> = [5n,6n]; let b: Arr<u256,2> = a; return b[1]; } }`);
    accepts(`class C { get f(): External<u256> { let b: Arr<u256,3> = [1n,2n,3n]; return b[2]; } }`);
  });
});

describe('AUDIT OA-2..5: a library (static class) may not declare a special entry, @virtual, or @override', () => {
  const G = `\nclass C { get g(): External<u256> { return L.f(1n); } }`;
  it('rejects library receive/fallback/@virtual/@override; a plain library fn still accepts', () => {
    rejects(`static class L { receive() {} f(a: u256): u256 { return a; } }${G}`);
    rejects(`static class L { fallback() {} f(a: u256): u256 { return a; } }${G}`);
    rejects(`static class L { fallback(input: bytes): bytes { return input; } f(a: u256): u256 { return a; } }${G}`);
    rejects(`static class L { @virtual f(a: u256): u256 { return a; } }${G}`);
    rejects(`static class L { @override f(a: u256): u256 { return a; } }${G}`);
    accepts(`static class L { f(a: u256): u256 { return a; } }${G}`);
  });
});

describe('AUDIT OA-6: a decorator written in a non-identifier shape is not silently dropped', () => {
  it('a property-access decorator on a method rejects (would else strip the guard); paren form still applies it', () => {
    // @a.nonReentrant used to be silently dropped, yielding an UNGUARDED contract with no diagnostic.
    rejects(`class C { s: u256; @a.nonReentrant m(v: u256): External<void> { this.s = v; } }`);
    // @(nonReentrant) is the parenthesized form of @nonReentrant: it must APPLY the guard, not drop it.
    // Prove the guard is installed by byte-comparing to the bare @nonReentrant form.
    const g = compile(`class C { s: u256; @nonReentrant m(v: u256): External<void> { this.s = v; } }`, { fileName: 'C.jeth' }).creationBytecode;
    const p = compile(`class C { s: u256; @(nonReentrant) m(v: u256): External<void> { this.s = v; } }`, { fileName: 'C.jeth' }).creationBytecode;
    const plain = compile(`class C { s: u256; m(v: u256): External<void> { this.s = v; } }`, { fileName: 'C.jeth' }).creationBytecode;
    expect(p).toBe(g); // paren form == guarded form
    expect(p).not.toBe(plain); // and NOT the unguarded form
    accepts(`class C { s: u256; @nonReentrant m(v: u256): External<void> { this.s = v; } }`); // control
  });
});
