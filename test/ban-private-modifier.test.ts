// Consistency ban: the TS `private` access modifier has no JETH meaning and was silently IGNORED (a
// function / state variable is internal by default). It is now a loud reject (JETH445), matching the
// getters/setters ban - so it is never a silent no-op. (Private visibility is intended to be expressed by
// a JS `#`-prefixed member name; the bare `private` keyword is not it.)
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};

describe('ban the bare TS `private` access modifier (JETH445)', () => {
  it('a `private` method is a loud reject, not a silent no-op', () => {
    expect(codes(`class C { private f(): u256 { return 1n; } }`)).toContain('JETH445');
  });
  it('a `private` field is rejected (never silently accepted)', () => {
    expect(codes(`class C { private y: u256; }`).length).toBeGreaterThan(0);
  });
  it('plain internal / @external / @state members are unaffected', () => {
    expect(codes(`class C { f(): u256 { return 1n; } get g(): External<u256> { return this.f(); } }`)).toEqual([]);
    expect(codes(`class C { get f(): External<u256> { return 1n; } }`)).toEqual([]);
    expect(codes(`class C { y: u256; get g(): External<u256> { return this.y; } }`)).toEqual([]);
  });
});
