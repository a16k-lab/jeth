// Stage-2 ban completeness (JETH481): a retired legacy decorator placed on a native `type` / `interface`
// / `enum` declaration must reject, not silently drop. TS cannot decorate these declarations
// (ts.canHaveDecorators=false, getDecorators()=[]) - the parser stores the stray `@dec` in node.modifiers
// with only a TS1206 grammar error - so `@struct type P = {..}` used to compile SILENTLY (the decorator +
// any argument were dropped, byte-identical to the decorator-free source: inert but a ban-completeness
// hole). collectBannedDecorators now scans node.modifiers on these three declaration kinds too, the
// sibling of the JETH479 VariableStatement fix. Native declarations without a stray decorator still compile.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW'];
  }
};

describe('legacy decorator ban on native type/interface/enum declarations (JETH481)', () => {
  it('a banned decorator on a `type` alias rejects JETH481', () => {
    expect(codes('@struct type P = { a: u256 }; class C { get g(): External<u256> { return 1n; } }')).toContain('JETH481');
    expect(codes('@event type E = { a: u256 }; class C { get g(): External<u256> { return 1n; } }')).toContain('JETH481');
  });

  it('a banned decorator on an `interface` rejects JETH481', () => {
    expect(codes('@contract interface I { f(): View<u256>; } class C { get g(): External<u256> { return 1n; } }')).toContain('JETH481');
    expect(codes('@external interface I { f(): View<u256>; } class C { get g(): External<u256> { return 1n; } }')).toContain('JETH481');
  });

  it('a banned decorator on an `enum` rejects JETH481', () => {
    expect(codes('@view enum E { A, B } class C { get g(): External<u256> { return 1n; } }')).toContain('JETH481');
    expect(codes('@public enum E { A, B } class C { get g(): External<u256> { return 1n; } }')).toContain('JETH481');
  });

  it('the dropped decorator ARGUMENT (a call to an undefined name) does not mask the ban', () => {
    // the whole `@constant(nope())` is dropped by TS; the ban must still fire on the name.
    expect(codes('@constant(nope()) type P = { a: u256 }; class C { get g(): External<u256> { return 1n; } }')).toContain('JETH481');
  });

  it('clean native declarations (no stray decorator) still compile', () => {
    expect(codes('type P = { a: u256 }; class C { get g(): External<u256> { let p: P = P(3n); return p.a; } }')).toEqual([]);
    expect(codes('interface I { f(): View<u256>; } class C extends I { get f(): External<u256> { return 5n; } }')).toEqual([]);
    expect(codes('enum E { A, B } class C { get g(): External<u256> { return 1n; } }')).toEqual([]);
  });
});
