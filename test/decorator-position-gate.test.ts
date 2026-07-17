// DECORATOR-POSITION GATE (JETH490). A decorator in CLASS / FIELD / PARAM position that is (a) an
// UNKNOWN name (notably a TYPO of a real decorator - `@storag('ns')`, `@diamon('array')`,
// `@nonReentrent`), (b) a KNOWN name in an ILLEGAL position (@nonReentrant / @virtual / @override on a
// class, @nonReentrant / @diamond / @using / @modifier on a field, ANY decorator on a parameter), or
// (c) a MIS-SHAPED decorator (`@a.b`, `@a[0]`) used to be SILENTLY DROPPED: a `@storag('ns')` lost the
// storage namespace, a `@diamon('array')` lost the whole diamond, with NO diagnostic. It is now a loud
// reject (JETH490), the mirror of the already-closed METHOD position (JETH329). The legal (decorator x
// position) pairs stay byte-identical; the event/error-field (JETH353), method (JETH329) and retired
// (JETH481) territories are untouched. Each buggy cell below is pinned with the exact pre-fix
// SILENT-ACCEPT it now rejects.
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
const accepts = (src: string): boolean => codes(src).length === 0;
const G = ' get gg(): External<u256> { return 1n; }';

describe('JETH490: CLASS-position decorator gate', () => {
  // Pre-fix these ALL silently ACCEPTED (byte-identical to a bare `class C {}`); now each rejects.
  it('unknown name @foo on a class rejects', () => {
    expect(codes(`@foo class C {${G} }`)).toContain('JETH490');
  });
  it('TYPO @storag (of @storage) rejects instead of silently losing the namespace', () => {
    expect(codes(`@storag('a.b') class C {${G} }`)).toContain('JETH490');
  });
  it('TYPO @diamon (of @diamond) rejects instead of silently losing the diamond', () => {
    expect(codes(`@diamon('array') class C {${G} }`)).toContain('JETH490');
  });
  it('known name in the wrong position: @nonReentrant / @virtual / @override / @modifier / @anonymous on a class reject', () => {
    for (const d of ['nonReentrant', 'virtual', 'override', 'modifier', 'anonymous']) {
      expect(codes(`@${d} class C {${G} }`)).toContain('JETH490');
    }
  });
  it('mis-shaped @a.b on a class rejects', () => {
    expect(codes(`@a.b class C {${G} }`)).toContain('JETH490');
  });

  // Legal class decorators are NOT flagged by the gate (JETH490 absent). Semantics unchanged.
  it('legal class decorators (@storage/@proxy/@facet/@using) are not flagged', () => {
    expect(accepts(`@storage('a.b') class C { x: u256;${G} }`)).toBe(true);
    expect(accepts(`@proxy class C {}`)).toBe(true);
    expect(accepts(`@facet class C { x: u256;${G} }`)).toBe(true);
    expect(
      accepts(
        `static class L { inc(self: u256): u256 { return self+1n; } } @using(L) class C { x: u256; f(): External<void>{ this.x = this.x.inc(); } }`,
      ),
    ).toBe(true);
  });
  it('@diamond / @beacon / @uups names are recognized (a semantic error, never JETH490)', () => {
    // Malformed on purpose: the analyzer/diamond gate fires its own code; the NAME is never JETH490.
    expect(codes(`@diamond('array') class C { x: u256;${G} }`)).not.toContain('JETH490');
    expect(codes(`@beacon class C {}`)).not.toContain('JETH490');
    expect(codes(`@proxy @uups class C {}`)).not.toContain('JETH490');
  });
});

describe('JETH490: FIELD-position decorator gate', () => {
  // Pre-fix these silently ACCEPTED (byte-identical to the bare field); now each rejects.
  it('unknown name @foo on a field rejects', () => {
    expect(codes(`class C { @foo x: u256;${G} }`)).toContain('JETH490');
  });
  it('known name in the wrong position: @nonReentrant / @diamond / @using / @modifier on a field reject', () => {
    expect(codes(`class C { @nonReentrant x: u256;${G} }`)).toContain('JETH490');
    expect(codes(`class C { @diamond('array') x: u256;${G} }`)).toContain('JETH490');
    expect(codes(`static class L{f(self:u256):u256{return self;}} class C { @using(L) x: u256;${G} }`)).toContain('JETH490');
    expect(codes(`class C { @modifier x: u256;${G} }`)).toContain('JETH490');
  });

  // Legal field decorators are NOT flagged.
  it('legal field decorators (@storage on a field, @override on a getter-var) are not flagged', () => {
    expect(accepts(`class C { @storage('a.b') x: u256; get g(): External<u256>{return this.x;} }`)).toBe(true);
    expect(accepts(`interface I { g(): View<u256>; } class C extends I { @override g: Visible<u256>; }`)).toBe(true);
  });
  it('@virtual on a field is NOT flagged by the gate (a solc `public virtual x` name)', () => {
    // The gate lets @virtual through at field position; whatever the analyzer then does, it is not JETH490.
    expect(codes(`class C { @virtual x: u256;${G} }`)).not.toContain('JETH490');
  });
});

describe('JETH490: PARAM-position decorator gate', () => {
  // Pre-fix a parameter decorator was silently ACCEPTED; now ANY parameter decorator rejects.
  it('@foo on a getter parameter rejects', () => {
    expect(codes(`class C { x:u256; get gg(@foo v: u256): External<u256> { return this.x+v; } }`)).toContain('JETH490');
  });
  it('@foo on a method parameter rejects', () => {
    expect(codes(`class C { f(@foo v: u256): External<void> {} }`)).toContain('JETH490');
  });
  it('@foo on a constructor parameter rejects', () => {
    expect(codes(`class C { x: u256; constructor(@foo v: u256) { this.x = v; }${G} }`)).toContain('JETH490');
  });
});

describe('JETH490: adjacent territories are untouched (no double-report / no code change)', () => {
  it('event-field stray decorator stays JETH353 (not JETH490)', () => {
    const c = codes(`class C { @foo E: event<{ a: u256 }>;${G} }`);
    expect(c).toContain('JETH353');
    expect(c).not.toContain('JETH490');
  });
  it('@anonymous on an event field still accepts', () => {
    expect(accepts(`class C { @anonymous E: event<{ a: u256 }>;${G} }`)).toBe(true);
  });
  it('method-position unknown decorator stays JETH329 (not JETH490)', () => {
    const c = codes(`class C { @foo f(): External<void> {} }`);
    expect(c).toContain('JETH329');
    expect(c).not.toContain('JETH490');
    const g = codes(`class C { x:u256; @foo get gg(): External<u256> { return this.x; } }`);
    expect(g).toContain('JETH329');
    expect(g).not.toContain('JETH490');
  });
  it('retired legacy decorators stay JETH481 (not JETH490)', () => {
    // A banned name on a class / field / parameter is JETH481 only - never double-reported as JETH490.
    const cls = codes(`@contract class C {${G} }`);
    expect(cls).toContain('JETH481');
    expect(cls).not.toContain('JETH490');
    const fld = codes(`class C { @state x: u256;${G} }`);
    expect(fld).toContain('JETH481');
    expect(fld).not.toContain('JETH490');
    const par = codes(`class C { x:u256; get gg(@indexed v: u256): External<u256> { return this.x+v; } }`);
    expect(par).toContain('JETH481');
    expect(par).not.toContain('JETH490');
  });
});
