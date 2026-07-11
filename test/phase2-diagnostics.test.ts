// Phase 2 analyzer diagnostics: control-flow, scoping, require/revert/errors, events.
// Native mode: mutability is INFERRED, so a plain writer is `f(): External<void>`. Every control-flow /
// scoping / require / revert / error / event rule below still fires natively (JETH113/110/111/072/068/
// 120-130/143-148). Two legacy-only shapes retarget: an `@error` declaration with a BODY (JETH125) is
// not expressible natively (errors are `X: error<{..}>` fields), and "emit from a @view/@pure function"
// (JETH149) has no declared-mutability form - the native read-only context is a `get` accessor, whose
// emit is JETH043.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';

function codesFor(source: string): string[] {
  try {
    compile(source, { fileName: 't.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}
const fn = (body: string) =>
  `class T {
  x: u256 = 0n;
  E: error<{ a: u256 }>;
  Ev: event<{ a: indexed<u256>; b: u256 }>;
  f(): External<void> {
    ${body}
  }
}`;
// the native read-only context (a `get` accessor) - the analog of a legacy @view/@pure function.
const getFn = (body: string) =>
  `class T {
  x: u256 = 0n;
  Ev: event<{ a: indexed<u256>; b: u256 }>;
  get f(): External<u256> {
    ${body}
  }
}`;

describe('Phase 2 diagnostics', () => {
  it('rejects break/continue outside a loop', () => {
    expect(codesFor(fn('break;'))).toContain('JETH113');
    expect(codesFor(fn('continue;'))).toContain('JETH113');
  });

  it('accepts break/continue inside a loop', () => {
    expect(codesFor(fn('for (let i: u256 = 0n; i < 5n; i += 1n) { break; }'))).toEqual([]);
  });

  it('rejects a non-bool condition', () => {
    expect(codesFor(fn('if (1n) { this.x = 1n; }'))).toContain('JETH110');
    expect(codesFor(fn('while (this.x) {}'))).toContain('JETH110');
  });

  it('rejects for-in, and a type-annotated for-of binding (for-of itself is supported)', () => {
    expect(codesFor(fn('for (const k in this.x) {}'))).toContain('JETH111');
    expect(codesFor(fn('for (let i: u256 of xs) {}'))).toContain('JETH116');
  });

  it('allows a nested local to shadow an outer-scope variable (like solc), but rejects same-scope redeclaration', () => {
    expect(codesFor(fn('let a: u256 = 1n; if (a > 0n) { let a: u256 = 2n; }'))).toEqual([]); // cross-scope shadow: allowed
    expect(codesFor(fn('let a: u256 = 1n; let a: u256 = 2n;'))).toContain('JETH068'); // same-scope redecl: rejected
  });

  it('allows disjoint sibling blocks to reuse a name', () => {
    expect(codesFor(fn('{ let a: u256 = 1n; } { let a: u256 = 2n; }'))).toEqual([]);
  });

  it('drops a for-init variable after the loop (not visible)', () => {
    expect(codesFor(fn('for (let i: u256 = 0n; i < 3n; i += 1n) {} this.x = i;'))).toContain('JETH072');
  });

  it('rejects require/revert arity and bad reasons', () => {
    expect(codesFor(fn('require();'))).toContain('JETH120');
    expect(codesFor(fn('require(this.x);'))).toContain('JETH121'); // non-bool condition
    expect(codesFor(fn('revert(1n, 2n);'))).toContain('JETH122');
    expect(codesFor(fn('revert(1n);'))).toContain('JETH123'); // not a string/error ctor
    expect(codesFor(fn('revert(this.x);'))).toContain('JETH206'); // u256 is not a valid Error(string) message
  });

  it('rejects unknown custom error and arg-count mismatch', () => {
    expect(codesFor(fn('revert(Unknown(1n));'))).toContain('JETH129');
    expect(codesFor(fn('revert(E(1n, 2n));'))).toContain('JETH130');
  });

  it('rejects malformed @error declarations', () => {
    // the legacy `@error Bad(...) { body }` form is banned (JETH481) - native errors are `X: error<{..}>`
    // fields and cannot carry a body, so the old JETH125 "error decl has a body" rule is unreachable.
    expect(codesFor(`class T { @error Bad(a: u256) { return; } }`)).toContain('JETH481');
    expect(codesFor(`class T { Ok: error<{ a: Arr<u256, 3> }>; }`)).toEqual([]); // static fixed-array arg now supported (inline head)
    expect(codesFor(`type D = { s: string; };\nclass T { Bad: error<{ d: D }>; }`)).toEqual([]); // a DYNAMIC struct error arg is now supported (revert data byte-identical to solc)
    expect(codesFor(`class T { Ok: error<{ a: u256[] }>; }`)).toEqual([]); // dynamic-array args supported (G3)
    expect(codesFor(`class T { Ok: error<{ a: string }>; }`)).toEqual([]); // bytes/string args supported (4e-7)
    expect(codesFor(`class T { E: error<{ a: u256 }>; E: error<{ b: u256 }>; }`)).toContain('JETH128'); // dup
  });

  it('rejects malformed @event declarations and emits', () => {
    expect(codesFor(fn('emit(Missing(1n));'))).toContain('JETH147'); // unknown event
    expect(codesFor(fn('emit(Ev(1n, 2n, 3n));'))).toContain('JETH148'); // arg count
    expect(
      codesFor(
        `class T { E: event<{ a: indexed<u256>; b: indexed<u256>; c: indexed<u256>; d: indexed<u256> }>; }`,
      ),
    ).toContain('JETH143'); // >3 indexed
    // an indexed dynamic VALUE-element array is now allowed (keccak topic of the element words)
    expect(codesFor(`class T { E: event<{ a: indexed<u256[]> }>; }`)).toEqual([]);
    // an indexed FIXED array / static struct is now supported (keccak topic); a supported DYNAMIC struct too
    expect(codesFor(`class T { E: event<{ a: indexed<Arr<u256,2>> }>; }`)).toEqual([]);
    expect(codesFor(`type D = { s: string; };\nclass T { E: event<{ d: indexed<D> }>; }`)).toEqual([]);
    // a dynamic struct with a NESTED dynamic struct field is now supported (indexed topic = keccak of
    // the recursively flattened payload; byte-identical to solc, verified in fix-all-divergences.test.ts)
    expect(
      codesFor(
        `type I = { p: u256; s: string; };\ntype D2 = { x: u256; i: I; };\nclass T { E: event<{ d: indexed<D2> }>; }`,
      ),
    ).toEqual([]);
    // an indexed bytes/string event param is now allowed (keccak topic, G4)
    expect(codesFor(`class T { E: event<{ s: indexed<string>; v: u256 }>; }`)).toEqual([]);
    // a non-indexed string event param is allowed (Phase 4)
    expect(codesFor(`class T { E: event<{ m: string }>; }`)).toEqual([]);
  });

  it('rejects emitting an event from a read-only (get) accessor', () => {
    // Native analog of the legacy "emit from a @view/@pure function" rule (JETH149). Native mode infers
    // mutability, so the only DECLARED read-only context is a `get` accessor; emitting inside one is
    // JETH043 ("a getter is read-only"). The legacy @view and @pure spellings both collapse to this.
    expect(codesFor(getFn('emit(Ev(1n, 2n)); return 0n;'))).toContain('JETH043');
  });
});
