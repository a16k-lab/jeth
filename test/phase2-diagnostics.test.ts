// Phase 2 analyzer diagnostics: control-flow, scoping, require/revert/errors, events.
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
const fn = (body: string, ret = 'void', mut = '@external') =>
  `class T {
  x: u256 = 0n;
  E: error<{ a: u256 }>;
  Ev: event<{ a: indexed<u256>; b: u256 }>;
  ${mut}
  f(): ${ret} {
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
    expect(codesFor(`@contract\nclass T { @error Bad(a: u256) { return; } }`)).toContain('JETH125'); // has body
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

  it('rejects emitting an event from a view/pure function', () => {
    expect(codesFor(fn('emit(Ev(1n, 2n));', 'void', '@view'))).toContain('JETH149');
    expect(codesFor(fn('emit(Ev(1n, 2n));', 'void', '@pure'))).toContain('JETH149');
  });
});
