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
  `@contract
class T {
  @state x: u256 = 0n;
  @error E(a: u256);
  @event Ev(@indexed a: u256, b: u256);
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

  it('rejects for-of / for-in', () => {
    expect(codesFor(fn('for (let i: u256 of xs) {}'))).toContain('JETH111');
  });

  it('rejects a local that shadows an outer-scope variable', () => {
    expect(codesFor(fn('let a: u256 = 1n; if (a > 0n) { let a: u256 = 2n; }'))).toContain('JETH068');
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
    expect(codesFor(`@contract\nclass T { @error Bad(a: u256[]); }`)).toContain('JETH127'); // dynamic-array arg deferred
    expect(codesFor(`@contract\nclass T { @error Ok(a: string); }`)).toEqual([]); // bytes/string args supported (4e-7)
    expect(codesFor(`@contract\nclass T { @error E(a: u256); @error E(b: u256); }`)).toContain('JETH128'); // dup
  });

  it('rejects malformed @event declarations and emits', () => {
    expect(codesFor(fn('emit(Missing(1n));'))).toContain('JETH147'); // unknown event
    expect(codesFor(fn('emit(Ev(1n, 2n, 3n));'))).toContain('JETH148'); // arg count
    expect(codesFor(`@contract\nclass T { @event E(@indexed a: u256, @indexed b: u256, @indexed c: u256, @indexed d: u256); }`)).toContain('JETH143'); // >3 indexed
    expect(codesFor(`@contract\nclass T { @event E(@indexed s: string); }`)).toContain('JETH207'); // indexed dynamic deferred
    // a non-indexed string event param is now allowed (Phase 4)
    expect(codesFor(`@contract\nclass T { @event E(m: string); }`)).toEqual([]);
  });

  it('rejects emitting an event from a view/pure function', () => {
    expect(codesFor(fn('emit(Ev(1n, 2n));', 'void', '@view'))).toContain('JETH149');
    expect(codesFor(fn('emit(Ev(1n, 2n));', 'void', '@pure'))).toContain('JETH149');
  });
});
