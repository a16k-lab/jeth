// Phase 0: the subset validator must reject non-EVM constructs with diagnostics.
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

const wrap = (body: string) => `@contract
class T {
  @state x: u256 = 0n;
  @external
  f(): void {
    ${body}
  }
}`;

describe('subset validator', () => {
  it("rejects the 'number' type", () => {
    expect(codesFor(`@contract\nclass T { @state x: number = 0n; }`)).toContain('JETH001');
  });

  it('rejects floating-point literals', () => {
    expect(codesFor(wrap('this.x = 1.5;'))).toContain('JETH003');
  });

  it('rejects async / await', () => {
    const src = `@contract\nclass T { @external async f(): void {} }`;
    expect(codesFor(src)).toContain('JETH020');
  });

  it('rejects a non-interface-call try block and throw', () => {
    // try/catch is supported ONLY around a high-level interface call (Feature 2). A try whose first
    // statement is not such a call is rejected by the analyzer (JETH361), not the blanket MVP gate.
    expect(codesFor(wrap('try { this.x = 1n; } catch (e) {}'))).toContain('JETH361');
    expect(codesFor(wrap('throw 1n;'))).toContain('JETH025');
  });

  it("rejects 'new', typeof, delete, instanceof", () => {
    expect(codesFor(wrap('let y: u256 = new Foo();'))).toContain('JETH023');
    expect(codesFor(wrap('let y: u256 = typeof this.x;'))).toContain('JETH030');
  });

  it('rejects a plain numeric literal in favor of BigInt', () => {
    expect(codesFor(wrap('this.x = 5;'))).toContain('JETH071');
  });

  it('rejects an unmarked contract field', () => {
    expect(codesFor(`@contract\nclass T { y: u256 = 0n; }`)).toContain('JETH045');
  });

  it('rejects @view functions that write storage', () => {
    const src = `@contract
class T {
  @state x: u256 = 0n;
  @view
  f(): void { this.x = 1n; }
}`;
    expect(codesFor(src)).toContain('JETH054');
  });

  it('rejects a literal out of range for its type', () => {
    const src = `@contract\nclass T { @state x: u8 = 256n; }`;
    expect(codesFor(src)).toContain('JETH070');
  });

  it('rejects an integer literal assigned to a bool state var', () => {
    // soundness hole: a BigInt literal must not initialize a bool (would store a
    // non-0/1 word, corrupting the bool invariant)
    expect(codesFor(`@contract\nclass T { @state b: bool = 999n; }`)).toContain('JETH086');
  });

  it('rejects a bool literal assigned to an integer state var', () => {
    expect(codesFor(`@contract\nclass T { @state x: u256 = true; }`)).toContain('JETH087');
  });

  it('allows a local to shadow a parameter (like solc; codegen gives each a unique Yul name)', () => {
    const src = `@contract
class T {
  @state x: u256 = 0n;
  @external f(a: u256): u256 { let a: u256 = 1n; return a; }
}`;
    expect(codesFor(src)).toEqual([]); // cross-scope shadow of a parameter is allowed (warning-only in solc)
  });

  it('accepts the Counter shape', () => {
    expect(codesFor(wrap('this.x += 1n;'))).toEqual([]);
  });
});
