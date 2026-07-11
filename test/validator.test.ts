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

const wrap = (body: string) => `class T {
  x: u256 = 0n;
  f(): External<void> {
    ${body}
  }
}`;

describe('subset validator', () => {
  it("rejects the 'number' type", () => {
    expect(codesFor(`class T { x: number = 0n; }`)).toContain('JETH001');
  });

  it('rejects floating-point literals', () => {
    expect(codesFor(wrap('this.x = 1.5;'))).toContain('JETH003');
  });

  it('rejects async / await', () => {
    const src = `class T { async f(): External<void> {} }`;
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

  it('accepts a bare integer literal (the n-suffix requirement was lifted for solc parity)', () => {
    // A bare decimal / hex integer literal is now accepted as an integer, identical to its `n`-suffixed
    // form (JETH historically required the `n`; solc has no such distinction). A FLOAT still rejects
    // (see 'rejects floating-point literals'), as does a non-integer numeric form.
    expect(codesFor(wrap('this.x = 5;'))).toEqual([]);
    expect(codesFor(wrap('this.x = 0x2a;'))).toEqual([]);
    expect(codesFor(wrap('this.x = 1_000_000;'))).toEqual([]);
    // a hex literal whose digits contain e/E is NOT a float: the guard must not misfire (0xcafe/0xdead).
    expect(codesFor(wrap('this.x = 0xcafe;'))).toEqual([]);
    expect(codesFor(wrap('this.x = 0xdeadBEEF;'))).toEqual([]);
    expect(codesFor(wrap('this.x = 0xe;'))).toEqual([]);
    // a whole-number decimal / scientific literal IS a valid integer to solc and is accepted (1e18, 1.5e18,
    // 10e-1==1, 2.5e1==25, 1.0==1). Its exact value is computed downstream (BigInt('1e18') would throw).
    expect(codesFor(wrap('this.x = 1e18;'))).toEqual([]);
    expect(codesFor(wrap('this.x = 1.5e18;'))).toEqual([]);
    expect(codesFor(wrap('this.x = 10e-1;'))).toEqual([]);
    expect(codesFor(wrap('this.x = 2.5e1;'))).toEqual([]);
    expect(codesFor(wrap('this.x = 1.0;'))).toEqual([]);
    // a GENUINE fraction still rejects (JETH003): a non-whole rational.
    expect(codesFor(wrap('this.x = 1.5;'))).toContain('JETH003');
    expect(codesFor(wrap('this.x = 1e-1;'))).toContain('JETH003');
    expect(codesFor(wrap('this.x = 25e-1;'))).toContain('JETH003');
  });

  it('the retired `// use @decorators` pragma is rejected (JETH480); a bare native field is @state (item #9)', () => {
    // stage 2: the legacy decorator mode was removed - the pragma is a hard error.
    expect(codesFor(`// use @decorators\n@contract\nclass T { y: u256 = 0n; }`)).toContain('JETH480');
    // native (the only mode): a bare non-static field IS a @state storage variable - accepted.
    expect(codesFor(`class T { y: u256 = 0n; get g(): External<u256> { return this.y; } }`)).not.toContain('JETH045');
  });

  it('the retired @view / @contract / @state decorators are rejected (JETH481)', () => {
    const src = `@contract
class T {
  @state x: u256 = 0n;
  @view
  f(): void { this.x = 1n; }
}`;
    // mutability is inferred in native mode; @view (and @contract/@state) are banned structural spellings.
    expect(codesFor(src)).toContain('JETH481');
  });

  it('rejects a literal out of range for its type', () => {
    const src = `class T { x: u8 = 256n; }`;
    expect(codesFor(src)).toContain('JETH070');
  });

  it('rejects an integer literal assigned to a bool state var', () => {
    // soundness hole: a BigInt literal must not initialize a bool (would store a
    // non-0/1 word, corrupting the bool invariant)
    expect(codesFor(`class T { b: bool = 999n; }`)).toContain('JETH086');
  });

  it('rejects a bool literal assigned to an integer state var', () => {
    expect(codesFor(`class T { x: u256 = true; }`)).toContain('JETH087');
  });

  it('allows a local to shadow a parameter (like solc; codegen gives each a unique Yul name)', () => {
    const src = `class T {
  x: u256 = 0n;
  get f(a: u256): External<u256> { let a: u256 = 1n; return a; }
}`;
    expect(codesFor(src)).toEqual([]); // cross-scope shadow of a parameter is allowed (warning-only in solc)
  });

  it('accepts the Counter shape', () => {
    expect(codesFor(wrap('this.x += 1n;'))).toEqual([]);
  });
});
