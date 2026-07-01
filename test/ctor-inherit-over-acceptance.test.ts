// SOUNDNESS regression: three constructor/inheritance OVER-ACCEPTANCES found by the whole-surface
// differential sweep - JETH compiled programs that solc 0.8.35 rejects at compile time. Each is now a
// clean reject (matching solc), with no over-rejection introduced for valid patterns.
//   BUG 1 (JETH379): base constructor arguments given twice - `constructor() A(2n)` (which TypeScript
//     mis-parses as a phantom method named A) alongside a heritage `extends A(1n)`. JETH silently dropped
//     the A(2n) form; solc: "Base constructor arguments given twice."
//   BUG 2 (JETH369): `@override` on a function that overrides nothing (no base, or bases with unrelated
//     names). The gate previously fired only when a base declared a same-named function; solc rejects
//     unconditionally: "Function has override specified but does not override anything." (JETH369 is the
//     inverse of JETH374 = a base function overridden WITHOUT @override.)
//   BUG 3 (JETH162): `msg.value` read in a NON-payable BASE constructor even when the derived ctor is
//     @payable. Each constructor body is now checked under its own payability; solc: "msg.value can only
//     be used in payable constructors."
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};

describe('constructor / inheritance over-acceptances now reject like solc 0.8.35', () => {
  it('BUG1: base constructor arguments given twice is rejected (JETH379), across every provision variant', () => {
    // heritage extends A(1n) + modifier-style constructor() A(2n): the modifier form is parsed by TS as a
    // phantom method A, so it was silently dropped (JETH used the heritage value). All variants now reject.
    expect(
      codes('@abstract class A { @state a: u256; constructor(v: u256){ this.a = v; } } @contract class C extends A(1n) { constructor() A(2n) { } }'),
    ).toContain('JETH379');
    // same value provided twice
    expect(
      codes('@abstract class A { @state a: u256; constructor(v: u256){ this.a = v; } } @contract class C extends A(5n) { constructor() A(5n) { } }'),
    ).toContain('JETH379');
    // address argument provided twice
    expect(
      codes('@abstract class A { @state o: address; constructor(v: address){ this.o = v; } } @contract class C extends A(address(0x11n)) { constructor() A(address(0x22n)) { } }'),
    ).toContain('JETH379');
    // multi-hop grandbase: A's args given via B's heritage AND via C's modifier-style clause
    expect(
      codes('@abstract class A { @state a: u256; constructor(v: u256){ this.a = v; } } @abstract class B extends A(1n) { } @contract class C extends B { constructor() A(3n) { } }'),
    ).toContain('JETH379');
    // grandbase with an intermediate parameterized ctor: A(1n) via B, B(7n) via C heritage, A(3n) via C ctor
    expect(
      codes('@abstract class A { @state a: u256; constructor(v: u256){ this.a = v; } } @abstract class B extends A(1n) { @state b: u256; constructor(w: u256){ this.b = w; } } @contract class C extends B(7n) { constructor() A(3n) { } }'),
    ).toContain('JETH379');
    // control: a single heritage provider must STILL compile (no over-rejection)
    expect(codes('@abstract class A { @state a: u256; constructor(v: u256){ this.a = v; } } @contract class C extends A(1n) { }')).toEqual([]);
  });

  it('BOUNDARY: modifier-style base args used ALONE stay a SOUND reject (not liftable), never miscompiled', () => {
    // `constructor() A(7n)` is not valid TypeScript: TS error-recovery parses `A(7n)` as a phantom method
    // named A whose "parameter" is an empty identifier - the argument VALUE is destroyed by the parse
    // (`A(v*2)` mangles into three empty params, `A(3,4)` loses both values). The args are unrecoverable
    // from the AST, so this form can never be safely lowered (a guessed value would be a MISCOMPILE). It
    // is therefore a clean JETH379 reject that points the user at the fully-supported heritage form
    // `extends A(args)`, even when it is the ONLY provider (no heritage args to conflict with). solc
    // ACCEPTS these (modifier-style base args are its idiom), so JETH is a sound over-rejection here - a
    // deliberate, fail-safe boundary of the TS-subset, never wrong bytes.
    // single base with a parameterized ctor, args only via the modifier form -> the required-args check fires
    expect(
      codes('@abstract class A { @state x: u256; constructor(v: u256){ this.x = v; } } @contract class C extends A { constructor() A(7n) { } }'),
    ).toContain('JETH379');
    // a TYPED phantom (`A(v: u256)`) is treated as a real member, so the base is left without args -> reject
    expect(
      codes('@abstract class A { @state x: u256; constructor(v: u256){ this.x = v; } } @contract class C extends A { constructor() A(v: u256) { } }'),
    ).toContain('JETH379');
    // a no-arg phantom `A()` against a parameterized base -> reject (never accepted with a defaulted arg)
    expect(
      codes('@abstract class A { @state x: u256; constructor(v: u256){ this.x = v; } } @contract class C extends A { constructor() A() { } }'),
    ).toContain('JETH379');
    // control: the SAME program expressed via the supported heritage form compiles cleanly (the lift path)
    expect(codes('@abstract class A { @state x: u256; constructor(v: u256){ this.x = v; } } @contract class C extends A(7n) { constructor() { } }')).toEqual([]);
  });

  it('BUG2: @override that overrides nothing is rejected (JETH369) - no base, and base lacking the fn', () => {
    expect(codes('@contract class C { @override @external f(): u256 { return 42n; } }')).toContain('JETH369');
    expect(
      codes('@abstract class A { @state x: u256; } @contract class C extends A { @override @external f(): u256 { return 42n; } }'),
    ).toContain('JETH369');
  });

  it('BUG3: msg.value in a non-payable base constructor is rejected (JETH162), even with a payable derived ctor', () => {
    expect(
      codes('@abstract class A { @state v: u256; constructor(){ this.v = msg.value; } } @contract class C extends A { @payable constructor(){ } }'),
    ).toContain('JETH162');
    // deeper: a non-payable MIDDLE base reading msg.value is still caught.
    expect(
      codes('@abstract class A { @state v: u256; constructor(){ this.v = msg.value; } } @abstract class B extends A { } @contract class C extends B { @payable constructor(){ } }'),
    ).toContain('JETH162');
  });

  it('valid inheritance / constructor / override / payable patterns still compile (no over-rejection)', () => {
    // single heritage base-arg provider
    expect(codes('@abstract class A { @state a: u256; constructor(v: u256){ this.a = v; } } @contract class C extends A(1n) { }')).toEqual([]);
    // valid @override of a @virtual base function
    expect(codes('@abstract class A { @virtual f(): u256 { return 1n; } } @contract class C extends A { @override f(): u256 { return 2n; } }')).toEqual([]);
    // payable base + payable derived reading msg.value
    expect(codes('@abstract class A { @state v: u256; @payable constructor(){ this.v = msg.value; } } @contract class C extends A { @payable constructor(){ } }')).toEqual([]);
    // msg.sender (NOT payability-gated) in a non-payable base + payable derived
    expect(codes('@abstract class A { @state o: address; constructor(){ this.o = msg.sender; } } @contract class C extends A { @payable constructor(){ } }')).toEqual([]);
    // a single payable constructor reading msg.value
    expect(codes('@contract class C { @state v: u256; @payable constructor(){ this.v = msg.value; } }')).toEqual([]);
    // a 3-level chain with base args
    expect(codes('@abstract class A { @state a: u256; constructor(x: u256){ this.a = x; } } @abstract class B extends A(1n) { @state b: u256; constructor(y: u256){ this.b = y; } } @contract class C extends B(2n) { constructor() { } }')).toEqual([]);
    // a real method whose name matches a base but is a genuine function (typed params) is not mistaken for base args
    expect(codes('@abstract class A { @state a: u256; constructor(v: u256){ this.a = v; } @external @view A(z: u256): u256 { return z; } } @contract class C extends A(1n) { }')).toEqual([]);
    // same-name / different-signature botched override still rejects (unchanged)
    expect(codes('@abstract class A { @virtual g(x: u256): u256 { return x; } } @contract class C extends A { @override g(): u256 { return 1n; } }').length).toBeGreaterThan(0);
  });
});
