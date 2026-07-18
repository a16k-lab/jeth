// UNEXTENDED-ABSTRACT (solc parity): solc type-checks EVERY contract a file declares, whether or not
// anything deploys or derives from it. JETH analyzes only the ROUTE class + its linearization, so an
// `abstract class` that nothing extends was DEAD CODE that reached no type checker at all: every unknown
// or misspelled type in its signatures was silently accepted while solc rejects the twin. That is an
// OVER-ACCEPTANCE (JETH accepts a program solc rejects), closed here for the SIGNATURE surface.
//
// SCOPE - signatures only (fields, parameters, returns), deliberately NOT bodies. An unextended abstract
// base legitimately holds code that only makes sense in a deriving contract, and re-running full body
// analysis over a class with no linearization would over-reject a long tail of LEGAL bases. The
// over-rejection guard at the bottom is the load-bearing half of this file: it pins that 30 real
// abstract-base shapes still compile AND stay byte-identical.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
/** The diagnostic codes of a rejected compile ([] when it is accepted). */
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    return ((e as { diagnostics?: { code: string }[] }).diagnostics ?? []).map((d) => d.code);
  }
};
const accepts = (src: string): boolean => codes(src).length === 0;
const creation = (src: string): string => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const solcAccepts = (src: string, name = 'C'): boolean => {
  try {
    compileSolidity(SPDX + src, name);
    return true;
  } catch {
    return false;
  }
};

// A deployable sibling: the unit MUST have one, or the abstract-only JETH041 gate fires first (an
// abstract-only unit emits no bytecode, so there is no artifact to prove byte-identical - that gate stays).
const DEPLOYABLE = `class C { get z(): External<u256> { return 7n; } }`;
const SOL_DEPLOYABLE = `contract C { function z() external pure returns (uint256) { return 7; } }`;

describe('an unextended abstract class is type-checked (solc parity)', () => {
  it('an UNDEFINED type in an unextended abstract base rejects (JETH013), like solc', () => {
    // return type
    expect(codes(`abstract class B { get a(): NoSuchType { return 1n; } }\n${DEPLOYABLE}`)).toContain('JETH013');
    // field type
    expect(codes(`abstract class B { f: Nope; }\n${DEPLOYABLE}`)).toContain('JETH013');
    // parameter type
    expect(codes(`abstract class B { m(x: Nope): u256 { return 1n; } }\n${DEPLOYABLE}`)).toContain('JETH013');
    // a SOLIDITY spelling that is not a JETH type: `uint256` is `u256`, `Map` is `mapping`
    expect(codes(`abstract class B { get a(): uint256 { return 1n; } }\n${DEPLOYABLE}`)).toContain('JETH013');
    expect(codes(`abstract class B { m: Map<address, u256>; }\n${DEPLOYABLE}`)).toContain('JETH013');

    // THE SOLC WITNESSES for the rule above: an undefined type is an error in an abstract contract that
    // nothing extends, exactly as it is in a deployed one.
    expect(solcAccepts(`abstract contract B { Nope f; } ${SOL_DEPLOYABLE}`)).toBe(false);
    expect(solcAccepts(`abstract contract B { uint256 f; } ${SOL_DEPLOYABLE}`)).toBe(true);
  });

  it('NON-VACUITY: the identical base is rejected whether it is EXTENDED or not', () => {
    // the extended twin always rejected (it is in the route's linearization) - proving the assertion
    // above is the NEW unextended path, not the old chain walk.
    expect(codes(`abstract class B { f: Nope; }\nclass C extends B { get z(): External<u256> { return 7n; } }`)).toContain('JETH013');
    expect(codes(`abstract class B { f: Nope; }\n${DEPLOYABLE}`)).toContain('JETH013');
    // and the CONTROL: the same base with a LEGAL type accepts on both paths (so the reject above is
    // driven by the type, not merely by the presence of an unextended abstract class).
    expect(accepts(`abstract class B { f: u256; }\nclass C extends B { get z(): External<u256> { return 7n; } }`)).toBe(true);
    expect(accepts(`abstract class B { f: u256; }\n${DEPLOYABLE}`)).toBe(true);
  });

  it('a stray abstract is checked on a MULTI-CONTRACT file too (every route)', () => {
    expect(
      codes(`abstract class B { f: Nope; }\nclass C { get z(): External<u256> { return 7n; } }\nclass D2 { get y(): External<u256> { return 8n; } }`),
    ).toContain('JETH013');
    // control: both deployables + a legal stray still compile, and BOTH artifacts are emitted
    const r = compile(
      `abstract class B { f: u256; }\nclass C { get z(): External<u256> { return 7n; } }\nclass D2 { get y(): External<u256> { return 8n; } }`,
      { fileName: 'C.jeth' },
    );
    expect(r.contracts?.length).toBe(2);
  });

  it('the abstract-ONLY unit is untouched by this work (it was ALREADY type-checked)', () => {
    // SCOPE PIN. A unit with NO deployable takes the non-deployable path, which already resolved its
    // types - the gap closed here is narrower: an abstract class that is a SIBLING of a deployable and
    // that nothing extends, which only the route chain ever visited.
    expect(codes(`abstract class B { f: Nope; }`)).toContain('JETH013'); // already rejected before this change
    // a single abstract-only unit still compiles to NO bytecode (there is no artifact to prove
    // byte-identical, which is why the abstract-leaf gate stays); two or more leaves stay JETH041.
    expect(compile(`abstract class B { f: u256; }`, { fileName: 'C.jeth' }).creationBytecode).toBe('');
    expect(codes(`abstract class B { f: u256; }\nabstract class D { g: u256; }`)).toContain('JETH041');
  });

  it('an UNDEFINED type in an event/error FIELD, a CONSTRUCTOR param, or a @modifier param rejects (JETH013), like solc', () => {
    // These four member surfaces were the HOLE in the first pass: an event/error field's parameter types
    // (inside `event<{...}>` / `error<{...}>`), a constructor's parameter types, and a @modifier's
    // parameter types reached no type checker on a stray abstract base, so an undefined type there was
    // silently accepted while solc rejects the twin (an over-acceptance).
    // event field param (through the `indexed<...>` unwrap):
    expect(codes(`abstract class B { E: event<{ x: indexed<Nope> }>; }\n${DEPLOYABLE}`)).toContain('JETH013');
    // error field param:
    expect(codes(`abstract class B { Bad: error<{ n: Nope }>; }\n${DEPLOYABLE}`)).toContain('JETH013');
    // constructor param:
    expect(codes(`abstract class B { constructor(x: Nope) {} }\n${DEPLOYABLE}`)).toContain('JETH013');
    // @modifier param:
    expect(codes(`abstract class B { @modifier only(x: Nope) { _; } }\n${DEPLOYABLE}`)).toContain('JETH013');

    // THE CONTROLS: the identical shapes with a LEGAL type accept on BOTH JETH and solc (so the reject is
    // driven by the undefined type, not by the member kind - `indexed<u256>` must NOT reject on the
    // `indexed` wrapper).
    expect(accepts(`abstract class B { E: event<{ x: indexed<u256> }>; }\n${DEPLOYABLE}`)).toBe(true);
    expect(accepts(`abstract class B { Bad: error<{ n: u256 }>; }\n${DEPLOYABLE}`)).toBe(true);
    expect(accepts(`abstract class B { constructor(x: u256) {} }\n${DEPLOYABLE}`)).toBe(true);
    expect(accepts(`abstract class B { @modifier only(x: u256) { _; } }\n${DEPLOYABLE}`)).toBe(true);

    // THE SOLC WITNESSES: each undefined-typed form is an error, its legal twin accepts.
    expect(solcAccepts(`abstract contract B { event E(Nope indexed x); } ${SOL_DEPLOYABLE}`)).toBe(false);
    expect(solcAccepts(`abstract contract B { event E(uint256 indexed x); } ${SOL_DEPLOYABLE}`)).toBe(true);
    expect(solcAccepts(`abstract contract B { error Bad(Nope n); } ${SOL_DEPLOYABLE}`)).toBe(false);
    expect(solcAccepts(`abstract contract B { error Bad(uint256 n); } ${SOL_DEPLOYABLE}`)).toBe(true);
    expect(solcAccepts(`abstract contract B { constructor(Nope x) {} } ${SOL_DEPLOYABLE}`)).toBe(false);
    expect(solcAccepts(`abstract contract B { constructor(uint256 x) {} } ${SOL_DEPLOYABLE}`)).toBe(true);
    expect(solcAccepts(`abstract contract B { modifier only(Nope x) { _; } } ${SOL_DEPLOYABLE}`)).toBe(false);
    expect(solcAccepts(`abstract contract B { modifier only(uint256 x) { _; } } ${SOL_DEPLOYABLE}`)).toBe(true);
  });

  // ---- THE OVER-REJECTION GUARD (the #1 risk of this change) --------------------------------------
  // An unextended abstract base may legitimately contain anything a deriving contract would use. Each
  // shape below must still COMPILE, and the emitted creation bytecode must be UNCHANGED by the added
  // check (it is a pure type-resolution pass: it must never alter codegen).
  it('30 real abstract-base shapes still compile, and the deployable stays byte-identical', () => {
    const shapes: [string, string][] = [
      ['virtual method', `abstract class B { @virtual m(): u256 { return 1n; } }`],
      ['bodyless abstract get', `abstract class B { abstract get g(): u256; }`],
      ['bodyless abstract method', `abstract class B { abstract m(x: u256): u256; }`],
      ['storage field', `abstract class B { n: u256; }`],
      ['many field types', `abstract class B { a: u256; b: address; c: bool; d: bytes32; e: string; f: bytes; }`],
      ['mapping field', `abstract class B { m: mapping<address, u256>; }`],
      ['nested mapping', `abstract class B { m: mapping<address, mapping<address, u256>>; }`],
      ['dyn array field', `abstract class B { xs: u256[]; }`],
      ['fixed array field', `abstract class B { xs: Arr<u256, 3>; }`],
      ['static constant', `abstract class B { static K: u256 = 5n; }`],
      ['static immutable + ctor', `abstract class B { static M: u256; constructor() { B.M = 1n; } }`],
      ['constructor with args', `abstract class B { n: u256; constructor(x: u256) { this.n = x; } }`],
      ['modifier', `abstract class B { @modifier only() { if (1n > 2n) { revert("no"); } _; } }`],
      ['event field', `abstract class B { Transfer: event<{ from: indexed<address>; amt: u256 }>; }`],
      ['error field', `abstract class B { Bad: error<{ need: u256 }>; }`],
      ['Visible field', `abstract class B { v: Visible<u256> = 3n; }`],
      ['External method', `abstract class B { e(): External<void> { } }`],
      ['get accessor', `abstract class B { n: u256; get g(): External<u256> { return this.n; } }`],
      ['struct field', `type P = { x: u256; y: u256 };\nabstract class B { p: P; }`],
      ['struct param', `type P = { x: u256 };\nabstract class B { m(p: P): u256 { return p.x; } }`],
      ['enum field', `enum E { A, B }\nabstract class B2 { e: E; }`],
      ['branded type', `type Id = Brand<u256>;\nabstract class B { i: Id; }`],
      ['funcref param', `abstract class B { m(f: (x: u256) => u256): u256 { return f(1n); } }`],
      ['interface-typed param', `interface I { p(): View<u256>; }\nabstract class B { m(i: I): u256 { return i.p(); } }`],
      ['contract-typed param', `abstract class B { m(c: C): address { return address(c); } }`],
      ['abstract extends abstract', `abstract class A0 { @virtual m(): u256 { return 1n; } }\nabstract class B extends A0 { @override m(): u256 { return 2n; } }`],
      ['payable ctor', `abstract class B { @payable constructor() { } }`],
      ['this.field in body', `abstract class B { n: u256; m(): u256 { this.n = 1n; return this.n; } }`],
      ['multi-return', `abstract class B { m(): [u256, address] { return [1n, address(0n)]; } }`],
      ['Arr of struct', `type P = { x: u256 };\nabstract class B { ps: Arr<P, 2>; }`],
    ];
    // the BASELINE: the deployable compiled with NO abstract sibling at all. The added pass only resolves
    // types, so every shape must leave this creation bytecode untouched.
    const baseline = creation(DEPLOYABLE);
    const rejected: string[] = [];
    const drifted: string[] = [];
    for (const [label, base] of shapes) {
      const src = `${base}\n${DEPLOYABLE}`;
      const cs = codes(src);
      if (cs.length) {
        rejected.push(`${label} -> ${cs.join(',')}`);
        continue;
      }
      if (creation(src) !== baseline) drifted.push(label);
    }
    expect(rejected).toEqual([]);
    expect(drifted).toEqual([]);
    expect(shapes.length).toBe(30);
  });
});
