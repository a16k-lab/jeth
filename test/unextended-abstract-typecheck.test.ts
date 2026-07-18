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

  it('an UNDEFINED type in a BARE/positional event/error field rejects (JETH013), like solc', () => {
    // OA4b - the SECOND hole in the event/error field surface: the first pass walked only the
    // OBJECT-LITERAL form `event<{ x: T }>` and silently accepted the BARE/positional form (a single type,
    // an array, an `indexed<T>`, or a comma list) with an undefined leaf. solc rejects the positional twin
    // `event E(Nope)` / `error Bad(Nope)` just as it does the named one, so JETH accepting was an
    // over-acceptance. Every bare position - single, array, indexed, indexed-array, and each slot of a
    // comma list, on BOTH event and error - now resolves its leaf and reports JETH013.
    expect(codes(`abstract class B { E: event<Nope>; }\n${DEPLOYABLE}`)).toContain('JETH013'); // bare single
    expect(codes(`abstract class B { Bad: error<Nope>; }\n${DEPLOYABLE}`)).toContain('JETH013'); // bare single error
    expect(codes(`abstract class B { E: event<Nope[]>; }\n${DEPLOYABLE}`)).toContain('JETH013'); // bare array
    expect(codes(`abstract class B { E: event<indexed<Nope>>; }\n${DEPLOYABLE}`)).toContain('JETH013'); // bare indexed
    expect(codes(`abstract class B { E: event<indexed<Nope[]>>; }\n${DEPLOYABLE}`)).toContain('JETH013'); // bare indexed array
    expect(codes(`abstract class B { E: event<Nope, u256>; }\n${DEPLOYABLE}`)).toContain('JETH013'); // multi, first slot
    expect(codes(`abstract class B { E: event<u256, Nope>; }\n${DEPLOYABLE}`)).toContain('JETH013'); // multi, second slot
    expect(codes(`abstract class B { Bad: error<Nope[]>; }\n${DEPLOYABLE}`)).toContain('JETH013'); // bare array error
    expect(codes(`abstract class B { Bad: error<u256, Nope>; }\n${DEPLOYABLE}`)).toContain('JETH013'); // multi error

    // THE CONTROLS. Once the unextended-abstract BODY-check routes a stray abstract through the full
    // deployed-path analysis, a stray abstract behaves exactly like a deployed one: (1) the OA that matters -
    // an UNDEFINED leaf - stays closed (JETH013) in the canonical OBJECT-LITERAL spelling too; (2) a valid-type
    // BARE/positional event/error param now rejects JETH353 on a stray base, because JETH requires the
    // object-literal `event<{ x: T }>` spelling on EVERY path (positional unnamed params are a pre-existing
    // safe over-rejection - the deployed/extended paths reject them too - now applied uniformly to stray
    // abstracts instead of the old stray-only leniency). The canonical object-literal forms accept.
    expect(accepts(`abstract class B { E: event<{ x: u256 }>; }\n${DEPLOYABLE}`)).toBe(true);
    expect(accepts(`abstract class B { E: event<{ x: indexed<u256> }>; }\n${DEPLOYABLE}`)).toBe(true);
    expect(accepts(`abstract class B { Bad: error<{ n: u256 }>; }\n${DEPLOYABLE}`)).toBe(true);
    expect(codes(`abstract class B { E: event<{ x: Nope }>; }\n${DEPLOYABLE}`)).toContain('JETH013'); // object-literal undefined leaf
    expect(codes(`abstract class B { Bad: error<{ n: Nope }>; }\n${DEPLOYABLE}`)).toContain('JETH013');
    // a valid-type BARE/positional form rejects JETH353 (unsupported spelling), consistently with the deployed path.
    expect(codes(`abstract class B { E: event<u256>; }\n${DEPLOYABLE}`)).toContain('JETH353');
    expect(codes(`abstract class B { Bad: error<u256>; }\n${DEPLOYABLE}`)).toContain('JETH353');
    expect(codes(`abstract class B { E: event<u256, address>; }\n${DEPLOYABLE}`)).toContain('JETH353');

    // THE SOLC WITNESSES: each undefined bare form is an error; its defined twin accepts.
    expect(solcAccepts(`abstract contract B { event E(Nope); } ${SOL_DEPLOYABLE}`)).toBe(false);
    expect(solcAccepts(`abstract contract B { event E(uint256); } ${SOL_DEPLOYABLE}`)).toBe(true);
    expect(solcAccepts(`abstract contract B { error Bad(Nope); } ${SOL_DEPLOYABLE}`)).toBe(false);
    expect(solcAccepts(`abstract contract B { error Bad(uint256); } ${SOL_DEPLOYABLE}`)).toBe(true);
    expect(solcAccepts(`abstract contract B { event E(Nope[]); } ${SOL_DEPLOYABLE}`)).toBe(false);
    expect(solcAccepts(`abstract contract B { event E(uint256[]); } ${SOL_DEPLOYABLE}`)).toBe(true);
    expect(solcAccepts(`abstract contract B { event E(Nope indexed); } ${SOL_DEPLOYABLE}`)).toBe(false);
    expect(solcAccepts(`abstract contract B { event E(uint256 indexed); } ${SOL_DEPLOYABLE}`)).toBe(true);
    expect(solcAccepts(`abstract contract B { event E(Nope, uint256); } ${SOL_DEPLOYABLE}`)).toBe(false);
    expect(solcAccepts(`abstract contract B { event E(uint256, address); } ${SOL_DEPLOYABLE}`)).toBe(true);
  });

  it('an `indexed` parameter on an ERROR field rejects (JETH129) on a stray base too, like solc', () => {
    // `indexed` is an event-only marker: solc rejects `error Bad(uint256 indexed)` whether the base is
    // deployed or stray. The bare-form fix routes `indexed<T>` through the deployed path's own gate, so an
    // `indexed<T>` on a stray error field is JETH129 in BOTH spellings (this also closes the same OA the
    // object-literal form had). A valid `indexed<T>` on an EVENT still accepts.
    expect(codes(`abstract class B { Bad: error<indexed<u256>>; }\n${DEPLOYABLE}`)).toContain('JETH129'); // bare
    expect(codes(`abstract class B { Bad: error<{ n: indexed<u256> }>; }\n${DEPLOYABLE}`)).toContain('JETH129'); // object-literal
    expect(accepts(`abstract class B { E: event<{ x: indexed<u256> }>; }\n${DEPLOYABLE}`)).toBe(true); // valid indexed event (object-literal) still accepts
    // solc witnesses: indexed-on-error rejects, indexed-on-event accepts.
    expect(solcAccepts(`abstract contract B { error Bad(uint256 indexed); } ${SOL_DEPLOYABLE}`)).toBe(false);
    expect(solcAccepts(`abstract contract B { event E(uint256 indexed); } ${SOL_DEPLOYABLE}`)).toBe(true);
  });

  it('BYTE-IDENTITY: a valid stray abstract base does not change the deployable bytecode', () => {
    // The check-route is diagnostics-only (its IR is discarded), so the deployable's creation bytecode must be
    // UNCHANGED by prepending any valid stray abstract base - a canonical object-literal event/error field, or a
    // well-typed method / constructor / modifier body.
    const baseline = creation(DEPLOYABLE);
    const validBases = [
      `abstract class B { E: event<{ x: u256 }>; }`,
      `abstract class B { Bad: error<{ n: u256 }>; }`,
      `abstract class B { E: event<{ x: indexed<u256> }>; }`,
      `abstract class B { m(x: u256): u256 { return x + 1n; } }`,
      `abstract class B { constructor(x: u256) {} }`,
      `abstract class B { @modifier only(x: u256) { _; } }`,
    ];
    for (const base of validBases) {
      expect(accepts(`${base}\n${DEPLOYABLE}`)).toBe(true);
      expect(creation(`${base}\n${DEPLOYABLE}`)).toBe(baseline);
    }
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

// UNEXTENDED-ABSTRACT BODY CHECK (solc parity): the SIGNATURE pass above resolved a stray abstract's
// param/field/return TYPES but never its member BODIES, so a broken body (undeclared identifier, bad
// assignment, wrong return arity/overflow, illegal @override, view/pure mutation, unknown or wrong-arity
// call) was silently ACCEPTED while solc rejects it. The driver now re-parses once per stray unextended
// abstract LEAF (a pristine AST - analyzeContract strips markers in place, so a leaf sharing a base with the
// route cannot be checked on the route's tree) and runs the full body analysis. These pins close that OA for
// EVERY (check-kind x member-position) cell, and the control block below is the load-bearing half: a valid
// stray abstract with any member body still compiles AND leaves the deployable byte-identical (the check is a
// dead-code type pass, never codegen), including the double-strip-hazard shared-base case.
describe('an unextended abstract class BODY is type-checked (solc parity)', () => {
  // both must REJECT: the JETH reject is the newly-closed body check, and the solc mirror rejects too
  // (non-vacuous - the SAME file with the body fixed compiles on both).
  const bothReject = (j: string, s: string): boolean => !accepts(`${j}\n${DEPLOYABLE}`) && !solcAccepts(`${s}\n${SOL_DEPLOYABLE}`);

  it('METHOD body: each broken-body kind rejects, like solc', () => {
    expect(bothReject(`abstract class A { m(): u256 { return q; } }`, `abstract contract A { function m() internal pure returns (uint256) { return q; } }`)).toBe(true); // undeclared
    expect(bothReject(`abstract class A { m(): u256 { let y: u256 = true; return y; } }`, `abstract contract A { function m() internal pure returns (uint256) { uint256 y = true; return y; } }`)).toBe(true); // bad assign
    expect(bothReject(`abstract class A { m(): u256 { return; } }`, `abstract contract A { function m() internal pure returns (uint256) { return; } }`)).toBe(true); // return arity
    expect(bothReject(`abstract class A { m(): u8 { return 300n; } }`, `abstract contract A { function m() internal pure returns (uint8) { return 300; } }`)).toBe(true); // overflow
    expect(bothReject(`abstract class A { @override m(): u256 { return 1n; } }`, `abstract contract A { function m() internal pure override returns (uint256) { return 1; } }`)).toBe(true); // illegal override
    expect(bothReject(`abstract class A { m(): u256 { return this.nope(); } }`, `abstract contract A { function m() internal returns (uint256) { return this.nope(); } }`)).toBe(true); // unknown call
    expect(bothReject(`abstract class A { h(x: u256): u256 { return x; } m(): u256 { return this.h(); } }`, `abstract contract A { function h(uint256 x) internal pure returns (uint256){return x;} function m() internal returns (uint256) { return this.h(); } }`)).toBe(true); // wrong arg count
  });

  it('GETTER body: undeclared / view-mutation / bad-assign / overflow reject, like solc', () => {
    expect(bothReject(`abstract class A { get g(): External<u256> { return q; } }`, `abstract contract A { function g() public view returns (uint256) { return q; } }`)).toBe(true);
    expect(bothReject(`abstract class A { n: u256; get g(): External<u256> { this.n = 5n; return this.n; } }`, `abstract contract A { uint256 n; function g() public view returns (uint256) { n = 5; return n; } }`)).toBe(true); // a get is read-only
    expect(bothReject(`abstract class A { get g(): External<u256> { let y: u256 = true; return y; } }`, `abstract contract A { function g() public view returns (uint256) { uint256 y = true; return y; } }`)).toBe(true);
    expect(bothReject(`abstract class A { get g(): External<u8> { return 300n; } }`, `abstract contract A { function g() public view returns (uint8) { return 300; } }`)).toBe(true);
  });

  it('CONSTRUCTOR body: undeclared / bad-assign / unknown-call reject, like solc', () => {
    expect(bothReject(`abstract class A { n: u256; constructor() { this.n = q; } }`, `abstract contract A { uint256 n; constructor() { n = q; } }`)).toBe(true);
    expect(bothReject(`abstract class A { n: u256; constructor() { this.n = true; } }`, `abstract contract A { uint256 n; constructor() { n = true; } }`)).toBe(true);
    expect(bothReject(`abstract class A { constructor() { this.nope(); } }`, `abstract contract A { constructor() { nope(); } }`)).toBe(true);
  });

  it('FIELD INITIALIZER: undeclared / bad-type / overflow reject, like solc', () => {
    expect(bothReject(`abstract class A { x: u256 = q; }`, `abstract contract A { uint256 x = q; }`)).toBe(true);
    expect(bothReject(`abstract class A { x: u256 = true; }`, `abstract contract A { uint256 x = true; }`)).toBe(true);
    expect(bothReject(`abstract class A { x: u8 = 300n; }`, `abstract contract A { uint8 x = 300; }`)).toBe(true);
  });

  it('APPLIED @modifier body + @nonReentrant body: broken body rejects, like solc', () => {
    expect(bothReject(`abstract class A { @modifier only() { require(q, "x"); _; } @only m(): External<void> {} }`, `abstract contract A { modifier only() { require(q, "x"); _; } function m() external only {} }`)).toBe(true);
    expect(bothReject(`abstract class A { x: u256; @nonReentrant m(): External<void> { this.x = q; } }`, `abstract contract A { uint256 x; function m() external { x = q; } }`)).toBe(true);
  });

  it('a CHAIN of unextended abstracts (nothing concrete extends): a broken body in EITHER link rejects', () => {
    // broken BASE body, checked via the extending leaf's linearization
    expect(bothReject(`abstract class A0 { m(): u256 { return q; } }\nabstract class B extends A0 { }`, `abstract contract A0 { function m() internal pure returns (uint256) { return q; } }\nabstract contract B is A0 { }`)).toBe(true);
    // broken LEAF body
    expect(bothReject(`abstract class A0 { }\nabstract class B extends A0 { m(): u256 { return q; } }`, `abstract contract A0 { }\nabstract contract B is A0 { function m() internal pure returns (uint256) { return q; } }`)).toBe(true);
  });

  it('SHARED BASE with the deployed route (the marker-strip hazard): sound + byte-identical', () => {
    // C and the stray abstract A both extend B. A broken body in A must reject; a valid A must accept AND
    // leave C byte-identical to the C-extends-B baseline (the re-parse per leaf is what makes this sound - an
    // in-place re-analysis would demote B's markers to internal, corrupting C's dispatcher).
    const baseB = `abstract class B { bhelper(): u256 { return 1n; } }\nclass C extends B { get z(): External<u256> { return 7n; } }`;
    const withValidStray = `${baseB}\nabstract class A extends B { m(): u256 { return this.bhelper(); } }`;
    const withBrokenStray = `${baseB}\nabstract class A extends B { m(): u256 { return q; } }`;
    expect(accepts(withValidStray)).toBe(true);
    expect(creation(withValidStray)).toBe(creation(baseB)); // C's bytecode untouched by the valid stray
    expect(codes(withBrokenStray)).toContain('JETH072'); // the broken stray still rejects
  });

  it('NO NEW OVER-REJECTION: valid bodies in every position still compile (solc accepts them too)', () => {
    const valid: [string, string][] = [
      [`abstract class A { m(): u256 { return 1n; } }`, `abstract contract A { function m() internal pure returns (uint256) { return 1; } }`],
      [`abstract class A { n: u256; get g(): External<u256> { return this.n; } }`, `abstract contract A { uint256 n; function g() public view returns (uint256) { return n; } }`],
      [`abstract class A { n: u256; @modifier only() { require(this.n > 0n, "x"); _; } @only m(): External<void> {} }`, `abstract contract A { uint256 n; modifier only() { require(n > 0, "x"); _; } function m() external only {} }`],
      [`abstract class A { n: u256; constructor(x: u256) { this.n = x; } }`, `abstract contract A { uint256 n; constructor(uint256 x) { n = x; } }`],
      [`abstract class A { x: u256 = 5n; }`, `abstract contract A { uint256 x = 5; }`],
      [`abstract class A { x: u256; @nonReentrant m(): External<void> { this.x = 1n; } }`, `abstract contract A { uint256 x; function m() external { x = 1; } }`],
      // the INTERFACE-SURFACE idiom: an abstract used only as a nominal TYPE, carrying View/Pure markers and a
      // read-only External method (solc accepts both; the body check must NOT resurrect the deliberate JETH
      // class-mutability over-rejections JETH498 / JETH352-read-only-external over this dead code).
      [`abstract class T { @virtual v(): View<u256>; transfer(to: address, amt: u256): External<bool> { return true; } }`, `abstract contract T { function v() external view virtual returns (uint256); function transfer(address to, uint256 amt) external returns (bool) { return true; } }`],
    ];
    const rejected: string[] = [];
    const drifted: string[] = [];
    const baseline = creation(DEPLOYABLE);
    for (const [aj, as] of valid) {
      const src = `${aj}\n${DEPLOYABLE}`;
      if (!accepts(src)) rejected.push(aj);
      else if (creation(src) !== baseline) drifted.push(aj);
      // sanity: solc accepts the twin (non-vacuous control)
      expect(solcAccepts(`${as}\n${SOL_DEPLOYABLE}`)).toBe(true);
    }
    expect(rejected).toEqual([]);
    expect(drifted).toEqual([]);
  });
});
