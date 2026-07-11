// W8B - MODIFIER / @storage DUPLICATE-IDENTIFIER PARITY. A @modifier shares the contract-level
// identifier namespace with @state/@constant/@immutable, @function, @event and @error; solc rejects a
// modifier reusing any such name (same contract, cross-inheritance, or diamond) as a DeclarationError.
// JETH previously accepted these silently. A @storage('ns') field name likewise shares the this.<name>
// binding with @state (and with other namespaces): reusing a name orphans a slot / aliases an ambiguous
// binding, so it is rejected. A file-level @struct/enum/@interface type is a SEPARATE (file) scope, so a
// modifier reusing a type name is NOT a clash (solc accepts it) - that legal reuse must stay accepted.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
const jethAccepts = (src: string): boolean => codes(src).length === 0;
const solcAccepts = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return true;
  } catch {
    return false;
  }
};
// A pair rejected by BOTH (parity). The solc mirror MAY be omitted for the JETH-only @storage surface.
const bothReject = (j: string, s?: string) => {
  expect(jethAccepts(j)).toBe(false);
  if (s !== undefined) expect(solcAccepts(s)).toBe(false);
};
const bothAccept = (j: string, s: string) => {
  expect(codes(j)).toEqual([]);
  expect(solcAccepts(s)).toBe(true);
};

describe('W8B: @modifier cross-kind duplicate identifiers (same contract)', () => {
  it('modifier vs @state -> both reject', () =>
    bothReject(
      `class C { x: u256; @modifier x() { _; } get f(): External<u256> { return this.x; } }`,
      `contract C { uint256 x; modifier x() { _; } function f() public view returns (uint256){ return x; } }`,
    ));
  it('modifier vs @constant -> both reject', () =>
    bothReject(
      `class C { static x: u256 = 5n; @modifier x() { _; } }`,
      `contract C { uint256 constant x = 5; modifier x() { _; } }`,
    ));
  it('modifier vs @immutable -> both reject', () =>
    bothReject(
      `class C { static x: u256; @modifier x() { _; } constructor(){ this.x = 1n; } }`,
      `contract C { uint256 immutable x; modifier x() { _; } constructor(){ x = 1; } }`,
    ));
  it('modifier vs @event -> both reject', () =>
    bothReject(`class C { x: event<{}>; @modifier x() { _; } }`, `contract C { event x(); modifier x() { _; } }`));
  it('modifier vs @error -> both reject', () =>
    bothReject(`class C { x: error<{}>; @modifier x() { _; } }`, `contract C { error x(); modifier x() { _; } }`));
  it('modifier vs @function -> both reject', () =>
    bothReject(
      `class C { @modifier x() { _; } get x(): External<u256> { return 1n; } }`,
      `contract C { modifier x() { _; } function x() public pure returns (uint256){ return 1; } }`,
    ));
  it('modifier vs @state declared AFTER the modifier -> both reject (order independent)', () =>
    bothReject(
      `class C { @modifier x() { _; } x: u256; get f(): External<u256> { return this.x; } }`,
      `contract C { modifier x() { _; } uint256 x; function f() public view returns (uint256){ return x; } }`,
    ));
  it('uses JETH133 for a same-contract modifier-vs-field clash', () =>
    expect(codes(`class C { x: u256; @modifier x() { _; } }`)).toContain('JETH133'));
});

describe('W8B: @modifier cross-inheritance duplicate identifiers (both directions + diamond)', () => {
  it('base @modifier + derived @state -> both reject', () =>
    bothReject(
      `abstract class B { @modifier x() { _; } } class C extends B { x: u256; get f(): External<u256> { return this.x; } }`,
      `abstract contract B { modifier x() { _; } } contract C is B { uint256 x; function f() public view returns (uint256){ return x; } }`,
    ));
  it('base @modifier + derived @event -> both reject', () =>
    bothReject(
      `abstract class B { @modifier x() { _; } } class C extends B { x: event<{}>; }`,
      `abstract contract B { modifier x() { _; } } contract C is B { event x(); }`,
    ));
  it('base @modifier + derived @error -> both reject', () =>
    bothReject(
      `abstract class B { @modifier x() { _; } } class C extends B { x: error<{}>; }`,
      `abstract contract B { modifier x() { _; } } contract C is B { error x(); }`,
    ));
  it('base @modifier + derived @function -> both reject', () =>
    bothReject(
      `abstract class B { @modifier x() { _; } } class C extends B { get x(): External<u256> { return 1n; } }`,
      `abstract contract B { modifier x() { _; } } contract C is B { function x() public pure returns (uint256){ return 1; } }`,
    ));
  it('base @state + derived @modifier -> both reject', () =>
    bothReject(
      `abstract class B { x: u256; } class C extends B { @modifier x() { _; } get f(): External<u256> { return this.x; } }`,
      `abstract contract B { uint256 x; } contract C is B { modifier x() { _; } function f() public view returns (uint256){ return x; } }`,
    ));
  it('base @event + derived @modifier -> both reject', () =>
    bothReject(
      `abstract class B { x: event<{}>; } class C extends B { @modifier x() { _; } }`,
      `abstract contract B { event x(); } contract C is B { modifier x() { _; } }`,
    ));
  it('base @function + derived @modifier -> both reject', () =>
    bothReject(
      `abstract class B { @virtual get x(): External<u256> { return 1n; } } class C extends B { @modifier x() { _; } }`,
      `abstract contract B { function x() external pure virtual returns (uint256){ return 1; } } contract C is B { modifier x() { _; } }`,
    ));
  it('diamond: a base state var vs a derived modifier -> both reject', () =>
    bothReject(
      `abstract class A { z: u256; } abstract class B extends A { x: u256; } class C extends B { @modifier x() { _; } get f(): External<u256> { return this.x; } }`,
      `abstract contract A { uint256 z; } abstract contract B is A { uint256 x; } contract C is B { modifier x() { _; } function f() public view returns (uint256){ return x; } }`,
    ));
});

describe('W8B: @storage(ns) duplicate identifiers', () => {
  it('@storage(ns) x + @state x (same contract) -> reject (ambiguous this.x)', () =>
    expect(codes(`class C { @storage('a.b') x: u256; x: u256; get f(): External<u256> { return this.x; } }`)).toContain('JETH046'));
  it('@state x + @storage(ns) x (reversed order) -> reject', () =>
    expect(codes(`class C { x: u256; @storage('a.b') x: u256; get f(): External<u256> { return this.x; } }`)).toContain('JETH046'));
  it('@storage(ns) x + @constant x -> reject', () =>
    expect(codes(`class C { @storage('a.b') x: u256; static x: u256 = 3n; }`)).toContain('JETH046'));
  it('@storage(ns) x + @modifier x -> reject (cross-kind JETH133)', () =>
    expect(codes(`class C { @storage('a.b') x: u256; @modifier x() { _; } get f(): External<u256> { return 1n; } }`)).toContain('JETH133'));
  it('two @storage fields, different namespaces, same name -> reject (ambiguous binding)', () =>
    expect(codes(`class C { @storage('a') x: u256; @storage('b') x: u256; get f(): External<u256> { return this.x; } }`)).toContain('JETH046'));
});

describe('W8B: legal reuse must stay ACCEPTED (no over-rejection)', () => {
  it('function overloading', () =>
    bothAccept(
      `class C { get x(): External<u256> { return 1n; } get x(a: u256): External<u256> { return a; } }`,
      `contract C { function x() public pure returns (uint256){ return 1; } function x(uint256 a) public pure returns (uint256){ return a; } }`,
    ));
  it('event overloading by signature', () =>
    bothAccept(`class C { x: event<{}>; x: event<{ a: u256 }>; }`, `contract C { event x(); event x(uint256 a); }`));
  it('a modifier and a differently-named member', () =>
    bothAccept(
      `class C { s: u256; @modifier onlyOwner() { _; } @onlyOwner set(v: u256): External<void> { this.s = v; } }`,
      `contract C { uint256 s; modifier onlyOwner() { _; } function set(uint256 v) public onlyOwner { s = v; } }`,
    ));
  it('an inherited modifier with NO same-named derived member', () =>
    bothAccept(
      `abstract class B { @modifier x() { _; } } class C extends B { y: u256; }`,
      `abstract contract B { modifier x() { _; } } contract C is B { uint256 y; }`,
    ));
  it('a modifier vs a FILE-LEVEL @struct type of the same name (separate scope)', () =>
    bothAccept(
      `type x = { a: u256; }; class C { @modifier x() { _; } }`,
      `struct x { uint256 a; } contract C { modifier x() { _; } }`,
    ));
  it('a modifier vs a FILE-LEVEL enum type of the same name (separate scope)', () =>
    bothAccept(
      `enum x { A, B } class C { @modifier x() { _; } }`,
      `enum x { A, B } contract C { modifier x() { _; } }`,
    ));
  it('a local variable shadowing a modifier name', () =>
    bothAccept(
      `class C { @modifier x() { _; } get f(): External<u256> { let x: u256 = 3n; return x; } }`,
      `contract C { modifier x() { _; } function f() public pure returns (uint256){ uint256 x = 3; return x; } }`,
    ));
  it('two @storage fields in different namespaces with DISTINCT names', () =>
    expect(codes(`class C { @storage('a') p: u256; @storage('b') q: u256; get f(): External<u256> { return this.p + this.q; } }`)).toEqual([]));
  it('a @storage field and a @state var with DISTINCT names', () =>
    expect(codes(`class C { @storage('a.b') y: u256; x: u256; get f(): External<u256> { return this.x + this.y; } }`)).toEqual([]));
});
