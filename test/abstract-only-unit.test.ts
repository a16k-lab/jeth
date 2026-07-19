// ABSTRACT-ONLY / INTERFACE-ONLY translation unit (lifts JETH040 over-rejection). solc accepts a file
// whose only top-level declarations are abstract contracts and/or interfaces: it type-checks every member
// but emits NO deployable bytecode (neither is instantiable). JETH previously rejected the whole file with
// JETH040 ("no @contract class found"). These files are NON-DEPLOYABLE, so runtime byte-identity is
// vacuous - solc itself emits empty creation bytecode; the verification here is (a) JETH now ACCEPTS the
// same files solc accepts, with empty creation bytecode; (b) member/body validation still fires, so a
// genuinely-invalid abstract body / bad override / illegal member STILL rejects (no accept-all); (c) a file
// with no contract-like declaration still rejects JETH040; (d) a normal concrete contract is unaffected.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e;
  }
};
// creation bytecode (undefined-safe): an accepted non-deployable unit returns ''.
const crt = (src: string): string => compile(src, { fileName: 'C.jeth' }).creationBytecode;

describe('ABSTRACT-ONLY / INTERFACE-ONLY unit: accept with empty bytecode, matching solc', () => {
  it('accepts an abstract-only file with empty creation bytecode (solc: same)', () => {
    const j = `abstract class C { abstract m(): External<u256>; }`;
    const s = `abstract contract C { function m() external virtual returns (uint256); }`;
    expect(codes(j)).toEqual([]);
    expect(crt(j)).toBe('');
    expect(compileSolidity(SPDX + s, 'C').creation).toBe(''); // solc also emits no deployable bytecode
  });

  it('accepts an interface-only file with empty creation bytecode (solc: same)', () => {
    const j = `interface C { m(): View<u256>; }`;
    const s = `interface C { function m() external view returns (uint256); }`;
    expect(codes(j)).toEqual([]);
    expect(crt(j)).toBe('');
    expect(compileSolidity(SPDX + s, 'C').creation).toBe('');
  });

  it('accepts an abstract contract that mixes a bodyless obligation with implemented members', () => {
    expect(codes(`abstract class C { total: u256; abstract m(): External<u256>; get val(): External<u256> { return this.total; } add(a: u256, b: u256): u256 { return a + b; } }`)).toEqual([]);
    // solc accepts the twin (empty bytecode).
    expect(compileSolidity(SPDX + `abstract contract C { uint256 total; function m() external virtual returns(uint256); function val() external view returns(uint256){ return total; } function add(uint256 a, uint256 b) internal pure returns(uint256){ return a + b; } }`, 'C').creation).toBe('');
  });

  it('accepts abstract-extends-abstract, abstract-extends-interface (unimplemented), and interface-extends-interface', () => {
    expect(codes(`abstract class B { abstract m(): External<u256>; } abstract class C extends B { abstract n(): External<u256>; }`)).toEqual([]);
    expect(codes(`interface I { foo(): View<u256>; } abstract class C extends I { abstract m(): External<u256>; }`)).toEqual([]);
    expect(codes(`interface I { a(): View<u256>; } interface J extends I { b(): View<u256>; }`)).toEqual([]);
  });

  it('validates a bad body in a flattened abstract BASE of the leaf (no over-acceptance)', () => {
    // Bad is an abstract base of the leaf C; analyzing C flattens Bad, so Bad's type error still rejects.
    expect(codes(`abstract class Bad { f(a: u256): u256 { return true; } abstract p(): External<u256>; } abstract class C extends Bad { abstract m(): External<u256>; }`)).toContain('JETH085');
  });

  it('emits one empty, independently checked artifact per abstract leaf', () => {
    const src = `abstract class A { abstract m(): External<u256>; } abstract class B { abstract n(): External<u256>; }`;
    const r = compile(src, { fileName: 'C.jeth' });
    expect(codes(src)).toEqual([]);
    expect(r.contracts?.map((c) => [c.contractName, c.creationBytecode, c.runtimeBytecode])).toEqual([
      ['A', '', ''],
      ['B', '', ''],
    ]);
    expect(compileSolidity(SPDX + `abstract contract A { function m() external virtual returns(uint256); } abstract contract B { function n() external virtual returns(uint256); }`, 'A').creation).toBe('');
  });

  it('still rejects a bad body in the second independent abstract leaf', () => {
    expect(codes(`abstract class A { abstract m(): External<u256>; } abstract class B { abstract n(): External<u256>; f(): u256 { return true; } }`)).toContain('JETH085');
  });

  // ---- NEGATIVES: member/body validation must STILL fire (no silent accept-all) ----
  it('rejects a genuinely-invalid abstract body (type error), matching solc', () => {
    expect(codes(`abstract class C { abstract m(): External<u256>; add(a: u256): u256 { return true; } }`)).toContain('JETH085');
  });
  it('rejects an undeclared reference in an abstract method body', () => {
    expect(codes(`abstract class C { abstract m(): External<u256>; run(): void { y = 3n; } }`)).toContain('JETH066');
  });
  it('rejects a getter that writes state inside an abstract contract', () => {
    expect(codes(`abstract class C { x: u256; abstract m(): External<u256>; get bad(): External<u256> { this.x = 5n; return this.x; } }`)).toContain('JETH043');
  });
  it('rejects a duplicate function definition inside an abstract contract', () => {
    expect(codes(`abstract class C { abstract m(): External<u256>; f(): void {} f(): void {} }`)).toContain('JETH044');
  });
  it('rejects a bad emit arity inside an abstract method body', () => {
    expect(codes(`abstract class C { E: event<{ a: u256 }>; abstract m(): External<u256>; fire(): void { emit(this.E(1n, 2n)); } }`)).toContain('JETH148');
  });
  it('rejects an interface method that carries a body', () => {
    expect(codes(`interface C { m(): View<u256> { return 3n; } }`).length).toBeGreaterThan(0);
  });

  // ---- a file with NO contract-like declaration still rejects JETH040 ----
  it('still rejects a struct-only / empty file with JETH040', () => {
    expect(codes(`type P = { a: u256 };`)).toContain('JETH040');
    expect(codes(``)).toContain('JETH040');
    expect(codes(`static class L { f(): u256 { return 1n; } }`)).toContain('JETH040'); // library-only: unchanged
  });

  // ---- a normal concrete contract still compiles + deploys (no regression) ----
  it('a normal concrete contract is unaffected: deploys + runs byte-identically to solc', async () => {
    const j = `class C { x: u256; set(v: u256): External<void> { this.x = v; } get val(): External<u256> { return this.x; } }`;
    const s = `contract C { uint256 x; function set(uint256 v) external { x = v; } function val() external view returns(uint256){ return x; } }`;
    expect(codes(j)).toEqual([]);
    expect(crt(j).length).toBeGreaterThan(0);
    const h = await Harness.create();
    const aj = await h.deploy(crt(j));
    const as = await h.deploy(compileSolidity(SPDX + s, 'C').creation);
    // seed a distinct value, then read it back: identical returnHex proves runtime byte-identity.
    await h.call(aj, sel('set(uint256)') + pad32(0x1234n));
    await h.call(as, sel('set(uint256)') + pad32(0x1234n));
    expect((await h.call(aj, sel('val()'))).returnHex).toBe((await h.call(as, sel('val()'))).returnHex);
    expect((await h.call(aj, sel('val()'))).returnHex).toBe('0x' + pad32(0x1234n));
  });
});
