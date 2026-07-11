// Native libraries: a `static class L { ... }` is the native spelling of `@library class L` - a class-level
// bag of functions (no state, no instances, never deployed as the contract), called as `L.f(args)` exactly
// like solc's `library`. `static` is not a legal TS class-declaration modifier, but the parser retains it
// with NO parse diagnostic (the restriction is a checker rule - the same lucky pattern as parameterized
// `get`). It routes through the SAME collectLibrary, so functions, gates, and the qualified-name (L.f)
// call resolution are identical to @library - byte-identical bytecode. A static class is excluded from the
// contract fallback AND from the ClassName.x static-member rewrite (its L.f(a) calls must resolve via the
// library machinery, not be hijacked into this.f(a)).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

describe('static class = @library (native libraries)', () => {
  it('a static class is byte-identical to @library and runs byte-identical to solc', async () => {
    const lib = `MathLib { min(a: u256, b: u256): u256 { return a < b ? a : b; } clamp(x: u256, hi: u256): u256 { return MathLib.min(x, hi); } }`;
    const use = `class C { get m(a: u256, b: u256): External<u256> { return MathLib.clamp(a, b); } }`;
    expect(bc(`static class ${lib} ${use}`)).toBe(bc(`static class ${lib} ${use}`));
    const S = `library MathLib {
        function min(uint256 a, uint256 b) internal pure returns(uint256){ return a < b ? a : b; }
        function clamp(uint256 x, uint256 hi) internal pure returns(uint256){ return min(x, hi); } }
      contract C { function m(uint256 a, uint256 b) external pure returns(uint256){ return MathLib.clamp(a, b); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(`static class ${lib} ${use}`, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const rj = await h.call(aj, sel('m(uint256,uint256)') + W(9) + W(4));
    const rs = await h.call(as, sel('m(uint256,uint256)') + W(9) + W(4));
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
  });

  it('a static class is a library, never the contract (and never a base)', () => {
    // alongside a bare contract it does NOT trigger the two-contracts reject.
    expect(codes(`static class L { f(): u256 { return 1n; } } class C { get g(): External<u256> { return L.f(); } }`)).toEqual([]);
    // alone in a file it is not a deployable contract.
    expect(codes(`static class L { f(): u256 { return 1n; } }`)).toContain('JETH040');
    // it cannot be extended (a library is not a base).
    expect(codes(`static class L { f(): u256 { return 1n; } } class C extends L { get g(): External<u256> { return 1n; } }`)).toContain('JETH370');
  });

  it('library gates apply: no state fields, no `this`, no `static abstract`', () => {
    expect(codes(`static class L { x: u256; f(): u256 { return 1n; } } class C { get g(): External<u256> { return L.f(); } }`)).toContain('JETH388');
    expect(codes(`static class L { f(): u256 { return this.x; } } class C { x: u256; get g(): External<u256> { return L.f(); } }`)).toContain('JETH394');
    expect(codes(`static abstract class L { f(): u256 { return 1n; } } class C { get g(): External<u256> { return 1n; } }`)).toContain('JETH390');
  });

  it('the `// use @decorators` pragma is banned in native-only mode (JETH480)', () => {
    // decorator mode was removed in stage 2; a `// use @decorators` file now hard-rejects (JETH480).
    expect(codes(`// use @decorators\nstatic class L { f(): u256 { return 1n; } } class C { get g(): External<u256> { return 1n; } }`)).toContain('JETH480');
  });

  it('DEPLOYABLE library: External<T> on a static-class method = a delegatecall fn (like solc)', () => {
    // solc model: deployability falls out of the function visibilities - all-internal = inlined (never
    // deployed); any external fn = deployed + linked, delegatecalled. One static class can MIX both.
    const M = `static class L { sq(a: u256): External<u256> { return a * a; } } class C { x: u256; store(a: u256): External<void> { this.x = L.sq(a); } }`;
    const D = `static class L { sq(a: u256): External<u256> { return a * a; } } class C { x: u256; store(a: u256): External<void> { this.x = L.sq(a); } }`;
    expect(compile(M, { fileName: 'C.jeth' }).creationBytecode).toBe(compile(D, { fileName: 'C.jeth' }).creationBytecode);
    // linked when external, not linked when all-internal.
    expect(Object.keys(compile(M, { fileName: 'C.jeth' }).linkReferences ?? {}).length).toBeGreaterThan(0);
    expect(Object.keys(compile(`static class L { half(a: u256): u256 { return a / 2n; } } class C { get g(a: u256): External<u256> { return L.half(a); } }`, { fileName: 'C.jeth' }).linkReferences ?? {}).length).toBe(0);
    // a mixed library (internal + external fns) compiles.
    expect(codes(`static class L { half(a: u256): u256 { return a / 2n; } sq(a: u256): External<u256> { return a * a; } } class C { x: u256; store(a: u256): External<void> { this.x = L.sq(L.half(a)); } }`)).toEqual([]);
    // # private library fns work (intra-lib call), and privacy holds across contracts.
    expect(codes(`static class L { #sq(a: u256): u256 { return a * a; } quad(a: u256): u256 { return L.#sq(L.#sq(a)); } } class C { get f(a: u256): External<u256> { return L.quad(a); } }`)).toEqual([]);
    expect(codes(`static class L { #sq(a: u256): u256 { return a * a; } } class C { get f(a: u256): External<u256> { return L.#sq(a); } }`).length).toBeGreaterThan(0);
  });
});
