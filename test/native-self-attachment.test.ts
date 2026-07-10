// Native attached calls (the `self` convention - the native @using). A library function whose FIRST
// parameter is literally named `self` is ATTACHABLE: `a.min(b)` desugars to `M.min(a, b)` when exactly one
// in-scope library declares `min(self: <typeof a>, ...)`. The library AUTHOR opts in at the declaration
// (the spirit of solc's `using {M.min} for uint256 global`); no contract-side @using needed. It reuses the
// @using attachment machinery wholesale, so the safety rules hold unchanged: built-ins and struct fields
// always win, an ambiguous attachment (two libraries claiming one (type, name)) rejects at the call site,
// and the trigger is purely ADDITIVE - it only fires where the call would previously reject. Native mode
// only (decorator mode keeps requiring @using(L)).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string, sources?: Record<string, string>): string[] => {
  try { compile(src, { fileName: 'vault.jeth', sources }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

describe('the self convention (native attached calls)', () => {
  it('a `self`-first-param library fn attaches with no @using; a non-self fn stays detached', () => {
    expect(codes(`static class M { min(self: u256, b: u256): u256 { return self < b ? self : b; } } class C { get f(a: u256, b: u256): External<u256> { return a.min(b); } }`)).toEqual([]);
    expect(codes(`static class M { min(x: u256, b: u256): u256 { return x < b ? x : b; } } class C { get f(a: u256, b: u256): External<u256> { return a.min(b); } }`)).toContain('JETH074');
  });

  it('an attached call is byte-identical to the explicit M.min(a, b) and to solc using-for', async () => {
    const A = `static class M { min(self: u256, b: u256): u256 { return self < b ? self : b; } } class C { get f(a: u256, b: u256): External<u256> { return a.min(b); } }`;
    expect(bc(A)).toBe(bc(`static class M { min(self: u256, b: u256): u256 { return self < b ? self : b; } } class C { get f(a: u256, b: u256): External<u256> { return M.min(a, b); } }`));
    const S = `library M { function min(uint256 self, uint256 b) internal pure returns(uint256){ return self < b ? self : b; } }
      contract C { using M for uint256; function f(uint256 a, uint256 b) external pure returns(uint256){ return a.min(b); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(A, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const rj = await h.call(aj, sel('f(uint256,uint256)') + W(9) + W(4));
    const rs = await h.call(as, sel('f(uint256,uint256)') + W(9) + W(4));
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
  });

  it('safety rules hold: ambiguity rejects; builtins and struct fields win over attachments', () => {
    // two libraries self-marking the same (type, name) -> ambiguous at the call site.
    expect(codes(`static class M1 { min(self: u256, b: u256): u256 { return self; } } static class M2 { min(self: u256, b: u256): u256 { return b; } } class C { get f(a: u256, b: u256): External<u256> { return a.min(b); } }`)).toContain('JETH393');
    // a self-marked fn named like a receiver-type BUILT-IN member rejects (never silently shadows).
    expect(codes(`static class M { push(self: u256[], v: u256): u256 { return v; } } class C { xs: u256[]; f(v: u256): External<void> { this.xs.push(v); } }`).length).toBeGreaterThan(0);
    // a struct FIELD of the same name wins (p.min stays the field read).
    expect(codes(`type P = { min: u256 }; static class M { min(self: P, b: u256): u256 { return b; } } class C { get f(b: u256): External<u256> { let p: P = P(5n); return p.min; } }`)).toEqual([]);
  });

  it('composes with multi-file imports; decorator mode still requires @using', () => {
    expect(codes(`import { M } from "./m.jeth";\nclass C { get f(a: u256, b: u256): External<u256> { return a.min(b); } }`,
      { 'm.jeth': `export static class M { min(self: u256, b: u256): u256 { return self < b ? self : b; } }` })).toEqual([]);
    expect(codes(`// use @decorators\n@library class M { min(self: u256, b: u256): u256 { return self < b ? self : b; } } @contract class C { @external @pure f(a: u256, b: u256): u256 { return a.min(b); } }`)).toContain('JETH074');
  });
});
