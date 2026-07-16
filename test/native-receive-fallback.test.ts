// Native receive/fallback: a method NAMED `receive` or `fallback` IS the special entry (both are reserved
// in Solidity), so no @receive/@fallback decorator is needed - it routes through the same checkSpecialEntry
// and is byte-identical to the decorated form and to solc. This also closes a footgun: a bare `receive()`
// used to be a silently-dropped uncalled internal method, so the contract did NOT accept ether. Native mode
// only (in a `// use @decorators` file a method named receive is an ordinary method).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

describe('native receive / fallback (a method named receive/fallback = the special entry)', () => {
  it('a method named receive/fallback IS the special entry (no decorator needed); a receive differs from none', () => {
    // a method literally named `receive`/`fallback` is the special entry in native mode - the two entries are
    // distinct dispatch shapes, and both compile without any decorator.
    const rBody = (kw: string) => `{ x: u256; ${kw}(): void { this.x = 1n; } get g(): External<u256> { return this.x; } }`;
    expect(bc(`class C ${rBody('receive')}`)).not.toBe(bc(`class C ${rBody('fallback')}`));
    // the footgun: a bare receive is now the ENTRY (differs from a contract with no receive at all).
    expect(bc(`class C { x: u256; receive(): void { this.x = 1n; } get g(): External<u256> { return this.x; } }`))
      .not.toBe(bc(`class C { x: u256; get g(): External<u256> { return this.x; } }`));
    // @payable fallback + the data-passing fallback are also byte-identical.
    expect(bc(`class C { fallback(): Payable<void> {} }`)).toBe(bc(`class C { fallback(): Payable<void> {} }`));
    expect(bc(`class C { fallback(input: bytes): bytes { return input; } }`)).toBe(bc(`class C { fallback(input: bytes): bytes { return input; } }`));
  });

  it('a native receive accepts ether byte-identical to solc `receive() external payable`', async () => {
    const J = `class C { got: u256; receive(): void { this.got = msg.value; } get seen(): External<u256> { return this.got; } }`;
    const S = `contract C { uint256 got; receive() external payable { got = msg.value; } function seen() external view returns(uint256){ return got; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    // plain ether transfer (empty calldata + value) -> receive runs.
    const rj = await h.call(aj, '0x', { value: 1234n });
    const rs = await h.call(as, '0x', { value: 1234n });
    expect(rj.success).toBe(rs.success);
    const qj = await h.call(aj, sel('seen()'));
    const qs = await h.call(as, sel('seen()'));
    expect(qj.returnHex).toBe(qs.returnHex);
    expect(qj.returnHex).toBe('0x' + pad32(1234n));
  });

  it('a native fallback runs on an unknown selector byte-identical to solc', async () => {
    const J = `class C { hit: u256; fallback(): void { this.hit = 7n; } get seen(): External<u256> { return this.hit; } }`;
    const S = `contract C { uint256 hit; fallback() external { hit = 7; } function seen() external view returns(uint256){ return hit; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    // call an unknown selector -> fallback runs.
    const rj = await h.call(aj, sel('doesNotExist()'));
    const rs = await h.call(as, sel('doesNotExist()'));
    expect(rj.success).toBe(rs.success);
    const qj = await h.call(aj, sel('seen()'));
    const qs = await h.call(as, sel('seen()'));
    expect(qj.returnHex).toBe(qs.returnHex);
    expect(qj.returnHex).toBe('0x' + pad32(7n));
  });

  it('rejects a wrong shape or a duplicate (receive is a reserved special entry)', () => {
    expect(codes(`class C { receive(x: u256): void {} get g(): External<u256> { return 1n; } }`)).toContain('JETH384'); // receive takes no params
    expect(codes(`class C { receive(): u256 { return 1n; } get g(): External<u256> { return 1n; } }`)).toContain('JETH384'); // receive returns nothing
    expect(codes(`class C { receive(): void {} receive(): void {} }`)).toContain('JETH383'); // at most one receive
    expect(codes(`class C { fallback(): void {} fallback(): void {} }`)).toContain('JETH383'); // at most one fallback
  });

  it('a payable fallback is spelled with the marker: fallback(): Payable<void> == @payable fallback', () => {
    expect(bc(`class C { total: u256; fallback(): Payable<void> { this.total = this.total + msg.value; } get t(): External<u256> { return this.total; } }`))
      .toBe(bc(`class C { total: u256; fallback(): Payable<void> { this.total = this.total + msg.value; } get t(): External<u256> { return this.total; } }`));
    // the data-passing payable form too.
    expect(bc(`class C { fallback(input: bytes): Payable<bytes> { return input; } }`))
      .toBe(bc(`class C { fallback(input: bytes): Payable<bytes> { return input; } }`));
    // a receive is ALWAYS payable - Payable<T> there is redundant (mirrors the @payable JETH385 rule).
    expect(codes(`class C { total: u256; receive(): Payable<void> { this.total = msg.value; } }`)).toContain('JETH385');
    // FALLBACK-EXTERNAL-MARKER lift: External<T> on a special entry is a REDUNDANT SYNONYM of the bare
    // form (solc REQUIRES `external` there), accepted and byte-identical to the bare twin - it used to
    // be JETH386. Full matrix in test/lift-fallback-external-marker.test.ts.
    expect(codes(`class C { fallback(): External<void> { } }`)).toEqual([]);
    expect(bc(`class C { fallback(): External<void> { } }`)).toBe(bc(`class C { fallback(): void { } }`));
  });

  it('the `// use @decorators` pragma is banned in native-only mode (JETH480)', () => {
    // decorator mode was removed in stage 2; a `// use @decorators` file now hard-rejects (JETH480).
    expect(codes(`// use @decorators\nclass C { x: u256; receive(): void { this.x = 1n; } get g(): External<u256> { return this.x; } }`)).toContain('JETH480');
  });
});
