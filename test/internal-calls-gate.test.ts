// G8 gate parity: the transitive-purity fixpoint and internal-call gates must match solc's
// acceptance boundary. solc is the oracle for the purity rejections (it rejects the same
// programs); the first-cut composition gates (aggregate args, multi-return, external target)
// are JETH-only intentional rejections documented here.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { compileSolidity } from './_solidity.js';

function jethCodes(src: string): string[] | null {
  try {
    compile(src, { fileName: 'C.jeth' });
    return null;
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.filter((d) => d.severity === 'error').map((d) => d.code);
    throw e;
  }
}
function solcRejects(src: string): boolean {
  try {
    compileSolidity('// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n' + src, 'C');
    return false;
  } catch {
    return true;
  }
}

describe('internal-call gates (G8)', () => {
  it('@view calling a state-writer is rejected (JETH054), like solc', () => {
    const codes = jethCodes(
      `@contract class C { @state x: u256; w(): void { this.x = 1n; } @view f(): u256 { this.w(); return this.x; } }`,
    );
    expect(codes).toContain('JETH481');
    expect(
      solcRejects(
        `contract C { uint256 x; function w() internal { x = 1; } function f() external view returns (uint256){ w(); return x; } }`,
      ),
    ).toBe(true);
  });
  it('@pure calling a state-reader is rejected (JETH055), like solc', () => {
    const codes = jethCodes(
      `@contract class C { @state x: u256; @view r(): u256 { return this.x; } @pure f(): u256 { return this.r(); } }`,
    );
    expect(codes).toContain('JETH481');
    expect(
      solcRejects(
        `contract C { uint256 x; function r() internal view returns (uint256){ return x; } function f() external pure returns (uint256){ return r(); } }`,
      ),
    ).toBe(true);
  });
  it('@pure calling an env-reader is rejected (JETH164), like solc', () => {
    const codes = jethCodes(
      `@contract class C { @view r(): address { return msg.sender; } @pure f(): address { return this.r(); } }`,
    );
    expect(codes).toContain('JETH481');
    expect(
      solcRejects(
        `contract C { function r() internal view returns (address){ return msg.sender; } function f() external pure returns (address){ return r(); } }`,
      ),
    ).toBe(true);
  });
  it('transitive purity is NOT over-rejected: @pure calling a @pure helper compiles', () => {
    expect(
      jethCodes(
        `class C { a(n: u256): u256 { return n + 1n; } f(n: u256): u256 { return this.a(n) * 2n; } }`,
      ),
    ).toBeNull();
  });
  it('a BARE-name call to an @external function is rejected (JETH240); a this.-prefixed self-call is a valid external call', () => {
    // bare g(n) (no this.) cannot call an @external function by name (solc rejects too) -> JETH240.
    expect(
      jethCodes(`class C { get g(n: u256): External<u256> { return n; } get f(n: u256): External<u256> { return g(n); } }`),
    ).toContain('JETH240');
    // this.g(n) from a NON-pure @external caller is a real external self-call to address(this), byte-identical
    // to solc (covered in external-self-call.test.ts) -> now compiles.
    expect(
      jethCodes(`class C { get g(n: u256): External<u256> { return n; } f(n: u256): External<u256> { return this.g(n); } }`),
    ).toBeNull();
  });
  it('struct arg to an internal callee now compiles (G8+G9)', () => {
    expect(
      jethCodes(
        `type P = { a: u256; b: u256; }; class C { h(p: P): u256 { return p.a; } get f(): External<u256> { let p: P = P(1n, 2n); return this.h(p); } }`,
      ),
    ).toBeNull();
  });
  it('struct arg to an @external callee: BARE-name rejects (JETH240); a this.-prefixed self-call is a valid external call', () => {
    // bare h(p) to an @external h is not internally callable -> JETH240.
    expect(
      jethCodes(
        `type P = { a: u256; b: u256; }; class C { get h(p: P): External<u256> { return p.a; } get f(): External<u256> { let p: P = P(1n, 2n); return h(p); } }`,
      ),
    ).toEqual(expect.arrayContaining(['JETH240']));
    // this.h(p) from a NON-pure @external caller is a real external self-call (staticcall, h is @pure),
    // byte-identical to solc (covered in external-self-call.test.ts) -> now compiles.
    expect(
      jethCodes(
        `@struct class P { a: u256; b: u256; } @contract class C { @external @pure h(p: P): u256 { return p.a; } @external f(): u256 { let p: P = P(1n, 2n); return this.h(p); } }`,
      ),
    ).toBeNull();
  });
  it('multi-value return through an internal call is gated (JETH241)', () => {
    expect(
      jethCodes(
        `class C { two(): [u256, u256] { return [1n, 2n]; } get f(): External<u256> { let a: u256 = this.two(); return a; } }`,
      ),
    ).toEqual(expect.arrayContaining(['JETH241']));
  });
});
