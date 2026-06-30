// Two parity fixes, both verified byte-identical to solc 0.8.35 on the EVM harness:
//
// (A) A constructor that calls an internal helper which READS an @immutable. JETH used to crash
//     (JETH901: solc's legacy assembler rejects "push and assign immutables in the same assembly
//     subroutine") because the ctor-reachable helper copy emitted loadimmutable in the SAME creation
//     subroutine as the ctor's setimmutable. The fix reads the STAGED value from a reserved creation-
//     block memory cell inside the helper instead of loadimmutable (mirroring each staged write), the
//     way solc reads an immutable during construction. Covers u256/address, same-contract + abstract-
//     base helpers, and a ctor-reachable call chain. A direct ctor read and a runtime read are unaffected.
//
// (B) The data-passing @fallback `fallback(input: bytes): bytes` (solc's
//     `fallback(bytes calldata input) external [payable] returns (bytes memory)`). The param receives
//     the whole calldata; `return <bytes>` returns the RAW bytes content (no ABI wrapper - solc's
//     fallback return is the literal returndata). Verified via raw calls with arbitrary non-matching
//     calldata. The bare no-arg/no-return @fallback still works; half-forms are rejected (both-or-none).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
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

async function deployJ(src: string, ctorArg = '') {
  const h = await Harness.create();
  return { h, a: await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode + ctorArg) };
}
async function deployS(src: string, ctorArg = '') {
  const h = await Harness.create();
  return { h, a: await h.deploy(compileSolidity(SPDX + src, 'C').creation + ctorArg) };
}

/** deploy J + S with the same ctor arg; call one getter selector; assert success + returndata parity. */
async function sameGetter(J: string, S: string, sig: string, ctorArg = '') {
  const j = await deployJ(J, ctorArg);
  const s = await deployS(S, ctorArg);
  const rj = await j.h.call(j.a, '0x' + functionSelector(sig));
  const rs = await s.h.call(s.a, '0x' + functionSelector(sig));
  expect(rj.success).toBe(true);
  expect(rs.success).toBe(true);
  expect(rj.returnHex).toBe(rs.returnHex);
  return rj.returnHex;
}

/** deploy J + S; send raw `dataHex` (with `value`); assert success + raw returndata parity. */
async function sameRaw(J: string, S: string, dataHex: string, value = 0n) {
  const j = await deployJ(J);
  const s = await deployS(S);
  const rj = await j.h.call(j.a, dataHex, { value });
  const rs = await s.h.call(s.a, dataHex, { value });
  expect(rj.success).toBe(rs.success);
  expect(rj.returnHex).toBe(rs.returnHex);
  return rj;
}

describe('(A) ctor calls a helper that reads an @immutable (was JETH901) vs solc 0.8.35', () => {
  it('same-contract u256 helper read (g() -> 15)', () =>
    sameGetter(
      `@contract class C { @immutable b: u256; @state o: u256; helper(): u256 { return this.b; } constructor(x: u256){ this.b = x; this.o = this.helper(); } @external @view g(): u256 { return this.o; } }`,
      `contract C { uint256 immutable b; uint256 o; function helper() internal view returns(uint256){return b;} constructor(uint256 x){ b=x; o=helper(); } function g() external view returns(uint256){return o;} }`,
      'g()',
      pad32(15n).replace(/^0x/, ''),
    ).then((r) => expect(BigInt(r)).toBe(15n)));

  it('same-contract address helper read', () =>
    sameGetter(
      `@contract class C { @immutable owner: address; @state o: address; who(): address { return this.owner; } constructor(a: address){ this.owner = a; this.o = this.who(); } @external @view g(): address { return this.o; } }`,
      `contract C { address immutable owner; address o; function who() internal view returns(address){return owner;} constructor(address a){ owner=a; o=who(); } function g() external view returns(address){return o;} }`,
      'g()',
      pad32(BigInt('0x00000000000000000000000011223344556677889900aabbccddeeff0011aabb')).replace(/^0x/, ''),
    ));

  it('ctor-reachable call chain (outer -> inner reads immutable)', () =>
    sameGetter(
      `@contract class C { @immutable b: u256; @state o: u256; inner(): u256 { return this.b; } outer(): u256 { return this.inner() + 1n; } constructor(x: u256){ this.b = x; this.o = this.outer(); } @external @view g(): u256 { return this.o; } }`,
      `contract C { uint256 immutable b; uint256 o; function inner() internal view returns(uint256){return b;} function outer() internal view returns(uint256){return inner()+1;} constructor(uint256 x){ b=x; o=outer(); } function g() external view returns(uint256){return o;} }`,
      'g()',
      pad32(99n).replace(/^0x/, ''),
    ).then((r) => expect(BigInt(r)).toBe(100n)));

  it('helper inherited from an abstract base reads the base immutable', () =>
    sameGetter(
      `@abstract class A { @immutable b: u256; helper(): u256 { return this.b; } } @contract class C extends A { @state o: u256; constructor(x: u256){ this.b = x; this.o = this.helper(); } @external @view g(): u256 { return this.o; } }`,
      `abstract contract A { uint256 immutable b; function helper() internal view returns(uint256){return b;} } contract C is A { uint256 o; constructor(uint256 x){ b=x; o=helper(); } function g() external view returns(uint256){return o;} }`,
      'g()',
      pad32(123n).replace(/^0x/, ''),
    ).then((r) => expect(BigInt(r)).toBe(123n)));

  it('a runtime read of the immutable still uses loadimmutable (no regression)', () =>
    sameGetter(
      `@contract class C { @immutable b: u256; constructor(x: u256){ this.b = x; } @external @view readb(): u256 { return this.b; } }`,
      `contract C { uint256 immutable b; constructor(uint256 x){ b=x; } function readb() external view returns(uint256){return b;} }`,
      'readb()',
      pad32(77n).replace(/^0x/, ''),
    ).then((r) => expect(BigInt(r)).toBe(77n)));

  it('a direct ctor read of the immutable is still byte-identical', () =>
    sameGetter(
      `@contract class C { @immutable b: u256; @state o: u256; constructor(x: u256){ this.b = x; this.o = this.b + 1n; } @external @view g(): u256 { return this.o; } }`,
      `contract C { uint256 immutable b; uint256 o; constructor(uint256 x){ b=x; o=b+1; } function g() external view returns(uint256){return o;} }`,
      'g()',
      pad32(41n).replace(/^0x/, ''),
    ).then((r) => expect(BigInt(r)).toBe(42n)));
});

describe('(B) data-passing @fallback fb(input: bytes): bytes vs solc 0.8.35', () => {
  const ECHO_J = `@contract class C { @fallback fb(input: bytes): bytes { return input; } }`;
  const ECHO_S = `contract C { fallback(bytes calldata input) external returns (bytes memory) { return input; } }`;

  it('echoes arbitrary non-matching calldata raw (no ABI wrapper)', async () => {
    for (const d of ['0xdeadbeef', '0x' + '11'.repeat(40), '0x', '0xab', '0x' + 'cc'.repeat(100)]) {
      const r = await sameRaw(ECHO_J, ECHO_S, d);
      expect(r.returnHex).toBe(d);
    }
  });

  it('fall-off the end returns empty bytes', async () => {
    const r = await sameRaw(
      `@contract class C { @fallback fb(input: bytes): bytes { } }`,
      `contract C { fallback(bytes calldata input) external returns (bytes memory) { } }`,
      '0xdeadbeef',
    );
    expect(r.returnHex).toBe('0x');
  });

  it('payable form accepts value; non-payable reverts on value', async () => {
    await sameRaw(
      `@contract @payable class C { @fallback @payable fb(input: bytes): bytes { return input; } }`,
      `contract C { fallback(bytes calldata input) external payable returns (bytes memory) { return input; } }`,
      '0xcafe',
      100n,
    );
    const r = await sameRaw(ECHO_J, ECHO_S, '0xcafe', 100n);
    expect(r.success).toBe(false);
  });

  it('returns a constructed bytes value', () =>
    sameRaw(
      `@contract class C { @fallback fb(input: bytes): bytes { return bytes("hi"); } }`,
      `contract C { fallback(bytes calldata input) external returns (bytes memory) { return bytes("hi"); } }`,
      '0x1234',
    ).then((r) => expect(r.returnHex).toBe('0x6869')));

  it('reads input.length, slices, and branches', async () => {
    await sameRaw(
      `@contract class C { @state n: u256; @fallback fb(input: bytes): bytes { this.n = input.length; return input.slice(1n, 3n); } @external @view getN(): u256 { return this.n; } }`,
      `contract C { uint256 n; fallback(bytes calldata input) external returns (bytes memory) { n = input.length; return input[1:3]; } function getN() external view returns(uint256){return n;} }`,
      '0x00112233445566',
    ).then((r) => expect(r.returnHex).toBe('0x1122'));
  });

  it('coexists with an external function: matching selector vs fallback', async () => {
    const J = `@contract class C { @external @view foo(): u256 { return 7n; } @fallback fb(input: bytes): bytes { return input; } }`;
    const S = `contract C { function foo() external view returns(uint256){return 7;} fallback(bytes calldata input) external returns (bytes memory) { return input; } }`;
    const rFoo = await sameRaw(J, S, '0x' + functionSelector('foo()'));
    expect(BigInt(rFoo.returnHex)).toBe(7n);
    const rFb = await sameRaw(J, S, '0xabcdef01');
    expect(rFb.returnHex).toBe('0xabcdef01');
  });

  it('the bare no-arg/no-return @fallback still works', () =>
    sameRaw(
      `@contract class C { @state n: u256; @fallback fb(): void { this.n = 5n; } @external @view getN(): u256 { return this.n; } }`,
      `contract C { uint256 n; fallback() external { n = 5; } function getN() external view returns(uint256){return n;} }`,
      '0xdead',
    ).then((r) => expect(r.success).toBe(true)));

  it('rejects half-forms and bad param/return types (clean JETH384, no over-acceptance)', () => {
    // solc requires BOTH the bytes param AND the bytes return, or NEITHER.
    expect(codes(`@contract class C { @fallback fb(): bytes { return bytes("x"); } }`)).toContain('JETH384');
    expect(codes(`@contract class C { @fallback fb(input: bytes): void { } }`)).toContain('JETH384');
    expect(codes(`@contract class C { @fallback fb(x: u256): void {} }`)).toContain('JETH384');
    expect(codes(`@contract class C { @fallback fb(x: string): bytes { return bytes("x"); } }`)).toContain('JETH384');
    // @receive never takes a param or a return type.
    expect(codes(`@contract class C { @receive r(x: bytes): void {} }`)).toContain('JETH384');
    // the valid data-passing form compiles.
    expect(codes(`@contract class C { @fallback fb(input: bytes): bytes { return input; } }`)).toEqual([]);
  });
});
