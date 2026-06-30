// Safe over-rejections found by the full differential audit (JETH rejected valid Solidity; never a
// miscompile). Lifted byte-identical to solc 0.8.35. This file grows as more are lifted.
//  OR0: @constant fold of bytesN(uintM(...)) / bytesN(bytesM(...)) casts (runtime already accepted).
//  OR2: @constant fold of address<->uint160 casts (u160(address(x)) / address(u160(x))).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function eqValue(jeth: string, sol: string, sig: string) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  const rj = await hj.call(aj, sel(sig));
  const rs = await hs.call(as, sel(sig));
  expect(rj.success).toBe(rs.success);
  expect(rj.returnHex).toBe(rs.returnHex);
}

describe('audit over-rejections lifted byte-identical', () => {
  it('OR0: @constant bytesN(uintM(x)) / bytesN(bytesM(x)) fold to solc values', async () => {
    await eqValue(
      '@contract class C { @constant K: bytes32 = bytes32(u256(0x1234n)); @external @pure get(): bytes32 { return this.K; } }',
      'contract C { bytes32 constant K = bytes32(uint256(0x1234)); function get() external pure returns (bytes32) { return K; } }',
      'get()',
    );
    await eqValue(
      '@contract class C { @constant K: bytes4 = bytes4(bytes2(0x1234n)); @external @pure get(): bytes4 { return this.K; } }',
      'contract C { bytes4 constant K = bytes4(bytes2(0x1234)); function get() external pure returns (bytes4) { return K; } }',
      'get()',
    );
    await eqValue(
      '@contract class C { @constant K: bytes2 = bytes2(bytes4(0x12345678n)); @external @pure get(): bytes2 { return this.K; } }',
      'contract C { bytes2 constant K = bytes2(bytes4(0x12345678)); function get() external pure returns (bytes2) { return K; } }',
      'get()',
    );
  });

  it('OR2: @constant address<->uint160 casts fold to solc values', async () => {
    await eqValue(
      '@contract class C { @constant K: u160 = u160(address(0x1234n)); @external @pure get(): u160 { return this.K; } }',
      'contract C { uint160 constant K = uint160(address(0x1234)); function get() external pure returns (uint160) { return K; } }',
      'get()',
    );
    await eqValue(
      '@contract class C { @constant K: address = address(u160(0x1234n)); @external @pure get(): address { return this.K; } }',
      'contract C { address constant K = address(uint160(0x1234)); function get() external pure returns (address) { return K; } }',
      'get()',
    );
  });

  it('OR7: two unrelated sibling bases with same-sig @virtual, merged with @override(A,B)', async () => {
    await eqValue(
      '@abstract class A { @virtual @external f(): u256 { return 1n; } } @abstract class B { @virtual @external f(): u256 { return 2n; } } @contract class C extends A, B { @override(A,B) @external f(): u256 { return 9n; } }',
      'abstract contract A { function f() external virtual returns(uint256){ return 1; } } abstract contract B { function f() external virtual returns(uint256){ return 2; } } contract C is A, B { function f() external override(A,B) returns(uint256){ return 9; } }',
      'f()',
    );
  });

  it('OR6: a nested-dynamic-struct memory local (construct / return / emit / abi.encode / field)', async () => {
    const T = '@struct class T { n: u256; s: string; } @struct class S { a: u256; t: T; }';
    const Ts = 'struct T { uint256 n; string s; } struct S { uint256 a; T t; }';
    // return v (build + read-back), v.a value-field read, abi.encode(v), deep 3-level, value-nested-value layout
    await eqValue(
      `${T} @contract class C { @external @pure f(): S { let v: S = S(1n, T(2n, "deep")); return v; } }`,
      `contract C { ${Ts} function f() external pure returns(S memory){ S memory v = S(1, T(2, "deep")); return v; } }`,
      'f()',
    );
    await eqValue(
      `${T} @contract class C { @external @pure f(): bytes { let v: S = S(1n, T(2n, "deep")); return abi.encode(v); } }`,
      `contract C { ${Ts} function f() external pure returns(bytes memory){ S memory v = S(1, T(2, "deep")); return abi.encode(v); } }`,
      'f()',
    );
    await eqValue(
      `${T} @contract class C { @external @pure f(): u256 { let v: S = S(5n, T(2n,"x")); v.a = 99n; return v.a; } }`,
      `contract C { ${Ts} function f() external pure returns(uint256){ S memory v = S(5, T(2,"x")); v.a = 99; return v.a; } }`,
      'f()',
    );
    // 3-level dynamic nesting
    const D = '@struct class U { m: u256; s: string; } @struct class T2 { n: u256; u: U; } @struct class S2 { a: u256; t: T2; }';
    const Ds = 'struct U { uint256 m; string s; } struct T2 { uint256 n; U u; } struct S2 { uint256 a; T2 t; }';
    await eqValue(
      `${D} @contract class C { @external @pure f(): S2 { let v: S2 = S2(1n, T2(2n, U(3n, "deepest"))); return v; } }`,
      `contract C { ${Ds} function f() external pure returns(S2 memory){ S2 memory v = S2(1, T2(2, U(3, "deepest"))); return v; } }`,
      'f()',
    );
  });

  it('OR6: a nested-dynamic-struct memory local emits a byte-identical event log', async () => {
    const T = '@struct class T { n: u256; s: string; } @struct class S { a: u256; t: T; }';
    const Ts = 'struct T { uint256 n; string s; } struct S { uint256 a; T t; }';
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(
      compile(`${T} @contract class C { @event E(v: S); @external f(): void { let v: S = S(1n, T(2n, "deep")); emit(E(v)); } }`, { fileName: 'C.jeth' }).creationBytecode,
    );
    const as = await hs.deploy(compileSolidity(SPDX + `contract C { ${Ts} event E(S v); function f() external { S memory v = S(1, T(2, "deep")); emit E(v); } }`, 'C').creation);
    const rj = await hj.call(aj, sel('f()'));
    const rs = await hs.call(as, sel('f()'));
    const logs = (r: { logs?: { topics: string[]; data: string }[] }) => JSON.stringify(r.logs?.map((l) => ({ t: l.topics, d: l.data })) ?? []);
    expect(logs(rj)).toBe(logs(rs));
  });

  it('OR5: indexed dynamic-struct-element array event emits a byte-identical keccak topic', async () => {
    const W = (n: bigint) => n.toString(16).padStart(64, '0');
    const padR = (h: string) => h + '0'.repeat((64 - (h.length % 64)) % 64);
    const logs = (r: { logs?: { topics: string[]; data: string }[] }) => JSON.stringify(r.logs?.map((l) => ({ t: l.topics, d: l.data })) ?? []);
    const run = async (jeth: string, sol: string, sig: string, args: string) => {
      const hj = await Harness.create();
      const hs = await Harness.create();
      const aj = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
      const as = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
      const rj = await hj.call(aj, sel(sig) + args);
      const rs = await hs.call(as, sel(sig) + args);
      expect(rj.success).toBe(rs.success);
      expect(logs(rj)).toBe(logs(rs));
    };
    // P[] = [P(7,"aa"), P(9,"bbbb")]
    await run(
      '@struct class P { a: u256; s: string; } @contract class C { @event E(@indexed ps: P[]); @external f(ps: P[]): void { emit(E(ps)); } }',
      'contract C { struct P { uint256 a; string s; } event E(P[] indexed ps); function f(P[] calldata ps) external { emit E(ps); } }',
      'f((uint256,string)[])',
      W(0x20n) + W(2n) + W(0x40n) + W(0xc0n) + W(7n) + W(0x40n) + W(2n) + padR('6161') + W(9n) + W(0x40n) + W(4n) + padR('62626262'),
    );
    // empty array
    await run(
      '@struct class P { a: u256; s: string; } @contract class C { @event E(@indexed ps: P[]); @external f(ps: P[]): void { emit(E(ps)); } }',
      'contract C { struct P { uint256 a; string s; } event E(P[] indexed ps); function f(P[] calldata ps) external { emit E(ps); } }',
      'f((uint256,string)[])',
      W(0x20n) + W(0n),
    );
    // fixed outer Arr<P,2>
    await run(
      '@struct class P { a: u256; s: string; } @contract class C { @event E(@indexed ps: Arr<P,2>); @external f(ps: Arr<P,2>): void { emit(E(ps)); } }',
      'contract C { struct P { uint256 a; string s; } event E(P[2] indexed ps); function f(P[2] calldata ps) external { emit E(ps); } }',
      'f((uint256,string)[2])',
      W(0x20n) + W(0x40n) + W(0xc0n) + W(7n) + W(0x40n) + W(2n) + padR('6161') + W(9n) + W(0x40n) + W(4n) + padR('62626262'),
    );
  });

  it('OR5: a struct element with a dyn-array / nested-dyn-struct field stays a clean reject', () => {
    const rej = (s: string) => {
      try {
        compile(s, { fileName: 'C.jeth' });
        return [];
      } catch (e: unknown) {
        return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
      }
    };
    expect(rej('@struct class P { a: u256; tags: u256[]; } @contract class C { @event E(@indexed ps: P[]); @external f(ps: P[]): void { emit(E(ps)); } }')).toContain('JETH207');
    expect(rej('@struct class T { n: u256; s: string; } @struct class P { a: u256; t: T; } @contract class C { @event E(@indexed ps: P[]); @external f(ps: P[]): void { emit(E(ps)); } }')).toContain('JETH207');
  });

  it('still rejects illegal const casts (no over-acceptance regression)', () => {
    const rej = (s: string) => {
      try {
        compile(s, { fileName: 'C.jeth' });
        return false;
      } catch {
        return true;
      }
    };
    // wrong-size uintM -> bytesN is still rejected (solc rejects bytes4(uint256(x)))
    expect(rej('@contract class C { @constant K: bytes4 = bytes4(u256(0x12n)); @external @pure get(): bytes4 { return this.K; } }')).toBe(true);
  });
});
