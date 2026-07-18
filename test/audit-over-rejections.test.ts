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
const W = (n: bigint) => n.toString(16).padStart(64, '0');
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

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

describe('audit over-rejections lifted byte-identical', () => {
  it('OR0: @constant bytesN(uintM(x)) / bytesN(bytesM(x)) fold to solc values', async () => {
    await eqValue(
      'class C { static K: bytes32 = bytes32(u256(0x1234n)); get get(): External<bytes32> { return this.K; } }',
      'contract C { bytes32 constant K = bytes32(uint256(0x1234)); function get() external pure returns (bytes32) { return K; } }',
      'get()',
    );
    await eqValue(
      'class C { static K: bytes4 = bytes4(bytes2(0x1234n)); get get(): External<bytes4> { return this.K; } }',
      'contract C { bytes4 constant K = bytes4(bytes2(0x1234)); function get() external pure returns (bytes4) { return K; } }',
      'get()',
    );
    await eqValue(
      'class C { static K: bytes2 = bytes2(bytes4(0x12345678n)); get get(): External<bytes2> { return this.K; } }',
      'contract C { bytes2 constant K = bytes2(bytes4(0x12345678)); function get() external pure returns (bytes2) { return K; } }',
      'get()',
    );
  });

  it('OR8: @constant bytesN(stringLiteral) folds to the left-aligned UTF-8 bytes (solc parity)', async () => {
    // Every width bytes1..bytes32, short / exact-width / empty string, via the explicit getter and the
    // auto-generated @external @constant getter. The folded value is the UTF-8 bytes LEFT-aligned in the
    // high N bytes, byte-identical to solc's `bytesN("...")` literal conversion.
    for (const [n, s] of [
      [1, 'x'],
      [2, 'a'],
      [4, 'abcd'],
      [4, 'ab'],
      [4, ''],
      [8, 'abcdefgh'],
      [32, 'hello'],
      [32, 'abcdefghijklmnopqrstuvwxyzABCDEF'],
    ] as [number, string][]) {
      await eqValue(
        `class C { static K: bytes${n} = bytes${n}("${s}"); get get(): External<bytes${n}> { return this.K; } }`,
        `contract C { bytes${n} constant K = bytes${n}("${s}"); function get() external pure returns (bytes${n}) { return K; } }`,
        'get()',
      );
    }
    // auto-getter form (@external @constant synthesizes solc's public-constant getter)
    await eqValue(
      'class C { static K: Visible<bytes4> = bytes4("abcd"); }',
      'contract C { bytes4 public constant K = bytes4("abcd"); }',
      'K()',
    );
    // NON-VACUOUS concrete decode: bytes4("abcd") == 0x61626364.. (the UTF-8 bytes of "abcd", left-aligned)
    const hj = await Harness.create();
    const aj: Address = await hj.deploy(
      compile('class C { static K: Visible<bytes4> = bytes4("abcd"); }', { fileName: 'C.jeth' })
        .creationBytecode,
    );
    const rk = await hj.call(aj, sel('K()'));
    expect(rk.success).toBe(true);
    expect(rk.returnHex).toBe('0x6162636400000000000000000000000000000000000000000000000000000000');
  });

  it('OR8: still rejects an OVER-LENGTH bytesN(stringLiteral) @constant (no over-acceptance)', () => {
    const rej = (s: string) => {
      try {
        compile(s, { fileName: 'C.jeth' });
        return false;
      } catch {
        return true;
      }
    };
    // solc rejects "Explicit type conversion not allowed ... Literal is larger than the type"; JETH keeps
    // its clean reject (byteLen > N).
    expect(rej('class C { static K: bytes2 = bytes2("abcd"); get get(): External<bytes2> { return this.K; } }')).toBe(true);
    expect(rej('class C { static K: bytes1 = bytes1("ab"); get get(): External<bytes1> { return this.K; } }')).toBe(true);
    expect(rej('class C { static K: bytes4 = bytes4("abcde"); get get(): External<bytes4> { return this.K; } }')).toBe(true);
  });

  it('OR-b lock: @constant bytesN(bytesM(const)) same/narrower/wider folds to solc values', async () => {
    // Same-width identity, narrowing (keep high bytes), and WIDENING (zero-pad on the right) all fold
    // byte-identically to solc. This is already handled by the OR0 bytesN(bytesM) const-cast path; the
    // test locks it against regression alongside the OR8 string-literal fold.
    await eqValue(
      'class C { static K: bytes4 = bytes4(bytes4(0xababababn)); get get(): External<bytes4> { return this.K; } }',
      'contract C { bytes4 constant K = bytes4(bytes4(0xabababab)); function get() external pure returns (bytes4) { return K; } }',
      'get()',
    );
    await eqValue(
      'class C { static K: bytes4 = bytes4(bytes8(0x1122334455667788n)); get get(): External<bytes4> { return this.K; } }',
      'contract C { bytes4 constant K = bytes4(bytes8(0x1122334455667788)); function get() external pure returns (bytes4) { return K; } }',
      'get()',
    );
    // widening bytes4 -> bytes8 (solc ACCEPTS, zero-pads on the right)
    await eqValue(
      'class C { static K: bytes8 = bytes8(bytes4(0x12345678n)); get get(): External<bytes8> { return this.K; } }',
      'contract C { bytes8 constant K = bytes8(bytes4(0x12345678)); function get() external pure returns (bytes8) { return K; } }',
      'get()',
    );
    // NON-VACUOUS decode: bytes8(bytes4(0x12345678)) == 0x1234567800000000 (zero-padded right)
    const hj = await Harness.create();
    const aj: Address = await hj.deploy(
      compile(
        'class C { static K: bytes8 = bytes8(bytes4(0x12345678n)); get get(): External<bytes8> { return this.K; } }',
        { fileName: 'C.jeth' },
      ).creationBytecode,
    );
    const rk = await hj.call(aj, sel('get()'));
    expect(rk.returnHex).toBe('0x1234567800000000000000000000000000000000000000000000000000000000');
  });

  it('OR-c LIFTED: an inline array literal for a value / nested-dynamic-leaf dynamic-array struct field now accepts (superset, byte-identical to new+fill); Arr<T,N>[] and Q[] literals stay rejected', () => {
    // solc REJECTS the literal spelling `P(7, ["x","y"])` (uint256[N] does NOT implicitly convert to
    // uint256[]) in EVERY position, so this is a DOCUMENTED JETH SUPERSET (like `let a: u256[] = [..]`),
    // byte-identical to solc's `new T[](n)` + fill value form (verified deploy+run+decode elsewhere).
    // Admitted for a value-element or nested-dynamic-leaf dynamic-array field; a FIXED-inner value array
    // (Arr<T,N>[]) and a struct-element array (Q[]) STAY a clean JETH226 reject.
    const acc = (s: string) => {
      try {
        compile(s, { fileName: 'C.jeth' });
        return true;
      } catch {
        return false;
      }
    };
    // LIFTED (now accept):
    expect(acc('type P = { id: u256; tags: string[]; }; class C { get f(): External<P> { let p: P = P(7n, ["x","y"]); return p; } }')).toBe(true);
    expect(acc('type P = { id: u256; nums: u256[]; }; class C { get f(): External<P> { let p: P = P(7n, [1n,2n]); return p; } }')).toBe(true);
    expect(acc('type P = { id: u256; nums: u256[]; }; class C { get f(): External<P> { let p: P = P(7n, []); return p; } }')).toBe(true);
    // STILL REJECT (fixed-inner value array hits a pre-existing mem->storage copy bug; struct-element array
    // solc-unsupported) - kept a clean JETH226 reject:
    expect(acc('type P = { id: u256; g: Arr<u256,2>[]; }; class C { get f(): External<u256> { let p: P = P(7n, [[u256(1n),2n]]); return p.id; } }')).toBe(false);
    expect(acc('type Q = { x: u256 }; type P = { id: u256; qs: Q[]; }; class C { get f(): External<u256> { let p: P = P(7n, [Q(1n)]); return p.id; } }')).toBe(false);
    // the true-dynamic-array-VALUE form is still accepted - not regressed.
    expect(acc('type P = { id: u256; nums: u256[]; }; class C { get f(): External<P> { let a: u256[] = new Array<u256>(2n); a[0n]=1n; a[1n]=2n; let p: P = P(7n, a); return p; } }')).toBe(true);
  });

  it('OR2: @constant address<->uint160 casts fold to solc values', async () => {
    await eqValue(
      'class C { static K: u160 = u160(address(0x1234n)); get get(): External<u160> { return this.K; } }',
      'contract C { uint160 constant K = uint160(address(0x1234)); function get() external pure returns (uint160) { return K; } }',
      'get()',
    );
    await eqValue(
      'class C { static K: address = address(u160(0x1234n)); get get(): External<address> { return this.K; } }',
      'contract C { address constant K = address(uint160(0x1234)); function get() external pure returns (address) { return K; } }',
      'get()',
    );
  });

  it('OR7: two unrelated sibling bases with same-sig @virtual, merged with @override(A,B)', async () => {
    await eqValue(
      'abstract class A { @virtual get f(): External<u256> { return 1n; } } abstract class B { @virtual get f(): External<u256> { return 2n; } } class C extends A, B { @override(A,B) get f(): External<u256> { return 9n; } }',
      'abstract contract A { function f() external virtual returns(uint256){ return 1; } } abstract contract B { function f() external virtual returns(uint256){ return 2; } } contract C is A, B { function f() external override(A,B) returns(uint256){ return 9; } }',
      'f()',
    );
  });

  it('OR6: a nested-dynamic-struct memory local (construct / return / emit / abi.encode / field)', async () => {
    const T = 'type T = { n: u256; s: string; }; type S = { a: u256; t: T; };';
    const Ts = 'struct T { uint256 n; string s; } struct S { uint256 a; T t; }';
    // return v (build + read-back), v.a value-field read, abi.encode(v), deep 3-level, value-nested-value layout
    await eqValue(
      `${T} class C { get f(): External<S> { let v: S = S(1n, T(2n, "deep")); return v; } }`,
      `contract C { ${Ts} function f() external pure returns(S memory){ S memory v = S(1, T(2, "deep")); return v; } }`,
      'f()',
    );
    await eqValue(
      `${T} class C { get f(): External<bytes> { let v: S = S(1n, T(2n, "deep")); return abi.encode(v); } }`,
      `contract C { ${Ts} function f() external pure returns(bytes memory){ S memory v = S(1, T(2, "deep")); return abi.encode(v); } }`,
      'f()',
    );
    await eqValue(
      `${T} class C { get f(): External<u256> { let v: S = S(5n, T(2n,"x")); v.a = 99n; return v.a; } }`,
      `contract C { ${Ts} function f() external pure returns(uint256){ S memory v = S(5, T(2,"x")); v.a = 99; return v.a; } }`,
      'f()',
    );
    // 3-level dynamic nesting
    const D = 'type U = { m: u256; s: string; }; type T2 = { n: u256; u: U; }; type S2 = { a: u256; t: T2; };';
    const Ds = 'struct U { uint256 m; string s; } struct T2 { uint256 n; U u; } struct S2 { uint256 a; T2 t; }';
    await eqValue(
      `${D} class C { get f(): External<S2> { let v: S2 = S2(1n, T2(2n, U(3n, "deepest"))); return v; } }`,
      `contract C { ${Ds} function f() external pure returns(S2 memory){ S2 memory v = S2(1, T2(2, U(3, "deepest"))); return v; } }`,
      'f()',
    );
  });

  it('OR6: a nested-dynamic-struct memory local emits a byte-identical event log', async () => {
    const T = 'type T = { n: u256; s: string; }; type S = { a: u256; t: T; };';
    const Ts = 'struct T { uint256 n; string s; } struct S { uint256 a; T t; }';
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(
      compile(`${T} class C { E: event<{ v: S }>; f(): External<void> { let v: S = S(1n, T(2n, "deep")); emit(E(v)); } }`, { fileName: 'C.jeth' }).creationBytecode,
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
      'type P = { a: u256; s: string; }; class C { E: event<{ ps: indexed<P[]> }>; f(ps: P[]): External<void> { emit(E(ps)); } }',
      'contract C { struct P { uint256 a; string s; } event E(P[] indexed ps); function f(P[] calldata ps) external { emit E(ps); } }',
      'f((uint256,string)[])',
      W(0x20n) + W(2n) + W(0x40n) + W(0xc0n) + W(7n) + W(0x40n) + W(2n) + padR('6161') + W(9n) + W(0x40n) + W(4n) + padR('62626262'),
    );
    // empty array
    await run(
      'type P = { a: u256; s: string; }; class C { E: event<{ ps: indexed<P[]> }>; f(ps: P[]): External<void> { emit(E(ps)); } }',
      'contract C { struct P { uint256 a; string s; } event E(P[] indexed ps); function f(P[] calldata ps) external { emit E(ps); } }',
      'f((uint256,string)[])',
      W(0x20n) + W(0n),
    );
    // fixed outer Arr<P,2>
    await run(
      'type P = { a: u256; s: string; }; class C { E: event<{ ps: indexed<Arr<P,2>> }>; f(ps: Arr<P,2>): External<void> { emit(E(ps)); } }',
      'contract C { struct P { uint256 a; string s; } event E(P[2] indexed ps); function f(P[2] calldata ps) external { emit E(ps); } }',
      'f((uint256,string)[2])',
      W(0x20n) + W(0x40n) + W(0xc0n) + W(7n) + W(0x40n) + W(2n) + padR('6161') + W(9n) + W(0x40n) + W(4n) + padR('62626262'),
    );
  });

  it('Edge C: a struct element with a dyn-array / nested-dyn-struct field is now ACCEPTED (byte-identical topic)', () => {
    // Lifted by Edge C: packTopicStructFromAbi follows a dyn-array field / nested-dyn-struct field through
    // its head offset and recurses, byte-identical to solc (verified on the harness in
    // event-indexed-dyn-struct-array.test.ts). These were previously sound JETH207 rejects.
    const codes = (s: string) => {
      try {
        compile(s, { fileName: 'C.jeth' });
        return [];
      } catch (e: unknown) {
        return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
      }
    };
    expect(codes('type P = { a: u256; tags: u256[]; }; class C { E: event<{ ps: indexed<P[]> }>; f(ps: P[]): External<void> { emit(E(ps)); } }')).toEqual([]);
    expect(codes('type T = { n: u256; s: string; }; type P = { a: u256; t: T; }; class C { E: event<{ ps: indexed<P[]> }>; f(ps: P[]): External<void> { emit(E(ps)); } }')).toEqual([]);
  });

  it('OR1: indexing a @constant bytesN value (this.B[i]) returns the indexed byte', async () => {
    // const index (each byte) + runtime index (incl OOB) byte-identical to solc.
    await eqValue(
      'class C { static B: bytes4 = bytes4(0x12345678n); get g0(): External<bytes1> { return this.B[0n]; } get g3(): External<bytes1> { return this.B[3n]; } }',
      'contract C { bytes4 constant B = 0x12345678; function g0() external pure returns(bytes1){ return B[0]; } function g3() external pure returns(bytes1){ return B[3]; } }',
      'g0()',
    );
    await eqCalls(
      'class C { static B: bytes4 = bytes4(0x12345678n); get g(i: u256): External<bytes1> { return this.B[i]; } }',
      'contract C { bytes4 constant B = 0x12345678; function g(uint256 i) external pure returns(bytes1){ return B[i]; } }',
      [['g(uint256)', W(0n)], ['g(uint256)', W(3n)], ['g(uint256)', W(4n)]], // 4 = runtime OOB
    );
    // a const OOB index is a compile reject in both
    let codes: string[] = [];
    try {
      compile('class C { static B: bytes4 = bytes4(0x12345678n); get g(): External<bytes1> { return this.B[4n]; } }', { fileName: 'C.jeth' });
    } catch (e: unknown) {
      codes = ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
    }
    expect(codes).toContain('JETH152');
  });

  it('OR4: abi.encode of a calldata dyn-struct leaf value-array field (abi.encode(p.tags))', async () => {
    const cd = W(9n) + W(0x40n) + W(3n) + W(11n) + W(22n) + W(33n); // P(9, [11,22,33])
    await eqCalls(
      'type P = { a: u256; tags: u256[]; }; class C { get f(p: P): External<bytes> { return abi.encode(p.tags); } get g(p: P): External<bytes> { return abi.encodePacked(p.tags); } get h(p: P): External<bytes32> { return keccak256(abi.encode(p.tags)); } get m(p: P): External<bytes> { return abi.encode(p.a, p.tags); } }',
      'contract C { struct P { uint256 a; uint256[] tags; } function f(P calldata p) external pure returns(bytes memory){ return abi.encode(p.tags); } function g(P calldata p) external pure returns(bytes memory){ return abi.encodePacked(p.tags); } function h(P calldata p) external pure returns(bytes32){ return keccak256(abi.encode(p.tags)); } function m(P calldata p) external pure returns(bytes memory){ return abi.encode(p.a, p.tags); } }',
      [['f((uint256,uint256[]))', cd], ['g((uint256,uint256[]))', cd], ['h((uint256,uint256[]))', cd], ['m((uint256,uint256[]))', cd], ['f((uint256,uint256[]))', W(9n) + W(0x40n) + W(0n)]],
    );
  });

  it('OR3: binding a fixed value-array element of a memory outer array aliases (write-through)', async () => {
    await eqValue(
      'class C { get f(): External<u256> { let xs: Arr<u256,2>[] = [[1n,2n],[3n,4n]]; let row: Arr<u256,2> = xs[0n]; row[0n] = 99n; return xs[0n][0n]; } }',
      'contract C { function f() external pure returns(uint256){ uint256[2][] memory xs = new uint256[2][](2); xs[0]=[uint256(1),2]; xs[1]=[uint256(3),4]; uint256[2] memory row = xs[0]; row[0]=99; return xs[0][0]; } }',
      'f()',
    );
    // for-of over the outer array (reads each fixed-array element)
    await eqValue(
      'class C { get f(): External<u256> { let xs: Arr<u256,2>[] = [[1n,2n],[3n,4n]]; let s: u256 = 0n; for (let row of xs) { s = s + row[0n] + row[1n]; } return s; } }',
      'contract C { function f() external pure returns(uint256){ uint256[2][] memory xs = new uint256[2][](2); xs[0]=[uint256(1),2]; xs[1]=[uint256(3),4]; uint256 s=0; for (uint i=0;i<xs.length;i++){ uint256[2] memory row=xs[i]; s+=row[0]+row[1]; } return s; } }',
      'f()',
    );
    // runtime index bind + write-through
    await eqCalls(
      'class C { get f(i: u256): External<u256> { let xs: Arr<u256,2>[] = [[1n,2n],[3n,4n]]; let row: Arr<u256,2> = xs[i]; row[1n] = 77n; return xs[i][1n]; } }',
      'contract C { function f(uint256 i) external pure returns(uint256){ uint256[2][] memory xs = new uint256[2][](2); xs[0]=[uint256(1),2]; xs[1]=[uint256(3),4]; uint256[2] memory row = xs[i]; row[1]=77; return xs[i][1]; } }',
      [['f(uint256)', W(0n)], ['f(uint256)', W(1n)]],
    );
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
    expect(rej('class C { static K: bytes4 = bytes4(u256(0x12n)); get get(): External<bytes4> { return this.K; } }')).toBe(true);
  });
});
