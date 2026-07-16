// Edge A (over-rejection lifted byte-identical): reading and writing a LEAF field of a NESTED DYNAMIC
// struct of a dynamic-field struct memory local - v.t.n. The nested dynamic-struct field's head word holds
// a POINTER to the nested image; the access derefs the chain to the inner image, then reads/writes the
// final field. Previously JETH900 (read) / JETH214 (write); now byte-identical to solc 0.8.35.
//
// Covered: value read/write, packed sibling fields (u8/u128), compound-assign (+= -= *= ++), string/bytes
// read + re-point, a dynamic value-array field whole read + re-point, 3- and 4-level nesting, offset math
// when a dynamic / static-aggregate field precedes the nested struct, address/bool/int leaves, emit, and
// copy-on-assignment (deep-copy) semantics. The whole-nested-struct read consumed by return / abi.encode
// stays a clean reject (a PRE-EXISTING single-level limitation, shared by `return v.t`, not a miscompile).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => n.toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

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

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};

describe('Edge A: nested dynamic-struct leaf field read/write - byte-identical to solc 0.8.35', () => {
  it('value read + write + sibling, after a dynamic field', async () => {
    await eqCalls(
      'type T = { s: string; n: u256; m: u256 }; type S = { a: u256; t: T }; class C { get go(): External<u256> { let v: S = S(1n, T("hi", 7n, 8n)); v.t.n = 100n; v.t.m = 200n; v.a = 9n; return v.t.n + v.t.m + v.a; } }',
      'struct T { string s; uint256 n; uint256 m; } struct S { uint256 a; T t; } contract C { function go() external pure returns(uint256){ S memory v=S(1,T("hi",7,8)); v.t.n=100; v.t.m=200; v.a=9; return v.t.n+v.t.m+v.a; } }',
      [['go()', '']],
    );
  });

  it('packed sibling value fields (u8 / u128 / u256)', async () => {
    await eqCalls(
      'type T = { a: u8; b: u128; c: u256 }; type S = { x: u256; t: T }; class C { get ga(): External<u8> { let v: S=S(9n,T(3n,4n,5n)); return v.t.a; } get gb(): External<u128> { let v: S=S(9n,T(3n,4n,5n)); return v.t.b; } get gc(): External<u256> { let v: S=S(9n,T(3n,4n,5n)); v.t.c = 77n; return v.t.c; } }',
      'struct T { uint8 a; uint128 b; uint256 c; } struct S { uint256 x; T t; } contract C { function ga() external pure returns(uint8){ S memory v=S(9,T(3,4,5)); return v.t.a; } function gb() external pure returns(uint128){ S memory v=S(9,T(3,4,5)); return v.t.b; } function gc() external pure returns(uint256){ S memory v=S(9,T(3,4,5)); v.t.c=77; return v.t.c; } }',
      [['ga()', ''], ['gb()', ''], ['gc()', '']],
    );
  });

  it('compound-assign forms (+= -= *= ++)', async () => {
    await eqCalls(
      'type T = { n: u256 }; type S = { a: u256; t: T }; class C { get go(): External<u256> { let v: S=S(1n,T(100n)); v.t.n += 5n; v.t.n -= 2n; v.t.n *= 3n; v.t.n++; return v.t.n; } }',
      'struct T { uint256 n; } struct S { uint256 a; T t; } contract C { function go() external pure returns(uint256){ S memory v=S(1,T(100)); v.t.n+=5; v.t.n-=2; v.t.n*=3; v.t.n++; return v.t.n; } }',
      [['go()', '']],
    );
  });

  it('string read + re-point write (length change)', async () => {
    await eqCalls(
      'type T = { n: u256; s: string }; type S = { a: u256; t: T }; class C { get rd(): External<string> { let v: S=S(1n,T(2n,"hello")); return v.t.s; } get wr(): External<string> { let v: S=S(1n,T(2n,"hi")); v.t.s = "changed-to-a-much-longer-string-value"; return v.t.s; } }',
      'struct T { uint256 n; string s; } struct S { uint256 a; T t; } contract C { function rd() external pure returns(string memory){ S memory v=S(1,T(2,"hello")); return v.t.s; } function wr() external pure returns(string memory){ S memory v=S(1,T(2,"hi")); v.t.s="changed-to-a-much-longer-string-value"; return v.t.s; } }',
      [['rd()', ''], ['wr()', '']],
    );
  });

  it('bytes read + re-point write', async () => {
    await eqCalls(
      'type T = { b: bytes; n: u256 }; type S = { a: u256; t: T }; class C { get go(): External<bytes> { let v: S=S(1n,T(bytes("abc"),9n)); v.t.b = bytes("xyzw"); return v.t.b; } }',
      'struct T { bytes b; uint256 n; } struct S { uint256 a; T t; } contract C { function go() external pure returns(bytes memory){ S memory v=S(1,T(bytes("abc"),9)); v.t.b=bytes("xyzw"); return v.t.b; } }',
      [['go()', '']],
    );
  });

  it('dynamic value-array field: whole read + re-point write (from a calldata source)', async () => {
    await eqCalls(
      'type T = { arr: u256[]; n: u256 }; type S = { a: u256; t: T }; class C { get rd(xs: u256[]): External<u256[]> { let v: S=S(1n,T(xs,9n)); return v.t.arr; } get wr(xs: u256[], ys: u256[]): External<u256[]> { let v: S=S(1n,T(xs,9n)); v.t.arr = ys; return v.t.arr; } }',
      'struct T { uint256[] arr; uint256 n; } struct S { uint256 a; T t; } contract C { function rd(uint256[] calldata xs) external pure returns(uint256[] memory){ S memory v=S(1,T(xs,9)); return v.t.arr; } function wr(uint256[] calldata xs, uint256[] calldata ys) external pure returns(uint256[] memory){ S memory v=S(1,T(xs,9)); v.t.arr=ys; return v.t.arr; } }',
      [
        ['rd(uint256[])', W(0x20n) + W(2n) + W(7n) + W(8n)],
        ['wr(uint256[],uint256[])', W(0x40n) + W(0xa0n) + W(1n) + W(5n) + W(2n) + W(7n) + W(8n)],
      ],
    );
  });

  it('3-level nesting (value + string leaves through a dynamic chain)', async () => {
    await eqCalls(
      'type U = { m: u256; s: string }; type T = { u: U; n: u256 }; type S = { a: u256; t: T }; class C { get go(): External<u256> { let v: S=S(1n,T(U(5n,"z"),2n)); v.t.u.m = 42n; return v.t.u.m + v.t.n; } get gs(): External<string> { let v: S=S(1n,T(U(5n,"deep"),2n)); return v.t.u.s; } }',
      'struct U { uint256 m; string s; } struct T { U u; uint256 n; } struct S { uint256 a; T t; } contract C { function go() external pure returns(uint256){ S memory v=S(1,T(U(5,"z"),2)); v.t.u.m=42; return v.t.u.m+v.t.n; } function gs() external pure returns(string memory){ S memory v=S(1,T(U(5,"deep"),2)); return v.t.u.s; } }',
      [['go()', ''], ['gs()', '']],
    );
  });

  it('4-level nesting through an all-dynamic chain (value + string leaves)', async () => {
    await eqCalls(
      'type A4 = { v: u256; tag: string }; type U = { a4: A4; m: u256 }; type T = { u: U; n: u256 }; type S = { x: u256; t: T }; class C { get go(): External<u256> { let s: S=S(1n,T(U(A4(7n,"x"),2n),3n)); s.t.u.a4.v = 70n; s.t.u.m = 20n; return s.t.u.a4.v + s.t.u.m + s.t.n; } get gs(): External<string> { let s: S=S(1n,T(U(A4(0n,"deep"),0n),0n)); return s.t.u.a4.tag; } }',
      'struct A4 { uint256 v; string tag; } struct U { A4 a4; uint256 m; } struct T { U u; uint256 n; } struct S { uint256 x; T t; } contract C { function go() external pure returns(uint256){ S memory s=S(1,T(U(A4(7,"x"),2),3)); s.t.u.a4.v=70; s.t.u.m=20; return s.t.u.a4.v+s.t.u.m+s.t.n; } function gs() external pure returns(string memory){ S memory s=S(1,T(U(A4(0,"deep"),0),0)); return s.t.u.a4.tag; } }',
      [['go()', ''], ['gs()', '']],
    );
  });

  it('offset math: a static-aggregate field precedes the nested struct', async () => {
    await eqCalls(
      'type T = { n: u256 }; type S = { fa: Arr<u256,2>; t: T }; class C { get go(): External<u256> { let v: S=S([u256(10n),20n],T(30n)); v.t.n = 99n; return v.t.n + v.fa[0n] + v.fa[1n]; } }',
      'struct T { uint256 n; } struct S { uint256[2] fa; T t; } contract C { function go() external pure returns(uint256){ S memory v=S([uint256(10),20],T(30)); v.t.n=99; return v.t.n+v.fa[0]+v.fa[1]; } }',
      [['go()', '']],
    );
  });

  it('address / bool / int leaves', async () => {
    await eqCalls(
      'type T = { ad: address; fl: bool; iv: i256 }; type S = { a: u256; t: T }; class C { get ga(): External<address> { let v: S=S(1n,T(address(0x1234n),true,-5n)); return v.t.ad; } get gf(): External<bool> { let v: S=S(1n,T(address(0n),true,0n)); return v.t.fl; } get gi(): External<i256> { let v: S=S(1n,T(address(0n),false,-99n)); v.t.iv = -7n; return v.t.iv; } }',
      'struct T { address ad; bool fl; int256 iv; } struct S { uint256 a; T t; } contract C { function ga() external pure returns(address){ S memory v=S(1,T(address(0x1234),true,-5)); return v.t.ad; } function gf() external pure returns(bool){ S memory v=S(1,T(address(0),true,0)); return v.t.fl; } function gi() external pure returns(int256){ S memory v=S(1,T(address(0),false,-99)); v.t.iv=-7; return v.t.iv; } }',
      [['ga()', ''], ['gf()', ''], ['gi()', '']],
    );
  });

  it('emit with nested value + string fields', async () => {
    const hj = await Harness.create();
    const hs = await Harness.create();
    const J = 'type T = { n: u256; s: string }; type S = { a: u256; t: T }; class C { E: event<{ x: u256; y: string }>; go(): External<void> { let v: S=S(1n,T(42n,"hello")); emit(E(v.t.n, v.t.s)); } }';
    const So = 'struct T { uint256 n; string s; } struct S { uint256 a; T t; } contract C { event E(uint256 x, string y); function go() external { S memory v=S(1,T(42,"hello")); emit E(v.t.n, v.t.s); } }';
    const aj = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await hs.deploy(compileSolidity(SPDX + So, 'C').creation);
    const rj = await hj.call(aj, sel('go()'));
    const rs = await hs.call(as, sel('go()'));
    const fmt = (r: { logs?: { topics: string[]; data: string }[] }) =>
      JSON.stringify((r.logs ?? []).map((l) => ({ t: l.topics, d: l.data })));
    expect(fmt(rj)).toBe(fmt(rs));
  });

  it('copy-on-assignment: let w = v deep-copies (mutating w.t.n leaves v.t.n untouched)', async () => {
    await eqCalls(
      'type T = { n: u256 }; type S = { a: u256; t: T }; class C { get go(): External<u256> { let v: S=S(1n,T(5n)); let w: S = v; w.t.n = 99n; return v.t.n; } }',
      'struct T { uint256 n; } struct S { uint256 a; T t; } contract C { function go() external pure returns(uint256){ S memory v=S(1,T(5)); S memory w=v; w.t.n=99; return v.t.n; } }',
      [['go()', '']],
    );
  });

  it('a wrong nested field name is a clean reject (JETH210), not a crash', () => {
    expect(
      codes('type T = { n: u256 }; type S = { a: u256; t: T }; class C { get go(): External<u256> { let v: S=S(1n,T(2n)); return v.t.nope; } }'),
    ).toContain('JETH210');
  });
});

// Edge B: consuming a WHOLE nested dynamic-struct field value (v.t single-level, v.t.u multi-level) as an
// aggregate - return it, abi.encode it, pass it to an internal function, bind it to a local (an ALIAS,
// solc memory-reference semantics), emit it, write it to a storage struct / mapping value / nested storage
// field. The field's head word holds an absolute pointer to the nested image; the codecs (tupleSrc /
// buildDynStructLocal / storeStructTo) take that pointer. Previously JETH900; now byte-identical to solc.
describe('Edge B: whole nested dyn-struct field as an aggregate value - byte-identical to solc 0.8.35', () => {
  const D1 = 'type T = { n: u256; s: string }; type S = { a: u256; t: T };';
  const D1s = 'struct T { uint256 n; string s; } struct S { uint256 a; T t; }';

  it('return v.t (single) and v.t.u (multi)', async () => {
    await eqCalls(
      `${D1} class C { get go(): External<T> { let v: S=S(1n,T(7n,"hi")); return v.t; } }`,
      `${D1s} contract C { function go() external pure returns(T memory){ S memory v=S(1,T(7,"hi")); return v.t; } }`,
      [['go()', '']],
    );
    await eqCalls(
      'type U = { m: u256; s: string }; type T = { u: U; n: u256 }; type S = { a: u256; t: T }; class C { get go(): External<U> { let v: S=S(1n,T(U(7n,"hi"),2n)); return v.t.u; } }',
      'struct U { uint256 m; string s; } struct T { U u; uint256 n; } struct S { uint256 a; T t; } contract C { function go() external pure returns(U memory){ S memory v=S(1,T(U(7,"hi"),2)); return v.t.u; } }',
      [['go()', '']],
    );
  });

  it('abi.encode(v.t), keccak256(abi.encode(v.t)), abi.encode(v.a, v.t)', async () => {
    await eqCalls(
      `type T = { n: u256; m: u256 }; type S = { a: u256; t: T }; class C { get enc(): External<bytes> { let v: S=S(1n,T(7n,8n)); return abi.encode(v.t); } get kk(): External<bytes32> { let v: S=S(1n,T(7n,8n)); return keccak256(abi.encode(v.t)); } get mx(): External<bytes> { let v: S=S(3n,T(7n,8n)); return abi.encode(v.a, v.t); } }`,
      `struct T { uint256 n; uint256 m; } struct S { uint256 a; T t; } contract C { function enc() external pure returns(bytes memory){ S memory v=S(1,T(7,8)); return abi.encode(v.t); } function kk() external pure returns(bytes32){ S memory v=S(1,T(7,8)); return keccak256(abi.encode(v.t)); } function mx() external pure returns(bytes memory){ S memory v=S(3,T(7,8)); return abi.encode(v.a, v.t); } }`,
      [['enc()', ''], ['kk()', ''], ['mx()', '']],
    );
  });

  it('pass v.t to an internal fn; aliasing write-through; 2-hop chain', async () => {
    await eqCalls(
      `${D1} class C { g(t: T): u256 { return t.n; } mut(t: T): void { t.n = 99n; } h(t: T): T { t.n = t.n + 1n; return t; } get callit(): External<u256> { let v: S=S(1n,T(7n,"hi")); return this.g(v.t); } get aliasw(): External<u256> { let v: S=S(1n,T(7n,"hi")); this.mut(v.t); return v.t.n; } get chain(): External<u256> { let v: S=S(1n,T(7n,"hi")); return this.g(this.h(v.t)); } }`,
      `${D1s} contract C { function g(T memory t) internal pure returns(uint256){ return t.n; } function mut(T memory t) internal pure { t.n=99; } function h(T memory t) internal pure returns(T memory){ t.n=t.n+1; return t; } function callit() external pure returns(uint256){ S memory v=S(1,T(7,"hi")); return g(v.t); } function aliasw() external pure returns(uint256){ S memory v=S(1,T(7,"hi")); mut(v.t); return v.t.n; } function chain() external pure returns(uint256){ S memory v=S(1,T(7,"hi")); return g(h(v.t)); } }`,
      [['callit()', ''], ['aliasw()', ''], ['chain()', '']],
    );
  });

  it('bind let t: T = v.t aliases (mutating t writes through to v)', async () => {
    await eqCalls(
      `${D1} class C { get go(): External<u256> { let v: S=S(1n,T(7n,"hi")); let t: T = v.t; t.n = 9n; return v.t.n; } }`,
      `${D1s} contract C { function go() external pure returns(uint256){ S memory v=S(1,T(7,"hi")); T memory t=v.t; t.n=9; return v.t.n; } }`,
      [['go()', '']],
    );
  });

  it('emit(E(v.t)) non-indexed log is byte-identical', async () => {
    const hj = await Harness.create();
    const hs = await Harness.create();
    const J = `${D1} class C { E: event<{ t: T }>; go(): External<void> { let v: S=S(1n,T(42n,"hello")); emit(E(v.t)); } }`;
    const So = `${D1s} contract C { event E(T t); function go() external { S memory v=S(1,T(42,"hello")); emit E(v.t); } }`;
    const aj = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await hs.deploy(compileSolidity(SPDX + So, 'C').creation);
    const rj = await hj.call(aj, sel('go()'));
    const rs = await hs.call(as, sel('go()'));
    const fmt = (r: { logs?: { topics: string[]; data: string }[] }) =>
      JSON.stringify((r.logs ?? []).map((l) => ({ t: l.topics, d: l.data })));
    expect(fmt(rj)).toBe(fmt(rs));
  });

  it('storage struct field / mapping value / nested storage field = v.t round-trips', async () => {
    await eqCalls(
      `${D1} class C { d: T; m: mapping<u256,T>; sd(): External<void> { let v: S=S(1n,T(42n,"stored")); this.d = v.t; } sm(k: u256): External<void> { let v: S=S(1n,T(5n,"mapval")); this.m[k] = v.t; } get dn(): External<u256> { return this.d.n; } get ds(): External<string> { return this.d.s; } get mn(k: u256): External<u256> { return this.m[k].n; } get ms(k: u256): External<string> { return this.m[k].s; } }`,
      `${D1s} contract C { T d; mapping(uint256=>T) m; function sd() external { S memory v=S(1,T(42,"stored")); d=v.t; } function sm(uint256 k) external { S memory v=S(1,T(5,"mapval")); m[k]=v.t; } function dn() external view returns(uint256){ return d.n; } function ds() external view returns(string memory){ return d.s; } function mn(uint256 k) external view returns(uint256){ return m[k].n; } function ms(uint256 k) external view returns(string memory){ return m[k].s; } }`,
      [['sd()', ''], ['sm(uint256)', W(3n)], ['dn()', ''], ['ds()', ''], ['mn(uint256)', W(3n)], ['ms(uint256)', W(3n)]],
    );
  });
});
