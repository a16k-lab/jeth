// FIX-ALL sweep, Batch 1: pure-analyzer over-rejection lifts, each byte-identical to solc 0.8.35.
//  OR6  internal call returning a dynamic-leaf array (bytes[]/string[]/P[]) - returnSupported now mirrors
//       the param predicate (aggArrayByRef).
//  OR11 a qualified internal-library tuple return L.f(...) - direct return / destructure / tuple-assign
//       (tupleCallName + resolveTupleCall now resolve a library callee).
//  OR17 abi.encodeCall(IFoo.bar, [args]) - selector + ABI-encoded args (sugar over encodeWithSelector).
//  OR18 type(C).name / type(IFoo).name - a compile-time contract/interface-name string constant.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => pad32(n);

async function diff(J: string, S: string, calls: [string, string][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sig, args] of calls) {
    const data = sel(sig) + (args || '');
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sig).toBe(rs.success);
    expect(rj.returnHex, sig).toBe(rs.returnHex);
  }
}

describe('FIX-ALL batch 1: pure-analyzer over-rejection lifts vs solc 0.8.35', () => {
  it('OR6: internal call returning bytes[] / string[] / P[]', async () => {
    await diff(
      `@contract class C { mk(): bytes[] { let m: bytes[] = new Array<bytes>(2n); m[0n]=abi.encode(7n); m[1n]=abi.encode(8n); return m; } @external @pure get(): bytes[] { return this.mk(); } }`,
      `contract C { function mk() internal pure returns (bytes[] memory) { bytes[] memory m=new bytes[](2); m[0]=abi.encode(uint256(7)); m[1]=abi.encode(uint256(8)); return m; } function get() external pure returns (bytes[] memory) { return mk(); } }`,
      [['get()', '']],
    );
    await diff(
      `@struct class P{a:u256;b:u256;} @contract class C { mk(): P[] { let m: P[] = [P(1n,2n),P(3n,4n)]; return m; } @external @pure get(): P[] { return this.mk(); } }`,
      `struct P{uint256 a;uint256 b;} contract C { function mk() internal pure returns (P[] memory) { P[] memory m=new P[](2); m[0]=P(1,2); m[1]=P(3,4); return m; } function get() external pure returns (P[] memory) { return mk(); } }`,
      [['get()', '']],
    );
  });

  it('OR11: qualified internal-library tuple return (return / destructure / tuple-assign / 3-tuple)', async () => {
    const L = '@library class L { swap(a: u256, b: u256): [u256, u256] { return [b, a]; } }';
    const SL =
      'library L { function swap(uint256 a, uint256 b) internal pure returns (uint256, uint256){ return (b, a); } }';
    await diff(
      `${L} @contract class C { @external @pure f(a: u256, b: u256): [u256, u256] { return L.swap(a, b); } }`,
      `${SL} contract C { function f(uint256 a, uint256 b) external pure returns (uint256, uint256){ return L.swap(a,b); } }`,
      [['f(uint256,uint256)', W(7n) + W(9n)]],
    );
    await diff(
      `${L} @contract class C { @external @pure f(a: u256, b: u256): u256 { let [x, y]: [u256,u256] = L.swap(a, b); return x*100n + y; } }`,
      `${SL} contract C { function f(uint256 a, uint256 b) external pure returns (uint256){ (uint256 x, uint256 y) = L.swap(a,b); return x*100+y; } }`,
      [['f(uint256,uint256)', W(7n) + W(9n)]],
    );
    await diff(
      `${L} @contract class C { @external @pure f(a: u256, b: u256): u256 { let x: u256 = 0n; let y: u256 = 0n; [x, y] = L.swap(a, b); return x*100n + y; } }`,
      `${SL} contract C { function f(uint256 a, uint256 b) external pure returns (uint256){ uint256 x; uint256 y; (x, y) = L.swap(a,b); return x*100+y; } }`,
      [['f(uint256,uint256)', W(7n) + W(9n)]],
    );
    await diff(
      `@library class L { tri(a:u256): [u256,u256,u256] { return [a, a*2n, a*3n]; } } @contract class C { @external @pure f(a: u256): u256 { let [x,y,z]: [u256,u256,u256] = L.tri(a); return x+y+z; } }`,
      `library L { function tri(uint256 a) internal pure returns (uint256,uint256,uint256){ return (a, a*2, a*3); } } contract C { function f(uint256 a) external pure returns (uint256){ (uint256 x,uint256 y,uint256 z) = L.tri(a); return x+y+z; } }`,
      [['f(uint256)', W(5n)]],
    );
  });

  it('OR17: abi.encodeCall(IFoo.bar, [args]) - single, multi, dynamic-arg', async () => {
    await diff(
      `@interface class I { @external foo(x: u256): u256; } @contract class C { @external @pure k(): bytes { return abi.encodeCall(I.foo, [5n]); } }`,
      `interface I { function foo(uint256 x) external returns(uint256); } contract C { function k() external pure returns(bytes memory){ return abi.encodeCall(I.foo, (5)); } }`,
      [['k()', '']],
    );
    await diff(
      `@interface class I { @external foo(x: u256, a: address): bytes32; } @contract class C { @external @pure k(a: address): bytes { return abi.encodeCall(I.foo, [5n, a]); } }`,
      `interface I { function foo(uint256 x, address a) external returns(bytes32); } contract C { function k(address a) external pure returns(bytes memory){ return abi.encodeCall(I.foo, (5, a)); } }`,
      [['k(address)', W(0x1234n)]],
    );
    await diff(
      `@interface class I { @external foo(s: string, n: u256): bool; } @contract class C { @external @pure k(): bytes { return abi.encodeCall(I.foo, ["hi", 7n]); } }`,
      `interface I { function foo(string calldata s, uint256 n) external returns(bool); } contract C { function k() external pure returns(bytes memory){ return abi.encodeCall(I.foo, ("hi", 7)); } }`,
      [['k()', '']],
    );
  });

  it('OR18: type(C).name and type(IFoo).name', async () => {
    await diff(
      `@contract class C { @external @pure k(): string { return type(C).name; } }`,
      `contract C { function k() external pure returns(string memory){ return type(C).name; } }`,
      [['k()', '']],
    );
    await diff(
      `@interface class IFoo { @external foo(x: u256): u256; } @contract class C { @external @pure k(): string { return type(IFoo).name; } }`,
      `interface IFoo { function foo(uint256 x) external returns(uint256); } contract C { function k() external pure returns(string memory){ return type(IFoo).name; } }`,
      [['k()', '']],
    );
  });
});
