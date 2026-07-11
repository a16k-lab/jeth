// W6B (tuple-return-alloc-clobber): an external-ABI tuple-literal RETURN whose LATER component
// is keccak256/sha256 over a freshly-allocated memory blob CLOBBERED an earlier tuple component.
// encodeReturnTuple captured `ptr := mload(0x40)` and then lowered static value components INSIDE
// the head/tail loop with the free pointer still pointing at `ptr`: the component's scratch blob
// (abi.encode -> [len=0x20][data], encodePacked -> its own layout) landed ON the tuple buffer, so
// word0 became the blob's length word (0x20 for abi.encode, 0xc0 for encodePacked, d.length for
// keccak256(d)). The fix reserves the buffer frontier (mstore(0x40, cursor)) BEFORE every in-loop
// component-expression evaluation (static value comps, static structNew field args, storage-agg
// slot index exprs) - the scratch then allocates ABOVE the buffer; a later tail write overwriting
// that dead scratch is harmless. Evaluation ORDER is unchanged. The same encoder serves plain
// external returns, @external library multi-returns, interface-call tuples and self-call tuples,
// so all four surfaces are covered here, byte-identical to solc 0.8.35.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity, compileSolidityLinked, deploySolLinked } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));

const J = `type P = { a: u256; b: u256; };
class C {
  h(x: u256): bytes32 { return keccak256(abi.encode(x)); }
  get t1(x: u256): External<[u256, bytes32]> { return [x, keccak256(abi.encode(x))]; }
  get t2(x: u256, y: u256): External<[u256, u256, bytes32]> { return [x, y, keccak256(abi.encode(x))]; }
  get t3(x: u256, y: u256): External<[u256, bytes32, u256, u256]> { return [x, keccak256(abi.encode(y)), y, x]; }
  get t4(x: u256): External<[u256, bytes32]> { return [7n, keccak256(abi.encode(x))]; }
  get t5(x: u256): External<[u256, bytes32]> { return [x, keccak256(abi.encodePacked(x))]; }
  get t6(x: u256, d: bytes): External<[u256, bytes32]> { return [x, keccak256(d)]; }
  get t7(x: u256): External<[u256, bytes32]> { return [x, sha256(abi.encode(x))]; }
  get t8(x: u256, c: bool): External<[u256, bytes32]> { return [x, c ? keccak256(abi.encode(x)) : keccak256(abi.encodePacked(x))]; }
  get t9(x: u256): External<[u256, bytes32]> { return [x, this.h(x)]; }
  get t10(x: u256, a: u256[]): External<[u256, bytes32]> { return [x, keccak256(abi.encode(a.slice(1n)))]; }
  get t11(x: u256): External<[bool, bytes32]> { return [true, keccak256(abi.encode(x))]; }
  get t12(x: u256, a: address): External<[address, bytes32]> { return [a, keccak256(abi.encode(x))]; }
  get t13(x: u256): External<[P, bytes32]> { return [P(x, 2n), keccak256(abi.encode(x))]; }
  get t14(x: u256): External<[u256, P]> { return [x, P(u256(keccak256(abi.encode(x))), 2n)]; }
  get pair(x: u256): External<[u256, bytes32]> { return [x, keccak256(abi.encode(x))]; }
  go(x: u256): External<u256> { let [a, b]: [u256, bytes32] = this.pair(x); return b == bytes32(0n) ? 0n : a; }
  get c1(x: u256): External<[bytes32, u256]> { return [keccak256(abi.encode(x)), x]; }
  get c2(x: u256): External<[u256, bytes]> { return [x, abi.encode(x)]; }
  get c3(x: u256): External<[u256, bytes32]> { const hh: bytes32 = keccak256(abi.encode(x)); return [x, hh]; }
  get c4(c: bool): External<[u256, bytes32]> { if (c) { return [1n, keccak256(abi.encode(1n))]; } }
}`;

const S = `contract C { struct P { uint256 a; uint256 b; }
  function h(uint256 x) internal pure returns (bytes32) { return keccak256(abi.encode(x)); }
  function t1(uint256 x) external pure returns (uint256, bytes32) { return (x, keccak256(abi.encode(x))); }
  function t2(uint256 x, uint256 y) external pure returns (uint256, uint256, bytes32) { return (x, y, keccak256(abi.encode(x))); }
  function t3(uint256 x, uint256 y) external pure returns (uint256, bytes32, uint256, uint256) { return (x, keccak256(abi.encode(y)), y, x); }
  function t4(uint256 x) external pure returns (uint256, bytes32) { return (7, keccak256(abi.encode(x))); }
  function t5(uint256 x) external pure returns (uint256, bytes32) { return (x, keccak256(abi.encodePacked(x))); }
  function t6(uint256 x, bytes calldata d) external pure returns (uint256, bytes32) { return (x, keccak256(d)); }
  function t7(uint256 x) external pure returns (uint256, bytes32) { return (x, sha256(abi.encode(x))); }
  function t8(uint256 x, bool c) external pure returns (uint256, bytes32) { return (x, c ? keccak256(abi.encode(x)) : keccak256(abi.encodePacked(x))); }
  function t9(uint256 x) external pure returns (uint256, bytes32) { return (x, h(x)); }
  function t10(uint256 x, uint256[] calldata a) external pure returns (uint256, bytes32) { return (x, keccak256(abi.encode(a[1:]))); }
  function t11(uint256 x) external pure returns (bool, bytes32) { return (true, keccak256(abi.encode(x))); }
  function t12(uint256 x, address a) external pure returns (address, bytes32) { return (a, keccak256(abi.encode(x))); }
  function t13(uint256 x) external pure returns (P memory, bytes32) { return (P(x, 2), keccak256(abi.encode(x))); }
  function t14(uint256 x) external pure returns (uint256, P memory) { return (x, P(uint256(keccak256(abi.encode(x))), 2)); }
  function pair(uint256 x) external pure returns (uint256, bytes32) { return (x, keccak256(abi.encode(x))); }
  function go(uint256 x) external returns (uint256) { (uint256 a, bytes32 b) = this.pair(x); return b == bytes32(0) ? 0 : a; }
  function c1(uint256 x) external pure returns (bytes32, uint256) { return (keccak256(abi.encode(x)), x); }
  function c2(uint256 x) external pure returns (uint256, bytes memory) { return (x, abi.encode(x)); }
  function c3(uint256 x) external pure returns (uint256, bytes32) { bytes32 hh = keccak256(abi.encode(x)); return (x, hh); }
  function c4(bool c) external pure returns (uint256, bytes32) { if (c) { return (1, keccak256(abi.encode(1))); } }
}`;

const ADDR = '000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
const BYTES3 = W(0x40) + W(3) + 'a1b2c3'.padEnd(64, '0');
const ARR3 = W(0x40) + W(3) + W(11) + W(22) + W(33);

describe('W6B: allocating later tuple component no longer clobbers earlier components', () => {
  it('plain external tuple returns: every confirmed clobber shape is byte-identical to solc', async () => {
    const h = await Harness.create();
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const calls: [string, string][] = [
      ['t1(uint256)', W(5)],
      ['t1(uint256)', W(123456789)],
      ['t1(uint256)', W((1n << 256n) - 1n)],
      ['t2(uint256,uint256)', W(5) + W(7)],
      ['t3(uint256,uint256)', W(5) + W(7)],
      ['t4(uint256)', W(5)],
      ['t5(uint256)', W(5)],
      ['t6(uint256,bytes)', W(9) + BYTES3],
      ['t7(uint256)', W(5)],
      ['t8(uint256,bool)', W(5) + W(1)],
      ['t8(uint256,bool)', W(5) + W(0)],
      ['t9(uint256)', W(5)],
      ['t10(uint256,uint256[])', W(9) + ARR3],
      ['t11(uint256)', W(5)],
      ['t12(uint256,address)', W(5) + ADDR],
      ['t13(uint256)', W(5)],
      ['t14(uint256)', W(5)],
      ['go(uint256)', W(5)], // external SELF-CALL tuple destructure
      // controls (were already correct; must stay correct)
      ['c1(uint256)', W(5)],
      ['c2(uint256)', W(5)],
      ['c3(uint256)', W(5)],
      ['c4(bool)', W(1)],
      ['c4(bool)', W(0)],
    ];
    for (const [sg, args] of calls) {
      const data = sel(sg) + args;
      const jr = await h.call(ja, data);
      const sr = await h.call(sa, data);
      expect(jr.success, sg).toBe(sr.success);
      expect(jr.returnHex, sg).toBe(sr.returnHex);
    }
    // NON-VACUITY: word0 of t1(5) is the literal x=5 (the bug returned the blob length 0x20).
    const r = await h.call(ja, sel('t1(uint256)') + W(5));
    expect(r.returnHex.slice(2, 66)).toBe(W(5));
  });

  it('@external library multi-return destructure hands the caller the real components', async () => {
    const jl = `static class L {
      mm(x: u256): External<[u256, bytes32]> { return [x, keccak256(abi.encode(x))]; }
      mb(x: u256): External<[bool, bytes32]> { return [true, keccak256(abi.encode(x))]; } }
    class C {
      go(x: u256): External<u256> { let [a, b]: [u256, bytes32] = L.mm(x); return b == bytes32(0n) ? 0n : a; }
      gb(x: u256): External<u256> { let [a, b]: [bool, bytes32] = L.mb(x); return a ? 1n : 2n; } }`;
    const sl = `library L {
      function mm(uint256 x) public pure returns (uint256, bytes32) { return (x, keccak256(abi.encode(x))); }
      function mb(uint256 x) public pure returns (bool, bytes32) { return (true, keccak256(abi.encode(x))); } }
    contract C {
      function go(uint256 x) external returns (uint256) { (uint256 a, bytes32 b) = L.mm(x); return b == bytes32(0) ? 0 : a; }
      function gb(uint256 x) external returns (uint256) { (bool a, bytes32 b) = L.mb(x); b; return a ? 1 : 2; } }`;
    const jb = compile(jl, { fileName: 'C.jeth' });
    const sb = compileSolidityLinked(SPDX + sl, 'C', ['L']);
    const jeth = await Harness.create();
    const sol = await Harness.create();
    const ja = (await jeth.deployLinked(jb)).address;
    const sa = await deploySolLinked(sol, sb);
    for (const [sg, args] of [['go(uint256)', W(5)], ['gb(uint256)', W(5)]] as const) {
      const jr = await jeth.call(ja, sel(sg) + args);
      const sr = await sol.call(sa, sel(sg) + args);
      expect(jr.success, sg).toBe(sr.success);
      expect(jr.returnHex, sg).toBe(sr.returnHex);
    }
    // NON-VACUITY: go(5) returns 5 (the bug returned 0x20; the bool variant REVERTED empty).
    const r = await jeth.call(ja, sel('go(uint256)') + W(5));
    expect(r.returnHex).toBe('0x' + W(5));
  });

  it('interface-call tuple destructure decodes the real components', async () => {
    const jCallee = `class D { get pair(x: u256): External<[u256, bytes32]> { return [x, keccak256(abi.encode(x))]; } }`;
    const sCallee = `contract D { function pair(uint256 x) external pure returns (uint256, bytes32) { return (x, keccak256(abi.encode(x))); } }`;
    const jCaller = `interface IFoo { pair(x: u256): Pure<[u256, bytes32]>; }
      class C { get go(t: address, x: u256): External<u256> { let [a, b]: [u256, bytes32] = IFoo(t).pair(x); return b == bytes32(0n) ? 0n : a; } }`;
    const sCaller = `interface IFoo { function pair(uint256 x) external pure returns (uint256, bytes32); }
      contract C { function go(address t, uint256 x) external view returns (uint256) { (uint256 a, bytes32 b) = IFoo(t).pair(x); return b == bytes32(0) ? 0 : a; } }`;
    const jeth = await Harness.create();
    const sol = await Harness.create();
    const jd = await jeth.deploy(compile(jCallee, { fileName: 'D.jeth' }).creationBytecode);
    const jc = await jeth.deploy(compile(jCaller, { fileName: 'C.jeth' }).creationBytecode);
    const sd = await sol.deploy(compileSolidity(SPDX + sCallee, 'D').creation);
    const sc = await sol.deploy(compileSolidity(SPDX + sCaller, 'C').creation);
    const jr = await jeth.call(jc, sel('go(address,uint256)') + pad32(BigInt(jd.toString())) + W(5));
    const sr = await sol.call(sc, sel('go(address,uint256)') + pad32(BigInt(sd.toString())) + W(5));
    expect(jr.success).toBe(sr.success);
    expect(jr.returnHex).toBe(sr.returnHex);
    expect(jr.returnHex).toBe('0x' + W(5)); // non-vacuous: the bug decoded a=0x20
  });
});
