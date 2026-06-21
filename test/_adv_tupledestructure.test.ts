// Adversarial differential tests for tuple destructuring + multi-value internal calls.
// Oracle: solc. Invariant: byte-identical returndata, success flag, and raw storage slots.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

// ----------------------------------------------------------------------------
// One big contract pair covering many attack vectors. Each external fn has a
// JETH twin and a Solidity twin with identical semantics.
// ----------------------------------------------------------------------------

const JETH = `@contract class C {
  @state x: u256;
  @state y: u256;
  @state z: u256;
  @state counter: u256;
  @state pa: u128;            // packed pair in one slot with pb
  @state pb: u128;
  @state arr: Arr<u256, 4>;   // fixed array (storage)
  @state dyn: u256[];         // dynamic array
  @state m: mapping<u256, u256>;

  bump(): u256 { this.counter = this.counter + 1n; return this.counter; }
  idx0(): u256 { this.counter = this.counter + 1n; return 0n; }
  idx1(): u256 { this.counter = this.counter + 100n; return 1n; }
  // order-tracing helpers: append a decimal tag to a sequence so the full order
  // of evaluation is captured (not just the multiset of side effects).
  tag(t: u256): u256 { this.counter = this.counter * 10n + t; return t; }
  tagIdx(t: u256, ret: u256): u256 { this.counter = this.counter * 10n + t; return ret; }

  @pure two(): [u256, u256] { return [11n, 22n]; }
  @pure three(): [u256, u256, u256] { return [1n, 2n, 3n]; }
  @pure addsub(a: u256, b: u256): [u256, u256] { return [a + b, a - b]; }
  @pure mixT(): [u8, bool, i64, address, bytes32] {
    return [255n, true, -5n, address(0xaan), bytes32(0x1122334455667788990011223344556677889900112233445566778899001122n)];
  }
  @pure widenSrc(): [u8, u16] { return [200n, 60000n]; }
  nested(): [u256, u256] { let [a, b] = this.two(); return [a + 1n, b + 1n]; }
  recurT(n: u256): [u256, u256] {
    if (n == 0n) { return [0n, 1n]; }
    let [a, b] = this.recurT(n - 1n);
    return [b, a + b];
  }

  // --- eval-order: tuple-literal RHS with side-effecting components, left-to-right ---
  @external orderLit(): u256 {
    this.counter = 0n;
    let [a, b, c] = [this.bump(), this.bump(), this.bump()];
    return a * 1000000n + b * 1000n + c;
  }
  // --- eval-order: assign form, RHS components side-effecting; targets are locals ---
  @external orderAssignLit(): u256 {
    this.counter = 0n;
    let a: u256 = 0n; let b: u256 = 0n;
    [a, b] = [this.bump(), this.bump()];
    return a * 1000n + b;
  }
  // --- eval-order: side-effecting INDEX expressions on the LHS targets ---
  // (a[idx0()], a[idx1()]) = (RHS). counter encodes which index-fn ran and order.
  @external orderTargetIdx(): u256 {
    this.counter = 0n;
    this.arr[0n] = 0n; this.arr[1n] = 0n;
    [this.arr[this.idx0()], this.arr[this.idx1()]] = this.two();
    return this.counter;
  }
  // returns the final array contents too
  @external orderTargetIdxVals(): u256 {
    this.arr[0n] = 0n; this.arr[1n] = 0n;
    [this.arr[this.idx0()], this.arr[this.idx1()]] = this.two();
    return this.arr[0n] * 1000n + this.arr[1n];
  }
  // --- mixed: target index AND side-effecting RHS, interleaved ---
  @external orderMixed(): u256 {
    this.counter = 0n;
    this.arr[0n] = 0n; this.arr[1n] = 0n;
    [this.arr[this.idx0()], this.arr[this.idx1()]] = [this.bump(), this.bump()];
    return this.counter;
  }

  // --- swaps ---
  @external @pure swap2(p: u256, q: u256): u256 { let a: u256 = p; let b: u256 = q; [a, b] = [b, a]; return a * 1000000n + b; }
  @external @pure rotate3(p: u256, q: u256, r: u256): u256 {
    let a: u256 = p; let b: u256 = q; let c: u256 = r;
    [a, b, c] = [c, a, b];
    return a * 1000000n + b * 1000n + c;
  }
  @external @pure noop2(p: u256, q: u256): u256 { let a: u256 = p; let b: u256 = q; [a, b] = [a, b]; return a * 1000000n + b; }
  @external swapState(p: u256, q: u256): u256 { this.x = p; this.y = q; [this.x, this.y] = [this.y, this.x]; return this.x * 1000000n + this.y; }
  // swap two PACKED state vars (both in one slot)
  @external swapPacked(p: u128, q: u128): u256 { this.pa = p; this.pb = q; [this.pa, this.pb] = [this.pb, this.pa]; return u256(this.pa) * 1000000n + u256(this.pb); }
  // rotate three state vars via tuple
  @external rotateState(p: u256, q: u256, r: u256): u256 {
    this.x = p; this.y = q; this.z = r;
    [this.x, this.y, this.z] = [this.z, this.x, this.y];
    return this.x * 1000000n + this.y * 1000n + this.z;
  }

  // --- multi-return variety ---
  @external @pure nestedCall(): u256 { let [a, b] = this.nested(); return a * 1000n + b; }
  @external recur(n: u256): u256 { let [a, b] = this.recurT(n); return a * 1000000n + b; }
  // multi-return fn called in a loop, accumulate
  @external loopSum(n: u256): u256 {
    let acc: u256 = 0n;
    let i: u256 = 0n;
    while (i < n) { let [s, d] = this.addsub(i + 10n, i); acc = acc + s + d; i = i + 1n; }
    return acc;
  }
  // skipped CALL components: call still runs once (counter), value discarded
  @external skipCallSide(): u256 {
    this.counter = 0n;
    let [a, , c] = this.threeSide();
    return a * 1000000n + c * 1000n + this.counter;
  }
  threeSide(): [u256, u256, u256] { this.counter = this.counter + 7n; return [1n, 2n, 3n]; }
  // skipped TUPLE-literal components: side effects still happen
  @external skipLitSide(): u256 {
    this.counter = 0n;
    let [a, , c] = [this.bump(), this.bump(), this.bump()];
    return a * 1000000n + c * 1000n + this.counter;
  }
  // leading + trailing skips
  @external @pure skipEnds(): u256 { let [ , b, ,] = this.three(); return b; }
  @external @pure allButOne(): u256 { let [ , , c] = this.three(); return c; }

  // --- mixed component types & widening ---
  @external @pure mixedTypes(): u256 {
    let [a, f, sg, ad, bz] = this.mixT();
    let r: u256 = u256(a);
    if (f) { r = r + 1000n; }
    r = r + (u256(u64(sg)) & 0xffn);          // low byte of the signed value as evidence
    r = r + (u256(u160(ad)) & 0xffn) * 100000n;
    r = r + ((u256(bz) & 0xffn) == 0x22n ? 7000000n : 0n);
    return r;
  }
  // widen u8/u16 components into u256 targets (assign form, existing vars)
  @external widenAssign(): u256 {
    let a: u256 = 123n; let b: u256 = 456n;
    [a, b] = this.widenSrc();
    return a * 1000000n + b;
  }
  // widen in decl form
  @external @pure widenDecl(): u256 {
    let [a, b]: [u256, u256] = [u256(7n), u256(8n)];
    let [c, d] = this.widenSrc();   // u8,u16 -> declared as their own types
    return a + b + u256(c) + u256(d);
  }

  // --- signed min/max via tuple ---
  @pure signs(): [i256, i256] { return [-57896044618658097711785492504343953926634992332820282019728792003956564819968n, 57896044618658097711785492504343953926634992332820282019728792003956564819967n]; }
  @external @pure signMinMax(): i256 { let [lo, hi] = this.signs(); return lo + hi; }

  // --- targets: struct fields, array elems, mapping values ---
  @external arrTargets(): u256 {
    this.arr[2n] = 0n; this.arr[3n] = 0n;
    [this.arr[2n], this.arr[3n]] = this.two();
    return this.arr[2n] * 1000n + this.arr[3n];
  }
  @external mapTargets(k: u256): u256 {
    this.m[k] = 0n; this.m[k + 1n] = 0n;
    [this.m[k], this.m[k + 1n]] = this.two();
    return this.m[k] * 1000n + this.m[k + 1n];
  }
  // mixed targets: one state, one local
  @external mixedTargets(): u256 { let b: u256 = 0n; [this.x, b] = this.two(); return this.x * 1000n + b; }
  // self-referential swap-ish: [a, b] = [b, a] where b reads state mutated? (pure locals here)

  // --- nesting in control flow ---
  @external @pure inIf(c: bool): u256 {
    let r: u256 = 0n;
    if (c) { let [a, b] = this.two(); r = a + b; } else { let [a, b] = this.three2(); r = a + b; }
    return r;
  }
  @pure three2(): [u256, u256] { return [100n, 200n]; }
  @external @pure inFor(n: u256): u256 {
    let acc: u256 = 0n;
    for (let i: u256 = 0n; i < n; i = i + 1n) { let [a, b] = this.two(); acc = acc + a + b; }
    return acc;
  }

  // RHS reads state, targets are the SAME state vars: classic "must snapshot RHS
  // before any store" case. [this.x, this.y] = [this.y, this.x + this.y].
  @external stateFib(p: u256, q: u256): u256 {
    this.x = p; this.y = q;
    [this.x, this.y] = [this.y, this.x + this.y];
    return this.x * 1000000n + this.y;
  }
  // checked-arith revert parity: addsub underflows when b > a.
  @external @pure underflow(p: u256, q: u256): u256 { let [s, d] = this.addsub(p, q); return s + d; }
  // dynamic-array element targets via tuple (with a resize first).
  @external dynTargets(): u256 {
    this.dyn = [0n, 0n, 0n];
    [this.dyn[0n], this.dyn[2n]] = this.two();
    return this.dyn[0n] * 1000n + this.dyn[2n] + this.dyn[1n];
  }
  // out-of-bounds dynamic index in a tuple target must panic like solc.
  @external dynOOB(): u256 {
    this.dyn = [0n];
    [this.dyn[0n], this.dyn[5n]] = this.two();
    return this.dyn[0n];
  }

  // ORDER TRACE: side-effecting target indices vs side-effecting RHS. The final
  // counter encodes the exact interleaving (each helper appends a decimal digit).
  // assign form, tuple-literal RHS: targets arr[tagIdx(1,0)] and arr[tagIdx(2,1)],
  // RHS components tag(3), tag(4). Whatever order solc picks, counter must match.
  @external traceLitIdx(): u256 {
    this.counter = 0n;
    this.arr[0n] = 0n; this.arr[1n] = 0n;
    [this.arr[this.tagIdx(1n, 0n)], this.arr[this.tagIdx(2n, 1n)]] = [this.tag(3n), this.tag(4n)];
    return this.counter;
  }
  // assign form, multi-call RHS: targets evaluated around the single call.
  @external traceCallIdx(): u256 {
    this.counter = 0n;
    this.arr[0n] = 0n; this.arr[1n] = 0n;
    [this.arr[this.tagIdx(1n, 0n)], this.arr[this.tagIdx(2n, 1n)]] = this.twoTag();
    return this.counter;
  }
  twoTag(): [u256, u256] { this.counter = this.counter * 10n + 9n; return [11n, 22n]; }
  // mapping-key side effects as targets
  @external traceMapKey(): u256 {
    this.counter = 0n;
    [this.m[this.tag(1n)], this.m[this.tag(2n)]] = [this.tag(3n), this.tag(4n)];
    return this.counter;
  }
  // tuple-literal RHS only, three components, order trace
  @external traceLit3(): u256 {
    this.counter = 0n;
    let a: u256 = 0n; let b: u256 = 0n; let c: u256 = 0n;
    [a, b, c] = [this.tag(1n), this.tag(2n), this.tag(3n)];
    return this.counter * 1000000n + a * 10000n + b * 100n + c;
  }

  @external getCounter(): u256 { return this.counter; }
  @external getArr(i: u256): u256 { return this.arr[i]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256 x; uint256 y; uint256 z; uint256 counter;
  uint128 pa; uint128 pb;
  uint256[4] arr;
  uint256[] dyn;
  mapping(uint256 => uint256) m;

  function bump() internal returns (uint256) { counter = counter + 1; return counter; }
  function idx0() internal returns (uint256) { counter = counter + 1; return 0; }
  function idx1() internal returns (uint256) { counter = counter + 100; return 1; }
  function tag(uint256 t) internal returns (uint256) { counter = counter * 10 + t; return t; }
  function tagIdx(uint256 t, uint256 ret) internal returns (uint256) { counter = counter * 10 + t; return ret; }

  function two() internal pure returns (uint256, uint256) { return (11, 22); }
  function three() internal pure returns (uint256, uint256, uint256) { return (1, 2, 3); }
  function addsub(uint256 a, uint256 b) internal pure returns (uint256, uint256) { return (a + b, a - b); }
  function mixT() internal pure returns (uint8, bool, int64, address, bytes32) {
    return (255, true, -5, address(uint160(0xaa)), 0x1122334455667788990011223344556677889900112233445566778899001122);
  }
  function widenSrc() internal pure returns (uint8, uint16) { return (200, 60000); }
  function nested() internal pure returns (uint256, uint256) { (uint256 a, uint256 b) = two(); return (a + 1, b + 1); }
  function recurT(uint256 n) internal returns (uint256, uint256) {
    if (n == 0) { return (0, 1); }
    (uint256 a, uint256 b) = recurT(n - 1);
    return (b, a + b);
  }

  function orderLit() external returns (uint256) {
    counter = 0;
    (uint256 a, uint256 b, uint256 c) = (bump(), bump(), bump());
    return a * 1000000 + b * 1000 + c;
  }
  function orderAssignLit() external returns (uint256) {
    counter = 0;
    uint256 a = 0; uint256 b = 0;
    (a, b) = (bump(), bump());
    return a * 1000 + b;
  }
  function orderTargetIdx() external returns (uint256) {
    counter = 0;
    arr[0] = 0; arr[1] = 0;
    (arr[idx0()], arr[idx1()]) = two();
    return counter;
  }
  function orderTargetIdxVals() external returns (uint256) {
    arr[0] = 0; arr[1] = 0;
    (arr[idx0()], arr[idx1()]) = two();
    return arr[0] * 1000 + arr[1];
  }
  function orderMixed() external returns (uint256) {
    counter = 0;
    arr[0] = 0; arr[1] = 0;
    (arr[idx0()], arr[idx1()]) = (bump(), bump());
    return counter;
  }

  function swap2(uint256 p, uint256 q) external pure returns (uint256) { uint256 a = p; uint256 b = q; (a, b) = (b, a); return a * 1000000 + b; }
  function rotate3(uint256 p, uint256 q, uint256 r) external pure returns (uint256) {
    uint256 a = p; uint256 b = q; uint256 c = r;
    (a, b, c) = (c, a, b);
    return a * 1000000 + b * 1000 + c;
  }
  function noop2(uint256 p, uint256 q) external pure returns (uint256) { uint256 a = p; uint256 b = q; (a, b) = (a, b); return a * 1000000 + b; }
  function swapState(uint256 p, uint256 q) external returns (uint256) { x = p; y = q; (x, y) = (y, x); return x * 1000000 + y; }
  function swapPacked(uint128 p, uint128 q) external returns (uint256) { pa = p; pb = q; (pa, pb) = (pb, pa); return uint256(pa) * 1000000 + uint256(pb); }
  function rotateState(uint256 p, uint256 q, uint256 r) external returns (uint256) {
    x = p; y = q; z = r;
    (x, y, z) = (z, x, y);
    return x * 1000000 + y * 1000 + z;
  }

  function nestedCall() external pure returns (uint256) { (uint256 a, uint256 b) = nested(); return a * 1000 + b; }
  function recur(uint256 n) external returns (uint256) { (uint256 a, uint256 b) = recurT(n); return a * 1000000 + b; }
  function loopSum(uint256 n) external returns (uint256) {
    uint256 acc = 0;
    uint256 i = 0;
    while (i < n) { (uint256 s, uint256 d) = addsub(i + 10, i); acc = acc + s + d; i = i + 1; }
    return acc;
  }
  function threeSide() internal returns (uint256, uint256, uint256) { counter = counter + 7; return (1, 2, 3); }
  function skipCallSide() external returns (uint256) {
    counter = 0;
    (uint256 a, , uint256 c) = threeSide();
    return a * 1000000 + c * 1000 + counter;
  }
  function skipLitSide() external returns (uint256) {
    counter = 0;
    (uint256 a, , uint256 c) = (bump(), bump(), bump());
    return a * 1000000 + c * 1000 + counter;
  }
  function skipEnds() external pure returns (uint256) { (, uint256 b, ) = three(); return b; }
  function allButOne() external pure returns (uint256) { ( , , uint256 c) = three(); return c; }

  function mixedTypes() external pure returns (uint256) {
    (uint8 a, bool f, int64 sg, address ad, bytes32 bz) = mixT();
    uint256 r = uint256(a);
    if (f) { r = r + 1000; }
    r = r + (uint256(uint64(sg)) & 0xff);
    r = r + (uint256(uint160(ad)) & 0xff) * 100000;
    r = r + ((uint256(bz) & 0xff) == 0x22 ? 7000000 : 0);
    return r;
  }
  function widenAssign() external pure returns (uint256) {
    uint256 a = 123; uint256 b = 456;
    (a, b) = widenSrc();
    return a * 1000000 + b;
  }
  function widenDecl() external pure returns (uint256) {
    (uint256 a, uint256 b) = (uint256(7), uint256(8));
    (uint8 c, uint16 d) = widenSrc();
    return a + b + uint256(c) + uint256(d);
  }

  function signs() internal pure returns (int256, int256) { return (type(int256).min, type(int256).max); }
  function signMinMax() external pure returns (int256) { (int256 lo, int256 hi) = signs(); return lo + hi; }

  function arrTargets() external returns (uint256) {
    arr[2] = 0; arr[3] = 0;
    (arr[2], arr[3]) = two();
    return arr[2] * 1000 + arr[3];
  }
  function mapTargets(uint256 k) external returns (uint256) {
    m[k] = 0; m[k + 1] = 0;
    (m[k], m[k + 1]) = two();
    return m[k] * 1000 + m[k + 1];
  }
  function mixedTargets() external returns (uint256) { uint256 b = 0; (x, b) = two(); return x * 1000 + b; }

  function inIf(bool c) external pure returns (uint256) {
    uint256 r = 0;
    if (c) { (uint256 a, uint256 b) = two(); r = a + b; } else { (uint256 a, uint256 b) = three2(); r = a + b; }
    return r;
  }
  function three2() internal pure returns (uint256, uint256) { return (100, 200); }
  function inFor(uint256 n) external pure returns (uint256) {
    uint256 acc = 0;
    for (uint256 i = 0; i < n; i = i + 1) { (uint256 a, uint256 b) = two(); acc = acc + a + b; }
    return acc;
  }

  function stateFib(uint256 p, uint256 q) external returns (uint256) {
    x = p; y = q;
    (x, y) = (y, x + y);
    return x * 1000000 + y;
  }
  function underflow(uint256 p, uint256 q) external pure returns (uint256) { (uint256 s, uint256 d) = addsub(p, q); return s + d; }
  function dynTargets() external returns (uint256) {
    dyn = [0, 0, 0];
    (dyn[0], dyn[2]) = two();
    return dyn[0] * 1000 + dyn[2] + dyn[1];
  }
  function dynOOB() external returns (uint256) {
    dyn = [0];
    (dyn[0], dyn[5]) = two();
    return dyn[0];
  }
  function traceLitIdx() external returns (uint256) {
    counter = 0;
    arr[0] = 0; arr[1] = 0;
    (arr[tagIdx(1, 0)], arr[tagIdx(2, 1)]) = (tag(3), tag(4));
    return counter;
  }
  function traceCallIdx() external returns (uint256) {
    counter = 0;
    arr[0] = 0; arr[1] = 0;
    (arr[tagIdx(1, 0)], arr[tagIdx(2, 1)]) = twoTag();
    return counter;
  }
  function twoTag() internal returns (uint256, uint256) { counter = counter * 10 + 9; return (11, 22); }
  function traceMapKey() external returns (uint256) {
    counter = 0;
    (m[tag(1)], m[tag(2)]) = (tag(3), tag(4));
    return counter;
  }
  function traceLit3() external returns (uint256) {
    counter = 0;
    uint256 a = 0; uint256 b = 0; uint256 c = 0;
    (a, b, c) = (tag(1), tag(2), tag(3));
    return counter * 1000000 + a * 10000 + b * 100 + c;
  }

  function getCounter() external view returns (uint256) { return counter; }
  function getArr(uint256 i) external view returns (uint256) { return arr[i]; }
}`;

describe('adversarial tuple destructuring vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;

  async function eq(label: string, data: string, slots: bigint[] = []) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError} / sol err=${s.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    for (const sl of slots) {
      const js = await readSlot(jeth, aj, sl);
      const ss = await readSlot(sol, as, sl);
      expect(js, `${label} slot ${sl}`).toBe(ss);
    }
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('eval order: tuple-literal RHS side effects, left-to-right', async () => {
    await eq('orderLit', encodeCall(sel('orderLit()'), []));
    await eq('orderAssignLit', encodeCall(sel('orderAssignLit()'), []));
  });

  it('eval order: side-effecting LHS target index expressions', async () => {
    // counter encodes which index helper ran (idx0 += 1, idx1 += 100). The raw
    // slot for arr[0]/arr[1] is checked too so we catch wrong-target stores.
    await eq('orderTargetIdx', encodeCall(sel('orderTargetIdx()'), []));
    // slot layout: x=0 y=1 z=2 counter=3 pa/pb=4 arr base=5..8 dyn len=9 ...
    await eq('orderTargetIdxVals', encodeCall(sel('orderTargetIdxVals()'), []), [5n, 6n]);
    await eq('orderMixed', encodeCall(sel('orderMixed()'), []), [5n, 6n]);
  });

  it('RHS snapshot vs same-target state / revert parity / dynamic-array targets', async () => {
    for (const [p, q] of [[1n, 1n], [3n, 5n], [0n, 7n]] as const) {
      await eq(`stateFib(${p},${q})`, encodeCall(sel('stateFib(uint256,uint256)'), [p, q]), [0n, 1n]);
    }
    // underflow: b > a reverts (Panic 0x11) in both; b <= a returns.
    await eq('underflow(10,3)', encodeCall(sel('underflow(uint256,uint256)'), [10n, 3n]));
    await eq('underflow(3,10)', encodeCall(sel('underflow(uint256,uint256)'), [3n, 10n]));
    await eq('dynTargets', encodeCall(sel('dynTargets()'), []));
    await eq('dynOOB', encodeCall(sel('dynOOB()'), []));
  });

  it('eval order TRACE: exact interleaving of target-index and RHS side effects', async () => {
    // counter accumulates a decimal digit per helper call in evaluation order, so a
    // wrong order produces a different counter even when the multiset is identical.
    // arr base slot = 5, so arr[0]=slot5 arr[1]=slot6.
    await eq('traceLitIdx', encodeCall(sel('traceLitIdx()'), []), [5n, 6n]);
    await eq('traceCallIdx', encodeCall(sel('traceCallIdx()'), []), [5n, 6n]);
    await eq('traceMapKey', encodeCall(sel('traceMapKey()'), []));
    await eq('traceLit3', encodeCall(sel('traceLit3()'), []));
  });

  it('swaps: local / rotate / no-op / state / packed', async () => {
    for (const [p, q] of [[3n, 9n], [0n, 0n], [1n, 2n], [255n, 1n]] as const) {
      await eq(`swap2(${p},${q})`, encodeCall(sel('swap2(uint256,uint256)'), [p, q]));
      await eq(`noop2(${p},${q})`, encodeCall(sel('noop2(uint256,uint256)'), [p, q]));
      await eq(`swapState(${p},${q})`, encodeCall(sel('swapState(uint256,uint256)'), [p, q]), [0n, 1n]);
      await eq(`swapPacked(${p},${q})`, encodeCall(sel('swapPacked(uint128,uint128)'), [p, q]), [4n]);
    }
    for (const [p, q, r] of [[1n, 2n, 3n], [9n, 0n, 5n]] as const) {
      await eq(`rotate3(${p},${q},${r})`, encodeCall(sel('rotate3(uint256,uint256,uint256)'), [p, q, r]));
      await eq(`rotateState(${p},${q},${r})`, encodeCall(sel('rotateState(uint256,uint256,uint256)'), [p, q, r]), [0n, 1n, 2n]);
    }
  });

  it('multi-return variety: nested / recursion / loop', async () => {
    await eq('nestedCall', encodeCall(sel('nestedCall()'), []));
    for (const n of [0n, 1n, 2n, 5n, 10n]) await eq(`recur(${n})`, encodeCall(sel('recur(uint256)'), [n]));
    for (const n of [0n, 1n, 3n, 8n]) await eq(`loopSum(${n})`, encodeCall(sel('loopSum(uint256)'), [n]));
  });

  it('skipped components: call runs once / literal side effects still fire', async () => {
    await eq('skipCallSide', encodeCall(sel('skipCallSide()'), []));
    await eq('skipLitSide', encodeCall(sel('skipLitSide()'), []));
    await eq('skipEnds', encodeCall(sel('skipEnds()'), []));
    await eq('allButOne', encodeCall(sel('allButOne()'), []));
  });

  it('mixed component types + widening + signed extremes', async () => {
    await eq('mixedTypes', encodeCall(sel('mixedTypes()'), []));
    await eq('widenAssign', encodeCall(sel('widenAssign()'), []));
    await eq('widenDecl', encodeCall(sel('widenDecl()'), []));
    await eq('signMinMax', encodeCall(sel('signMinMax()'), []));
  });

  it('targets of every kind: array / mapping / mixed', async () => {
    await eq('arrTargets', encodeCall(sel('arrTargets()'), []), [7n, 8n]);
    for (const k of [0n, 5n, 42n]) await eq(`mapTargets(${k})`, encodeCall(sel('mapTargets(uint256)'), [k]));
    await eq('mixedTargets', encodeCall(sel('mixedTargets()'), []), [0n]);
  });

  it('nesting in control flow', async () => {
    await eq('inIf(true)', encodeCall(sel('inIf(bool)'), [1n]));
    await eq('inIf(false)', encodeCall(sel('inIf(bool)'), [0n]));
    for (const n of [0n, 1n, 4n]) await eq(`inFor(${n})`, encodeCall(sel('inFor(uint256)'), [n]));
  });
});
