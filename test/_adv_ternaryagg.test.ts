// Adversarial differential test for the JETH074-remainder feature: a ternary over a STATIC
// struct / STATIC fixed array `c ? A : B`. Each branch is materialized to a fresh memory image
// (storage -> COPY, ctor -> alloc, memory local -> alias) and the POINTER is selected by a
// short-circuit switch (only the taken branch materialized). Used as a memory-aggregate local
// init or as a return value. We try HARD to diverge from solc on returndata, success, and (for
// the storage-independence cases) raw storage slots.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

// A pair of (jeth,sol) harnesses for one contract, seeded once.
interface Pair {
  jeth: Harness; sol: Harness; aj: Address; as: Address;
}
async function build(jethSrc: string, solSrc: string, seedCalls: string[] = []): Promise<Pair> {
  const jb = compile(jethSrc, { fileName: 'C.jeth' });
  const sb = compileSolidity(solSrc, 'C');
  const jeth = await Harness.create(); const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode); const as = await sol.deploy(sb.creation);
  for (const s of seedCalls) {
    await jeth.call(aj, encodeCall(sel(s), []));
    await sol.call(as, encodeCall(sel(s), []));
  }
  return { jeth, sol, aj, as };
}
function mkEq(p: Pair) {
  return async (label: string, data: string) => {
    const j = await p.jeth.call(p.aj, data); const s = await p.sol.call(p.as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  };
}
async function slotsEq(p: Pair, label: string, slots: bigint[]) {
  for (const sl of slots) {
    const jv = await readSlot(p.jeth, p.aj, sl);
    const sv = await readSlot(p.sol, p.as, sl);
    expect(jv, `${label} slot ${sl}`).toBe(sv);
  }
}

// ───────────────────────────────────────────────────────────────────────────────────────────
// Contract 1: STORAGE-COPY INDEPENDENCE + packed/signed/bytesN fields + field read after select.
// P packs (b:u8, c:address, e:bool) into one slot alongside a:u256 and d:i128. Mutating the
// memory local must NOT touch storage; verify via getters AND raw slots, both branch directions.
// ───────────────────────────────────────────────────────────────────────────────────────────
const J1 = `@struct class P { a: u256; b: u8; c: address; d: i128; e: bool; f: bytes32; }
@contract class C {
  @state x: P; @state y: P;
  @external seed(): void {
    this.x = P(11n, 200n, address(0xa1n), -5n, true, bytes32(0x1122n));
    this.y = P(33n, 44n, address(0xb2n), 99n, false, bytes32(0xdeadbeefn));
  }
  @view getX(): P { return this.x; }
  @view getY(): P { return this.y; }
  // copy via ternary, mutate every field of the local, return it (storage must be untouched)
  @external mutLocal(c: bool): P {
    let p: P = c ? this.x : this.y;
    p.a = 7777n; p.b = 1n; p.c = address(0xcafen); p.d = -42n; p.e = false; p.f = bytes32(0x9999n);
    return p;
  }
  @view pickStruct(c: bool): P { return c ? this.x : this.y; }
  @view pickStructLocal(c: bool): P { let p: P = c ? this.x : this.y; return p; }
  // field read after select via a memory-aggregate local (the supported form)
  @view fieldA(c: bool): u256 { let p: P = c ? this.x : this.y; return p.a; }
  @view fieldB(c: bool): u8 { let p: P = c ? this.x : this.y; return p.b; }
  @view fieldD(c: bool): i128 { let p: P = c ? this.x : this.y; return p.d; }
  @view fieldE(c: bool): bool { let p: P = c ? this.x : this.y; return p.e; }
  @view fieldF(c: bool): bytes32 { let p: P = c ? this.x : this.y; return p.f; }
}`;
const S1 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; address c; int128 d; bool e; bytes32 f; }
  P x; P y;
  function seed() external {
    x = P(11, 200, address(0xa1), -5, true, bytes32(uint256(0x1122)));
    y = P(33, 44, address(0xb2), 99, false, bytes32(uint256(0xdeadbeef)));
  }
  function getX() external view returns (P memory) { return x; }
  function getY() external view returns (P memory) { return y; }
  function mutLocal(bool c) external returns (P memory) {
    P memory p = c ? x : y;
    p.a = 7777; p.b = 1; p.c = address(0xcafe); p.d = -42; p.e = false; p.f = bytes32(uint256(0x9999));
    return p;
  }
  function pickStruct(bool c) external view returns (P memory) { return c ? x : y; }
  function pickStructLocal(bool c) external view returns (P memory) { P memory p = c ? x : y; return p; }
  function fieldA(bool c) external view returns (uint256) { P memory p = c ? x : y; return p.a; }
  function fieldB(bool c) external view returns (uint8) { P memory p = c ? x : y; return p.b; }
  function fieldD(bool c) external view returns (int128) { P memory p = c ? x : y; return p.d; }
  function fieldE(bool c) external view returns (bool) { P memory p = c ? x : y; return p.e; }
  function fieldF(bool c) external view returns (bytes32) { P memory p = c ? x : y; return p.f; }
}`;

// ───────────────────────────────────────────────────────────────────────────────────────────
// Contract 2: SHORT-CIRCUIT. The untaken constructor branch contains a checked-arithmetic
// revert (division by zero, subtraction underflow, multiplication overflow). When the storage
// branch is taken (c true) the ctor must NOT be evaluated -> no revert. solc must agree.
// ───────────────────────────────────────────────────────────────────────────────────────────
const J2 = `@struct class P { a: u256; b: u256; }
@contract class C {
  @state x: P;
  @external seed(): void { this.x = P(100n, 200n); }
  // ctor branch divides by v: if v==0 and ctor branch is TAKEN -> revert; if NOT taken -> ok.
  @external divBranch(c: bool, v: u256): P { return c ? this.x : P(1000n / v, 2n); }
  // ctor branch underflows: 5 - v underflows when v>5 and the ctor branch is taken.
  @external subBranch(c: bool, v: u256): P { return c ? this.x : P(5n - v, 3n); }
  // ctor branch overflows on a 256-bit multiply.
  @external mulBranch(c: bool, v: u256): P { return c ? this.x : P(v * v, 4n); }
  // local-init form (same short-circuit requirement)
  @external divLocal(c: bool, v: u256): P { let p: P = c ? this.x : P(1000n / v, 2n); return p; }
}`;
const S2 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint256 b; }
  P x;
  function seed() external { x = P(100, 200); }
  function divBranch(bool c, uint256 v) external view returns (P memory) { return c ? x : P(1000 / v, 2); }
  function subBranch(bool c, uint256 v) external view returns (P memory) { return c ? x : P(5 - v, 3); }
  function mulBranch(bool c, uint256 v) external view returns (P memory) { return c ? x : P(v * v, 4); }
  function divLocal(bool c, uint256 v) external view returns (P memory) { P memory p = c ? x : P(1000 / v, 2); return p; }
}`;

// ───────────────────────────────────────────────────────────────────────────────────────────
// Contract 3: NESTED aggregates. Struct-with-fixed-array-field, fixed-array-of-struct,
// nested fixed arrays uint256[2][3], plus packed u8 arrays. Whole-aggregate return via ternary.
// ───────────────────────────────────────────────────────────────────────────────────────────
const J3 = `@struct class Inner { p: u128; q: u128; }
@struct class WithArr { tag: u256; arr: Arr<u256,3>; }
@contract class C {
  @state wx: WithArr; @state wy: WithArr;
  @state sx: Arr<Inner,2>; @state sy: Arr<Inner,2>;
  @state nx: Arr<Arr<u256,2>,3>; @state ny: Arr<Arr<u256,2>,3>;
  @state bx: Arr<u8,5>; @state by: Arr<u8,5>;
  @external seed(): void {
    this.wx = WithArr(1n, [10n, 20n, 30n]); this.wy = WithArr(2n, [40n, 50n, 60n]);
    this.sx[0n] = Inner(1n, 2n); this.sx[1n] = Inner(3n, 4n);
    this.sy[0n] = Inner(5n, 6n); this.sy[1n] = Inner(7n, 8n);
    this.nx[0n][0n] = 1n; this.nx[0n][1n] = 2n; this.nx[1n][0n] = 3n; this.nx[1n][1n] = 4n; this.nx[2n][0n] = 5n; this.nx[2n][1n] = 6n;
    this.ny[0n][0n] = 7n; this.ny[0n][1n] = 8n; this.ny[1n][0n] = 9n; this.ny[1n][1n] = 10n; this.ny[2n][0n] = 11n; this.ny[2n][1n] = 12n;
    this.bx[0n] = 255n; this.bx[1n] = 1n; this.bx[2n] = 128n; this.bx[3n] = 0n; this.bx[4n] = 77n;
    this.by[0n] = 9n; this.by[1n] = 8n; this.by[2n] = 7n; this.by[3n] = 6n; this.by[4n] = 5n;
  }
  @view pickWithArr(c: bool): WithArr { return c ? this.wx : this.wy; }
  @view pickArrOfStruct(c: bool): Arr<Inner,2> { return c ? this.sx : this.sy; }
  @view pickNested(c: bool): Arr<Arr<u256,2>,3> { return c ? this.nx : this.ny; }
  @view pickPacked(c: bool): Arr<u8,5> { return c ? this.bx : this.by; }
  // local + field read on the nested ones
  @view withArrLocal(c: bool): WithArr { let w: WithArr = c ? this.wx : this.wy; return w; }
  @view packedElem(c: bool, i: u256): u8 { let a: Arr<u8,5> = c ? this.bx : this.by; return a[i]; }
  // mutate the value field of a struct-with-array local; storage must be untouched (independence)
  @external mutWithArr(c: bool): WithArr { let w: WithArr = c ? this.wx : this.wy; w.tag = 999n; return w; }
  @view getWx(): WithArr { return this.wx; }
  @view getWy(): WithArr { return this.wy; }
}`;
const S3 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Inner { uint128 p; uint128 q; }
  struct WithArr { uint256 tag; uint256[3] arr; }
  WithArr wx; WithArr wy;
  Inner[2] sx; Inner[2] sy;
  uint256[2][3] nx; uint256[2][3] ny;
  uint8[5] bx; uint8[5] by;
  function seed() external {
    wx = WithArr(1, [uint256(10), 20, 30]); wy = WithArr(2, [uint256(40), 50, 60]);
    sx[0] = Inner(1, 2); sx[1] = Inner(3, 4); sy[0] = Inner(5, 6); sy[1] = Inner(7, 8);
    nx[0][0]=1; nx[0][1]=2; nx[1][0]=3; nx[1][1]=4; nx[2][0]=5; nx[2][1]=6;
    ny[0][0]=7; ny[0][1]=8; ny[1][0]=9; ny[1][1]=10; ny[2][0]=11; ny[2][1]=12;
    bx[0]=255; bx[1]=1; bx[2]=128; bx[3]=0; bx[4]=77;
    by[0]=9; by[1]=8; by[2]=7; by[3]=6; by[4]=5;
  }
  function pickWithArr(bool c) external view returns (WithArr memory) { return c ? wx : wy; }
  function pickArrOfStruct(bool c) external view returns (Inner[2] memory) { return c ? sx : sy; }
  function pickNested(bool c) external view returns (uint256[2][3] memory) { return c ? nx : ny; }
  function pickPacked(bool c) external view returns (uint8[5] memory) { return c ? bx : by; }
  function withArrLocal(bool c) external view returns (WithArr memory) { WithArr memory w = c ? wx : wy; return w; }
  function packedElem(bool c, uint256 i) external view returns (uint8) { uint8[5] memory a = c ? bx : by; return a[i]; }
  function mutWithArr(bool c) external returns (WithArr memory) { WithArr memory w = c ? wx : wy; w.tag = 999; return w; }
  function getWx() external view returns (WithArr memory) { return wx; }
  function getWy() external view returns (WithArr memory) { return wy; }
}`;

// ───────────────────────────────────────────────────────────────────────────────────────────
// Contract 4: MIXED branch sources + nested ternary + boundary values.
//  - storage vs ctor, storage vs another memory local, two ctors, nested ternary c ? x : (d ? y : z).
//  - boundary values: 0, 2^256-1, signed min/max, max address, max bytesN.
// ───────────────────────────────────────────────────────────────────────────────────────────
const J4 = `@struct class P { a: u256; s: i256; ad: address; bn: bytes32; }
@contract class C {
  @state x: P; @state y: P; @state z: P;
  @external seed(): void {
    this.x = P(0n, 0n, address(0n), bytes32(0n));
    this.y = P(115792089237316195423570985008687907853269984665640564039457584007913129639935n,
               57896044618658097711785492504343953926634992332820282019728792003956564819967n,
               address(0xffffffffffffffffffffffffffffffffffffffffn), bytes32(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn));
    this.z = P(42n, -57896044618658097711785492504343953926634992332820282019728792003956564819968n, address(0x1n), bytes32(0x1n));
  }
  // storage vs ctor with boundary literal args
  @external sVsCtor(c: bool, v: i256): P { return c ? this.x : P(v == 0n ? 0n : u256(1n), v, address(0x2n), bytes32(0x3n)); }
  // storage vs another memory local
  @external sVsLocal(c: bool): P { let m: P = P(9n, -1n, address(0x7n), bytes32(0x8n)); return c ? this.x : m; }
  // two constructors
  @external twoCtor(c: bool, v: u256): P { return c ? P(v, 1n, address(0xaan), bytes32(0xbbn)) : P(v + 1n, -1n, address(0xccn), bytes32(0xddn)); }
}`;
const S4 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; int256 s; address ad; bytes32 bn; }
  P x; P y; P z;
  function seed() external {
    x = P(0, 0, address(0), bytes32(uint256(0)));
    y = P(type(uint256).max, type(int256).max, address(type(uint160).max), bytes32(type(uint256).max));
    z = P(42, type(int256).min, address(0x1), bytes32(uint256(0x1)));
  }
  function sVsCtor(bool c, int256 v) external view returns (P memory) { return c ? x : P(v == 0 ? 0 : uint256(1), v, address(0x2), bytes32(uint256(0x3))); }
  function sVsLocal(bool c) external view returns (P memory) { P memory m = P(9, -1, address(0x7), bytes32(uint256(0x8))); return c ? x : m; }
  function twoCtor(bool c, uint256 v) external view returns (P memory) { return c ? P(v, 1, address(0xaa), bytes32(uint256(0xbb))) : P(v + 1, -1, address(0xcc), bytes32(uint256(0xdd))); }
}`;

// ───────────────────────────────────────────────────────────────────────────────────────────
// Contract 5: Fixed-array element-type variety: address arrays, bytesN arrays, write p[i]=v
// after select then return (the local must be an independent copy of storage).
// ───────────────────────────────────────────────────────────────────────────────────────────
const J5 = `@contract class C {
  @state ax: Arr<address,3>; @state ay: Arr<address,3>;
  @state bx: Arr<bytes4,4>; @state by: Arr<bytes4,4>;
  @external seed(): void {
    this.ax[0n] = address(0xa1n); this.ax[1n] = address(0xa2n); this.ax[2n] = address(0xffffffffffffffffffffffffffffffffffffffffn);
    this.ay[0n] = address(0xb1n); this.ay[1n] = address(0xb2n); this.ay[2n] = address(0x0n);
    this.bx[0n] = bytes4(u32(0x11223344n)); this.bx[1n] = bytes4(u32(0xffffffffn)); this.bx[2n] = bytes4(u32(0x0n)); this.bx[3n] = bytes4(u32(0xdeadbeefn));
    this.by[0n] = bytes4(u32(0xaabbccddn)); this.by[1n] = bytes4(u32(0x1n)); this.by[2n] = bytes4(u32(0x2n)); this.by[3n] = bytes4(u32(0x3n));
  }
  @view pickAddrs(c: bool): Arr<address,3> { return c ? this.ax : this.ay; }
  @view pickBytes4(c: bool): Arr<bytes4,4> { return c ? this.bx : this.by; }
  // write an element after select, return whole; storage must be untouched (independence)
  @external mutAddrs(c: bool): Arr<address,3> { let a: Arr<address,3> = c ? this.ax : this.ay; a[1n] = address(0xdeadn); return a; }
  @view addrElem(c: bool, i: u256): address { let a: Arr<address,3> = c ? this.ax : this.ay; return a[i]; }
  @view getAx(): Arr<address,3> { return this.ax; }
  @view getAy(): Arr<address,3> { return this.ay; }
}`;
const S5 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  address[3] ax; address[3] ay;
  bytes4[4] bx; bytes4[4] by;
  function seed() external {
    ax[0]=address(0xa1); ax[1]=address(0xa2); ax[2]=address(type(uint160).max);
    ay[0]=address(0xb1); ay[1]=address(0xb2); ay[2]=address(0x0);
    bx[0]=bytes4(uint32(0x11223344)); bx[1]=bytes4(uint32(0xffffffff)); bx[2]=bytes4(uint32(0x0)); bx[3]=bytes4(uint32(0xdeadbeef));
    by[0]=bytes4(uint32(0xaabbccdd)); by[1]=bytes4(uint32(0x1)); by[2]=bytes4(uint32(0x2)); by[3]=bytes4(uint32(0x3));
  }
  function pickAddrs(bool c) external view returns (address[3] memory) { return c ? ax : ay; }
  function pickBytes4(bool c) external view returns (bytes4[4] memory) { return c ? bx : by; }
  function mutAddrs(bool c) external returns (address[3] memory) { address[3] memory a = c ? ax : ay; a[1] = address(0xdead); return a; }
  function addrElem(bool c, uint256 i) external view returns (address) { address[3] memory a = c ? ax : ay; return a[i]; }
  function getAx() external view returns (address[3] memory) { return ax; }
  function getAy() external view returns (address[3] memory) { return ay; }
}`;

describe('adversarial: static-aggregate ternary vs Solidity', () => {
  // ── Contract 1: storage independence, packed/signed/bytesN fields, field reads ──
  describe('storage-copy independence + packed/signed/bytesN fields', () => {
    let p: Pair; let eq: ReturnType<typeof mkEq>;
    beforeAll(async () => { p = await build(J1, S1, ['seed()']); eq = mkEq(p); });
    it('pickStruct / pickStructLocal whole-struct, both directions', async () => {
      for (const c of [1n, 0n]) {
        await eq(`pickStruct(${c})`, encodeCall(sel('pickStruct(bool)'), [c]));
        await eq(`pickStructLocal(${c})`, encodeCall(sel('pickStructLocal(bool)'), [c]));
      }
    });
    it('field read after select (a,b,d,e,f), both directions', async () => {
      for (const c of [1n, 0n]) {
        await eq(`fieldA(${c})`, encodeCall(sel('fieldA(bool)'), [c]));
        await eq(`fieldB(${c})`, encodeCall(sel('fieldB(bool)'), [c]));
        await eq(`fieldD(${c})`, encodeCall(sel('fieldD(bool)'), [c]));
        await eq(`fieldE(${c})`, encodeCall(sel('fieldE(bool)'), [c]));
        await eq(`fieldF(${c})`, encodeCall(sel('fieldF(bool)'), [c]));
      }
    });
    it('mutate the local: returndata matches AND storage is untouched (both directions)', async () => {
      // raw slots of x (0,1) and y (2,3): P has a:slot, packed{b,c,e}:slot, d:slot, f:slot -> 4 slots each
      const allSlots = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n];
      for (const c of [1n, 0n]) {
        await eq(`mutLocal(${c})`, encodeCall(sel('mutLocal(bool)'), [c]));
        // re-read storage via getters AND raw slots: must equal the un-mutated seed
        await eq(`getX after mutLocal(${c})`, encodeCall(sel('getX()'), []));
        await eq(`getY after mutLocal(${c})`, encodeCall(sel('getY()'), []));
        await slotsEq(p, `storage after mutLocal(${c})`, allSlots);
      }
    });
  });

  // ── Contract 2: short-circuit (untaken ctor revert must not fire) ──
  describe('short-circuit: untaken constructor revert', () => {
    let p: Pair; let eq: ReturnType<typeof mkEq>;
    beforeAll(async () => { p = await build(J2, S2, ['seed()']); eq = mkEq(p); });
    it('div-by-zero in untaken ctor branch (c=true: no revert; c=false: revert)', async () => {
      // c=true picks storage; ctor 1000/0 must NOT be evaluated -> success on both
      await eq('divBranch(true, 0)', encodeCall(sel('divBranch(bool,uint256)'), [1n, 0n]));
      await eq('divLocal(true, 0)', encodeCall(sel('divLocal(bool,uint256)'), [1n, 0n]));
      // c=false takes the ctor -> div by zero -> both revert
      await eq('divBranch(false, 0)', encodeCall(sel('divBranch(bool,uint256)'), [0n, 0n]));
      await eq('divLocal(false, 0)', encodeCall(sel('divLocal(bool,uint256)'), [0n, 0n]));
      // c=false with a valid divisor -> both succeed
      await eq('divBranch(false, 4)', encodeCall(sel('divBranch(bool,uint256)'), [0n, 4n]));
    });
    it('underflow in untaken ctor branch', async () => {
      await eq('subBranch(true, 9)', encodeCall(sel('subBranch(bool,uint256)'), [1n, 9n]));   // taken=storage -> ok
      await eq('subBranch(false, 9)', encodeCall(sel('subBranch(bool,uint256)'), [0n, 9n]));  // 5-9 underflow -> revert
      await eq('subBranch(false, 2)', encodeCall(sel('subBranch(bool,uint256)'), [0n, 2n]));  // 5-2 ok
    });
    it('overflow in untaken ctor branch', async () => {
      const big = (1n << 200n);
      await eq('mulBranch(true, big)', encodeCall(sel('mulBranch(bool,uint256)'), [1n, big]));   // storage -> ok
      await eq('mulBranch(false, big)', encodeCall(sel('mulBranch(bool,uint256)'), [0n, big]));  // overflow -> revert
      await eq('mulBranch(false, 3)', encodeCall(sel('mulBranch(bool,uint256)'), [0n, 3n]));     // ok
    });
  });

  // ── Contract 3: nested aggregates ──
  describe('nested aggregates (struct-with-array, array-of-struct, nested arrays, packed)', () => {
    let p: Pair; let eq: ReturnType<typeof mkEq>;
    beforeAll(async () => { p = await build(J3, S3, ['seed()']); eq = mkEq(p); });
    it('whole-aggregate ternary returns, both directions', async () => {
      for (const c of [1n, 0n]) {
        await eq(`pickWithArr(${c})`, encodeCall(sel('pickWithArr(bool)'), [c]));
        await eq(`pickArrOfStruct(${c})`, encodeCall(sel('pickArrOfStruct(bool)'), [c]));
        await eq(`pickNested(${c})`, encodeCall(sel('pickNested(bool)'), [c]));
        await eq(`pickPacked(${c})`, encodeCall(sel('pickPacked(bool)'), [c]));
        await eq(`withArrLocal(${c})`, encodeCall(sel('withArrLocal(bool)'), [c]));
      }
    });
    it('packed element read after select', async () => {
      for (const c of [1n, 0n]) for (const i of [0n, 1n, 2n, 3n, 4n]) {
        await eq(`packedElem(${c},${i})`, encodeCall(sel('packedElem(bool,uint256)'), [c, i]));
      }
    });
    it('mutate struct-with-array local: returndata matches AND storage untouched', async () => {
      // wx occupies slots 0..3 (tag + arr[0..2]); wy occupies slots 4..7.
      for (const c of [1n, 0n]) {
        await eq(`mutWithArr(${c})`, encodeCall(sel('mutWithArr(bool)'), [c]));
        await eq(`getWx after mutWithArr(${c})`, encodeCall(sel('getWx()'), []));
        await eq(`getWy after mutWithArr(${c})`, encodeCall(sel('getWy()'), []));
        await slotsEq(p, `WithArr storage after mutWithArr(${c})`, [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n]);
      }
    });
  });

  // ── Contract 4: mixed sources + nested ternary + boundaries ──
  describe('mixed branch sources + nested ternary + boundary values', () => {
    let p: Pair; let eq: ReturnType<typeof mkEq>;
    beforeAll(async () => { p = await build(J4, S4, ['seed()']); eq = mkEq(p); });
    it('storage vs ctor / vs local / two ctors, both directions, boundary args', async () => {
      const sMin = -(1n << 255n); const sMax = (1n << 255n) - 1n;
      for (const c of [1n, 0n]) {
        for (const v of [0n, 1n, -1n, sMin, sMax]) {
          await eq(`sVsCtor(${c},${v})`, encodeCall(sel('sVsCtor(bool,int256)'), [c, v]));
        }
        await eq(`sVsLocal(${c})`, encodeCall(sel('sVsLocal(bool)'), [c]));
        for (const v of [0n, M - 2n, 12345n]) {
          await eq(`twoCtor(${c},${v})`, encodeCall(sel('twoCtor(bool,uint256)'), [c, v]));
        }
      }
    });
  });

  // ── NESTED aggregate ternary `c ? this.x : (d ? this.y : this.z)` (now supported) ──
  // The inner ternary materializes + selects recursively (aggToMemPtr 'ternary' -> lowerExpr).
  // Byte-identical to solc across all (c,d) combinations.
  describe('nested aggregate ternary c ? x : (d ? y : z)', () => {
    const Jn = `@struct class P { a: u256; b: u8; c: address; }
@contract class C {
  @state x: P; @state y: P; @state z: P;
  @external seed(): void { this.x = P(1n, 2n, address(0xa1n)); this.y = P(3n, 4n, address(0xb2n)); this.z = P(5n, 6n, address(0xc3n)); }
  @external @view nested(c: bool, d: bool): P { return c ? this.x : (d ? this.y : this.z); }
}`;
    const Sn = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; address c; }
  P x; P y; P z;
  function seed() external { x = P(1, 2, address(0xa1)); y = P(3, 4, address(0xb2)); z = P(5, 6, address(0xc3)); }
  function nested(bool c, bool d) external view returns (P memory) { return c ? x : (d ? y : z); }
}`;
    let p: Pair; let eq: ReturnType<typeof mkEq>;
    beforeAll(async () => { p = await build(Jn, Sn, ['seed()']); eq = mkEq(p); });
    it('all (c,d) combinations byte-identical', async () => {
      for (const c of [1n, 0n]) for (const d of [1n, 0n]) await eq(`nested(${c},${d})`, encodeCall(sel('nested(bool,bool)'), [c, d]));
    });
  });

  // ── Contract 5: fixed-array element-type variety + element write independence ──
  describe('fixed-array element variety (address/bytesN) + element-write independence', () => {
    let p: Pair; let eq: ReturnType<typeof mkEq>;
    beforeAll(async () => { p = await build(J5, S5, ['seed()']); eq = mkEq(p); });
    it('pickAddrs / pickBytes4 whole arrays, both directions', async () => {
      for (const c of [1n, 0n]) {
        await eq(`pickAddrs(${c})`, encodeCall(sel('pickAddrs(bool)'), [c]));
        await eq(`pickBytes4(${c})`, encodeCall(sel('pickBytes4(bool)'), [c]));
      }
    });
    it('element read after select', async () => {
      for (const c of [1n, 0n]) for (const i of [0n, 1n, 2n]) {
        await eq(`addrElem(${c},${i})`, encodeCall(sel('addrElem(bool,uint256)'), [c, i]));
      }
    });
    it('element write after select: returndata matches AND storage untouched', async () => {
      // ax: slots 0,1,2 ; ay: slots 3,4,5
      for (const c of [1n, 0n]) {
        await eq(`mutAddrs(${c})`, encodeCall(sel('mutAddrs(bool)'), [c]));
        await eq(`getAx after mutAddrs(${c})`, encodeCall(sel('getAx()'), []));
        await eq(`getAy after mutAddrs(${c})`, encodeCall(sel('getAy()'), []));
        await slotsEq(p, `addr storage after mutAddrs(${c})`, [0n, 1n, 2n, 3n, 4n, 5n]);
      }
    });
  });
});
