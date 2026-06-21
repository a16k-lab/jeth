// _vf_packing: adversarial differential test of STORAGE LAYOUT & PACKING vs solc.
// Many independent JETH/Solidity contract pairs, each deployed to its own in-process
// EVM. We compare: every field getter (sign-extension, bytesN left-align, bool/address
// packing), whole-struct ABI return, AND raw storage slots (byte-identical layout +
// partial-slot RMW that must preserve neighbor fields). Adversarial: dirty high bits in
// calldata, type-max / INT_MIN / negative values, slot-straddling fields, overwrite-then-
// read, array-of-packed-struct strides, push/pop slot reuse.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { keccak256 } from 'ethereum-cryptography/keccak.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const mask = (bits: bigint) => (1n << bits) - 1n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}
function kdataSlot(baseSlot: bigint): bigint {
  return BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(baseSlot), 'hex'))).toString('hex'));
}
function kmapSlot(key: bigint, base: bigint): bigint {
  return BigInt('0x' + Buffer.from(keccak256(Buffer.from(pad(key) + pad(base), 'hex'))).toString('hex'));
}

interface Pair {
  jeth: Harness;
  sol: Harness;
  aj: Address;
  as: Address;
}

async function deployPair(jethSrc: string, solSrc: string): Promise<Pair> {
  const jc = compile(jethSrc, { fileName: 'C.jeth' });
  const sc = compileSolidity(solSrc, 'C');
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jc.creationBytecode);
  const as = await sol.deploy(sc.creation);
  return { jeth, sol, aj, as };
}

// Global mismatch collector across all blocks.
const mism: string[] = [];
let count = 0;

async function eq(p: Pair, label: string, data: string) {
  count++;
  const j = await p.jeth.call(p.aj, data);
  const s = await p.sol.call(p.as, data);
  if (j.success !== s.success || j.returnHex !== s.returnHex) {
    mism.push(
      label +
        ': jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError + '} ' +
        'sol{ok=' + s.success + ',ret=' + s.returnHex + '}',
    );
  }
}

async function eqSlot(p: Pair, label: string, slot: bigint) {
  count++;
  const jv = await readSlot(p.jeth, p.aj, slot);
  const sv = await readSlot(p.sol, p.as, slot);
  if (jv !== sv) {
    mism.push(label + ' slot[' + slot.toString() + ']: jeth=' + jv + ' sol=' + sv);
  }
}

// Run a write call on both (success must match); used to drive state before slot checks.
async function send(p: Pair, label: string, data: string) {
  count++;
  const j = await p.jeth.call(p.aj, data);
  const s = await p.sol.call(p.as, data);
  if (j.success !== s.success) {
    mism.push(label + ' (send): jeth{ok=' + j.success + ',err=' + j.exceptionError + '} sol{ok=' + s.success + '}');
  }
}

// Adversarial set of "register words" for narrow types: we deliberately leave DIRTY
// HIGH BITS in the 32-byte ABI word to test that JETH masks/cleans exactly like solc.
const DIRTY = (1n << 256n) - 1n; // all ones in the upper bits

describe('vf_packing', () => {
  // Each pair built once.
  let P1: Pair, P2: Pair, P3: Pair, P4: Pair, P5: Pair, P6: Pair, P7: Pair, P8: Pair, P9: Pair, P10: Pair, P11: Pair;
  let P12: Pair, P13: Pair, P14: Pair, P15: Pair;

  beforeAll(async () => {
    // ---- P1: classic mixed-width state vars (not a struct) ------------------
    const J1 = `
@contract class C {
  @state a: u8;
  @state b: i16;
  @state c: bytes3;
  @state d: bool;
  @state e: u32;
  @state f: address;
  @state g: i40;
  @state h: bytes7;
  @external setA(v: u8) { this.a = v; }
  @external setB(v: i16) { this.b = v; }
  @external setC(v: bytes3) { this.c = v; }
  @external setD(v: bool) { this.d = v; }
  @external setE(v: u32) { this.e = v; }
  @external setF(v: address) { this.f = v; }
  @external setG(v: i40) { this.g = v; }
  @external setH(v: bytes7) { this.h = v; }
  @external @view getA(): u8 { return this.a; }
  @external @view getB(): i16 { return this.b; }
  @external @view getC(): bytes3 { return this.c; }
  @external @view getD(): bool { return this.d; }
  @external @view getE(): u32 { return this.e; }
  @external @view getF(): address { return this.f; }
  @external @view getG(): i40 { return this.g; }
  @external @view getH(): bytes7 { return this.h; }
}`;
    const S1 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint8 a; int16 b; bytes3 c; bool d; uint32 e; address f; int40 g; bytes7 h;
  function setA(uint8 v) external { a = v; }
  function setB(int16 v) external { b = v; }
  function setC(bytes3 v) external { c = v; }
  function setD(bool v) external { d = v; }
  function setE(uint32 v) external { e = v; }
  function setF(address v) external { f = v; }
  function setG(int40 v) external { g = v; }
  function setH(bytes7 v) external { h = v; }
  function getA() external view returns (uint8){ return a; }
  function getB() external view returns (int16){ return b; }
  function getC() external view returns (bytes3){ return c; }
  function getD() external view returns (bool){ return d; }
  function getE() external view returns (uint32){ return e; }
  function getF() external view returns (address){ return f; }
  function getG() external view returns (int40){ return g; }
  function getH() external view returns (bytes7){ return h; }
}`;

    // ---- P2: struct that straddles a 32-byte boundary exactly ---------------
    // a(u128=16) b(u64=8) c(bool=1) d(bytes4=4) => 29 bytes; e(u64=8) won't fit -> slot1
    // f(bytes32) -> slot2. Whole-struct return + per-field getters + raw slots.
    const J2 = `
@struct class S { a: u128; b: u64; c: bool; d: bytes4; e: u64; f: bytes32; }
@contract class C {
  @state s: S;
  @state sentinel: u256;
  @external setAll(a: u128, b: u64, c: bool, d: bytes4, e: u64, f: bytes32) {
    this.s = S(a, b, c, d, e, f); this.sentinel = 0xdeadn;
  }
  @external setA(v: u128) { this.s.a = v; }
  @external setB(v: u64) { this.s.b = v; }
  @external setC(v: bool) { this.s.c = v; }
  @external setD(v: bytes4) { this.s.d = v; }
  @external setE(v: u64) { this.s.e = v; }
  @external setF(v: bytes32) { this.s.f = v; }
  @external @view getA(): u128 { return this.s.a; }
  @external @view getB(): u64 { return this.s.b; }
  @external @view getC(): bool { return this.s.c; }
  @external @view getD(): bytes4 { return this.s.d; }
  @external @view getE(): u64 { return this.s.e; }
  @external @view getF(): bytes32 { return this.s.f; }
  @external @view getAll(): S { return this.s; }
  @external @view getSentinel(): u256 { return this.sentinel; }
}`;
    const S2 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint128 a; uint64 b; bool c; bytes4 d; uint64 e; bytes32 f; }
  S s; uint256 sentinel;
  function setAll(uint128 a, uint64 b, bool c, bytes4 d, uint64 e, bytes32 f) external {
    s = S(a, b, c, d, e, f); sentinel = 0xdead;
  }
  function setA(uint128 v) external { s.a = v; }
  function setB(uint64 v) external { s.b = v; }
  function setC(bool v) external { s.c = v; }
  function setD(bytes4 v) external { s.d = v; }
  function setE(uint64 v) external { s.e = v; }
  function setF(bytes32 v) external { s.f = v; }
  function getA() external view returns (uint128){ return s.a; }
  function getB() external view returns (uint64){ return s.b; }
  function getC() external view returns (bool){ return s.c; }
  function getD() external view returns (bytes4){ return s.d; }
  function getE() external view returns (uint64){ return s.e; }
  function getF() external view returns (bytes32){ return s.f; }
  function getAll() external view returns (S memory){ return s; }
  function getSentinel() external view returns (uint256){ return sentinel; }
}`;

    // ---- P3: ALL-SIGNED narrow struct, sign-bit packing & RMW ---------------
    // i8 i16 i24 i32 i40 i48 i56 = 1+2+3+4+5+6+7 = 28 bytes -> single slot.
    const J3 = `
@struct class S { a: i8; b: i16; c: i24; d: i32; e: i40; f: i48; g: i56; }
@contract class C {
  @state s: S;
  @external setAll(a: i8, b: i16, c: i24, d: i32, e: i40, f: i48, g: i56) { this.s = S(a,b,c,d,e,f,g); }
  @external setA(v: i8) { this.s.a = v; }
  @external setC(v: i24) { this.s.c = v; }
  @external setG(v: i56) { this.s.g = v; }
  @external @view getA(): i8 { return this.s.a; }
  @external @view getB(): i16 { return this.s.b; }
  @external @view getC(): i24 { return this.s.c; }
  @external @view getD(): i32 { return this.s.d; }
  @external @view getE(): i40 { return this.s.e; }
  @external @view getF(): i48 { return this.s.f; }
  @external @view getG(): i56 { return this.s.g; }
  @external @view getAll(): S { return this.s; }
}`;
    const S3 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { int8 a; int16 b; int24 c; int32 d; int40 e; int48 f; int56 g; }
  S s;
  function setAll(int8 a, int16 b, int24 c, int32 d, int40 e, int48 f, int56 g) external { s = S(a,b,c,d,e,f,g); }
  function setA(int8 v) external { s.a = v; }
  function setC(int24 v) external { s.c = v; }
  function setG(int56 v) external { s.g = v; }
  function getA() external view returns (int8){ return s.a; }
  function getB() external view returns (int16){ return s.b; }
  function getC() external view returns (int24){ return s.c; }
  function getD() external view returns (int32){ return s.d; }
  function getE() external view returns (int40){ return s.e; }
  function getF() external view returns (int48){ return s.f; }
  function getG() external view returns (int56){ return s.g; }
  function getAll() external view returns (S memory){ return s; }
}`;

    // ---- P4: bool + address packing (bool then address fits in 1 slot: 1+20=21) -
    const J4 = `
@struct class S { flag1: bool; owner: address; flag2: bool; small: u8; }
@contract class C {
  @state s: S;
  @external setAll(f1: bool, o: address, f2: bool, sm: u8) { this.s = S(f1, o, f2, sm); }
  @external setOwner(v: address) { this.s.owner = v; }
  @external setF1(v: bool) { this.s.flag1 = v; }
  @external setF2(v: bool) { this.s.flag2 = v; }
  @external @view getF1(): bool { return this.s.flag1; }
  @external @view getOwner(): address { return this.s.owner; }
  @external @view getF2(): bool { return this.s.flag2; }
  @external @view getSmall(): u8 { return this.s.small; }
  @external @view getAll(): S { return this.s; }
}`;
    const S4 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { bool flag1; address owner; bool flag2; uint8 small; }
  S s;
  function setAll(bool f1, address o, bool f2, uint8 sm) external { s = S(f1, o, f2, sm); }
  function setOwner(address v) external { s.owner = v; }
  function setF1(bool v) external { s.flag1 = v; }
  function setF2(bool v) external { s.flag2 = v; }
  function getF1() external view returns (bool){ return s.flag1; }
  function getOwner() external view returns (address){ return s.owner; }
  function getF2() external view returns (bool){ return s.flag2; }
  function getSmall() external view returns (uint8){ return s.small; }
  function getAll() external view returns (S memory){ return s; }
}`;

    // ---- P5: array of packed struct (Rec packs into 1 slot), stride + RMW ----
    const J5 = `
@struct class Rec { a: u128; b: u64; c: bool; d: bytes4; }
@contract class C {
  @state arr: Arr<Rec, 4>;
  @external setRec(i: u256, a: u128, b: u64, c: bool, d: bytes4) { this.arr[i] = Rec(a,b,c,d); }
  @external setA(i: u256, v: u128) { this.arr[i].a = v; }
  @external setC(i: u256, v: bool) { this.arr[i].c = v; }
  @external @view getA(i: u256): u128 { return this.arr[i].a; }
  @external @view getB(i: u256): u64 { return this.arr[i].b; }
  @external @view getC(i: u256): bool { return this.arr[i].c; }
  @external @view getD(i: u256): bytes4 { return this.arr[i].d; }
  @external @view getRec(i: u256): Rec { return this.arr[i]; }
}`;
    const S5 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Rec { uint128 a; uint64 b; bool c; bytes4 d; }
  Rec[4] arr;
  function setRec(uint256 i, uint128 a, uint64 b, bool c, bytes4 d) external { arr[i] = Rec(a,b,c,d); }
  function setA(uint256 i, uint128 v) external { arr[i].a = v; }
  function setC(uint256 i, bool v) external { arr[i].c = v; }
  function getA(uint256 i) external view returns (uint128){ return arr[i].a; }
  function getB(uint256 i) external view returns (uint64){ return arr[i].b; }
  function getC(uint256 i) external view returns (bool){ return arr[i].c; }
  function getD(uint256 i) external view returns (bytes4){ return arr[i].d; }
  function getRec(uint256 i) external view returns (Rec memory){ return arr[i]; }
}`;

    // ---- P6: dynamic array of packed struct, push/pop slot reuse ------------
    const J6 = `
@struct class Rec { a: u128; b: u64; c: bool; d: bytes4; }
@contract class C {
  @state recs: Rec[];
  @external pushV(a: u128, b: u64, c: bool, d: bytes4) { this.recs.push(Rec(a,b,c,d)); }
  @external pop() { this.recs.pop(); }
  @external setA(i: u256, v: u128) { this.recs[i].a = v; }
  @external setC(i: u256, v: bool) { this.recs[i].c = v; }
  @external @view getA(i: u256): u128 { return this.recs[i].a; }
  @external @view getC(i: u256): bool { return this.recs[i].c; }
  @external @view getRec(i: u256): Rec { return this.recs[i]; }
  @external @view len(): u256 { return this.recs.length; }
}`;
    const S6 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Rec { uint128 a; uint64 b; bool c; bytes4 d; }
  Rec[] recs;
  function pushV(uint128 a, uint64 b, bool c, bytes4 d) external { recs.push(Rec(a,b,c,d)); }
  function pop() external { recs.pop(); }
  function setA(uint256 i, uint128 v) external { recs[i].a = v; }
  function setC(uint256 i, bool v) external { recs[i].c = v; }
  function getA(uint256 i) external view returns (uint128){ return recs[i].a; }
  function getC(uint256 i) external view returns (bool){ return recs[i].c; }
  function getRec(uint256 i) external view returns (Rec memory){ return recs[i]; }
  function len() external view returns (uint256){ return recs.length; }
}`;

    // ---- P7: packed value arrays (Arr<uN,K>) various widths, straddle -------
    const J7 = `
@contract class C {
  @state a: Arr<u40, 7>;
  @state b: Arr<u80, 5>;
  @state c: Arr<bytes5, 7>;
  @external setA(i: u256, v: u40) { this.a[i] = v; }
  @external setB(i: u256, v: u80) { this.b[i] = v; }
  @external setC(i: u256, v: bytes5) { this.c[i] = v; }
  @external @view getA(i: u256): u40 { return this.a[i]; }
  @external @view getB(i: u256): u80 { return this.b[i]; }
  @external @view getC(i: u256): bytes5 { return this.c[i]; }
}`;
    const S7 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint40[7] a; uint80[5] b; bytes5[7] c;
  function setA(uint256 i, uint40 v) external { a[i] = v; }
  function setB(uint256 i, uint80 v) external { b[i] = v; }
  function setC(uint256 i, bytes5 v) external { c[i] = v; }
  function getA(uint256 i) external view returns (uint40){ return a[i]; }
  function getB(uint256 i) external view returns (uint80){ return b[i]; }
  function getC(uint256 i) external view returns (bytes5){ return c[i]; }
}`;

    // ---- P8: signed packed value array (dirty/negative) ---------------------
    const J8 = `
@contract class C {
  @state a: Arr<i40, 7>;
  @state b: i48[];
  @external setA(i: u256, v: i40) { this.a[i] = v; }
  @external pushB(v: i48) { this.b.push(v); }
  @external popB() { this.b.pop(); }
  @external @view getA(i: u256): i40 { return this.a[i]; }
  @external @view getB(i: u256): i48 { return this.b[i]; }
}`;
    const S8 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  int40[7] a; int48[] b;
  function setA(uint256 i, int40 v) external { a[i] = v; }
  function pushB(int48 v) external { b.push(v); }
  function popB() external { b.pop(); }
  function getA(uint256 i) external view returns (int40){ return a[i]; }
  function getB(uint256 i) external view returns (int48){ return b[i]; }
}`;

    // ---- P9: mapping value = packed struct, RMW per field -------------------
    const J9 = `
@struct class S { a: u64; b: i64; flag: bool; addr: address; }
@contract class C {
  @state m: mapping<u256, S>;
  @external setAll(k: u256, a: u64, b: i64, flag: bool, addr: address) { this.m[k] = S(a,b,flag,addr); }
  @external setA(k: u256, v: u64) { this.m[k].a = v; }
  @external setFlag(k: u256, v: bool) { this.m[k].flag = v; }
  @external @view getA(k: u256): u64 { return this.m[k].a; }
  @external @view getB(k: u256): i64 { return this.m[k].b; }
  @external @view getFlag(k: u256): bool { return this.m[k].flag; }
  @external @view getAddr(k: u256): address { return this.m[k].addr; }
  @external @view getAll(k: u256): S { return this.m[k]; }
}`;
    const S9 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint64 a; int64 b; bool flag; address addr; }
  mapping(uint256 => S) m;
  function setAll(uint256 k, uint64 a, int64 b, bool flag, address addr) external { m[k] = S(a,b,flag,addr); }
  function setA(uint256 k, uint64 v) external { m[k].a = v; }
  function setFlag(uint256 k, bool v) external { m[k].flag = v; }
  function getA(uint256 k) external view returns (uint64){ return m[k].a; }
  function getB(uint256 k) external view returns (int64){ return m[k].b; }
  function getFlag(uint256 k) external view returns (bool){ return m[k].flag; }
  function getAddr(uint256 k) external view returns (address){ return m[k].addr; }
  function getAll(uint256 k) external view returns (S memory){ return m[k]; }
}`;

    // ---- P10: struct with a whole-slot fixed array field between packed fields
    // tag(u8) alone (slot0), data(u128[3] -> but u128 packs 2 per slot? NO: array
    // elements pack. u128[3] => slots1,2 (2 per slot, 3 elems => 2 slots). flag(u8) slot3.
    const J10 = `
@struct class T { tag: u8; data: Arr<u128, 3>; flag: u8; mid: bytes4; }
@contract class C {
  @state t: T;
  @external setTag(v: u8) { this.t.tag = v; }
  @external setData(i: u256, v: u128) { this.t.data[i] = v; }
  @external setFlag(v: u8) { this.t.flag = v; }
  @external setMid(v: bytes4) { this.t.mid = v; }
  @external @view getTag(): u8 { return this.t.tag; }
  @external @view getData(i: u256): u128 { return this.t.data[i]; }
  @external @view getFlag(): u8 { return this.t.flag; }
  @external @view getMid(): bytes4 { return this.t.mid; }
}`;
    const S10 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct T { uint8 tag; uint128[3] data; uint8 flag; bytes4 mid; }
  T t;
  function setTag(uint8 v) external { t.tag = v; }
  function setData(uint256 i, uint128 v) external { t.data[i] = v; }
  function setFlag(uint8 v) external { t.flag = v; }
  function setMid(bytes4 v) external { t.mid = v; }
  function getTag() external view returns (uint8){ return t.tag; }
  function getData(uint256 i) external view returns (uint128){ return t.data[i]; }
  function getFlag() external view returns (uint8){ return t.flag; }
  function getMid() external view returns (bytes4){ return t.mid; }
}`;

    // ---- P11: nested struct field, packed inner straddling outer fields ------
    const J11 = `
@struct class Inner { x: u64; y: u64; z: bool; }
@struct class Outer { lead: u8; inner: Inner; trail: bytes20; }
@contract class C {
  @state o: Outer;
  @external setLead(v: u8) { this.o.lead = v; }
  @external setX(v: u64) { this.o.inner.x = v; }
  @external setY(v: u64) { this.o.inner.y = v; }
  @external setZ(v: bool) { this.o.inner.z = v; }
  @external setTrail(v: bytes20) { this.o.trail = v; }
  @external setInner(x: u64, y: u64, z: bool) { this.o.inner = Inner(x,y,z); }
  @external @view getLead(): u8 { return this.o.lead; }
  @external @view getX(): u64 { return this.o.inner.x; }
  @external @view getY(): u64 { return this.o.inner.y; }
  @external @view getZ(): bool { return this.o.inner.z; }
  @external @view getTrail(): bytes20 { return this.o.trail; }
  @external @view getInner(): Inner { return this.o.inner; }
}`;
    const S11 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Inner { uint64 x; uint64 y; bool z; }
  struct Outer { uint8 lead; Inner inner; bytes20 trail; }
  Outer o;
  function setLead(uint8 v) external { o.lead = v; }
  function setX(uint64 v) external { o.inner.x = v; }
  function setY(uint64 v) external { o.inner.y = v; }
  function setZ(bool v) external { o.inner.z = v; }
  function setTrail(bytes20 v) external { o.trail = v; }
  function setInner(uint64 x, uint64 y, bool z) external { o.inner = Inner(x,y,z); }
  function getLead() external view returns (uint8){ return o.lead; }
  function getX() external view returns (uint64){ return o.inner.x; }
  function getY() external view returns (uint64){ return o.inner.y; }
  function getZ() external view returns (bool){ return o.inner.z; }
  function getTrail() external view returns (bytes20){ return o.trail; }
  function getInner() external view returns (Inner memory){ return o.inner; }
}`;

    // ---- P12: struct that EXACTLY fills a 32-byte slot, neighbor must NOT pack
    // a(u128)+b(u128)=32 bytes exactly -> slot0 full. c(u8) -> slot1. A trailing
    // state var (after) must take its own slot (no packing across aggregate boundary).
    const J12 = `
@struct class S { a: u128; b: u128; c: u8; }
@contract class C {
  @state s: S;
  @state after_: u8;
  @external setAll(a: u128, b: u128, c: u8) { this.s = S(a,b,c); }
  @external setAfter(v: u8) { this.after_ = v; }
  @external setA(v: u128) { this.s.a = v; }
  @external setB(v: u128) { this.s.b = v; }
  @external setC(v: u8) { this.s.c = v; }
  @external @view getA(): u128 { return this.s.a; }
  @external @view getB(): u128 { return this.s.b; }
  @external @view getC(): u8 { return this.s.c; }
  @external @view getAfter(): u8 { return this.after_; }
  @external @view getAll(): S { return this.s; }
}`;
    const S12 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint128 a; uint128 b; uint8 c; }
  S s; uint8 after_;
  function setAll(uint128 a, uint128 b, uint8 c) external { s = S(a,b,c); }
  function setAfter(uint8 v) external { after_ = v; }
  function setA(uint128 v) external { s.a = v; }
  function setB(uint128 v) external { s.b = v; }
  function setC(uint8 v) external { s.c = v; }
  function getA() external view returns (uint128){ return s.a; }
  function getB() external view returns (uint128){ return s.b; }
  function getC() external view returns (uint8){ return s.c; }
  function getAfter() external view returns (uint8){ return after_; }
  function getAll() external view returns (S memory){ return s; }
}`;

    // ---- P13: storage-to-storage whole-struct COPY with trailing space ------
    // S { u64 a; u64 b; bool c } = 17 bytes in slot0 (trailing 15 bytes unused).
    // Copy m[src] -> m[dst]; the copy must zero the dst's full slot region (no leak
    // of dst's prior packed neighbors), byte-identical to solc's struct copy.
    const J13 = `
@struct class S { a: u64; b: u64; c: bool; }
@contract class C {
  @state m: mapping<u256, S>;
  @external setAll(k: u256, a: u64, b: u64, c: bool) { this.m[k] = S(a,b,c); }
  @external copy(dst: u256, src: u256) { this.m[dst] = this.m[src]; }
  @external @view getA(k: u256): u64 { return this.m[k].a; }
  @external @view getB(k: u256): u64 { return this.m[k].b; }
  @external @view getC(k: u256): bool { return this.m[k].c; }
  @external @view getAll(k: u256): S { return this.m[k]; }
}`;
    const S13 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint64 a; uint64 b; bool c; }
  mapping(uint256 => S) m;
  function setAll(uint256 k, uint64 a, uint64 b, bool c) external { m[k] = S(a,b,c); }
  function copy(uint256 dst, uint256 src) external { m[dst] = m[src]; }
  function getA(uint256 k) external view returns (uint64){ return m[k].a; }
  function getB(uint256 k) external view returns (uint64){ return m[k].b; }
  function getC(uint256 k) external view returns (bool){ return m[k].c; }
  function getAll(uint256 k) external view returns (S memory){ return m[k]; }
}`;

    // ---- P14: bytesN packing where a bytesN field forces a new slot ---------
    // a(bytes16)+b(bytes16)=32 exact -> slot0. c(bytes1) slot1. d(bytes32) slot2.
    // Plus an "almost fits" straddle: e(bytes30)+f(bytes4) -> e fills 30 of slot3,
    // f(4) does not fit (only 2 left) -> slot4.
    const J14 = `
@struct class S { a: bytes16; b: bytes16; c: bytes1; d: bytes32; e: bytes30; f: bytes4; }
@contract class C {
  @state s: S;
  @external setA(v: bytes16) { this.s.a = v; }
  @external setB(v: bytes16) { this.s.b = v; }
  @external setC(v: bytes1) { this.s.c = v; }
  @external setD(v: bytes32) { this.s.d = v; }
  @external setE(v: bytes30) { this.s.e = v; }
  @external setF(v: bytes4) { this.s.f = v; }
  @external @view getA(): bytes16 { return this.s.a; }
  @external @view getC(): bytes1 { return this.s.c; }
  @external @view getE(): bytes30 { return this.s.e; }
  @external @view getF(): bytes4 { return this.s.f; }
  @external @view getAll(): S { return this.s; }
}`;
    const S14 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { bytes16 a; bytes16 b; bytes1 c; bytes32 d; bytes30 e; bytes4 f; }
  S s;
  function setA(bytes16 v) external { s.a = v; }
  function setB(bytes16 v) external { s.b = v; }
  function setC(bytes1 v) external { s.c = v; }
  function setD(bytes32 v) external { s.d = v; }
  function setE(bytes30 v) external { s.e = v; }
  function setF(bytes4 v) external { s.f = v; }
  function getA() external view returns (bytes16){ return s.a; }
  function getC() external view returns (bytes1){ return s.c; }
  function getE() external view returns (bytes30){ return s.e; }
  function getF() external view returns (bytes4){ return s.f; }
  function getAll() external view returns (S memory){ return s; }
}`;

    // ---- P15: overwrite whole struct with smaller field set, stale-bytes ----
    // Pack many small fields; setAll a big value, then setAll a tiny value -> the
    // RMW of individual high fields must not leave stale bytes. Also setSome only
    // writes a subset; the rest must persist. i120 sign extremes included.
    const J15 = `
@struct class S { a: u16; b: i120; c: bool; d: u8; }
@contract class C {
  @state s: S;
  @external setAll(a: u16, b: i120, c: bool, d: u8) { this.s = S(a,b,c,d); }
  @external setB(v: i120) { this.s.b = v; }
  @external setD(v: u8) { this.s.d = v; }
  @external @view getA(): u16 { return this.s.a; }
  @external @view getB(): i120 { return this.s.b; }
  @external @view getC(): bool { return this.s.c; }
  @external @view getD(): u8 { return this.s.d; }
  @external @view getAll(): S { return this.s; }
}`;
    const S15 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct S { uint16 a; int120 b; bool c; uint8 d; }
  S s;
  function setAll(uint16 a, int120 b, bool c, uint8 d) external { s = S(a,b,c,d); }
  function setB(int120 v) external { s.b = v; }
  function setD(uint8 v) external { s.d = v; }
  function getA() external view returns (uint16){ return s.a; }
  function getB() external view returns (int120){ return s.b; }
  function getC() external view returns (bool){ return s.c; }
  function getD() external view returns (uint8){ return s.d; }
  function getAll() external view returns (S memory){ return s; }
}`;

    [P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P12, P13, P14, P15] = await Promise.all([
      deployPair(J1, S1),
      deployPair(J2, S2),
      deployPair(J3, S3),
      deployPair(J4, S4),
      deployPair(J5, S5),
      deployPair(J6, S6),
      deployPair(J7, S7),
      deployPair(J8, S8),
      deployPair(J9, S9),
      deployPair(J10, S10),
      deployPair(J11, S11),
      deployPair(J12, S12),
      deployPair(J13, S13),
      deployPair(J14, S14),
      deployPair(J15, S15),
    ]);
  });

  it('runs', async () => {
    // ===== P1: mixed-width state vars, dirty-bit calldata, then slots =========
    // Each set call sends a DIRTY 32-byte word (upper bits all ones) for the value;
    // JETH must clean exactly as solc does. We use OR with DIRTY masked to the slot.
    const p1cases: [string, bigint][] = [
      ['setA(uint8)', 0xffn],
      ['setB(int16)', (-1n & mask(16n))], // -1 as 16-bit, but we widen below
      ['setC(bytes3)', 0xaabbccn << 232n],
      ['setD(bool)', 1n],
      ['setE(uint32)', 0xdeadbeefn],
      ['setF(address)', 0x1234567890abcdef1234567890abcdef12345678n],
      ['setG(int40)', ((-1234567n) % M + M) % M],
      ['setH(bytes7)', 0xaabbccddeeff00n << 200n],
    ];
    for (const [s, v] of p1cases) await send(P1, 'P1.' + s, encodeCall(sel(s), [v]));
    await eqSlot(P1, 'P1', 0n);
    await eqSlot(P1, 'P1', 1n); // address takes its own slot? f is 4 bytes after; check
    for (const g of ['getA()', 'getB()', 'getC()', 'getD()', 'getE()', 'getF()', 'getG()', 'getH()'])
      await eq(P1, 'P1.' + g, encodeCall(sel(g)));

    // Now overwrite with DIRTY-HIGH-BIT words: solc must mask. For signed types pass
    // values with garbage in the high 256-bit region (the ABI word) - solc cleans on store.
    await send(P1, 'P1.setA-dirty', encodeCall(sel('setA(uint8)'), [DIRTY])); // 0xff..ff -> a=0xff
    await send(P1, 'P1.setB-dirty', encodeCall(sel('setB(int16)'), [DIRTY])); // -1
    await send(P1, 'P1.setG-dirty', encodeCall(sel('setG(int40)'), [DIRTY])); // -1
    await send(P1, 'P1.setC-dirty', encodeCall(sel('setC(bytes3)'), [DIRTY])); // top 3 bytes
    await eqSlot(P1, 'P1-dirty', 0n);
    for (const g of ['getA()', 'getB()', 'getC()', 'getG()'])
      await eq(P1, 'P1-dirty.' + g, encodeCall(sel(g)));

    // boundary values for signed
    await send(P1, 'P1.setB-min', encodeCall(sel('setB(int16)'), [(-(1n << 15n)) % M + M]));
    await eq(P1, 'P1.getB-min', encodeCall(sel('getB()')));
    await eqSlot(P1, 'P1-bmin', 0n);
    await send(P1, 'P1.setB-max', encodeCall(sel('setB(int16)'), [(1n << 15n) - 1n]));
    await eq(P1, 'P1.getB-max', encodeCall(sel('getB()')));
    await send(P1, 'P1.setG-min', encodeCall(sel('setG(int40)'), [(-(1n << 39n)) % M + M]));
    await eq(P1, 'P1.getG-min', encodeCall(sel('getG()')));
    await eqSlot(P1, 'P1-gmin', 0n);

    // ===== P2: straddling struct ============================================
    const a128 = (1n << 128n) - 1n;
    const b64 = 0x1122334455667788n;
    const dB4 = 0xaabbccddn << 224n;
    const e64 = 0xdeadbeefcafef00dn;
    const f32 = (1n << 256n) - 7n;
    await send(P2, 'P2.setAll', encodeCall(sel('setAll(uint128,uint64,bool,bytes4,uint64,bytes32)'), [a128, b64, 1n, dB4, e64, f32]));
    for (const s of [0n, 1n, 2n, 3n]) await eqSlot(P2, 'P2', s);
    for (const g of ['getA()', 'getB()', 'getC()', 'getD()', 'getE()', 'getF()', 'getAll()', 'getSentinel()'])
      await eq(P2, 'P2.' + g, encodeCall(sel(g)));
    // partial RMW each field, recheck slots + getAll each time (neighbor preservation)
    await send(P2, 'P2.setA', encodeCall(sel('setA(uint128)'), [0x42n]));
    await eqSlot(P2, 'P2-rmwA', 0n);
    await eq(P2, 'P2-rmwA.getAll', encodeCall(sel('getAll()')));
    await send(P2, 'P2.setC0', encodeCall(sel('setC(bool)'), [0n]));
    await eqSlot(P2, 'P2-rmwC0', 0n);
    await eq(P2, 'P2-rmwC0.getAll', encodeCall(sel('getAll()')));
    await send(P2, 'P2.setD-dirty', encodeCall(sel('setD(bytes4)'), [DIRTY]));
    await eqSlot(P2, 'P2-rmwD', 0n);
    await eq(P2, 'P2-rmwD.getD', encodeCall(sel('getD()')));
    await eq(P2, 'P2-rmwD.getAll', encodeCall(sel('getAll()')));
    await send(P2, 'P2.setE', encodeCall(sel('setE(uint64)'), [0xcafen]));
    await eqSlot(P2, 'P2-rmwE', 1n);
    await eq(P2, 'P2-rmwE.getAll', encodeCall(sel('getAll()')));

    // ===== P3: all-signed narrow struct, sign-bit packing ===================
    const signedVals: bigint[] = [
      ((-1n) % M + M), // i8 = -1
      ((-300n) % M + M), // i16
      ((-1n << 23n) % M + M), // i24 min
      0x7fffffffn, // i32 max
      ((-(1n << 39n)) % M + M), // i40 min
      ((1n << 47n) - 1n), // i48 max
      ((-12345678901234n) % M + M), // i56
    ];
    await send(P3, 'P3.setAll', encodeCall(sel('setAll(int8,int16,int24,int32,int40,int48,int56)'), signedVals));
    await eqSlot(P3, 'P3', 0n);
    for (const g of ['getA()', 'getB()', 'getC()', 'getD()', 'getE()', 'getF()', 'getG()', 'getAll()'])
      await eq(P3, 'P3.' + g, encodeCall(sel(g)));
    // RMW a middle field with a positive value (sign bit 0) then a negative
    await send(P3, 'P3.setC+', encodeCall(sel('setC(int24)'), [0x123456n]));
    await eqSlot(P3, 'P3-rmwC+', 0n);
    await eq(P3, 'P3-rmwC+.getAll', encodeCall(sel('getAll()')));
    await send(P3, 'P3.setC-', encodeCall(sel('setC(int24)'), [((-2n) % M + M)]));
    await eqSlot(P3, 'P3-rmwC-', 0n);
    await eq(P3, 'P3-rmwC-.getAll', encodeCall(sel('getAll()')));
    await send(P3, 'P3.setG-dirty', encodeCall(sel('setG(int56)'), [DIRTY])); // -1
    await eqSlot(P3, 'P3-rmwGdirty', 0n);
    await eq(P3, 'P3-rmwGdirty.getG', encodeCall(sel('getG()')));
    await send(P3, 'P3.setA-min', encodeCall(sel('setA(int8)'), [0x80n]));
    await eqSlot(P3, 'P3-rmwAmin', 0n);
    await eq(P3, 'P3-rmwAmin.getA', encodeCall(sel('getA()')));
    await eq(P3, 'P3-rmwAmin.getAll', encodeCall(sel('getAll()')));

    // ===== P4: bool + address packing =======================================
    const addr = 0xCaFE0000000000000000000000000000DeAd0001n;
    await send(P4, 'P4.setAll', encodeCall(sel('setAll(bool,address,bool,uint8)'), [1n, addr, 1n, 0x7fn]));
    await eqSlot(P4, 'P4', 0n);
    for (const g of ['getF1()', 'getOwner()', 'getF2()', 'getSmall()', 'getAll()'])
      await eq(P4, 'P4.' + g, encodeCall(sel(g)));
    // bool dirty (any nonzero -> true is normalized to 1 by solc on store of a bool literal;
    // but passing a dirty bool via ABI: solc validates bool calldata? It cleans to bool).
    await send(P4, 'P4.setF1-dirty', encodeCall(sel('setF1(bool)'), [1n]));
    await eqSlot(P4, 'P4-f1', 0n);
    await send(P4, 'P4.setF1-0', encodeCall(sel('setF1(bool)'), [0n]));
    await eqSlot(P4, 'P4-f10', 0n);
    await eq(P4, 'P4-f10.getAll', encodeCall(sel('getAll()')));
    await send(P4, 'P4.setOwner-dirty', encodeCall(sel('setOwner(address)'), [0xffffffffffffffffffffffffffffffffffffffffn]));
    await eqSlot(P4, 'P4-owner', 0n);
    await eq(P4, 'P4-owner.getOwner', encodeCall(sel('getOwner()')));
    await eq(P4, 'P4-owner.getAll', encodeCall(sel('getAll()')));

    // ===== P5: array of packed struct =======================================
    await send(P5, 'P5.setRec0', encodeCall(sel('setRec(uint256,uint128,uint64,bool,bytes4)'), [0n, a128, b64, 1n, dB4]));
    await send(P5, 'P5.setRec3', encodeCall(sel('setRec(uint256,uint128,uint64,bool,bytes4)'), [3n, 0x1234n, 0x5678n, 0n, 0x11223344n << 224n]));
    for (const s of [0n, 1n, 2n, 3n]) await eqSlot(P5, 'P5', s);
    for (const i of [0n, 1n, 3n]) {
      for (const g of ['getA(uint256)', 'getB(uint256)', 'getC(uint256)', 'getD(uint256)', 'getRec(uint256)'])
        await eq(P5, 'P5.' + g + '@' + i, encodeCall(sel(g), [i]));
    }
    // partial RMW on elem 0 and 3
    await send(P5, 'P5.setA0', encodeCall(sel('setA(uint256,uint128)'), [0n, 0xabcdn]));
    await eqSlot(P5, 'P5-rmwA0', 0n);
    await eq(P5, 'P5-rmwA0.getRec0', encodeCall(sel('getRec(uint256)'), [0n]));
    await send(P5, 'P5.setC3-dirty', encodeCall(sel('setC(uint256,bool)'), [3n, 1n]));
    await eqSlot(P5, 'P5-rmwC3', 3n);
    await eq(P5, 'P5-rmwC3.getRec3', encodeCall(sel('getRec(uint256)'), [3n]));
    // OOB index
    await eq(P5, 'P5.getA-oob', encodeCall(sel('getA(uint256)'), [4n]));

    // ===== P6: dynamic array of packed struct, push/pop reuse ================
    const dataSlot6 = kdataSlot(0n);
    await send(P6, 'P6.push0', encodeCall(sel('pushV(uint128,uint64,bool,bytes4)'), [a128, e64, 1n, dB4]));
    await send(P6, 'P6.push1', encodeCall(sel('pushV(uint128,uint64,bool,bytes4)'), [0x1234n, 0x5678n, 0n, 0x11223344n << 224n]));
    await send(P6, 'P6.pop', encodeCall(sel('pop()')));
    await eqSlot(P6, 'P6-afterpop', 0n);
    await eqSlot(P6, 'P6-afterpop', dataSlot6);
    await eqSlot(P6, 'P6-afterpop', dataSlot6 + 1n); // freed slot must be zero
    // push again into reused slot, must fully overwrite (no stale bytes)
    await send(P6, 'P6.push2', encodeCall(sel('pushV(uint128,uint64,bool,bytes4)'), [0x1n, 0x2n, 1n, 0x99aabbccn << 224n]));
    await eqSlot(P6, 'P6-reuse', dataSlot6 + 1n);
    await send(P6, 'P6.setA0', encodeCall(sel('setA(uint256,uint128)'), [0n, 0x42n]));
    await send(P6, 'P6.setC1', encodeCall(sel('setC(uint256,bool)'), [1n, 0n]));
    await eqSlot(P6, 'P6-rmw', dataSlot6);
    await eqSlot(P6, 'P6-rmw', dataSlot6 + 1n);
    for (const i of [0n, 1n]) {
      await eq(P6, 'P6.getRec@' + i, encodeCall(sel('getRec(uint256)'), [i]));
      await eq(P6, 'P6.getA@' + i, encodeCall(sel('getA(uint256)'), [i]));
      await eq(P6, 'P6.getC@' + i, encodeCall(sel('getC(uint256)'), [i]));
    }
    await eq(P6, 'P6.len', encodeCall(sel('len()')));
    await eq(P6, 'P6.getRec-oob', encodeCall(sel('getRec(uint256)'), [2n]));

    // ===== P7: packed value arrays ==========================================
    const p7a: [string, bigint, bigint][] = [
      ['setA(uint256,uint40)', 0n, mask(40n)],
      ['setA(uint256,uint40)', 6n, 0x1122334455n],
      ['setA(uint256,uint40)', 4n, 0xffffffffffn],
      ['setB(uint256,uint80)', 0n, mask(80n)],
      ['setB(uint256,uint80)', 4n, 0xdeadbeefcafef00dabcdn],
      ['setC(uint256,bytes5)', 0n, 0xaabbccddeen << 216n],
      ['setC(uint256,bytes5)', 6n, 0x1122334455n << 216n],
    ];
    for (const [s, i, v] of p7a) await send(P7, 'P7.' + s + '@' + i, encodeCall(sel(s), [i, v]));
    for (const s of [0n, 1n, 2n, 3n, 4n]) await eqSlot(P7, 'P7', s);
    for (const i of [0n, 4n, 6n]) {
      await eq(P7, 'P7.getA@' + i, encodeCall(sel('getA(uint256)'), [i]));
      await eq(P7, 'P7.getC@' + i, encodeCall(sel('getC(uint256)'), [i]));
    }
    for (const i of [0n, 4n]) await eq(P7, 'P7.getB@' + i, encodeCall(sel('getB(uint256)'), [i]));

    // ===== P8: signed packed value array + dynamic signed ====================
    const p8a: [bigint, bigint][] = [
      [0n, ((-1n) % M + M)],
      [1n, ((-(1n << 39n)) % M + M)], // i40 min
      [3n, ((1n << 39n) - 1n)], // i40 max
      [6n, ((-987654n) % M + M)],
    ];
    for (const [i, v] of p8a) await send(P8, 'P8.setA@' + i, encodeCall(sel('setA(uint256,int40)'), [i, v]));
    for (const s of [0n, 1n]) await eqSlot(P8, 'P8', s);
    for (const i of [0n, 1n, 3n, 6n]) await eq(P8, 'P8.getA@' + i, encodeCall(sel('getA(uint256)'), [i]));
    // dynamic i48[]
    await send(P8, 'P8.pushB-1', encodeCall(sel('pushB(int48)'), [((-1n) % M + M)]));
    await send(P8, 'P8.pushB-max', encodeCall(sel('pushB(int48)'), [((1n << 47n) - 1n)]));
    await send(P8, 'P8.pushB-min', encodeCall(sel('pushB(int48)'), [((-(1n << 47n)) % M + M)]));
    const dataSlot8 = kdataSlot(1n); // b is state var index 1
    await eqSlot(P8, 'P8-dyn', 1n);
    await eqSlot(P8, 'P8-dyn', dataSlot8);
    for (const i of [0n, 1n, 2n]) await eq(P8, 'P8.getB@' + i, encodeCall(sel('getB(uint256)'), [i]));
    await send(P8, 'P8.popB', encodeCall(sel('popB()')));
    await eqSlot(P8, 'P8-afterpop', dataSlot8);

    // ===== P9: mapping value = packed struct =================================
    const key = (1n << 200n) | 0xabcdn;
    const base9 = kmapSlot(key, 0n);
    await send(P9, 'P9.setAll', encodeCall(sel('setAll(uint256,uint64,int64,bool,address)'), [key, 0xdeadn, ((-77n) % M + M), 1n, addr]));
    await eqSlot(P9, 'P9', base9);
    await eqSlot(P9, 'P9', base9 + 1n);
    for (const g of ['getA(uint256)', 'getB(uint256)', 'getFlag(uint256)', 'getAddr(uint256)', 'getAll(uint256)'])
      await eq(P9, 'P9.' + g, encodeCall(sel(g), [key]));
    await send(P9, 'P9.setA', encodeCall(sel('setA(uint256,uint64)'), [key, 0x9999n]));
    await eqSlot(P9, 'P9-rmwA', base9);
    await eq(P9, 'P9-rmwA.getAll', encodeCall(sel('getAll(uint256)'), [key]));
    await send(P9, 'P9.setFlag0', encodeCall(sel('setFlag(uint256,bool)'), [key, 0n]));
    await eqSlot(P9, 'P9-rmwFlag', base9);
    await eq(P9, 'P9-rmwFlag.getAll', encodeCall(sel('getAll(uint256)'), [key]));
    // unset key reads zero struct
    await eq(P9, 'P9.getAll-unset', encodeCall(sel('getAll(uint256)'), [0x999999n]));

    // ===== P10: struct with whole-slot fixed array field =====================
    await send(P10, 'P10.setTag', encodeCall(sel('setTag(uint8)'), [0x7fn]));
    await send(P10, 'P10.setData0', encodeCall(sel('setData(uint256,uint128)'), [0n, a128]));
    await send(P10, 'P10.setData1', encodeCall(sel('setData(uint256,uint128)'), [1n, 0x1234n]));
    await send(P10, 'P10.setData2', encodeCall(sel('setData(uint256,uint128)'), [2n, 0x5678n]));
    await send(P10, 'P10.setFlag', encodeCall(sel('setFlag(uint8)'), [0x99n]));
    await send(P10, 'P10.setMid-dirty', encodeCall(sel('setMid(bytes4)'), [DIRTY]));
    for (const s of [0n, 1n, 2n, 3n, 4n]) await eqSlot(P10, 'P10', s);
    for (const g of ['getTag()', 'getFlag()', 'getMid()'])
      await eq(P10, 'P10.' + g, encodeCall(sel(g)));
    for (const i of [0n, 1n, 2n]) await eq(P10, 'P10.getData@' + i, encodeCall(sel('getData(uint256)'), [i]));

    // ===== P11: nested struct field packing ==================================
    const trail = 0xaabbccddeeff00112233445566778899aabbccddn << 96n; // bytes20 left-aligned
    await send(P11, 'P11.setInner', encodeCall(sel('setInner(uint64,uint64,bool)'), [0x1111111111111111n, 0x2222222222222222n, 1n]));
    await send(P11, 'P11.setLead', encodeCall(sel('setLead(uint8)'), [0x42n]));
    await send(P11, 'P11.setTrail', encodeCall(sel('setTrail(bytes20)'), [trail]));
    for (const s of [0n, 1n, 2n, 3n]) await eqSlot(P11, 'P11', s);
    for (const g of ['getLead()', 'getX()', 'getY()', 'getZ()', 'getTrail()', 'getInner()'])
      await eq(P11, 'P11.' + g, encodeCall(sel(g)));
    // RMW inner.x then inner.z, ensure lead/trail preserved
    await send(P11, 'P11.setX', encodeCall(sel('setX(uint64)'), [0xdeadbeefn]));
    await eq(P11, 'P11-rmwX.getInner', encodeCall(sel('getInner()')));
    await eq(P11, 'P11-rmwX.getLead', encodeCall(sel('getLead()')));
    await send(P11, 'P11.setZ0', encodeCall(sel('setZ(bool)'), [0n]));
    await eq(P11, 'P11-rmwZ.getInner', encodeCall(sel('getInner()')));
    for (const s of [0n, 1n, 2n, 3n]) await eqSlot(P11, 'P11-final', s);

    // ===== P12: exact-fill slot, no cross-aggregate packing ==================
    await send(P12, 'P12.setAll', encodeCall(sel('setAll(uint128,uint128,uint8)'), [a128, a128 - 1n, 0xffn]));
    await send(P12, 'P12.setAfter', encodeCall(sel('setAfter(uint8)'), [0x7fn]));
    for (const s of [0n, 1n, 2n]) await eqSlot(P12, 'P12', s);
    for (const g of ['getA()', 'getB()', 'getC()', 'getAfter()', 'getAll()'])
      await eq(P12, 'P12.' + g, encodeCall(sel(g)));
    // RMW: write c (in slot1 low byte). after_ is also in slot1 at offset 1 -> must
    // be preserved. This is the cross-aggregate neighbor test.
    await send(P12, 'P12.setC', encodeCall(sel('setC(uint8)'), [0x11n]));
    await eqSlot(P12, 'P12-rmwC', 1n);
    await eq(P12, 'P12-rmwC.getAfter', encodeCall(sel('getAfter()')));
    await eq(P12, 'P12-rmwC.getC', encodeCall(sel('getC()')));
    await send(P12, 'P12.setAfter2', encodeCall(sel('setAfter(uint8)'), [0x22n]));
    await eqSlot(P12, 'P12-rmwAfter', 1n);
    await eq(P12, 'P12-rmwAfter.getC', encodeCall(sel('getC()')));
    await eq(P12, 'P12-rmwAfter.getAfter', encodeCall(sel('getAfter()')));
    await send(P12, 'P12.setA', encodeCall(sel('setA(uint128)'), [0x99n]));
    await eqSlot(P12, 'P12-rmwA', 0n);
    await eq(P12, 'P12-rmwA.getB', encodeCall(sel('getB()')));

    // ===== P13: storage-to-storage struct copy, trailing-space clearing ======
    const k1 = 7n, k2 = 8n, k3 = 9n;
    const b13_1 = kmapSlot(k1, 0n), b13_2 = kmapSlot(k2, 0n), b13_3 = kmapSlot(k3, 0n);
    // src has full data; dst3 pre-populated with DIFFERENT data then overwritten by copy.
    await send(P13, 'P13.setSrc', encodeCall(sel('setAll(uint256,uint64,uint64,bool)'), [k1, 0xdeadbeefn, 0xcafef00dn, 1n]));
    await send(P13, 'P13.setDst3', encodeCall(sel('setAll(uint256,uint64,uint64,bool)'), [k3, 0xffffffffffffffffn, 0xeeeeeeeeeeeeeeeen, 1n]));
    await send(P13, 'P13.copy-empty', encodeCall(sel('copy(uint256,uint256)'), [k2, 0x123n])); // copy zero src -> dst2
    await send(P13, 'P13.copy-over', encodeCall(sel('copy(uint256,uint256)'), [k3, k1])); // overwrite k3 with k1
    await eqSlot(P13, 'P13-src', b13_1);
    await eqSlot(P13, 'P13-dst2zero', b13_2);
    await eqSlot(P13, 'P13-dst3copied', b13_3);
    for (const k of [k1, k2, k3]) {
      for (const g of ['getA(uint256)', 'getB(uint256)', 'getC(uint256)', 'getAll(uint256)'])
        await eq(P13, 'P13.' + g + '@' + k, encodeCall(sel(g), [k]));
    }

    // ===== P14: bytesN packing forcing new slots =============================
    const b16hi = (mask(128n)) << 128n; // bytes16 left-aligned all-ones
    await send(P14, 'P14.setA', encodeCall(sel('setA(bytes16)'), [b16hi]));
    await send(P14, 'P14.setB', encodeCall(sel('setB(bytes16)'), [0xaabbccddeeff00112233445566778899n << 128n]));
    await send(P14, 'P14.setC', encodeCall(sel('setC(bytes1)'), [0x7fn << 248n]));
    await send(P14, 'P14.setD', encodeCall(sel('setD(bytes32)'), [(1n << 256n) - 3n]));
    await send(P14, 'P14.setE', encodeCall(sel('setE(bytes30)'), [(mask(240n)) << 16n]));
    await send(P14, 'P14.setF-dirty', encodeCall(sel('setF(bytes4)'), [DIRTY]));
    for (const s of [0n, 1n, 2n, 3n, 4n]) await eqSlot(P14, 'P14', s);
    for (const g of ['getA()', 'getC()', 'getE()', 'getF()', 'getAll()'])
      await eq(P14, 'P14.' + g, encodeCall(sel(g)));
    // RMW e (slot3) then f (slot4) and check no leak / left-alignment
    await send(P14, 'P14.setE2', encodeCall(sel('setE(bytes30)'), [0x112233445566778899aabbccddeeff00112233445566778899aabbccddeen << 16n]));
    await eqSlot(P14, 'P14-rmwE', 3n);
    await eq(P14, 'P14-rmwE.getE', encodeCall(sel('getE()')));
    await eq(P14, 'P14-rmwE.getAll', encodeCall(sel('getAll()')));

    // ===== P15: overwrite + stale-bytes hazard, signed extremes ==============
    const i120max = (1n << 119n) - 1n;
    const i120min = ((-(1n << 119n)) % M + M);
    await send(P15, 'P15.setAll-big', encodeCall(sel('setAll(uint16,int120,bool,uint8)'), [0xffffn, i120min, 1n, 0xffn]));
    await eqSlot(P15, 'P15-big', 0n);
    await eq(P15, 'P15-big.getAll', encodeCall(sel('getAll()')));
    // overwrite with a tiny set: stale high bytes of b must be cleared
    await send(P15, 'P15.setAll-tiny', encodeCall(sel('setAll(uint16,int120,bool,uint8)'), [1n, 1n, 0n, 1n]));
    await eqSlot(P15, 'P15-tiny', 0n);
    await eq(P15, 'P15-tiny.getAll', encodeCall(sel('getAll()')));
    // setB to max positive then to -1 (dirty), only b should change
    await send(P15, 'P15.setB-max', encodeCall(sel('setB(int120)'), [i120max]));
    await eqSlot(P15, 'P15-bmax', 0n);
    await eq(P15, 'P15-bmax.getAll', encodeCall(sel('getAll()')));
    await send(P15, 'P15.setB-dirty', encodeCall(sel('setB(int120)'), [DIRTY])); // -1
    await eqSlot(P15, 'P15-bdirty', 0n);
    await eq(P15, 'P15-bdirty.getB', encodeCall(sel('getB()')));
    await eq(P15, 'P15-bdirty.getA', encodeCall(sel('getA()')));
    await eq(P15, 'P15-bdirty.getAll', encodeCall(sel('getAll()')));
    await send(P15, 'P15.setD', encodeCall(sel('setD(uint8)'), [0xden]));
    await eqSlot(P15, 'P15-d', 0n);
    await eq(P15, 'P15-d.getAll', encodeCall(sel('getAll()')));

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else {
      console.log('ALL ' + count + ' byte-identical');
    }
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
