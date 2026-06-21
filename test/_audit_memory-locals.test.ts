// ADVERSARIAL differential audit for the MEMORY-LOCALS family vs solc.
// Invariant: byte-identical returndata AND success/revert/Panic parity AND raw storage slots.
//
// Coverage (all forms in the assigned family):
//  - static struct memory locals: construct/read/write/alias/return, nested fields, pass-by-ref
//  - static fixed-array memory locals: r/w, +=, ++, OOB Panic 0x32, alias, whole return, storage copy
//  - dynamic value-array memory locals: a[i] r/w, OOB read/write
//  - bytes/string memory locals: construct, .length, b[i] (Panic 0x32 OOB), alias, return
//  - dynamic-field struct memory locals: construct/copy from storage|calldata|local|alias,
//    value+bytes/string field read/write, alias-visible mutation, DIRTY-calldata-copy validation
//  - internal/private calls: value, void, static-struct params/returns, recursion, transitive purity
//  - multi-value internal calls via tuple destructuring: decl, assign to storage+local, swap,
//    skipped components, RHS-before-LHS evaluation order
// Storage targets compared by RAW SLOT (direct + computed keccak data slots).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const hx = (s: string) => Buffer.from(s, 'utf8').toString('hex');
// dynamic [len][right-padded data] tail block from a utf8 string
const encStr = (s: string) => { const h = hx(s); return pad(BigInt(h.length / 2)) + h.padEnd(Math.ceil(h.length / 64) * 64, '0'); };
// same from a raw byte buffer (lets us inject arbitrary bytes / dirty payloads)
const encBuf = (b: Buffer) => { const h = b.toString('hex'); return pad(BigInt(b.length)) + h.padEnd(Math.ceil(b.length / 32) * 64, '0'); };
const wordsFor = (byteLen: number) => 32 + Math.ceil(byteLen / 32) * 32; // tail size of one dyn block

// payload zoo: empty / 1 / 31 / 32 / 33 / 63 / 64 / 65 / multi-word
const LENS = [0, 1, 31, 32, 33, 63, 64, 65, 96, 100];
const strOf = (n: number) => Array.from({ length: n }, (_, i) => String.fromCharCode(97 + (i % 26))).join('');
const bufOf = (n: number) => Buffer.from(Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff));
const STRS = LENS.map(strOf);
const BUFS = LENS.map(bufOf);

// ---- calldata builders for various param shapes -----------------------------
// (value, string): head=[v][off=0x40], tail=[len][data]
const cd_v_s = (sig: string, v: bigint, s: string) => '0x' + sel(sig) + pad(v) + pad(0x40n) + encStr(s);
// (string, value): head=[off=0x40][v], tail=[len][data]
// (bytes, uint256): head=[off=0x40][i], tail=[len][data]
const cd_b_u = (sig: string, b: Buffer, i: bigint) => '0x' + sel(sig) + pad(0x40n) + pad(i) + encBuf(b);
// single string param: head=[off=0x20], tail=[len][data]
const cd_s1 = (sig: string, s: string) => '0x' + sel(sig) + pad(0x20n) + encStr(s);
// single bytes param (raw buffer): head=[off=0x20], tail=[len][data]
const cd_b1 = (sig: string, b: Buffer) => '0x' + sel(sig) + pad(0x20n) + encBuf(b);

// ----------------------------- sources ---------------------------------------
const JETH = `
@struct class P { a: u256; b: u8; c: i64; d: address; }
@struct class Q { x: u128; y: u128; }
@struct class Inner { a: u256; b: i64; }
@struct class Outer { tag: u256; inner: Inner; z: u8; }
@struct class VS  { a: u256; s: string; }
@struct class SV  { s: string; a: u256; }
@struct class SV2 { s: string; a: u8; }
@struct class D4  { a: u256; s: string; b: bytes; n: u64; }
@struct class DN  { x: u8; y: i16; z: address; w: bytes4; flag: bool; s: string; }
@contract class C {
  @state s: P;                  // slots 0..3 (a=0,b/?=1 actually a=slot0; struct packs: a=slot0, b+c+d=slot1)
  @state q: Q;                  // packed x,y in one slot
  @state st: VS;                // dynamic-field storage struct
  @state st4: D4;
  @state m: mapping<u256, u256>;
  @state arr: Arr<u256, 4>;     // fixed storage array
  @state dyn: u256[];           // dynamic storage array
  @state cnt: u256;
  @state acc: u256;
  @state g3: Arr<u256, 3>;      // fixed storage array source for memory copy

  // ===== static struct memory locals =====
  @external @pure mkP(a: u256, b: u8, c: i64, d: address): P { let p: P = P(a, b, c, d); return p; }
  @external @pure readWrite(a: u256, b: u8, c: i64, d: address, na: u256): P {
    let p: P = P(a, b, c, d); let k: u256 = p.a; p.a = k + na; return p;
  }
  // aliasing: q aliases p; mutate through q; read p
  @external @pure aliasMut(a: u128, b: u128, nx: u128): Q {
    let p: Q = Q(a, b); let r: Q = p; r.x = r.x + nx; r.y = nx; return p;
  }
  // nested-field whole read: let inn = o.inner aliases the parent; mutate inn; read o
  @external @pure nestedAlias(t: u256, ia: u256, ib: i64, z: u8, nv: u256): Outer {
    let o: Outer = Outer(t, Inner(ia, ib), z);
    let inn: Inner = o.inner;
    inn.a = nv;
    return o;
  }
  // pass-by-ref helper mutates a memory struct param
  @pure setQ(p: Q, nx: u128, ny: u128): void { p.x = nx; p.y = ny; }
  @external @pure refMut(a: u128, b: u128, nx: u128, ny: u128): Q {
    let p: Q = Q(a, b); this.setQ(p, nx, ny); return p;
  }
  // copy storage struct -> mutate local -> return (storage must NOT change)
  @external setS(a: u256, b: u8, c: i64, d: address): void { this.s = P(a, b, c, d); }
  @external copyMutS(na: u256): P { let p: P = this.s; p.a = na; p.b = 255n; return p; }
  @external @view getS(): P { return this.s; }

  // ===== static fixed-array memory locals =====
  @external @pure fa_build(x: u256, y: u256, z: u256, i: u256): u256 {
    let a: Arr<u256, 3> = [x, y, z]; a[0n] += 1n; a[1n]++; return a[i];
  }
  @external @pure fa_oobR(x: u256, i: u256): u256 { let a: Arr<u256, 3> = [x, x, x]; return a[i]; }
  @external @pure fa_oobW(x: u256, i: u256): u256 { let a: Arr<u256, 3> = [x, x, x]; a[i] = 9n; return a[0n]; }
  @external @pure fa_alias(x: u256): Arr<u256, 3> { let a: Arr<u256, 3> = [x, x, x]; let b: Arr<u256, 3> = a; b[0n] = 99n; return a; }
  @external @pure fa_return(p: u256, q: u256): Arr<u256, 2> { let a: Arr<u256, 2> = [p, q]; a[1n] += 5n; return a; }
  @external @pure fa_narrow(p: u8, q: u8): Arr<u8, 4> { let a: Arr<u8, 4> = [p, q, 255n, 0n]; a[1n] = 200n; a[0n] += 50n; return a; }
  @external setG3(x: u256, y: u256, z: u256): void { this.g3[0n] = x; this.g3[1n] = y; this.g3[2n] = z; }
  @external @view fa_fromStorage(): Arr<u256, 3> { let a: Arr<u256, 3> = this.g3; a[0n] = a[0n] + 1000n; a[2n]++; return a; }

  // ===== dynamic value-array memory locals =====
  @external @pure dv_build(a: u256, b: u256, c: u256, i: u256): u256 { let xs: u256[] = [a, b, c]; xs[1n] = xs[1n] + 7n; return xs[i]; }
  @external @pure dv_oobR(a: u256, i: u256): u256 { let xs: u256[] = [a, a]; return xs[i]; }
  @external @pure dv_oobW(a: u256, i: u256): u256 { let xs: u256[] = [a, a]; xs[i] = 5n; return xs[0n]; }
  @external @pure dv_len(a: u256, b: u256, c: u256): u256 { let xs: u256[] = [a, b, c]; return xs.length; }

  // ===== bytes/string memory locals =====
  @external @pure bs_echo(s: string): string { let t: string = s; return t; }
  @external @pure bs_len(b: bytes): u256 { let t: bytes = b; return t.length; }
  @external @pure bs_at(b: bytes, i: u256): u8 { let t: bytes = b; return u8(t[i]); }
  @external @pure bs_litLen(): u256 { let t: bytes = "literal payload exceeding thirty-two bytes for a length read!"; return t.length; }
  @external @view bs_fromStorageLen(): u256 { let t: bytes = this.st4.b; return t.length; }
  @external seedStS(av: u256, s: string): void { this.st = VS(av, s); }

  // ===== dynamic-field struct memory locals =====
  @external @pure dyn_mkVS(a: u256, s: string): VS { let d: VS = VS(a, s); return d; }
  @external @pure dyn_writeVal(a: u256, s: string, na: u256): VS { let d: VS = VS(a, s); d.a = d.a + na; return d; }
  @external @pure dyn_writeStr(a: u256, s: string, ns: string): VS { let d: VS = VS(a, s); d.s = ns; return d; }
  // value field AFTER the dynamic field (head-offset under write)
  @external @pure dyn_writeSVa(s: string, a: u256, na: u256): SV { let d: SV = SV(s, a); d.a = na; return d; }
  // copy from storage struct -> return whole (storage unchanged)
  @external seedSt4(av: u256, s: string, b: bytes, n: u64): void { this.st4 = D4(av, s, b, n); }
  @external @view dyn_fromSt4(): D4 { let d: D4 = this.st4; return d; }
  @external @view dyn_fromSt4Write(ns: string, nb: bytes, nv: u256): D4 { let d: D4 = this.st4; d.s = ns; d.b = nb; d.a = nv; return d; }
  // copy from calldata struct param -> return whole
  @external @pure dyn_fromCd(x: D4): D4 { let d: D4 = x; return d; }
  // copy from calldata DN (narrow/signed/address/bytes4/bool fields) -> validation parity
  @external @pure dyn_fromDNcd(x: DN): DN { let d: DN = x; return d; }
  @external @pure dyn_mkDN(x: u8, y: i16, z: address, w: bytes4, flag: bool, s: string): DN { let d: DN = DN(x, y, z, w, flag, s); return d; }
  // copy from another LOCAL (alias chain) then mutate through alias; read original
  @external @pure dyn_aliasCross(av: u256, s: string, ns: string, nv: u256): VS {
    let d: VS = VS(av, s); let e: VS = d; e.s = ns; e.a = nv; return d;
  }
  // mutate through alias is visible in the ORIGINAL's bytes read (length)
  @external @view dyn_aliasLen(): u256 { let d: D4 = this.st4; let e: D4 = d; d.b = "ZZZ"; return e.b.length; }
  // byte index on a dyn field of a constructed struct (in-bounds + OOB)
  @external @pure dyn_bAt(b: bytes, i: u256): u8 { let d: D4 = D4(0n, "", b, 0n); return u8(d.b[i]); }
  // construct a dyn-struct from a calldata NARROW value param placed AFTER the dyn field;
  // a dirty u8/i16/bool param surfaces as a checked param-validation revert (before any struct work)
  @external @pure dyn_mkPostNarrow(s: string, a: u8): SV2 { let d: SV2 = SV2(s, a); return d; }
  // calldata copy of SV2 (value field after dyn field): solc validates the narrow word on copy
  @external @pure dyn_fromCdPost(x: SV2): SV2 { let d: SV2 = x; return d; }
  // tuple destructuring where a MEMORY struct field is a target (swap two fields of a memory struct)
  @external @pure td_memField(a: u128, b: u128): Q { let p: Q = Q(a, b); [p.x, p.y] = [p.y, p.x]; return p; }
  // tuple destructuring assigning a call result to two memory-struct fields
  @external @pure td_memFieldCall(a: u256, b: u256): Inner { let p: Inner = Inner(0n, 0n); [p.a, p.b] = this.addsubI(a, b); return p; }
  @pure addsubI(a: u256, b: u256): [u256, i64] { return [a + b, i64(u64(a)) - i64(u64(b))]; }

  // ===== internal/private calls: value/void/struct, recursion, purity =====
  @pure addV(a: u256, b: u256): u256 { return a + b; }
  @external @pure callV(a: u256, b: u256): u256 { return this.addV(a, b) * 2n; }
  bumpAcc(by: u256): void { this.acc = this.acc + by; }
  @external doBump(x: u256): void { this.bumpAcc(x); this.bumpAcc(x); }
  @external @view getAcc(): u256 { return this.acc; }
  // struct param + struct return through an internal call
  @pure twP(p: P): P { return P(p.a + 1n, u8(p.b + 1n), i64(p.c - 1n), p.d); }
  @external @pure callStructPR(a: u256, b: u8, c: i64, d: address): P { return this.twP(P(a, b, c, d)); }
  // recursion that takes AND returns a struct
  @pure climb(p: Q, n: u128): Q { if (n == 0n) { return p; } return this.climb(Q(p.x + 1n, p.y + 2n), n - 1n); }
  @external @pure climbE(a: u128, b: u128, n: u128): Q { return this.climb(Q(a, b), n); }
  // recursion that mutates the param by-ref each level
  @pure accDown(p: Q, n: u128): void { if (n == 0n) { return; } p.x = p.x + n; this.accDown(p, n - 1n); }
  @external @pure accE(a: u128, n: u128): Q { let p: Q = Q(a, 0n); this.accDown(p, n); return p; }
  // transitive purity: pure -> pure -> pure
  @pure d4(x: u256): u256 { return x * 8n; }
  @pure c4(x: u256): u256 { return this.d4(x) + 4n; }
  @pure b4(x: u256): u256 { return this.c4(x) + 2n; }
  @external @pure chainE(x: u256): u256 { return this.b4(x) + 1n; }
  // private call (bare name)
  @pure priv(a: u256): u256 { return a * 3n; }
  @external @pure callPriv(a: u256): u256 { return priv(a) + 1n; }

  // ===== multi-value internal calls via tuple destructuring =====
  @pure two(): [u256, u256] { return [11n, 22n]; }
  @pure addsub(a: u256, b: u256): [u256, u256] { return [a + b, a - b]; }
  @external @pure td_decl(): u256 { let [a, b] = this.two(); return a * 1000n + b; }
  @external @pure td_skip(): u256 { let [ , b] = this.two(); return b; }
  @external @pure td_underflow(p: u256, qv: u256): u256 { let [s, d] = this.addsub(p, qv); return s + d; }
  // assign to existing locals
  @external @pure td_assignLocal(p: u256, qv: u256): u256 { let a: u256 = 1n; let b: u256 = 2n; [a, b] = this.addsub(p, qv); return a * 1000000n + b; }
  // swap via tuple
  @external @pure td_swap(p: u256, qv: u256): u256 { let a: u256 = p; let b: u256 = qv; [a, b] = [b, a]; return a * 1000000n + b; }
  // assign to STORAGE targets; compare raw slots
  @external td_storage(p: u256, qv: u256): u256 { [this.acc, this.cnt] = this.addsub(p, qv); return this.acc * 1000000n + this.cnt; }
  // swap two PACKED state vars (one slot) via tuple
  @external td_swapPacked(p: u128, qv: u128): u256 { this.q.x = p; this.q.y = qv; [this.q.x, this.q.y] = [this.q.y, this.q.x]; return u256(this.q.x) * 1000000n + u256(this.q.y); }
  // RHS evaluated BEFORE LHS store: [this.acc, this.cnt] = [this.cnt, this.acc + this.cnt]
  @external td_rhsFirst(p: u256, qv: u256): u256 { this.acc = p; this.cnt = qv; [this.acc, this.cnt] = [this.cnt, this.acc + this.cnt]; return this.acc * 1000000n + this.cnt; }
  // skipped CALL component: call runs once (side effect), value discarded
  threeSide(): [u256, u256, u256] { this.cnt = this.cnt + 7n; return [1n, 2n, 3n]; }
  @external td_skipCall(): u256 { this.cnt = 0n; let [a, , c] = this.threeSide(); return a * 1000000n + c * 1000n + this.cnt; }
  @view getCnt(): u256 { return this.cnt; }
  @view getQ(): Q { return this.q; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; int64 c; address d; }
  struct Q { uint128 x; uint128 y; }
  struct Inner { uint256 a; int64 b; }
  struct Outer { uint256 tag; Inner inner; uint8 z; }
  struct VS  { uint256 a; string s; }
  struct SV  { string s; uint256 a; }
  struct SV2 { string s; uint8 a; }
  struct D4  { uint256 a; string s; bytes b; uint64 n; }
  struct DN  { uint8 x; int16 y; address z; bytes4 w; bool flag; string s; }
  P s;
  Q q;
  VS st;
  D4 st4;
  mapping(uint256 => uint256) m;
  uint256[4] arr;
  uint256[] dyn;
  uint256 cnt;
  uint256 acc;
  uint256[3] g3;

  function mkP(uint256 a, uint8 b, int64 c, address d) external pure returns (P memory){ P memory p = P(a, b, c, d); return p; }
  function readWrite(uint256 a, uint8 b, int64 c, address d, uint256 na) external pure returns (P memory){
    P memory p = P(a, b, c, d); uint256 k = p.a; p.a = k + na; return p;
  }
  function aliasMut(uint128 a, uint128 b, uint128 nx) external pure returns (Q memory){
    Q memory p = Q(a, b); Q memory r = p; r.x = r.x + nx; r.y = nx; return p;
  }
  function nestedAlias(uint256 t, uint256 ia, int64 ib, uint8 z, uint256 nv) external pure returns (Outer memory){
    Outer memory o = Outer(t, Inner(ia, ib), z);
    Inner memory inn = o.inner;
    inn.a = nv;
    return o;
  }
  function setQ(Q memory p, uint128 nx, uint128 ny) internal pure { p.x = nx; p.y = ny; }
  function refMut(uint128 a, uint128 b, uint128 nx, uint128 ny) external pure returns (Q memory){
    Q memory p = Q(a, b); setQ(p, nx, ny); return p;
  }
  function setS(uint256 a, uint8 b, int64 c, address d) external { s = P(a, b, c, d); }
  function copyMutS(uint256 na) external view returns (P memory){ P memory p = s; p.a = na; p.b = 255; return p; }
  function getS() external view returns (P memory){ return s; }

  function fa_build(uint256 x, uint256 y, uint256 z, uint256 i) external pure returns (uint256){
    uint256[3] memory a = [x, y, z]; a[0] += 1; a[1]++; return a[i];
  }
  function fa_oobR(uint256 x, uint256 i) external pure returns (uint256){ uint256[3] memory a = [x, x, x]; return a[i]; }
  function fa_oobW(uint256 x, uint256 i) external pure returns (uint256){ uint256[3] memory a = [x, x, x]; a[i] = 9; return a[0]; }
  function fa_alias(uint256 x) external pure returns (uint256[3] memory){ uint256[3] memory a = [x, x, x]; uint256[3] memory b = a; b[0] = 99; return a; }
  function fa_return(uint256 p, uint256 q_) external pure returns (uint256[2] memory){ uint256[2] memory a = [p, q_]; a[1] += 5; return a; }
  function fa_narrow(uint8 p, uint8 q_) external pure returns (uint8[4] memory){ uint8[4] memory a = [p, q_, 255, 0]; a[1] = 200; a[0] += 50; return a; }
  function setG3(uint256 x, uint256 y, uint256 z) external { g3[0] = x; g3[1] = y; g3[2] = z; }
  function fa_fromStorage() external view returns (uint256[3] memory){ uint256[3] memory a = g3; a[0] = a[0] + 1000; a[2]++; return a; }

  function dv_build(uint256 a, uint256 b, uint256 c, uint256 i) external pure returns (uint256){ uint256[] memory xs = new uint256[](3); xs[0]=a; xs[1]=b; xs[2]=c; xs[1] = xs[1] + 7; return xs[i]; }
  function dv_oobR(uint256 a, uint256 i) external pure returns (uint256){ uint256[] memory xs = new uint256[](2); xs[0]=a; xs[1]=a; return xs[i]; }
  function dv_oobW(uint256 a, uint256 i) external pure returns (uint256){ uint256[] memory xs = new uint256[](2); xs[0]=a; xs[1]=a; xs[i] = 5; return xs[0]; }
  function dv_len(uint256 a, uint256 b, uint256 c) external pure returns (uint256){ uint256[] memory xs = new uint256[](3); xs[0]=a; xs[1]=b; xs[2]=c; return xs.length; }

  function bs_echo(string calldata s_) external pure returns (string memory){ string memory t = s_; return t; }
  function bs_len(bytes calldata b) external pure returns (uint256){ bytes memory t = b; return t.length; }
  function bs_at(bytes calldata b, uint256 i) external pure returns (uint8){ bytes memory t = b; return uint8(t[i]); }
  function bs_litLen() external pure returns (uint256){ bytes memory t = "literal payload exceeding thirty-two bytes for a length read!"; return t.length; }
  function bs_fromStorageLen() external view returns (uint256){ bytes memory t = st4.b; return t.length; }
  function seedStS(uint256 av, string calldata s_) external { st = VS(av, s_); }

  function dyn_mkVS(uint256 a, string calldata s_) external pure returns (VS memory){ VS memory d = VS(a, s_); return d; }
  function dyn_writeVal(uint256 a, string calldata s_, uint256 na) external pure returns (VS memory){ VS memory d = VS(a, s_); d.a = d.a + na; return d; }
  function dyn_writeStr(uint256 a, string calldata s_, string calldata ns) external pure returns (VS memory){ VS memory d = VS(a, s_); d.s = ns; return d; }
  function dyn_writeSVa(string calldata s_, uint256 a, uint256 na) external pure returns (SV memory){ SV memory d = SV(s_, a); d.a = na; return d; }
  function seedSt4(uint256 av, string calldata s_, bytes calldata b, uint64 n) external { st4 = D4(av, s_, b, n); }
  function dyn_fromSt4() external view returns (D4 memory){ D4 memory d = st4; return d; }
  function dyn_fromSt4Write(string calldata ns, bytes calldata nb, uint256 nv) external view returns (D4 memory){ D4 memory d = st4; d.s = ns; d.b = nb; d.a = nv; return d; }
  function dyn_fromCd(D4 calldata x) external pure returns (D4 memory){ D4 memory d = x; return d; }
  function dyn_fromDNcd(DN calldata x) external pure returns (DN memory){ DN memory d = x; return d; }
  function dyn_mkDN(uint8 x, int16 y, address z, bytes4 w, bool flag, string calldata s_) external pure returns (DN memory){ DN memory d = DN(x, y, z, w, flag, s_); return d; }
  function dyn_aliasCross(uint256 av, string calldata s_, string calldata ns, uint256 nv) external pure returns (VS memory){
    VS memory d = VS(av, s_); VS memory e = d; e.s = ns; e.a = nv; return d;
  }
  function dyn_aliasLen() external view returns (uint256){ D4 memory d = st4; D4 memory e = d; d.b = "ZZZ"; return e.b.length; }
  function dyn_bAt(bytes calldata b, uint256 i) external pure returns (uint8){ D4 memory d = D4(0, "", b, 0); return uint8(d.b[i]); }
  function dyn_mkPostNarrow(string calldata s_, uint8 a) external pure returns (SV2 memory){ SV2 memory d = SV2(s_, a); return d; }
  function dyn_fromCdPost(SV2 calldata x) external pure returns (SV2 memory){ SV2 memory d = x; return d; }
  function td_memField(uint128 a, uint128 b) external pure returns (Q memory){ Q memory p = Q(a, b); (p.x, p.y) = (p.y, p.x); return p; }
  function td_memFieldCall(uint256 a, uint256 b) external pure returns (Inner memory){ Inner memory p = Inner(0, 0); (p.a, p.b) = addsubI(a, b); return p; }
  function addsubI(uint256 a, uint256 b) internal pure returns (uint256, int64){ return (a + b, int64(uint64(a)) - int64(uint64(b))); }

  function addV(uint256 a, uint256 b) internal pure returns (uint256){ return a + b; }
  function callV(uint256 a, uint256 b) external pure returns (uint256){ return addV(a, b) * 2; }
  function bumpAcc(uint256 by) internal { acc = acc + by; }
  function doBump(uint256 x) external { bumpAcc(x); bumpAcc(x); }
  function getAcc() external view returns (uint256){ return acc; }
  function twP(P memory p) internal pure returns (P memory){ return P(p.a + 1, uint8(p.b + 1), int64(p.c - 1), p.d); }
  function callStructPR(uint256 a, uint8 b, int64 c, address d) external pure returns (P memory){ return twP(P(a, b, c, d)); }
  function climb(Q memory p, uint128 n) internal pure returns (Q memory){ if (n == 0) { return p; } return climb(Q(p.x + 1, p.y + 2), n - 1); }
  function climbE(uint128 a, uint128 b, uint128 n) external pure returns (Q memory){ return climb(Q(a, b), n); }
  function accDown(Q memory p, uint128 n) internal pure { if (n == 0) { return; } p.x = p.x + n; accDown(p, n - 1); }
  function accE(uint128 a, uint128 n) external pure returns (Q memory){ Q memory p = Q(a, 0); accDown(p, n); return p; }
  function d4f(uint256 x) internal pure returns (uint256){ return x * 8; }
  function c4f(uint256 x) internal pure returns (uint256){ return d4f(x) + 4; }
  function b4f(uint256 x) internal pure returns (uint256){ return c4f(x) + 2; }
  function chainE(uint256 x) external pure returns (uint256){ return b4f(x) + 1; }
  function priv(uint256 a) internal pure returns (uint256){ return a * 3; }
  function callPriv(uint256 a) external pure returns (uint256){ return priv(a) + 1; }

  function two() internal pure returns (uint256, uint256){ return (11, 22); }
  function addsub(uint256 a, uint256 b) internal pure returns (uint256, uint256){ return (a + b, a - b); }
  function td_decl() external pure returns (uint256){ (uint256 a, uint256 b) = two(); return a * 1000 + b; }
  function td_skip() external pure returns (uint256){ ( , uint256 b) = two(); return b; }
  function td_underflow(uint256 p, uint256 q_) external pure returns (uint256){ (uint256 s_, uint256 d) = addsub(p, q_); return s_ + d; }
  function td_assignLocal(uint256 p, uint256 q_) external pure returns (uint256){ uint256 a = 1; uint256 b = 2; (a, b) = addsub(p, q_); return a * 1000000 + b; }
  function td_swap(uint256 p, uint256 q_) external pure returns (uint256){ uint256 a = p; uint256 b = q_; (a, b) = (b, a); return a * 1000000 + b; }
  function td_storage(uint256 p, uint256 q_) external returns (uint256){ (acc, cnt) = addsub(p, q_); return acc * 1000000 + cnt; }
  function td_swapPacked(uint128 p, uint128 q_) external returns (uint256){ q.x = p; q.y = q_; (q.x, q.y) = (q.y, q.x); return uint256(q.x) * 1000000 + uint256(q.y); }
  function td_rhsFirst(uint256 p, uint256 q_) external returns (uint256){ acc = p; cnt = q_; (acc, cnt) = (cnt, acc + cnt); return acc * 1000000 + cnt; }
  function threeSide() internal returns (uint256, uint256, uint256){ cnt = cnt + 7; return (1, 2, 3); }
  function td_skipCall() external returns (uint256){ cnt = 0; (uint256 a, , uint256 c) = threeSide(); return a * 1000000 + c * 1000 + cnt; }
  function getCnt() external view returns (uint256){ return cnt; }
  function getQ() external view returns (Q memory){ return q; }
}`;

describe('ADVERSARIAL memory-locals vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  let divergence = 0, count = 0;
  const fails: string[] = [];

  async function eq(label: string, data: string, slots: bigint[] = []) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex) {
      divergence++;
      fails.push(`DIVERGENCE @ ${label}\n  data=${data}\n  jeth ok=${j.success} err=${j.exceptionError} ret=${j.returnHex}\n  sol  ok=${s.success} ret=${s.returnHex}`);
    }
    for (const sl of slots) {
      const js = await readSlot(jeth, aj, sl);
      const ss = await readSlot(sol, as, sl);
      if (js !== ss) { divergence++; fails.push(`SLOT DIVERGENCE @ ${label} slot ${sl}\n  jeth=${js}\n  sol =${ss}`); }
    }
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  // drive both then compare a view (for stateful sequences)
  async function drive(data: string) { await jeth.call(aj, data); await sol.call(as, data); }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  const I64MAX = (1n << 63n) - 1n, I64MIN = M - (1n << 63n);
  const U128MAX = (1n << 128n) - 1n;
  const ADDRMAX = (1n << 160n) - 1n;

  it('static struct memory locals: construct/read/write/alias/nested/refmut', async () => {
    const Pcases: [bigint, bigint, bigint, bigint][] = [
      [0n, 0n, 0n, 0n], [1n, 1n, 1n, 1n], [M - 1n, 255n, I64MAX, ADDRMAX],
      [12345n, 7n, I64MIN, 0xdeadbeefn], [M - 2n, 254n, M - 1n, 0xcafen],
    ];
    for (const [a, b, c, d] of Pcases) {
      await eq(`mkP`, encodeCall(sel('mkP(uint256,uint8,int64,address)'), [a, b, c, d]));
      await eq(`readWrite`, encodeCall(sel('readWrite(uint256,uint8,int64,address,uint256)'), [a, b, c, d, 1000n]));
      await eq(`callStructPR`, encodeCall(sel('callStructPR(uint256,uint8,int64,address)'), [a, b, c, d]));
    }
    const Qpairs: [bigint, bigint][] = [[0n, 0n], [1n, 2n], [U128MAX, 0n], [U128MAX, U128MAX], [5n, 7n]];
    for (const [a, b] of Qpairs) {
      await eq(`aliasMut`, encodeCall(sel('aliasMut(uint128,uint128,uint128)'), [a, b, 100n]));
      await eq(`refMut`, encodeCall(sel('refMut(uint128,uint128,uint128,uint128)'), [a, b, 9n, 8n]));
    }
    for (const nv of [0n, 1n, M - 1n, 1n << 200n]) {
      await eq(`nestedAlias`, encodeCall(sel('nestedAlias(uint256,uint256,int64,uint8,uint256)'), [42n, 7n, I64MAX, 9n, nv]));
    }
  });

  it('storage struct copy -> mutate local -> storage unchanged (raw slots)', async () => {
    // P layout: a=slot0, {b,c,d} packed in slot1.
    await drive(encodeCall(sel('setS(uint256,uint8,int64,address)'), [0xabcn, 200n, I64MIN, ADDRMAX]));
    await eq('copyMutS', encodeCall(sel('copyMutS(uint256)'), [777n]), [0n, 1n]);
    await eq('getS (slots unchanged)', encodeCall(sel('getS()'), []), [0n, 1n]);
  });

  it('fixed-array memory locals: r/w, OOB read/write Panic, alias, return, storage copy', async () => {
    for (const i of [0n, 1n, 2n]) await eq(`fa_build i=${i}`, encodeCall(sel('fa_build(uint256,uint256,uint256,uint256)'), [10n, 20n, 30n, i]));
    for (const i of [3n, 4n, M - 1n, 1n << 200n]) {
      await eq(`fa_oobR i=${i}`, encodeCall(sel('fa_oobR(uint256,uint256)'), [5n, i]));
      await eq(`fa_oobW i=${i}`, encodeCall(sel('fa_oobW(uint256,uint256)'), [5n, i]));
    }
    await eq('fa_alias', encodeCall(sel('fa_alias(uint256)'), [7n]));
    for (const [p, q] of [[0n, 0n], [M - 6n, 1n], [M - 1n, M - 1n]] as [bigint, bigint][]) await eq('fa_return', encodeCall(sel('fa_return(uint256,uint256)'), [p, q]));
    for (const [p, q] of [[0n, 0n], [100n, 200n], [255n, 255n], [206n, 100n]] as [bigint, bigint][]) await eq('fa_narrow', encodeCall(sel('fa_narrow(uint8,uint8)'), [p, q]));
    await drive(encodeCall(sel('setG3(uint256,uint256,uint256)'), [111n, 222n, 333n]));
    await eq('fa_fromStorage', encodeCall(sel('fa_fromStorage()'), []));
    await eq('fa_fromStorage again', encodeCall(sel('fa_fromStorage()'), []));
  });

  it('dynamic value-array memory locals: r/w, OOB read/write Panic, length', async () => {
    for (const i of [0n, 1n, 2n]) await eq(`dv_build i=${i}`, encodeCall(sel('dv_build(uint256,uint256,uint256,uint256)'), [1n, 2n, 3n, i]));
    for (const i of [2n, 5n, M - 1n]) {
      await eq(`dv_oobR i=${i}`, encodeCall(sel('dv_oobR(uint256,uint256)'), [9n, i]));
      await eq(`dv_oobW i=${i}`, encodeCall(sel('dv_oobW(uint256,uint256)'), [9n, i]));
    }
    await eq('dv_len', encodeCall(sel('dv_len(uint256,uint256,uint256)'), [1n, 2n, 3n]));
  });

  it('bytes/string memory locals: echo, length, byte index OOB, literal, storage', async () => {
    for (const s of STRS) await eq(`bs_echo ${s.length}`, cd_s1('bs_echo(string)', s));
    for (const b of BUFS) await eq(`bs_len ${b.length}`, cd_b1('bs_len(bytes)', b));
    for (const b of [bufOf(5), bufOf(32), bufOf(33), bufOf(64)]) {
      for (let i = 0n; i < BigInt(b.length); i++) await eq(`bs_at ${b.length}@${i}`, cd_b_u('bs_at(bytes,uint256)', b, i));
      await eq(`bs_at OOB ${b.length}`, cd_b_u('bs_at(bytes,uint256)', b, BigInt(b.length)));
      await eq(`bs_at OOB huge ${b.length}`, cd_b_u('bs_at(bytes,uint256)', b, M - 1n));
    }
    await eq('bs_at empty@0', cd_b_u('bs_at(bytes,uint256)', Buffer.alloc(0), 0n));
    await eq('bs_litLen', encodeCall(sel('bs_litLen()'), []));
    await drive(mk_seedSt4(7n, 'storstr', bufOf(40), 0x55n));
    await eq('bs_fromStorageLen', encodeCall(sel('bs_fromStorageLen()'), []));
  });

  it('dynamic-field struct memory locals: construct/read/write/alias, all lengths', async () => {
    for (const s of STRS) for (const a of [0n, 1n, M - 1n]) {
      await eq(`dyn_mkVS ${s.length}`, cd_v_s('dyn_mkVS(uint256,string)', a, s));
      await eq(`dyn_writeVal ${s.length}`, '0x' + sel('dyn_writeVal(uint256,string,uint256)') + pad(a) + pad(0x60n) + pad(99n) + encStr(s));
      await eq(`dyn_writeStr ${s.length}`, mk_v_s_s('dyn_writeStr(uint256,string,string)', a, s, 'replacement string value!'));
      await eq(`dyn_writeSVa ${s.length}`, '0x' + sel('dyn_writeSVa(string,uint256,uint256)') + pad(0x60n) + pad(a) + pad(7n) + encStr(s));
      await eq(`dyn_aliasCross ${s.length}`, mk_v_s_s_v('dyn_aliasCross(uint256,string,string,uint256)', a, s, 'aliased!', 0xbeefn));
    }
  });

  it('dyn-struct copy from storage struct: mutate local, storage slots unchanged', async () => {
    for (const s of [STRS[1], STRS[4], STRS[7]] as string[]) for (const b of [BUFS[0], BUFS[3], BUFS[8]] as Buffer[]) {
      await drive(mk_seedSt4(7n, s, b, 0x1234n));
      await eq(`dyn_fromSt4 ${s.length}/${b.length}`, encodeCall(sel('dyn_fromSt4()'), []));
      await eq(`dyn_fromSt4Write ${s.length}/${b.length}`, mk_st4write('dyn_fromSt4Write(string,bytes,uint256)', 'newstr', bufOf(40), 999n));
      await eq(`dyn_aliasLen ${s.length}/${b.length}`, encodeCall(sel('dyn_aliasLen()'), []));
    }
  });

  it('dyn-struct byte index in/out of bounds', async () => {
    for (const b of [bufOf(5), bufOf(32), bufOf(33)]) {
      for (let i = 0n; i < BigInt(b.length); i++) await eq(`dyn_bAt ${b.length}@${i}`, cd_b_u('dyn_bAt(bytes,uint256)', b, i));
      await eq(`dyn_bAt OOB ${b.length}`, cd_b_u('dyn_bAt(bytes,uint256)', b, BigInt(b.length)));
    }
  });

  it('dyn-struct copy from calldata: clean fields succeed, DIRTY fields revert identically', async () => {
    // clean D4 copies of every length
    for (const s of [STRS[0], STRS[3], STRS[5]] as string[]) for (const b of [BUFS[0], BUFS[4], BUFS[7]] as Buffer[]) {
      await eq(`dyn_fromCd ${s.length}/${b.length}`, mk_D4_cd('dyn_fromCd((uint256,string,bytes,uint64))', 42n, s, b, 0x99n));
    }
    // clean DN copies (narrow/signed/address/bytes4/bool)
    await eq('dyn_fromDNcd clean', mk_DN_cd('dyn_fromDNcd((uint8,int16,address,bytes4,bool,string))', 200n, -5n, 0xcafen, 0xaabbccddn << 224n, 1n, 'hi'));
    await eq('dyn_mkDN', mk_DN_flat('dyn_mkDN(uint8,int16,address,bytes4,bool,string)', 7n, 100n, 0xdeadn, 0xffffffffn << 224n, 0n, STRS[4] as string));
    // DIRTY: each value field has junk high bits -> solc validates on copy-to-memory -> revert.
    await eq('DN dirty u8', mk_DN_cd('dyn_fromDNcd((uint8,int16,address,bytes4,bool,string))', 256n, 0n, 0n, 0n, 0n, 'x'));
    await eq('DN dirty u8 max', mk_DN_cd('dyn_fromDNcd((uint8,int16,address,bytes4,bool,string))', M - 1n, 0n, 0n, 0n, 0n, 'x'));
    await eq('DN dirty i16', mk_DN_cd('dyn_fromDNcd((uint8,int16,address,bytes4,bool,string))', 0n, 32768n, 0n, 0n, 0n, 'x'));
    await eq('DN dirty i16 unext', mk_DN_cd('dyn_fromDNcd((uint8,int16,address,bytes4,bool,string))', 0n, 0xffffn, 0n, 0n, 0n, 'x'));
    await eq('DN dirty addr', mk_DN_cd('dyn_fromDNcd((uint8,int16,address,bytes4,bool,string))', 0n, 0n, 1n << 160n, 0n, 0n, 'x'));
    await eq('DN dirty bytes4', mk_DN_cd('dyn_fromDNcd((uint8,int16,address,bytes4,bool,string))', 0n, 0n, 0n, 0xffn, 0n, 'x'));
    await eq('DN dirty bool', mk_DN_cd('dyn_fromDNcd((uint8,int16,address,bytes4,bool,string))', 0n, 0n, 0n, 0n, 2n, 'x'));
    await eq('DN dirty bool big', mk_DN_cd('dyn_fromDNcd((uint8,int16,address,bytes4,bool,string))', 0n, 0n, 0n, 0n, M - 1n, 'x'));
    // narrow value field AFTER a dyn field, both flat-param and struct-copy forms.
    for (const s of [STRS[0], STRS[4], STRS[7]] as string[]) for (const a of [0n, 1n, 255n]) {
      await eq(`dyn_mkPostNarrow ${s.length}/${a}`, '0x' + sel('dyn_mkPostNarrow(string,uint8)') + pad(0x40n) + pad(a) + encStr(s));
      await eq(`dyn_fromCdPost ${s.length}/${a}`, mk_SV2_cd('dyn_fromCdPost((string,uint8))', s, a));
    }
    // dirty u8 in both forms -> revert parity (flat-param checks eagerly; struct copy lazily).
    await eq('postNarrow dirty flat', '0x' + sel('dyn_mkPostNarrow(string,uint8)') + pad(0x40n) + pad(256n) + encStr('z'));
    await eq('postNarrow dirty flat max', '0x' + sel('dyn_mkPostNarrow(string,uint8)') + pad(0x40n) + pad(M - 1n) + encStr('z'));
    await eq('fromCdPost dirty', mk_SV2_cd('dyn_fromCdPost((string,uint8))', 'z', 256n));
    await eq('fromCdPost dirty max', mk_SV2_cd('dyn_fromCdPost((string,uint8))', 'z', M - 1n));
  });

  it('tuple destructuring into MEMORY-STRUCT fields: swap + call result', async () => {
    for (const [a, b] of [[1n, 2n], [U128MAX, 0n], [0n, U128MAX], [5n, 5n]] as [bigint, bigint][]) {
      await eq(`td_memField`, encodeCall(sel('td_memField(uint128,uint128)'), [a, b]));
    }
    for (const [a, b] of [[10n, 3n], [3n, 10n], [0n, 0n], [(1n << 64n) - 1n, 0n]] as [bigint, bigint][]) {
      await eq(`td_memFieldCall`, encodeCall(sel('td_memFieldCall(uint256,uint256)'), [a, b]));
    }
  });

  it('dyn-struct calldata: malformed offsets / lengths -> revert parity', async () => {
    // D4 with the string offset pointing past calldatasize.
    const selr = sel('dyn_fromCd((uint256,string,bytes,uint64))');
    // valid baseline first for sanity
    await eq('D4 cd ok', mk_D4_cd('dyn_fromCd((uint256,string,bytes,uint64))', 1n, 'ab', bufOf(3), 5n));
    // craft a struct head with a corrupt inner string offset (huge), payloads present.
    // struct is dynamic so param head = [off=0x20]; struct tuple = [a][off_s][off_b][n]...
    const badOffStr = '0x' + selr + pad(0x20n) + pad(7n) + pad(1n << 64n) + pad(0xc0n) + pad(9n) + encStr('aa') + encBuf(bufOf(2));
    await eq('D4 cd str off 2^64', badOffStr);
    const badOffHigh = '0x' + selr + pad(0x20n) + pad(7n) + pad(1n << 255n) + pad(0xc0n) + pad(9n) + encStr('aa') + encBuf(bufOf(2));
    await eq('D4 cd str off 2^255', badOffHigh);
    // bytes length = 2^64 (Panic 0x41 region on decode-to-memory)
    const badLen = '0x' + selr + pad(0x20n) + pad(7n) + pad(0x80n) + pad(0xc0n) + pad(9n) + encStr('') + pad(1n << 64n) + pad(0n);
    await eq('D4 cd bytes len 2^64', badLen);
    // string length points past end (truncated tail)
    const truncTail = '0x' + selr + pad(0x20n) + pad(7n) + pad(0x80n) + pad(0xe0n) + pad(9n) + pad(100n) /* claims 100 bytes */ + pad(0n) + pad(0n) + encBuf(bufOf(2));
    await eq('D4 cd str len past end', truncTail);
  });

  it('internal/private calls: value/void/struct/recursion/transitive purity', async () => {
    for (const [a, b] of [[1n, 2n], [M - 1n, 0n], [M >> 1n, M >> 1n]] as [bigint, bigint][]) {
      await eq('callV', encodeCall(sel('callV(uint256,uint256)'), [a, b]));
    }
    for (const x of [0n, 1n, 100n, (M - 1n) / 8n + 1n /* d4 ovf */]) await eq('chainE', encodeCall(sel('chainE(uint256)'), [x]));
    for (const a of [0n, 1n, M - 1n, M / 3n]) await eq('callPriv', encodeCall(sel('callPriv(uint256)'), [a]));
    for (const n of [0n, 1n, 5n, 50n]) await eq(`climbE n=${n}`, encodeCall(sel('climbE(uint128,uint128,uint128)'), [10n, 20n, n]));
    for (const [a, n] of [[0n, 0n], [5n, 1n], [3n, 10n], [100n, 100n]] as [bigint, bigint][]) await eq(`accE`, encodeCall(sel('accE(uint128,uint128)'), [a, n]));
    // void with state: doBump accumulates acc (slot 8). Compare raw slot.
    await drive(encodeCall(sel('doBump(uint256)'), [5n]));
    await drive(encodeCall(sel('doBump(uint256)'), [11n]));
    await eq('getAcc', encodeCall(sel('getAcc()'), []), [8n]);
  });

  it('tuple destructuring: decl/skip/swap/assign/underflow', async () => {
    await eq('td_decl', encodeCall(sel('td_decl()'), []));
    await eq('td_skip', encodeCall(sel('td_skip()'), []));
    for (const [p, q] of [[10n, 3n], [3n, 10n], [0n, 0n], [M - 1n, M - 1n]] as [bigint, bigint][]) {
      await eq(`td_underflow`, encodeCall(sel('td_underflow(uint256,uint256)'), [p, q]));
      await eq(`td_assignLocal`, encodeCall(sel('td_assignLocal(uint256,uint256)'), [p, q]));
      await eq(`td_swap`, encodeCall(sel('td_swap(uint256,uint256)'), [p, q]));
    }
  });

  it('tuple destructuring to STORAGE targets: raw slots + RHS-before-LHS', async () => {
    // acc=slot8, cnt=slot7.
    for (const [p, q] of [[5n, 3n], [100n, 50n], [0n, 0n]] as [bigint, bigint][]) {
      await eq(`td_storage`, encodeCall(sel('td_storage(uint256,uint256)'), [p, q]), [7n, 8n]);
      await eq(`td_rhsFirst`, encodeCall(sel('td_rhsFirst(uint256,uint256)'), [p, q]), [7n, 8n]);
    }
    // packed swap (q.x,q.y in slot 1)
    for (const [p, q] of [[1n, 2n], [U128MAX, 0n], [0n, U128MAX]] as [bigint, bigint][]) {
      await eq(`td_swapPacked`, encodeCall(sel('td_swapPacked(uint128,uint128)'), [p, q]), [1n]);
    }
    await eq('td_skipCall', encodeCall(sel('td_skipCall()'), []), [7n]);
  });

  it('summary: zero divergence across all cases', () => {
    if (fails.length) for (const f of fails.slice(0, 30)) console.error(f);
    console.log(`[audit memory-locals] ${count} differential cases, ${divergence} divergences`);
    expect(divergence, fails.slice(0, 10).join('\n')).toBe(0);
    expect(count, 'at least 60 adversarial cases').toBeGreaterThanOrEqual(60);
  });
});

// ---- extra calldata builders (hoisted) --------------------------------------
// (uint256, string, string): head=[a][off1][off2], two tail blocks.
function mk_v_s_s(sig: string, a: bigint, s1: string, s2: string) {
  const off1 = 0x60;
  const off2 = off1 + wordsFor(Buffer.byteLength(s1, 'utf8'));
  return '0x' + sel(sig) + pad(a) + pad(BigInt(off1)) + pad(BigInt(off2)) + encStr(s1) + encStr(s2);
}
// overload for the 4-arg dyn_aliasCross (uint256,string,string,uint256): head=[a][off1][off2][nv]
function mk_v_s_s_v(sig: string, a: bigint, s1: string, s2: string, nv: bigint) {
  const off1 = 0x80;
  const off2 = off1 + wordsFor(Buffer.byteLength(s1, 'utf8'));
  return '0x' + sel(sig) + pad(a) + pad(BigInt(off1)) + pad(BigInt(off2)) + pad(nv) + encStr(s1) + encStr(s2);
}
// seedSt4(uint256 av, string s, bytes b, uint64 n): head=[av][off_s][off_b][n], two tails.
function mk_seedSt4(av: bigint, s: string, b: Buffer, n: bigint) {
  const offS = 0x80;
  const offB = offS + wordsFor(Buffer.byteLength(s, 'utf8'));
  return '0x' + sel('seedSt4(uint256,string,bytes,uint64)') + pad(av) + pad(BigInt(offS)) + pad(BigInt(offB)) + pad(n) + encStr(s) + encBuf(b);
}
// dyn_fromSt4Write(string ns, bytes nb, uint256 nv): head=[off_s][off_b][nv], two tails.
function mk_st4write(sig: string, ns: string, nb: Buffer, nv: bigint) {
  const offS = 0x60;
  const offB = offS + wordsFor(Buffer.byteLength(ns, 'utf8'));
  return '0x' + sel(sig) + pad(BigInt(offS)) + pad(BigInt(offB)) + pad(nv) + encStr(ns) + encBuf(nb);
}
// D4 calldata param: param head=[off=0x20]; struct tuple=[a][off_s][off_b][n], two tails.
function mk_D4_cd(sig: string, a: bigint, s: string, b: Buffer, n: bigint) {
  const tupleHead = 4 * 32; // a, off_s, off_b, n
  const offS = tupleHead;
  const offB = offS + wordsFor(Buffer.byteLength(s, 'utf8'));
  return '0x' + sel(sig) + pad(0x20n)
    + pad(a) + pad(BigInt(offS)) + pad(BigInt(offB)) + pad(n)
    + encStr(s) + encBuf(b);
}
// DN calldata param: param head=[off=0x20]; tuple=[x][y][z][w][flag][off_s], one tail.
function mk_DN_cd(sig: string, x: bigint, y: bigint, z: bigint, w: bigint, flag: bigint, s: string) {
  const tupleHead = 6 * 32;
  const offS = tupleHead;
  return '0x' + sel(sig) + pad(0x20n)
    + pad(x) + pad(y) + pad(z) + pad(w) + pad(flag) + pad(BigInt(offS))
    + encStr(s);
}
// six FLAT params (uint8,int16,address,bytes4,bool,string): [x][y][z][w][flag][off=0xc0] + tail.
function mk_DN_flat(sig: string, x: bigint, y: bigint, z: bigint, w: bigint, flag: bigint, s: string) {
  const offS = 6 * 32; // 0xc0, relative to start of args
  return '0x' + sel(sig)
    + pad(x) + pad(y) + pad(z) + pad(w) + pad(flag) + pad(BigInt(offS))
    + encStr(s);
}
// SV2 calldata param {string s; uint8 a}: param head=[off=0x20]; tuple=[off_s=0x40][a]; tail.
function mk_SV2_cd(sig: string, s: string, a: bigint) {
  return '0x' + sel(sig) + pad(0x20n) + pad(0x40n) + pad(a) + encStr(s);
}
