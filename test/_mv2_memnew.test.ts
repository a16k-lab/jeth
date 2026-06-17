// MV2: adversarial differential hammer of the freshly-added MEMORY-aggregate and
// array-composition features against real solc (0.8.x, cancun, optimizer on). Compares
// returndata AND raw storage slots byte-for-byte. ONLY exercises SUPPORTED shapes
// (gated shapes = compile errors are deliberately excluded).
//
// Features hammered:
//  1. struct memory-local COPY from storage (this.s) / calldata param; packed/narrow/signed
//     fields (u8, i64, address, bytesN, i128 INT_MIN/MAX); mutate copy + prove storage independent.
//  2. WHOLE nested struct-field read: let q = p.inner aliases the parent; pass p.inner by ref.
//  3. bytes/string memory locals (calldata / literal / storage / alias source); return, .length
//     (via bytes), b[i] (Panic 0x32 OOB), short/exactly-32/long/empty.
//  4. FIXED-array memory locals: literal/alias/storage source; a[i] r/w, +=, ++, OOB panic,
//     whole return, copy-from-storage independence; N=2..5; T = u256/u8/i64/address/bytesN.
//  5. G6 composite ABI: return storage Arr<u256,2>[] and Arr<u256[],2>; echo calldata Arr<u256,2>[].
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const kc = (p: bigint) => BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(p)) as `0x${string}`))));
const encStr = (s: string) => { const h = Buffer.from(s, 'utf8').toString('hex'); return pad(BigInt(h.length / 2)) + h.padEnd(Math.ceil(h.length / 64) * 64, '0'); };
// left-aligned bytesN word (value v occupying the high `size` bytes)
const b4 = (v: bigint) => (v << (256n - 32n)) % M; // bytes4 word
const b8 = (v: bigint) => (v << (256n - 64n)) % M; // bytes8 word
const b32 = (v: bigint) => v % M;                  // bytes32 word
// flat static words
const call = (sig: string, words: bigint[]) => '0x' + sel(sig) + words.map(pad).join('');
// single bytes/string arg
const cd1 = (sig: string, s: string) => '0x' + sel(sig) + pad(0x20n) + encStr(s);
// (bytes, uint256): offset(0x40) + value + [len][data]
const cdBU = (sig: string, s: string, v: bigint) => '0x' + sel(sig) + pad(0x40n) + pad(v) + encStr(s);
// uint256[2][] calldata
const cdComposite = (sig: string, rows: bigint[][]) => '0x' + sel(sig) + pad(0x20n) + pad(BigInt(rows.length)) + rows.flat().map(pad).join('');

const I64MAX = (1n << 63n) - 1n;
const I64MIN = M - (1n << 63n);          // -2^63 as a u256 word
const I128MAX = (1n << 127n) - 1n;
const I128MIN = M - (1n << 127n);        // -2^127 as a u256 word

const JETH = `@struct class P { a: u256; b: u8; c: i64; d: address; e: bytes4; f: i128; }
@struct class Inner { a: u256; b: i64; }
@struct class Outer { tag: u256; inner: Inner; z: u8; }
@contract class C {
  @state s: P;
  @state st: string;
  @state g: Arr<u256, 3>;
  @state g5: Arr<i64, 5>;
  @state gb: Arr<bytes8, 4>;
  @state comp: Arr<u256, 2>[];        // uint256[2][]
  @state nest: Arr<u256[], 2>;        // uint256[][2]

  // ---- (1) struct copy from storage ----
  @external setS(a: u256, b: u8, c: i64, d: address, e: bytes4, f: i128): void {
    this.s.a = a; this.s.b = b; this.s.c = c; this.s.d = d; this.s.e = e; this.s.f = f;
  }
  // copy storage -> memory, mutate copy, return copy whole (storage must NOT change)
  @external copyMut(na: u256, nb: u8): P {
    let p: P = this.s;
    p.a = na; p.b = nb; p.f = ${'-'}1n;
    return p;
  }
  @external @view snap(): P { let p: P = this.s; return p; }
  // sum-style readback so a packed-transcode bug shows in the return value too
  @external @view packedSum(): u256 {
    let p: P = this.s;
    return p.a + u256(p.b) + u256(u64(p.c)) + u256(u128(p.f));
  }
  @view getSa(): u256 { return this.s.a; }
  @view getSb(): u8 { return this.s.b; }
  @view getSf(): i128 { return this.s.f; }
  // copy storage struct, push narrow/signed fields to extremes via mutation, return WHOLE
  // (a missing mask on the memory->ABI encode of b:u8 / c:i64 / e:bytes4 would surface here)
  @external @view copyExtreme(): P {
    let p: P = this.s;
    p.b = 255n; p.c = ${'-'}1n; p.e = bytes4(u32(0xFFFFFFFFn)); p.f = ${'-'}1n;
    return p;
  }
  // copy a CALLDATA struct param -> memory; mutate; return; (prove echo of unchanged param too)
  @external @pure fromParam(q: P, na: u256): P { let p: P = q; p.a = na; p.d = address(0x999n); p.e = bytes4(u32(0n)); return p; }

  // ---- (2) whole nested struct-field read + alias + pass-by-ref ----
  @external @pure getInner(t: u256, a: u256, b: i64): Inner {
    let p: Outer = Outer(t, Inner(a, b), 0n);
    return p.inner;
  }
  @external @pure aliasMut(a: u256, b: i64): Outer {
    let p: Outer = Outer(9n, Inner(a, b), 5n);
    let q: Inner = p.inner;
    q.a = q.a + 1000n; q.b = ${'-'}3n;
    return p;
  }
  @internal bump(i: Inner): void { i.a = i.a + 1n; i.b = i.b - 7n; }
  @external @pure passInner(a: u256, b: i64): Outer {
    let p: Outer = Outer(7n, Inner(a, b), 2n);
    this.bump(p.inner);
    return p;
  }

  // ---- (3) bytes/string memory locals ----
  @external setSt(x: string): void { this.st = x; }
  @external @pure echo(x: string): string { let s: string = x; return s; }
  @external @pure echoLit(): string { let s: string = "hello, this is a string literal that exceeds 32 bytes!!"; return s; }
  @view fromStorageStr(): string { let s: string = this.st; return s; }
  @external @pure blen(x: bytes): u256 { let b: bytes = x; return b.length; }
  @external @pure byteAt(x: bytes, i: u256): u8 { let b: bytes = x; return u8(b[i]); }
  @external @pure aliasLen(x: bytes): u256 { let s: bytes = x; let t: bytes = s; return t.length; }
  @external @pure litByteAt(i: u256): u8 { let b: bytes = "abcdefghijklmnopqrstuvwxyz0123456789"; return u8(b[i]); }

  // ---- (4) fixed-array memory locals ----
  @external @pure build(x: u256, y: u256, z: u256): Arr<u256, 3> {
    let a: Arr<u256, 3> = [x, y, z];
    a[0n] = a[0n] + 1n; a[1n]++; a[2n] += 10n;
    return a;
  }
  @external @pure oob(x: u256, i: u256): u256 { let a: Arr<u256, 3> = [x, x, x]; return a[i]; }
  @external @pure aliasArr(x: u256): Arr<u256, 3> { let a: Arr<u256, 3> = [x, x, x]; let b: Arr<u256, 3> = a; b[0n] = 99n; return a; }
  @external @pure two(p: u256, q: u256): Arr<u256, 2> { let a: Arr<u256, 2> = [p, q]; a[1n] += 5n; return a; }
  @external @pure five(p: i64, q: i64): Arr<i64, 5> { let a: Arr<i64, 5> = [p, q, ${'-'}1n, 0n, q]; a[2n]++; a[3n] -= 4n; return a; }
  @external @pure addrArr(p: address, q: address): Arr<address, 3> { let a: Arr<address, 3> = [p, q, address(0n)]; a[2n] = p; return a; }
  @external @pure bytesArr(p: bytes8, q: bytes8): Arr<bytes8, 4> { let a: Arr<bytes8, 4> = [p, q, p, q]; return a; }
  @external @pure narrowArr(p: u8, q: u8): Arr<u8, 4> { let a: Arr<u8, 4> = [p, q, 255n, 0n]; a[1n] = 200n; a[0n] += 50n; return a; }
  // copy from a storage fixed array -> mutate the COPY -> storage stays intact
  @view fromG(): Arr<u256, 3> { let a: Arr<u256, 3> = this.g; a[0n] = a[0n] + 1000n; a[2n]++; return a; }
  @view getG(i: u256): u256 { return this.g[i]; }
  @external setG(i: u256, v: u256): void { this.g[i] = v; }
  @view fromG5(): Arr<i64, 5> { let a: Arr<i64, 5> = this.g5; a[0n]++; return a; }
  @external setG5(i: u256, v: i64): void { this.g5[i] = v; }
  @view fromGb(): Arr<bytes8, 4> { let a: Arr<bytes8, 4> = this.gb; return a; }
  @external setGb(i: u256, v: bytes8): void { this.gb[i] = v; }

  // ---- (5) G6 composite ABI ----
  @external pushComp(): void { this.comp.push(); }
  @external popComp(): void { this.comp.pop(); }
  @external setComp(i: u256, j: u256, v: u256): void { this.comp[i][j] = v; }
  @view allComp(): Arr<u256, 2>[] { return this.comp; }
  @external @pure echoComp(x: Arr<u256, 2>[]): Arr<u256, 2>[] { return x; }
  @external pushNest(i: u256, v: u256): void { this.nest[i].push(v); }
  @external setNest(i: u256, j: u256, v: u256): void { this.nest[i][j] = v; }
  @external popNest(i: u256): void { this.nest[i].pop(); }
  @view getNest(i: u256, j: u256): u256 { return this.nest[i][j]; }
  @view lenNest(i: u256): u256 { return this.nest[i].length; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; int64 c; address d; bytes4 e; int128 f; }
  struct Inner { uint256 a; int64 b; }
  struct Outer { uint256 tag; Inner inner; uint8 z; }
  P s;
  string st;
  uint256[3] g;
  int64[5] g5;
  bytes8[4] gb;
  uint256[2][] comp;
  uint256[][2] nest;

  function setS(uint256 a, uint8 b, int64 c, address d, bytes4 e, int128 f) external {
    s.a = a; s.b = b; s.c = c; s.d = d; s.e = e; s.f = f;
  }
  function copyMut(uint256 na, uint8 nb) external returns (P memory) {
    P memory p = s;
    p.a = na; p.b = nb; p.f = -1;
    return p;
  }
  function snap() external view returns (P memory) { P memory p = s; return p; }
  function packedSum() external view returns (uint256) {
    P memory p = s;
    return p.a + uint256(p.b) + uint256(uint64(p.c)) + uint256(uint128(p.f));
  }
  function getSa() external view returns (uint256) { return s.a; }
  function getSb() external view returns (uint8) { return s.b; }
  function getSf() external view returns (int128) { return s.f; }
  function copyExtreme() external view returns (P memory) {
    P memory p = s;
    p.b = 255; p.c = -1; p.e = bytes4(uint32(0xFFFFFFFF)); p.f = -1;
    return p;
  }
  function fromParam(P calldata q, uint256 na) external pure returns (P memory) { P memory p = q; p.a = na; p.d = address(0x999); p.e = bytes4(0); return p; }

  function getInner(uint256 t, uint256 a, int64 b) external pure returns (Inner memory) {
    Outer memory p = Outer(t, Inner(a, b), 0);
    return p.inner;
  }
  function aliasMut(uint256 a, int64 b) external pure returns (Outer memory) {
    Outer memory p = Outer(9, Inner(a, b), 5);
    Inner memory q = p.inner;
    q.a = q.a + 1000; q.b = -3;
    return p;
  }
  function bump(Inner memory i) internal pure { i.a = i.a + 1; i.b = i.b - 7; }
  function passInner(uint256 a, int64 b) external pure returns (Outer memory) {
    Outer memory p = Outer(7, Inner(a, b), 2);
    bump(p.inner);
    return p;
  }

  function setSt(string calldata x) external { st = x; }
  function echo(string calldata x) external pure returns (string memory) { string memory s2 = x; return s2; }
  function echoLit() external pure returns (string memory) { string memory s2 = "hello, this is a string literal that exceeds 32 bytes!!"; return s2; }
  function fromStorageStr() external view returns (string memory) { string memory s2 = st; return s2; }
  function blen(bytes calldata x) external pure returns (uint256) { bytes memory b = x; return b.length; }
  function byteAt(bytes calldata x, uint256 i) external pure returns (uint8) { bytes memory b = x; return uint8(b[i]); }
  function aliasLen(bytes calldata x) external pure returns (uint256) { bytes memory s2 = x; bytes memory t = s2; return t.length; }
  function litByteAt(uint256 i) external pure returns (uint8) { bytes memory b = "abcdefghijklmnopqrstuvwxyz0123456789"; return uint8(b[i]); }

  function build(uint256 x, uint256 y, uint256 z) external pure returns (uint256[3] memory) {
    uint256[3] memory a = [x, y, z];
    a[0] = a[0] + 1; a[1]++; a[2] += 10;
    return a;
  }
  function oob(uint256 x, uint256 i) external pure returns (uint256) { uint256[3] memory a = [x, x, x]; return a[i]; }
  function aliasArr(uint256 x) external pure returns (uint256[3] memory) { uint256[3] memory a = [x, x, x]; uint256[3] memory b = a; b[0] = 99; return a; }
  function two(uint256 p, uint256 q) external pure returns (uint256[2] memory) { uint256[2] memory a = [p, q]; a[1] += 5; return a; }
  function five(int64 p, int64 q) external pure returns (int64[5] memory) { int64[5] memory a = [p, q, -1, int64(0), q]; a[2]++; a[3] -= 4; return a; }
  function addrArr(address p, address q) external pure returns (address[3] memory) { address[3] memory a = [p, q, address(0)]; a[2] = p; return a; }
  function bytesArr(bytes8 p, bytes8 q) external pure returns (bytes8[4] memory) { bytes8[4] memory a = [p, q, p, q]; return a; }
  function narrowArr(uint8 p, uint8 q) external pure returns (uint8[4] memory) { uint8[4] memory a = [p, q, 255, 0]; a[1] = 200; a[0] += 50; return a; }
  function fromG() external view returns (uint256[3] memory) { uint256[3] memory a = g; a[0] = a[0] + 1000; a[2]++; return a; }
  function getG(uint256 i) external view returns (uint256) { return g[i]; }
  function setG(uint256 i, uint256 v) external { g[i] = v; }
  function fromG5() external view returns (int64[5] memory) { int64[5] memory a = g5; a[0]++; return a; }
  function setG5(uint256 i, int64 v) external { g5[i] = v; }
  function fromGb() external view returns (bytes8[4] memory) { bytes8[4] memory a = gb; return a; }
  function setGb(uint256 i, bytes8 v) external { gb[i] = v; }

  function pushComp() external { comp.push(); }
  function popComp() external { comp.pop(); }
  function setComp(uint256 i, uint256 j, uint256 v) external { comp[i][j] = v; }
  function allComp() external view returns (uint256[2][] memory) { return comp; }
  function echoComp(uint256[2][] calldata x) external pure returns (uint256[2][] memory) { return x; }
  function pushNest(uint256 i, uint256 v) external { nest[i].push(v); }
  function setNest(uint256 i, uint256 j, uint256 v) external { nest[i][j] = v; }
  function popNest(uint256 i) external { nest[i].pop(); }
  function getNest(uint256 i, uint256 j) external view returns (uint256) { return nest[i][j]; }
  function lenNest(uint256 i) external view returns (uint256) { return nest[i].length; }
}`;

describe('memnew adversarial (mv2)', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function send(d: string) { await jeth.call(aj, d); await sol.call(as, d); }
  async function eqRet(label: string, d: string) {
    count++;
    const j = await jeth.call(aj, d), s = await sol.call(as, d);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push('RET ' + label + ' jeth{' + j.success + ',' + j.returnHex + ',err=' + j.exceptionError + '} sol{' + s.success + ',' + s.returnHex + '}');
  }
  async function eqSlot(slot: bigint, label: string) {
    count++;
    const a = await readSlot(jeth, aj, slot), b = await readSlot(sol, as, slot);
    if (a !== b) mism.push('SLOT ' + label + ' @' + slot.toString(16) + ' jeth=' + a + ' sol=' + b);
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    // ===== (1) struct copy from storage + calldata =====
    const Pcases: [bigint, bigint, bigint, bigint, bigint, bigint][] = [
      [100n, 5n, 9n, 0x1234n, b4(0xCAFEBABEn), 77n],
      [M - 1n, 255n, I64MAX, 0xbeefn, b4(0xFFFFFFFFn), I128MAX],
      [0n, 0n, I64MIN, 0n, b4(0n), I128MIN],
      [42n, 200n, -1n + M, 0xABCDn, b4(0x00112233n), -1n + M],
    ];
    for (const [a, b, c, d, e, f] of Pcases) {
      await send(call('setS(uint256,uint8,int64,address,bytes4,int128)', [a, b, c, d, e, f]));
      await eqRet('snap', call('snap()', []));
      await eqRet('packedSum', call('packedSum()', []));
      await eqRet('copyMut', call('copyMut(uint256,uint8)', [9n, 3n]));
      await eqRet('copyExtreme', call('copyExtreme()', []));
      // storage independence after copyMut mutated its memory copy
      await eqRet('getSa', call('getSa()', []));
      await eqRet('getSb', call('getSb()', []));
      await eqRet('getSf', call('getSf()', []));
      // raw storage slots (solc layout: a@0; b/c/d packed @1; e/f packed @2)
      await eqSlot(0n, 's.a');
      await eqSlot(1n, 's packed b/c/d');
      await eqSlot(2n, 's packed e/f');
    }
    // calldata struct param copy: P static = 6 inline words; then na
    for (const [a, b, c, d, e, f] of Pcases)
      await eqRet('fromParam', call('fromParam((uint256,uint8,int64,address,bytes4,int128),uint256)', [a, b, c, d, e, f, 123n]));

    // ===== (2) nested struct field read =====
    const NIcases: [bigint, bigint][] = [[1n, 2n], [0n, -1n + M], [M - 1n, I64MAX], [42n, I64MIN]];
    for (const [a, b] of NIcases) {
      await eqRet('getInner', call('getInner(uint256,uint256,int64)', [9n, a, b]));
      await eqRet('aliasMut', call('aliasMut(uint256,int64)', [a, b]));
      await eqRet('passInner', call('passInner(uint256,int64)', [a, b]));
    }

    // ===== (3) bytes/string memory locals =====
    const STRS = ['', 'a', 'abc', 'abcdefghijklmnopqrstuvwxyz012345', 'abcdefghijklmnopqrstuvwxyz0123456', 'this string is definitely longer than thirty-two bytes for fuzz testing'];
    await eqRet('echoLit', call('echoLit()', []));
    for (const sx of STRS) {
      await eqRet('echo "' + sx.slice(0, 6) + '"', cd1('echo(string)', sx));
      await eqRet('blen "' + sx.slice(0, 6) + '"', cd1('blen(bytes)', sx));
      await eqRet('aliasLen "' + sx.slice(0, 6) + '"', cd1('aliasLen(bytes)', sx));
      await send(cd1('setSt(string)', sx));
      await eqRet('fromStorageStr', call('fromStorageStr()', []));
      // storage string raw slots: slot for st. short string -> slot 1 (after s spans 0..2). Layout differs; check via return only.
    }
    // byteAt over "abcde" + OOB (Panic 0x32)
    for (let i = 0n; i < 7n; i++) await eqRet('byteAt(' + i + ')', cdBU('byteAt(bytes,uint256)', 'abcde', i));
    // literal byte index incl OOB
    for (const i of [0n, 10n, 35n, 36n, 100n]) await eqRet('litByteAt(' + i + ')', call('litByteAt(uint256)', [i]));

    // ===== (4) fixed-array memory locals =====
    for (const [x, y, z] of [[1n, 2n, 3n], [0n, 0n, 0n], [M - 1n, M - 2n, 5n]] as [bigint, bigint, bigint][]) {
      await eqRet('build', call('build(uint256,uint256,uint256)', [x, y, z]));
      await eqRet('aliasArr', call('aliasArr(uint256)', [x]));
      await eqRet('two', call('two(uint256,uint256)', [x, y]));
    }
    for (const i of [0n, 2n, 3n, 100n, M - 1n]) await eqRet('oob(' + i + ')', call('oob(uint256,uint256)', [42n, i]));
    for (const [p, q] of [[1n, -1n + M], [I64MAX, I64MIN], [0n, 7n]] as [bigint, bigint][])
      await eqRet('five', call('five(int64,int64)', [p, q]));
    await eqRet('addrArr', call('addrArr(address,address)', [0xAAAAn, 0xBBBBn]));
    await eqRet('bytesArr', call('bytesArr(bytes8,bytes8)', [b8(0x1122334455667788n), b8(0xFFEEDDCCBBAA9988n)]));
    for (const [p, q] of [[7n, 9n], [255n, 0n], [200n, 100n]] as [bigint, bigint][])
      await eqRet('narrowArr(' + p + ',' + q + ')', call('narrowArr(uint8,uint8)', [p, q]));
    // copy-from-storage independence + raw slots
    for (const [i, v] of [[0n, 10n], [1n, 20n], [2n, 30n]] as [bigint, bigint][]) await send(call('setG(uint256,uint256)', [i, v]));
    await eqRet('fromG', call('fromG()', []));
    for (const i of [0n, 1n, 2n]) await eqRet('getG(' + i + ')', call('getG(uint256)', [i]));
    await eqSlot(4n, 'g[0]'); await eqSlot(5n, 'g[1]'); await eqSlot(6n, 'g[2]');
    for (const [i, v] of [[0n, 7n], [2n, -1n + M], [4n, I64MIN]] as [bigint, bigint][]) await send(call('setG5(uint256,int64)', [i, v]));
    await eqRet('fromG5', call('fromG5()', []));
    // g5: int64[5] packed across slots 7,8 (4 per slot + 1). Negative entries must NOT bleed.
    await eqSlot(7n, 'g5[0..3] packed'); await eqSlot(8n, 'g5[4] packed');
    for (const [i, v] of [[0n, b8(0x1111111111111111n)], [3n, b8(0x2222222222222222n)]] as [bigint, bigint][]) await send(call('setGb(uint256,bytes8)', [i, v]));
    await eqRet('fromGb', call('fromGb()', []));
    await eqSlot(9n, 'gb[0..3] packed bytes8'); // 4*8 = 32 bytes, exactly one slot

    // ===== (5) G6 composite ABI =====
    for (let i = 0; i < 3; i++) await send(call('pushComp()', []));
    for (const [i, j, v] of [[0n, 0n, 1n], [0n, 1n, 2n], [1n, 0n, 3n], [2n, 1n, 9n]] as [bigint, bigint, bigint][])
      await send(call('setComp(uint256,uint256,uint256)', [i, j, v]));
    await eqRet('allComp', call('allComp()', []));
    await eqSlot(10n, 'comp.length');
    await eqSlot(kc(10n) + 0n, 'comp[0][0]'); await eqSlot(kc(10n) + 1n, 'comp[0][1]');
    await eqSlot(kc(10n) + 2n, 'comp[1][0]'); await eqSlot(kc(10n) + 5n, 'comp[2][1]');
    // pop the LAST element (frees keccak(10)+4,+5), push back (re-zeroed)
    await send(call('setComp(uint256,uint256,uint256)', [2n, 0n, 0xAAAAn]));
    await send(call('setComp(uint256,uint256,uint256)', [2n, 1n, 0xBBBBn]));
    await send(call('popComp()', []));
    await send(call('pushComp()', []));
    await eqRet('getComp(2,0) after pop+push', call('allComp()', []));
    await eqSlot(kc(10n) + 4n, 'freed comp[2][0] cleared'); await eqSlot(kc(10n) + 5n, 'freed comp[2][1] cleared');
    // echo calldata uint256[2][]
    await eqRet('echoComp []', cdComposite('echoComp(uint256[2][])', []));
    await eqRet('echoComp [[1,2]]', cdComposite('echoComp(uint256[2][])', [[1n, 2n]]));
    await eqRet('echoComp 3rows', cdComposite('echoComp(uint256[2][])', [[1n, 2n], [3n, 4n], [M - 1n, 0n]]));
    // nest: uint256[][2] @ slots 11,12 (each an inner dyn-array length slot)
    for (const v of [11n, 12n, 13n]) await send(call('pushNest(uint256,uint256)', [0n, v]));
    for (const v of [21n, 22n]) await send(call('pushNest(uint256,uint256)', [1n, v]));
    await send(call('setNest(uint256,uint256,uint256)', [0n, 1n, 99n]));
    await eqRet('lenNest(0)', call('lenNest(uint256)', [0n]));
    await eqRet('lenNest(1)', call('lenNest(uint256)', [1n]));
    await eqRet('getNest(0,1)', call('getNest(uint256,uint256)', [0n, 1n]));
    await eqRet('getNest(1,1)', call('getNest(uint256,uint256)', [1n, 1n]));
    await eqSlot(11n, 'nest[0].length'); await eqSlot(12n, 'nest[1].length');
    await eqSlot(kc(11n) + 2n, 'nest[0][2]'); await eqSlot(kc(12n) + 0n, 'nest[1][0]');
    // pop inner of nest[0] -> frees its last data slot
    await send(call('popNest(uint256)', [0n]));
    await eqRet('lenNest(0) after pop', call('lenNest(uint256)', [0n]));
    await eqSlot(kc(11n) + 2n, 'nest[0][2] freed cleared');

    if (mism.length) { console.log('MISMATCHES ' + mism.length + '/' + count); for (const m of mism.slice(0, 40)) console.log(m); }
    else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
