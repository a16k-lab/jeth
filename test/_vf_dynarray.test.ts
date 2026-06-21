// _vf_dynarray: adversarial differential test for dynamic arrays T[].
// push/pop/length/index OOB panic 0x32, pop-empty panic 0x31, nested T[][],
// bytes[]/string[], storage->storage whole copy, memory->storage shrink/grow tail
// clearing, array of dynamic structs, returning whole + nested arrays, overwrite
// longer-with-shorter and read back. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const MAX = M - 1n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

// Build calldata for a single dynamic array arg: selector + [0x20][len][elems...]
function encArr(sig: string, elems: bigint[]): string {
  return '0x' + sel(sig) + pad(0x20n) + pad(BigInt(elems.length)) + elems.map(pad).join('');
}
// Build calldata for (uintK, T[]) : head=[k][0x40], tail=[len][elems...]
function encKArr(sig: string, k: bigint, elems: bigint[]): string {
  return '0x' + sel(sig) + pad(k) + pad(0x40n) + pad(BigInt(elems.length)) + elems.map(pad).join('');
}
// Build calldata for one string/bytes value param at the start: selector + [0x20][len][data...]
function encStr(sig: string, s: string): string {
  const b = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(b.length / 32);
  let data = '';
  for (let i = 0; i < nwords; i++) data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)]).subarray(0, 32).toString('hex');
  return '0x' + sel(sig) + pad(0x20n) + pad(BigInt(b.length)) + data;
}
// Build calldata for (uint256 head, string) param: head=[i][0x40], tail=[len][data]
function encIStr(sig: string, i: bigint, s: string): string {
  const b = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(b.length / 32);
  let data = '';
  for (let w = 0; w < nwords; w++) data += Buffer.concat([b.subarray(w * 32, w * 32 + 32), Buffer.alloc(32)]).subarray(0, 32).toString('hex');
  return '0x' + sel(sig) + pad(i) + pad(0x40n) + pad(BigInt(b.length)) + data;
}

const JETH = `@struct class P { x: u128; y: u128; }
@struct class D { a: u256; s: string; }
@contract class C {
  @state u: u256[];
  @state u2: u256[];
  @state p8: u8[];
  @state i8a: i8[];
  @state ba: bool[];
  @state adr: address[];
  @state b16: bytes16[];
  @state pa: P[];
  @state pb: P[];
  @state dd: u256[][];
  @state ss: string[];
  @state sb: string[];
  @state by: bytes[];
  @state da: D[];
  @state db: D[];

  @external pushU(v: u256): void { this.u.push(v); }
  @external pushU2(v: u256): void { this.u2.push(v); }
  @external popU(): void { this.u.pop(); }
  @external setU(i: u256, v: u256): void { this.u[i] = v; }
  @external incU(i: u256, v: u256): void { this.u[i] += v; }
  @external @view getU(i: u256): u256 { return this.u[i]; }
  @external @view lenU(): u256 { return this.u.length; }
  @external @view allU(): u256[] { return this.u; }
  @external clearU(): void { this.u = this.u2; }
  @external copyUFromU2(): void { this.u = this.u2; }

  @external pushP8(v: u8): void { this.p8.push(v); }
  @external popP8(): void { this.p8.pop(); }
  @external @view getP8(i: u256): u8 { return this.p8[i]; }
  @external @view lenP8(): u256 { return this.p8.length; }
  @external @view allP8(): u8[] { return this.p8; }

  @external pushI8(v: i8): void { this.i8a.push(v); }
  @external popI8(): void { this.i8a.pop(); }
  @external @view getI8(i: u256): i8 { return this.i8a[i]; }
  @external @view allI8(): i8[] { return this.i8a; }

  @external pushBa(v: bool): void { this.ba.push(v); }
  @external popBa(): void { this.ba.pop(); }
  @external @view getBa(i: u256): bool { return this.ba[i]; }
  @external @view allBa(): bool[] { return this.ba; }

  @external pushAdr(v: address): void { this.adr.push(v); }
  @external popAdr(): void { this.adr.pop(); }
  @external @view getAdr(i: u256): address { return this.adr[i]; }
  @external @view allAdr(): address[] { return this.adr; }

  @external pushB16(v: bytes16): void { this.b16.push(v); }
  @external popB16(): void { this.b16.pop(); }
  @external @view getB16(i: u256): bytes16 { return this.b16[i]; }
  @external @view allB16(): bytes16[] { return this.b16; }

  @external pushPb(x: u128, y: u128): void { this.pb.push(P(x, y)); }
  @external popPa(): void { this.pa.pop(); }
  @external copyPaFromPb(): void { this.pa = this.pb; }
  @external @view getPaX(i: u256): u128 { return this.pa[i].x; }
  @external @view allPa(): P[] { return this.pa; }

  @external pushOuter(): void { this.dd.push(); }
  @external pushInner(i: u256, v: u256): void { this.dd[i].push(v); }
  @external popInner(i: u256): void { this.dd[i].pop(); }
  @external setInner(i: u256, j: u256, v: u256): void { this.dd[i][j] = v; }
  @external @view ddOuterLen(): u256 { return this.dd.length; }
  @external @view ddInnerLen(i: u256): u256 { return this.dd[i].length; }
  @external @view ddAt(i: u256, j: u256): u256 { return this.dd[i][j]; }
  @external @view allDD(): u256[][] { return this.dd; }

  @external pushSs(s: string): void { this.ss.push(s); }
  @external pushSb(s: string): void { this.sb.push(s); }
  @external popSs(): void { this.ss.pop(); }
  @external copySsFromSb(): void { this.ss = this.sb; }
  @external @view getSs(i: u256): string { return this.ss[i]; }
  @external @view lenSs(): u256 { return this.ss.length; }
  @external @view allSs(): string[] { return this.ss; }

  @external pushBy(b: bytes): void { this.by.push(b); }
  @external popBy(): void { this.by.pop(); }
  @external @view getBy(i: u256): bytes { return this.by[i]; }
  @external @view allBy(): bytes[] { return this.by; }

  @external pushDb(a: u256, s: string): void { this.db.push(D(a, s)); }
  @external popDa(): void { this.da.pop(); }
  @external copyDaFromDb(): void { this.da = this.db; }
  @external @view allDa(): D[] { return this.da; }

  @external @pure echoU(x: u256[]): u256[] { return x; }
  @external @pure sumU(x: u256[]): u256 {
    let s: u256 = 0n;
    for (let i: u256 = 0n; i < x.length; i += 1n) { s += x[i]; }
    return s;
  }
  @external @pure mkAndShrink(n: u256): u256[] {
    let xs: u256[] = [1n, 2n, 3n, 4n, 5n];
    return xs;
  }
  // memory -> storage assign with grow & shrink tail clear
  @external memToStore(a: u256, b: u256, c: u256): void {
    let xs: u256[] = [a, b, c];
    this.u = xs;
  }
  @external memToStore2(a: u256, b: u256): void {
    let xs: u256[] = [a, b];
    this.u = xs;
  }
  @external mixKLen(k: u256, x: u256[]): u256 { return k + x.length; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint128 x; uint128 y; }
  struct D { uint256 a; string s; }
  uint256[] u; uint256[] u2; uint8[] p8; int8[] i8a; bool[] ba; address[] adr; bytes16[] b16;
  P[] pa; P[] pb; uint256[][] dd; string[] ss; string[] sb; bytes[] by; D[] da; D[] db;

  function pushU(uint256 v) external { u.push(v); }
  function pushU2(uint256 v) external { u2.push(v); }
  function popU() external { u.pop(); }
  function setU(uint256 i, uint256 v) external { u[i] = v; }
  function incU(uint256 i, uint256 v) external { u[i] += v; }
  function getU(uint256 i) external view returns (uint256){ return u[i]; }
  function lenU() external view returns (uint256){ return u.length; }
  function allU() external view returns (uint256[] memory){ return u; }
  function clearU() external { u = u2; }
  function copyUFromU2() external { u = u2; }

  function pushP8(uint8 v) external { p8.push(v); }
  function popP8() external { p8.pop(); }
  function getP8(uint256 i) external view returns (uint8){ return p8[i]; }
  function lenP8() external view returns (uint256){ return p8.length; }
  function allP8() external view returns (uint8[] memory){ return p8; }

  function pushI8(int8 v) external { i8a.push(v); }
  function popI8() external { i8a.pop(); }
  function getI8(uint256 i) external view returns (int8){ return i8a[i]; }
  function allI8() external view returns (int8[] memory){ return i8a; }

  function pushBa(bool v) external { ba.push(v); }
  function popBa() external { ba.pop(); }
  function getBa(uint256 i) external view returns (bool){ return ba[i]; }
  function allBa() external view returns (bool[] memory){ return ba; }

  function pushAdr(address v) external { adr.push(v); }
  function popAdr() external { adr.pop(); }
  function getAdr(uint256 i) external view returns (address){ return adr[i]; }
  function allAdr() external view returns (address[] memory){ return adr; }

  function pushB16(bytes16 v) external { b16.push(v); }
  function popB16() external { b16.pop(); }
  function getB16(uint256 i) external view returns (bytes16){ return b16[i]; }
  function allB16() external view returns (bytes16[] memory){ return b16; }

  function pushPb(uint128 x, uint128 y) external { pb.push(P(x, y)); }
  function popPa() external { pa.pop(); }
  function copyPaFromPb() external { pa = pb; }
  function getPaX(uint256 i) external view returns (uint128){ return pa[i].x; }
  function allPa() external view returns (P[] memory){ return pa; }

  function pushOuter() external { dd.push(); }
  function pushInner(uint256 i, uint256 v) external { dd[i].push(v); }
  function popInner(uint256 i) external { dd[i].pop(); }
  function setInner(uint256 i, uint256 j, uint256 v) external { dd[i][j] = v; }
  function ddOuterLen() external view returns (uint256){ return dd.length; }
  function ddInnerLen(uint256 i) external view returns (uint256){ return dd[i].length; }
  function ddAt(uint256 i, uint256 j) external view returns (uint256){ return dd[i][j]; }
  function allDD() external view returns (uint256[][] memory){ return dd; }

  function pushSs(string calldata s) external { ss.push(s); }
  function pushSb(string calldata s) external { sb.push(s); }
  function popSs() external { ss.pop(); }
  function copySsFromSb() external { ss = sb; }
  function getSs(uint256 i) external view returns (string memory){ return ss[i]; }
  function lenSs() external view returns (uint256){ return ss.length; }
  function allSs() external view returns (string[] memory){ return ss; }

  function pushBy(bytes calldata b) external { by.push(b); }
  function popBy() external { by.pop(); }
  function getBy(uint256 i) external view returns (bytes memory){ return by[i]; }
  function allBy() external view returns (bytes[] memory){ return by; }

  function pushDb(uint256 a, string calldata s) external { db.push(D(a, s)); }
  function popDa() external { da.pop(); }
  function copyDaFromDb() external { da = db; }
  function allDa() external view returns (D[] memory){ return da; }

  function echoU(uint256[] calldata x) external pure returns (uint256[] memory){ return x; }
  function sumU(uint256[] calldata x) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<x.length;i+=1){ s+=x[i]; } return s; }
  function mkAndShrink(uint256 n) external pure returns (uint256[] memory){ uint256[] memory xs = new uint256[](5); xs[0]=1;xs[1]=2;xs[2]=3;xs[3]=4;xs[4]=5; return xs; }
  function memToStore(uint256 a, uint256 b, uint256 c) external { uint256[] memory xs = new uint256[](3); xs[0]=a;xs[1]=b;xs[2]=c; u = xs; }
  function memToStore2(uint256 a, uint256 b) external { uint256[] memory xs = new uint256[](2); xs[0]=a;xs[1]=b; u = xs; }
  function mixKLen(uint256 k, uint256[] calldata x) external pure returns (uint256){ return k + x.length; }
}`;

describe('_vf_dynarray probe', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(label + ': jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError + '} sol{ok=' + s.success + ',ret=' + s.returnHex + '}');
  }
  // send (state change) then implicitly compare success via eq on a follow-up read; but
  // also assert success parity here.
  async function send(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(label + '(send): jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError + '} sol{ok=' + s.success + ',ret=' + s.returnHex + '}');
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    const ADDR1 = BigInt('0x' + 'aa'.repeat(20));
    const ADDR2 = BigInt('0x' + 'bb'.repeat(20));
    const ADDRD = (1n << 256n) - 1n; // dirty high bits beyond 20 bytes -> solc masks to 20

    // ---- 1. u256[] whole-slot push/length/index/set/pop + OOB panics --------
    for (const v of [0n, 1n, MAX, M >> 1n, 0xdeadbeefn]) await send('pushU', encodeCall(sel('pushU(uint256)'), [v]));
    await eq('lenU=5', encodeCall(sel('lenU()')));
    for (let i = 0; i < 5; i++) await eq('getU[' + i + ']', encodeCall(sel('getU(uint256)'), [BigInt(i)]));
    await eq('getU OOB 5', encodeCall(sel('getU(uint256)'), [5n]));
    await eq('getU OOB max', encodeCall(sel('getU(uint256)'), [MAX]));
    await eq('setU OOB 5', encodeCall(sel('setU(uint256,uint256)'), [5n, 1n]));
    await eq('setU OOB max', encodeCall(sel('setU(uint256,uint256)'), [MAX, 1n]));
    await send('setU[2]', encodeCall(sel('setU(uint256,uint256)'), [2n, 0x4242n]));
    await eq('getU[2] after set', encodeCall(sel('getU(uint256)'), [2n]));
    await send('incU[1] += MAX (wrap check)', encodeCall(sel('incU(uint256,uint256)'), [1n, MAX]));
    await eq('getU[1] after inc wrap', encodeCall(sel('getU(uint256)'), [1n]));
    await eq('allU', encodeCall(sel('allU()')));

    // ---- 2. pop freed slot zeroing + pop-empty 0x31 --------
    await send('popU x1', encodeCall(sel('popU()')));
    await eq('lenU=4 after pop', encodeCall(sel('lenU()')));
    await eq('allU after pop', encodeCall(sel('allU()')));
    // push back, ensure freed slot was zeroed (re-push should not see stale)
    await send('pushU 0 (reuse freed slot)', encodeCall(sel('pushU(uint256)'), [0n]));
    await eq('getU[4] reused == 0', encodeCall(sel('getU(uint256)'), [4n]));
    // drain to empty then pop-empty
    for (let i = 0; i < 5; i++) await send('drain popU', encodeCall(sel('popU()')));
    await eq('lenU=0', encodeCall(sel('lenU()')));
    await eq('popU empty -> 0x31', encodeCall(sel('popU()')));
    await eq('getU[0] empty -> 0x32', encodeCall(sel('getU(uint256)'), [0n]));

    // ---- 3. overwrite longer with shorter via storage->storage copy + read back ----
    for (const v of [11n, 22n, 33n]) await send('u2 push', encodeCall(sel('pushU2(uint256)'), [v]));
    for (const v of [9n, 8n, 7n, 6n, 5n, 4n]) await send('u push (longer)', encodeCall(sel('pushU(uint256)'), [v]));
    await send('copy u=u2 (shrink 6->3)', encodeCall(sel('copyUFromU2()')));
    await eq('lenU=3 after shrink copy', encodeCall(sel('lenU()')));
    await eq('allU after shrink copy', encodeCall(sel('allU()')));
    // the freed tail slots [3],[4],[5] must read as cleared if we grow back
    for (const v of [100n, 200n, 300n] as bigint[]) await send('regrow u', encodeCall(sel('pushU(uint256)'), [v]));
    await eq('allU after regrow (tail must be 100,200,300 not stale)', encodeCall(sel('allU()')));
    await eq('getU[3] not stale', encodeCall(sel('getU(uint256)'), [3n]));
    await eq('getU[4] not stale', encodeCall(sel('getU(uint256)'), [4n]));
    await eq('getU[5] not stale', encodeCall(sel('getU(uint256)'), [5n]));

    // ---- 4. memory -> storage with grow then shrink (tail clearing) --------
    await send('memToStore 3 (grow)', encodeCall(sel('memToStore(uint256,uint256,uint256)'), [0x71n, 0x72n, 0x73n]));
    await eq('allU after memToStore3', encodeCall(sel('allU()')));
    // u currently length 6 -> set to length 3 above already; push to 5 then shrink to 2
    for (const v of [1n, 2n]) await send('grow u to 5', encodeCall(sel('pushU(uint256)'), [v]));
    await send('memToStore2 (shrink 5->2)', encodeCall(sel('memToStore2(uint256,uint256)'), [0xa1n, 0xa2n]));
    await eq('allU after memToStore2 shrink', encodeCall(sel('allU()')));
    for (const v of [0xb1n, 0xb2n, 0xb3n] as bigint[]) await send('regrow after mem shrink', encodeCall(sel('pushU(uint256)'), [v]));
    await eq('allU regrow after mem shrink (no stale)', encodeCall(sel('allU()')));

    // ---- 5. packed uint8[] (32/slot), partial-byte pop clearing --------
    for (let i = 1; i <= 40; i++) await send('pushP8', encodeCall(sel('pushP8(uint8)'), [BigInt(i)]));
    await eq('lenP8=40', encodeCall(sel('lenP8()')));
    await eq('getP8[31]', encodeCall(sel('getP8(uint256)'), [31n]));
    await eq('getP8[32]', encodeCall(sel('getP8(uint256)'), [32n]));
    await eq('getP8[39]', encodeCall(sel('getP8(uint256)'), [39n]));
    await eq('getP8 OOB 40', encodeCall(sel('getP8(uint256)'), [40n]));
    await eq('allP8', encodeCall(sel('allP8()')));
    // pop across a slot boundary (40 -> 32), the high slot must be cleared
    for (let i = 0; i < 8; i++) await send('popP8 to 32', encodeCall(sel('popP8()')));
    await eq('lenP8=32 after pops', encodeCall(sel('lenP8()')));
    await eq('allP8 after slot-boundary pops', encodeCall(sel('allP8()')));
    // grow back: new elements must not carry stale packed bytes
    for (let i = 100; i < 105; i++) await send('regrow P8', encodeCall(sel('pushP8(uint8)'), [BigInt(i)]));
    await eq('allP8 regrow no-stale', encodeCall(sel('allP8()')));
    await eq('getP8[32] regrown', encodeCall(sel('getP8(uint256)'), [32n]));

    // ---- 6. int8[] sign extension on read + return --------
    for (const v of [0n, 1n, 127n, 128n /*->-128 wrap? push as int8 expects -128 via 2^8-128*/, 255n /*->-1*/, 200n]) {
      // int8 ABI arg: value already masked by solc to low 8 bits then sign-extended
      await send('pushI8', encodeCall(sel('pushI8(int8)'), [v]));
    }
    await eq('allI8 (sign-ext)', encodeCall(sel('allI8()')));
    await eq('getI8[3] (-128?)', encodeCall(sel('getI8(uint256)'), [3n]));
    await eq('getI8[4] (-1?)', encodeCall(sel('getI8(uint256)'), [4n]));
    await eq('getI8 OOB', encodeCall(sel('getI8(uint256)'), [99n]));

    // ---- 7. bool[] packed --------
    for (const v of [1n, 0n, 1n, 1n, 0n]) await send('pushBa', encodeCall(sel('pushBa(bool)'), [v]));
    await eq('allBa', encodeCall(sel('allBa()')));
    await eq('getBa[2]', encodeCall(sel('getBa(uint256)'), [2n]));
    await eq('getBa OOB', encodeCall(sel('getBa(uint256)'), [5n]));
    // bool with dirty high bits in calldata (solc treats nonzero as true)
    await send('pushBa dirty 0xff', '0x' + sel('pushBa(bool)') + pad(0xffn));
    await send('pushBa dirty huge', '0x' + sel('pushBa(bool)') + pad(M - 1n));
    await eq('allBa dirty', encodeCall(sel('allBa()')));
    await send('popBa', encodeCall(sel('popBa()')));
    await eq('allBa after pop', encodeCall(sel('allBa()')));

    // ---- 8. address[] (unpacked) + dirty high bits --------
    for (const a of [ADDR1, ADDR2]) await send('pushAdr', encodeCall(sel('pushAdr(address)'), [a]));
    await send('pushAdr dirty', '0x' + sel('pushAdr(address)') + pad(ADDRD)); // dirty top bytes
    await eq('allAdr (dirty masked)', encodeCall(sel('allAdr()')));
    await eq('getAdr[2] masked', encodeCall(sel('getAdr(uint256)'), [2n]));
    await eq('getAdr OOB', encodeCall(sel('getAdr(uint256)'), [9n]));

    // ---- 9. bytes16[] (packed 2/slot) + dirty low bits --------
    for (const v of [0n, MAX, 1n << 255n, 0xabcdn]) await send('pushB16', encodeCall(sel('pushB16(bytes16)'), [v << 128n]));
    // bytes16 ABI is left-aligned; pass already shifted. Also pass a "dirty" low-half value:
    await send('pushB16 dirty low', '0x' + sel('pushB16(bytes16)') + pad(MAX)); // low 16 bytes nonzero -> solc masks
    await eq('allB16 (dirty masked)', encodeCall(sel('allB16()')));
    await eq('getB16[1]', encodeCall(sel('getB16(uint256)'), [1n]));
    await eq('getB16[4] masked', encodeCall(sel('getB16(uint256)'), [4n]));
    await eq('getB16 OOB', encodeCall(sel('getB16(uint256)'), [9n]));
    await send('popB16', encodeCall(sel('popB16()')));
    await eq('allB16 after pop (boundary clear)', encodeCall(sel('allB16()')));

    // ---- 10. static-struct array P[] copy + element field read --------
    for (const [x, y] of [[1n, 2n], [3n, 4n], [5n, 6n]] as [bigint, bigint][]) await send('pushPb', encodeCall(sel('pushPb(uint128,uint128)'), [x, y]));
    await send('copyPa=Pb', encodeCall(sel('copyPaFromPb()')));
    await eq('allPa after copy', encodeCall(sel('allPa()')));
    await eq('getPaX[1]', encodeCall(sel('getPaX(uint256)'), [1n]));
    await eq('getPaX OOB', encodeCall(sel('getPaX(uint256)'), [9n]));
    await send('popPa', encodeCall(sel('popPa()')));
    await eq('allPa after pop', encodeCall(sel('allPa()')));
    await eq('getPaX OOB after pop (==len)', encodeCall(sel('getPaX(uint256)'), [2n]));

    // ---- 11. nested u256[][] push/index/pop/return + OOB --------
    await send('pushOuter x3', encodeCall(sel('pushOuter()')));
    await send('pushOuter x3', encodeCall(sel('pushOuter()')));
    await send('pushOuter x3', encodeCall(sel('pushOuter()')));
    for (const [i, v] of [[0n, 11n], [0n, 12n], [0n, 13n], [1n, 21n], [2n, 31n], [2n, 32n]] as [bigint, bigint][])
      await send('pushInner', encodeCall(sel('pushInner(uint256,uint256)'), [i, v]));
    await eq('ddOuterLen=3', encodeCall(sel('ddOuterLen()')));
    await eq('ddInnerLen[0]=3', encodeCall(sel('ddInnerLen(uint256)'), [0n]));
    await eq('ddInnerLen[1]=1', encodeCall(sel('ddInnerLen(uint256)'), [1n]));
    await eq('ddAt[0][2]', encodeCall(sel('ddAt(uint256,uint256)'), [0n, 2n]));
    await eq('ddAt OOB inner', encodeCall(sel('ddAt(uint256,uint256)'), [1n, 5n]));
    await eq('ddAt OOB outer', encodeCall(sel('ddAt(uint256,uint256)'), [9n, 0n]));
    await eq('ddInnerLen OOB outer', encodeCall(sel('ddInnerLen(uint256)'), [9n]));
    await send('setInner[0][1]', encodeCall(sel('setInner(uint256,uint256,uint256)'), [0n, 1n, 0x999n]));
    await eq('ddAt[0][1] after set', encodeCall(sel('ddAt(uint256,uint256)'), [0n, 1n]));
    await eq('allDD', encodeCall(sel('allDD()')));
    await send('popInner[0]', encodeCall(sel('popInner(uint256)'), [0n]));
    await eq('allDD after popInner', encodeCall(sel('allDD()')));
    // grow inner back, ensure freed slot cleared
    await send('pushInner[0] regrow', encodeCall(sel('pushInner(uint256,uint256)'), [0n, 0n]));
    await eq('ddAt[0][2] regrown ==0 not stale', encodeCall(sel('ddAt(uint256,uint256)'), [0n, 2n]));
    await eq('allDD after regrow', encodeCall(sel('allDD()')));

    // ---- 12. string[] storage: push (short/long/exact32/empty), index, pop, copy, return ----
    const SHORT = 'hi';
    const EXACT32 = 'abcdefghijklmnopqrstuvwxyz012345'; // 32 bytes
    const LONG = 'a definitely-longer-than-thirty-two-byte string element for the copy test path!!';
    await send('pushSs short', encStr('pushSs(string)', SHORT));
    await send('pushSs long', encStr('pushSs(string)', LONG));
    await send('pushSs exact32', encStr('pushSs(string)', EXACT32));
    await send('pushSs empty', encStr('pushSs(string)', ''));
    await eq('lenSs=4', encodeCall(sel('lenSs()')));
    await eq('getSs[0] short', encodeCall(sel('getSs(uint256)'), [0n]));
    await eq('getSs[1] long', encodeCall(sel('getSs(uint256)'), [1n]));
    await eq('getSs[2] exact32', encodeCall(sel('getSs(uint256)'), [2n]));
    await eq('getSs[3] empty', encodeCall(sel('getSs(uint256)'), [3n]));
    await eq('getSs OOB', encodeCall(sel('getSs(uint256)'), [4n]));
    await eq('allSs', encodeCall(sel('allSs()')));
    // pop a LONG element (must clear its data slots), then re-push short into reused slot
    await send('popSs (was empty)', encodeCall(sel('popSs()')));
    await send('popSs (was exact32 -> clears 1 data slot)', encodeCall(sel('popSs()')));
    await send('popSs (was long -> clears multi data slots)', encodeCall(sel('popSs()')));
    await eq('lenSs=1 after 3 pops', encodeCall(sel('lenSs()')));
    await send('pushSs short again (reuse slots, no stale)', encStr('pushSs(string)', 'x'));
    await eq('getSs[1] reused no stale', encodeCall(sel('getSs(uint256)'), [1n]));
    await eq('allSs after pop+repush', encodeCall(sel('allSs()')));
    // copy string[] storage->storage (sb has different mix)
    await send('pushSb a', encStr('pushSb(string)', 'alpha'));
    await send('pushSb b', encStr('pushSb(string)', LONG));
    await send('copySs=Sb', encodeCall(sel('copySsFromSb()')));
    await eq('allSs after copy from Sb', encodeCall(sel('allSs()')));
    await eq('lenSs after copy', encodeCall(sel('lenSs()')));

    // ---- 13. bytes[] storage --------
    await send('pushBy short', encStr('pushBy(bytes)', 'ab'));
    await send('pushBy long', encStr('pushBy(bytes)', LONG));
    await send('pushBy empty', encStr('pushBy(bytes)', ''));
    await eq('getBy[1] long', encodeCall(sel('getBy(uint256)'), [1n]));
    await eq('getBy[2] empty', encodeCall(sel('getBy(uint256)'), [2n]));
    await eq('getBy OOB', encodeCall(sel('getBy(uint256)'), [3n]));
    await eq('allBy', encodeCall(sel('allBy()')));
    await send('popBy long', encodeCall(sel('popBy()')));
    await eq('allBy after pop', encodeCall(sel('allBy()')));

    // ---- 14. dynamic-struct array D[] (struct with string field) copy + return ----
    await send('pushDb 1', encIStr('pushDb(uint256,string)', 5n, 'hi'));
    await send('pushDb 2', encIStr('pushDb(uint256,string)', 6n, LONG));
    await send('pushDb 3 empty str', encIStr('pushDb(uint256,string)', 7n, ''));
    await send('copyDa=Db', encodeCall(sel('copyDaFromDb()')));
    await eq('allDa after copy', encodeCall(sel('allDa()')));
    await send('popDa', encodeCall(sel('popDa()')));
    await eq('allDa after pop', encodeCall(sel('allDa()')));

    // ---- 15. ABI echo/sum with adversarial calldata --------
    await eq('echoU [1,2,3]', encArr('echoU(uint256[])', [1n, 2n, 3n]));
    await eq('echoU []', encArr('echoU(uint256[])', []));
    await eq('echoU [max,0]', encArr('echoU(uint256[])', [MAX, 0n]));
    await eq('sumU [5,7,9]', encArr('sumU(uint256[])', [5n, 7n, 9n]));
    await eq('sumU [] ', encArr('sumU(uint256[])', []));
    await eq('sumU overflow [max,1]', encArr('sumU(uint256[])', [MAX, 1n])); // checked add -> panic 0x11
    await eq('mixKLen(100,[1,2])', encKArr('mixKLen(uint256,uint256[])', 100n, [1n, 2n]));
    await eq('mkAndShrink', encodeCall(sel('mkAndShrink(uint256)'), [0n]));

    // adversarial calldata: bad offset, huge length, truncated tail
    await eq('echoU offset past cd', '0x' + sel('echoU(uint256[])') + pad(0x1000n));
    await eq('echoU huge length', '0x' + sel('echoU(uint256[])') + pad(0x20n) + pad(1n << 200n) + pad(1n));
    await eq('echoU len5 tail truncated', '0x' + sel('echoU(uint256[])') + pad(0x20n) + pad(5n) + pad(1n));
    await eq('echoU offset odd 0x21', '0x' + sel('echoU(uint256[])') + pad(0x21n) + pad(1n) + pad(7n));
    await eq('echoU offset 0 (points at itself)', '0x' + sel('echoU(uint256[])') + pad(0n) + pad(1n));
    await eq('echoU len at 0x20 = 2^256-1', '0x' + sel('echoU(uint256[])') + pad(0x20n) + pad(MAX));
    // extra trailing bytes beyond declared array (solc ignores tail)
    await eq('echoU [1,2] with trailing junk', encArr('echoU(uint256[])', [1n, 2n]) + pad(0xdeadn));

    if (mism.length) { process.stderr.write('MISMATCHES ' + mism.length + '/' + count + '\n'); for (const m of mism.slice(0, 40)) process.stderr.write(m + '\n'); }
    else process.stderr.write('ALL ' + count + ' byte-identical\n');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
