// Storage / mapping-valued DYNAMIC STRUCTS (a @struct with a bytes/string field),
// byte-identical to Solidity incl. raw storage slots. A dynamic struct occupies
// contiguous slots; each static field uses normal packed storage and each
// bytes/string field at base+fieldSlot is a normal storage bytes/string (short <32
// inline / long >=32 with keccak(headerSlot) data slots, overwrite-clearing on
// re-assign and full-clear on pop). Covers:
//  - bare struct d: this.d.a/.s read+write, whole-struct assign this.d = D(a,s)
//  - D[] recs: push(D(a,s)) / push() / pop() / .length / this.recs[i].a/.s read+write
//  - mapping<address,D>: this.m[k].a/.s read+write, per-key isolation
//  - E{uint64 id; bytes b; uint64 x}: a bytes field, .length, byte index, packing
//  - nested Outer{x; D inner; y}: this.o.inner.a/.s, this.o.x/.y
//  - sentinel non-disturbance, OOB Panic(0x32), pop-empty Panic(0x31)
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const enc = new TextEncoder();
const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const sel = (s: string) => functionSelector(s);
const A1 = BigInt('0x' + '11'.repeat(20));
const A2 = BigInt('0x' + '22'.repeat(20));

const slotKeccak = (p: bigint) => BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(p)) as `0x${string}`))));
const mapSlot = (key: bigint, slot: bigint) =>
  BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(key) + pad(slot)) as `0x${string}`))));

// the right-padded payload words for a dynamic bytes/string arg (no length word).
function payload(bytes: Uint8Array): string {
  const words = Math.ceil(bytes.length / 32);
  let data = '';
  for (let i = 0; i < words * 32; i++) data += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return data;
}
// selector + static head words + [offset word to the sole dyn arg] + [len][payload].
function callDyn(selSig: string, staticHead: bigint[], bytes: Uint8Array): string {
  const headWords = staticHead.length + 1;
  let h = '0x' + sel(selSig);
  for (const w of staticHead) h += pad(w);
  h += pad(BigInt(headWords * 32));
  h += pad(BigInt(bytes.length)) + payload(bytes);
  return h;
}
const s = (str: string) => enc.encode(str);

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract StorageDynStruct {
  struct D { uint256 a; string s; }
  struct E { uint64 id; bytes b; uint64 x; }
  struct Outer { uint256 x; D inner; uint256 y; }
  D d;                                  // slot 0..1
  uint256 sentinel;                     // slot 2
  D[] recs;                             // slot 3
  mapping(address => D) byKey;          // slot 4
  E e;                                  // slot 5..7
  Outer o;                              // slot 8..11
  mapping(address => D[]) byKeyArr;     // slot 12
  function setDa(uint256 v) external { d.a = v; }
  function setDs(string calldata v) external { d.s = v; }
  function setD(uint256 a, string calldata ss) external { d = D(a, ss); }
  function getDa() external view returns (uint256){ return d.a; }
  function getDs() external view returns (string memory){ return d.s; }
  function pushRec(uint256 a, string calldata ss) external { recs.push(D(a, ss)); }
  function pushEmptyRec() external { recs.push(); }
  function popRec() external { recs.pop(); }
  function setRecA(uint256 i, uint256 v) external { recs[i].a = v; }
  function setRecS(uint256 i, string calldata v) external { recs[i].s = v; }
  function recsLen() external view returns (uint256){ return recs.length; }
  function recAt(uint256 i) external view returns (string memory){ return recs[i].s; }
  function recAtA(uint256 i) external view returns (uint256){ return recs[i].a; }
  function setKa(address k, uint256 v) external { byKey[k].a = v; }
  function setKs(address k, string calldata v) external { byKey[k].s = v; }
  function getKa(address k) external view returns (uint256){ return byKey[k].a; }
  function getKs(address k) external view returns (string memory){ return byKey[k].s; }
  function setEid(uint64 v) external { e.id = v; }
  function setEb(bytes calldata v) external { e.b = v; }
  function setEx(uint64 v) external { e.x = v; }
  function getEid() external view returns (uint64){ return e.id; }
  function getEb() external view returns (bytes memory){ return e.b; }
  function getEx() external view returns (uint64){ return e.x; }
  function ebLen() external view returns (uint256){ return e.b.length; }
  function ebByte(uint256 j) external view returns (bytes1){ return e.b[j]; }
  function setOx(uint256 v) external { o.x = v; }
  function setOy(uint256 v) external { o.y = v; }
  function setOInnerA(uint256 v) external { o.inner.a = v; }
  function setOInnerS(string calldata v) external { o.inner.s = v; }
  function getOx() external view returns (uint256){ return o.x; }
  function getOy() external view returns (uint256){ return o.y; }
  function getOInnerA() external view returns (uint256){ return o.inner.a; }
  function getOInnerS() external view returns (string memory){ return o.inner.s; }
  function pushKA(address k, uint256 a, string calldata ss) external { byKeyArr[k].push(D(a, ss)); }
  function popKA(address k) external { byKeyArr[k].pop(); }
  function kaLen(address k) external view returns (uint256){ return byKeyArr[k].length; }
  function setKAs(address k, uint256 i, string calldata v) external { byKeyArr[k][i].s = v; }
  function kaAtA(address k, uint256 i) external view returns (uint256){ return byKeyArr[k][i].a; }
  function kaAt(address k, uint256 i) external view returns (string memory){ return byKeyArr[k][i].s; }
  function setSentinel(uint256 c) external { sentinel = c; }
  function getSentinel() external view returns (uint256){ return sentinel; }
}`;

describe('storage / mapping-valued dynamic structs vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const sr = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(sr.success);
    expect(j.returnHex, `${label} returndata`).toBe(sr.returnHex);
    return { j, s: sr };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'StorageDynStruct.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'StorageDynStruct.jeth' });
    const sb = compileSolidity(SOL, 'StorageDynStruct');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  const SHORT = 'ab';
  const EXACT31 = 'Y'.repeat(31);
  const LONG40 = 'X'.repeat(40);
  const LONG70 = 'Q'.repeat(70);

  it('bare struct d: a + s fields, raw slots, overwrite-clearing', async () => {
    await eq('setDa', encodeCall(sel('setDa(uint256)'), [0x77n]));
    await eq('setDs long40', callDyn('setDs(string)', [], s(LONG40)));
    await eqSlot(0n, 'd.a slot0');
    await eqSlot(1n, 'd.s header slot1');
    await eqSlot(slotKeccak(1n), 'd.s long data w0');
    await eqSlot(slotKeccak(1n) + 1n, 'd.s long data w1');
    let r = await eq('getDa', encodeCall(sel('getDa()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0x77n);
    await eq('getDs long40', encodeCall(sel('getDs()'), []));
    // overwrite long -> short: old data slots must be cleared
    await eq('setDs short', callDyn('setDs(string)', [], s(SHORT)));
    await eqSlot(1n, 'd.s header after short');
    await eqSlot(slotKeccak(1n), 'd.s old data w0 cleared');
    await eqSlot(slotKeccak(1n) + 1n, 'd.s old data w1 cleared');
    await eq('getDs short', encodeCall(sel('getDs()'), []));
    // overwrite short -> long again
    await eq('setDs long70', callDyn('setDs(string)', [], s(LONG70)));
    await eqSlot(1n, 'd.s header long70');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(1n) + i, `d.s long70 data w${i}`);
    await eq('getDs long70', encodeCall(sel('getDs()'), []));
  });

  it('whole-struct assign this.d = D(a, s) (raw slots)', async () => {
    await eq('setD', callDyn('setD(uint256,string)', [0x1234n], s(EXACT31)));
    await eqSlot(0n, 'd.a after whole assign');
    await eqSlot(1n, 'd.s header after whole assign');
    const r = await eq('getDa after whole', encodeCall(sel('getDa()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0x1234n);
    await eq('getDs after whole', encodeCall(sel('getDs()'), []));
    // whole-assign with a long string after a short: clears nothing stale, encodes ok
    await eq('setD long', callDyn('setD(uint256,string)', [0x5n], s(LONG40)));
    await eqSlot(0n, 'd.a after whole long');
    await eqSlot(1n, 'd.s header after whole long');
    await eqSlot(slotKeccak(1n), 'd.s long data after whole');
    await eq('getDs after whole long', encodeCall(sel('getDs()'), []));
    // whole-assign a SHORT string after a long: old long data slots must be cleared
    // (byte-identical to solc).
    await eq('setD short-after-long', callDyn('setD(uint256,string)', [0x6n], s(SHORT)));
    await eqSlot(0n, 'd.a after whole short');
    await eqSlot(1n, 'd.s header after whole short');
    await eqSlot(slotKeccak(1n), 'd.s old long data cleared after whole short');
    await eq('getDs after whole short', encodeCall(sel('getDs()'), []));
  });

  it('D[] recs: push(D)/push()/pop/length/field read+write (raw slots + full-clear on pop)', async () => {
    const data = slotKeccak(3n); // recs data base; stride = storageSlotCount(D) = 2
    await eq('pushRec short', callDyn('pushRec(uint256,string)', [0xa0n], s(SHORT)));
    await eq('pushRec long40', callDyn('pushRec(uint256,string)', [0xa1n], s(LONG40)));
    const r = await eq('recsLen=2', encodeCall(sel('recsLen()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    await eqSlot(3n, 'recs length slot');
    await eqSlot(data + 0n, 'recs[0].a');
    await eqSlot(data + 1n, 'recs[0].s header (short)');
    await eqSlot(data + 2n, 'recs[1].a');
    await eqSlot(data + 3n, 'recs[1].s header (long)');
    await eqSlot(slotKeccak(data + 3n), 'recs[1].s long data w0');
    await eqSlot(slotKeccak(data + 3n) + 1n, 'recs[1].s long data w1');
    for (let i = 0n; i < 2n; i++) await eq(`recAt#${i}`, encodeCall(sel('recAt(uint256)'), [i]));
    for (let i = 0n; i < 2n; i++) await eq(`recAtA#${i}`, encodeCall(sel('recAtA(uint256)'), [i]));
    // field writes via this.recs[i].a / this.recs[i].s
    await eq('setRecA[0]', encodeCall(sel('setRecA(uint256,uint256)'), [0n, 0xbeefn]));
    await eqSlot(data + 0n, 'recs[0].a after write');
    await eq('setRecS[0]=long70', callDyn('setRecS(uint256,string)', [0n], s(LONG70)));
    await eqSlot(data + 1n, 'recs[0].s header long70');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(data + 1n) + i, `recs[0].s long70 data w${i}`);
    await eq('recAt#0 after', encodeCall(sel('recAt(uint256)'), [0n]));
    // pop recs[1] (long) -> its header AND long data slots fully cleared
    await eq('popRec', encodeCall(sel('popRec()'), []));
    await eqSlot(3n, 'recs length after pop');
    await eqSlot(data + 2n, 'recs[1].a cleared');
    await eqSlot(data + 3n, 'recs[1].s header cleared');
    await eqSlot(slotKeccak(data + 3n), 'recs[1].s long data cleared');
    await eqSlot(slotKeccak(data + 3n) + 1n, 'recs[1].s long data w1 cleared');
    // pop recs[0] (now long70) -> all data slots cleared
    await eq('popRec 0', encodeCall(sel('popRec()'), []));
    await eqSlot(data + 0n, 'recs[0].a cleared');
    await eqSlot(data + 1n, 'recs[0].s header cleared');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(data + 1n) + i, `recs[0].s long70 data cleared w${i}`);
    // pop empty -> Panic(0x31)
    await eq('popRec empty', encodeCall(sel('popRec()'), []));
  });

  it('push() (no-arg empty element) then assign into it', async () => {
    const data = slotKeccak(3n);
    await eq('pushEmptyRec', encodeCall(sel('pushEmptyRec()'), []));
    await eqSlot(3n, 'recs length after empty push');
    await eqSlot(data + 0n, 'recs[0].a empty (0)');
    await eqSlot(data + 1n, 'recs[0].s empty header (0)');
    await eq('recAt#0 empty', encodeCall(sel('recAt(uint256)'), [0n]));
    await eq('setRecS[0]=long', callDyn('setRecS(uint256,string)', [0n], s(LONG40)));
    await eqSlot(data + 1n, 'recs[0].s header after assign');
    await eqSlot(slotKeccak(data + 1n), 'recs[0].s long data after assign');
    await eq('recAt#0 after assign', encodeCall(sel('recAt(uint256)'), [0n]));
    await eq('popRec cleanup', encodeCall(sel('popRec()'), []));
  });

  it('mapping<address, D>: per-key isolation, raw slots', async () => {
    await eq('setKa A1', encodeCall(sel('setKa(address,uint256)'), [A1, 0x99n]));
    await eq('setKs A1 long', callDyn('setKs(address,string)', [A1], s(LONG40)));
    await eq('setKa A2', encodeCall(sel('setKa(address,uint256)'), [A2, 0xaaaan]));
    await eq('setKs A2 short', callDyn('setKs(address,string)', [A2], s(SHORT)));
    const b1 = mapSlot(A1, 4n), b2 = mapSlot(A2, 4n);
    await eqSlot(b1 + 0n, 'byKey[A1].a');
    await eqSlot(b1 + 1n, 'byKey[A1].s header (long)');
    await eqSlot(slotKeccak(b1 + 1n), 'byKey[A1].s long data');
    await eqSlot(b2 + 0n, 'byKey[A2].a');
    await eqSlot(b2 + 1n, 'byKey[A2].s header (short)');
    let r = await eq('getKa A1', encodeCall(sel('getKa(address)'), [A1]));
    expect(decodeUint(r.j.returnHex)).toBe(0x99n);
    r = await eq('getKa A2', encodeCall(sel('getKa(address)'), [A2]));
    expect(decodeUint(r.j.returnHex)).toBe(0xaaaan);
    await eq('getKs A1', encodeCall(sel('getKs(address)'), [A1]));
    await eq('getKs A2', encodeCall(sel('getKs(address)'), [A2]));
  });

  it('E{uint64 id; bytes b; uint64 x}: packing around the dyn field, .length, byte index', async () => {
    await eq('setEid', encodeCall(sel('setEid(uint64)'), [0x42n]));
    await eq('setEx', encodeCall(sel('setEx(uint64)'), [0x43n]));
    await eq('setEb long40', callDyn('setEb(bytes)', [], s(LONG40)));
    await eqSlot(5n, 'e.id slot5 (NOT packed with x; b is between)');
    await eqSlot(6n, 'e.b header slot6');
    await eqSlot(7n, 'e.x slot7');
    await eqSlot(slotKeccak(6n), 'e.b long data w0');
    let r = await eq('getEid', encodeCall(sel('getEid()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0x42n);
    r = await eq('getEx', encodeCall(sel('getEx()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0x43n);
    await eq('getEb', encodeCall(sel('getEb()'), []));
    r = await eq('ebLen', encodeCall(sel('ebLen()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(40n);
    for (let j = 0n; j < 40n; j += 7n) await eq(`ebByte#${j}`, encodeCall(sel('ebByte(uint256)'), [j]));
    await eq('ebByte OOB', encodeCall(sel('ebByte(uint256)'), [40n])); // Panic(0x32)
  });

  it('nested Outer{x; D inner; y}: x/y + inner.a/inner.s (raw slots)', async () => {
    await eq('setOx', encodeCall(sel('setOx(uint256)'), [0x1111n]));
    await eq('setOy', encodeCall(sel('setOy(uint256)'), [0x3333n]));
    await eq('setOInnerA', encodeCall(sel('setOInnerA(uint256)'), [0x2222n]));
    await eq('setOInnerS long', callDyn('setOInnerS(string)', [], s(LONG40)));
    // Outer: x@8, inner.a@9, inner.s@10, y@11
    await eqSlot(8n, 'o.x slot8');
    await eqSlot(9n, 'o.inner.a slot9');
    await eqSlot(10n, 'o.inner.s header slot10');
    await eqSlot(11n, 'o.y slot11');
    await eqSlot(slotKeccak(10n), 'o.inner.s long data');
    let r = await eq('getOx', encodeCall(sel('getOx()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0x1111n);
    r = await eq('getOy', encodeCall(sel('getOy()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0x3333n);
    r = await eq('getOInnerA', encodeCall(sel('getOInnerA()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0x2222n);
    await eq('getOInnerS', encodeCall(sel('getOInnerS()'), []));
  });

  it('mapping<address, D[]>: per-key dynamic-struct array, raw slots', async () => {
    // length at keccak(k.12); data at keccak(lenSlot); element i at data+i*2.
    const lenA1 = mapSlot(A1, 12n);
    const lenA2 = mapSlot(A2, 12n);
    const dataA1 = slotKeccak(lenA1);
    await eq('pushKA A1 short', callDyn('pushKA(address,uint256,string)', [A1, 0xc0n], s(SHORT)));
    await eq('pushKA A1 long', callDyn('pushKA(address,uint256,string)', [A1, 0xc1n], s(LONG40)));
    await eq('pushKA A2 long', callDyn('pushKA(address,uint256,string)', [A2, 0xd0n], s(LONG70)));
    let r = await eq('kaLen A1=2', encodeCall(sel('kaLen(address)'), [A1]));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    r = await eq('kaLen A2=1', encodeCall(sel('kaLen(address)'), [A2]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    await eqSlot(lenA1, 'byKeyArr[A1] length');
    await eqSlot(lenA2, 'byKeyArr[A2] length');
    await eqSlot(dataA1 + 0n, 'byKeyArr[A1][0].a');
    await eqSlot(dataA1 + 1n, 'byKeyArr[A1][0].s header (short)');
    await eqSlot(dataA1 + 2n, 'byKeyArr[A1][1].a');
    await eqSlot(dataA1 + 3n, 'byKeyArr[A1][1].s header (long)');
    await eqSlot(slotKeccak(dataA1 + 3n), 'byKeyArr[A1][1].s long data');
    for (let i = 0n; i < 2n; i++) await eq(`kaAt A1 #${i}`, encodeCall(sel('kaAt(address,uint256)'), [A1, i]));
    for (let i = 0n; i < 2n; i++) await eq(`kaAtA A1 #${i}`, encodeCall(sel('kaAtA(address,uint256)'), [A1, i]));
    await eq('kaAt A2 #0', encodeCall(sel('kaAt(address,uint256)'), [A2, 0n]));
    // field write + overwrite-clear inside an element
    await eq('setKAs A1[1]=long70', callDyn('setKAs(address,uint256,string)', [A1, 1n], s(LONG70)));
    await eqSlot(dataA1 + 3n, 'byKeyArr[A1][1].s header long70');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(dataA1 + 3n) + i, `byKeyArr[A1][1].s long70 data w${i}`);
    await eq('kaAt A1 #1 after', encodeCall(sel('kaAt(address,uint256)'), [A1, 1n]));
    // pop A1[1] (long70) -> full clear incl data slots
    await eq('popKA A1', encodeCall(sel('popKA(address)'), []));
    await eqSlot(lenA1, 'byKeyArr[A1] length after pop');
    await eqSlot(dataA1 + 3n, 'byKeyArr[A1][1].s header cleared');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(dataA1 + 3n) + i, `byKeyArr[A1][1].s data cleared w${i}`);
    // wrong selector args for popKA: keep A2 intact (isolation)
    r = await eq('kaLen A2 still 1', encodeCall(sel('kaLen(address)'), [A2]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    await eq('kaAt A1 OOB', encodeCall(sel('kaAt(address,uint256)'), [A1, 5n])); // Panic 0x32
  });

  it('OOB index on D[] -> Panic(0x32); sentinel never disturbed', async () => {
    await eq('recAt OOB', encodeCall(sel('recAt(uint256)'), [99n]));
    await eq('setRecA OOB', encodeCall(sel('setRecA(uint256,uint256)'), [99n, 1n]));
    await eq('setSentinel', encodeCall(sel('setSentinel(uint256)'), [0xdeadbeefn]));
    await eqSlot(2n, 'sentinel after all dyn-struct writes');
    const r = await eq('getSentinel', encodeCall(sel('getSentinel()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0xdeadbeefn);
  });

  it('malformed setDs calldata (bad offset) reverts identically, no slot written', async () => {
    // offset word points past calldatasize -> EMPTY revert in both
    const bad = '0x' + sel('setDs(string)') + pad(0xffffffffn);
    await eq('setDs bad offset', bad);
    await eqSlot(1n, 'd.s header unchanged after bad setDs');
  });

  it('adversarial setD / setRecS / pushRec calldata: byte-identical revert, no partial write', async () => {
    // First establish a known d (so we can confirm a malformed setD does NOT clobber it).
    await eq('setD known', callDyn('setD(uint256,string)', [0xa11n], s('ok')));
    await eqSlot(0n, 'd.a known'); await eqSlot(1n, 'd.s known');
    // setD with the string offset pointing past calldatasize: solc reverts at param
    // decode BEFORE writing a -> a must be UNCHANGED in both.
    const badSetD = '0x' + sel('setD(uint256,string)') + pad(0x999n) + pad(0xffffffffffffffffn);
    await eq('setD bad string offset', badSetD);
    await eqSlot(0n, 'd.a unchanged after bad setD (no partial write)');
    await eqSlot(1n, 'd.s unchanged after bad setD');
    // length implies payload past calldatasize: declared len huge, no backing bytes.
    const badLen = '0x' + sel('setD(uint256,string)') + pad(0x7n) + pad(0x40n) + pad((1n << 64n) - 1n);
    await eq('setD huge len', badLen);
    await eqSlot(0n, 'd.a unchanged after huge-len setD');
    // pushRec with a truncated string payload (declares len but no/short bytes).
    const before = await jeth.call(aj, encodeCall(sel('recsLen()'), []));
    const truncPush = '0x' + sel('pushRec(uint256,string)') + pad(0x1n) + pad(0x40n) + pad(0x40n); // len=64, no data
    await eq('pushRec truncated', truncPush);
    const after = await jeth.call(aj, encodeCall(sel('recsLen()'), []));
    expect(after.returnHex, 'recsLen unchanged after a reverted push').toBe(before.returnHex);
    // setRecS at a valid index but malformed string -> EMPTY revert, element untouched.
    await eq('pushRec ok for setRecS', callDyn('pushRec(uint256,string)', [0x1n], s('seed')));
    const data = slotKeccak(3n);
    const idx = (await jeth.call(aj, encodeCall(sel('recsLen()'), []))).returnHex;
    const last = decodeUint(idx) - 1n;
    const badSetRecS = '0x' + sel('setRecS(uint256,string)') + pad(last) + pad(0xffffffffn);
    await eq('setRecS bad offset', badSetRecS);
    await eqSlot(data + last * 2n + 1n, 'recs[last].s header unchanged after bad setRecS');
  });
});
