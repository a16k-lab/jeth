// G7 adversarial: a @struct may have a MAPPING field (storage-only). Differential vs solc
// (0.8.x, cancun, optimizer on) on BOTH return values AND RAW STORAGE SLOTS. A storage-layout
// miscompile is the worst kind, so every leaf is verified by raw slot keccak as well as getter.
//
// Supported shapes exercised (others are intentionally GATED = compile errors, not tested here):
//  - @struct with mapping field(s) as a @state var: this.s.bal[a], packed neighbours, first/last/
//    only mapping field, multiple maps interspersed with value fields.
//  - mapping VALUE is a struct-with-mapping: this.m[k].bal[a], this.m[k].head.
//  - mapping<K1, mapping<K2, S>> where S has a mapping: this.mm[k1][k2].bal[a].
//  - struct field that is mapping<K, struct-with-mapping>: this.s.im[k].ibal[a] (the supported
//    "nested struct that has a mapping" form, reached through a mapping).
//  - deep nesting: this.md[k].inner[k2].dm[a] (mapping value -> struct -> mapping value -> struct
//    -> mapping value).
//  - key-type variety (address/uintN/intN/bool/bytesN, boundary values incl. INT_MIN / type-max)
//    and value-type variety (u256, narrow uint, address, bytesN, bool, signed int sign-ext).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
// mapping value slot = keccak256(pad32(key) ++ pad32(slot)); the key word IS the ABI-padded key
// (uint/address/bool zero-extended, intN sign-extended -> full two's complement word, bytesN
// left-aligned). For bytesN keys the caller supplies the already-left-aligned word.
const mapSlot = (key: bigint, slot: bigint) =>
  BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(key) + pad(slot)) as `0x${string}`))));

// left-align a bytesN value into a 32-byte word (high bytes), as the ABI / mapping key encodes it.
const bytesNWord = (val: bigint, n: number) => val << BigInt((32 - n) * 8);

const JETH = `
@struct class Acct { head: u256; bal: mapping<address, u256>; tail: u64; }
@struct class Pk { a: u8; b: u16; c: bool; m: mapping<u256, u256>; d: u8; e: u32; f: address; }
@struct class FirstMap { m: mapping<address, u256>; a: u64; b: u64; }
@struct class OnlyMap { m: mapping<u256, u64>; }
@struct class Multi { x: u128; m1: mapping<u256, u256>; y: u128; z: u128; m2: mapping<address, u64>; w: u64; }
@struct class Inner { ihead: u64; ibal: mapping<address, u256>; itail: u64; }
@struct class WithInnerMap { sa: u64; im: mapping<u256, Inner>; sb: u64; }
@struct class Deep { d: u256; dm: mapping<address, u256>; }
@struct class OuterDeep { oh: u256; inner: mapping<u256, Deep>; ot: u64; }
@struct class KV { ku8: mapping<u8, u8>; ki: mapping<i256, i256>; kb: mapping<bool, address>; k4: mapping<bytes4, bytes32>; k32: mapping<bytes32, u256>; ki8: mapping<i8, u256>; }
@contract class C {
  @state acct: Acct;
  @state pk: Pk;
  @state fm: FirstMap;
  @state om: OnlyMap;
  @state multi: Multi;
  @state mp: mapping<u256, Acct>;
  @state mm: mapping<u256, mapping<u256, Acct>>;
  @state wim: WithInnerMap;
  @state md: mapping<u256, OuterDeep>;
  @state kv: KV;
  @state sentinel: u256;

  // --- Acct: struct with a mapping field surrounded by value fields ---
  @external setHead(v: u256): void { this.acct.head = v; }
  @external setTail(v: u64): void { this.acct.tail = v; }
  @external setBal(a: address, v: u256): void { this.acct.bal[a] = v; }
  @external incBal(a: address, v: u256): void { this.acct.bal[a] = this.acct.bal[a] + v; }
  @external @view getHead(): u256 { return this.acct.head; }
  @external @view getTail(): u64 { return this.acct.tail; }
  @external @view getBal(a: address): u256 { return this.acct.bal[a]; }

  // --- Pk: a mapping field tightly packed between small fields on BOTH sides ---
  @external setPkPacked(a: u8, b: u16, c: bool, d: u8, e: u32, f: address): void {
    this.pk.a = a; this.pk.b = b; this.pk.c = c; this.pk.d = d; this.pk.e = e; this.pk.f = f;
  }
  @external setPkM(k: u256, v: u256): void { this.pk.m[k] = v; }
  @external @view getPkA(): u8 { return this.pk.a; }
  @external @view getPkB(): u16 { return this.pk.b; }
  @external @view getPkC(): bool { return this.pk.c; }
  @external @view getPkD(): u8 { return this.pk.d; }
  @external @view getPkE(): u32 { return this.pk.e; }
  @external @view getPkF(): address { return this.pk.f; }
  @external @view getPkM(k: u256): u256 { return this.pk.m[k]; }

  // --- FirstMap: FIRST field is a mapping ---
  @external setFmM(a: address, v: u256): void { this.fm.m[a] = v; }
  @external setFm(a: u64, b: u64): void { this.fm.a = a; this.fm.b = b; }
  @external @view getFmM(a: address): u256 { return this.fm.m[a]; }
  @external @view getFmA(): u64 { return this.fm.a; }
  @external @view getFmB(): u64 { return this.fm.b; }

  // --- OnlyMap: the ONLY field is a mapping (narrow value u64) ---
  @external setOmM(k: u256, v: u64): void { this.om.m[k] = v; }
  @external @view getOmM(k: u256): u64 { return this.om.m[k]; }

  // --- Multi: two mappings interspersed with value fields ---
  @external setMulti(x: u128, y: u128, z: u128, w: u64): void {
    this.multi.x = x; this.multi.y = y; this.multi.z = z; this.multi.w = w;
  }
  @external setMultiM1(k: u256, v: u256): void { this.multi.m1[k] = v; }
  @external setMultiM2(a: address, v: u64): void { this.multi.m2[a] = v; }
  @external @view getMultiX(): u128 { return this.multi.x; }
  @external @view getMultiY(): u128 { return this.multi.y; }
  @external @view getMultiZ(): u128 { return this.multi.z; }
  @external @view getMultiW(): u64 { return this.multi.w; }
  @external @view getMultiM1(k: u256): u256 { return this.multi.m1[k]; }
  @external @view getMultiM2(a: address): u64 { return this.multi.m2[a]; }

  // --- mp: mapping<u256, Acct> (struct-with-mapping as a mapping value) ---
  @external setMpHead(k: u256, v: u256): void { this.mp[k].head = v; }
  @external setMpTail(k: u256, v: u64): void { this.mp[k].tail = v; }
  @external setMpBal(k: u256, a: address, v: u256): void { this.mp[k].bal[a] = v; }
  @external @view getMpHead(k: u256): u256 { return this.mp[k].head; }
  @external @view getMpTail(k: u256): u64 { return this.mp[k].tail; }
  @external @view getMpBal(k: u256, a: address): u256 { return this.mp[k].bal[a]; }

  // --- mm: mapping<u256, mapping<u256, Acct>> (two outer keys, then struct-with-mapping) ---
  @external setMmHead(k1: u256, k2: u256, v: u256): void { this.mm[k1][k2].head = v; }
  @external setMmBal(k1: u256, k2: u256, a: address, v: u256): void { this.mm[k1][k2].bal[a] = v; }
  @external @view getMmHead(k1: u256, k2: u256): u256 { return this.mm[k1][k2].head; }
  @external @view getMmBal(k1: u256, k2: u256, a: address): u256 { return this.mm[k1][k2].bal[a]; }

  // --- wim: a struct field that is mapping<u256, Inner> where Inner has a mapping ---
  @external setWim(sa: u64, sb: u64): void { this.wim.sa = sa; this.wim.sb = sb; }
  @external setWimHead(k: u256, v: u64): void { this.wim.im[k].ihead = v; }
  @external setWimTail(k: u256, v: u64): void { this.wim.im[k].itail = v; }
  @external setWimBal(k: u256, a: address, v: u256): void { this.wim.im[k].ibal[a] = v; }
  @external @view getWimSa(): u64 { return this.wim.sa; }
  @external @view getWimSb(): u64 { return this.wim.sb; }
  @external @view getWimHead(k: u256): u64 { return this.wim.im[k].ihead; }
  @external @view getWimTail(k: u256): u64 { return this.wim.im[k].itail; }
  @external @view getWimBal(k: u256, a: address): u256 { return this.wim.im[k].ibal[a]; }

  // --- md: mapping<u256, OuterDeep>; OuterDeep.inner is mapping<u256, Deep>; Deep has a mapping ---
  @external setMdH(k: u256, v: u256): void { this.md[k].oh = v; }
  @external setMdT(k: u256, v: u64): void { this.md[k].ot = v; }
  @external setMdInnerD(k: u256, k2: u256, v: u256): void { this.md[k].inner[k2].d = v; }
  @external setMdDeep(k: u256, k2: u256, a: address, v: u256): void { this.md[k].inner[k2].dm[a] = v; }
  @external @view getMdH(k: u256): u256 { return this.md[k].oh; }
  @external @view getMdT(k: u256): u64 { return this.md[k].ot; }
  @external @view getMdInnerD(k: u256, k2: u256): u256 { return this.md[k].inner[k2].d; }
  @external @view getMdDeep(k: u256, k2: u256, a: address): u256 { return this.md[k].inner[k2].dm[a]; }

  // --- KV: key-type and value-type variety in struct-field mappings ---
  @external setKu8(k: u8, v: u8): void { this.kv.ku8[k] = v; }
  @external @view getKu8(k: u8): u8 { return this.kv.ku8[k]; }
  @external setKi(k: i256, v: i256): void { this.kv.ki[k] = v; }
  @external @view getKi(k: i256): i256 { return this.kv.ki[k]; }
  @external setKb(k: bool, v: address): void { this.kv.kb[k] = v; }
  @external @view getKb(k: bool): address { return this.kv.kb[k]; }
  @external setK4(k: bytes4, v: bytes32): void { this.kv.k4[k] = v; }
  @external @view getK4(k: bytes4): bytes32 { return this.kv.k4[k]; }
  @external setK32(k: bytes32, v: u256): void { this.kv.k32[k] = v; }
  @external @view getK32(k: bytes32): u256 { return this.kv.k32[k]; }
  @external setKi8(k: i8, v: u256): void { this.kv.ki8[k] = v; }
  @external @view getKi8(k: i8): u256 { return this.kv.ki8[k]; }

  @external setSentinel(v: u256): void { this.sentinel = v; }
  @external @view getSentinel(): u256 { return this.sentinel; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Acct { uint256 head; mapping(address=>uint256) bal; uint64 tail; }
  struct Pk { uint8 a; uint16 b; bool c; mapping(uint256=>uint256) m; uint8 d; uint32 e; address f; }
  struct FirstMap { mapping(address=>uint256) m; uint64 a; uint64 b; }
  struct OnlyMap { mapping(uint256=>uint64) m; }
  struct Multi { uint128 x; mapping(uint256=>uint256) m1; uint128 y; uint128 z; mapping(address=>uint64) m2; uint64 w; }
  struct Inner { uint64 ihead; mapping(address=>uint256) ibal; uint64 itail; }
  struct WithInnerMap { uint64 sa; mapping(uint256=>Inner) im; uint64 sb; }
  struct Deep { uint256 d; mapping(address=>uint256) dm; }
  struct OuterDeep { uint256 oh; mapping(uint256=>Deep) inner; uint64 ot; }
  struct KV { mapping(uint8=>uint8) ku8; mapping(int256=>int256) ki; mapping(bool=>address) kb; mapping(bytes4=>bytes32) k4; mapping(bytes32=>uint256) k32; mapping(int8=>uint256) ki8; }
  Acct acct; Pk pk; FirstMap fm; OnlyMap om; Multi multi;
  mapping(uint256=>Acct) mp; mapping(uint256=>mapping(uint256=>Acct)) mm;
  WithInnerMap wim; mapping(uint256=>OuterDeep) md; KV kv; uint256 sentinel;

  function setHead(uint256 v) external { acct.head = v; }
  function setTail(uint64 v) external { acct.tail = v; }
  function setBal(address a, uint256 v) external { acct.bal[a] = v; }
  function incBal(address a, uint256 v) external { acct.bal[a] = acct.bal[a] + v; }
  function getHead() external view returns (uint256){ return acct.head; }
  function getTail() external view returns (uint64){ return acct.tail; }
  function getBal(address a) external view returns (uint256){ return acct.bal[a]; }

  function setPkPacked(uint8 a, uint16 b, bool c, uint8 d, uint32 e, address f) external {
    pk.a = a; pk.b = b; pk.c = c; pk.d = d; pk.e = e; pk.f = f;
  }
  function setPkM(uint256 k, uint256 v) external { pk.m[k] = v; }
  function getPkA() external view returns (uint8){ return pk.a; }
  function getPkB() external view returns (uint16){ return pk.b; }
  function getPkC() external view returns (bool){ return pk.c; }
  function getPkD() external view returns (uint8){ return pk.d; }
  function getPkE() external view returns (uint32){ return pk.e; }
  function getPkF() external view returns (address){ return pk.f; }
  function getPkM(uint256 k) external view returns (uint256){ return pk.m[k]; }

  function setFmM(address a, uint256 v) external { fm.m[a] = v; }
  function setFm(uint64 a, uint64 b) external { fm.a = a; fm.b = b; }
  function getFmM(address a) external view returns (uint256){ return fm.m[a]; }
  function getFmA() external view returns (uint64){ return fm.a; }
  function getFmB() external view returns (uint64){ return fm.b; }

  function setOmM(uint256 k, uint64 v) external { om.m[k] = v; }
  function getOmM(uint256 k) external view returns (uint64){ return om.m[k]; }

  function setMulti(uint128 x, uint128 y, uint128 z, uint64 w) external {
    multi.x = x; multi.y = y; multi.z = z; multi.w = w;
  }
  function setMultiM1(uint256 k, uint256 v) external { multi.m1[k] = v; }
  function setMultiM2(address a, uint64 v) external { multi.m2[a] = v; }
  function getMultiX() external view returns (uint128){ return multi.x; }
  function getMultiY() external view returns (uint128){ return multi.y; }
  function getMultiZ() external view returns (uint128){ return multi.z; }
  function getMultiW() external view returns (uint64){ return multi.w; }
  function getMultiM1(uint256 k) external view returns (uint256){ return multi.m1[k]; }
  function getMultiM2(address a) external view returns (uint64){ return multi.m2[a]; }

  function setMpHead(uint256 k, uint256 v) external { mp[k].head = v; }
  function setMpTail(uint256 k, uint64 v) external { mp[k].tail = v; }
  function setMpBal(uint256 k, address a, uint256 v) external { mp[k].bal[a] = v; }
  function getMpHead(uint256 k) external view returns (uint256){ return mp[k].head; }
  function getMpTail(uint256 k) external view returns (uint64){ return mp[k].tail; }
  function getMpBal(uint256 k, address a) external view returns (uint256){ return mp[k].bal[a]; }

  function setMmHead(uint256 k1, uint256 k2, uint256 v) external { mm[k1][k2].head = v; }
  function setMmBal(uint256 k1, uint256 k2, address a, uint256 v) external { mm[k1][k2].bal[a] = v; }
  function getMmHead(uint256 k1, uint256 k2) external view returns (uint256){ return mm[k1][k2].head; }
  function getMmBal(uint256 k1, uint256 k2, address a) external view returns (uint256){ return mm[k1][k2].bal[a]; }

  function setWim(uint64 sa, uint64 sb) external { wim.sa = sa; wim.sb = sb; }
  function setWimHead(uint256 k, uint64 v) external { wim.im[k].ihead = v; }
  function setWimTail(uint256 k, uint64 v) external { wim.im[k].itail = v; }
  function setWimBal(uint256 k, address a, uint256 v) external { wim.im[k].ibal[a] = v; }
  function getWimSa() external view returns (uint64){ return wim.sa; }
  function getWimSb() external view returns (uint64){ return wim.sb; }
  function getWimHead(uint256 k) external view returns (uint64){ return wim.im[k].ihead; }
  function getWimTail(uint256 k) external view returns (uint64){ return wim.im[k].itail; }
  function getWimBal(uint256 k, address a) external view returns (uint256){ return wim.im[k].ibal[a]; }

  function setMdH(uint256 k, uint256 v) external { md[k].oh = v; }
  function setMdT(uint256 k, uint64 v) external { md[k].ot = v; }
  function setMdInnerD(uint256 k, uint256 k2, uint256 v) external { md[k].inner[k2].d = v; }
  function setMdDeep(uint256 k, uint256 k2, address a, uint256 v) external { md[k].inner[k2].dm[a] = v; }
  function getMdH(uint256 k) external view returns (uint256){ return md[k].oh; }
  function getMdT(uint256 k) external view returns (uint64){ return md[k].ot; }
  function getMdInnerD(uint256 k, uint256 k2) external view returns (uint256){ return md[k].inner[k2].d; }
  function getMdDeep(uint256 k, uint256 k2, address a) external view returns (uint256){ return md[k].inner[k2].dm[a]; }

  function setKu8(uint8 k, uint8 v) external { kv.ku8[k] = v; }
  function getKu8(uint8 k) external view returns (uint8){ return kv.ku8[k]; }
  function setKi(int256 k, int256 v) external { kv.ki[k] = v; }
  function getKi(int256 k) external view returns (int256){ return kv.ki[k]; }
  function setKb(bool k, address v) external { kv.kb[k] = v; }
  function getKb(bool k) external view returns (address){ return kv.kb[k]; }
  function setK4(bytes4 k, bytes32 v) external { kv.k4[k] = v; }
  function getK4(bytes4 k) external view returns (bytes32){ return kv.k4[k]; }
  function setK32(bytes32 k, uint256 v) external { kv.k32[k] = v; }
  function getK32(bytes32 k) external view returns (uint256){ return kv.k32[k]; }
  function setKi8(int8 k, uint256 v) external { kv.ki8[k] = v; }
  function getKi8(int8 k) external view returns (uint256){ return kv.ki8[k]; }

  function setSentinel(uint256 v) external { sentinel = v; }
  function getSentinel() external view returns (uint256){ return sentinel; }
}`;

describe('mapinstruct', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(
        'RET ' +
          label +
          ': jeth{ok=' +
          j.success +
          ',ret=' +
          j.returnHex +
          ',err=' +
          j.exceptionError +
          '} sol{ok=' +
          s.success +
          ',ret=' +
          s.returnHex +
          '}',
      );
  }
  async function eqSlot(slot: bigint, label: string) {
    count++;
    const a = await readSlot(jeth, aj, slot);
    const b = await readSlot(sol, as, slot);
    if (a !== b) mism.push('SLOT ' + label + ' @' + slot.toString(16) + ': jeth=' + a + ' sol=' + b);
  }
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success)
      mism.push(
        'SEND ' +
          data.slice(0, 10) +
          ': jeth{ok=' +
          j.success +
          ',err=' +
          j.exceptionError +
          '} sol{ok=' +
          s.success +
          '}',
      );
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // state base slots (verified identical to solc storageLayout):
  // acct@0 pk@3 fm@6 om@8 multi@9 mp@14 mm@15 wim@16 md@19 kv@20 sentinel@26
  const A1 = 0x1111n;
  const A2 = 0xdeadbeefn;
  const A3 = (1n << 160n) - 1n; // max address
  const MAXU = M - 1n;
  const INT_MIN = -(1n << 255n);
  const INT_MAX = (1n << 255n) - 1n;

  it('runs', async () => {
    // ============ Acct: struct with a mapping field, value-field neighbours ============
    await send(encodeCall(sel('setHead(uint256)'), [12345n]));
    await send(encodeCall(sel('setTail(uint64)'), [0xabcdn]));
    await send(encodeCall(sel('setBal(address,uint256)'), [A1, 100n]));
    await send(encodeCall(sel('setBal(address,uint256)'), [A2, 999n]));
    await send(encodeCall(sel('setBal(address,uint256)'), [A3, MAXU])); // max addr key, max value
    await send(encodeCall(sel('incBal(address,uint256)'), [A1, 5n])); // read-modify-write
    await send(encodeCall(sel('setBal(address,uint256)'), [0n, 7n])); // zero (address(0)) key
    await eq('getHead', encodeCall(sel('getHead()'), []));
    await eq('getTail', encodeCall(sel('getTail()'), []));
    await eq('getBal(A1)', encodeCall(sel('getBal(address)'), [A1]));
    await eq('getBal(A2)', encodeCall(sel('getBal(address)'), [A2]));
    await eq('getBal(A3)', encodeCall(sel('getBal(address)'), [A3]));
    await eq('getBal(0)', encodeCall(sel('getBal(address)'), [0n]));
    await eq('getBal(unset)', encodeCall(sel('getBal(address)'), [0x5555n]));
    await eqSlot(0n, 'acct.head');
    await eqSlot(2n, 'acct.tail');
    await eqSlot(1n, 'acct.bal base (must stay empty)');
    await eqSlot(mapSlot(A1, 1n), 'acct.bal[A1]');
    await eqSlot(mapSlot(A2, 1n), 'acct.bal[A2]');
    await eqSlot(mapSlot(A3, 1n), 'acct.bal[A3=maxaddr]');
    await eqSlot(mapSlot(0n, 1n), 'acct.bal[0]');

    // ============ Pk: mapping packed between small fields on BOTH sides ============
    await send(
      encodeCall(sel('setPkPacked(uint8,uint16,bool,uint8,uint32,address)'), [
        0xa5n,
        0xbeefn,
        1n,
        0x7fn,
        0xcafef00dn,
        A2,
      ]),
    );
    await send(encodeCall(sel('setPkM(uint256,uint256)'), [3n, 777n]));
    await send(encodeCall(sel('setPkM(uint256,uint256)'), [MAXU, 888n]));
    await eq('getPkA', encodeCall(sel('getPkA()'), []));
    await eq('getPkB', encodeCall(sel('getPkB()'), []));
    await eq('getPkC', encodeCall(sel('getPkC()'), []));
    await eq('getPkD', encodeCall(sel('getPkD()'), []));
    await eq('getPkE', encodeCall(sel('getPkE()'), []));
    await eq('getPkF', encodeCall(sel('getPkF()'), []));
    await eq('getPkM(3)', encodeCall(sel('getPkM(uint256)'), [3n]));
    await eq('getPkM(max)', encodeCall(sel('getPkM(uint256)'), [MAXU]));
    // pk@3: slot 3 holds a,b,c (offsets 0,1,3); slot 4 = mapping base (must be empty);
    // slot 5 holds d,e,f (offsets 0,1,5).
    await eqSlot(3n, 'pk slot0 (a|b|c packed)');
    await eqSlot(4n, 'pk.m base (must stay empty)');
    await eqSlot(5n, 'pk slot2 (d|e|f packed)');
    await eqSlot(mapSlot(3n, 4n), 'pk.m[3]');
    await eqSlot(mapSlot(MAXU, 4n), 'pk.m[max]');

    // ============ FirstMap: FIRST field is a mapping ============
    await send(encodeCall(sel('setFmM(address,uint256)'), [A1, 4242n]));
    await send(encodeCall(sel('setFm(uint64,uint64)'), [0x1234n, 0x5678n]));
    await eq('getFmM(A1)', encodeCall(sel('getFmM(address)'), [A1]));
    await eq('getFmA', encodeCall(sel('getFmA()'), []));
    await eq('getFmB', encodeCall(sel('getFmB()'), []));
    // fm@6: slot 6 = mapping base (empty); slot 7 holds a,b packed.
    await eqSlot(6n, 'fm.m base (must stay empty)');
    await eqSlot(7n, 'fm slot1 (a|b packed)');
    await eqSlot(mapSlot(A1, 6n), 'fm.m[A1]');

    // ============ OnlyMap: the ONLY field is a mapping (narrow u64 value) ============
    await send(encodeCall(sel('setOmM(uint256,uint64)'), [5n, 0xffffffffffffffffn]));
    await eq('getOmM(5)', encodeCall(sel('getOmM(uint256)'), [5n]));
    await eq('getOmM(unset)', encodeCall(sel('getOmM(uint256)'), [9n]));
    await eqSlot(8n, 'om.m base (must stay empty)');
    await eqSlot(mapSlot(5n, 8n), 'om.m[5] (single narrow value takes a full slot)');

    // ============ Multi: two mappings interspersed with value fields ============
    await send(encodeCall(sel('setMulti(uint128,uint128,uint128,uint64)'), [11n, 22n, 33n, 44n]));
    await send(encodeCall(sel('setMultiM1(uint256,uint256)'), [1n, 1000n]));
    await send(encodeCall(sel('setMultiM2(address,uint64)'), [A1, 0x99n]));
    await eq('getMultiX', encodeCall(sel('getMultiX()'), []));
    await eq('getMultiY', encodeCall(sel('getMultiY()'), []));
    await eq('getMultiZ', encodeCall(sel('getMultiZ()'), []));
    await eq('getMultiW', encodeCall(sel('getMultiW()'), []));
    await eq('getMultiM1(1)', encodeCall(sel('getMultiM1(uint256)'), [1n]));
    await eq('getMultiM2(A1)', encodeCall(sel('getMultiM2(address)'), [A1]));
    // multi@9: x@9; m1 base@10; y,z packed@11; m2 base@12; w@13.
    await eqSlot(9n, 'multi.x');
    await eqSlot(10n, 'multi.m1 base (empty)');
    await eqSlot(11n, 'multi y|z packed');
    await eqSlot(12n, 'multi.m2 base (empty)');
    await eqSlot(13n, 'multi.w');
    await eqSlot(mapSlot(1n, 10n), 'multi.m1[1]');
    await eqSlot(mapSlot(A1, 12n), 'multi.m2[A1]');

    // ============ mp: mapping<u256, Acct> (struct-with-mapping as a mapping value) ============
    await send(encodeCall(sel('setMpHead(uint256,uint256)'), [7n, 42n]));
    await send(encodeCall(sel('setMpTail(uint256,uint64)'), [7n, 0x1234n]));
    await send(encodeCall(sel('setMpBal(uint256,address,uint256)'), [7n, A1, 500n]));
    await send(encodeCall(sel('setMpBal(uint256,address,uint256)'), [9n, A2, 600n]));
    await send(encodeCall(sel('setMpHead(uint256,uint256)'), [0n, 1n])); // key 0
    await eq('getMpHead(7)', encodeCall(sel('getMpHead(uint256)'), [7n]));
    await eq('getMpTail(7)', encodeCall(sel('getMpTail(uint256)'), [7n]));
    await eq('getMpBal(7,A1)', encodeCall(sel('getMpBal(uint256,address)'), [7n, A1]));
    await eq('getMpBal(9,A2)', encodeCall(sel('getMpBal(uint256,address)'), [9n, A2]));
    await eq('getMpBal(9,A1) unset', encodeCall(sel('getMpBal(uint256,address)'), [9n, A1]));
    await eq('getMpHead(0)', encodeCall(sel('getMpHead(uint256)'), [0n]));
    {
      const b7 = mapSlot(7n, 14n); // mp@14; mp[7] struct base
      await eqSlot(b7, 'mp[7].head');
      await eqSlot(b7 + 2n, 'mp[7].tail');
      await eqSlot(b7 + 1n, 'mp[7].bal base (empty)');
      await eqSlot(mapSlot(A1, b7 + 1n), 'mp[7].bal[A1]');
      await eqSlot(mapSlot(A2, mapSlot(9n, 14n) + 1n), 'mp[9].bal[A2]');
      await eqSlot(mapSlot(0n, 14n), 'mp[0].head');
    }

    // ============ mm: mapping<u256, mapping<u256, Acct>> (two outer keys) ============
    await send(encodeCall(sel('setMmHead(uint256,uint256,uint256)'), [1n, 2n, 333n]));
    await send(encodeCall(sel('setMmBal(uint256,uint256,address,uint256)'), [1n, 2n, A1, 444n]));
    await send(encodeCall(sel('setMmBal(uint256,uint256,address,uint256)'), [3n, 4n, A2, 555n]));
    await eq('getMmHead(1,2)', encodeCall(sel('getMmHead(uint256,uint256)'), [1n, 2n]));
    await eq('getMmBal(1,2,A1)', encodeCall(sel('getMmBal(uint256,uint256,address)'), [1n, 2n, A1]));
    await eq('getMmBal(3,4,A2)', encodeCall(sel('getMmBal(uint256,uint256,address)'), [3n, 4n, A2]));
    await eq('getMmBal(1,2,A2) unset', encodeCall(sel('getMmBal(uint256,uint256,address)'), [1n, 2n, A2]));
    {
      const base12 = mapSlot(2n, mapSlot(1n, 15n)); // mm@15; mm[1][2] struct base
      await eqSlot(base12, 'mm[1][2].head');
      await eqSlot(mapSlot(A1, base12 + 1n), 'mm[1][2].bal[A1]');
      const base34 = mapSlot(4n, mapSlot(3n, 15n));
      await eqSlot(mapSlot(A2, base34 + 1n), 'mm[3][4].bal[A2]');
    }

    // ============ wim: struct field that is mapping<u256, Inner> (Inner has a mapping) ============
    await send(encodeCall(sel('setWim(uint64,uint64)'), [0x111n, 0x222n]));
    await send(encodeCall(sel('setWimHead(uint256,uint64)'), [5n, 0x1010n]));
    await send(encodeCall(sel('setWimTail(uint256,uint64)'), [5n, 0x2020n]));
    await send(encodeCall(sel('setWimBal(uint256,address,uint256)'), [5n, A1, 909n]));
    await send(encodeCall(sel('setWimBal(uint256,address,uint256)'), [6n, A2, 808n]));
    await eq('getWimSa', encodeCall(sel('getWimSa()'), []));
    await eq('getWimSb', encodeCall(sel('getWimSb()'), []));
    await eq('getWimHead(5)', encodeCall(sel('getWimHead(uint256)'), [5n]));
    await eq('getWimTail(5)', encodeCall(sel('getWimTail(uint256)'), [5n]));
    await eq('getWimBal(5,A1)', encodeCall(sel('getWimBal(uint256,address)'), [5n, A1]));
    await eq('getWimBal(6,A2)', encodeCall(sel('getWimBal(uint256,address)'), [6n, A2]));
    await eq('getWimBal(5,unset)', encodeCall(sel('getWimBal(uint256,address)'), [5n, 0x1n]));
    {
      // wim@16: sa,sb packed in slots 16/18; im (mapping<u256,Inner>) base @ 17.
      await eqSlot(16n, 'wim.sa');
      await eqSlot(18n, 'wim.sb');
      await eqSlot(17n, 'wim.im base (empty)');
      const inner5 = mapSlot(5n, 17n); // Inner struct base for key 5
      await eqSlot(inner5, 'wim.im[5].ihead');
      await eqSlot(inner5 + 2n, 'wim.im[5].itail');
      await eqSlot(inner5 + 1n, 'wim.im[5].ibal base (empty)');
      await eqSlot(mapSlot(A1, inner5 + 1n), 'wim.im[5].ibal[A1]');
      await eqSlot(mapSlot(A2, mapSlot(6n, 17n) + 1n), 'wim.im[6].ibal[A2]');
    }

    // ============ md: mapping<u256, OuterDeep>; OuterDeep.inner is mapping<u256, Deep>; Deep has a mapping ============
    await send(encodeCall(sel('setMdH(uint256,uint256)'), [1n, 1111n]));
    await send(encodeCall(sel('setMdT(uint256,uint64)'), [1n, 0x99n]));
    await send(encodeCall(sel('setMdInnerD(uint256,uint256,uint256)'), [1n, 2n, 2222n]));
    await send(encodeCall(sel('setMdDeep(uint256,uint256,address,uint256)'), [1n, 2n, A1, 3333n]));
    await send(encodeCall(sel('setMdDeep(uint256,uint256,address,uint256)'), [1n, 8n, A2, 4444n]));
    await eq('getMdH(1)', encodeCall(sel('getMdH(uint256)'), [1n]));
    await eq('getMdT(1)', encodeCall(sel('getMdT(uint256)'), [1n]));
    await eq('getMdInnerD(1,2)', encodeCall(sel('getMdInnerD(uint256,uint256)'), [1n, 2n]));
    await eq('getMdDeep(1,2,A1)', encodeCall(sel('getMdDeep(uint256,uint256,address)'), [1n, 2n, A1]));
    await eq('getMdDeep(1,8,A2)', encodeCall(sel('getMdDeep(uint256,uint256,address)'), [1n, 8n, A2]));
    await eq('getMdDeep(1,2,unset)', encodeCall(sel('getMdDeep(uint256,uint256,address)'), [1n, 2n, 0x7n]));
    {
      const outer1 = mapSlot(1n, 19n); // md@19; OuterDeep base for key 1
      await eqSlot(outer1, 'md[1].oh');
      await eqSlot(outer1 + 2n, 'md[1].ot');
      await eqSlot(outer1 + 1n, 'md[1].inner base (empty)');
      const deep12 = mapSlot(2n, outer1 + 1n); // Deep base for inner key 2
      await eqSlot(deep12, 'md[1].inner[2].d');
      await eqSlot(deep12 + 1n, 'md[1].inner[2].dm base (empty)');
      await eqSlot(mapSlot(A1, deep12 + 1n), 'md[1].inner[2].dm[A1]');
      const deep18 = mapSlot(8n, outer1 + 1n);
      await eqSlot(mapSlot(A2, deep18 + 1n), 'md[1].inner[8].dm[A2]');
    }

    // ============ KV: key-type and value-type variety, boundary keys/values ============
    // kv@20: ku8@20, ki@21, kb@22, k4@23, k32@24, ki8@25.
    await send(encodeCall(sel('setKu8(uint8,uint8)'), [0xffn, 0xeen])); // max u8 key, narrow value
    await send(encodeCall(sel('setKu8(uint8,uint8)'), [0n, 1n]));
    await eq('getKu8(255)', encodeCall(sel('getKu8(uint8)'), [0xffn]));
    await eq('getKu8(0)', encodeCall(sel('getKu8(uint8)'), [0n]));
    await eq('getKu8(unset)', encodeCall(sel('getKu8(uint8)'), [7n]));
    await eqSlot(mapSlot(0xffn, 20n), 'kv.ku8[255]');
    await eqSlot(mapSlot(0n, 20n), 'kv.ku8[0]');

    // int256 key (negative / INT_MIN / INT_MAX), signed value (sign-extension)
    await send(encodeCall(sel('setKi(int256,int256)'), [-1n, -42n]));
    await send(encodeCall(sel('setKi(int256,int256)'), [INT_MIN, INT_MAX]));
    await send(encodeCall(sel('setKi(int256,int256)'), [INT_MAX, INT_MIN]));
    await send(encodeCall(sel('setKi(int256,int256)'), [7n, -7n]));
    await eq('getKi(-1)', encodeCall(sel('getKi(int256)'), [-1n]));
    await eq('getKi(INT_MIN)', encodeCall(sel('getKi(int256)'), [INT_MIN]));
    await eq('getKi(INT_MAX)', encodeCall(sel('getKi(int256)'), [INT_MAX]));
    await eq('getKi(7)', encodeCall(sel('getKi(int256)'), [7n]));
    await eqSlot(mapSlot(-1n, 21n), 'kv.ki[-1]');
    await eqSlot(mapSlot(INT_MIN, 21n), 'kv.ki[INT_MIN]');
    await eqSlot(mapSlot(INT_MAX, 21n), 'kv.ki[INT_MAX]');
    await eqSlot(mapSlot(7n, 21n), 'kv.ki[7]');

    // bool key, address value
    await send(encodeCall(sel('setKb(bool,address)'), [1n, A1]));
    await send(encodeCall(sel('setKb(bool,address)'), [0n, A2]));
    await eq('getKb(true)', encodeCall(sel('getKb(bool)'), [1n]));
    await eq('getKb(false)', encodeCall(sel('getKb(bool)'), [0n]));
    await eqSlot(mapSlot(1n, 22n), 'kv.kb[true]');
    await eqSlot(mapSlot(0n, 22n), 'kv.kb[false]');

    // bytes4 key (left-aligned word), bytes32 value
    {
      const k4val = 0xcafebaben; // logical bytes4
      const k4word = bytesNWord(k4val, 4);
      const v32 = (0x1122334455667788n << 192n) | 0x99aabbccn;
      await send(encodeCall(sel('setK4(bytes4,bytes32)'), [k4word, v32]));
      await eq('getK4(cafebabe)', encodeCall(sel('getK4(bytes4)'), [k4word]));
      await eq('getK4(unset)', encodeCall(sel('getK4(bytes4)'), [bytesNWord(0x1n, 4)]));
      await eqSlot(mapSlot(k4word, 23n), 'kv.k4[cafebabe]');
    }

    // bytes32 key (full word)
    {
      const k32 = (1n << 255n) | 0xdeadbeefn;
      await send(encodeCall(sel('setK32(bytes32,uint256)'), [k32, 123456n]));
      await eq('getK32(k)', encodeCall(sel('getK32(bytes32)'), [k32]));
      await eqSlot(mapSlot(k32, 24n), 'kv.k32[k]');
    }

    // int8 key (negative, sign-extended to a full word for the preimage)
    await send(encodeCall(sel('setKi8(int8,uint256)'), [-128n, 77n])); // INT8_MIN
    await send(encodeCall(sel('setKi8(int8,uint256)'), [127n, 88n])); // INT8_MAX
    await send(encodeCall(sel('setKi8(int8,uint256)'), [-1n, 99n]));
    await eq('getKi8(-128)', encodeCall(sel('getKi8(int8)'), [-128n]));
    await eq('getKi8(127)', encodeCall(sel('getKi8(int8)'), [127n]));
    await eq('getKi8(-1)', encodeCall(sel('getKi8(int8)'), [-1n]));
    await eqSlot(mapSlot(-128n, 25n), 'kv.ki8[-128]'); // pad(-128n) sign-extends to full word
    await eqSlot(mapSlot(127n, 25n), 'kv.ki8[127]');
    await eqSlot(mapSlot(-1n, 25n), 'kv.ki8[-1]');

    // ============ overwrite / accumulate / same key twice ============
    await send(encodeCall(sel('setBal(address,uint256)'), [A1, 1n])); // overwrite A1 (was 105)
    await eq('getBal(A1) overwritten', encodeCall(sel('getBal(address)'), [A1]));
    await eqSlot(mapSlot(A1, 1n), 'acct.bal[A1] overwritten');
    await send(encodeCall(sel('incBal(address,uint256)'), [A1, 10n]));
    await send(encodeCall(sel('incBal(address,uint256)'), [A1, 10n]));
    await eq('getBal(A1) accumulated', encodeCall(sel('getBal(address)'), [A1]));
    await eqSlot(mapSlot(A1, 1n), 'acct.bal[A1] accumulated');

    // ============ sentinel: catch any slot over/underflow into neighbours ============
    await send(encodeCall(sel('setSentinel(uint256)'), [0xfeedface_deadbeefn]));
    await eq('getSentinel', encodeCall(sel('getSentinel()'), []));
    await eqSlot(26n, 'sentinel');
    // sweep every contract slot 0..26 to catch stray writes anywhere in the value-field region
    for (let s = 0n; s <= 26n; s++) await eqSlot(s, 'sweep slot ' + s);

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
