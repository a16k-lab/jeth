// G7: a @struct with a mapping field (storage-only). this.s.inner[k] and this.m[k].inner[ik]
// access, packed non-mapping neighbours, multiple mapping fields. Byte-identical to solc on
// BOTH return values AND raw storage slots (layout interop). Plus gate parity (storage-only:
// no return / param / construct / whole-copy).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const mapSlot = (key: bigint, slot: bigint) =>
  BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(key) + pad(slot)) as `0x${string}`))));

const JETH = `@struct class Acct { head: u256; bal: mapping<address, u256>; tail: u64; }
@struct class Pk { a: u64; m: mapping<u256, u256>; b: u64; }
@struct class Two { x: u256; m1: mapping<u256, u256>; m2: mapping<address, u64>; y: u256; }
@contract class C {
  @state s: Acct;
  @state mp: mapping<u256, Acct>;
  @state pk: Pk;
  @state tw: Two;
  @external setHead(v: u256): void { this.s.head = v; }
  @external setTail(v: u64): void { this.s.tail = v; }
  @external setBal(a: address, v: u256): void { this.s.bal[a] = v; }
  @external incBal(a: address, v: u256): void { this.s.bal[a] = this.s.bal[a] + v; }
  @external @view getHead(): u256 { return this.s.head; }
  @external @view getTail(): u64 { return this.s.tail; }
  @external @view getBal(a: address): u256 { return this.s.bal[a]; }
  // mapping value is a struct-with-mapping (nested)
  @external setMHead(k: u256, v: u256): void { this.mp[k].head = v; }
  @external setMBal(k: u256, a: address, v: u256): void { this.mp[k].bal[a] = v; }
  @external @view getMBal(k: u256, a: address): u256 { return this.mp[k].bal[a]; }
  @external @view getMHead(k: u256): u256 { return this.mp[k].head; }
  // packed neighbours around a mapping field
  @external setPk(a: u64, b: u64): void { this.pk.a = a; this.pk.b = b; }
  @external setPkM(k: u256, v: u256): void { this.pk.m[k] = v; }
  @external @view getPkA(): u64 { return this.pk.a; }
  @external @view getPkB(): u64 { return this.pk.b; }
  @external @view getPkM(k: u256): u256 { return this.pk.m[k]; }
  // two mapping fields with different key/value types
  @external setTwo(x: u256, y: u256): void { this.tw.x = x; this.tw.y = y; }
  @external setTwoM1(k: u256, v: u256): void { this.tw.m1[k] = v; }
  @external setTwoM2(a: address, v: u64): void { this.tw.m2[a] = v; }
  @external @view getTwoM1(k: u256): u256 { return this.tw.m1[k]; }
  @external @view getTwoM2(a: address): u64 { return this.tw.m2[a]; }
  @external @view getTwoX(): u256 { return this.tw.x; }
  @external @view getTwoY(): u256 { return this.tw.y; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Acct { uint256 head; mapping(address=>uint256) bal; uint64 tail; }
  struct Pk { uint64 a; mapping(uint256=>uint256) m; uint64 b; }
  struct Two { uint256 x; mapping(uint256=>uint256) m1; mapping(address=>uint64) m2; uint256 y; }
  Acct s; mapping(uint256=>Acct) mp; Pk pk; Two tw;
  function setHead(uint256 v) external { s.head = v; }
  function setTail(uint64 v) external { s.tail = v; }
  function setBal(address a, uint256 v) external { s.bal[a] = v; }
  function incBal(address a, uint256 v) external { s.bal[a] = s.bal[a] + v; }
  function getHead() external view returns (uint256){ return s.head; }
  function getTail() external view returns (uint64){ return s.tail; }
  function getBal(address a) external view returns (uint256){ return s.bal[a]; }
  function setMHead(uint256 k, uint256 v) external { mp[k].head = v; }
  function setMBal(uint256 k, address a, uint256 v) external { mp[k].bal[a] = v; }
  function getMBal(uint256 k, address a) external view returns (uint256){ return mp[k].bal[a]; }
  function getMHead(uint256 k) external view returns (uint256){ return mp[k].head; }
  function setPk(uint64 a, uint64 b) external { pk.a = a; pk.b = b; }
  function setPkM(uint256 k, uint256 v) external { pk.m[k] = v; }
  function getPkA() external view returns (uint64){ return pk.a; }
  function getPkB() external view returns (uint64){ return pk.b; }
  function getPkM(uint256 k) external view returns (uint256){ return pk.m[k]; }
  function setTwo(uint256 x, uint256 y) external { tw.x = x; tw.y = y; }
  function setTwoM1(uint256 k, uint256 v) external { tw.m1[k] = v; }
  function setTwoM2(address a, uint64 v) external { tw.m2[a] = v; }
  function getTwoM1(uint256 k) external view returns (uint256){ return tw.m1[k]; }
  function getTwoM2(address a) external view returns (uint64){ return tw.m2[a]; }
  function getTwoX() external view returns (uint256){ return tw.x; }
  function getTwoY() external view returns (uint256){ return tw.y; }
}`;

describe('mapping as a struct field (G7) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${j.exceptionError}`).toBe(s.success);
  }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), `slot ${label}`).toBe(await readSlot(sol, as, slot));
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  const A1 = 0x1111n,
    A2 = 0xbeefn;
  // Layout: s @ slots 0(head),1(bal base),2(tail);  mp @ slot 3;  pk @ 4(a),5(m base),6(b);  tw @ 7(x),8(m1),9(m2),10(y)
  it('struct with a mapping field: per-key set/get + raw slots', async () => {
    await send(encodeCall(sel('setHead(uint256)'), [12345n]));
    await send(encodeCall(sel('setTail(uint64)'), [0xabcdn]));
    await send(encodeCall(sel('setBal(address,uint256)'), [A1, 100n]));
    await send(encodeCall(sel('setBal(address,uint256)'), [A2, 999n]));
    await send(encodeCall(sel('incBal(address,uint256)'), [A1, 5n]));
    await eq('getHead', encodeCall(sel('getHead()'), []));
    await eq('getTail', encodeCall(sel('getTail()'), []));
    await eq('getBal(A1)', encodeCall(sel('getBal(address)'), [A1]));
    await eq('getBal(A2)', encodeCall(sel('getBal(address)'), [A2]));
    await eq('getBal(unset)', encodeCall(sel('getBal(address)'), [0xdead0000n]));
    // raw slots: head@0, tail@2, bal[A1]@keccak(A1.1), bal[A2]@keccak(A2.1)
    await eqSlot(0n, 's.head');
    await eqSlot(2n, 's.tail');
    await eqSlot(1n, 's.bal base (empty)');
    await eqSlot(mapSlot(A1, 1n), 's.bal[A1]');
    await eqSlot(mapSlot(A2, 1n), 's.bal[A2]');
  });
  it('mapping<K, struct-with-mapping>: nested, raw slots', async () => {
    await send(encodeCall(sel('setMHead(uint256,uint256)'), [7n, 42n]));
    await send(encodeCall(sel('setMBal(uint256,address,uint256)'), [7n, A1, 500n]));
    await send(encodeCall(sel('setMBal(uint256,address,uint256)'), [9n, A2, 600n]));
    await eq('getMHead(7)', encodeCall(sel('getMHead(uint256)'), [7n]));
    await eq('getMBal(7,A1)', encodeCall(sel('getMBal(uint256,address)'), [7n, A1]));
    await eq('getMBal(9,A2)', encodeCall(sel('getMBal(uint256,address)'), [9n, A2]));
    await eq('getMBal(9,A1) unset', encodeCall(sel('getMBal(uint256,address)'), [9n, A1]));
    // mp @ slot 3; mp[7] base = keccak(7.3); head at base; bal[A1] at keccak(A1 . base+1)
    const b7 = mapSlot(7n, 3n);
    await eqSlot(b7, 'mp[7].head');
    await eqSlot(mapSlot(A1, b7 + 1n), 'mp[7].bal[A1]');
    await eqSlot(mapSlot(A2, mapSlot(9n, 3n) + 1n), 'mp[9].bal[A2]');
  });
  it('packed neighbours around a mapping field (raw slots)', async () => {
    await send(encodeCall(sel('setPk(uint64,uint64)'), [0xaaaan, 0xbbbbn]));
    await send(encodeCall(sel('setPkM(uint256,uint256)'), [3n, 777n]));
    await eq('getPkA', encodeCall(sel('getPkA()'), []));
    await eq('getPkB', encodeCall(sel('getPkB()'), []));
    await eq('getPkM(3)', encodeCall(sel('getPkM(uint256)'), [3n]));
    // pk @ 4(a, offset 0), 5(m base), 6(b, offset 0)
    await eqSlot(4n, 'pk.a');
    await eqSlot(6n, 'pk.b');
    await eqSlot(mapSlot(3n, 5n), 'pk.m[3]');
  });
  it('two mapping fields with different key/value types (raw slots)', async () => {
    await send(encodeCall(sel('setTwo(uint256,uint256)'), [11n, 22n]));
    await send(encodeCall(sel('setTwoM1(uint256,uint256)'), [1n, 1000n]));
    await send(encodeCall(sel('setTwoM2(address,uint64)'), [A1, 0x99n]));
    await eq('getTwoX', encodeCall(sel('getTwoX()'), []));
    await eq('getTwoY', encodeCall(sel('getTwoY()'), []));
    await eq('getTwoM1(1)', encodeCall(sel('getTwoM1(uint256)'), [1n]));
    await eq('getTwoM2(A1)', encodeCall(sel('getTwoM2(address)'), [A1]));
    // tw @ 7(x), 8(m1 base), 9(m2 base), 10(y)
    await eqSlot(7n, 'tw.x');
    await eqSlot(10n, 'tw.y');
    await eqSlot(mapSlot(1n, 8n), 'tw.m1[1]');
    await eqSlot(mapSlot(A1, 9n), 'tw.m2[A1]');
  });
});

describe('mapping-in-struct gate parity (storage-only)', () => {
  function jethCodes(src: string): string[] | null {
    try {
      compile(src, { fileName: 'C.jeth' });
      return null;
    } catch (e) {
      if (e instanceof CompileError) return e.diagnostics.filter((d) => d.severity === 'error').map((d) => d.code);
      throw e;
    }
  }
  function solcRejects(src: string): boolean {
    try {
      compileSolidity('// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n' + src, 'C');
      return false;
    } catch {
      return true;
    }
  }
  const DECL = `@struct class S { head: u256; bal: mapping<address, u256>; }`;
  const SOLDECL = `contract C { struct S { uint256 head; mapping(address=>uint256) bal; }`;
  it('cannot RETURN a struct-with-mapping (JETH247, like solc)', () => {
    expect(jethCodes(`${DECL} @contract class C { @state s: S; @view f(): S { return this.s; } }`)).toContain(
      'JETH247',
    );
    expect(solcRejects(`${SOLDECL} S s; function f() external view returns (S memory){ return s; } }`)).toBe(true);
  });
  it('cannot take a struct-with-mapping PARAM (JETH247, like solc)', () => {
    expect(jethCodes(`${DECL} @contract class C { @external f(p: S): void { } }`)).toContain('JETH247');
    expect(solcRejects(`${SOLDECL} function f(S memory p) external {} }`)).toBe(true);
  });
  it('cannot CONSTRUCT a struct-with-mapping (JETH247, like solc)', () => {
    expect(
      jethCodes(`${DECL} @contract class C { @state s: S; @external f(): void { let x: S = S(1n); } }`),
    ).not.toBeNull();
    expect(solcRejects(`${SOLDECL} function f() external { S memory x = S(1); } }`)).toBe(true);
  });
  it('cannot whole-COPY a struct-with-mapping (JETH247, like solc)', () => {
    expect(
      jethCodes(`${DECL} @contract class C { @state s: S; @state t: S; @external f(): void { this.s = this.t; } }`),
    ).toContain('JETH247');
    expect(solcRejects(`${SOLDECL} S s; S t; function f() external { s = t; } }`)).toBe(true);
  });
});
