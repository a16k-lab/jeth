// Closes the gap from the Phase 3 verification's crashed mapping-slots dimension:
// directly differential-tests the key/value/nesting combos not covered elsewhere
// (signed keys sign-extended, bytesN keys left-aligned, bool keys, 3-level nesting,
// edge key values, adjacent mappings) against Solidity, incl. raw slots.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const U256_MAX = (1n << 256n) - 1n;
const I256_MIN = -(1n << 255n);
const B4 = BigInt('0xdeadbeef' + '00'.repeat(28)); // bytes4 left-aligned register word

function pad32(v: bigint): Uint8Array {
  return hexToBytes(
    ('0x' + (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0')) as `0x${string}`,
  );
}
function mapSlot(keyWord: bigint, baseSlot: bigint): bigint {
  const buf = new Uint8Array(64);
  buf.set(pad32(keyWord), 0);
  buf.set(pad32(baseSlot), 32);
  return BigInt('0x' + toHex(keccak(buf)));
}

const JETH = `class K {
  si: mapping<i256, u256>;
  b4: mapping<bytes4, u256>;
  bl: mapping<bool, u256>;
  deep: mapping<u256, mapping<u256, mapping<u256, u256>>>;
  edge: mapping<u256, u256>;
  adj0: mapping<u256, u256>;
  adj1: mapping<u256, u256>;
  setSi(k: i256, v: u256): External<void> { this.si[k] = v; }
  get getSi(k: i256): External<u256> { return this.si[k]; }
  setB4(k: bytes4, v: u256): External<void> { this.b4[k] = v; }
  get getB4(k: bytes4): External<u256> { return this.b4[k]; }
  setBl(k: bool, v: u256): External<void> { this.bl[k] = v; }
  get getBl(k: bool): External<u256> { return this.bl[k]; }
  setDeep(a: u256, b: u256, c: u256, v: u256): External<void> { this.deep[a][b][c] = v; }
  get getDeep(a: u256, b: u256, c: u256): External<u256> { return this.deep[a][b][c]; }
  setEdge(k: u256, v: u256): External<void> { this.edge[k] = v; }
  get getEdge(k: u256): External<u256> { return this.edge[k]; }
  setAdj(v0: u256, v1: u256): External<void> { this.adj0[0n] = v0; this.adj1[0n] = v1; }
  get getAdj0(): External<u256> { return this.adj0[0n]; }
  get getAdj1(): External<u256> { return this.adj1[0n]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract K {
  mapping(int256 => uint256) si;
  mapping(bytes4 => uint256) b4;
  mapping(bool => uint256) bl;
  mapping(uint256 => mapping(uint256 => mapping(uint256 => uint256))) deep;
  mapping(uint256 => uint256) edge;
  mapping(uint256 => uint256) adj0;
  mapping(uint256 => uint256) adj1;
  function setSi(int256 k, uint256 v) external { si[k] = v; }
  function getSi(int256 k) external view returns (uint256){ return si[k]; }
  function setB4(bytes4 k, uint256 v) external { b4[k] = v; }
  function getB4(bytes4 k) external view returns (uint256){ return b4[k]; }
  function setBl(bool k, uint256 v) external { bl[k] = v; }
  function getBl(bool k) external view returns (uint256){ return bl[k]; }
  function setDeep(uint256 a, uint256 b, uint256 c, uint256 v) external { deep[a][b][c] = v; }
  function getDeep(uint256 a, uint256 b, uint256 c) external view returns (uint256){ return deep[a][b][c]; }
  function setEdge(uint256 k, uint256 v) external { edge[k] = v; }
  function getEdge(uint256 k) external view returns (uint256){ return edge[k]; }
  function setAdj(uint256 v0, uint256 v1) external { adj0[0] = v0; adj1[0] = v1; }
  function getAdj0() external view returns (uint256){ return adj0[0]; }
  function getAdj1() external view returns (uint256){ return adj1[0]; }
}`;

describe('mapping key/value/nesting edge cases vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  const sel = (s: string) => functionSelector(s);

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'K.jeth' });
    const sb = compileSolidity(SOL, 'K');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('sign-extends signed keys (slot byte-identical)', async () => {
    for (const k of [-1n, I256_MIN, 7n]) {
      await both(encodeCall(sel('setSi(int256,uint256)'), [k, 42n + (k & 0xffn)]));
      const r = await both(encodeCall(sel('getSi(int256)'), [k]));
      expect(r.j.returnHex, `getSi(${k})`).toBe(r.s.returnHex);
      const slot = mapSlot(k, 0n); // key word is the sign-extended value
      expect(await readSlot(jeth, aj, slot)).toBe(await readSlot(sol, as, slot));
    }
  });

  it('left-aligns bytesN keys and handles bool keys', async () => {
    await both(encodeCall(sel('setB4(bytes4,uint256)'), [B4, 123n]));
    let r = await both(encodeCall(sel('getB4(bytes4)'), [B4]));
    expect(r.j.returnHex).toBe(r.s.returnHex);
    expect(await readSlot(jeth, aj, mapSlot(B4, 1n))).toBe(await readSlot(sol, as, mapSlot(B4, 1n)));

    await both(encodeCall(sel('setBl(bool,uint256)'), [1n, 7n]));
    await both(encodeCall(sel('setBl(bool,uint256)'), [0n, 9n]));
    r = await both(encodeCall(sel('getBl(bool)'), [1n]));
    expect(decodeUint(r.j.returnHex)).toBe(7n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    expect(await readSlot(jeth, aj, mapSlot(1n, 2n))).toBe(await readSlot(sol, as, mapSlot(1n, 2n)));
  });

  it('derives 3-level nested slots identically', async () => {
    await both(encodeCall(sel('setDeep(uint256,uint256,uint256,uint256)'), [1n, 2n, 3n, 777n]));
    const r = await both(encodeCall(sel('getDeep(uint256,uint256,uint256)'), [1n, 2n, 3n]));
    expect(decodeUint(r.j.returnHex)).toBe(777n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    const slot = mapSlot(3n, mapSlot(2n, mapSlot(1n, 3n)));
    expect(await readSlot(jeth, aj, slot)).toBe(await readSlot(sol, as, slot));
  });

  it('handles edge key values and adjacent mappings without collision', async () => {
    for (const k of [0n, U256_MAX]) {
      await both(encodeCall(sel('setEdge(uint256,uint256)'), [k, k === 0n ? 11n : 22n]));
      const r = await both(encodeCall(sel('getEdge(uint256)'), [k]));
      expect(r.j.returnHex, `getEdge(${k})`).toBe(r.s.returnHex);
    }
    await both(encodeCall(sel('setAdj(uint256,uint256)'), [100n, 200n]));
    const r0 = await both(encodeCall(sel('getAdj0()')));
    const r1 = await both(encodeCall(sel('getAdj1()')));
    expect(decodeUint(r0.j.returnHex)).toBe(100n);
    expect(decodeUint(r1.j.returnHex)).toBe(200n);
    expect(r0.j.returnHex).toBe(r0.s.returnHex);
    expect(r1.j.returnHex).toBe(r1.s.returnHex);
  });
});
