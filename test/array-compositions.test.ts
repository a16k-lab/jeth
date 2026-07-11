// G6: storage array compositions - Arr<u256[],N> (uint256[][N], a fixed array of DYNAMIC arrays)
// and Arr<u256,N>[] (uint256[N][], a dynamic array of FIXED arrays). Byte-identical to solc on
// return values AND raw storage slots (layout interop).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const kc = (p: bigint) => BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(p)) as `0x${string}`)))); // keccak256(pad32(p))

const JETH = `class C {
  a: Arr<u256[], 2>;     // uint256[][2]: slots 0,1 (each an inner dyn-array length slot)
  b: Arr<u256, 2>[];     // uint256[2][]: slot 2 length; element i = uint256[2] at keccak(2)+i*2
  pk: Arr<u8, 4>[];      // uint8[4][]: packed fixed element (1 slot each)
  pushA(i: u256, v: u256): External<void> { this.a[i].push(v); }
  setA(i: u256, j: u256, v: u256): External<void> { this.a[i][j] = v; }
  get getA(i: u256, j: u256): External<u256> { return this.a[i][j]; }
  get lenA(i: u256): External<u256> { return this.a[i].length; }
  pushB(): External<void> { this.b.push(); }
  popB(): External<void> { this.b.pop(); }
  setB(i: u256, j: u256, v: u256): External<void> { this.b[i][j] = v; }
  get getB(i: u256, j: u256): External<u256> { return this.b[i][j]; }
  get lenB(): External<u256> { return this.b.length; }
  pushPk(): External<void> { this.pk.push(); }
  setPk(i: u256, j: u256, v: u8): External<void> { this.pk[i][j] = v; }
  get getPk(i: u256, j: u256): External<u8> { return this.pk[i][j]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[][2] a;
  uint256[2][] b;
  uint8[4][] pk;
  function pushA(uint256 i, uint256 v) external { a[i].push(v); }
  function setA(uint256 i, uint256 j, uint256 v) external { a[i][j] = v; }
  function getA(uint256 i, uint256 j) external view returns (uint256){ return a[i][j]; }
  function lenA(uint256 i) external view returns (uint256){ return a[i].length; }
  function pushB() external { b.push(); }
  function popB() external { b.pop(); }
  function setB(uint256 i, uint256 j, uint256 v) external { b[i][j] = v; }
  function getB(uint256 i, uint256 j) external view returns (uint256){ return b[i][j]; }
  function lenB() external view returns (uint256){ return b.length; }
  function pushPk() external { pk.push(); }
  function setPk(uint256 i, uint256 j, uint8 v) external { pk[i][j] = v; }
  function getPk(uint256 i, uint256 j) external view returns (uint8){ return pk[i][j]; }
}`;

describe('storage array compositions (G6) vs Solidity', () => {
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

  it('Arr<u256[],2> (uint256[][2]): per-row push/index + raw slots', async () => {
    for (const v of [11n, 12n, 13n]) await send(encodeCall(sel('pushA(uint256,uint256)'), [0n, v]));
    for (const v of [21n, 22n]) await send(encodeCall(sel('pushA(uint256,uint256)'), [1n, v]));
    await send(encodeCall(sel('setA(uint256,uint256,uint256)'), [0n, 1n, 99n]));
    await eq('lenA(0)', encodeCall(sel('lenA(uint256)'), [0n]));
    await eq('lenA(1)', encodeCall(sel('lenA(uint256)'), [1n]));
    await eq('getA(0,1)', encodeCall(sel('getA(uint256,uint256)'), [0n, 1n]));
    await eq('getA(1,1)', encodeCall(sel('getA(uint256,uint256)'), [1n, 1n]));
    // raw slots: a[0].length@0, a[1].length@1; a[0][2]@keccak(0)+2; a[1][0]@keccak(1)
    await eqSlot(0n, 'a[0].length');
    await eqSlot(1n, 'a[1].length');
    await eqSlot(kc(0n) + 2n, 'a[0][2]');
    await eqSlot(kc(1n) + 0n, 'a[1][0]');
  });
  it('Arr<u256,2>[] (uint256[2][]): push/index + raw slots', async () => {
    await send(encodeCall(sel('pushB()'), []));
    await send(encodeCall(sel('pushB()'), []));
    await send(encodeCall(sel('pushB()'), []));
    for (const [i, j, v] of [
      [0n, 0n, 100n],
      [0n, 1n, 101n],
      [1n, 0n, 110n],
      [2n, 1n, 121n],
    ] as [bigint, bigint, bigint][])
      await send(encodeCall(sel('setB(uint256,uint256,uint256)'), [i, j, v]));
    await eq('lenB', encodeCall(sel('lenB()'), []));
    await eq('getB(0,1)', encodeCall(sel('getB(uint256,uint256)'), [0n, 1n]));
    await eq('getB(2,1)', encodeCall(sel('getB(uint256,uint256)'), [2n, 1n]));
    // b@slot2: length@2; element i = uint256[2] at keccak(2)+i*2; b[i][j] at keccak(2)+i*2+j
    await eqSlot(2n, 'b.length');
    await eqSlot(kc(2n) + 0n, 'b[0][0]');
    await eqSlot(kc(2n) + 1n, 'b[0][1]');
    await eqSlot(kc(2n) + 2n, 'b[1][0]');
    await eqSlot(kc(2n) + 5n, 'b[2][1]');
  });
  it('Arr<u256,2>[] pop() zeroes ALL slots of the freed multi-slot element', async () => {
    // b has length 3 from the prior block (indices 0,1,2). Fill the LAST element b[2], pop it
    // (frees its 2 slots at keccak(2)+4 and +5), then push (re-adds b[2]): it must read all-zero.
    // The pre-G6-fix bug left one slot stale; jeth-vs-solc differential catches it either way.
    await send(encodeCall(sel('setB(uint256,uint256,uint256)'), [2n, 0n, 0xaaaan]));
    await send(encodeCall(sel('setB(uint256,uint256,uint256)'), [2n, 1n, 0xbbbbn]));
    await send(encodeCall(sel('popB()'), []));
    await send(encodeCall(sel('pushB()'), []));
    await eq('getB(2,0) after pop+push (must be 0)', encodeCall(sel('getB(uint256,uint256)'), [2n, 0n]));
    await eq('getB(2,1) after pop+push (must be 0)', encodeCall(sel('getB(uint256,uint256)'), [2n, 1n]));
    await eq('lenB after pop+push', encodeCall(sel('lenB()'), []));
    await eqSlot(kc(2n) + 4n, 'freed b[2][0] cleared');
    await eqSlot(kc(2n) + 5n, 'freed b[2][1] cleared');
  });
  it('Arr<u8,4>[] (uint8[4][]): packed fixed element + raw slots', async () => {
    await send(encodeCall(sel('pushPk()'), []));
    await send(encodeCall(sel('pushPk()'), []));
    for (const [i, j, v] of [
      [0n, 0n, 1n],
      [0n, 3n, 4n],
      [1n, 1n, 9n],
      [1n, 2n, 200n],
    ] as [bigint, bigint, bigint][])
      await send(encodeCall(sel('setPk(uint256,uint256,uint8)'), [i, j, v]));
    await eq('getPk(0,0)', encodeCall(sel('getPk(uint256,uint256)'), [0n, 0n]));
    await eq('getPk(0,3)', encodeCall(sel('getPk(uint256,uint256)'), [0n, 3n]));
    await eq('getPk(1,2)', encodeCall(sel('getPk(uint256,uint256)'), [1n, 2n]));
    // pk@slot3: length@3; element i = uint8[4] packed in 1 slot at keccak(3)+i
    await eqSlot(3n, 'pk.length');
    await eqSlot(kc(3n) + 0n, 'pk[0] packed');
    await eqSlot(kc(3n) + 1n, 'pk[1] packed');
  });
});
