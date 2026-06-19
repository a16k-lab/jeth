// JETH226 lift: in-place assignment of a WHOLE fixed-array element, `this.dd[i] = <array>`, where the
// element is itself a fixed array (e.g. uint256[2][2], or uint256[2][] dynamic-outer). The static
// aggregate is copied into the element's base slot (array literal -> writeArrayLit, storage source ->
// copyFixedArray), same source set as the whole-array `this.g = src`. Byte-identical to solc on raw
// storage slots + returndata + OOB Panic 0x32.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

describe('whole fixed-array-element assign (JETH226) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `@contract class C {
    @state dd: Arr<Arr<u256,2>,2>;
    @state src: Arr<u256,2>;
    @state ee: Arr<u256,2>[];
    @external setDD(i: u256, a: u256, b: u256): void { this.dd[i] = [a, b]; }
    @external setSrc(a: u256, b: u256): void { this.src = [a, b]; }
    @external copyToDD(i: u256): void { this.dd[i] = this.src; }
    @external pushEE(a: u256, b: u256): void { this.ee.push([a, b]); }
    @external setEE(i: u256, a: u256, b: u256): void { this.ee[i] = [a, b]; }
    @external @view get(i: u256, j: u256): u256 { return this.dd[i][j]; }
    @external @view getEE(i: u256, j: u256): u256 { return this.ee[i][j]; } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  uint256[2][2] dd;
  uint256[2] src;
  uint256[2][] ee;
  function setDD(uint256 i, uint256 a, uint256 b) external { dd[i] = [a, b]; }
  function setSrc(uint256 a, uint256 b) external { src = [a, b]; }
  function copyToDD(uint256 i) external { dd[i] = src; }
  function pushEE(uint256 a, uint256 b) external { ee.push([a, b]); }
  function setEE(uint256 i, uint256 a, uint256 b) external { ee[i] = [a, b]; }
  function get(uint256 i, uint256 j) external view returns (uint256) { return dd[i][j]; }
  function getEE(uint256 i, uint256 j) external view returns (uint256) { return ee[i][j]; } }`;

  beforeAll(async () => {
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });

  const both = async (data: string) => [await jeth.call(aj, data), await sol.call(as, data)] as const;

  it('literal-source element assign: raw slots + reads match solc', async () => {
    for (const [i, a, b] of [[0n, 7n, 8n], [1n, 9n, 10n], [0n, 111n, 222n]] as const) {
      const [j, s] = await both('0x' + sel('setDD(uint256,uint256,uint256)') + pad32(i) + pad32(a) + pad32(b));
      expect(j.success).toBe(s.success);
    }
    for (const slot of [0n, 1n, 2n, 3n]) expect(await readSlot(jeth, aj, slot), `slot ${slot}`).toBe(await readSlot(sol, as, slot));
    for (const [i, jx] of [[0n, 0n], [0n, 1n], [1n, 0n], [1n, 1n]] as const) {
      const [j, s] = await both('0x' + sel('get(uint256,uint256)') + pad32(i) + pad32(jx));
      expect(j.returnHex).toBe(s.returnHex);
    }
  });
  it('storage-source element assign (this.dd[i] = this.src): raw slots match solc', async () => {
    await both('0x' + sel('setSrc(uint256,uint256)') + pad32(333n) + pad32(444n));
    await both('0x' + sel('copyToDD(uint256)') + pad32(1n));
    for (const slot of [0n, 1n, 2n, 3n, 4n, 5n]) expect(await readSlot(jeth, aj, slot), `slot ${slot}`).toBe(await readSlot(sol, as, slot));
  });
  it('OOB element assign reverts Panic 0x32, matching solc', async () => {
    const [j, s] = await both('0x' + sel('setDD(uint256,uint256,uint256)') + pad32(2n) + pad32(1n) + pad32(2n));
    expect(j.success).toBe(s.success);
    expect(j.returnHex).toBe(s.returnHex);
  });
  it('dynamic-outer fixed-inner (uint256[2][]) element assign: reads + slots match solc', async () => {
    await both('0x' + sel('pushEE(uint256,uint256)') + pad32(1n) + pad32(2n));
    await both('0x' + sel('pushEE(uint256,uint256)') + pad32(3n) + pad32(4n));
    await both('0x' + sel('setEE(uint256,uint256,uint256)') + pad32(1n) + pad32(55n) + pad32(66n));
    for (const [i, jx] of [[0n, 0n], [0n, 1n], [1n, 0n], [1n, 1n]] as const) {
      const [j, s] = await both('0x' + sel('getEE(uint256,uint256)') + pad32(i) + pad32(jx));
      expect(j.returnHex, `ee[${i}][${jx}]`).toBe(s.returnHex);
    }
    // ee length slot (ee is the 3rd state var: dd=slots0-3, src=4-5, ee=slot6)
    expect(await readSlot(jeth, aj, 6n)).toBe(await readSlot(sol, as, 6n));
  });
});

// Regression for a PRE-EXISTING miscompile this work uncovered: `Arr<T,N>[].push([...])` (a fixed-array
// element pushed onto a dynamic array) wrote a dynamic-array layout into the element slot instead of the
// N inline words. Now byte-identical to solc, incl. packed (<256-bit) elements.
describe('push of a fixed-array element onto a dynamic array (pre-existing fix) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `@contract class C { @state ee: Arr<u8,4>[]; @state src: Arr<u8,4>;
    @external pushLit(a: u8, b: u8, c: u8, d: u8): void { this.ee.push([a, b, c, d]); }
    @external setSrc(a: u8, b: u8, c: u8, d: u8): void { this.src = [a, b, c, d]; }
    @external pushSrc(): void { this.ee.push(this.src); }
    @external @view get(i: u256, j: u256): u8 { return this.ee[i][j]; } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C { uint8[4][] ee; uint8[4] src;
  function pushLit(uint8 a, uint8 b, uint8 c, uint8 d) external { ee.push([a, b, c, d]); }
  function setSrc(uint8 a, uint8 b, uint8 c, uint8 d) external { src = [a, b, c, d]; }
  function pushSrc() external { ee.push(src); }
  function get(uint256 i, uint256 j) external view returns (uint8) { return ee[i][j]; } }`;
  beforeAll(async () => {
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });
  it('packed uint8[4][] push(literal) + push(storage src) + read are byte-identical', async () => {
    const run = async (d: string) => { await jeth.call(aj, d); await sol.call(as, d); };
    await run('0x' + sel('pushLit(uint8,uint8,uint8,uint8)') + pad32(10n) + pad32(20n) + pad32(30n) + pad32(40n));
    await run('0x' + sel('setSrc(uint8,uint8,uint8,uint8)') + pad32(50n) + pad32(60n) + pad32(70n) + pad32(80n));
    await run('0x' + sel('pushSrc()'));
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 4n; j++) {
      const data = '0x' + sel('get(uint256,uint256)') + pad32(i) + pad32(j);
      expect((await jeth.call(aj, data)).returnHex, `ee[${i}][${j}]`).toBe((await sol.call(as, data)).returnHex);
    }
    expect(await readSlot(jeth, aj, 0n)).toBe(await readSlot(sol, as, 0n)); // ee length
  });
});
