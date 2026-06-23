// Phase 4b: dynamic arrays T[] byte-identical to Solidity — storage (whole-slot +
// packed + unpacked-address), push/pop/length/index/set with Panic codes, calldata
// decode, and ABI return encode. Raw slots compared via readSlot.
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
const ADDR1 = BigInt('0x' + 'aa'.repeat(20));
const ADDR2 = BigInt('0x' + 'bb'.repeat(20));

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
function dataBase(slot: bigint): bigint {
  return BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad32(slot)) as `0x${string}`))));
}
/** ABI-encode a single T[] arg: selector + [0x20][len][elem words]. */
function encArr(sig: string, elems: bigint[]): string {
  return '0x' + functionSelector(sig) + pad32(0x20n) + pad32(BigInt(elems.length)) + elems.map(pad32).join('');
}

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Arrays {
  uint256[] u; uint8[] p; bool[] b; address[] adr;
  function pushU(uint256 v) external { u.push(v); }
  function lenU() external view returns (uint256){ return u.length; }
  function getU(uint256 i) external view returns (uint256){ return u[i]; }
  function setU(uint256 i, uint256 v) external { u[i] = v; }
  function popU() external { u.pop(); }
  function pushP(uint8 v) external { p.push(v); }
  function getP(uint256 i) external view returns (uint8){ return p[i]; }
  function lenP() external view returns (uint256){ return p.length; }
  function popP() external { p.pop(); }
  function pushB(bool v) external { b.push(v); }
  function getB(uint256 i) external view returns (bool){ return b[i]; }
  function pushAdr(address v) external { adr.push(v); }
  function getAdr(uint256 i) external view returns (address){ return adr[i]; }
  function mk() external pure returns (uint256[] memory){ uint256[] memory a = new uint256[](3); a[0]=0xaa; a[1]=0xbb; a[2]=0xcc; return a; }
  function echoU(uint256[] calldata x) external pure returns (uint256[] memory){ return x; }
  function empty() external pure returns (uint256[] memory){ return new uint256[](0); }
  function sum(uint256[] calldata x) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<x.length;i+=1){ s+=x[i]; } return s; }
  function echoP(uint8[] calldata x) external pure returns (uint8[] memory){ return x; }
  function echoAdr(address[] calldata x) external pure returns (address[] memory){ return x; }
  function mix(uint256 k, uint256[] calldata x) external pure returns (uint256){ return k + x.length; }
  function echoStoreU() external view returns (uint256[] memory){ return u; }
}`;

describe('dynamic arrays vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'Arrays.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'Arrays.jeth' });
    const sb = compileSolidity(SOL, 'Arrays');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('u256[] push/length/index/set + raw slots, with Panic parity', async () => {
    for (const v of [0x1111n, 0x2222n, 0x3333n]) await both(encodeCall(sel('pushU(uint256)'), [v]));
    await eqSlot(0n, 'u len');
    const base = dataBase(0n);
    for (let i = 0; i < 3; i++) await eqSlot(base + BigInt(i), `u[${i}]`);
    let r = await both(encodeCall(sel('getU(uint256)'), [1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0x2222n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    // OOB read + write -> Panic 0x32
    const oob: { sig: string; args: bigint[] }[] = [
      { sig: 'getU(uint256)', args: [3n] },
      { sig: 'setU(uint256,uint256)', args: [3n, 9n] },
    ];
    for (const fn of oob) {
      r = await both(encodeCall(sel(fn.sig), fn.args));
      expect(r.j.success).toBe(false);
      expect(r.j.returnHex).toBe(r.s.returnHex);
      expect(r.j.returnHex.slice(0, 10)).toBe('0x4e487b71');
      expect(r.j.returnHex.endsWith('32')).toBe(true);
    }
    // set then read
    await both(encodeCall(sel('setU(uint256,uint256)'), [1n, 0x99n]));
    await eqSlot(base + 1n, 'u[1] after set');
  });

  it('pop zeroes the freed slot; pop-empty -> Panic 0x31', async () => {
    await both(encodeCall(sel('popU()'))); // len 3 -> 2
    await eqSlot(0n, 'u len after pop');
    await eqSlot(dataBase(0n) + 2n, 'u[2] freed slot');
    await both(encodeCall(sel('popU()')));
    await both(encodeCall(sel('popU()'))); // now empty
    const r = await both(encodeCall(sel('popU()'))); // pop empty
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    expect(r.j.returnHex.endsWith('31')).toBe(true); // Panic 0x31
  });

  it('packs uint8[] (32/slot) and bool[] like Solidity (raw slots)', async () => {
    for (let i = 1; i <= 35; i++) await both(encodeCall(sel('pushP(uint8)'), [BigInt(i)]));
    await eqSlot(1n, 'p len');
    await eqSlot(dataBase(1n), 'p slot0 (elems 0..31 packed)');
    await eqSlot(dataBase(1n) + 1n, 'p slot1 (elems 32..34)');
    let r = await both(encodeCall(sel('getP(uint256)'), [33n]));
    expect(decodeUint(r.j.returnHex)).toBe(34n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    // pop a packed element clears just its byte(s)
    await both(encodeCall(sel('popP()')));
    await eqSlot(dataBase(1n) + 1n, 'p slot1 after pop');
    // bool[]
    for (const v of [1n, 0n, 1n]) await both(encodeCall(sel('pushB(bool)'), [v]));
    await eqSlot(2n, 'b len');
    await eqSlot(dataBase(2n), 'b slot0 packed');
    r = await both(encodeCall(sel('getB(uint256)'), [2n]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
  });

  it('address[] is unpacked (1/slot), raw slots match', async () => {
    for (const a of [ADDR1, ADDR2]) await both(encodeCall(sel('pushAdr(address)'), [a]));
    await eqSlot(3n, 'adr len');
    await eqSlot(dataBase(3n), 'adr[0]');
    await eqSlot(dataBase(3n) + 1n, 'adr[1]');
    const r = await both(encodeCall(sel('getAdr(uint256)'), [1n]));
    expect(r.j.returnHex).toBe(r.s.returnHex);
  });

  it('encodes/decodes array ABI byte-identically (mk/echo/empty/sum/mix)', async () => {
    const cases: [string, string][] = [
      [encodeCall(sel('mk()')), 'mk'],
      [encArr('echoU(uint256[])', [0x11n, 0x22n, 0x33n]), 'echoU'],
      [encArr('echoU(uint256[])', []), 'echoU empty'],
      [encodeCall(sel('empty()')), 'empty'],
      [encArr('sum(uint256[])', [5n, 7n, 9n]), 'sum'],
      [encArr('echoP(uint8[])', [1n, 2n, 3n]), 'echoP (unpacked words)'],
      [encArr('echoAdr(address[])', [ADDR1, ADDR2]), 'echoAdr'],
      [encodeCall(sel('echoStoreU()')), 'echoStoreU'],
    ];
    for (const [data, label] of cases) {
      const r = await both(data);
      expect(r.j.success, `${label} success (err=${r.j.exceptionError})`).toBe(r.s.success);
      expect(r.j.returnHex, `${label} returndata`).toBe(r.s.returnHex);
    }
    // mixed static+dynamic args
    const mixData =
      '0x' +
      functionSelector('mix(uint256,uint256[])') +
      pad32(100n) +
      pad32(0x40n) +
      pad32(2n) +
      pad32(1n) +
      pad32(2n);
    const r = await both(mixData);
    expect(decodeUint(r.j.returnHex)).toBe(102n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
  });

  it('matches Solidity on adversarial array calldata', async () => {
    const s4 = functionSelector('echoU(uint256[])');
    const cases = [
      '0x' + s4 + pad32(0x1000n), // offset past calldata -> revert
      '0x' + s4 + pad32(0x20n) + pad32(1n << 200n) + pad32(1n), // huge length -> revert
      '0x' + s4 + pad32(0x20n) + pad32(5n) + pad32(1n), // length says 5 but tail truncated -> revert
    ];
    for (const data of cases) {
      const r = await both(data);
      expect(r.j.success).toBe(r.s.success);
      expect(r.j.returnHex).toBe(r.s.returnHex);
    }
  });
});
