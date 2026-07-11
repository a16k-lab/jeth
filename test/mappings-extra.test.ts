// Nested mappings + narrow value types + non-address keys, differential vs Solidity
// (the allowance pattern, packed mapping values, uint/bytes keys).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const O = BigInt('0x' + 'aa'.repeat(20));
const S = BigInt('0x' + 'bb'.repeat(20));

function pad32(v: bigint): Uint8Array {
  return hexToBytes(('0x' + (v % (1n << 256n)).toString(16).padStart(64, '0')) as `0x${string}`);
}
function mapSlot(keyWord: bigint, baseSlot: bigint): bigint {
  const buf = new Uint8Array(64);
  buf.set(pad32(keyWord), 0);
  buf.set(pad32(baseSlot), 32);
  return BigInt('0x' + toHex(keccak(buf)));
}

const JETH = `class M {
  allowance: mapping<address, mapping<address, u256>>;
  flags: mapping<address, bool>;
  counts: mapping<u256, u8>;
  names: mapping<address, bytes4>;
  signed: mapping<u256, i16>;
  setAllow(o: address, s: address, v: u256): External<void> { this.allowance[o][s] = v; }
  incAllow(o: address, s: address, d: u256): External<void> { this.allowance[o][s] += d; }
  get getAllow(o: address, s: address): External<u256> { return this.allowance[o][s]; }
  setFlag(a: address, b: bool): External<void> { this.flags[a] = b; }
  get getFlag(a: address): External<bool> { return this.flags[a]; }
  setCount(k: u256, v: u8): External<void> { this.counts[k] = v; }
  get getCount(k: u256): External<u8> { return this.counts[k]; }
  setName(a: address, n: bytes4): External<void> { this.names[a] = n; }
  get getName(a: address): External<bytes4> { return this.names[a]; }
  setSigned(k: u256, v: i16): External<void> { this.signed[k] = v; }
  get getSigned(k: u256): External<i16> { return this.signed[k]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract M {
  mapping(address => mapping(address => uint256)) allowance;
  mapping(address => bool) flags;
  mapping(uint256 => uint8) counts;
  mapping(address => bytes4) names;
  mapping(uint256 => int16) signed;
  function setAllow(address o, address s, uint256 v) external { allowance[o][s] = v; }
  function incAllow(address o, address s, uint256 d) external { allowance[o][s] += d; }
  function getAllow(address o, address s) external view returns (uint256){ return allowance[o][s]; }
  function setFlag(address a, bool b) external { flags[a] = b; }
  function getFlag(address a) external view returns (bool){ return flags[a]; }
  function setCount(uint256 k, uint8 v) external { counts[k] = v; }
  function getCount(uint256 k) external view returns (uint8){ return counts[k]; }
  function setName(address a, bytes4 n) external { names[a] = n; }
  function getName(address a) external view returns (bytes4){ return names[a]; }
  function setSigned(uint256 k, int16 v) external { signed[k] = v; }
  function getSigned(uint256 k) external view returns (int16){ return signed[k]; }
}`;

describe('nested / narrow-value / non-address-key mappings vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'M.jeth' });
    const sb = compileSolidity(SOL, 'M');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('nested allowance[o][s] read/write/compound matches Solidity + raw slot', async () => {
    await both(encodeCall(functionSelector('setAllow(address,address,uint256)'), [O, S, 500n]));
    await both(encodeCall(functionSelector('incAllow(address,address,uint256)'), [O, S, 25n]));
    const r = await both(encodeCall(functionSelector('getAllow(address,address)'), [O, S]));
    expect(decodeUint(r.j.returnHex)).toBe(525n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    // nested slot = keccak(S . keccak(O . 0))
    const inner = mapSlot(O, 0n);
    const slot = mapSlot(S, inner);
    expect(await readSlot(jeth, aj, slot)).toBe(await readSlot(sol, as, slot));
    expect(decodeUint(await readSlot(jeth, aj, slot))).toBe(525n);
  });

  it('packs narrow mapping values (bool/uint8/bytes4/int16) like Solidity', async () => {
    const A = O;
    const cases: [string, bigint[], string][] = [
      ['setFlag(address,bool)', [A, 1n], 'getFlag(address)'],
      ['setCount(uint256,uint8)', [7n, 255n], 'getCount(uint256)'],
      ['setName(address,bytes4)', [A, BigInt('0xdeadbeef' + '00'.repeat(28))], 'getName(address)'],
      ['setSigned(uint256,int16)', [9n, -1234n & ((1n << 256n) - 1n)], 'getSigned(uint256)'],
    ];
    for (const [setSig, args, getSig] of cases) {
      await both(encodeCall(functionSelector(setSig), args));
      const key = setSig.startsWith('setFlag') || setSig.startsWith('setName') ? A : args[0]!;
      const baseSlot = setSig.startsWith('setFlag')
        ? 1n
        : setSig.startsWith('setCount')
          ? 2n
          : setSig.startsWith('setName')
            ? 3n
            : 4n;
      // raw slot byte-identical
      const slot = mapSlot(key, baseSlot);
      expect(await readSlot(jeth, aj, slot), `${setSig} raw slot`).toBe(await readSlot(sol, as, slot));
      // getter byte-identical
      const r = await both(encodeCall(functionSelector(getSig), [key]));
      expect(r.j.returnHex, `${getSig} getter`).toBe(r.s.returnHex);
    }
  });
});
