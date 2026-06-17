// Phase 4e-2c: nested struct construction Outer(p, Inner(a,b), q) flattened into
// packed slots, byte-identical to Solidity incl. raw slots (push + whole assign).
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
function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
const DATA0 = BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad32(0n)) as `0x${string}`))));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract NestedConstruct {
  struct Inner { uint128 a; uint128 b; }
  struct Outer { uint64 p; Inner inner; uint64 q; }
  Outer[] outers;
  Outer one;
  function addOuter(uint64 p, uint128 a, uint128 b, uint64 q) external { outers.push(Outer(p, Inner(a, b), q)); }
  function setOne(uint64 p, uint128 a, uint128 b, uint64 q) external { one = Outer(p, Inner(a, b), q); }
  function oP(uint256 i) external view returns (uint64){ return outers[i].p; }
  function oA(uint256 i) external view returns (uint128){ return outers[i].inner.a; }
  function oB(uint256 i) external view returns (uint128){ return outers[i].inner.b; }
  function oQ(uint256 i) external view returns (uint64){ return outers[i].q; }
  function oneA() external view returns (uint128){ return one.inner.a; }
  function oneQ() external view returns (uint64){ return one.q; }
}`;

describe('nested struct construction vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eqCall(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }
  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'NestedConstruct.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'NestedConstruct.jeth' });
    const sb = compileSolidity(SOL, 'NestedConstruct');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('push(Outer(p, Inner(a,b), q)) flattens into packed slots', async () => {
    await eqCall('addOuter#0', encodeCall(sel('addOuter(uint64,uint128,uint128,uint64)'), [11n, 0xaaaan, 0xbbbbn, 22n]));
    await eqCall('addOuter#1', encodeCall(sel('addOuter(uint64,uint128,uint128,uint64)'), [33n, 0xccccn, 0xddddn, 44n]));
    // Outer = 3 slots: slot0 p(u64), slot1 inner.a|inner.b, slot2 q(u64)
    for (let i = 0; i < 2; i++) {
      for (let s = 0; s < 3; s++) await eqSlot(DATA0 + BigInt(i) * 3n + BigInt(s), `outers[${i}].slot${s}`);
    }
    for (const i of [0n, 1n]) {
      for (const g of ['oP(uint256)', 'oA(uint256)', 'oB(uint256)', 'oQ(uint256)']) {
        await eqCall(`${g}@${i}`, encodeCall(sel(g), [i]));
      }
    }
    const r = await eqCall('oA@1', encodeCall(sel('oA(uint256)'), [1n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xccccn);
  });

  it('whole-struct assign this.one = Outer(p, Inner(a,b), q)', async () => {
    await eqCall('setOne', encodeCall(sel('setOne(uint64,uint128,uint128,uint64)'), [5n, 0x111n, 0x222n, 6n]));
    for (let s = 0; s < 3; s++) await eqSlot(1n + BigInt(s), `one.slot${s}`);
    let r = await eqCall('oneA', encodeCall(sel('oneA()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0x111n); // inner.a == a
    r = await eqCall('oneQ', encodeCall(sel('oneQ()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(6n);
  });
});
