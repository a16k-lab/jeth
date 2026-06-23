// Phase 4c-2: fixed arrays Arr<T,N> byte-identical to Solidity — inline storage
// (whole-slot + packed, straddle-free), index/set/length, runtime Panic(0x32),
// and constant out-of-bounds as a compile error.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FixedArrays {
  uint256[3] u; uint256 sentinel; uint8[5] p; uint256 s2; uint96[5] w; uint256 s3;
  function fillU() external { u[0]=0xAA; u[1]=0xBB; u[2]=0xCC; sentinel=0xFF; }
  function getU(uint256 i) external view returns (uint256){ return u[i]; }
  function setU(uint256 i, uint256 v) external { u[i] = v; }
  function lenU() external view returns (uint256){ return u.length; }
  function fillP() external { p[0]=0x11; p[1]=0x22; p[2]=0x33; p[3]=0x44; p[4]=0x55; s2=0xFF; }
  function getP(uint256 i) external view returns (uint8){ return p[i]; }
  function fillW() external { w[0]=0x10; w[1]=0x11; w[2]=0x12; w[3]=0x13; w[4]=0x14; s3=0xFF; }
  function getW(uint256 i) external view returns (uint96){ return w[i]; }
}`;

function codesFor(source: string): string[] {
  try {
    compile(source, { fileName: 't.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}

describe('fixed arrays vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'FixedArrays.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'FixedArrays.jeth' });
    const sb = compileSolidity(SOL, 'FixedArrays');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('whole-slot Arr<u256,3>: raw slots, index, set, length, bounds', async () => {
    await both(encodeCall(sel('fillU()')));
    for (let i = 0; i < 3; i++) await eqSlot(BigInt(i), `u[${i}]`);
    await eqSlot(3n, 'sentinel');
    expect(decodeUint(await readSlot(jeth, aj, 3n))).toBe(0xffn);
    for (const i of [0n, 1n, 2n]) {
      const r = await both(encodeCall(sel('getU(uint256)'), [i]));
      expect(r.j.returnHex, `getU(${i})`).toBe(r.s.returnHex);
    }
    let r = await both(encodeCall(sel('lenU()')));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    // runtime OOB -> Panic 0x32
    r = await both(encodeCall(sel('getU(uint256)'), [5n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    expect(r.j.returnHex.endsWith('32')).toBe(true);
    // set + read back
    await both(encodeCall(sel('setU(uint256,uint256)'), [1n, 0x99n]));
    await eqSlot(1n, 'u[1] after set');
    r = await both(encodeCall(sel('setU(uint256,uint256)'), [3n, 1n])); // OOB write
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(r.s.returnHex);
  });

  it('packed Arr<u8,5> (one slot) raw bytes match', async () => {
    await both(encodeCall(sel('fillP()')));
    await eqSlot(4n, 'p packed slot');
    await eqSlot(5n, 's2');
    for (const i of [0n, 2n, 4n]) {
      const r = await both(encodeCall(sel('getP(uint256)'), [i]));
      expect(r.j.returnHex, `getP(${i})`).toBe(r.s.returnHex);
    }
    const r = await both(encodeCall(sel('getP(uint256)'), [5n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(r.s.returnHex);
  });

  it('packed Arr<u96,5> is straddle-free (2 per slot)', async () => {
    await both(encodeCall(sel('fillW()')));
    for (const slot of [6n, 7n, 8n]) await eqSlot(slot, `w slot ${slot}`);
    await eqSlot(9n, 's3');
    for (const i of [0n, 1n, 4n]) {
      const r = await both(encodeCall(sel('getW(uint256)'), [i]));
      expect(r.j.returnHex, `getW(${i})`).toBe(r.s.returnHex);
    }
  });

  it('rejects a constant out-of-bounds index at compile time (JETH211)', () => {
    const src = `@contract\nclass T { @state a: Arr<u256, 3>; @view f(): u256 { return this.a[3n]; } }`;
    expect(codesFor(src)).toContain('JETH211');
    // in-bounds constant compiles
    expect(codesFor(`@contract\nclass T { @state a: Arr<u256, 3>; @view f(): u256 { return this.a[2n]; } }`)).toEqual(
      [],
    );
    // push/pop on a fixed array is rejected
    expect(
      codesFor(`@contract\nclass T { @state a: Arr<u256, 3>; @external f(): void { this.a.push(1n); } }`),
    ).toContain('JETH218');
  });
});
