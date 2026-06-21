// Phase 4e-3: returning a whole storage struct array byte-identical to Solidity
// (head/tail encode, packed-storage -> unpacked-ABI transcoding).
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const A1 = BigInt('0x' + '11'.repeat(20));
const A2 = BigInt('0x' + '22'.repeat(20));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract RetStructArray {
  struct Rec { uint64 id; address owner; uint128 amount; bool active; }
  struct Pt { uint256 x; uint256 y; }
  Rec[] recs;
  Pt[] pts;
  function addRec(uint64 id, address owner, uint128 amount, bool active) external { recs.push(Rec(id, owner, amount, active)); }
  function addPt(uint256 x, uint256 y) external { pts.push(Pt(x, y)); }
  function allRecs() external view returns (Rec[] memory){ return recs; }
  function allPts() external view returns (Pt[] memory){ return pts; }
  function recCount() external view returns (uint256){ return recs.length; }
}`;

describe('returning a storage struct array vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eqCall(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }
  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'RetStructArray.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'RetStructArray.jeth' });
    const sb = compileSolidity(SOL, 'RetStructArray');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('returns Rec[] (packed fields) byte-identical', async () => {
    await eqCall('empty allRecs', encodeCall(sel('allRecs()'), []));
    await eqCall('addRec#0', encodeCall(sel('addRec(uint64,address,uint128,bool)'), [10n, A1, 1000n, 1n]));
    await eqCall('addRec#1', encodeCall(sel('addRec(uint64,address,uint128,bool)'), [20n, A2, 2000n, 0n]));
    await eqCall('addRec#2', encodeCall(sel('addRec(uint64,address,uint128,bool)'), [30n, A1, 3000n, 1n]));
    const r = await eqCall('allRecs n=3', encodeCall(sel('allRecs()'), []));
    // sanity: ABI envelope [0x20][3][...], 3*4 = 12 element words
    expect(r.j.returnHex.length).toBe(2 + 2 * 32 * (2 + 12)); // 0x + (head+len+12 words)*64 hex
  });

  it('returns Pt[] (whole-slot fields) byte-identical', async () => {
    await eqCall('addPt#0', encodeCall(sel('addPt(uint256,uint256)'), [(1n << 200n) | 7n, 8n]));
    await eqCall('addPt#1', encodeCall(sel('addPt(uint256,uint256)'), [0n, (1n << 255n)]));
    await eqCall('allPts n=2', encodeCall(sel('allPts()'), []));
  });
});
