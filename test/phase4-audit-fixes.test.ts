// Regression tests for divergences the Phase 4 full audit confirmed and we fixed:
//  B1 (HIGH): T[][] echo must VALIDATE dirty narrow inner elements (revert EMPTY),
//             not clean them - solc fully decodes + validates each inner array.
//  B5 (LOW):  `.length` of a fixed-array field of a calldata aggregate param is a
//             compile-time constant (was over-rejected with JETH230).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

describe('Phase 4 audit fix B1: T[][] echo validates dirty inner elements', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = functionSelector('echo8(uint8[][])');
  const JETH = `class Aud { get echo8(m: u8[][]): External<u8[][]> { return m; } }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Aud { function echo8(uint8[][] calldata m) external pure returns (uint8[][] memory){ return m; } }`;
  // single inner array [[v]]: outer off 0x20, outer_len 1, off0 0x20, inner_len 1, v
  const oneElem = (v: bigint) => '0x' + sel + pad(0x20n) + pad(1n) + pad(0x20n) + pad(1n) + pad(v);

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'Aud.jeth' });
    const sb = compileSolidity(SOL, 'Aud');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  it('clean inner element echoes byte-identically', async () => {
    const r = await eq('clean [[42]]', oneElem(42n));
    expect(r.j.success).toBe(true);
  });
  it('dirty inner element (256 > uint8 max) reverts EMPTY, matching solc', async () => {
    const r = await eq('dirty [[256]]', oneElem(256n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });
  it('dirty in a longer inner array also reverts', async () => {
    // [[1, 300]]: outer off 0x20, len 1, off0 0x20, inner_len 2, [1, 300]
    const data = '0x' + sel + pad(0x20n) + pad(1n) + pad(0x20n) + pad(2n) + pad(1n) + pad(300n);
    const r = await eq('dirty [[1,300]]', data);
    expect(r.j.success).toBe(false);
  });
});

describe('Phase 4 audit fix B5: .length of a fixed-array field of a calldata struct param', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = functionSelector('dlen((uint64,uint256[3]))');
  const JETH = `type S = { id: u64; data: Arr<u256,3>; };
class A { get dlen(s: S): External<u256> { return s.data.length; } }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A { struct S { uint64 id; uint256[3] data; } function dlen(S calldata s) external pure returns(uint256){ return s.data.length; } }`;

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'A.jeth' }); // must compile (was JETH230 over-rejection)
    const sb = compileSolidity(SOL, 'A');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('returns the constant length 3, byte-identical to solc', async () => {
    const data = encodeCall(sel, [9n, 0n, 0n, 0n]); // S = (id=9, data=[0,0,0])
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.returnHex).toBe(s.returnHex);
    expect(decodeUint(j.returnHex)).toBe(3n);
  });
});
