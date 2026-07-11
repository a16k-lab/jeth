// Phase 4: D[] = dynamic array of DYNAMIC struct (D{uint a; string s}) as a calldata
// param + return, byte-identical to Solidity. solc encodes a known D[] (makeD), then
// both echo it back; element/field access compared too.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `type D = { a: u256; s: string; };
class DA {
  get echoD(ds: D[]): External<D[]> { return ds; }
  get dA(ds: D[], i: u256): External<u256> { return ds[i].a; }
  get dS(ds: D[], i: u256): External<string> { return ds[i].s; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract DA {
  struct D { uint256 a; string s; }
  function makeD() external pure returns (D[] memory ds) {
    ds = new D[](3);
    ds[0] = D(7, "hi");
    ds[1] = D(8, "a longer string that is definitely beyond thirty-two bytes for padding");
    ds[2] = D(9, "");
  }
  function echoD(D[] calldata ds) external pure returns (D[] memory) { return ds; }
  function dA(D[] calldata ds, uint256 i) external pure returns (uint256){ return ds[i].a; }
  function dS(D[] calldata ds, uint256 i) external pure returns (string memory){ return ds[i].s; }
}`;

describe('D[] (dynamic array of dynamic struct) param/return vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'DA.jeth' });
    const sb = compileSolidity(SOL, 'DA');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('echoD byte-identical (head/tail of dynamic-struct elements)', async () => {
    const r = await sol.call(as, '0x' + sel('makeD()')); // [0x20][D[] encoding]
    const data = '0x' + sel('echoD((uint256,string)[])') + r.returnHex.slice(2);
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `echoD success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, 'echoD returndata').toBe(s.returnHex);
    expect(j.returnHex, 'echoD identity').toBe(r.returnHex);
  });

  it('ds[i].a (static field) and ds[i].s (string field) byte-identical, OOB Panic', async () => {
    const r = await sol.call(as, '0x' + sel('makeD()'));
    const mdata = r.returnHex.slice(2 + 64); // drop the leading 0x20 offset word
    async function eq(label: string, selSig: string, i: bigint) {
      const data = '0x' + sel(selSig) + pad(0x40n) + pad(i) + mdata;
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(j.success, `${label} success`).toBe(s.success);
      expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
      return { j, s };
    }
    for (const i of [0n, 1n, 2n]) {
      await eq(`dA[${i}]`, 'dA((uint256,string)[],uint256)', i);
      await eq(`dS[${i}]`, 'dS((uint256,string)[],uint256)', i);
    }
    // OOB index -> Panic(0x32) identically
    const oob = await eq('dA OOB', 'dA((uint256,string)[],uint256)', 3n);
    expect(oob.j.success).toBe(false);
  });
});
