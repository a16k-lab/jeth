// Phase 4: Arr<dynamic,N> = a FIXED array of a DYNAMIC element (Arr<string,3>) as a
// calldata param + return, byte-identical to Solidity (N-word offset table, no
// length). solc encodes a known string[3] (makeA), both echo it; a[i] access compared.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `class FA {
  get echoA(a: Arr<string,3>): External<Arr<string,3>> { return a; }
  get atA(a: Arr<string,3>, i: u256): External<string> { return a[i]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FA {
  function makeA() external pure returns (string[3] memory a) {
    a[0] = "x";
    a[1] = "a string that is certainly longer than thirty-two bytes for the padding case";
    a[2] = "";
  }
  function echoA(string[3] calldata a) external pure returns (string[3] memory) { return a; }
  function atA(string[3] calldata a, uint256 i) external pure returns (string memory){ return a[i]; }
}`;

describe('Arr<dynamic,N> (fixed array of dynamic element) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'FA.jeth' });
    const sb = compileSolidity(SOL, 'FA');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('echoA byte-identical (offset table of N words, no length)', async () => {
    const r = await sol.call(as, '0x' + sel('makeA()'));
    const data = '0x' + sel('echoA(string[3])') + r.returnHex.slice(2);
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `echoA success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, 'echoA returndata').toBe(s.returnHex);
    expect(j.returnHex, 'echoA identity').toBe(r.returnHex);
  });

  it('a[i] element access byte-identical + OOB Panic', async () => {
    const r = await sol.call(as, '0x' + sel('makeA()'));
    const adata = r.returnHex.slice(2 + 64); // drop leading 0x20
    for (const i of [0n, 1n, 2n]) {
      const data = '0x' + sel('atA(string[3],uint256)') + pad(0x40n) + pad(i) + adata;
      const jr = await jeth.call(aj, data);
      const sr = await sol.call(as, data);
      expect(jr.returnHex, `a[${i}]`).toBe(sr.returnHex);
    }
    const oob = '0x' + sel('atA(string[3],uint256)') + pad(0x40n) + pad(3n) + adata;
    const jr = await jeth.call(aj, oob);
    const sr = await sol.call(as, oob);
    expect(jr.success).toBe(false);
    expect(jr.returnHex).toBe(sr.returnHex);
  });
});

const JETHD = `type D = { a: u256; s: string; };
class FD {
  get echoD(xs: Arr<D,2>): External<Arr<D,2>> { return xs; }
  get dA(xs: Arr<D,2>, i: u256): External<u256> { return xs[i].a; }
  get dS(xs: Arr<D,2>, i: u256): External<string> { return xs[i].s; }
}`;
const SOLD = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FD {
  struct D { uint256 a; string s; }
  function makeD() external pure returns (D[2] memory xs) {
    xs[0] = D(11, "first");
    xs[1] = D(22, "a second value that exceeds thirty-two bytes for the long-string path");
  }
  function echoD(D[2] calldata xs) external pure returns (D[2] memory) { return xs; }
  function dA(D[2] calldata xs, uint256 i) external pure returns (uint256){ return xs[i].a; }
  function dS(D[2] calldata xs, uint256 i) external pure returns (string memory){ return xs[i].s; }
}`;

describe('Arr<D,N> (fixed array of dynamic struct) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  beforeAll(async () => {
    const jb = compile(JETHD, { fileName: 'FD.jeth' });
    const sb = compileSolidity(SOLD, 'FD');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('echoD + xs[i].a + xs[i].s byte-identical, OOB Panic', async () => {
    const r = await sol.call(as, '0x' + sel('makeD()'));
    const data = '0x' + sel('echoD((uint256,string)[2])') + r.returnHex.slice(2);
    const j = await jeth.call(aj, data);
    expect(j.returnHex, 'echoD').toBe((await sol.call(as, data)).returnHex);
    expect(j.returnHex).toBe(r.returnHex);
    const xdata = r.returnHex.slice(2 + 64);
    for (const i of [0n, 1n]) {
      for (const f of ['dA((uint256,string)[2],uint256)', 'dS((uint256,string)[2],uint256)']) {
        const cd = '0x' + sel(f) + pad(0x40n) + pad(i) + xdata;
        expect((await jeth.call(aj, cd)).returnHex, `${f}@${i}`).toBe((await sol.call(as, cd)).returnHex);
      }
    }
    const oob = '0x' + sel('dA((uint256,string)[2],uint256)') + pad(0x40n) + pad(2n) + xdata;
    expect((await jeth.call(aj, oob)).success).toBe(false);
  });
});
