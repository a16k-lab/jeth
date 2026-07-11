// Regression tests for the two bugs the adversarial verification workflow found:
//  A) param/local Yul name collision (param `x_0` vs local `x`) -> solc crash
//  B) negative INT_MIN literals wrongly rejected (range-checked before negation)
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const I256_MIN = -(1n << 255n);

interface Case {
  sig: string;
  args: bigint[];
}

async function differential(jethSrc: string, solSrc: string, name: string, cases: Case[]) {
  const jb = compile(jethSrc, { fileName: `${name}.jeth` });
  const sb = compileSolidity(solSrc, name);
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jb.creationBytecode);
  const as = await hs.deploy(sb.creation);
  for (const c of cases) {
    const data = encodeCall(functionSelector(c.sig), c.args);
    const r1 = await hj.call(aj, data);
    const r2 = await hs.call(as, data);
    const label = `${name}.${c.sig} [${c.args.join(', ')}]`;
    expect(r1.success, `${label}: success (jeth err=${r1.exceptionError})`).toBe(r2.success);
    expect(r1.returnHex, `${label}: returndata`).toBe(r2.returnHex);
  }
}

describe('Phase 2 regression: param/local name collision (Bug A)', () => {
  const JETH = `class NameClash {
  get f(x_0: u256): External<u256> { let x: u256 = 5n; return x_0 + x; }
  get g(s_0: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < s_0; i += 1n) { s += i; } return s; }
  get h(i_1: u256, n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i += 1n) { s += i_1; } return s; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract NameClash {
  function f(uint256 x_0) external pure returns (uint256){ uint256 x=5; return x_0 + x; }
  function g(uint256 s_0) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<s_0;i+=1){ s+=i; } return s; }
  function h(uint256 i_1, uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ s+=i_1; } return s; }
}`;

  it('compiles (no longer crashes solc) and matches Solidity', async () => {
    await differential(JETH, SOL, 'NameClash', [
      { sig: 'f(uint256)', args: [0n] },
      { sig: 'f(uint256)', args: [7n] },
      { sig: 'f(uint256)', args: [100n] },
      { sig: 'g(uint256)', args: [10n] },
      { sig: 'h(uint256,uint256)', args: [3n, 4n] },
    ]);
  });
});

describe('Phase 2 regression: negative INT_MIN literals (Bug B)', () => {
  const JETH = `class NegLit {
  s8: i8 = -128n;
  I16: error<{ x: i16 }>;
  I8: error<{ x: i8 }>;
  get retMin16(): External<i16> { return -32768n; }
  get retMin8(): External<i8> { return -128n; }
  get retMin256(): External<i256> { return ${I256_MIN.toString()}n; }
  errMin16(): External<void> { revert(I16(-32768n)); }
  errMin8(): External<void> { require(false, I8(-128n)); }
  get getS8(): External<i8> { return this.s8; }
  get negVar(x: i8): External<i8> { return -x; }
}`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract NegLit {
  int8 s8 = -128;
  error I16(int16 x);
  error I8(int8 x);
  function retMin16() external pure returns (int16){ return -32768; }
  function retMin8() external pure returns (int8){ return -128; }
  function retMin256() external pure returns (int256){ return ${I256_MIN.toString()}; }
  function errMin16() external pure { revert I16(-32768); }
  function errMin8() external pure { require(false, I8(-128)); }
  function getS8() external view returns (int8){ return s8; }
  function negVar(int8 x) external pure returns (int8){ return -x; }
}`;

  it('accepts INT_MIN literals everywhere and matches Solidity', async () => {
    await differential(JETH, SOL, 'NegLit', [
      { sig: 'retMin16()', args: [] },
      { sig: 'retMin8()', args: [] },
      { sig: 'retMin256()', args: [] },
      { sig: 'errMin16()', args: [] },
      { sig: 'errMin8()', args: [] },
      { sig: 'getS8()', args: [] }, // negative state initializer
      { sig: 'negVar(int8)', args: [5n] },
      { sig: 'negVar(int8)', args: [-128n] }, // runtime checked negation still reverts on INT_MIN
    ]);
  });

  it('still rejects an out-of-range negative literal', () => {
    let codes: string[] = [];
    try {
      compile(`class T { get f(): External<i8> { return -129n; } }`, { fileName: 't.jeth' });
    } catch (e: any) {
      codes = e.diagnostics?.map((d: any) => d.code) ?? [];
    }
    expect(codes).toContain('JETH070');
  });
});
