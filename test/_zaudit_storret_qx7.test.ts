// THROWAWAY adversarial audit: whole-aggregate ENCODE-FROM-STORAGE returns.
// Hunting silent runtime miscompiles vs solc 0.8.35 cancun. Distinct value per leaf.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

async function deployPair(JETH: string, jName: string, SOL: string, sName: string) {
  const jb = compile(JETH, { fileName: jName + '.jeth' });
  const sb = compileSolidity(SOL, sName);
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  return { jeth, sol, aj, as };
}

describe('SANITY: comparator catches a wrong Solidity contract', () => {
  it('flags a returndata mismatch when SOL returns the wrong thing', async () => {
    const JETH = `@contract class S {
      @state x: u256;
      @external setx(v: u256): void { this.x = v; }
      @external @view getx(): u256 { return this.x; }
    }`;
    const SOL = `pragma solidity ^0.8.20;
    contract S {
      uint256 x;
      function setx(uint256 v) external { x = v; }
      function getx() external view returns (uint256){ return x + 1; } // WRONG on purpose
    }`;
    const { jeth, sol, aj, as } = await deployPair(JETH, 'S', SOL, 'S');
    await jeth.call(aj, encodeCall(sel('setx(uint256)'), [42n]));
    await sol.call(as, encodeCall(sel('setx(uint256)'), [42n]));
    const j = await jeth.call(aj, encodeCall(sel('getx()'), []));
    const s = await sol.call(as, encodeCall(sel('getx()'), []));
    expect(j.returnHex).not.toBe(s.returnHex); // comparator would catch a real bug
  });
});

// ----- 2D / 3D / 4D fixed VALUE arrays (u256) -----
describe('multi-dim fixed u256 arrays whole + row returns', () => {
  let H: Awaited<ReturnType<typeof deployPair>>;
  const JETH = `@contract class M {
    @state a2: Arr<Arr<u256, 2>, 3>;
    @state a3: Arr<Arr<Arr<u256, 2>, 3>, 2>;
    @state a4: Arr<Arr<Arr<Arr<u256, 2>, 2>, 2>, 2>;
    @external s2(i: u256, j: u256, v: u256): void { this.a2[i][j] = v; }
    @external s3(i: u256, j: u256, k: u256, v: u256): void { this.a3[i][j][k] = v; }
    @external s4(i: u256, j: u256, k: u256, l: u256, v: u256): void { this.a4[i][j][k][l] = v; }
    @external @view w2(): Arr<Arr<u256, 2>, 3> { return this.a2; }
    @external @view r2(i: u256): Arr<u256, 2> { return this.a2[i]; }
    @external @view w3(): Arr<Arr<Arr<u256, 2>, 3>, 2> { return this.a3; }
    @external @view p3(i: u256): Arr<Arr<u256, 2>, 3> { return this.a3[i]; }
    @external @view r3(i: u256, j: u256): Arr<u256, 2> { return this.a3[i][j]; }
    @external @view w4(): Arr<Arr<Arr<Arr<u256, 2>, 2>, 2>, 2> { return this.a4; }
    @external @view c4(i: u256): Arr<Arr<Arr<u256, 2>, 2>, 2> { return this.a4[i]; }
    @external @view p4(i: u256, j: u256): Arr<Arr<u256, 2>, 2> { return this.a4[i][j]; }
    @external @view r4(i: u256, j: u256, k: u256): Arr<u256, 2> { return this.a4[i][j][k]; }
  }`;
  const SOL = `pragma solidity ^0.8.20;
  contract M {
    uint256[2][3] a2;
    uint256[2][3][2] a3;
    uint256[2][2][2][2] a4;
    function s2(uint256 i,uint256 j,uint256 v) external { a2[i][j]=v; }
    function s3(uint256 i,uint256 j,uint256 k,uint256 v) external { a3[i][j][k]=v; }
    function s4(uint256 i,uint256 j,uint256 k,uint256 l,uint256 v) external { a4[i][j][k][l]=v; }
    function w2() external view returns (uint256[2][3] memory){ return a2; }
    function r2(uint256 i) external view returns (uint256[2] memory){ return a2[i]; }
    function w3() external view returns (uint256[2][3][2] memory){ return a3; }
    function p3(uint256 i) external view returns (uint256[2][3] memory){ return a3[i]; }
    function r3(uint256 i,uint256 j) external view returns (uint256[2] memory){ return a3[i][j]; }
    function w4() external view returns (uint256[2][2][2][2] memory){ return a4; }
    function c4(uint256 i) external view returns (uint256[2][2][2] memory){ return a4[i]; }
    function p4(uint256 i,uint256 j) external view returns (uint256[2][2] memory){ return a4[i][j]; }
    function r4(uint256 i,uint256 j,uint256 k) external view returns (uint256[2] memory){ return a4[i][j][k]; }
  }`;
  beforeAll(async () => { H = await deployPair(JETH, 'M', SOL, 'M'); });

  async function send(data: string) {
    const j = await H.jeth.call(H.aj, data); const s = await H.sol.call(H.as, data);
    expect(j.success, `setter jeth err=${j.exceptionError}`).toBe(true);
    expect(s.success).toBe(true);
  }
  async function eq(label: string, data: string) {
    const j = await H.jeth.call(H.aj, data); const s = await H.sol.call(H.as, data);
    expect(j.success, `${label} success jeth err=${j.exceptionError}`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }

  it('populate + return all dims with distinct leaves', async () => {
    let v = 1000n;
    // a2: 3x2
    for (let i = 0n; i < 3n; i++) for (let j = 0n; j < 2n; j++)
      await send(encodeCall(sel('s2(uint256,uint256,uint256)'), [i, j, v++]));
    // a3: 2x3x2
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 3n; j++) for (let k = 0n; k < 2n; k++)
      await send(encodeCall(sel('s3(uint256,uint256,uint256,uint256)'), [i, j, k, v++]));
    // a4: 2x2x2x2
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++) for (let k = 0n; k < 2n; k++) for (let l = 0n; l < 2n; l++)
      await send(encodeCall(sel('s4(uint256,uint256,uint256,uint256,uint256)'), [i, j, k, l, v++]));

    await eq('w2', encodeCall(sel('w2()'), []));
    for (let i = 0n; i < 3n; i++) await eq(`r2[${i}]`, encodeCall(sel('r2(uint256)'), [i]));
    await eq('w3', encodeCall(sel('w3()'), []));
    for (let i = 0n; i < 2n; i++) await eq(`p3[${i}]`, encodeCall(sel('p3(uint256)'), [i]));
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 3n; j++) await eq(`r3[${i}][${j}]`, encodeCall(sel('r3(uint256,uint256)'), [i, j]));
    await eq('w4', encodeCall(sel('w4()'), []));
    for (let i = 0n; i < 2n; i++) await eq(`c4[${i}]`, encodeCall(sel('c4(uint256)'), [i]));
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++) await eq(`p4[${i}][${j}]`, encodeCall(sel('p4(uint256,uint256)'), [i, j]));
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++) for (let k = 0n; k < 2n; k++) await eq(`r4[${i}][${j}][${k}]`, encodeCall(sel('r4(uint256,uint256,uint256)'), [i, j, k]));
  });
});
