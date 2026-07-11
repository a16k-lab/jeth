// Regression lock for two deeper aggregate edges that were once sound rejects / runtime-Panics (flagged in
// the 2026-06-29 memory) and have since been lifted byte-identical by the accumulated aggregate-codec work
// (Cat A/B/C, Batch A/B/C, Edges A-E). This test pins them so they cannot silently regress:
//   1. A value fixed-array element of a DYNAMIC-outer array - Arr<u256,N>[] (uint256[N][]) - inner element
//      write xs[i][j] = v (storage + memory), incl compound assign, packed inner (Arr<u128,2>[]), deeper
//      nesting Arr<Arr<u256,2>,2>[], and runtime-index / OOB Panic 0x32 parity.
//   2. abi.encode / encodePacked / keccak / return of a leaf ARRAY FIELD of a CALLDATA struct param -
//      abi.encode(s.tags) where s: S{a; tags: u256[] / string[] / u256[][] / bytes / string}.
// All verified byte-identical to solc 0.8.35.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => BigInt(n).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

describe('value Arr<u256,N>[] inner-element write - byte-identical to solc 0.8.35', () => {
  it('storage uint256[3][] runtime-index inner write + OOB Panic 0x32', async () => {
    await eqCalls(
      'class C { xs: Arr<u256,3>[]; seed(): External<void> { this.xs.push([1n,2n,3n]); this.xs.push([4n,5n,6n]); } setit(i: u256, j: u256, v: u256): External<void> { this.xs[i][j] = v; } get r(i: u256, j: u256): External<u256> { return this.xs[i][j]; } }',
      'contract C { uint256[3][] xs; function seed() external { xs.push([uint256(1),2,3]); xs.push([uint256(4),5,6]); } function setit(uint256 i,uint256 j,uint256 v) external { xs[i][j]=v; } function r(uint256 i,uint256 j) external view returns(uint256){ return xs[i][j]; } }',
      [
        ['seed()', ''],
        ['setit(uint256,uint256,uint256)', W(1) + W(2) + W(88)],
        ['r(uint256,uint256)', W(1) + W(2)],
        ['setit(uint256,uint256,uint256)', W(2) + W(0) + W(9)], // outer OOB -> Panic
        ['setit(uint256,uint256,uint256)', W(0) + W(3) + W(9)], // inner OOB -> Panic
      ],
    );
  });

  it('storage packed uint128[2][] inner write + compound assign', async () => {
    await eqCalls(
      'class C { xs: Arr<u128,2>[]; seed(): External<void> { this.xs.push([10n,20n]); } setit(): External<void> { this.xs[0n][0n] = 111n; this.xs[0n][1n] += 5n; } get r(j: u256): External<u128> { return this.xs[0n][j]; } }',
      'contract C { uint128[2][] xs; function seed() external { xs.push([uint128(10),20]); } function setit() external { xs[0][0]=111; xs[0][1]+=5; } function r(uint256 j) external view returns(uint128){ return xs[0][j]; } }',
      [['seed()', ''], ['setit()', ''], ['r(uint256)', W(0)], ['r(uint256)', W(1)]],
    );
  });

  it('memory uint256[2][] runtime inner write + OOB, and deep uint256[2][2][] write', async () => {
    await eqCalls(
      'class C { get go(i: u256): External<u256> { let xs: Arr<u256,2>[] = [[1n,2n],[3n,4n]]; xs[i][0n] = 50n; return xs[i][0n]; } }',
      'contract C { function go(uint256 i) external pure returns(uint256){ uint256[2][] memory xs=new uint256[2][](2); xs[0]=[uint256(1),2]; xs[1]=[uint256(3),4]; xs[i][0]=50; return xs[i][0]; } }',
      [['go(uint256)', W(0)], ['go(uint256)', W(1)], ['go(uint256)', W(2)]],
    );
    await eqCalls(
      'class C { xs: Arr<Arr<u256,2>,2>[]; seed(): External<void> { this.xs.push([[1n,2n],[3n,4n]]); } setit(): External<void> { this.xs[0n][1n][0n] = 88n; } get r(a: u256, b: u256): External<u256> { return this.xs[0n][a][b]; } }',
      'contract C { uint256[2][2][] xs; function seed() external { xs.push([[uint256(1),2],[uint256(3),4]]); } function setit() external { xs[0][1][0]=88; } function r(uint256 a,uint256 b) external view returns(uint256){ return xs[0][a][b]; } }',
      [['seed()', ''], ['setit()', ''], ['r(uint256,uint256)', W(1) + W(0)], ['r(uint256,uint256)', W(0) + W(0)]],
    );
  });
});

describe('abi.encode / encodePacked / return of a calldata-struct leaf-array field - byte-identical to solc 0.8.35', () => {
  it('abi.encode(s.tags) u256[], keccak, encodePacked, empty, and mixed abi.encode(s.a, s.tags)', async () => {
    const J = 'type S = {a:u256;tags:u256[]}; class C { get enc(s: S): External<bytes> { return abi.encode(s.tags); } get kk(s: S): External<bytes32> { return keccak256(abi.encode(s.tags)); } get pk(s: S): External<bytes> { return abi.encodePacked(s.tags); } get mx(s: S): External<bytes> { return abi.encode(s.a, s.tags); } get ret(s: S): External<u256[]> { return s.tags; } }';
    const S = 'contract C { struct S{uint256 a;uint256[] tags;} function enc(S calldata s) external pure returns(bytes memory){ return abi.encode(s.tags); } function kk(S calldata s) external pure returns(bytes32){ return keccak256(abi.encode(s.tags)); } function pk(S calldata s) external pure returns(bytes memory){ return abi.encodePacked(s.tags); } function mx(S calldata s) external pure returns(bytes memory){ return abi.encode(s.a, s.tags); } function ret(S calldata s) external pure returns(uint256[] memory){ return s.tags; } }';
    const full = W(0x20) + W(7) + W(0x40) + W(3) + W(1) + W(2) + W(3);
    const empty = W(0x20) + W(7) + W(0x40) + W(0);
    await eqCalls(J, S, [
      ['enc((uint256,uint256[]))', full], ['kk((uint256,uint256[]))', full], ['pk((uint256,uint256[]))', full],
      ['mx((uint256,uint256[]))', full], ['ret((uint256,uint256[]))', full],
      ['enc((uint256,uint256[]))', empty], ['ret((uint256,uint256[]))', empty],
    ]);
  });

  it('abi.encode of string[] / u256[][] / bytes / string leaf fields', async () => {
    await eqCalls(
      'type S = {a:u256;names:string[]}; class C { get go(s: S): External<bytes> { return abi.encode(s.names); } }',
      'contract C { struct S{uint256 a;string[] names;} function go(S calldata s) external pure returns(bytes memory){ return abi.encode(s.names); } }',
      [['go((uint256,string[]))', W(0x20) + W(7) + W(0x40) + W(2) + W(0x40) + W(0x80) + W(2) + '6161'.padEnd(64, '0') + W(2) + '6262'.padEnd(64, '0')]],
    );
    await eqCalls(
      'type S = {a:u256;grid:u256[][]}; class C { get go(s: S): External<bytes> { return abi.encode(s.grid); } }',
      'contract C { struct S{uint256 a;uint256[][] grid;} function go(S calldata s) external pure returns(bytes memory){ return abi.encode(s.grid); } }',
      [['go((uint256,uint256[][]))', W(0x20) + W(5) + W(0x40) + W(2) + W(0x40) + W(0xa0) + W(2) + W(1) + W(2) + W(1) + W(3)]],
    );
    await eqCalls(
      'type S = {a:u256;blob:bytes;name:string}; class C { get gb(s: S): External<bytes> { return abi.encode(s.blob); } get gn(s: S): External<bytes> { return abi.encode(s.name); } }',
      'contract C { struct S{uint256 a;bytes blob;string name;} function gb(S calldata s) external pure returns(bytes memory){ return abi.encode(s.blob); } function gn(S calldata s) external pure returns(bytes memory){ return abi.encode(s.name); } }',
      [
        ['gb((uint256,bytes,string))', W(0x20) + W(7) + W(0x60) + W(0xa0) + W(3) + '616263'.padEnd(64, '0') + W(2) + '7878'.padEnd(64, '0')],
        ['gn((uint256,bytes,string))', W(0x20) + W(7) + W(0x60) + W(0xa0) + W(3) + '616263'.padEnd(64, '0') + W(2) + '7878'.padEnd(64, '0')],
      ],
    );
  });
});
