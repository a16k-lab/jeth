// JETH242/243 lift: a dynamic value-element array / bytes / string passed to OR returned from an
// @internal/@private function, BY MEMORY REFERENCE (like solc). A memory-source arg ALIASES (a callee
// mutation is visible to the caller); a calldata source is COPIED (masking dirty value-array elements,
// like solc's calldata->memory copy); a storage source is copied via the storage encoder. Returns
// compose with the external encoder. Byte-identical to solc 0.8.35.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const cdArr = (xs: readonly bigint[]) => pad32(0x20n) + pad32(BigInt(xs.length)) + xs.map(pad32).join('');

describe('aggregate param/return through an internal call (JETH242/243) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `@contract class C {
    @internal sum(xs: u256[]): u256 { let t: u256 = 0n; for (const v of xs) { t = t + v; } return t; }
    @internal nsum(xs: u64[]): u256 { let t: u256 = 0n; for (const v of xs) { t = t + v; } return t; }
    @internal bump(xs: u256[]): void { xs[0n] = 99n; }
    @internal mk(n: u256): u256[] { let m: u256[] = [n, n + 1n, n + 2n]; return m; }
    @internal twice(xs: u256[]): u256 { return this.sum(xs) + this.sum(xs); }
    @internal mkB(): bytes { let s: bytes = "hello world, JETH"; return s; }
    @internal blen(b: bytes): u256 { return b.length; }
    @external @pure sumCd(a: u256[]): u256 { return this.sum(a); }
    @external @pure nsumCd(a: u64[]): u256 { return this.nsum(a); }
    @external @pure sumMem(): u256 { let m: u256[] = [10n, 20n, 30n]; return this.sum(m); }
    @external @pure aliasTest(): u256 { let m: u256[] = [1n, 2n]; this.bump(m); return m[0n]; }
    @external @pure copyNoMutate(a: u256[]): u256 { this.bump(a); return a[0n]; }
    @external @pure mkRet(n: u256): u256[] { return this.mk(n); }
    @external @pure mkBind(n: u256): u256 { let xs: u256[] = this.mk(n); return xs[1n]; }
    @external @pure chained(a: u256[]): u256 { return this.twice(a); }
    @external @pure mkBytes(): bytes { return this.mkB(); }
    @external @pure blenCd(b: bytes): u256 { return this.blen(b); }
    @external @pure emptySum(a: u256[]): u256 { return this.sum(a); }
    @state s: u256[];
    @external pushS(v: u256): void { this.s.push(v); }
    @external @view sumStore(): u256 { return this.sum(this.s); } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  function sum(uint256[] memory xs) internal pure returns (uint256) { uint256 t=0; for (uint256 i=0;i<xs.length;i++){t+=xs[i];} return t; }
  function nsum(uint64[] memory xs) internal pure returns (uint256) { uint256 t=0; for (uint256 i=0;i<xs.length;i++){t+=xs[i];} return t; }
  function bump(uint256[] memory xs) internal pure { xs[0]=99; }
  function mk(uint256 n) internal pure returns (uint256[] memory) { uint256[] memory m=new uint256[](3); m[0]=n;m[1]=n+1;m[2]=n+2; return m; }
  function twice(uint256[] memory xs) internal pure returns (uint256) { return sum(xs)+sum(xs); }
  function mkB() internal pure returns (bytes memory) { return "hello world, JETH"; }
  function blen(bytes memory b) internal pure returns (uint256) { return b.length; }
  function sumCd(uint256[] calldata a) external pure returns (uint256) { return sum(a); }
  function nsumCd(uint64[] calldata a) external pure returns (uint256) { return nsum(a); }
  function sumMem() external pure returns (uint256) { uint256[] memory m=new uint256[](3); m[0]=10;m[1]=20;m[2]=30; return sum(m); }
  function aliasTest() external pure returns (uint256) { uint256[] memory m=new uint256[](2); m[0]=1;m[1]=2; bump(m); return m[0]; }
  function copyNoMutate(uint256[] calldata a) external pure returns (uint256) { bump(a); return a[0]; }
  function mkRet(uint256 n) external pure returns (uint256[] memory) { return mk(n); }
  function mkBind(uint256 n) external pure returns (uint256) { uint256[] memory xs=mk(n); return xs[1]; }
  function chained(uint256[] calldata a) external pure returns (uint256) { return twice(a); }
  function mkBytes() external pure returns (bytes memory) { return mkB(); }
  function blenCd(bytes calldata b) external pure returns (uint256) { return blen(b); }
  function emptySum(uint256[] calldata a) external pure returns (uint256) { return sum(a); }
  uint256[] s;
  function pushS(uint256 v) external { s.push(v); }
  function sumStore() external view returns (uint256) { return sum(s); } }`;

  beforeAll(async () => {
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });
  const cmp = async (data: string, label: string) => {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
  };

  it('array PARAM from calldata / memory / storage sources', async () => {
    await cmp('0x' + sel('sumCd(uint256[])') + cdArr([5n, 6n, 7n, 8n]), 'sum(calldata)');
    await cmp('0x' + sel('sumMem()'), 'sum(memory)');
    await cmp('0x' + sel('emptySum(uint256[])') + cdArr([]), 'sum(empty calldata)');
    await jeth.call(aj, '0x' + sel('pushS(uint256)') + pad32(11n)); await sol.call(as, '0x' + sel('pushS(uint256)') + pad32(11n));
    await jeth.call(aj, '0x' + sel('pushS(uint256)') + pad32(22n)); await sol.call(as, '0x' + sel('pushS(uint256)') + pad32(22n));
    await cmp('0x' + sel('sumStore()'), 'sum(storage)');
  });
  it('a NARROW value-array calldata arg COPIES with masking (dirty bits do not revert), like solc', async () => {
    await cmp('0x' + sel('nsumCd(uint64[])') + cdArr([5n, 6n, 7n]), 'nsum clean');
    // a dirty u64 element: solc's calldata->memory copy MASKS (no revert); JETH must match (not validate)
    const dirty = pad32(0x20n) + pad32(2n) + ('ff' + pad32(5n).slice(2)) + pad32(6n);
    await cmp('0x' + sel('nsumCd(uint64[])') + dirty, 'nsum dirty (masked)');
  });
  it('mutation through a MEMORY arg propagates to the caller (alias, like solc)', async () => {
    await cmp('0x' + sel('aliasTest()'), 'aliasTest');
  });
  it('a CALLDATA-source arg is COPIED (callee mutation does not affect the source)', async () => {
    await cmp('0x' + sel('copyNoMutate(uint256[])') + cdArr([7n, 8n]), 'copyNoMutate');
  });
  it('array RETURN: external, let-bound, and chained helper calls', async () => {
    await cmp('0x' + sel('mkRet(uint256)') + pad32(100n), 'mkRet (external)');
    await cmp('0x' + sel('mkBind(uint256)') + pad32(50n), 'mkBind (let)');
    await cmp('0x' + sel('chained(uint256[])') + cdArr([3n, 4n, 5n]), 'chained');
  });
  it('bytes/string param + return compose with the external encoder', async () => {
    await cmp('0x' + sel('mkBytes()'), 'mkBytes');
    await cmp('0x' + sel('blenCd(bytes)') + pad32(0x20n) + pad32(11n) + 'aabbccddeeff0011223344'.padEnd(64, '0'), 'blenCd');
  });
});
