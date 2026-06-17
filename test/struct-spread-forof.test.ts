// F2: `for...of` (desugars to an indexed loop) and struct spread / object-literal construction
// (desugars to the same structNew as positional StructName(...)). Both must be byte-identical to
// solc on returndata + raw storage slots.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => v.toString(16).padStart(64, '0');

describe('F2 for-of', () => {
  const J = `@contract class C {
    @state xs: u256[];
    @external push(v: u256): void { this.xs.push(v); }
    @external @view sum(): u256 { let s: u256 = 0n; for (const v of this.xs) { s = s + v; } return s; }
    @external @view countGt(t: u256): u256 { let n: u256 = 0n; for (const v of this.xs) { if (v > t) { n = n + 1n; } } return n; }
    @external @pure sumCd(a: u256[]): u256 { let s: u256 = 0n; for (const v of a) { s = s + v; } return s; }
    @external @pure firstZero(a: u256[]): u256 { let i: u256 = 0n; for (const v of a) { if (v == 0n) { return i; } i = i + 1n; } return 999n; }
    @external @pure sumFixed(): u256 { let a: Arr<u256,4> = [3n,5n,7n,9n]; let s: u256 = 0n; for (const v of a) { s = s + v; } return s; }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[] xs;
  function push(uint256 v) external { xs.push(v); }
  function sum() external view returns (uint256) { uint256 s = 0; for (uint256 i = 0; i < xs.length; i = i + 1) { uint256 v = xs[i]; s = s + v; } return s; }
  function countGt(uint256 t) external view returns (uint256) { uint256 n = 0; for (uint256 i = 0; i < xs.length; i = i + 1) { uint256 v = xs[i]; if (v > t) { n = n + 1; } } return n; }
  function sumCd(uint256[] calldata a) external pure returns (uint256) { uint256 s = 0; for (uint256 i = 0; i < a.length; i = i + 1) { uint256 v = a[i]; s = s + v; } return s; }
  function firstZero(uint256[] calldata a) external pure returns (uint256) { uint256 i = 0; for (uint256 k = 0; k < a.length; k = k + 1) { uint256 v = a[k]; if (v == 0) { return i; } i = i + 1; } return 999; }
  function sumFixed() external pure returns (uint256) { uint256[4] memory a = [uint256(3),5,7,9]; uint256 s = 0; for (uint256 i = 0; i < a.length; i = i + 1) { uint256 v = a[i]; s = s + v; } return s; }
}`;
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} jeth=${j.exceptionError}`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(J, { fileName: 'C.jeth' }); const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
    for (const v of [5n, 0n, 12n, 7n, 0n, 30n]) {
      const d = encodeCall(sel('push(uint256)'), [v]);
      await jeth.call(aj, d); await sol.call(as, d);
    }
  });
  it('storage / calldata / fixed-array iteration matches solc', async () => {
    await eq('sum', encodeCall(sel('sum()'), []));
    await eq('countGt(6)', encodeCall(sel('countGt(uint256)'), [6n]));
    await eq('sumFixed', encodeCall(sel('sumFixed()'), []));
    const cd = '0x' + sel('sumCd(uint256[])') + pad(32n) + pad(4n) + pad(10n) + pad(20n) + pad(30n) + pad(40n);
    await eq('sumCd', cd);
    const fz = '0x' + sel('firstZero(uint256[])') + pad(32n) + pad(3n) + pad(8n) + pad(0n) + pad(9n);
    await eq('firstZero', fz);
  });
});

describe('F2 struct spread / object literal', () => {
  const J = `@struct class P { x: u256; y: u256; flag: bool; }
  @contract class C {
    @state p: P;
    @external setRaw(x: u256, y: u256, f: bool): void { this.p = P(x, y, f); }
    @external bumpX(dx: u256): void { this.p = { ...this.p, x: this.p.x + dx }; }
    @external toggle(): void { this.p = { ...this.p, flag: !this.p.flag }; }
    @external @pure mk(x: u256, y: u256): P { return { x: x, y: y, flag: true }; }
    @external @pure withY(p: P, ny: u256): P { return { ...p, y: ny }; }
    @view get(): P { return this.p; }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 x; uint256 y; bool flag; }
  P p;
  function setRaw(uint256 x, uint256 y, bool f) external { p = P(x, y, f); }
  function bumpX(uint256 dx) external { P memory q = p; q.x = q.x + dx; p = q; }
  function toggle() external { P memory q = p; q.flag = !q.flag; p = q; }
  function mk(uint256 x, uint256 y) external pure returns (P memory) { return P(x, y, true); }
  function withY(P calldata pp, uint256 ny) external pure returns (P memory) { P memory q = pp; q.y = ny; return q; }
  function get() external view returns (P memory) { return p; }
}`;
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function both(data: string) { await jeth.call(aj, data); await sol.call(as, data); }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} jeth=${j.exceptionError}`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(J, { fileName: 'C.jeth' }); const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });
  it('spread update + full literal match solc incl. raw slots', async () => {
    await both('0x' + sel('setRaw(uint256,uint256,bool)') + pad(11n) + pad(22n) + pad(1n));
    await both(encodeCall(sel('bumpX(uint256)'), [5n]));    // x: 11 -> 16, y/flag preserved
    await both(encodeCall(sel('toggle()'), []));            // flag: true -> false
    for (const slot of [0n, 1n, 2n]) expect(await readSlot(jeth, aj, slot), `slot ${slot}`).toBe(await readSlot(sol, as, slot));
    await eq('get', encodeCall(sel('get()'), []));
    await eq('mk', encodeCall(sel('mk(uint256,uint256)'), [7n, 8n]));
    const wy = '0x' + sel('withY((uint256,uint256,bool),uint256)') + pad(100n) + pad(200n) + pad(1n) + pad(999n);
    await eq('withY', wy);
  });
});
