// Arch over-rejection #1 (lifted): bind a calldata struct-array ELEMENT to a memory struct LOCAL
// (`let p: P = ps[0n]` / `for (const p of ps)` where ps: P[] calldata). solc accepts (a memory
// COPY of the calldata element); JETH used to JETH900-reject. The element is materialized into a
// fresh memory image via the SAME machinery the whole-param path uses (a STATIC struct element uses
// the static-aggregate calldata->memory copy abiEncFromCd; a DYNAMIC-field struct element uses
// buildDynStructFromCalldata at the element's offset-located calldata base). This proves
// byte-identity vs solc 0.8.35 for field reads, the for-of sum, the dynamic-field (bytes / u256[])
// copy, OOB Panic 0x32, and the copy-not-alias property (mutating the local leaves the calldata
// element observably unchanged).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

// calldata for f(P[]) where P = {uint256 a; uint256 b} (STATIC element). head = [off=0x20];
// at off: [len][a0][b0][a1][b1]...]. optional trailing uint256 i appended after the array offset.
const buildP = (selStr: string, ps: readonly (readonly [bigint, bigint])[], i?: bigint): string => {
  const offPs = i === undefined ? 0x20n : 0x40n;
  const head = i === undefined ? pad32(offPs) : pad32(offPs) + pad32(i);
  const body = pad32(BigInt(ps.length)) + ps.map(([a, b]) => pad32(a) + pad32(b)).join('');
  return '0x' + sel(selStr) + head + body;
};

// calldata for f(D[]) where D = {uint256 a; bytes b} (DYNAMIC element). head = [off=0x20];
// at off: [len][off_d0][off_d1]...] each relative to the array-data start; each tuple at its
// offset = [a][off_b=0x40][len_b][b_data padded]. optional trailing uint256 i appended.
const buildD = (selStr: string, ds: readonly (readonly [bigint, string])[], i?: bigint): string => {
  const offArr = i === undefined ? 0x20n : 0x40n;
  const head = i === undefined ? pad32(offArr) : pad32(offArr) + pad32(i);
  const n = ds.length;
  // each tuple: head [a][off_b] = 0x40 bytes, then bytes tail [len][data padded to 32].
  const tuples = ds.map(([a, bHex]) => {
    const bytesLen = bHex.length / 2;
    const padded = bHex + '00'.repeat((32 - (bytesLen % 32)) % 32);
    return pad32(a) + pad32(0x40n) + pad32(BigInt(bytesLen)) + padded;
  });
  // offset table: n words, each = (n * 32) + sum(prevTupleSizes)
  let acc = BigInt(n) * 0x20n;
  const offTable: string[] = [];
  for (let k = 0; k < n; k++) {
    offTable.push(pad32(acc));
    acc += BigInt(tuples[k]!.length / 2);
  }
  const body = pad32(BigInt(n)) + offTable.join('') + tuples.join('');
  return '0x' + sel(selStr) + head + body;
};

describe('calldata struct-array element bound to a memory struct local (arch #1) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;

  // J = JETH source; S = the solc 0.8.35 mirror, semantically identical.
  const J = `type P = { a: u256; b: u256; };
type D = { a: u256; b: bytes; };
type E = { a: u256; xs: u256[]; };
class C {
  // STATIC struct element -> memory local, read both fields
  get stat(ps: P[]): External<u256> { let p: P = ps[0n]; return p.a + p.b; }
  get statAt(ps: P[], i: u256): External<u256> { let p: P = ps[i]; return p.a * 1000n + p.b; }
  // for-of over a calldata struct array (same materialization)
  get sumA(ps: P[]): External<u256> { let t: u256 = 0n; for (const p of ps) { t = t + p.a; } return t; }
  get sumAB(ps: P[]): External<u256> { let t: u256 = 0n; for (const p of ps) { t = t + p.a + p.b; } return t; }
  // COPY-not-alias: mutate the local's field, return the mutated local AND the untouched ps[0].a
  get copyNoAlias(ps: P[]): External<u256> { let p: P = ps[0n]; p.a = p.a + 1000n; return p.a * 1000000n + ps[0n].a; }
  // DYNAMIC-field struct element (bytes field) -> memory local, read the value field + the bytes via .length and a byte
  get dynA(ds: D[], i: u256): External<u256> { let d: D = ds[i]; return d.a; }
  get dynBLen(ds: D[], i: u256): External<u256> { let d: D = ds[i]; return d.b.length; }
  get dynByte(ds: D[], i: u256): External<u256> { let d: D = ds[i]; return u256(u8(d.b[i])); }
  // DYNAMIC value-array field (u256[]) -> memory local, read its length and an element-derived sum
  get dynArrLen(es: E[], i: u256): External<u256> { let e: E = es[i]; return e.xs.length; }
  get dynArrSum(es: E[], i: u256): External<u256> { let e: E = es[i]; let t: u256 = 0n; for (const v of e.xs) { t = t + v; } return e.a + t; }
}`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  struct P { uint256 a; uint256 b; }
  struct D { uint256 a; bytes b; }
  struct E { uint256 a; uint256[] xs; }
  function stat(P[] calldata ps) external pure returns (uint256) { P memory p = ps[0]; return p.a + p.b; }
  function statAt(P[] calldata ps, uint256 i) external pure returns (uint256) { P memory p = ps[i]; return p.a * 1000 + p.b; }
  function sumA(P[] calldata ps) external pure returns (uint256) { uint256 t = 0; for (uint256 k = 0; k < ps.length; k++) { P memory p = ps[k]; t = t + p.a; } return t; }
  function sumAB(P[] calldata ps) external pure returns (uint256) { uint256 t = 0; for (uint256 k = 0; k < ps.length; k++) { P memory p = ps[k]; t = t + p.a + p.b; } return t; }
  function copyNoAlias(P[] calldata ps) external pure returns (uint256) { P memory p = ps[0]; p.a = p.a + 1000; return p.a * 1000000 + ps[0].a; }
  function dynA(D[] calldata ds, uint256 i) external pure returns (uint256) { D memory d = ds[i]; return d.a; }
  function dynBLen(D[] calldata ds, uint256 i) external pure returns (uint256) { D memory d = ds[i]; return d.b.length; }
  function dynByte(D[] calldata ds, uint256 i) external pure returns (uint256) { D memory d = ds[i]; return uint256(uint8(d.b[i])); }
  function dynArrLen(E[] calldata es, uint256 i) external pure returns (uint256) { E memory e = es[i]; return e.xs.length; }
  function dynArrSum(E[] calldata es, uint256 i) external pure returns (uint256) { E memory e = es[i]; uint256 t = 0; for (uint256 k = 0; k < e.xs.length; k++) { t = t + e.xs[k]; } return e.a + t; }
}`;

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });

  const cmp = async (data: string, label: string) => {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
  };

  const P3 = [
    [11n, 22n],
    [3n, 4n],
    [100n, 7n],
  ] as const;

  it('STATIC struct element bound to a local: read p.a + p.b, byte-identical', async () => {
    await cmp(buildP('stat((uint256,uint256)[])', P3), 'stat ps[0]');
    await cmp(buildP('stat((uint256,uint256)[])', [[42n, 58n]]), 'stat single');
  });

  it('STATIC element at a runtime index + OOB Panic 0x32, byte-identical', async () => {
    for (const i of [0n, 1n, 2n])
      await cmp(buildP('statAt((uint256,uint256)[],uint256)', P3, i), `statAt[${i}]`);
    await cmp(buildP('statAt((uint256,uint256)[],uint256)', P3, 3n), 'statAt OOB');
    await cmp(buildP('statAt((uint256,uint256)[],uint256)', [], 0n), 'statAt empty OOB');
  });

  it('for-of over a calldata struct array binds the element to a local, sums byte-identically', async () => {
    await cmp(buildP('sumA((uint256,uint256)[])', P3), 'sumA');
    await cmp(buildP('sumAB((uint256,uint256)[])', P3), 'sumAB');
    await cmp(buildP('sumA((uint256,uint256)[])', []), 'sumA empty');
  });

  it('the local is a COPY: mutating it leaves the calldata element unchanged, byte-identical', async () => {
    await cmp(buildP('copyNoAlias((uint256,uint256)[])', P3), 'copyNoAlias');
  });

  it('DYNAMIC-field (bytes) struct element bound to a local: value field + bytes length/byte', async () => {
    const D2 = [
      [9n, 'deadbeefcafe'],
      [5n, 'ff00112233445566778899aabbccddeeff'],
    ] as const;
    await cmp(buildD('dynA((uint256,bytes)[],uint256)', D2, 0n), 'dynA[0]');
    await cmp(buildD('dynA((uint256,bytes)[],uint256)', D2, 1n), 'dynA[1]');
    await cmp(buildD('dynBLen((uint256,bytes)[],uint256)', D2, 0n), 'dynBLen[0]');
    await cmp(buildD('dynBLen((uint256,bytes)[],uint256)', D2, 1n), 'dynBLen[1]');
    // dynByte(ds, i): reads byte i of element i's bytes (i in-range for both)
    await cmp(buildD('dynByte((uint256,bytes)[],uint256)', D2, 0n), 'dynByte[0]');
    await cmp(buildD('dynByte((uint256,bytes)[],uint256)', D2, 1n), 'dynByte[1]');
    // OOB element index -> Panic 0x32
    await cmp(buildD('dynA((uint256,bytes)[],uint256)', D2, 2n), 'dynA OOB');
  });

  it('DYNAMIC value-array (u256[]) field struct element bound to a local: length + sum', async () => {
    // E[] with a u256[] field; reuse the buildD shape by encoding the array tail manually is complex,
    // so encode E[] inline here: head [off=0x40 (+i)]; arr [len][off_e0]...; each E [a][off_xs=0x40][lenxs][elems].
    const buildE = (selStr: string, es: readonly (readonly [bigint, readonly bigint[]])[], i: bigint): string => {
      const head = pad32(0x40n) + pad32(i);
      const n = es.length;
      const tuples = es.map(([a, xs]) => pad32(a) + pad32(0x40n) + pad32(BigInt(xs.length)) + xs.map((v) => pad32(v)).join(''));
      let acc = BigInt(n) * 0x20n;
      const offTable: string[] = [];
      for (let k = 0; k < n; k++) {
        offTable.push(pad32(acc));
        acc += BigInt(tuples[k]!.length / 2);
      }
      const body = pad32(BigInt(n)) + offTable.join('') + tuples.join('');
      return '0x' + sel(selStr) + head + body;
    };
    const E2 = [
      [3n, [10n, 20n, 30n]],
      [7n, [1n, 2n]],
    ] as const;
    await cmp(buildE('dynArrLen((uint256,uint256[])[],uint256)', E2, 0n), 'dynArrLen[0]');
    await cmp(buildE('dynArrLen((uint256,uint256[])[],uint256)', E2, 1n), 'dynArrLen[1]');
    await cmp(buildE('dynArrSum((uint256,uint256[])[],uint256)', E2, 0n), 'dynArrSum[0]');
    await cmp(buildE('dynArrSum((uint256,uint256[])[],uint256)', E2, 1n), 'dynArrSum[1]');
    await cmp(buildE('dynArrLen((uint256,uint256[])[],uint256)', E2, 2n), 'dynArrLen OOB');
  });
});
