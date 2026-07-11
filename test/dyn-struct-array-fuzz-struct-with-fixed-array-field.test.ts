// Phase 4e-1 scenario "struct-with-fixed-array-field": a DYNAMIC ARRAY of a STATIC
// struct whose element struct has a FIXED-ARRAY field.
//   WithArr { uint64 id; uint256[2] data; }   ->  element stride = 3 leaf words.
// Differential vs Solidity (the oracle), byte-for-byte on returndata + success +
// revert form. Covered ops:
//   - ps[i].id            element value-field read (bounds-check -> Panic(0x32) OOB)
//   - echo WithArr[]      whole-array copy VALIDATES every leaf field (reads all),
//                         so a single dirty id reverts EMPTY (struct-element echo
//                         does NOT clean, unlike a value-element array).
//   - ps.length
//   - up-front payload check uses stride 3: declare len but supply short payload
//     (one element's worth missing) -> EMPTY revert independent of any index.
//   - ps[i].data[j]: inner fixed-array element of a dyn-array struct element, read
//     byte-identically (element word at i*stride + dataFieldHeadWord + j), with
//     OOB Panic(0x32) on both the outer index and the inner fixed-array index.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

// JETH source (inline). Element struct has a fixed-array field: stride = 3 words.
const JETH = `type WithArr = { id: u64; data: Arr<u256, 2>; };
class StructWithFixedArrayField {
  get echoArr(ps: WithArr[]): External<WithArr[]> { return ps; }
  get idAt(ps: WithArr[], i: u256): External<u64> { return ps[i].id; }
  get lenOf(ps: WithArr[]): External<u256> { return ps.length; }
  get dataAt(ps: WithArr[], i: u256, j: u256): External<u256> { return ps[i].data[j]; }
}`;

// Faithful Solidity mirror. Selector expands the struct to a tuple:
//   echoArr((uint64,uint256[2])[]) etc.
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract StructWithFixedArrayField {
  struct WithArr { uint64 id; uint256[2] data; }
  function echoArr(WithArr[] calldata ps) external pure returns (WithArr[] memory){ return ps; }
  function idAt(WithArr[] calldata ps, uint256 i) external pure returns (uint64){ return ps[i].id; }
  function lenOf(WithArr[] calldata ps) external pure returns (uint256){ return ps.length; }
  function dataAt(WithArr[] calldata ps, uint256 i, uint256 j) external pure returns (uint256){ return ps[i].data[j]; }
}`;

const ECHO = 'echoArr((uint64,uint256[2])[])';
const IDAT = 'idAt((uint64,uint256[2])[],uint256)';
const LEN = 'lenOf((uint64,uint256[2])[])';
const DAT = 'dataAt((uint64,uint256[2])[],uint256,uint256)';

describe('struct-with-fixed-array-field (WithArr[]) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);

  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  // sole dyn-array param: head = [offset=0x20], then [len][flat words]
  const arr1 = (selSig: string, flat: bigint[], len: number) =>
    '0x' + sel(selSig) + pad(0x20n) + pad(BigInt(len)) + flat.map(pad).join('');
  // (dyn-array, uint256 i): head = [offset=0x40][i], then [len][flat words]
  const arr2 = (selSig: string, flat: bigint[], len: number, i: bigint) =>
    '0x' + sel(selSig) + pad(0x40n) + pad(i) + pad(BigInt(len)) + flat.map(pad).join('');
  // (dyn-array, uint256 i, uint256 j): head = [offset=0x60][i][j], then [len][flat words]
  const arr3 = (selSig: string, flat: bigint[], len: number, i: bigint, j: bigint) =>
    '0x' + sel(selSig) + pad(0x60n) + pad(i) + pad(j) + pad(BigInt(len)) + flat.map(pad).join('');

  // one WithArr element = [id][data0][data1] (3 unpacked words)
  const elem = (id: bigint, d0: bigint, d1: bigint) => [id, d0, d1];

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'StructWithFixedArrayField.jeth' });
    const sb = compileSolidity(SOL, 'StructWithFixedArrayField');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('echoes WithArr[] byte-identically (stride = 3 words)', async () => {
    // 2 elements: {1,[10,11]}, {2,[20,21]}
    const two = [...elem(1n, 10n, 11n), ...elem(2n, 20n, 21n)];
    await eq('echoArr n=2', arr1(ECHO, two, 2));
    await eq('echoArr n=0', arr1(ECHO, [], 0));
    await eq('echoArr n=1', arr1(ECHO, elem(7n, 70n, 71n), 1));
  });

  it('whole-array echo VALIDATES every field: dirty id -> EMPTY revert', async () => {
    // clean baseline (1 elem) must round-trip
    await eq('echoArr clean', arr1(ECHO, elem(5n, 100n, 101n), 1));
    // dirty id: bit 64 set (id is uint64, so high bits are dirty). data words are
    // full uint256 so never dirty. Whole-array struct echo reads all leaves -> revert.
    const dirtyId = [(1n << 64n) | 5n, 100n, 101n];
    const r = await eq('echoArr dirty id -> revert', arr1(ECHO, dirtyId, 1));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('reads ps[i].id with bounds-check Panic(0x32) on OOB', async () => {
    const two = [...elem(0xa1n, 1n, 2n), ...elem(0xb2n, 3n, 4n)];
    let r = await eq('idAt i=0', arr2(IDAT, two, 2, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(0xa1n);
    r = await eq('idAt i=1', arr2(IDAT, two, 2, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(0xb2n);
    // OOB i=2 (len 2) -> Panic(0x32), identical revert bytes
    r = await eq('idAt OOB i=2', arr2(IDAT, two, 2, 2n));
    expect(r.j.success).toBe(false);
    // dirty id single read -> EMPTY revert (never masks)
    r = await eq('idAt dirty id', arr2(IDAT, [(1n << 64n) | 5n, 100n, 101n], 1, 0n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('ps.length', async () => {
    const three = [...elem(1n, 0n, 0n), ...elem(2n, 0n, 0n), ...elem(3n, 0n, 0n)];
    const r = await eq('lenOf n=3', arr1(LEN, three, 3));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
  });

  it('up-front payload check uses stride 3 (declare len=2, supply 1 element + extra word -> EMPTY)', async () => {
    // Declare len=2 -> required payload = 2 * 3 = 6 words past the length slot.
    // Supply only 5 words (1 full element = 3 words, plus 2 extra). Because the
    // up-front length*stride bound exceeds calldatasize, decode reverts EMPTY
    // BEFORE touching any index -- proving stride 3 (not stride 1).
    const fiveWords = [1n, 10n, 11n, 2n, 20n]; // 5 words < 6 required
    const truncated = '0x' + sel(ECHO) + pad(0x20n) + pad(2n) + fiveWords.map(pad).join('');
    const r = await eq('echoArr len=2 short payload -> EMPTY', truncated);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // Control: the SAME 6-word payload with len=2 must succeed (stride 3 satisfied).
    const sixWords = [...elem(1n, 10n, 11n), ...elem(2n, 20n, 21n)];
    const okFull = arr1(ECHO, sixWords, 2);
    const ro = await eq('echoArr len=2 full payload -> ok', okFull);
    expect(ro.j.success).toBe(true);

    // Boundary: exactly 5 words but len=1 (needs 3) -> succeeds, isolating that the
    // failure above is the per-element stride times length, not generic shortness.
    const len1ok = arr1(ECHO, [1n, 10n, 11n], 1);
    const r1 = await eq('echoArr len=1 (3 words) -> ok', len1ok);
    expect(r1.j.success).toBe(true);

    // If stride were mistakenly 1, len=5 over 5 supplied words would pass; it must
    // NOT (needs 15 words) -> EMPTY, further pinning stride=3 behavior.
    const wrongStride = '0x' + sel(ECHO) + pad(0x20n) + pad(5n) + fiveWords.map(pad).join('');
    const rw = await eq('echoArr len=5 over 5 words -> EMPTY', wrongStride);
    expect(rw.j.success).toBe(false);
    expect(rw.j.returnHex).toBe('0x');
  });

  it('reads ps[i].data[j] (inner fixed-array element) byte-identically incl OOB Panic(0x32)', async () => {
    // 2 elements: {1,[10,11]}, {2,[20,21]}; stride 3, data field at head word 1.
    const two = [...elem(1n, 10n, 11n), ...elem(2n, 20n, 21n)];
    let r = await eq('dataAt i=0 j=0', arr3(DAT, two, 2, 0n, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(10n);
    r = await eq('dataAt i=0 j=1', arr3(DAT, two, 2, 0n, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(11n);
    r = await eq('dataAt i=1 j=0', arr3(DAT, two, 2, 1n, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(20n);
    r = await eq('dataAt i=1 j=1', arr3(DAT, two, 2, 1n, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(21n);
    // inner OOB j=2 (fixed length 2) -> Panic(0x32), byte-identical revert
    r = await eq('dataAt i=0 j=2 OOB', arr3(DAT, two, 2, 0n, 2n));
    expect(r.j.success).toBe(false);
    // outer OOB i=2 (len 2) -> Panic(0x32), byte-identical revert
    r = await eq('dataAt i=2 j=0 OOB', arr3(DAT, two, 2, 2n, 0n));
    expect(r.j.success).toBe(false);
    // both OOB -> still byte-identical (whichever solc checks first)
    await eq('dataAt i=9 j=9 OOB', arr3(DAT, two, 2, 9n, 9n));
  });
});
