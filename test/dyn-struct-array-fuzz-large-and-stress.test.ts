// Phase 4e-1 scenario "large-and-stress": dynamic array of static struct as a
// calldata param under stress. Pt[] (stride 2 words) at lengths 0,1,2,17,64 echoed
// byte-for-byte (0x20 head + length word + all element words). Getters at the last
// index and length-1, OOB at exactly length (Panic 0x32) vs length-1 (OK). Plus a
// struct array S[] with a single uint256 field (stride 1 word) to confirm it still
// echoes/validates like a struct (not a value-element array). All vs Solidity oracle.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

// JETH source for the stress contract.
const JETH = `// stress: dynamic array of static struct
@struct class Pt { x: u128; y: u128; }
@struct class S { v: u256; }

@contract
class Stress {
  @external @pure echoPts(ps: Pt[]): Pt[] { return ps; }
  @external @pure ptX(ps: Pt[], i: u256): u128 { return ps[i].x; }
  @external @pure ptY(ps: Pt[], i: u256): u128 { return ps[i].y; }
  @external @pure len(ps: Pt[]): u256 { return ps.length; }
  @external @pure echoS(a: S[]): S[] { return a; }
  @external @pure sV(a: S[], i: u256): u256 { return a[i].v; }
}`;

// Faithful Solidity mirror (struct expands to tuple in the selector).
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Stress {
  struct Pt { uint128 x; uint128 y; }
  struct S { uint256 v; }
  function echoPts(Pt[] calldata ps) external pure returns (Pt[] memory){ return ps; }
  function ptX(Pt[] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].x; }
  function ptY(Pt[] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].y; }
  function len(Pt[] calldata ps) external pure returns (uint256){ return ps.length; }
  function echoS(S[] calldata a) external pure returns (S[] memory){ return a; }
  function sV(S[] calldata a, uint256 i) external pure returns (uint256){ return a[i].v; }
}`;

describe('Phase 4e-1 large-and-stress: dyn array of static struct vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);

  // sole dynamic-array param: head = [offset=0x20], then [len][flat words]
  const arr1 = (selSig: string, flat: bigint[], len: number) =>
    '0x' + sel(selSig) + pad(0x20n) + pad(BigInt(len)) + flat.map(pad).join('');
  // (dynamic-array, uint256 i): head = [offset=0x40][i], then [len][flat words]
  const arr2 = (selSig: string, flat: bigint[], len: number, i: bigint) =>
    '0x' + sel(selSig) + pad(0x40n) + pad(i) + pad(BigInt(len)) + flat.map(pad).join('');

  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'Stress.jeth' });
    const sb = compileSolidity(SOL, 'Stress');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // Build a deterministic Pt[] flat word list of `n` structs: x=10*k+1, y=10*k+2.
  const ptsFlat = (n: number): bigint[] => {
    const out: bigint[] = [];
    for (let k = 0; k < n; k++) {
      out.push(BigInt(10 * k + 1));
      out.push(BigInt(10 * k + 2));
    }
    return out;
  };

  it('echoes Pt[] byte-for-byte across stress lengths 0,1,2,17,64', async () => {
    const ECHO = 'echoPts((uint128,uint128)[])';
    for (const n of [0, 1, 2, 17, 64]) {
      const flat = ptsFlat(n);
      const r = await eq(`echoPts n=${n}`, arr1(ECHO, flat, n));
      // Sanity: returndata is [0x20 head][len][2*n element words] = (2 + 2n) words.
      const wordsHex = r.s.returnHex.slice(2);
      expect(wordsHex.length, `echoPts n=${n} word count`).toBe((2 + 2 * n) * 64);
      // Confirm the decoded length word matches n.
      expect(decodeUint('0x' + wordsHex.slice(64, 128))).toBe(BigInt(n));
    }
  });

  it('length getter matches across stress lengths', async () => {
    const LEN = 'len((uint128,uint128)[])';
    for (const n of [0, 1, 2, 17, 64]) {
      const r = await eq(`len n=${n}`, arr1(LEN, ptsFlat(n), n));
      expect(decodeUint(r.j.returnHex)).toBe(BigInt(n));
    }
  });

  it('getter at last index (length-1) ok; OOB at exactly length Panics(0x32)', async () => {
    const PTX = 'ptX((uint128,uint128)[],uint256)';
    const PTY = 'ptY((uint128,uint128)[],uint256)';
    const PANIC32 = '0x4e487b71' + '0000000000000000000000000000000000000000000000000000000000000032';
    for (const n of [1, 2, 17, 64]) {
      const flat = ptsFlat(n);
      const last = BigInt(n - 1);
      // ptX at the last valid index.
      let r = await eq(`ptX n=${n} i=len-1`, arr2(PTX, flat, n, last));
      expect(decodeUint(r.j.returnHex)).toBe(BigInt(10 * (n - 1) + 1));
      // ptY at the last valid index.
      r = await eq(`ptY n=${n} i=len-1`, arr2(PTY, flat, n, last));
      expect(decodeUint(r.j.returnHex)).toBe(BigInt(10 * (n - 1) + 2));
      // OOB at exactly i==length -> Panic(0x32), byte-identical.
      r = await eq(`ptX n=${n} i==len OOB`, arr2(PTX, flat, n, BigInt(n)));
      expect(r.j.success).toBe(false);
      expect(r.j.returnHex).toBe(PANIC32);
    }
    // length 0: index 0 is already OOB -> Panic(0x32).
    const r0 = await eq('ptX n=0 i=0 OOB', arr2(PTX, [], 0, 0n));
    expect(r0.j.success).toBe(false);
    expect(r0.j.returnHex).toBe(PANIC32);
  });

  it('single-field struct array S[] (stride 1 word) still echoes + validates like a struct', async () => {
    const ECHO = 'echoS((uint256)[])';
    const SV = 'sV((uint256)[],uint256)';
    // clean echo across lengths: returndata is [0x20][len][n words].
    for (const n of [0, 1, 2, 17, 64]) {
      const flat: bigint[] = [];
      for (let k = 0; k < n; k++) flat.push(BigInt(1000 + k));
      const r = await eq(`echoS n=${n}`, arr1(ECHO, flat, n));
      expect(r.s.returnHex.slice(2).length, `echoS n=${n} word count`).toBe((2 + n) * 64);
      expect(decodeUint('0x' + r.s.returnHex.slice(2).slice(64, 128))).toBe(BigInt(n));
    }
    // field read at last index and length-1.
    const flat = [111n, 222n, 333n];
    let r = await eq('sV i=len-1', arr2(SV, flat, 3, 2n));
    expect(decodeUint(r.j.returnHex)).toBe(333n);
    // OOB at exactly length -> Panic(0x32).
    const PANIC32 = '0x4e487b71' + '0000000000000000000000000000000000000000000000000000000000000032';
    r = await eq('sV i==len OOB', arr2(SV, flat, 3, 3n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(PANIC32);
    // A uint256 leaf cannot be "dirty" (full word), so echo never reverts; whole-array
    // copy still validates by reading every leaf. Confirm a large clean value echoes.
    const big = (1n << 255n) | 7n;
    r = await eq('echoS big-clean', arr1(ECHO, [big, 5n], 2));
    expect(r.j.success).toBe(true);
  });

  it('whole-array echo VALIDATES every field: any dirty field -> empty revert (0x)', async () => {
    const ECHO = 'echoPts((uint128,uint128)[])';
    // Three clean Pts, then make the y of the middle element dirty (high bits set).
    const flat = ptsFlat(3);
    flat[3] = (1n << 200n) | flat[3]!; // ps[1].y dirty
    const r = await eq('echoPts dirty-mid->revert', arr1(ECHO, flat, 3));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // Dirty the very first field of a long (17) array.
    const flat17 = ptsFlat(17);
    flat17[0] = (1n << 128n) | flat17[0]!; // ps[0].x dirty
    const r2 = await eq('echoPts dirty-head-n17->revert', arr1(ECHO, flat17, 17));
    expect(r2.j.success).toBe(false);
    expect(r2.j.returnHex).toBe('0x');
    // Dirty the very last field of a 64-long array.
    const flat64 = ptsFlat(64);
    flat64[127] = (1n << 130n) | flat64[127]!; // ps[63].y dirty
    const r3 = await eq('echoPts dirty-tail-n64->revert', arr1(ECHO, flat64, 64));
    expect(r3.j.success).toBe(false);
    expect(r3.j.returnHex).toBe('0x');
  });
});
