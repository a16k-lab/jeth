// Phase 4e-4: string[] / bytes[] (array of DYNAMIC elements) as a calldata param
// and as a return, byte-identical to Solidity. Covers: echo (n=0,1,3 incl an
// empty-string element and a >32-byte element), a[i] read + a.length, OOB Panic,
// malformed-offset/truncation EMPTY revert. The array's element-offset table base
// is the word AFTER the length word (spec section 4); element offsets are relative
// to that table start; outer offset base is calldata byte 4.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const enc = new TextEncoder();
const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract StringArray {
  function echoS(string[] calldata a) external pure returns (string[] memory){ return a; }
  function echoB(bytes[] calldata a) external pure returns (bytes[] memory){ return a; }
  function at(string[] calldata a, uint256 i) external pure returns (string memory){ return a[i]; }
  function atB(bytes[] calldata a, uint256 i) external pure returns (bytes memory){ return a[i]; }
  function count(string[] calldata a) external pure returns (uint256){ return a.length; }
}`;

const sel = (s: string) => functionSelector(s);

// Right-pad raw bytes to a 32-byte multiple, hex (no 0x). A 0-length string has no
// payload word.
function padData(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  const words = Math.ceil(bytes.length / 32);
  let h = '';
  for (let i = 0; i < words * 32; i++) h += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return h;
}

// ABI-encode a string[]/bytes[] DATA REGION (no outer offset): [len][offset table]
// [payloads]. Offsets are relative to the table start (the word after len), per
// spec section 4.1. Returns the hex (no 0x).
function encodeArrayRegion(strs: Uint8Array[]): string {
  const L = strs.length;
  // payload offsets accumulate from the table start; table is L words.
  const payloads = strs.map((s) => pad(BigInt(s.length)) + padData(s));
  let offBytes = L * 32; // first payload sits right after the table
  let table = '';
  for (const p of payloads) {
    table += pad(BigInt(offBytes));
    offBytes += p.length / 2; // hex chars / 2 = byte length of this element's encoding
  }
  return pad(BigInt(L)) + table + payloads.join('');
}

// Full calldata for a sole string[]/bytes[] param: selector + [outer off=0x20] + region.
function callArr1(selSig: string, strs: Uint8Array[]): string {
  return '0x' + sel(selSig) + pad(0x20n) + encodeArrayRegion(strs);
}
// Calldata for (string[] a, uint256 i): selector + [outer off=0x40][i] + region.
function callArr2(selSig: string, strs: Uint8Array[], i: bigint): string {
  return '0x' + sel(selSig) + pad(0x40n) + pad(i) + encodeArrayRegion(strs);
}

const s = (str: string) => enc.encode(str);

describe('string[] / bytes[] (array of dynamic) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const sr = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(sr.success);
    expect(j.returnHex, `${label} returndata`).toBe(sr.returnHex);
    return { j, s: sr };
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'StringArray.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'StringArray.jeth' });
    const sb = compileSolidity(SOL, 'StringArray');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('echoes string[] byte-identically (n=0,1,3 incl empty + >32-byte element)', async () => {
    await eq('echoS n=0', callArr1('echoS(string[])', []));
    await eq('echoS n=1', callArr1('echoS(string[])', [s('hello')]));
    // n=3: empty string, a >32-byte string, and a short one.
    const big = 'X'.repeat(40);
    const three = [s('ab'), s(''), s(big)];
    await eq('echoS n=3 (empty + >32B)', callArr1('echoS(string[])', three));
    // exact-32-byte and 33-byte boundary elements.
    await eq(
      'echoS boundary 31/32/33',
      callArr1('echoS(string[])', [s('Y'.repeat(31)), s('Z'.repeat(32)), s('W'.repeat(33))]),
    );
  });

  it('echoes bytes[] byte-identically (identical layout to string[])', async () => {
    await eq('echoB n=0', callArr1('echoB(bytes[])', []));
    const raw = new Uint8Array([0, 1, 2, 255, 0, 0, 0, 9]);
    const big = new Uint8Array(50).map((_, k) => (k * 7) & 0xff);
    await eq('echoB n=3', callArr1('echoB(bytes[])', [raw, new Uint8Array(0), big]));
  });

  it('reads a[i] (re-encoded standalone string) + a.length', async () => {
    const big = 'Q'.repeat(70);
    const arr = [s('first'), s(''), s(big)];
    let r = await eq('at i=0', callArr2('at(string[],uint256)', arr, 0n));
    r = await eq('at i=1 (empty)', callArr2('at(string[],uint256)', arr, 1n));
    r = await eq('at i=2 (>32B)', callArr2('at(string[],uint256)', arr, 2n));
    // bytes[] element read
    await eq('atB i=0', callArr2('atB(bytes[],uint256)', [new Uint8Array([1, 2, 3])], 0n));
    // length
    r = await eq('count n=3', callArr1('count(string[])', arr));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    r = await eq('count n=0', callArr1('count(string[])', []));
    expect(decodeUint(r.j.returnHex)).toBe(0n);
  });

  it('OOB index -> Panic(0x32)', async () => {
    const arr = [s('a'), s('b')];
    // i == len (==2) is OOB.
    const r = await eq('at OOB i=2', callArr2('at(string[],uint256)', arr, 2n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
    // far OOB
    await eq('at OOB i=99', callArr2('at(string[],uint256)', arr, 99n));
  });

  it('malformed: bad outer offset / truncated table / bad element offset -> EMPTY revert', async () => {
    // outer offset points past calldata.
    const off = '0x' + sel('count(string[])') + pad(0x1000n);
    let r = await eq('count bad outer offset', off);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // declares len=3 but only 1 table word present (truncated offset table).
    const trunc = '0x' + sel('count(string[])') + pad(0x20n) + pad(3n) + pad(0x60n);
    r = await eq('count truncated table', trunc);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // len=1, element offset points past calldata -> empty revert on the a[i] read.
    const badElemOff = '0x' + sel('at(string[],uint256)') + pad(0x40n) + pad(0n) + pad(1n) + pad(0x1000n);
    r = await eq('at bad element offset', badElemOff);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // len=1, valid table word (off=0x20) but element length implies payload past
    // calldatasize (declares 0x40-byte string with no payload words).
    const badPayload = '0x' + sel('at(string[],uint256)') + pad(0x40n) + pad(0n) + pad(1n) + pad(0x20n) + pad(0x40n);
    r = await eq('at element payload past end', badPayload);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');

    // element offsets given relative to the WRONG base (calldata byte 0 instead of
    // the table start): here a too-large table offset -> length word OOB -> empty.
    const wrongBase = '0x' + sel('at(string[],uint256)') + pad(0x40n) + pad(0n) + pad(1n) + pad(0x100n);
    r = await eq('at wrong-base offset', wrongBase);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('non-canonical but in-range element offsets are accepted (no alignment/order checks)', async () => {
    // Build a string[] of 2 elements ["WX"(2B), "Y"*40(40B)] laid out canonically,
    // then read both via at(); JETH must match solc exactly (pure pointer arithmetic).
    const arr = [s('WX'), s('Y'.repeat(40))];
    await eq('at noncanon i=0', callArr2('at(string[],uint256)', arr, 0n));
    await eq('at noncanon i=1', callArr2('at(string[],uint256)', arr, 1n));
    // Decoy/overlap: both table words point at the SAME element (the first). solc
    // accepts overlapping offsets; both reads return that element.
    const L = 2;
    const e0 = pad(2n) + padData(s('WX'));
    const e1 = pad(40n) + padData(s('Y'.repeat(40)));
    const tableStartToFirst = L * 32; // 0x40
    // both offsets -> first element.
    const region = pad(BigInt(L)) + pad(BigInt(tableStartToFirst)) + pad(BigInt(tableStartToFirst)) + e0 + e1;
    const data = '0x' + sel('at(string[],uint256)') + pad(0x40n) + pad(1n) + region;
    const r = await eq('at overlapping offsets i=1->first', data);
    expect(r.j.success).toBe(true);
  });
});
