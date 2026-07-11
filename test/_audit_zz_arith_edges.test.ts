// THROWAWAY audit harness: broad arithmetic / cast / shift / exponent edge hunt.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

// Arithmetic / cast / shift / exponent surface. Mirrors solc 0.8.x cancun.
const JETH = `class A {
  // checked arithmetic at narrow widths
  get addU8(a: u8, b: u8): External<u8> { return a + b; }
  get subU8(a: u8, b: u8): External<u8> { return a - b; }
  get mulU8(a: u8, b: u8): External<u8> { return a * b; }
  get addI8(a: i8, b: i8): External<i8> { return a + b; }
  get subI8(a: i8, b: i8): External<i8> { return a - b; }
  get mulI8(a: i8, b: i8): External<i8> { return a * b; }
  get divI8(a: i8, b: i8): External<i8> { return a / b; }
  get modI8(a: i8, b: i8): External<i8> { return a % b; }
  get negI8(a: i8): External<i8> { return -a; }
  get negI256(a: i256): External<i256> { return -a; }
  get divI256(a: i256, b: i256): External<i256> { return a / b; }
  get modI256(a: i256, b: i256): External<i256> { return a % b; }
  // unchecked
  get uAddU8(a: u8, b: u8): External<u8> { unchecked: { return a + b; } }
  get uSubU8(a: u8, b: u8): External<u8> { unchecked: { return a - b; } }
  get uMulU8(a: u8, b: u8): External<u8> { unchecked: { return a * b; } }
  get uNegI8(a: i8): External<i8> { unchecked: { return -a; } }
  get uDivI8(a: i8, b: i8): External<i8> { unchecked: { return a / b; } }
  get uDivI256(a: i256, b: i256): External<i256> { unchecked: { return a / b; } }
  get uAddI256(a: i256, b: i256): External<i256> { unchecked: { return a + b; } }
  get uMulI256(a: i256, b: i256): External<i256> { unchecked: { return a * b; } }
  // exponent
  get powU8(a: u8, b: u8): External<u8> { return a ** b; }
  get powU256(a: u256, b: u256): External<u256> { return a ** b; }
  get powI8(a: i8, b: u8): External<i8> { return a ** b; }
  get powI256(a: i256, b: u256): External<i256> { return a ** b; }
  get uPowU8(a: u8, b: u8): External<u8> { unchecked: { return a ** b; } }
  get uPowI8(a: i8, b: u8): External<i8> { unchecked: { return a ** b; } }
  // shifts
  get shlU8(a: u8, s: u8): External<u8> { return a << s; }
  get shrU8(a: u8, s: u8): External<u8> { return a >> s; }
  get shlI8(a: i8, s: u8): External<i8> { return a << s; }
  get shrI8(a: i8, s: u8): External<i8> { return a >> s; }
  get shlU256(a: u256, s: u256): External<u256> { return a << s; }
  get shrI256(a: i256, s: u256): External<i256> { return a >> s; }
  // bit ops on narrow
  get notU8(a: u8): External<u8> { return ~a; }
  get notI8(a: i8): External<i8> { return ~a; }
  get andU8(a: u8, b: u8): External<u8> { return a & b; }
  // casts
  get i256ToI8(a: i256): External<i8> { return i8(a); }
  get u256ToU8(a: u256): External<u8> { return u8(a); }
  get i8ToU8(a: i8): External<u8> { return u8(a); }
  get u8ToI8(a: u8): External<i8> { return i8(a); }
  get i8ToI256(a: i8): External<i256> { return i256(a); }
  get u8ToU256(a: u8): External<u256> { return u256(a); }
  get b32ToU256(a: bytes32): External<u256> { return u256(a); }
  get u256ToB32(a: u256): External<bytes32> { return bytes32(a); }
  get b4ToU32(a: bytes4): External<u32> { return u32(a); }
  get u32ToB4(a: u32): External<bytes4> { return bytes4(a); }
  get b32ToB4(a: bytes32): External<bytes4> { return bytes4(a); }
  get b4ToB32(a: bytes4): External<bytes32> { return bytes32(a); }
  // cross-sign + narrowing must be two-step (both solc and JETH reject a single u8(i16))
  get i16ToU8(a: i16): External<u8> { return u8(u16(a)); }
  get u16ToI8(a: u16): External<i8> { return i8(i16(a)); }
  // mixed-width implicit widen arith
  get mixAdd(a: u8, b: u16): External<u16> { return a + b; }
  get mixMul(a: i8, b: i32): External<i32> { return a * b; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  function addU8(uint8 a, uint8 b) external pure returns (uint8){ return a + b; }
  function subU8(uint8 a, uint8 b) external pure returns (uint8){ return a - b; }
  function mulU8(uint8 a, uint8 b) external pure returns (uint8){ return a * b; }
  function addI8(int8 a, int8 b) external pure returns (int8){ return a + b; }
  function subI8(int8 a, int8 b) external pure returns (int8){ return a - b; }
  function mulI8(int8 a, int8 b) external pure returns (int8){ return a * b; }
  function divI8(int8 a, int8 b) external pure returns (int8){ return a / b; }
  function modI8(int8 a, int8 b) external pure returns (int8){ return a % b; }
  function negI8(int8 a) external pure returns (int8){ return -a; }
  function negI256(int256 a) external pure returns (int256){ return -a; }
  function divI256(int256 a, int256 b) external pure returns (int256){ return a / b; }
  function modI256(int256 a, int256 b) external pure returns (int256){ return a % b; }
  function uAddU8(uint8 a, uint8 b) external pure returns (uint8){ unchecked { return a + b; } }
  function uSubU8(uint8 a, uint8 b) external pure returns (uint8){ unchecked { return a - b; } }
  function uMulU8(uint8 a, uint8 b) external pure returns (uint8){ unchecked { return a * b; } }
  function uNegI8(int8 a) external pure returns (int8){ unchecked { return -a; } }
  function uDivI8(int8 a, int8 b) external pure returns (int8){ unchecked { return a / b; } }
  function uDivI256(int256 a, int256 b) external pure returns (int256){ unchecked { return a / b; } }
  function uAddI256(int256 a, int256 b) external pure returns (int256){ unchecked { return a + b; } }
  function uMulI256(int256 a, int256 b) external pure returns (int256){ unchecked { return a * b; } }
  function powU8(uint8 a, uint8 b) external pure returns (uint8){ return a ** b; }
  function powU256(uint256 a, uint256 b) external pure returns (uint256){ return a ** b; }
  function powI8(int8 a, uint8 b) external pure returns (int8){ return a ** b; }
  function powI256(int256 a, uint256 b) external pure returns (int256){ return a ** b; }
  function uPowU8(uint8 a, uint8 b) external pure returns (uint8){ unchecked { return a ** b; } }
  function uPowI8(int8 a, uint8 b) external pure returns (int8){ unchecked { return a ** b; } }
  function shlU8(uint8 a, uint8 s) external pure returns (uint8){ return a << s; }
  function shrU8(uint8 a, uint8 s) external pure returns (uint8){ return a >> s; }
  function shlI8(int8 a, uint8 s) external pure returns (int8){ return a << s; }
  function shrI8(int8 a, uint8 s) external pure returns (int8){ return a >> s; }
  function shlU256(uint256 a, uint256 s) external pure returns (uint256){ return a << s; }
  function shrI256(int256 a, uint256 s) external pure returns (int256){ return a >> s; }
  function notU8(uint8 a) external pure returns (uint8){ return ~a; }
  function notI8(int8 a) external pure returns (int8){ return ~a; }
  function andU8(uint8 a, uint8 b) external pure returns (uint8){ return a & b; }
  function i256ToI8(int256 a) external pure returns (int8){ return int8(a); }
  function u256ToU8(uint256 a) external pure returns (uint8){ return uint8(a); }
  function i8ToU8(int8 a) external pure returns (uint8){ return uint8(a); }
  function u8ToI8(uint8 a) external pure returns (int8){ return int8(a); }
  function i8ToI256(int8 a) external pure returns (int256){ return int256(a); }
  function u8ToU256(uint8 a) external pure returns (uint256){ return uint256(a); }
  function b32ToU256(bytes32 a) external pure returns (uint256){ return uint256(a); }
  function u256ToB32(uint256 a) external pure returns (bytes32){ return bytes32(a); }
  function b4ToU32(bytes4 a) external pure returns (uint32){ return uint32(a); }
  function u32ToB4(uint32 a) external pure returns (bytes4){ return bytes4(a); }
  function b32ToB4(bytes32 a) external pure returns (bytes4){ return bytes4(a); }
  function b4ToB32(bytes4 a) external pure returns (bytes32){ return bytes32(a); }
  function i16ToU8(int16 a) external pure returns (uint8){ return uint8(uint16(a)); }
  function u16ToI8(uint16 a) external pure returns (int8){ return int8(int16(a)); }
  function mixAdd(uint8 a, uint16 b) external pure returns (uint16){ return a + b; }
  function mixMul(int8 a, int32 b) external pure returns (int32){ return a * b; }
}`;

describe('arithmetic/cast/shift/exponent edge differential', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  let mismatches: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex) {
      mismatches.push(
        `${label}: jeth{ok=${j.success},ret=${j.returnHex},err=${j.exceptionError}} sol{ok=${s.success},ret=${s.returnHex}}`,
      );
    }
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'A.jeth' });
    const sb = compileSolidity(SOL, 'A');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    const u8s = [0n, 1n, 2n, 3n, 7n, 15n, 16n, 100n, 127n, 128n, 200n, 254n, 255n];
    const i8s = [-128n, -127n, -100n, -2n, -1n, 0n, 1n, 2n, 100n, 126n, 127n];
    const bigs = [
      0n,
      1n,
      2n,
      (1n << 255n) - 1n,
      1n << 255n,
      (1n << 255n) + 1n,
      M - 1n,
      M - 2n,
      1n << 128n,
      0xdeadbeefn,
    ];
    const i256s = [-(1n << 255n), -(1n << 255n) + 1n, -1n, 0n, 1n, (1n << 255n) - 1n, -42n, 12345n, -(1n << 200n)];

    for (const a of u8s)
      for (const b of u8s) {
        await eq(`addU8(${a},${b})`, encodeCall(sel('addU8(uint8,uint8)'), [a, b]));
        await eq(`subU8(${a},${b})`, encodeCall(sel('subU8(uint8,uint8)'), [a, b]));
        await eq(`mulU8(${a},${b})`, encodeCall(sel('mulU8(uint8,uint8)'), [a, b]));
        await eq(`uAddU8(${a},${b})`, encodeCall(sel('uAddU8(uint8,uint8)'), [a, b]));
        await eq(`uSubU8(${a},${b})`, encodeCall(sel('uSubU8(uint8,uint8)'), [a, b]));
        await eq(`uMulU8(${a},${b})`, encodeCall(sel('uMulU8(uint8,uint8)'), [a, b]));
        await eq(`andU8(${a},${b})`, encodeCall(sel('andU8(uint8,uint8)'), [a, b]));
      }
    for (const a of i8s)
      for (const b of i8s) {
        await eq(`addI8(${a},${b})`, encodeCall(sel('addI8(int8,int8)'), [a, b]));
        await eq(`subI8(${a},${b})`, encodeCall(sel('subI8(int8,int8)'), [a, b]));
        await eq(`mulI8(${a},${b})`, encodeCall(sel('mulI8(int8,int8)'), [a, b]));
        await eq(`divI8(${a},${b})`, encodeCall(sel('divI8(int8,int8)'), [a, b]));
        await eq(`modI8(${a},${b})`, encodeCall(sel('modI8(int8,int8)'), [a, b]));
        await eq(`uDivI8(${a},${b})`, encodeCall(sel('uDivI8(int8,int8)'), [a, b]));
      }
    for (const a of i8s) {
      await eq(`negI8(${a})`, encodeCall(sel('negI8(int8)'), [a]));
      await eq(`uNegI8(${a})`, encodeCall(sel('uNegI8(int8)'), [a]));
      await eq(`notI8(${a})`, encodeCall(sel('notI8(int8)'), [a]));
      await eq(`u8ToI8(${a & 255n})`, encodeCall(sel('u8ToI8(uint8)'), [a & 255n]));
    }
    for (const a of u8s) {
      await eq(`notU8(${a})`, encodeCall(sel('notU8(uint8)'), [a]));
      await eq(`i8ToU8(${a})`, encodeCall(sel('i8ToU8(int8)'), [a]));
      await eq(`u8ToU256(${a})`, encodeCall(sel('u8ToU256(uint8)'), [a]));
      await eq(`i8ToI256(${a})`, encodeCall(sel('i8ToI256(int8)'), [a]));
    }
    for (const a of i256s)
      for (const b of i256s) {
        await eq(`divI256(${a},${b})`, encodeCall(sel('divI256(int256,int256)'), [a, b]));
        await eq(`modI256(${a},${b})`, encodeCall(sel('modI256(int256,int256)'), [a, b]));
        await eq(`uDivI256(${a},${b})`, encodeCall(sel('uDivI256(int256,int256)'), [a, b]));
        await eq(`uAddI256(${a},${b})`, encodeCall(sel('uAddI256(int256,int256)'), [a, b]));
        await eq(`uMulI256(${a},${b})`, encodeCall(sel('uMulI256(int256,int256)'), [a, b]));
      }
    for (const a of i256s) await eq(`negI256(${a})`, encodeCall(sel('negI256(int256)'), [a]));
    // exponent
    for (const a of u8s)
      for (const b of [0n, 1n, 2n, 3n, 4n, 5n, 7n, 8n, 255n]) {
        await eq(`powU8(${a},${b})`, encodeCall(sel('powU8(uint8,uint8)'), [a, b]));
        await eq(`uPowU8(${a},${b})`, encodeCall(sel('uPowU8(uint8,uint8)'), [a, b]));
      }
    for (const a of i8s)
      for (const b of [0n, 1n, 2n, 3n, 4n, 5n, 7n]) {
        await eq(`powI8(${a},${b})`, encodeCall(sel('powI8(int8,uint8)'), [a, b]));
        await eq(`uPowI8(${a},${b})`, encodeCall(sel('uPowI8(int8,uint8)'), [a, b]));
      }
    for (const a of [0n, 1n, 2n, 3n, 10n, 255n, 256n, 65535n, 1n << 200n])
      for (const b of [0n, 1n, 2n, 3n, 5n, 32n, 64n, 255n, 256n, 1000n]) {
        await eq(`powU256(${a},${b})`, encodeCall(sel('powU256(uint256,uint256)'), [a, b]));
      }
    for (const a of i256s)
      for (const b of [0n, 1n, 2n, 3n, 5n, 200n, 255n]) {
        await eq(`powI256(${a},${b})`, encodeCall(sel('powI256(int256,uint256)'), [a, b]));
      }
    // shifts
    for (const a of u8s)
      for (const s of [0n, 1n, 2n, 4n, 7n, 8n, 9n, 16n, 255n, 256n, 300n]) {
        await eq(`shlU8(${a},${s})`, encodeCall(sel('shlU8(uint8,uint8)'), [a, s]));
        await eq(`shrU8(${a},${s})`, encodeCall(sel('shrU8(uint8,uint8)'), [a, s]));
      }
    for (const a of i8s)
      for (const s of [0n, 1n, 2n, 4n, 7n, 8n, 9n, 16n, 255n]) {
        await eq(`shlI8(${a},${s})`, encodeCall(sel('shlI8(int8,uint8)'), [a, s]));
        await eq(`shrI8(${a},${s})`, encodeCall(sel('shrI8(int8,uint8)'), [a, s]));
      }
    for (const a of bigs)
      for (const s of [0n, 1n, 127n, 128n, 255n, 256n, 257n, 1000n]) {
        await eq(`shlU256(${a},${s})`, encodeCall(sel('shlU256(uint256,uint256)'), [a, s]));
      }
    for (const a of i256s)
      for (const s of [0n, 1n, 127n, 128n, 255n, 256n, 300n]) {
        await eq(`shrI256(${a},${s})`, encodeCall(sel('shrI256(int256,uint256)'), [a, s]));
      }
    // casts (full-word inputs)
    for (const a of bigs) {
      await eq(`i256ToI8(${a})`, encodeCall(sel('i256ToI8(int256)'), [a]));
      await eq(`u256ToU8(${a})`, encodeCall(sel('u256ToU8(uint256)'), [a]));
      await eq(`b32ToU256(${a})`, encodeCall(sel('b32ToU256(bytes32)'), [a]));
      await eq(`u256ToB32(${a})`, encodeCall(sel('u256ToB32(uint256)'), [a]));
      await eq(`b32ToB4(${a})`, encodeCall(sel('b32ToB4(bytes32)'), [a]));
    }
    for (const a of [0n, 0xffffffffn, 0x12345678n, 0xdeadbeefn, 0x80000000n]) {
      await eq(`b4ToU32(${a})`, encodeCall(sel('b4ToU32(bytes4)'), [a << (28n * 8n)]));
      await eq(`u32ToB4(${a})`, encodeCall(sel('u32ToB4(uint32)'), [a]));
      await eq(`b4ToB32(${a})`, encodeCall(sel('b4ToB32(bytes4)'), [a << (28n * 8n)]));
    }
    for (const a of [0n, 1n, 127n, 128n, 255n, 256n, 1000n, 32767n, 32768n, 65535n]) {
      await eq(`i16ToU8(${a})`, encodeCall(sel('i16ToU8(int16)'), [a]));
      await eq(`u16ToI8(${a})`, encodeCall(sel('u16ToI8(uint16)'), [a]));
    }
    // mixed-width
    for (const a of u8s)
      for (const b of [0n, 1n, 255n, 256n, 65535n, 65280n]) {
        await eq(`mixAdd(${a},${b})`, encodeCall(sel('mixAdd(uint8,uint16)'), [a, b]));
      }
    for (const a of i8s)
      for (const b of [0n, 1n, -1n, 100n, -100n, (1n << 31n) - 1n, -(1n << 31n), 1000000n]) {
        await eq(`mixMul(${a},${b})`, encodeCall(sel('mixMul(int8,int32)'), [a, b]));
      }

    if (mismatches.length) {
      console.log(`\n=== ${mismatches.length} MISMATCHES (of ${count} cases) ===`);
      for (const m of mismatches.slice(0, 60)) console.log(m);
    } else {
      console.log(`\nAll ${count} arith/cast/shift cases byte-identical.`);
    }
    expect(mismatches, mismatches.slice(0, 20).join('\n')).toEqual([]);
  });
});
