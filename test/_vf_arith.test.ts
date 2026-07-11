// _vf_arith: adversarial differential probe for integer arithmetic & casts at ALL widths.
// Targets checked-overflow boundary reverts, signed div/mod INT_MIN/-1, div/mod by zero,
// negation of INT_MIN, shifts >= bit width, ** exponent edges, unchecked wraparound,
// mixed-width widening, address<->u160<->bytes20, bytesN<->uintN<->bytesM two-step casts,
// and DIRTY calldata high bits. Verified byte-identical to solc 0.8.x cancun.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

const JETH = `class C {
  // ---- checked add/sub/mul at many widths (overflow -> Panic 0x11) ----
  get addU16(a: u16, b: u16): External<u16> { return a + b; }
  get subU16(a: u16, b: u16): External<u16> { return a - b; }
  get mulU16(a: u16, b: u16): External<u16> { return a * b; }
  get addU32(a: u32, b: u32): External<u32> { return a + b; }
  get subU32(a: u32, b: u32): External<u32> { return a - b; }
  get mulU32(a: u32, b: u32): External<u32> { return a * b; }
  get addU64(a: u64, b: u64): External<u64> { return a + b; }
  get mulU64(a: u64, b: u64): External<u64> { return a * b; }
  get addU128(a: u128, b: u128): External<u128> { return a + b; }
  get mulU128(a: u128, b: u128): External<u128> { return a * b; }
  get addU256(a: u256, b: u256): External<u256> { return a + b; }
  get subU256(a: u256, b: u256): External<u256> { return a - b; }
  get mulU256(a: u256, b: u256): External<u256> { return a * b; }
  get addI16(a: i16, b: i16): External<i16> { return a + b; }
  get subI16(a: i16, b: i16): External<i16> { return a - b; }
  get mulI16(a: i16, b: i16): External<i16> { return a * b; }
  get addI32(a: i32, b: i32): External<i32> { return a + b; }
  get mulI32(a: i32, b: i32): External<i32> { return a * b; }
  get addI128(a: i128, b: i128): External<i128> { return a + b; }
  get mulI128(a: i128, b: i128): External<i128> { return a * b; }
  get addI256(a: i256, b: i256): External<i256> { return a + b; }
  get subI256(a: i256, b: i256): External<i256> { return a - b; }
  get mulI256(a: i256, b: i256): External<i256> { return a * b; }

  // ---- signed div/mod: INT_MIN/-1 (Panic 0x11), x/0 (Panic 0x12) ----
  get divI16(a: i16, b: i16): External<i16> { return a / b; }
  get modI16(a: i16, b: i16): External<i16> { return a % b; }
  get divI32(a: i32, b: i32): External<i32> { return a / b; }
  get modI32(a: i32, b: i32): External<i32> { return a % b; }
  get divI128(a: i128, b: i128): External<i128> { return a / b; }
  get modI128(a: i128, b: i128): External<i128> { return a % b; }
  get divI256(a: i256, b: i256): External<i256> { return a / b; }
  get modI256(a: i256, b: i256): External<i256> { return a % b; }
  get divU256(a: u256, b: u256): External<u256> { return a / b; }
  get modU256(a: u256, b: u256): External<u256> { return a % b; }
  get divU8(a: u8, b: u8): External<u8> { return a / b; }
  get modU8(a: u8, b: u8): External<u8> { return a % b; }

  // ---- negation of INT_MIN (Panic 0x11) at many widths ----
  get negI16(a: i16): External<i16> { return -a; }
  get negI32(a: i32): External<i32> { return -a; }
  get negI64(a: i64): External<i64> { return -a; }
  get negI128(a: i128): External<i128> { return -a; }
  get negI256b(a: i256): External<i256> { return -a; }

  // ---- unchecked wraparound ----
  get uAddU16(a: u16, b: u16): External<u16> { unchecked: { return a + b; } }
  get uSubU16(a: u16, b: u16): External<u16> { unchecked: { return a - b; } }
  get uMulU16(a: u16, b: u16): External<u16> { unchecked: { return a * b; } }
  get uNegI16(a: i16): External<i16> { unchecked: { return -a; } }
  get uNegI256(a: i256): External<i256> { unchecked: { return -a; } }
  get uAddI16(a: i16, b: i16): External<i16> { unchecked: { return a + b; } }
  get uSubI16(a: i16, b: i16): External<i16> { unchecked: { return a - b; } }
  get uMulI16(a: i16, b: i16): External<i16> { unchecked: { return a * b; } }
  get uSubU256(a: u256, b: u256): External<u256> { unchecked: { return a - b; } }
  get uMulU256(a: u256, b: u256): External<u256> { unchecked: { return a * b; } }

  // ---- exponent edges: checked (Panic 0x11) + unchecked wrap ----
  get powU16(a: u16, b: u16): External<u16> { return a ** b; }
  get powU32(a: u32, b: u32): External<u32> { return a ** b; }
  get powU64(a: u64, b: u64): External<u64> { return a ** b; }
  get powU128(a: u128, b: u128): External<u128> { return a ** b; }
  get powI16(a: i16, b: u16): External<i16> { return a ** b; }
  get powI32(a: i32, b: u32): External<i32> { return a ** b; }
  get powI256b(a: i256, b: u256): External<i256> { return a ** b; }
  get uPowU16(a: u16, b: u16): External<u16> { unchecked: { return a ** b; } }
  get uPowU256(a: u256, b: u256): External<u256> { unchecked: { return a ** b; } }
  get uPowI16(a: i16, b: u16): External<i16> { unchecked: { return a ** b; } }

  // ---- shifts: amount >= bit width, dirty amount, signed >> ----
  get shlU16(a: u16, s: u256): External<u16> { return a << s; }
  get shrU16(a: u16, s: u256): External<u16> { return a >> s; }
  get shlU32(a: u32, s: u256): External<u32> { return a << s; }
  get shrU32(a: u32, s: u256): External<u32> { return a >> s; }
  get shlI16(a: i16, s: u256): External<i16> { return a << s; }
  get shrI16(a: i16, s: u256): External<i16> { return a >> s; }
  get shlI256(a: i256, s: u256): External<i256> { return a << s; }
  get shrI256b(a: i256, s: u256): External<i256> { return a >> s; }
  get shlU256(a: u256, s: u256): External<u256> { return a << s; }
  get shrU256(a: u256, s: u256): External<u256> { return a >> s; }
  get shlU8b(a: u8, s: u8): External<u8> { return a << s; }

  // ---- mixed-width arithmetic (implicit widening) ----
  get mixAddDiff(a: u8, b: u32, c: u16): External<u64> { return a + b + c; }
  get mixSubI(a: i8, b: i64): External<i64> { return b - a; }
  get mixMulI(a: i16, b: i128): External<i128> { return a * b; }
  get mixDivU(a: u8, b: u64): External<u64> { return b / a; }
  get mixModU(a: u16, b: u128): External<u128> { return b % a; }
  get mixCmpAdd(a: u32, b: u8): External<u32> { let x: u32 = a; x += b; return x; }

  // ---- compound assignment with checked overflow ----
  get cAddU8(a: u8, b: u8): External<u8> { let x: u8 = a; x += b; return x; }
  get cSubU8(a: u8, b: u8): External<u8> { let x: u8 = a; x -= b; return x; }
  get cMulU8(a: u8, b: u8): External<u8> { let x: u8 = a; x *= b; return x; }
  get cMulI8(a: i8, b: i8): External<i8> { let x: i8 = a; x *= b; return x; }
  get cDivU8(a: u8, b: u8): External<u8> { let x: u8 = a; x /= b; return x; }
  get cModI8(a: i8, b: i8): External<i8> { let x: i8 = a; x %= b; return x; }
  get cShlU16(a: u16, s: u256): External<u16> { let x: u16 = a; x <<= s; return x; }
  get cShrI16(a: i16, s: u256): External<i16> { let x: i16 = a; x >>= s; return x; }
  get cAndU16(a: u16, b: u16): External<u16> { let x: u16 = a; x &= b; return x; }
  get cXorU16(a: u16, b: u16): External<u16> { let x: u16 = a; x ^= b; return x; }
  get cOrU16(a: u16, b: u16): External<u16> { let x: u16 = a; x |= b; return x; }

  // ---- type(T).max/min used in arithmetic ----
  get maxAddU8(a: u8): External<u8> { return type(u8).max - a; }
  get minSubI8(a: i8): External<i256> { return i256(type(i8).min) - i256(a); }
  get maxPlusOneU16(): External<u16> { return type(u16).max + 1n; }
  get minNegI16(): External<i16> { return -type(i16).min; }

  // ---- casts: bytesN <-> uintN <-> bytesM, odd widths ----
  get b3ToU24(a: bytes3): External<u24> { return u24(a); }
  get u24ToB3(a: u24): External<bytes3> { return bytes3(a); }
  get b7ToU56(a: bytes7): External<u56> { return u56(a); }
  get b32ToB7(a: bytes32): External<bytes7> { return bytes7(a); }
  get b7ToB32(a: bytes7): External<bytes32> { return bytes32(a); }
  get b1ToB32(a: bytes1): External<bytes32> { return bytes32(a); }
  get b32ToB1(a: bytes32): External<bytes1> { return bytes1(a); }
  get u24ToB3ToU24(a: u24): External<u24> { return u24(bytes3(a)); }
  get b5ToU40ToB5(a: bytes5): External<bytes5> { return bytes5(u40(a)); }
  get widenU24ToU256(a: u24): External<u256> { return u256(a); }
  get narrowU256ToU24(a: u256): External<u24> { return u24(a); }
  get i40ToI256(a: i40): External<i256> { return i256(a); }
  get i256ToI40(a: i256): External<i40> { return i40(a); }
  get i24ToU24(a: i24): External<u24> { return u24(a); }
  get u24ToI24(a: u24): External<i24> { return i24(a); }

  // ---- address <-> u160 <-> bytes20 round-trips ----
  get addrToU160(a: address): External<u160> { return u160(a); }
  get u160ToAddr(a: u160): External<address> { return address(a); }
  get addrToB20(a: address): External<bytes20> { return bytes20(a); }
  get b20ToAddr(a: bytes20): External<address> { return address(a); }
  get addrRound(a: address): External<address> { return address(u160(a)); }
  get addrRoundB(a: address): External<address> { return address(bytes20(a)); }
  get u160ToB20(a: u160): External<bytes20> { return bytes20(address(a)); }

  // ---- not / and / or / xor at narrow widths (cleaned result) ----
  get notU16(a: u16): External<u16> { return ~a; }
  get notI16(a: i16): External<i16> { return ~a; }
  get xorU16(a: u16, b: u16): External<u16> { return a ^ b; }
  get orU16(a: u16, b: u16): External<u16> { return a | b; }
  get notU24(a: u24): External<u24> { return ~a; }

  // ---- comparison across signedness widths (returns bool as uint) ----
  get ltI16(a: i16, b: i16): External<bool> { return a < b; }
  get gtMixed(a: u8, b: u32): External<bool> { return a > b; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function addU16(uint16 a, uint16 b) external pure returns (uint16){ return a + b; }
  function subU16(uint16 a, uint16 b) external pure returns (uint16){ return a - b; }
  function mulU16(uint16 a, uint16 b) external pure returns (uint16){ return a * b; }
  function addU32(uint32 a, uint32 b) external pure returns (uint32){ return a + b; }
  function subU32(uint32 a, uint32 b) external pure returns (uint32){ return a - b; }
  function mulU32(uint32 a, uint32 b) external pure returns (uint32){ return a * b; }
  function addU64(uint64 a, uint64 b) external pure returns (uint64){ return a + b; }
  function mulU64(uint64 a, uint64 b) external pure returns (uint64){ return a * b; }
  function addU128(uint128 a, uint128 b) external pure returns (uint128){ return a + b; }
  function mulU128(uint128 a, uint128 b) external pure returns (uint128){ return a * b; }
  function addU256(uint256 a, uint256 b) external pure returns (uint256){ return a + b; }
  function subU256(uint256 a, uint256 b) external pure returns (uint256){ return a - b; }
  function mulU256(uint256 a, uint256 b) external pure returns (uint256){ return a * b; }
  function addI16(int16 a, int16 b) external pure returns (int16){ return a + b; }
  function subI16(int16 a, int16 b) external pure returns (int16){ return a - b; }
  function mulI16(int16 a, int16 b) external pure returns (int16){ return a * b; }
  function addI32(int32 a, int32 b) external pure returns (int32){ return a + b; }
  function mulI32(int32 a, int32 b) external pure returns (int32){ return a * b; }
  function addI128(int128 a, int128 b) external pure returns (int128){ return a + b; }
  function mulI128(int128 a, int128 b) external pure returns (int128){ return a * b; }
  function addI256(int256 a, int256 b) external pure returns (int256){ return a + b; }
  function subI256(int256 a, int256 b) external pure returns (int256){ return a - b; }
  function mulI256(int256 a, int256 b) external pure returns (int256){ return a * b; }
  function divI16(int16 a, int16 b) external pure returns (int16){ return a / b; }
  function modI16(int16 a, int16 b) external pure returns (int16){ return a % b; }
  function divI32(int32 a, int32 b) external pure returns (int32){ return a / b; }
  function modI32(int32 a, int32 b) external pure returns (int32){ return a % b; }
  function divI128(int128 a, int128 b) external pure returns (int128){ return a / b; }
  function modI128(int128 a, int128 b) external pure returns (int128){ return a % b; }
  function divI256(int256 a, int256 b) external pure returns (int256){ return a / b; }
  function modI256(int256 a, int256 b) external pure returns (int256){ return a % b; }
  function divU256(uint256 a, uint256 b) external pure returns (uint256){ return a / b; }
  function modU256(uint256 a, uint256 b) external pure returns (uint256){ return a % b; }
  function divU8(uint8 a, uint8 b) external pure returns (uint8){ return a / b; }
  function modU8(uint8 a, uint8 b) external pure returns (uint8){ return a % b; }
  function negI16(int16 a) external pure returns (int16){ return -a; }
  function negI32(int32 a) external pure returns (int32){ return -a; }
  function negI64(int64 a) external pure returns (int64){ return -a; }
  function negI128(int128 a) external pure returns (int128){ return -a; }
  function negI256b(int256 a) external pure returns (int256){ return -a; }
  function uAddU16(uint16 a, uint16 b) external pure returns (uint16){ unchecked { return a + b; } }
  function uSubU16(uint16 a, uint16 b) external pure returns (uint16){ unchecked { return a - b; } }
  function uMulU16(uint16 a, uint16 b) external pure returns (uint16){ unchecked { return a * b; } }
  function uNegI16(int16 a) external pure returns (int16){ unchecked { return -a; } }
  function uNegI256(int256 a) external pure returns (int256){ unchecked { return -a; } }
  function uAddI16(int16 a, int16 b) external pure returns (int16){ unchecked { return a + b; } }
  function uSubI16(int16 a, int16 b) external pure returns (int16){ unchecked { return a - b; } }
  function uMulI16(int16 a, int16 b) external pure returns (int16){ unchecked { return a * b; } }
  function uSubU256(uint256 a, uint256 b) external pure returns (uint256){ unchecked { return a - b; } }
  function uMulU256(uint256 a, uint256 b) external pure returns (uint256){ unchecked { return a * b; } }
  function powU16(uint16 a, uint16 b) external pure returns (uint16){ return a ** b; }
  function powU32(uint32 a, uint32 b) external pure returns (uint32){ return a ** b; }
  function powU64(uint64 a, uint64 b) external pure returns (uint64){ return a ** b; }
  function powU128(uint128 a, uint128 b) external pure returns (uint128){ return a ** b; }
  function powI16(int16 a, uint16 b) external pure returns (int16){ return a ** b; }
  function powI32(int32 a, uint32 b) external pure returns (int32){ return a ** b; }
  function powI256b(int256 a, uint256 b) external pure returns (int256){ return a ** b; }
  function uPowU16(uint16 a, uint16 b) external pure returns (uint16){ unchecked { return a ** b; } }
  function uPowU256(uint256 a, uint256 b) external pure returns (uint256){ unchecked { return a ** b; } }
  function uPowI16(int16 a, uint16 b) external pure returns (int16){ unchecked { return a ** b; } }
  function shlU16(uint16 a, uint256 s) external pure returns (uint16){ return a << s; }
  function shrU16(uint16 a, uint256 s) external pure returns (uint16){ return a >> s; }
  function shlU32(uint32 a, uint256 s) external pure returns (uint32){ return a << s; }
  function shrU32(uint32 a, uint256 s) external pure returns (uint32){ return a >> s; }
  function shlI16(int16 a, uint256 s) external pure returns (int16){ return a << s; }
  function shrI16(int16 a, uint256 s) external pure returns (int16){ return a >> s; }
  function shlI256(int256 a, uint256 s) external pure returns (int256){ return a << s; }
  function shrI256b(int256 a, uint256 s) external pure returns (int256){ return a >> s; }
  function shlU256(uint256 a, uint256 s) external pure returns (uint256){ return a << s; }
  function shrU256(uint256 a, uint256 s) external pure returns (uint256){ return a >> s; }
  function shlU8b(uint8 a, uint8 s) external pure returns (uint8){ return a << s; }
  function mixAddDiff(uint8 a, uint32 b, uint16 c) external pure returns (uint64){ return a + b + c; }
  function mixSubI(int8 a, int64 b) external pure returns (int64){ return b - a; }
  function mixMulI(int16 a, int128 b) external pure returns (int128){ return a * b; }
  function mixDivU(uint8 a, uint64 b) external pure returns (uint64){ return b / a; }
  function mixModU(uint16 a, uint128 b) external pure returns (uint128){ return b % a; }
  function mixCmpAdd(uint32 a, uint8 b) external pure returns (uint32){ uint32 x = a; x += b; return x; }
  function cAddU8(uint8 a, uint8 b) external pure returns (uint8){ uint8 x = a; x += b; return x; }
  function cSubU8(uint8 a, uint8 b) external pure returns (uint8){ uint8 x = a; x -= b; return x; }
  function cMulU8(uint8 a, uint8 b) external pure returns (uint8){ uint8 x = a; x *= b; return x; }
  function cMulI8(int8 a, int8 b) external pure returns (int8){ int8 x = a; x *= b; return x; }
  function cDivU8(uint8 a, uint8 b) external pure returns (uint8){ uint8 x = a; x /= b; return x; }
  function cModI8(int8 a, int8 b) external pure returns (int8){ int8 x = a; x %= b; return x; }
  function cShlU16(uint16 a, uint256 s) external pure returns (uint16){ uint16 x = a; x <<= s; return x; }
  function cShrI16(int16 a, uint256 s) external pure returns (int16){ int16 x = a; x >>= s; return x; }
  function cAndU16(uint16 a, uint16 b) external pure returns (uint16){ uint16 x = a; x &= b; return x; }
  function cXorU16(uint16 a, uint16 b) external pure returns (uint16){ uint16 x = a; x ^= b; return x; }
  function cOrU16(uint16 a, uint16 b) external pure returns (uint16){ uint16 x = a; x |= b; return x; }
  function maxAddU8(uint8 a) external pure returns (uint8){ return type(uint8).max - a; }
  function minSubI8(int8 a) external pure returns (int256){ return int256(type(int8).min) - int256(a); }
  function maxPlusOneU16() external pure returns (uint16){ return type(uint16).max + 1; }
  function minNegI16() external pure returns (int16){ return -type(int16).min; }
  function b3ToU24(bytes3 a) external pure returns (uint24){ return uint24(a); }
  function u24ToB3(uint24 a) external pure returns (bytes3){ return bytes3(a); }
  function b7ToU56(bytes7 a) external pure returns (uint56){ return uint56(a); }
  function b32ToB7(bytes32 a) external pure returns (bytes7){ return bytes7(a); }
  function b7ToB32(bytes7 a) external pure returns (bytes32){ return bytes32(a); }
  function b1ToB32(bytes1 a) external pure returns (bytes32){ return bytes32(a); }
  function b32ToB1(bytes32 a) external pure returns (bytes1){ return bytes1(a); }
  function u24ToB3ToU24(uint24 a) external pure returns (uint24){ return uint24(bytes3(a)); }
  function b5ToU40ToB5(bytes5 a) external pure returns (bytes5){ return bytes5(uint40(a)); }
  function widenU24ToU256(uint24 a) external pure returns (uint256){ return uint256(a); }
  function narrowU256ToU24(uint256 a) external pure returns (uint24){ return uint24(a); }
  function i40ToI256(int40 a) external pure returns (int256){ return int256(a); }
  function i256ToI40(int256 a) external pure returns (int40){ return int40(a); }
  function i24ToU24(int24 a) external pure returns (uint24){ return uint24(a); }
  function u24ToI24(uint24 a) external pure returns (int24){ return int24(a); }
  function addrToU160(address a) external pure returns (uint160){ return uint160(a); }
  function u160ToAddr(uint160 a) external pure returns (address){ return address(a); }
  function addrToB20(address a) external pure returns (bytes20){ return bytes20(a); }
  function b20ToAddr(bytes20 a) external pure returns (address){ return address(a); }
  function addrRound(address a) external pure returns (address){ return address(uint160(a)); }
  function addrRoundB(address a) external pure returns (address){ return address(bytes20(a)); }
  function u160ToB20(uint160 a) external pure returns (bytes20){ return bytes20(address(a)); }
  function notU16(uint16 a) external pure returns (uint16){ return ~a; }
  function notI16(int16 a) external pure returns (int16){ return ~a; }
  function xorU16(uint16 a, uint16 b) external pure returns (uint16){ return a ^ b; }
  function orU16(uint16 a, uint16 b) external pure returns (uint16){ return a | b; }
  function notU24(uint24 a) external pure returns (uint24){ return ~a; }
  function ltI16(int16 a, int16 b) external pure returns (bool){ return a < b; }
  function gtMixed(uint8 a, uint32 b) external pure returns (bool){ return a > b; }
}`;

describe('probe arith', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  // raw=true means args are passed as RAW words (possibly dirty above the param width),
  // exercising calldata input validation. encodeCall keeps them mod 2^256.
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(
        label +
          ': jeth{ok=' +
          j.success +
          ',ret=' +
          j.returnHex +
          ',err=' +
          j.exceptionError +
          '} sol{ok=' +
          s.success +
          ',ret=' +
          s.returnHex +
          '}',
      );
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    // boundary value sets per width
    const max = (bits: bigint) => (1n << bits) - 1n; // uintN max
    const smax = (bits: bigint) => (1n << (bits - 1n)) - 1n; // intN max
    const smin = (bits: bigint) => -(1n << (bits - 1n)); // intN min
    const sword = (bits: bigint, v: bigint) => ((v % (1n << bits)) + (1n << bits)) % (1n << bits); // intN -> word

    // ---------------- checked add/sub/mul boundaries ----------------
    const u16v = [0n, 1n, 2n, 100n, max(16n) - 1n, max(16n), max(16n) / 2n, max(16n) / 2n + 1n, 255n, 256n, 65280n];
    for (const a of u16v)
      for (const b of u16v) {
        await eq(`addU16(${a},${b})`, encodeCall(sel('addU16(uint16,uint16)'), [a, b]));
        await eq(`subU16(${a},${b})`, encodeCall(sel('subU16(uint16,uint16)'), [a, b]));
        await eq(`mulU16(${a},${b})`, encodeCall(sel('mulU16(uint16,uint16)'), [a, b]));
        await eq(`uAddU16(${a},${b})`, encodeCall(sel('uAddU16(uint16,uint16)'), [a, b]));
        await eq(`uSubU16(${a},${b})`, encodeCall(sel('uSubU16(uint16,uint16)'), [a, b]));
        await eq(`uMulU16(${a},${b})`, encodeCall(sel('uMulU16(uint16,uint16)'), [a, b]));
      }
    const u32v = [0n, 1n, max(32n), max(32n) - 1n, max(16n), max(16n) + 1n, 1n << 31n, max(32n) / 2n];
    for (const a of u32v)
      for (const b of u32v) {
        await eq(`addU32(${a},${b})`, encodeCall(sel('addU32(uint32,uint32)'), [a, b]));
        await eq(`subU32(${a},${b})`, encodeCall(sel('subU32(uint32,uint32)'), [a, b]));
        await eq(`mulU32(${a},${b})`, encodeCall(sel('mulU32(uint32,uint32)'), [a, b]));
      }
    const u64v = [0n, 1n, max(64n), max(64n) - 1n, max(32n), max(32n) + 1n, 1n << 33n, (1n << 64n) / 2n];
    for (const a of u64v)
      for (const b of u64v) {
        await eq(`addU64(${a},${b})`, encodeCall(sel('addU64(uint64,uint64)'), [a, b]));
        await eq(`mulU64(${a},${b})`, encodeCall(sel('mulU64(uint64,uint64)'), [a, b]));
      }
    const u128v = [0n, 1n, max(128n), max(128n) - 1n, max(64n), max(64n) + 1n, 1n << 100n];
    for (const a of u128v)
      for (const b of u128v) {
        await eq(`addU128(${a},${b})`, encodeCall(sel('addU128(uint128,uint128)'), [a, b]));
        await eq(`mulU128(${a},${b})`, encodeCall(sel('mulU128(uint128,uint128)'), [a, b]));
      }
    const u256v = [
      0n,
      1n,
      2n,
      M - 1n,
      M - 2n,
      1n << 128n,
      (1n << 128n) - 1n,
      1n << 255n,
      (M - 1n) / 2n,
      (M - 1n) / 2n + 1n,
    ];
    for (const a of u256v)
      for (const b of u256v) {
        await eq(`addU256(${a},${b})`, encodeCall(sel('addU256(uint256,uint256)'), [a, b]));
        await eq(`subU256(${a},${b})`, encodeCall(sel('subU256(uint256,uint256)'), [a, b]));
        await eq(`mulU256(${a},${b})`, encodeCall(sel('mulU256(uint256,uint256)'), [a, b]));
        await eq(`uSubU256(${a},${b})`, encodeCall(sel('uSubU256(uint256,uint256)'), [a, b]));
        await eq(`uMulU256(${a},${b})`, encodeCall(sel('uMulU256(uint256,uint256)'), [a, b]));
      }

    // signed boundaries: encode intN values as their N-bit two's complement word
    const i16raw = [smin(16n), smin(16n) + 1n, -1n, 0n, 1n, smax(16n), smax(16n) - 1n, -100n, 100n, smin(16n) / 2n].map(
      (v) => sword(16n, v),
    );
    for (const a of i16raw)
      for (const b of i16raw) {
        await eq(`addI16(${a},${b})`, encodeCall(sel('addI16(int16,int16)'), [a, b]));
        await eq(`subI16(${a},${b})`, encodeCall(sel('subI16(int16,int16)'), [a, b]));
        await eq(`mulI16(${a},${b})`, encodeCall(sel('mulI16(int16,int16)'), [a, b]));
        await eq(`divI16(${a},${b})`, encodeCall(sel('divI16(int16,int16)'), [a, b]));
        await eq(`modI16(${a},${b})`, encodeCall(sel('modI16(int16,int16)'), [a, b]));
        await eq(`uAddI16(${a},${b})`, encodeCall(sel('uAddI16(int16,int16)'), [a, b]));
        await eq(`uSubI16(${a},${b})`, encodeCall(sel('uSubI16(int16,int16)'), [a, b]));
        await eq(`uMulI16(${a},${b})`, encodeCall(sel('uMulI16(int16,int16)'), [a, b]));
      }
    const i32raw = [smin(32n), smin(32n) + 1n, -1n, 0n, 1n, smax(32n), -65536n, 65536n].map((v) => sword(32n, v));
    for (const a of i32raw)
      for (const b of i32raw) {
        await eq(`addI32(${a},${b})`, encodeCall(sel('addI32(int32,int32)'), [a, b]));
        await eq(`mulI32(${a},${b})`, encodeCall(sel('mulI32(int32,int32)'), [a, b]));
        await eq(`divI32(${a},${b})`, encodeCall(sel('divI32(int32,int32)'), [a, b]));
        await eq(`modI32(${a},${b})`, encodeCall(sel('modI32(int32,int32)'), [a, b]));
      }
    const i128raw = [smin(128n), smin(128n) + 1n, -1n, 0n, 1n, smax(128n)].map((v) => sword(128n, v));
    for (const a of i128raw)
      for (const b of i128raw) {
        await eq(`addI128(${a},${b})`, encodeCall(sel('addI128(int128,int128)'), [a, b]));
        await eq(`mulI128(${a},${b})`, encodeCall(sel('mulI128(int128,int128)'), [a, b]));
        await eq(`divI128(${a},${b})`, encodeCall(sel('divI128(int128,int128)'), [a, b]));
        await eq(`modI128(${a},${b})`, encodeCall(sel('modI128(int128,int128)'), [a, b]));
      }
    const i256raw = [-(1n << 255n), -(1n << 255n) + 1n, -1n, 0n, 1n, (1n << 255n) - 1n, -42n, 1n << 254n].map((v) =>
      sword(256n, v),
    );
    for (const a of i256raw)
      for (const b of i256raw) {
        await eq(`addI256(${a},${b})`, encodeCall(sel('addI256(int256,int256)'), [a, b]));
        await eq(`subI256(${a},${b})`, encodeCall(sel('subI256(int256,int256)'), [a, b]));
        await eq(`mulI256(${a},${b})`, encodeCall(sel('mulI256(int256,int256)'), [a, b]));
        await eq(`divI256(${a},${b})`, encodeCall(sel('divI256(int256,int256)'), [a, b]));
        await eq(`modI256(${a},${b})`, encodeCall(sel('modI256(int256,int256)'), [a, b]));
      }

    // div/mod by zero (Panic 0x12) + by one + INT_MIN/-1 already covered above
    for (const a of [0n, 1n, 255n, 128n, 100n])
      for (const b of [0n, 1n, 2n, 7n, 255n]) {
        await eq(`divU8(${a},${b})`, encodeCall(sel('divU8(uint8,uint8)'), [a, b]));
        await eq(`modU8(${a},${b})`, encodeCall(sel('modU8(uint8,uint8)'), [a, b]));
      }
    for (const a of u256v)
      for (const b of [0n, 1n, 2n, M - 1n, 7n]) {
        await eq(`divU256(${a},${b})`, encodeCall(sel('divU256(uint256,uint256)'), [a, b]));
        await eq(`modU256(${a},${b})`, encodeCall(sel('modU256(uint256,uint256)'), [a, b]));
      }

    // ---------------- negation of INT_MIN at each width ----------------
    for (const v of [smin(16n), smin(16n) + 1n, -1n, 0n, 1n, smax(16n)])
      await eq(`negI16(${v})`, encodeCall(sel('negI16(int16)'), [sword(16n, v)]));
    for (const v of [smin(32n), smin(32n) + 1n, -1n, 0n, smax(32n)])
      await eq(`negI32(${v})`, encodeCall(sel('negI32(int32)'), [sword(32n, v)]));
    for (const v of [smin(64n), smin(64n) + 1n, -1n, 0n, smax(64n)])
      await eq(`negI64(${v})`, encodeCall(sel('negI64(int64)'), [sword(64n, v)]));
    for (const v of [smin(128n), smin(128n) + 1n, -1n, 0n, smax(128n)])
      await eq(`negI128(${v})`, encodeCall(sel('negI128(int128)'), [sword(128n, v)]));
    for (const v of [-(1n << 255n), -(1n << 255n) + 1n, -1n, 0n, (1n << 255n) - 1n])
      await eq(`negI256b(${v})`, encodeCall(sel('negI256b(int256)'), [sword(256n, v)]));
    for (const v of [smin(16n), -1n, 0n, smax(16n)])
      await eq(`uNegI16(${v})`, encodeCall(sel('uNegI16(int16)'), [sword(16n, v)]));
    for (const v of [-(1n << 255n), -1n, 0n])
      await eq(`uNegI256(${v})`, encodeCall(sel('uNegI256(int256)'), [sword(256n, v)]));

    // ---------------- exponent edges ----------------
    const expSmall = [0n, 1n, 2n, 3n, 4n, 5n, 7n, 8n, 15n, 16n, 17n, 255n, 256n, 1000n, 65535n];
    for (const a of [0n, 1n, 2n, 3n, 10n, 255n, 256n, max(16n)])
      for (const b of expSmall) {
        await eq(`powU16(${a},${b})`, encodeCall(sel('powU16(uint16,uint16)'), [a, b]));
        await eq(`uPowU16(${a},${b})`, encodeCall(sel('uPowU16(uint16,uint16)'), [a, b]));
      }
    for (const a of [0n, 1n, 2n, 3n, 10n, max(32n)])
      for (const b of [0n, 1n, 2n, 5n, 10n, 16n, 31n, 32n, 33n]) {
        await eq(`powU32(${a},${b})`, encodeCall(sel('powU32(uint32,uint32)'), [a, b]));
      }
    for (const a of [0n, 1n, 2n, 3n, max(64n)])
      for (const b of [0n, 1n, 2n, 32n, 63n, 64n, 65n]) {
        await eq(`powU64(${a},${b})`, encodeCall(sel('powU64(uint64,uint64)'), [a, b]));
      }
    for (const a of [0n, 1n, 2n, 3n, max(128n)])
      for (const b of [0n, 1n, 2n, 64n, 127n, 128n, 129n]) {
        await eq(`powU128(${a},${b})`, encodeCall(sel('powU128(uint128,uint128)'), [a, b]));
      }
    for (const a of [0n, 1n, max(256n)])
      for (const b of [0n, 1n, 2n, 3n, 255n, 256n, 257n]) {
        await eq(`uPowU256(${a},${b})`, encodeCall(sel('uPowU256(uint256,uint256)'), [a, b]));
      }
    const i16e = [smin(16n), -100n, -2n, -1n, 0n, 1n, 2n, 3n, smax(16n)];
    for (const a of i16e)
      for (const b of [0n, 1n, 2n, 3n, 4n, 5n, 8n, 15n, 16n, 17n]) {
        await eq(`powI16(${a},${b})`, encodeCall(sel('powI16(int16,uint16)'), [sword(16n, a), b]));
        await eq(`uPowI16(${a},${b})`, encodeCall(sel('uPowI16(int16,uint16)'), [sword(16n, a), b]));
      }
    for (const a of [smin(32n), -2n, -1n, 0n, 1n, 2n, smax(32n)])
      for (const b of [0n, 1n, 2n, 16n, 31n, 32n]) {
        await eq(`powI32(${a},${b})`, encodeCall(sel('powI32(int32,uint32)'), [sword(32n, a), b]));
      }
    for (const a of i256raw)
      for (const b of [0n, 1n, 2n, 3n, 5n, 200n, 255n, 256n]) {
        await eq(`powI256b(${a},${b})`, encodeCall(sel('powI256b(int256,uint256)'), [a, b]));
      }

    // ---------------- shifts: amount >= width, dirty/huge amounts ----------------
    const shAmts = [
      0n,
      1n,
      2n,
      4n,
      7n,
      8n,
      9n,
      15n,
      16n,
      17n,
      31n,
      32n,
      63n,
      64n,
      127n,
      128n,
      255n,
      256n,
      257n,
      1000n,
      M - 1n,
      1n << 200n,
    ];
    for (const a of [0n, 1n, max(16n), 0x8000n, 0x00ffn, 0xff00n, 12345n])
      for (const s of shAmts) {
        await eq(`shlU16(${a},${s})`, encodeCall(sel('shlU16(uint16,uint256)'), [a, s]));
        await eq(`shrU16(${a},${s})`, encodeCall(sel('shrU16(uint16,uint256)'), [a, s]));
      }
    for (const a of [0n, 1n, max(32n), 0x80000000n, 0xdeadbeefn])
      for (const s of shAmts) {
        await eq(`shlU32(${a},${s})`, encodeCall(sel('shlU32(uint32,uint256)'), [a, s]));
        await eq(`shrU32(${a},${s})`, encodeCall(sel('shrU32(uint32,uint256)'), [a, s]));
      }
    for (const a of [smin(16n), -1n, -2n, 1n, smax(16n), -256n].map((v) => sword(16n, v)))
      for (const s of shAmts) {
        await eq(`shlI16(${a},${s})`, encodeCall(sel('shlI16(int16,uint256)'), [a, s]));
        await eq(`shrI16(${a},${s})`, encodeCall(sel('shrI16(int16,uint256)'), [a, s]));
      }
    for (const a of i256raw)
      for (const s of shAmts) {
        await eq(`shlI256(${a},${s})`, encodeCall(sel('shlI256(int256,uint256)'), [a, s]));
        await eq(`shrI256b(${a},${s})`, encodeCall(sel('shrI256b(int256,uint256)'), [a, s]));
      }
    for (const a of u256v)
      for (const s of shAmts) {
        await eq(`shlU256(${a},${s})`, encodeCall(sel('shlU256(uint256,uint256)'), [a, s]));
        await eq(`shrU256(${a},${s})`, encodeCall(sel('shrU256(uint256,uint256)'), [a, s]));
      }
    for (const a of [0n, 1n, 128n, 255n])
      for (const s of [0n, 1n, 7n, 8n, 9n, 255n]) {
        await eq(`shlU8b(${a},${s})`, encodeCall(sel('shlU8b(uint8,uint8)'), [a, s]));
      }

    // ---------------- mixed-width arithmetic ----------------
    for (const a of [0n, 1n, 255n])
      for (const b of [0n, 1n, max(32n)])
        for (const c of [0n, 1n, max(16n)]) {
          await eq(`mixAddDiff(${a},${b},${c})`, encodeCall(sel('mixAddDiff(uint8,uint32,uint16)'), [a, b, c]));
        }
    for (const a of [-128n, -1n, 0n, 1n, 127n].map((v) => sword(8n, v)))
      for (const b of [smin(64n), -1n, 0n, 1n, smax(64n)].map((v) => sword(64n, v))) {
        await eq(`mixSubI(${a},${b})`, encodeCall(sel('mixSubI(int8,int64)'), [a, b]));
      }
    for (const a of [smin(16n), -1n, 0n, 1n, smax(16n)].map((v) => sword(16n, v)))
      for (const b of [smin(128n), -1n, 0n, 1n, smax(128n)].map((v) => sword(128n, v))) {
        await eq(`mixMulI(${a},${b})`, encodeCall(sel('mixMulI(int16,int128)'), [a, b]));
      }
    for (const a of [0n, 1n, 2n, 7n, 255n])
      for (const b of [0n, 1n, 100n, max(64n)]) {
        await eq(`mixDivU(${a},${b})`, encodeCall(sel('mixDivU(uint8,uint64)'), [a, b]));
        await eq(`mixModU(${a % (1n << 16n)},${b})`, encodeCall(sel('mixModU(uint16,uint128)'), [a, b]));
      }
    for (const a of [0n, max(32n), 1000n])
      for (const b of [0n, 1n, 255n]) {
        await eq(`mixCmpAdd(${a},${b})`, encodeCall(sel('mixCmpAdd(uint32,uint8)'), [a, b]));
      }

    // ---------------- compound assignment ----------------
    const u8v = [0n, 1n, 100n, 127n, 128n, 200n, 254n, 255n];
    for (const a of u8v)
      for (const b of u8v) {
        await eq(`cAddU8(${a},${b})`, encodeCall(sel('cAddU8(uint8,uint8)'), [a, b]));
        await eq(`cSubU8(${a},${b})`, encodeCall(sel('cSubU8(uint8,uint8)'), [a, b]));
        await eq(`cMulU8(${a},${b})`, encodeCall(sel('cMulU8(uint8,uint8)'), [a, b]));
      }
    for (const a of [-128n, -1n, 0n, 1n, 127n].map((v) => sword(8n, v)))
      for (const b of [-128n, -1n, 0n, 1n, 2n, 127n].map((v) => sword(8n, v))) {
        await eq(`cMulI8(${a},${b})`, encodeCall(sel('cMulI8(int8,int8)'), [a, b]));
        await eq(`cModI8(${a},${b})`, encodeCall(sel('cModI8(int8,int8)'), [a, b]));
      }
    for (const a of u8v)
      for (const b of [0n, 1n, 2n, 7n, 255n]) {
        await eq(`cDivU8(${a},${b})`, encodeCall(sel('cDivU8(uint8,uint8)'), [a, b]));
      }
    for (const a of [0n, 1n, 0x8000n, max(16n), 0x00ffn])
      for (const s of [0n, 1n, 8n, 15n, 16n, 17n, 255n, 256n, M - 1n]) {
        await eq(`cShlU16(${a},${s})`, encodeCall(sel('cShlU16(uint16,uint256)'), [a, s]));
        await eq(`cShrI16(${sword(16n, a)},${s})`, encodeCall(sel('cShrI16(int16,uint256)'), [sword(16n, a), s]));
      }
    for (const a of [0n, 0xff00n, 0x00ffn, max(16n)])
      for (const b of [0n, 0xff00n, 0x00ffn, max(16n)]) {
        await eq(`cAndU16(${a},${b})`, encodeCall(sel('cAndU16(uint16,uint16)'), [a, b]));
        await eq(`cXorU16(${a},${b})`, encodeCall(sel('cXorU16(uint16,uint16)'), [a, b]));
        await eq(`cOrU16(${a},${b})`, encodeCall(sel('cOrU16(uint16,uint16)'), [a, b]));
      }

    // ---------------- type(T).max/min arithmetic ----------------
    for (const a of u8v) await eq(`maxAddU8(${a})`, encodeCall(sel('maxAddU8(uint8)'), [a]));
    for (const a of [-128n, -1n, 0n, 1n, 127n].map((v) => sword(8n, v)))
      await eq(`minSubI8(${a})`, encodeCall(sel('minSubI8(int8)'), [a]));
    await eq('maxPlusOneU16', encodeCall(sel('maxPlusOneU16()'), []));
    await eq('minNegI16', encodeCall(sel('minNegI16()'), []));

    // ---------------- casts (odd widths) ----------------
    const wordsForBytes = (sz: bigint, v: bigint) => v << ((32n - sz) * 8n); // left-align bytesN
    for (const v of [0n, 0x010203n, 0xffffffn, 0xabcdefn]) {
      await eq(`b3ToU24(${v})`, encodeCall(sel('b3ToU24(bytes3)'), [wordsForBytes(3n, v)]));
      await eq(`u24ToB3(${v})`, encodeCall(sel('u24ToB3(uint24)'), [v]));
      await eq(`u24ToB3ToU24(${v})`, encodeCall(sel('u24ToB3ToU24(uint24)'), [v]));
      await eq(`widenU24ToU256(${v})`, encodeCall(sel('widenU24ToU256(uint24)'), [v]));
    }
    for (const v of [0n, 0x01020304050607n, BigInt('0xffffffffffffff')]) {
      await eq(`b7ToU56(${v})`, encodeCall(sel('b7ToU56(bytes7)'), [wordsForBytes(7n, v)]));
    }
    for (const v of [0n, BigInt('0x' + 'a5'.repeat(32)), BigInt('0x' + 'ff'.repeat(32)), M - 1n]) {
      await eq(`b32ToB7(${v})`, encodeCall(sel('b32ToB7(bytes32)'), [v]));
      await eq(`b32ToB1(${v})`, encodeCall(sel('b32ToB1(bytes32)'), [v]));
    }
    for (const v of [0n, 0x01020304050607n, BigInt('0xdeadbeefcafe01')]) {
      await eq(`b7ToB32(${v})`, encodeCall(sel('b7ToB32(bytes7)'), [wordsForBytes(7n, v)]));
    }
    for (const v of [0n, 0xa5n, 0xffn])
      await eq(`b1ToB32(${v})`, encodeCall(sel('b1ToB32(bytes1)'), [wordsForBytes(1n, v)]));
    for (const v of [0n, 0x0102030405n, BigInt('0xffffffffff')])
      await eq(`b5ToU40ToB5(${v})`, encodeCall(sel('b5ToU40ToB5(bytes5)'), [wordsForBytes(5n, v)]));
    for (const v of [0n, 0x010203n, 0xffffffn, M - 1n, 0x1000000n])
      await eq(`narrowU256ToU24(${v})`, encodeCall(sel('narrowU256ToU24(uint256)'), [v]));
    for (const v of [0n, 1n, smax(40n), smin(40n), -1n].map((x) => sword(40n, x))) {
      await eq(`i40ToI256(${v})`, encodeCall(sel('i40ToI256(int40)'), [v]));
    }
    for (const v of [0n, 1n, -1n, smin(40n), smax(40n), 1n << 254n, M - 1n].map((x) => sword(256n, x))) {
      await eq(`i256ToI40(${v})`, encodeCall(sel('i256ToI40(int256)'), [v]));
    }
    for (const v of [0n, 1n, smax(24n), smin(24n), -1n].map((x) => sword(24n, x))) {
      await eq(`i24ToU24(${v})`, encodeCall(sel('i24ToU24(int24)'), [v]));
    }
    for (const v of [0n, 1n, max(24n), max(24n) / 2n, max(24n) / 2n + 1n]) {
      await eq(`u24ToI24(${v})`, encodeCall(sel('u24ToI24(uint24)'), [v]));
    }

    // ---------------- address <-> u160 <-> bytes20 ----------------
    const addrs = [0n, 1n, BigInt('0x' + '11'.repeat(20)), (1n << 160n) - 1n, BigInt('0xdeadbeef')];
    for (const a of addrs) {
      await eq(`addrToU160(${a})`, encodeCall(sel('addrToU160(address)'), [a]));
      await eq(`u160ToAddr(${a})`, encodeCall(sel('u160ToAddr(uint160)'), [a]));
      await eq(`addrToB20(${a})`, encodeCall(sel('addrToB20(address)'), [a]));
      await eq(`b20ToAddr(${a})`, encodeCall(sel('b20ToAddr(bytes20)'), [a << 96n]));
      await eq(`addrRound(${a})`, encodeCall(sel('addrRound(address)'), [a]));
      await eq(`addrRoundB(${a})`, encodeCall(sel('addrRoundB(address)'), [a]));
      await eq(`u160ToB20(${a})`, encodeCall(sel('u160ToB20(uint160)'), [a]));
    }

    // ---------------- not / xor / or at narrow widths ----------------
    for (const a of u16v) {
      await eq(`notU16(${a})`, encodeCall(sel('notU16(uint16)'), [a]));
      await eq(`notI16(${a})`, encodeCall(sel('notI16(int16)'), [sword(16n, a)]));
    }
    for (const v of [0n, 1n, max(24n), 0x800000n]) await eq(`notU24(${v})`, encodeCall(sel('notU24(uint24)'), [v]));
    for (const a of [0n, 0xff00n, 0x00ffn, max(16n)])
      for (const b of [0n, 0xff00n, 0x00ffn, max(16n)]) {
        await eq(`xorU16(${a},${b})`, encodeCall(sel('xorU16(uint16,uint16)'), [a, b]));
        await eq(`orU16(${a},${b})`, encodeCall(sel('orU16(uint16,uint16)'), [a, b]));
      }

    // ---------------- comparisons ----------------
    for (const a of [smin(16n), -1n, 0n, 1n, smax(16n)].map((v) => sword(16n, v)))
      for (const b of [smin(16n), -1n, 0n, 1n, smax(16n)].map((v) => sword(16n, v))) {
        await eq(`ltI16(${a},${b})`, encodeCall(sel('ltI16(int16,int16)'), [a, b]));
      }
    for (const a of [0n, 1n, 255n])
      for (const b of [0n, 1n, 255n, max(32n)]) {
        await eq(`gtMixed(${a},${b})`, encodeCall(sel('gtMixed(uint8,uint32)'), [a, b]));
      }

    // ---------------- DIRTY calldata high bits (input validation parity) ----------------
    // Pass words with bits set ABOVE the declared param width. solc 0.8 rejects dirty
    // calldata for narrow types; JETH should match. Each yields a clean low-bits value
    // plus garbage in high bits.
    const dirty16 = [
      (1n << 16n) | 5n, // bit just above u16
      M - 1n, // all ones
      (0xdeadn << 16n) | 0x42n, // high garbage, low valid
      (1n << 255n) | 1n, // top bit + low
    ];
    for (const a of dirty16)
      for (const b of [0n, 1n]) {
        await eq(`dirty.addU16(${a},${b})`, encodeCall(sel('addU16(uint16,uint16)'), [a, b]));
      }
    for (const a of dirty16) {
      await eq(`dirty.notU16(${a})`, encodeCall(sel('notU16(uint16)'), [a]));
      await eq(`dirty.shlU16amt(${a})`, encodeCall(sel('shlU16(uint16,uint256)'), [1n, a])); // dirty amount is fine (u256), but a fine
      await eq(`dirty.addrToU160(${a})`, encodeCall(sel('addrToU160(address)'), [a])); // address dirty above 160
      await eq(`dirty.b3ToU24(${a})`, encodeCall(sel('b3ToU24(bytes3)'), [a])); // bytes3 with dirty low 29 bytes
      await eq(`dirty.negI16(${a})`, encodeCall(sel('negI16(int16)'), [a])); // int16 dirty above 16
      await eq(`dirty.divI16(${a},1)`, encodeCall(sel('divI16(int16,int16)'), [a, 1n]));
    }
    // bool param dirtiness via gtMixed first arg is uint8 -> dirty above 8 bits
    for (const a of [(1n << 8n) | 3n, M - 1n, (0xffn << 8n) | 7n]) {
      await eq(`dirty.gtMixed(${a},0)`, encodeCall(sel('gtMixed(uint8,uint32)'), [a, 0n]));
    }

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
