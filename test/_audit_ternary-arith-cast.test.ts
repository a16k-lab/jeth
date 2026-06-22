// _audit_ternary-arith-cast: adversarial differential probe for the TERNARY + ARITHMETIC +
// CASTS + control-flow family. Tries HARD to diverge from solc 0.8.x cancun on returndata,
// success/revert/Panic parity, raw storage slots, and event logs.
//
// Coverage:
//  - ternary over a value (boundary conds, short-circuit of untaken side-effect/reverting branch)
//  - ternary over bytes/string (literal / storage / calldata / memory-local branches, nesting)
//  - ternary over a static struct / fixed array (storage-copy independence, untaken reverting
//    branch, nested ternary)
//  - checked + unchecked arithmetic across widths (INT_MIN/-1, overflow Panic 0x11, /0 Panic 0x12,
//    exponentiation, negation of INT_MIN)
//  - implicit widening + explicit numeric/bytes casts (mask / sign-extend / truncate)
//  - evaluation ORDER of side effects (binary operands RIGHT-to-LEFT, arg lists LEFT-to-RIGHT,
//    inc/dec, assignment expressions, ternary-branch selection)
//  - loop and conditional forms (for/while, break/continue, early return)
//  - require / revert / custom-error reasons (string + custom-error, eager arg eval)
//  - DIRTY calldata high bits, boundary + signed min/max inputs.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const encStr = (s: string) => {
  const h = Buffer.from(s, 'utf8').toString('hex');
  return pad(BigInt(h.length / 2)) + h.padEnd(Math.ceil(h.length / 64) * 64, '0');
};
// width helpers
const umax = (bits: bigint) => (1n << bits) - 1n;
const smax = (bits: bigint) => (1n << (bits - 1n)) - 1n;
const smin = (bits: bigint) => -(1n << (bits - 1n));
const sword = (bits: bigint, v: bigint) => ((v % (1n << bits)) + (1n << bits)) % (1n << bits); // intN -> word
const leftAlign = (sz: bigint, v: bigint) => v << ((32n - sz) * 8n); // bytesN word

interface Pair { jeth: Harness; sol: Harness; aj: Address; as: Address; }
async function build(jethSrc: string, solSrc: string, seedSigs: string[] = []): Promise<Pair> {
  const jb = compile(jethSrc, { fileName: 'C.jeth' });
  const sb = compileSolidity(solSrc, 'C');
  const jeth = await Harness.create(); const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode); const as = await sol.deploy(sb.creation);
  for (const s of seedSigs) { await jeth.call(aj, encodeCall(sel(s), [])); await sol.call(as, encodeCall(sel(s), [])); }
  return { jeth, sol, aj, as };
}
// shared mismatch collector across a describe block
function mkEq(p: Pair, mism: string[], counter: { n: number }) {
  return async (label: string, data: string) => {
    counter.n++;
    const j = await p.jeth.call(p.aj, data); const s = await p.sol.call(p.as, data);
    const jlog = JSON.stringify(j.logs); const slog = JSON.stringify(s.logs);
    if (j.success !== s.success || j.returnHex !== s.returnHex || jlog !== slog) {
      mism.push(`${label}: jeth{ok=${j.success},ret=${j.returnHex},err=${j.exceptionError},logs=${jlog}} sol{ok=${s.success},ret=${s.returnHex},logs=${slog}}`);
    }
    return { j, s };
  };
}
async function slotsEq(p: Pair, label: string, slots: bigint[], mism: string[]) {
  for (const sl of slots) {
    const jv = await readSlot(p.jeth, p.aj, sl);
    const sv = await readSlot(p.sol, p.as, sl);
    if (jv !== sv) mism.push(`${label} slot ${sl}: jeth=${jv} sol=${sv}`);
  }
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Contract A: VALUE ternary + short-circuit of untaken reverting/side-effecting branch.
// ════════════════════════════════════════════════════════════════════════════════════════════
const JA = `@contract class C {
  @state seq: u256;
  // basic value ternary, narrow result type (truncation parity)
  @external @pure pick8(c: bool, a: u8, b: u8): u8 { return c ? a : b; }
  @external @pure pickI16(c: bool, a: i16, b: i16): i16 { return c ? a : b; }
  // condition computed from arithmetic; untaken branch DIVIDES BY ZERO -> must short-circuit
  @external @pure divGuard(a: u256, b: u256): u256 { return b == 0n ? 0n : a / b; }
  // untaken branch OVERFLOWS (checked) -> must not fire when condition picks safe branch
  @external @pure ovGuard(c: bool, a: u256, b: u256): u256 { return c ? a : a * b; }
  // untaken branch is INT_MIN negation -> Panic only if taken
  @external @pure negGuard(c: bool, a: i256): i256 { return c ? 0n : -a; }
  // nested value ternary with three side-effecting writes; only one path runs
  @external nestedSeq(c: bool, d: bool): u256 { this.seq = 0n; let r: u256 = c ? (this.seq = this.seq + 1n) : (d ? (this.seq = this.seq + 2n) : (this.seq = this.seq + 3n)); return this.seq * 10n + r; }
  // ternary result widened to wider type (implicit widen of both arms)
  @external @pure widenArms(c: bool, a: u8, b: u16): u256 { return u256(c ? u16(a) : b); }
  // ternary as operand of arithmetic (precedence / cleaning)
  @external @pure ternArith(c: bool, a: u8, b: u8): u8 { return (c ? a : b) + 1n; }
  // dirty-bool condition: any nonzero word is "true" in solc once cleaned; param is bool
  @external @pure boolPick(c: bool, a: u256, b: u256): u256 { return c ? a : b; }
  @external @view getSeq(): u256 { return this.seq; }
}`;
const SA = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256 seq;
  function pick8(bool c, uint8 a, uint8 b) external pure returns (uint8){ return c ? a : b; }
  function pickI16(bool c, int16 a, int16 b) external pure returns (int16){ return c ? a : b; }
  function divGuard(uint256 a, uint256 b) external pure returns (uint256){ return b == 0 ? 0 : a / b; }
  function ovGuard(bool c, uint256 a, uint256 b) external pure returns (uint256){ return c ? a : a * b; }
  function negGuard(bool c, int256 a) external pure returns (int256){ return c ? int256(0) : -a; }
  function nestedSeq(bool c, bool d) external returns (uint256){ seq = 0; uint256 r = c ? (seq = seq + 1) : (d ? (seq = seq + 2) : (seq = seq + 3)); return seq * 10 + r; }
  function widenArms(bool c, uint8 a, uint16 b) external pure returns (uint256){ return uint256(c ? uint16(a) : b); }
  function ternArith(bool c, uint8 a, uint8 b) external pure returns (uint8){ return (c ? a : b) + 1; }
  function boolPick(bool c, uint256 a, uint256 b) external pure returns (uint256){ return c ? a : b; }
  function getSeq() external view returns (uint256){ return seq; }
}`;

// ════════════════════════════════════════════════════════════════════════════════════════════
// Contract B: bytes/string ternary — literal / storage / calldata / memory-local branches,
// short-circuit, nesting, .length, indexing, use as event arg.
// ════════════════════════════════════════════════════════════════════════════════════════════
const SHORT = 'yes', LONG = 'no, this is a string that runs well past thirty-two bytes for the long case';
const JB = `@contract class C {
  @state a: string; @state b: string;
  @event Ev(s: string);
  @external setAB(x: string, y: string): void { this.a = x; this.b = y; }
  @external @pure lit(c: bool): string { return c ? "${SHORT}" : "${LONG}"; }
  @external @view stor(c: bool): string { let s: string = c ? this.a : this.b; return s; }
  @external @pure cd(c: bool, x: string, y: string): string { return c ? x : y; }
  @external @pure cdLen(c: bool, x: bytes, y: bytes): u256 { return (c ? x : y).length; }
  @external @pure nested(c: bool, d: bool, x: string, y: string): string { return c ? (d ? x : y) : "fallback string that is also over thirty-two bytes long ok"; }
  // ternary with a memory-local branch
  @external @pure memLocal(c: bool, x: string): string { let m: string = "local literal value that exceeds thirty two bytes for the heap path"; return c ? x : m; }
  // ternary string as event arg (log parity)
  @external emitPick(c: bool, x: string, y: string): void { emit(Ev(c ? x : y)); }
}`;
const SB = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  string a; string b;
  event Ev(string s);
  function setAB(string calldata x, string calldata y) external { a = x; b = y; }
  function lit(bool c) external pure returns (string memory){ return c ? "${SHORT}" : "${LONG}"; }
  function stor(bool c) external view returns (string memory){ string memory s = c ? a : b; return s; }
  function cd(bool c, string calldata x, string calldata y) external pure returns (string memory){ return c ? x : y; }
  function cdLen(bool c, bytes calldata x, bytes calldata y) external pure returns (uint256){ return (c ? x : y).length; }
  function nested(bool c, bool d, string calldata x, string calldata y) external pure returns (string memory){ return c ? (d ? x : y) : "fallback string that is also over thirty-two bytes long ok"; }
  function memLocal(bool c, string calldata x) external pure returns (string memory){ string memory m = "local literal value that exceeds thirty two bytes for the heap path"; return c ? x : m; }
  function emitPick(bool c, string calldata x, string calldata y) external { emit Ev(c ? x : y); }
}`;

// ════════════════════════════════════════════════════════════════════════════════════════════
// Contract D: static struct / fixed-array ternary — storage-copy independence, untaken reverting
// ctor branch, nested aggregate ternary, packed/signed/bytesN fields.
// ════════════════════════════════════════════════════════════════════════════════════════════
const JD = `@struct class P { a: u256; b: u8; c: address; d: i128; e: bool; f: bytes32; }
@contract class C {
  @state x: P; @state y: P; @state z: P;
  @state ax: Arr<u256,3>; @state ay: Arr<u256,3>;
  @external seed(): void {
    this.x = P(11n, 200n, address(0xa1n), -5n, true, bytes32(u256(0x1122n)));
    this.y = P(33n, 44n, address(0xb2n), 99n, false, bytes32(u256(0xdeadbeefn)));
    this.z = P(55n, 66n, address(0xc3n), -77n, true, bytes32(u256(0xfeedn)));
    this.ax[0n] = 1n; this.ax[1n] = 2n; this.ax[2n] = 3n;
    this.ay[0n] = 7n; this.ay[1n] = 8n; this.ay[2n] = 9n;
  }
  @external @view getX(): P { return this.x; }
  @external @view getY(): P { return this.y; }
  @external @view pickStruct(c: bool): P { return c ? this.x : this.y; }
  @external @view pickArr(c: bool): Arr<u256,3> { return c ? this.ax : this.ay; }
  @external @view fieldD(c: bool): i128 { let p: P = c ? this.x : this.y; return p.d; }
  // mutate the copied local: storage must be untouched
  @external mutLocal(c: bool): P { let p: P = c ? this.x : this.y; p.a = 7777n; p.b = 1n; p.d = -42n; p.e = false; return p; }
  // nested aggregate ternary
  @external @view nestedAgg(c: bool, d: bool): P { return c ? this.x : (d ? this.y : this.z); }
  // untaken ctor branch divides by zero -> short-circuit
  @external divBranch(c: bool, v: u256): P { return c ? this.x : P(1000n / v, 2n, address(0n), 0n, false, bytes32(u256(0n))); }
  @external @view getArr(i: u256): u256 { return this.ax[i]; }
}`;
const SD = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; address c; int128 d; bool e; bytes32 f; }
  P x; P y; P z;
  uint256[3] ax; uint256[3] ay;
  function seed() external {
    x = P(11, 200, address(0xa1), -5, true, bytes32(uint256(0x1122)));
    y = P(33, 44, address(0xb2), 99, false, bytes32(uint256(0xdeadbeef)));
    z = P(55, 66, address(0xc3), -77, true, bytes32(uint256(0xfeed)));
    ax[0]=1; ax[1]=2; ax[2]=3; ay[0]=7; ay[1]=8; ay[2]=9;
  }
  function getX() external view returns (P memory){ return x; }
  function getY() external view returns (P memory){ return y; }
  function pickStruct(bool c) external view returns (P memory){ return c ? x : y; }
  function pickArr(bool c) external view returns (uint256[3] memory){ return c ? ax : ay; }
  function fieldD(bool c) external view returns (int128){ P memory p = c ? x : y; return p.d; }
  function mutLocal(bool c) external returns (P memory){ P memory p = c ? x : y; p.a = 7777; p.b = 1; p.d = -42; p.e = false; return p; }
  function nestedAgg(bool c, bool d) external view returns (P memory){ return c ? x : (d ? y : z); }
  function divBranch(bool c, uint256 v) external view returns (P memory){ return c ? x : P(1000 / v, 2, address(0), 0, false, bytes32(uint256(0))); }
  function getArr(uint256 i) external view returns (uint256){ return ax[i]; }
}`;

// ════════════════════════════════════════════════════════════════════════════════════════════
// Contract E: ARITHMETIC + CASTS at many widths (checked overflow Panic 0x11, /0 Panic 0x12,
// INT_MIN/-1, negation, exponentiation, unchecked wrap, implicit widen, explicit casts).
// ════════════════════════════════════════════════════════════════════════════════════════════
const JE = `@contract class C {
  @external @pure addU8(a: u8, b: u8): u8 { return a + b; }
  @external @pure subU8(a: u8, b: u8): u8 { return a - b; }
  @external @pure mulU8(a: u8, b: u8): u8 { return a * b; }
  @external @pure addI8(a: i8, b: i8): i8 { return a + b; }
  @external @pure subI8(a: i8, b: i8): i8 { return a - b; }
  @external @pure mulI8(a: i8, b: i8): i8 { return a * b; }
  @external @pure divI8(a: i8, b: i8): i8 { return a / b; }
  @external @pure modI8(a: i8, b: i8): i8 { return a % b; }
  @external @pure negI8(a: i8): i8 { return -a; }
  @external @pure addU256(a: u256, b: u256): u256 { return a + b; }
  @external @pure subU256(a: u256, b: u256): u256 { return a - b; }
  @external @pure mulU256(a: u256, b: u256): u256 { return a * b; }
  @external @pure divI256(a: i256, b: i256): i256 { return a / b; }
  @external @pure modI256(a: i256, b: i256): i256 { return a % b; }
  @external @pure negI256(a: i256): i256 { return -a; }
  @external @pure powU8(a: u8, b: u8): u8 { return a ** b; }
  @external @pure powI8(a: i8, b: u8): i8 { return a ** b; }
  @external @pure powU256(a: u256, b: u256): u256 { return a ** b; }
  // unchecked variants
  @external @pure uAddU8(a: u8, b: u8): u8 { unchecked: { return a + b; } }
  @external @pure uMulU8(a: u8, b: u8): u8 { unchecked: { return a * b; } }
  @external @pure uNegI8(a: i8): i8 { unchecked: { return -a; } }
  @external @pure uPowU8(a: u8, b: u8): u8 { unchecked: { return a ** b; } }
  @external @pure uSubU256(a: u256, b: u256): u256 { unchecked: { return a - b; } }
  // implicit widening chains
  @external @pure widen(a: u8, b: u16, c: u32): u64 { return a + b + c; }
  @external @pure widenMul(a: i8, b: i64): i128 { return a * b; }
  // explicit casts: truncate / sign-extend / mask
  @external @pure narrow(a: u256): u8 { return u8(a); }
  @external @pure signExt(a: i8): i256 { return i256(a); }
  @external @pure u2i(a: u8): i8 { return i8(a); }
  @external @pure i2u(a: i8): u8 { return u8(a); }
  @external @pure b1u8(a: bytes1): u8 { return u8(a); }
  @external @pure u8b1(a: u8): bytes1 { return bytes1(a); }
  @external @pure b32b4(a: bytes32): bytes4 { return bytes4(a); }
  @external @pure b4b32(a: bytes4): bytes32 { return bytes32(a); }
  @external @pure addrU160(a: address): u160 { return u160(a); }
  @external @pure u160addr(a: u160): address { return address(a); }
  @external @pure i24round(a: i24): i24 { return i24(u24(a)); }
  @external @pure castInTern(c: bool, a: u256): u8 { return c ? u8(a) : 0n; }
}`;
const SE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function addU8(uint8 a, uint8 b) external pure returns (uint8){ return a + b; }
  function subU8(uint8 a, uint8 b) external pure returns (uint8){ return a - b; }
  function mulU8(uint8 a, uint8 b) external pure returns (uint8){ return a * b; }
  function addI8(int8 a, int8 b) external pure returns (int8){ return a + b; }
  function subI8(int8 a, int8 b) external pure returns (int8){ return a - b; }
  function mulI8(int8 a, int8 b) external pure returns (int8){ return a * b; }
  function divI8(int8 a, int8 b) external pure returns (int8){ return a / b; }
  function modI8(int8 a, int8 b) external pure returns (int8){ return a % b; }
  function negI8(int8 a) external pure returns (int8){ return -a; }
  function addU256(uint256 a, uint256 b) external pure returns (uint256){ return a + b; }
  function subU256(uint256 a, uint256 b) external pure returns (uint256){ return a - b; }
  function mulU256(uint256 a, uint256 b) external pure returns (uint256){ return a * b; }
  function divI256(int256 a, int256 b) external pure returns (int256){ return a / b; }
  function modI256(int256 a, int256 b) external pure returns (int256){ return a % b; }
  function negI256(int256 a) external pure returns (int256){ return -a; }
  function powU8(uint8 a, uint8 b) external pure returns (uint8){ return a ** b; }
  function powI8(int8 a, uint8 b) external pure returns (int8){ return a ** b; }
  function powU256(uint256 a, uint256 b) external pure returns (uint256){ return a ** b; }
  function uAddU8(uint8 a, uint8 b) external pure returns (uint8){ unchecked { return a + b; } }
  function uMulU8(uint8 a, uint8 b) external pure returns (uint8){ unchecked { return a * b; } }
  function uNegI8(int8 a) external pure returns (int8){ unchecked { return -a; } }
  function uPowU8(uint8 a, uint8 b) external pure returns (uint8){ unchecked { return a ** b; } }
  function uSubU256(uint256 a, uint256 b) external pure returns (uint256){ unchecked { return a - b; } }
  function widen(uint8 a, uint16 b, uint32 c) external pure returns (uint64){ return a + b + c; }
  function widenMul(int8 a, int64 b) external pure returns (int128){ return a * b; }
  function narrow(uint256 a) external pure returns (uint8){ return uint8(a); }
  function signExt(int8 a) external pure returns (int256){ return int256(a); }
  function u2i(uint8 a) external pure returns (int8){ return int8(a); }
  function i2u(int8 a) external pure returns (uint8){ return uint8(a); }
  function b1u8(bytes1 a) external pure returns (uint8){ return uint8(a); }
  function u8b1(uint8 a) external pure returns (bytes1){ return bytes1(a); }
  function b32b4(bytes32 a) external pure returns (bytes4){ return bytes4(a); }
  function b4b32(bytes4 a) external pure returns (bytes32){ return bytes32(a); }
  function addrU160(address a) external pure returns (uint160){ return uint160(a); }
  function u160addr(uint160 a) external pure returns (address){ return address(a); }
  function i24round(int24 a) external pure returns (int24){ return int24(uint24(a)); }
  function castInTern(bool c, uint256 a) external pure returns (uint8){ return c ? uint8(a) : 0; }
}`;

// ════════════════════════════════════════════════════════════════════════════════════════════
// Contract F: evaluation ORDER + control flow + require/revert/custom-error reasons.
// ════════════════════════════════════════════════════════════════════════════════════════════
const JF = `@contract class C {
  @error Er2(x: u256, y: u256);
  @event Ev3(a: u256, b: u256, c: u256);
  // binary operands RIGHT-to-LEFT
  @external @pure subOrder(): u256 { let s: u256 = 0n; let r: u256 = (s = s * 10n + 1n) - (s = s * 10n + 2n) + 100n; return s * 1000n + r; }
  @external @pure mulOrder(): u256 { let s: u256 = 0n; let r: u256 = (s = s * 10n + 3n) * (s = s * 10n + 5n); return s * 1000n + r; }
  // arg lists LEFT-to-RIGHT
  @external @pure argOrder(): u256 { let s: u256 = 0n; return this.sum3((s = s*10n+1n),(s = s*10n+2n),(s = s*10n+3n)) * 10000n + s; }
  @pure sum3(a: u256, b: u256, c: u256): u256 { return a * 100n + b * 10n + c; }
  // inc/dec in operands
  @external @pure incBin(): u256 { let x: u256 = 5n; let y: u256 = (++x) * 100n + (++x); return x * 100000n + y; }
  @external @pure postBin(): u256 { let x: u256 = 5n; let y: u256 = (x++) * 100n + (x++); return x * 100000n + y; }
  // ternary in operand: branch selection order with side effects
  @external @pure ternOrder(c: bool): u256 { let s: u256 = 0n; let r: u256 = (c ? (s = s*10n+1n) : (s = s*10n+2n)) + (s = s*10n+9n); return s * 1000n + r; }
  // for loop accumulation (overflow inside loop -> revert parity)
  @external @pure factorial(n: u256): u256 { let r: u256 = 1n; for (let i: u256 = 1n; i <= n; i += 1n) { r *= i; } return r; }
  // while with break/continue
  @external @pure skipEven(n: u256): u256 { let s: u256 = 0n; let i: u256 = 0n; while (i < n) { i += 1n; if (i % 2n == 0n) { continue; } s += i; } return s; }
  @external @pure breakAt(n: u256, k: u256): u256 { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i += 1n) { if (i == k) { break; } s += i; } return s; }
  // if/else-if classify
  @external @pure classify(x: u256): u256 { if (x < 10n) { return 1n; } else if (x < 20n) { return 2n; } else { return 3n; } }
  // require with string reason
  @external @pure reqStr(a: u256): u256 { require(a > 0n, "must be positive"); return a; }
  // require with custom error, eager arg eval (left to right)
  @external @pure reqErr(a: u256, b: u256): u256 { require(a > b, Er2(a, b)); return a; }
  // revert with custom error + side-effecting args
  @external @pure revArgs(): u256 { let s: u256 = 0n; revert(Er2((s = s*10n+1n), (s = s*10n+2n))); }
  // revert with bare string
  @external @pure revStr(): void { revert("boom long reason string that is definitely over thirty-two bytes ok"); }
  // emit with side-effecting args (left to right) + log parity
  @external emitOrd(): u256 { let s: u256 = 0n; emit(Ev3((s=s*10n+1n),(s=s*10n+2n),(s=s*10n+3n))); return s; }
  // short-circuit && / || (no divide-by-zero when guarded)
  @external @pure scAnd(a: u256): bool { return (a > 0n) && ((10n / a) > 0n); }
  @external @pure scOr(a: u256): bool { return (a == 0n) || ((10n / a) > 5n); }
}`;
const SF = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  error Er2(uint256 x, uint256 y);
  event Ev3(uint256 a, uint256 b, uint256 c);
  function subOrder() external pure returns (uint256){ uint256 s = 0; uint256 r = (s = s * 10 + 1) - (s = s * 10 + 2) + 100; return s * 1000 + r; }
  function mulOrder() external pure returns (uint256){ uint256 s = 0; uint256 r = (s = s * 10 + 3) * (s = s * 10 + 5); return s * 1000 + r; }
  function argOrder() external pure returns (uint256){ uint256 s = 0; return sum3((s = s*10+1),(s = s*10+2),(s = s*10+3)) * 10000 + s; }
  function sum3(uint256 a, uint256 b, uint256 c) internal pure returns (uint256){ return a * 100 + b * 10 + c; }
  function incBin() external pure returns (uint256){ uint256 x = 5; uint256 y = (++x) * 100 + (++x); return x * 100000 + y; }
  function postBin() external pure returns (uint256){ uint256 x = 5; uint256 y = (x++) * 100 + (x++); return x * 100000 + y; }
  function ternOrder(bool c) external pure returns (uint256){ uint256 s = 0; uint256 r = (c ? (s = s*10+1) : (s = s*10+2)) + (s = s*10+9); return s * 1000 + r; }
  function factorial(uint256 n) external pure returns (uint256){ uint256 r = 1; for (uint256 i = 1; i <= n; i += 1) { r *= i; } return r; }
  function skipEven(uint256 n) external pure returns (uint256){ uint256 s = 0; uint256 i = 0; while (i < n) { i += 1; if (i % 2 == 0) { continue; } s += i; } return s; }
  function breakAt(uint256 n, uint256 k) external pure returns (uint256){ uint256 s = 0; for (uint256 i = 0; i < n; i += 1) { if (i == k) { break; } s += i; } return s; }
  function classify(uint256 x) external pure returns (uint256){ if (x < 10) { return 1; } else if (x < 20) { return 2; } else { return 3; } }
  function reqStr(uint256 a) external pure returns (uint256){ require(a > 0, "must be positive"); return a; }
  function reqErr(uint256 a, uint256 b) external pure returns (uint256){ require(a > b, Er2(a, b)); return a; }
  function revArgs() external pure returns (uint256){ uint256 s = 0; revert Er2((s = s*10+1), (s = s*10+2)); }
  function revStr() external pure { revert("boom long reason string that is definitely over thirty-two bytes ok"); }
  function emitOrd() external returns (uint256){ uint256 s = 0; emit Ev3((s=s*10+1),(s=s*10+2),(s=s*10+3)); return s; }
  function scAnd(uint256 a) external pure returns (bool){ return (a > 0) && ((10 / a) > 0); }
  function scOr(uint256 a) external pure returns (bool){ return (a == 0) || ((10 / a) > 5); }
}`;

describe('AUDIT ternary-arith-cast vs Solidity', () => {
  const mism: string[] = [];
  const counter = { n: 0 };

  describe('A: value ternary + short-circuit', () => {
    let p: Pair; let eq: ReturnType<typeof mkEq>;
    beforeAll(async () => { p = await build(JA, SA); eq = mkEq(p, mism, counter); });
    it('runs', async () => {
      const u8v = [0n, 1n, 127n, 128n, 255n];
      for (const c of [1n, 0n]) for (const a of u8v) for (const b of u8v) {
        await eq(`pick8(${c},${a},${b})`, encodeCall(sel('pick8(bool,uint8,uint8)'), [c, a, b]));
      }
      const i16v = [smin(16n), -1n, 0n, 1n, smax(16n)].map(v => sword(16n, v));
      for (const c of [1n, 0n]) for (const a of i16v) for (const b of i16v) {
        await eq(`pickI16(${c},${a},${b})`, encodeCall(sel('pickI16(bool,int16,int16)'), [c, a, b]));
      }
      // divGuard: b==0 must short-circuit to 0 (no Panic), else divide
      for (const a of [0n, 1n, 100n, M - 1n]) for (const b of [0n, 1n, 3n, 7n]) {
        await eq(`divGuard(${a},${b})`, encodeCall(sel('divGuard(uint256,uint256)'), [a, b]));
      }
      // ovGuard: c=true picks a (safe); c=false multiplies (may overflow)
      for (const c of [1n, 0n]) for (const a of [0n, 1n, 1n << 200n, M - 1n]) for (const b of [0n, 1n, 2n, 1n << 200n]) {
        await eq(`ovGuard(${c},${a},${b})`, encodeCall(sel('ovGuard(bool,uint256,uint256)'), [c, a, b]));
      }
      // negGuard: c=true -> 0; c=false -> -a (Panic if a==INT_MIN)
      for (const c of [1n, 0n]) for (const a of [smin(256n), -1n, 0n, 1n, smax(256n)].map(v => sword(256n, v))) {
        await eq(`negGuard(${c},${a})`, encodeCall(sel('negGuard(bool,int256)'), [c, a]));
      }
      // nestedSeq: only one of three writes runs; check returndata AND storage
      for (const c of [1n, 0n]) for (const d of [1n, 0n]) {
        await eq(`nestedSeq(${c},${d})`, encodeCall(sel('nestedSeq(bool,bool)'), [c, d]));
        await eq(`getSeq after nestedSeq(${c},${d})`, encodeCall(sel('getSeq()'), []));
        await slotsEq(p, `seq slot after nestedSeq(${c},${d})`, [0n], mism);
      }
      for (const c of [1n, 0n]) for (const a of [0n, 1n, 255n]) for (const b of [0n, 1n, 65535n]) {
        await eq(`widenArms(${c},${a},${b})`, encodeCall(sel('widenArms(bool,uint8,uint16)'), [c, a, b]));
      }
      for (const c of [1n, 0n]) for (const a of [255n, 200n]) for (const b of [1n, 0n]) {
        await eq(`ternArith(${c},${a},${b})`, encodeCall(sel('ternArith(bool,uint8,uint8)'), [c, a, b]));
      }
      // DIRTY bool condition: high garbage bits above bit 0. solc cleans to {0,1}.
      for (const c of [2n, (1n << 8n) | 1n, M - 1n, 1n << 255n]) {
        await eq(`dirty.boolPick(${c})`, encodeCall(sel('boolPick(bool,uint256,uint256)'), [c, 111n, 222n]));
      }
    });
  });

  describe('B: bytes/string ternary', () => {
    let p: Pair; let eq: ReturnType<typeof mkEq>;
    // calldata layout for (bool c, T x, T y): [c][off_x=0x60][off_y][x..][y..]
    const cdBSS = (sig: string, c: boolean, x: string, y: string) => {
      const tx = encStr(x); const offY = 0x60 + tx.length / 2;
      return '0x' + sel(sig) + pad(c ? 1n : 0n) + pad(0x60n) + pad(BigInt(offY)) + tx + encStr(y);
    };
    // (string x, string y): [off_x=0x40][off_y][x..][y..]
    const cdSS = (sig: string, x: string, y: string) => {
      const tx = encStr(x); const offY = 0x40 + tx.length / 2;
      return '0x' + sel(sig) + pad(0x40n) + pad(BigInt(offY)) + tx + encStr(y);
    };
    // (bool c, string x): [c][off_x=0x40][x..]
    const cdBS = (sig: string, c: boolean, x: string) => '0x' + sel(sig) + pad(c ? 1n : 0n) + pad(0x40n) + encStr(x);
    async function seedAB(x: string, y: string) {
      const d = cdSS('setAB(string,string)', x, y);
      await p.jeth.call(p.aj, d); await p.sol.call(p.as, d);
    }
    beforeAll(async () => { p = await build(JB, SB); eq = mkEq(p, mism, counter); });
    it('runs', async () => {
      const pairs: [string, string][] = [[SHORT, LONG], [LONG, SHORT], ['', 'x'], ['ab', ''], ['', ''],
        ['exactly thirty-two bytes long!!!', 'thirty-three bytes long string xx']];
      for (const c of [true, false]) {
        await eq(`lit(${c})`, encodeCall(sel('lit(bool)'), [c ? 1n : 0n]));
        await eq(`memLocal(${c})`, cdBS('memLocal(bool,string)', c, c ? 'short cd' : LONG));
        for (const [x, y] of pairs) {
          await eq(`cd(${c})[${x.length},${y.length}]`, cdBSS('cd(bool,string,string)', c, x, y));
          await eq(`cdLen(${c})[${x.length},${y.length}]`, cdBSS('cdLen(bool,string,string)', c, x, y));
          await eq(`emitPick(${c})[${x.length},${y.length}]`, cdBSS('emitPick(bool,string,string)', c, x, y));
        }
        for (const d of [true, false]) {
          await eq(`nested(${c},${d})`, '0x' + sel('nested(bool,bool,string,string)') + pad(c ? 1n : 0n) + pad(d ? 1n : 0n) + pad(0x80n) + pad(BigInt(0x80 + encStr(SHORT).length / 2)) + encStr(SHORT) + encStr(LONG));
        }
      }
      // storage-string ternary both directions, short/long
      for (const [x, y] of [[SHORT, LONG], [LONG, SHORT], ['', 'nonempty value here']] as [string, string][]) {
        await seedAB(x, y);
        await eq('stor(true)', encodeCall(sel('stor(bool)'), [1n]));
        await eq('stor(false)', encodeCall(sel('stor(bool)'), [0n]));
      }
    });
  });

  describe('D: static struct / fixed-array ternary', () => {
    let p: Pair; let eq: ReturnType<typeof mkEq>;
    beforeAll(async () => { p = await build(JD, SD, ['seed()']); eq = mkEq(p, mism, counter); });
    it('runs', async () => {
      for (const c of [1n, 0n]) {
        await eq(`pickStruct(${c})`, encodeCall(sel('pickStruct(bool)'), [c]));
        await eq(`pickArr(${c})`, encodeCall(sel('pickArr(bool)'), [c]));
        await eq(`fieldD(${c})`, encodeCall(sel('fieldD(bool)'), [c]));
      }
      for (const c of [1n, 0n]) for (const d of [1n, 0n]) {
        await eq(`nestedAgg(${c},${d})`, encodeCall(sel('nestedAgg(bool,bool)'), [c, d]));
      }
      // mutate copied local: returndata matches AND storage untouched (x:0..3, y:4..7)
      const structSlots = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n];
      for (const c of [1n, 0n]) {
        await eq(`mutLocal(${c})`, encodeCall(sel('mutLocal(bool)'), [c]));
        await eq(`getX after mutLocal(${c})`, encodeCall(sel('getX()'), []));
        await eq(`getY after mutLocal(${c})`, encodeCall(sel('getY()'), []));
        await slotsEq(p, `struct storage after mutLocal(${c})`, structSlots, mism);
      }
      // untaken ctor branch divides by zero -> short-circuit when c=true
      await eq('divBranch(true,0)', encodeCall(sel('divBranch(bool,uint256)'), [1n, 0n]));
      await eq('divBranch(false,0)', encodeCall(sel('divBranch(bool,uint256)'), [0n, 0n]));
      await eq('divBranch(false,4)', encodeCall(sel('divBranch(bool,uint256)'), [0n, 4n]));
    });
  });

  describe('E: arithmetic + casts at widths', () => {
    let p: Pair; let eq: ReturnType<typeof mkEq>;
    beforeAll(async () => { p = await build(JE, SE); eq = mkEq(p, mism, counter); });
    it('runs', async () => {
      const u8v = [0n, 1n, 2n, 16n, 127n, 128n, 200n, 254n, 255n];
      for (const a of u8v) for (const b of u8v) {
        await eq(`addU8(${a},${b})`, encodeCall(sel('addU8(uint8,uint8)'), [a, b]));
        await eq(`subU8(${a},${b})`, encodeCall(sel('subU8(uint8,uint8)'), [a, b]));
        await eq(`mulU8(${a},${b})`, encodeCall(sel('mulU8(uint8,uint8)'), [a, b]));
        await eq(`uAddU8(${a},${b})`, encodeCall(sel('uAddU8(uint8,uint8)'), [a, b]));
        await eq(`uMulU8(${a},${b})`, encodeCall(sel('uMulU8(uint8,uint8)'), [a, b]));
      }
      const i8v = [smin(8n), smin(8n) + 1n, -1n, 0n, 1n, smax(8n), -100n, 100n].map(v => sword(8n, v));
      for (const a of i8v) for (const b of i8v) {
        await eq(`addI8(${a},${b})`, encodeCall(sel('addI8(int8,int8)'), [a, b]));
        await eq(`subI8(${a},${b})`, encodeCall(sel('subI8(int8,int8)'), [a, b]));
        await eq(`mulI8(${a},${b})`, encodeCall(sel('mulI8(int8,int8)'), [a, b]));
        await eq(`divI8(${a},${b})`, encodeCall(sel('divI8(int8,int8)'), [a, b]));
        await eq(`modI8(${a},${b})`, encodeCall(sel('modI8(int8,int8)'), [a, b]));
      }
      for (const a of [smin(8n), -1n, 0n, 1n, smax(8n)].map(v => sword(8n, v))) {
        await eq(`negI8(${a})`, encodeCall(sel('negI8(int8)'), [a]));
        await eq(`uNegI8(${a})`, encodeCall(sel('uNegI8(int8)'), [a]));
      }
      const u256v = [0n, 1n, 2n, M - 1n, 1n << 128n, (1n << 255n)];
      for (const a of u256v) for (const b of u256v) {
        await eq(`addU256(${a},${b})`, encodeCall(sel('addU256(uint256,uint256)'), [a, b]));
        await eq(`subU256(${a},${b})`, encodeCall(sel('subU256(uint256,uint256)'), [a, b]));
        await eq(`mulU256(${a},${b})`, encodeCall(sel('mulU256(uint256,uint256)'), [a, b]));
        await eq(`uSubU256(${a},${b})`, encodeCall(sel('uSubU256(uint256,uint256)'), [a, b]));
      }
      // signed div/mod incl INT_MIN/-1 (Panic 0x11) and /0 (Panic 0x12)
      const i256v = [smin(256n), smin(256n) + 1n, -1n, 0n, 1n, smax(256n), -7n, 7n].map(v => sword(256n, v));
      for (const a of i256v) for (const b of i256v) {
        await eq(`divI256(${a},${b})`, encodeCall(sel('divI256(int256,int256)'), [a, b]));
        await eq(`modI256(${a},${b})`, encodeCall(sel('modI256(int256,int256)'), [a, b]));
      }
      for (const a of [smin(256n), smin(256n) + 1n, -1n, 0n, smax(256n)].map(v => sword(256n, v))) {
        await eq(`negI256(${a})`, encodeCall(sel('negI256(int256)'), [a]));
      }
      // exponentiation edges
      for (const a of [0n, 1n, 2n, 3n, 15n, 16n, 255n]) for (const b of [0n, 1n, 2n, 3n, 7n, 8n, 9n, 255n]) {
        await eq(`powU8(${a},${b})`, encodeCall(sel('powU8(uint8,uint8)'), [a, b]));
        await eq(`uPowU8(${a},${b})`, encodeCall(sel('uPowU8(uint8,uint8)'), [a, b]));
      }
      for (const a of [smin(8n), -2n, -1n, 0n, 1n, 2n, smax(8n)].map(v => sword(8n, v))) for (const b of [0n, 1n, 2n, 3n, 7n, 8n]) {
        await eq(`powI8(${a},${b})`, encodeCall(sel('powI8(int8,uint8)'), [a, b]));
      }
      for (const a of [0n, 1n, 2n, 3n, M - 1n]) for (const b of [0n, 1n, 2n, 3n, 255n, 256n]) {
        await eq(`powU256(${a},${b})`, encodeCall(sel('powU256(uint256,uint256)'), [a, b]));
      }
      // implicit widening
      for (const a of [0n, 1n, 255n]) for (const b of [0n, 1n, 65535n]) for (const c of [0n, 1n, umax(32n)]) {
        await eq(`widen(${a},${b},${c})`, encodeCall(sel('widen(uint8,uint16,uint32)'), [a, b, c]));
      }
      for (const a of [smin(8n), -1n, 1n, smax(8n)].map(v => sword(8n, v))) for (const b of [smin(64n), -1n, 0n, 1n, smax(64n)].map(v => sword(64n, v))) {
        await eq(`widenMul(${a},${b})`, encodeCall(sel('widenMul(int8,int64)'), [a, b]));
      }
      // explicit casts: truncate / sign-extend / mask
      for (const a of [0n, 1n, 255n, 256n, 0x1ffn, M - 1n, 0xabcdn]) {
        await eq(`narrow(${a})`, encodeCall(sel('narrow(uint256)'), [a]));
      }
      for (const a of [smin(8n), -1n, 0n, 1n, smax(8n)].map(v => sword(8n, v))) {
        await eq(`signExt(${a})`, encodeCall(sel('signExt(int8)'), [a]));
        await eq(`u2i(${a})`, encodeCall(sel('u2i(uint8)'), [a]));
        await eq(`i2u(${a})`, encodeCall(sel('i2u(int8)'), [a]));
      }
      for (const a of [0n, 0xa5n, 0xffn]) {
        await eq(`b1u8(${a})`, encodeCall(sel('b1u8(bytes1)'), [leftAlign(1n, a)]));
        await eq(`u8b1(${a})`, encodeCall(sel('u8b1(uint8)'), [a]));
      }
      for (const a of [0n, BigInt('0x' + 'a5'.repeat(32)), M - 1n, 0xdeadbeefcafen]) {
        await eq(`b32b4(${a})`, encodeCall(sel('b32b4(bytes32)'), [a]));
      }
      for (const a of [0n, 0x11223344n, 0xffffffffn]) {
        await eq(`b4b32(${a})`, encodeCall(sel('b4b32(bytes4)'), [leftAlign(4n, a)]));
      }
      const addrs = [0n, 1n, BigInt('0x' + '11'.repeat(20)), (1n << 160n) - 1n];
      for (const a of addrs) {
        await eq(`addrU160(${a})`, encodeCall(sel('addrU160(address)'), [a]));
        await eq(`u160addr(${a})`, encodeCall(sel('u160addr(uint160)'), [a]));
      }
      for (const a of [smin(24n), -1n, 0n, 1n, smax(24n)].map(v => sword(24n, v))) {
        await eq(`i24round(${a})`, encodeCall(sel('i24round(int24)'), [a]));
      }
      for (const c of [1n, 0n]) for (const a of [0n, 255n, 256n, M - 1n]) {
        await eq(`castInTern(${c},${a})`, encodeCall(sel('castInTern(bool,uint256)'), [c, a]));
      }
      // DIRTY calldata high bits on narrow params (solc validates)
      const dirty = [(1n << 8n) | 5n, M - 1n, (0xdeadn << 8n) | 0x42n, (1n << 255n) | 1n];
      for (const a of dirty) for (const b of [0n, 1n]) {
        await eq(`dirty.addU8(${a},${b})`, encodeCall(sel('addU8(uint8,uint8)'), [a, b]));
      }
      for (const a of dirty) {
        await eq(`dirty.negI8(${a})`, encodeCall(sel('negI8(int8)'), [a]));
        await eq(`dirty.addrU160(${a})`, encodeCall(sel('addrU160(address)'), [a]));
        await eq(`dirty.b1u8(${a})`, encodeCall(sel('b1u8(bytes1)'), [a]));   // bytes1 with dirty low 31 bytes
      }
    });
  });

  describe('F: eval-order + control flow + require/revert/error', () => {
    let p: Pair; let eq: ReturnType<typeof mkEq>;
    beforeAll(async () => { p = await build(JF, SF); eq = mkEq(p, mism, counter); });
    it('runs', async () => {
      for (const n of ['subOrder', 'mulOrder', 'argOrder', 'incBin', 'postBin', 'emitOrd', 'revArgs', 'revStr']) {
        await eq(n, encodeCall(sel(n + '()'), []));
      }
      for (const c of [1n, 0n]) await eq(`ternOrder(${c})`, encodeCall(sel('ternOrder(bool)'), [c]));
      // loops incl overflow-in-loop revert parity (factorial(57) overflows uint256? no — 58! > 2^256)
      for (const n of [0n, 1n, 5n, 10n, 20n, 50n, 57n, 58n, 100n]) {
        await eq(`factorial(${n})`, encodeCall(sel('factorial(uint256)'), [n]));
      }
      for (const n of [0n, 1n, 2n, 3n, 5n, 6n, 7n, 10n]) await eq(`skipEven(${n})`, encodeCall(sel('skipEven(uint256)'), [n]));
      for (const [n, k] of [[10n, 3n], [10n, 100n], [0n, 0n], [5n, 0n]] as [bigint, bigint][]) {
        await eq(`breakAt(${n},${k})`, encodeCall(sel('breakAt(uint256,uint256)'), [n, k]));
      }
      for (const x of [0n, 9n, 10n, 19n, 20n, 1000n]) await eq(`classify(${x})`, encodeCall(sel('classify(uint256)'), [x]));
      // require with string reason (true: ok; false: revert with Error(string))
      for (const a of [0n, 1n, 100n]) await eq(`reqStr(${a})`, encodeCall(sel('reqStr(uint256)'), [a]));
      // require with custom error
      for (const [a, b] of [[5n, 3n], [3n, 5n], [0n, 0n], [M - 1n, 0n]] as [bigint, bigint][]) {
        await eq(`reqErr(${a},${b})`, encodeCall(sel('reqErr(uint256,uint256)'), [a, b]));
      }
      // short-circuit && / ||
      for (const a of [0n, 1n, 2n, 3n, 10n]) {
        await eq(`scAnd(${a})`, encodeCall(sel('scAnd(uint256)'), [a]));
        await eq(`scOr(${a})`, encodeCall(sel('scOr(uint256)'), [a]));
      }
    });
  });

  it('SUMMARY: zero divergences', () => {
    if (mism.length) { console.log(`MISMATCHES ${mism.length}/${counter.n}`); for (const m of mism.slice(0, 50)) console.log(m); }
    else console.log(`ALL ${counter.n} cases byte-identical (returndata + success + logs + slots)`);
    expect(mism, mism.slice(0, 20).join('\n')).toEqual([]);
  });
});
