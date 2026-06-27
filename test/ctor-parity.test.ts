// Constructor parity (JETH302 + JETH303): a constructor may take AGGREGATE / DYNAMIC params
// (u256[], bytes, string, a value struct, Arr<u256,N>, a dynamic-field struct) and may CALL an
// internal/private function (incl. a transitive helper-calls-helper chain). Each is decoded from the
// ABI-encoded args appended to the creation bytecode (the same blob solc decodes) and verified
// byte-identical to a solc 0.8.35 mirror on RAW STORAGE SLOTS + deploy-revert parity. The internal
// callees are duplicated into the creation object so the ctor body's calls resolve there.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity, readSlot } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const caller = new Address(Buffer.from('1234123412341234123412341234123412341234', 'hex'));

// ---- minimal ABI encoders (no 0x prefix; appended directly to creation bytecode) ----
const hex = (s: string) => s; // identity (kept for readability)
// a single 32-byte word for a non-negative bigint.
const word = (v: bigint) => pad32(v);
// right-pad raw bytes to a multiple of 32 (the data payload of bytes/string).
function payload(bytes: Uint8Array): string {
  const n = Math.ceil(bytes.length / 32) * 32;
  let s = '';
  for (let i = 0; i < n; i++) s += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return s;
}
// the tuple encoding of a single dynamic argument `T arg` where T is bytes/string/T[]:
// one head OFFSET word (= 0x20) then the value's own encoding (length + payload / elements).
const enc = new TextEncoder();
// ABI-encode a single `bytes`/`string` argument (offset head + [len][padded data]).
const encBytesArg = (b: Uint8Array) => word(0x20n) + word(BigInt(b.length)) + payload(b);
// ABI-encode a single `uint256[]` argument (offset head + [len][elem words]).
const encUintArrayArg = (xs: bigint[]) => word(0x20n) + word(BigInt(xs.length)) + xs.map(word).join('');

async function deployJ(src: string, argsHex: string, value = 0n) {
  const h = await Harness.create();
  await h.fund(caller, 10n ** 20n);
  const a = await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode + argsHex, { caller, value });
  return { h, a };
}
async function deployS(src: string, argsHex: string, value = 0n) {
  const h = await Harness.create();
  await h.fund(caller, 10n ** 20n);
  const a = await h.deploy(compileSolidity(SPDX + src, 'C').creation + argsHex, { caller, value });
  return { h, a };
}
async function slots(h: Harness, a: Address, n: number) {
  const r: string[] = [];
  for (let i = 0; i < n; i++) r.push(await readSlot(h, a, BigInt(i)));
  return r;
}
/** deploy J + S with identical appended args; assert raw slots 0..n-1 are byte-identical. */
async function sameSlots(J: string, S: string, argsHex = '', n = 3, value = 0n) {
  const j = await deployJ(J, argsHex, value);
  const s = await deployS(S, argsHex, value);
  expect(await slots(j.h, j.a, n)).toEqual(await slots(s.h, s.a, n));
}
/** deploy J + S with the same (possibly malformed) args; assert BOTH revert. */
async function bothRevert(J: string, S: string, argsHex: string, value = 0n) {
  let jr = false,
    sr = false;
  try {
    await deployJ(J, argsHex, value);
  } catch {
    jr = true;
  }
  try {
    await deployS(S, argsHex, value);
  } catch {
    sr = true;
  }
  expect({ jeth: jr, solc: sr }).toEqual({ jeth: true, solc: true });
}

describe('Constructor aggregate/dynamic params + internal calls vs solc 0.8.35 (JETH302/JETH303)', () => {
  // ---- JETH302: aggregate / dynamic constructor params ----

  it('u256[] param: decode + store length and xs[0] (raw slots identical)', () =>
    sameSlots(
      `@contract class C { @state n: u256; @state first: u256; constructor(xs: u256[]) { this.n = xs.length; this.first = xs[0n]; } }`,
      `contract C { uint256 n; uint256 first; constructor(uint256[] memory xs){ n = xs.length; first = xs[0]; } }`,
      encUintArrayArg([0xaan, 0xbbn, 0xccn]),
      2,
    ));

  it('bytes param: store length + a byte (raw slots identical)', () =>
    sameSlots(
      `@contract class C { @state n: u256; @state b1: u256; constructor(b: bytes) { this.n = b.length; this.b1 = u256(u8(b[1n])); } }`,
      `contract C { uint256 n; uint256 b1; constructor(bytes memory b){ n = b.length; b1 = uint256(uint8(b[1])); } }`,
      encBytesArg(enc.encode('hello world')),
      2,
    ));

  it('string param: store length (raw slots identical)', () =>
    sameSlots(
      `@contract class C { @state n: u256; constructor(s: string) { this.n = bytes(s).length; } }`,
      `contract C { uint256 n; constructor(string memory s){ n = bytes(s).length; } }`,
      encBytesArg(enc.encode('a longer string value here')),
      1,
    ));

  it('value-struct param S{a;b}: store both fields (raw slots identical)', () =>
    sameSlots(
      `@struct class S { a: u256; b: address } @contract class C { @state x: u256; @state who: address; constructor(s: S) { this.x = s.a; this.who = s.b; } }`,
      `struct S { uint256 a; address b; } contract C { uint256 x; address who; constructor(S memory s){ x = s.a; who = s.b; } }`,
      word(0x99n) + word(BigInt('0x' + 'ab'.repeat(20))),
      2,
    ));

  it('fixed Arr<u256,3> param: store each element (raw slots identical)', () =>
    sameSlots(
      `@contract class C { @state a0: u256; @state a1: u256; @state a2: u256; constructor(a: Arr<u256,3>) { this.a0 = a[0n]; this.a1 = a[1n]; this.a2 = a[2n]; } }`,
      `contract C { uint256 a0; uint256 a1; uint256 a2; constructor(uint256[3] memory a){ a0 = a[0]; a1 = a[1]; a2 = a[2]; } }`,
      word(0x10n) + word(0x20n) + word(0x30n),
      3,
    ));

  it('dynamic-field struct param D{a;s:bytes}: store a + s.length + s[0] (raw slots identical)', () =>
    sameSlots(
      `@struct class D { a: u256; s: bytes } @contract class C { @state x: u256; @state n: u256; @state b0: u256; constructor(d: D) { this.x = d.a; this.n = d.s.length; this.b0 = u256(u8(d.s[0n])); } }`,
      `struct D { uint256 a; bytes s; } contract C { uint256 x; uint256 n; uint256 b0; constructor(D memory d){ x = d.a; n = d.s.length; b0 = uint256(uint8(d.s[0])); } }`,
      // a dynamic struct argument: head OFFSET word (0x20) to the tuple, then the tuple
      // {a inline, s offset word (0x40 from the tuple start)} + [len][payload].
      word(0x20n) + word(0x77n) + word(0x40n) + word(BigInt(enc.encode('abcd').length)) + payload(enc.encode('abcd')),
      3,
    ));

  // ---- JETH303: constructor calling an internal/private function ----

  it('ctor calling an internal helper (this.x = this.helper()) (raw slots identical)', () =>
    sameSlots(
      `@contract class C { @state x: u256; helper(): u256 { return 41n + 1n; } constructor() { this.x = this.helper(); } }`,
      `contract C { uint256 x; function helper() internal pure returns(uint256){ return 41 + 1; } constructor(){ x = helper(); } }`,
      '',
      1,
    ));

  it('ctor calling a TRANSITIVE internal chain (helper calls helper2) (raw slots identical)', () =>
    sameSlots(
      `@contract class C { @state x: u256; inner(): u256 { return 100n; } outer(): u256 { return this.inner() + 7n; } constructor() { this.x = this.outer(); } }`,
      `contract C { uint256 x; function inner() internal pure returns(uint256){ return 100; } function outer() internal pure returns(uint256){ return inner() + 7; } constructor(){ x = outer(); } }`,
      '',
      1,
    ));

  it('ctor internal call that READS msg.sender / writes state (raw slots identical)', () =>
    sameSlots(
      `@contract class C { @state owner: address; setup(): address { return msg.sender; } constructor() { this.owner = this.setup(); } }`,
      `contract C { address owner; function setup() internal view returns(address){ return msg.sender; } constructor(){ owner = setup(); } }`,
      '',
      1,
    ));

  // ---- combined: an aggregate param AND an internal call ----

  it('aggregate param + internal call combo (raw slots identical)', () =>
    sameSlots(
      `@contract class C { @state x: u256; dbl(v: u256): u256 { return v * 2n; } constructor(xs: u256[]) { this.x = this.dbl(xs[0n]) + xs.length; } }`,
      `contract C { uint256 x; function dbl(uint256 v) internal pure returns(uint256){ return v * 2; } constructor(uint256[] memory xs){ x = dbl(xs[0]) + xs.length; } }`,
      encUintArrayArg([0x21n, 0x22n]),
      1,
    ));

  it('internal helper TAKING an aggregate (memory array) param (raw slots identical)', () =>
    sameSlots(
      `@contract class C { @state x: u256; sumFirstTwo(arr: u256[]): u256 { return arr[0n] + arr[1n]; } constructor(xs: u256[]) { this.x = this.sumFirstTwo(xs); } }`,
      `contract C { uint256 x; function sumFirstTwo(uint256[] memory arr) internal pure returns(uint256){ return arr[0] + arr[1]; } constructor(uint256[] memory xs){ x = sumFirstTwo(xs); } }`,
      encUintArrayArg([0x5n, 0x6n, 0x7n]),
      1,
    ));

  // ---- SHORT-ARGS revert parity ----

  it('SHORT ARGS (truncated u256[] header): both revert', () =>
    bothRevert(
      `@contract class C { @state n: u256; constructor(xs: u256[]) { this.n = xs.length; } }`,
      `contract C { uint256 n; constructor(uint256[] memory xs){ n = xs.length; } }`,
      // a single short word: not even the offset head fits the 1-word minimum cleanly when truncated.
      hex(word(0x20n).slice(0, 40)),
    ));

  it('SHORT ARGS (offset points past the blob): both revert', () =>
    bothRevert(
      `@contract class C { @state n: u256; constructor(b: bytes) { this.n = b.length; } }`,
      `contract C { uint256 n; constructor(bytes memory b){ n = b.length; } }`,
      // offset word present but pointing far beyond the (tiny) blob -> out-of-bounds revert.
      word(0x1000n),
    ));

  it('SHORT ARGS (array length present, element words missing): both revert', () =>
    bothRevert(
      `@contract class C { @state n: u256; @state f: u256; constructor(xs: u256[]) { this.n = xs.length; this.f = xs[0n]; } }`,
      `contract C { uint256 n; uint256 f; constructor(uint256[] memory xs){ n = xs.length; f = xs[0]; } }`,
      // offset (0x20) + a claimed length of 3 but ZERO element words supplied.
      word(0x20n) + word(3n),
    ));
});
