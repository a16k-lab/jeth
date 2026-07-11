// Phase 4e-1 differential scenario "mixed-head-cursor": dynamic array of static
// struct (Pt[]) mixed with other params, exercising head-cursor correctness.
//   (1) f(Pt[] ps, uint256 i)            -> ps[i].x   (offset word, then i; tail after)
//   (2) g(uint256 x, Pt[] ps, uint256 i) -> ps[i].y   (static x inline, then offset, then i)
//       gx(uint256 x, Pt[] ps, uint256 i)-> x         (same layout; proves the static head
//                                                       word is read distinct from offset/tail)
//   (3) h(Pt[] a, Pt[] b, uint256 i)     -> a[i].x + b[i].y (two offsets, two tails sequential)
// All offsets are relative to the args region base = byte 4. For Pt{u128 x;u128 y}
// the element stride = 2 leaf words = 64 bytes (struct UNPACKED, one word per leaf).
// Whole-array echo of a struct array VALIDATES every field (reverts EMPTY on dirty);
// a single field read validates only the read field (lazy). OOB index -> Panic(0x32).
//
// NOTE on return types: JETH defers general numeric widening casts (u128->u256), so
// `x + ps[i].y` (u256 + u128) and returning a u128 sum as u256 are rejected by the
// type system (JETH083/JETH085). That is an intended language limitation, not a
// head-cursor gap. The head-cursor mechanics are purely about ABI offsets and are
// fully exercised here with type-correct expressions and identical calldata layouts:
//   - g returns the u128 array read (ps[i].y) -> proves the array tail offset is
//     computed AFTER the static head word.
//   - gx returns the static x word -> proves the static head word is read and is
//     NOT collided with the array offset/tail.
//   - h returns u128 + u128 (same-width) -> proves two offsets / two sequential tails.
//
// Solidity is the oracle: every probe (success, returndata, revert form) must be
// byte-identical between JETH and Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const W = 32n; // one word in bytes
const STRIDE = 64n; // Pt = 2 leaf words
const PANIC32 = '0x4e487b710000000000000000000000000000000000000000000000000000000000000032';

// --- JETH source (mirror of the Solidity below) ---------------------------
const JETH = `// scenario mixed-head-cursor
type Pt = { x: u128; y: u128; };

class MixedHead {
  // (1) array first, then index
  get f(ps: Pt[], i: u256): External<u128> { return ps[i].x; }
  // (2) static value first, then array, then index. g reads the array tail (proves
  // the tail offset is computed after the static word); gx reads the static word.
  get g(x: u256, ps: Pt[], i: u256): External<u128> { return ps[i].y; }
  get gx(x: u256, ps: Pt[], i: u256): External<u256> { return x; }
  // (3) two dynamic struct arrays then index; sum two same-width reads.
  get h(a: Pt[], b: Pt[], i: u256): External<u128> { return a[i].x + b[i].y; }
  // echoes to confirm head/tail round-trip with surrounding params
  get echoF(ps: Pt[], i: u256): External<Pt[]> { return ps; }
  get echoG(x: u256, ps: Pt[]): External<Pt[]> { return ps; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MixedHead {
  struct Pt { uint128 x; uint128 y; }
  function f(Pt[] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].x; }
  function g(uint256 x, Pt[] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].y; }
  function gx(uint256 x, Pt[] calldata ps, uint256 i) external pure returns (uint256){ return x; }
  function h(Pt[] calldata a, Pt[] calldata b, uint256 i) external pure returns (uint128){ return a[i].x + b[i].y; }
  function echoF(Pt[] calldata ps, uint256 i) external pure returns (Pt[] memory){ return ps; }
  function echoG(uint256 x, Pt[] calldata ps) external pure returns (Pt[] memory){ return ps; }
}`;

// signatures (struct expands to tuple) ------------------------------------
const SIG_F = 'f((uint128,uint128)[],uint256)';
const SIG_G = 'g(uint256,(uint128,uint128)[],uint256)';
const SIG_GX = 'gx(uint256,(uint128,uint128)[],uint256)';
const SIG_H = 'h((uint128,uint128)[],(uint128,uint128)[],uint256)';
const SIG_ECHOF = 'echoF((uint128,uint128)[],uint256)';
const SIG_ECHOG = 'echoG(uint256,(uint128,uint128)[])';

describe('mixed-head-cursor: Pt[] with surrounding params, byte-identical to Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);

  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  // tail blob for a Pt[] of `len` structs from flat leaf words
  const tail = (flat: bigint[], len: number) => pad(BigInt(len)) + flat.map(pad).join('');

  // (1) f(Pt[] ps, uint256 i): head = [offset=0x40][i]; tail at 0x40
  const buildF = (flat: bigint[], len: number, i: bigint) => '0x' + sel(SIG_F) + pad(0x40n) + pad(i) + tail(flat, len);
  const buildEchoF = (flat: bigint[], len: number, i: bigint) =>
    '0x' + sel(SIG_ECHOF) + pad(0x40n) + pad(i) + tail(flat, len);

  // (2) g/gx(uint256 x, Pt[] ps, uint256 i): head = [x][offset=0x60][i]; tail at 0x60
  const buildG = (selSig: string, x: bigint, flat: bigint[], len: number, i: bigint) =>
    '0x' + sel(selSig) + pad(x) + pad(0x60n) + pad(i) + tail(flat, len);
  const buildEchoG = (x: bigint, flat: bigint[], len: number) =>
    '0x' + sel(SIG_ECHOG) + pad(x) + pad(0x40n) + tail(flat, len);

  // (3) h(Pt[] a, Pt[] b, uint256 i): head = [offA][offB][i].
  // offA = 0x60 (3 head words). tail a = [len_a][flat_a]; tail b follows.
  // offB = offA + 32 + len_a*STRIDE.
  const buildH = (flatA: bigint[], lenA: number, flatB: bigint[], lenB: number, i: bigint) => {
    const offA = 0x60n;
    const offB = offA + W + BigInt(lenA) * STRIDE;
    return '0x' + sel(SIG_H) + pad(offA) + pad(offB) + pad(i) + tail(flatA, lenA) + tail(flatB, lenB);
  };

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'MixedHead.jeth' });
    const sb = compileSolidity(SOL, 'MixedHead');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('(1) f(Pt[], i): array first then index, reads ps[i].x', async () => {
    // ps = [{0xaaa,0xbbb},{0xccc,0xddd},{0xeee,0xfff}]
    const flat = [0xaaan, 0xbbbn, 0xcccn, 0xdddn, 0xeeen, 0xfffn];
    let r = await eq('f i=0', buildF(flat, 3, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(0xaaan);
    r = await eq('f i=1', buildF(flat, 3, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(0xcccn);
    r = await eq('f i=2', buildF(flat, 3, 2n));
    expect(decodeUint(r.j.returnHex)).toBe(0xeeen);
    // OOB i=3 (len 3) -> Panic(0x32)
    r = await eq('f OOB i=3', buildF(flat, 3, 3n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(PANIC32);
    // dirty x at the read index -> revert EMPTY
    const dirty = [(1n << 128n) | 0xaaan, 0xbbbn]; // x has high bit set
    r = await eq('f dirty-x i=0 -> empty', buildF(dirty, 1, 0n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // dirty y (UNREAD by f which reads x) -> OK (lazy)
    const dy = [0xaaan, (1n << 128n) | 0xbbbn];
    r = await eq('f dirty-unread-y i=0 -> ok', buildF(dy, 1, 0n));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0xaaan);
  });

  it('(1e) echoF: whole-array echo with trailing index param validates all fields', async () => {
    const flat = [1n, 2n, 3n, 4n];
    await eq('echoF clean n=2', buildEchoF(flat, 2, 0n));
    await eq('echoF clean n=0', buildEchoF([], 0, 0n));
    // ANY dirty field (here y of pt1) -> whole-array copy reverts EMPTY
    const dirty = [1n, 2n, 3n, (1n << 200n) | 4n];
    const r = await eq('echoF dirty-any -> empty', buildEchoF(dirty, 2, 0n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('(2) g(uint256 x, Pt[], i): static head word precedes offset; tail read lands correctly', async () => {
    const flat = [0x10n, 0x20n, 0x30n, 0x40n]; // pt0={0x10,0x20}, pt1={0x30,0x40}
    // g returns ps[i].y: proves the array tail offset is computed AFTER the static x word.
    let r = await eq('g i=0', buildG(SIG_G, 100n, flat, 2, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(0x20n);
    r = await eq('g i=1', buildG(SIG_G, 7n, flat, 2, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(0x40n);
    // gx returns the static x word: proves it is read and not collided with offset/tail.
    r = await eq('gx x=100', buildG(SIG_GX, 100n, flat, 2, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(100n);
    const big = (1n << 200n) | 5n;
    r = await eq('gx x=big', buildG(SIG_GX, big, flat, 2, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(big);
    // OOB i=2 (len 2) -> Panic(0x32)
    r = await eq('g OOB i=2', buildG(SIG_G, 1n, flat, 2, 2n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(PANIC32);
    // dirty y at read index -> revert EMPTY (g reads y)
    const dy = [0x10n, (1n << 128n) | 0x20n];
    r = await eq('g dirty-y i=0 -> empty', buildG(SIG_G, 1n, dy, 1, 0n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // dirty x (UNREAD by g which reads y) -> OK (lazy)
    const dx = [(1n << 128n) | 0x10n, 0x20n];
    r = await eq('g dirty-unread-x i=0 -> ok', buildG(SIG_G, 1n, dx, 1, 0n));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0x20n);
    // gx: a dirty ARRAY field is irrelevant (gx never reads the array element fields).
    // Solidity still does not validate it for gx; both must agree (OK).
    r = await eq('gx dirty-array-ignored', buildG(SIG_GX, 42n, [(1n << 200n) | 0x10n, 0x20n], 1, 0n));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(42n);
  });

  it('(2e) echoG: value param before array echoes array byte-identically', async () => {
    const flat = [9n, 8n, 7n, 6n, 5n, 4n];
    await eq('echoG x=42 n=3', buildEchoG(42n, flat, 3));
    await eq('echoG x=0 n=0', buildEchoG(0n, [], 0));
    // echoG validates every struct field on copy: dirty -> EMPTY revert
    const dirty = [9n, 8n, (1n << 200n) | 7n, 6n];
    const r = await eq('echoG dirty -> empty', buildEchoG(1n, dirty, 2));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('(3) h(Pt[] a, Pt[] b, i): two dynamic struct arrays, sequential tails, both bases = byte 4', async () => {
    // a = [{1,2},{3,4}] (len 2), b = [{10,20},{30,40},{50,60}] (len 3)
    const flatA = [1n, 2n, 3n, 4n];
    const flatB = [10n, 20n, 30n, 40n, 50n, 60n];
    // offB must equal offA + 32 + len_a*stride = 0x60 + 32 + 2*64 = 96+32+128 = 256 = 0x100
    const offA = 0x60n;
    const offB = offA + W + 2n * STRIDE;
    expect(offB).toBe(0x100n);

    let r = await eq('h i=0', buildH(flatA, 2, flatB, 3, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(1n + 20n); // a[0].x + b[0].y
    r = await eq('h i=1', buildH(flatA, 2, flatB, 3, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(3n + 40n); // a[1].x + b[1].y
    // i=2: a has len 2 (OOB on a) -> Panic(0x32). a is read first.
    r = await eq('h i=2 OOB-on-a', buildH(flatA, 2, flatB, 3, 2n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(PANIC32);
    // Make a longer than b so OOB falls on b: a len 3, b len 2, i=2 -> a ok, b OOB Panic
    const flatA3 = [1n, 2n, 3n, 4n, 5n, 6n];
    const flatB2 = [10n, 20n, 30n, 40n];
    r = await eq('h i=2 OOB-on-b', buildH(flatA3, 3, flatB2, 2, 2n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(PANIC32);
    // both ok with equal lengths
    r = await eq('h equal-len i=2', buildH(flatA3, 3, flatB, 3, 2n));
    expect(decodeUint(r.j.returnHex)).toBe(5n + 60n); // a[2].x + b[2].y
    // dirty x in a at read index -> revert EMPTY (a read first, reads x)
    const dA = [(1n << 128n) | 1n, 2n];
    r = await eq('h dirty-a.x -> empty', buildH(dA, 1, [10n, 20n], 1, 0n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // a clean, dirty y in b at read index -> revert EMPTY (b.y is read)
    const dB = [10n, (1n << 128n) | 20n];
    r = await eq('h dirty-b.y -> empty', buildH([1n, 2n], 1, dB, 1, 0n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // a.y dirty (UNREAD: h reads a.x) and b.x dirty (UNREAD: h reads b.y) -> OK (lazy)
    const dAy = [1n, (1n << 128n) | 2n];
    const dBx = [(1n << 128n) | 10n, 20n];
    r = await eq('h dirty-unread a.y,b.x -> ok', buildH(dAy, 1, dBx, 1, 0n));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(1n + 20n);
  });

  it('(3-offset) second array offset = first_offset + 32 + len_a*stride is what decode expects', async () => {
    // Build with a deliberately malformed offB that points b at a's length word. Whatever
    // Solidity does (it interprets a's [len][...] as b's), JETH must match byte-for-byte.
    const flatA = [1n, 2n, 3n, 4n];
    const flatB = [10n, 20n, 30n, 40n, 50n, 60n];
    const offA = 0x60n;
    const wrongOffB = offA; // b aliases a
    const bad =
      '0x' +
      sel(SIG_H) +
      pad(offA) +
      pad(wrongOffB) +
      pad(0n) +
      pad(2n) +
      flatA.map(pad).join('') +
      pad(3n) +
      flatB.map(pad).join('');
    await eq('h wrong-offB (oracle-defined)', bad);
  });

  it('short/malformed calldata reverts empty identically', async () => {
    // f: head needs 2 words (offset+i); supply only 1 -> EMPTY revert
    const shortF = '0x' + sel(SIG_F) + pad(0x40n);
    let r = await eq('f short head', shortF);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // f: declares len=3 but only 1 Pt of payload -> EMPTY (payload check independent of i)
    const truncF = '0x' + sel(SIG_F) + pad(0x40n) + pad(0n) + pad(3n) + pad(1n) + pad(2n);
    r = await eq('f truncated payload', truncF);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // g: offset past calldatasize -> EMPTY
    const badOffG = '0x' + sel(SIG_G) + pad(1n) + pad(0x1000n) + pad(0n);
    r = await eq('g bad offset', badOffG);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // h: second offset past calldatasize -> EMPTY
    const flatA = [1n, 2n];
    const badOffH = '0x' + sel(SIG_H) + pad(0x60n) + pad(0x9000n) + pad(0n) + pad(1n) + flatA.map(pad).join('');
    r = await eq('h bad offB', badOffH);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });
});
