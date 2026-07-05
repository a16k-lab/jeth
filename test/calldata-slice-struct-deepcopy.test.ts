// W5B shapes 3 + 4: calldata array SLICES - (3) abi.encode(a.slice(...)) / keccak256(abi.encode) /
// mixed-arg abi.encode re-encode the narrowed window DIRECTLY from calldata, VALIDATING each in-window
// element (empty revert on dirty bits, out-of-range enum) and IGNORING dirt outside the window, exactly
// like solc's abi.encode(a[s:e]); (4) STATIC-STRUCT element slices (P[] calldata): field read
// ps.slice(s)[i].f (one-deep + nested static chain), whole-element ps.slice(s)[i], bind-to-local DEEP
// COPY (pointer-headed P[] image, per-leaf validated), bound .length, whole-slice re-encode, internal
// arg, slice-of-slice - each byte-identical to solc 0.8.35 across an exhaustive start/end bounds sweep.
// DYNAMIC-element slices (bytes[]/u256[][]/dyn-struct[]) stay rejected: solc 0.8.35 itself rejects
// "index range access ... with dynamically encoded base types" - BOTH-REJECT parity, not a lift.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint | string) => (typeof n === 'string' ? BigInt(n) : BigInt(n)).toString(16).padStart(64, '0');

function jethAccepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
function solAccepts(src: string): boolean {
  try {
    compileSolidity(SPDX + src, 'C');
    return true;
  } catch {
    return false;
  }
}

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  const out: { success: boolean; returnHex: string }[] = [];
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig}(${args.slice(0, 40)}...) success`).toBe(rs.success);
    expect(rj.returnHex, `${sig}(${args.slice(0, 40)}...) return`).toBe(rs.returnHex);
    out.push(rj);
  }
  return out;
}

describe('W5B shape 3: abi.encode of a calldata value-array slice', () => {
  const J = `@contract class C {
    @external enc(a: u256[], s: u256, e: u256): bytes { return abi.encode(a.slice(s, e)); }
    @external kc(a: u8[]): bytes32 { return keccak256(abi.encode(a.slice(1n))); }
    @external mix(a: u256[], n: u256): bytes { return abi.encode(n, a.slice(1n), true); }
  }`;
  const S = `contract C {
    function enc(uint256[] calldata a, uint256 s, uint256 e) external pure returns (bytes memory) { return abi.encode(a[s:e]); }
    function kc(uint8[] calldata a) external pure returns (bytes32) { return keccak256(abi.encode(a[1:])); }
    function mix(uint256[] calldata a, uint256 n) external pure returns (bytes memory) { return abi.encode(n, a[1:], true); }
  }`;
  const arr = (ws: string[]) => W(ws.length) + ws.join('');
  const A3 = arr([W(5), W(6), W(7)]);

  it('honest slices + exhaustive bounds sweep (incl start>end, end>len, empty)', async () => {
    const calls: [string, string][] = [];
    for (const s of [0, 1, 2, 3, 4]) for (const e of [0, 1, 2, 3, 4, 5]) calls.push(['enc(uint256[],uint256,uint256)', W(96) + W(s) + W(e) + A3]);
    const rs = await eqCalls(J, S, calls);
    // non-vacuous: the full [1:3] slice encodes [6, 7]
    const full = rs[9]!; // s=1,e=3
    expect(full.success).toBe(true);
    expect(full.returnHex).toContain(W(6));
    expect(full.returnHex).toContain(W(7));
  });

  it('keccak256(abi.encode(slice)) and mixed abi.encode(n, slice, true)', async () => {
    await eqCalls(J, S, [
      ['kc(uint8[])', W(32) + arr([W(1), W(2), W(3)])],
      ['mix(uint256[],uint256)', W(64) + W(9) + A3],
    ]);
  });

  it('VALIDATES in-window dirt (empty revert), ignores out-of-window dirt - like solc', async () => {
    const DIRTY = 'ff'.repeat(31) + '05';
    await eqCalls(J, S, [
      ['kc(uint8[])', W(32) + arr([W(1), DIRTY])], // dirty INSIDE [1:] -> both revert empty
      ['kc(uint8[])', W(32) + arr([DIRTY, W(1)])], // dirty OUTSIDE the window -> both encode fine
    ]);
  });

  it('enum slice: out-of-range in-window reverts empty; out-of-window ignored', async () => {
    const JE = `enum Color { Red, Green, Blue }
    @contract class C { @external enc(a: Color[]): bytes { return abi.encode(a.slice(1n)); } }`;
    const SE = `contract C { enum Color { Red, Green, Blue } function enc(Color[] calldata a) external pure returns (bytes memory) { return abi.encode(a[1:]); } }`;
    await eqCalls(JE, SE, [
      ['enc(uint8[])', W(32) + arr([W(0), W(2)])],
      ['enc(uint8[])', W(32) + arr([W(0), W(3)])],
      ['enc(uint8[])', W(32) + arr([W(7), W(1)])],
    ]);
  });
});

describe('W5B shape 4: STATIC-STRUCT calldata array slices (P[] -> ps.slice(s, e))', () => {
  const HDR = `@struct class P { x: u256; y: u256 }
  @struct class Q { a: u8; b: bool; c: address }
  @struct class In2 { m: u256; n: u8 }
  @struct class R { pre: Arr<u256,2>; inn: In2; t: u256 }`;
  const SHDR = `struct P { uint256 x; uint256 y; }
    struct Q { uint8 a; bool b; address c; }
    struct In2 { uint256 m; uint8 n; }
    struct R { uint256[2] pre; In2 inn; uint256 t; }`;
  const J = `${HDR}
  @contract class C {
    @external f1(ps: P[], s: u256, e: u256, i: u256): u256 { return ps.slice(s, e)[i].y; }
    @external f2(qs: Q[], i: u256): bytes { let s: Q[] = qs.slice(1n); return abi.encode(s.length, s[i].a, s[i].b, s[i].c); }
    @external f3(rs: R[], i: u256): bytes { return abi.encode(rs.slice(1n)[i].inn.m, rs.slice(1n)[i].inn.n, rs.slice(1n)[i].t); }
    @external f4(ps: P[]): P { return ps.slice(1n)[0n]; }
    @external f5(ps: P[]): P[] { let s: P[] = ps.slice(1n); return s; }
    @external f6(ps: P[], s: u256): bytes { return abi.encode(ps.slice(s)); }
    g(xs: P[]): u256 { return xs.length * 1000n + (xs.length > 0n ? xs[0n].x : 0n); }
    @external f7(ps: P[], s: u256, e: u256): u256 { return this.g(ps.slice(s, e)); }
    @external f9(ps: P[]): u256 { let s: P[] = ps.slice(1n).slice(1n); return s.length * 100n + s[0n].x; }
    @external fm(ps: P[]): bytes { let s: P[] = ps.slice(1n); s[0n].x = 777n; return abi.encode(s[0n].x, ps[1n].x); }
  }`;
  const S = `contract C {
    ${SHDR}
    function f1(P[] calldata ps, uint256 s, uint256 e, uint256 i) external pure returns (uint256) { return ps[s:e][i].y; }
    function f2(Q[] calldata qs, uint256 i) external pure returns (bytes memory) { Q[] memory s = qs[1:]; return abi.encode(s.length, s[i].a, s[i].b, s[i].c); }
    function f3(R[] calldata rs, uint256 i) external pure returns (bytes memory) { return abi.encode(rs[1:][i].inn.m, rs[1:][i].inn.n, rs[1:][i].t); }
    function f4(P[] calldata ps) external pure returns (P memory) { return ps[1:][0]; }
    function f5(P[] calldata ps) external pure returns (P[] memory) { P[] memory s = ps[1:]; return s; }
    function f6(P[] calldata ps, uint256 s) external pure returns (bytes memory) { return abi.encode(ps[s:]); }
    function g(P[] memory xs) internal pure returns (uint256) { return xs.length * 1000 + (xs.length > 0 ? xs[0].x : 0); }
    function f7(P[] calldata ps, uint256 s, uint256 e) external pure returns (uint256) { return g(ps[s:e]); }
    function f9(P[] calldata ps) external pure returns (uint256) { P[] memory s = ps[1:][1:]; return s.length * 100 + s[0].x; }
    function fm(P[] calldata ps) external pure returns (bytes memory) { P[] memory s = ps[1:]; s[0].x = 777; return abi.encode(s[0].x, ps[1].x); }
  }`;
  const pArr = (pairs: [number, number][]) => W(pairs.length) + pairs.map(([x, y]) => W(x) + W(y)).join('');
  const P3 = pArr([[1, 2], [3, 4], [5, 6]]);
  const psig = '((uint256,uint256)[])';
  const CLEAN_ADDR = '00'.repeat(12) + '22'.repeat(20);
  const DIRTY_ADDR = 'ff'.repeat(12) + '22'.repeat(20);
  const qArr = (ts: [number, number, string][]) => W(ts.length) + ts.map(([a, b, c]) => W(a) + W(b) + c).join('');

  it('field read via the rebased window: exhaustive (s, e, i) bounds sweep, Panic 0x32 parity', async () => {
    const sig = 'f1((uint256,uint256)[],uint256,uint256,uint256)';
    const calls: [string, string][] = [];
    for (const s of [0, 1, 2, 3, 4]) for (const e of [0, 1, 2, 3, 4, 5]) calls.push([sig, W(128) + W(s) + W(e) + W(0) + P3]);
    calls.push([sig, W(128) + W(1) + W(3) + W(1) + P3], [sig, W(128) + W(0) + W(3) + W(2) + P3]);
    const rs = await eqCalls(J, S, calls);
    // non-vacuous: [1:3][0].y = 4 (element 1 of the base)
    const hit = rs.find((r) => r.success && r.returnHex === '0x' + W(4));
    expect(hit).toBeTruthy();
  });

  it('bind-to-local deep copy: narrow fields validated in-window only; bound .length; OOB elem Panic', async () => {
    const sig = 'f2((uint8,bool,address)[],uint256)';
    await eqCalls(J, S, [
      [sig, W(64) + W(0) + qArr([[9, 1, CLEAN_ADDR], [200, 0, CLEAN_ADDR]])],
      [sig, W(64) + W(5) + qArr([[9, 1, CLEAN_ADDR], [200, 0, CLEAN_ADDR]])], // i OOB after bind
      [sig, W(64) + W(0) + qArr([[9, 1, CLEAN_ADDR], [9, 1, DIRTY_ADDR]])], // dirty IN window
      [sig, W(64) + W(0) + qArr([[9, 1, DIRTY_ADDR], [9, 1, CLEAN_ADDR]])], // dirty OUTSIDE window
      [sig, W(64) + W(0) + qArr([[1, 1, CLEAN_ADDR], [1, 7, CLEAN_ADDR]])], // bad bool IN window
    ]);
  });

  it('nested static struct + fixed-array field element; whole element; bind+return; encode sweep', async () => {
    const rArr = (rs: number[][]) => W(rs.length) + rs.map((r) => r.map((n) => W(n)).join('')).join('');
    const R3 = rArr([[11, 12, 13, 14, 15], [21, 22, 23, 24, 25], [31, 32, 33, 34, 35]]);
    const f3sig = 'f3((uint256[2],(uint256,uint8),uint256)[],uint256)';
    await eqCalls(J, S, [
      [f3sig, W(64) + W(0) + R3],
      [f3sig, W(64) + W(1) + R3],
      [f3sig, W(64) + W(2) + R3], // i OOB inside the slice
    ]);
    await eqCalls(J, S, [
      ['f4' + psig, W(32) + P3],
      ['f4' + psig, W(32) + pArr([[1, 2]])], // empty slice -> [0] Panics
      ['f5' + psig, W(32) + P3],
      ['f5' + psig, W(32) + pArr([[1, 2]])], // empty slice returns []
    ]);
    const f6sig = 'f6((uint256,uint256)[],uint256)';
    await eqCalls(J, S, [0, 1, 2, 3, 4].map((s): [string, string] => [f6sig, W(64) + W(s) + P3]));
  });

  it('internal arg, slice-of-slice, deep-copy independence (mutating the copy leaves calldata intact)', async () => {
    const f7sig = 'f7((uint256,uint256)[],uint256,uint256)';
    await eqCalls(J, S, [
      [f7sig, W(96) + W(1) + W(3) + P3],
      [f7sig, W(96) + W(3) + W(3) + P3],
      [f7sig, W(96) + W(2) + W(1) + P3],
    ]);
    await eqCalls(J, S, [
      ['f9' + psig, W(32) + P3],
      ['f9' + psig, W(32) + pArr([[1, 2], [3, 4]])], // inner slice empty -> [0] Panics
    ]);
    const [rm] = await eqCalls(J, S, [['fm' + psig, W(32) + P3]]);
    expect(rm!.returnHex).toContain(W(777)); // the mutated copy
    expect(rm!.returnHex).toContain(W(3)); // the untouched calldata ps[1].x
  });

  it('PARITY rejects: unbound slice .length; dynamic-element slices (solc rejects them too)', () => {
    expect(jethAccepts(`@struct class P { x: u256; y: u256 } @contract class C { @external f(ps: P[]): u256 { return ps.slice(1n).length; } }`)).toBe(false);
    expect(solAccepts(`contract C { struct P { uint256 x; uint256 y; } function f(P[] calldata ps) external pure returns (uint256) { return ps[1:].length; } }`)).toBe(false);
    expect(jethAccepts(`@struct class D { s: string; n: u256 } @contract class C { @external f(ds: D[]): u256 { return ds.slice(1n)[0n].n; } }`)).toBe(false);
    expect(solAccepts(`contract C { struct D { string s; uint256 n; } function f(D[] calldata ds) external pure returns (uint256) { return ds[1:][0].n; } }`)).toBe(false);
    expect(jethAccepts(`@contract class C { @external f(bs: bytes[]): u256 { let s: bytes[] = bs.slice(1n); return s.length; } }`)).toBe(false);
    expect(solAccepts(`contract C { function f(bytes[] calldata bs) external pure returns (uint256) { bytes[] memory s = bs[1:]; return s.length; } }`)).toBe(false);
  });
});
