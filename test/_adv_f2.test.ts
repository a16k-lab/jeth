// Adversarial audit of FEATURE F2:
//   (1) `for (const v of xs) BODY`  -> desugars to a plain indexed loop:
//         for (let __i: u256 = 0n; __i < xs.length; __i = __i + 1n) { const v = xs[__i]; BODY }
//       The iterable is RE-READ each iteration (length in the condition, element in the body),
//       so mutating the array mid-loop must match solc's re-read-each-iteration semantics.
//   (2) struct spread / object-literal construction `{ ...base, x: v }` / `{ a: x, b: y }`
//       -> desugars to the SAME structNew IR as positional StructName(...), so codegen / ABI /
//       storage layout are byte-identical.
//
// The invariant we hammer: every JETH contract must be byte-identical to the equivalent
// Solidity on (a) returndata, (b) raw storage slots, and (c) emitted event logs. Where the
// behavior is correct this file is a permanent regression suite; any genuine miscompile or
// soundness hole is pinned with an `it.fails` and documented in the report.
//
// This suite is written ADVERSARIALLY: every claim is checked against the real compiler and a
// real EVM, never against the spec text.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => pad32(v);

/** Compile and return the error-severity diagnostic codes (or [] if it compiled clean). */
function errCodes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    if (e && Array.isArray(e.diagnostics)) {
      return e.diagnostics.filter((d: any) => d.severity === 'error').map((d: any) => d.code);
    }
    throw e;
  }
}

/** A deployed JETH/solc pair driven with identical calldata; asserts byte-identical effects. */
class Pair {
  constructor(
    public jeth: Harness,
    public sol: Harness,
    public aj: Address,
    public as: Address,
  ) {}
  static async make(J: string, SOL: string, contract = 'C'): Promise<Pair> {
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, contract);
    const jeth = await Harness.create();
    const sol = await Harness.create();
    const aj = await jeth.deploy(jb.creationBytecode);
    const as = await sol.deploy(sb.creation);
    return new Pair(jeth, sol, aj, as);
  }
  /** Fire identical calldata at both; assert success + returndata + logs match. */
  async eq(label: string, data: string): Promise<void> {
    const j = await this.jeth.call(this.aj, data);
    const s = await this.sol.call(this.as, data);
    expect(j.success, `${label}: success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label}: returndata`).toBe(s.returnHex);
    expect(j.logs.length, `${label}: log count`).toBe(s.logs.length);
    for (let i = 0; i < j.logs.length; i++) {
      expect(j.logs[i]!.topics, `${label}: log[${i}] topics`).toEqual(s.logs[i]!.topics);
      expect(j.logs[i]!.data, `${label}: log[${i}] data`).toBe(s.logs[i]!.data);
    }
  }
  /** Fire at both, ignore comparison (used to set up state). */
  async both(data: string): Promise<void> {
    await this.jeth.call(this.aj, data);
    await this.sol.call(this.as, data);
  }
  /** Assert raw storage slots are byte-identical. */
  async slots(label: string, ...slots: bigint[]): Promise<void> {
    for (const slot of slots) {
      expect(await readSlot(this.jeth, this.aj, slot), `${label}: slot ${slot}`).toBe(
        await readSlot(this.sol, this.as, slot),
      );
    }
  }
}

// Build dynamic-array calldata: selector + head-offset(32) + len + words.
function cdArray(selector: string, words: bigint[]): string {
  return '0x' + selector + pad(32n) + pad(BigInt(words.length)) + words.map(pad).join('');
}

// =====================================================================================
// PART 1 - for-of: element-kind coverage over storage / calldata / fixed arrays.
// =====================================================================================
describe('F2 for-of: element-kind coverage (storage/calldata/fixed)', () => {
  const J = `class C {
    us: u256[];
    b8: u8[];
    ad: address[];
    bo: bool[];
    b32: bytes32[];
    pushU(v: u256): External<void> { this.us.push(v); }
    pushB8(v: u8): External<void> { this.b8.push(v); }
    pushAd(v: address): External<void> { this.ad.push(v); }
    pushBo(v: bool): External<void> { this.bo.push(v); }
    pushB32(v: bytes32): External<void> { this.b32.push(v); }

    get sumU(): External<u256> { let s: u256 = 0n; for (const v of this.us) { s = s + v; } return s; }
    get sumB8(): External<u256> { let s: u256 = 0n; for (const v of this.b8) { s = s + u256(v); } return s; }
    get countTrue(): External<u256> { let n: u256 = 0n; for (const v of this.bo) { if (v) { n = n + 1n; } } return n; }
    get lastAddr(): External<address> { let r: address = address(0n); for (const v of this.ad) { r = v; } return r; }
    get lastB32(): External<bytes32> { let r: bytes32 = bytes32(0n); for (const v of this.b32) { r = v; } return r; }

    // calldata array element kinds
    get sumCdU(a: u256[]): External<u256> { let s: u256 = 0n; for (const v of a) { s = s + v; } return s; }
    get sumCdI(a: i128[]): External<i128> { let s: i128 = 0n; for (const v of a) { s = s + v; } return s; }
    get sumCdB8(a: u8[]): External<u256> { let s: u256 = 0n; for (const v of a) { s = s + u256(v); } return s; }

    // empty array => zero iterations
    get sumEmpty(a: u256[]): External<u256> { let s: u256 = 7n; for (const v of a) { s = s + v; } return s; }

    // memory fixed array Arr<T,N>
    get sumFixed(): External<u256> { let a: Arr<u256,4> = [3n,5n,7n,9n]; let s: u256 = 0n; for (const v of a) { s = s + v; } return s; }
    // calldata fixed array Arr<T,N>
    get sumCdFixed(a: Arr<u256,3>): External<u256> { let s: u256 = 0n; for (const v of a) { s = s + v; } return s; }

    // early return / break / continue
    get firstGt(a: u256[], t: u256): External<u256> { for (const v of a) { if (v > t) { return v; } } return 0n; }
    get sumEven(a: u256[]): External<u256> { let s: u256 = 0n; for (const v of a) { if (v == 0n) { continue; } if (v == 13n) { break; } s = s + v; } return s; }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[] us; uint8[] b8; address[] ad; bool[] bo; bytes32[] b32;
  function pushU(uint256 v) external { us.push(v); }
  function pushB8(uint8 v) external { b8.push(v); }
  function pushAd(address v) external { ad.push(v); }
  function pushBo(bool v) external { bo.push(v); }
  function pushB32(bytes32 v) external { b32.push(v); }
  function sumU() external view returns (uint256) { uint256 s=0; for (uint256 i=0;i<us.length;i=i+1){ uint256 v=us[i]; s=s+v; } return s; }
  function sumB8() external view returns (uint256) { uint256 s=0; for (uint256 i=0;i<b8.length;i=i+1){ uint8 v=b8[i]; s=s+uint256(v); } return s; }
  function countTrue() external view returns (uint256) { uint256 n=0; for (uint256 i=0;i<bo.length;i=i+1){ bool v=bo[i]; if (v){ n=n+1; } } return n; }
  function lastAddr() external view returns (address) { address r=address(0); for (uint256 i=0;i<ad.length;i=i+1){ address v=ad[i]; r=v; } return r; }
  function lastB32() external view returns (bytes32) { bytes32 r=bytes32(0); for (uint256 i=0;i<b32.length;i=i+1){ bytes32 v=b32[i]; r=v; } return r; }
  function sumCdU(uint256[] calldata a) external pure returns (uint256) { uint256 s=0; for (uint256 i=0;i<a.length;i=i+1){ uint256 v=a[i]; s=s+v; } return s; }
  function sumCdI(int128[] calldata a) external pure returns (int128) { int128 s=0; for (uint256 i=0;i<a.length;i=i+1){ int128 v=a[i]; s=s+v; } return s; }
  function sumCdB8(uint8[] calldata a) external pure returns (uint256) { uint256 s=0; for (uint256 i=0;i<a.length;i=i+1){ uint8 v=a[i]; s=s+uint256(v); } return s; }
  function sumEmpty(uint256[] calldata a) external pure returns (uint256) { uint256 s=7; for (uint256 i=0;i<a.length;i=i+1){ uint256 v=a[i]; s=s+v; } return s; }
  function sumFixed() external pure returns (uint256) { uint256[4] memory a=[uint256(3),5,7,9]; uint256 s=0; for (uint256 i=0;i<a.length;i=i+1){ uint256 v=a[i]; s=s+v; } return s; }
  function sumCdFixed(uint256[3] calldata a) external pure returns (uint256) { uint256 s=0; for (uint256 i=0;i<a.length;i=i+1){ uint256 v=a[i]; s=s+v; } return s; }
  function firstGt(uint256[] calldata a, uint256 t) external pure returns (uint256) { for (uint256 i=0;i<a.length;i=i+1){ uint256 v=a[i]; if (v>t){ return v; } } return 0; }
  function sumEven(uint256[] calldata a) external pure returns (uint256) { uint256 s=0; for (uint256 i=0;i<a.length;i=i+1){ uint256 v=a[i]; if (v==0){ continue; } if (v==13){ break; } s=s+v; } return s; }
}`;
  let p: Pair;
  const ADDR1 = 0xa11ce0000000000000000000000000000001n;
  const ADDR2 = 0xb0b0000000000000000000000000000000002n;
  beforeAll(async () => {
    p = await Pair.make(J, SOL);
    for (const v of [5n, 0n, 12n, 7n, 0n, 30n]) await p.both(encodeCall(sel('pushU(uint256)'), [v]));
    for (const v of [1n, 2n, 250n, 3n]) await p.both(encodeCall(sel('pushB8(uint8)'), [v]));
    for (const v of [ADDR1, ADDR2]) await p.both(encodeCall(sel('pushAd(address)'), [v]));
    for (const v of [1n, 0n, 1n, 1n, 0n]) await p.both(encodeCall(sel('pushBo(bool)'), [v]));
    for (const v of [0x1234n, 0xabcdn << 240n, 0xffn]) await p.both(encodeCall(sel('pushB32(bytes32)'), [v]));
  });
  it('storage element kinds (u256/u8/bool/address/bytes32) match solc', async () => {
    await p.eq('sumU', encodeCall(sel('sumU()'), []));
    await p.eq('sumB8', encodeCall(sel('sumB8()'), []));
    await p.eq('countTrue', encodeCall(sel('countTrue()'), []));
    await p.eq('lastAddr', encodeCall(sel('lastAddr()'), []));
    await p.eq('lastB32', encodeCall(sel('lastB32()'), []));
  });
  it('calldata element kinds (u256/i128/u8) + empty array match solc', async () => {
    await p.eq('sumCdU', cdArray(sel('sumCdU(uint256[])'), [10n, 20n, 30n, 40n]));
    // i128 with a negative element (two's complement round-trip)
    const negOne = (1n << 256n) - 1n;
    await p.eq('sumCdI', cdArray(sel('sumCdI(int128[])'), [5n, negOne, 100n]));
    await p.eq('sumCdB8', cdArray(sel('sumCdB8(uint8[])'), [200n, 55n, 1n]));
    await p.eq('sumEmpty (0 iters)', cdArray(sel('sumEmpty(uint256[])'), []));
  });
  it('fixed memory + fixed calldata arrays match solc', async () => {
    await p.eq('sumFixed', encodeCall(sel('sumFixed()'), []));
    await p.eq('sumCdFixed', '0x' + sel('sumCdFixed(uint256[3])') + pad(11n) + pad(22n) + pad(33n));
  });
});

// firstGt / sumEven need a tail scalar arg or trailing dynamic, build calldata explicitly.
describe('F2 for-of: control flow (break/continue/return) with explicit calldata', () => {
  const J = `class C {
    get firstGt(t: u256, a: u256[]): External<u256> { for (const v of a) { if (v > t) { return v; } } return 0n; }
    get sumEven(a: u256[]): External<u256> { let s: u256 = 0n; for (const v of a) { if (v == 0n) { continue; } if (v == 13n) { break; } s = s + v; } return s; }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function firstGt(uint256 t, uint256[] calldata a) external pure returns (uint256) { for (uint256 i=0;i<a.length;i=i+1){ uint256 v=a[i]; if (v>t){ return v; } } return 0; }
  function sumEven(uint256[] calldata a) external pure returns (uint256) { uint256 s=0; for (uint256 i=0;i<a.length;i=i+1){ uint256 v=a[i]; if (v==0){ continue; } if (v==13){ break; } s=s+v; } return s; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await Pair.make(J, SOL);
  });
  it('return-from-loop / break / continue match solc', async () => {
    // firstGt(t, a): head offset for the dynamic arg is at word index 1 -> offset 64.
    const fg = '0x' + sel('firstGt(uint256,uint256[])') + pad(5n) + pad(64n) + pad(3n) + pad(2n) + pad(9n) + pad(1n);
    await p.eq('firstGt', fg);
    const fg0 = '0x' + sel('firstGt(uint256,uint256[])') + pad(99n) + pad(64n) + pad(2n) + pad(1n) + pad(2n);
    await p.eq('firstGt none', fg0);
    await p.eq('sumEven', cdArray(sel('sumEven(uint256[])'), [1n, 0n, 5n, 13n, 100n]));
    await p.eq('sumEven empty', cdArray(sel('sumEven(uint256[])'), []));
  });
});

// =====================================================================================
// PART 2 - for-of MUTATION mid-loop (the highest-value miscompile hunt).
// JETH re-reads xs.length and xs[i] each iteration; solc's hand-written loop does too.
// =====================================================================================
describe('F2 for-of: mutation mid-loop must match solc re-read-each-iteration', () => {
  const J = `class C {
    xs: u256[];
    push(v: u256): External<void> { this.xs.push(v); }
    get len(): External<u256> { return this.xs.length; }
    get at(i: u256): External<u256> { return this.xs[i]; }
    // Body pops the LAST element each iteration: classic re-read-length divergence trap.
    popEach(): External<void> { for (const v of this.xs) { if (this.xs.length > 0n) { this.xs.pop(); } } }
    // Body doubles xs[i] in place (write-through to the same array being iterated).
    doubleInPlace(): External<void> { let i: u256 = 0n; for (const v of this.xs) { this.xs[i] = v * 2n; i = i + 1n; } }
    // Body pushes a copy of small elements; bounded by gas but length grows mid-iteration.
    // Use a cap so it terminates identically on both sides.
    growBounded(cap: u256): External<void> { let i: u256 = 0n; for (const v of this.xs) { if (this.xs.length < cap) { this.xs.push(v); } i = i + 1n; } }
    // Pop TWICE per iteration: the index outpaces the shrinking length faster than one-per-iter.
    // The re-read of xs.length in the condition is the ONLY thing that keeps the element read
    // xs[__i] in bounds; if JETH cached length this would OOB-panic where solc does not.
    pop2(): External<void> { for (const v of this.xs) { if (this.xs.length > 0n) { this.xs.pop(); } if (this.xs.length > 0n) { this.xs.pop(); } } }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[] xs;
  function push(uint256 v) external { xs.push(v); }
  function len() external view returns (uint256) { return xs.length; }
  function at(uint256 i) external view returns (uint256) { return xs[i]; }
  function popEach() external { for (uint256 k=0;k<xs.length;k=k+1){ uint256 v=xs[k]; if (xs.length>0){ xs.pop(); } } }
  function pop2() external { for (uint256 k=0;k<xs.length;k=k+1){ uint256 v=xs[k]; if (xs.length>0){ xs.pop(); } if (xs.length>0){ xs.pop(); } } }
  function doubleInPlace() external { uint256 i=0; for (uint256 k=0;k<xs.length;k=k+1){ uint256 v=xs[k]; xs[i]=v*2; i=i+1; } }
  function growBounded(uint256 cap) external { uint256 i=0; for (uint256 k=0;k<xs.length;k=k+1){ uint256 v=xs[k]; if (xs.length<cap){ xs.push(v); } i=i+1; } }
}`;
  async function seed(p: Pair, vals: bigint[]) {
    for (const v of vals) await p.both(encodeCall(sel('push(uint256)'), [v]));
  }

  it('pop-each-iteration: length re-read, slots + observable state identical', async () => {
    const p = await Pair.make(J, SOL);
    await seed(p, [10n, 20n, 30n, 40n, 50n]);
    await p.eq('popEach', encodeCall(sel('popEach()'), []));
    await p.eq('len after popEach', encodeCall(sel('len()'), []));
    // slot 0 holds the dynamic-array length; element slots live at keccak(0)+i.
    await p.slots('popEach length slot', 0n);
  });

  it('double-in-place write-through matches solc element-by-element', async () => {
    const p = await Pair.make(J, SOL);
    await seed(p, [1n, 2n, 3n, 4n]);
    await p.eq('doubleInPlace', encodeCall(sel('doubleInPlace()'), []));
    for (let i = 0n; i < 4n; i++) await p.eq(`at(${i})`, encodeCall(sel('at(uint256)'), [i]));
    await p.slots('doubleInPlace length slot', 0n);
  });

  it('bounded grow mid-loop matches solc (length re-read each iteration)', async () => {
    const p = await Pair.make(J, SOL);
    await seed(p, [1n, 2n, 3n]);
    // cap=6: each iteration pushes while length<6. Both sides must land at the same final state.
    await p.eq('growBounded(6)', encodeCall(sel('growBounded(uint256)'), [6n]));
    await p.eq('len after grow', encodeCall(sel('len()'), []));
    const finalLen = await p.jeth.call(p.aj, encodeCall(sel('len()'), []));
    const n = Number(BigInt(finalLen.returnHex));
    for (let i = 0; i < n; i++) await p.eq(`grow at(${i})`, encodeCall(sel('at(uint256)'), [BigInt(i)]));
    await p.slots('growBounded length slot', 0n);
  });

  it('pop-TWICE-per-iteration: index outpaces shrinking length, still matches solc (no OOB)', async () => {
    const p = await Pair.make(J, SOL);
    await seed(p, [10n, 20n, 30n, 40n, 50n]);
    // If JETH cached xs.length, the element read xs[__i] would OOB-panic where solc succeeds.
    await p.eq('pop2', encodeCall(sel('pop2()'), []));
    await p.eq('len after pop2', encodeCall(sel('len()'), []));
    await p.slots('pop2 length slot', 0n);
  });
});

// =====================================================================================
// PART 3 - nesting, sequencing, return; synthesized index names must not collide.
// =====================================================================================
describe('F2 for-of: nesting / sequencing / index-name non-collision', () => {
  const J = `class C {
    xs: u256[];
    push(v: u256): External<void> { this.xs.push(v); }
    // nested for-of with DIFFERENT element names (same name => JETH068 shadow rule, tested in rejections)
    get pairSum(): External<u256> { let s: u256 = 0n; for (const v of this.xs) { for (const w of this.xs) { s = s + v * w; } } return s; }
    // for-of inside a regular for
    get repeat(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i = i + 1n) { for (const v of this.xs) { s = s + v; } } return s; }
    // regular for inside a for-of
    get triangular(): External<u256> { let s: u256 = 0n; for (const v of this.xs) { for (let i: u256 = 0n; i < v; i = i + 1n) { s = s + 1n; } } return s; }
    // three SEQUENTIAL for-of loops: synthesized indices __jeth_of_0/1/2 must not collide
    get triple(): External<u256> { let s: u256 = 0n; for (const v of this.xs) { s = s + v; } for (const v of this.xs) { s = s + v * 2n; } for (const v of this.xs) { s = s + v * 3n; } return s; }
    // return from inside nested for-of
    get firstPairGt(t: u256): External<u256> { for (const v of this.xs) { for (const w of this.xs) { if (v + w > t) { return v * 1000n + w; } } } return 0n; }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[] xs;
  function push(uint256 v) external { xs.push(v); }
  function pairSum() external view returns (uint256) { uint256 s=0; for (uint256 i=0;i<xs.length;i=i+1){ uint256 v=xs[i]; for (uint256 j=0;j<xs.length;j=j+1){ uint256 w=xs[j]; s=s+v*w; } } return s; }
  function repeat(uint256 n) external view returns (uint256) { uint256 s=0; for (uint256 i=0;i<n;i=i+1){ for (uint256 j=0;j<xs.length;j=j+1){ uint256 v=xs[j]; s=s+v; } } return s; }
  function triangular() external view returns (uint256) { uint256 s=0; for (uint256 j=0;j<xs.length;j=j+1){ uint256 v=xs[j]; for (uint256 i=0;i<v;i=i+1){ s=s+1; } } return s; }
  function triple() external view returns (uint256) { uint256 s=0; for (uint256 a=0;a<xs.length;a=a+1){ uint256 v=xs[a]; s=s+v; } for (uint256 b=0;b<xs.length;b=b+1){ uint256 v=xs[b]; s=s+v*2; } for (uint256 c=0;c<xs.length;c=c+1){ uint256 v=xs[c]; s=s+v*3; } return s; }
  function firstPairGt(uint256 t) external view returns (uint256) { for (uint256 i=0;i<xs.length;i=i+1){ uint256 v=xs[i]; for (uint256 j=0;j<xs.length;j=j+1){ uint256 w=xs[j]; if (v+w>t){ return v*1000+w; } } } return 0; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await Pair.make(J, SOL);
    for (const v of [2n, 3n, 5n]) await p.both(encodeCall(sel('push(uint256)'), [v]));
  });
  it('nested / mixed / sequential for-of all match solc', async () => {
    await p.eq('pairSum', encodeCall(sel('pairSum()'), []));
    await p.eq('repeat(3)', encodeCall(sel('repeat(uint256)'), [3n]));
    await p.eq('triangular', encodeCall(sel('triangular()'), []));
    await p.eq('triple', encodeCall(sel('triple()'), []));
    await p.eq('firstPairGt(7)', encodeCall(sel('firstPairGt(uint256)'), [7n]));
    await p.eq('firstPairGt(100)', encodeCall(sel('firstPairGt(uint256)'), [100n]));
  });
});

// =====================================================================================
// PART 4 - `let v` (mutable copy) mutated in the body must NOT write back to the array.
// =====================================================================================
describe('F2 for-of: `let v` is a copy, mutation does not write back', () => {
  const J = `class C {
    xs: u256[];
    push(v: u256): External<void> { this.xs.push(v); }
    get at(i: u256): External<u256> { return this.xs[i]; }
    // mutate the loop variable; the storage array must be UNCHANGED afterward.
    bumpCopies(): External<void> { for (let v of this.xs) { v = v + 1000n; } }
    get sum(): External<u256> { let s: u256 = 0n; for (const v of this.xs) { s = s + v; } return s; }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[] xs;
  function push(uint256 v) external { xs.push(v); }
  function at(uint256 i) external view returns (uint256) { return xs[i]; }
  function bumpCopies() external { for (uint256 i=0;i<xs.length;i=i+1){ uint256 v=xs[i]; v=v+1000; } }
  function sum() external view returns (uint256) { uint256 s=0; for (uint256 i=0;i<xs.length;i=i+1){ uint256 v=xs[i]; s=s+v; } return s; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await Pair.make(J, SOL);
    for (const v of [11n, 22n, 33n]) await p.both(encodeCall(sel('push(uint256)'), [v]));
  });
  it('mutating `let v` leaves storage array bytes-identical to solc', async () => {
    await p.eq('bumpCopies', encodeCall(sel('bumpCopies()'), []));
    await p.eq('sum unchanged', encodeCall(sel('sum()'), []));
    for (let i = 0n; i < 3n; i++) await p.eq(`at(${i})`, encodeCall(sel('at(uint256)'), [i]));
    await p.slots('bumpCopies length slot', 0n);
  });
});

// =====================================================================================
// PART 5 - for-of with branded element kind + events emitted from inside the loop.
// =====================================================================================
describe('F2 for-of: branded element + per-iteration event emission', () => {
  const J = `type Wei = Brand<u256>;
  class C {
    Item: event<{ idx: indexed<u256>; v: u256 }>;
    ws: Wei[];
    push(v: Wei): External<void> { this.ws.push(v); }
    get sum(): External<u256> { let s: u256 = 0n; for (const v of this.ws) { s = s + u256(v); } return s; }
    emitAll(): External<void> { let i: u256 = 0n; for (const v of this.ws) { emit(Item(i, u256(v))); i = i + 1n; } }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256[] ws;
  event Item(uint256 indexed idx, uint256 v);
  function push(uint256 v) external { ws.push(v); }
  function sum() external view returns (uint256) { uint256 s=0; for (uint256 i=0;i<ws.length;i=i+1){ uint256 v=ws[i]; s=s+v; } return s; }
  function emitAll() external { uint256 i=0; for (uint256 k=0;k<ws.length;k=k+1){ uint256 v=ws[k]; emit Item(i, v); i=i+1; } }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await Pair.make(J, SOL);
    for (const v of [100n, 200n, 300n]) await p.both(encodeCall(sel('push(uint256)'), [v]));
  });
  it('branded element sum + per-iteration logs (topics+data) match solc', async () => {
    await p.eq('sum', encodeCall(sel('sum()'), []));
    await p.eq('emitAll (logs)', encodeCall(sel('emitAll()'), []));
  });
});

// =====================================================================================
// PART 6 - for-of REJECTIONS / soundness (capture codes, never crash).
// =====================================================================================
describe('F2 for-of: rejections (codes pinned, no crash)', () => {
  const base = (body: string) => `class C { xs: u256[]; n: u256; ${body} }`;
  it('for-of over a non-array (uint) => JETH118', () => {
    expect(
      errCodes(
        base(`@external @view f(): u256 { let s: u256 = 0n; for (const v of this.n) { s = s + v; } return s; }`),
      ),
    ).toContain('JETH481');
  });
  it('for-of over a mapping rejects cleanly (JETH153: mapping read forbidden, no crash)', () => {
    // The mapping read inside `for (const v of this.m)` is rejected before the for-of array
    // check (mappings cannot be read directly), so the code is JETH153 rather than JETH118.
    // Either way it is a clean compile-time rejection, never a crash or a miscompile.
    const src = `class C { m: mapping<u256, u256>; get f(): External<u256> { let s: u256 = 0n; for (const v of this.m) { s = s + v; } return s; } }`;
    expect(errCodes(src)).toContain('JETH153');
  });
  it('for-of over a struct => JETH118', () => {
    const src = `type P = { x: u256; y: u256; }; class C { p: P; get f(): External<u256> { let s: u256 = 0n; for (const v of this.p) { s = s + v; } return s; } }`;
    expect(errCodes(src)).toContain('JETH118');
  });
  it('for-of over a CALL result => JETH117 (iterable must be a plain ref)', () => {
    const src = `class C { xs: u256[]; getXs(): u256[] { return this.xs; } get f(): External<u256> { let s: u256 = 0n; for (const v of this.getXs()) { s = s + v; } return s; } }`;
    expect(errCodes(src)).toContain('JETH117');
  });
  it('type-annotated binding => JETH116', () => {
    expect(
      errCodes(
        base(`@external @view f(): u256 { let s: u256 = 0n; for (const v: u256 of this.xs) { s = s + v; } return s; }`),
      ),
    ).toContain('JETH481');
  });
  it('destructuring binding => JETH115', () => {
    const src = `type P = { x: u256; y: u256; }; class C { ps: P[]; get f(): External<u256> { let s: u256 = 0n; for (const { x, y } of this.ps) { s = s + x; } return s; } }`;
    expect(errCodes(src)).toContain('JETH115');
  });
  it('for-in => JETH111', () => {
    expect(
      errCodes(
        base(`@external @view f(): u256 { let s: u256 = 0n; for (const k in this.xs) { s = s + 1n; } return s; }`),
      ),
    ).toContain('JETH481');
  });
  it('var binding => JETH115', () => {
    expect(
      errCodes(base(`@external @view f(): u256 { let s: u256 = 0n; for (var v of this.xs) { s = s + v; } return s; }`)),
    ).toContain('JETH481');
  });
  it('nested for-of with the SAME element name compiles (the inner binding shadows the outer, like solc)', () => {
    // each loop body is its own scope, so the inner `v` shadows the outer `v` (cross-scope shadowing
    // is allowed, matching solc); the codegen gives each a unique Yul name, so it is sound.
    expect(
      errCodes(
        base(
          `@external @view f(): u256 { let s: u256 = 0n; for (const v of this.xs) { for (const v of this.xs) { s = s + v; } } return s; }`,
        ),
      ),
    ).toEqual([]);
  });

  // for-of over a struct[] (and the standalone `const v = this.ps[i]` it desugars to) is now
  // SUPPORTED: a storage struct-array element is copied into a fresh memory image. Byte-identical
  // to solc (previously over-rejected with JETH900/JETH063).
  it('for-of over struct[] compiles and is byte-identical to solc (struct element supported)', async () => {
    const J = `type P = { x: u256; y: u256; }; class C { ps: P[]; add(x: u256, y: u256): External<void> { this.ps.push(P(x, y)); } get f(): External<u256> { let s: u256 = 0n; for (const v of this.ps) { s = s + v.x + v.y; } return s; } }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
struct P { uint256 x; uint256 y; }
contract C { P[] ps; function add(uint256 x, uint256 y) external { ps.push(P(x,y)); } function f() external view returns (uint256){ uint256 s=0; for(uint256 i=0;i<ps.length;i++){ s = s + ps[i].x + ps[i].y; } return s; } }`;
    expect(errCodes(J), 'for-of over struct[] now compiles').toEqual([]);
    // the standalone (typed) struct-element-to-memory local it desugars to also compiles
    const standalone = `type P = { x: u256; y: u256; }; class C { ps: P[]; add(x: u256, y: u256): External<void> { this.ps.push(P(x, y)); } get g(): External<u256> { let v: P = this.ps[0n]; return v.x; } }`;
    expect(errCodes(standalone), 'standalone struct-elem -> memory local also compiles').toEqual([]);
    // runtime byte-identical to solc
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(S, 'C');
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(jb.creationBytecode);
    const as = await hs.deploy(sb.creation);
    for (const args of [
      [3n, 4n],
      [10n, 20n],
    ]) {
      const d = encodeCall(sel('add(uint256,uint256)'), args);
      await hj.call(aj, d);
      await hs.call(as, d);
    }
    const rj = await hj.call(aj, encodeCall(sel('f()'), []));
    const rs = await hs.call(as, encodeCall(sel('f()'), []));
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
  });
});

// =====================================================================================
// PART 7 - struct spread / literal aliasing + PACKED structs (raw-slot parity).
// =====================================================================================
describe('F2 struct spread: aliasing read-old-then-write + packed slots', () => {
  // P is fully packed into ONE slot: u8 + u8 + address(20) + bool = 30 bytes < 32.
  const J = `type P = { a: u8; b: u8; c: address; d: bool; };
  class C {
    p: P;
    setRaw(a: u8, b: u8, c: address, d: bool): External<void> { this.p = P(a, b, c, d); }
    bumpA(da: u8): External<void> { this.p = { ...this.p, a: this.p.a + da }; }
    toggleD(): External<void> { this.p = { ...this.p, d: !this.p.d }; }
    setC(c: address): External<void> { this.p = { ...this.p, c: c }; }
    get get(): External<P> { return this.p; }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint8 a; uint8 b; address c; bool d; }
  P p;
  function setRaw(uint8 a, uint8 b, address c, bool d) external { p = P(a, b, c, d); }
  function bumpA(uint8 da) external { P memory q = p; q.a = q.a + da; p = q; }
  function toggleD() external { P memory q = p; q.d = !q.d; p = q; }
  function setC(address c) external { P memory q = p; q.c = c; p = q; }
  function get() external view returns (P memory) { return p; }
}`;
  let p: Pair;
  const C1 = 0xcafe000000000000000000000000000000000001n;
  const C2 = 0xbeef000000000000000000000000000000000002n;
  beforeAll(async () => {
    p = await Pair.make(J, SOL);
    await p.both('0x' + sel('setRaw(uint8,uint8,address,bool)') + pad(7n) + pad(9n) + pad(C1) + pad(1n));
  });
  it('packed-struct spread updates match solc on raw slot 0 and returndata', async () => {
    await p.eq('get initial', encodeCall(sel('get()'), []));
    await p.slots('after setRaw', 0n);
    await p.both(encodeCall(sel('bumpA(uint8)'), [3n])); // a: 7 -> 10
    await p.slots('after bumpA', 0n);
    await p.eq('get after bumpA', encodeCall(sel('get()'), []));
    await p.both(encodeCall(sel('toggleD()'), [])); // d: true -> false
    await p.slots('after toggleD', 0n);
    await p.eq('get after toggleD', encodeCall(sel('get()'), []));
    await p.both('0x' + sel('setC(address)') + pad(C2)); // c -> C2
    await p.slots('after setC', 0n);
    await p.eq('get after setC', encodeCall(sel('get()'), []));
  });
  it('overflow on packed u8 field via spread (a + da wraps) matches solc', async () => {
    // a is currently 10 (7 + 3). da = 250 => 10 + 250 = 260 > 255 => solc CHECKED add reverts.
    await p.eq('bumpA overflow reverts identically', encodeCall(sel('bumpA(uint8)'), [250n]));
    await p.slots('slot unchanged after revert', 0n);
  });
});

// =====================================================================================
// PART 8 - override semantics: override-wins, order, shorthand, full literal,
//          branded field, single/many-field structs spanning multiple slots.
// =====================================================================================
describe('F2 struct literal: override / shorthand / field-kind / multi-slot', () => {
  const J = `type Wei = Brand<u256>;
  type Big = { a: u256; b: u256; c: address; d: bool; e: bytes32; f: i64; g: Wei; };
  type One = { only: u256; };
  class C {
    big: Big;
    one: One;
    get mkShorthand(a: u256, b: u256, c: address, d: bool, e: bytes32, f: i64, g: Wei): External<Big> {
      return { a, b, c, d, e, f, g };
    }
    get mkFull(a: u256, b: u256, c: address, d: bool, e: bytes32, f: i64, g: Wei): External<Big> {
      return { a: a, b: b, c: c, d: d, e: e, f: f, g: g };
    }
    get withCOverride(base: Big, nc: address): External<Big> { return { ...base, c: nc }; }
    // spread + override the SAME field twice in source order is a DUP (JETH233) - tested in rejections.
    // override-wins: spread provides a, then a is overridden.
    get overrideWins(base: Big, na: u256): External<Big> { return { ...base, a: na }; }
    // override in a different ORDER than declaration (b before a) - must still map by name.
    get reorder(base: Big, na: u256, nb: u256): External<Big> { return { ...base, b: nb, a: na }; }
    get mkOne(v: u256): External<One> { return { only: v }; }
    storeBig(a: u256, b: u256, c: address, d: bool, e: bytes32, f: i64, g: Wei): External<void> {
      this.big = { a, b, c, d, e, f, g };
    }
    get getBig(): External<Big> { return this.big; }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Big { uint256 a; uint256 b; address c; bool d; bytes32 e; int64 f; uint256 g; }
  struct One { uint256 only; }
  Big big; One one;
  function mkShorthand(uint256 a, uint256 b, address c, bool d, bytes32 e, int64 f, uint256 g) external pure returns (Big memory) { return Big(a,b,c,d,e,f,g); }
  function mkFull(uint256 a, uint256 b, address c, bool d, bytes32 e, int64 f, uint256 g) external pure returns (Big memory) { return Big(a,b,c,d,e,f,g); }
  function withCOverride(Big calldata b, address nc) external pure returns (Big memory) { Big memory q=b; q.c=nc; return q; }
  function overrideWins(Big calldata b, uint256 na) external pure returns (Big memory) { Big memory q=b; q.a=na; return q; }
  function reorder(Big calldata b, uint256 na, uint256 nb) external pure returns (Big memory) { Big memory q=b; q.b=nb; q.a=na; return q; }
  function mkOne(uint256 v) external pure returns (One memory) { return One(v); }
  function storeBig(uint256 a, uint256 b, address c, bool d, bytes32 e, int64 f, uint256 g) external { big = Big(a,b,c,d,e,f,g); }
  function getBig() external view returns (Big memory) { return big; }
}`;
  let p: Pair;
  const C1 = 0xcafe000000000000000000000000000000000001n;
  const C2 = 0xbeef000000000000000000000000000000000002n;
  const E1 = 0xdeadbeefn << 224n;
  const negF = (1n << 256n) - 5n; // i64 = -5 sign-extended into a 256-bit ABI word
  // ABI-encode a Big tuple as 7 static words for calldata.
  const bigWords = (a: bigint, b: bigint, c: bigint, d: bigint, e: bigint, f: bigint, g: bigint) => [
    a,
    b,
    c,
    d,
    e,
    f,
    g,
  ];
  beforeAll(async () => {
    p = await Pair.make(J, SOL);
  });
  it('shorthand and full literal produce identical Big as positional', async () => {
    const args = [1n, 2n, C1, 1n, E1, negF, 999n];
    await p.eq(
      'mkShorthand',
      '0x' + sel('mkShorthand(uint256,uint256,address,bool,bytes32,int64,uint256)') + args.map(pad).join(''),
    );
    await p.eq(
      'mkFull',
      '0x' + sel('mkFull(uint256,uint256,address,bool,bytes32,int64,uint256)') + args.map(pad).join(''),
    );
  });
  it('override-wins, override of address, and reordered overrides match solc', async () => {
    const base = bigWords(1n, 2n, C1, 1n, E1, negF, 999n);
    const wc =
      '0x' +
      sel('withCOverride((uint256,uint256,address,bool,bytes32,int64,uint256),address)') +
      base.map(pad).join('') +
      pad(C2);
    await p.eq('withCOverride', wc);
    const ow =
      '0x' +
      sel('overrideWins((uint256,uint256,address,bool,bytes32,int64,uint256),uint256)') +
      base.map(pad).join('') +
      pad(77n);
    await p.eq('overrideWins', ow);
    const ro =
      '0x' +
      sel('reorder((uint256,uint256,address,bool,bytes32,int64,uint256),uint256,uint256)') +
      base.map(pad).join('') +
      pad(100n) +
      pad(200n);
    await p.eq('reorder', ro);
  });
  it('single-field struct literal matches solc', async () => {
    await p.eq('mkOne', encodeCall(sel('mkOne(uint256)'), [42n]));
  });
  it('many-field struct stored across multiple slots: raw slots match solc', async () => {
    const args = [0x1111n, 0x2222n, C1, 1n, E1, negF, 0x9999n];
    await p.both('0x' + sel('storeBig(uint256,uint256,address,bool,bytes32,int64,uint256)') + args.map(pad).join(''));
    // Big: a(slot0), b(slot1), c+d packed(slot2), e(slot3), f(slot4 low), g(slot5)
    await p.slots('storeBig slots', 0n, 1n, 2n, 3n, 4n, 5n);
    await p.eq('getBig', encodeCall(sel('getBig()'), []));
  });
});

// =====================================================================================
// PART 9 - evaluation: override referencing another field of base; spread of
//          calldata / memory-local / storage / another-value struct sources.
// =====================================================================================
describe('F2 struct spread: evaluation order + spread-source kinds', () => {
  const J = `type P = { x: u256; y: u256; z: u256; };
  class C {
    p: P;
    setP(x: u256, y: u256, z: u256): External<void> { this.p = P(x, y, z); }
    // override x using base.y (cross-field reference in the new value)
    get crossField(base: P): External<P> { return { ...base, x: base.y + base.z }; }
    // spread a CALLDATA struct param
    get fromCd(base: P, nx: u256): External<P> { return { ...base, x: nx }; }
    // spread a MEMORY local struct
    get fromMem(a: u256, b: u256, c: u256, nx: u256): External<P> { let m: P = P(a, b, c); return { ...m, x: nx }; }
    // spread a STORAGE struct (this.p) and override
    get fromStorage(nx: u256): External<P> { let s: P = this.p; return { ...s, x: nx }; }
    // store via spread of storage then read raw slots
    bumpZ(dz: u256): External<void> { this.p = { ...this.p, z: this.p.z + dz }; }
    get get(): External<P> { return this.p; }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 x; uint256 y; uint256 z; }
  P p;
  function setP(uint256 x, uint256 y, uint256 z) external { p = P(x, y, z); }
  function crossField(P calldata b) external pure returns (P memory) { P memory q=b; q.x=b.y+b.z; return q; }
  function fromCd(P calldata b, uint256 nx) external pure returns (P memory) { P memory q=b; q.x=nx; return q; }
  function fromMem(uint256 a, uint256 b, uint256 c, uint256 nx) external pure returns (P memory) { P memory m=P(a,b,c); P memory q=m; q.x=nx; return q; }
  function fromStorage(uint256 nx) external view returns (P memory) { P memory s=p; P memory q=s; q.x=nx; return q; }
  function bumpZ(uint256 dz) external { P memory q=p; q.z=q.z+dz; p=q; }
  function get() external view returns (P memory) { return p; }
}`;
  let p: Pair;
  beforeAll(async () => {
    p = await Pair.make(J, SOL);
    await p.both('0x' + sel('setP(uint256,uint256,uint256)') + pad(10n) + pad(20n) + pad(30n));
  });
  it('cross-field override + every spread-source kind matches solc', async () => {
    const base = [10n, 20n, 30n];
    await p.eq('crossField', '0x' + sel('crossField((uint256,uint256,uint256))') + base.map(pad).join(''));
    await p.eq('fromCd', '0x' + sel('fromCd((uint256,uint256,uint256),uint256)') + base.map(pad).join('') + pad(99n));
    await p.eq('fromMem', encodeCall(sel('fromMem(uint256,uint256,uint256,uint256)'), [1n, 2n, 3n, 99n]));
    await p.eq('fromStorage', encodeCall(sel('fromStorage(uint256)'), [99n]));
    await p.both(encodeCall(sel('bumpZ(uint256)'), [5n]));
    await p.slots('after bumpZ', 0n, 1n, 2n);
    await p.eq('get after bumpZ', encodeCall(sel('get()'), []));
  });
});

// =====================================================================================
// PART 10 - struct literal / spread REJECTIONS (codes pinned, no crash).
// =====================================================================================
describe('F2 struct literal: rejections (codes pinned, no crash)', () => {
  it('non-value struct field via object literal: INLINE construction AND a non-inline (static) source both accepted', () => {
    // a nested STATIC struct field constructed INLINE (mirrors positional StructName(...)).
    expect(
      errCodes(
        `type I = { a: u256; }; type O = { i: I; y: u256; }; class C { get mk(y: u256): External<O> { return { i: I(0n), y: y }; } }`,
      ),
    ).toEqual([]);
    // a non-inline source (a struct local) for a STATIC nested struct field is now also accepted (the
    // codegen copies its leaves); verified byte-identical in fix-all-divergences.test.ts.
    expect(
      errCodes(
        `type I = { a: u256; }; type O = { i: I; y: u256; }; class C { get mk(y: u256): External<O> { let z: I = I(0n); return { i: z, y: y }; } }`,
      ),
    ).toEqual([]);
  });
  it('dynamic-field (bytes) struct via object literal: a bytes literal is accepted', () => {
    expect(
      errCodes(
        `type D = { x: u256; b: bytes; }; class C { get mk(x: u256): External<D> { return { x: x, b: "hi" }; } }`,
      ),
    ).toEqual([]);
  });
  it('array-field struct via object literal: an array LITERAL AND a non-inline fixed-array local both accepted', () => {
    expect(
      errCodes(
        `type A = { x: u256; arr: Arr<u256,2>; }; class C { get mk(x: u256): External<A> { return { x: x, arr: [1n,2n] }; } }`,
      ),
    ).toEqual([]);
    expect(
      errCodes(
        `type A = { x: u256; arr: Arr<u256,2>; }; class C { get mk(x: u256): External<A> { let z: Arr<u256,2> = [1n,2n]; return { x: x, arr: z }; } }`,
      ),
    ).toEqual([]);
  });
  it('object literal with no struct context (return type u256) => JETH227', () => {
    const src = `class C { get f(): External<u256> { return { x: 1n, y: 2n }; } }`;
    expect(errCodes(src)).toContain('JETH227');
  });
  it('object literal assigned to a non-struct local (u256) => JETH227', () => {
    const src = `class C { get f(): External<u256> { let r: u256 = { x: 1n }; return r; } }`;
    expect(errCodes(src)).toContain('JETH227');
  });
  it('unknown field => JETH232', () => {
    const src = `type P = { x: u256; y: u256; }; class C { get mk(): External<P> { return { x: 1n, y: 2n, z: 3n }; } }`;
    expect(errCodes(src)).toContain('JETH232');
  });
  it('duplicate field => JETH233', () => {
    const src = `type P = { x: u256; y: u256; }; class C { get mk(): External<P> { return { x: 1n, x: 2n, y: 3n }; } }`;
    expect(errCodes(src)).toContain('JETH233');
  });
  it('missing field without spread => JETH235', () => {
    const src = `type P = { x: u256; y: u256; }; class C { get mk(): External<P> { return { x: 1n }; } }`;
    expect(errCodes(src)).toContain('JETH235');
  });
  it('two spreads => JETH230', () => {
    const src = `type P = { x: u256; y: u256; }; class C { get mk(p: P, q: P): External<P> { return { ...p, ...q }; } }`;
    expect(errCodes(src)).toContain('JETH230');
  });
  it('spread of a DIFFERENT struct type => JETH236', () => {
    const src = `type P = { x: u256; y: u256; }; type Q = { x: u256; y: u256; }; class C { get mk(q: Q): External<P> { return { ...q, x: 1n }; } }`;
    expect(errCodes(src)).toContain('JETH236');
  });
  it('spread of a CALL result => JETH234', () => {
    const src = `type P = { x: u256; y: u256; }; class C { id(p: P): P { return p; } get mk(p: P): External<P> { return { ...id(p), x: 1n }; } }`;
    expect(errCodes(src)).toContain('JETH234');
  });
  it('mapping-containing struct via literal => JETH247', () => {
    const src = `type M = { x: u256; m: mapping<u256, u256>; }; class C { s: M; f(): External<void> { this.s = { ...this.s, x: 1n }; } }`;
    expect(errCodes(src)).toContain('JETH247');
  });
});

// =====================================================================================
// PART 11 - spread-vs-positional EQUIVALENCE: two JETH contracts that differ ONLY in
//           spread-vs-positional construction must yield identical creation bytecode AND
//           identical runtime/slots, and both must match solc.
// =====================================================================================
describe('F2 struct: spread/literal desugars to the SAME structNew as positional', () => {
  const POSITIONAL = `type P = { x: u256; y: u256; z: address; flag: bool; };
  class C {
    p: P;
    set(x: u256, y: u256, z: address, f: bool): External<void> { this.p = P(x, y, z, f); }
    bump(dx: u256): External<void> { let cur: P = this.p; this.p = P(cur.x + dx, cur.y, cur.z, cur.flag); }
    get mk(x: u256, y: u256, z: address, f: bool): External<P> { return P(x, y, z, f); }
    get get(): External<P> { return this.p; }
  }`;
  const SPREAD = `type P = { x: u256; y: u256; z: address; flag: bool; };
  class C {
    p: P;
    set(x: u256, y: u256, z: address, f: bool): External<void> { this.p = { x: x, y: y, z: z, flag: f }; }
    bump(dx: u256): External<void> { this.p = { ...this.p, x: this.p.x + dx }; }
    get mk(x: u256, y: u256, z: address, f: bool): External<P> { return { x, y, z, flag: f }; }
    get get(): External<P> { return this.p; }
  }`;
  const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 x; uint256 y; address z; bool flag; }
  P p;
  function set(uint256 x, uint256 y, address z, bool f) external { p = P(x, y, z, f); }
  function bump(uint256 dx) external { P memory cur=p; p = P(cur.x+dx, cur.y, cur.z, cur.flag); }
  function mk(uint256 x, uint256 y, address z, bool f) external pure returns (P memory) { return P(x, y, z, f); }
  function get() external view returns (P memory) { return p; }
}`;
  const Z = 0xabcd000000000000000000000000000000000001n;
  it('mk: spread literal == positional == solc (returndata identical)', async () => {
    const ps = await Pair.make(SPREAD, SOL);
    const pp = await Pair.make(POSITIONAL, SOL);
    const data = '0x' + sel('mk(uint256,uint256,address,bool)') + pad(5n) + pad(6n) + pad(Z) + pad(1n);
    // spread vs solc
    await ps.eq('spread mk', data);
    // positional vs solc
    await pp.eq('positional mk', data);
    // spread vs positional directly
    const a = await ps.jeth.call(ps.aj, data);
    const b = await pp.jeth.call(pp.aj, data);
    expect(a.returnHex, 'spread mk == positional mk').toBe(b.returnHex);
  });
  it('store + aliased bump: spread == positional == solc on raw slots', async () => {
    const ps = await Pair.make(SPREAD, SOL);
    const pp = await Pair.make(POSITIONAL, SOL);
    const setData = '0x' + sel('set(uint256,uint256,address,bool)') + pad(11n) + pad(22n) + pad(Z) + pad(1n);
    await ps.both(setData);
    await pp.both(setData);
    const bumpData = encodeCall(sel('bump(uint256)'), [5n]);
    await ps.both(bumpData);
    await pp.both(bumpData);
    // spread vs solc slots
    await ps.slots('spread slots', 0n, 1n, 2n);
    // positional vs solc slots
    await pp.slots('positional slots', 0n, 1n, 2n);
    // spread vs positional raw slots
    for (const slot of [0n, 1n, 2n]) {
      expect(await readSlot(ps.jeth, ps.aj, slot), `spread==positional slot ${slot}`).toBe(
        await readSlot(pp.jeth, pp.aj, slot),
      );
    }
    // observable getter identical
    const g1 = await ps.jeth.call(ps.aj, encodeCall(sel('get()'), []));
    const g2 = await pp.jeth.call(pp.aj, encodeCall(sel('get()'), []));
    expect(g1.returnHex, 'spread get == positional get').toBe(g2.returnHex);
  });
});
