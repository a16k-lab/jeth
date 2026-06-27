// Residual C: abi.decode into ARRAY targets, byte-identical to solc 0.8.35's abi.decode-from-memory.
//  C1: u256[][] (and a fixed-outer Arr<u256[],N> nested value array)
//  C2: P[] where P is a STATIC struct (inline-block image, == the standard ABI image)
//  C3: bytes[] / string[] (absolute-pointer-of-blobs image)
//  + the tuple form [u256, P[]] (reuses the same abiDecode IR once the component decoder exists)
// The decoders are abiDecFromMem (C2, value/static) and the new abiDecFromMemToImage (C1/C3, absolute-
// pointer image). We assert a DERIVED value read (m[0][0], ps[0].a, bs[0].length, ss[1]) so a wrong image
// would surface as a MISCOMPILE, and a TRUNCATED/malformed blob must revert in BOTH (memory-decode parity).
// The genuinely-deferred targets (dynamic-struct P[], P[][], bytes[][]) stay rejecting cleanly.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';
import { Address } from '@ethereumjs/util';
import { keccak256 } from 'ethereum-cryptography/keccak.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const W = (b: bigint | number) => pad32(BigInt(b));
const BI = (h: string) => (!h || h === '0x' ? 0n : BigInt(h));
const sel = (s: string) => '0x' + functionSelector(s);
const ret = (r: any) => (r.returnHex.startsWith('0x') ? r.returnHex.slice(2) : r.returnHex);
// the abi.decode source bytes are themselves an ABI-encoded `bytes` argument: [0x20 offset][len][blob].
const wrap = (blob: string) => W(0x20) + W(blob.length / 2) + blob;
// right-pad raw bytes to a 32-byte boundary (the ABI bytes/string tail data padding).
const padR = (hex: string) => hex + '00'.repeat((32 - (hex.length / 2) % 32) % 32);

// ---- hand-built ABI blobs ----
// `abi.decode(b, (T))` reads `b` as the ABI encoding of the TUPLE `(T)`: a DYNAMIC top-level component
// `T` therefore has a LEADING tuple-offset word (0x20 for a single component). Inner-array offsets are
// relative to the data area (right after that component's length word, or the offset-table start for a
// fixed outer). These match solc's canonical `abi.encode(value)` (verified against the solc encoder).

// u256[][] value [[7,8,9],[10]]: tuple offset 0x20, then [len=2][off0=0x40][off1=0xc0], inners.
const blob_uu = (() => {
  const head = W(2) + W(0x40) + W(0xc0);
  const inner0 = W(3) + W(7) + W(8) + W(9);
  const inner1 = W(1) + W(10);
  return W(0x20) + head + inner0 + inner1;
})();

// Arr<u256[],2> value [[5,6],[8]] (fixed outer of 2, dynamic inner): tuple offset 0x20, then the value
// (NO length word): [off0=0x40][off1=0xa0] then inner0 [2][5][6], inner1 [1][8] (offsets relative to the
// offset-table start).
const blob_fu = (() => {
  const head = W(0x40) + W(0xa0);
  const inner0 = W(2) + W(5) + W(6);
  const inner1 = W(1) + W(8);
  return W(0x20) + head + inner0 + inner1;
})();

// P[] (static struct {a,b}) value [{1,2},{3,4},{5,6}]: tuple offset 0x20, then [len=3] + 3 inline blocks.
const blob_ps = W(0x20) + W(3) + W(1) + W(2) + W(3) + W(4) + W(5) + W(6);

// bytes[] value ["aabb","cc"]: tuple offset 0x20, then [len=2][off0=0x40][off1=0x80], element blobs.
// (element 0 = [len][1 word of data] = 0x40 bytes, so off1 = 0x40 + 0x40 = 0x80.)
const blob_bs = (() => {
  const head = W(2) + W(0x40) + W(0x80);
  const b0 = W(2) + padR('aabb');
  const b1 = W(1) + padR('cc');
  return W(0x20) + head + b0 + b1;
})();

// string[] value ["hi","abc"]: tuple offset 0x20, then [len=2][off0=0x40][off1=0x80], element blobs.
const ascii = (s: string) => Buffer.from(s, 'ascii').toString('hex');
const blob_ss = (() => {
  const head = W(2) + W(0x40) + W(0x80);
  const s0 = W(2) + padR(ascii('hi'));
  const s1 = W(3) + padR(ascii('abc'));
  return W(0x20) + head + s0 + s1;
})();

// u256[][][] value [[[1,2]],[[3],[4,5]]]: solc's canonical blob (verified against the solc encoder). The
// leading 0x20 is the tuple offset; the rest is the triple-nested image. Exercises the recursive decoder's
// allocation ordering (each sub-image must alloc PAST the parent's pointer table - a wrong order would
// clobber the in-progress image, a MISCOMPILE). m[1][1][1] == 5, m[0][0][0] == 1.
const blob_uuu =
  '0000000000000000000000000000000000000000000000000000000000000020' +
  '0000000000000000000000000000000000000000000000000000000000000002' +
  '0000000000000000000000000000000000000000000000000000000000000040' +
  '00000000000000000000000000000000000000000000000000000000000000e0' +
  '0000000000000000000000000000000000000000000000000000000000000001' +
  '0000000000000000000000000000000000000000000000000000000000000020' +
  '0000000000000000000000000000000000000000000000000000000000000002' +
  '0000000000000000000000000000000000000000000000000000000000000001' +
  '0000000000000000000000000000000000000000000000000000000000000002' +
  '0000000000000000000000000000000000000000000000000000000000000002' +
  '0000000000000000000000000000000000000000000000000000000000000040' +
  '0000000000000000000000000000000000000000000000000000000000000080' +
  '0000000000000000000000000000000000000000000000000000000000000001' +
  '0000000000000000000000000000000000000000000000000000000000000003' +
  '0000000000000000000000000000000000000000000000000000000000000002' +
  '0000000000000000000000000000000000000000000000000000000000000004' +
  '0000000000000000000000000000000000000000000000000000000000000005';

// empty u256[][] value []: tuple offset 0x20, then [len=0] (no tails).
const blob_empty = W(0x20) + W(0);

// [u256, P[]] tuple value (10, [{1,2},{3,4}]): the tuple head is [10][offset=0x40], the tail is the P[]
// encoding [len=2][{1,2}][{3,4}]. (No extra leading offset: the static u256 is inline, the P[] is the
// only dynamic component and its head offset is 0x40 = past the 2-word head.)
const blob_tup = (() => {
  const head = W(10) + W(0x40);
  const psTail = W(2) + W(1) + W(2) + W(3) + W(4);
  return head + psTail;
})();

const J = `@struct class P { a: u256; b: u256; }
@contract class C {
  @external @pure duu(b: bytes): u256 { let m: u256[][] = abi.decode(b, u256[][]); return m[0n][0n] + m[0n][2n] + m[1n][0n]; }
  @external @pure dfu(b: bytes): u256 { let m: Arr<u256[],2> = abi.decode(b, Arr<u256[],2>); return m[0n][1n] + m[1n][0n]; }
  @external @pure duuu(b: bytes): u256 { let m: u256[][][] = abi.decode(b, u256[][][]); return m[0n][0n][0n] * 1000n + m[1n][1n][1n] * 100n + m[1n][0n][0n] * 10n + m.length; }
  @external @pure dempty(b: bytes): u256 { let m: u256[][] = abi.decode(b, u256[][]); return m.length; }
  @external @pure dps(b: bytes): u256 { let ps: P[] = abi.decode(b, P[]); return ps[0n].a + ps[1n].b + ps[2n].a + ps.length; }
  @external @pure dbs(b: bytes): u256 { let bs: bytes[] = abi.decode(b, bytes[]); return bs[0n].length * 100n + bs[1n].length * 10n + bs.length; }
  @external @pure dbsk(b: bytes): bytes32 { let bs: bytes[] = abi.decode(b, bytes[]); return keccak256(bs[1n]); }
  @external @pure dss(b: bytes): u256 { let ss: string[] = abi.decode(b, string[]); return bytes(ss[0n]).length * 100n + bytes(ss[1n]).length * 10n + ss.length; }
  @external @pure dssk(b: bytes): bytes32 { let ss: string[] = abi.decode(b, string[]); return keccak256(bytes(ss[0n])); }
  @external @pure dtup(b: bytes): u256 { let [n, ps]: [u256, P[]] = abi.decode(b, [u256, P[]]); return n + ps[0n].a + ps[1n].b + ps.length; } }`;

const S = `struct P { uint a; uint b; }
contract C {
  function duu(bytes calldata b) external pure returns(uint){ uint[][] memory m = abi.decode(b,(uint[][])); return m[0][0]+m[0][2]+m[1][0]; }
  function dfu(bytes calldata b) external pure returns(uint){ uint[][2] memory m = abi.decode(b,(uint[][2])); return m[0][1]+m[1][0]; }
  function duuu(bytes calldata b) external pure returns(uint){ uint[][][] memory m = abi.decode(b,(uint[][][])); return m[0][0][0]*1000+m[1][1][1]*100+m[1][0][0]*10+m.length; }
  function dempty(bytes calldata b) external pure returns(uint){ uint[][] memory m = abi.decode(b,(uint[][])); return m.length; }
  function dps(bytes calldata b) external pure returns(uint){ P[] memory ps = abi.decode(b,(P[])); return ps[0].a+ps[1].b+ps[2].a+ps.length; }
  function dbs(bytes calldata b) external pure returns(uint){ bytes[] memory bs = abi.decode(b,(bytes[])); return bs[0].length*100+bs[1].length*10+bs.length; }
  function dbsk(bytes calldata b) external pure returns(bytes32){ bytes[] memory bs = abi.decode(b,(bytes[])); return keccak256(bs[1]); }
  function dss(bytes calldata b) external pure returns(uint){ string[] memory ss = abi.decode(b,(string[])); return bytes(ss[0]).length*100+bytes(ss[1]).length*10+ss.length; }
  function dssk(bytes calldata b) external pure returns(bytes32){ string[] memory ss = abi.decode(b,(string[])); return keccak256(bytes(ss[0])); }
  function dtup(bytes calldata b) external pure returns(uint){ (uint n, P[] memory ps) = abi.decode(b,(uint,P[])); return n+ps[0].a+ps[1].b+ps.length; } }`;

describe('Residual C: abi.decode into array targets (u256[][], P[], bytes[], string[], tuple)', () => {
  it('byte-identical to solc 0.8.35 (value reads + derived reads + malformed-blob revert parity)', async () => {
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    const cmp = async (data: string) => {
      const jr = await h.call(ja, data);
      const sr = await h.call(sa, data);
      expect(ret(jr)).toBe(ret(sr));
      expect(jr.success).toBe(sr.success);
      return jr;
    };
    // C1: nested value array, dynamic outer.
    expect(BI('0x' + ret(await cmp(sel('duu(bytes)') + wrap(blob_uu))))).toBe(7n + 9n + 10n);
    // C1: nested value array, FIXED outer of dynamic inner.
    expect(BI('0x' + ret(await cmp(sel('dfu(bytes)') + wrap(blob_fu))))).toBe(6n + 8n);
    // C1: TRIPLE-nested value array (recursive decoder allocation-ordering anti-miscompile).
    expect(BI('0x' + ret(await cmp(sel('duuu(bytes)') + wrap(blob_uuu))))).toBe(1n * 1000n + 5n * 100n + 3n * 10n + 2n);
    // C1: EMPTY nested array (len=0, no tails).
    expect(BI('0x' + ret(await cmp(sel('dempty(bytes)') + wrap(blob_empty))))).toBe(0n);
    // C2: static-struct array (inline blocks).
    expect(BI('0x' + ret(await cmp(sel('dps(bytes)') + wrap(blob_ps))))).toBe(1n + 4n + 5n + 3n);
    // C3: bytes[] (absolute-pointer-of-blobs).
    expect(BI('0x' + ret(await cmp(sel('dbs(bytes)') + wrap(blob_bs))))).toBe(2n * 100n + 1n * 10n + 2n);
    // C3: bytes[] DATA-content check (keccak of the actual element bytes, not just the length) - a wrong
    // image (garbage data) would diverge here. cmp already asserts JETH == solc; pin to keccak256(0xcc).
    expect('0x' + ret(await cmp(sel('dbsk(bytes)') + wrap(blob_bs)))).toBe(
      '0x' + Buffer.from(keccak256(Uint8Array.from([0xcc]))).toString('hex'), // keccak256(hex"cc")
    );
    // C3: string[].
    expect(BI('0x' + ret(await cmp(sel('dss(bytes)') + wrap(blob_ss))))).toBe(2n * 100n + 3n * 10n + 2n);
    // C3: string[] DATA-content check (keccak of element 0's bytes).
    await cmp(sel('dssk(bytes)') + wrap(blob_ss)); // cmp asserts byte-identical JETH == solc
    // tuple [u256, P[]].
    expect(BI('0x' + ret(await cmp(sel('dtup(bytes)') + wrap(blob_tup))))).toBe(10n + 1n + 4n + 2n);

    // ---- malformed / truncated blobs: BOTH must revert identically (memory-decode parity) ----
    // u256[][]: outer says len=2 but the blob is truncated to the offset table only (no inner tails).
    const badUU = await cmp(sel('duu(bytes)') + wrap(W(0x20) + W(2) + W(0x40) + W(0xc0)));
    expect(badUU.success).toBe(false);
    // u256[][]: an inner offset points past the blob end.
    const badUU2 = await cmp(sel('duu(bytes)') + wrap(W(0x20) + W(2) + W(0x40) + W(0xffffffff) + W(1) + W(7)));
    expect(badUU2.success).toBe(false);
    // P[]: len=3 but only 1 inline block present (payload short).
    const badPS = await cmp(sel('dps(bytes)') + wrap(W(0x20) + W(3) + W(1) + W(2)));
    expect(badPS.success).toBe(false);
    // bytes[]: an element offset is fine but the element's length runs past the blob.
    const badBS = await cmp(sel('dbs(bytes)') + wrap(W(0x20) + W(1) + W(0x20) + W(0xff)));
    expect(badBS.success).toBe(false);
    // string[]: outer length is absurd (>2^64) -> cap revert in both.
    const badSS = await cmp(sel('dss(bytes)') + wrap(W(0x20) + W(BigInt('0x1' + '0'.repeat(20)))));
    expect(badSS.success).toBe(false);
    // tuple: the P[] component offset points past the blob.
    const badTup = await cmp(sel('dtup(bytes)') + wrap(W(10) + W(0xffffffff)));
    expect(badTup.success).toBe(false);
  });

  it('still rejects the genuinely-deferred array decode targets (clean over-rejections)', () => {
    const codes = (src: string): string[] => {
      try {
        compile(src, { fileName: 'C.jeth' });
        return [];
      } catch (e: any) {
        return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
      }
    };
    // a DYNAMIC-field struct array P[] (P has a bytes field): no memory-local representation / decoder yet.
    const preD = `@struct class D { a: u256; tags: bytes; } @contract class C { @external @pure f(b: bytes): u256 {`;
    expect(codes(`${preD} let ds: D[] = abi.decode(b, D[]); return ds.length; } }`).length).toBeGreaterThan(0);
    // a nested-aggregate array P[][] (array of static-struct arrays).
    const preP = `@struct class P { a: u256; b: u256; } @contract class C { @external @pure f(b: bytes): u256 {`;
    expect(codes(`${preP} let m: P[][] = abi.decode(b, P[][]); return m.length; } }`).length).toBeGreaterThan(0);
    // a nested-aggregate array bytes[][].
    const preC = `@contract class C { @external @pure f(b: bytes): u256 {`;
    expect(codes(`${preC} let m: bytes[][] = abi.decode(b, bytes[][]); return m.length; } }`).length).toBeGreaterThan(0);
  });
});
