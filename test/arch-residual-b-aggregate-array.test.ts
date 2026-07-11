// Residual B: aggregate/bytes-leaf MEMORY-array locals (lift JETH200).
// B1: a DYNAMIC array of a STATIC struct (P[]). B2: a DYNAMIC array of bytes/string (bytes[]/string[]).
// Both as memory locals. Construction (array literal / new Array<E>(n)), element field/length/byte
// access, xs.length, return xs, abi.encode(xs) - all proven BYTE-IDENTICAL to solc 0.8.35 via a
// differential Harness (deploy JETH + the equivalent pragma 0.8.35 contract, call matching selectors,
// assert returnHex + success equal). The DEFERRED shapes (P[][], bytes[][], Arr<P,N>, dynamic-struct
// P[], element WRITE) are asserted to STILL throw a JETH diagnostic (clean over-rejection).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';
import { Address } from '@ethereumjs/util';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);

// ---- B1: P[] (static struct element) -------------------------------------------------------------
const J1 = `type P = { a: u256; b: u256; };
class C {
  get lit(): External<P[]> { let xs: P[] = [P(1n,2n), P(3n,4n), P(5n,6n)]; return xs; }
  get empty(): External<P[]> { let xs: P[] = []; return xs; }
  get zeroed(): External<P[]> { let xs: P[] = new Array<P>(3n); return xs; }
  get fieldA(): External<u256> { let xs: P[] = [P(1n,2n), P(3n,4n)]; return xs[1n].a; }
  get fieldB(): External<u256> { let xs: P[] = [P(1n,2n), P(3n,4n)]; return xs[1n].b; }
  get len(): External<u256> { let xs: P[] = [P(1n,2n), P(3n,4n)]; return xs.length; }
  get elem(): External<P> { let xs: P[] = [P(7n,8n), P(9n,10n)]; return xs[0n]; }
  get enc(): External<bytes> { let xs: P[] = [P(1n,2n), P(3n,4n)]; return abi.encode(xs); }
  get oob(): External<u256> { let xs: P[] = [P(1n,2n)]; return xs[5n].a; } }`;

const S1 = `contract C {
  struct P { uint a; uint b; }
  function lit() external pure returns (P[] memory) { P[] memory xs = new P[](3); xs[0]=P(1,2); xs[1]=P(3,4); xs[2]=P(5,6); return xs; }
  function empty() external pure returns (P[] memory) { P[] memory xs = new P[](0); return xs; }
  function zeroed() external pure returns (P[] memory) { P[] memory xs = new P[](3); return xs; }
  function fieldA() external pure returns (uint) { P[] memory xs = new P[](2); xs[0]=P(1,2); xs[1]=P(3,4); return xs[1].a; }
  function fieldB() external pure returns (uint) { P[] memory xs = new P[](2); xs[0]=P(1,2); xs[1]=P(3,4); return xs[1].b; }
  function len() external pure returns (uint) { P[] memory xs = new P[](2); xs[0]=P(1,2); xs[1]=P(3,4); return xs.length; }
  function elem() external pure returns (P memory) { P[] memory xs = new P[](2); xs[0]=P(7,8); xs[1]=P(9,10); return xs[0]; }
  function enc() external pure returns (bytes memory) { P[] memory xs = new P[](2); xs[0]=P(1,2); xs[1]=P(3,4); return abi.encode(xs); }
  function oob() external pure returns (uint) { P[] memory xs = new P[](1); xs[0]=P(1,2); return xs[5].a; } }`;

// ---- B2: bytes[] / string[] (dynamic byte-sequence element) --------------------------------------
const J2 = `class C {
  get lit(): External<bytes[]> { let bs: bytes[] = [bytes("hello"), bytes("world!!"), bytes("")]; return bs; }
  get slit(): External<string[]> { let ss: string[] = ["alpha", "a-much-longer-string-past-32-bytes-boundary-yes"]; return ss; }
  get empty(): External<bytes[]> { let bs: bytes[] = []; return bs; }
  get zeroed(): External<bytes[]> { let bs: bytes[] = new Array<bytes>(3n); return bs; }
  get elen(): External<u256> { let bs: bytes[] = [bytes("abc"), bytes("de")]; return bs[0n].length; }
  get byteAt(): External<bytes1> { let bs: bytes[] = [bytes("xyz"), bytes("qrs")]; return bs[1n][2n]; }
  get elem(): External<bytes> { let bs: bytes[] = [bytes("first"), bytes("second")]; return bs[1n]; }
  get len(): External<u256> { let bs: bytes[] = [bytes("a"), bytes("b"), bytes("c")]; return bs.length; }
  get enc(): External<bytes> { let bs: bytes[] = [bytes("aa"), bytes("bbbb")]; return abi.encode(bs); }
  get oob(): External<u256> { let bs: bytes[] = [bytes("a")]; return bs[5n].length; } }`;

const S2 = `contract C {
  function lit() external pure returns (bytes[] memory) { bytes[] memory bs = new bytes[](3); bs[0]=bytes("hello"); bs[1]=bytes("world!!"); bs[2]=bytes(""); return bs; }
  function slit() external pure returns (string[] memory) { string[] memory ss = new string[](2); ss[0]="alpha"; ss[1]="a-much-longer-string-past-32-bytes-boundary-yes"; return ss; }
  function empty() external pure returns (bytes[] memory) { bytes[] memory bs = new bytes[](0); return bs; }
  function zeroed() external pure returns (bytes[] memory) { bytes[] memory bs = new bytes[](3); return bs; }
  function elen() external pure returns (uint) { bytes[] memory bs = new bytes[](2); bs[0]=bytes("abc"); bs[1]=bytes("de"); return bs[0].length; }
  function byteAt() external pure returns (bytes1) { bytes[] memory bs = new bytes[](2); bs[0]=bytes("xyz"); bs[1]=bytes("qrs"); return bs[1][2]; }
  function elem() external pure returns (bytes memory) { bytes[] memory bs = new bytes[](2); bs[0]=bytes("first"); bs[1]=bytes("second"); return bs[1]; }
  function len() external pure returns (uint) { bytes[] memory bs = new bytes[](3); bs[0]=bytes("a"); bs[1]=bytes("b"); bs[2]=bytes("c"); return bs.length; }
  function enc() external pure returns (bytes memory) { bytes[] memory bs = new bytes[](2); bs[0]=bytes("aa"); bs[1]=bytes("bbbb"); return abi.encode(bs); }
  function oob() external pure returns (uint) { bytes[] memory bs = new bytes[](1); bs[0]=bytes("a"); return bs[5].length; } }`;

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};

describe('Residual B1: P[] (static-struct element) memory local - byte-identical to solc 0.8.35', () => {
  it('construct/zero-init/field/length/element/encode/OOB all match solc', async () => {
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J1, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S1, 'C').creation, { caller: me });
    for (const sg of ['lit()', 'empty()', 'zeroed()', 'fieldA()', 'fieldB()', 'len()', 'elem()', 'enc()', 'oob()']) {
      const jr = await h.call(ja, sel(sg));
      const sr = await h.call(sa, sel(sg));
      expect(jr.returnHex, sg).toBe(sr.returnHex);
      expect(jr.success, sg).toBe(sr.success);
    }
  });
});

describe('Residual B2: bytes[] / string[] memory local - byte-identical to solc 0.8.35', () => {
  it('construct/zero-init/element length+byte/whole element/length/encode/OOB all match solc', async () => {
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J2, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S2, 'C').creation, { caller: me });
    for (const sg of ['lit()', 'slit()', 'empty()', 'zeroed()', 'elen()', 'byteAt()', 'elem()', 'len()', 'enc()', 'oob()']) {
      const jr = await h.call(ja, sel(sg));
      const sr = await h.call(sa, sel(sg));
      expect(jr.returnHex, sg).toBe(sr.returnHex);
      expect(jr.success, sg).toBe(sr.success);
    }
  });
});

describe('Residual B4/B3: nested-dynamic-leaf + dyn-struct arrays now ACCEPT (lifted, byte-identical)', () => {
  it('B4: nested-dynamic-leaf arrays (bytes[][]) now ACCEPT (byte-identity in nested-dynamic-leaf-array.test.ts)', () => {
    // bytes[][] / string[][] are the B4 lift: pointer-headed [len][ptr..] outer, each ptr -> inner bytes[].
    expect(codes(`class C { get f(): External<bytes[][]> { let m: bytes[][] = [[bytes("a")]]; return m; } }`)).toEqual([]);
  });
  it('B3: a DYNAMIC struct element array (P with a bytes field) now ACCEPTS (byte-identity in dyn-array-field-struct-local.test.ts)', () => {
    // each P[] element is an absolute pointer to a pointer-headed dyn-struct image (empty sentinels on new).
    expect(codes(`type P = {a:u256;s:bytes;}; class C { get f(): External<P[]> { let m: P[] = [P(1n,bytes("x"))]; return m; } }`)).toEqual([]);
  });
  it('P[][], FIXED-outer Arr<P,N> static-struct arrays, and Arr<bytes,N> (Edge D) now ACCEPT (pointer-headed)', () => {
    // P[][] (Cat B) and Arr<P,N> (Batch A) are now POINTER-HEADED like solc (byte-identity in
    // pointer-headed-static-struct-array.test.ts / fixed-static-struct-array.test.ts).
    expect(codes(`type P = {a:u256;b:u256;}; class C { get f(): External<P[][]> { let m: P[][] = [[P(1n,2n)]]; return m; } }`)).toEqual([]);
    expect(codes(`type P = {a:u256;b:u256;}; class C { get f(): External<Arr<P,2>> { let m: Arr<P,2> = [P(1n,2n),P(3n,4n)]; return m; } }`)).toEqual([]);
    // Edge D: a FIXED array of a bytes/string DYNAMIC element (Arr<bytes,N>) is now lifted byte-identical
    // (build / element read+write / return), see fixed-dynamic-leaf-array.test.ts.
    expect(codes(`class C { get f(): External<Arr<bytes,2>> { let m: Arr<bytes,2> = [bytes("a"),bytes("b")]; return m; } }`)).toEqual([]);
  });
  it('struct-array element WRITE xs[i] = P(...) and bytes[] element write bs[i] = bytes(..) now ACCEPT (lifted)', () => {
    // both are now byte-identical to solc (byte-identity covered in lift-over-rejections.test.ts):
    // xs[i] = P(...) is a whole-element image copy; bs[i] = <bytes> re-points the element pointer.
    expect(
      codes(`type P = {a:u256;b:u256;}; class C { get f(): External<u256> { let xs: P[] = [P(1n,2n)]; xs[0n] = P(9n,9n); return xs[0n].a; } }`),
    ).toEqual([]);
    expect(
      codes(`class C { get f(): External<u256> { let bs: bytes[] = [bytes("a")]; bs[0n] = bytes("zz"); return bs[0n].length; } }`),
    ).toEqual([]);
  });
});
