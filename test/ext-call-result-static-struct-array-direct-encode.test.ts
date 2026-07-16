// REGRESSION: an EXTERNAL self-call result of a static-struct FIXED-ARRAY (Arr<In,N>,
// Arr<Arr<In,M>,K>) consumed DIRECTLY - either by abi.encode* or as another external-call
// argument - `abi.encode(this.produce())` / `this.consume(this.produce())`.
//
// A static-struct fixed array is STATIC but POINTER-HEADED in memory (N absolute-pointer words ->
// per-element images). `this.produce()` is analyzed as `abiDecode(extCall, Arr<In,N>)`, and
// lowerAbiDecode materializes exactly that pointer-headed image. Before the fix, prepEncodeComponent's
// memFixedSrc set (the branch that transcodes the pointer-headed image to the flat inline ABI body via
// abiEncFromMemBlob) recognized an internal `call` but NOT an `abiDecode`, so the external-call result
// fell through to the plain static-aggregate branch (aggToMemPtr) that returned the pointer-headed
// image as a supposedly-flat inline body. The N leading ABSOLUTE element pointers then leaked into the
// ABI head - a MISCOMPILE: `abi.encode(this.produce())` emitted [0x20][0xc0][0x240][0x280][0x2c0][11]..
// instead of [0x20][0xc0][11][12][21][22][31][32], and `this.consume(this.produce())` re-decoded the
// pointer words as data (returned 1292 instead of 63). The fix adds `abiDecode` to memFixedSrc so the
// external-call result rides the SAME transcode the bind-first local already uses, byte-identical to solc.
//
// NON-VACUITY: every returned word is decoded with DISTINCT non-zero seeds and asserted equal to the
// exact solc bytes (never a pointer word / zero). Controls (bind-first, direct-return, internal-call-
// result, a value fixed array Arr<u256,N>, a whole struct, a nested Arr<Arr<In,M>,K>) prove the shared
// aggregate paths stay byte-identical.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (v: bigint | number) => BigInt(v).toString(16).padStart(64, '0');

let h: Harness;
beforeAll(async () => {
  h = await Harness.create();
});

async function pair(jeth: string, sol: string) {
  const aj = await h.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { aj, as };
}
async function callOne(addr: Address, sig: string, cd: string) {
  try {
    const r = await h.call(addr, '0x' + sel(sig) + cd, {});
    return { s: r.success, r: r.returnHex };
  } catch {
    return { s: false, r: 'THROW' };
  }
}
async function expectSame(a: { aj: Address; as: Address }, sig: string, cd = '') {
  const j = await callOne(a.aj, sig, cd);
  const s = await callOne(a.as, sig, cd);
  expect({ success: j.s, ret: j.r }).toEqual({ success: s.s, ret: s.r });
  return { j, s };
}

const IN = `type In = { a: u256; b: u256 };`;
const SIN = `struct In { uint256 a; uint256 b; }`;

describe('external-call result of a static-struct fixed array consumed directly (the live miscompile)', () => {
  it('Arr<In,3>: abi.encode(this.produce()) + this.consume(this.produce()) are byte-identical', async () => {
    const a = await pair(
      `${IN}
       class C {
         get produce(): External<Arr<In,3>> { return [In(11n,12n),In(21n,22n),In(31n,32n)]; }
         encDirect(): External<bytes> { return abi.encode(this.produce()); }
         get consume(xs: Arr<In,3>): External<u256> { return xs[0n].a+xs[1n].a+xs[2n].a; }
         fwdDirect(): External<u256> { return this.consume(this.produce()); }
         encBound(): External<bytes> { let m: Arr<In,3> = this.produce(); return abi.encode(m); }
         retDirect(): External<Arr<In,3>> { return this.produce(); } }`,
      `${SIN}
       contract C {
         function produce() external pure returns (In[3] memory) { return [In(11,12),In(21,22),In(31,32)]; }
         function encDirect() external view returns (bytes memory) { return abi.encode(this.produce()); }
         function consume(In[3] memory xs) external pure returns (uint256) { return xs[0].a+xs[1].a+xs[2].a; }
         function fwdDirect() external view returns (uint256) { return this.consume(this.produce()); }
         function encBound() external view returns (bytes memory) { In[3] memory m = this.produce(); return abi.encode(m); }
         function retDirect() external view returns (In[3] memory) { return this.produce(); } }`,
    );
    // encDirect: [0x20][0xc0][11][12][21][22][31][32] - the flat body, NO leaked element pointers.
    const { j: jEnc } = await expectSame(a, 'encDirect()');
    expect(jEnc.r).toBe(
      '0x' + W(0x20) + W(0xc0) + W(11) + W(12) + W(21) + W(22) + W(31) + W(32),
    );
    // fwdDirect: 11+21+31 = 63, NOT a re-decode of the leaked pointer words.
    const { j: jFwd } = await expectSame(a, 'fwdDirect()');
    expect(jFwd.r).toBe('0x' + W(63));
    // controls that were already correct: bind-first + direct-return stay byte-identical.
    const { j: jBound } = await expectSame(a, 'encBound()');
    expect(jBound.r).toBe(jEnc.r); // bind-first == direct: both flat
    const { j: jRet } = await expectSame(a, 'retDirect()');
    expect(jRet.r).toBe('0x' + W(11) + W(12) + W(21) + W(22) + W(31) + W(32));
  });

  it('Arr<In,3>: an INTERNAL-call result direct-encode stays byte-identical (control)', async () => {
    const a = await pair(
      `${IN}
       class C {
         iproduce(): Arr<In,3> { return [In(11n,12n),In(21n,22n),In(31n,32n)]; }
         get encInternal(): External<bytes> { return abi.encode(this.iproduce()); } }`,
      `${SIN}
       contract C {
         function iproduce() internal pure returns (In[3] memory) { return [In(11,12),In(21,22),In(31,32)]; }
         function encInternal() external pure returns (bytes memory) { return abi.encode(iproduce()); } }`,
    );
    const { j } = await expectSame(a, 'encInternal()');
    expect(j.r).toBe('0x' + W(0x20) + W(0xc0) + W(11) + W(12) + W(21) + W(22) + W(31) + W(32));
  });

  it('nested Arr<Arr<In,2>,3> external-call result direct-consume is byte-identical', async () => {
    const a = await pair(
      `${IN}
       class C {
         get produce(): External<Arr<Arr<In,2>,3>> {
           return [[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)],[In(9n,10n),In(11n,12n)]]; }
         encDirect(): External<bytes> { return abi.encode(this.produce()); }
         get consume(xs: Arr<Arr<In,2>,3>): External<u256> { return xs[0n][0n].a+xs[1n][1n].b+xs[2n][0n].a; }
         fwdDirect(): External<u256> { return this.consume(this.produce()); } }`,
      `${SIN}
       contract C {
         function produce() external pure returns (In[2][3] memory) {
           return [[In(1,2),In(3,4)],[In(5,6),In(7,8)],[In(9,10),In(11,12)]]; }
         function encDirect() external view returns (bytes memory) { return abi.encode(this.produce()); }
         function consume(In[2][3] memory xs) external pure returns (uint256) { return xs[0][0].a+xs[1][1].b+xs[2][0].a; }
         function fwdDirect() external view returns (uint256) { return this.consume(this.produce()); } }`,
    );
    // flat inline body: 12 words (2*3 elements * 2 fields), NO leaked pointers.
    const { j: jEnc } = await expectSame(a, 'encDirect()');
    expect(jEnc.r).toBe(
      '0x' + W(0x20) + W(0x180) +
        W(1) + W(2) + W(3) + W(4) + W(5) + W(6) + W(7) + W(8) + W(9) + W(10) + W(11) + W(12),
    );
    // 1 (xs[0][0].a) + 8 (xs[1][1].b) + 9 (xs[2][0].a) = 18.
    const { j: jFwd } = await expectSame(a, 'fwdDirect()');
    expect(jFwd.r).toBe('0x' + W(18));
  });

  it('a VALUE fixed array Arr<u256,3> external-call result direct-consume stays byte-identical (control)', async () => {
    const a = await pair(
      `class C {
         get produce(): External<Arr<u256,3>> { return [u256(11n),22n,33n]; }
         encDirect(): External<bytes> { return abi.encode(this.produce()); }
         get consume(xs: Arr<u256,3>): External<u256> { return xs[0n]+xs[1n]+xs[2n]; }
         fwdDirect(): External<u256> { return this.consume(this.produce()); } }`,
      `contract C {
         function produce() external pure returns (uint256[3] memory) { return [uint256(11),22,33]; }
         function encDirect() external view returns (bytes memory) { return abi.encode(this.produce()); }
         function consume(uint256[3] memory xs) external pure returns (uint256) { return xs[0]+xs[1]+xs[2]; }
         function fwdDirect() external view returns (uint256) { return this.consume(this.produce()); } }`,
    );
    const { j: jEnc } = await expectSame(a, 'encDirect()');
    expect(jEnc.r).toBe('0x' + W(0x20) + W(0x60) + W(11) + W(22) + W(33));
    const { j: jFwd } = await expectSame(a, 'fwdDirect()');
    expect(jFwd.r).toBe('0x' + W(66));
  });

  it('a whole STATIC struct external-call result direct-consume stays byte-identical (control)', async () => {
    const a = await pair(
      `${IN}
       class C {
         get produce(): External<In> { return In(77n,88n); }
         encDirect(): External<bytes> { return abi.encode(this.produce()); }
         get consume(x: In): External<u256> { return x.a+x.b; }
         fwdDirect(): External<u256> { return this.consume(this.produce()); } }`,
      `${SIN}
       contract C {
         function produce() external pure returns (In memory) { return In(77,88); }
         function encDirect() external view returns (bytes memory) { return abi.encode(this.produce()); }
         function consume(In memory x) external pure returns (uint256) { return x.a+x.b; }
         function fwdDirect() external view returns (uint256) { return this.consume(this.produce()); } }`,
    );
    // abi.encode(In) of a STATIC struct is the flat tuple [77][88]; the outer `bytes` return
    // wraps it in [offset=0x20][len=0x40].
    const { j: jEnc } = await expectSame(a, 'encDirect()');
    expect(jEnc.r).toBe('0x' + W(0x20) + W(0x40) + W(77) + W(88));
    const { j: jFwd } = await expectSame(a, 'fwdDirect()');
    expect(jFwd.r).toBe('0x' + W(165));
  });

  it('a real abi.decode(b, Arr<In,3>) direct-encode is byte-identical (the abiDecode node from a decode)', async () => {
    const a = await pair(
      `${IN}
       class C {
         get encFromDecode(b: bytes): External<bytes> { return abi.encode(abi.decode(b, Arr<In,3>)); }
         get roundtrip(b: bytes): External<bytes> { let d: Arr<In,3> = abi.decode(b, Arr<In,3>); return abi.encode(d); } }`,
      `${SIN}
       contract C {
         function encFromDecode(bytes calldata b) external pure returns (bytes memory) { return abi.encode(abi.decode(b, (In[3]))); }
         function roundtrip(bytes calldata b) external pure returns (bytes memory) { In[3] memory d = abi.decode(b, (In[3])); return abi.encode(d); } }`,
    );
    // bytes arg = [offset=0x20][len=0xc0][11][12][21][22][31][32]
    const blob = W(0x20) + W(0xc0) + W(11) + W(12) + W(21) + W(22) + W(31) + W(32);
    const { j: jFrom } = await expectSame(a, 'encFromDecode(bytes)', blob);
    expect(jFrom.r).toBe('0x' + W(0x20) + W(0xc0) + W(11) + W(12) + W(21) + W(22) + W(31) + W(32));
    const { j: jRt } = await expectSame(a, 'roundtrip(bytes)', blob);
    expect(jRt.r).toBe(jFrom.r);
  });
});
