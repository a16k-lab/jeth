// `new Array<Arr<P,N>>(n)` - the zero image of a FIXED static-struct-array ELEMENT (Arr<In,2>[]).
//
// THE MISCOMPILE (pre-existing, live on the base): zeroInitNestedMemArray routes a POINTER-HEADED element
// (isPointerHeadedStaticElem: a static struct, or a fixed array whose leaf is a static struct) to a per-element
// emptyInnerImage. emptyInnerImage had a case for a dyn-field struct and one for a STATIC struct, then fell
// through to a DYNAMIC-array tail that emits a single [len=0] word - so an `Arr<In,2>` element (which is NOT a
// dynamic array: it is 2 absolute-pointer words, no [len] header) got a ONE-WORD image where an N-pointer block
// was expected. Every outer slot then pointed at that word, so:
//   - `m[0][0] = In(1,2)` stored its fresh In POINTER into the word, and `m[0][0].a` read the raw pointer back
//     -> 288 (0x120) where solc returns 1;                                                  <- the headline bug
//   - `m[0][0].a = 1; m[0][1].a = 3` ALIASED (both inner elements resolved to the same word) -> 3, not 1;
//   - a whole-array return / abi.encode leaked a stale pointer word (0xe0) into the ABI payload, even with
//     NO writes at all.
// The bug was INVISIBLE whenever every inner element was whole-assigned (`m[i] = q` overwrites the bogus
// pointer outright), which is why the storage-multihop mc3/mc4w/mc5w tests were already byte-identical.
// FIX: emptyInnerImage routes a fixed static-struct-leaf array element to emptyFixedDynImage, which builds
// exactly the N-pointer block (recursing for a deeper fixed level, bottoming out on the static-struct case).
//
// SCOPE (verified against solc 0.8.35 by deploy+run+decode, not "both compile"): `Arr<P,N>[]` - a dynamic outer
// over EXACTLY ONE fixed static-struct-array level - is now byte-identical everywhere. A DEEPER fixed level
// (`Arr<Arr<In,2>,2>[]`) is NOT fixable this way and now REJECTS: at that depth JETH's element read path and
// its ABI encoder disagree about the image (the encoder emitted all-zero payload words where solc emits the
// written leaves; the storage twin leaked a raw 0x140 pointer out of `m[0][0][0].a`) - that is the B-21
// member-layout family (abiHeadWords conflating ABI head words with the memory word offset), which carries a
// standing USER RULING to KEEP THE REJECT. A VALUE-leaf element (Arr<u256,2>[]) is INLINE and never reached the
// bug; In[] / In[][] have no fixed level at all.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const IN = `type In = { a: u256; b: u256; };`;
const SIN = `struct In { uint256 a; uint256 b; }`;
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};
const rejects = (src: string): boolean => codes(src).length > 0;

describe('new Array<Arr<P,N>>(n) zero image - byte-identical to solc 0.8.35', () => {
  it('Arr<In,2>[] is byte-identical across every consumer, with the raw-pointer leak pinned as non-vacuity', async () => {
    const J = `${IN}
      class C {
        get mc(): External<u256> { let m: Arr<In,2>[] = new Array<Arr<In,2>>(1); m[0n][0n]=In(1n,2n); m[0n][1n]=In(3n,4n); return m[0n][0n].a; }
        get aliasF(): External<u256> { let m: Arr<In,2>[] = new Array<Arr<In,2>>(1); m[0n][0n].a=1n; m[0n][1n].a=3n; return m[0n][0n].a; }
        get freshRet(): External<Arr<In,2>[]> { let m: Arr<In,2>[] = new Array<Arr<In,2>>(1); return m; }
        get retW(): External<Arr<In,2>[]> { let m: Arr<In,2>[] = new Array<Arr<In,2>>(1); m[0n][0n]=In(1n,2n); m[0n][1n]=In(3n,4n); return m; }
        get enc(): External<bytes> { let m: Arr<In,2>[] = new Array<Arr<In,2>>(1); m[0n][0n]=In(1n,2n); m[0n][1n]=In(3n,4n); return abi.encode(m); }
        get two(): External<u256> { let m: Arr<In,2>[] = new Array<Arr<In,2>>(2); m[0n][0n]=In(1n,2n); m[0n][1n]=In(3n,4n); m[1n][0n]=In(5n,6n); m[1n][1n]=In(7n,8n); return m[0n][0n].a * 1000n + m[1n][1n].a; }
        get forof(): External<u256> { let m: Arr<In,2>[] = new Array<Arr<In,2>>(2); m[0n][0n]=In(1n,2n); m[0n][1n]=In(3n,4n); m[1n][0n]=In(5n,6n); m[1n][1n]=In(7n,8n); let s: u256 = 0n; for (const e of m) { s = s + e[0n].a + e[1n].b; } return s; }
        get whole(): External<u256> { let m: Arr<In,2>[] = new Array<Arr<In,2>>(1); let q: Arr<In,2> = [In(1n,2n), In(3n,4n)]; m[0n]=q; return m[0n][0n].a; } }`;
    const S = `${SIN}
      contract C {
        function mc() external pure returns (uint256) { In[2][] memory m = new In[2][](1); m[0][0]=In(1,2); m[0][1]=In(3,4); return m[0][0].a; }
        function alias_() external pure returns (uint256) { In[2][] memory m = new In[2][](1); m[0][0].a=1; m[0][1].a=3; return m[0][0].a; }
        function freshRet() external pure returns (In[2][] memory) { In[2][] memory m = new In[2][](1); return m; }
        function retW() external pure returns (In[2][] memory) { In[2][] memory m = new In[2][](1); m[0][0]=In(1,2); m[0][1]=In(3,4); return m; }
        function enc() external pure returns (bytes memory) { In[2][] memory m = new In[2][](1); m[0][0]=In(1,2); m[0][1]=In(3,4); return abi.encode(m); }
        function two() external pure returns (uint256) { In[2][] memory m = new In[2][](2); m[0][0]=In(1,2); m[0][1]=In(3,4); m[1][0]=In(5,6); m[1][1]=In(7,8); return m[0][0].a * 1000 + m[1][1].a; }
        function forof() external pure returns (uint256) { In[2][] memory m = new In[2][](2); m[0][0]=In(1,2); m[0][1]=In(3,4); m[1][0]=In(5,6); m[1][1]=In(7,8); uint256 s = 0; for (uint i=0;i<m.length;i++) { s = s + m[i][0].a + m[i][1].b; } return s; }
        function whole() external pure returns (uint256) { In[2][] memory m = new In[2][](1); In[2] memory q = [In(1,2), In(3,4)]; m[0]=q; return m[0][0].a; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    // the JETH getter is `alias`; solc reserves it, so the mirror is alias_() - compare by explicit pairing.
    const pairs: [string, string][] = [
      ['mc()', 'mc()'],
      ['aliasF()', 'alias_()'],
      ['freshRet()', 'freshRet()'],
      ['retW()', 'retW()'],
      ['enc()', 'enc()'],
      ['two()', 'two()'],
      ['forof()', 'forof()'],
      ['whole()', 'whole()'],
    ];
    for (const [jsig, ssig] of pairs) {
      const rj = await h.call(aj, sel(jsig));
      const rs = await h.call(as, sel(ssig));
      expect(rj.success, `${jsig} jeth reverted`).toBe(true);
      expect(rs.success, `${ssig} solc reverted`).toBe(true);
      expect(rj.returnHex, `${jsig} vs solc`).toBe(rs.returnHex);
    }
    // NON-VACUITY: pin the exact pre-fix wrong values, so a regression cannot pass by "both compile".
    const mc = await h.call(aj, sel('mc()'));
    expect(BigInt(mc.returnHex!)).toBe(1n); // was 288 = 0x120, a raw memory pointer
    const al = await h.call(aj, sel('aliasF()'));
    expect(BigInt(al.returnHex!)).toBe(1n); // was 3: both inner elements aliased ONE word
    // the fresh (never-written) return must be ALL ZERO - it leaked a stale 0xe0 pointer word before.
    // (pad32/W returns 64 hex chars with NO 0x prefix - never .slice(2) it.)
    const fr = await h.call(aj, sel('freshRet()'));
    expect(fr.returnHex).toBe('0x' + W(0x20) + W(1) + W(0).repeat(4));
    // the written return must carry the real leaves 1,2,3,4 - word[2] was 0x120 before.
    const rw = await h.call(aj, sel('retW()'));
    expect(rw.returnHex).toBe('0x' + W(0x20) + W(1) + W(1) + W(2) + W(3) + W(4));
    const tw = await h.call(aj, sel('two()'));
    expect(BigInt(tw.returnHex!)).toBe(1007n);
  });

  it('the clean SIBLING element kinds are untouched (value leaf / struct leaf / all-dynamic)', async () => {
    const J = `${IN}
      class C {
        get val(): External<Arr<u256,2>[]> { let m: Arr<u256,2>[] = new Array<Arr<u256,2>>(1); m[0n][0n]=1n; m[0n][1n]=2n; return m; }
        get st(): External<In[]> { let m: In[] = new Array<In>(2); m[0n]=In(1n,2n); m[1n]=In(3n,4n); return m; }
        get dd(): External<In[][]> { let m: In[][] = new Array<In[]>(1); m[0n]=new Array<In>(2); m[0n][0n]=In(1n,2n); m[0n][1n]=In(3n,4n); return m; } }`;
    const S = `${SIN}
      contract C {
        function val() external pure returns (uint256[2][] memory) { uint256[2][] memory m = new uint256[2][](1); m[0][0]=1; m[0][1]=2; return m; }
        function st() external pure returns (In[] memory) { In[] memory m = new In[](2); m[0]=In(1,2); m[1]=In(3,4); return m; }
        function dd() external pure returns (In[][] memory) { In[][] memory m = new In[][](1); m[0]=new In[](2); m[0][0]=In(1,2); m[0][1]=In(3,4); return m; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const sg of ['val()', 'st()', 'dd()']) {
      const rj = await h.call(aj, sel(sg));
      const rs = await h.call(as, sel(sg));
      expect(rj.success, `${sg} jeth`).toBe(true);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
    // non-vacuity: the payload really carries the seeded leaves.
    expect(BigInt((await h.call(aj, sel('val()'))).returnHex!.slice(0, 2 + 64 * 3).slice(-64))).toBe(1n);
  });

  it('a DEEPER fixed level (Arr<Arr<In,2>,2>[]) REJECTS - read path vs ABI encoder disagree (B-21)', () => {
    const D = `${IN} class C { `;
    // every spelling that miscompiled at depth 2 must now reject, in BOTH producers.
    expect(
      rejects(
        `${D} get f(): External<u256> { let m: Arr<Arr<In,2>,2>[] = new Array<Arr<Arr<In,2>,2>>(1); m[0n][0n][0n]=In(7n,0n); m[0n][0n][1n]=In(8n,8n); m[0n][1n][0n]=In(9n,9n); m[0n][1n][1n]=In(6n,6n); return m[0n][0n][0n].a; } }`,
      ),
    ).toBe(true);
    expect(
      rejects(
        `${D} get f(): External<bytes> { let m: Arr<Arr<In,2>,2>[] = new Array<Arr<Arr<In,2>,2>>(1); m[0n][0n][0n]=In(7n,0n); return abi.encode(m); } }`,
      ),
    ).toBe(true);
    expect(
      rejects(`${IN} class C { st: Arr<Arr<In,2>,2>[]; get f(): External<u256> { let m: Arr<Arr<In,2>,2>[] = this.st; return m[0n][0n][0n].a; } }`),
    ).toBe(true);
    // the depth-1 twin stays ACCEPTED (the whole point of the narrow boundary).
    expect(
      rejects(`${D} get f(): External<u256> { let m: Arr<In,2>[] = new Array<Arr<In,2>>(1); m[0n][0n]=In(1n,2n); return m[0n][0n].a; } }`),
    ).toBe(false);
  });
});

describe('TERN-STRUCT-ARR gate - the family gate is a per-shape predicate, not the codec one', () => {
  it('a ternary over a MIXED dyn-outer/fixed-inner chain rejects; the all-dynamic scope stays lifted', () => {
    const D = `${IN} class C { st: Arr<Arr<In,2>,2>[]; `;
    // Arr<Arr<In,2>,2>[] through the ternary MISCOMPILED its storage arm (a raw 0x440 where solc gives 100)
    // when the gate used the codec-dispatch predicate isStaticStructAnyLeafArray, which descends through ANY
    // mix of levels so the fixed level hid INSIDE the `length === undefined` outer restriction.
    expect(
      rejects(
        `${D} get bind(c: bool): External<u256> { let m: Arr<Arr<In,2>,2>[] = new Array<Arr<Arr<In,2>,2>>(1); let p: Arr<Arr<In,2>,2>[] = c ? m : this.st; return p[0n][0n][0n].a; } }`,
      ),
    ).toBe(true);
    // the ALL-DYNAMIC scope the lift actually verified stays admitted.
    expect(
      rejects(
        `${IN} class C { st: In[]; get bind(c: bool): External<u256> { let m: In[] = new Array<In>(2); m[0n]=In(1n,2n); m[1n]=In(3n,4n); let p: In[] = c ? m : this.st; return p[0n].a; } }`,
      ),
    ).toBe(false);
    expect(
      rejects(
        `${IN} class C { st: In[][]; get bind(c: bool): External<u256> { let m: In[][] = new Array<In[]>(1); m[0n]=new Array<In>(1); m[0n][0n]=In(1n,2n); let p: In[][] = c ? m : this.st; return p[0n][0n].a; } }`,
      ),
    ).toBe(false);
  });
});
