// TERN-STRUCT-ARR mixed-chain residual lift: a ternary over a DYNAMIC-outer array whose element is EXACTLY
// ONE FIXED static-struct level (Arr<In,2>[], = solc's In[2][]) in the let-bind / index / element-write /
// return / abi.encode positions was rejected JETH074 (its dynamic-outer image is pointer-headed - [len][one
// absolute-pointer word per element] -> an N-pointer Arr<In,2> block -> per-element In blocks - which the flat
// consumers cannot read; the aliasing memArrayExpr path and the bare-value return/encode path both refused it).
//
// THE SEMANTICS (re-derived from solc 0.8.35 here, NOT assumed - deploy+run+DECODE both arms): solc unifies the
// mixed ternary to a MEMORY reference with the SAME asymmetric rule as In[]: the MEMORY arm is ALIASED, the
// STORAGE arm is DEEP-COPIED. Proven LIVE below on BOTH inner fixed elements (a one-element probe is vacuous):
//   w1  `r=c?m:st; st[0][0].a=999; return r[0][0].a`  -> c=0 gives 100, NOT 999  => storage arm COPIES (pre-mutation)
//   w2  `r[0][0].a=777; return st[0][0].a`            -> c=0 gives 100, NOT 777  => the copy is discarded (no write-back)
//   w2b `r[0][0].a=777; return m[0][0].a`             -> c=1 gives 777           => memory arm ALIASES (write visible in m)
//   w4  `r[0][1].b=88;  return m[0][1].b`             -> c=1 gives 88            => the SECOND inner element aliases too
//
// KEPT REJECTING (sound, verified vs solc by decode): the DEEPER chain Arr<Arr<In,2>,2>[] (= In[2][2][]) - its
// element read path and ABI encoder disagree about the memory image (the B-21 pointer-word leak; solc returns
// 1/100 where a widened JETH leaks a raw pointer - USER RULING: KEEP THE REJECT), on BOTH let-bind and return;
// and a cd|storage MIX (solc TypeError). The gate uses the PER-SHAPE isStaticStructFixedElemDynArray, which
// admits EXACTLY one fixed level and excludes the deeper chain (NOT isStaticStructAnyLeafArray, which would
// re-admit it - the 628a5bc miscompile).
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

// m has BOTH fixed elements written (non-vacuous), st seeded with distinct values.
const M = `let m: Arr<In,2>[] = new Array<Arr<In,2>>(1); m[0n][0n]=In(1n,2n); m[0n][1n]=In(3n,4n);`;
const SM = `In[2][] memory m = new In[2][](1); m[0][0]=In(1,2); m[0][1]=In(3,4);`;

describe('TERN-STRUCT-ARR mixed-chain Arr<In,2>[] - byte-identical to solc 0.8.35', () => {
  it('alias/deep-copy asymmetry (BOTH inner elements) + let-bind/index/write match solc, PROVEN LIVE', async () => {
    const J = `${IN}
      class C {
        st: Arr<In,2>[];
        seed(): External<void> { this.st.push(); this.st[0n][0n]=In(100n,200n); this.st[0n][1n]=In(300n,400n); }
        reset(): External<void> { this.st[0n][0n]=In(100n,200n); this.st[0n][1n]=In(300n,400n); }
        get bindA(c: bool): External<u256> { ${M} let p: Arr<In,2>[] = c ? m : this.st; return p[0n][0n].a; }
        get bindB(c: bool): External<u256> { ${M} let p: Arr<In,2>[] = c ? m : this.st; return p[0n][1n].b; }
        get idxD(c: bool): External<u256> { ${M} return (c ? m : this.st)[0n][1n].a; }
        get encT(c: bool): External<bytes> { ${M} let p: Arr<In,2>[] = c ? m : this.st; return abi.encode(p); }
        w1(c: bool): External<u256> { ${M} let r: Arr<In,2>[] = c ? m : this.st; this.st[0n][0n].a=999n; return r[0n][0n].a; }
        get w2(c: bool): External<u256> { ${M} let r: Arr<In,2>[] = c ? m : this.st; r[0n][0n].a=777n; return this.st[0n][0n].a; }
        get w2b(c: bool): External<u256> { ${M} let r: Arr<In,2>[] = c ? m : this.st; r[0n][0n].a=777n; return m[0n][0n].a; }
        get w4(c: bool): External<u256> { ${M} let p: Arr<In,2>[] = c ? m : this.st; p[0n][1n].b=88n; return m[0n][1n].b; } }`;
    const S = `${SIN}
      contract C {
        In[2][] st;
        function seed() external { st.push(); st[0][0]=In(100,200); st[0][1]=In(300,400); }
        function reset() external { st[0][0]=In(100,200); st[0][1]=In(300,400); }
        function bindA(bool c) external view returns (uint256) { ${SM} In[2][] memory p = c ? m : st; return p[0][0].a; }
        function bindB(bool c) external view returns (uint256) { ${SM} In[2][] memory p = c ? m : st; return p[0][1].b; }
        function idxD(bool c) external view returns (uint256) { ${SM} return (c ? m : st)[0][1].a; }
        function encT(bool c) external view returns (bytes memory) { ${SM} In[2][] memory p = c ? m : st; return abi.encode(p); }
        function w1(bool c) external returns (uint256) { ${SM} In[2][] memory r = c ? m : st; st[0][0].a=999; return r[0][0].a; }
        function w2(bool c) external view returns (uint256) { ${SM} In[2][] memory r = c ? m : st; r[0][0].a=777; return st[0][0].a; }
        function w2b(bool c) external view returns (uint256) { ${SM} In[2][] memory r = c ? m : st; r[0][0].a=777; return m[0][0].a; }
        function w4(bool c) external view returns (uint256) { ${SM} In[2][] memory p = c ? m : st; p[0][1].b=88; return m[0][1].b; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, sel('seed()'));
    await h.call(as, sel('seed()'));
    const calls: [string, string][] = [
      ['bindA(bool)', W(1)], ['bindA(bool)', W(0)],
      ['bindB(bool)', W(1)], ['bindB(bool)', W(0)],
      ['idxD(bool)', W(1)], ['idxD(bool)', W(0)],
      ['encT(bool)', W(1)], ['encT(bool)', W(0)],
      ['w1(bool)', W(0)], ['w1(bool)', W(1)],
      ['w2(bool)', W(0)], ['w2(bool)', W(1)],
      ['w2b(bool)', W(1)], ['w2b(bool)', W(0)],
      ['w4(bool)', W(1)], ['w4(bool)', W(0)],
    ];
    for (const [sg, args] of calls) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg + ' ' + args).toBe(rs.success);
      expect(rj.returnHex, sg + ' ' + args).toBe(rs.returnHex);
    }
    // non-vacuity + asymmetry anchors (each arm selects a DIFFERENT value; both inner elements exercised).
    // Reset storage first: w1 above mutated st[0][0].a to 999 (a WRITER); the read-only anchors want the seed.
    await h.call(aj, sel('reset()'));
    const val = async (sg: string, a: string) => BigInt((await h.call(aj, sel(sg) + a)).returnHex);
    // view anchors (w2/w2b/w4 write MEMORY only; storage stays at the seed):
    expect(await val('bindA(bool)', W(1))).toBe(1n); // m[0][0].a
    expect(await val('bindA(bool)', W(0))).toBe(100n); // st copy
    expect(await val('bindB(bool)', W(1))).toBe(4n); // m[0][1].b (second inner element)
    expect(await val('bindB(bool)', W(0))).toBe(400n); // st copy, second inner element
    expect(await val('w2b(bool)', W(1))).toBe(777n); // memory arm ALIASES: write through r is seen in m
    expect(await val('w2(bool)', W(0))).toBe(100n); // storage arm copy discarded: st untouched
    expect(await val('w4(bool)', W(1))).toBe(88n); // second inner element aliases too
    // w1 MUTATES storage - run it LAST (c=0 deep-copies r BEFORE the st write, so it still reads the seed):
    expect(await val('w1(bool)', W(0))).toBe(100n); // storage arm deep-copied BEFORE the st mutation
  });

  it('bare-value ternary in return / abi.encode position matches solc (mem|storage and storage|storage arms)', async () => {
    const J = `${IN}
      class C {
        st: Arr<In,2>[]; st2: Arr<In,2>[];
        seed(): External<void> { this.st.push(); this.st[0n][0n]=In(100n,200n); this.st[0n][1n]=In(300n,400n); }
        seed2(): External<void> { this.st2.push(); this.st2[0n][0n]=In(11n,22n); this.st2[0n][1n]=In(33n,44n); }
        get retT(c: bool): External<Arr<In,2>[]> { ${M} return c ? m : this.st; }
        get encBare(c: bool): External<bytes> { ${M} return abi.encode(c ? m : this.st); }
        get retSS(c: bool): External<Arr<In,2>[]> { return c ? this.st : this.st2; } }`;
    const S = `${SIN}
      contract C {
        In[2][] st; In[2][] st2;
        function seed() external { st.push(); st[0][0]=In(100,200); st[0][1]=In(300,400); }
        function seed2() external { st2.push(); st2[0][0]=In(11,22); st2[0][1]=In(33,44); }
        function retT(bool c) external view returns (In[2][] memory) { ${SM} return c ? m : st; }
        function encBare(bool c) external view returns (bytes memory) { ${SM} return abi.encode(c ? m : st); }
        function retSS(bool c) external view returns (In[2][] memory) { return c ? st : st2; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, sel('seed()'));
    await h.call(as, sel('seed()'));
    await h.call(aj, sel('seed2()'));
    await h.call(as, sel('seed2()'));
    const calls: [string, string][] = [
      ['retT(bool)', W(1)], ['retT(bool)', W(0)],
      ['encBare(bool)', W(1)], ['encBare(bool)', W(0)],
      ['retSS(bool)', W(1)], ['retSS(bool)', W(0)],
    ];
    for (const [sg, args] of calls) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg + ' ' + args).toBe(rs.success);
      expect(rj.returnHex, sg + ' ' + args).toBe(rs.returnHex);
    }
    // non-vacuity: the two return arms differ, and the whole-array ABI image is non-empty.
    const r1 = (await h.call(aj, sel('retT(bool)') + W(1))).returnHex;
    const r0 = (await h.call(aj, sel('retT(bool)') + W(0))).returnHex;
    expect(r1).not.toBe(r0);
    expect(r1.length).toBeGreaterThan(2);
  });

  it('KEEPS REJECTING the deeper chain Arr<Arr<In,2>,2>[] (both let-bind and return) and cd|storage mixes', () => {
    // deeper chain (In[2][2][]) - solc ACCEPTS these, JETH must REJECT (B-21 pointer-word leak; KEEP THE REJECT).
    expect(
      rejects(
        `${IN} class C { st: Arr<Arr<In,2>,2>[]; st2: Arr<Arr<In,2>,2>[]; get f(c: bool): External<u256> { let p: Arr<Arr<In,2>,2>[] = c ? this.st : this.st2; return p[0n][0n][0n].a; } }`,
      ),
    ).toBe(true);
    expect(
      rejects(
        `${IN} class C { st: Arr<Arr<In,2>,2>[]; st2: Arr<Arr<In,2>,2>[]; get f(c: bool): External<Arr<Arr<In,2>,2>[]> { return c ? this.st : this.st2; } }`,
      ),
    ).toBe(true);
    // cd|storage MIX (solc TypeError) - let-bind and return both stay rejected.
    expect(
      rejects(
        `${IN} class C { st: Arr<In,2>[]; get f(c: bool, p: Arr<In,2>[]): External<u256> { let q: Arr<In,2>[] = c ? p : this.st; return q[0n][0n].a; } }`,
      ),
    ).toBe(true);
    expect(
      rejects(
        `${IN} class C { st: Arr<In,2>[]; get f(c: bool, p: Arr<In,2>[]): External<Arr<In,2>[]> { return c ? p : this.st; } }`,
      ),
    ).toBe(true);
  });

  it('the mixed chain is NON-VACUOUS: the exact OR shape accepts (base 79f8c00 rejected it JETH074)', () => {
    expect(
      rejects(
        `${IN} class C { st: Arr<In,2>[]; get f(c: bool): External<u256> { let m: Arr<In,2>[] = new Array<Arr<In,2>>(1); let p: Arr<In,2>[] = c ? m : this.st; return p[0n][0n].a; } }`,
      ),
    ).toBe(false);
  });
});
