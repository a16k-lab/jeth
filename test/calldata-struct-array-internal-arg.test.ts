// REGRESSION: forwarding a WHOLE calldata static-struct FIXED-ARRAY param (Arr<In,N>,
// Arr<Arr<In,N>,M>) as an INTERNAL-call argument. A static-struct fixed array is STATIC but
// POINTER-HEADED in memory (N absolute-pointer words -> per-element images), and the internal
// callee binds the param as a MEMORY reference and reads a[i] as the i-th pointer word. Before
// the fix, aggArgToMemPtr materialized the whole calldata param via allocAggFromCalldata (the
// FLAT ABI image: N inline es-word blocks) - the callee then read the flat leading VALUE words as
// element pointers, returning ALL-ZERO memory: a MISCOMPILE (both compile + run, JETH returned two
// zero words while solc returned the real struct). The fix routes such a param through the same
// pointer-headed calldata->memory codec (abiDecFromCdToImage) the memory-local bind uses, byte-
// identical to solc.
//
// NON-VACUITY: every cell decodes the FULL returned word(s) and asserts they equal the seeded
// calldata values (never zero), and each contract is deployed with the EXPANDED-TUPLE selector a
// struct param actually dispatches on. Controls prove the shared internal-arg path (flat static
// struct, value fixed array, dyn struct, dyn value array, struct-from-literals, memory-local) stays
// byte-identical.
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
async function expectSame(a: { aj: Address; as: Address }, sig: string, cd: string) {
  const j = await callOne(a.aj, sig, cd);
  const s = await callOne(a.as, sig, cd);
  expect({ success: j.s, ret: j.r }).toEqual({ success: s.s, ret: s.r });
  return { j, s };
}

const IN = `type In = { a: u256; b: u256 };`;
const SIN = `struct In { uint256 a; uint256 b; }`;

describe('calldata static-struct fixed-array forwarded as an internal-call arg (the live miscompile)', () => {
  it('Arr<In,2> internal-arg: byte-identical, returns the real element (never zero)', async () => {
    const a = await pair(
      `${IN}
       class C {
         pick(a: Arr<In,2>, i: u256): In { return a[i]; }
         get via(a: Arr<In,2>, i: u256): External<In> { return this.pick(a, i); } }`,
      `${SIN}
       contract C {
         function pick(In[2] memory a, uint256 i) internal pure returns (In memory) { return a[i]; }
         function via(In[2] calldata a, uint256 i) external pure returns (In memory) { return pick(a, i); } }`,
    );
    const body = W(0x1111) + W(0x2222) + W(0x3333) + W(0x4444);
    const sig = 'via((uint256,uint256)[2],uint256)';
    // NON-VACUOUS: decode the exact returned struct and assert it is the seeded element, NOT zero.
    const { j: j0 } = await expectSame(a, sig, body + W(0));
    expect(j0.r).toBe('0x' + W(0x1111) + W(0x2222));
    const { j: j1 } = await expectSame(a, sig, body + W(1));
    expect(j1.r).toBe('0x' + W(0x3333) + W(0x4444)); // the exact miscompile input; must be non-zero
    await expectSame(a, sig, body + W(2)); // OOB index -> Panic 0x32 on both
  });

  it('Arr<In,3> internal-arg at every index', async () => {
    const a = await pair(
      `${IN}
       class C {
         pick(a: Arr<In,3>, i: u256): In { return a[i]; }
         get via(a: Arr<In,3>, i: u256): External<In> { return this.pick(a, i); } }`,
      `${SIN}
       contract C {
         function pick(In[3] memory a, uint256 i) internal pure returns (In memory) { return a[i]; }
         function via(In[3] calldata a, uint256 i) external pure returns (In memory) { return pick(a, i); } }`,
    );
    const body = W(0x1111) + W(0x2222) + W(0x3333) + W(0x4444) + W(0x5555) + W(0x6666);
    const sig = 'via((uint256,uint256)[3],uint256)';
    const expected = ['0x' + W(0x1111) + W(0x2222), '0x' + W(0x3333) + W(0x4444), '0x' + W(0x5555) + W(0x6666)];
    for (let i = 0; i < 3; i++) {
      const { j } = await expectSame(a, sig, body + W(i));
      expect(j.r).toBe(expected[i]);
    }
    await expectSame(a, sig, body + W(3)); // OOB
  });

  it('nested Arr<Arr<In,2>,2> internal-arg (a[i][j])', async () => {
    const a = await pair(
      `${IN}
       class C {
         pick(a: Arr<Arr<In,2>,2>, i: u256, j: u256): In { return a[i][j]; }
         get via(a: Arr<Arr<In,2>,2>, i: u256, j: u256): External<In> { return this.pick(a, i, j); } }`,
      `${SIN}
       contract C {
         function pick(In[2][2] memory a, uint256 i, uint256 j) internal pure returns (In memory) { return a[i][j]; }
         function via(In[2][2] calldata a, uint256 i, uint256 j) external pure returns (In memory) { return pick(a, i, j); } }`,
    );
    const body = W(0x11) + W(0x12) + W(0x21) + W(0x22) + W(0x31) + W(0x32) + W(0x41) + W(0x42);
    const sig = 'via((uint256,uint256)[2][2],uint256,uint256)';
    const exp: Record<string, string> = {
      '0,0': '0x' + W(0x11) + W(0x12), '0,1': '0x' + W(0x21) + W(0x22),
      '1,0': '0x' + W(0x31) + W(0x32), '1,1': '0x' + W(0x41) + W(0x42),
    };
    for (const [i, jx] of [[0, 0], [0, 1], [1, 0], [1, 1]] as const) {
      const { j } = await expectSame(a, sig, body + W(i) + W(jx));
      expect(j.r).toBe(exp[`${i},${jx}`]);
    }
    await expectSame(a, sig, body + W(2) + W(0)); // OOB outer
  });

  it('nested internal calls forwarding the struct-array arg (two hops)', async () => {
    const a = await pair(
      `${IN}
       class C {
         pick2(a: Arr<In,2>, i: u256): In { return a[i]; }
         pick(a: Arr<In,2>, i: u256): In { return this.pick2(a, i); }
         get via(a: Arr<In,2>, i: u256): External<In> { return this.pick(a, i); } }`,
      `${SIN}
       contract C {
         function pick2(In[2] memory a, uint256 i) internal pure returns (In memory) { return a[i]; }
         function pick(In[2] memory a, uint256 i) internal pure returns (In memory) { return pick2(a, i); }
         function via(In[2] calldata a, uint256 i) external pure returns (In memory) { return pick(a, i); } }`,
    );
    const body = W(0x1111) + W(0x2222) + W(0x3333) + W(0x4444);
    const sig = 'via((uint256,uint256)[2],uint256)';
    const { j } = await expectSame(a, sig, body + W(1));
    expect(j.r).toBe('0x' + W(0x3333) + W(0x4444));
  });

  it('callee mutates its (pass-by-memory copy) struct-array arg, returns the element', async () => {
    const a = await pair(
      `${IN}
       class C {
         bump(a: Arr<In,2>, i: u256): In { a[i].a = a[i].a + 1n; return a[i]; }
         get via(a: Arr<In,2>, i: u256): External<In> { return this.bump(a, i); } }`,
      `${SIN}
       contract C {
         function bump(In[2] memory a, uint256 i) internal pure returns (In memory) { a[i].a = a[i].a + 1; return a[i]; }
         function via(In[2] calldata a, uint256 i) external pure returns (In memory) { return bump(a, i); } }`,
    );
    const body = W(0x1111) + W(0x2222) + W(0x3333) + W(0x4444);
    const sig = 'via((uint256,uint256)[2],uint256)';
    const { j } = await expectSame(a, sig, body + W(1));
    expect(j.r).toBe('0x' + W(0x3334) + W(0x4444)); // a incremented, b unchanged, non-zero
  });

  it('dirty struct-field word trap is preserved (bool field validated lazily like solc)', async () => {
    const a = await pair(
      `type F = { on: bool; k: u256 };
       class C {
         getK(a: Arr<F,2>, i: u256): u256 { return a[i].k; }
         get via(a: Arr<F,2>, i: u256): External<u256> { return this.getK(a, i); } }`,
      `struct F { bool on; uint256 k; }
       contract C {
         function getK(F[2] memory a, uint256 i) internal pure returns (uint256) { return a[i].k; }
         function via(F[2] calldata a, uint256 i) external pure returns (uint256) { return getK(a, i); } }`,
    );
    const sig = 'via((bool,uint256)[2],uint256)';
    const { j } = await expectSame(a, sig, W(1) + W(0x11) + W(0) + W(0x22) + W(1)); // clean
    expect(j.r).toBe('0x' + W(0x22));
    await expectSame(a, sig, W(2) + W(0x11) + W(0) + W(0x22) + W(1)); // dirty bool word -> match solc
  });
});

describe('CONTROLS: the shared internal-arg path stays byte-identical (no regression)', () => {
  it('flat static struct forwarded as an internal arg (still the FLAT copy)', async () => {
    const a = await pair(
      `type Nest = { x: u256; y: u256; z: u256 };
       class C {
         ident(n: Nest): Nest { return n; }
         get via(n: Nest): External<Nest> { return this.ident(n); } }`,
      `struct Nest { uint256 x; uint256 y; uint256 z; }
       contract C {
         function ident(Nest memory n) internal pure returns (Nest memory) { return n; }
         function via(Nest calldata n) external pure returns (Nest memory) { return ident(n); } }`,
    );
    const { j } = await expectSame(a, 'via((uint256,uint256,uint256))', W(0xa) + W(0xb) + W(0xc));
    expect(j.r).toBe('0x' + W(0xa) + W(0xb) + W(0xc));
  });

  it('value fixed array Arr<u256,3> internal-arg (still flat inline, memStaticElem undefined)', async () => {
    const a = await pair(
      `class C {
         pick(a: Arr<u256,3>, i: u256): u256 { return a[i]; }
         get via(a: Arr<u256,3>, i: u256): External<u256> { return this.pick(a, i); } }`,
      `contract C {
         function pick(uint256[3] memory a, uint256 i) internal pure returns (uint256) { return a[i]; }
         function via(uint256[3] calldata a, uint256 i) external pure returns (uint256) { return pick(a, i); } }`,
    );
    const { j } = await expectSame(a, 'via(uint256[3],uint256)', W(0xaa) + W(0xbb) + W(0xcc) + W(2));
    expect(j.r).toBe('0x' + W(0xcc));
  });

  it('calldata dyn-field struct internal-arg (pointer-headed dyn image, unchanged path)', async () => {
    const a = await pair(
      `type D = { s: string; k: u256 };
       class C {
         getK(d: D): u256 { return d.k; }
         get via(d: D): External<u256> { return this.getK(d); } }`,
      `struct D { string s; uint256 k; }
       contract C {
         function getK(D memory d) internal pure returns (uint256) { return d.k; }
         function via(D calldata d) external pure returns (uint256) { return getK(d); } }`,
    );
    // d is a DYNAMIC struct param: an outer offset (0x20) to the tuple, then the tuple
    // (string field offset 0x40 within the tuple, k, then the string [len][data]).
    const cd = W(0x20) + W(0x40) + W(0x99) + W(3) + '6162630000000000000000000000000000000000000000000000000000000000';
    const { j } = await expectSame(a, 'via((string,uint256))', cd);
    expect(j.r).toBe('0x' + W(0x99));
  });

  it('calldata dyn value-array u256[] internal-arg (calldataArray path, unchanged)', async () => {
    const a = await pair(
      `class C {
         at(a: u256[], i: u256): u256 { return a[i]; }
         get via(a: u256[], i: u256): External<u256> { return this.at(a, i); } }`,
      `contract C {
         function at(uint256[] memory a, uint256 i) internal pure returns (uint256) { return a[i]; }
         function via(uint256[] calldata a, uint256 i) external pure returns (uint256) { return at(a, i); } }`,
    );
    const { j } = await expectSame(a, 'via(uint256[],uint256)', W(0x40) + W(1) + W(2) + W(0xde) + W(0xad));
    expect(j.r).toBe('0x' + W(0xad));
  });

  it('struct-from-literals internal-arg (allocAggToMem path, unchanged)', async () => {
    const a = await pair(
      `type P = { a: u256; b: u256 };
       class C {
         getA(p: P): u256 { return p.a; }
         get via(): External<u256> { return this.getA(P(0x33n, 0x44n)); } }`,
      `struct P { uint256 a; uint256 b; }
       contract C {
         function getA(P memory p) internal pure returns (uint256) { return p.a; }
         function via() external pure returns (uint256) { return getA(P(0x33, 0x44)); } }`,
    );
    const { j } = await expectSame(a, 'via()', '');
    expect(j.r).toBe('0x' + W(0x33));
  });

  it('memory-local Arr<In,2> (built from literals) internal-arg still MATCHes', async () => {
    const a = await pair(
      `${IN}
       class C {
         pick2(a: Arr<In,2>, i: u256): In { return a[i]; }
         get via(i: u256): External<In> { let m: Arr<In,2> = [ In(0x1111n, 0x2222n), In(0x3333n, 0x4444n) ]; return this.pick2(m, i); } }`,
      `${SIN}
       contract C {
         function pick2(In[2] memory a, uint256 i) internal pure returns (In memory) { return a[i]; }
         function via(uint256 i) external pure returns (In memory) { In[2] memory m = [In(0x1111, 0x2222), In(0x3333, 0x4444)]; return pick2(m, i); } }`,
    );
    const { j } = await expectSame(a, 'via(uint256)', W(1));
    expect(j.r).toBe('0x' + W(0x3333) + W(0x4444));
  });

  it('return a / abi.encode(a) / a[i] / a[i].a whole-param echo paths still MATCH', async () => {
    const args = W(0x1111) + W(0x2222) + W(0x3333) + W(0x4444) + W(1);
    const retA = await pair(
      `${IN}
       class C { get f(a: Arr<In,2>, i: u256): External<Arr<In,2>> { return a; } }`,
      `${SIN}
       contract C { function f(In[2] calldata a, uint256 i) external pure returns (In[2] memory) { return a; } }`,
    );
    await expectSame(retA, 'f((uint256,uint256)[2],uint256)', args);
    const enc = await pair(
      `${IN}
       class C { get f(a: Arr<In,2>, i: u256): External<bytes> { return abi.encode(a); } }`,
      `${SIN}
       contract C { function f(In[2] calldata a, uint256 i) external pure returns (bytes memory) { return abi.encode(a); } }`,
    );
    await expectSame(enc, 'f((uint256,uint256)[2],uint256)', args);
    const elem = await pair(
      `${IN}
       class C { get f(a: Arr<In,2>, i: u256): External<In> { return a[i]; } }`,
      `${SIN}
       contract C { function f(In[2] calldata a, uint256 i) external pure returns (In memory) { return a[i]; } }`,
    );
    const { j } = await expectSame(elem, 'f((uint256,uint256)[2],uint256)', args);
    expect(j.r).toBe('0x' + W(0x3333) + W(0x4444));
    const fld = await pair(
      `${IN}
       class C { get f(a: Arr<In,2>, i: u256): External<u256> { return a[i].a; } }`,
      `${SIN}
       contract C { function f(In[2] calldata a, uint256 i) external pure returns (uint256) { return a[i].a; } }`,
    );
    const r = await expectSame(fld, 'f((uint256,uint256)[2],uint256)', args);
    expect(r.j.r).toBe('0x' + W(0x3333));
  });
});
