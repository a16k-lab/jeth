// L7(a) LIFT: a DEAD-after aggregate-capture local folds into its already-accepted inline constructor form.
//
//   type In = { a: u256; b: u256 };
//   type S1 = { pre: Arr<In,2>; n: u256 };
//   class C { get f(): External<u256> {
//     let a: Arr<In,2> = [In(1n,2n), In(3n,4n)];   // a pure aggregate literal
//     let s: S1 = S1(a, 5n);                        // captured into a POINTER-HEADED static-struct fixed-array field
//     return s.pre[0n].a; } }                       // a DEAD after the ctor (its only use is the capture)
//
// solc stores a LIVE REFERENCE to `a` in s.pre; JETH's flat inline image cannot, so a NON-INLINE source was
// rejected (JETH465). But when `a` is DEAD after the ctor (referenced exactly once - the capture - never
// mutated, never read, never passed onward), neither `a[i]=..; read s.pre` NOR `s.pre[i]=..; read a` is
// reachable, so the alias is UNOBSERVABLE and a copy is byte-identical. The compiler folds `S1(a, N)` into
// `S1([In(1n,2n),In(3n,4n)], N)` verbatim at the IR level, so the emitted bytecode is sha256-identical to
// that already-accepted inline form (which is byte-identical to solc). A LIVE reference (mutated / read
// after, or used more than once, or an impure/order-dependent initializer) is NOT dead -> the JETH465
// reject is KEPT: lifting it would emit the copy solc's alias diverges from (the mutate-after decodes 99 in
// solc, 1 for a copy).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const bytes = (src: string): string => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};
async function decode(src: string, sig: string, args = ''): Promise<{ ok: boolean; hex: string }> {
  const h = await Harness.create();
  const a = await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode);
  const r = await h.call(a, sel(sig) + args);
  return { ok: r.success, hex: r.returnHex };
}
async function solDecode(src: string, sig: string, args = ''): Promise<bigint> {
  const h = await Harness.create();
  const a = await h.deploy(compileSolidity(SPDX + src, 'C').creation);
  const r = await h.call(a, sel(sig) + args);
  return BigInt(r.returnHex);
}
async function diff(J: string, S: string, calls: [string, string?][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, a] of calls) {
    const data = sel(sg) + (a || '');
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
  }
}

const IN = 'type In = { a: u256; b: u256 };\ntype S1 = { pre: Arr<In,2>; n: u256 };\ntype S2 = { n: u256; pre: Arr<In,2> };\n';
const SIN = 'struct In { uint256 a; uint256 b; }\nstruct S1 { In[2] pre; uint256 n; }\nstruct S2 { uint256 n; In[2] pre; }\n';

describe('L7(a): DEAD-after aggregate-capture local folds to the inline form', () => {
  it('the OR: accepts, byte-identical to the inline form AND to solc (run+decode)', async () => {
    const bound = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(1n,2n), In(3n,4n)]; let s: S1 = S1(a, 5n); return s.pre[0n].a; } }`;
    const inline = IN + `class C { get f(): External<u256> { let s: S1 = S1([In(1n,2n), In(3n,4n)], 5n); return s.pre[0n].a; } }`;
    const S = SIN + `contract C { function f() external pure returns (uint256) { In[2] memory a = [In(1,2), In(3,4)]; S1 memory s = S1(a, 5); return s.pre[0].a; } }`;
    expect(codes(bound)).toEqual([]);
    expect(bytes(bound)).toBe(bytes(inline)); // bytecode sha-identical to the already-accepted inline-literal form
    const r = await decode(bound, 'f()');
    expect(r.ok).toBe(true);
    expect(r.hex).toBe('0x' + pad32(1n)); // NON-VACUITY: reads the seeded value 1
    await diff(bound, S, [['f()', '']]);
  });

  it('folds regardless of field position, return target, and array size (each byte-identical to solc)', async () => {
    // last field (S2 = { n; pre })
    const lastB = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let s: S2 = S2(5n, a); return s.pre[1n].b; } }`;
    const lastI = IN + `class C { get f(): External<u256> { let s: S2 = S2(5n, [In(1n,2n),In(3n,4n)]); return s.pre[1n].b; } }`;
    const lastS = SIN + `contract C { function f() external pure returns (uint256) { In[2] memory a=[In(1,2),In(3,4)]; S2 memory s=S2(5,a); return s.pre[1].b; } }`;
    expect(codes(lastB)).toEqual([]);
    expect(bytes(lastB)).toBe(bytes(lastI));
    await diff(lastB, lastS, [['f()', '']]);

    // return s.n (the sibling field), read s.pre too
    const nB = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(7n,8n),In(3n,4n)]; let s: S1 = S1(a, 6n); return s.pre[0n].a + s.pre[1n].b + s.n; } }`;
    const nI = IN + `class C { get f(): External<u256> { let s: S1 = S1([In(7n,8n),In(3n,4n)], 6n); return s.pre[0n].a + s.pre[1n].b + s.n; } }`;
    const nS = SIN + `contract C { function f() external pure returns (uint256) { In[2] memory a=[In(7,8),In(3,4)]; S1 memory s=S1(a,6); return s.pre[0].a + s.pre[1].b + s.n; } }`;
    expect(codes(nB)).toEqual([]);
    expect(bytes(nB)).toBe(bytes(nI));
    await diff(nB, nS, [['f()', '']]);
  });

  it('two dead-after bound vars into two ctors each fold independently', async () => {
    const bound = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let b: Arr<In,2> = [In(5n,6n),In(7n,8n)]; let s: S1 = S1(a, 5n); let t: S2 = S2(6n, b); return s.pre[0n].a + t.pre[1n].b; } }`;
    const inline = IN + `class C { get f(): External<u256> { let s: S1 = S1([In(1n,2n),In(3n,4n)], 5n); let t: S2 = S2(6n, [In(5n,6n),In(7n,8n)]); return s.pre[0n].a + t.pre[1n].b; } }`;
    const S = SIN + `contract C { function f() external pure returns (uint256) { In[2] memory a=[In(1,2),In(3,4)]; In[2] memory b=[In(5,6),In(7,8)]; S1 memory s=S1(a,5); S2 memory t=S2(6,b); return s.pre[0].a + t.pre[1].b; } }`;
    expect(codes(bound)).toEqual([]);
    expect(bytes(bound)).toBe(bytes(inline));
    await diff(bound, S, [['f()', '']]);
  });

  it('folds inside a nested block (decl + capture both in the if branch)', async () => {
    const bound = IN + `class C { get f(c: bool): External<u256> { if (c) { let a: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let s: S1 = S1(a, 5n); return s.pre[0n].a; } return 0n; } }`;
    const inline = IN + `class C { get f(c: bool): External<u256> { if (c) { let s: S1 = S1([In(1n,2n),In(3n,4n)], 5n); return s.pre[0n].a; } return 0n; } }`;
    const S = SIN + `contract C { function f(bool c) external pure returns (uint256) { if (c) { In[2] memory a=[In(1,2),In(3,4)]; S1 memory s=S1(a,5); return s.pre[0].a; } return 0; } }`;
    expect(codes(bound)).toEqual([]);
    expect(bytes(bound)).toBe(bytes(inline));
    await diff(bound, S, [['f(bool)', pad32(1n)], ['f(bool)', pad32(0n)]]);
  });

  // ---------------- ESCAPE: the alias is observable, so the JETH465 reject is KEPT ----------------

  it('FAIL-FIRST: a MUTATED after the ctor - solc reads 99 through the alias; folding would emit a copy (1) => MISCOMPILE. KEPT REJECTED.', async () => {
    const bound = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(1n,2n), In(3n,4n)]; let s: S1 = S1(a, 5n); a[0n] = In(99n,99n); return s.pre[0n].a; } }`;
    const S = SIN + `contract C { function f() external pure returns (uint256) { In[2] memory a = [In(1,2), In(3,4)]; S1 memory s = S1(a, 5); a[0] = In(99,99); return s.pre[0].a; } }`;
    // The decoded direction that fixes the miscompile: solc = 99 (via the live alias), a copy would be 1.
    expect(await solDecode(S, 'f()')).toBe(99n);
    expect(codes(bound)).toContain('JETH465');
  });

  it('ESCAPE: a-element-field mutated after (a[0].a = ..) - KEPT REJECTED', () => {
    const bound = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(1n,2n), In(3n,4n)]; let s: S1 = S1(a, 5n); a[0n].a = 77n; return s.pre[0n].a; } }`;
    expect(codes(bound)).toContain('JETH465');
  });

  it('ESCAPE: s.pre mutated then a read (the reverse alias direction) - KEPT REJECTED', async () => {
    const bound = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(1n,2n), In(3n,4n)]; let s: S1 = S1(a, 5n); s.pre[0n] = In(88n,88n); return a[0n].a; } }`;
    const S = SIN + `contract C { function f() external pure returns (uint256) { In[2] memory a = [In(1,2), In(3,4)]; S1 memory s = S1(a, 5); s.pre[0] = In(88,88); return a[0].a; } }`;
    expect(await solDecode(S, 'f()')).toBe(88n); // solc: the write shows through the alias
    expect(codes(bound).length).toBeGreaterThan(0); // JETH keeps rejecting (never over-accepts)
    expect(codes(bound)).not.toEqual([]);
  });

  it('ESCAPE: a READ after the ctor - KEPT REJECTED', () => {
    const bound = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(1n,2n), In(3n,4n)]; let s: S1 = S1(a, 5n); return s.pre[0n].a + a[1n].b; } }`;
    expect(codes(bound)).toContain('JETH465');
  });

  it('ESCAPE: a aliased into another local (let x = a) - KEPT REJECTED', () => {
    const bound = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(1n,2n), In(3n,4n)]; let s: S1 = S1(a, 5n); let x: Arr<In,2> = a; return s.pre[0n].a + x[0n].b; } }`;
    expect(codes(bound)).toContain('JETH465');
  });

  it('ESCAPE: a passed onward (abi.encode(a)) - KEPT REJECTED', () => {
    const bound = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(1n,2n), In(3n,4n)]; let s: S1 = S1(a, 5n); let z: bytes = abi.encode(a); return s.pre[0n].a + u256(z.length); } }`;
    expect(codes(bound)).toContain('JETH465');
  });

  it('ESCAPE: a captured into TWO ctors (used more than once) - KEPT REJECTED', () => {
    const bound = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(1n,2n), In(3n,4n)]; let s: S1 = S1(a, 5n); let t: S1 = S1(a, 6n); return s.pre[0n].a + t.n; } }`;
    expect(codes(bound)).toContain('JETH465');
  });

  it('ESCAPE: an ORDER-DEPENDENT initializer (a state read) is not folded - KEPT REJECTED', () => {
    const bound = IN + `class C { z: u256 = 3n; get f(): External<u256> { let a: Arr<In,2> = [In(this.z,2n), In(3n,4n)]; let s: S1 = S1(a, 5n); return s.pre[0n].a; } }`;
    expect(codes(bound)).toContain('JETH465');
  });

  // ---------------- CONTROLS: families the fold must NOT touch ----------------

  it('CONTROL: a VALUE-array local (Arr<u256,2>) capture is OUTSIDE the L7a type gate - unchanged (still JETH465)', () => {
    // The fold's type gate is isStaticStructFixedLeafArray, which EXCLUDES value leaves (Arr<u256,N>).
    // That family keeps its existing reject; the fold conservatively does not widen to it.
    const J = `type P = { xs: Arr<u256,2>; n: u256 };\nclass C { get f(): External<u256> { let a: Arr<u256,2> = [u256(4n), 9n]; let p: P = P(a, 5n); return p.xs[1n] + p.n; } }`;
    expect(codes(J)).toContain('JETH465');
  });

  it('CONTROL: an unused aggregate local (zero uses) is untouched and still compiles', async () => {
    const J = IN + `class C { get f(): External<u256> { let a: Arr<In,2> = [In(1n,2n), In(3n,4n)]; return 42n; } }`;
    const S = SIN + `contract C { function f() external pure returns (uint256) { In[2] memory a = [In(1,2), In(3,4)]; return 42; } }`;
    expect(codes(J)).toEqual([]);
    await diff(J, S, [['f()', '']]);
  });
});
