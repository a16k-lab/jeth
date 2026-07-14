// RECURSIVE-REF-STRUCT (JETH013 lift, 2026-07-14). A struct that references itself (directly or mutually)
// through a REFERENCE-type field (a dynamic array `P[]` or a mapping value) is accepted, byte-identical to
// solc: two-phase struct registration (shells -> resolve -> cycle-classify -> gate) + a `recursiveRef`
// sentinel that breaks the object-graph back-edge so every compile-time type-walk terminates. A by-value
// self-cycle stays a clean reject (JETH487 = solc "Recursive struct definition"). Only the storage var +
// static-value-leaf surface is proven byte-identical here; the ABI/memory/kids-codec consumers that solc
// also rejects stay rejected, and the ones solc accepts but JETH scopes out stay clean over-rejections.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector, keccak } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const hx = (s: string) => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));
const th = (u: Uint8Array) => Buffer.from(u).toString('hex');
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e;
  }
};

describe('RECURSIVE-REF-STRUCT: self / mutual reference through a P[] / mapping field', () => {
  it('storage var + static-leaf read/write + auto-getter are byte-identical to solc', async () => {
    const J = `type P = { x: u256; kids: P[] };\nclass C { p: Visible<P>; setx(v: u256): External<void> { this.p.x = v; } get gx(): External<u256> { return this.p.x; } }`;
    const S = `contract C { struct P { uint256 x; P[] kids; } P public p; function setx(uint256 v) external { p.x = v; } function gx() external view returns(uint256){ return p.x; } }`;
    expect(codes(J)).toEqual([]);
    const h = await Harness.create();
    const aj = await h.deploy(bc(J));
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const stor = async (a: any, slot: bigint) => th(await h.evm.stateManager.getStorage(a, hx(pad32(slot))));
    for (const v of [7n, 0xdeadbeefcafef00d12345n, (1n << 256n) - 1n]) {
      const rj = await h.call(aj, sel('setx(uint256)') + W(v));
      const rs = await h.call(as, sel('setx(uint256)') + W(v));
      expect(rj.success).toBe(rs.success);
      expect(await stor(aj, 0n)).toBe(await stor(as, 0n)); // p.x
      expect(await stor(aj, 1n)).toBe(await stor(as, 1n)); // kids head stays 0 in both
      expect((await h.call(aj, sel('gx()'))).returnHex).toBe((await h.call(as, sel('gx()'))).returnHex);
      expect((await h.call(aj, sel('p()'))).returnHex).toBe((await h.call(as, sel('p()'))).returnHex);
    }
  });

  it('top-level P[] of a recursive struct: push/index/read/length byte-identical (incl. raw storage)', async () => {
    const J = `type P = { x: u256; kids: P[] };\nclass C { ps: P[]; pu(): External<void> { this.ps.push(); } s(i: u256, v: u256): External<void> { this.ps[i].x = v; } get g(i: u256): External<u256> { return this.ps[i].x; } get l(): External<u256> { return this.ps.length; } }`;
    const S = `contract C { struct P { uint256 x; P[] kids; } P[] ps; function pu() external { ps.push(); } function s(uint256 i, uint256 v) external { ps[i].x = v; } function g(uint256 i) external view returns(uint256){ return ps[i].x; } function l() external view returns(uint256){ return ps.length; } }`;
    expect(codes(J)).toEqual([]);
    const h = await Harness.create();
    const aj = await h.deploy(bc(J));
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const stor = async (a: any, slot: bigint) => th(await h.evm.stateManager.getStorage(a, hx(pad32(slot))));
    for (const seq of [['pu()'], ['pu()'], ['s(uint256,uint256)', 0, 0xaa11n], ['s(uint256,uint256)', 1, 0xbb22n]] as const) {
      const [f, ...a] = seq;
      const cd = sel(f as string) + (a as (number | bigint)[]).map(W).join('');
      expect((await h.call(aj, cd)).success).toBe((await h.call(as, cd)).success);
    }
    expect((await h.call(aj, sel('l()'))).returnHex).toBe((await h.call(as, sel('l()'))).returnHex);
    for (const i of [0n, 1n]) {
      expect((await h.call(aj, sel('g(uint256)') + W(i))).returnHex).toBe((await h.call(as, sel('g(uint256)') + W(i))).returnHex);
    }
    const base = BigInt('0x' + th(keccak(hx(pad32(0n)))));
    for (let i = 0; i < 6; i++) expect(await stor(aj, base + BigInt(i))).toBe(await stor(as, base + BigInt(i)));
  });

  it('mutual reference cycle + mapping-field self-reference: static-leaf read byte-identical', async () => {
    const h = await Harness.create();
    const stor = async (a: any, slot: bigint) => th(await h.evm.stateManager.getStorage(a, hx(pad32(slot))));
    const run = async (J: string, S: string) => {
      expect(codes(J)).toEqual([]);
      const aj = await h.deploy(bc(J));
      const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
      await h.call(aj, sel('s(uint256)') + W(0x1234n));
      await h.call(as, sel('s(uint256)') + W(0x1234n));
      expect((await h.call(aj, sel('g()'))).returnHex).toBe((await h.call(as, sel('g()'))).returnHex);
      expect(await stor(aj, 0n)).toBe(await stor(as, 0n));
    };
    await run(
      `type A = { x: u256; bs: B[] }; type B = { y: u256; as: A[] };\nclass C { a: A; s(v: u256): External<void> { this.a.x = v; } get g(): External<u256> { return this.a.x; } }`,
      `contract C { struct A { uint256 x; B[] bs; } struct B { uint256 y; A[] as_; } A a; function s(uint256 v) external { a.x = v; } function g() external view returns(uint256){ return a.x; } }`,
    );
    await run(
      `type Q = { x: u256; m: mapping<u256, Q> };\nclass C { q: Q; s(v: u256): External<void> { this.q.x = v; } get g(): External<u256> { return this.q.x; } }`,
      `contract C { struct Q { uint256 x; mapping(uint256=>Q) m; } Q q; function s(uint256 v) external { q.x = v; } function g() external view returns(uint256){ return q.x; } }`,
    );
  });

  it('forward / later-declared struct references now resolve (acyclic), byte-identical', async () => {
    const J = `type A = { b: B; z: u256 }; type B = { x: u256 };\nclass C { a: A; s(v: u256): External<void> { this.a.b.x = v; } get g(): External<u256> { return this.a.b.x; } }`;
    const S = `contract C { struct A { B b; uint256 z; } struct B { uint256 x; } A a; function s(uint256 v) external { a.b.x = v; } function g() external view returns(uint256){ return a.b.x; } }`;
    expect(codes(J)).toEqual([]);
    const h = await Harness.create();
    const aj = await h.deploy(bc(J));
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, sel('s(uint256)') + W(0x555n));
    await h.call(as, sel('s(uint256)') + W(0x555n));
    expect((await h.call(aj, sel('g()'))).returnHex).toBe((await h.call(as, sel('g()'))).returnHex);
  });

  it('by-value self-recursion stays a clean reject (JETH487 = solc "Recursive struct definition")', () => {
    expect(codes(`type P = { x: u256; next: P }; class C { p: P; }`)).toContain('JETH487');
    expect(codes(`type P = { x: u256; kids: Arr<P,2> }; class C { p: P; }`)).toContain('JETH487');
    expect(codes(`type A = { b: B }; type B = { a: A }; class C { a: A; }`)).toContain('JETH487');
    expect(codes(`type P = { self: P; other: P[] }; class C { p: P; }`)).toContain('JETH487');
    expect(codes(`type A = { b: B }; type B = { c: C2 }; type C2 = { a: A }; class C { a: A; }`)).toContain('JETH487');
  });

  it('consumers solc ALSO rejects stay rejected; only the memory-codec ones remain clean over-rejections', () => {
    const P = 'type P = { x: u256; kids: P[] };';
    // solc rejects these too (recursive type in ABI / cannot encode / event) -> JETH reject is byte-identical.
    expect(codes(`${P} class C { p: P; g(): External<P> { return this.p; } }`).length).toBeGreaterThan(0);
    expect(codes(`${P} class C { p: P; g(): External<bytes> { return abi.encode(this.p); } }`).length).toBeGreaterThan(0);
    // abi.encode of the bare recursive FIELD `p.kids` (a P[] whose element is a recursiveRef sentinel): solc
    // "This type cannot be encoded". Previously slipped through the `t.kind === 'array'` encode clause (a
    // pre-existing over-acceptance); now gated by typeContainsRecursiveRef. Standard + packed both reject.
    expect(codes(`${P} class C { p: P; get g(): External<bytes> { return abi.encode(this.p.kids); } }`)).toContain('JETH173');
    expect(codes(`${P} class C { p: P; get g(): External<bytes> { return abi.encodePacked(this.p.kids); } }`)).toContain('JETH173');
    expect(codes(`${P} class C { E: event<{ p: P }>; p: P; g(): External<void> { emit(this.E(this.p)); } }`).length).toBeGreaterThan(0);
    // The STORAGE index-into-recursive-field surface is now LIFTED (byte-identical, proven below). What solc
    // ACCEPTS but JETH still scopes out are the MEMORY-codec consumers: a whole recursive struct-element copy,
    // a `P` memory local, and an internal `P` memory return (the recursive image codec is a separate step).
    expect(codes(`${P} class C { p: P; get g(i: u256): External<u256> { let m = this.p.kids[i]; return m.x; } }`).length).toBeGreaterThan(0);
    expect(codes(`${P} class C { g(): External<u256> { let m: P; return m.x; } }`).length).toBeGreaterThan(0);
    expect(codes(`${P} class C { p: P; h(): P { return this.p; } g(): External<u256> { return this.h().x; } }`).length).toBeGreaterThan(0);
  });

  it('LIFTED: index a recursive field p.kids[i].x reached via struct-fields (read/write/push/pop/length) byte-identical', async () => {
    // The recursiveRef sentinel's stub stride (1) is resolved back to the real struct's finite slot count when
    // the recursive array is reached through STRUCT-FIELDS ONLY (no poppable/deletable container above it):
    // element addressing + the single-level push/pop clear then match solc exactly (incl. clearing a DIRTIED
    // element on pop). A recursive field UNDER a container (ps[i].kids, m[k].kids, p.kids[i].kids) stays a
    // clean over-rejection (JETH210) because solc's pop/delete of the container would deep-clear the recursive
    // sub-array - a recursion JETH's static clear cannot emit. `w` covers the value-leaf write; the second
    // struct-var `w2` proves a recursive field one static-struct hop down (o.p.kids[i].x) also lifts.
    const J = `type P = { x: u256; kids: P[] }; type O = { p: P };
class C { p: P; o: O;
  pu(): External<void> { this.p.kids.push(); }
  po(): External<void> { this.p.kids.pop(); }
  w(i: u256, v: u256): External<void> { this.p.kids[i].x = v; }
  puo(): External<void> { this.o.p.kids.push(); }
  w2(i: u256, v: u256): External<void> { this.o.p.kids[i].x = v; }
  get g(i: u256): External<u256> { return this.p.kids[i].x; }
  get g2(i: u256): External<u256> { return this.o.p.kids[i].x; }
  get l(): External<u256> { return this.p.kids.length; } }`;
    const S = `contract C { struct P { uint256 x; P[] kids; } struct O { P p; } P p; O o;
  function pu() external { p.kids.push(); }
  function po() external { p.kids.pop(); }
  function w(uint256 i,uint256 v) external { p.kids[i].x=v; }
  function puo() external { o.p.kids.push(); }
  function w2(uint256 i,uint256 v) external { o.p.kids[i].x=v; }
  function g(uint256 i) external view returns(uint256){ return p.kids[i].x; }
  function g2(uint256 i) external view returns(uint256){ return o.p.kids[i].x; }
  function l() external view returns(uint256){ return p.kids.length; } }`;
    expect(codes(J)).toEqual([]);
    const h = await Harness.create();
    const aj = await h.deploy(bc(J));
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const stor = async (a: any, slot: bigint) => th(await h.evm.stateManager.getStorage(a, hx(pad32(slot))));
    const run = async (f: string, ...a: (number | bigint)[]) => {
      const cd = sel(f) + a.map(W).join('');
      const rj = await h.call(aj, cd), rs = await h.call(as, cd);
      expect(rj.success).toBe(rs.success);
    };
    // populate + write DISTINCT + DIRTY-high-bit values, then pop a DIRTIED element and re-push (must zero).
    const script: [string, ...(number | bigint)[]][] = [
      ['pu()'], ['pu()'], ['pu()'],
      ['w(uint256,uint256)', 0, 0xdeadn], ['w(uint256,uint256)', 1, (1n << 256n) - 1n], ['w(uint256,uint256)', 2, (1n << 255n) + 9n],
      ['po()'], ['pu()'], ['w(uint256,uint256)', 2, 0x1234n], // pop the dirtied tail, re-push -> index 2 must re-zero
      ['puo()'], ['puo()'], ['w2(uint256,uint256)', 0, 0xabcn], ['w2(uint256,uint256)', 1, 0xf00dn],
    ];
    for (const [f, ...a] of script) await run(f, ...a);
    for (const i of [0n, 1n, 2n]) expect((await h.call(aj, sel('g(uint256)') + W(i))).returnHex).toBe((await h.call(as, sel('g(uint256)') + W(i))).returnHex);
    for (const i of [0n, 1n]) expect((await h.call(aj, sel('g2(uint256)') + W(i))).returnHex).toBe((await h.call(as, sel('g2(uint256)') + W(i))).returnHex);
    expect((await h.call(aj, sel('l()'))).returnHex).toBe((await h.call(as, sel('l()'))).returnHex);
    // raw-storage compare across p.kids data (slots 0,1 + keccak(1)+0..7) and o.p.kids data (o at slot 2 => o.p.kids head slot 3, data keccak(3)+0..5).
    const KEC = (slot: bigint) => BigInt('0x' + th(keccak(hx(pad32(slot)))));
    const slots = new Set<bigint>([0n, 1n, 2n, 3n]);
    const K1 = KEC(1n);
    for (let i = 0; i < 8; i++) slots.add(K1 + BigInt(i));
    const Ko = KEC(3n);
    for (let i = 0; i < 6; i++) slots.add(Ko + BigInt(i));
    for (const s of slots) expect(await stor(aj, s)).toBe(await stor(as, s));
    // OOB index reverts identically (dynamic-array bound).
    const oj = await h.call(aj, sel('g(uint256)') + W(50)), os = await h.call(as, sel('g(uint256)') + W(50));
    expect(oj.success).toBe(os.success);
  });

  it('recursive field UNDER a poppable/deletable container stays a clean over-rejection (deep-clear soundness)', () => {
    const P = 'type P = { x: u256; kids: P[] };';
    // solc ACCEPTS all of these; JETH scopes them out (JETH210) so that no recursive sub-array is ever
    // populated inside a container whose pop()/delete would need a recursive deep-clear JETH cannot emit.
    expect(codes(`${P} class C { ps: P[]; w(i: u256, j: u256, v: u256): External<void> { this.ps[i].kids[j].x = v; } }`).length).toBeGreaterThan(0); // under a dynamic array
    expect(codes(`${P} class C { ps: P[]; get g(i: u256, j: u256): External<u256> { return this.ps[i].kids[j].x; } }`).length).toBeGreaterThan(0);
    expect(codes(`type P = { x: u256; kids: P[] };\nclass C { m: mapping<u256, P>; w(k: u256, i: u256, v: u256): External<void> { this.m[k].kids[i].x = v; } }`).length).toBeGreaterThan(0); // under a mapping value
    expect(codes(`${P} class C { p: P; w(i: u256, j: u256, v: u256): External<void> { this.p.kids[i].kids[j].x = v; } }`).length).toBeGreaterThan(0); // nested recursive (under the outer kids element)
    expect(codes(`${P} class C { p: P; f(i: u256): External<void> { this.p.kids[i].kids.push(); } }`).length).toBeGreaterThan(0); // nested push
  });

  it('recursive kids field: push()/pop()/length + whole-struct storage copy are byte-identical', async () => {
    const J = `type P = { x: u256; kids: P[] };\nclass C { p: P; q: P; puq(): External<void> { this.q.kids.push(); } setqx(v: u256): External<void> { this.q.x = v; } po(): External<void> { this.q.kids.pop(); } cp(): External<void> { this.p = this.q; } get gl(): External<u256> { return this.q.kids.length; } get gpx(): External<u256> { return this.p.x; } }`;
    const S = `contract C { struct P { uint256 x; P[] kids; } P p; P q; function puq() external { q.kids.push(); } function setqx(uint256 v) external { q.x = v; } function po() external { q.kids.pop(); } function cp() external { p = q; } function gl() external view returns(uint256){ return q.kids.length; } function gpx() external view returns(uint256){ return p.x; } }`;
    expect(codes(J)).toEqual([]);
    const h = await Harness.create();
    const aj = await h.deploy(bc(J));
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const stor = async (a: any, slot: bigint) => th(await h.evm.stateManager.getStorage(a, hx(pad32(slot))));
    for (const op of ['puq()', 'puq()', 'puq()', 'po()']) { await h.call(aj, sel(op)); await h.call(as, sel(op)); }
    await h.call(aj, sel('setqx(uint256)') + W(0xc0ffeen));
    await h.call(as, sel('setqx(uint256)') + W(0xc0ffeen));
    expect((await h.call(aj, sel('gl()'))).returnHex).toBe((await h.call(as, sel('gl()'))).returnHex);
    await h.call(aj, sel('cp()')); await h.call(as, sel('cp()'));
    expect((await h.call(aj, sel('gpx()'))).returnHex).toBe((await h.call(as, sel('gpx()'))).returnHex);
    // raw storage of the copied p region + its kids data slots
    expect(await stor(aj, 0n)).toBe(await stor(as, 0n));
    expect(await stor(aj, 1n)).toBe(await stor(as, 1n));
    const pkb = BigInt('0x' + th(keccak(hx(pad32(1n)))));
    for (let i = 0; i < 6; i++) expect(await stor(aj, pkb + BigInt(i))).toBe(await stor(as, pkb + BigInt(i)));
  });
});
