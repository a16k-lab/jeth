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
      `type A = { x: u256; bs: B[] }; type B = { y: u256; asF: A[] };\nclass C { a: A; s(v: u256): External<void> { this.a.x = v; } get g(): External<u256> { return this.a.x; } }`,
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

  it('consumers solc ALSO rejects stay rejected; index-into-recursive-field stays a clean over-rejection', () => {
    const P = 'type P = { x: u256; kids: P[] };';
    // solc rejects these too (recursive type in ABI / cannot encode / event) -> JETH reject is byte-identical.
    expect(codes(`${P} class C { p: P; g(): External<P> { return this.p; } }`).length).toBeGreaterThan(0);
    expect(codes(`${P} class C { p: P; g(): External<bytes> { return abi.encode(this.p); } }`).length).toBeGreaterThan(0);
    expect(codes(`${P} class C { E: event<{ p: P }>; p: P; g(): External<void> { emit(this.E(this.p)); } }`).length).toBeGreaterThan(0);
    // solc ACCEPTS these but JETH scopes them out (SAFE over-rejection, no miscompile): indexing INTO the
    // recursive field (its element is a sentinel), a memory local, and an internal memory return.
    expect(codes(`${P} class C { p: P; g(i: u256): External<u256> { return this.p.kids[i].x; } }`).length).toBeGreaterThan(0);
    expect(codes(`${P} class C { g(): External<u256> { let m: P; return m.x; } }`).length).toBeGreaterThan(0);
    expect(codes(`${P} class C { p: P; h(): P { return this.p; } g(): External<u256> { return this.h().x; } }`).length).toBeGreaterThan(0);
  });

  it('REC-STRUCT-MEMLOCAL: a recursive struct memory local stays a clean over-rejection (JETH495)', () => {
    // RULING (2026-07-16): this shape is a DELIBERATE DESIGN reject, not a "not supported yet" gap, so it
    // was reclassified off the generic JETH200/JETH074 catch-alls onto the targeted JETH495 (the Group-A
    // "Deliberate DESIGN rejects" family, alongside JETH492/493/494). DIAGNOSTIC-ONLY: the ACCEPT/REJECT
    // sets are unchanged (every shape below still rejects; only the code + message moved).
    // WITNESS (differential, populated 3-level tree): solc lowers `P memory m = p` to an UNBOUNDED
    // RUNTIME-RECURSIVE DEEP COPY of the whole tree (a pointer-headed memory image whose size depends on
    // every level's runtime array length; mutating m leaves storage untouched). JETH represents the
    // recursive back-edge as a `recursiveRef` EMPTY-FIELDS sentinel, deliberately engineered so no finite
    // compile-time codec walks it (isStaticType forced false, isDynStructLeaf / isDynStructElemArrayField /
    // isSupportedDynStructLocal all reject it). JETH has no runtime-recursive struct-copy codegen, so the
    // memory-local materialization is UNREPRODUCIBLE: admitting it would either drop the nested payload
    // (the sentinel stub lays out zero/one word per kids element - the exact silent miscompile that reverted
    // REC-STRUCT-CONSUMERS) or build a wrong image. A clean reject beats a miscompile; KEEP the reject.
    const P = 'type P = { x: u256; kids: P[] };';
    // (a) the exact item shape - storage-initialized memory local + static-value-leaf read (solc ACCEPTS).
    expect(codes(`${P} class C { p: P; get g(): External<u256> { let m: P = this.p; return m.x; } }`)).toEqual(['JETH495', 'JETH074']);
    // (b) uninitialized memory local; (c) deep recursive read - all reject.
    expect(codes(`${P} class C { get g(): External<u256> { let m: P; return m.x; } }`)).toEqual(['JETH495', 'JETH074']);
    expect(codes(`${P} class C { p: P; get g(): External<u256> { let m: P = this.p; return m.kids[0n].x; } }`)).toEqual(['JETH495', 'JETH074']);
    // (d) internal function returning P memory (solc ACCEPTS), in both the member-read and call-statement
    // forms. The trailing JETH074 in (a)-(c) is the cascade from reading `m.x` after the local was refused.
    expect(codes(`${P} class C { p: P; h(): P { return this.p; } get g(): External<u256> { return this.h().x; } }`)).toEqual(['JETH495']);
    expect(codes(`${P} class C { p: P; h(): P { return this.p; } f(): External<void> { this.h(); } }`)).toEqual(['JETH495']);
    // (e) constructor local.
    expect(codes(`${P} class C { p: P; constructor() { let m: P; } get g(): External<u256> { return this.p.x; } }`)).toEqual(['JETH495']);
    // NON-VACUITY: solc genuinely ACCEPTS the read shapes above (so these are real over-rejections, not
    // shapes solc also rejects) - proves the reject is a deliberate soundness choice, not a parser gap.
    const solcOk = (s: string) => { try { compileSolidity(SPDX + s, 'C'); return true; } catch { return false; } };
    expect(solcOk(`struct P { uint256 x; P[] kids; } contract C { P p; function g() external view returns (uint256) { P memory m = p; return m.x; } }`)).toBe(true);
    expect(solcOk(`struct P { uint256 x; P[] kids; } contract C { P p; function h() internal view returns (P memory) { return p; } function g() external view returns (uint256) { return h().x; } }`)).toBe(true);
    // REJECT-PARITY: the one memory->storage direction solc ALSO rejects (legacy: "Copying of type struct
    // P memory[] memory to storage is not supported") - JETH rejects it too, so no divergence there.
    expect(codes(`${P} class C { p: P; set(): External<void> { let m: P; this.p = m; } }`).length).toBeGreaterThan(0);
    expect(solcOk(`struct P { uint256 x; P[] kids; } contract C { P p; function set() external { P memory m; p = m; } }`)).toBe(false);
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
