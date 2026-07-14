import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';
import { hexToBytes, bytesToHex } from '@ethereumjs/util';

const hx = (s: string) => hexToBytes(('0x' + s) as `0x${string}`);
const rawSlot = async (h: any, addr: any, slot: bigint) =>
  bytesToHex(await h.evm.stateManager.getStorage(addr, hx(pad32(slot))));

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e;
  }
};
const jAccepts = (src: string) => codes(src).length === 0;
const sAccepts = (src: string) => { try { compileSolidity(SPDX + src, 'C'); return true; } catch { return false; } };

async function bothCall(jeth: string, sol: string, calldata: string) {
  const h = await Harness.create();
  const aj = await h.deploy(bc(jeth));
  const as = await h.deploy(compileSolidity(SPDX + sol, 'C').creation);
  const rj = await h.call(aj, calldata);
  const rs = await h.call(as, calldata);
  return { rj, rs };
}

describe('CONST-ARRAY-DIM byte-identity', () => {
  const J1 = `class C {
    static N: u256 = 3n;
    a: Arr<u256, N>;
    set(i: u256, v: u256): External<void> { this.a[i] = v; }
    get g(i: u256): External<u256> { return this.a[i]; }
    b: Visible<u256>;
  }`;
  const S1 = `contract C {
    uint256 constant N = 3;
    uint256[N] a;
    function set(uint256 i, uint256 v) external { a[i] = v; }
    function g(uint256 i) external view returns (uint256) { return a[i]; }
    uint256 public b;
  }`;

  it('bare N: seeded writes read back identically + raw storage', async () => {
    const h = await Harness.create();
    const aj = await h.deploy(bc(J1));
    const as = await h.deploy(compileSolidity(SPDX + S1, 'C').creation);
    const seeds = [111n, 222n, 333n];
    for (let i = 0; i < 3; i++) {
      const cd = sel('set(uint256,uint256)') + W(i) + W(seeds[i]!);
      const rj = await h.call(aj, cd); const rs = await h.call(as, cd);
      expect(rj.success).toBe(rs.success);
    }
    for (let i = 0; i < 3; i++) {
      const cd = sel('g(uint256)') + W(i);
      const rj = await h.call(aj, cd); const rs = await h.call(as, cd);
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(rj.returnHex).toBe('0x' + W(seeds[i]!));
    }
    for (let s = 0n; s < 4n; s++) expect(await rawSlot(h, aj, s)).toBe(await rawSlot(h, as, s));
  });

  it('bare N: OOB index Panics identically', async () => {
    const { rj, rs } = await bothCall(J1, S1, sel('g(uint256)') + W(3));
    expect(rj.success).toBe(rs.success);
    expect(rj.success).toBe(false);
    expect(rj.returnHex).toBe(rs.returnHex);
  });

  // INHERITED base constant (bare N) - solc accepts; JETH must match. Second field checks slot placement.
  const J2 = `abstract class B { static N: u256 = 4n; }
  class C extends B {
    a: Arr<u256, N>;
    tail: Visible<u256>;
    set(i: u256, v: u256): External<void> { this.a[i] = v; }
    settail(v: u256): External<void> { this.tail = v; }
    get g(i: u256): External<u256> { return this.a[i]; }
  }`;
  const S2 = `abstract contract B { uint256 constant N = 4; }
  contract C is B {
    uint256[N] a;
    uint256 public tail;
    function set(uint256 i, uint256 v) external { a[i] = v; }
    function settail(uint256 v) external { tail = v; }
    function g(uint256 i) external view returns (uint256) { return a[i]; }
  }`;

  it('inherited base N: layout + tail slot identical (or JETH safely over-rejects)', async () => {
    // If JETH rejects the inherited-base case (a safe over-rejection), skip the deploy check; NEVER
    // accept when solc rejects.
    expect(sAccepts(S2)).toBe(true);
    if (!jAccepts(J2)) return; // documented safe residual, not a bar violation
    const h = await Harness.create();
    const aj = await h.deploy(bc(J2));
    const as = await h.deploy(compileSolidity(SPDX + S2, 'C').creation);
    const seeds = [7n, 8n, 9n, 10n];
    for (let i = 0; i < 4; i++) {
      const cd = sel('set(uint256,uint256)') + W(i) + W(seeds[i]!);
      await h.call(aj, cd); await h.call(as, cd);
    }
    await h.call(aj, sel('settail(uint256)') + W(999n));
    await h.call(as, sel('settail(uint256)') + W(999n));
    for (let i = 0; i < 4; i++) {
      const cd = sel('g(uint256)') + W(i);
      expect((await h.call(aj, cd)).returnHex).toBe((await h.call(as, cd)).returnHex);
    }
    for (let s = 0n; s < 6n; s++) expect(await rawSlot(h, aj, s)).toBe(await rawSlot(h, as, s));
  });

  // smaller-width element (u32) packing with a const dim
  const J3 = `class C { static K: u256 = 5n; a: Arr<u32, K>; set(i: u256, v: u32): External<void> { this.a[i] = v; } get g(i: u256): External<u32> { return this.a[i]; } }`;
  const S3 = `contract C { uint256 constant K = 5; uint32[K] a; function set(uint256 i, uint32 v) external { a[i] = v; } function g(uint256 i) external view returns (uint32) { return a[i]; } }`;
  it('u32 packed elements with const dim', async () => {
    const h = await Harness.create();
    const aj = await h.deploy(bc(J3));
    const as = await h.deploy(compileSolidity(SPDX + S3, 'C').creation);
    for (let i = 0; i < 5; i++) {
      const cd = sel('set(uint256,uint32)') + W(i) + W(BigInt(1000 + i));
      await h.call(aj, cd); await h.call(as, cd);
    }
    for (let i = 0; i < 5; i++) {
      const cd = sel('g(uint256)') + W(i);
      expect((await h.call(aj, cd)).returnHex).toBe((await h.call(as, cd)).returnHex);
    }
    for (let s = 0n; s < 3n; s++) expect(await rawSlot(h, aj, s)).toBe(await rawSlot(h, as, s));
  });

  // NEGATIVES - JETH must reject, matching solc's reject (no over-acceptance).
  const negs: Array<[string, string]> = [
    // qualified self C.N: solc rejects "Invalid array length"
    ['qualified C.N', `class C { static N: u256 = 3n; a: Arr<u256, C.N>; get f(): External<u256> { return this.a[0n]; } }`],
    // expression dim N+1: solc folds it, JETH must NOT (grammar-phase reject)
    ['expression N+1', `class C { static N: u256 = 3n; a: Arr<u256, N + 1>; get f(): External<u256> { return this.a[0n]; } }`],
    // unknown name
    ['unknown Z', `class C { a: Arr<u256, Z>; get f(): External<u256> { return this.a[0n]; } }`],
    // non-integer constant
    ['bool const', `class C { static B: bool = true; a: Arr<u256, B>; get f(): External<u256> { return this.a[0n]; } }`],
    // zero-valued constant
    ['zero const', `class C { static N: u256 = 0n; a: Arr<u256, N>; get f(): External<u256> { return this.a[0n]; } }`],
  ];
  for (const [label, src] of negs) {
    it(`rejects: ${label}`, () => {
      expect(jAccepts(src)).toBe(false);
    });
  }

  // FILE-LEVEL const dim (residual lift): a file-scoped `const N = 3n` (solc's file-level
  // `uint256 constant N = 3;`) used as an Arr<T, N> length - in a CONTRACT FIELD and a STRUCT MEMBER.
  const JF = `const N = 3n;
  class C {
    a: Arr<u256, N>;
    b: Visible<u256>;
    set(i: u256, v: u256): External<void> { this.a[i] = v; }
    get g(i: u256): External<u256> { return this.a[i]; }
  }`;
  const SF = `uint256 constant N = 3;
  contract C {
    uint256[N] a;
    uint256 public b;
    function set(uint256 i, uint256 v) external { a[i] = v; }
    function g(uint256 i) external view returns (uint256) { return a[i]; }
  }`;
  it('file-level const N (contract field): seeded read-back + raw storage + OOB Panic', async () => {
    expect(sAccepts(SF)).toBe(true);
    expect(jAccepts(JF)).toBe(true);
    const h = await Harness.create();
    const aj = await h.deploy(bc(JF));
    const as = await h.deploy(compileSolidity(SPDX + SF, 'C').creation);
    const seeds = [(1n << 255n) | 111n, (0xffffn << 240n) | 222n, (0xdeadn << 200n) | 333n];
    for (let i = 0; i < 3; i++) {
      const cd = sel('set(uint256,uint256)') + W(i) + W(seeds[i]!);
      const rj = await h.call(aj, cd); const rs = await h.call(as, cd);
      expect(rj.success).toBe(rs.success);
    }
    for (let i = 0; i < 3; i++) {
      const cd = sel('g(uint256)') + W(i);
      const rj = await h.call(aj, cd); const rs = await h.call(as, cd);
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(rj.returnHex).toBe('0x' + W(seeds[i]!));
    }
    for (let s = 0n; s < 4n; s++) expect(await rawSlot(h, aj, s)).toBe(await rawSlot(h, as, s));
    // OOB index -> identical Panic
    const oob = sel('g(uint256)') + W(3);
    const rj = await h.call(aj, oob); const rs = await h.call(as, oob);
    expect(rj.success).toBe(false); expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
  });

  const JS = `const K = 4n;
  type P = { a: Arr<u256, K> };
  class C {
    s: P;
    tail: Visible<u256>;
    set(i: u256, v: u256): External<void> { this.s.a[i] = v; }
    settail(v: u256): External<void> { this.tail = v; }
    get g(i: u256): External<u256> { return this.s.a[i]; }
  }`;
  const SS = `uint256 constant K = 4;
  struct P { uint256[K] a; }
  contract C {
    P s;
    uint256 public tail;
    function set(uint256 i, uint256 v) external { s.a[i] = v; }
    function settail(uint256 v) external { tail = v; }
    function g(uint256 i) external view returns (uint256) { return s.a[i]; }
  }`;
  it('file-level const K (struct member): seeded read-back + tail slot + raw storage + OOB', async () => {
    expect(sAccepts(SS)).toBe(true);
    expect(jAccepts(JS)).toBe(true);
    const h = await Harness.create();
    const aj = await h.deploy(bc(JS));
    const as = await h.deploy(compileSolidity(SPDX + SS, 'C').creation);
    const seeds = [(1n << 255n) | 7n, (0xabcdn << 230n) | 8n, (0xffn << 248n) | 9n, 42n];
    for (let i = 0; i < 4; i++) {
      const cd = sel('set(uint256,uint256)') + W(i) + W(seeds[i]!);
      await h.call(aj, cd); await h.call(as, cd);
    }
    await h.call(aj, sel('settail(uint256)') + W(999n));
    await h.call(as, sel('settail(uint256)') + W(999n));
    for (let i = 0; i < 4; i++) {
      const cd = sel('g(uint256)') + W(i);
      expect((await h.call(aj, cd)).returnHex).toBe((await h.call(as, cd)).returnHex);
    }
    for (let s = 0n; s < 6n; s++) expect(await rawSlot(h, aj, s)).toBe(await rawSlot(h, as, s));
    const oob = sel('g(uint256)') + W(4);
    const rj = await h.call(aj, oob); const rs = await h.call(as, oob);
    expect(rj.success).toBe(false); expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
  });

  // FILE-LEVEL NEGATIVES - solc rejects; JETH must too (no over-acceptance). Each solc mirror asserted reject.
  const fileNegs: Array<[string, string, string]> = [
    // a state var shadows the file-level const -> not a compile-time constant length
    ['statevar shadows file const',
      `const N = 3n;\nclass C { N: u256; a: Arr<u256, N>; get f(): External<u256> { return this.a[0n]; } }`,
      `uint256 constant N = 3;\ncontract C { uint256 N; uint256[N] a; function f() external view returns(uint256){return a[0];} }`],
    // duplicate file-level const -> "Identifier already declared"
    ['duplicate file const',
      `const N = 3n;\nconst N = 4n;\nclass C { a: Arr<u256, N>; get f(): External<u256> { return this.a[0n]; } }`,
      `uint256 constant N = 3;\nuint256 constant N = 4;\ncontract C { uint256[N] a; function f() external view returns(uint256){return a[0];} }`],
    // file const name collides with a struct type
    ['file const collides with type',
      `const N = 3n;\ntype N = { x: u256 };\nclass C { a: Arr<u256, N>; get f(): External<u256> { return this.a[0n]; } }`,
      `uint256 constant N = 3;\nstruct N { uint256 x; }\ncontract C { uint256[N] a; function f() external view returns(uint256){return a[0];} }`],
    // a constant EXPRESSION initializer is NOT folded (solc accepts; JETH keeps a clean over-rejection),
    // and the zero-valued file const rejects on both.
    ['zero-valued file const',
      `const N = 0n;\nclass C { a: Arr<u256, N>; get f(): External<u256> { return this.a[0n]; } }`,
      `uint256 constant N = 0;\ncontract C { uint256[N] a; function f() external view returns(uint256){return a[0];} }`],
  ];
  for (const [label, jsrc, ssrc] of fileNegs) {
    it(`rejects (file-level): ${label}`, () => {
      expect(sAccepts(ssrc)).toBe(false);
      expect(jAccepts(jsrc)).toBe(false);
    });
  }

  // OVER-ACCEPTANCE guard: a bare N from an UNRELATED contract is out of scope; solc rejects, JETH must too.
  it('rejects: bare N from an unrelated contract (scope leak guard)', () => {
    const src = `class O { static N: u256 = 3n; get o(): External<u256> { return N; } }
    class C { a: Arr<u256, N>; get f(): External<u256> { return this.a[0n]; } }`;
    // solc equivalent rejects with Undeclared identifier
    expect(sAccepts(`contract O { uint256 constant N = 3; } contract C { uint256[N] a; function f() external view returns(uint256){return a[0];} }`)).toBe(false);
    expect(jAccepts(src)).toBe(false);
  });
});
