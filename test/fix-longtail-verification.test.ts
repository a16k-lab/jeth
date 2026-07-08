// Bar-violation fixes found by the long-tail campaign's final adversarial verification workflow
// (429 differential cases, every finding adversarially re-verified). Three confirmed violations,
// all closed here, byte-identical to solc 0.8.35:
//
// MC-MEMARR-BYTES-WRITE (silent miscompile, campaign-exposed): a byte write into a plain `bytes`
//   FIELD of a MEMORY struct-ARRAY element (xs[i].b[j] = v, xs: Arr<Q,N> / Q[]) compiled and ran
//   but the mstore8 never landed (the element-rooted field chain fell to the storage byteIndexStore
//   path, which mis-resolved the memory blob as a storage slot). The READ side already rejects
//   JETH217; the write now rejects symmetrically at resolveMemDynStructArrayField instead of
//   dropping the store. Controls M1 / L13 / storage-native writes stay byte-identical.
//
// DRIFT-MC-1 (silent miscompile, pre-existing): a value-array ternary-base element write
//   (c ? this.a : this.b)[i] = v (u256[] / Arr<u256,N> / address[], plain and compound) was
//   accepted but wrote a discarded MEMORY COPY of the selected storage array (a JETH ternary is a
//   value, never a reference). The ternary-chain branch-push desugar - previously gated to fire
//   only when the direct lvalue REJECTED - now takes precedence for ANY ternary-bottomed write, so
//   the write lands in storage exactly like solc. A storage|memory mix stays a clean reject
//   (TERN-LV-MIX: solc's memory-copy semantics are unreproducible).
//
// MATRIX-OA-1 (over-acceptance, campaign-introduced, root pre-existing): a wrong-struct RHS through
//   a ternary-lvalue whole-element write (c ? this.A : this.B)[i] = P(9n) (P a different struct than
//   the element type In) was accepted where solc rejects the type mismatch. Root: the static-struct
//   local-decl nominal name check omitted the constructor kinds, so materializeAggregateRhsToTemp's
//   synthesized `let tmp: In = P(9n)` bound P's image into an In local. The check is now blanket
//   over every initializer kind, closing both the desugar over-acceptance and the underlying
//   `let a: In = P(...)` let-bind hole.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const run = async (J: string, S: string, calls: ReadonlyArray<readonly [string, string]>) => {
  const h = await Harness.create();
  await h.fund(me, 10n ** 20n);
  const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
  const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
  for (const [sg, args] of calls) {
    const jr = await h.call(ja, sel(sg) + args);
    const sr = await h.call(sa, sel(sg) + args);
    expect(jr.returnHex, `${sg} ${args.slice(0, 12)}`).toBe(sr.returnHex);
    expect(jr.success, sg).toBe(sr.success);
  }
};
const rejects = (src: string): boolean => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
};

describe('long-tail final-verification bar-violation fixes (byte-identical to solc 0.8.35)', () => {
  it('MC-MEMARR-BYTES-WRITE: byte write into a bytes field of a memory struct-array element rejects (was a silent drop)', async () => {
    // fixed Arr<Q2,N> and dynamic Q2[] memory element byte-writes both reject (matching the read side).
    expect(
      rejects(`@struct class Q2 { b: bytes; n: u256 }
@contract class C { @external @pure f(): bytes { let xs: Arr<Q2, 2> = [Q2(bytes("aabb"), 1n), Q2(bytes("ccdd"), 2n)]; xs[1n].b[0n] = 0x5an; return xs[1n].b; } }`),
    ).toBe(true);
    expect(
      rejects(`@struct class Q2 { b: bytes; n: u256 }
@contract class C { @external @pure f(): bytes { let xs: Q2[] = [Q2(bytes("aabb"), 1n)]; xs[0n].b[0n] = 0x5an; return xs[0n].b; } }`),
    ).toBe(true);
    // string field is not indexable either (JETH205, solc parity).
    expect(
      rejects(`@struct class Q2 { s: string; n: u256 }
@contract class C { @external @pure f(): u256 { let xs: Arr<Q2, 2> = [Q2("aa", 1n), Q2("bb", 2n)]; xs[0n].s[0n] = 0x5an; return 1n; } }`),
    ).toBe(true);
    // controls that MUST stay byte-identical: plain memory-struct byte write (M1), bytes[]-element
    // write (L13), and storage-native struct-array element byte write.
    await run(
      `@struct class Q { b: bytes; n: u256 }
@contract class C { @external @pure f(): bytes { let q: Q = Q(bytes("wxyz"), 1n); q.b[2n] = 0x2an; return q.b; } }`,
      `contract C { struct Q { bytes b; uint256 n; } function f() external pure returns (bytes memory) { Q memory q = Q(bytes("wxyz"), 1); q.b[2] = 0x2a; return q.b; } }`,
      [['f()', '']] as const,
    );
    await run(
      `@struct class Q2 { b: bytes; n: u256 }
@contract class C { @state xs: Q2[]; @external seed(): void { this.xs.push(Q2(bytes("ccdd"), 2n)); } @external w(): bytes { this.xs[0n].b[0n] = 0x5an; return this.xs[0n].b; } }`,
      `contract C { struct Q2 { bytes b; uint256 n; } Q2[] xs; function seed() external { xs.push(Q2(bytes("ccdd"), 2)); } function w() external returns (bytes memory) { xs[0].b[0] = 0x5a; return xs[0].b; } }`,
      [['seed()', ''], ['w()', '']] as const,
    );
  });

  it('DRIFT-MC-1: value-array ternary-base element writes land in storage (was a silent copy-drop)', async () => {
    await run(
      `@contract class C { @state a: u256[]; @state b: u256[];
        @external seed(): void { this.a.push(0n); this.b.push(0n); }
        @external w(c: bool, v: u256): void { (c ? this.a : this.b)[0n] = v; }
        @external cw(c: bool, v: u256): void { (c ? this.a : this.b)[0n] += v; }
        @external @view ra(): u256 { return this.a[0n]; }
        @external @view rb(): u256 { return this.b[0n]; } }`,
      `contract C { uint256[] a; uint256[] b;
        function seed() external { a.push(0); b.push(0); }
        function w(bool c, uint256 v) external { (c ? a : b)[0] = v; }
        function cw(bool c, uint256 v) external { (c ? a : b)[0] += v; }
        function ra() external view returns (uint256) { return a[0]; }
        function rb() external view returns (uint256) { return b[0]; } }`,
      [
        ['seed()', ''],
        ['w(bool,uint256)', W(1) + W(11)], ['ra()', ''],
        ['w(bool,uint256)', W(0) + W(22)], ['rb()', ''],
        ['cw(bool,uint256)', W(1) + W(4)], ['ra()', ''],
      ] as const,
    );
    // fixed Arr<u256,2> and address[] variants likewise land in storage.
    await run(
      `@contract class C { @state a: Arr<u256,2>; @state b: Arr<u256,2>;
        @external w(c: bool, v: u256): void { (c ? this.a : this.b)[1n] = v; }
        @external @view ra(): u256 { return this.a[1n]; } }`,
      `contract C { uint256[2] a; uint256[2] b;
        function w(bool c, uint256 v) external { (c ? a : b)[1] = v; }
        function ra() external view returns (uint256) { return a[1]; } }`,
      [['w(bool,uint256)', W(1) + W(55)], ['ra()', '']] as const,
    );
    // a storage|memory location MIX stays a clean reject (TERN-LV-MIX: solc unifies to a memory copy).
    expect(
      rejects(`@contract class C { @state a: u256[]; @external @pure w(c: bool, v: u256): u256 { let m: u256[] = [0n]; (c ? this.a : m)[0n] = v; return m[0n]; } }`),
    ).toBe(true);
  });

  it('MATRIX-OA-1: a wrong-struct RHS through a ternary-lvalue / let-bind rejects (nominal typing)', async () => {
    const P_IN = `@struct class P { a: u256 }\n@struct class In { x: u256; y: u256 }\n`;
    // ternary-lvalue whole-element write with the wrong struct.
    expect(
      rejects(`${P_IN}@contract class C { @state A: Arr<In,2>; @state B: Arr<In,2>;
        @external w(c: bool): u256 { (c ? this.A : this.B)[0n] = P(9n); return this.A[0n].x; } }`),
    ).toBe(true);
    // nested-ternary variant.
    expect(
      rejects(`${P_IN}@contract class C { @state A: Arr<In,2>; @state B: Arr<In,2>; @state D: Arr<In,2>;
        @external w(c: bool, d: bool): u256 { (c ? this.A : (d ? this.B : this.D))[0n] = P(9n); return this.A[0n].x; } }`),
    ).toBe(true);
    // the underlying let-bind hole: a wrong struct whose fields merely fit.
    expect(rejects(`${P_IN}@contract class C { @external @pure f(): u256 { let a: In = P(9n); return a.x; } }`)).toBe(true);
    expect(
      rejects(`@struct class P3 { a: u256; b: u256; c: u256 }
@struct class In { x: u256; y: u256 }
@contract class C { @external @pure f(): u256 { let a: In = P3(1n,2n,3n); return a.x; } }`),
    ).toBe(true);
    // the correct struct still compiles and runs byte-identically.
    await run(
      `@struct class In { x: u256; y: u256 }
@contract class C { @state A: Arr<In,2>; @state B: Arr<In,2>;
  @external w(c: bool): void { (c ? this.A : this.B)[0n] = In(9n, 8n); }
  @external @view g(): u256 { return this.A[0n].x*1000n + this.A[0n].y; } }`,
      `contract C { struct In { uint256 x; uint256 y; } In[2] A; In[2] B;
  function w(bool c) external { (c ? A : B)[0] = In(9, 8); }
  function g() external view returns (uint256) { return A[0].x*1000 + A[0].y; } }`,
      [['w(bool)', W(1)], ['g()', '']] as const,
    );
  });
});
