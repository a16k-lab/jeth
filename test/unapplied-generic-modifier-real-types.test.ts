// UNAPPLIED-GENERIC-REAL-TYPES: standalone checking of an unused generic @modifier must use the
// passable concrete types that actually exist in the compilation unit. The former finite probe set
// invented flat structs for every property name. That both accepted a body valid only for an imaginary
// type (OA) and rejected a body valid for a real nested aggregate outside the invented shapes (OR).
import { describe, expect, it } from 'vitest';
import { compile } from '../src/compile.js';

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return (e?.diagnostics ?? []).map((d: any) => d.code);
  }
};

describe('unapplied generic modifier validation uses real compilation-unit types', () => {
  it('rejects a member access that is valid only on the former imaginary synthetic probe', () => {
    expect(
      codes(`class C {
        @modifier m<U>(v: U) { let x: u256 = v.ghost; _; }
        get z(): External<u256> { return 7n; }
      }`),
    ).toContain('JETH074');
  });

  it('rejects an enum value member access that no real passable type supports', () => {
    expect(
      codes(`enum E { A, B }
      class C {
        @modifier m<U>(v: U) { let x: u256 = u256(v.B); _; }
        get z(): External<u256> { return 7n; }
      }`),
    ).toContain('JETH074');
  });

  it('accepts a body valid for a real nested struct type', () => {
    expect(
      codes(`type Inner = { value: u256 };
      type Outer = { inner: Inner };
      class C {
        @modifier m<U>(v: U) { let x: u256 = v.inner.value; _; }
        get z(): External<u256> { return 7n; }
      }`),
    ).toEqual([]);
  });

  it('accepts real aggregate field capabilities and keeps type-independent errors rejecting', () => {
    expect(
      codes(`type P = { tags: string[] };
      class C {
        @modifier m<U>(v: U) { let n: u256 = v.tags.length; _; }
        get z(): External<u256> { return 7n; }
      }`),
    ).toEqual([]);
    expect(
      codes(`type P = { tags: string[] };
      class C {
        @modifier m<U>(v: U) { let n: u256 = v.tags.length; missing; _; }
        get z(): External<u256> { return 7n; }
      }`),
    ).toContain('JETH072');
  });

  it('finds directly-annotated array and function-reference types outside named structs', () => {
    expect(
      codes(`class C {
        rows: bytes[];
        cb: (x: u256) => u256;
        @modifier arrayCap<U>(v: U) { let n: u256 = v[0n].length; _; }
        @modifier callCap<U>(v: U) { let n: u256 = v(7n); _; }
        get z(): External<u256> { return 7n; }
      }`),
    ).toEqual([]);
  });

  it('uses the real-type cross product for heterogeneous type parameters', () => {
    expect(
      codes(`type Inner = { value: u256 };
      type Outer = { inner: Inner };
      class C {
        @modifier m<A, B>(a: A, b: B) { let x: u256 = a.inner.value; require(b && true); _; }
        get z(): External<u256> { return 7n; }
      }`),
    ).toEqual([]);
  });

  it('does not let unused validation change emitted bytecode', () => {
    const base = compile(`class C { get z(): External<u256> { return 7n; } }`, { fileName: 'C.jeth' });
    const plus = compile(
      `type Inner = { value: u256 };
       type Outer = { inner: Inner };
       class C {
         @modifier m<U>(v: U) { let x: u256 = v.inner.value; _; }
         get z(): External<u256> { return 7n; }
       }`,
      { fileName: 'C.jeth' },
    );
    expect(plus.creationBytecode).toBe(base.creationBytecode);
    expect(plus.runtimeBytecode).toBe(base.runtimeBytecode);
  });
});
