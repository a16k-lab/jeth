// Gate tests: the genuinely-deeper dynamic-struct forms beyond storage/mapping
// field access must be REJECTED with a precise diagnostic (never miscompiled).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

function diags(src: string): { code: string; message: string }[] {
  try {
    compile(src, { fileName: 'G.jeth' });
    return [];
  } catch (e: any) {
    return (e.diagnostics ?? e.items ?? []).map((d: any) => ({ code: d.code, message: d.message }));
  }
}
const HEAD = 'type D = { a: u256; s: string; };\n';

describe('storage dynamic struct: deeper forms stay gated', () => {
  it('D[] as a CALLDATA PARAM is now SUPPORTED (recursive codec)', () => {
    const d = diags(HEAD + 'class G {\n  get f(xs: D[]): External<u256> { return xs.length; }\n}');
    expect(d).toEqual([]);
  });

  it('D[] as a CALLDATA param + RETURN (echo) is now SUPPORTED', () => {
    const d = diags(HEAD + 'class G {\n  get f(xs: D[]): External<D[]> { return xs; }\n}');
    expect(d).toEqual([]);
  });

  it('returning a whole STORAGE D[] is now SUPPORTED (storage-source recursive encoder)', () => {
    const d = diags(
      HEAD + 'class G {\n  recs: D[];\n  get f(): External<D[]> { return this.recs; }\n}',
    );
    expect(d).toEqual([]);
  });

  it('fixed Arr<D, N> of a dynamic struct is now SUPPORTED in storage (contiguous N*slotCount slots)', () => {
    const d = diags(
      HEAD +
        'class G {\n  fa: Arr<D, 3>;\n  get f(i: u256): External<u256> { return this.fa[i].a; }\n}',
    );
    expect(d).toEqual([]);
  });

  it('returning a whole storage dynamic struct is now SUPPORTED', () => {
    const d = diags(HEAD + 'class G {\n  d: D;\n  get f(): External<D> { return this.d; }\n}');
    expect(d).toEqual([]);
  });

  it('returning a whole struct mapping value is now SUPPORTED (storage-source encoder)', () => {
    const d = diags(
      HEAD +
        'class G {\n  m: mapping<address, D>;\n  get f(k: address): External<D> { return this.m[k]; }\n}',
    );
    expect(d).toEqual([]);
  });

  it('a string[] struct field is now SUPPORTED in storage (array at the field slot)', () => {
    const d = diags(
      'type B = { a: u256; ss: string[]; };\nclass G {\n  b: B;\n  push(s: string): External<void> { this.b.ss.push(s); }\n}',
    );
    expect(d).toEqual([]);
  });

  it('a T[] (dynamic-array) struct field is now SUPPORTED in storage (array at the field slot)', () => {
    const d = diags(
      'type B = { a: u256; xs: u256[]; };\nclass G {\n  b: B;\n  push(v: u256): External<void> { this.b.xs.push(v); }\n}',
    );
    expect(d).toEqual([]);
  });

  it('mapping<K, D[]> of a dynamic struct COMPILES (storage, recursive)', () => {
    const src =
      HEAD +
      `class G {
  m: mapping<address, D[]>;
  pushK(k: address, a: u256, s: string): External<void> { this.m[k].push(D(a, s)); }
  popK(k: address): External<void> { this.m[k].pop(); }
  kLen(k: address): u256 { return this.m[k].length; }
  setKs(k: address, i: u256, v: string): External<void> { this.m[k][i].s = v; }
  kAtA(k: address, i: u256): u256 { return this.m[k][i].a; }
  kAt(k: address, i: u256): string { return this.m[k][i].s; }
}`;
    expect(diags(src)).toEqual([]);
  });
});
