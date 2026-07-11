// Over-acceptance closed: a COMPILE-TIME-CONSTANT out-of-bounds index on a fixed array of dynamic
// structs (Arr<In,N>) must reject with JETH211 (solc: "Out of bounds array access"), exactly like the
// sibling fixed-of-dynamic families (Arr<string,N> / Arr<u256[],N>) and plain Arr<u256,N>. The #4 lift
// (memory-local Arr<In,N>) initially routed the a[i].field index through resolveMemDynStructArrayField
// without the const-bound check, so a[5n].n on an Arr<In,2> compiled (then Panic 0x32 at runtime) while
// solc rejects at compile time. checkArrExprBound is now applied at that index step. A RUNTIME index
// stays accepted (runtime Panic 0x32), matching solc.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};

const IN = 'type In = { s: string; n: u256 };';

describe('Arr<In,N> (fixed array of dynamic structs): const-OOB index rejects (JETH211)', () => {
  it('a[5n].field on a local rejects', () => {
    expect(codes(`${IN} class C { get f(): External<u256> { let a: Arr<In,2> = [In("x",1n),In("y",2n)]; return a[5n].n; } }`)).toContain('JETH211');
    expect(codes(`${IN} class C { get f(): External<string> { let a: Arr<In,2> = [In("x",1n),In("y",2n)]; return a[5n].s; } }`)).toContain('JETH211');
  });
  it('d.items[5n].field on a struct-field array rejects', () => {
    expect(codes(`${IN} type D = { items: Arr<In,2>; k: u256 }; class C { get f(): External<string> { let d: D = D([In("a",1n),In("b",2n)], 7n); return d.items[5n].s; } }`)).toContain('JETH211');
  });
  it('a[0n][5n].field nested-inner OOB rejects', () => {
    expect(codes(`${IN} class C { get f(): External<string> { let a: Arr<Arr<In,2>,2> = [[In("a",1n),In("b",2n)],[In("c",3n),In("d",4n)]]; return a[0n][5n].s; } }`)).toContain('JETH211');
  });
  it('a valid const index and a runtime index still compile', () => {
    expect(codes(`${IN} class C { get f(): External<u256> { let a: Arr<In,2> = [In("x",1n),In("y",2n)]; return a[1n].n; } }`)).toEqual([]);
    expect(codes(`${IN} class C { get f(i: u256): External<u256> { let a: Arr<In,2> = [In("x",1n),In("y",2n)]; return a[i].n; } }`)).toEqual([]);
  });
});
