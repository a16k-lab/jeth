// Residual A: a whole-inner-array element assignment to a nested MEMORY array local (m[i] = [...]).
// Historically JETH900: the assign-to-arrayElem path routed a memory-array element through the
// storage-only structArrayElemSlot. A DYNAMIC inner element is one absolute-pointer word (store the
// materialized RHS pointer - a reference assignment, exactly like solc): u256[][], Arr<u256[],2> stay
// supported and byte-identical, including reference-semantics aliasing (refsem).
// A STATIC (inline value-word) inner element (Arr<Arr<u256,2>,2>, Arr<u256,2>[]) is laid out INLINE, so
// a whole-element write can only DEEP-COPY the sub-image where solc RE-POINTS: writing then immediately
// returning happens to coincide, but a later mutation through an alias (m[0]=row; row[0]=v) diverges
// (P0-14 / P0-13). It is therefore a sound clean reject now (JETH429) - a copy-vs-re-point miscompile
// eliminated. A second, latent bug from the nested-memory codec (a fixed-of-fixed Arr<Arr<u256,2>,2>
// memory LOCAL was wrongly claimed by resolveCalldataPlace as a read-only calldata place -> mislabeled
// JETH230) was also fixed by excluding memAggregateLocals from that resolver's root ownership.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';
import { Address } from '@ethereumjs/util';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);

// DYNAMIC-inner (pointer-headed) nested memory arrays: a whole-inner-array element write RE-POINTS the
// element's pointer word, exactly like solc, so these stay byte-identical (incl. OOB Panic + aliasing).
const J = `@contract class C {
  @external @pure dyn(): u256[][] { let m: u256[][] = [[1n,2n],[3n]]; m[0n] = [9n,8n,7n]; return m; }
  @external @pure fd(): Arr<u256[],2> { let m: Arr<u256[],2> = [[1n,2n],[3n]]; m[0n] = [9n,8n,7n]; return m; }
  @external @pure oob(): u256 { let m: u256[][] = [[1n,2n],[3n]]; m[5n] = [9n]; return m[0n][0n]; }
  @external @pure refsem(): u256[][] { let inner: u256[] = [7n,7n]; let m: u256[][] = [[1n,2n],[3n]]; m[0n] = inner; inner[0n] = 99n; return m; } }`;

const S = `contract C {
  function dyn() external pure returns (uint[][] memory) { uint[][] memory m = new uint[][](2); m[0]=new uint[](2); m[0][0]=1; m[0][1]=2; m[1]=new uint[](1); m[1][0]=3; uint[] memory r=new uint[](3); r[0]=9;r[1]=8;r[2]=7; m[0]=r; return m; }
  function fd() external pure returns (uint[][2] memory) { uint[][2] memory m; m[0]=new uint[](2); m[0][0]=1;m[0][1]=2; m[1]=new uint[](1); m[1][0]=3; uint[] memory r=new uint[](3); r[0]=9;r[1]=8;r[2]=7; m[0]=r; return m; }
  function oob() external pure returns (uint) { uint[][] memory m=new uint[][](2); m[0]=new uint[](2);m[0][0]=1;m[0][1]=2;m[1]=new uint[](1);m[1][0]=3; uint[] memory r=new uint[](1);r[0]=9; m[5]=r; return m[0][0]; }
  function refsem() external pure returns (uint[][] memory) { uint[] memory inner=new uint[](2); inner[0]=7;inner[1]=7; uint[][] memory m=new uint[][](2); m[0]=new uint[](2);m[0][0]=1;m[0][1]=2;m[1]=new uint[](1);m[1][0]=3; m[0]=inner; inner[0]=99; return m; } }`;

describe('Residual A: whole-inner-array assignment m[i] = [...] on a nested memory array (JETH900 lifted)', () => {
  it('byte-identical to solc 0.8.35 across dynamic-inner nestings, OOB Panic, and reference semantics', async () => {
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    for (const sg of ['dyn()', 'fd()', 'oob()', 'refsem()']) {
      const jr = await h.call(ja, sel(sg));
      const sr = await h.call(sa, sel(sg));
      expect(jr.returnHex, sg).toBe(sr.returnHex);
      expect(jr.success, sg).toBe(sr.success);
    }
  });

  it('rejects a whole-element write into a STATIC (inline value-word) inner array [copy-vs-re-point, JETH429]', () => {
    const codes = (src: string): string[] => {
      try {
        compile(src, { fileName: 'C.jeth' });
        return [];
      } catch (e: any) {
        return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
      }
    };
    // Arr<Arr<u256,2>,2> (P0-14) and Arr<u256,2>[] (P0-13): the inner element is INLINE, so a whole-element
    // write deep-copies where solc re-points. Sound clean reject (a return-immediately form would coincide,
    // but the write semantics diverge under aliasing).
    expect(codes(`@contract class C { @external @pure ff(): Arr<Arr<u256,2>,2> { let m: Arr<Arr<u256,2>,2> = [[1n,2n],[3n,4n]]; m[0n] = [9n,8n]; return m; } }`)).toContain('JETH429');
    expect(codes(`@contract class C { @external @pure df(): Arr<u256,2>[] { let m: Arr<u256,2>[] = [[1n,2n],[3n,4n],[5n,6n]]; m[1n] = [9n,8n]; return m; } }`)).toContain('JETH429');
  });

  it('still rejects a write to a calldata aggregate parameter (read-only)', () => {
    const codes = (src: string): string[] => {
      try {
        compile(src, { fileName: 'C.jeth' });
        return [];
      } catch (e: any) {
        return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
      }
    };
    // a calldata fixed-of-fixed param and a calldata static struct param remain read-only.
    expect(codes(`@contract class C { @external @pure f(p: Arr<Arr<u256,2>,2>): u256 { p[0n] = [9n,8n]; return p[0n][0n]; } }`).length).toBeGreaterThan(0);
    expect(codes(`@struct class P{a:u256;b:u256;} @contract class C { @external @pure f(p: P): u256 { p.a = 9n; return p.a; } }`).length).toBeGreaterThan(0);
  });
});
