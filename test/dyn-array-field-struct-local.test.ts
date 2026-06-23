// JETH200 lift: a struct MEMORY LOCAL whose struct has a dynamic VALUE-element ARRAY field
// (`let p: S = S(a, ys, b)` / `= this.s`, where S { a: u256; xs: u256[]; b: u256; }). The local is a
// pointer-headed image: value fields inline, the array field a pointer to [len][elems] (like a
// bytes field). Supports construct (from a constructor / storage / another local), read (p.a / p.xs
// whole / p.xs.length / p.xs[i]), and whole-struct `return p`. Byte-identical to solc 0.8.35.
// Gated cleanly (JETH200): cd-source construct, storage construct, array-field write, string[]/T[][] fields.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
const cdArr = (xs: readonly bigint[]) => pad32(BigInt(xs.length)) + xs.map(pad32).join('');
function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}

describe('dynamic-array-field struct memory local (JETH200) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `@struct class S { a: u256; xs: u256[]; b: u256; }
@contract class C {
  @external @pure mk(ys: u256[], a: u256, b: u256): S { let p: S = S(a, ys, b); return p; }
  @external @pure rd(ys: u256[], i: u256): u256 { let p: S = S(7n, ys, 9n); return p.xs[i]; }
  @external @pure rlen(ys: u256[]): u256 { let p: S = S(7n, ys, 9n); return p.xs.length; }
  @external @pure rab(ys: u256[]): u256 { let p: S = S(7n, ys, 9n); return p.a + p.b; }
  @external @pure sumLocal(ys: u256[]): u256 { let p: S = S(1n, ys, 2n); let t: u256 = 0n; for (const v of p.xs) { t = t + v; } return t; }
  @state s: S;
  @external setSa(v: u256): void { this.s.a = v; }
  @external setSb(v: u256): void { this.s.b = v; }
  @external pushSx(v: u256): void { this.s.xs.push(v); }
  @external @view cpRet(): S { let p: S = this.s; return p; }
  @external @view cpIdx(i: u256): u256 { let p: S = this.s; return p.xs[i]; } }`;
  const So = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  struct S { uint256 a; uint256[] xs; uint256 b; }
  function mk(uint256[] calldata ys, uint256 a, uint256 b) external pure returns (S memory) { S memory p = S(a, ys, b); return p; }
  function rd(uint256[] calldata ys, uint256 i) external pure returns (uint256) { S memory p = S(7, ys, 9); return p.xs[i]; }
  function rlen(uint256[] calldata ys) external pure returns (uint256) { S memory p = S(7, ys, 9); return p.xs.length; }
  function rab(uint256[] calldata ys) external pure returns (uint256) { S memory p = S(7, ys, 9); return p.a + p.b; }
  function sumLocal(uint256[] calldata ys) external pure returns (uint256) { S memory p = S(1, ys, 2); uint256 t=0; for (uint256 i=0;i<p.xs.length;i++){t+=p.xs[i];} return t; }
  S s;
  function setSa(uint256 v) external { s.a = v; }
  function setSb(uint256 v) external { s.b = v; }
  function pushSx(uint256 v) external { s.xs.push(v); }
  function cpRet() external view returns (S memory) { S memory p = s; return p; }
  function cpIdx(uint256 i) external view returns (uint256) { S memory p = s; return p.xs[i]; } }`;

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(So, 'C').creation);
  });
  const cmp = async (data: string, label: string) => {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, label).toBe(s.returnHex);
  };

  it('construct + read (value fields, p.xs[i], p.xs.length, for-of) byte-identical', async () => {
    const ys = [10n, 20n, 30n];
    for (const [v, len] of [
      [[3n, 5n, 8n, 13n], 4],
      [[42n], 1],
      [[], 0],
    ] as const) {
      void len;
      const tail = pad32(BigInt(v.length)) + v.map(pad32).join('');
      await cmp('0x' + sel('rlen(uint256[])') + pad32(0x20n) + tail, `rlen(${v.length})`);
      await cmp('0x' + sel('rab(uint256[])') + pad32(0x20n) + tail, `rab(${v.length})`);
      await cmp('0x' + sel('sumLocal(uint256[])') + pad32(0x20n) + tail, `sumLocal(${v.length})`);
    }
    for (const i of [0n, 1n, 2n, 5n])
      await cmp('0x' + sel('rd(uint256[],uint256)') + pad32(0x40n) + pad32(i) + cdArr(ys), `rd[${i}]`);
  });
  it('whole-struct return (the array-field tail encoder) byte-identical', async () => {
    for (const ys of [[10n, 20n, 30n], [], [99n]] as const) {
      const data = '0x' + sel('mk(uint256[],uint256,uint256)') + pad32(0x60n) + pad32(7n) + pad32(9n) + cdArr(ys);
      await cmp(data, `mk(${ys.length})`);
    }
  });
  it('copy from storage -> read + whole return byte-identical (raw slots independent)', async () => {
    const run = async (d: string) => {
      await jeth.call(aj, d);
      await sol.call(as, d);
    };
    await run('0x' + sel('setSa(uint256)') + pad32(11n));
    await run('0x' + sel('setSb(uint256)') + pad32(99n));
    for (const v of [5n, 6n, 7n]) await run('0x' + sel('pushSx(uint256)') + pad32(v));
    await cmp('0x' + sel('cpRet()'), 'cpRet');
    for (const i of [0n, 1n, 2n]) await cmp('0x' + sel('cpIdx(uint256)') + pad32(i), `cpIdx[${i}]`);
  });
  it('clean gates (JETH200): cd-construct, storage construct, array-field write, string[] field', () => {
    const Sd = '@struct class S { a: u256; xs: u256[]; b: u256; }\n';
    // (cd-struct -> mem local with a value-array field, and storage-struct construct with a value-array
    //  field, are now SUPPORTED and byte-identical to solc - see the dyn value-array assign tests.)
    expect(
      codes(
        Sd +
          '@contract class C { @external @pure f(ys: u256[]): u256 { let p: S = S(1n, ys, 2n); p.xs = ys; return p.a; } }',
      ),
    ).toContain('JETH200');
    expect(
      codes(
        '@struct class T { a: u256; ts: string[]; }\n@contract class C { @external @pure f(): u256 { let p: T = T(1n, []); return p.a; } }',
      ),
    ).toContain('JETH200');
  });
});
