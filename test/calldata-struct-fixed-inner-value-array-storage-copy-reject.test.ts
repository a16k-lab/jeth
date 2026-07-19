// SOUNDNESS (JETH470): a whole calldata or memory struct copied into storage must reject when one of
// its fields contains a dynamic array with a fixed-size value-array level. The storage copier cannot
// transcode that pointer-headed inner image: JETH used to compile the assignment and then revert in
// setD(), leaving storage untouched, while solc 0.8.35 stores the full payload.
import { describe, expect, it } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const W = (n: bigint) => pad32(n).replace(/^0x/, '');
const sel = (sig: string) => '0x' + functionSelector(sig);

function diagnostics(src: string): { code: string; message: string }[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ?? [{ code: 'THROW', message: String(e) }];
  }
}

function codes(src: string): string[] {
  return [...new Set(diagnostics(src).map((d) => d.code))];
}

describe('JETH470: calldata whole-struct -> storage copy with a fixed-inner value array', () => {
  it('rejects the exact uint256[2][] witness while solc 0.8.35 deploys, stores, and decodes it', async () => {
    const J = `type D = { a: u256; xs: Arr<u256,2>[] };
      class C { d: D;
        setD(dd: D): External<void> { this.d = dd; }
        get gl(): External<u256> { return this.d.xs.length; }
        get e(): External<u256> { return this.d.xs[1n][0n]; }
      }`;
    const ds = diagnostics(J);
    expect(ds.map((d) => d.code)).toEqual(['JETH470']);
    expect(ds[0]!.message).toContain('dynamic array with a fixed-size value-array level');

    const S = `${SPDX}
      struct D { uint256 a; uint256[2][] xs; }
      contract C { D d;
        function setD(D calldata dd) external { d = dd; }
        function gl() external view returns (uint256) { return d.xs.length; }
        function e() external view returns (uint256) { return d.xs[1][0]; }
      }`;
    const h = await Harness.create();
    const addr = await h.deploy(compileSolidity(S, 'C').creation);
    const setData = sel('setD((uint256,uint256[2][]))') + [32n, 7n, 64n, 2n, 1n, 2n, 3n, 4n].map(W).join('');
    const set = await h.call(addr, setData);
    expect(set.success).toBe(true);
    expect((await h.call(addr, sel('gl()'))).returnHex).toBe('0x' + W(2n));
    expect((await h.call(addr, sel('e()'))).returnHex).toBe('0x' + W(3n));
  });

  const rejects: [string, string][] = [
    [
      'address[2][] field',
      `type D = { xs: Arr<address,2>[] }; class C { d: D; setD(x: D): External<void> { this.d = x; } }`,
    ],
    [
      'dynamic depth before the fixed level',
      `type D = { xs: Arr<u256,2>[][] }; class C { d: D; setD(x: D): External<void> { this.d = x; } }`,
    ],
    [
      'multiple fixed value-array levels',
      `type D = { xs: Arr<Arr<u256,2>,3>[] }; class C { d: D; setD(x: D): External<void> { this.d = x; } }`,
    ],
    [
      'nested struct field',
      `type I = { xs: Arr<u256,2>[] }; type D = { a: u256; i: I }; class C { d: D; setD(x: D): External<void> { this.d = x; } }`,
    ],
    [
      'nested struct field behind an array wrapper',
      `type I = { xs: Arr<u256,2>[] }; type D = { items: I[] }; class C { d: D; setD(x: D): External<void> { this.d = x; } }`,
    ],
    [
      'memory abi.decode source',
      `type D = { xs: Arr<u256,2>[] }; class C { d: D; setD(b: bytes): External<void> { this.d = abi.decode(b, D); } }`,
    ],
    [
      'storage dynamic-array push sink',
      `type D = { xs: Arr<u256,2>[] }; class C { ds: D[]; add(x: D): External<void> { this.ds.push(x); } }`,
    ],
    [
      'storage dynamic-array element assignment sink',
      `type D = { xs: Arr<u256,2>[] }; class C { ds: D[]; set(i: u256, x: D): External<void> { this.ds[i] = x; } }`,
    ],
  ];

  for (const [name, src] of rejects) {
    it(`rejects ${name}`, () => {
      expect(codes(src)).toEqual(['JETH470']);
    });
  }

  it('preserves the neighboring JETH900 and JETH226 gates', () => {
    expect(codes(`class C { xs: Arr<u256,2>[]; set(xs: Arr<u256,2>[]): External<void> { this.xs = xs; } }`)).toEqual([
      'JETH900',
    ]);
    expect(
      codes(
        `type D = { id: u256; xs: Arr<u256,2>[] }; class C { ds: D[]; add(): External<void> { this.ds.push(D(1n, [[u256(1n), 2n]])); } }`,
      ),
    ).toEqual(['JETH226']);
  });

  it('does not reject storage-to-storage copy of the same shape, which runs byte-identically', async () => {
    const J = `type D = { a: u256; xs: Arr<u256,2>[] };
      class C { src: D; dst: D;
        seed(): External<void> { this.src.a = 7n; this.src.xs.push([1n,2n]); this.src.xs.push([3n,4n]); }
        copy(): External<void> { this.dst = this.src; }
        get gl(): External<u256> { return this.dst.xs.length; }
        get e(): External<u256> { return this.dst.xs[1n][0n]; }
      }`;
    const S = `${SPDX}
      struct D { uint256 a; uint256[2][] xs; }
      contract C { D src; D dst;
        function seed() external { src.a = 7; src.xs.push([uint256(1),2]); src.xs.push([uint256(3),4]); }
        function copy() external { dst = src; }
        function gl() external view returns (uint256) { return dst.xs.length; }
        function e() external view returns (uint256) { return dst.xs[1][0]; }
      }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(S, 'C').creation);
    for (const sig of ['seed()', 'copy()', 'gl()', 'e()']) {
      const rj = await h.call(aj, sel(sig));
      const rs = await h.call(as, sel(sig));
      expect(rj.success, `${sig} success`).toBe(rs.success);
      expect(rj.returnHex, `${sig} returndata`).toBe(rs.returnHex);
    }
  });
});
