// Arch over-rejection #2 (lifted): NESTED / multi-dimensional MEMORY-array LOCALS whose leaves are
// value types - u256[][], Arr<Arr<u256,2>,2>, Arr<u256[],2>, u256[][][], new Array<u256[][]>(n).
// A FLAT value-element memory array already worked; only the nested element types were JETH200-gated.
// The recursive memory codec builds JETH's nested image (a dynamic outer level = [len][inline static
// blocks | absolute pointers]; a fixed-of-dynamic level = an N-word pointer table; a pure-static
// fixed-of-fixed level = inline words) and abiEncFromMem re-encodes it (relative offsets) for the
// observable surfaces. This proves byte-identity vs solc 0.8.35 for: the whole-array RETURN
// (ABI-encoded dynamic array of dynamic/fixed arrays), abi.encode(m) keccak parity, element reads
// m[i][j], .length of the outer and an inner, mutation m[i][j]=v then return, the new Array<u256[][]>(n)
// zero-init return, plus address leaves and empty inner/outer arrays.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

describe('nested / multi-dim memory-array locals (arch #2) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;

  // J = JETH source; S = the solc 0.8.35 mirror, semantically identical.
  const J = `@contract class C {
    // --- u256[][] dynamic-of-dynamic ---
    @external @pure dynDyn(): u256[][] { let m: u256[][] = [[1n,2n],[3n]]; return m; }
    @external @pure readIJ(): u256 { let m: u256[][] = [[1n,2n],[3n]]; return m[0n][1n]; }
    @external @pure lens(): u256 { let m: u256[][] = [[1n,2n,5n],[3n]]; return m.length * 100n + m[0n].length; }
    @external @pure mutate(): u256[][] { let m: u256[][] = [[1n,2n],[3n]]; m[0n][1n] = 99n; m[1n][0n] = 77n; return m; }
    @external @pure encKec(): bytes32 { let m: u256[][] = [[1n,2n],[3n]]; return keccak256(abi.encode(m)); }
    @external @pure empties(): u256[][] { let m: u256[][] = [[],[5n]]; return m; }
    @external @pure emptyOuter(): u256[][] { let m: u256[][] = []; return m; }
    // --- Arr<Arr<u256,2>,2> fixed-of-fixed (pure static, inline image) ---
    @external @pure fixFix(): Arr<Arr<u256,2>,2> { let f: Arr<Arr<u256,2>,2> = [[1n,2n],[3n,4n]]; return f; }
    @external @pure fixFixRead(): u256 { let f: Arr<Arr<u256,2>,2> = [[1n,2n],[3n,4n]]; return f[1n][0n] * 10n + f[0n][1n]; }
    // --- Arr<u256[],2> fixed-of-dynamic (pointer table) ---
    @external @pure fixDyn(): Arr<u256[],2> { let g: Arr<u256[],2> = [[1n],[2n,3n]]; return g; }
    @external @pure fixDynRW(): u256 { let g: Arr<u256[],2> = [[1n],[2n,3n]]; g[1n][0n] = 9n; return g[0n][0n]*100n + g[1n][0n]*10n + g[1n][1n] + g.length; }
    // --- new Array zero-init (u256[][][]) ---
    @external @pure newZero(): u256[][][] { let h: u256[][][] = new Array<u256[][]>(2n); return h; }
    // --- u256[][][] deep literal ---
    @external @pure deep3(): u256[][][] { let h: u256[][][] = [[[1n,2n],[3n]],[[4n]]]; return h; }
    // --- address leaves ---
    @external @pure addrs(): address[][] { let m: address[][] = [[address(0x11n)],[address(0x22n),address(0x33n)]]; return m; }
    // --- alias an inner array into a flat local (reference semantics) ---
    @external @pure aliasMut(): u256[][] { let m: u256[][] = [[1n,2n],[3n]]; let r: u256[] = m[0n]; r[0n] = 99n; return m; }
  }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  function dynDyn() external pure returns (uint256[][] memory) {
    uint256[][] memory m = new uint256[][](2);
    m[0] = new uint256[](2); m[0][0]=1; m[0][1]=2; m[1] = new uint256[](1); m[1][0]=3; return m;
  }
  function readIJ() external pure returns (uint256) {
    uint256[][] memory m = new uint256[][](2);
    m[0] = new uint256[](2); m[0][0]=1; m[0][1]=2; m[1] = new uint256[](1); m[1][0]=3; return m[0][1];
  }
  function lens() external pure returns (uint256) {
    uint256[][] memory m = new uint256[][](2);
    m[0] = new uint256[](3); m[0][0]=1; m[0][1]=2; m[0][2]=5; m[1] = new uint256[](1); m[1][0]=3;
    return m.length * 100 + m[0].length;
  }
  function mutate() external pure returns (uint256[][] memory) {
    uint256[][] memory m = new uint256[][](2);
    m[0] = new uint256[](2); m[0][0]=1; m[0][1]=2; m[1] = new uint256[](1); m[1][0]=3;
    m[0][1] = 99; m[1][0] = 77; return m;
  }
  function encKec() external pure returns (bytes32) {
    uint256[][] memory m = new uint256[][](2);
    m[0] = new uint256[](2); m[0][0]=1; m[0][1]=2; m[1] = new uint256[](1); m[1][0]=3;
    return keccak256(abi.encode(m));
  }
  function empties() external pure returns (uint256[][] memory) {
    uint256[][] memory m = new uint256[][](2); m[0] = new uint256[](0); m[1] = new uint256[](1); m[1][0]=5; return m;
  }
  function emptyOuter() external pure returns (uint256[][] memory) { return new uint256[][](0); }
  function fixFix() external pure returns (uint256[2][2] memory) {
    uint256[2][2] memory f = [[uint256(1),2],[uint256(3),4]]; return f;
  }
  function fixFixRead() external pure returns (uint256) {
    uint256[2][2] memory f = [[uint256(1),2],[uint256(3),4]]; return f[1][0] * 10 + f[0][1];
  }
  function fixDyn() external pure returns (uint256[][2] memory) {
    uint256[][2] memory g; g[0]=new uint256[](1); g[0][0]=1; g[1]=new uint256[](2); g[1][0]=2; g[1][1]=3; return g;
  }
  function fixDynRW() external pure returns (uint256) {
    uint256[][2] memory g; g[0]=new uint256[](1); g[0][0]=1; g[1]=new uint256[](2); g[1][0]=2; g[1][1]=3;
    g[1][0]=9; return g[0][0]*100 + g[1][0]*10 + g[1][1] + g.length;
  }
  function newZero() external pure returns (uint256[][][] memory) { return new uint256[][][](2); }
  function deep3() external pure returns (uint256[][][] memory) {
    uint256[][][] memory h = new uint256[][][](2);
    h[0] = new uint256[][](2); h[0][0]=new uint256[](2); h[0][0][0]=1; h[0][0][1]=2; h[0][1]=new uint256[](1); h[0][1][0]=3;
    h[1] = new uint256[][](1); h[1][0]=new uint256[](1); h[1][0][0]=4; return h;
  }
  function addrs() external pure returns (address[][] memory) {
    address[][] memory m = new address[][](2);
    m[0]=new address[](1); m[0][0]=address(0x11); m[1]=new address[](2); m[1][0]=address(0x22); m[1][1]=address(0x33); return m;
  }
  function aliasMut() external pure returns (uint256[][] memory) {
    uint256[][] memory m = new uint256[][](2);
    m[0] = new uint256[](2); m[0][0]=1; m[0][1]=2; m[1] = new uint256[](1); m[1][0]=3;
    uint256[] memory r = m[0]; r[0]=99; return m;
  }
}`;

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });

  const cmp = async (sig: string) => {
    const data = '0x' + sel(sig);
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${sig} success`).toBe(s.success);
    expect(j.returnHex, sig).toBe(s.returnHex);
  };

  it('u256[][] whole-array RETURN is byte-identical (ABI dyn-of-dyn)', async () => {
    await cmp('dynDyn()');
    await cmp('deep3()');
  });

  it('element reads m[i][j] and mutation then return are byte-identical', async () => {
    await cmp('readIJ()');
    await cmp('mutate()');
  });

  it('.length of the outer and an inner array is byte-identical', async () => {
    await cmp('lens()');
  });

  it('abi.encode(m) keccak parity', async () => {
    await cmp('encKec()');
  });

  it('Arr<Arr<u256,2>,2> fixed-of-fixed return + read are byte-identical (static inline image)', async () => {
    await cmp('fixFix()');
    await cmp('fixFixRead()');
  });

  it('Arr<u256[],2> fixed-of-dynamic return + read/write/length are byte-identical (pointer table)', async () => {
    await cmp('fixDyn()');
    await cmp('fixDynRW()');
  });

  it('new Array<u256[][]>(n) zero-init return is byte-identical (active empty-inner zero-init)', async () => {
    await cmp('newZero()');
  });

  it('address leaves and empty inner/outer arrays are byte-identical', async () => {
    await cmp('addrs()');
    await cmp('empties()');
    await cmp('emptyOuter()');
  });

  it('aliasing an inner array into a flat local has reference semantics (mutation reflects)', async () => {
    await cmp('aliasMut()');
  });

  it('residuals stay rejected (struct/bytes leaves): clean over-rejection, not a miscompile', () => {
    // (whole-inner-array assignment m[i] = [...] is now supported - Residual A, see
    // arch-residual-a-nested-array-assign.test.ts.)
    // a STRUCT-leaf nested array (P[][]) stays JETH200 (the codec only lays out value leaves).
    expect(() =>
      compile(`@struct class P { a: u256; } @contract class C { @external @pure f(): u256 { let m: P[][] = [[P(1n)]]; return 0n; } }`, {
        fileName: 'C.jeth',
      }),
    ).toThrow();
    // a BYTES-leaf nested array (bytes[][]) stays JETH200.
    expect(() =>
      compile(`@contract class C { @external @pure f(): u256 { let m: bytes[][] = [[]]; return 0n; } }`, {
        fileName: 'C.jeth',
      }),
    ).toThrow();
  });
});
