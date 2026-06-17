// AUDIT (panics-reverts-edges): formerly-divergent JETH-vs-solc cases found while
// auditing Phase 4 panic/revert discipline. The inner/member-offset divergences are
// now CLOSED (the four inner-offset helpers use solc's signed-offset form, and the
// echo encoders apply the alloc Panic(0x41)); these tests now assert BYTE-IDENTITY
// vs solc and double as regression anchors.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}

describe('AUDIT panics/reverts edges: inner/element offset high-bit divergence', () => {
  // Root cause (now FIXED): JETH used to guard inner/element calldata offsets with
  //   `if gt(off, 0xffffffffffffffff) { revert(0,0) }`
  // (a 2^64 cap) in jeth_calldata_inner_array / jeth_calldata_dyn_elem /
  // calldataDynAt. solc's LAZY-ACCESS path (m[i][j], a[i], d.s) has NO such cap; it
  // does modular pointer arithmetic and uses signed comparisons, so an offset with
  // the high bit set (>= 2^255) wraps and reads zeros, yielding Panic(0x32) or an
  // empty value rather than an empty revert. The lazy-access helpers now use that
  // signed form, so these cases are byte-identical to solc.
  let jeth: Harness, sol: Harness, aj: Address, as: Address;

  const JETH = `@struct class D { a: u256; b: bytes; }
@contract class C {
  @external @pure mm(m: u256[][], i: u256, j: u256): u256 { return m[i][j]; }
  @external @pure saAt(a: string[], i: u256): string { return a[i]; }
  @external @pure dbLen(d: D): u256 { return d.b.length; }
}`;
  const SOL = `pragma solidity ^0.8.20;
struct D { uint256 a; bytes b; }
contract C {
  function mm(uint256[][] calldata m, uint256 i, uint256 j) external pure returns(uint256){ return m[i][j]; }
  function saAt(string[] calldata a, uint256 i) external pure returns(string memory){ return a[i]; }
  function dbLen(D calldata d) external pure returns(uint256){ return d.b.length; }
}`;

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  const HI = 1n << 255n;

  // byte-identity helper: JETH and solc must agree on success + returndata.
  async function same(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success).toBe(s.success);
    expect(j.returnHex).toBe(s.returnHex);
    return { j, s };
  }

  it('T[][] inner offset = 2^255: byte-identical (solc Panics 0x32, JETH matches)', async () => {
    // head: [off_m=0x60][i=0][j=0]; region@0x64: [outer_len=1][inner_off0=2^255][real inner len=2,...]
    const data =
      sel('mm(uint256[][],uint256,uint256)') +
      pad32(0x60n) + pad32(0n) + pad32(0n) +
      pad32(1n) + pad32(HI) + pad32(2n) + pad32(0x77n) + pad32(0x88n);
    const { s } = await same(data);
    // solc: inner_off high bit -> wrapped lenPtr reads 0 -> innerLen 0 -> j=0 OOB -> Panic(0x32)
    expect(s.success).toBe(false);
    expect(s.returnHex).toBe('0x4e487b71' + pad32(0x32n));
  });

  it('T[][] inner offset = 2^256-0x20 (wrap): byte-identical (solc reads wrapped element)', async () => {
    const WRAP = (1n << 256n) - 0x20n;
    const data =
      sel('mm(uint256[][],uint256,uint256)') +
      pad32(0x60n) + pad32(0n) + pad32(0n) +
      pad32(1n) + pad32(WRAP) + pad32(2n) + pad32(0x77n) + pad32(0x88n);
    const { s } = await same(data);
    expect(s.success).toBe(true); // solc reads a wrapped element; JETH matches byte-for-byte
  });

  it('string[] element offset = 2^255: byte-identical (solc returns empty string)', async () => {
    const data =
      sel('saAt(string[],uint256)') +
      pad32(0x40n) + pad32(0n) +
      pad32(2n) + pad32(HI) + pad32(0xa0n) +
      pad32(2n) + '6162'.padEnd(64, '0') +
      pad32(4n) + '63646566'.padEnd(64, '0');
    const { s } = await same(data);
    expect(s.success).toBe(true); // solc returns "" ; JETH matches
  });

  it('dynamic-struct field offset = 2^255: byte-identical (solc returns len 0)', async () => {
    const data = sel('dbLen((uint256,bytes))') + pad32(0x20n) + pad32(7n) + pad32(HI);
    const { s } = await same(data);
    expect(s.success).toBe(true); // solc reads len 0 ; JETH matches
    expect(s.returnHex).toBe('0x' + pad32(0n));
  });

  it('CONTROL: small inner offsets and the 2^64 boundary do NOT diverge', async () => {
    for (const o of [0x20n, 0x40n, (1n << 64n) - 1n, 1n << 64n, 1n << 200n, (1n << 255n) - 1n]) {
      const data =
        sel('mm(uint256[][],uint256,uint256)') +
        pad32(0x60n) + pad32(0n) + pad32(0n) +
        pad32(1n) + pad32(o) + pad32(2n) + pad32(0x77n) + pad32(0x88n);
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(j.success, `o=${o}`).toBe(s.success);
      expect(j.returnHex, `o=${o}`).toBe(s.returnHex);
    }
  });
});

describe('AUDIT panics/reverts edges: zero-length fixed array over-acceptance', () => {
  // solc rejects `T[0]` ("Array with zero length specified") in EVERY position.
  // JETH accepts `Arr<T,0>` and emits running bytecode (indexing always Panics
  // 0x32; a @state Arr<T,0> consumes 0 slots, overlapping the next field).
  function tryJeth(src: string): string {
    try {
      compile(src, { fileName: 'C.jeth' });
      return 'COMPILES';
    } catch (e: any) {
      return 'REJECT';
    }
  }
  function trySol(src: string): string {
    try {
      compileSolidity(src, 'C');
      return 'COMPILES';
    } catch {
      return 'REJECT';
    }
  }

  // FIXED (JETH013): JETH now rejects a zero-length fixed array in every position,
  // matching solc ("Array with zero length specified").
  it('Arr<u256,0> param: both JETH and solc reject', () => {
    const j = `@contract class C { @external @pure f(a: Arr<u256,0>): u256 { return 1n; } }`;
    const s = `pragma solidity ^0.8.20; contract C { function f(uint256[0] calldata a) external pure returns(uint256){ return 1; } }`;
    expect(tryJeth(j)).toBe('REJECT');
    expect(trySol(s)).toBe('REJECT');
  });

  it('@state Arr<u256,0> is rejected (no zero-slot aliasing)', () => {
    const j = `@contract class C { @state a: Arr<u256,0>; @state b: u256; @external @view f(): u256 { return this.b; } }`;
    expect(tryJeth(j)).toBe('REJECT');
  });

  it('Arr<u256,0> in struct field / mapping value / nested fixed: both JETH and solc reject', () => {
    const cases: [string, string][] = [
      [
        `@struct class S { a: Arr<u256,0>; b: u256; } @contract class C { @state s: S; @external @view f(): u256 { return this.s.b; } }`,
        `pragma solidity ^0.8.20; struct S { uint256[0] a; uint256 b; } contract C { S s; function f() external view returns(uint256){ return s.b; } }`,
      ],
      [
        `@contract class C { @state m: mapping<u256, Arr<u256,0>>; @external @view f(): u256 { return 0n; } }`,
        `pragma solidity ^0.8.20; contract C { mapping(uint256=>uint256[0]) m; function f() external view returns(uint256){ return 0; } }`,
      ],
      [
        `@contract class C { @state m: Arr<Arr<u256,0>,3>; @external @view f(): u256 { return 0n; } }`,
        `pragma solidity ^0.8.20; contract C { uint256[0][3] m; function f() external view returns(uint256){ return 0; } }`,
      ],
    ];
    for (const [jsrc, ssrc] of cases) {
      expect(tryJeth(jsrc)).toBe('REJECT');
      expect(trySol(ssrc)).toBe('REJECT');
    }
  });
});
