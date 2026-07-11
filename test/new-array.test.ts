// Phase 6: `new Array<T>(n)` - dynamic memory array allocation (a zero-initialized T[] of length n),
// byte-identical to solc 0.8.35 `new T[](n)`. Differential tests: a JETH contract using
// `new Array<T>(n)` and a solc contract using `new T[](n)` are fed the same calldata and the result
// (success + returndata) is diffed byte-for-byte. Also covers the accept/reject gates (value-type
// element only, length must be unsigned-coercible, etc.) and two fixed over-rejections (a direct
// abi.encode of a new Array, and a ternary branch that is a new Array).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const P = (n: bigint) => pad32(n);

function jethAccepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
function jethCodes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return (e.diagnostics ?? []).map((d: any) => d.code);
  }
}

/** Deploy a JETH + a solc contract with matching external sigs; for each (sig, argWords) diff the call. */
async function rt(jeth: string, sol: string, cases: { sig: string; args?: string; label: string }[]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const c of cases) {
    const data = '0x' + sel(c.sig) + (c.args ?? '');
    const opts = { gasLimit: 30_000_000n };
    const rj = await hj.call(aj, data, opts);
    const rs = await hs.call(as, data, opts);
    expect(rj.success, `${c.label}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.label}: returndata`).toBe(rs.returnHex);
  }
}

describe('new Array<T>(n): byte-identical vs solc', () => {
  it('zero-init, writes, .length, OOB, huge-n (u256[])', async () => {
    const J = `class C {
      get mk(n: u256): External<bytes> { let a: u256[] = new Array<u256>(n); return abi.encode(a); }
      get mkw(n: u256): External<bytes> { let a: u256[] = new Array<u256>(n); a[0n] = 7n; a[2n] = 9n; return abi.encode(a); }
      get len(n: u256): External<u256> { let a: u256[] = new Array<u256>(n); return a.length; }
      get oob(n: u256): External<u256> { let a: u256[] = new Array<u256>(n); return a[n]; }
      get huge(n: u256): External<u256> { let a: u256[] = new Array<u256>(n); return a.length; }
    }`;
    const S = `contract C {
      function mk(uint256 n) external pure returns (bytes memory){ uint256[] memory a = new uint256[](n); return abi.encode(a); }
      function mkw(uint256 n) external pure returns (bytes memory){ uint256[] memory a = new uint256[](n); a[0]=7; a[2]=9; return abi.encode(a); }
      function len(uint256 n) external pure returns (uint256){ uint256[] memory a = new uint256[](n); return a.length; }
      function oob(uint256 n) external pure returns (uint256){ uint256[] memory a = new uint256[](n); return a[n]; }
      function huge(uint256 n) external pure returns (uint256){ uint256[] memory a = new uint256[](n); return a.length; }
    }`;
    await rt(J, S, [
      { sig: 'mk(uint256)', args: P(0n), label: 'mk(0)' },
      { sig: 'mk(uint256)', args: P(1n), label: 'mk(1)' },
      { sig: 'mk(uint256)', args: P(3n), label: 'mk(3)' },
      { sig: 'mk(uint256)', args: P(64n), label: 'mk(64)' },
      { sig: 'mkw(uint256)', args: P(3n), label: 'mkw(3)' },
      { sig: 'len(uint256)', args: P(5n), label: 'len(5)' },
      { sig: 'oob(uint256)', args: P(3n), label: 'oob(3) -> Panic 0x32' },
      { sig: 'oob(uint256)', args: P(0n), label: 'oob(0) -> Panic 0x32' },
      { sig: 'huge(uint256)', args: P(1n << 64n), label: '2^64 -> Panic 0x41' },
      { sig: 'huge(uint256)', args: P((1n << 256n) - 1n), label: 'max -> Panic 0x41' },
    ]);
  });

  it('value element types (u8/bool/address/bytes32/i128/enum/brand), full-word + write-cleanup', async () => {
    const J = `type Tok = Brand<u256>;
    enum Color { Red, Green, Blue }
    class C {
      get u8a(n: u256, v: u256): External<bytes> { let a: u8[] = new Array<u8>(n); a[0n] = u8(v); return abi.encode(a); }
      get boola(n: u256): External<bytes> { let a: bool[] = new Array<bool>(n); a[1n] = true; return abi.encode(a); }
      get addra(n: u256): External<bytes> { let a: address[] = new Array<address>(n); return abi.encode(a); }
      get b32a(n: u256): External<bytes> { let a: bytes32[] = new Array<bytes32>(n); return abi.encode(a); }
      get i128a(n: u256, v: u256): External<bytes> { let a: i128[] = new Array<i128>(n); a[0n] = i128(i256(v)); return abi.encode(a); }
      get enuma(n: u256): External<bytes> { let a: Color[] = new Array<Color>(n); return abi.encode(a); }
      get toka(n: u256): External<bytes> { let a: Tok[] = new Array<Tok>(n); return abi.encode(a); }
    }`;
    const S = `contract C {
      enum Color { Red, Green, Blue }
      function u8a(uint256 n, uint256 v) external pure returns (bytes memory){ uint8[] memory a = new uint8[](n); a[0]=uint8(v); return abi.encode(a); }
      function boola(uint256 n) external pure returns (bytes memory){ bool[] memory a = new bool[](n); a[1]=true; return abi.encode(a); }
      function addra(uint256 n) external pure returns (bytes memory){ address[] memory a = new address[](n); return abi.encode(a); }
      function b32a(uint256 n) external pure returns (bytes memory){ bytes32[] memory a = new bytes32[](n); return abi.encode(a); }
      function i128a(uint256 n, uint256 v) external pure returns (bytes memory){ int128[] memory a = new int128[](n); a[0]=int128(int256(v)); return abi.encode(a); }
      function enuma(uint256 n) external pure returns (bytes memory){ Color[] memory a = new Color[](n); return abi.encode(a); }
      function toka(uint256 n) external pure returns (bytes memory){ uint256[] memory a = new uint256[](n); return abi.encode(a); }
    }`;
    await rt(J, S, [
      { sig: 'u8a(uint256,uint256)', args: P(3n) + P(0x1ffn), label: 'u8[] masks low 8 bits (0x1ff->0xff)' },
      { sig: 'boola(uint256)', args: P(3n), label: 'bool[]' },
      { sig: 'addra(uint256)', args: P(2n), label: 'address[] zero' },
      { sig: 'b32a(uint256)', args: P(2n), label: 'bytes32[] zero' },
      { sig: 'i128a(uint256,uint256)', args: P(2n) + P((1n << 256n) - 1n), label: 'i128[] sign-extend (-1)' },
      { sig: 'enuma(uint256)', args: P(3n), label: 'enum[] zero' },
      { sig: 'toka(uint256)', args: P(3n), label: 'Brand<u256>[] zero' },
    ]);
  });

  it('direct return + abi.encode(direct) + abi.encode(multi) + encodePacked(direct) [regression: was JETH900]', async () => {
    const J = `class C {
      get ret(n: u256): External<u256[]> { return new Array<u256>(n); }
      get enc(n: u256): External<bytes> { return abi.encode(new Array<u256>(n)); }
      get multi(n: u256): External<bytes> { return abi.encode(7n, new Array<u256>(n), 9n); }
      get packed(n: u256): External<bytes> { return abi.encodePacked(new Array<u256>(n)); }
    }`;
    const S = `contract C {
      function ret(uint256 n) external pure returns (uint256[] memory){ return new uint256[](n); }
      function enc(uint256 n) external pure returns (bytes memory){ return abi.encode(new uint256[](n)); }
      function multi(uint256 n) external pure returns (bytes memory){ return abi.encode(uint256(7), new uint256[](n), uint256(9)); }
      function packed(uint256 n) external pure returns (bytes memory){ return abi.encodePacked(new uint256[](n)); }
    }`;
    await rt(J, S, [
      { sig: 'ret(uint256)', args: P(2n), label: 'direct return' },
      { sig: 'enc(uint256)', args: P(3n), label: 'abi.encode(direct)' },
      { sig: 'multi(uint256)', args: P(3n), label: 'abi.encode(multi)' },
      { sig: 'packed(uint256)', args: P(3n), label: 'abi.encodePacked(direct)' },
    ]);
  });

  it('ternary branch is a new Array [regression: was JETH074 over-rejection]', async () => {
    const J = `class C {
      get tvl(c: bool, n: u256): External<bytes> { let b: u256[] = new Array<u256>(5n); b[0n] = 99n; let r: u256[] = c ? new Array<u256>(n) : b; return abi.encode(r); }
      get tvn(c: bool, n: u256, m: u256): External<bytes> { let r: u256[] = c ? new Array<u256>(n) : new Array<u256>(m); return abi.encode(r); }
    }`;
    const S = `contract C {
      function tvl(bool c, uint256 n) external pure returns (bytes memory){ uint256[] memory b = new uint256[](5); b[0]=99; uint256[] memory r = c ? new uint256[](n) : b; return abi.encode(r); }
      function tvn(bool c, uint256 n, uint256 m) external pure returns (bytes memory){ uint256[] memory r = c ? new uint256[](n) : new uint256[](m); return abi.encode(r); }
    }`;
    await rt(J, S, [
      { sig: 'tvl(bool,uint256)', args: P(1n) + P(3n), label: 'c?newArray:local (true)' },
      { sig: 'tvl(bool,uint256)', args: P(0n) + P(3n), label: 'c?newArray:local (false)' },
      { sig: 'tvn(bool,uint256,uint256)', args: P(1n) + P(3n) + P(4n), label: 'c?newArray:newArray (true)' },
      { sig: 'tvn(bool,uint256,uint256)', args: P(0n) + P(3n) + P(4n), label: 'c?newArray:newArray (false)' },
    ]);
  });

  it('zero-init is active (all-zero even after prior memory use)', async () => {
    const J = `class C {
      get dirty(n: u256): External<bytes> { let scratch: u256[] = new Array<u256>(8n); scratch[0n] = 0xdeadn; scratch[7n] = 0xbeefn; let a: u256[] = new Array<u256>(n); return abi.encode(a); }
    }`;
    const S = `contract C {
      function dirty(uint256 n) external pure returns (bytes memory){ uint256[] memory scratch = new uint256[](8); scratch[0]=0xdead; scratch[7]=0xbeef; uint256[] memory a = new uint256[](n); return abi.encode(a); }
    }`;
    await rt(J, S, [
      { sig: 'dirty(uint256)', args: P(4n), label: 'second alloc all-zero' },
      { sig: 'dirty(uint256)', args: P(0n), label: 'second alloc empty' },
    ]);
  });

  it('accepts value-element new Array forms', () => {
    const ok = (b: string) => `class C { get f(n: u256): External<bytes> { ${b} } }`;
    expect(jethAccepts(ok('let a: u256[] = new Array<u256>(n); return abi.encode(a);'))).toBe(true);
    expect(jethAccepts(ok('let a: bool[] = new Array<bool>(n); return abi.encode(a);'))).toBe(true);
    expect(jethAccepts(ok('let a: address[] = new Array<address>(n); return abi.encode(a);'))).toBe(true);
    expect(jethAccepts(ok('let a: bytes4[] = new Array<bytes4>(n); return abi.encode(a);'))).toBe(true);
    // Residual B: new Array<bytes>(n) / new Array<string>(n) (B2, zero-init each element to an empty
    // blob) and new Array<P>(n) for a STATIC struct P (B1) are now accepted, byte-identical to solc.
    expect(jethAccepts(ok('let a: bytes[] = new Array<bytes>(n); return abi.encode(a);'))).toBe(true);
    expect(jethAccepts(ok('let a: string[] = new Array<string>(n); return abi.encode(a);'))).toBe(true);
    expect(
      jethAccepts(`type P = {a:u256;b:u256;}; class C { get f(n: u256): External<bytes> { let a: P[] = new Array<P>(n); return abi.encode(a); } }`),
    ).toBe(true);
  });

  it('cleanly rejects (no crash) unsupported new Array forms', () => {
    const f = (b: string) => `class C { get f(n: u256): External<bytes> { ${b} } }`;
    // signed-int length -> rejected (matches solc: no implicit int->uint256), no crash
    expect(
      jethCodes(
        `class C { get f(s: i128): External<bytes> { let a: u256[] = new Array<u256>(s); return abi.encode(a); } }`,
      ).length > 0,
    ).toBe(true);
    // B4: a nested-dynamic-leaf array (string[][]) is now ACCEPTED (byte-identical, see
    // nested-dynamic-leaf-array.test.ts). B3: a DYNAMIC-field struct element array (P with a bytes
    // field) is also ACCEPTED (dyn-array-field-struct-local.test.ts).
    expect(jethCodes(f('let a: string[][] = new Array<string[]>(n); return abi.encode(a);'))).toEqual([]);
    expect(
      jethCodes(`type P = {a:u256;s:bytes;}; class C { get f(n: u256): External<bytes> { let a: P[] = new Array<P>(n); return abi.encode(a); } }`),
    ).toEqual([]);
    // a STATIC-struct-leaf nested array (Q[][]) now ACCEPTS (pointer-headed, byte-identical - see
    // pointer-headed-static-struct-array.test.ts).
    expect(jethCodes(`type Q = {a:u256;b:u256;}; class C { get f(n: u256): External<bytes> { let a: Q[][] = new Array<Q[]>(n); return abi.encode(a); } }`)).toEqual([]);
    expect(jethCodes(f('let a: u256[][] = new Array<u256[]>(n); return abi.encode(a);'))).not.toContain('JETH900');
    // wrong arity -> JETH363, no crash
    expect(jethCodes(f('let a: u256[] = new Array<u256>(); return abi.encode(a);'))).toContain('JETH363');
    expect(jethCodes(f('let a: u256[] = new Array<u256>(n, n); return abi.encode(a);'))).toContain('JETH363');
    // non-Array new -> JETH023, no crash
    expect(
      jethCodes(`class C { get f(n: u256): External<u256> { let x = new Foo(n); return 1n; } }`),
    ).toContain('JETH023');
    // none of the above is an internal crash
    for (const src of [
      f('let a: string[] = new Array<string>(n); return abi.encode(a);'),
      f('let a: u256[] = new Array<u256>(); return abi.encode(a);'),
    ])
      expect(jethCodes(src)).not.toContain('JETH900');
  });
});
