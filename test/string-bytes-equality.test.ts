// String compare feature: `a == b` / `a != b` on `string`|`string` or `bytes`|`bytes` (which solc rejects
// as a native op) desugars to the idiomatic `keccak256(bytes(a)) == keccak256(bytes(b))` - byte-identical
// to what a solc user writes. Ordered comparisons (< > <= >=) stay a clean JETH088 reject (no idiom).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const rejects = (src: string): boolean => { try { compile(src, { fileName: 'C.jeth' }); return false; } catch { return true; } };

describe('string / bytes equality (== / !=) - byte-identical to the solc keccak idiom', () => {
  it('==, !=, bytes, long strings all match keccak256(bytes(a)) == keccak256(bytes(b))', async () => {
    const J = `@contract class C {
      @external @pure eq(): bool { let a: string = "hello"; let b: string = "hello"; return a == b; }
      @external @pure ne(): bool { let a: string = "hello"; let b: string = "world"; return a == b; }
      @external @pure nq(): bool { let a: string = "hello"; let b: string = "world"; return a != b; }
      @external @pure by(): bool { let a: bytes = bytes("abc"); let b: bytes = bytes("abd"); return a == b; }
      @external @pure lg(): bool { let a: string = "the quick brown fox jumps over"; let b: string = "the quick brown fox jumps over"; return a == b; } }`;
    const S = `contract C {
      function eq() external pure returns(bool){ string memory a="hello"; string memory b="hello"; return keccak256(bytes(a))==keccak256(bytes(b)); }
      function ne() external pure returns(bool){ string memory a="hello"; string memory b="world"; return keccak256(bytes(a))==keccak256(bytes(b)); }
      function nq() external pure returns(bool){ string memory a="hello"; string memory b="world"; return keccak256(bytes(a))!=keccak256(bytes(b)); }
      function by() external pure returns(bool){ bytes memory a=bytes("abc"); bytes memory b=bytes("abd"); return keccak256(a)==keccak256(b); }
      function lg() external pure returns(bool){ string memory a="the quick brown fox jumps over"; string memory b="the quick brown fox jumps over"; return keccak256(bytes(a))==keccak256(bytes(b)); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const sg of ['eq()', 'ne()', 'nq()', 'by()', 'lg()']) {
      const rj = await h.call(aj, sel(sg));
      const rs = await h.call(as, sel(sg));
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });
  it('ordered comparisons on string/bytes stay rejected (JETH088)', () => {
    expect(rejects(`@contract class C { @external @pure f(a: string, b: string): bool { return a < b; } }`)).toBe(true);
    expect(rejects(`@contract class C { @external @pure f(a: bytes, b: bytes): bool { return a > b; } }`)).toBe(true);
    // a string-vs-bytes == mix still rejects (no common type; matches solc)
    expect(rejects(`@contract class C { @external @pure f(a: string, b: bytes): bool { return a == b; } }`)).toBe(true);
  });
});
