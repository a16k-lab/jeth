// Regression tests for the two bugs the Phase 4 verification workflow confirmed:
//  A) echoing a calldata array of a narrow element type must CLEAN dirty elements
//     (not revert), matching Solidity's array-to-memory copy.
//  B) a struct with a multi-word (array/nested) field is rejected (1-word-per-field
//     return assumption stays valid); deferred to the nested-access increment.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

function pad32(v: bigint): string {
  return (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
}
function codesFor(source: string): string[] {
  try {
    compile(source, { fileName: 't.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}

const JETH = `@contract
class E {
  @external @pure echoU8(x: u8[]): u8[] { return x; }
  @external @pure echoI8(x: i8[]): i8[] { return x; }
  @external @pure echoBool(x: bool[]): bool[] { return x; }
  @external @pure echoB4(x: bytes4[]): bytes4[] { return x; }
  @external @pure echoI16(x: i16[]): i16[] { return x; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract E {
  function echoU8(uint8[] calldata x) external pure returns (uint8[] memory){ return x; }
  function echoI8(int8[] calldata x) external pure returns (int8[] memory){ return x; }
  function echoBool(bool[] calldata x) external pure returns (bool[] memory){ return x; }
  function echoB4(bytes4[] calldata x) external pure returns (bytes4[] memory){ return x; }
  function echoI16(int16[] calldata x) external pure returns (int16[] memory){ return x; }
}`;

describe('Phase 4 regression: clean dirty calldata array elements (Bug A)', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'E.jeth' });
    const sb = compileSolidity(SOL, 'E');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('cleans dirty elements byte-identically to Solidity (no spurious revert)', async () => {
    const dirty: [string, bigint][] = [
      ['echoU8(uint8[])', 0x1ffn], // high bits set -> cleaned to 0xff
      ['echoI8(int8[])', 0x80n], // not a valid int8 sign-ext -> -128
      ['echoBool(bool[])', 2n], // >1 -> 1
      ['echoB4(bytes4[])', BigInt('0xaabbccdd' + 'ff'.repeat(28))], // dirty low bytes -> masked
      ['echoI16(int16[])', 0xffffn], // -> -1 (sign-extended)
    ];
    for (const [sig, elem] of dirty) {
      const data = '0x' + functionSelector(sig) + pad32(0x20n) + pad32(1n) + pad32(elem);
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(j.success, `${sig} success (jeth err=${j.exceptionError})`).toBe(true);
      expect(s.success, `${sig} sol success`).toBe(true);
      expect(j.returnHex, `${sig} returndata`).toBe(s.returnHex);
    }
  });
});

describe('Phase 4 regression: struct field/return gating (Bug B)', () => {
  it('static struct returns (incl fixed-array / nested-static-struct fields) compile via the storage encoder', () => {
    // returning a struct with a fixed-array or nested-static-struct field is now SUPPORTED
    // (the storage-source recursive encoder flattens it via structStorageLeaves;
    // byte-identical to solc, verified in fixed-array-return.test.ts).
    expect(codesFor(`@struct class S { a: u256; arr: Arr<u256,2>; b: u256; }\n@contract class T { @state s: S; @view f(): S { return this.s; } }`)).toEqual([]);
    expect(codesFor(`@struct class Inner { x: u256; }\n@struct class S { a: u256; inner: Inner; }\n@contract class T { @state s: S; @view f(): S { return this.s; } }`)).toEqual([]);
    // a dynamic (string) struct is now SUPPORTED in storage as a bare @state var
    // (each bytes/string field is a normal storage bytes/string at base+fieldSlot);
    // the bare declaration compiles cleanly.
    expect(codesFor(`@struct class S { a: u256; b: string; }\n@contract class T { @state s: S; @external set(v: string): void { this.s.b = v; } }`)).toEqual([]);
    // returning a WHOLE storage dynamic struct is now SUPPORTED (storage-source
    // recursive head/tail encoder; byte-identical to solc).
    expect(codesFor(`@struct class S { a: u256; b: string; }\n@contract class T { @state s: S; @view f(): S { return this.s; } }`)).toEqual([]);
    // a flat value-only struct return still compiles
    expect(codesFor(`@struct class S { a: u128; b: bool; }\n@contract class T { @state s: S; @view f(): S { return this.s; } }`)).toEqual([]);
  });
});
