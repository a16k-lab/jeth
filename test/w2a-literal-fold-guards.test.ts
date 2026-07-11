// W2A literal / fold guards: OVER-ACCEPTANCE + CRASH fixes where JETH used to accept what solc rejects.
// Each family asserts (a) the target now REJECTS with the intended diagnostic, and (b) an adjacent VALID
// battery still compiles and runs BYTE-IDENTICAL to solc 0.8.35 (no new over-rejection).
//  P0-27/30-octal: a leading-zero (C-style octal) decimal literal `010` / `08` / `0777` / `0_1` is a solc
//                  parser error; JETH used to fold `010` -> 10. rejectUppercaseHexPrefix now screens it.
//  P0-28: an enum compared to an out-of-range integer literal (`c == 300`) - solc forbids enum OP int_const
//         for ANY literal; widenLiteralOperand.fit() now bails on an enum operand (JETH280).
//  P0-29: abi.encodePacked of an untyped literal (`abi.encodePacked(42)`) - solc "Cannot perform packed
//         encoding for a literal"; checkAbiEncode now rejects a syntactic int_const arg in packed mode.
//  P0-30-enum-hoist: an enum declared inside a method body was hoisted + compiled; the parser now hoists
//         ONLY enums directly in a class body (a method-body enum reaches the analyzer as JETH061).
//  P0-31: an Arr<T,N> length above 2^53 was silently rounded through a JS double (mislaying storage
//         slots); the length is now read exactly and a > MAX_SAFE_INTEGER length is a sound reject.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => n.toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

function rejectCodes(jeth: string): string[] {
  try {
    compile(jeth, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
}

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + (args ?? ''));
    const rs = await hs.call(as, sel(sig) + (args ?? ''));
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

describe('W2A: leading-zero (octal) decimal literals rejected', () => {
  for (const lit of ['010', '08', '09', '00', '0777', '0_1'])
    it(`rejects ${lit}`, () => {
      expect(rejectCodes(`class C { get f(): External<u256> { return ${lit}; } }`)).toContain('JETH049');
    });
  it('keeps 0 / 0x2a / 0e5 / 0.5e1 / 0n byte-identical', async () => {
    for (const [j, s] of [
      ['0n', '0'],
      ['0x2a', '0x2a'],
      ['0n', '0e5'], // 0e5 == 0
      ['5n', '0.5e1'], // 0.5e1 == 5
    ] as [string, string][])
      await eqCalls(
        `class C { get f(): External<u256> { return ${j}; } }`,
        `contract C { function f() external pure returns (uint256){ return ${s}; } }`,
        [['f()', '']],
      );
  });
});

describe('W2A: enum vs out-of-range integer-literal comparison rejected', () => {
  const JH = 'class C { enum Color { Red, Green, Blue }\n';
  for (const op of ['==', '!=', '<', '>', '<=', '>='])
    it(`rejects c ${op} 300n`, () => {
      expect(rejectCodes(`${JH} get f(c: Color): External<bool> { return c ${op} 300n; } }`)).toContain('JETH280');
    });
  it('rejects 300n == c (reversed operand order)', () => {
    expect(rejectCodes(`${JH} get f(c: Color): External<bool> { return 300n == c; } }`)).toContain('JETH280');
  });
  it('keeps enum vs enum-member comparisons byte-identical', async () => {
    const SH = 'contract C { enum Color { Red, Green, Blue }\n';
    for (const op of ['==', '!=', '<', '>', '<=', '>='])
      await eqCalls(
        `${JH} get f(c: Color): External<bool> { return c ${op} Color.Green; } }`,
        `${SH} function f(Color c) external pure returns (bool){ return c ${op} Color.Green; } }`,
        [['f(uint8)', W(1n)]],
      );
  });
  it('keeps a plain uint8 var vs 300 (intended widening) byte-identical', async () => {
    await eqCalls(
      'class C { get f(x: u8): External<bool> { return x == 300n; } }',
      'contract C { function f(uint8 x) external pure returns (bool){ return x == 300; } }',
      [['f(uint8)', W(5n)]],
    );
  });
});

describe('W2A: packed abi encoding of an untyped literal rejected', () => {
  const wrap = (arg: string) => `class C { get f(): External<bytes> { return abi.encodePacked(${arg}); } }`;
  for (const arg of ['42n', '0x2a', '1000000000000000000n', '-1n', '(42n)', '1n + 1n', '2n ** 8n', '1n << 4n'])
    it(`rejects abi.encodePacked(${arg})`, () => {
      expect(rejectCodes(wrap(arg))).toContain('JETH173');
    });
  it('rejects keccak256(abi.encodePacked(7n, 9n))', () => {
    expect(
      rejectCodes('class C { get f(): External<bytes32> { return keccak256(abi.encodePacked(7n, 9n)); } }'),
    ).toContain('JETH173');
  });
  it('keeps a typed local / explicit cast / bool / string / address literal byte-identical', async () => {
    await eqCalls(
      'class C { get f(x: u8): External<bytes> { return abi.encodePacked(x, true, "hi"); } }',
      'contract C { function f(uint8 x) external pure returns (bytes memory){ return abi.encodePacked(x, true, "hi"); } }',
      [['f(uint8)', W(0x2an)]],
    );
    await eqCalls(
      'class C { get f(): External<bytes> { return abi.encodePacked(u256(1n + 1n), address(0n)); } }',
      'contract C { function f() external pure returns (bytes memory){ return abi.encodePacked(uint256(1 + 1), address(0)); } }',
      [['f()', '']],
    );
  });
  it('keeps a literal in standard abi.encode / encodeWithSignature byte-identical', async () => {
    await eqCalls(
      'class C { get f(): External<bytes> { return abi.encode(42n, true); } }',
      'contract C { function f() external pure returns (bytes memory){ return abi.encode(42, true); } }',
      [['f()', '']],
    );
    await eqCalls(
      'class C { get f(): External<bytes> { return abi.encodeWithSignature("g(uint256)", 42n); } }',
      'contract C { function f() external pure returns (bytes memory){ return abi.encodeWithSignature("g(uint256)", 42); } }',
      [['f()', '']],
    );
  });
});

describe('W2A: enum declared inside a method body rejected (not hoisted)', () => {
  it('rejects a method-body enum', () => {
    expect(
      rejectCodes('class C { get f(): External<u8> { enum E { A, B, Z } return u8(E.Z); } }'),
    ).toContain('JETH061');
  });
  it('rejects a nested-block enum', () => {
    expect(
      rejectCodes(
        'class C { get f(): External<u8> { if (true) { enum E { A, B } return u8(E.B); } return 0n; } }',
      ),
    ).toContain('JETH061');
  });
  it('rejects a method-body enum even when a class-level enum is also present', () => {
    expect(
      rejectCodes(
        'class C { enum Color { Red, Green }\n get f(): External<u8> { enum E { A, B } return u8(E.B); } }',
      ),
    ).toContain('JETH061');
  });
  it('keeps a class-level enum (declared after a method with a nested block) byte-identical', async () => {
    await eqCalls(
      'class C { get g(): External<u8> { if (true) { return 1n; } return 0n; }\n enum Color { Red, Green, Blue }\n get f(): External<u8> { return u8(Color.Blue); } }',
      'contract C { function g() external pure returns (uint8) { if (true) { return 1; } return 0; }\n enum Color { Red, Green, Blue }\n function f() external pure returns (uint8) { return uint8(Color.Blue); } }',
      [['f()', ''], ['g()', '']],
    );
  });
});

describe('W2A: over-2^53 fixed-array length rejected (no silent double rounding)', () => {
  const st = (len: string) =>
    `class C { a: Arr<u256, ${len}>;\n b: u256;\n get g(): External<u256> { return this.b; } }`;
  it('rejects 2^53+1 (9007199254740993)', () => {
    expect(rejectCodes(st('9007199254740993'))).toContain('JETH446');
  });
  it('rejects 2^53 (9007199254740992)', () => {
    expect(rejectCodes(st('9007199254740992'))).toContain('JETH446');
  });
  it('rejects 2^54+1 (18014398509481985)', () => {
    expect(rejectCodes(st('18014398509481985'))).toContain('JETH446');
  });
  it('keeps normal small lengths byte-identical, incl. a for-of over Arr<u256,2>[]', async () => {
    await eqCalls(
      'class C { a: Arr<u256,3>;\n setz(v: u256): External<void> { this.a[1n] = v; }\n get getz(): External<u256> { return this.a[1n]; } }',
      'contract C { uint256[3] a;\n function setz(uint256 v) external { a[1]=v; }\n function getz() external view returns (uint256){ return a[1]; } }',
      [['setz(uint256)', W(0x2an)], ['getz()', '']],
    );
    await eqCalls(
      'class C { get f(): External<u256> { let xs: Arr<u256,2>[] = [[1n,2n],[3n,4n]]; let s: u256 = 0n; for (let row of xs) { s = s + row[0n] + row[1n]; } return s; } }',
      'contract C { function f() external pure returns(uint256){ uint256[2][] memory xs = new uint256[2][](2); xs[0]=[uint256(1),2]; xs[1]=[uint256(3),4]; uint256 s=0; for (uint i=0;i<xs.length;i++){ uint256[2] memory row=xs[i]; s+=row[0]+row[1]; } return s; } }',
      [['f()', '']],
    );
  });
});
