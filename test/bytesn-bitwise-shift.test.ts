// Conformance audit fixes (operator type rules). solc 0.8 allows the bit-vector operators
// & | ^ ~ << >> on fixed bytes (bytesN); JETH used to reject them (isInteger gate too narrow, the
// sibling of the bool-ordering gap). It also used to ACCEPT a signed shift amount and a signed
// exponent that solc rejects, and to REJECT the no-op bool(x) self-cast that solc accepts. This pins
// all of them to solc, byte-identical at runtime.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
const wrap = (v: bigint) => (((v % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
function codes(src: string): string[] {
  try { compile(src, { fileName: 'C.jeth' }); return []; }
  catch (e) { if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e; }
}

const J = `@contract class C {
  @external @pure and4(a: bytes4, b: bytes4): bytes4 { return a & b; }
  @external @pure or4(a: bytes4, b: bytes4): bytes4 { return a | b; }
  @external @pure xor4(a: bytes4, b: bytes4): bytes4 { return a ^ b; }
  @external @pure not4(a: bytes4): bytes4 { return ~a; }
  @external @pure not32(a: bytes32): bytes32 { return ~a; }
  @external @pure shl4(a: bytes4, n: u8): bytes4 { return a << n; }
  @external @pure shr4(a: bytes4, n: u8): bytes4 { return a >> n; }
  @external @pure shr32(a: bytes32, n: u8): bytes32 { return a >> n; }
  @external @pure and32(a: bytes32, b: bytes32): bytes32 { return a & b; }
  @external @pure boolId(a: bool): bool { return bool(a); }
}`;
const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  function and4(bytes4 a, bytes4 b) external pure returns(bytes4){return a & b;}
  function or4(bytes4 a, bytes4 b) external pure returns(bytes4){return a | b;}
  function xor4(bytes4 a, bytes4 b) external pure returns(bytes4){return a ^ b;}
  function not4(bytes4 a) external pure returns(bytes4){return ~a;}
  function not32(bytes32 a) external pure returns(bytes32){return ~a;}
  function shl4(bytes4 a, uint8 n) external pure returns(bytes4){return a << n;}
  function shr4(bytes4 a, uint8 n) external pure returns(bytes4){return a >> n;}
  function shr32(bytes32 a, uint8 n) external pure returns(bytes32){return a >> n;}
  function and32(bytes32 a, bytes32 b) external pure returns(bytes32){return a & b;}
  function boolId(bool a) external pure returns(bool){return bool(a);}
}`;

describe('bytesN bitwise/shift + signedness + bool-cast conformance', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  let bad = 0;
  async function eq(label: string, sig: string, ...args: bigint[]) {
    const data = '0x' + sel(sig) + args.map(wrap).join('');
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });

  it('bytesN & | ^ ~ are byte-identical to solc', async () => {
    const A = 0xaabbccddn << 224n, B = 0x0f0f0f0fn << 224n;
    await eq('and4', 'and4(bytes4,bytes4)', A, B);
    await eq('or4', 'or4(bytes4,bytes4)', A, B);
    await eq('xor4', 'xor4(bytes4,bytes4)', A, B);
    await eq('not4', 'not4(bytes4)', A);                 // low 28 bytes must stay zero
    await eq('not32', 'not32(bytes32)', 0xffffffffn << 224n);
    await eq('and32', 'and32(bytes32,bytes32)', (1n << 255n) | 7n, (1n << 255n) | 3n);
  });

  it('bytesN << >> are byte-identical across every shift amount (incl. the masked >> low region)', async () => {
    const A = 0xaabbccddn << 224n;
    for (const n of [0n, 1n, 3n, 4n, 8n, 12n, 16n, 24n, 31n, 32n, 33n, 255n]) {
      await eq(`shl4 n=${n}`, 'shl4(bytes4,uint8)', A, n);
      await eq(`shr4 n=${n}`, 'shr4(bytes4,uint8)', A, n);
    }
    await eq('shr32', 'shr32(bytes32,uint8)', (0x1234n << 240n) | 0xabn, 8n);
  });

  it('bool(x) self-cast is byte-identical to solc', async () => {
    await eq('boolId(false)', 'boolId(bool)', 0n);
    await eq('boolId(true)', 'boolId(bool)', 1n);
  });

  it('rejects what solc rejects: signed exponent and signed shift amount', () => {
    expect(codes('@contract class C { @external @pure f(a: i8, b: i8): i8 { return a ** b; } }')).toContain('JETH082');
    expect(codes('@contract class C { @external @pure f(a: u8, n: i8): u8 { return a << n; } }')).toContain('JETH081');
    expect(codes('@contract class C { @external @pure f(a: u8, n: i8): u8 { return a >> n; } }')).toContain('JETH081');
  });

  it('still rejects what solc rejects: arithmetic (+ - * / %) on bytesN', () => {
    for (const op of ['+', '-', '*', '/', '%']) {
      expect(codes(`@contract class C { @external @pure f(a: bytes4, b: bytes4): bytes4 { return a ${op} b; } }`), `'${op}' on bytesN`).toContain('JETH082');
    }
  });

  it('still accepts unsigned exponent and unsigned shift amount, and integer bitwise', () => {
    expect(codes('@contract class C { @external @pure f(a: u8, b: u8): u8 { return a ** b; } }')).toEqual([]);
    expect(codes('@contract class C { @external @pure f(a: u8, n: u8): u8 { return a << n; } }')).toEqual([]);
    expect(codes('@contract class C { @external @pure f(a: u8, b: u8): u8 { return a & b; } }')).toEqual([]);
  });

  it('the literal 0 implicitly converts to bytesN like solc; any other literal does not', async () => {
    expect(codes('@contract class C { @external @pure f(): bytes32 { return 0n; } }')).toEqual([]);     // solc accepts
    expect(codes('@contract class C { @external @pure f(): bytes4 { let b: bytes4 = 0n; return b; } }')).toEqual([]);
    expect(codes('@contract class C { @external @pure f(): bytes32 { return 1n; } }')).toContain('JETH084'); // only 0
    // runtime: 0n -> bytes32 is the all-zero word
    const J0 = '@contract class C { @external @pure z(): bytes32 { return 0n; } }';
    const h0 = await Harness.create(); const a0 = await h0.deploy(compile(J0, { fileName: 'C.jeth' }).creationBytecode);
    expect((await h0.call(a0, '0x' + sel('z()'))).returnHex).toBe('0x' + '0'.repeat(64));
  });
});
