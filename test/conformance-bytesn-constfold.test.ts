// Conformance audit fixes: bytesN[i] indexing (#10), empty-statement rejection (#13), and
// constant-folding in state initializers (#9), each matched to solc 0.8.35.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => v.toString(16).padStart(64, '0');
function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}

describe('bytesN[i] indexing (#10) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `class C { s: bytes32;
    setS(v: bytes32): External<void> { this.s = v; }
    get at(i: u256): External<bytes1> { return this.s[i]; }
    get atP(b: bytes32, i: u256): External<bytes1> { return b[i]; } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C { bytes32 s;
  function setS(bytes32 v) external { s = v; }
  function at(uint256 i) external view returns (bytes1) { return s[i]; }
  function atP(bytes32 b, uint256 i) external pure returns (bytes1) { return b[i]; } }`;
  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
    const V = (0xaabbccddn << 224n) | (0xeen << 8n);
    await jeth.call(aj, '0x' + sel('setS(bytes32)') + pad(V));
    await sol.call(as, '0x' + sel('setS(bytes32)') + pad(V));
  });
  it('every index (state + value base) is byte-identical incl. OOB Panic 0x32', async () => {
    const V = (0xaabbccddn << 224n) | (0xeen << 8n);
    for (const i of [0n, 1n, 3n, 4n, 30n, 31n, 32n, 255n]) {
      for (const [label, data] of [
        [`at(${i})`, '0x' + sel('at(uint256)') + pad(i)] as const,
        [`atP(${i})`, '0x' + sel('atP(bytes32,uint256)') + pad(V) + pad(i)] as const,
      ]) {
        const j = await jeth.call(aj, data);
        const s = await sol.call(as, data);
        expect(j.success, `${label}`).toBe(s.success);
        expect(j.returnHex, `${label}`).toBe(s.returnHex);
      }
    }
  });
  it('a constant out-of-range byte index is a compile error; a dynamic-bytes b[i] is unaffected', () => {
    expect(codes('class C { get f(b: bytes4): External<bytes1> { return b[5n]; } }')).toContain('JETH152');
    expect(codes('class C { get f(b: bytes4): External<bytes1> { return b[3n]; } }')).toEqual([]);
    expect(codes('class C { get f(b: bytes, i: u256): External<bytes1> { return b[i]; } }')).toEqual([]);
  });
});

describe('empty statement (#13)', () => {
  it('a lone `;` is rejected, matching solc grammar', () => {
    expect(codes('class C { get f(): External<u256> { ; return 1n; } }')).toContain('JETH061');
  });
});

describe('constant folding in state initializers (#9) vs solc', () => {
  it('folds + - * ** << >> & | ^ % (and exact /) with unbounded intermediates + final range-check', () => {
    // accepted (final value fits, intermediates unbounded)
    for (const init of [
      '100n + 50n',
      '300n - 200n',
      '2n * 100n',
      '1n << 4n',
      '0xffn & 0x0fn',
      '6n / 2n',
      '10n % 3n',
      '255n >> 1n',
    ]) {
      expect(codes(`class C { x: u8 = ${init}; }`), init).toEqual([]);
    }
    for (const init of ['10n ** 18n', '2n ** 255n', '(2n ** 256n) - 1n']) {
      expect(codes(`class C { x: u256 = ${init}; }`), init).toEqual([]);
    }
    expect(codes('class C { x: i8 = -(100n + 28n); }')).toEqual([]); // -128 fits i8
    // rejected with a range error (the folded final value overflows)
    for (const init of ['100n + 200n', '255n + 1n', '3n * 100n', '1n << 8n']) {
      expect(codes(`class C { x: u8 = ${init}; }`), init).toContain('JETH070');
    }
    expect(codes('class C { x: u256 = 2n ** 256n; }')).toContain('JETH070');
    // a fractional `/` is not a foldable constant (solc also rejects it), so it is JETH048
    expect(codes('class C { x: u8 = 7n / 2n; }')).toContain('JETH048');
  });
  it('a folded initializer is byte-identical to solc at runtime', async () => {
    const J =
      'class C { DEC: u256 = 10n ** 18n; Y: u8 = 300n - 200n; get dec(): External<u256> { return this.DEC; } get y(): External<u8> { return this.Y; } }';
    const S =
      '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\ncontract C { uint256 public DEC = 10**18; uint8 public Y = 300-200; }';
    const h = await Harness.create();
    const hs = await Harness.create();
    const a = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const b = await hs.deploy(compileSolidity(S, 'C').creation);
    expect((await h.call(a, '0x' + sel('dec()'))).returnHex).toBe((await hs.call(b, '0x' + sel('DEC()'))).returnHex);
    expect((await h.call(a, '0x' + sel('y()'))).returnHex).toBe((await hs.call(b, '0x' + sel('Y()'))).returnHex);
  });
});
