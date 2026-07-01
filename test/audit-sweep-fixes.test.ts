// Fixes for divergences found by the whole-surface adversarial sweep (all confirmed vs solc 0.8.35):
//  - MISCOMPILE: a `\xNN` string-literal escape was decoded as a JS code unit (U+00NN -> UTF-8) instead of
//    a RAW byte, so bytes("\xff") / keccak256 / concat produced wrong bytes (silent wrong hashes). Now
//    decoded Solidity-style (raw byte). A `\xNN`-invalid-UTF-8 STRING literal is rejected (JETH281).
//  - MISCOMPILE: abi.encode of a STORAGE struct whose field is a nested DYNAMIC struct (W{id; t: T{n; s}})
//    corrupted the nested member (dropped n / bad offsets / spurious revert). The storage->memory copy now
//    stores the nested dynamic struct as a head pointer to a recursively-built image.
//  - MISCOMPILE: a value-returning high-level interface call whose result is DISCARDED (IFoo(a).f();)
//    skipped solc's returndata-size validation, so a short/malformed return succeeded instead of reverting.
//  - OVER-ACCEPTANCE: a bare integer implicitly converted to an enum in a @constant initializer
//    (@constant K: Color = 2n) - solc rejects int_const -> enum; now JETH280, like the local form.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => n.toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};

describe('audit sweep fixes - byte-identical to solc 0.8.35', () => {
  it('\\xNN string escapes are raw bytes (bytes / keccak / concat)', async () => {
    await eqCalls(
      '@contract class C { @external @pure a(): bytes { return bytes("\\xff"); } @external @pure b(): bytes32 { return keccak256(bytes("\\xff")); } @external @pure c(): bytes { return bytes("\\xC0\\xFF\\xEE"); } @external @pure d(): bytes { return bytes.concat(bytes("\\x80"), bytes("ab")); } }',
      'contract C { function a() external pure returns(bytes memory){ return bytes("\\xff"); } function b() external pure returns(bytes32){ return keccak256(bytes("\\xff")); } function c() external pure returns(bytes memory){ return bytes("\\xC0\\xFF\\xEE"); } function d() external pure returns(bytes memory){ return bytes.concat(bytes("\\x80"), bytes("ab")); } }',
      [['a()', ''], ['b()', ''], ['c()', ''], ['d()', '']],
    );
  });

  it('\\xNN in a template-literal static part (with substitution) is a raw byte too', async () => {
    await eqCalls(
      '@contract class C { @external @pure f(x: string): string { return `A\\xc3\\xa9${x}`; } }',
      'contract C { function f(string calldata x) external pure returns(string memory){ return string.concat("A\\xc3\\xa9", x); } }',
      [['f(string)', W(0x20n) + W(1n) + '7a'.padEnd(64, '0')]],
    );
  });

  it('a \\xNN-invalid-UTF-8 string literal is rejected (JETH281); valid UTF-8 / ascii accepted', () => {
    expect(codes('@contract class C { @external @pure f(): string { return "\\xe9"; } }')).toContain('JETH281');
    expect(codes('@contract class C { @external @pure f(): string { return "\\xc3\\xa9"; } }')).toEqual([]);
    expect(codes('@contract class C { @external @pure f(): string { return "hello"; } }')).toEqual([]);
  });

  it('abi.encode of a storage struct with a nested dynamic-struct field (empty + non-empty inner string)', async () => {
    const D = '@struct class T { n: u256; s: string; } @struct class W { id: u256; t: T; }';
    const Ds = 'struct T { uint256 n; string s; } struct W { uint256 id; T t; }';
    await eqCalls(
      `${D} @contract class C { @state w: W; @external e(): bytes { this.w.id=9n; this.w.t.n=100n; this.w.t.s=""; return abi.encode(this.w); } @external ne(): bytes { this.w.id=9n; this.w.t.n=100n; this.w.t.s="hello-world"; return abi.encode(this.w); } }`,
      `${Ds} contract C { W w; function e() external returns(bytes memory){ w.id=9; w.t.n=100; w.t.s=""; return abi.encode(w); } function ne() external returns(bytes memory){ w.id=9; w.t.n=100; w.t.s="hello-world"; return abi.encode(w); } }`,
      [['e()', ''], ['ne()', '']],
    );
  });

  it('@constant enum from a bare integer is rejected (JETH280); member / cast accepted byte-identical', async () => {
    const E = 'enum Color { Red, Green, Blue } ';
    expect(codes(E + '@contract class C { @constant K: Color = 2n; @external @pure f(): Color { return this.K; } }')).toContain('JETH280');
    expect(codes(E + '@contract class C { @constant K: Color = 3n; @external @pure f(): Color { return this.K; } }')).toContain('JETH280');
    await eqCalls(
      E + '@contract class C { @constant K: Color = Color.Blue; @external @pure f(): Color { return this.K; } }',
      'enum Color { Red, Green, Blue } contract C { Color constant K = Color.Blue; function f() external pure returns(Color){ return K; } }',
      [['f()', '']],
    );
    await eqCalls(
      E + '@contract class C { @constant K: Color = Color(1n); @external @pure f(): Color { return this.K; } }',
      'enum Color { Red, Green, Blue } contract C { Color constant K = Color(1); function f() external pure returns(Color){ return K; } }',
      [['f()', '']],
    );
  });

  it('a discarded value-returning interface call validates returndata size (reverts on a short return)', async () => {
    const jethC = '@interface class IERC20 { @external transfer(to: address, amt: u256): bool; } @contract class C { @external f(t: address): u256 { IERC20(t).transfer(t, 1n); return 42n; } }';
    const solC = 'interface IERC20 { function transfer(address to, uint256 amt) external returns(bool); } contract C { function f(address t) external returns(uint256){ IERC20(t).transfer(t, 1); return 42; } }';
    const targets = {
      good: 'contract T { function transfer(address, uint256) external returns(bool){ return true; } }',
      bad: 'contract T { fallback() external {} }', // returns 0 bytes
    } as const;
    for (const [label, tsrc] of Object.entries(targets)) {
      for (const [name, creation] of [
        ['jeth', compile(jethC, { fileName: 'C.jeth' }).creationBytecode],
        ['sol', compileSolidity(SPDX + solC, 'C').creation],
      ] as const) {
        const h = await Harness.create();
        const t = await h.deploy(compileSolidity(SPDX + tsrc, 'T').creation);
        const c = await h.deploy(creation);
        const r = await h.call(c, sel('f(address)') + pad32(BigInt(t.toString())).toString());
        // good target: both succeed (return 42). bad target: both revert (short returndata).
        if (label === 'good') expect(r.success, `${label}/${name}`).toBe(true);
        else expect(r.success, `${label}/${name}`).toBe(false);
      }
    }
  });
});
