// Fixes for divergences found by the whole-surface adversarial sweep (all confirmed vs solc 0.8.35):
//  - MISCOMPILE: a `\xNN` string-literal escape was decoded as a JS code unit (U+00NN -> UTF-8) instead of
//    a RAW byte, so bytes("\xff") / keccak256 / concat produced wrong bytes (silent wrong hashes). Now
//    decoded Solidity-style (raw byte). A `\xNN`-invalid-UTF-8 STRING literal is rejected (JETH447).
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
      'class C { get a(): External<bytes> { return bytes("\\xff"); } get b(): External<bytes32> { return keccak256(bytes("\\xff")); } get c(): External<bytes> { return bytes("\\xC0\\xFF\\xEE"); } get d(): External<bytes> { return bytes.concat(bytes("\\x80"), bytes("ab")); } }',
      'contract C { function a() external pure returns(bytes memory){ return bytes("\\xff"); } function b() external pure returns(bytes32){ return keccak256(bytes("\\xff")); } function c() external pure returns(bytes memory){ return bytes("\\xC0\\xFF\\xEE"); } function d() external pure returns(bytes memory){ return bytes.concat(bytes("\\x80"), bytes("ab")); } }',
      [['a()', ''], ['b()', ''], ['c()', ''], ['d()', '']],
    );
  });

  it('\\xNN in a template-literal static part (with substitution) is a raw byte too', async () => {
    await eqCalls(
      'class C { get f(x: string): External<string> { return `A\\xc3\\xa9${x}`; } }',
      'contract C { function f(string calldata x) external pure returns(string memory){ return string.concat("A\\xc3\\xa9", x); } }',
      [['f(string)', W(0x20n) + W(1n) + '7a'.padEnd(64, '0')]],
    );
  });

  it('a \\xNN-invalid-UTF-8 string literal is rejected (JETH447); valid UTF-8 / ascii accepted', () => {
    expect(codes('class C { get f(): External<string> { return "\\xe9"; } }')).toContain('JETH447');
    expect(codes('class C { get f(): External<string> { return "\\xc3\\xa9"; } }')).toEqual([]);
    expect(codes('class C { get f(): External<string> { return "hello"; } }')).toEqual([]);
  });

  it('abi.encode of a storage struct with a nested dynamic-struct field (empty + non-empty inner string)', async () => {
    const D = 'type T = { n: u256; s: string; }; type W = { id: u256; t: T; };';
    const Ds = 'struct T { uint256 n; string s; } struct W { uint256 id; T t; }';
    await eqCalls(
      `${D} class C { w: W; e(): External<bytes> { this.w.id=9n; this.w.t.n=100n; this.w.t.s=""; return abi.encode(this.w); } ne(): External<bytes> { this.w.id=9n; this.w.t.n=100n; this.w.t.s="hello-world"; return abi.encode(this.w); } }`,
      `${Ds} contract C { W w; function e() external returns(bytes memory){ w.id=9; w.t.n=100; w.t.s=""; return abi.encode(w); } function ne() external returns(bytes memory){ w.id=9; w.t.n=100; w.t.s="hello-world"; return abi.encode(w); } }`,
      [['e()', ''], ['ne()', '']],
    );
  });

  it('@constant enum from a bare integer is rejected (JETH280); member / cast accepted byte-identical', async () => {
    const E = 'enum Color { Red, Green, Blue } ';
    expect(codes(E + 'class C { static K: Color = 2n; get f(): External<Color> { return this.K; } }')).toContain('JETH280');
    expect(codes(E + 'class C { static K: Color = 3n; get f(): External<Color> { return this.K; } }')).toContain('JETH280');
    await eqCalls(
      E + 'class C { static K: Color = Color.Blue; get f(): External<Color> { return this.K; } }',
      'enum Color { Red, Green, Blue } contract C { Color constant K = Color.Blue; function f() external pure returns(Color){ return K; } }',
      [['f()', '']],
    );
    await eqCalls(
      E + 'class C { static K: Color = Color(1n); get f(): External<Color> { return this.K; } }',
      'enum Color { Red, Green, Blue } contract C { Color constant K = Color(1); function f() external pure returns(Color){ return K; } }',
      [['f()', '']],
    );
  });

  it('a discarded value-returning interface call validates returndata size (reverts on a short return)', async () => {
    const jethC = 'interface IERC20 { transfer(to: address, amt: u256): bool; } class C { f(t: address): External<u256> { IERC20(t).transfer(t, 1n); return 42n; } }';
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
