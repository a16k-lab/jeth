// STR-EQ-LIT lift: a BARE string literal as a string-equality operand (`s == "hi"`, `"hi" == s`,
// `s != "hi"`, `"a" == "b"`) now compiles EXACTLY like its explicit-cast twin `s == string("hi")`
// (pre-fix: JETH074 "a string literal is only valid where a string/bytes value is expected").
// The literal is typed `string` iff the OTHER equality operand is string-typed (or both are bare
// literals), so the operands reach the existing keccak-equality desugar unchanged - the lowered
// form is `keccak256(bytes(a)) == keccak256(bytes(b))`, byte-identical to the solc idiom.
// Solc witnesses (0.8.35, recorded before the lift): native `s == "hi"` REJECTS ("Built-in binary
// operator == cannot be applied to types string memory and literal_string"), ordered `s < "hi"`
// REJECTS, `bytes == literal` REJECTS, `"a" == "b"` REJECTS, `s == 5` REJECTS; every keccak
// mirror (incl. empty / long / unicode / lit==lit / require / ternary) ACCEPTS.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string): string => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    if (e && Array.isArray(e.diagnostics)) {
      return e.diagnostics.filter((d: any) => d.severity === 'error').map((d: any) => d.code);
    }
    return ['THREW-NON-COMPILE-ERROR'];
  }
};
// ABI-encode a single dynamic string argument (head offset 0x20 + length + right-padded data).
const enc = (s: string): string => {
  const b = Buffer.from(s, 'utf8');
  return W(0x20) + W(b.length) + b.toString('hex').padEnd(Math.ceil(b.length / 32) * 64, '0');
};
const LONG = 'the quick brown fox jumps over the lazy dog again'; // 50 bytes > 31

describe('string == bare-literal (STR-EQ-LIT): byte-identical to the string("...") cast twin', () => {
  it('twin bytecode identity across operand shapes, both operators, both literal sides', () => {
    const cells: [string, string, string][] = [
      ['param == lit-R', `class C { get eq(s: string): External<bool> { return s == "hi"; } }`,
        `class C { get eq(s: string): External<bool> { return s == string("hi"); } }`],
      ['param != lit-R', `class C { get eq(s: string): External<bool> { return s != "hi"; } }`,
        `class C { get eq(s: string): External<bool> { return s != string("hi"); } }`],
      ['param == lit-L', `class C { get eq(s: string): External<bool> { return "hi" == s; } }`,
        `class C { get eq(s: string): External<bool> { return string("hi") == s; } }`],
      ['param != lit-L', `class C { get eq(s: string): External<bool> { return "hi" != s; } }`,
        `class C { get eq(s: string): External<bool> { return string("hi") != s; } }`],
      ['local operand', `class C { get eq(x: string): External<bool> { let a: string = x; return a == "loc"; } }`,
        `class C { get eq(x: string): External<bool> { let a: string = x; return a == string("loc"); } }`],
      ['state operand', `class C { t: string; set(v: string): External<void> { this.t = v; } get eq(): External<bool> { return this.t == "seed"; } }`,
        `class C { t: string; set(v: string): External<void> { this.t = v; } get eq(): External<bool> { return this.t == string("seed"); } }`],
      ['mapping-read operand', `class C { m: mapping<u256, string>; get eq(k: u256): External<bool> { return this.m[k] == "map"; } }`,
        `class C { m: mapping<u256, string>; get eq(k: u256): External<bool> { return this.m[k] == string("map"); } }`],
      ['attached-recv operand', `static class L { id(self: string): string { return self; } }\nclass C { get eq(s: string): External<bool> { return s.id() == "hi"; } }`,
        `static class L { id(self: string): string { return self; } }\nclass C { get eq(s: string): External<bool> { return s.id() == string("hi"); } }`],
      ['internal-call operand', `class C { mk(x: string): string { return x; } get eq(s: string): External<bool> { return this.mk(s) == "hi"; } }`,
        `class C { mk(x: string): string { return x; } get eq(s: string): External<bool> { return this.mk(s) == string("hi"); } }`],
      ['empty literal', `class C { get eq(s: string): External<bool> { return s == ""; } }`,
        `class C { get eq(s: string): External<bool> { return s == string(""); } }`],
      ['long literal', `class C { get eq(s: string): External<bool> { return s == "${LONG}"; } }`,
        `class C { get eq(s: string): External<bool> { return s == string("${LONG}"); } }`],
      ['unicode literal', `class C { get eq(s: string): External<bool> { return s == "h\\u00e9llo \\u2713"; } }`,
        `class C { get eq(s: string): External<bool> { return s == string("h\\u00e9llo \\u2713"); } }`],
      ['inside require()', `class C { get f(s: string): External<u256> { require(s == "ok", "no"); return 1n; } }`,
        `class C { get f(s: string): External<u256> { require(s == string("ok"), "no"); return 1n; } }`],
      ['ternary condition', `class C { get f(s: string): External<u256> { return s == "ok" ? 7n : 3n; } }`,
        `class C { get f(s: string): External<u256> { return s == string("ok") ? 7n : 3n; } }`],
      ['lit == lit unequal', `class C { get eq(): External<bool> { return "a" == "b"; } }`,
        `class C { get eq(): External<bool> { return string("a") == string("b"); } }`],
      ['lit == lit equal', `class C { get eq(): External<bool> { return "a" == "a"; } }`,
        `class C { get eq(): External<bool> { return string("a") == string("a"); } }`],
      ['lit != lit', `class C { get eq(): External<bool> { return "a" != "b"; } }`,
        `class C { get eq(): External<bool> { return string("a") != string("b"); } }`],
    ];
    for (const [label, bare, cast] of cells) {
      expect(bc(bare), label).toBe(bc(cast));
    }
  });

  it('CONTROL: the pre-fix reject flipped - the bare form compiles, the SAME literal in a non-string context still rejects JETH074', () => {
    // pre-fix this exact source rejected JETH074; post-fix it compiles.
    expect(codes(`class C { get eq(s: string): External<bool> { return s == "hi"; } }`)).toEqual([]);
    // the JETH074 path itself is intact (non-vacuous control): the identical literal against a
    // NON-string operand still hits the untyped-bare-literal reject.
    expect(codes(`class C { get eq(u: u256): External<bool> { return u == "hi"; } }`)).toEqual(['JETH074']);
  });

  it('runtime differential vs the solc keccak mirror: param / lit-left / empty / long / unicode seeds', async () => {
    const J = `class C {
      get eq(s: string): External<bool> { return s == "hi"; }
      get nl(s: string): External<bool> { return "abc" != s; }
      get em(s: string): External<bool> { return s == ""; }
      get lg(s: string): External<bool> { return s == "${LONG}"; }
      get un(s: string): External<bool> { return s == "h\\u00e9llo \\u2713"; }
      get ll(): External<bool> { return "a" == "b"; }
      get le(): External<bool> { return "zz" == "zz"; } }`;
    const S = `contract C {
      function eq(string memory s) external pure returns (bool) { return keccak256(bytes(s)) == keccak256(bytes("hi")); }
      function nl(string memory s) external pure returns (bool) { return keccak256(bytes("abc")) != keccak256(bytes(s)); }
      function em(string memory s) external pure returns (bool) { return keccak256(bytes(s)) == keccak256(bytes("")); }
      function lg(string memory s) external pure returns (bool) { return keccak256(bytes(s)) == keccak256(bytes("${LONG}")); }
      function un(string memory s) external pure returns (bool) { return keccak256(bytes(s)) == keccak256(bytes(unicode"h\\u00e9llo \\u2713")); }
      function ll() external pure returns (bool) { return keccak256(bytes("a")) == keccak256(bytes("b")); }
      function le() external pure returns (bool) { return keccak256(bytes("zz")) == keccak256(bytes("zz")); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(bc(J));
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const calls: [string, string][] = [
      ['eq(string)', enc('hi')], // equal
      ['eq(string)', enc('ho')], // unequal
      ['eq(string)', enc('')], // empty vs non-empty literal
      ['nl(string)', enc('abc')],
      ['nl(string)', enc('abd')],
      ['em(string)', enc('')], // empty == empty
      ['em(string)', enc('x')],
      ['lg(string)', enc(LONG)], // long equal
      ['lg(string)', enc(LONG.slice(0, -1) + 'x')], // long unequal (last byte)
      ['lg(string)', enc(LONG.slice(0, 31))], // short prefix of the long literal
      ['un(string)', enc('héllo ✓')],
      ['un(string)', enc('hello v')],
      ['ll()', ''],
      ['le()', ''],
    ];
    for (const [sg, args] of calls) {
      const data = sel(sg) + args;
      const rj = await h.call(aj, data);
      const rs = await h.call(as, data);
      expect(rj.success, sg + ' ' + args.slice(0, 80)).toBe(rs.success);
      expect(rj.returnHex, sg + ' ' + args.slice(0, 80)).toBe(rs.returnHex);
    }
    // non-vacuity: the equal seeds actually return true, the unequal seeds false.
    expect((await h.call(aj, sel('eq(string)') + enc('hi'))).returnHex).toBe('0x' + W(1));
    expect((await h.call(aj, sel('eq(string)') + enc('ho'))).returnHex).toBe('0x' + W(0));
    expect((await h.call(aj, sel('le()'))).returnHex).toBe('0x' + W(1));
    expect((await h.call(aj, sel('ll()'))).returnHex).toBe('0x' + W(0));
  });

  it('runtime differential: state / mapping operands and require / ternary contexts', async () => {
    const J = `class C {
      t: string; m: mapping<u256, string>;
      set(v: string): External<void> { this.t = v; }
      put(k: u256, v: string): External<void> { this.m[k] = v; }
      get eq(): External<bool> { return this.t == "seed77"; }
      get mq(k: u256): External<bool> { return this.m[k] == "map9"; }
      get rq(s: string): External<u256> { require(s == "ok", "no"); return 1n; }
      get tn(s: string): External<u256> { return s == "pick" ? 7n : 3n; } }`;
    const S = `contract C {
      string t; mapping(uint256 => string) m;
      function set(string memory v) external { t = v; }
      function put(uint256 k, string memory v) external { m[k] = v; }
      function eq() external view returns (bool) { return keccak256(bytes(t)) == keccak256(bytes("seed77")); }
      function mq(uint256 k) external view returns (bool) { return keccak256(bytes(m[k])) == keccak256(bytes("map9")); }
      function rq(string memory s) external pure returns (uint256) { require(keccak256(bytes(s)) == keccak256(bytes("ok")), "no"); return 1; }
      function tn(string memory s) external pure returns (uint256) { return keccak256(bytes(s)) == keccak256(bytes("pick")) ? 7 : 3; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(bc(J));
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const putArgs = W(4) + W(0x40) + W(4) + Buffer.from('map9').toString('hex').padEnd(64, '0');
    const calls: [string, string][] = [
      ['eq()', ''], // unseeded state (empty string) vs literal
      ['set(string)', enc('seed77')],
      ['eq()', ''], // seeded equal
      ['set(string)', enc('seed78')],
      ['eq()', ''], // seeded unequal
      ['mq(uint256)', W(4)], // unseeded mapping slot
      ['put(uint256,string)', putArgs],
      ['mq(uint256)', W(4)], // seeded equal
      ['mq(uint256)', W(5)], // different key
      ['rq(string)', enc('ok')], // require passes
      ['rq(string)', enc('nope')], // require reverts (revert data must match too)
      ['tn(string)', enc('pick')],
      ['tn(string)', enc('pack')],
    ];
    for (const [sg, args] of calls) {
      const data = sel(sg) + args;
      const rj = await h.call(aj, data);
      const rs = await h.call(as, data);
      expect(rj.success, sg + ' ' + args.slice(0, 80)).toBe(rs.success);
      expect(rj.returnHex, sg + ' ' + args.slice(0, 80)).toBe(rs.returnHex);
    }
    // non-vacuity: seeded mapping read is true; the require revert really reverts.
    expect((await h.call(aj, sel('mq(uint256)') + W(4))).returnHex).toBe('0x' + W(1));
    expect((await h.call(aj, sel('rq(string)') + enc('nope'))).success).toBe(false);
  });

  it('scope guards keep rejecting with exact codes (each matches its cast twin in accept/reject outcome)', () => {
    // string vs int literal (solc: == not applicable to string and int_const)
    expect(codes(`class C { get eq(s: string): External<bool> { return s == 5n; } }`)).toEqual(['JETH084']);
    // bytes vs string literal: stays the untyped-literal reject; the cast twin `b == string("hi")`
    // is ALSO a reject (JETH083 string-vs-bytes unify failure), matching solc's reject.
    expect(codes(`class C { get eq(b: bytes): External<bool> { return b == "hi"; } }`)).toEqual(['JETH074']);
    expect(codes(`class C { get eq(b: bytes): External<bool> { return "hi" == b; } }`)).toEqual(['JETH074']);
    expect(codes(`class C { get eq(b: bytes): External<bool> { return b == string("hi"); } }`)).toEqual(['JETH083']);
    // ordered comparisons on a string vs a literal stay rejected (solc rejects ordered string
    // compare; the cast twin `s < string("hi")` is the same reject downstream as JETH088).
    expect(codes(`class C { get eq(s: string): External<bool> { return s < "hi"; } }`)).toEqual(['JETH074']);
    expect(codes(`class C { get eq(s: string): External<bool> { return "hi" < s; } }`)).toEqual(['JETH074']);
    expect(codes(`class C { get eq(s: string): External<bool> { return s >= "hi"; } }`)).toEqual(['JETH074']);
    expect(codes(`class C { get eq(s: string): External<bool> { return s < string("hi"); } }`)).toEqual(['JETH088']);
    // the pre-existing asymmetric bytesN-literal comparison is untouched: literal-on-right accepts,
    // literal-on-left rejects (solc types a comparison literal by the LEFT operand only).
    expect(codes(`class C { get eq(b: bytes4): External<bool> { return b == "abcd"; } }`)).toEqual([]);
    expect(codes(`class C { get eq(b: bytes4): External<bool> { return "abcd" == b; } }`)).toEqual(['JETH074']);
  });
});
