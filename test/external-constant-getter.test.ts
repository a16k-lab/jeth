// W6D: `@external @constant` synthesizes solc's `public constant` auto-getter, byte-identical to
// solc 0.8.35. Previously @external on a @constant was SILENTLY IGNORED: the field compiled but no
// getter existed and the selector was missing from the dispatcher, so K() reverted 0x while the solc
// mirror (`uint256 public constant K = 7;`) returned the value - a both-accept behavioral divergence.
// Covered here:
//  - every supported @constant type (int widths, bool, address, bytesN, enum, string) returns the
//    folded literal byte-identical to solc's constant getter;
//  - a PLAIN @constant (no @external) still gets NO getter (both sides revert on the selector);
//  - inherited base `@external @constant` enters the derived dispatcher (solc inherits the getter);
//  - the getter is non-payable (msg.value reverts) exactly like solc's;
//  - name collisions / redeclarations reject cleanly (solc: "Identifier already declared");
//  - every OTHER exposure/mutability decorator on @constant is a clean JETH466 reject (never a
//    silently-ignored decorator), including @override/@virtual which solc also rejects standalone.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}
const solcRejects = (src: string) => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};

async function eqCalls(jeth: string, sol: string, calls: [string, string][], opts: { value?: bigint } = {}) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  const callOpt = opts.value !== undefined ? { value: opts.value } : {};
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + (args ?? ''), callOpt);
    const rs = await hs.call(as, sel(sig) + (args ?? ''), callOpt);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

describe('@external @constant auto-getter (solc public constant), byte-identical', () => {
  it('u256 / bool / address getters return the folded literal (the original miscompile repro)', async () => {
    await eqCalls(
      `class C { static K: Visible<u256> = 7n; get other(): External<u256> { return 1n; } }`,
      `contract C { uint256 public constant K = 7; function other() external pure returns (uint256) { return 1; } }`,
      [['K()', ''], ['other()', '']],
    );
    await eqCalls(
      `class C { static B: Visible<bool> = true; static A: Visible<address> = address(0n); }`,
      `contract C { bool public constant B = true; address public constant A = address(0); }`,
      [['B()', ''], ['A()', '']],
    );
  });

  it('narrow ints, negatives, bytesN, and enum getters encode like solc', async () => {
    await eqCalls(
      `enum Color { Red, Green, Blue }
       class C {
         static U8: Visible<u8> = 255n;
         static I8: Visible<i8> = -5n;
         static I256: Visible<i256> = -1n;
         static B4: Visible<bytes4> = bytes4(0xdeadbeefn);
         static B32: Visible<bytes32> = bytes32(0xdeadbeef00000000000000000000000000000000000000000000000000000001n);
         static E: Visible<Color> = Color.Blue; }`,
      `contract C {
         enum Color { Red, Green, Blue }
         uint8 public constant U8 = 255;
         int8 public constant I8 = -5;
         int256 public constant I256 = -1;
         bytes4 public constant B4 = 0xdeadbeef;
         bytes32 public constant B32 = 0xdeadbeef00000000000000000000000000000000000000000000000000000001;
         Color public constant E = Color.Blue; }`,
      [['U8()', ''], ['I8()', ''], ['I256()', ''], ['B4()', ''], ['B32()', ''], ['E()', '']],
    );
  });

  it('string constant getters ABI-encode offset/len/data like solc (empty, 31B, 32B, long, unicode)', async () => {
    await eqCalls(
      `class C {
         static S0: Visible<string> = "";
         static S1: Visible<string> = "hi";
         static S31: Visible<string> = "0123456789012345678901234567890";
         static S32: Visible<string> = "01234567890123456789012345678901";
         static SL: Visible<string> = "the quick brown fox jumps over the lazy dog and then some extra!";
         static SU: Visible<string> = "h\\u00e9llo \\u2713"; }`,
      `contract C {
         string public constant S0 = "";
         string public constant S1 = "hi";
         string public constant S31 = "0123456789012345678901234567890";
         string public constant S32 = "01234567890123456789012345678901";
         string public constant SL = "the quick brown fox jumps over the lazy dog and then some extra!";
         string public constant SU = unicode"héllo ✓"; }`,
      [['S0()', ''], ['S1()', ''], ['S31()', ''], ['S32()', ''], ['SL()', ''], ['SU()', '']],
    );
  });

  it('a PLAIN @constant still gets NO getter (both revert on the selector) and coexists with getters', async () => {
    await eqCalls(
      `class C { static A: Visible<u256> = 1n; static Hidden: u256 = 2n; get viaFn(): External<u256> { return this.Hidden; } }`,
      `contract C { uint256 public constant A = 1; uint256 constant Hidden = 2; function viaFn() external pure returns (uint256) { return Hidden; } }`,
      [['A()', ''], ['Hidden()', ''], ['viaFn()', '']],
    );
  });

  it('an inherited base @external @constant enters the derived dispatcher (solc inherits the getter)', async () => {
    await eqCalls(
      `abstract class B { static K: Visible<u256> = 7n; static P: u256 = 3n; }
       class C extends B { get other(): External<u256> { return 1n; } }`,
      `contract B { uint256 public constant K = 7; uint256 constant P = 3; }
       contract C is B { function other() external pure returns (uint256) { return 1; } }`,
      [['K()', ''], ['P()', ''], ['other()', '']],
    );
  });

  it('the constant getter is non-payable: msg.value reverts exactly like solc', async () => {
    await eqCalls(
      `class C { static K: Visible<u256> = 7n; }`,
      `contract C { uint256 public constant K = 7; }`,
      [['K()', '']],
      { value: 1n },
    );
  });

  it('constant getters coexist with @external @state and @external @immutable getters (unregressed)', async () => {
    await eqCalls(
      `class C { static A: Visible<u256> = 1n; s: Visible<u256> = 9n; static m: Visible<u256>; constructor() { this.m = 5n; } }`,
      `contract C { uint256 public constant A = 1; uint256 public s = 9; uint256 public immutable m; constructor() { m = 5; } }`,
      [['A()', ''], ['s()', ''], ['m()', '']],
    );
  });

  it('rejects a getter/function name collision cleanly (solc: Identifier already declared)', () => {
    const j1 = `class C { static K: Visible<u256> = 7n; get K(): External<u256> { return 1n; } }`;
    const s1 = `contract C { uint256 public constant K = 7; function K() external pure returns (uint256) { return 1; } }`;
    expect(codes(j1)).toContain('JETH133');
    expect(solcRejects(s1)).toBe(true);
    // overload-style same-name function: still a name clash on both sides
    const j2 = `class C { static K: Visible<u256> = 7n; get K(x: u256): External<u256> { return x; } }`;
    const s2 = `contract C { uint256 public constant K = 7; function K(uint256 x) external pure returns (uint256) { return x; } }`;
    expect(codes(j2)).toContain('JETH133');
    expect(solcRejects(s2)).toBe(true);
    // derived redeclaring a base @external @constant: duplicate on both sides
    const j3 = `abstract class B { static K: Visible<u256> = 7n; } class C extends B { static K: Visible<u256> = 9n; }`;
    const s3 = `contract B { uint256 public constant K = 7; } contract C is B { uint256 public constant K = 9; }`;
    expect(codes(j3).length).toBeGreaterThan(0);
    expect(solcRejects(s3)).toBe(true);
  });

  it('every non-Visible exposure/mutability decorator on a static constant is a clean reject (never silently ignored)', () => {
    // native adjudication: a @constant is a `static K = v` field; the ONLY exposure marker is Visible<T>. Every
    // extra decorator is loud, never swallowed - which is exactly what this test guards. The specific code splits
    // three ways: a RETIRED name (public/internal/private/view/pure/payable/read) is the native-only ban JETH481;
    // @hidden is a METHOD-only decorator in an illegal FIELD position, caught by the decorator-position gate
    // (JETH490) ahead of analysis; @override/@virtual ARE legal field-position names (a getter-var), so they pass
    // the position gate and reach the constant collector, which rejects them as nonsensical on a slot-free
    // constant (JETH466).
    const expected: Record<string, string> = {
      public: 'JETH481', internal: 'JETH481', private: 'JETH481', view: 'JETH481',
      pure: 'JETH481', payable: 'JETH481', read: 'JETH481',
      hidden: 'JETH490', override: 'JETH466', virtual: 'JETH466',
    };
    for (const [dec, code] of Object.entries(expected)) {
      expect(codes(`class C { @${dec} static K: u256 = 7n; get f(): External<u256> { return 1n; } }`), `@${dec}`).toContain(code);
    }
    // and solc rejects the standalone analogue that parses at all
    expect(solcRejects(`contract C { uint256 public constant override K = 7; }`)).toBe(true); // overrides nothing
  });
});
