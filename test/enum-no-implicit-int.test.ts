// An enum MEMBER literal (Color.Blue) is nominally an enum, NOT a free integer literal: solc forbids
// implicitly converting it to an integer type (`uint256 x = Color.Blue;` is a compile error; you must
// write `uint256(Color.Blue)`). JETH used to over-accept this because the enum member is produced as a
// `literalInt` carrying the enum type, and the literal-retyping fast-path freely retyped it to any
// integer target that fit the value, ignoring the enum brand. Fixed in retypeLiteral: an enum-typed
// literal only implicitly converts to the SAME enum (handled upstream by typesEqual); to an int it now
// rejects with JETH085 (matching the non-literal enum value), while an EXPLICIT cast still works.
//
// This also removes a spurious overload ambiguity: for { pick(Color), pick(u256) } called with an enum
// literal pick(Color.Blue), the enum literal no longer coerces to u256, so only pick(Color) is viable
// and resolution succeeds (solc resolves it the same way) instead of JETH reporting JETH434.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}
const PRE = 'enum Color { Red, Green, Blue }\n';
const J = (body: string) => `${PRE}class C { ${body} }`;
const S = (body: string) =>
  `// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\ncontract C { enum Color { Red, Green, Blue }\n${body} }`;
const solRejects = (src: string) => {
  try {
    compileSolidity(src, 'C');
    return false;
  } catch {
    return true;
  }
};

describe('enum member literal is not implicitly convertible to an integer (vs solc)', () => {
  // (1) return Color.Blue from a uint-returning function: JETH-REJECT, solc-REJECT.
  it('rejects `return Color.Blue;` from a u256 function (both reject)', () => {
    expect(codes(J('get f(): External<u256> { return Color.Blue; }'))).toContain('JETH085');
    expect(solRejects(S('function f() external pure returns (uint256) { return Color.Blue; }'))).toBe(true);
  });

  // (2) let x: u256 = Color.Green: JETH-REJECT, solc-REJECT.
  it('rejects `let x: u256 = Color.Green;` (both reject)', () => {
    expect(codes(J('get f(): External<u256> { let x: u256 = Color.Green; return x; }'))).toContain('JETH085');
    expect(solRejects(S('function f() external pure returns (uint256) { uint256 x = Color.Green; return x; }'))).toBe(
      true,
    );
  });

  // (3) an enum literal argument into a single (non-overloaded) uint param: JETH-REJECT, solc-REJECT.
  it('rejects an enum-literal argument into a u256 parameter (both reject)', () => {
    const j = 'pick(u: u256): u256 { return u; } get f(): External<u256> { return this.pick(Color.Blue); }';
    expect(codes(J(j))).toContain('JETH085');
    const s =
      'function pick(uint256 u) internal pure returns (uint256) { return u; } function f() external pure returns (uint256) { return pick(Color.Blue); }';
    expect(solRejects(S(s))).toBe(true);
  });

  // (4) cross-enum implicit conversion is also rejected (the literal only converts to its OWN enum).
  it('rejects an enum-literal of one enum used where another enum is expected (both reject)', () => {
    const j =
      'enum Color { Red, Green, Blue }\nenum Status { Off, On }\nclass C { get f(): External<Status> { return Color.Red; } }';
    expect(codes(j)).toContain('JETH085');
    const s = 'enum Status { Off, On } function f() external pure returns (Status) { return Color.Red; }';
    expect(solRejects(S(s))).toBe(true);
  });

  // POSITIVE controls: the EXPLICIT cast still compiles and is byte-identical; same-enum return works.
  describe('explicit cast and same-enum assignment still work, byte-identical to solc', () => {
    let jeth: Harness, sol: Harness, aj: Address, as: Address;
    const body = `
      get cast(): External<u256> { return u256(Color.Blue); }
      get same(): External<Color> { return Color.Green; }
      get ovl(): External<u256> { return this.pick(Color.Blue); }
      pick(c: Color): u256 { return 100n; }
      pick(u: u256): u256 { return 200n; }`;
    const sbody = `
      function cast() external pure returns (uint256) { return uint256(Color.Blue); }
      function same() external pure returns (Color) { return Color.Green; }
      function ovl() external pure returns (uint256) { return pick(Color.Blue); }
      function pick(Color c) internal pure returns (uint256) { return 100; }
      function pick(uint256 u) internal pure returns (uint256) { return 200; }`;
    beforeAll(async () => {
      jeth = await Harness.create();
      sol = await Harness.create();
      aj = await jeth.deploy(compile(J(body), { fileName: 'C.jeth' }).creationBytecode);
      as = await sol.deploy(compileSolidity(S(sbody), 'C').creation);
    });
    const cmp = async (fn: string, label: string) => {
      const j = await jeth.call(aj, '0x' + sel(fn));
      const s = await sol.call(as, '0x' + sel(fn));
      expect(j.success, `${label} success`).toBe(s.success);
      expect(j.returnHex, label).toBe(s.returnHex);
    };
    it('u256(Color.Blue) explicit cast -> 2', () => cmp('cast()', 'cast'));
    it('return Color.Green from a Color function -> 1', () => cmp('same()', 'same'));
    it('overload {pick(Color),pick(u256)}(Color.Blue) resolves to pick(Color) -> 100', () => cmp('ovl()', 'ovl'));
  });
});
