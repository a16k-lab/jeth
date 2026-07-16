// ARRLIT-CONV (over-acceptance closed): solc types an inline array literal from its ELEMENTS ONLY - it
// never pushes the declared/expected type into the literal - and then converts that type to the target.
// solc's ArrayType::isImplicitlyConvertibleTo has exactly TWO branches, and which one applies is decided
// by the TARGET's data location (every row below probed against solc 0.8.35, not guessed):
//
//   * target is STORAGE and NOT a pointer (state var, storage struct field, storage array element,
//     mapping value, `push` argument, state-var initializer): "less restrictive conversion, since we
//     need to copy anyway" - the element type only has to be implicitly CONVERTIBLE, so
//     `uint256[2] s; s = [1,2];` ACCEPTS (uint8 -> uint256, element-wise).
//   * target is MEMORY / CALLDATA / a STORAGE POINTER (memory local decl+assign, memory struct field,
//     memory array element, return value, internal/external call argument, struct-constructor field,
//     event argument): no element-wise copy happens, so the base type must be IDENTICAL and
//     `uint256[2] memory a = [1,2];` REJECTS ("Type uint8[2] memory is not implicitly convertible to
//     expected type uint256[2] memory").
//
// JETH pushed `expected` into the literal everywhere, so it ACCEPTED every memory row whose declared
// element type is merely WIDER than the one solc infers (Arr<u256,2> = [1n,2n], Arr<i256,2> = [-1n,1n],
// Arr<u256,2> = [u8(1n),2n], ...) - an OVER-ACCEPTANCE, now JETH497.
//
// NON-VACUITY is asserted per cell, both ways: every REJECT row asserts the JETH code is exactly JETH497
// (not some unrelated earlier error) AND that solc rejects the mirror; every ACCEPT row is deployed, run
// and asserted byte-identical to solc on returndata (a "both compile" check would prove nothing).
//
// The two JETH-only SUGAR shapes stay accepted deliberately (they are NOT width questions): a solc array
// literal is always a FIXED T[n], so a DYNAMICALLY-SIZED array is unreachable as a literal's type at
// either level, and solc rejects those forms for EVERY element spelling. Their verified solc equivalent
// is `new` + per-element assign, so the identity rule does not apply - pinned below.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    const ds = (e as { diagnostics?: { code: string }[] }).diagnostics;
    return ds ? ds.map((d) => d.code) : ['THROW'];
  }
};
const solRejects = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};

/** Deploy BOTH and compare returndata call-by-call: the only evidence that an accepted row is right. */
async function bothMatch(J: string, S: string, calls: [string, string][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, args] of calls) {
    const data = sel(sg) + (args || '');
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
  }
}

/** A memory row that must REJECT: JETH497 fires AND solc rejects the mirror (both halves asserted, so a
 *  cell can never pass by rejecting for an unrelated reason or by mirroring a program solc also takes). */
function bothReject(label: string, J: string, S: string) {
  expect(codes(J), label + ' (jeth)').toContain('JETH497');
  expect(solRejects(S), label + ' (solc rejects the mirror)').toBe(true);
}

describe('ARRLIT-CONV: an array literal converts element-wise ONLY into storage; memory needs an IDENTICAL element type', () => {
  it('the reported OA rows: a WIDER declared element type at a memory local now rejects (solc parity)', () => {
    bothReject(
      'Arr<u256,2> = [1n,2n]',
      `class C { get f(): External<u256> { const a: Arr<u256,2> = [1n, 2n]; return u256(a[1n]); } }`,
      `contract C { function f() public pure returns (uint256) { uint256[2] memory a = [1, 2]; return a[1]; } }`,
    );
    bothReject(
      'Arr<u16,2> = [1n,2n]',
      `class C { get f(): External<u16> { const a: Arr<u16,2> = [1n, 2n]; return a[1n]; } }`,
      `contract C { function f() public pure returns (uint16) { uint16[2] memory a = [1, 2]; return a[1]; } }`,
    );
    bothReject(
      'Arr<u32,2> = [1n,300n]',
      `class C { get f(): External<u32> { const a: Arr<u32,2> = [1n, 300n]; return a[1n]; } }`,
      `contract C { function f() public pure returns (uint32) { uint32[2] memory a = [1, 300]; return a[1]; } }`,
    );
    bothReject(
      'Arr<i256,2> = [-1n,1n]',
      `class C { get f(): External<i256> { const a: Arr<i256,2> = [-1n, 1n]; return a[1n]; } }`,
      `contract C { function f() public pure returns (int256) { int256[2] memory a = [-1, 1]; return a[1]; } }`,
    );
    // the cast does not help when it is NARROWER than the declared type: [uint8(1), 2] is uint8[2].
    bothReject(
      'Arr<u256,2> = [u8(1n),2n]',
      `class C { get f(): External<u256> { const a: Arr<u256,2> = [u8(1n), 2n]; return u256(a[1n]); } }`,
      `contract C { function f() public pure returns (uint256) { uint256[2] memory a = [uint8(1), 2]; return a[1]; } }`,
    );
  });

  it('EVERY memory landing rejects, not just the local decl (assign / return / call args / ctor field / event / nested)', () => {
    bothReject(
      'memory assign',
      `class C { get f(): External<u256> { let a: Arr<u256,2> = [u256(0n),u256(0n)]; a = [1n, 2n]; return a[1n]; } }`,
      `contract C { function f() public pure returns (uint256) { uint256[2] memory a = [uint256(0),uint256(0)]; a = [1,2]; return a[1]; } }`,
    );
    bothReject(
      'return position',
      `class C { get f(): External<Arr<u256,2>> { return [1n, 2n]; } }`,
      `contract C { function f() public pure returns (uint256[2] memory) { return [1, 2]; } }`,
    );
    bothReject(
      'internal-call argument',
      `class C { g(a: Arr<u256,2>): u256 { return a[1n]; } get f(): External<u256> { return this.g([1n, 2n]); } }`,
      `contract C { function g(uint256[2] memory a) internal pure returns(uint256){return a[1];} function f() public pure returns (uint256) { return g([1, 2]); } }`,
    );
    bothReject(
      'external-call argument',
      `interface I { g(a: Arr<u256,2>): u256; } class C { h(t: address): External<u256> { return I(t).g([1n, 2n]); } }`,
      `interface I { function g(uint256[2] memory a) external returns(uint256); } contract C { function h(address t) public returns(uint256){ return I(t).g([1,2]); } }`,
    );
    bothReject(
      'struct-constructor field',
      `type S = { a: Arr<u256,2>; }; class C { get f(): External<u256> { const m: S = { a: [1n,2n] }; return m.a[1n]; } }`,
      `contract C { struct S { uint256[2] a; } function f() public pure returns (uint256) { S memory m = S([1,2]); return m.a[1]; } }`,
    );
    bothReject(
      'event argument',
      `class C { E: event<{ a: Arr<u256,2> }>; go(): External<void> { emit(E([1n, 2n])); } }`,
      `contract C { event E(uint256[2] a); function go() external { emit E([1,2]); } }`,
    );
    bothReject(
      'nested memory literal',
      `class C { get f(): External<u256> { const m: Arr<Arr<u256,2>,2> = [[1n,2n],[3n,4n]]; return m[1n][0n]; } }`,
      `contract C { function f() public pure returns (uint256) { uint256[2][2] memory m = [[1,2],[3,4]]; return m[1][0]; } }`,
    );
  });

  it('the element-wise-copy permission does NOT leak into a memory sub-expression of a storage assignment', () => {
    // `this.s` is STORAGE, but solc builds the struct in MEMORY first, so the literal lands in the
    // constructor's memory parameter and the strict rule still applies: `s = S([1,2])` is a TypeError
    // while `s = [1,2]` is fine. This is the cell that proves the permission is consumed rather than
    // inherited by everything under a storage assignment.
    bothReject(
      'struct ctor -> storage (the literal still lands in memory)',
      `type S = { a: Arr<u256,2>; }; class C { s: S; g(): External<void> { this.s = { a: [1n, 2n] }; } }`,
      `contract C { struct S { uint256[2] a; } S s; function g() public { s = S([1,2]); } }`,
    );
    // (the sibling `this.s = <call>([1n,2n])` shape is NOT pinned here: JETH900 independently rejects a
    // call-result mem->storage array copy at this shape, so the cell could not isolate the leak.)
  });

  it('EXACT-width memory rows keep accepting, byte-identical to solc (the fix must not over-reject)', async () => {
    await bothMatch(
      `class C { get f(): External<u8> { const a: Arr<u8,2> = [1n, 2n]; return a[1n]; } }`,
      `contract C { function f() public pure returns (uint8) { uint8[2] memory a = [1, 2]; return a[1]; } }`,
      [['f()', '']],
    );
    await bothMatch(
      `class C { get f(): External<u16> { const a: Arr<u16,2> = [1n, 300n]; return a[1n]; } }`,
      `contract C { function f() public pure returns (uint16) { uint16[2] memory a = [1, 300]; return a[1]; } }`,
      [['f()', '']],
    );
    await bothMatch(
      `class C { get f(): External<i8> { const a: Arr<i8,2> = [-1n, 1n]; return a[1n]; } }`,
      `contract C { function f() public pure returns (int8) { int8[2] memory a = [-1, 1]; return a[1]; } }`,
      [['f()', '']],
    );
    // the WIDENING cast on the first element is what makes the memory rows legal, in solc and in JETH.
    await bothMatch(
      `class C { get f(): External<u256> { const a: Arr<u256,2> = [u256(1n), 2n]; return a[1n]; } }`,
      `contract C { function f() public pure returns (uint256) { uint256[2] memory a = [uint256(1), 2]; return a[1]; } }`,
      [['f()', '']],
    );
    await bothMatch(
      `class C { get f(): External<u256> { const m: Arr<Arr<u256,2>,2> = [[u256(1n),2n],[u256(3n),4n]]; return m[1n][0n]; } }`,
      `contract C { function f() public pure returns (uint256) { uint256[2][2] memory m = [[uint256(1),2],[uint256(3),4]]; return m[1][0]; } }`,
      [['f()', '']],
    );
    // a concretely-typed (non-literal) element carries its own type, so no cast is needed.
    await bothMatch(
      `class C { g(x: u256, y: u256): u256 { const a: Arr<u256,2> = [x, y]; return a[1n]; } get f(): External<u256> { return this.g(7n, 9n); } }`,
      `contract C { function g(uint256 x, uint256 y) internal pure returns(uint256){ uint256[2] memory a = [x,y]; return a[1]; } function f() public pure returns (uint256) { return g(7, 9); } }`,
      [['f()', '']],
    );
  });

  it('THE STORAGE PATH keeps accepting a bare literal (element-wise copy), byte-identical to solc', async () => {
    // state var, and the same literal through a constructor.
    await bothMatch(
      `class C { s: Arr<u256,2>; g(): External<void> { this.s = [1n, 2n]; } get r(): External<u256> { return this.s[1n]; } }`,
      `contract C { uint256[2] s; function g() public { s = [1, 2]; } function r() public view returns (uint256) { return s[1]; } }`,
      [['g()', ''], ['r()', '']],
    );
    await bothMatch(
      `class C { s: Arr<i256,2>; g(): External<void> { this.s = [-1n, 1n]; } get r(): External<i256> { return this.s[0n]; } }`,
      `contract C { int256[2] s; function g() public { s = [-1, 1]; } function r() public view returns (int256) { return s[0]; } }`,
      [['g()', ''], ['r()', '']],
    );
    // storage ARRAY ELEMENT, storage STRUCT FIELD, MAPPING value, push(), state-var INITIALIZER.
    await bothMatch(
      `class C { s: Arr<Arr<u256,2>,2>; g(): External<void> { this.s[0n] = [1n, 2n]; } get r(): External<u256> { return this.s[0n][1n]; } }`,
      `contract C { uint256[2][2] s; function g() public { s[0] = [1, 2]; } function r() public view returns (uint256) { return s[0][1]; } }`,
      [['g()', ''], ['r()', '']],
    );
    await bothMatch(
      `type S = { a: Arr<u256,2>; }; class C { s: S; g(): External<void> { this.s.a = [1n, 2n]; } get r(): External<u256> { return this.s.a[1n]; } }`,
      `contract C { struct S { uint256[2] a; } S s; function g() public { s.a = [1, 2]; } function r() public view returns (uint256) { return s.a[1]; } }`,
      [['g()', ''], ['r()', '']],
    );
    await bothMatch(
      `class C { m: mapping<u256, Arr<u256,2>>; g(): External<void> { this.m[0n] = [1n, 2n]; } get r(): External<u256> { return this.m[0n][1n]; } }`,
      `contract C { mapping(uint256 => uint256[2]) m; function g() public { m[0] = [1, 2]; } function r() public view returns (uint256) { return m[0][1]; } }`,
      [['g()', ''], ['r()', '']],
    );
    await bothMatch(
      `class C { s: Arr<u256,2>[]; g(): External<void> { this.s.push([1n, 2n]); } get r(): External<u256> { return this.s[0n][1n]; } }`,
      `contract C { uint256[2][] s; function g() public { s.push([1, 2]); } function r() public view returns (uint256) { return s[0][1]; } }`,
      [['g()', ''], ['r()', '']],
    );
    await bothMatch(
      `class C { s: Arr<u256,2> = [1n, 2n]; get r(): External<u256> { return this.s[1n]; } }`,
      `contract C { uint256[2] s = [1, 2]; function r() public view returns (uint256) { return s[1]; } }`,
      [['r()', '']],
    );
    // NESTED literal into storage: solc's copy recurses, so the inner literals convert element-wise too.
    await bothMatch(
      `class C { s: Arr<Arr<u256,2>,2>; g(): External<void> { this.s = [[1n,2n],[3n,4n]]; } get r(): External<u256> { return this.s[1n][0n]; } }`,
      `contract C { uint256[2][2] s; function g() public { s = [[1,2],[3,4]]; } function r() public view returns (uint256) { return s[1][0]; } }`,
      [['g()', ''], ['r()', '']],
    );
    // a PARENTHESIZED literal is the same expression, and a TERNARY of literals is typed first and then
    // copied into storage - both solc-ACCEPT, so neither may lose the permission.
    await bothMatch(
      `class C { s: Arr<u256,2>; g(): External<void> { this.s = ([1n, 2n]); } get r(): External<u256> { return this.s[1n]; } }`,
      `contract C { uint256[2] s; function g() public { s = ([1, 2]); } function r() public view returns (uint256) { return s[1]; } }`,
      [['g()', ''], ['r()', '']],
    );
    await bothMatch(
      `class C { s: Arr<u256,2>; g(c: bool): External<void> { this.s = c ? [1n, 2n] : [3n, 4n]; } get r(): External<u256> { return this.s[0n]; } }`,
      `contract C { uint256[2] s; function g(bool c) public { s = c ? [1, 2] : [3, 4]; } function r() public view returns (uint256) { return s[0]; } }`,
      [['g(bool)', W(1)], ['r()', ''], ['g(bool)', W(0)], ['r()', '']],
    );
  });

  it('JETH-only sugar solc has no literal spelling for stays accepted (dynamic outer / dynamic element)', () => {
    // A solc literal is always a FIXED T[n], so BOTH of these are solc TypeErrors for EVERY element
    // spelling (not a width question) - JETH supports them as sugar for `new` + per-element assign.
    expect(codes(`class C { get f(): External<u256> { const a: u256[] = [1n, 2n]; return a[1n]; } }`)).toEqual([]);
    expect(
      solRejects(`contract C { function f() public pure returns(uint256){ uint256[] memory a = [1,2]; return a[1]; } }`),
    ).toBe(true);
    expect(
      solRejects(
        `contract C { function f() public pure returns(uint256){ uint256[] memory a = [uint256(1),2]; return a[1]; } }`,
      ),
    ).toBe(true);
    // dynamic ELEMENT: `uint256[][2] memory m = [[uint256(1),2],[uint256(3),4]]` is a TypeError too, so
    // the identity rule must not fire here either - and it must not split the family by whether the
    // inner literals happen to unify (`[[7n],[8n]]` vs the ragged `[[1n,2n],[3n]]`).
    expect(codes(`class C { get f(): External<u256> { const m: Arr<u256[],2> = [[7n],[8n]]; return m[0n][0n]; } }`)).toEqual(
      [],
    );
    expect(
      codes(`class C { get f(): External<u256> { const m: Arr<u256[],2> = [[1n,2n],[3n]]; return m[0n][1n]; } }`),
    ).toEqual([]);
    expect(
      solRejects(`contract C { function f() public pure { uint256[][2] memory m = [[uint256(1),2],[uint256(3),4]]; m; } }`),
    ).toBe(true);
  });
});
