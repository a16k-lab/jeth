// W7C: duplicate-identifier over-acceptances between @constant and @state. Previously
// `@external @constant K` + `@state K` (either order, plain @constant too) COMPILED: the constant
// silently shadowed every `this.K` read and the state slot was orphaned (the getter returned the
// constant). Same across inheritance: base @state x + derived @constant x (and the reverse, and the
// diamond where two bases contribute the pair) were accepted while solc rejects every one of them
// with DeclarationError "Identifier already declared". All now reject with JETH046.
//
// The accept/reject matrix over EVERY member-kind pair (state/constant/public-constant/immutable/
// function/event/error/modifier) x {same-contract, inherited, diamond} was pinned against solc
// 0.8.35 first: state x constant was the ONLY over-accepted family (all other pairs already
// rejected via JETH046/JETH133/JETH373/JETH044/JETH144/JETH328/JETH330). Legal name reuse (function
// and event overloads, @virtual/@override, the P1-4 getter var, local/param shadowing, unrelated
// contracts) stays accepted - each control is pinned against solc in this file too.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const W = (n: bigint | number) => BigInt(n).toString(16).padStart(64, '0');

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

// Pins the solc side (must reject) AND the JETH side (must emit the given code) in one step, so
// the spec each reject is matched against lives in the test.
function bothReject(jeth: string, sol: string, code = 'JETH046') {
  expect(solcRejects(sol), `solc must reject: ${sol}`).toBe(true);
  expect(codes(jeth), `jeth must reject ${code}: ${jeth}`).toContain(code);
}

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  expect(solcRejects(sol), `solc must accept: ${sol}`).toBe(false);
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

describe('W7C: @constant x @state duplicate identifier rejects (solc: "Identifier already declared")', () => {
  it('same contract, either order, public or plain constant (the original repro)', () => {
    bothReject(
      `class C { static K: Visible<u256> = 1n; K: u256 = 2n; }`,
      `contract C { uint256 public constant K = 1; uint256 K = 2; }`,
    );
    bothReject(
      `class C { K: u256 = 2n; static K: Visible<u256> = 1n; }`,
      `contract C { uint256 K = 2; uint256 public constant K = 1; }`,
    );
    bothReject(
      `class C { static K: u256 = 1n; K: u256 = 2n; }`,
      `contract C { uint256 constant K = 1; uint256 K = 2; }`,
    );
  });

  it('across inheritance, both directions, plus a deep chain', () => {
    bothReject(
      `abstract class A { x: u256 = 5n; } class C extends A { static x: Visible<u256> = 1n; }`,
      `contract A { uint256 x = 5; } contract C is A { uint256 public constant x = 1; }`,
    );
    bothReject(
      `abstract class A { static x: Visible<u256> = 1n; } class C extends A { x: u256 = 5n; }`,
      `contract A { uint256 public constant x = 1; } contract C is A { uint256 x = 5; }`,
    );
    bothReject(
      `abstract class A { static x: u256 = 1n; } class C extends A { x: u256 = 5n; }`,
      `contract A { uint256 constant x = 1; } contract C is A { uint256 x = 5; }`,
    );
    // grandbase constant vs leaf state (the collision skips a generation)
    bothReject(
      `abstract class A { static x: u256 = 1n; } abstract class B extends A { } class C extends B { x: u256 = 5n; }`,
      `contract A { uint256 constant x = 1; } contract B is A { } contract C is B { uint256 x = 5; }`,
    );
  });

  it('diamond: two bases contribute the colliding pair', () => {
    bothReject(
      `abstract class A { x: u256 = 5n; } abstract class B { static x: u256 = 1n; } class C extends A, B { }`,
      `contract A { uint256 x = 5; } contract B { uint256 constant x = 1; } contract C is A, B { }`,
    );
    bothReject(
      `abstract class A { static x: Visible<u256> = 1n; } abstract class B { x: u256 = 5n; } class C extends A, B { }`,
      `contract A { uint256 public constant x = 1; } contract B { uint256 x = 5; } contract C is A, B { }`,
    );
  });

  it('the neighbouring duplicate kinds still reject (unchanged guards)', () => {
    // state x state across the chain (JETH373), constant x constant (JETH046), immutable x state (JETH046)
    bothReject(
      `abstract class A { K: u256 = 1n; } class C extends A { K: u256 = 2n; }`,
      `contract A { uint256 K = 1; } contract C is A { uint256 K = 2; }`,
      'JETH373',
    );
    bothReject(
      `class C { static K: u256 = 1n; static K: u256 = 2n; }`,
      `contract C { uint256 constant K = 1; uint256 constant K = 2; }`,
    );
    bothReject(
      `class C { static K: u256; K: u256 = 2n; constructor(){ this.K = 1n; } }`,
      `contract C { uint256 immutable K = 1; uint256 K = 2; }`,
    );
  });
});

describe('W7C controls: legal name reuse stays accepted (behaviorally matching solc)', () => {
  it('function overloads and virtual/override keep compiling and matching', async () => {
    await eqCalls(
      `class C { get f(): External<u256> { return 1n; } get f(a: u256): External<u256> { return a; } }`,
      `contract C { function f() external pure returns (uint256) { return 1; } function f(uint256 a) external pure returns (uint256) { return a; } }`,
      [['f()', ''], ['f(uint256)', W(9n)]],
    );
    await eqCalls(
      `abstract class A { @virtual get f(): External<u256> { return 1n; } } class C extends A { @override get f(): External<u256> { return 2n; } }`,
      `contract A { function f() external pure virtual returns (uint256) { return 1; } } contract C is A { function f() external pure override returns (uint256) { return 2; } }`,
      [['f()', '']],
    );
  });

  it('P1-4 getter var over a base @virtual function stays accepted', async () => {
    await eqCalls(
      `abstract class A { @virtual x(): External<u256>; } class C extends A { @override x: Visible<u256>; set(v: u256): External<void> { this.x = v; } }`,
      `abstract contract A { function x() external view virtual returns (uint256); } contract C is A { uint256 public override x; function set(uint256 v) external { x = v; } }`,
      [['set(uint256)', W(42n)], ['x()', '']],
    );
  });

  it('local/param shadowing of a @constant or @state name stays accepted', async () => {
    await eqCalls(
      `class C { static K: u256 = 2n; get f(K: u256): External<u256> { return K; } get g(): External<u256> { return this.K; } }`,
      `contract C { uint256 constant K2 = 2; function f(uint256 K) external pure returns (uint256) { return K; } function g() external pure returns (uint256) { return K2; } }`,
      [['f(uint256)', W(9n)], ['g()', '']],
    );
  });

  it('the same name in UNRELATED contracts is not a collision', async () => {
    await eqCalls(
      `abstract class A { static K: u256 = 1n; } class C { K: u256 = 2n; get g(): External<u256> { return this.K; } }`,
      `contract A { uint256 constant K = 1; } contract C { uint256 K = 2; function g() external view returns (uint256) { return K; } }`,
      [['g()', '']],
    );
    await eqCalls(
      `abstract class A { K: u256 = 1n; } class C { static K: Visible<u256> = 2n; }`,
      `contract A { uint256 K = 1; } contract C { uint256 public constant K = 2; }`,
      [['K()', '']],
    );
  });

  it('the SAME grandbase constant reached via two diamond paths is one declaration, not a dup', async () => {
    await eqCalls(
      `abstract class G { static K: u256 = 5n; } abstract class A extends G { } abstract class B extends G { } class C extends A, B { get g(): External<u256> { return this.K; } }`,
      `contract G { uint256 constant K = 5; } contract A is G { } contract B is G { } contract C is A, B { function g() external pure returns (uint256) { return K; } }`,
      [['g()', '']],
    );
  });

  it('inherited state/constant used (not redeclared) in the derived contract stays accepted', async () => {
    await eqCalls(
      `abstract class A { K: u256 = 5n; } class C extends A { get g(): External<u256> { return this.K; } }`,
      `contract A { uint256 K = 5; } contract C is A { function g() external view returns (uint256) { return K; } }`,
      [['g()', '']],
    );
    await eqCalls(
      `abstract class A { static K: Visible<u256> = 5n; } class C extends A { get g(): External<u256> { return this.K; } }`,
      `contract A { uint256 public constant K = 5; } contract C is A { function g() external pure returns (uint256) { return K; } }`,
      [['g()', ''], ['K()', '']],
    );
  });
});
