// OVERRIDE-VAR-MULTIHEAD + TWO-BASE-GET-DIAMOND residual lifts, runtime-equal to solc 0.8.35.
//
// LIFT 1 (OVERRIDE-VAR-MULTIHEAD residuals): a Visible<T> CONSTANT (`static K: Visible<T> = v`) or
// IMMUTABLE (`static K: Visible<T>` + ctor assign) carrying @override / @override(A, B) implements the
// named interface / base heads exactly like a state getter var (solc `uint256 public constant
// override(A, B) x = 7;` and the immutable twin, both witnessed ACCEPT). solc's mutability rule for
// public-var overrides (witnessed): a CONSTANT getter counts as PURE (may override a pure head;
// "payable to pure" rejects), an IMMUTABLE/state getter counts as VIEW ("pure to view" rejects).
// Also the >= 0.8.8 no-override rule: a Visible const/immutable satisfies a SINGLE-head interface
// obligation with no @override, at the leaf and at non-abstract middles.
//   Pre-fix controls (REJECTED at base f484e36): const+@override(A,B) -> JETH466+JETH385x2;
//   immutable+@override(A,B) -> JETH385x2; const no-override iface impl -> JETH385;
//   const at a concrete middle -> JETH385+JETH483.
//
// LIFT 2 (TWO-BASE-GET-DIAMOND residuals): a getter VAR with @override(A2, B2) unifying a get/method
// declared by TWO (unrelated or diamond-middle) base contracts - the multi-head list machinery existed
// for the leaf `get` form but the VAR form still tripped JETH430 ("must override") + JETH044 (selector
// clash with the un-dropped base winner) + JETH133; and the var-form contract-head set was not
// per-direct-base MAXIMAL, so a deep diamond `@override(M1, M2)` over a common grandbase A was rejected
// as incomplete ("must specify @override(A, M1, M2)") while solc accepts exactly (M1, M2) and rejects a
// list naming A (witnessed).
//   Pre-fix controls (REJECTED at base f484e36): var over two base gets -> JETH430+JETH044 (bodyless
//   flavor +JETH380); const over two base gets -> JETH466+JETH430; immutable -> JETH430+JETH133+JETH044;
//   deep-diamond var -> JETH433+JETH430+JETH133+JETH044.
//
// OVER-ACCEPTANCES CLOSED (solc rejects, base f484e36 accepted): @override on a Visible immutable with
// NOTHING to override (silently swallowed); @virtual on an immutable (solc parse-rejects).
//
// Every reject cell below is solc-witnessed as a solc-reject (parity, no over-rejection).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n)).toString();
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

function codesOf(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    return ((e as { diagnostics?: { code: string }[] }).diagnostics ?? []).map((d) => d.code);
  }
}
const accepts = (src: string) => codesOf(src).length === 0;
const solcRejects = (src: string) => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};

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

describe('LIFT 1 residuals: Visible constant / immutable as the @override getter var', () => {
  it('constant + @override(A, B) over two same-sig interfaces (pre-fix: JETH466+JETH385x2)', async () => {
    await eqCalls(
      `interface A { x(): View<u256>; } interface B { x(): View<u256>; }
       class C extends A, B { @override(A, B) static x: Visible<u256> = 7001n; }`,
      `interface A { function x() external view returns (uint256); } interface B { function x() external view returns (uint256); }
       contract C is A, B { uint256 public constant override(A, B) x = 7001; }`,
      [['x()', '']],
    );
  });

  it('immutable + @override(A, B) over two same-sig interfaces (pre-fix: JETH385x2)', async () => {
    await eqCalls(
      `interface A { x(): View<u256>; } interface B { x(): View<u256>; }
       class C extends A, B { @override(A, B) static x: Visible<u256>; constructor() { this.x = 7002n; } }`,
      `interface A { function x() external view returns (uint256); } interface B { function x() external view returns (uint256); }
       contract C is A, B { uint256 public immutable override(A, B) x; constructor() { x = 7002; } }`,
      [['x()', '']],
    );
  });

  it('constant getter counts as PURE: @override over a Pure<T> interface method (solc-witnessed ACCEPT)', async () => {
    await eqCalls(
      `interface A { x(): Pure<u256>; } class C extends A { @override static x: Visible<u256> = 7003n; }`,
      `interface A { function x() external pure returns (uint256); } contract C is A { uint256 public constant override x = 7003; }`,
      [['x()', '']],
    );
    // and over a pure @virtual BASE get (witnessed ACCEPT: "pure" head, pure constant getter)
    await eqCalls(
      `abstract class A2 { @virtual get g(): External<u256> { return 1n; } }
       class C extends A2 { @override static g: Visible<u256> = 7004n; }`,
      `abstract contract A2 { function g() external pure virtual returns(uint256) { return 1; } }
       contract C is A2 { uint256 public constant override g = 7004; }`,
      [['g()', '']],
    );
  });

  it('no-@override single-head iface impl by a Visible constant / immutable (solc >= 0.8.8 rule)', async () => {
    await eqCalls(
      `interface A { x(): View<u256>; } class C extends A { static x: Visible<u256> = 7005n; }`,
      `interface A { function x() external view returns (uint256); } contract C is A { uint256 public constant x = 7005; }`,
      [['x()', '']],
    );
    await eqCalls(
      `interface A { x(): View<u256>; } class C extends A { static x: Visible<u256>; constructor() { this.x = 7006n; } }`,
      `interface A { function x() external view returns (uint256); } contract C is A { uint256 public immutable x; constructor() { x = 7006; } }`,
      [['x()', '']],
    );
  });

  it('constant + @override(B, A) over a base get AND an interface method (mixed heads)', async () => {
    await eqCalls(
      `abstract class B { @virtual get x(): External<u256> { return 1n; } } interface A { x(): View<u256>; }
       class C extends B, A { @override(B, A) static x: Visible<u256> = 7007n; }`,
      `abstract contract B { function x() external view virtual returns (uint256) { return 1; } } interface A { function x() external view returns (uint256); }
       contract C is B, A { uint256 public constant override(B, A) x = 7007; }`,
      [['x()', '']],
    );
  });

  it('bytes32 constant multi-head (value-type spread)', async () => {
    await eqCalls(
      `interface A { x(): View<bytes32>; } interface B { x(): View<bytes32>; }
       class C extends A, B { @override(A, B) static x: Visible<bytes32> = bytes32(0x1122334455667788112233445566778811223344556677881122334455667788n); }`,
      `interface A { function x() external view returns (bytes32); } interface B { function x() external view returns (bytes32); }
       contract C is A, B { bytes32 public constant override(A, B) x = bytes32(uint256(0x1122334455667788112233445566778811223344556677881122334455667788)); }`,
      [['x()', '']],
    );
  });

  it('iface obligation satisfied by a Visible const / immutable at a NON-abstract MIDDLE (pre-fix: JETH385+JETH483)', async () => {
    await eqCalls(
      `interface I { x(): View<u256>; } class M extends I { static x: Visible<u256> = 7008n; } class C extends M { get other(): External<u256> { return 5n; } }`,
      `interface I { function x() external view returns (uint256); } contract M is I { uint256 public constant x = 7008; } contract C is M { function other() external view returns (uint256) { return 5; } }`,
      [['x()', ''], ['other()', '']],
    );
    await eqCalls(
      `interface I { x(): View<u256>; } class M extends I { static x: Visible<u256>; constructor() { this.x = 7009n; } } class C extends M {}`,
      `interface I { function x() external view returns (uint256); } contract M is I { uint256 public immutable x; constructor() { x = 7009; } } contract C is M {}`,
      [['x()', '']],
    );
  });

  it('REJECT parity (each cell solc-witnessed as a reject): mutability / heads / visibility', () => {
    // immutable getter is VIEW: a pure iface head stays rejected ("pure to view"). The head DECLARES its
    // mutability, so it is final when the getter-var override is validated - this cell is the live one.
    expect(codesOf(`interface A { x(): Pure<u256>; } class C extends A { @override static x: Visible<u256>; constructor() { this.x = 7n; } }`)).toContain('JETH433');
    // The CONTRACT-base twin of the cell above: the pure head now comes from an INFERRED body (View<T>/
    // Pure<T> are interface-only, JETH498). This was a hole - resolveGetterOverrides runs at collection time
    // (base.mutability still the provisional nonpayable), and a base whose only override is a getter VAR is
    // dropped from dispatch so it was never inferred. CLOSED: the base's transitive effects are now computed
    // on the side (the base-effects pass in analyzeContract, byte-neutral) and the pure->view loosening is
    // rejected POST-fixpoint (getterVarBaseMutPairs). solc: "Overriding public state variable changes state
    // mutability from \"pure\" to \"view\"". An INFERRED-VIEW base (a body that reads storage/env) stays
    // accepted (view->view) - proven by the view-* cells elsewhere and the byte-identity sweep.
    expect(codesOf(`abstract class A2 { @virtual get g(): External<u256> { return 1n; } } class C extends A2 { @override static g: Visible<u256>; constructor() { this.g = 5n; } }`)).toContain('JETH433');
    // an INFERRED-VIEW base (reads storage) is view->view: ACCEPTED (must not over-reject; the closure above
    // must fire ONLY on a pure base, not on every getter-var-over-contract-base override).
    expect(accepts(`abstract class A2 { n: u256; @virtual get g(): External<u256> { return this.n; } } class C extends A2 { @override static g: Visible<u256>; constructor() { this.g = 5n; } }`)).toBe(true);
    // TRANSITIVITY: a pure-looking base body that CALLS a storage-reading helper is VIEW, not pure -> ACCEPT;
    // one that only calls a pure helper is PURE -> REJECT. The check must see the base's transitive effects.
    expect(accepts(`abstract class A2 { m: u256; h(): u256 { return this.m; } @virtual get g(): External<u256> { return this.h(); } } class C extends A2 { @override static g: Visible<u256>; constructor() { this.g = 5n; } }`)).toBe(true);
    expect(codesOf(`abstract class A2 { h(): u256 { return 2n; } @virtual get g(): External<u256> { return this.h(); } } class C extends A2 { @override static g: Visible<u256>; constructor() { this.g = 5n; } }`)).toContain('JETH433');
    // a CONSTANT getter counts as PURE, so pure-base -> pure-getter is NOT a loosening: ACCEPT (only a
    // payable base rejects for a constant).
    expect(accepts(`abstract class A2 { @virtual get g(): External<u256> { return 1n; } } class C extends A2 { @override static g: Visible<u256> = 7n; }`)).toBe(true);
    // a payable head rejects even for a constant ("payable to pure")
    expect(codesOf(`interface A { x(): Payable<u256>; } class C extends A { @override static x: Visible<u256> = 7n; }`)).toContain('JETH433');
    // const return-type mismatch vs the iface head
    expect(codesOf(`interface A { x(): View<u256>; } class C extends A { @override static x: Visible<u128> = 7n; }`)).toContain('JETH433');
    // missing one head / bare list over two ifaces still demands @override(A, B)
    expect(codesOf(`interface A { x(): View<u256>; } interface B { x(): View<u256>; } class C extends A, B { @override(A) static x: Visible<u256> = 7n; }`)).toContain('JETH433');
    expect(codesOf(`interface A { x(): View<u256>; } interface B { x(): View<u256>; } class C extends A, B { static x: Visible<u256> = 7n; }`)).toContain('JETH385');
    // duplicate head name
    expect(codesOf(`interface A { x(): View<u256>; } interface B { x(): View<u256>; } class C extends A, B { @override(A, A, B) static x: Visible<u256> = 7n; }`)).toContain('JETH433');
    // @override on a NON-Visible static: solc "Override can only be used with public state variables."
    expect(codesOf(`interface A { x(): View<u256>; } class C extends A { @override static x: u256 = 7n; }`)).toContain('JETH466');
    expect(codesOf(`interface A { x(): View<u256>; } class C extends A { @override static x: u256; constructor() { this.x = 7n; } }`)).toContain('JETH312');
    // const over a NON-virtual base get
    expect(codesOf(`abstract class A2 { get g(): External<u256> { return 1n; } } class C extends A2 { @override static g: Visible<u256> = 5n; }`)).toContain('JETH433');
    // const missing @override over a base-contract head (the 0.8.8 no-override rule is IFACE-only)
    expect(accepts(`abstract class A2 { @virtual get g(): External<u256> { return 1n; } } class C extends A2 { static g: Visible<u256> = 5n; }`)).toBe(false);
  });

  it('OA closed: an UNATTACHED same-file interface is no override target for a getter var', () => {
    // base f484e36 ACCEPTED the plain-var form (the iface-head existence probe scanned the whole-file
    // interface registry instead of the heritage-reachable heads); solc rejects all three ("Public
    // state variable has override specified but does not override anything.").
    expect(codesOf(`interface A { x(): View<u256>; } class C { @override x: Visible<u256>; }`)).toContain('JETH433');
    expect(codesOf(`interface A { x(): View<u256>; } class C { @override static x: Visible<u256> = 7n; }`)).toContain('JETH433');
    expect(codesOf(`interface A { x(): View<u256>; } class C { @override static x: Visible<u256>; constructor() { this.x = 1n; } }`)).toContain('JETH433');
    expect(solcRejects(`interface A { function x() external view returns (uint256); } contract C { uint256 public override x; }`)).toBe(true);
  });

  it('OA closed: immutable @override-of-nothing and @virtual immutable now reject (solc-witnessed rejects)', () => {
    // base f484e36 ACCEPTED both (the @override/@virtual decorator was silently swallowed on immutables)
    expect(codesOf(`class C { @override static x: Visible<u256>; constructor() { this.x = 1n; } }`)).toContain('JETH433');
    expect(codesOf(`class C { @virtual static x: Visible<u256>; constructor() { this.x = 1n; } }`)).toContain('JETH312');
    // the constant twins stay rejects (already gated at base)
    expect(codesOf(`class C { @override static x: Visible<u256> = 7n; }`)).toContain('JETH433');
    expect(codesOf(`class C { @virtual static x: Visible<u256> = 7n; }`)).toContain('JETH466');
    // solc parity for the two closed OAs
    expect(solcRejects(`contract C { uint256 public immutable override x; constructor() { x = 1; } }`)).toBe(true);
    expect(solcRejects(`contract C { uint256 public immutable virtual x; constructor() { x = 1; } }`)).toBe(true);
  });
});

// NOTE on base bodies: a base get that reads the environment (`return block.number`) INFERS view, matching
// the `external view virtual` mirror. These bases are DROPPED (a public var override is terminal), so the
// body never runs and its value is irrelevant - what matters is the inferred mutability. A body that returns
// only a literal INFERS pure (JETH picks the tightest mutability), and an IMMUTABLE/state getter (view) over
// a pure base is a pure->view loosening solc rejects (getterVarBaseMutPairs). A view base keeps view->view
// legal. The CONSTANT-getter cell below deliberately keeps a pure-literal base: a constant getter counts as
// pure, so pure->pure is legal and must accept.
describe('LIFT 2 residuals: getter var / static unifying a get declared by two base contracts', () => {
  it('var + @override(A2, B2) over two IMPLEMENTED base gets (pre-fix: JETH430+JETH044)', async () => {
    await eqCalls(
      `abstract class A2 { @virtual get g(): External<u256> { return block.number; } }
       abstract class B2 { @virtual get g(): External<u256> { return block.number; } }
       class C extends A2, B2 { @override(A2, B2) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`,
      `abstract contract A2 { function g() external view virtual returns(uint256) { return 1; } }
       abstract contract B2 { function g() external view virtual returns(uint256) { return 2; } }
       contract C is A2, B2 { uint256 public override(A2, B2) g; function set(uint256 v) external { g = v; } }`,
      [['g()', ''], ['set(uint256)', W(0x8101)], ['g()', '']],
    );
  });

  it('var + @override(A2, B2) over two BODYLESS @virtual base gets (pre-fix: JETH430+JETH380+JETH044)', async () => {
    await eqCalls(
      `abstract class A2 { @virtual get g(): External<u256>; }
       abstract class B2 { @virtual get g(): External<u256>; }
       class C extends A2, B2 { @override(A2, B2) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`,
      `abstract contract A2 { function g() external view virtual returns(uint256); }
       abstract contract B2 { function g() external view virtual returns(uint256); }
       contract C is A2, B2 { uint256 public override(A2, B2) g; function set(uint256 v) external { g = v; } }`,
      [['g()', ''], ['set(uint256)', W(0x8102)], ['g()', '']],
    );
  });

  it('constant / immutable + @override(A2, B2) over two base gets (pre-fix: JETH466+JETH430 / JETH430+JETH133+JETH044)', async () => {
    await eqCalls(
      `abstract class A2 { @virtual get g(): External<u256> { return 1n; } }
       abstract class B2 { @virtual get g(): External<u256> { return 2n; } }
       class C extends A2, B2 { @override(A2, B2) static g: Visible<u256> = 8103n; }`,
      `abstract contract A2 { function g() external view virtual returns(uint256) { return 1; } }
       abstract contract B2 { function g() external view virtual returns(uint256) { return 2; } }
       contract C is A2, B2 { uint256 public constant override(A2, B2) g = 8103; }`,
      [['g()', '']],
    );
    await eqCalls(
      `abstract class A2 { @virtual get g(): External<u256> { return block.number; } }
       abstract class B2 { @virtual get g(): External<u256> { return block.number; } }
       class C extends A2, B2 { @override(A2, B2) static g: Visible<u256>; constructor() { this.g = 8104n; } }`,
      `abstract contract A2 { function g() external view virtual returns(uint256) { return 1; } }
       abstract contract B2 { function g() external view virtual returns(uint256) { return 2; } }
       contract C is A2, B2 { uint256 public immutable override(A2, B2) g; constructor() { g = 8104; } }`,
      [['g()', '']],
    );
  });

  it('deep diamond: var @override(M1, M2) over middles that override a common grandbase (pre-fix: JETH433 head-maximality)', async () => {
    await eqCalls(
      `abstract class A { @virtual get g(): External<u256> { return block.number; } }
       abstract class M1 extends A { @virtual @override get g(): External<u256> { return block.number; } }
       abstract class M2 extends A { @virtual @override get g(): External<u256> { return block.number; } }
       class C extends M1, M2 { @override(M1, M2) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`,
      `abstract contract A { function g() external view virtual returns(uint256) { return 1; } }
       abstract contract M1 is A { function g() external view virtual override returns(uint256) { return 2; } }
       abstract contract M2 is A { function g() external view virtual override returns(uint256) { return 3; } }
       contract C is M1, M2 { uint256 public override(M1, M2) g; function set(uint256 v) external { g = v; } }`,
      [['g()', ''], ['set(uint256)', W(0x8105)], ['g()', '']],
    );
    // un-overridden sibling path: heads are {B, A} (A stays a head via K) - list must name BOTH
    await eqCalls(
      `abstract class A { @virtual get g(): External<u256> { return block.number; } }
       abstract class B extends A { @virtual @override get g(): External<u256> { return block.number; } }
       abstract class K extends A { }
       class C extends B, K { @override(B, A) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`,
      `abstract contract A { function g() external view virtual returns(uint256) { return 1; } }
       abstract contract B is A { function g() external view virtual override returns(uint256) { return 2; } }
       abstract contract K is A { }
       contract C is B, K { uint256 public override(B, A) g; function set(uint256 v) external { g = v; } }`,
      [['g()', ''], ['set(uint256)', W(0x8106)], ['g()', '']],
    );
  });

  it('var at a MIDDLE + deployed leaf; middle super-caller body dropped cleanly', async () => {
    await eqCalls(
      `abstract class A2 { @virtual get g(): External<u256> { return block.number; } }
       abstract class B2 { @virtual get g(): External<u256> { return block.number; } }
       abstract class M extends A2, B2 { @override(A2, B2) g: Visible<u256>; }
       class C extends M { set(v: u256): External<void> { this.g = v; } }`,
      `abstract contract A2 { function g() external view virtual returns(uint256) { return 1; } }
       abstract contract B2 { function g() external view virtual returns(uint256) { return 2; } }
       abstract contract M is A2, B2 { uint256 public override(A2, B2) g; }
       contract C is M { function set(uint256 v) external { g = v; } }`,
      [['g()', ''], ['set(uint256)', W(0x8107)], ['g()', '']],
    );
    await eqCalls(
      `abstract class A2 { @virtual x(): External<u256> { return block.number; } }
       abstract class M extends A2 { @virtual @override x(): External<u256> { return block.number; } }
       class C extends M { @override x: Visible<u256>; set(v: u256): External<void> { this.x = v; } }`,
      `abstract contract A2 { function x() external view virtual returns(uint256) { return 1; } }
       abstract contract M is A2 { function x() external view virtual override returns(uint256) { return 2; } }
       contract C is M { uint256 public override x; function set(uint256 v) external { x = v; } }`,
      [['x()', ''], ['set(uint256)', W(0x8108)], ['x()', '']],
    );
  });

  it('var override coexists with a same-name base OVERLOAD (dispatch stays correct)', async () => {
    await eqCalls(
      `abstract class A2 { @virtual get x(): External<u256> { return block.number; } get x2(a: u256): External<u256> { return a * 3n; } }
       abstract class B2 { @virtual get x(): External<u256> { return block.number; } }
       class C extends A2, B2 { @override(A2, B2) x: Visible<u256>; set(v: u256): External<void> { this.x = v; } }`,
      `abstract contract A2 { function x() external view virtual returns(uint256) { return 1; } function x2(uint256 a) external view returns(uint256) { return a * 3; } }
       abstract contract B2 { function x() external view virtual returns(uint256) { return 2; } }
       contract C is A2, B2 { uint256 public override(A2, B2) x; function set(uint256 v) external { x = v; } }`,
      [['x()', ''], ['x2(uint256)', W(9)], ['set(uint256)', W(0x8109)], ['x()', '']],
    );
  });

  it('REJECT parity (each cell solc-witnessed as a reject): completeness / maximality / abstractness', () => {
    // var over two base gets WITHOUT the full list ("needs to specify overridden contracts")
    expect(accepts(`abstract class A2 { @virtual get g(): External<u256> { return 1n; } } abstract class B2 { @virtual get g(): External<u256> { return 2n; } } class C extends A2, B2 { @override g: Visible<u256>; }`)).toBe(false);
    // deep-diamond var naming only the NON-maximal root A ("Invalid contract specified in override list")
    expect(accepts(`abstract class A { @virtual get g(): External<u256> { return 1n; } } abstract class M1 extends A { @virtual @override get g(): External<u256> { return 2n; } } abstract class M2 extends A { @virtual @override get g(): External<u256> { return 3n; } } class C extends M1, M2 { @override(A) g: Visible<u256>; }`)).toBe(false);
    // deep-diamond var listing the root ALONGSIDE the maximal heads is also rejected by solc
    expect(accepts(`abstract class A { @virtual get g(): External<u256> { return 1n; } } abstract class M1 extends A { @virtual @override get g(): External<u256> { return 2n; } } abstract class M2 extends A { @virtual @override get g(): External<u256> { return 3n; } } class C extends M1, M2 { @override(A, M1, M2) g: Visible<u256>; }`)).toBe(false);
    // a concrete MIDDLE that leaves the obligation open still rejects (leaf const does not excuse it)
    expect(codesOf(`interface I { x(): View<u256>; } class M extends I {} class C extends M { @override static x: Visible<u256> = 7n; }`)).toContain('JETH483');
    // leaf `get` diamond WITHOUT the list stays a reject (the pre-existing JETH381 gate, unchanged)
    expect(codesOf(`abstract class A2 { @virtual get g(): External<u256> { return 1n; } } abstract class B2 { @virtual get g(): External<u256> { return 2n; } } class C extends A2, B2 { @override get g(): External<u256> { return 9n; } }`)).toContain('JETH381');
    // sig mismatch between the two base gets stays a reject
    expect(codesOf(`abstract class A2 { @virtual get g(): External<u256> { return 1n; } } abstract class B2 { @virtual get g(): External<u128> { return 2n; } } class C extends A2, B2 { @override(A2, B2) get g(): External<u256> { return 9n; } }`)).toContain('JETH377');
  });
});

// MULTI-HEAD-ONE-PURE-HEAD OA (closed here): a getter VAR jointly overriding two-or-more same-signature base
// heads where AT LEAST ONE head infers PURE. An immutable/state getter is VIEW, so a pure head is the pure->
// view loosening solc rejects ("Overriding public state variable changes state mutability from \"pure\" to
// \"view\""). The single-head closure (LIFT 1 above) DEFERRED the base pure/payable check to a post-fixpoint
// pass, but keyed each dropped base's effects by the bare getter fkey - so two same-signature heads COLLIDED
// on one key and only the first-processed head's pureness survived, making the reject ORDER-DEPENDENT: a pure
// head that landed second (or was overwritten) slipped through as an OVER-ACCEPTANCE. Now each head's effects
// are computed under its OWN key and the check scans EVERY head, rejecting if ANY is pure. b0f61af (pre-defer)
// AND c3db959 (single-head defer, this hole's shipping state) BOTH over-accepted the pure-head-not-last cells.
describe('MULTI-HEAD getter var over one-pure-head: pure->view loosening rejects (JETH433), every head order', () => {
  // The FAITHFUL solc mirror of a pure-inferring head is `external pure` (a literal body); a view head is
  // `external view` (reads block.number). solc rejects the immutable/state override of a pure head.
  const mirror = (mutsInDeclOrder: string[], overrideList: string) => {
    const bases = mutsInDeclOrder
      .map((m, i) => {
        const nm = String.fromCharCode(65 + i) + '2'; // A2, B2, C2...
        const body = m === 'pure' ? 'return 1;' : 'return block.number;';
        return `abstract contract ${nm} { function g() external ${m} virtual returns(uint256) { ${body} } }`;
      })
      .join(' ');
    const inherit = mutsInDeclOrder.map((_, i) => String.fromCharCode(65 + i) + '2').join(', ');
    return `${bases} contract C is ${inherit} { uint256 public override(${overrideList}) g; function set(uint256 v) external { g = v; } }`;
  };

  it('pure head FIRST (A2 pure, B2 view) rejects JETH433 - the surviving OA', () => {
    const J = `abstract class A2 { @virtual get g(): External<u256> { return 1n; } }
      abstract class B2 { @virtual get g(): External<u256> { return block.number; } }
      class C extends A2, B2 { @override(A2, B2) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`;
    expect(codesOf(J)).toContain('JETH433');
    expect(solcRejects(mirror(['pure', 'view'], 'A2, B2'))).toBe(true); // solc-witnessed reject (parity)
  });

  it('pure head LAST (A2 view, B2 pure) rejects JETH433', () => {
    const J = `abstract class A2 { @virtual get g(): External<u256> { return block.number; } }
      abstract class B2 { @virtual get g(): External<u256> { return 1n; } }
      class C extends A2, B2 { @override(A2, B2) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`;
    expect(codesOf(J)).toContain('JETH433');
    expect(solcRejects(mirror(['view', 'pure'], 'A2, B2'))).toBe(true);
  });

  it('pure head first, EXTENDS/OVERRIDE order swapped (extends B2, A2) still rejects JETH433', () => {
    // the processing order follows the head-collection order; swap it to prove the reject is order-invariant.
    const J = `abstract class A2 { @virtual get g(): External<u256> { return 1n; } }
      abstract class B2 { @virtual get g(): External<u256> { return block.number; } }
      class C extends B2, A2 { @override(B2, A2) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`;
    expect(codesOf(J)).toContain('JETH433');
    expect(solcRejects(`abstract contract A2 { function g() external pure virtual returns(uint256) { return 1; } }
      abstract contract B2 { function g() external view virtual returns(uint256) { return block.number; } }
      contract C is B2, A2 { uint256 public override(B2, A2) g; function set(uint256 v) external { g = v; } }`)).toBe(true);
  });

  it('pure-ARITH head (return 3n * 4n) first and last both reject JETH433', () => {
    const first = `abstract class A2 { @virtual get g(): External<u256> { return 3n * 4n; } }
      abstract class B2 { @virtual get g(): External<u256> { return block.number; } }
      class C extends A2, B2 { @override(A2, B2) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`;
    const last = `abstract class A2 { @virtual get g(): External<u256> { return block.number; } }
      abstract class B2 { @virtual get g(): External<u256> { return 3n * 4n; } }
      class C extends A2, B2 { @override(A2, B2) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`;
    expect(codesOf(first)).toContain('JETH433');
    expect(codesOf(last)).toContain('JETH433');
    expect(solcRejects(mirror(['pure', 'view'], 'A2, B2'))).toBe(true);
    expect(solcRejects(mirror(['view', 'pure'], 'A2, B2'))).toBe(true);
  });

  it('THREE heads, exactly one pure (pure first / pure middle / pure last) all reject JETH433', () => {
    const mk = (a: string, b: string, d: string) =>
      `abstract class A2 { @virtual get g(): External<u256> { ${a} } }
       abstract class B2 { @virtual get g(): External<u256> { ${b} } }
       abstract class D2 { @virtual get g(): External<u256> { ${d} } }
       class C extends A2, B2, D2 { @override(A2, B2, D2) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`;
    const P = 'return 1n;';
    const V = 'return block.number;';
    expect(codesOf(mk(P, V, V))).toContain('JETH433'); // pure first
    expect(codesOf(mk(V, P, V))).toContain('JETH433'); // pure middle
    expect(codesOf(mk(V, V, P))).toContain('JETH433'); // pure last
    expect(solcRejects(mirror(['pure', 'view', 'view'], 'A2, B2, D2'))).toBe(true);
    expect(solcRejects(mirror(['view', 'pure', 'view'], 'A2, B2, D2'))).toBe(true);
    expect(solcRejects(mirror(['view', 'view', 'pure'], 'A2, B2, D2'))).toBe(true);
  });

  it('both heads pure, STATE getter (view) - pure->view rejects JETH433', () => {
    const J = `abstract class A2 { @virtual get g(): External<u256> { return 1n; } }
      abstract class B2 { @virtual get g(): External<u256> { return 2n; } }
      class C extends A2, B2 { @override(A2, B2) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`;
    expect(codesOf(J)).toContain('JETH433');
    expect(solcRejects(`abstract contract A2 { function g() external pure virtual returns(uint256) { return 1; } }
      abstract contract B2 { function g() external pure virtual returns(uint256) { return 2; } }
      contract C is A2, B2 { uint256 public override(A2, B2) g; function set(uint256 v) external { g = v; } }`)).toBe(true);
  });

  it('IMMUTABLE getter (view) over a one-pure-head set rejects JETH433', () => {
    const J = `abstract class A2 { @virtual get g(): External<u256> { return 1n; } }
      abstract class B2 { @virtual get g(): External<u256> { return block.number; } }
      class C extends A2, B2 { @override(A2, B2) static g: Visible<u256>; constructor() { this.g = 5n; } }`;
    expect(codesOf(J)).toContain('JETH433');
    expect(solcRejects(`abstract contract A2 { function g() external pure virtual returns(uint256) { return 1; } }
      abstract contract B2 { function g() external view virtual returns(uint256) { return block.number; } }
      contract C is A2, B2 { uint256 public immutable override(A2, B2) g; constructor() { g = 5; } }`)).toBe(true);
  });

  it('CONTROL - both heads VIEW: the immutable/state getter is view->view, ACCEPTED byte-identically', async () => {
    // must NOT over-reject: the closure fires ONLY on a pure head, never on every multi-head getter override.
    await eqCalls(
      `abstract class A2 { @virtual get g(): External<u256> { return block.number; } }
       abstract class B2 { @virtual get g(): External<u256> { return block.number; } }
       class C extends A2, B2 { @override(A2, B2) g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`,
      `abstract contract A2 { function g() external view virtual returns(uint256) { return 1; } }
       abstract contract B2 { function g() external view virtual returns(uint256) { return block.number; } }
       contract C is A2, B2 { uint256 public override(A2, B2) g; function set(uint256 v) external { g = v; } }`,
      [['g()', ''], ['set(uint256)', W(0x9001)], ['g()', '']],
    );
  });

  it('CONTROL - constant getter (pure) over pure heads is pure->pure: ACCEPTED (not a loosening)', () => {
    const J = `abstract class A2 { @virtual get g(): External<u256> { return 1n; } }
      abstract class B2 { @virtual get g(): External<u256> { return 2n; } }
      class C extends A2, B2 { @override(A2, B2) static g: Visible<u256> = 7n; }`;
    expect(accepts(J)).toBe(true);
    expect(solcRejects(`abstract contract A2 { function g() external pure virtual returns(uint256) { return 1; } }
      abstract contract B2 { function g() external pure virtual returns(uint256) { return 2; } }
      contract C is A2, B2 { uint256 public constant override(A2, B2) g = 7; }`)).toBe(false);
  });

  it('DIAGS-RESTORE control: a dropped base with a body JETH cannot lower still lets C compile if solc does', () => {
    // The base-effects pass checkFunction()s the DROPPED base to read its mutability. Its body diagnostics must
    // NOT surface (the base is never deployed; solc only reads its mutability here). Witness: the base body has
    // a recursive-struct MEMORY local (JETH495, unlowerable) but reads block.number FIRST so it robustly infers
    // VIEW (no pure->view reject). c3db959 leaked JETH495+JETH074; the diags-restore drops them and C compiles,
    // matching solc. (An INHERITED unlowerable STORAGE field would reject on C itself - here the construct is
    // strictly body-local to the dropped base.)
    const J = `type P = { x: u256; kids: P[] };
      abstract class A2 { p: P; @virtual get g(): External<u256> { let e: u256 = block.number; let m: P = this.p; return e + m.x; } }
      class C extends A2 { @override g: Visible<u256>; set(v: u256): External<void> { this.g = v; } }`;
    const S = `abstract contract A2 { struct P { uint256 x; P[] kids; } P p;
      function g() external view virtual returns (uint256) { uint256 e = block.number; P memory m = p; return e + m.x; } }
      contract C is A2 { uint256 public override g; function set(uint256 v) external { g = v; } }`;
    expect(accepts(J)).toBe(true); // diags-restore removed the spurious base-body reject
    expect(solcRejects(S)).toBe(false); // solc accepts the deriving contract
  });
});
