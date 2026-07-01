// Phase 6 - CONTRACT INHERITANCE. Multiple inheritance via compile-time C3 flattening: the deployed
// @contract is the C3-linearized merge of its @abstract base chain. Storage is most-base-first (with
// packing across the boundary), the override winner is the most-derived definition, super.f() walks
// the full linearization, and constructor bodies run most-base-first. Every case is verified
// byte-identical to solc 0.8.35 (raw storage slots + returndata + ABI + accept/reject). Base-ctor
// ARGUMENTS come in two forms. (1) The HERITAGE call-form (`extends A(7)`, `extends Owned(msg.sender)`):
// arg expressions evaluate in the inheritance-specifier scope (constants / msg.* / address(this), NOT
// state or ctor params - matching solc). (2) The MODIFIER form, expressed TS-natively as a `super(args)`
// call as the FIRST statement of the derived ctor body (`constructor(s){ super(s*2); }` == solc's
// `constructor(s) Base(s*2){}`): its args evaluate in the ctor's own PARAM scope (params VISIBLE), so a
// base-ctor arg may depend on the derived ctor's parameters. Both lower through the same base-ctor-arg
// machinery (so `super(5n)` and `extends B(5n)` emit identical bytecode) and bodies run most-base-first.
// The PHANTOM modifier form `constructor() A(7)` (TS mis-parses `A(7)` as a phantom method) and the
// diamond-same-name-sibling-param shape stay gated (JETH379) - clean over-rejections, never miscompiles.
// A super arg reading contract STATE is also a sound over-rejection (solc reads the zeroed slot; JETH
// rejects the footgun).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('1111111111111111111111111111111111111111', 'hex'));
const sel = (s: string) => functionSelector(s);
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; }
  catch (e) { if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e; }
};
const solcRejects = (src: string): boolean => { try { compileSolidity(SPDX + src, 'C'); return false; } catch { return true; } };
async function dJ(s: string, argsHex = '') { const h = await Harness.create(); await h.fund(me, 10n ** 20n); return { h, a: await h.deploy(compile(s, { fileName: 'C.jeth' }).creationBytecode + argsHex, { caller: me }) }; }
async function dS(s: string, argsHex = '') { const h = await Harness.create(); await h.fund(me, 10n ** 20n); return { h, a: await h.deploy(compileSolidity(SPDX + s, 'C').creation + argsHex, { caller: me }) }; }
/** deploy J + S (optionally with appended ctor args); assert each call's returndata/success + raw slots are byte-identical. */
async function same(J: string, S: string, calls: { sig: string; arg?: string }[], nslots = 3, argsHex = '') {
  const j = await dJ(J, argsHex), s = await dS(S, argsHex);
  for (const c of calls) {
    const d = '0x' + sel(c.sig) + (c.arg ?? '');
    const rj = await j.h.call(j.a, d), rs = await s.h.call(s.a, d);
    expect(rj.success, `${c.sig} success`).toBe(rs.success);
    expect(rj.returnHex, c.sig).toBe(rs.returnHex);
  }
  // Raw storage slots: same logical writes landing in different slots would diverge here, so this
  // verifies the merged layout parity directly (compileSolidity exposes storageLayout, not the ABI).
  const js: string[] = [], ss: string[] = [];
  for (let i = 0; i < nslots; i++) { js.push(await readSlot(j.h, j.a, BigInt(i))); ss.push(await readSlot(s.h, s.a, BigInt(i))); }
  expect(js).toEqual(ss);
}
/** deploy J + S with the same appended ctor args; assert BOTH revert at deploy (e.g. a base-arg
 *  expression that overflows u256 under checked arithmetic). */
async function bothDeployRevert(J: string, S: string, argsHex = '') {
  let jr = false, sr = false;
  try { await dJ(J, argsHex); } catch { jr = true; }
  try { await dS(S, argsHex); } catch { sr = true; }
  expect({ jeth: jr, solc: sr }).toEqual({ jeth: true, solc: true });
}

describe('Phase 6 contract inheritance vs solc 0.8.35', () => {
  it('single inheritance: merged state + inherited fn + override winner + base ctor', () =>
    same(
      `@abstract class A { @state x: u256; @external getX(): u256 { return this.x; } @virtual @external bump(): void { this.x = this.x + 1n; } constructor(){ this.x = 100n; } } @contract class C extends A { @state y: u256; @override @external bump(): void { this.x = this.x + 10n; } @external setY(v: u256): void { this.y = v; } }`,
      `abstract contract A { uint256 x; function getX() external returns(uint256){ return x; } function bump() external virtual { x=x+1; } constructor(){ x=100; } } contract C is A { uint256 y; function bump() external override { x=x+10; } function setY(uint256 v) external { y=v; } }`,
      [{ sig: 'getX()' }, { sig: 'bump()' }, { sig: 'getX()' }, { sig: 'setY(uint256)', arg: pad32(7n) }], 2));

  it('super walks a 3-level chain inner-to-outer (-> 321)', () =>
    same(
      `@abstract class A { @state log: u256; @virtual f(): void { this.log = this.log * 10n + 1n; } } @abstract class B extends A { @virtual @override f(): void { this.log = this.log * 10n + 2n; super.f(); } } @contract class C extends B { @override f(): void { this.log = this.log * 10n + 3n; super.f(); } @external run(): void { this.f(); } }`,
      `abstract contract A { uint256 log; function f() internal virtual { log=log*10+1; } } abstract contract B is A { function f() internal virtual override { log=log*10+2; super.f(); } } contract C is B { function f() internal override { log=log*10+3; super.f(); } function run() external { f(); } }`,
      [{ sig: 'run()' }], 1));

  it('diamond: C extends B, K resolves super to K (C3 [C,K,B,A] -> 3)', () =>
    same(
      `@abstract class A { @state n: u256; @virtual f(): u256 { return 1n; } } @abstract class B extends A { @virtual @override f(): u256 { return 2n; } } @abstract class K extends A { @virtual @override f(): u256 { return 3n; } } @contract class C extends B, K { @override(B, K) f(): u256 { return super.f(); } @external get(): u256 { return this.f(); } }`,
      `abstract contract A { uint256 n; function f() internal virtual returns(uint256){ return 1; } } abstract contract B is A { function f() internal virtual override returns(uint256){ return 2; } } abstract contract K is A { function f() internal virtual override returns(uint256){ return 3; } } contract C is B, K { function f() internal override(B,K) returns(uint256){ return super.f(); } function get() external returns(uint256){ return f(); } }`,
      [{ sig: 'get()' }], 1));

  it('diamond: C extends K, B resolves super to B (C3 [C,B,K,A] -> 2)', () =>
    same(
      `@abstract class A { @state n: u256; @virtual f(): u256 { return 1n; } } @abstract class B extends A { @virtual @override f(): u256 { return 2n; } } @abstract class K extends A { @virtual @override f(): u256 { return 3n; } } @contract class C extends K, B { @override(K, B) f(): u256 { return super.f(); } @external get(): u256 { return this.f(); } }`,
      `abstract contract A { uint256 n; function f() internal virtual returns(uint256){ return 1; } } abstract contract B is A { function f() internal virtual override returns(uint256){ return 2; } } abstract contract K is A { function f() internal virtual override returns(uint256){ return 3; } } contract C is K, B { function f() internal override(K,B) returns(uint256){ return super.f(); } function get() external returns(uint256){ return f(); } }`,
      [{ sig: 'get()' }], 1));

  it('diamond storage layout is most-base-first [C,K,B,A] with packing across the boundary', () =>
    same(
      `@abstract class A { @state a1: u128; } @abstract class B extends A { @state b1: u128; @state b2: u256; } @abstract class K extends A { @state k1: u256; } @contract class C extends B, K { @state d1: u256; @external setall(p: u256): void { this.a1 = u128(p); this.b1 = u128(p + 1n); this.b2 = p + 2n; this.k1 = p + 3n; this.d1 = p + 4n; } }`,
      `abstract contract A { uint128 a1; } abstract contract B is A { uint128 b1; uint256 b2; } abstract contract K is A { uint256 k1; } contract C is B, K { uint256 d1; function setall(uint256 p) external { a1=uint128(p); b1=uint128(p+1); b2=p+2; k1=p+3; d1=p+4; } }`,
      [{ sig: 'setall(uint256)', arg: pad32(50n) }], 5));

  it('no-arg base constructor chain runs most-base-first (Ownable pattern)', () =>
    same(
      `@abstract class Own { @state owner: address; constructor(){ this.owner = msg.sender; } @external @view getOwner(): address { return this.owner; } } @contract class C extends Own { @state n: u256; constructor(){ this.n = 42n; } }`,
      `abstract contract Own { address owner; constructor(){ owner = msg.sender; } function getOwner() external view returns(address){ return owner; } } contract C is Own { uint256 n; constructor(){ n=42; } }`,
      [{ sig: 'getOwner()' }], 2));

  it('an inherited @modifier guards a derived function', async () => {
    const J = `@abstract class Own { @state owner: address; constructor(){ this.owner = msg.sender; } @modifier onlyOwner() { require(msg.sender == this.owner, "no"); _; } } @contract class C extends Own { @state n: u256; @external @onlyOwner setN(v: u256): void { this.n = v; } }`;
    const S = `abstract contract Own { address owner; constructor(){ owner=msg.sender; } modifier onlyOwner(){ require(msg.sender==owner,"no"); _; } } contract C is Own { uint256 n; function setN(uint256 v) external onlyOwner { n=v; } }`;
    await same(J, S, [{ sig: 'setN(uint256)', arg: pad32(5n) }], 2); // owner caller succeeds
    const j = await dJ(J), s = await dS(S);
    const other = new Address(Buffer.from('2222222222222222222222222222222222222222', 'hex'));
    const rj = await j.h.call(j.a, '0x' + sel('setN(uint256)') + pad32(5n), { caller: other });
    const rs = await s.h.call(s.a, '0x' + sel('setN(uint256)') + pad32(5n), { caller: other });
    expect(rj.success).toBe(false);
    expect(rj.success).toBe(rs.success);
  });

  describe('accept/reject parity with solc', () => {
    const par = (J: string, S: string) => { expect(codes(J).length > 0).toBe(true); expect(solcRejects(S)).toBe(true); };
    it('override of a non-@virtual base -> both reject', () =>
      par(`@abstract class A { @external f(): void {} } @contract class C extends A { @override @external f(): void {} }`, `abstract contract A { function f() external {} } contract C is A { function f() external override {} }`));
    it('a redefinition missing @override -> both reject', () =>
      par(`@abstract class A { @virtual @external f(): void {} } @contract class C extends A { @external f(): void {} }`, `abstract contract A { function f() external virtual {} } contract C is A { function f() external {} }`));
    it('a same-name @state across the chain -> both reject', () =>
      par(`@abstract class A { @state x: u256; } @contract class C extends A { @state x: u256; }`, `abstract contract A { uint256 x; } contract C is A { uint256 x; }`));
    it('a diamond override missing the @override(B,K) list -> both reject', () =>
      par(`@abstract class A { @virtual @external f(): u256 { return 1n; } } @abstract class B extends A { @virtual @override @external f(): u256 { return 2n; } } @abstract class K extends A { @virtual @override @external f(): u256 { return 3n; } } @contract class C extends B, K { @override @external f(): u256 { return 9n; } }`, `abstract contract A { function f() external virtual returns(uint256){return 1;} } abstract contract B is A { function f() external virtual override returns(uint256){return 2;} } abstract contract K is A { function f() external virtual override returns(uint256){return 3;} } contract C is B, K { function f() external override returns(uint256){return 9;} }`));
    it('a non-@abstract contract with an unimplemented @virtual -> both reject', () =>
      par(`@abstract class A { @virtual @external f(): u256; } @contract class C extends A {}`, `abstract contract A { function f() external virtual returns(uint256); } contract C is A {}`));
    it('an override loosening mutability (view -> nonpayable) -> both reject', () =>
      par(`@abstract class A { @virtual @view @external f(): u256 { return 1n; } } @contract class C extends A { @override @external f(): u256 { return 2n; } }`, `abstract contract A { function f() external view virtual returns(uint256){return 1;} } contract C is A { function f() external override returns(uint256){return 2;} }`));
    it('a C3-impossible base order (C is B, A where B is A) -> both reject', () =>
      par(`@abstract class A {} @abstract class B extends A {} @contract class C extends B, A {}`, `abstract contract A {} abstract contract B is A {} contract C is B, A {}`));
    it('a diamond override WITH @override(B,K) -> both accept', () => {
      expect(codes(`@abstract class A { @virtual @external f(): u256 { return 1n; } } @abstract class B extends A { @virtual @override @external f(): u256 { return 2n; } } @abstract class K extends A { @virtual @override @external f(): u256 { return 3n; } } @contract class C extends B, K { @override(B, K) @external f(): u256 { return 9n; } }`)).toEqual([]);
    });
    // JETH415 - @override LIST MEMBERSHIP: every name in @override(...) must be exactly a branch head (a
    // maximal sibling this winner directly overrides). solc: a non-head name -> "Invalid contract specified
    // in override list"; an undeclared name -> "Identifier not found or not unique"; a repeat -> "Duplicate
    // contract found in override list". JETH previously never validated the CONTENTS of the list.
    it('JETH415: @override(B) where B is not an overridden base -> both reject', () =>
      par(`@abstract class A { @virtual @external f(): u256 { return 1n; } } @abstract class B { @virtual @external g(): u256 { return 2n; } } @contract class C extends A { @override(B) @external f(): u256 { return 9n; } }`, `abstract contract A { function f() external virtual returns(uint256){return 1;} } abstract contract B { function g() external virtual returns(uint256){return 2;} } contract C is A { function f() external override(B) returns(uint256){return 9;} }`));
    it('JETH415: @override(Z) with Z undeclared -> both reject', () =>
      par(`@abstract class A { @virtual @external f(): u256 { return 1n; } } @contract class C extends A { @override(Z) @external f(): u256 { return 9n; } }`, `abstract contract A { function f() external virtual returns(uint256){return 1;} } contract C is A { function f() external override(Z) returns(uint256){return 9;} }`));
    it('JETH415: @override(A, X) with a stray extra X on a real single base A -> both reject', () =>
      par(`@abstract class A { @virtual @external f(): u256 { return 1n; } } @abstract class X { @virtual @external h(): u256 { return 4n; } } @contract class C extends A { @override(A, X) @external f(): u256 { return 9n; } }`, `abstract contract A { function f() external virtual returns(uint256){return 1;} } abstract contract X { function h() external virtual returns(uint256){return 4;} } contract C is A { function f() external override(A,X) returns(uint256){return 9;} }`));
    it('JETH415: @override(A) naming a NON-maximal shared root in a diamond -> both reject', () =>
      par(`@abstract class A { @virtual @external f(): u256 { return 1n; } } @abstract class B extends A { @virtual @override @external f(): u256 { return 2n; } } @abstract class K extends A { @virtual @override @external f(): u256 { return 3n; } } @contract class C extends B, K { @override(A) @external f(): u256 { return 9n; } }`, `abstract contract A { function f() external virtual returns(uint256){return 1;} } abstract contract B is A { function f() external virtual override returns(uint256){return 2;} } abstract contract K is A { function f() external virtual override returns(uint256){return 3;} } contract C is B, K { function f() external override(A) returns(uint256){return 9;} }`));
    it('JETH415: @override(B, B, K) with a duplicate name -> both reject', () =>
      par(`@abstract class A { @virtual @external f(): u256 { return 1n; } } @abstract class B extends A { @virtual @override @external f(): u256 { return 2n; } } @abstract class K extends A { @virtual @override @external f(): u256 { return 3n; } } @contract class C extends B, K { @override(B, B, K) @external f(): u256 { return 9n; } }`, `abstract contract A { function f() external virtual returns(uint256){return 1;} } abstract contract B is A { function f() external virtual override returns(uint256){return 2;} } abstract contract K is A { function f() external virtual override returns(uint256){return 3;} } contract C is B, K { function f() external override(B,B,K) returns(uint256){return 9;} }`));
    it('JETH415 control: @override(A) naming the single valid base -> both accept', () => {
      expect(codes(`@abstract class A { @virtual @external f(): u256 { return 1n; } } @contract class C extends A { @override(A) @external f(): u256 { return 9n; } }`)).toEqual([]);
      expect(solcRejects(`abstract contract A { function f() external virtual returns(uint256){return 1;} } contract C is A { function f() external override(A) returns(uint256){return 9;} }`)).toBe(false);
    });
    // Completeness across an UN-overridden sibling path (the heads fix). A defines virtual f, B extends A
    // but does NOT override f, K overrides f, C is B, K: A's version reaches C un-overridden via B, so C
    // must name BOTH A and K (solc: "needs to specify overridden contract A"). The old "maximal among all
    // overridden" heads filter dropped A (hidden behind K on the other path) -> an incomplete list was
    // over-accepted, and once JETH415 membership was enforced the valid @override(A, K) was over-rejected.
    it('diamond completeness via an un-overridden sibling: incomplete rejects, @override(A,K) accepts', () => {
      const A = `@abstract class A { @virtual @external f(): u256 { return 1n; } }`;
      const B = `@abstract class B extends A { @external gg(): u256 { return 0n; } }`;
      const K = `@abstract class K extends A { @virtual @override @external f(): u256 { return 3n; } }`;
      const sA = `abstract contract A { function f() external virtual returns(uint256){return 1;} }`;
      const sB = `abstract contract B is A { function gg() external returns(uint256){return 0;} }`;
      const sK = `abstract contract K is A { function f() external virtual override returns(uint256){return 3;} }`;
      const C = (l: string) => `${A} ${B} ${K} @contract class C extends B, K { @override${l} @external f(): u256 { return 9n; } }`;
      const sC = (l: string) => `${sA} ${sB} ${sK} contract C is B, K { function f() external override${l} returns(uint256){return 9;} }`;
      par(C('(K)'), sC('(K)')); // needs A too
      par(C(''), sC('')); // bare, needs A and K
      par(C('(A)'), sC('(A)')); // needs K too
      expect(codes(C('(A, K)'))).toEqual([]); // complete -> accept (was over-rejected)
      expect(codes(C('(K, A)'))).toEqual([]); // order-insensitive
    });
    // An @interface counts as an override HEAD. A base CONTRACT B (@virtual) and an @interface I both
    // declaring g(): solc requires @override(B, I) naming BOTH. Interface methods live in a separate
    // registry (never in the flattened contract-function list), so the heads computation must add a
    // direct-base interface declaring the winner's signature as its own head. Previously an @override(B)
    // omitting I was over-accepted, and the valid @override(B, I) was over-rejected (JETH415).
    it('interface + base-contract override heads: incomplete/bare reject, @override(B,I) accepts', () => {
      const j = (l: string) =>
        `@interface class I { @external g(): u256; } @abstract class B { @virtual @external g(): u256 { return 1n; } @virtual @external f(): u256 { return 2n; } } @contract class C extends B, I { @override${l} @external g(): u256 { return 30n; } @override @external f(): u256 { return 20n; } }`;
      const s = (l: string) =>
        `interface I { function g() external returns(uint256); } abstract contract B { function g() external virtual returns(uint256){ return 1; } function f() external virtual returns(uint256){ return 2; } } contract C is B, I { function g() external override${l} returns(uint256){ return 30; } function f() external override returns(uint256){ return 20; } }`;
      par(j('(B)'), s('(B)')); // omits I
      par(j('(I)'), s('(I)')); // omits B
      par(j(''), s('')); // bare, needs B and I
      par(j('(B, I, B)'), s('(B, I, B)')); // duplicate
      expect(codes(j('(B, I)'))).toEqual([]); // complete -> accept
      expect(codes(j('(I, B)'))).toEqual([]); // order-insensitive
    });
    it('interface + base-contract override(B,I): g()=30 / f()=20 byte-identical to solc', async () => {
      await same(
        `@interface class I { @external g(): u256; } @abstract class B { @virtual @external g(): u256 { return 1n; } @virtual @external f(): u256 { return 2n; } } @contract class C extends B, I { @override(B, I) @external g(): u256 { return 30n; } @override @external f(): u256 { return 20n; } }`,
        `interface I { function g() external returns(uint256); } abstract contract B { function g() external virtual returns(uint256){ return 1; } function f() external virtual returns(uint256){ return 2; } } contract C is B, I { function g() external override(B,I) returns(uint256){ return 30; } function f() external override returns(uint256){ return 20; } }`,
        [{ sig: 'g()' }, { sig: 'f()' }],
        1,
      );
    });
    // Two direct-base @interface heads (no base contract): the group never reaches the diamond block (only
    // C declares g() among contracts), so the completeness/membership must also be enforced there. solc:
    // @override(I, J) required; a single interface head needs no list; a transitively-inherited interface
    // named in the list is "Invalid contract specified".
    it('two-interface override heads (no base contract): @override(I,J) required, single head not', () => {
      const j2 = (l: string) =>
        `@interface class I { @external g(): u256; } @interface class J { @external g(): u256; } @contract class C extends I, J { @override${l} @external g(): u256 { return 7n; } }`;
      const s2 = (l: string) =>
        `interface I { function g() external returns(uint256); } interface J { function g() external returns(uint256); } contract C is I, J { function g() external override${l} returns(uint256){ return 7; } }`;
      par(j2(''), s2('')); // bare, needs I and J
      par(j2('(I)'), s2('(I)')); // omits J
      par(j2('(I, J, I)'), s2('(I, J, I)')); // duplicate
      expect(codes(j2('(I, J)'))).toEqual([]); // complete -> accept
      expect(codes(j2('(J, I)'))).toEqual([]); // order-insensitive
      // J extends I, C extends J only: single DIRECT head J; naming I (a transitive, non-direct interface) is invalid.
      par(
        `@interface class I { @external g(): u256; } @interface class J extends I { @external g(): u256; } @contract class C extends J { @override(I, J) @external g(): u256 { return 8n; } }`,
        `interface I { function g() external returns(uint256); } interface J is I { function g() external returns(uint256); } contract C is J { function g() external override(I,J) returns(uint256){ return 8; } }`,
      );
      expect(
        codes(
          `@interface class I { @external g(): u256; } @interface class J extends I { @external g(): u256; } @contract class C extends J { @override(J) @external g(): u256 { return 8n; } }`,
        ),
      ).toEqual([]); // single direct head J -> @override(J) accepts
    });
    // ---- base-constructor-argument accept/reject parity ----
    it('a heritage base-arg referencing a ctor parameter -> both reject (state/params not in scope)', () =>
      par(`@abstract class A { @state x: u256; constructor(v: u256){ this.x = v; } } @contract class C extends A(p + 1n) { constructor(p: u256){} }`, `abstract contract A { uint256 x; constructor(uint256 v){ x=v; } } contract C is A(p+1) { constructor(uint256 p){} }`));
    it('a heritage base-arg reading contract state -> both reject (state not yet initialized)', () =>
      par(`@abstract class A { @state x: u256; constructor(v: u256){ this.x = v; } } @contract class C extends A(this.x) { constructor(){} }`, `abstract contract A { uint256 x; constructor(uint256 v){ x=v; } } contract C is A(x) { constructor(){} }`));
    it('a missing required base-ctor arg on a concrete derived -> both reject', () =>
      par(`@abstract class A { @state x: u256; constructor(v: u256){ this.x = v; } } @contract class C extends A {}`, `abstract contract A { uint256 x; constructor(uint256 v){ x=v; } } contract C is A {}`));
    it('args given to a no-parameter base ctor -> both reject', () =>
      par(`@abstract class A { @state x: u256; constructor(){ this.x = 1n; } } @contract class C extends A(7n) {}`, `abstract contract A { uint256 x; constructor(){ x=1; } } contract C is A(7) {}`));
    it('a base-ctor arg count mismatch -> both reject', () =>
      par(`@abstract class A { @state x: u256; constructor(a: u256, b: u256){ this.x = a + b; } } @contract class C extends A(7n) {}`, `abstract contract A { uint256 x; constructor(uint256 a, uint256 b){ x=a+b; } } contract C is A(7) {}`));
    it('a diamond shared base given args by BOTH branches -> both reject (given twice)', () =>
      par(`@abstract class A { @state x: u256; constructor(v: u256){ this.x = v; } } @abstract class B extends A(1n) {} @abstract class K extends A(2n) {} @contract class C extends B, K {}`, `abstract contract A { uint256 x; constructor(uint256 v){ x=v; } } abstract contract B is A(1) {} abstract contract K is A(2) {} contract C is B, K {}`));
    it('a valid heritage base-arg (constant) -> both accept', () => {
      expect(codes(`@abstract class A { @state x: u256; constructor(v: u256){ this.x = v; } } @contract class C extends A(7n) {}`)).toEqual([]);
      expect(solcRejects(`abstract contract A { uint256 x; constructor(uint256 v){ x=v; } } contract C is A(7) {}`)).toBe(false);
    });
    it('modifier-style base args (`constructor() A(7)`) stay gated (JETH379; clean over-rejection)', () => {
      // solc accepts modifier-style base init; JETH gates it (ambiguous with a real @modifier application).
      expect(codes(`@abstract class A { @state x: u256; constructor(v: u256){ this.x = v; } } @contract class C extends A { @A(7n) constructor(){} }`)).toContain('JETH379');
      expect(solcRejects(`abstract contract A { uint256 x; constructor(uint256 v){ x=v; } } contract C is A { constructor() A(7) {} }`)).toBe(false);
    });
    it('a diamond where one provider gives two bases the SAME ctor-param name stays gated (JETH379)', () => {
      // both bases bound in the same provider block -> a flat-name-map collision; gated (never a miscompile).
      expect(codes(`@abstract class A {} @abstract class B extends A { @state bv: u256; constructor(x: u256){ this.bv = x; } } @abstract class K extends A { @state kv: u256; constructor(x: u256){ this.kv = x; } } @contract class C extends B(1n), K(2n) {}`)).toContain('JETH379');
      expect(solcRejects(`abstract contract A {} abstract contract B is A { uint256 bv; constructor(uint256 x){ bv=x; } } abstract contract K is A { uint256 kv; constructor(uint256 x){ kv=x; } } contract C is B(1), K(2) {}`)).toBe(false);
    });
  });

  // ---- base-constructor-argument codegen (byte-identical: raw slots + returndata) ----
  describe('base-constructor arguments (heritage call-form)', () => {
    it('single chain `extends A(7)`: A ctor sets state from its arg', () =>
      same(
        `@abstract class A { @state x: u256; constructor(v: u256){ this.x = v; } @external @view gx(): u256 { return this.x; } } @contract class C extends A(7n) { @state y: u256; constructor(){ this.y = 3n; } }`,
        `abstract contract A { uint256 x; constructor(uint256 v){ x=v; } function gx() external view returns(uint256){return x;} } contract C is A(7) { uint256 y; constructor(){ y=3; } }`,
        [{ sig: 'gx()' }], 2));

    it('deep chain with a constant base arg at each level + a deployed deploy-arg', () =>
      same(
        `@abstract class A { @state a: u256; constructor(v: u256){ this.a = v; } } @abstract class B extends A(11n) { @state b: u256; constructor(w: u256){ this.b = w; } } @contract class C extends B(22n) { @state c: u256; constructor(p: u256){ this.c = p; } }`,
        `abstract contract A { uint256 a; constructor(uint256 v){ a=v; } } abstract contract B is A(11) { uint256 b; constructor(uint256 w){ b=w; } } contract C is B(22) { uint256 c; constructor(uint256 p){ c=p; } }`,
        [], 3, pad32(99n)));

    it('SIDE-EFFECT ORDER: ctor bodies run most-base-first (accumulator A,B,C => 123)', () =>
      same(
        `@abstract class A { @state log: u256; constructor(v: u256){ this.log = this.log * 10n + 1n; } } @abstract class B extends A(0n) { constructor(w: u256){ this.log = this.log * 10n + 2n; } } @contract class C extends B(0n) { constructor(){ this.log = this.log * 10n + 3n; } }`,
        `abstract contract A { uint256 log; constructor(uint256 v){ log=log*10+1; } } abstract contract B is A(0) { constructor(uint256 w){ log=log*10+2; } } contract C is B(0) { constructor(){ log=log*10+3; } }`,
        [], 1));

    it('arg VALUES route to the correct base param at each level', () =>
      same(
        `@abstract class A { @state a: u256; constructor(v: u256){ this.a = v; } } @abstract class B extends A(5n) { @state b: u256; constructor(w: u256){ this.b = w; } } @contract class C extends B(6n) { @state c: u256; constructor(){ this.c = 7n; } }`,
        `abstract contract A { uint256 a; constructor(uint256 v){ a=v; } } abstract contract B is A(5) { uint256 b; constructor(uint256 w){ b=w; } } contract C is B(6) { uint256 c; constructor(){ c=7; } }`,
        [], 3));

    it('Ownable(msg.sender, 999) base + a base @immutable set from a base ctor arg', () =>
      same(
        `@abstract class Owned { @state owner: address; @immutable cap: u256; constructor(o: address, m: u256){ this.owner = o; this.cap = m; } @external @view getOwner(): address { return this.owner; } @external @view getCap(): u256 { return this.cap; } } @contract class C extends Owned(msg.sender, 999n) { @state n: u256; constructor(){ this.n = 1n; } }`,
        `abstract contract Owned { address owner; uint256 immutable cap; constructor(address o, uint256 m){ owner=o; cap=m; } function getOwner() external view returns(address){return owner;} function getCap() external view returns(uint256){return cap;} } contract C is Owned(msg.sender, 999) { uint256 n; constructor(){ n=1; } }`,
        [{ sig: 'getOwner()' }, { sig: 'getCap()' }], 1));

    it('a deployed ctor param used in the body, base initialized via a heritage constant', () =>
      same(
        `@abstract class A { @state a: u256; constructor(v: u256){ this.a = v; } } @contract class C extends A(100n) { @state c: u256; constructor(p: u256){ this.c = p + 1n; } }`,
        `abstract contract A { uint256 a; constructor(uint256 v){ a=v; } } contract C is A(100) { uint256 c; constructor(uint256 p){ c=p+1; } }`,
        [], 2, pad32(41n)));

    it('diamond: only one branch gives the shared base args, the other is bare', () =>
      same(
        `@abstract class A { @state av: u256; constructor(p: u256){ this.av = p; } } @abstract class B extends A(1n) { @state bv: u256; constructor(q: u256){ this.bv = q; } } @abstract class K extends A { @state kv: u256; constructor(r: u256){ this.kv = r; } } @contract class C extends B(7n), K(8n) { @state cv: u256; constructor(){ this.cv = 9n; } }`,
        `abstract contract A { uint256 av; constructor(uint256 p){ av=p; } } abstract contract B is A(1) { uint256 bv; constructor(uint256 q){ bv=q; } } abstract contract K is A { uint256 kv; constructor(uint256 r){ kv=r; } } contract C is B(7), K(8) { uint256 cv; constructor(){ cv=9; } }`,
        [], 4));

    it('diamond: the shared base args supplied by the deployed (listed first)', () =>
      same(
        `@abstract class A { @state av: u256; constructor(p: u256){ this.av = p; } } @abstract class B extends A { @state bv: u256; constructor(){ this.bv = 2n; } } @abstract class K extends A { @state kv: u256; constructor(){ this.kv = 3n; } } @contract class C extends A(55n), B, K { @state cv: u256; constructor(){ this.cv = 4n; } }`,
        `abstract contract A { uint256 av; constructor(uint256 p){ av=p; } } abstract contract B is A { uint256 bv; constructor(){ bv=2; } } abstract contract K is A { uint256 kv; constructor(){ kv=3; } } contract C is A(55), B, K { uint256 cv; constructor(){ cv=4; } }`,
        [], 4));
  });

  // ---- super(args): PARAMETER-DEPENDENT base-ctor arguments (the TS-native modifier form) ----------
  // solc lets a base-ctor arg depend on the derived ctor's params ONLY via the modifier form
  // `constructor(uint s) Base(s*2){}` - which is not valid TypeScript. The TS-native equivalent is a
  // `super(args)` call as the FIRST statement of the derived ctor body (TS forbids `this` before super,
  // and solc runs base ctors before the derived body). super args are the MODIFIER form: unlike a
  // heritage `extends B(args)` (params HIDDEN), they evaluate in the ctor's own PARAM scope (params
  // VISIBLE). Every case is verified byte-identical to solc 0.8.35 (raw slots + returndata + accept/
  // reject). super() lowers through the exact base-ctor-arg machinery, so `super(5n)` produces the same
  // bytecode as `extends B(5n)`.
  describe('super(args) parameter-dependent base-constructor arguments (modifier form)', () => {
    it('TARGET super(s*2): getCap() == 2*s, byte-identical to solc modifier form', () =>
      same(
        `@abstract class Token { @state cap: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token { constructor(s: u256) { super(s * 2n); } @external @view getCap(): u256 { return this.cap; } }`,
        `abstract contract Token { uint256 cap; constructor(uint256 c){ cap=c; } } contract C is Token { constructor(uint256 s) Token(s*2){} function getCap() external view returns(uint256){ return cap; } }`,
        [{ sig: 'getCap()' }], 1, pad32(21n)));

    it('super(5n) constant == the heritage extends Token(5n) form', () =>
      same(
        `@abstract class Token { @state cap: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token { constructor() { super(5n); } @external @view g(): u256 { return this.cap; } }`,
        `abstract contract Token { uint256 cap; constructor(uint256 c){ cap=c; } } contract C is Token { constructor() Token(5){} function g() external view returns(uint256){ return cap; } }`,
        [{ sig: 'g()' }], 1));

    it('super(5n) produces byte-identical creation bytecode to `extends Token(5n)`', () => {
      const bySuper = compile(
        `@abstract class Token { @state cap: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token { constructor() { super(5n); } @external @view g(): u256 { return this.cap; } }`,
        { fileName: 'C.jeth' },
      ).creationBytecode;
      const byHeritage = compile(
        `@abstract class Token { @state cap: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token(5n) { @external @view g(): u256 { return this.cap; } }`,
        { fileName: 'C.jeth' },
      ).creationBytecode;
      expect(bySuper).toBe(byHeritage);
    });

    it('super(a+b) references multiple ctor params', () =>
      same(
        `@abstract class Token { @state cap: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token { constructor(a: u256, b: u256) { super(a + b); } @external @view g(): u256 { return this.cap; } }`,
        `abstract contract Token { uint256 cap; constructor(uint256 c){ cap=c; } } contract C is Token { constructor(uint256 a, uint256 b) Token(a+b){} function g() external view returns(uint256){ return cap; } }`,
        [{ sig: 'g()' }], 1, pad32(10n) + pad32(7n)));

    it('super(msg.sender) address argument', () =>
      same(
        `@abstract class Own { @state o: address; constructor(x: address){ this.o = x; } } @contract class C extends Own { constructor() { super(msg.sender); } @external @view getO(): address { return this.o; } }`,
        `abstract contract Own { address o; constructor(address x){ o=x; } } contract C is Own { constructor() Own(msg.sender){} function getO() external view returns(address){ return o; } }`,
        [{ sig: 'getO()' }], 1));

    it('super(msg.sender, m): two base params, one a ctor param', () =>
      same(
        `@abstract class Owned { @state owner: address; @state cap: u256; constructor(o: address, m: u256){ this.owner = o; this.cap = m; } } @contract class C extends Owned { constructor(m: u256) { super(msg.sender, m); } @external @view go(): address { return this.owner; } @external @view gc(): u256 { return this.cap; } }`,
        `abstract contract Owned { address owner; uint256 cap; constructor(address o, uint256 m){ owner=o; cap=m; } } contract C is Owned { constructor(uint256 m) Owned(msg.sender, m){} function go() external view returns(address){ return owner; } function gc() external view returns(uint256){ return cap; } }`,
        [{ sig: 'go()' }, { sig: 'gc()' }], 2, pad32(999n)));

    it('super then derived-body statements run AFTER the base ctor (this.n = s)', () =>
      same(
        `@abstract class Token { @state cap: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token { @state n: u256; constructor(s: u256) { super(s * 2n); this.n = s; } @external @view gc(): u256 { return this.cap; } @external @view gn(): u256 { return this.n; } }`,
        `abstract contract Token { uint256 cap; constructor(uint256 c){ cap=c; } } contract C is Token { uint256 n; constructor(uint256 s) Token(s*2){ n = s; } function gc() external view returns(uint256){ return cap; } function gn() external view returns(uint256){ return n; } }`,
        [{ sig: 'gc()' }, { sig: 'gn()' }], 2, pad32(5n)));

    it('3-level chain: C super() to B, B initialized A via heritage', () =>
      same(
        `@abstract class A { @state a: u256; constructor(v: u256){ this.a = v; } } @abstract class B extends A(11n) { @state b: u256; constructor(w: u256){ this.b = w; } } @contract class C extends B { constructor(p: u256) { super(p + 1n); } @external @view ga(): u256 { return this.a; } @external @view gb(): u256 { return this.b; } }`,
        `abstract contract A { uint256 a; constructor(uint256 v){ a=v; } } abstract contract B is A(11) { uint256 b; constructor(uint256 w){ b=w; } } contract C is B { constructor(uint256 p) B(p+1){} function ga() external view returns(uint256){ return a; } function gb() external view returns(uint256){ return b; } }`,
        [{ sig: 'ga()' }, { sig: 'gb()' }], 2, pad32(40n)));

    it('super arg OVERFLOW (s*2 wraps u256) deploy-reverts on both', () =>
      bothDeployRevert(
        `@abstract class Token { @state cap: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token { constructor(s: u256) { super(s * 2n); } }`,
        `abstract contract Token { uint256 cap; constructor(uint256 c){ cap=c; } } contract C is Token { constructor(uint256 s) Token(s*2){} }`,
        pad32(1n << 255n)));

    it('super(msg.value) in a @payable ctor routes the deploy value', async () => {
      const J = `@abstract class Token { @state cap: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token { @payable constructor() { super(msg.value); } @external @view g(): u256 { return this.cap; } }`;
      const S = `abstract contract Token { uint256 cap; constructor(uint256 c){ cap=c; } } contract C is Token { constructor() payable Token(msg.value){} function g() external view returns(uint256){ return cap; } }`;
      const hj = await Harness.create();
      await hj.fund(me, 10n ** 20n);
      const aj = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me, value: 777n });
      const hs = await Harness.create();
      await hs.fund(me, 10n ** 20n);
      const as = await hs.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me, value: 777n });
      expect(await readSlot(hj, aj, 0n)).toBe(await readSlot(hs, as, 0n));
      const d = '0x' + sel('g()');
      const rj = await hj.call(aj, d), rs = await hs.call(as, d);
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(BigInt(rj.returnHex)).toBe(777n);
    });

    describe('super(args) accept/reject parity', () => {
      const par = (J: string, S: string) => {
        expect(codes(J).length > 0).toBe(true);
        expect(solcRejects(S)).toBe(true);
      };
      it('super args given to a NO-param base -> both reject (wrong argument count)', () =>
        par(
          `@abstract class Token { @state cap: u256; constructor(){ this.cap = 1n; } } @contract class C extends Token { constructor() { super(5n); } }`,
          `abstract contract Token { uint256 cap; constructor(){ cap=1; } } contract C is Token { constructor() Token(5){} }`,
        ));
      it('super() AND heritage extends Token(1n) for the SAME base -> both reject (given twice)', () =>
        par(
          `@abstract class Token { @state cap: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token(1n) { constructor(s: u256) { super(s * 2n); } }`,
          `abstract contract Token { uint256 cap; constructor(uint256 c){ cap=c; } } contract C is Token(1) { constructor(uint256 s) Token(s*2){} }`,
        ));
      it('super arity mismatch (too few / too many) -> both reject', () => {
        par(
          `@abstract class T { @state a: u256; @state b: u256; constructor(x: u256, y: u256){ this.a = x; this.b = y; } } @contract class C extends T { constructor(s: u256) { super(s); } }`,
          `abstract contract T { uint256 a; uint256 b; constructor(uint256 x, uint256 y){ a=x; b=y; } } contract C is T { constructor(uint256 s) T(s){} }`,
        );
        par(
          `@abstract class T { @state a: u256; constructor(x: u256){ this.a = x; } } @contract class C extends T { constructor(s: u256) { super(s, s); } }`,
          `abstract contract T { uint256 a; constructor(uint256 x){ a=x; } } contract C is T { constructor(uint256 s) T(s, s){} }`,
        );
      });
      it('super(msg.value) in a NON-payable ctor -> both reject (JETH162 / payability)', () =>
        par(
          `@abstract class Token { @state cap: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token { constructor() { super(msg.value); } }`,
          `abstract contract Token { uint256 cap; constructor(uint256 c){ cap=c; } } contract C is Token { constructor() Token(msg.value){} }`,
        ));
      it('super() ambiguous: two direct bases with parameterized ctors -> JETH rejects (heritage form required)', () => {
        expect(
          codes(
            `@abstract class A { @state a: u256; constructor(x: u256){ this.a = x; } } @abstract class B { @state b: u256; constructor(y: u256){ this.b = y; } } @contract class C extends A, B { constructor() { super(1n); } }`,
          ),
        ).toContain('JETH379');
      });
      it('super arg reading contract STATE stays a SOUND JETH over-rejection (solc accepts the modifier form)', () => {
        // solc ACCEPTS `constructor() Token(s)` reading a state variable (it reads the zeroed slot); JETH
        // deliberately rejects (state is not yet initialized when base args are evaluated - a footgun, and
        // a clean reject always beats risking wrong bytes on this degenerate case). Documented boundary.
        expect(
          codes(
            `@abstract class Token { @state cap: u256; @state s: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token { constructor() { super(this.s); } }`,
          ),
        ).toContain('JETH379');
        expect(
          solcRejects(
            `abstract contract Token { uint256 cap; uint256 s; constructor(uint256 c){ cap=c; } } contract C is Token { constructor() Token(s){} }`,
          ),
        ).toBe(false); // solc accepts it (the boundary we sound-over-reject)
      });
      it('the phantom modifier form `constructor() Token(5n)` STILL cleanly rejects (JETH379, not parsed as super)', () => {
        expect(
          codes(`@abstract class Token { @state cap: u256; constructor(c: u256){ this.cap = c; } } @contract class C extends Token { constructor() Token(5n) {} }`),
        ).toContain('JETH379');
      });
    });
  });

  // The two @override-specifier problems carry DISTINCT codes (as solc uses two distinct TypeErrors):
  //   JETH369 - @override present but overrides NOTHING ("has override specified but does not override
  //             anything"). No base / bases with unrelated names / a same-name-different-signature base.
  //   JETH374 - a base @virtual function redefined WITHOUT @override ("overriding function is missing
  //             'override' specifier"). The inverse condition.
  // A genuine override of a @virtual base must still compile (no over-rejection). JETH369 previously
  // did not fire when there was no same-named base function - an over-acceptance now closed.
  describe('@override specifier problems reject with distinct codes, matching solc 0.8.35', () => {
    it('JETH369: @override overrides nothing - no base at all', () => {
      expect(codes('@contract class C { @override @external f(): u256 { return 42n; } }')).toContain('JETH369');
      expect(solcRejects('contract C { function f() external override returns(uint256){ return 42; } }')).toBe(true);
    });
    it('JETH369: @override overrides nothing - extends a base that does not declare the function', () => {
      expect(
        codes('@abstract class A { @state x: u256; } @contract class C extends A { @override @external f(): u256 { return 1n; } }'),
      ).toContain('JETH369');
      expect(
        solcRejects('abstract contract A { uint256 x; } contract C is A { function f() external override returns(uint256){ return 1; } }'),
      ).toBe(true);
    });
    it('JETH369: @override overrides nothing - base declares a DIFFERENT-named virtual function', () => {
      expect(
        codes('@abstract class A { @virtual @external g(): u256 { return 0n; } } @contract class C extends A { @override @external f(): u256 { return 1n; } }'),
      ).toContain('JETH369');
    });
    it('JETH374: a @virtual base function redefined WITHOUT @override (the inverse) still rejects', () => {
      expect(
        codes('@abstract class A { @virtual @external f(): u256 { return 0n; } } @contract class C extends A { @external f(): u256 { return 1n; } }'),
      ).toContain('JETH374');
      expect(
        solcRejects('abstract contract A { function f() external virtual returns(uint256){ return 0; } } contract C is A { function f() external returns(uint256){ return 1; } }'),
      ).toBe(true);
    });
    it('control: a genuine @override of a real @virtual base function still compiles on both', () => {
      expect(
        codes('@abstract class A { @virtual @external f(): u256 { return 0n; } } @contract class C extends A { @override @external f(): u256 { return 1n; } }'),
      ).toEqual([]);
      expect(
        solcRejects('abstract contract A { function f() external virtual returns(uint256){ return 0; } } contract C is A { function f() external override returns(uint256){ return 1; } }'),
      ).toBe(false);
    });
  });
});
