// LIB-CONST / LIB-MEMBER-EVENT / LIB-MEMBER-ERROR: a `static class` library may declare constants,
// events, and errors (solc parity). All three are PER-LIBRARY scoped (two libraries may share a name; a
// library decl and a contract decl are distinct; a bare name in a contract never sees a library's decls),
// so the selector/topic0 (keccak of the bare signature, scope-independent) is byte-identical to solc's
// inlined library event/error. Reads: `L.K` from a contract + bare `K` inside a lib fn; raises:
// `revert(Bad(a))` / `emit(E(a))` inside a lib fn + qualified `revert(L.Bad(a))` from a contract.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e;
  }
};
async function sameRun(jsrc: string, ssrc: string, calls: [string, string?][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(jsrc, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + ssrc, 'C').creation);
  for (const [g, a = ''] of calls) {
    const rj = await h.call(aj, sel(g) + a), rs = await h.call(as, sel(g) + a);
    expect(rj.success, g).toBe(rs.success);
    expect(rj.returnHex, g).toBe(rs.returnHex);
    expect(JSON.stringify(rj.logs ?? []), g).toBe(JSON.stringify(rs.logs ?? []));
  }
}

describe('LIB-CONST: a library constant', () => {
  it('reads byte-identically to solc as L.K and bare K inside a lib fn (value / string / bytes)', async () => {
    await sameRun(
      `static class L { static K: u256 = 5n; g(): u256 { return K; } }\nclass C { get f(): External<u256> { return L.g() + L.K; } }`,
      `library L { uint256 internal constant K = 5; function g() internal pure returns(uint256){ return K; } }\ncontract C { function f() external pure returns(uint256){ return L.g() + L.K; } }`,
      [['f()']],
    );
    await sameRun(
      `static class L { static S: string = "hi"; }\nclass C { get f(): External<string> { return L.S; } }`,
      `library L { string internal constant S = "hi"; }\ncontract C { function f() external pure returns(string memory){ return L.S; } }`,
      [['f()']],
    );
    await sameRun(
      `static class L { static B: bytes = "abc"; }\nclass C { get f(): External<bytes32> { return keccak256(L.B); } }`,
      `library L { bytes internal constant B = "abc"; }\ncontract C { function f() external pure returns(bytes32){ return keccak256(L.B); } }`,
      [['f()']],
    );
  });
  it('is PER-LIBRARY: two libraries share a name, a library K and a contract K stay distinct', async () => {
    await sameRun(
      `static class A { static K: u256 = 1n; }\nstatic class B { static K: u256 = 2n; }\nclass C { get f(): External<u256> { return A.K * 10n + B.K; } }`,
      `library A { uint256 internal constant K = 1; }\nlibrary B { uint256 internal constant K = 2; }\ncontract C { function f() external pure returns(uint256){ return A.K * 10 + B.K; } }`,
      [['f()']],
    );
    await sameRun(
      `static class L { static K: u256 = 9n; }\nclass C { static K: u256 = 3n; get f(): External<u256> { return C.K * 100n + L.K; } }`,
      `library L { uint256 internal constant K = 9; }\ncontract C { uint256 constant K = 3; function f() external pure returns(uint256){ return C.K * 100 + L.K; } }`,
      [['f()']],
    );
  });
  it('NEGATIVES: @state / no-init / aggregate / cross-scope reads all stay rejected', () => {
    expect(codes(`static class L { x: u256; }\nclass C { get f(): External<u256> { return 1n; } }`)).toContain('JETH388');
    expect(codes(`static class L { static K: u256; }\nclass C { get f(): External<u256> { return 1n; } }`)).toContain('JETH388');
    expect(codes(`static class L { static K: u256[] = [1n]; }\nclass C { get f(): External<u256> { return 1n; } }`)).toContain('JETH050');
    // a bare K in a CONTRACT (only a library has K) is undeclared; this.K in a lib fn is JETH394; L.K = v is not an lvalue
    expect(codes(`static class L { static K: u256 = 5n; }\nclass C { get f(): External<u256> { return K; } }`)).toContain('JETH072');
    expect(codes(`static class L { static K: u256 = 5n; g(): u256 { return this.K; } }\nclass C { get f(): External<u256> { return L.g(); } }`)).toContain('JETH394');
    expect(codes(`static class L { static K: u256 = 5n; }\nclass C { f(): External<void> { L.K = 9n; } }`)).toContain('JETH067');
    // a library initializer referencing a contract constant does NOT silently bind it (libraries fold first)
    expect(codes(`static class L { static K: u256 = M + 1n; }\nclass C { static M: u256 = 5n; get f(): External<u256> { return L.K; } }`)).toContain('JETH048');
  });
});

describe('LIB-MEMBER-ERROR: a library error', () => {
  it('revert(Bad(a)) inside a lib fn and revert(L.Bad(a)) from a contract are byte-identical to solc', async () => {
    await sameRun(
      `static class L { Bad: error<{ a: u256 }>; check(a: u256): void { if (a > 5n) { revert(Bad(a)); } } }\nclass C { f(a: u256): External<void> { L.check(a); } }`,
      `library L { error Bad(uint256 a); function check(uint256 a) internal pure { if (a > 5) revert Bad(a); } }\ncontract C { function f(uint256 a) external pure { L.check(a); } }`,
      [['f(uint256)', W(6)], ['f(uint256)', W(3)]],
    );
    await sameRun(
      `static class L { Bad: error<{ a: u256 }>; }\nclass C { f(a: u256): External<void> { if (a > 5n) { revert(L.Bad(a)); } } }`,
      `library L { error Bad(uint256 a); }\ncontract C { function f(uint256 a) external pure { if (a > 5) revert L.Bad(a); } }`,
      [['f(uint256)', W(6)], ['f(uint256)', W(3)]],
    );
  });
  it('is PER-LIBRARY and closes the pre-existing over-acceptance (lib fn raising a CONTRACT error)', () => {
    // two libraries + a contract may each declare `Bad` (distinct scopes)
    expect(codes(`static class A { Bad: error<{ a: u256 }>; }\nstatic class B { Bad: error<{ b: address }>; }\nclass C { f(a: u256, x: address): External<void> { if (a > 0n) { revert(A.Bad(a)); } revert(B.Bad(x)); } }`)).toEqual([]);
    expect(codes(`static class L { Bad: error<{ a: u256 }>; }\nclass C { Bad: error<{ b: address }>; f(a: u256): External<void> { if (a > 0n) { revert(L.Bad(a)); } throw this.Bad(address(0n)); } }`)).toEqual([]);
    // OVER-ACCEPTANCE CLOSED: a lib fn raising a bare name that is a CONTRACT member error now rejects
    // (solc: a library cannot see a contract's errors). A FILE-LEVEL error stays visible in a lib fn.
    expect(codes(`static class L { check(a: u256): void { revert(Bad(a)); } }\nclass C { Bad: error<{ a: u256 }>; f(a: u256): External<void> { L.check(a); } }`)).toContain('JETH129');
    expect(codes(`type Boom = error<{ a: u256 }>;\nstatic class L { check(a: u256): void { revert(Boom(a)); } }\nclass C { f(a: u256): External<void> { L.check(a); } }`)).toEqual([]);
  });
  it('NEGATIVES: reserved Error name, @indexed param, in-library duplicate, this.Bad, wrong qualifier', () => {
    expect(codes(`static class L { Error: error<{ a: u256 }>; check(): void { revert(Error(1n)); } }\nclass C { f(): External<void> { L.check(); } }`)).toContain('JETH132');
    expect(codes(`static class L { Bad: error<{ a: indexed<u256> }>; }\nclass C { f(): External<void> { revert(L.Bad(1n)); } }`)).toContain('JETH129');
    expect(codes(`static class L { Bad: error<{ a: u256 }>; Bad: error<{ b: u256 }>; }\nclass C { f(): External<void> { revert(L.Bad(1n)); } }`)).toContain('JETH128');
    expect(codes(`static class L { Bad: error<{ a: u256 }>; check(a: u256): void { revert(this.Bad({a})); } }\nclass C { f(a: u256): External<void> { L.check(a); } }`)).toContain('JETH394');
  });
});

describe('LIB-MEMBER-EVENT: a library event', () => {
  it('emit(E(a)) inside a lib fn logs byte-identically to solc (plain + indexed)', async () => {
    await sameRun(
      `static class L { E: event<{ a: u256 }>; log(a: u256): void { emit(E(a)); } }\nclass C { f(a: u256): External<void> { L.log(a); } }`,
      `library L { event E(uint256 a); function log(uint256 a) internal { emit E(a); } }\ncontract C { function f(uint256 a) external { L.log(a); } }`,
      [['f(uint256)', W(7)]],
    );
    await sameRun(
      `static class L { E: event<{ who: indexed<address>; amt: u256 }>; log(w: address, a: u256): void { emit(E(w, a)); } }\nclass C { f(w: address, a: u256): External<void> { L.log(w, a); } }`,
      `library L { event E(address indexed who, uint256 amt); function log(address w, uint256 a) internal { emit E(w, a); } }\ncontract C { function f(address w, uint256 a) external { L.log(w, a); } }`,
      [['f(address,uint256)', W(BigInt('0x1111111111111111111111111111111111111111')) + W(9)]],
    );
  });
  it('is PER-LIBRARY, coexists with a contract event, closes the over-acceptance (lib fn emits a contract event)', () => {
    expect(codes(`static class A { E: event<{ a: u256 }>; log(a: u256): void { emit(E(a)); } }\nstatic class B { E: event<{ b: address }>; log(x: address): void { emit(E(x)); } }\nclass C { f(a: u256, x: address): External<void> { A.log(a); B.log(x); } }`)).toEqual([]);
    expect(codes(`static class L { E: event<{ a: u256 }>; log(a: u256): void { emit(E(a)); } }\nclass C { E: event<{ a: u256 }>; f(a: u256): External<void> { L.log(a); emit(this.E(a)); } }`)).toEqual([]);
    // OVER-ACCEPTANCE CLOSED: a lib fn emitting a bare name that is a CONTRACT event now rejects.
    expect(codes(`static class L { log(a: u256): void { emit(E(a)); } }\nclass C { E: event<{ a: u256 }>; f(a: u256): External<void> { L.log(a); } }`)).toContain('JETH147');
    // a FILE-LEVEL event stays visible in a lib fn.
    expect(codes(`type E = event<{ a: u256 }>;\nstatic class L { log(a: u256): void { emit(E(a)); } }\nclass C { f(a: u256): External<void> { L.log(a); } }`)).toEqual([]);
  });
  it('NEGATIVES: an event with an initializer, this.E in a lib fn, in-library duplicate, emit in a view lib fn', () => {
    expect(codes(`static class L { E: event<{ a: u256 }> = 1n; }\nclass C { f(): External<void> { } }`)).toContain('JETH353');
    expect(codes(`static class L { E: event<{ a: u256 }>; log(a: u256): void { emit(this.E({a})); } }\nclass C { f(a: u256): External<void> { L.log(a); } }`)).toContain('JETH394');
    expect(codes(`static class L { E: event<{ a: u256 }>; E: event<{ a: u256 }>; log(a: u256): void { emit(E(a)); } }\nclass C { f(a: u256): External<void> { L.log(a); } }`)).toContain('JETH144');
    // a `get` lib fn is read-only; emitting a log rejects (a log is a state change)
    expect(codes(`static class L { E: event<{ a: u256 }>; get bad(a: u256): u256 { emit(E(a)); return a; } }\nclass C { get f(a: u256): External<u256> { return L.bad(a); } }`)).toContain('JETH043');
  });
});

// LIB-NAMEDARG: a NAMED-argument raise `{ name: value }` of a LIBRARY-scoped event/error reorders the
// keys to the declaration's param order and lowers through the positional path, so it is BYTE-IDENTICAL
// to its positional twin (which already worked). Covers the qualified `emit(L.E({...}))` /
// `revert(L.Bad({...}))` (inside a lib fn AND from a contract) and the bare `emit(E({...}))` /
// `revert(Bad({...}))` inside the owning library. Before this lift these all over-rejected (JETH148 for
// events, JETH130 for errors) while solc accepts them. Scrambled key orders + distinct values make the
// reordering load-bearing: a no-op reorder would log/revert the WRONG bytes and diverge from solc.
const AB = W(7) + W(0xaan); // (uint256 x = 7, address y = 0xaa)
describe('LIB-NAMEDARG: a named-argument raise of a library-scoped event/error', () => {
  it('qualified emit(L.E({...})) + bare emit(E({...})) + from-contract log byte-identically to the positional twin (scrambled order, indexed)', async () => {
    // qualified L.E({ b, a }) inside a lib fn, keys scrambled, an INDEXED field
    await sameRun(
      `static class L { E: event<{ a: indexed<u256>; b: address }>; log(x: u256, y: address): void { emit(L.E({ b: y, a: x })); } }\nclass C { f(x: u256, y: address): External<void> { L.log(x, y); } }`,
      `library L { event E(uint256 indexed a, address b); function log(uint256 x, address y) internal { emit E(x, y); } }\ncontract C { function f(uint256 x, address y) external { L.log(x, y); } }`,
      [['f(uint256,address)', AB]],
    );
    // bare E({ b, a }) inside the owning library's body (the "inside-a-lib-body" form)
    await sameRun(
      `static class L { E: event<{ a: u256; b: indexed<address> }>; log(x: u256, y: address): void { emit(E({ b: y, a: x })); } }\nclass C { f(x: u256, y: address): External<void> { L.log(x, y); } }`,
      `library L { event E(uint256 a, address indexed b); function log(uint256 x, address y) internal { emit E(x, y); } }\ncontract C { function f(uint256 x, address y) external { L.log(x, y); } }`,
      [['f(uint256,address)', AB]],
    );
    // qualified emit(L.E({...})) FROM A CONTRACT (the event is declared in the library)
    await sameRun(
      `static class L { E: event<{ a: indexed<u256>; b: address }>; }\nclass C { f(x: u256, y: address): External<void> { emit(L.E({ b: y, a: x })); } }`,
      `library L { event E(uint256 indexed a, address b); }\ncontract C { function f(uint256 x, address y) external { emit L.E(x, y); } }`,
      [['f(uint256,address)', AB]],
    );
  });

  it('qualified revert(L.Bad({...})) + bare revert(Bad({...})) + from-contract carry byte-identical revert data (scrambled order)', async () => {
    await sameRun(
      `static class L { Bad: error<{ a: u256; b: address }>; chk(x: u256, y: address): void { revert(L.Bad({ b: y, a: x })); } }\nclass C { f(x: u256, y: address): External<void> { L.chk(x, y); } }`,
      `library L { error Bad(uint256 a, address b); function chk(uint256 x, address y) internal pure { revert Bad(x, y); } }\ncontract C { function f(uint256 x, address y) external pure { L.chk(x, y); } }`,
      [['f(uint256,address)', AB]],
    );
    await sameRun(
      `static class L { Bad: error<{ a: u256; b: address }>; chk(x: u256, y: address): void { revert(Bad({ b: y, a: x })); } }\nclass C { f(x: u256, y: address): External<void> { L.chk(x, y); } }`,
      `library L { error Bad(uint256 a, address b); function chk(uint256 x, address y) internal pure { revert Bad(x, y); } }\ncontract C { function f(uint256 x, address y) external pure { L.chk(x, y); } }`,
      [['f(uint256,address)', AB]],
    );
    await sameRun(
      `static class L { Bad: error<{ a: u256; b: address }>; }\nclass C { f(x: u256, y: address): External<void> { revert(L.Bad({ b: y, a: x })); } }`,
      `library L { error Bad(uint256 a, address b); }\ncontract C { function f(uint256 x, address y) external pure { revert L.Bad(x, y); } }`,
      [['f(uint256,address)', AB]],
    );
  });

  it('NON-VACUITY: a scrambled-key named emit logs data in DECLARATION order (checked independently of solc)', async () => {
    const h = await Harness.create();
    const aj = await h.deploy(
      compile(
        `static class L { E: event<{ a: u256; b: address }>; log(x: u256, y: address): void { emit(L.E({ b: y, a: x })); } }\nclass C { f(x: u256, y: address): External<void> { L.log(x, y); } }`,
        { fileName: 'C.jeth' },
      ).creationBytecode,
    );
    const r = await h.call(aj, sel('f(uint256,address)') + AB);
    expect(r.success).toBe(true);
    expect(r.logs.length).toBe(1);
    expect(r.logs[0]!.topics.length).toBe(1); // topic0 only (no indexed fields)
    // data = a (0x07) then b (0xaa), the DECLARATION order, despite `{ b: y, a: x }` scrambling the keys
    expect(r.logs[0]!.data).toBe('0x' + W(7) + W(0xaan));
  });

  it('REJECTS: an unknown key, wrong arity, and a duplicate key (event + error), matching solc', () => {
    expect(codes(`static class L { E: event<{ a: u256; b: address }>; log(x: u256, y: address): void { emit(L.E({ a: x, z: y })); } }\nclass C { f(x: u256, y: address): External<void> { L.log(x, y); } }`)).toContain('JETH130');
    expect(codes(`static class L { E: event<{ a: u256; b: address }>; log(x: u256, y: address): void { emit(E({ a: x, b: y, c: x })); } }\nclass C { f(x: u256, y: address): External<void> { L.log(x, y); } }`)).toContain('JETH130');
    expect(codes(`static class L { E: event<{ a: u256; b: address }>; log(x: u256, y: address): void { emit(L.E({ a: x, a: x, b: y })); } }\nclass C { f(x: u256, y: address): External<void> { L.log(x, y); } }`)).toContain('JETH130');
    expect(codes(`static class L { Bad: error<{ a: u256; b: address }>; chk(x: u256, y: address): void { revert(L.Bad({ a: x })); } }\nclass C { f(x: u256, y: address): External<void> { L.chk(x, y); } }`)).toContain('JETH130');
  });

  it('GUARD: a NON-library named raise is unchanged (contract bare-named still rejects; positional + this.X untouched)', async () => {
    // a contract's OWN event/error: the bare named form stays a reject (only `this.E({...})` is native)
    expect(codes(`class C { E: event<{ a: u256; b: address }>; f(x: u256, y: address): External<void> { emit(E({ a: x, b: y })); } }`)).toContain('JETH148');
    expect(codes(`class C { Bad: error<{ a: u256; b: address }>; f(x: u256, y: address): External<void> { revert(Bad({ a: x, b: y })); } }`)).toContain('JETH130');
    // solc rejects `this.E` inside a library too - the literal this.X-in-lib stays a correct both-reject
    expect(codes(`static class L { E: event<{ a: u256; b: address }>; log(x: u256, y: address): void { emit(this.E({ a: x, b: y })); } }\nclass C { f(x: u256, y: address): External<void> { L.log(x, y); } }`)).toContain('JETH394');
    // the working contract `this.E({...})` named form is untouched (byte-identical to solc)
    await sameRun(
      `class C { E: event<{ a: u256; b: address }>; f(x: u256, y: address): External<void> { emit(this.E({ b: y, a: x })); } }`,
      `contract C { event E(uint256 a, address b); function f(uint256 x, address y) external { emit E(x, y); } }`,
      [['f(uint256,address)', AB]],
    );
  });
});

// Over-acceptances found + fixed by the adversarial sweep (all three are scope/declaration gaps the
// lifts opened; solc rejects each, so the bar demands a reject).
describe('library-decls over-acceptance closures', () => {
  it('CROSS-KIND collision: a library reusing a name across kinds rejects (JETH133), like solc', () => {
    // a library has a SINGLE member namespace (functions/constants/events/errors); a name shared across
    // two kinds is "Identifier already declared" in solc. Intra-kind overloads (fn/event) stay legal.
    expect(codes(`static class L { static K: u256 = 5n; K(): u256 { return 1n; } }\nclass C { get f(): External<u256> { return L.K; } }`)).toContain('JETH133');
    expect(codes(`static class L { static K: u256 = 5n; K: event<{a: u256}>; }\nclass C { f(): External<void> {} }`)).toContain('JETH133');
    expect(codes(`static class L { static K: u256 = 5n; K: error<{a: u256}>; }\nclass C { f(): External<void> {} }`)).toContain('JETH133');
    expect(codes(`static class L { E: event<{a: u256}>; E: error<{a: u256}>; }\nclass C { f(): External<void> {} }`)).toContain('JETH133');
    expect(codes(`static class L { K(): u256 { return 1n; } K: event<{a: u256}>; }\nclass C { f(): External<void> {} }`)).toContain('JETH133');
    // distinct names + function overloads stay legal
    expect(codes(`static class L { static K: u256 = 5n; E: event<{a: u256}>; Bad: error<{a: u256}>; log(a: u256): void { emit(E(a)); } }\nclass C { f(a: u256): External<void> { L.log(a); } }`)).toEqual([]);
    expect(codes(`static class L { m(a: u256): u256 { return a; } m(a: u256, b: u256): u256 { return a+b; } }\nclass C { get f(): External<u256> { return L.m(1n) + L.m(2n, 3n); } }`)).toEqual([]);
  });
  it('EVENT SCOPE LEAK: a lib fn never binds a same-named CONTRACT event via the file-level fallback', () => {
    // a file-level E(uint256) is visible in the lib fn, the contract's E(address) is NOT; emit(E(address))
    // must fail the file-level overload (address does not fit uint256), never leak the contract overload.
    expect(codes(`type E = event<{ a: u256 }>;\nstatic class L { log(x: address): void { emit(E(x)); } }\nclass C { E: event<{ x: address }>; f(x: address): External<void> { L.log(x); } }`).some((c) => c === 'JETH085' || c === 'JETH148')).toBe(true);
    // a matching file-level emit inside the lib fn still works even with a same-named contract event
    expect(codes(`type E = event<{ a: u256 }>;\nstatic class L { log(a: u256): void { emit(E(a)); } }\nclass C { E: event<{ x: address }>; f(a: u256): External<void> { L.log(a); } }`)).toEqual([]);
  });
  it('QUALIFIED-ERROR SHADOW: revert(L.Bad(a)) rejects when L is shadowed by a param/local/state var', () => {
    expect(codes(`static class L { Bad: error<{ a: u256 }>; }\nclass C { f(L: u256): External<void> { revert(L.Bad(L)); } }`).length).toBeGreaterThan(0);
    expect(codes(`static class L { Bad: error<{ a: u256 }>; }\nclass C { f(): External<void> { let L: u256 = 3n; revert(L.Bad(1n)); } }`).length).toBeGreaterThan(0);
    expect(codes(`static class L { Bad: error<{ a: u256 }>; }\nclass C { L: u256; f(): External<void> { revert(L.Bad(1n)); } }`).length).toBeGreaterThan(0);
    // unshadowed qualified raise still works
    expect(codes(`static class L { Bad: error<{ a: u256 }>; }\nclass C { f(a: u256): External<void> { if (a > 5n) { revert(L.Bad(a)); } } }`)).toEqual([]);
  });
});
