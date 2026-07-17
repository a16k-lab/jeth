// CLASS-MUT-BAN (JETH498): `View<T>` / `Pure<T>` are INTERFACE-ONLY markers. An interface method has no
// body, so it MUST declare its mutability; a CLASS member (contract `class C`, `abstract class B`, library
// `static class L`) HAS a body, so its mutability is INFERRED from that body - unless it is `static`, which
// DECLARES it pure. The only accepted class forms are:
//   get a(): T          -> mutability INFERRED (view if it reads state/env, pure if it reads nothing)
//   static a(): T       -> PURE (declared)
//   static get a(): T   -> PURE (declared)
//
// STATIC-IS-PURE (author ruling): `static` DECLARES the member pure - it is the ONLY declared-mutability
// anchor left in the language, every other spelling having been removed by JETH481 (decorators) and JETH498
// (View<T>/Pure<T> in a class). A pure member may not read storage, write storage, emit, or read the
// execution environment (msg.*/block.*/tx.*/address(this)). An impure static is therefore REJECTED - by
// JETH164 for an env read, JETH055 for a state touch, JETH149 for a direct emit - and those codes, dead
// since JETH481/JETH498 left nothing able to declare a mutability, are live again because of this ruling.
// This is a deliberate OVER-REJECTION: `static a(): u256 { return msg.value; }` used to accept and infer
// view, matching solc's `function a() internal view` twin byte for byte. An over-rejection never emits
// wrong bytes, so the cost is accepted; a genuinely-pure static stays legal and byte-identical, and JETH's
// pure-legal set is exactly solc's (constant / msg.sig / msg.data / keccak256 / type(T).max are pure-legal;
// an immutable / block.* / tx.* / address(this) are not).
// The VISIBILITY markers are unaffected: External<T> / Payable<T> on a method, Visible<T> on a field.
// Since View<T>/Pure<T> on a `get` ALSO meant EXTERNAL, the migration of an exposed accessor is
// `get f(): View<T>` -> `get f(): External<T>` (dropping to a bare `T` would make it INTERNAL and
// silently remove it from the ABI).
//
// KNOWN + ACCEPTED CONSEQUENCE (ruled by the language author): `get f(): View<u256> { return 1n; }`
// (declared view over a PURE body) emitted ABI `view`; the same function now infers `pure`, so its ABI
// flips view->pure. solc accepts `function f() external view returns (uint256) { return 42; }`, so
// declaring view-on-a-pure-body is INEXPRESSIBLE in JETH: a deliberate OVER-REJECTION (safe - an
// over-rejection never emits wrong bytes). It also retires the GET-MUT-HEADROOM idiom; see the
// capability-loss test at the bottom for the two supported workarounds.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const mut = (src: string): Record<string, string> => {
  const abi = compile(src, { fileName: 'C.jeth' }).abi as { type: string; name?: string; stateMutability?: string }[];
  return Object.fromEntries(abi.filter((e) => e.type === 'function').map((f) => [f.name!, f.stateMutability!]));
};
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};
const msgs = (src: string): string => {
  try { compile(src, { fileName: 'C.jeth' }); return ''; } catch (e: any) { return (e?.diagnostics ?? []).map((d: any) => d.message).join(' '); }
};
const runBoth = async (J: string, S: string, calls: [string, string][]): Promise<void> => {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, args] of calls) {
    const rj = await h.call(aj, sel(sg) + args);
    const rs = await h.call(as, sel(sg) + args);
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
  }
};

describe('JETH498: View<T>/Pure<T> are banned in EVERY class context', () => {
  it('CONTRACT class: every get / static / static-get / plain spelling rejects JETH498', () => {
    for (const m of [
      `get a(): View<u256> { return this.s; }`,
      `get a(): Pure<u256> { return 1n; }`,
      `static get a(): View<u256> { return 1n; }`,
      `static get a(): Pure<u256> { return 1n; }`,
      `static a(): View<u256> { return 1n; }`,
      `static a(): Pure<u256> { return 1n; }`,
      // a plain method: pre-ban these were an ACCIDENTAL JETH013 "unknown type", not a principled rule
      `a(): View<u256> { return this.s; }`,
      `a(): Pure<u256> { return 1n; }`,
    ]) {
      expect(codes(`class C { s: u256 = 7n; ${m} }`), m).toContain('JETH498');
    }
  });

  it('ABSTRACT class: every spelling rejects JETH498 (incl. the BODYLESS declaration)', () => {
    for (const m of [
      `get a(): View<u256> { return this.s; }`,
      `get a(): Pure<u256> { return 1n; }`,
      `static get a(): Pure<u256> { return 1n; }`,
      `static a(): View<u256> { return 1n; }`,
      `@virtual get a(): View<u256>;`, // bodyless: nothing to infer from, still banned
      `abstract get a(): Pure<u256>;`,
    ]) {
      expect(codes(`abstract class B { s: u256 = 7n; ${m} }\nclass C extends B {}`), m).toContain('JETH498');
    }
  });

  it('LIBRARY (static class L): a marked method rejects JETH498; a `get` stays the pre-existing JETH043', () => {
    const LIB = (m: string) => `static class L { ${m} }\nclass C { s: u256 = 1n; get z(): External<u256> { return this.s; } }`;
    // the marker spellings REACHABLE in a library -> the ban (pre-ban: an accidental JETH013)
    expect(codes(LIB(`a(): View<u256> { return 1n; }`))).toContain('JETH498');
    expect(codes(LIB(`a(): Pure<u256> { return 1n; }`))).toContain('JETH498');
    expect(codes(LIB(`static a(): View<u256> { return 1n; }`))).toContain('JETH498');
    expect(codes(LIB(`static a(): Pure<u256> { return 1n; }`))).toContain('JETH498');
    // a `get` is not a library concept AT ALL (marker-independent): JETH043 fires first and is the
    // RIGHT pointer here - JETH498's "use `get a(): T`" advice would be wrong inside a library.
    expect(codes(LIB(`get a(): View<u256> { return 1n; }`))).toContain('JETH043');
    expect(codes(LIB(`get a(): u256 { return 1n; }`))).toContain('JETH043');
  });

  it('the pointer names the native forms (JETH481-style) and the interface-only rule', () => {
    const m = msgs(`class C { s: u256 = 7n; get a(): View<u256> { return this.s; } }`);
    expect(m).toContain('View<T> is an interface-only marker');
    expect(m).toContain('mutability is inferred from the body');
    expect(m).toContain('get a(...): T');
    expect(m).toContain('static a(...): T');
    expect(m).toContain('static get a(...): T');
    // the pointer names the OFFENDING marker, not a fixed one
    expect(msgs(`class C { get a(): Pure<u256> { return 1n; } }`)).toContain('Pure<T> is an interface-only marker');
  });
});

describe('INTERFACES are the only home of the markers', () => {
  it('an interface still accepts View<T> / Pure<T> and the full marker surface', () => {
    expect(codes(`interface I { m(): View<u256>; }\nclass C { s: u256 = 1n; get z(): External<u256> { return this.s; } }`)).toEqual([]);
    expect(codes(`interface I { m(): Pure<u256>; }\nclass C { s: u256 = 1n; get z(): External<u256> { return this.s; } }`)).toEqual([]);
    expect(codes(`interface I { a(): View<u256>; b(): Pure<u256>; c(): Payable<u256>; d(x: u256): u256; }
      class C { s: u256 = 1n; get z(): External<u256> { return this.s; } }`)).toEqual([]);
  });

  it('an interface CALL through View/Pure methods runs byte-equal to solc (non-vacuous: decodes a seeded value)', async () => {
    await runBoth(
      `interface I { peek(): View<u256>; calc(x: u256): Pure<u256>; }
       class C {
         s: u256 = 0n;
         poke(a: address): External<u256> { this.s = I(a).peek(); return this.s; }
         get thru(a: address, x: u256): External<u256> { return I(a).calc(x); }
       }`,
      `interface I { function peek() external view returns (uint256); function calc(uint256 x) external pure returns (uint256); }
       contract C {
         uint256 s = 0;
         function poke(address a) external returns (uint256) { s = I(a).peek(); return s; }
         function thru(address a, uint256 x) external view returns (uint256) { return I(a).calc(x); }
       }`,
      // calling into a non-contract address reverts identically in both - the point is the ENCODING
      [['poke(address)', W(0)], ['thru(address,uint256)', W(0) + W(9)]],
    );
  });

  it('an interface implemented by a class: the obligation ladder is unchanged (JETH387 preserved)', () => {
    // a state-reading impl cannot satisfy a PURE obligation (solc: pure -> view TypeError)
    expect(codes(`interface I { f(): Pure<u256>; }
      class C extends I { x: u256 = 7n; get f(): External<u256> { return this.x; } }`)).toContain('JETH387');
    // a pure impl of a View obligation TIGHTENS - accepted
    expect(codes(`interface I { f(): View<u256>; }
      class C extends I { get f(): External<u256> { return 5n; } }`)).toEqual([]);
    // a view impl of a View obligation - accepted
    expect(codes(`interface I { f(): View<u256>; }
      class C extends I { x: u256 = 1n; get f(): External<u256> { return this.x; } }`)).toEqual([]);
  });
});

describe('the three legal class forms still work (mutability INFERRED / forced pure)', () => {
  // NON-VACUITY: a body that reads NOTHING infers pure EITHER WAY, so every probe below uses a
  // DISCRIMINATING body - one that reads STORAGE, one that reads the ENVIRONMENT, one genuinely pure.
  it('`get` INFERS view from a STORAGE read, view from an ENV read, and pure from a pure body', () => {
    expect(mut(`class C { s: u256 = 7n; get f(): External<u256> { return this.s; } }`)).toEqual({ f: 'view' });
    expect(mut(`class C { get f(): External<u256> { return u256(block.timestamp); } }`)).toEqual({ f: 'view' });
    expect(mut(`class C { get f(): External<address> { return msg.sender; } }`)).toEqual({ f: 'view' });
    expect(mut(`class C { get f(): External<u256> { return 41n + 1n; } }`)).toEqual({ f: 'pure' });
  });

  it('`static` DECLARES pure: a pure body is pure, an ENV-reading body is REJECTED (JETH164)', () => {
    expect(mut(`class C { static get f(): External<u256> { return 41n + 1n; } }`)).toEqual({ f: 'pure' });
    // an internal `static f(): T` has no ABI row of its own; witness its purity through a caller
    expect(mut(`class C { static f(): u256 { return 41n + 1n; } get g(): External<u256> { return C.f(); } }`)).toEqual({ g: 'pure' });

    // THE DISCRIMINATING CASE, REWRITTEN BY AUTHOR RULING (`static` DECLARES the member pure - the ONLY
    // declared-mutability anchor left in the language). This block previously asserted the OPPOSITE: that
    // an ENV-reading static INFERS view, on the reasoning that forcing pure would be an over-acceptance.
    // That reasoning was wrong in one step - forcing pure does not emit a pure ABI for an env-reading body,
    // it REJECTS the program (JETH164). A reject is an OVER-REJECTION, which is always safe; it can never
    // emit an ABI solc disagrees with. The file header said "static a(): T -> PURE" from the start; the
    // header was right and this block was the inconsistency. The ruling resolves it in the header's favour.
    expect(codes(`class C { static get f(): External<u256> { return u256(block.timestamp); } }`)).toContain('JETH164');
    expect(codes(`class C { static get f(): External<address> { return msg.sender; } }`)).toContain('JETH164');
    // ...and the `static` (non-get) twin of each: the ruling covers BOTH forms. This half only works
    // because the get-accessor synthesis forwards the `static` modifier; drop that and these two accept.
    expect(codes(`class C { static f(): u256 { return u256(block.timestamp); } get g(): External<u256> { return C.f(); } }`)).toContain('JETH164');
    expect(codes(`class C { static f(): address { return msg.sender; } get g(): External<address> { return C.f(); } }`)).toContain('JETH164');

    // CONTROL (non-vacuity): the NON-static twin still INFERS view and still compiles - proving the four
    // rejects above are the `static` anchor firing, not a blanket ban on reading the environment.
    expect(mut(`class C { get f(): External<u256> { return u256(block.timestamp); } }`)).toEqual({ f: 'view' });
    expect(mut(`class C { get f(): External<address> { return msg.sender; } }`)).toEqual({ f: 'view' });

    // THE ACCEPTED COST, witnessed against solc: the shape JETH now rejects is one solc COMPILES as view.
    // That is a deliberate over-rejection, not a parity bug - so pin BOTH halves of the witness:
    //   - solc's `view` twin ACCEPTS  -> our reject is strictly stricter than solc (the cost we accept)
    //   - solc's `pure` twin REJECTS  -> the ruling's pure DECLARATION genuinely contradicts an env read,
    //                                    so JETH164 is the honest code for it
    expect(() => compileSolidity(SPDX + `contract C { function f() external view returns (uint256) { return block.timestamp; } }`, 'C')).not.toThrow();
    expect(() => compileSolidity(SPDX + `contract C { function f() external pure returns (uint256) { return block.timestamp; } }`, 'C')).toThrow();
  });

  it('`static` matches solc\'s pure-LEGAL set exactly: msg.sig/msg.data/keccak256/type().max/constant', () => {
    // The ruling forbids reading the ENVIRONMENT, and JETH's notion of that is solc's: calldata
    // (msg.sig / msg.data) and compile-time values are pure-LEGAL and must still compile. A blanket
    // "static touches nothing" rule would over-reject these; each is pinned with its solc pure witness.
    expect(codes(`class C { static get f(): External<bytes4> { return msg.sig; } }`)).toEqual([]);
    expect(codes(`class C { static get f(): External<u256> { return msg.data.length; } }`)).toEqual([]);
    expect(codes(`class C { static get f(): External<bytes32> { return keccak256(abi.encode(1n)); } }`)).toEqual([]);
    expect(codes(`class C { static get f(): External<u256> { return type(u256).max; } }`)).toEqual([]);
    expect(codes(`class C { static K: u256 = 7n; static get f(): External<u256> { return C.K; } }`)).toEqual([]);
    // each stays `pure` in the ABI (not silently downgraded to view)
    expect(mut(`class C { static get f(): External<bytes4> { return msg.sig; } }`)).toEqual({ f: 'pure' });
    // solc agrees these are pure-legal (the witness that our accept-set is not accidentally too wide)
    expect(() => compileSolidity(SPDX + `contract C { function f() external pure returns (bytes4) { return msg.sig; } }`, 'C')).not.toThrow();
    expect(() => compileSolidity(SPDX + `contract C { function f() external pure returns (uint256) { return msg.data.length; } }`, 'C')).not.toThrow();
  });

  it('`static` rejects a STATE touch: emit direct (JETH149) and emit through a callee (JETH055)', () => {
    // storage via `this` is unreachable from a static by construction (the JETH354 `this`-ban pre-pass
    // fires first), so a state touch reaches the declared-pure gates only through emit or a callee.
    expect(codes(`class C { E: event<{ v: u256 }>; static f(): u256 { emit(E(1n)); return 1n; } probe(): External<u256> { return C.f(); } }`)).toContain('JETH149');
    // TRANSITIVE: a static calling a library function that emits - caught by the post-fixpoint JETH055.
    expect(codes(`static class L { E: event<{ v: u256 }>; g(): u256 { emit(E(1n)); return 1n; } }
      class C { static f(): u256 { return L.g(); } probe(): External<u256> { return C.f(); } }`)).toContain('JETH055');
    // CONTROL (non-vacuity): the NON-static twin of each still compiles, so the rejects above are the
    // `static` anchor, not a broken emit path.
    expect(codes(`class C { E: event<{ v: u256 }>; f(): u256 { emit(E(1n)); return 1n; } probe(): External<u256> { return this.f(); } }`)).toEqual([]);
    expect(codes(`static class L { E: event<{ v: u256 }>; g(): u256 { emit(E(1n)); return 1n; } }
      class C { f(): u256 { return L.g(); } probe(): External<u256> { return this.f(); } }`)).toEqual([]);
  });

  it('a `get` is READ-ONLY: a writing body still rejects JETH043', () => {
    expect(codes(`class C { s: u256; get f(): External<u256> { this.s = 1n; return this.s; } }`)).toContain('JETH043');
  });

  it('the VISIBILITY markers are unaffected: External<T>, Payable<T>, Visible<T>', () => {
    expect(mut(`class C { s: u256 = 7n; get f(): External<u256> { return this.s; } }`)).toEqual({ f: 'view' });
    expect(mut(`class C { s: u256; f(): External<void> { this.s = 1n; } }`)).toEqual({ f: 'nonpayable' });
    expect(mut(`class C { s: u256; f(): Payable<void> { this.s = msg.value; } }`)).toEqual({ f: 'payable' });
    expect(mut(`class C { x: Visible<u256> = 3n; }`)).toEqual({ x: 'view' });
    // a FIELD keeps its own pointer (Visible<T> owns fields) - the ban must not steal it
    expect(codes(`class C { x: View<u256>; }`)).toContain('JETH482');
    expect(codes(`class C { x: Pure<u256>; }`)).toContain('JETH482');
    // a SPECIAL ENTRY keeps its own reject
    expect(codes(`class C { receive(): View<void> {} }`)).toContain('JETH384');
    // a Payable<T> get stays the read-only contradiction
    expect(codes(`class C { get f(): Payable<u256> { return 1n; } }`)).toContain('JETH352');
  });

  it('runs byte-equal to solc: an inferred-view parameterized get (mapping) + an inferred-view tuple get', async () => {
    await runBoth(
      `class C {
        m: mapping<u256, u256>;
        set(k: u256, v: u256): External<void> { this.m[k] = v; }
        get at(k: u256): External<u256> { return this.m[k]; }
      }`,
      `contract C {
        mapping(uint256 => uint256) m;
        function set(uint256 k, uint256 v) external { m[k] = v; }
        function at(uint256 k) external view returns (uint256) { return m[k]; }
      }`,
      [['set(uint256,uint256)', W(3) + W(1234)], ['at(uint256)', W(3)], ['at(uint256)', W(4)]],
    );
    await runBoth(
      `class C { x: u256 = 5n; get pair(): External<[u256, bool]> { return [this.x, true]; } }`,
      `contract C { uint256 x = 5; function pair() external view returns (uint256, bool) { return (x, true); } }`,
      [['pair()', '']],
    );
  });
});

describe('the ACCEPTED consequence + the retired GET-MUT-HEADROOM (documented over-rejection)', () => {
  it('ABI FLIP: a pure body that WAS declared view now infers pure (solc still accepts view -> over-rejection)', () => {
    // pre-ban `get f(): View<u256> { return 42n; }` emitted ABI view; the native form infers pure.
    expect(mut(`class C { get f(): External<u256> { return 42n; } }`)).toEqual({ f: 'pure' });
    // the shape that produced ABI view is now inexpressible - the deliberate over-rejection
    expect(codes(`class C { get f(): View<u256> { return 42n; } }`)).toContain('JETH498');
    // ... while solc happily compiles the view-on-a-pure-body mirror (this is what makes it an OR)
    expect(() => compileSolidity(SPDX + `contract C { function f() external view returns (uint256) { return 42; } }`, 'C')).not.toThrow();
    // NO flip when the body genuinely reads state - it still infers view (the common case, and the
    // reason the migration is byte-identical almost everywhere)
    expect(mut(`class C { s: u256 = 7n; get f(): External<u256> { return this.s; } }`)).toEqual({ f: 'view' });
  });

  it('the flipped function still RUNS byte-equal to its solc `pure` mirror (the flip is ABI-only)', async () => {
    await runBoth(
      `class C { get f(): External<u256> { return 42n; } }`,
      `contract C { function f() external pure returns (uint256) { return 42; } }`,
      [['f()', '']],
    );
  });

  it('CAPABILITY LOSS + workarounds: a pure-bodied virtual base can no longer reserve view HEADROOM', () => {
    // pre-ban: `@virtual get f(): View<u256> { return 1n; }` DECLARED view over a pure body, letting a
    // state-reading override in (solc parity). Now inexpressible: the base infers pure and the ladder
    // rejects JETH378. This is the documented consequence of the one-uniform-rule ruling.
    expect(codes(`class B { @virtual get f(): View<u256> { return 1n; } }
      class C extends B { x: u256 = 7n; @override get f(): External<u256> { return this.x; } }`)).toContain('JETH498');
    expect(codes(`class B { @virtual get f(): External<u256> { return 1n; } }
      class C extends B { x: u256 = 7n; @override get f(): External<u256> { return this.x; } }`)).toContain('JETH378');
    // WORKAROUND 1: give the BASE a body that reads state -> it infers view -> the ladder accepts.
    expect(codes(`class B { y: u256 = 1n; @virtual get f(): External<u256> { return this.y; } }
      class C extends B { x: u256 = 7n; @override get f(): External<u256> { return this.x; } }`)).toEqual([]);
    // WORKAROUND 2: a BODYLESS abstract virtual get has no body to infer from and never anchored a
    // declared mutability - it takes the override's inferred mutability (unchanged by the ban).
    expect(codes(`abstract class B { @virtual get f(): External<u256>; }
      class C extends B { x: u256 = 7n; @override get f(): External<u256> { return this.x; } }`)).toEqual([]);
  });

  it('the bodyless-abstract ladder still lands on view and runs byte-equal to solc (migration proof)', async () => {
    // the migrated form of `abstract class B { @virtual get f(): View<u256>; }`. It keeps the SAME ABI
    // (view): a bodyless declaration never carried an inference of its own, so this migration is a
    // pure rename - no ABI flip.
    expect(mut(`abstract class B { @virtual get f(): External<u256>; }
      class C extends B { x: u256 = 7n; @override get f(): External<u256> { return this.x; } }`)).toEqual({ f: 'view' });
    await runBoth(
      `abstract class B { @virtual get f(): External<u256>; }
       class C extends B { x: u256 = 7n; @override get f(): External<u256> { return this.x; } }`,
      `abstract contract B { function f() external view virtual returns (uint256); }
       contract C is B { uint256 x = 7; function f() external view override returns (uint256) { return x; } }`,
      [['f()', '']],
    );
  });

  it('a Visible<T> field can still override a bodyless virtual get (getter-var interplay preserved)', () => {
    expect(codes(`abstract class B { @virtual get f(): External<u256>; }
      class C extends B { @override f: Visible<u256> = 7n; }`)).toEqual([]);
  });
});
