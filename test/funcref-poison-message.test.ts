// FUNCREF-PROVENANCE (diagnostic accuracy). A JETH funcref type - `(x: u256) => u256` - carries NO
// mutability. Solidity's does: `function(uint256) internal returns (uint256)` and
// `function(uint256) internal pure returns (uint256)` are DIFFERENT types, so solc can keep a writer and
// a pure function in two distinct pointer types where JETH has one. When a pointer call cannot be
// resolved to a single target, the purity fixpoint must assume EVERY same-signature address-taken
// function is a possible callee (the signature-union fallback). That is a SOUND approximation and the
// reject stays - but the message was FALSE: it told the author their function "may not modify state
// (write to storage or emit an event)" when the function writes nothing at all and merely calls through
// a pointer that some unrelated writer shares a signature with.
//
// This file pins the message CONTENT, not the accept/reject sets: the reject, the diagnostic CODE and the
// emitted bytecode are all unchanged by this work (the fixpoint now keeps provenance it used to discard).
//
// Of the gates that validate a DECLARED mutability (JETH054/055/056/164), JETH054 and JETH056 are
// unreachable in native mode - nothing declares `view` (the decorators are JETH481, View<T>/Pure<T> in a
// class are JETH498, and an interface method is bodyless). JETH055/JETH164 ARE reachable: the
// STATIC-IS-PURE ruling made `static` a DECLARED-pure anchor (see class-mutability-marker-ban.test.ts).
// Neither is what this file exercises - it pins the message of the INFERRED read-only gate, JETH043.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const msg = (src: string, code = 'JETH043'): string => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return '<ACCEPTED>';
  } catch (e) {
    const ds = (e as { diagnostics?: { code: string; message: string }[] }).diagnostics ?? [];
    return ds.find((d) => d.code === code)?.message ?? `<no ${code}: ${ds.map((d) => d.code).join(',')}>`;
  }
};
const mut = (src: string): Record<string, string> => {
  const abi = compile(src, { fileName: 'C.jeth' }).abi as { type: string; name?: string; stateMutability?: string }[];
  return Object.fromEntries(abi.filter((e) => e.type === 'function').map((f) => [f.name!, f.stateMutability!]));
};

// `linc` WRITES and `dbl` is PURE, and they share the signature (x: u256) => u256. `ord` address-takes
// the WRITER, which is what poisons the whole (u256)->u256 pointer group.
const WRITER_AND_PURE = `linc(x: u256): u256 { this.n = x; return x; }
  dbl(x: u256): u256 { return x*2n; }`;
const POISONED = `type Fd = { f: (x: u256) => u256 };
class C { n: u256;
  ${WRITER_AND_PURE}
  ord(): External<void> { let d: Fd = { f: this.linc }; d.f(1n); }
  get b(): External<u256> { let d: Fd = { f: this.dbl }; return d.f(2n); } }`;

describe('the funcref signature-union reject explains itself truthfully', () => {
  it('a POISONED accessor is not told it modifies state - it is told WHY, and by whom', () => {
    const m = msg(POISONED);
    // the FALSE claim is gone: `b` writes no storage and emits no event.
    expect(m).not.toContain('may not modify state');
    // (1) it cannot be PROVEN read-only - not that it is not read-only
    expect(m).toContain('cannot be PROVEN read-only');
    // (2) WHY: a pointer call, the signature, the named culprit, and the missing-mutability reason
    expect(m).toContain('function pointer of type `(p1: u256) => u256`');
    expect(m).toContain("state-modifying function 'linc'");
    expect(m).toContain('funcref type carries no mutability');
    // (3) the workaround, and the untrackable sources to avoid
    expect(m).toContain('let g: (p1: u256) => u256 = this.<fn>');
    expect(m).toContain('a struct field, a parameter, a storage round-trip or a call result');
    // the signature is quoted in JETH type names - `uint256` is the ABI canonical name, NOT a JETH type,
    // so a workaround quoting it would not compile (see the paste test below).
    expect(m).not.toContain('uint256');
  });

  it('THE WORKAROUND THE MESSAGE PROMISES ACTUALLY COMPILES (pasted verbatim)', () => {
    // the exact annotation the message prints, `(p1: u256) => u256`, used as the tracked-let type.
    const fixed = `class C { n: u256;
      ${WRITER_AND_PURE}
      ord(): External<void> { let g: (p1: u256) => u256 = this.linc; g(1n); }
      get b(): External<u256> { let g: (p1: u256) => u256 = this.dbl; return g(2n); } }`;
    expect(mut(fixed).b).toBe('pure'); // compiles AND is proven pure - the promise is kept
  });

  it('every source the message calls UNTRACKABLE really is (the claim is not invented)', () => {
    const pre = `type Fd = { f: (x: u256) => u256 };
      class C { n: u256;
      ${WRITER_AND_PURE}
      ord(): External<void> { let d: Fd = { f: this.linc }; d.f(1n); }`;
    // a struct field
    expect(msg(POISONED)).toContain('cannot be PROVEN read-only');
    // a storage round-trip
    expect(
      msg(`class C { n: u256; s: (x: u256) => u256;
        ${WRITER_AND_PURE}
        ord(): External<void> { let d: (p1: u256) => u256 = this.linc; d(1n); }
        get b(): External<u256> { return this.s(2n); } }`),
    ).toContain('cannot be PROVEN read-only');
    // a call result
    expect(msg(`${pre}
      mk(): (x: u256) => u256 { return this.dbl; }
      get b(): External<u256> { return this.mk()(2n); } }`)).toContain('cannot be PROVEN read-only');
  });

  it('the poisoning is followed through ORDINARY calls, naming the body that holds the pointer call', () => {
    const m = msg(`class C { n: u256;
      ${WRITER_AND_PURE}
      ord(): External<void> { let g: (p1: u256) => u256 = this.linc; g(1n); }
      via(f: (x: u256) => u256, v: u256): u256 { return f(v); }
      get b(): External<u256> { return this.via(this.dbl, 2n); } }`);
    expect(m).toContain('cannot be PROVEN read-only');
    expect(m).toContain("it calls 'via', which calls through a function pointer"); // the real site
  });

  // ---- THE GENUINE CASES MUST STAY BLUNT (the other half of accuracy) ---------------------------
  it('a getter that REALLY modifies state is still told exactly that', () => {
    const plain = 'may not modify state (write to storage or emit an event)';
    // its own body writes
    expect(msg(`class C { n: u256; get b(): External<u256> { this.n = 1n; return this.n; } }`)).toContain(plain);
    // a direct callee writes
    expect(msg(`class C { n: u256; w(): void { this.n = 1n; } get b(): External<u256> { this.w(); return 1n; } }`)).toContain(plain);
    // two hops
    expect(msg(`class C { n: u256; w(): void { this.n = 1n; } mid(): void { this.w(); } get b(): External<u256> { this.mid(); return 1n; } }`)).toContain(plain);
    // it emits
    expect(msg(`class C { Ev: event<{ a: u256 }>; get b(): External<u256> { emit(this.Ev(1n)); return 1n; } }`)).toContain(plain);
    // A RESOLVED pointer target is EXACT, not an approximation: calling a writer through a tracked local
    // really does write, so it must be reported plainly too (this is the case a naive provenance gets
    // wrong by lumping resolved pointer targets in with the signature-union fallback).
    expect(
      msg(`class C { n: u256; w(x: u256): u256 { this.n = x; return x; }
        get b(): External<u256> { let g: (p1: u256) => u256 = this.w; return g(1n); } }`),
    ).toContain(plain);
  });

  it('NON-VACUITY: the poisoned and genuine shapes really do take different branches', () => {
    // same reject code, different explanation - so the assertions above cannot both pass by accident
    expect(msg(POISONED)).not.toContain('may not modify state');
    expect(msg(`class C { n: u256; get b(): External<u256> { this.n = 1n; return this.n; } }`)).not.toContain(
      'cannot be PROVEN read-only',
    );
    // and with NO writer address-taken the same pointer-through-a-struct-field shape COMPILES, proving
    // the reject is driven by the address-taken writer and not by the struct-field pointer itself.
    expect(
      mut(`type Fd = { f: (x: u256) => u256 };
        class C { dbl(x: u256): u256 { return x*2n; }
        get b(): External<u256> { let d: Fd = { f: this.dbl }; return d.f(2n); } }`).b,
    ).toBe('pure');
  });
});
