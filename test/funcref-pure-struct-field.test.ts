// FUNCREF-PURE (compiler-only subset lift). A JETH funcref type - `(x: u256) => u256` - carries NO
// mutability, so a call through a funcref whose exact target is unknown must assume EVERY same-signature
// address-taken function is a possible callee (the signature-union fallback). solc's pointer TYPES carry
// mutability (`function(uint256) internal pure` is a DISTINCT type from `function(uint256) internal`), so
// solc keeps a pure pointer and a writer pointer apart where JETH's single spelling cannot. JETH already
// discriminates a TRACKED funcref `let` per-variable (W5D-2); this lift extends that to a funcref FIELD of
// a NON-ESCAPING local STRUCT LITERAL, so a declared-pure (`static`) function calling `z.f(v)` is ACCEPTED
// iff `z.f`'s PROVABLE target set is entirely pure - the exact set solc accepts.
//
// THE OVER-ACCEPTANCE GUARD IS THE WHOLE GAME. The tracked target set must be COMPLETE: the struct is
// POISONED (dropping back to the signature union) on ANY escape that could re-point a funcref field to a
// state-writer - the struct reassigned, its field reassigned, or the struct read as a whole value
// (aliased / passed / returned / stored). A struct built from a param / storage / call result / another
// struct is never a candidate at all. Accepting any of those would publish `pure` for a function that can
// write - a bar violation. EVERY probe carries the poisoning writer (`o` address-takes the state-writing
// `w` with the same signature); without it, a body that reaches only pure targets infers pure EITHER WAY
// and proves nothing.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
const mut = (src: string): Record<string, string> =>
  Object.fromEntries(
    (compile(src, { fileName: 'C.jeth' }).abi as { type: string; name: string; stateMutability: string }[])
      .filter((f) => f.type === 'function')
      .map((f) => [f.name, f.stateMutability]),
  );
const solcOk = (body: string): boolean => {
  try {
    compileSolidity(SPDX + body, 'C');
    return true;
  } catch {
    return false;
  }
};

// The shared preamble: `w` WRITES and `d` is PURE, same signature (u256)=>u256; `o` address-takes the
// WRITER into a struct field, poisoning the whole (u256)->u256 pointer group.
const PRE = `type Fd = { f: (x: u256) => u256 };
class C { n: u256;
  static d(x: u256): u256 { return x * 2n; }
  w(x: u256): u256 { this.n = x; return x; }
  o(): External<void> { let z: Fd = { f: this.w }; z.f(1n); }`;

describe('FUNCREF-PURE: a NON-escaping local struct-literal funcref field is TRACKED (accepted pure)', () => {
  it('the OR: `static get p` calling z.f through a non-escaping struct literal is PURE, WITH the writer live', () => {
    const J = `${PRE}
      static get p(): External<u256> { let z: Fd = { f: C.d }; return z.f(5n); } }`;
    // ACCEPTED and the DECLARATION reaches the ABI as pure - not a downgraded view/nonpayable.
    expect(codes(J)).toEqual([]);
    expect(mut(J).p).toBe('pure');
  });

  it('the funcref at a NON-first field offset resolves to the right source', () => {
    const J = `type Fd2 = { a: u256, f: (x: u256) => u256 };
      class C { n: u256;
        static d(x: u256): u256 { return x * 2n; }
        w(x: u256): u256 { this.n = x; return x; }
        o(): External<void> { let z: Fd2 = { a: 0n, f: this.w }; z.f(1n); }
        static get p(): External<u256> { let z: Fd2 = { a: 7n, f: C.d }; return z.f(5n); } }`;
    expect(mut(J).p).toBe('pure');
  });

  it('the field source composes through a tracked funcref `let` and a ternary', () => {
    expect(
      mut(`${PRE}
        static get p(): External<u256> { let g: (x: u256) => u256 = C.d; let z: Fd = { f: g }; return z.f(5n); } }`).p,
    ).toBe('pure');
    expect(
      mut(`type Fd = { f: (x: u256) => u256 };
        class C { n: u256;
          static d(x: u256): u256 { return x * 2n; }
          static e(x: u256): u256 { return x + 1n; }
          w(x: u256): u256 { this.n = x; return x; }
          o(): External<void> { let z: Fd = { f: this.w }; z.f(1n); }
          static get p(c: bool): External<u256> {
            let z: Fd = { f: C.d }; let y: Fd = { f: C.e };
            let g: (x: u256) => u256 = c ? z.f : y.f; return g(5n); } }`).p,
    ).toBe('pure');
  });

  it('runs identically to its two-struct solc twin, and the `pure` ABI is CORRECT (deploy + decode)', async () => {
    const J = `${PRE}
      static get p(): External<u256> { let z: Fd = { f: C.d }; return z.f(5n); }
      get getN(): External<u256> { return this.n; } }`;
    // solc needs TWO struct types (its funcref field carries mutability); this is the exact program the
    // JETH single-spelling models. `p` is genuinely pure; `o` writes n through the writer pointer.
    const S = `contract C { uint256 n;
      function d(uint256 x) internal pure returns(uint256) { return x * 2; }
      function w(uint256 x) internal returns(uint256) { n = x; return x; }
      struct FdMut { function(uint256) internal returns(uint256) f; }
      struct FdPure { function(uint256) internal pure returns(uint256) f; }
      function o() external { FdMut memory z; z.f = w; z.f(1); }
      function p() external pure returns(uint256) { FdPure memory z; z.f = d; return z.f(5); }
      function getN() external view returns(uint256){ return n; } }`;
    const jb = compile(J, { fileName: 'C.jeth' });
    expect((jb.abi as { name: string; stateMutability: string }[]).find((f) => f.name === 'p')?.stateMutability).toBe(
      'pure',
    );
    const h = await Harness.create();
    const aj = await h.deploy(jb.creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    // p() is pure: identical decoded return, and NON-VACUOUS (d(5) = 10, not a zero image).
    const pj = await h.call(aj, sel('p()'));
    const ps = await h.call(as, sel('p()'));
    expect(pj.success).toBe(true);
    expect(pj.returnHex).toBe(ps.returnHex);
    expect(BigInt(pj.returnHex)).toBe(10n);
    // o() writes n=1 through the writer pointer in BOTH; read it back to prove the write landed identically.
    await h.call(aj, sel('o()'));
    await h.call(as, sel('o()'));
    const nj = await h.call(aj, sel('getN()'));
    const ns = await h.call(as, sel('getN()'));
    expect(nj.returnHex).toBe(ns.returnHex);
    expect(BigInt(nj.returnHex)).toBe(1n);
  });
});

describe('FUNCREF-PURE: the OVER-ACCEPTANCE guard - every escape / untrackable source STILL rejects', () => {
  // Each keeps the poisoning writer live, declares `static get p` PURE, and reaches its pointer through a
  // source that is NOT a provable single target - so JETH055 must fire (accepting would publish a wrong
  // `pure` ABI). `wd` is a pure static of the same signature, used where a static needs a same-sig target.
  const REJECTS: [string, string][] = [
    ['z reassigned wholesale', `static get p(): External<u256> { let z: Fd = { f: C.d }; z = { f: C.wd }; return z.f(5n); }`],
    ['z.f field reassigned', `static get p(): External<u256> { let z: Fd = { f: C.d }; z.f = C.wd; return z.f(5n); }`],
    ['struct ALIASED', `static get p(): External<u256> { let z: Fd = { f: C.d }; let y: Fd = z; return y.f(5n); }`],
    ['struct PASSED to a helper', `static h(q: Fd): u256 { return q.f(1n); }
      static get p(): External<u256> { let z: Fd = { f: C.d }; return C.h(z); }`],
    ['struct built from a PARAM', `static viaParam(z: Fd): u256 { return z.f(5n); }
      static get p(): External<u256> { return C.viaParam({ f: C.d }); }`],
    ['struct field from a CALL RESULT', `static mk(): (x: u256) => u256 { return C.d; }
      static get p(): External<u256> { let z: Fd = { f: C.mk() }; return z.f(5n); }`],
    ['pointer from a direct CALL RESULT', `static mk(): (x: u256) => u256 { return C.d; }
      static get p(): External<u256> { return C.mk()(5n); }`],
  ];
  for (const [label, member] of REJECTS) {
    it(`REJECTS (JETH055): ${label}`, () => {
      const c = codes(`${PRE}
        static wd(x: u256): u256 { return x + 3n; }
        ${member} }`);
      expect(c).toContain('JETH055');
    });
  }

  // The STORAGE-sourced field and the STORED struct are unreachable from a `static` (a static has no
  // `this`), so they are exercised on the INFERENCE path: a `get` accessor whose funcref-field pointer
  // reaches the signature union (holding the writer `w`) writes, and a getter that writes is JETH043.
  const GETTER_REJECTS: [string, string][] = [
    ['struct field from STORAGE', `sf: (x: u256) => u256;
      get p(): External<u256> { let z: Fd = { f: this.sf }; return z.f(5n); }`],
    ['struct STORED to storage', `st: Fd;
      get p(): External<u256> { let z: Fd = { f: this.d2() }; this.st = z; return z.f(5n); } d2(): (x: u256) => u256 { return this.dd; } dd(x: u256): u256 { return x; }`],
  ];
  for (const [label, member] of GETTER_REJECTS) {
    it(`REJECTS (JETH043, inference path): ${label}`, () => {
      const c = codes(`type Fd = { f: (x: u256) => u256 };
        class C { n: u256;
          d(x: u256): u256 { return x * 2n; }
          w(x: u256): u256 { this.n = x; return x; }
          o(): External<void> { let z: Fd = { f: this.w }; z.f(1n); }
          ${member} }`);
      expect(c).toContain('JETH043');
    });
  }

  it('NON-VACUITY: the SAME body without the escape ACCEPTS, so the reject is driven by the escape', () => {
    // z reassigned -> reject; z NOT reassigned -> accept. Only difference is the escape.
    expect(codes(`${PRE} static wd(x: u256): u256 { return x + 3n; }
      static get p(): External<u256> { let z: Fd = { f: C.d }; z = { f: C.wd }; return z.f(5n); } }`)).toContain('JETH055');
    expect(mut(`${PRE} static wd(x: u256): u256 { return x + 3n; }
      static get p(): External<u256> { let z: Fd = { f: C.d }; return z.f(5n); } }`).p).toBe('pure');
  });

  it('the guard is SOUND vs solc: an escape that reaches the writer is rejected by BOTH (decoded)', () => {
    // A NON-static getter (view) builds {f: this.d}, ALIASES it, then reassigns the alias field to the
    // WRITER `this.w`. At runtime z.f == w, so the getter WRITES: solc rejects a view function that writes,
    // and JETH must reject too (accepting would publish `view` for a writing function - an over-acceptance).
    const J = `type Fd = { f: (x: u256) => u256 };
      class C { n: u256;
        w(x: u256): u256 { this.n = x; return x; }
        d(x: u256): u256 { return x * 2n; }
        o(): External<void> { let z: Fd = { f: this.w }; z.f(1n); }
        get p(): External<u256> { let z: Fd = { f: this.d }; let y: Fd = z; y.f = this.w; return z.f(5n); } }`;
    expect(codes(J)).toContain('JETH043'); // a getter that (through the alias) writes
    // solc's mirror: a VIEW getter whose pointer is reassigned to the writer -> rejected.
    expect(
      solcOk(`contract C { uint256 n;
        function w(uint256 x) internal returns(uint256) { n = x; return x; }
        function d(uint256 x) internal pure returns(uint256) { return x * 2; }
        struct Fd { function(uint256) internal returns(uint256) f; }
        function o() external { Fd memory z; z.f = w; z.f(1); }
        function p() external view returns(uint256) { Fd memory z; z.f = d; Fd memory y = z; y.f = w; return z.f(5); } }`),
    ).toBe(false);
  });
});
