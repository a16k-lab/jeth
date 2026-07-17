// STATIC-IS-PURE (author ruling): `static` on a class member DECLARES the member PURE.
//
//   static a(...): T       -> PURE (declared)
//   static get a(...): T   -> PURE (declared)
//
// A pure member may not read storage, may not write storage, may not emit, and MAY NOT READ THE EXECUTION
// ENVIRONMENT (msg.*/block.*/tx.*/address(this), or an immutable). `static` is the ONLY declared-mutability
// anchor left in the language: JETH481 banned the @view/@pure/@read decorators and JETH498 made View<T>/
// Pure<T> interface-only, which left the JETH055 ("declared pure touches state") and JETH164 ("declared
// pure reads the environment") gates as dead code. This ruling revives them.
//
// THIS DELIBERATELY ADDS OVER-REJECTIONS. `static a(): u256 { return msg.value; }` used to ACCEPT and infer
// view, and its artifact matched solc's honest `function a() internal view` twin byte for byte. It is now a
// hard reject. That is the ruling, not a parity bug: an over-rejection emits no bytes, so it can never be
// wrong, and every cell below pins the solc twin that ACCEPTS to show the cost is deliberate and known.
//
// NON-VACUITY IS THE WHOLE GAME HERE. Comparing `static a(): u256 { return 1n; }` to `a(): u256 { return
// 1n; }` proves NOTHING: a body that reads nothing infers pure EITHER WAY. Every probe below therefore uses
// a DISCRIMINATING body - one that reads the ENVIRONMENT, one that touches STATE, one genuinely pure - and
// every reject is paired with its NON-STATIC control, which must still compile and still infer view.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness, pad32 } from '../src/evm.js';
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

// The ENV-reading bodies the ruling outlaws, each with the solc twin that compiles it as `view`.
// [label, JETH return type, JETH body, solc return type, solc body]
const ENV: [string, string, string, string, string][] = [
  ['msg.value', 'u256', 'return msg.value;', 'uint256', 'return msg.value;'],
  ['msg.sender', 'address', 'return msg.sender;', 'address', 'return msg.sender;'],
  ['block.timestamp', 'u256', 'return block.timestamp;', 'uint256', 'return block.timestamp;'],
  ['tx.origin', 'address', 'return tx.origin;', 'address', 'return tx.origin;'],
  ['address(this)', 'address', 'return address(this);', 'address', 'return address(this);'],
];

describe('STATIC-IS-PURE: an env-reading static is REJECTED (JETH164), in BOTH static forms', () => {
  for (const [label, T, body, S, sBody] of ENV) {
    it(`static / static get reading ${label} -> JETH164 (solc's view twin accepts: the accepted cost)`, () => {
      // `static get a(): External<T>` - the ABI-exposed form.
      expect(codes(`class C { static get a(): External<${T}> { ${body} } }`)).toContain('JETH164');
      // `static a(): T` - internal, witnessed through a caller so it is really collected + checked.
      expect(
        codes(`class C { static a(): ${T} { ${body} } get p(): External<${T}> { return C.a(); } }`),
      ).toContain('JETH164');

      // CONTROL (non-vacuity): drop ONLY the `static` - same body, same internal-plus-caller shape as the
      // probe above - and it compiles, with the caller inferring view. This is what proves JETH164 above is
      // the `static` anchor firing and not a blanket ban on reading ${label}. (The member is kept INTERNAL
      // here because an EXTERNALLY reachable msg.value read has its own pre-existing rule, JETH162.)
      const control = `class C { a(): ${T} { ${body} } get p(): External<${T}> { return this.a(); } }`;
      expect(codes(control)).toEqual([]);
      expect(mut(control)).toEqual({ p: 'view' });

      // SOLC PARITY, both halves - this is what makes the over-rejection deliberate rather than a bug:
      //   the `view` twin ACCEPTS -> JETH is now strictly stricter than solc here (the cost we accept)
      //   the `pure` twin REJECTS -> a pure DECLARATION really does contradict this body, so JETH164 is
      //                             the honest code (we are not inventing a rule solc disagrees with)
      // The twin mirrors the probe's internal-plus-caller shape: msg.value is legal in an INTERNAL solc
      // function but not in a non-payable EXTERNAL one, so an external twin would test solc's payable
      // rule instead of its purity rule.
      const twin = (m: string) =>
        `contract C { function a() internal ${m} returns (${S}) { ${sBody} } function p() external ${m} returns (${S}) { return a(); } }`;
      expect(solcOk(twin('view'))).toBe(true);
      expect(solcOk(twin('pure'))).toBe(false);
    });
  }

  it('address(this) also trips the JETH354 `this`-ban first - it stays a reject either way', () => {
    // Pre-existing and NOT reordered: `address(this)` mentions `this`, which a static may not, so the
    // JETH354 pre-pass reports alongside JETH164. Pinned so a future gate-order change is visible.
    const c = codes(`class C { static get a(): External<address> { return address(this); } }`);
    expect(c).toContain('JETH354');
    expect(c).toContain('JETH164');
  });
});

describe('STATIC-IS-PURE: a state-touching static is REJECTED', () => {
  it('emit DIRECTLY from a static -> JETH149 (+ JETH055 from the fixpoint)', () => {
    const c = codes(
      `class C { E: event<{ v: u256 }>; static a(): u256 { emit(E(1n)); return 1n; } p(): External<u256> { return C.a(); } }`,
    );
    expect(c).toContain('JETH149');
    expect(c).toContain('JETH055');
    // CONTROL: the non-static twin emits happily.
    expect(
      codes(
        `class C { E: event<{ v: u256 }>; a(): u256 { emit(E(1n)); return 1n; } p(): External<u256> { return this.a(); } }`,
      ),
    ).toEqual([]);
  });

  it('emit through a CALLEE -> JETH055 (the transitive route into the declared-pure gate)', () => {
    const c = codes(`static class L { E: event<{ v: u256 }>; g(): u256 { emit(E(1n)); return 1n; } }
      class C { static a(): u256 { return L.g(); } p(): External<u256> { return C.a(); } }`);
    expect(c).toContain('JETH055');
    // CONTROL: same call chain without `static` compiles.
    expect(codes(`static class L { E: event<{ v: u256 }>; g(): u256 { emit(E(1n)); return 1n; } }
      class C { a(): u256 { return L.g(); } p(): External<u256> { return this.a(); } }`)).toEqual([]);
  });

  it('storage via `this` is unreachable from a static: JETH354 fires first (pre-existing, not reordered)', () => {
    // A static has no instance, so a storage read/write can only be spelled `this.n` - which the JETH354
    // pre-pass rejects before the mutability gates ever see it. JETH055 rides along from the fixpoint.
    for (const body of ['return this.n;', 'this.n = 5n; return 1n;']) {
      const c = codes(`class C { n: u256 = 0n; static a(): u256 { ${body} } p(): External<u256> { return C.a(); } }`);
      expect(c).toContain('JETH354');
    }
  });
});

describe('STATIC-IS-PURE: the pure-LEGAL set is solc\'s, exactly - these must all still compile', () => {
  // A blanket "a static touches nothing" rule would over-reject these. The ruling forbids reading the
  // ENVIRONMENT, and JETH's notion of that is solc's: calldata (msg.sig/msg.data) and compile-time values
  // are pure-legal. Each cell pins the solc `pure` witness so our accept-set cannot silently drift wider.
  const LEGAL: [string, string, string, string, string][] = [
    ['literal', 'u256', 'return 41n + 1n;', 'uint256', 'return 41 + 1;'],
    ['msg.sig', 'bytes4', 'return msg.sig;', 'bytes4', 'return msg.sig;'],
    ['msg.data', 'u256', 'return msg.data.length;', 'uint256', 'return msg.data.length;'],
    ['keccak256', 'bytes32', 'return keccak256(abi.encode(1n));', 'bytes32', 'return keccak256(abi.encode(uint256(1)));'],
    ['type(u256).max', 'u256', 'return type(u256).max;', 'uint256', 'return type(uint256).max;'],
  ];
  for (const [label, T, body, S, sBody] of LEGAL) {
    it(`${label} stays LEGAL in a static and a static get, and stays PURE in the ABI`, () => {
      expect(codes(`class C { static get a(): External<${T}> { ${body} } }`)).toEqual([]);
      expect(codes(`class C { static a(): ${T} { ${body} } get p(): External<${T}> { return C.a(); } }`)).toEqual([]);
      // not silently downgraded to view - the DECLARATION holds
      expect(mut(`class C { static get a(): External<${T}> { ${body} } }`)).toEqual({ a: 'pure' });
      // solc agrees this body is pure-legal
      expect(solcOk(`contract C { function a() external pure returns (${S}) { ${sBody} } }`)).toBe(true);
    });
  }

  it('a static may read a static CONSTANT and call another static (pure-legal by solc)', () => {
    expect(
      codes(
        `class C { static K: u256 = 10n; static f(a: u256): u256 { return C.g(a) + C.K; } static g(a: u256): u256 { return a * 2n; } get d(): External<u256> { return C.f(5n); } }`,
      ),
    ).toEqual([]);
    expect(solcOk(`contract C { uint256 constant K = 10;
      function g(uint256 a) internal pure returns (uint256) { return a * 2; }
      function f(uint256 a) internal pure returns (uint256) { return g(a) + K; }
      function d() external pure returns (uint256) { return f(5); } }`)).toBe(true);
  });

  it('an IMMUTABLE read is NOT pure-legal (solc parity: it reads the environment) -> JETH164', () => {
    // The boundary case that separates "constant" (folded, pure) from "immutable" (a code read solc still
    // calls environment). Reached via ClassName.M, so no `this` and no JETH354 in the way.
    expect(
      codes(`class C { static M: u256; constructor(){ this.M = 7n; } static get a(): External<u256> { return C.M; } }`),
    ).toContain('JETH164');
    expect(solcOk(`contract C { uint256 immutable M; constructor(){ M = 7; }
      function a() external view returns (uint256) { return M; } }`)).toBe(true);
    expect(solcOk(`contract C { uint256 immutable M; constructor(){ M = 7; }
      function a() external pure returns (uint256) { return M; } }`)).toBe(false);
  });
});

describe('STATIC-IS-PURE: a genuinely-pure static still compiles and still runs like solc', () => {
  it('a pure static RUNS identically to its declared-pure solc twin, and keeps a `pure` ABI row', async () => {
    // "Both compile" is not parity: deploy both and compare the DECODED return, so a codegen drift in the
    // static path cannot hide behind a green accept-check. (Creation-image identity to solc is not the
    // claim for this shape - see the sibling pin in native-static-const-immutable.test.ts, which likewise
    // compares behaviour. The bytes-unchanged claim for this ruling is a BASE-vs-worktree comparison of
    // JETH's own artifact, which no in-suite test can express.)
    const J = `class C { static FEE: u256 = 100n; static feeOn(amt: u256): u256 { return amt * C.FEE / 10000n; } get quote(a: u256): External<u256> { return C.feeOn(a); } }`;
    const S = `contract C { uint256 constant FEE = 100; function feeOn(uint256 amt) internal pure returns(uint256){ return amt * FEE / 10000; } function quote(uint256 a) external pure returns(uint256){ return feeOn(a); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const rj = await h.call(aj, sel('quote(uint256)') + pad32(50000n));
    const rs = await h.call(as, sel('quote(uint256)') + pad32(50000n));
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    // NON-VACUITY: the call really returned 50000*100/10000 = 500, not a zero image.
    expect(BigInt(rj.returnHex)).toBe(500n);
    // the DECLARATION reaches the ABI: `pure`, not a downgraded `view`.
    expect(mut(J)).toEqual({ quote: 'pure' });
  });
});

// A declared-pure static SKIPS the post-fixpoint inference branch - and that branch is where JETH043 /
// JETH473 / JETH352 live. A first cut of this ruling set the mutability slot and stopped there, which
// silently dropped all three for statics. Two of the resulting holes were mere lost diagnostics, but the
// third shipped a WRONG ABI: `@nonReentrant static a(): External<void>` compiled to a row claiming `pure`
// while the body TSTOREs the reentrancy mutex, so every staticcall/eth_call of it reverts against a pure
// promise. These pin all three, since none of them is covered by the ruling's own reject set.
describe('STATIC-IS-PURE: the declared-pure path keeps the post-inference validation', () => {
  it('JETH352: External<T> is still the WRITER form for a static (a read-only external is a `get`)', () => {
    expect(codes(`class C { static a(): External<u256> { return 1n; } }`)).toContain('JETH352');
    // the same rule on the non-static twin, unchanged
    expect(codes(`class C { a(): External<u256> { return 1n; } }`)).toContain('JETH352');
    // EXEMPT (unchanged): a value-less External<void> assert-style static is not a getter
    expect(codes(`class C { static a(x: u256): External<void> { require(x > 0n, "x"); } }`)).toEqual([]);
  });

  it('JETH260: @nonReentrant + `static` is a contradiction (the guard TSTOREs; `static` declares pure)', () => {
    // BOTH forms, and note the method form ACCEPTED before the ruling (as nonpayable) - it is the ruling
    // that makes it a contradiction, and it must reject rather than ship a `pure` ABI over a TSTORE.
    expect(codes(`class C { @nonReentrant static a(x: u256): External<void> { require(x > 0n, "x"); } }`)).toContain('JETH260');
    expect(codes(`class C { @nonReentrant static get a(): External<u256> { return 1n; } }`)).toContain('JETH260');
    // CONTROL: @nonReentrant on a non-static WRITER is still perfectly legal and still nonpayable.
    expect(mut(`class C { s: u256 = 0n; @nonReentrant a(): External<void> { this.s = 1n; } }`)).toEqual({ a: 'nonpayable' });
  });

  it('JETH043: a writing `static get` still trips the getter-is-read-only gate', () => {
    expect(codes(`static class L { E: event<{ v: u256 }>; g(): u256 { emit(E(1n)); return 1n; } }
      class C { static get a(): External<u256> { return L.g(); } }`)).toContain('JETH043');
  });
});

describe('STATIC-IS-PURE: the ruling does not leak into non-static inference', () => {
  it('a non-static `get` still infers view from storage, view from env, pure from a pure body', () => {
    expect(mut(`class C { s: u256 = 7n; get f(): External<u256> { return this.s; } }`)).toEqual({ f: 'view' });
    expect(mut(`class C { get f(): External<u256> { return block.timestamp; } }`)).toEqual({ f: 'view' });
    expect(mut(`class C { get f(): External<address> { return msg.sender; } }`)).toEqual({ f: 'view' });
    expect(mut(`class C { get f(): External<u256> { return 41n + 1n; } }`)).toEqual({ f: 'pure' });
  });

  it('a non-static method still infers nonpayable from a write and view from an env read', () => {
    expect(mut(`class C { s: u256 = 0n; f(): External<void> { this.s = 1n; } }`)).toEqual({ f: 'nonpayable' });
    expect(mut(`class C { get f(): External<u256> { return block.timestamp + 1n; } }`)).toEqual({ f: 'view' });
    // an INTERNAL non-static reader of msg.value still infers view through its caller. (An EXTERNALLY
    // reachable msg.value read needs Payable<T> - JETH162 - which is a separate, pre-existing rule.)
    expect(mut(`class C { v(): u256 { return msg.value; } f(): Payable<u256> { return this.v(); } }`)).toEqual({
      f: 'payable',
    });
  });

  it('an INTERFACE keeps View<T>/Pure<T>, and a Pure<T> interface method may still be env-free', () => {
    // Interfaces are collected elsewhere (collectNativeInterfaces) and are untouched by the ruling.
    expect(codes(`interface I { f(): View<u256>; g(): Pure<u256>; }
      class C extends I { x: u256 = 1n; get f(): External<u256> { return this.x; } get g(): External<u256> { return 1n; } }`)).toEqual([]);
  });
});
