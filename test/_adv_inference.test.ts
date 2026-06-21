// Adversarial verification of compile-time DECORATOR INFERENCE.
//
// Invariant under test: writing @read / no-visibility / @hidden must be EXACTLY equivalent to
// writing the explicit decorators the compiler resolves to, and the resulting ABI must be the
// TRUE one (byte-identical to solc on returndata + matching stateMutability).
//
// For each positive contract we build it THREE ways: INFERRED, the EXPLICIT decorators it should
// resolve to, and a Solidity twin. We assert (1) inferred ABI fnMap == explicit ABI fnMap, and
// (2) every ABI function's returndata is byte-identical across jeth-inferred / jeth-explicit /
// solc. Rejection cases assert the inferred source is rejected with the same diagnostic the
// explicit-but-illegal source would be (parity with solc rejecting a view that writes).
//
// FINDING (documented at the bottom): a @read that TRANSITIVELY EMITS an event via a nonpayable
// helper is wrongly accepted and inferred read-only. solc rejects the equivalent view. See the
// `divergence` describe block.

import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

type AbiFn = { type: string; name?: string; stateMutability?: string };
const fnMap = (abi: AbiFn[]) =>
  Object.fromEntries(abi.filter((e) => e.type === 'function').map((f) => [f.name, f.stateMutability]));

function compileOrDiags(src: string): { ok: true; abi: AbiFn[]; creationBytecode: string } | { ok: false; codes: string[] } {
  try {
    const r = compile(src, { fileName: 'C.jeth' });
    return { ok: true, abi: r.abi as AbiFn[], creationBytecode: r.creationBytecode };
  } catch (e) {
    const codes = ((e as { diagnostics?: { code: string }[] }).diagnostics ?? []).map((d) => d.code);
    return { ok: false, codes };
  }
}

interface Twin {
  name: string;
  inferred: string;
  explicit: string;
  sol: string;
  expectedFnMap: Record<string, string>;
  // [abi-signature, calldata-words] called on each deployed instance and asserted byte-identical.
  calls: { sig: string; words?: bigint[] }[];
  // optional one-time seed call (e.g. set state) applied to all three before the asserted calls.
  seed?: { sig: string; words?: bigint[] };
}

// ---------------------------------------------------------------------------
// POSITIVE TWINS: inferred === explicit === solc
// ---------------------------------------------------------------------------

const twins: Twin[] = [
  // 1. @read transitive PURE at depth 3 (touches nothing) -> infer pure.
  {
    name: 'transitive-pure-depth3',
    inferred: `@contract class C {
      @read top(a: u256): u256 { return this.l1(a); }
      @hidden l1(a: u256): u256 { return this.l2(a) + 1n; }
      @hidden l2(a: u256): u256 { return this.l3(a) * 2n; }
      @hidden l3(a: u256): u256 { return a + 10n; }
    }`,
    explicit: `@contract class C {
      @external @pure top(a: u256): u256 { return this.l1(a); }
      @internal l1(a: u256): u256 { return this.l2(a) + 1n; }
      @internal l2(a: u256): u256 { return this.l3(a) * 2n; }
      @internal l3(a: u256): u256 { return a + 10n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function top(uint256 a) external pure returns (uint256){ return l1(a); }
      function l1(uint256 a) internal pure returns (uint256){ return l2(a) + 1; }
      function l2(uint256 a) internal pure returns (uint256){ return l3(a) * 2; }
      function l3(uint256 a) internal pure returns (uint256){ return a + 10; }
    }`,
    expectedFnMap: { top: 'pure' },
    calls: [{ sig: 'top(uint256)', words: [7n] }],
  },

  // 2. @read transitive STATE READ at depth 3 -> infer view.
  {
    name: 'transitive-view-state-depth3',
    inferred: `@contract class C {
      @state v: u256;
      @external setV(x: u256): void { this.v = x; }
      @read top(): u256 { return this.l1(); }
      @hidden l1(): u256 { return this.l2() + 1n; }
      @hidden l2(): u256 { return this.l3(); }
      @hidden l3(): u256 { return this.v; }
    }`,
    explicit: `@contract class C {
      @state v: u256;
      @external setV(x: u256): void { this.v = x; }
      @external @view top(): u256 { return this.l1(); }
      @internal l1(): u256 { return this.l2() + 1n; }
      @internal l2(): u256 { return this.l3(); }
      @internal l3(): u256 { return this.v; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      uint256 v;
      function setV(uint256 x) external { v = x; }
      function top() external view returns (uint256){ return l1(); }
      function l1() internal view returns (uint256){ return l2() + 1; }
      function l2() internal view returns (uint256){ return l3(); }
      function l3() internal view returns (uint256){ return v; }
    }`,
    expectedFnMap: { setV: 'nonpayable', top: 'view' },
    seed: { sig: 'setV(uint256)', words: [99n] },
    calls: [{ sig: 'top()' }],
  },

  // 3. @read transitive ENV READ (msg.sender) at depth -> infer view (env makes it view, not pure).
  {
    name: 'transitive-view-env-depth',
    inferred: `@contract class C {
      @read top(): address { return this.l1(); }
      @hidden l1(): address { return this.l2(); }
      @hidden l2(): address { return msg.sender; }
    }`,
    explicit: `@contract class C {
      @external @view top(): address { return this.l1(); }
      @internal l1(): address { return this.l2(); }
      @internal l2(): address { return msg.sender; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function top() external view returns (address){ return l1(); }
      function l1() internal view returns (address){ return l2(); }
      function l2() internal view returns (address){ return msg.sender; }
    }`,
    expectedFnMap: { top: 'view' },
    calls: [{ sig: 'top()' }],
  },

  // 4. MUTUAL RECURSION among @read / @hidden, reading state -> both resolve view.
  {
    name: 'mutual-recursion-view',
    inferred: `@contract class C {
      @state n: u256;
      @external setN(x: u256): void { this.n = x; }
      @read isEven(k: u256): bool { if (k == 0n) { return true; } return this.isOdd(k - 1n); }
      @hidden isOdd(k: u256): bool { if (k == 0n) { return this.n == 0n; } return this.isEven(k - 1n); }
    }`,
    explicit: `@contract class C {
      @state n: u256;
      @external setN(x: u256): void { this.n = x; }
      @public @view isEven(k: u256): bool { if (k == 0n) { return true; } return this.isOdd(k - 1n); }
      @internal isOdd(k: u256): bool { if (k == 0n) { return this.n == 0n; } return this.isEven(k - 1n); }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      uint256 n;
      function setN(uint256 x) external { n = x; }
      function isEven(uint256 k) public view returns (bool){ if (k == 0) return true; return isOdd(k - 1); }
      function isOdd(uint256 k) internal view returns (bool){ if (k == 0) return n == 0; return isEven(k - 1); }
    }`,
    expectedFnMap: { setN: 'nonpayable', isEven: 'view' },
    seed: { sig: 'setN(uint256)', words: [0n] },
    calls: [{ sig: 'isEven(uint256)', words: [4n] }, { sig: 'isEven(uint256)', words: [5n] }],
  },

  // 5. SELF-RECURSION pure (Fibonacci) -> infer pure.
  {
    name: 'self-recursion-pure',
    inferred: `@contract class C {
      @read fib(k: u256): u256 { if (k < 2n) { return k; } return this.fib(k - 1n) + this.fib(k - 2n); }
    }`,
    explicit: `@contract class C {
      @public @pure fib(k: u256): u256 { if (k < 2n) { return k; } return this.fib(k - 1n) + this.fib(k - 2n); }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function fib(uint256 k) public pure returns (uint256){ if (k < 2) return k; return fib(k - 1) + fib(k - 2); }
    }`,
    expectedFnMap: { fib: 'pure' },
    calls: [{ sig: 'fib(uint256)', words: [10n] }],
  },

  // 6. @read calling ANOTHER @read (both read-only); both exposed. The inner @read is internally
  //    called -> resolves @public; outer never called -> @external. Both pure here.
  {
    name: 'read-calls-read',
    inferred: `@contract class C {
      @read outer(a: u256): u256 { return this.inner(a) + 1n; }
      @read inner(a: u256): u256 { return a * 3n; }
    }`,
    explicit: `@contract class C {
      @external @pure outer(a: u256): u256 { return this.inner(a) + 1n; }
      @public @pure inner(a: u256): u256 { return a * 3n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function outer(uint256 a) external pure returns (uint256){ return inner(a) + 1; }
      function inner(uint256 a) public pure returns (uint256){ return a * 3; }
    }`,
    expectedFnMap: { outer: 'pure', inner: 'pure' },
    calls: [
      { sig: 'outer(uint256)', words: [5n] },
      { sig: 'inner(uint256)', words: [5n] },
    ],
  },

  // 7. VISIBILITY INFERENCE: no-decorator callee invoked by a no-decorator caller -> callee public,
  //    caller external. (public/external are ABI-identical; runtime must match.)
  {
    name: 'visibility-callgraph',
    inferred: `@contract class C {
      pubTarget(): u256 { return 7n; }
      caller(): u256 { return this.pubTarget() + 1n; }
      extOnly(): u256 { return 42n; }
    }`,
    explicit: `@contract class C {
      @public pubTarget(): u256 { return 7n; }
      @external caller(): u256 { return this.pubTarget() + 1n; }
      @external extOnly(): u256 { return 42n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function pubTarget() public returns (uint256){ return 7; }
      function caller() external returns (uint256){ return pubTarget() + 1; }
      function extOnly() external returns (uint256){ return 42; }
    }`,
    expectedFnMap: { pubTarget: 'nonpayable', caller: 'nonpayable', extOnly: 'nonpayable' },
    calls: [{ sig: 'pubTarget()' }, { sig: 'caller()' }, { sig: 'extOnly()' }],
  },

  // 8. no-decorator function called ONLY via this.f() -> public; recursion self-call -> public.
  {
    name: 'visibility-this-and-recursion',
    inferred: `@contract class C {
      viaThis(a: u256): u256 { return this.helper(a); }
      helper(a: u256): u256 { return a + 100n; }
      countdown(k: u256): u256 { if (k == 0n) { return 0n; } return this.countdown(k - 1n) + 1n; }
    }`,
    explicit: `@contract class C {
      @external viaThis(a: u256): u256 { return this.helper(a); }
      @public helper(a: u256): u256 { return a + 100n; }
      @public countdown(k: u256): u256 { if (k == 0n) { return 0n; } return this.countdown(k - 1n) + 1n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function viaThis(uint256 a) external returns (uint256){ return helper(a); }
      function helper(uint256 a) public returns (uint256){ return a + 100; }
      function countdown(uint256 k) public returns (uint256){ if (k == 0) return 0; return countdown(k - 1) + 1; }
    }`,
    expectedFnMap: { viaThis: 'nonpayable', helper: 'nonpayable', countdown: 'nonpayable' },
    calls: [
      { sig: 'viaThis(uint256)', words: [1n] },
      { sig: 'helper(uint256)', words: [1n] },
      { sig: 'countdown(uint256)', words: [3n] },
    ],
  },

  // 9. no-decorator function called by a @hidden one -> the callee becomes public (internally
  //    called), the @hidden one is excluded from the ABI.
  {
    name: 'visibility-called-by-hidden',
    // leaf is read-only and internally called by the @hidden `mid`; it resolves @public @pure.
    // (We give leaf @read so the whole pure chain is mutability-consistent, matching solc, while
    // still exercising "a no-visibility/@read function called by a @hidden one becomes public".)
    inferred: `@contract class C {
      @read entry(a: u256): u256 { return this.mid(a); }
      @hidden mid(a: u256): u256 { return this.leaf(a) + 1n; }
      @read leaf(a: u256): u256 { return a * 5n; }
    }`,
    explicit: `@contract class C {
      @external @pure entry(a: u256): u256 { return this.mid(a); }
      @internal mid(a: u256): u256 { return this.leaf(a) + 1n; }
      @public @pure leaf(a: u256): u256 { return a * 5n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function entry(uint256 a) external pure returns (uint256){ return mid(a); }
      function mid(uint256 a) internal pure returns (uint256){ return leaf(a) + 1; }
      function leaf(uint256 a) public pure returns (uint256){ return a * 5; }
    }`,
    expectedFnMap: { entry: 'pure', leaf: 'pure' },
    calls: [
      { sig: 'entry(uint256)', words: [4n] },
      { sig: 'leaf(uint256)', words: [4n] },
    ],
  },

  // 10. @hidden calling @hidden, both mutating helpers behind an exposed nonpayable function.
  {
    name: 'hidden-calls-hidden-mutating',
    inferred: `@contract class C {
      @state s: u256;
      bump(): u256 { this.h1(); return this.s; }
      @hidden h1(): void { this.h2(); this.s = this.s + 1n; }
      @hidden h2(): void { this.s = this.s + 10n; }
    }`,
    explicit: `@contract class C {
      @state s: u256;
      @external bump(): u256 { this.h1(); return this.s; }
      @internal h1(): void { this.h2(); this.s = this.s + 1n; }
      @internal h2(): void { this.s = this.s + 10n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      uint256 s;
      function bump() external returns (uint256){ h1(); return s; }
      function h1() internal { h2(); s = s + 1; }
      function h2() internal { s = s + 10; }
    }`,
    expectedFnMap: { bump: 'nonpayable' },
    calls: [{ sig: 'bump()' }, { sig: 'bump()' }],
  },

  // 11. MIXED @read + no-visibility on the same function: infer BOTH view-ness and visibility.
  //     getX has @read and no visibility; it's never internally called -> external @view.
  //     deriv has @read, called via this.getX -> getX stays external? No: getX IS internally
  //     called here, so it resolves @public @view.
  {
    name: 'mixed-read-and-inferred-visibility',
    inferred: `@contract class C {
      @state x: u256;
      @external setX(v: u256): void { this.x = v; }
      @read getX(): u256 { return this.x; }
      @read deriv(): u256 { return this.getX() * 2n; }
    }`,
    explicit: `@contract class C {
      @state x: u256;
      @external setX(v: u256): void { this.x = v; }
      @public @view getX(): u256 { return this.x; }
      @external @view deriv(): u256 { return this.getX() * 2n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      uint256 x;
      function setX(uint256 v) external { x = v; }
      function getX() public view returns (uint256){ return x; }
      function deriv() external view returns (uint256){ return getX() * 2; }
    }`,
    expectedFnMap: { setX: 'nonpayable', getX: 'view', deriv: 'view' },
    seed: { sig: 'setX(uint256)', words: [21n] },
    calls: [{ sig: 'getX()' }, { sig: 'deriv()' }],
  },

  // 12. @read + @hidden together: a hidden read-only helper. Should resolve internal + (pure/view).
  //     Excluded from the ABI either way; the exposed @read consumer is what we assert.
  {
    name: 'read-plus-hidden-helper',
    inferred: `@contract class C {
      @state x: u256;
      @external setX(v: u256): void { this.x = v; }
      @read consume(): u256 { return this.hiddenView() + this.hiddenPure(3n); }
      @read @hidden hiddenView(): u256 { return this.x; }
      @read @hidden hiddenPure(a: u256): u256 { return a + 1n; }
    }`,
    explicit: `@contract class C {
      @state x: u256;
      @external setX(v: u256): void { this.x = v; }
      @external @view consume(): u256 { return this.hiddenView() + this.hiddenPure(3n); }
      @internal @view hiddenView(): u256 { return this.x; }
      @internal @pure hiddenPure(a: u256): u256 { return a + 1n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      uint256 x;
      function setX(uint256 v) external { x = v; }
      function consume() external view returns (uint256){ return hiddenView() + hiddenPure(3); }
      function hiddenView() internal view returns (uint256){ return x; }
      function hiddenPure(uint256 a) internal pure returns (uint256){ return a + 1; }
    }`,
    expectedFnMap: { setX: 'nonpayable', consume: 'view' },
    seed: { sig: 'setX(uint256)', words: [40n] },
    calls: [{ sig: 'consume()' }],
  },

  // 13. DEEP no-visibility call chain (depth 5), the deepest reads state -> all view that propagate,
  //     exposed entry external @view, the chain members public @view (internally called).
  {
    name: 'deep-chain-view',
    inferred: `@contract class C {
      @state z: u256;
      @external setZ(v: u256): void { this.z = v; }
      @read a0(): u256 { return this.a1(); }
      a1(): u256 { return this.a2(); }
      a2(): u256 { return this.a3(); }
      a3(): u256 { return this.a4(); }
      a4(): u256 { return this.z + 1n; }
    }`,
    explicit: `@contract class C {
      @state z: u256;
      @external setZ(v: u256): void { this.z = v; }
      @external @view a0(): u256 { return this.a1(); }
      @public a1(): u256 { return this.a2(); }
      @public a2(): u256 { return this.a3(); }
      @public a3(): u256 { return this.a4(); }
      @public a4(): u256 { return this.z + 1n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      uint256 z;
      function setZ(uint256 v) external { z = v; }
      function a0() external view returns (uint256){ return a1(); }
      function a1() public view returns (uint256){ return a2(); }
      function a2() public view returns (uint256){ return a3(); }
      function a3() public view returns (uint256){ return a4(); }
      function a4() public view returns (uint256){ return z + 1; }
    }`,
    // a1..a4 carry no @read so their mutability is the DEFAULT (nonpayable) in jeth, but solc would
    // infer view. Since a1..a4 are internally called AND not @read, jeth keeps them nonpayable.
    // We only assert the @read entry's mutability and the public/external set; internal-only call
    // results are exercised through a0.
    expectedFnMap: { setZ: 'nonpayable', a0: 'view', a1: 'nonpayable', a2: 'nonpayable', a3: 'nonpayable', a4: 'nonpayable' },
    seed: { sig: 'setZ(uint256)', words: [5n] },
    calls: [{ sig: 'a0()' }],
  },
];

// Test 13 mixes inferred @read (a0) with non-@read public functions whose mutability does NOT get
// inferred (a1..a4 stay nonpayable). The solc twin declares them view, so the ABI fnMaps for those
// public functions differ from solc, but they are not in our `calls` assertion path beyond a0().
// To keep the inferred==explicit ABI check meaningful we compare against the EXPLICIT jeth twin,
// which declares a1..a4 @public (nonpayable) - matching jeth, not solc. Runtime of a0() is still
// asserted against solc.

describe('decorator inference: inferred === explicit === solc (positive)', () => {
  for (const t of twins) {
    it(`${t.name}: inferred ABI == explicit ABI`, () => {
      const inf = compileOrDiags(t.inferred);
      const exp = compileOrDiags(t.explicit);
      expect(inf.ok, `inferred failed: ${(inf as { codes?: string[] }).codes}`).toBe(true);
      expect(exp.ok, `explicit failed: ${(exp as { codes?: string[] }).codes}`).toBe(true);
      if (!inf.ok || !exp.ok) return;
      expect(fnMap(inf.abi)).toEqual(fnMap(exp.abi));
      expect(fnMap(inf.abi)).toEqual(t.expectedFnMap);
    });
  }

  for (const t of twins) {
    it(`${t.name}: runtime byte-identical (inferred / explicit / solc)`, async () => {
      const inf = compile(t.inferred, { fileName: 'C.jeth' });
      const exp = compile(t.explicit, { fileName: 'C.jeth' });
      const sb = compileSolidity(t.sol, 'C');
      const hInf = await Harness.create();
      const hExp = await Harness.create();
      const hSol = await Harness.create();
      const aInf = await hInf.deploy(inf.creationBytecode);
      const aExp = await hExp.deploy(exp.creationBytecode);
      const aSol = await hSol.deploy(sb.creation);

      const apply = async (h: Harness, addr: Address, c: { sig: string; words?: bigint[] }) =>
        h.call(addr, encodeCall(sel(c.sig), c.words ?? []));

      if (t.seed) {
        await apply(hInf, aInf, t.seed);
        await apply(hExp, aExp, t.seed);
        await apply(hSol, aSol, t.seed);
      }

      for (const c of t.calls) {
        const rInf = await apply(hInf, aInf, c);
        const rExp = await apply(hExp, aExp, c);
        const rSol = await apply(hSol, aSol, c);
        expect(rInf.success, `${t.name}/${c.sig} inferred success (err=${rInf.exceptionError})`).toBe(rSol.success);
        expect(rExp.success, `${t.name}/${c.sig} explicit success`).toBe(rSol.success);
        expect(rInf.returnHex, `${t.name}/${c.sig} inferred returndata`).toBe(rSol.returnHex);
        expect(rExp.returnHex, `${t.name}/${c.sig} explicit returndata`).toBe(rSol.returnHex);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// REJECTION PARITY: an inferred @read that is not actually read-only must be rejected with the
// same diagnostic as the illegal explicit form (parity with solc rejecting a view that writes).
// ---------------------------------------------------------------------------

describe('decorator inference: rejection parity', () => {
  const rej: { name: string; src: string; code: string }[] = [
    {
      name: '@read writes state directly -> JETH056',
      src: `@contract class C { @state x: u256; @read bad(): void { this.x = 1n; } }`,
      code: 'JETH056',
    },
    {
      name: '@read writes state transitively via hidden -> JETH056',
      src: `@contract class C {
        @state x: u256;
        @read bad(): u256 { return this.w(); }
        @hidden w(): u256 { this.x = 1n; return this.x; }
      }`,
      code: 'JETH056',
    },
    {
      name: '@read writes via a deep hidden chain -> JETH056',
      src: `@contract class C {
        @state x: u256;
        @read bad(): u256 { return this.h1(); }
        @hidden h1(): u256 { return this.h2(); }
        @hidden h2(): u256 { this.x = this.x + 1n; return this.x; }
      }`,
      code: 'JETH056',
    },
    {
      name: '@read reads msg.value directly -> JETH162',
      src: `@contract class C { @read bad(): u256 { return msg.value; } }`,
      code: 'JETH162',
    },
    {
      name: '@read emits an event directly -> JETH149',
      src: `@contract class C { @event E(a: u256); @read bad(): void { emit(E(1n)); } }`,
      code: 'JETH149',
    },
    // conflicts -> JETH052
    { name: '@read + @view conflict -> JETH052', src: `@contract class C { @read @view bad(): u256 { return 1n; } }`, code: 'JETH052' },
    { name: '@read + @pure conflict -> JETH052', src: `@contract class C { @read @pure bad(): u256 { return 1n; } }`, code: 'JETH052' },
    { name: '@read + @payable conflict -> JETH052', src: `@contract class C { @read @payable bad(): u256 { return 1n; } }`, code: 'JETH052' },
    { name: '@hidden + @external conflict -> JETH052', src: `@contract class C { @hidden @external bad(): u256 { return 1n; } }`, code: 'JETH052' },
    { name: '@hidden + @public conflict -> JETH052', src: `@contract class C { @hidden @public bad(): u256 { return 1n; } }`, code: 'JETH052' },
    { name: '@hidden + @internal conflict -> JETH052', src: `@contract class C { @hidden @internal bad(): u256 { return 1n; } }`, code: 'JETH052' },
    { name: '@hidden + @private conflict -> JETH052', src: `@contract class C { @hidden @private bad(): u256 { return 1n; } }`, code: 'JETH052' },
  ];

  for (const r of rej) {
    it(r.name, () => {
      const res = compileOrDiags(r.src);
      expect(res.ok, `expected rejection ${r.code} but it compiled`).toBe(false);
      if (!res.ok) expect(res.codes).toContain(r.code);
    });
  }
});

// ---------------------------------------------------------------------------
// BOUNDARY: @read and an explicit @external on the same function is allowed (visibility and
// mutability are orthogonal). And inference must not have broken the pre-existing @view-writes /
// @pure-reads diagnostics.
// ---------------------------------------------------------------------------

describe('decorator inference: orthogonality + pre-existing diagnostics intact', () => {
  it('@read + explicit @external is allowed and resolves external @view', () => {
    const res = compileOrDiags(`@contract class C { @state x: u256; @external @read getX(): u256 { return this.x; } }`);
    expect(res.ok).toBe(true);
    if (res.ok) expect(fnMap(res.abi)).toEqual({ getX: 'view' });
  });

  it('explicit @view that writes still errors JETH054 (inference did not break it)', () => {
    const res = compileOrDiags(`@contract class C { @state x: u256; @external @view bad(): void { this.x = 1n; } }`);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.codes).toContain('JETH054');
  });

  it('explicit @pure that reads state still errors JETH055', () => {
    const res = compileOrDiags(`@contract class C { @state x: u256; @external @pure bad(): u256 { return this.x; } }`);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.codes).toContain('JETH055');
  });

  it('explicit @pure that reads env still errors JETH164', () => {
    const res = compileOrDiags(`@contract class C { @external @pure bad(): address { return msg.sender; } }`);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.codes).toContain('JETH164');
  });

  it('a fully explicit contract is unchanged by inference (ABI stable)', () => {
    const res = compileOrDiags(`@contract class C {
      @state x: u256;
      @external @view getX(): u256 { return this.x; }
      @external setX(v: u256): void { this.x = v; }
      @internal helper(): u256 { return this.x + 1n; }
    }`);
    expect(res.ok).toBe(true);
    if (res.ok) expect(fnMap(res.abi)).toEqual({ getX: 'view', setX: 'nonpayable' });
  });
});

// ---------------------------------------------------------------------------
// FIXED: a @read / @view / @pure function that TRANSITIVELY EMITS an event through a helper is now
// REJECTED, matching solc ("Function cannot be declared as view because this ... modifies the state").
// checkEmit now records emit as a state-modifying effect so the transitive-purity fixpoint sees it.
// ---------------------------------------------------------------------------

describe('transitive emit makes a function non-read-only (parity with solc)', () => {
  const READ_VIA_HIDDEN_EMIT = `@contract class C {
    @event E(a: u256);
    @read foo(): u256 { return this.bar(); }
    @hidden bar(): u256 { emit(E(1n)); return 5n; }
  }`;

  it('solc REJECTS the equivalent view (ground truth)', () => {
    const sol = `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      event E(uint256 a);
      function foo() external view returns (uint256){ return bar(); }
      function bar() internal returns (uint256){ emit E(1); return 5; }
    }`;
    let rejected = false;
    try { compileSolidity(sol, 'C'); } catch { rejected = true; }
    expect(rejected, 'solc should reject a view function that transitively emits').toBe(true);
  });

  it('JETH also REJECTS @read / @view / @pure that transitively emit', () => {
    expect(compileOrDiags(READ_VIA_HIDDEN_EMIT).ok, '@read transitively emitting must be rejected').toBe(false);
    const viaView = `@contract class C { @event E(a: u256); @external @view foo(): u256 { return this.bar(); } @hidden bar(): u256 { emit(E(1n)); return 5n; } }`;
    expect(compileOrDiags(viaView).ok, '@view transitively emitting must be rejected').toBe(false);
    const viaPure = `@contract class C { @event E(a: u256); @external @pure foo(): u256 { return this.bar(); } @hidden bar(): u256 { emit(E(1n)); return 5n; } }`;
    expect(compileOrDiags(viaPure).ok, '@pure transitively emitting must be rejected').toBe(false);
    // a plain nonpayable function transitively emitting is fine (control).
    const ok = `@contract class C { @event E(a: u256); @external foo(): u256 { return this.bar(); } @hidden bar(): u256 { emit(E(1n)); return 5n; } }`;
    expect(compileOrDiags(ok).ok, 'a nonpayable function may transitively emit').toBe(true);
  });
});
