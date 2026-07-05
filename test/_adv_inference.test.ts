// Adversarial verification of compile-time DECORATOR INFERENCE.
//
// Invariant under test: writing @read / no-visibility / must be EXACTLY equivalent to
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

function compileOrDiags(
  src: string,
): { ok: true; abi: AbiFn[]; creationBytecode: string } | { ok: false; codes: string[] } {
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
      @external @read top(a: u256): u256 { return this.l1(a); }
      l1(a: u256): u256 { return this.l2(a) + 1n; }
      l2(a: u256): u256 { return this.l3(a) * 2n; }
      l3(a: u256): u256 { return a + 10n; }
    }`,
    explicit: `@contract class C {
      @external @pure top(a: u256): u256 { return this.l1(a); }
      l1(a: u256): u256 { return this.l2(a) + 1n; }
      l2(a: u256): u256 { return this.l3(a) * 2n; }
      l3(a: u256): u256 { return a + 10n; }
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
      @external @read top(): u256 { return this.l1(); }
      l1(): u256 { return this.l2() + 1n; }
      l2(): u256 { return this.l3(); }
      l3(): u256 { return this.v; }
    }`,
    explicit: `@contract class C {
      @state v: u256;
      @external setV(x: u256): void { this.v = x; }
      @external @view top(): u256 { return this.l1(); }
      l1(): u256 { return this.l2() + 1n; }
      l2(): u256 { return this.l3(); }
      l3(): u256 { return this.v; }
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
      @external @read top(): address { return this.l1(); }
      l1(): address { return this.l2(); }
      l2(): address { return msg.sender; }
    }`,
    explicit: `@contract class C {
      @external @view top(): address { return this.l1(); }
      l1(): address { return this.l2(); }
      l2(): address { return msg.sender; }
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

  // 4. MUTUAL RECURSION among internal helpers reading state -> the read-only-ness propagates so the
  //    exposed entry resolves view. In the @external-only model the mutually-recursive pair must be
  //    INTERNAL (an @external function is not internally callable), so a thin @external @read entry
  //    delegates into the recursion; the inferred view-ness still flows out through the entry.
  {
    name: 'mutual-recursion-view',
    inferred: `@contract class C {
      @state n: u256;
      @external setN(x: u256): void { this.n = x; }
      @external @read isEven(k: u256): bool { return this.evenI(k); }
      evenI(k: u256): bool { if (k == 0n) { return true; } return this.oddI(k - 1n); }
      oddI(k: u256): bool { if (k == 0n) { return this.n == 0n; } return this.evenI(k - 1n); }
    }`,
    explicit: `@contract class C {
      @state n: u256;
      @external setN(x: u256): void { this.n = x; }
      @external @view isEven(k: u256): bool { return this.evenI(k); }
      evenI(k: u256): bool { if (k == 0n) { return true; } return this.oddI(k - 1n); }
      oddI(k: u256): bool { if (k == 0n) { return this.n == 0n; } return this.evenI(k - 1n); }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      uint256 n;
      function setN(uint256 x) external { n = x; }
      function isEven(uint256 k) external view returns (bool){ return evenI(k); }
      function evenI(uint256 k) internal view returns (bool){ if (k == 0) return true; return oddI(k - 1); }
      function oddI(uint256 k) internal view returns (bool){ if (k == 0) return n == 0; return evenI(k - 1); }
    }`,
    expectedFnMap: { setN: 'nonpayable', isEven: 'view' },
    seed: { sig: 'setN(uint256)', words: [0n] },
    calls: [
      { sig: 'isEven(uint256)', words: [4n] },
      { sig: 'isEven(uint256)', words: [5n] },
    ],
  },

  // 5. SELF-RECURSION pure (Fibonacci) -> infer pure. The recursion lives in an INTERNAL helper
  //    (an @external function is not internally callable in the @external-only model); the exposed
  //    entry is a thin @external @read wrapper whose purity is inferred from the helper.
  {
    name: 'self-recursion-pure',
    inferred: `@contract class C {
      @external @read fib(k: u256): u256 { return this.fibI(k); }
      fibI(k: u256): u256 { if (k < 2n) { return k; } return this.fibI(k - 1n) + this.fibI(k - 2n); }
    }`,
    explicit: `@contract class C {
      @external @pure fib(k: u256): u256 { return this.fibI(k); }
      fibI(k: u256): u256 { if (k < 2n) { return k; } return this.fibI(k - 1n) + this.fibI(k - 2n); }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function fib(uint256 k) external pure returns (uint256){ return fibI(k); }
      function fibI(uint256 k) internal pure returns (uint256){ if (k < 2) return k; return fibI(k - 1) + fibI(k - 2); }
    }`,
    expectedFnMap: { fib: 'pure' },
    calls: [{ sig: 'fib(uint256)', words: [10n] }],
  },

  // 6. Two exposed @read entries sharing an internal read-only helper; both infer pure. (In the old
  //    model `inner` was a single @public function both exposed and internally called; the
  //    @external-only model splits that into an exposed @external @read `inner` plus the internal
  //    `innerI` that `outer` calls - both still infer pure and stay byte-identical.)
  {
    name: 'read-calls-read',
    inferred: `@contract class C {
      @external @read outer(a: u256): u256 { return this.innerI(a) + 1n; }
      @external @read inner(a: u256): u256 { return this.innerI(a); }
      innerI(a: u256): u256 { return a * 3n; }
    }`,
    explicit: `@contract class C {
      @external @pure outer(a: u256): u256 { return this.innerI(a) + 1n; }
      @external @pure inner(a: u256): u256 { return this.innerI(a); }
      innerI(a: u256): u256 { return a * 3n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function outer(uint256 a) external pure returns (uint256){ return innerI(a) + 1; }
      function inner(uint256 a) external pure returns (uint256){ return innerI(a); }
      function innerI(uint256 a) internal pure returns (uint256){ return a * 3; }
    }`,
    expectedFnMap: { outer: 'pure', inner: 'pure' },
    calls: [
      { sig: 'outer(uint256)', words: [5n] },
      { sig: 'inner(uint256)', words: [5n] },
    ],
  },

  // 7. VISIBILITY MODEL: @external is the ABI surface; an unmarked function is internal. An exposed
  //    entry that also needs its own logic reused internally factors that logic into an internal
  //    helper (an @external function is not internally callable). pubTarget/caller/extOnly are all
  //    exposed; caller reuses pubTarget's value through the internal pubTargetI.
  {
    name: 'visibility-callgraph',
    inferred: `@contract class C {
      @external pubTarget(): u256 { return this.pubTargetI(); }
      @external caller(): u256 { return this.pubTargetI() + 1n; }
      @external extOnly(): u256 { return 42n; }
      pubTargetI(): u256 { return 7n; }
    }`,
    explicit: `@contract class C {
      @external pubTarget(): u256 { return this.pubTargetI(); }
      @external caller(): u256 { return this.pubTargetI() + 1n; }
      @external extOnly(): u256 { return 42n; }
      pubTargetI(): u256 { return 7n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function pubTarget() external returns (uint256){ return pubTargetI(); }
      function caller() external returns (uint256){ return pubTargetI() + 1; }
      function extOnly() external returns (uint256){ return 42; }
      function pubTargetI() internal returns (uint256){ return 7; }
    }`,
    expectedFnMap: { pubTarget: 'nonpayable', caller: 'nonpayable', extOnly: 'nonpayable' },
    calls: [{ sig: 'pubTarget()' }, { sig: 'caller()' }, { sig: 'extOnly()' }],
  },

  // 8. an exposed entry reuses an internal helper by name; self-recursion lives in an internal
  //    worker (an @external function is not internally callable). viaThis/helper/countdown are
  //    exposed @external; helperI and countdownI are internal.
  {
    name: 'visibility-this-and-recursion',
    inferred: `@contract class C {
      @external viaThis(a: u256): u256 { return this.helperI(a); }
      @external helper(a: u256): u256 { return this.helperI(a); }
      @external countdown(k: u256): u256 { return this.countdownI(k); }
      helperI(a: u256): u256 { return a + 100n; }
      countdownI(k: u256): u256 { if (k == 0n) { return 0n; } return this.countdownI(k - 1n) + 1n; }
    }`,
    explicit: `@contract class C {
      @external viaThis(a: u256): u256 { return this.helperI(a); }
      @external helper(a: u256): u256 { return this.helperI(a); }
      @external countdown(k: u256): u256 { return this.countdownI(k); }
      helperI(a: u256): u256 { return a + 100n; }
      countdownI(k: u256): u256 { if (k == 0n) { return 0n; } return this.countdownI(k - 1n) + 1n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function viaThis(uint256 a) external returns (uint256){ return helperI(a); }
      function helper(uint256 a) external returns (uint256){ return helperI(a); }
      function countdown(uint256 k) external returns (uint256){ return countdownI(k); }
      function helperI(uint256 a) internal returns (uint256){ return a + 100; }
      function countdownI(uint256 k) internal returns (uint256){ if (k == 0) return 0; return countdownI(k - 1) + 1; }
    }`,
    expectedFnMap: { viaThis: 'nonpayable', helper: 'nonpayable', countdown: 'nonpayable' },
    calls: [
      { sig: 'viaThis(uint256)', words: [1n] },
      { sig: 'helper(uint256)', words: [1n] },
      { sig: 'countdown(uint256)', words: [3n] },
    ],
  },

  // 9. an unmarked (internal) function called by an exposed entry stays out of the ABI; the exposed
  //    entry's purity is inferred via @read. `leaf` is also exposed @read (its own selector) while
  //    the shared read-only logic is the internal `leafI`; `mid` is an internal helper.
  {
    name: 'visibility-called-by-hidden',
    inferred: `@contract class C {
      @external @read entry(a: u256): u256 { return this.mid(a); }
      mid(a: u256): u256 { return this.leafI(a) + 1n; }
      @external @read leaf(a: u256): u256 { return this.leafI(a); }
      leafI(a: u256): u256 { return a * 5n; }
    }`,
    explicit: `@contract class C {
      @external @pure entry(a: u256): u256 { return this.mid(a); }
      mid(a: u256): u256 { return this.leafI(a) + 1n; }
      @external @pure leaf(a: u256): u256 { return this.leafI(a); }
      leafI(a: u256): u256 { return a * 5n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      function entry(uint256 a) external pure returns (uint256){ return mid(a); }
      function mid(uint256 a) internal pure returns (uint256){ return leafI(a) + 1; }
      function leaf(uint256 a) external pure returns (uint256){ return leafI(a); }
      function leafI(uint256 a) internal pure returns (uint256){ return a * 5; }
    }`,
    expectedFnMap: { entry: 'pure', leaf: 'pure' },
    calls: [
      { sig: 'entry(uint256)', words: [4n] },
      { sig: 'leaf(uint256)', words: [4n] },
    ],
  },

  // 10. two internal mutating helpers behind one exposed nonpayable entry. bump is @external; h1/h2
  //     are internal (unmarked) and called by name.
  {
    name: 'hidden-calls-hidden-mutating',
    inferred: `@contract class C {
      @state s: u256;
      @external bump(): u256 { this.h1(); return this.s; }
      h1(): void { this.h2(); this.s = this.s + 1n; }
      h2(): void { this.s = this.s + 10n; }
    }`,
    explicit: `@contract class C {
      @state s: u256;
      @external bump(): u256 { this.h1(); return this.s; }
      h1(): void { this.h2(); this.s = this.s + 1n; }
      h2(): void { this.s = this.s + 10n; }
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

  // 11. @read mutability inference on two exposed entries that share an internal read-only helper.
  //     getX/deriv are @external @read (both infer view); the shared state read lives in the
  //     internal getXI (an @external function is not internally callable, so deriv cannot call getX
  //     by name). setX is the nonpayable writer.
  {
    name: 'mixed-read-and-inferred-visibility',
    inferred: `@contract class C {
      @state x: u256;
      @external setX(v: u256): void { this.x = v; }
      @external @read getX(): u256 { return this.getXI(); }
      @external @read deriv(): u256 { return this.getXI() * 2n; }
      getXI(): u256 { return this.x; }
    }`,
    explicit: `@contract class C {
      @state x: u256;
      @external setX(v: u256): void { this.x = v; }
      @external @view getX(): u256 { return this.getXI(); }
      @external @view deriv(): u256 { return this.getXI() * 2n; }
      getXI(): u256 { return this.x; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      uint256 x;
      function setX(uint256 v) external { x = v; }
      function getX() external view returns (uint256){ return getXI(); }
      function deriv() external view returns (uint256){ return getXI() * 2; }
      function getXI() internal view returns (uint256){ return x; }
    }`,
    expectedFnMap: { setX: 'nonpayable', getX: 'view', deriv: 'view' },
    seed: { sig: 'setX(uint256)', words: [21n] },
    calls: [{ sig: 'getX()' }, { sig: 'deriv()' }],
  },

  // 12. internal read-only helpers (no @external) behind one exposed @read entry. consume infers
  //     view; hiddenView/hiddenPure are internal and excluded from the ABI. @read still drives
  //     mutability inference on an internal function.
  {
    name: 'read-plus-hidden-helper',
    inferred: `@contract class C {
      @state x: u256;
      @external setX(v: u256): void { this.x = v; }
      @external @read consume(): u256 { return this.hiddenView() + this.hiddenPure(3n); }
      @read hiddenView(): u256 { return this.x; }
      @read hiddenPure(a: u256): u256 { return a + 1n; }
    }`,
    explicit: `@contract class C {
      @state x: u256;
      @external setX(v: u256): void { this.x = v; }
      @external @view consume(): u256 { return this.hiddenView() + this.hiddenPure(3n); }
      @view hiddenView(): u256 { return this.x; }
      @pure hiddenPure(a: u256): u256 { return a + 1n; }
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

  // 13. DEEP internal call chain (depth 5), the deepest reads state -> the read-only-ness propagates
  //     out to the single exposed @read entry, which infers view. a1..a4 are internal (unmarked) and
  //     excluded from the ABI; only a0 (exposed) and setZ appear.
  {
    name: 'deep-chain-view',
    inferred: `@contract class C {
      @state z: u256;
      @external setZ(v: u256): void { this.z = v; }
      @external @read a0(): u256 { return this.a1(); }
      a1(): u256 { return this.a2(); }
      a2(): u256 { return this.a3(); }
      a3(): u256 { return this.a4(); }
      a4(): u256 { return this.z + 1n; }
    }`,
    explicit: `@contract class C {
      @state z: u256;
      @external setZ(v: u256): void { this.z = v; }
      @external @view a0(): u256 { return this.a1(); }
      a1(): u256 { return this.a2(); }
      a2(): u256 { return this.a3(); }
      a3(): u256 { return this.a4(); }
      a4(): u256 { return this.z + 1n; }
    }`,
    sol: `// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;
    contract C {
      uint256 z;
      function setZ(uint256 v) external { z = v; }
      function a0() external view returns (uint256){ return a1(); }
      function a1() internal view returns (uint256){ return a2(); }
      function a2() internal view returns (uint256){ return a3(); }
      function a3() internal view returns (uint256){ return a4(); }
      function a4() internal view returns (uint256){ return z + 1; }
    }`,
    expectedFnMap: { setZ: 'nonpayable', a0: 'view' },
    seed: { sig: 'setZ(uint256)', words: [5n] },
    calls: [{ sig: 'a0()' }],
  },
];

// In the @external-only model every twin's deep helpers (a1..a4, getXI, leafI, ...) are INTERNAL,
// so they are absent from the ABI and the inferred / explicit / solc fnMaps agree on exactly the
// exposed @external entries. Runtime of each exposed entry is still asserted byte-identical to solc.

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
        w(): u256 { this.x = 1n; return this.x; }
      }`,
      code: 'JETH056',
    },
    {
      name: '@read writes via a deep hidden chain -> JETH056',
      src: `@contract class C {
        @state x: u256;
        @read bad(): u256 { return this.h1(); }
        h1(): u256 { return this.h2(); }
        h2(): u256 { this.x = this.x + 1n; return this.x; }
      }`,
      code: 'JETH056',
    },
    {
      // msg.value in an externally-reachable function needs @payable; @external makes bad reachable.
      name: '@external @read reads msg.value directly -> JETH162',
      src: `@contract class C { @external @read bad(): u256 { return msg.value; } }`,
      code: 'JETH162',
    },
    {
      name: '@read emits an event directly -> JETH149',
      src: `@contract class C { @event E(a: u256); @read bad(): void { emit(E(1n)); } }`,
      code: 'JETH149',
    },
    // @read mutability conflicts -> JETH052
    {
      name: '@read + @view conflict -> JETH052',
      src: `@contract class C { @read @view bad(): u256 { return 1n; } }`,
      code: 'JETH052',
    },
    {
      name: '@read + @pure conflict -> JETH052',
      src: `@contract class C { @read @pure bad(): u256 { return 1n; } }`,
      code: 'JETH052',
    },
    {
      name: '@read + @payable conflict -> JETH052',
      src: `@contract class C { @read @payable bad(): u256 { return 1n; } }`,
      code: 'JETH052',
    },
    // removed visibility decorators -> JETH440 (the @external-only model: write @external to expose,
    // everything else is internal by default; @public/@internal/@private/@hidden no longer exist).
    {
      name: '@public is removed -> JETH440',
      src: `@contract class C { @public bad(): u256 { return 1n; } }`,
      code: 'JETH440',
    },
    {
      name: '@internal is removed -> JETH440',
      src: `@contract class C { @internal bad(): u256 { return 1n; } }`,
      code: 'JETH440',
    },
    {
      name: '@private is removed -> JETH440',
      src: `@contract class C { @private bad(): u256 { return 1n; } }`,
      code: 'JETH440',
    },
    {
      name: '@hidden is removed -> JETH440',
      src: `@contract class C { @hidden bad(): u256 { return 1n; } }`,
      code: 'JETH440',
    },
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
      helper(): u256 { return this.x + 1n; }
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
    bar(): u256 { emit(E(1n)); return 5n; }
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
    try {
      compileSolidity(sol, 'C');
    } catch {
      rejected = true;
    }
    expect(rejected, 'solc should reject a view function that transitively emits').toBe(true);
  });

  it('JETH also REJECTS @read / @view / @pure that transitively emit', () => {
    expect(compileOrDiags(READ_VIA_HIDDEN_EMIT).ok, '@read transitively emitting must be rejected').toBe(false);
    const viaView = `@contract class C { @event E(a: u256); @external @view foo(): u256 { return this.bar(); } bar(): u256 { emit(E(1n)); return 5n; } }`;
    expect(compileOrDiags(viaView).ok, '@view transitively emitting must be rejected').toBe(false);
    const viaPure = `@contract class C { @event E(a: u256); @external @pure foo(): u256 { return this.bar(); } bar(): u256 { emit(E(1n)); return 5n; } }`;
    expect(compileOrDiags(viaPure).ok, '@pure transitively emitting must be rejected').toBe(false);
    // a plain nonpayable function transitively emitting is fine (control).
    const ok = `@contract class C { @event E(a: u256); @external foo(): u256 { return this.bar(); } bar(): u256 { emit(E(1n)); return 5n; } }`;
    expect(compileOrDiags(ok).ok, 'a nonpayable function may transitively emit').toBe(true);
  });
});
