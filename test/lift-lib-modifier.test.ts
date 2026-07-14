// LIB-MODIFIER lift (2026-07-14): solc accepts a `modifier` declared inside a `library`; JETH used to
// reject it (JETH390). A library @modifier is now collected through the same collectModifier pipeline a
// contract uses, registered under a QUALIFIED `L.name` key (never colliding with a contract's bare-name
// modifier nor another library's), and threaded through the existing modifier-application machinery,
// expanding at the library-function DEFINITION site (internal fns are inlined; @external fns are
// delegatecall). Each row below is byte-identical to solc 0.8.35 (deploy both, same calldata, compare
// returnHex + success + logs), with the negatives that must still reject pinned.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, compileSolidityLinked, deploySolLinked } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n)).toString();
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e;
  }
};

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await h.call(aj, sel(sig) + args);
    const rs = await h.call(as, sel(sig) + args);
    expect({ ok: rj.success, ret: rj.returnHex, logs: JSON.stringify(rj.logs) }, `${sig}(${args})`)
      .toEqual({ ok: rs.success, ret: rs.returnHex, logs: JSON.stringify(rs.logs) });
  }
}

describe('LIB-MODIFIER: a modifier declared in a library (solc parity)', () => {
  it('(a) an UNUSED library modifier is dead code (runtime == the no-library contract)', () => {
    const withMod = `static class L { @modifier only() { _; } }
      class C { get f(): View<u256> { return 42n; } }`;
    const noLib = `class C { get f(): View<u256> { return 42n; } }`;
    expect(codes(withMod)).toEqual([]);
    // truly dead: the emitted runtime bytecode is identical to the contract with no library at all.
    expect(compile(withMod, { fileName: 'C.jeth' }).runtimeBytecode)
      .toBe(compile(noLib, { fileName: 'C.jeth' }).runtimeBytecode);
  });

  it('(b) a require-guard modifier on an INTERNAL (inlined) library fn - pass + revert paths', async () => {
    const j = `static class L {
      @modifier onlyPos(v: u256) { require(v > 0n, "np"); _; }
      @onlyPos(v) inc(v: u256): u256 { return v + 1n; }
    }
    class C { get g(v: u256): External<u256> { return L.inc(v); } }`;
    const s = `library L {
      modifier onlyPos(uint256 v) { require(v > 0, "np"); _; }
      function inc(uint256 v) internal pure onlyPos(v) returns (uint256) { return v + 1; }
    }
    contract C { function g(uint256 v) external pure returns (uint256) { return L.inc(v); } }`;
    await eqCalls(j, s, [['g(uint256)', W(41)], ['g(uint256)', W(0)], ['g(uint256)', W((1n << 256n) - 2n)]]);
  });

  it('(c) STACKED modifiers on a library fn - guard order + arg eval (distinct revert reasons)', async () => {
    const j = `static class L {
      @modifier lo(a: u256) { require(a >= 10n, "lo"); _; }
      @modifier hi(b: u256) { require(b <= 100n, "hi"); _; }
      @lo(x) @hi(x) clamp(x: u256): u256 { return x * 2n; }
    }
    class C { get g(x: u256): External<u256> { return L.clamp(x); } }`;
    const s = `library L {
      modifier lo(uint256 a) { require(a >= 10, "lo"); _; }
      modifier hi(uint256 b) { require(b <= 100, "hi"); _; }
      function clamp(uint256 x) internal pure lo(x) hi(x) returns (uint256) { return x * 2; }
    }
    contract C { function g(uint256 x) external pure returns (uint256) { return L.clamp(x); } }`;
    await eqCalls(j, s, [['g(uint256)', W(50)], ['g(uint256)', W(5)], ['g(uint256)', W(200)]]);
  });

  it('(d) a pre-only guard on an @external (delegatecall) library fn', async () => {
    const j = `static class L {
      @modifier onlyPos(v: u256) { require(v > 0n, "np"); _; }
      @onlyPos(v) inc(v: u256): External<u256> { return v + 100n; }
    }
    class C { get g(v: u256): External<u256> { return L.inc(v); } }`;
    const s = `library L {
      modifier onlyPos(uint256 v) { require(v > 0, "np"); _; }
      function inc(uint256 v) external pure onlyPos(v) returns (uint256) { return v + 100; }
    }
    contract C { function g(uint256 v) external view returns (uint256) { return L.inc(v); } }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = (await hj.deployLinked(compile(j, { fileName: 'C.jeth' }))).address;
    const as = await deploySolLinked(hs, compileSolidityLinked(SPDX + s, 'C', ['L']));
    for (const v of [7n, 0n]) {
      const rj = await hj.call(aj, sel('g(uint256)') + W(v));
      const rs = await hs.call(as, sel('g(uint256)') + W(v));
      expect({ ok: rj.success, ret: rj.returnHex }, `v=${v}`).toEqual({ ok: rs.success, ret: rs.returnHex });
    }
  });

  it('(e) a modifier body may reference a library CONSTANT', async () => {
    const j = `static class L {
      static MIN: u256 = 10n;
      @modifier ok(v: u256) { require(v >= MIN, "m"); _; }
      @ok(v) inc(v: u256): u256 { return v + 1n; }
    }
    class C { get g(v: u256): External<u256> { return L.inc(v); } }`;
    const s = `library L {
      uint256 constant MIN = 10;
      modifier ok(uint256 v) { require(v >= MIN, "m"); _; }
      function inc(uint256 v) internal pure ok(v) returns (uint256) { return v + 1; }
    }
    contract C { function g(uint256 v) external pure returns (uint256) { return L.inc(v); } }`;
    await eqCalls(j, s, [['g(uint256)', W(10)], ['g(uint256)', W(9)]]);
  });

  it('(f) a SAME-NAMED contract and library modifier dispatch independently (no scope leak)', async () => {
    // Contract onlyPos requires >5; library onlyPos requires >0. Each function must use ITS OWN guard.
    const j = `static class L {
      @modifier onlyPos(v: u256) { require(v > 0n, "L"); _; }
      @onlyPos(v) inc(v: u256): u256 { return v + 1n; }
    }
    class C {
      @modifier onlyPos(v: u256) { require(v > 5n, "C"); _; }
      @onlyPos(v) get cf(v: u256): External<u256> { return v * 2n; }
      get lf(v: u256): External<u256> { return L.inc(v); }
    }`;
    const s = `library L {
      modifier onlyPos(uint256 v) { require(v > 0, "L"); _; }
      function inc(uint256 v) internal pure onlyPos(v) returns (uint256) { return v + 1; }
    }
    contract C {
      modifier onlyPos(uint256 v) { require(v > 5, "C"); _; }
      function cf(uint256 v) external pure onlyPos(v) returns (uint256) { return v * 2; }
      function lf(uint256 v) external pure returns (uint256) { return L.inc(v); }
    }`;
    await eqCalls(j, s, [
      ['cf(uint256)', W(3)], ['cf(uint256)', W(9)],
      ['lf(uint256)', W(0)], ['lf(uint256)', W(4)],
    ]);
  });

  describe('negatives that must still reject', () => {
    it('a lib fn applying a modifier not declared in the library rejects (no fall-through to a contract modifier)', () => {
      const j = `static class L { @onlyPos(v) inc(v: u256): u256 { return v; } }
        class C { @modifier onlyPos(v: u256) { require(v > 0n, "x"); _; } get g(v: u256): External<u256> { return L.inc(v); } }`;
      expect(codes(j)).toContain('JETH329');
    });
    it('a duplicate library modifier of the same name rejects (JETH046)', () => {
      const j = `static class L { @modifier m() { _; } @modifier m() { _; } } class C { get f(): View<u256> { return 1n; } }`;
      expect(codes(j)).toContain('JETH046');
    });
    it('a library modifier name colliding with a library function rejects (JETH133)', () => {
      const j = `static class L { @modifier m() { _; } m(): u256 { return 1n; } } class C { get f(): View<u256> { return 1n; } }`;
      expect(codes(j)).toContain('JETH133');
    });
    it('a library modifier name colliding with a library constant rejects (JETH133)', () => {
      const j = `static class L { static m: u256 = 3n; @modifier m() { _; } } class C { get f(): View<u256> { return 1n; } }`;
      expect(codes(j)).toContain('JETH133');
    });
    it('@virtual / @override on a library modifier rejects (a library cannot be inherited)', () => {
      expect(codes(`static class L { @modifier @virtual m() { _; } } class C { get f(): View<u256> { return 1n; } }`)).toContain('JETH390');
      expect(codes(`static class L { @modifier @override m() { _; } } class C { get f(): View<u256> { return 1n; } }`)).toContain('JETH390');
    });
    it('a generic library modifier is deferred (JETH390) - would leak its template into contract scope', () => {
      const j = `static class L { @modifier lim<T>(v: T) { require(abi.encode(v).length >= 1n, "e"); _; } } class C { get f(): View<u256> { return 1n; } }`;
      expect(codes(j)).toContain('JETH390');
    });
  });
});
