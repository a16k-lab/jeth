// DUP-BODYLESS-VIRTUAL (over-acceptance, closed): a SAME-CLASS duplicate signature involving a
// BODYLESS declaration used to compile silently. The concrete+concrete duplicate has always been
// rejected (JETH044: the duplicate-signature check runs on the final FunctionIR list), but a bodyless
// declaration never becomes a FunctionIR - resolveOverrides' signature grouping simply merged it into
// the override set - so `@virtual f(v: u256): External<u256>;` declared twice in one class (either
// spelling: @virtual or the TS `abstract` member, the mixed abstract/@virtual pair, a bodyless get
// pair, a bodyless+concrete mix, or the pair in a MIDDLE class of a chain) slipped through
// BYTE-IDENTICAL to the single declaration.
//
// PRE-FIX PIN (non-vacuity): at base 024b5b6 every reject below ACCEPTED, and the three headline
// bodyless-pair flavors (virtual+virtual, abstract+abstract, mixed) compiled byte-identical to the
// single-declaration control (sha256-verified). The fix is a same-contract duplicate check inside
// resolveOverrides' signature groups, keyed with the display-name-augmented sub-key of the downstream
// FunctionIR check (so a same-canonical different-JETH-type pair stays a selector-clash concern) and
// fires only when a duplicate involves a bodyless version (the concrete pair keeps its existing path).
//
// solc 0.8.35 witnesses (re-run at fix time, all DeclarationError "Function with same name and
// parameter types defined twice"): bodyless+bodyless pair, bodyless+concrete pair, bodyless pair in a
// middle contract, bodyless view-getter pair. Accept witnesses: distinct-signature bodyless overloads,
// the same signature redeclared across a chain (override), interface method + class implementation,
// concrete distinct-signature overloads.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

const bc = (src: string): string => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    const err = e as { diagnostics?: { code: string }[] };
    if (err.diagnostics) return [...new Set(err.diagnostics.map((d) => d.code))];
    throw e;
  }
};
const solcRejects = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};

// The shared concrete leaf: every duplicate flavor below is observed through the same deployed C.
const LEAF = `class C extends B {
  x: u256;
  @override f(v: u256): External<u256> { this.x = v; return this.x; }
}`;
const SOL_LEAF = `contract C is B {
  uint256 x;
  function f(uint256 v) external override returns (uint256) { x = v; return x; }
}`;

describe('DUP-BODYLESS-VIRTUAL: same-class duplicate signatures reject JETH044 (pre-fix: ACCEPTED byte-identical to the single declaration)', () => {
  it('bodyless @virtual pair -> JETH044; solc mirror rejects "defined twice"', () => {
    expect(
      codes(`abstract class B {
        @virtual f(v: u256): External<u256>;
        @virtual f(v: u256): External<u256>;
      }
      ${LEAF}`),
    ).toEqual(['JETH044']);
    expect(
      solcRejects(`abstract contract B {
        function f(uint256 v) external virtual returns (uint256);
        function f(uint256 v) external virtual returns (uint256);
      }
      ${SOL_LEAF}`),
    ).toBe(true);
  });

  it('TS `abstract` member pair -> JETH044 (same machinery as the @virtual spelling)', () => {
    expect(
      codes(`abstract class B {
        abstract f(v: u256): External<u256>;
        abstract f(v: u256): External<u256>;
      }
      ${LEAF}`),
    ).toEqual(['JETH044']);
  });

  it('MIXED abstract + @virtual pair -> JETH044 (the spellings are the same bodyless obligation)', () => {
    expect(
      codes(`abstract class B {
        abstract f(v: u256): External<u256>;
        @virtual f(v: u256): External<u256>;
      }
      ${LEAF}`),
    ).toEqual(['JETH044']);
  });

  it('bodyless + CONCRETE same signature in one class -> JETH044; solc mirror rejects', () => {
    expect(
      codes(`abstract class B {
        y: u256;
        abstract f(v: u256): External<u256>;
        @virtual f(v: u256): External<u256> { this.y = v; return this.y; }
      }
      ${LEAF}`),
    ).toEqual(['JETH044']);
    expect(
      codes(`abstract class B {
        y: u256;
        @virtual f(v: u256): External<u256>;
        @virtual f(v: u256): External<u256> { this.y = v; return this.y; }
      }
      ${LEAF}`),
    ).toEqual(['JETH044']);
    expect(
      solcRejects(`abstract contract B {
        function f(uint256 v) external virtual returns (uint256);
        function f(uint256 v) external virtual returns (uint256) { return v; }
      }
      ${SOL_LEAF}`),
    ).toBe(true);
  });

  it('bodyless get pair -> JETH044; solc view-getter mirror rejects', () => {
    expect(
      codes(`abstract class B {
        @virtual get g(): External<u256>;
        @virtual get g(): External<u256>;
      }
      class C extends B { x: u256; h(v: u256): External<void> { this.x = v; } @override get g(): External<u256> { return this.x; } }`),
    ).toEqual(['JETH044']);
    expect(
      solcRejects(`abstract contract B {
        function g() external view virtual returns (uint256);
        function g() external view virtual returns (uint256);
      }
      contract C is B { uint256 x; function h(uint256 v) external { x = v; } function g() external view override returns (uint256) { return x; } }`),
    ).toBe(true);
  });

  it('TRIPLE duplicate (virtual + abstract + virtual) -> JETH044', () => {
    expect(
      codes(`abstract class B {
        @virtual f(v: u256): External<u256>;
        abstract f(v: u256): External<u256>;
        @virtual f(v: u256): External<u256>;
      }
      ${LEAF}`),
    ).toEqual(['JETH044']);
  });

  it('bodyless pair in a MIDDLE class of a chain -> JETH044; solc mirror rejects', () => {
    expect(
      codes(`abstract class A {
        @virtual f(v: u256): External<u256>;
      }
      abstract class M extends A {
        @override @virtual f(v: u256): External<u256>;
        @override @virtual f(v: u256): External<u256>;
      }
      class C extends M {
        x: u256;
        @override f(v: u256): External<u256> { this.x = v; return this.x; }
      }`),
    ).toEqual(['JETH044']);
    expect(
      solcRejects(`abstract contract A {
        function f(uint256 v) external virtual returns (uint256);
      }
      abstract contract M is A {
        function f(uint256 v) external virtual override returns (uint256);
        function f(uint256 v) external virtual override returns (uint256);
      }
      contract C is M {
        uint256 x;
        function f(uint256 v) external override returns (uint256) { x = v; return x; }
      }`),
    ).toBe(true);
  });

  it('the concrete duplicate keeps its pre-existing JETH044 reject (unchanged path)', () => {
    expect(
      codes(`class C {
        x: u256;
        f(v: u256): External<u256> { this.x = v; return this.x; }
        f(v: u256): External<u256> { this.x = v; return this.x; }
      }`),
    ).toContain('JETH044');
  });
});

describe('DUP-BODYLESS-VIRTUAL: accept controls stay accepted (and solc-witnessed)', () => {
  it('the single-declaration idiom accepts in both spellings, byte-identical twins', () => {
    const virt = bc(`abstract class B { @virtual f(v: u256): External<u256>; }
      ${LEAF}`);
    const abs = bc(`abstract class B { abstract f(v: u256): External<u256>; }
      ${LEAF}`);
    expect(abs).toBe(virt);
  });

  it('DISTINCT-signature bodyless overloads in one class accept; solc mirror accepts', () => {
    expect(
      codes(`abstract class B {
        @virtual f(v: u256): External<u256>;
        @virtual f(v: u256, w: u256): External<u256>;
      }
      class C extends B {
        x: u256;
        @override f(v: u256): External<u256> { this.x = v; return this.x + 1n; }
        @override f(v: u256, w: u256): External<u256> { this.x = v + w; return this.x + 2n; }
      }`),
    ).toEqual([]);
    expect(
      solcRejects(`abstract contract B {
        function f(uint256 v) external virtual returns (uint256);
        function f(uint256 v, uint256 w) external virtual returns (uint256);
      }
      contract C is B {
        uint256 x;
        function f(uint256 v) external override returns (uint256) { x = v; return x + 1; }
        function f(uint256 v, uint256 w) external override returns (uint256) { x = v + w; return x + 2; }
      }`),
    ).toBe(false);
  });

  it('the same signature redeclared across DIFFERENT classes of a chain is overriding, not duplication; solc accepts', () => {
    expect(
      codes(`abstract class A { @virtual f(v: u256): External<u256>; }
      abstract class M extends A { @override @virtual f(v: u256): External<u256>; }
      class C extends M { x: u256; @override f(v: u256): External<u256> { this.x = v; return this.x; } }`),
    ).toEqual([]);
    expect(
      solcRejects(`abstract contract A { function f(uint256 v) external virtual returns (uint256); }
      abstract contract M is A { function f(uint256 v) external virtual override returns (uint256); }
      ${SOL_LEAF.replace('contract C is B', 'contract C is M')}`),
    ).toBe(false);
  });

  it('interface method + class implementation accepts (declaration vs implementation, not a duplicate)', () => {
    expect(
      codes(`interface I { f(v: u256): u256; }
      class C extends I { x: u256; @override f(v: u256): External<u256> { this.x = v; return v; } }`),
    ).toEqual([]);
  });

  it('concrete distinct-signature overloads in one class accept (the overload machinery)', () => {
    expect(
      codes(`class C {
        x: u256;
        f(v: u256): External<u256> { this.x = v; return this.x; }
        f(v: u256, w: u256): External<u256> { this.x = v + w; return this.x; }
      }`),
    ).toEqual([]);
  });

  it('run+decode anchor: distinct-signature bodyless overloads run byte-equal to the solc mirror (non-vacuous)', async () => {
    const J = `abstract class B {
      @virtual f(v: u256): External<u256>;
      @virtual f(v: u256, w: u256): External<u256>;
    }
    class C extends B {
      x: u256;
      @override f(v: u256): External<u256> { this.x = v; return this.x + 1n; }
      @override f(v: u256, w: u256): External<u256> { this.x = v + w; return this.x + 2n; }
    }`;
    const S = `abstract contract B {
      function f(uint256 v) external virtual returns (uint256);
      function f(uint256 v, uint256 w) external virtual returns (uint256);
    }
    contract C is B {
      uint256 x;
      function f(uint256 v) external override returns (uint256) { x = v; return x + 1; }
      function f(uint256 v, uint256 w) external override returns (uint256) { x = v + w; return x + 2; }
    }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const calls = [
      sel('f(uint256)') + W(41n),
      sel('f(uint256,uint256)') + W(5n) + W(6n),
      sel('f(uint256)') + W(1000003n),
    ];
    const out: string[] = [];
    for (const data of calls) {
      const rj = await h.call(aj, '0x' + data);
      const rs = await h.call(as, '0x' + data);
      expect(rj.success, `success parity for ${data.slice(0, 8)}`).toBe(rs.success);
      expect(rj.returnHex, `return parity for ${data.slice(0, 8)}`).toBe(rs.returnHex);
      out.push(rj.returnHex);
    }
    expect(out[0]).toBe('0x' + W(42n)); // seeded 41, +1 (non-vacuous read-back)
    expect(out[1]).toBe('0x' + W(13n)); // 5 + 6, +2 through the second overload
    expect(out[2]).toBe('0x' + W(1000004n));
  });
});
