// Two related NAME-VALIDATION bar violations, both ruled REJECT.
//
// (A) JETH499 - @nonReentrant NAME-COLLISION miscompile: a user `@modifier nonReentrant() { ... }`
//     applied via `@nonReentrant f()` was SILENTLY treated as the built-in transient-storage guard,
//     dropping the user modifier body. Proven a real miscompile below (setLock(1); bump() -> JETH
//     succeeds while solc reverts). RULING: a @modifier declared with a KEPT built-in decorator name
//     (nonReentrant / override; virtual / using are also reserved identifiers, JETH500) is a hard
//     error - a clean over-rejection that beats the silent-drop miscompile.
//
// (B) JETH500 - RESERVED-WORD identifiers: JETH's TS-based parser accepts `virtual` / `using` /
//     `anonymous` as declared identifier names (var / field / param / function / modifier / member)
//     that solc PARSE-REJECTS as reserved keywords. RULING: reject exactly this minimal set as a
//     declaration name.
import { describe, it, expect, beforeAll } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
const accepts = (src: string): boolean => codes(src).length === 0;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => v.toString(16).padStart(64, '0');

describe('JETH499: @modifier named like a kept built-in decorator', () => {
  it('a @modifier named nonReentrant rejects (the silent-drop miscompile)', () => {
    const src = `class C {
      lock: u256;
      @modifier nonReentrant() { require(this.lock == 0n, "u"); _; }
      @nonReentrant bump(): External<void> { this.lock = this.lock + 1n; }
    }`;
    expect(codes(src)).toContain('JETH499');
  });

  it('a @modifier named override rejects with JETH499', () => {
    const src = `class C {
      s: u256;
      @modifier override() { _; }
      f(): External<void> { this.s = 1n; }
    }`;
    expect(codes(src)).toContain('JETH499');
  });

  it('a @modifier named virtual / using rejects (via the JETH500 reserved-word gate)', () => {
    for (const nm of ['virtual', 'using']) {
      const src = `class C { s: u256; @modifier ${nm}() { _; } f(): External<void> { this.s = 1n; } }`;
      expect(codes(src)).toContain('JETH500');
    }
  });

  it('a NON-colliding user modifier still accepts (no over-rejection)', () => {
    expect(
      accepts(`class C {
        owner: address;
        s: u256;
        @modifier onlyOwner() { require(msg.sender == this.owner, "no"); _; }
        @onlyOwner f(): External<void> { this.s = 1n; }
      }`),
    ).toBe(true);
    expect(
      accepts(`class C {
        s: u256;
        @modifier myGuard() { require(true, "x"); _; }
        @myGuard f(): External<void> { this.s = 1n; }
      }`),
    ).toBe(true);
  });
});

describe('JETH500: reserved-word identifiers (virtual / using / anonymous)', () => {
  it('reserved words reject as a local var name', () => {
    for (const nm of ['virtual', 'using', 'anonymous']) {
      expect(codes(`class C { s: u256; f(): External<void> { let ${nm}: u256 = 1n; this.s = ${nm}; } }`)).toContain(
        'JETH500',
      );
    }
  });
  it('reserved words reject as a parameter name', () => {
    for (const nm of ['virtual', 'using', 'anonymous']) {
      expect(codes(`class C { s: u256; f(${nm}: u256): External<void> { this.s = ${nm}; } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as a state field name', () => {
    for (const nm of ['virtual', 'using', 'anonymous']) {
      expect(codes(`class C { ${nm}: u256; get f(): External<u256> { return this.${nm}; } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as a function name', () => {
    for (const nm of ['virtual', 'using', 'anonymous']) {
      expect(codes(`class C { s: u256; ${nm}(): External<void> { this.s = 1n; } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as a struct member name', () => {
    for (const nm of ['virtual', 'using', 'anonymous']) {
      expect(codes(`type P = { ${nm}: u256 }; class C { s: u256; f(p: P): External<void> { this.s = p.${nm}; } }`)).toContain(
        'JETH500',
      );
    }
  });

  it('CONTROLS: normal identifiers still accept', () => {
    expect(
      accepts(`class C {
        count: u256;
        f(value: u256, from: address, to: address): External<void> { let x: u256 = value; this.count = x; }
      }`),
    ).toBe(true);
  });

  it('CONTROLS: lookalike names (virtualX / usingList / anonymousUser) still accept', () => {
    expect(
      accepts(`class C {
        virtualX: u256; usingList: u256; anonymousUser: u256;
        f(): External<void> { this.virtualX = 1n; this.usingList = 2n; this.anonymousUser = 3n; }
      }`),
    ).toBe(true);
  });

  it('CONTROLS: the @virtual / @override / @using / @anonymous DECORATOR applications still accept', () => {
    // decorator applications name none of these as an identifier DECLARATION, so they are untouched.
    expect(
      accepts(`abstract class B { s: u256; @virtual f(): External<void> { this.s = 1n; } }
        class C extends B { @override f(): External<void> { this.s = 2n; } }`),
    ).toBe(true);
    expect(
      accepts(`static class L { add(a: u256, b: u256): u256 { return a + b; } }
        @using(L) class C { s: u256; f(): External<void> { this.s = (3n).add(4n); } }`),
    ).toBe(true);
    expect(
      accepts(`class C { @anonymous E: event<{ a: indexed<u256>; b: u256 }>; f(): External<void> { emit(E(7n, 9n)); } }`),
    ).toBe(true);
  });
});

describe('MC witness: @nonReentrant name-collision was a real run-diff miscompile (now rejected)', () => {
  // The rejected program below, if it had compiled, diverged from solc at runtime: with lock seeded to
  // 1, solc's user require() in the modifier reverts bump(); JETH silently ran the built-in mutex (no
  // lock check) and let bump() succeed. This test just re-affirms the reject; the run-diff was captured
  // out-of-band during the fix (JETH bump success=true vs solc success=false).
  it('is rejected, not compiled', () => {
    const src = `class C {
      lock: u256;
      @modifier nonReentrant() { require(this.lock == 0n, "u"); _; }
      setLock(v: u256): External<void> { this.lock = v; }
      @nonReentrant bump(): External<void> { this.lock = this.lock + 1n; }
    }`;
    expect(() => compile(src, { fileName: 'C.jeth' })).toThrow();
  });
});

describe('CONTROL: built-in @nonReentrant guard still reverts on re-entrance (untouched by the fix)', () => {
  const JETH = `class V {
    x: u256;
    @nonReentrant bump(): External<void> { this.x = this.x + 1n; }
    get get(): External<u256> { return this.x; }
  }`;
  let h: Harness;
  let addr: import('@ethereumjs/util').Address;
  beforeAll(async () => {
    h = await Harness.create();
    addr = await h.deploy('0x' + compile(JETH, { fileName: 'V.jeth' }).creationBytecode);
  });
  it('a single guarded entry succeeds and mutates state', async () => {
    const r = await h.call(addr, '0x' + sel('bump()'));
    expect(r.success).toBe(true);
    const g = await h.call(addr, '0x' + sel('get()'));
    expect(g.returnHex).toBe('0x' + pad(1n));
  });
});
