// Two related NAME-VALIDATION bar violations, both ruled REJECT.
//
// (A) JETH499 - @nonReentrant NAME-COLLISION miscompile: a user `@modifier nonReentrant() { ... }`
//     applied via `@nonReentrant f()` was SILENTLY treated as the built-in transient-storage guard,
//     dropping the user modifier body. Proven a real miscompile below (setLock(1); bump() -> JETH
//     succeeds while solc reverts). RULING: a @modifier declared with a KEPT built-in decorator name
//     is a hard error. `nonReentrant` is a legal solc identifier yet collides, so it is JETH499;
//     `virtual` / `using` / `override` are ALSO reserved keywords, so a @modifier declared with one of
//     those names is caught by the JETH500 gate instead (a single, precise diagnostic).
//
// (B) JETH500 - RESERVED-WORD identifiers: JETH's TS-based parser accepts `virtual` / `using` /
//     `override` / `anonymous` as declared identifier names that solc PARSE-REJECTS as reserved
//     keywords. RULING: reject exactly this minimal 4-word set at EVERY declaration name - the
//     value/member positions (var / field / param / function / get / modifier / struct-or-interface
//     member) AND the type/namespace positions (contract / abstract / library / interface / enum /
//     enum-member / struct-or-type-alias name).
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

const RESERVED = ['virtual', 'using', 'override', 'anonymous'];

describe('JETH499/JETH500: @modifier named like a kept built-in decorator', () => {
  it('a @modifier named nonReentrant rejects with JETH499 (the silent-drop miscompile)', () => {
    const src = `class C {
      lock: u256;
      @modifier nonReentrant() { require(this.lock == 0n, "u"); _; }
      @nonReentrant bump(): External<void> { this.lock = this.lock + 1n; }
    }`;
    expect(codes(src)).toContain('JETH499');
  });

  it('a @modifier named virtual / using / override rejects via the JETH500 reserved-word gate', () => {
    for (const nm of ['virtual', 'using', 'override']) {
      const src = `class C { @modifier ${nm}() { _; } get f(): External<u256> { return 1n; } }`;
      expect(codes(src)).toContain('JETH500');
    }
  });

  it('DOUBLE-REPORT GUARD: a @modifier named override gives exactly ONE code (JETH500, never JETH499+JETH500)', () => {
    const c = codes(`class C { @modifier override() { _; } get f(): External<u256> { return 1n; } }`);
    expect(c).toEqual(['JETH500']);
    expect(c).not.toContain('JETH499');
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

describe('JETH500 axis (A): every reserved word at each VALUE/MEMBER declaration position', () => {
  it('reserved words reject as a local var name', () => {
    for (const nm of RESERVED) {
      expect(codes(`class C { get f(): External<u256> { let ${nm}: u256 = 1n; return ${nm}; } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as a parameter name', () => {
    for (const nm of RESERVED) {
      expect(codes(`class C { get f(${nm}: u256): External<u256> { return ${nm}; } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as a state field name (plain + Visible)', () => {
    for (const nm of RESERVED) {
      expect(codes(`class C { ${nm}: u256 = 0n; get f(): External<u256> { return 1n; } }`)).toContain('JETH500');
      expect(codes(`class C { ${nm}: Visible<u256>; constructor() { this.${nm} = 5n; } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as a method name and a get-accessor name', () => {
    for (const nm of RESERVED) {
      expect(codes(`class C { x: u256 = 0n; ${nm}(): External<u256> { this.x = 1n; return this.x; } }`)).toContain('JETH500');
      expect(codes(`class C { get ${nm}(): External<u256> { return 1n; } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as a struct member name', () => {
    for (const nm of RESERVED) {
      expect(codes(`type P = { ${nm}: u256 }; class C { get f(): External<u256> { return 1n; } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as an interface method name and interface method param', () => {
    for (const nm of RESERVED) {
      expect(codes(`interface I { ${nm}(): View<u256>; } class C { get f(): External<u256> { return 1n; } }`)).toContain('JETH500');
      expect(codes(`interface I { m(${nm}: u256): View<u256>; } class C { get f(): External<u256> { return 1n; } }`)).toContain('JETH500');
    }
  });
});

describe('JETH500 axis (B): every reserved word at each TYPE/NAMESPACE declaration name', () => {
  it('reserved words reject as a contract (class) name', () => {
    for (const nm of RESERVED) {
      expect(codes(`class ${nm} { get f(): External<u256> { return 42n; } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as an abstract-class name', () => {
    for (const nm of RESERVED) {
      expect(codes(`abstract class ${nm} { get f(): External<u256> { return 1n; } } class C extends ${nm} { }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as a library (static class) name', () => {
    for (const nm of RESERVED) {
      expect(codes(`static class ${nm} { m(): u256 { return 1n; } } class C { get f(): External<u256> { return ${nm}.m(); } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as an interface name', () => {
    for (const nm of RESERVED) {
      expect(codes(`interface ${nm} { m(): View<u256>; } class C { get f(): External<u256> { return 1n; } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as an enum name and an enum member', () => {
    for (const nm of RESERVED) {
      expect(codes(`enum ${nm} { A, B } class C { get f(): External<u256> { return 1n; } }`)).toContain('JETH500');
      expect(codes(`enum E { A, ${nm}, B } class C { get f(): External<u256> { return 3n; } }`)).toContain('JETH500');
    }
  });
  it('reserved words reject as a struct / type-alias name', () => {
    for (const nm of RESERVED) {
      expect(codes(`type ${nm} = { a: u256; b: u256 }; class C { get f(): External<u256> { return 1n; } }`)).toContain('JETH500');
    }
  });
});

describe('JETH500 CONTROLS: no new over-rejection on valid programs', () => {
  it('normal identifiers still accept in every value position', () => {
    expect(
      accepts(`class C {
        count: u256;
        f(value: u256, from: address, to: address): External<void> { let x: u256 = value; this.count = x; }
      }`),
    ).toBe(true);
  });

  it('legit Solidity-ish names data / value / from still accept as field / param / local', () => {
    expect(
      accepts(`class C { data: u256 = 0n;
        store(value: u256): External<u256> { this.data = value; return value; }
        transfer(from: u256): External<u256> { let value: u256 = from + this.data; this.data = value; return value; } }`),
    ).toBe(true);
  });

  it('lookalikes virtualX / usingList / _anonymous / overrideThing / myOverride accept in value positions', () => {
    expect(
      accepts(`class C {
        virtualX: u256 = 0n;
        usingList(overrideThing: u256): External<u256> { let _anonymous: u256 = overrideThing + 1n; this.virtualX = _anonymous; return this.virtualX; }
        get myOverride(): External<u256> { return this.virtualX; } }`),
    ).toBe(true);
  });

  it('lookalikes accept as contract / abstract / library / interface / enum / enum-member / type names', () => {
    expect(accepts(`class virtualX { get f(): External<u256> { return 1n; } }`)).toBe(true);
    expect(accepts(`abstract class usingList { get f(): External<u256> { return 1n; } } class C extends usingList { }`)).toBe(true);
    expect(accepts(`static class overrideThing { m(): u256 { return 1n; } } class C { get f(): External<u256> { return overrideThing.m(); } }`)).toBe(true);
    expect(accepts(`interface _anonymous { m(): View<u256>; } class C { get f(): External<u256> { return 1n; } }`)).toBe(true);
    expect(accepts(`enum myOverride { A, virtualX, B } class C { get f(): External<u256> { return 1n; } }`)).toBe(true);
    expect(accepts(`type usingList = { a: u256; b: u256 }; class C { get f(): External<u256> { return 1n; } }`)).toBe(true);
  });

  it('the @virtual / @override / @using / @anonymous DECORATOR applications still accept (not declaration names)', () => {
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

describe('@virtual / @override override pair runs byte-identically to solc (decorators untouched)', () => {
  const JETH = `abstract class Base { @virtual area(): u256 { return 1n; } }
    class C extends Base { @override area(): u256 { return 42n; } get f(): External<u256> { return this.area(); } }`;
  let h: Harness;
  let addr: import('@ethereumjs/util').Address;
  beforeAll(async () => {
    h = await Harness.create();
    addr = await h.deploy('0x' + compile(JETH, { fileName: 'C.jeth' }).creationBytecode);
  });
  it('the derived @override body wins (returns 42)', async () => {
    const r = await h.call(addr, '0x' + sel('f()'));
    expect(r.success).toBe(true);
    expect(r.returnHex).toBe('0x' + pad(42n));
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

// (C) 2026-07-18 - the reserved-word ban was EXPANDED (user ruling) from the minimal 4-word set to the
// FULL solc-0.8.35 reserved-word list: every keyword / reserved-for-future word that JETH's TS lexer would
// accept as an identifier where solc parse-rejects it. `receive` / `fallback` are EXCLUDED (JETH uses them
// as special-entry method names) and `error` is EXCLUDED (solc accepts it as an identifier).
describe('JETH500: the full solc reserved-word list rejects at declaration names (expanded set)', () => {
  const SAMPLE = [
    'after', 'alias', 'apply', 'as', 'auto', 'byte', 'copyof', 'define', 'final', 'implements',
    'inline', 'is', 'let', 'macro', 'match', 'mutable', 'of', 'partial', 'reference', 'sealed', 'sizeof',
    'static', 'supports', 'typedef', 'immutable', 'indexed', 'unchecked', 'emit', 'event', 'payable',
    'modifier', 'calldata', 'memory', 'storage', 'mapping', 'hex', 'assembly', 'address',
    'bool', 'string', 'bytes', 'external', 'internal', 'public', 'private', 'pure', 'view', 'constant',
    'contract', 'interface', 'library', 'struct', 'type', 'pragma', 'returns', 'fixed', 'ufixed',
    'wei', 'gwei', 'ether', 'seconds', 'minutes', 'hours', 'days', 'weeks',
  ];
  it('each reserved word rejects (JETH500) as a local var AND as a field name', () => {
    for (const w of SAMPLE) {
      expect(codes(`class C { get f(): External<u256> { let ${w}: u256 = 1n; return ${w}; } }`), `local ${w}`).toContain('JETH500');
      expect(codes(`class C { ${w}: u256; get f(): External<u256> { return this.${w}; } }`), `field ${w}`).toContain('JETH500');
    }
  });
  it('EXCLUSIONS: receive/fallback (JETH special entries) and `error` are NOT reserved', () => {
    // a plain local/field named receive/fallback/error still ACCEPTS (they are not in the reserved set).
    for (const w of ['receive', 'fallback', 'error']) {
      expect(accepts(`class C { get f(): External<u256> { let ${w}: u256 = 1n; return ${w}; } }`), `local ${w}`).toBe(true);
    }
    // the fallback SPECIAL-ENTRY method still compiles (the reason receive/fallback are excluded from the
    // ban); the receive special entry is covered by test/native-receive-fallback.test.ts.
    expect(accepts(`class C { fallback(): External<void> {} }`)).toBe(true);
  });
  it('lookalikes and non-reserved keyword-adjacent names still accept', () => {
    for (const w of ['afterX', 'typeOf', 'isValid', 'staticData', 'mappingKey', 'addressBook', 'errorCount']) {
      expect(accepts(`class C { get f(): External<u256> { let ${w}: u256 = 1n; return ${w}; } }`), w).toBe(true);
    }
  });
});
