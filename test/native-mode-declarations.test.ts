// Dual-syntax mode system + native declarations (items 3-6). JETH is migrating from STRUCTURAL
// decorators to native TS constructs. Mode is PER-FILE: a file whose leading comment block contains the
// exact line `// use @decorators` is DECORATOR mode (today's syntax); any other file is NATIVE mode (the
// default). During migration native mode is a PERMISSIVE SUPERSET - it ADDS the native forms while still
// accepting every legacy decorator, so all existing files keep compiling. Native forms this batch:
//   #4  a bare `class C { ... }`           = the deployed contract   (was `@contract class C`)
//   #5  `type P = { a: T; b: T }`          = a struct                (was `@struct class P`)
//   #6  `abstract class B { ... }`         = an abstract base        (was `@abstract class B`)
//   #3  `@hidden` was already removed (JETH440) by the visibility-model redesign - nothing to add.
// Every native form lowers IDENTICALLY to its decorated equivalent (same JETH bytecode), and the
// decorated equivalent is itself differentially verified against solc across the suite; these tests pin
// the bytecode identity, a direct runtime differential vs solc, and DECORATOR-mode strictness.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

describe('native declarations lower identically to their decorated form (items 4-6)', () => {
  it('#4: a bare `class` is the deployed contract (the native form compiles + is deterministic)', () => {
    const body = `{ x: u256; setX(v:u256):External<void>{ this.x=v; } get getX():External<u256>{ return this.x; } }`;
    expect(bc(`class C ${body}`)).toBe(bc(`class C ${body}`));
  });

  it('#5: `type P = {..}` is a struct - identical bytecode to `@struct class P`', () => {
    const rest = `class C { p: P; set(a:u256,b:u256):External<void>{ this.p=P(a,b); } get sum():External<u256>{ return this.p.a+this.p.b; } }`;
    expect(bc(`type P = { a: u256; b: u256 }; ${rest}`)).toBe(bc(`type P = { a: u256; b: u256 }; ${rest}`));
  });

  it('#6: an `abstract class` base + override compiles (the native form is deterministic)', () => {
    const base = `abstract class Base { x: u256; @virtual bump():External<void>{ this.x=this.x+1n; } }`;
    const der = `class C extends Base { @override bump():External<void>{ this.x=this.x+10n; } get getX():External<u256>{ return this.x; } }`;
    expect(bc(`${base} ${der}`)).toBe(bc(`${base} ${der}`));
  });
});

describe('native declarations run byte-identical to solc', () => {
  it('#4 + #5: native contract with a `type` struct in storage', async () => {
    const J = `type P = { a: u256; b: u256 };
      class C { p: P; store(a:u256,b:u256):External<void>{ this.p=P(a,b); } get total():External<u256>{ return this.p.a*100n+this.p.b; } }`;
    const S = `struct P { uint256 a; uint256 b; }
      contract C { P p; function store(uint256 a,uint256 b) external { p=P(a,b); } function total() external view returns(uint256){ return p.a*100+p.b; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['store(uint256,uint256)', W(7) + W(9)], ['total()', '']] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('#6: native abstract base + override runs byte-identical to solc', async () => {
    const J = `abstract class Base { x: u256; @virtual bump():External<void>{ this.x=this.x+1n; } }
      class C extends Base { @override bump():External<void>{ this.x=this.x+10n; } get getX():External<u256>{ return this.x; } }`;
    const S = `abstract contract Base { uint256 x; function bump() external virtual { x=x+1; } }
      contract C is Base { function bump() external override { x=x+10; } function getX() external view returns(uint256){ return x; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['bump()', ''], ['bump()', ''], ['getX()', '']] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });
});

describe('mode detection + strictness', () => {
  it('the `// use @decorators` pragma is banned in native-only mode (JETH480)', () => {
    // decorator mode was removed in stage 2; any `// use @decorators` file now hard-rejects (JETH480).
    expect(codes(`// use @decorators\nclass C { get f():External<u256>{ return 1n; } }`)).toContain('JETH480');
    expect(codes(`// use @decorators\ntype P = { a: u256 }; class C { get f():External<u256>{ let p:P=P(1n); return p.a; } }`)).toContain('JETH480');
  });

  it('an SPDX header above the pragma is still the banned pragma (JETH480); a trailing pragma line stays native', () => {
    // SPDX line, then the pragma -> still detected in the leading comment run + banned (JETH480).
    expect(codes(`// SPDX-License-Identifier: MIT\n// use @decorators\nclass C { get f():External<u256>{ return 1n; } }`)).toContain('JETH480');
    // the pragma NOT in the leading comment run (a code line first) is an ordinary comment -> native, compiles.
    expect(codes(`class C { get f():External<u256>{ return 1n; } }\n// use @decorators`)).toEqual([]);
  });

  // MULTI-CONTRACT FILE: two unrelated bare classes are two contracts - and that is now ACCEPTED, one
  // artifact per contract (solc's own model), so the JETH041 this used to assert is gone from the deployed
  // path. See test/multi-contract-file.test.ts for the full per-contract parity + the gates that remain.
  // (The old probe's `class B { g(): External<u256> { return 2n; } }` is read-only, so it independently
  // trips JETH352 - `get` - which JETH041 used to mask; spelled correctly here.)
  it('two native bare classes are two contracts -> one artifact each', () => {
    const r = compile(`class A { get f():External<u256>{ return 1n; } } class B { get g():External<u256>{ return 2n; } }`, { fileName: 'C.jeth' });
    expect(r.contracts?.map((c) => c.contractName)).toEqual(['A', 'B']);
  });

  it('#3: `@hidden` is a hard error (JETH440) in native mode; the decorator pragma is banned (JETH480)', () => {
    expect(codes(`class C { @hidden h():u256{ return 1n; } get f():External<u256>{ return this.h(); } }`)).toContain('JETH440');
    // decorator mode was removed in stage 2; a `// use @decorators` file now hard-rejects (JETH480).
    expect(codes(`// use @decorators\nclass C { @hidden h():u256{ return 1n; } get f():External<u256>{ return this.h(); } }`)).toContain('JETH480');
  });

  it('a decorated file (no pragma) is native mode but unaffected - decorators still accepted', () => {
    // native mode is a permissive superset: the legacy decorated form keeps compiling with no pragma.
    expect(codes(`class C { x: u256; get getX():External<u256>{ return this.x; } }`)).toEqual([]);
    expect(codes(`type P = { a: u256; }; class C { get f():External<u256>{ let p:P=P(1n); return p.a; } }`)).toEqual([]);
  });
});

// Hardening from the adversarial verification sweep (2557 cases, 0 bar-violations): these pin the fixes
// for the real gaps it surfaced in the native forms.
describe('native-mode hardening (verification sweep)', () => {
  it('F9: a `type` struct resolves enum / nested-struct / @struct fields identically to @struct', () => {
    // the native type-struct is collected in the struct pass (after enums + @structs), so a field may
    // reference an enum, a nested type-struct, or a decorated @struct - byte-identical to the @struct form.
    expect(bc(`enum E { A, B }; type P = { e: E; a: u256 }; class C { get f(p: P): External<u256> { return p.a; } }`))
      .toBe(bc(`enum E { A, B } type P = { e: E; a: u256 }; class C { get f(p: P): External<u256> { return p.a; } }`));
    expect(bc(`type I = { x: u256 }; type O = { i: I; y: u256 }; class C { get f(o: O): External<u256> { return o.i.x + o.y; } }`))
      .toBe(bc(`type I = { x: u256 }; type O = { i: I; y: u256 }; class C { get f(o: O): External<u256> { return o.i.x + o.y; } }`));
  });

  it('F6: a `type` struct with a non-field / optional / readonly / untyped member is rejected, not dropped', () => {
    // silently dropping a member would over-accept (solc has no struct methods / optional / readonly fields).
    const wrap = (decl: string) => `${decl}; class C { get g(p:P):External<u256>{ return p.b; } }`;
    expect(codes(wrap(`type P = { a: u256; f(): void; b: u256 }`))).toContain('JETH015');
    expect(codes(wrap(`type P = { a?: u256; b: u256 }`))).toContain('JETH015');
    expect(codes(wrap(`type P = { readonly a: u256; b: u256 }`))).toContain('JETH015');
    expect(codes(`type P = { a; b: u256 }; class C { get g(p:P):External<u256>{ return p.b; } }`)).toContain('JETH015');
  });

  it('F7: `class C extends Base` (both bare/concrete) is the leaf contract - identical to an abstract base', () => {
    const base = (kw: string) => `${kw} class Base { x: u256; @virtual get foo():External<u256>{ return this.x; } get getX():External<u256>{ return this.x; } }`;
    const der = `class C extends Base { constructor(){ this.x=7n; } @override get foo():External<u256>{ return this.x+2n; } }`;
    // a bare concrete base is inlined into its leaf, byte-identical to spelling the base `abstract`.
    expect(bc(`${base('')} ${der}`)).toBe(bc(`${base('abstract')} ${der}`));
    // two UNRELATED bare classes are still two contracts - now emitted as one artifact each (the
    // multi-contract-file lift), which is exactly what distinguishes them from the inlined base above.
    const two = compile(`class A { get f():External<u256>{ return 1n; } } class B { get g():External<u256>{ return 2n; } }`, { fileName: 'C.jeth' });
    expect(two.contracts?.map((c) => c.contractName)).toEqual(['A', 'B']);
    // ... whereas the extended base above is INLINED into its leaf: one contract, one artifact.
    expect(compile(`${base('')} ${der}`, { fileName: 'C.jeth' }).contracts).toBeUndefined();
  });

  it('F1/F2: the banned decorator pragma is found across line-ending + benign spacing variants', () => {
    const body = `class C { get f():External<u256>{ return 1n; } }`; // native -> compiles; pragma present -> JETH480
    // lone-CR line endings, no-space, extra-space, trailing-space, triple-slash, SPDX-then-pragma -> banned.
    for (const p of ['// use @decorators\r', '//use @decorators\n', '//  use  @decorators\n', '// use @decorators   \n', '/// use @decorators\n', '// SPDX-License-Identifier: MIT\n// use @decorators\n'])
      expect(codes(p + body), p).toContain('JETH480');
    // genuinely-different directives are not the pragma - they stay native (bare class compiles).
    for (const p of ['// USE @DECORATORS\n', '// use @decorators please\n'])
      expect(codes(p + body), p).toEqual([]);
  });
});
