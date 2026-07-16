// INHERITED-METHOD-vs-IMPORTED-TYPE collision (multi-file). A CONTRACT-kind class whose VISIBLE method (own
// OR one inherited by walking the `extends` chain across imported files) shares a name with an in-scope
// IMPORTED file-level error / event / struct / enum / interface is an "Identifier already declared" reject:
// solc's member shadow leaves the file-level unusable, so `revert(Bad(1))` / `emit(Bad(1))` binds the 0-arg
// method ("Wrong argument count") and a type-position `Bad` gives "Name has to refer to a user-defined type".
// The SINGLE-FILE analyzer already rejects this JETH133 over the deployed contract's C3 linearization (own +
// inherited). But the v3 module rename mangles the imported `Bad` to `$mN$Bad`, and the 786b88e pre-pass only
// looked at OWN methods, so a bundle where the colliding method reached the use-site contract by INHERITANCE
// routed AROUND the gate (a residual over-acceptance). collectImportedMemberTypeCollisions now generalizes to
// VISIBLE methods (own UNION inherited via the merged-AST extends chain - multi-level, diamond, override,
// interface bases), emitting the SAME JETH133 the single-file path gives. Deliberate, user-endorsed reject
// (methods camelCase vs PascalCase types/errors/events), consistent single/multi-file even for a NO-USE
// shadow (solc accepts the pure shadow; JETH over-rejects it identically in both modes).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const mcodes = (entry: string, sources: Record<string, string>): string[] => {
  try {
    compile(entry, { fileName: 'main.jeth', sources });
    return [];
  } catch (e: any) {
    return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW'];
  }
};
const scodes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'main.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW'];
  }
};
const bc = (entry: string, sources: Record<string, string>): string =>
  compile(entry, { fileName: 'main.jeth', sources }).creationBytecode;

// per-kind: dep file-level type spelling + the use of the bare `Bad` inside the use-site contract
const KIND = {
  error: { decl: 'export type Bad = error<{ a: u256 }>;', use: 'f(): External<void> { revert(Bad(1n)); }' },
  event: { decl: 'export type Bad = event<{ a: u256 }>;', use: 'f(): External<void> { emit(Bad(1n)); }' },
  struct: { decl: 'export type Bad = { a: u256 };', use: 'f(): External<void> { let s: Bad = { a: 1n }; }' },
  enum: { decl: 'export enum Bad { A, B }', use: 'f(): External<void> { let s: Bad = Bad.A; }' },
  interface: {
    decl: 'export interface Bad { v(): View<u256>; }',
    use: 'f(a: address): External<void> { let s: Bad = Bad(a); }',
  },
} as const;

describe('INHERITED method collides with an imported file-level type/error/event -> JETH133 (V1-V4 + twins)', () => {
  // V1: base + error in the SAME dep file, entry imports both and extends the base
  for (const [kind, K] of Object.entries(KIND)) {
    it(`V1 ${kind}: base+decl same dep file, method inherited into entry contract`, () => {
      const dep = `${K.decl}\nexport abstract class B { Bad(): u256 { return 5n; } }`;
      const entry = `import { Bad, B } from './d.jeth';\nclass C extends B { ${K.use} }`;
      expect(mcodes(entry, { 'd.jeth': dep })).toContain('JETH133');
    });
  }

  it('V2: base / error / contract in THREE files', () => {
    const entry = `import { Bad } from './c.jeth';\nimport { B } from './b.jeth';\nclass C extends B { ${KIND.error.use} }`;
    expect(
      mcodes(entry, {
        'b.jeth': 'export abstract class B { Bad(): u256 { return 5n; } }',
        'c.jeth': 'export type Bad = error<{ a: u256 }>;',
      }),
    ).toContain('JETH133');
  });

  it('V3: 2-level chain B <- M <- C, error imported into the entry', () => {
    const entry = `import { Bad } from './c.jeth';\nimport { M } from './m.jeth';\nclass C extends M { ${KIND.error.use} }`;
    expect(
      mcodes(entry, {
        'b.jeth': 'export abstract class B { Bad(): u256 { return 5n; } }',
        'm.jeth': "import { B } from './b.jeth';\nexport abstract class M extends B { }",
        'c.jeth': 'export type Bad = error<{ a: u256 }>;',
      }),
    ).toContain('JETH133');
  });

  it('V4 event twin: emit(Bad(..)) with an inherited method Bad', () => {
    const dep = `export type Bad = event<{ a: u256 }>;\nexport abstract class B { Bad(): u256 { return 5n; } }`;
    const entry = `import { Bad, B } from './d.jeth';\nclass C extends B { ${KIND.event.use} }`;
    expect(mcodes(entry, { 'd.jeth': dep })).toContain('JETH133');
  });

  it('diamond: two bases, the colliding method reached through the SECOND base', () => {
    const entry =
      `import { Bad } from './e.jeth';\nimport { B1 } from './b1.jeth';\nimport { B2 } from './b2.jeth';\n` +
      `class C extends B1, B2 { ${KIND.error.use} }`;
    expect(
      mcodes(entry, {
        'e.jeth': 'export type Bad = error<{ a: u256 }>;',
        'b1.jeth': 'export abstract class B1 { foo(): u256 { return 1n; } }',
        'b2.jeth': 'export abstract class B2 { Bad(): u256 { return 5n; } }',
      }),
    ).toContain('JETH133');
  });

  it('override: C overrides the inherited Bad and still collides with the imported error', () => {
    const dep = `export type Bad = error<{ a: u256 }>;\nexport abstract class B { @virtual Bad(): u256 { return 5n; } }`;
    const entry = `import { Bad, B } from './d.jeth';\nclass C extends B { @override Bad(): u256 { return 6n; } ${KIND.error.use} }`;
    expect(mcodes(entry, { 'd.jeth': dep })).toContain('JETH133');
  });
});

describe('the inherited-method JETH133 matches the single-file linearization gate + no-use consistency', () => {
  it('NO-USE inherited collision rejects JETH133 in multi-file, matching the single-file all-in-one', () => {
    const dep = `export type Bad = error<{ a: u256 }>;\nexport abstract class B { Bad(): u256 { return 5n; } }`;
    const entry = `import { Bad, B } from './d.jeth';\nclass C extends B { n: u256; g(): External<void> { this.n = 1n; } }`;
    expect(mcodes(entry, { 'd.jeth': dep })).toContain('JETH133');
    const single =
      'type Bad = error<{ a: u256 }>;\nabstract class B { Bad(): u256 { return 5n; } }\n' +
      'class C extends B { n: u256; g(): External<void> { this.n = 1n; } }';
    expect(scodes(single)).toContain('JETH133');
  });

  it('the multi-file V1 reject is the SAME code the single-file all-in-one emits', () => {
    const dep = `export type Bad = error<{ a: u256 }>;\nexport abstract class B { Bad(): u256 { return 5n; } }`;
    const entry = `import { Bad, B } from './d.jeth';\nclass C extends B { ${KIND.error.use} }`;
    const single =
      'type Bad = error<{ a: u256 }>;\nabstract class B { Bad(): u256 { return 5n; } }\n' +
      `class C extends B { ${KIND.error.use} }`;
    expect(mcodes(entry, { 'd.jeth': dep })).toContain('JETH133');
    expect(scodes(single)).toContain('JETH133');
  });
});

describe('786b88e OWN-method collision cell still rejects (visible methods are a strict superset)', () => {
  it('own method Bad + imported error Bad -> JETH133', () => {
    const entry = `import { Bad } from './d.jeth';\nclass C { Bad(): u256 { return 5n; } ${KIND.error.use} }`;
    expect(mcodes(entry, { 'd.jeth': 'export type Bad = error<{ a: u256 }>;' })).toContain('JETH133');
  });
});

describe('value-member-shadow family still rejects (now the decl-level JETH133, single-file parity)', () => {
  // USER RULING (2026-07-16): multi-file behavior == single-file behavior EXACTLY across the whole
  // name-collision family. The single-file twin of this cell rejects [JETH133] at the DECLARATION (the
  // cross-scope member-vs-file-level gate), so the multi-file bundle now rejects the identical [JETH133]
  // via the generalized collectImportedMemberTypeCollisions pre-pass - not the old use-site JETH129.
  it('inherited value-member Bad colliding with an imported error rejects JETH133 (== single-file)', () => {
    const entry =
      `import { Bad } from './e.jeth';\nimport { Base } from './b.jeth';\n` +
      `class C extends Base { f(): External<void> { revert(Bad(1n)); } }`;
    expect(
      mcodes(entry, {
        'e.jeth': 'export type Bad = error<{ a: u256 }>;',
        'b.jeth': 'export abstract class Base { Bad: u256; }',
      }),
    ).toEqual(['JETH133']);
  });
});

describe('NON-COLLIDING inherited methods accept, byte-identical to the base with the chain inlined', () => {
  it('2-level chain, non-colliding method, legit imported error use -> ACCEPTS', () => {
    const entry =
      `import { M } from './m.jeth';\nexport type Bad = error<{ a: u256 }>;\n` +
      `class C extends M { f(): External<void> { revert(Bad(this.helper())); } }`;
    const sources = {
      'b.jeth': 'export abstract class B { helper(): u256 { return 5n; } }',
      'm.jeth': "import { B } from './b.jeth';\nexport abstract class M extends B { }",
    };
    expect(mcodes(entry, sources)).toEqual([]);
    // byte-identical to declaring the whole chain inline in one file
    const inline =
      'abstract class B { helper(): u256 { return 5n; } }\nabstract class M extends B { }\n' +
      'type Bad = error<{ a: u256 }>;\nclass C extends M { f(): External<void> { revert(Bad(this.helper())); } }';
    expect(bc(entry, sources)).toBe(compile(inline, { fileName: 'main.jeth' }).creationBytecode);
  });

  it('diamond (two bases), non-colliding -> ACCEPTS byte-identical to inline', () => {
    const entry =
      `import { B1 } from './b1.jeth';\nimport { B2 } from './b2.jeth';\n` +
      `class C extends B1, B2 { get f(): External<u256> { return this.foo() + this.bar(); } }`;
    const sources = {
      'b1.jeth': 'export abstract class B1 { foo(): u256 { return 1n; } }',
      'b2.jeth': 'export abstract class B2 { bar(): u256 { return 2n; } }',
    };
    expect(mcodes(entry, sources)).toEqual([]);
    const inline =
      'abstract class B1 { foo(): u256 { return 1n; } }\nabstract class B2 { bar(): u256 { return 2n; } }\n' +
      'class C extends B1, B2 { get f(): External<u256> { return this.foo() + this.bar(); } }';
    expect(bc(entry, sources)).toBe(compile(inline, { fileName: 'main.jeth' }).creationBytecode);
  });

  it('override, non-colliding -> ACCEPTS byte-identical to inline', () => {
    const entry =
      `import { B } from './b.jeth';\n` +
      `class C extends B { @override foo(): u256 { return 2n; } get f(): External<u256> { return this.foo(); } }`;
    const sources = { 'b.jeth': 'export abstract class B { @virtual foo(): u256 { return 1n; } }' };
    expect(mcodes(entry, sources)).toEqual([]);
    const inline =
      'abstract class B { @virtual foo(): u256 { return 1n; } }\n' +
      'class C extends B { @override foo(): u256 { return 2n; } get f(): External<u256> { return this.foo(); } }';
    expect(bc(entry, sources)).toBe(compile(inline, { fileName: 'main.jeth' }).creationBytecode);
  });

  it('inherited method named Bad but NO in-scope type/error/event of that name -> ACCEPTS', () => {
    const entry = `import { B } from './b.jeth';\nclass C extends B { get f(): External<u256> { return this.Bad(); } }`;
    expect(mcodes(entry, { 'b.jeth': 'export abstract class B { Bad(): u256 { return 5n; } }' })).toEqual([]);
  });

  it('a dep abstract base whose OWN same-file method shadows a same-file type is NOT over-rejected (solc accepts)', () => {
    const dep = 'export type Bad = error<{ a: u256 }>;\nexport abstract class B { Bad(): u256 { return 5n; } }';
    const entry = "import { B } from './d.jeth';\nclass C { n: u256; g(): External<void> { this.n = 1n; } }";
    expect(mcodes(entry, { 'd.jeth': dep })).toEqual([]);
  });
});

// An UNIMPLEMENTED interface method SIGNATURE does NOT shadow a free file-level error / event / struct / enum
// - in solc, in the single-file JETH133 linearization gate, and (after this corrective) in the multi-file
// pre-pass. An abstract contract that merely inherits the signature `Bad()` from an interface still binds a
// bare `Bad` to the in-scope file-level `Bad`, so `revert(Bad(1n))` / a `Bad`-typed local ACCEPTS. Only a
// concrete or bodyless-@virtual/abstract CLASS method named Bad shadows (the flip cells above). The
// generalization that closed the inherited-method over-acceptance briefly counted interface signatures too,
// over-rejecting this shape; the corrective restricts the shadow set back to class MethodDeclarations so
// multi-file == single-file == solc (all ACCEPT). Guards the over-rejection from silently returning.
describe('an UNIMPLEMENTED interface-signature inherit does NOT collide -> ACCEPTS (multi == single-file)', () => {
  for (const kind of ['error', 'event', 'struct', 'enum'] as const) {
    const K = KIND[kind];
    it(`${kind}: abstract C extends I{ Bad() } with an in-scope file-level ${kind} Bad -> ACCEPTS`, () => {
      const entry =
        `import { Bad } from './e.jeth';\nimport { I } from './i.jeth';\n` +
        `abstract class C extends I { ${K.use} }`;
      const sources = { 'e.jeth': K.decl, 'i.jeth': 'export interface I { Bad(): View<u256>; }' };
      // multi-file ACCEPTS (no JETH133) ...
      expect(mcodes(entry, sources)).toEqual([]);
      // ... exactly as the single-file all-in-one does (the decisive oracle).
      const single = `${K.decl}\ninterface I { Bad(): View<u256>; }\nabstract class C extends I { ${K.use} }`;
      expect(scodes(single)).toEqual([]);
      // and byte-identical to that inline program (both are the abstract-only artifact).
      expect(bc(entry, sources)).toBe(compile(single, { fileName: 'main.jeth' }).creationBytecode);
    });
  }
});
