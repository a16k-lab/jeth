// MEMBER-vs-FILE-LEVEL-TYPE name collisions: SINGLE-vs-MULTI FILE PARITY (the unified rule).
// USER RULING (2026-07-16): multi-file behavior must equal single-file behavior EXACTLY - thrown code
// lists included - across the whole name-collision family. The single-file blanket gate (analyzeContract's
// cross-scope loops) is the language rule: a contract member of ONE kind (function = method/get accessor,
// storage = every field flavor, member error<{}>, member event<{}>, @modifier) sharing a name with a
// file-level error / event / struct / enum / interface / Brand rejects [JETH133] at the DECLARATION,
// used or unused, own or inherited, with EXACTLY three coexistence exemptions (witnessed): member error x
// file error, member event x file event (the member shadows - the C2 lift), and @modifier x file type.
// collectImportedMemberTypeCollisions (src/compile.ts) mirrors that gate over the imported (alpha-renamed)
// declarations for the route contract's full `extends` chain; every cell below asserts the multi-file code
// list EQUALS the single-file twin's, and the accept cells additionally assert BYTE-IDENTITY to the twin.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const scodes = (src: string): string[] => {
  try { compile(src, { fileName: 'main.jeth' }); return ['ACCEPT']; }
  catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};
const mcodes = (entry: string, sources: Record<string, string>): string[] => {
  try { compile(entry, { fileName: 'main.jeth', sources }); return ['ACCEPT']; }
  catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};
const sorted = (l: string[]): string[] => [...l].sort();

// file-level kinds: the inline decl, the dep-file export, and a USE exercising the file-level meaning
const FILE: Record<string, { decl: string; use: string }> = {
  error:  { decl: `type Bad = error<{ a: u256 }>;`, use: `f(): External<void> { revert(Bad(1n)); }` },
  event:  { decl: `type Bad = event<{ a: u256 }>;`, use: `f(): External<void> { emit(Bad(1n)); }` },
  struct: { decl: `type Bad = { a: u256 };`,        use: `f(): External<void> { let s: Bad = { a: 1n }; }` },
  enum:   { decl: `enum Bad { A, B }`,              use: `f(): External<void> { let s: Bad = Bad.A; }` },
  // the brand USE stays in TYPE position: a bare CONSTRUCTION call `Bad(v)` is the documented bare-call
  // companion residual (single resolves a bare call member-first and adds an incidental JETH074 to the
  // already-JETH133-rejected program; see the interface-cast residual test in member-shadow-import.test.ts)
  brand:  { decl: `type Bad = Brand<u256>;`,        use: `f(v: Bad): External<void> { let s: Bad = v; }` },
};

// member kinds (single-kind cells; the entry may need a struct prelude)
const MEMBER: Record<string, { decl: string; pre?: string }> = {
  plainField:  { decl: `Bad: u256;` },
  constant:    { decl: `static Bad: u256 = 7n;` },
  immutable:   { decl: `static Bad: u256; constructor(){ this.Bad = 7n; }` },
  mapping:     { decl: `Bad: mapping<u256, u256>;` },
  structTyped: { decl: `Bad: S;`, pre: `type S = { q: u256 };\n` },
  visible:     { decl: `Bad: Visible<u256>;` },
  getter:      { decl: `x: u256; get Bad(): External<u256> { return this.x; }` },
  method:      { decl: `Bad(): u256 { return 5n; }` },
  memberError: { decl: `Bad: error<{ b: address }>;` },
  memberEvent: { decl: `Bad: event<{ b: address }>;` },
  modifier:    { decl: `@modifier Bad() { _; }` },
};

describe('FULL MATRIX: member kind x file-level kind x {unused, used} - multi code list == single, cell by cell', () => {
  for (const [mk, m] of Object.entries(MEMBER)) {
    for (const [fk, f] of Object.entries(FILE)) {
      for (const used of [false, true]) {
        it(`${mk} x ${fk} x ${used ? 'USED' : 'unused'}`, () => {
          const pre = m.pre ?? '';
          const body = `${m.decl} g(): External<void> {} ${used ? f.use : ''}`;
          const single = scodes(`${f.decl}\n${pre}class C { ${body} }`);
          const multi = mcodes(`import { Bad } from "./d.jeth";\n${pre}class C { ${body} }`, { 'd.jeth': `export ${f.decl}` });
          // sorted-set comparison: where a companion code exists, the single bag lists analyzer codes
          // before its gate's JETH133 while the multi bag lists the pre-pass JETH133 first (the same
          // pre-existing collection-order difference the bare-bodyless parity suite documents).
          expect(sorted(multi)).toEqual(sorted(single));
          // non-vacuity of the flipped cells: every cross-kind pair is a JETH133 reject on BOTH paths
          const sameKind = (mk === 'memberError' && fk === 'error') || (mk === 'memberEvent' && fk === 'event');
          const modifierType = mk === 'modifier' && (fk === 'struct' || fk === 'enum' || fk === 'brand');
          if (sameKind) {
            if (!used) expect(multi).toEqual(['ACCEPT']); // coexistence: the member shadows (C2)
          } else if (modifierType) {
            expect(multi).toEqual(['ACCEPT']); // a modifier name is never used in a type position
          } else {
            expect(multi).toContain('JETH133');
          }
        });
      }
    }
  }
});

describe('INHERITED members (imported abstract base) reject [JETH133] == single-file', () => {
  const DEP_E = `export type Bad = error<{ a: u256 }>;`;
  it('inherited plain field, unused', () => {
    const multi = mcodes(`import { Bad } from "./e.jeth";\nimport { B } from "./b.jeth";\nclass C extends B { g(): External<void> {} }`,
      { 'e.jeth': DEP_E, 'b.jeth': `export abstract class B { Bad: u256; }` });
    expect(multi).toEqual(['JETH133']);
    expect(multi).toEqual(scodes(`type Bad = error<{ a: u256 }>;\nabstract class B { Bad: u256; }\nclass C extends B { g(): External<void> {} }`));
  });
  it('inherited get accessor, USED raise (the pinned G5 fork cell)', () => {
    const multi = mcodes(`import { Bad } from "./e.jeth";\nimport { B } from "./b.jeth";\nclass C extends B { f(): External<void> { revert(Bad(1n)); } }`,
      { 'e.jeth': DEP_E, 'b.jeth': `export abstract class B { x: u256; get Bad(): External<u256> { return this.x; } }` });
    expect(multi).toEqual(['JETH133']);
    expect(multi).toEqual(scodes(`type Bad = error<{ a: u256 }>;\nabstract class B { x: u256; get Bad(): External<u256> { return this.x; } }\nclass C extends B { f(): External<void> { revert(Bad(1n)); } }`));
  });
  it('DEP-file base + SAME-dep file-level error (both renamed - invisible to the analyzer): [JETH133] == single', () => {
    const multi = mcodes(`import { B } from "./b.jeth";\nclass C extends B { g(): External<void> {} }`,
      { 'b.jeth': `export type Bad = error<{ a: u256 }>;\nexport abstract class B { Bad: u256; }` });
    expect(multi).toEqual(['JETH133']);
    expect(multi).toEqual(scodes(`type Bad = error<{ a: u256 }>;\nabstract class B { Bad: u256; }\nclass C extends B { g(): External<void> {} }`));
  });
  it('inherited member ERROR x imported error stays ACCEPTED (same-kind coexistence through the chain)', () => {
    expect(mcodes(`import { Bad } from "./e.jeth";\nimport { B } from "./b.jeth";\nclass C extends B { g(): External<void> {} }`,
      { 'e.jeth': DEP_E, 'b.jeth': `export abstract class B { Bad: error<{ b: address }>; }` })).toEqual(['ACCEPT']);
  });
});

describe('ROUTE EMULATION: cells where the single-file gate never fires stay JETH133-free in multi too', () => {
  const DEP_E = `export type Bad = error<{ a: u256 }>;`;
  it('ABSTRACT-ONLY unit (non-deployable route): colliding field fires the leaf gate, [JETH133] both', () => {
    const multi = mcodes(`import { Bad } from "./d.jeth";\nabstract class C { Bad: u256; g(): External<void> {} }`, { 'd.jeth': DEP_E });
    expect(multi).toEqual(['JETH133']);
    expect(multi).toEqual(scodes(`type Bad = error<{ a: u256 }>;\nabstract class C { Bad: u256; g(): External<void> {} }`));
  });
  it('TWO abstract leaves (JETH041 short-circuit): colliding field -> [JETH041] alone on BOTH paths', () => {
    const single = scodes(`type Bad = error<{ a: u256 }>;\nabstract class A { Bad: u256; }\nabstract class Z { g(): External<void> {} }`);
    const multi = mcodes(`import { Bad } from "./d.jeth";\nabstract class A { Bad: u256; }\nabstract class Z { g(): External<void> {} }`, { 'd.jeth': DEP_E });
    expect(single).toEqual(['JETH041']);
    expect(multi).toEqual(['JETH041']);
  });
  it('TWO abstract leaves + colliding METHOD: [JETH041] alone both (the pre-pass no longer adds JETH133)', () => {
    const single = scodes(`type Bad = error<{ a: u256 }>;\nabstract class A { Bad(): u256 { return 5n; } }\nabstract class Z { g(): External<void> {} }`);
    const multi = mcodes(`import { Bad } from "./d.jeth";\nabstract class A { Bad(): u256 { return 5n; } }\nabstract class Z { g(): External<void> {} }`, { 'd.jeth': DEP_E });
    expect(single).toEqual(['JETH041']);
    expect(multi).toEqual(['JETH041']);
  });
  it('STRAY abstract class (deployed route, off the chain) with a colliding FIELD: ACCEPT both (== single)', () => {
    const single = scodes(`type Bad = error<{ a: u256 }>;\nabstract class S { Bad: u256; }\nclass C { g(): External<void> {} }`);
    const multi = mcodes(`import { Bad } from "./d.jeth";\nabstract class S { Bad: u256; }\nclass C { g(): External<void> {} }`, { 'd.jeth': DEP_E });
    expect(single).toEqual(['ACCEPT']);
    expect(multi).toEqual(['ACCEPT']);
  });
  it('KNOWN RESIDUAL - stray abstract class with a colliding METHOD keeps the legacy multi-only JETH133', () => {
    // The single-file gate never counts a stray's members (it accepts), but the legacy method-only stray
    // reject predates the ruling and removing it would flip a reject to an accept (forbidden). Documented
    // deliberate multi-file-only over-rejection; value members follow the single-file rule (cell above).
    expect(scodes(`type Bad = error<{ a: u256 }>;\nabstract class S { Bad(): u256 { return 5n; } }\nclass C { g(): External<void> {} }`)).toEqual(['ACCEPT']);
    expect(mcodes(`import { Bad } from "./d.jeth";\nabstract class S { Bad(): u256 { return 5n; } }\nclass C { g(): External<void> {} }`, { 'd.jeth': DEP_E })).toEqual(['JETH133']);
  });
  it('member name carrying TWO kinds (field + method): the analyzer WITHIN-scope JETH133 alone, both paths', () => {
    const body = `Bad: u256; Bad(): u256 { return 5n; } g(): External<void> {}`;
    const single = scodes(`type Bad = error<{ a: u256 }>;\nclass C { ${body} }`);
    const multi = mcodes(`import { Bad } from "./d.jeth";\nclass C { ${body} }`, { 'd.jeth': DEP_E });
    expect(single).toEqual(['JETH133']);
    expect(multi).toEqual(['JETH133']); // exactly ONE JETH133 - the pre-pass mirrors the gate's 1-kind-only rule
  });
  it('member typed by an error ALIAS is not counted (JETH013 unknown type, both paths, no JETH133)', () => {
    const single = scodes(`type Bad = event<{ a: u256 }>;\ntype E = error<{ b: address }>;\nclass C { Bad: E; g(): External<void> {} }`);
    const multi = mcodes(`import { Bad } from "./d.jeth";\nimport { E } from "./f.jeth";\nclass C { Bad: E; g(): External<void> {} }`,
      { 'd.jeth': `export type Bad = event<{ a: u256 }>;`, 'f.jeth': `export type E = error<{ b: address }>;` });
    expect(single).toEqual(['JETH013']);
    expect(multi).toEqual(['JETH013']);
  });
});

describe('BYTE-IDENTITY guards: every accept cell compiles byte-identical to its inline single-file twin', () => {
  const bytes = (entry: string, sources?: Record<string, string>): string =>
    compile(entry, { fileName: 'main.jeth', ...(sources ? { sources } : {}) }).creationBytecode;
  it('F4 member error x imported error - bare raise + this.Bad named-arg raise channels', () => {
    expect(bytes(`import { Bad } from "./e.jeth";\nclass C { Bad: error<{ b: address }>; f(a: address): External<void> { revert(Bad(a)); } }`, { 'e.jeth': `export type Bad = error<{ a: u256 }>;` }))
      .toBe(bytes(`type Bad = error<{ a: u256 }>;\nclass C { Bad: error<{ b: address }>; f(a: address): External<void> { revert(Bad(a)); } }`));
    expect(bytes(`import { Bad } from "./e.jeth";\nclass C { Bad: error<{ b: address }>; f(): External<void> { throw this.Bad({ b: msg.sender }); } }`, { 'e.jeth': `export type Bad = error<{ a: u256 }>;` }))
      .toBe(bytes(`type Bad = error<{ a: u256 }>;\nclass C { Bad: error<{ b: address }>; f(): External<void> { throw this.Bad({ b: msg.sender }); } }`));
  });
  it('F4 member event x imported event - bare emit + this.Bad named-arg emit channels', () => {
    expect(bytes(`import { Bad } from "./e.jeth";\nclass C { Bad: event<{ b: address }>; f(a: address): External<void> { emit(Bad(a)); } }`, { 'e.jeth': `export type Bad = event<{ a: u256 }>;` }))
      .toBe(bytes(`type Bad = event<{ a: u256 }>;\nclass C { Bad: event<{ b: address }>; f(a: address): External<void> { emit(Bad(a)); } }`));
    expect(bytes(`import { Bad } from "./e.jeth";\nclass C { Bad: event<{ b: address }>; f(): External<void> { emit(this.Bad({ b: msg.sender })); } g(): External<void> { emit(Bad(msg.sender)); } }`, { 'e.jeth': `export type Bad = event<{ a: u256 }>;` }))
      .toBe(bytes(`type Bad = event<{ a: u256 }>;\nclass C { Bad: event<{ b: address }>; f(): External<void> { emit(this.Bad({ b: msg.sender })); } g(): External<void> { emit(Bad(msg.sender)); } }`));
  });
  it('heritage cell: extends an imported Base while declaring a member named Base (classes are OUTSIDE the gate)', () => {
    expect(bytes(`import { Base } from './b.jeth';\nclass C extends Base { Base: u256; g(x: u256): External<void> { this.Base = x; } get v(): External<u256> { return this.Base + this.p; } }`, { './b.jeth': `export abstract class Base { p: u256; }` }))
      .toBe(bytes(`abstract class Base { p: u256; }\nclass C extends Base { Base: u256; g(x: u256): External<void> { this.Base = x; } get v(): External<u256> { return this.Base + this.p; } }`));
  });
  it('non-colliding member + a legit import keeps resolving the import (byte-identical to inline)', () => {
    expect(bytes(`import { Bad } from "./e.jeth";\nclass C { gg(): u256 { return 1n; } f(): External<void> { revert(Bad(1n)); } }`, { 'e.jeth': `export type Bad = error<{ a: u256 }>;` }))
      .toBe(bytes(`type Bad = error<{ a: u256 }>;\nclass C { gg(): u256 { return 1n; } f(): External<void> { revert(Bad(1n)); } }`));
  });
});
