// BARE-BODYLESS METHOD vs IMPORTED-TYPE collision: single-vs-multi CODE-LIST parity (the JETH489
// short-circuit emulation in collectImportedMemberTypeCollisions). The single-file NON-DEPLOYABLE route
// (analyzeNonDeployableUnit) returns EARLY when any abstract class declares a bodyless method/get that is
// neither @virtual nor `abstract` (JETH489, "must be marked virtual") - BEFORE its JETH133 linearization
// gate ever runs - so the single-file code list for such a program is [JETH489] with NO JETH133; the
// ill-formed member is never counted as a shadowing member. The multi-file pre-pass previously counted
// EVERY MethodDeclaration, ADDING a JETH133 the single-file path cannot emit ([JETH133,JETH489] vs
// [JETH489]). The pre-pass now emulates the short-circuit: when the bundle takes the non-deployable route
// AND some abstract class trips the JETH489 gate, it emits nothing - the analyzer's own JETH489 (or its
// earlier JETH040/JETH041 gates, which return the same way) is the reject, exactly as single-file.
// The DEPLOYED route has NO such short-circuit (a deployed contract with a bare-bodyless colliding method
// rejects {JETH483,JETH380,JETH133} single-file, the linearization gate still counting the member), so a
// bundle WITH a deployed contract keeps the full pre-pass - those cells assert the suppression does NOT
// leak there. Every REJECT here is loud on both paths; no cell moves an accepted program to a reject or
// vice versa (verified against a 141-cell base-vs-fix adversarial sweep: 0 regressions, 0 acceptances).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const mcodes = (entry: string, sources: Record<string, string>): string[] => {
  try {
    compile(entry, { fileName: 'main.jeth', sources });
    return ['ACCEPT'];
  } catch (e: any) {
    return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW'];
  }
};
const scodes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'main.jeth' });
    return ['ACCEPT'];
  } catch (e: any) {
    return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW'];
  }
};
const sorted = (l: string[]): string[] => [...l].sort();

const DEP = 'export type Bad = error<{ a: u256 }>;';

describe('A: bare-bodyless COLLIDING method -> [JETH489] alone on BOTH paths (no pre-pass JETH133)', () => {
  it('A1/A2 own bare-bodyless Bad, abstract leaf: single == multi == [JETH489]', () => {
    const single = 'type Bad = error<{ a: u256 }>;\nabstract class C { Bad(): u256; g(): External<void> {} }';
    const entry = `import { Bad } from './d.jeth';\nabstract class C { Bad(): u256; g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH489']);
    expect(mcodes(entry, { 'd.jeth': DEP })).toEqual(['JETH489']);
  });

  it('INHERITED bare-bodyless Bad (imported abstract base), abstract leaf: single == multi == [JETH489]', () => {
    const single =
      'type Bad = error<{ a: u256 }>;\nabstract class B { Bad(): u256; }\n' +
      'abstract class C extends B { g(): External<void> {} }';
    const entry = `import { Bad } from './e.jeth';\nimport { B } from './b.jeth';\nabstract class C extends B { g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH489']);
    expect(mcodes(entry, { 'e.jeth': DEP, 'b.jeth': 'export abstract class B { Bad(): u256; }' })).toEqual(['JETH489']);
  });

  it('MIXED members (bare Bad + @virtual Worse, both colliding): the short-circuit drops BOTH JETH133s', () => {
    const single =
      'type Bad = error<{ a: u256 }>;\ntype Worse = error<{ b: u256 }>;\n' +
      'abstract class C { Bad(): u256; @virtual Worse(): u256; g(): External<void> {} }';
    const entry =
      `import { Bad } from './d.jeth';\nimport { Worse } from './w.jeth';\n` +
      `abstract class C { Bad(): u256; @virtual Worse(): u256; g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH489']);
    expect(mcodes(entry, { 'd.jeth': DEP, 'w.jeth': 'export type Worse = error<{ b: u256 }>;' })).toEqual(['JETH489']);
  });

  it('CONCRETE colliding Bad + bare-bodyless foo in the same abstract class: JETH489 still wins alone', () => {
    const single =
      'type Bad = error<{ a: u256 }>;\nabstract class C { Bad(): u256 { return 5n; } foo(): u256; g(): External<void> {} }';
    const entry = `import { Bad } from './d.jeth';\nabstract class C { Bad(): u256 { return 5n; } foo(): u256; g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH489']);
    expect(mcodes(entry, { 'd.jeth': DEP })).toEqual(['JETH489']);
  });

  it('two abstract leaves + a bare-bodyless member: single == multi == [JETH489]', () => {
    const single =
      'type Bad = error<{ a: u256 }>;\nabstract class B { foo(): u256; }\n' +
      'abstract class C { Bad(): u256 { return 5n; } g(): External<void> {} }';
    const entry = `import { Bad } from './d.jeth';\nimport { B } from './b.jeth';\nabstract class C { Bad(): u256 { return 5n; } g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH489']);
    expect(mcodes(entry, { 'd.jeth': DEP, 'b.jeth': 'export abstract class B { foo(): u256; }' })).toEqual(['JETH489']);
  });
});

describe('B/D controls: a @virtual / `abstract` bodyless colliding method IS a member -> [JETH133] both paths', () => {
  it('B own @virtual bodyless Bad: [JETH133] both', () => {
    const single = 'type Bad = error<{ a: u256 }>;\nabstract class C { @virtual Bad(): u256; g(): External<void> {} }';
    const entry = `import { Bad } from './d.jeth';\nabstract class C { @virtual Bad(): u256; g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH133']);
    expect(mcodes(entry, { 'd.jeth': DEP })).toEqual(['JETH133']);
  });

  it('D own `abstract` bodyless Bad: [JETH133] both', () => {
    const single = 'type Bad = error<{ a: u256 }>;\nabstract class C { abstract Bad(): u256; g(): External<void> {} }';
    const entry = `import { Bad } from './d.jeth';\nabstract class C { abstract Bad(): u256; g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH133']);
    expect(mcodes(entry, { 'd.jeth': DEP })).toEqual(['JETH133']);
  });

  it('INHERITED @virtual bodyless Bad (imported base), abstract leaf: [JETH133] both', () => {
    const single =
      'type Bad = error<{ a: u256 }>;\nabstract class B { @virtual Bad(): u256; }\n' +
      'abstract class C extends B { g(): External<void> {} }';
    const entry = `import { Bad } from './e.jeth';\nimport { B } from './b.jeth';\nabstract class C extends B { g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH133']);
    expect(mcodes(entry, { 'e.jeth': DEP, 'b.jeth': 'export abstract class B { @virtual Bad(): u256; }' })).toEqual(['JETH133']);
  });

  it('INHERITED `abstract` bodyless Bad (imported base), abstract leaf: [JETH133] both', () => {
    const single =
      'type Bad = error<{ a: u256 }>;\nabstract class B { abstract Bad(): u256; }\n' +
      'abstract class C extends B { g(): External<void> {} }';
    const entry = `import { Bad } from './e.jeth';\nimport { B } from './b.jeth';\nabstract class C extends B { g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH133']);
    expect(mcodes(entry, { 'e.jeth': DEP, 'b.jeth': 'export abstract class B { abstract Bad(): u256; }' })).toEqual(['JETH133']);
  });
});

describe('C / D3-D4 controls: non-colliding bodyless members are untouched', () => {
  it('C bare-bodyless foo (non-colliding): [JETH489] both', () => {
    const single = 'type Bad = error<{ a: u256 }>;\nabstract class C { foo(): u256; g(): External<void> {} }';
    const entry = `import { Bad } from './d.jeth';\nabstract class C { foo(): u256; g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH489']);
    expect(mcodes(entry, { 'd.jeth': DEP })).toEqual(['JETH489']);
  });

  it('C inherited bare-bodyless foo (non-colliding, imported base): [JETH489] both', () => {
    const single = 'abstract class B { foo(): u256; }\nabstract class C extends B { g(): External<void> {} }';
    const entry = `import { B } from './b.jeth';\nabstract class C extends B { g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH489']);
    expect(mcodes(entry, { 'b.jeth': 'export abstract class B { foo(): u256; }' })).toEqual(['JETH489']);
  });

  it('D3/D4 `abstract` foo (non-colliding): ACCEPT both', () => {
    const single = 'type Bad = error<{ a: u256 }>;\nabstract class C { abstract foo(): u256; g(): External<void> {} }';
    const entry = `import { Bad } from './d.jeth';\nabstract class C { abstract foo(): u256; g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['ACCEPT']);
    expect(mcodes(entry, { 'd.jeth': DEP })).toEqual(['ACCEPT']);
  });
});

describe('DEPLOYED route keeps the full pre-pass: the suppression never leaks onto it', () => {
  // Single-file emits the analyzer codes first and the multi-file bag lists the pre-pass JETH133 first,
  // so these multi-code cells are compared as SETS (the order difference predates this fix and is the
  // deployed-route diagnostic-collection order, not a behavior difference).
  it('own bare-bodyless colliding Bad in a DEPLOYED contract: {JETH483,JETH380,JETH133} both', () => {
    const single = 'type Bad = error<{ a: u256 }>;\nclass C { Bad(): u256; g(): External<void> {} }';
    const entry = `import { Bad } from './d.jeth';\nclass C { Bad(): u256; g(): External<void> {} }`;
    expect(sorted(scodes(single))).toEqual(['JETH133', 'JETH380', 'JETH483']);
    expect(sorted(mcodes(entry, { 'd.jeth': DEP }))).toEqual(['JETH133', 'JETH380', 'JETH483']);
  });

  it('INHERITED bare-bodyless colliding Bad, DEPLOYED leaf: {JETH380,JETH133} both', () => {
    const single =
      'type Bad = error<{ a: u256 }>;\nabstract class B { Bad(): u256; }\nclass C extends B { g(): External<void> {} }';
    const entry = `import { Bad } from './e.jeth';\nimport { B } from './b.jeth';\nclass C extends B { g(): External<void> {} }`;
    expect(sorted(scodes(single))).toEqual(['JETH133', 'JETH380']);
    expect(sorted(mcodes(entry, { 'e.jeth': DEP, 'b.jeth': 'export abstract class B { Bad(): u256; }' }))).toEqual([
      'JETH133',
      'JETH380',
    ]);
  });

  it('core V1 inherited-CONCRETE collision cell still rejects [JETH133] both', () => {
    const single =
      'type Bad = error<{ a: u256 }>;\nabstract class B { Bad(): u256 { return 5n; } }\n' +
      'class C extends B { g(): External<void> {} }';
    const entry = `import { Bad, B } from './d.jeth';\nclass C extends B { g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH133']);
    expect(mcodes(entry, { 'd.jeth': `${DEP}\nexport abstract class B { Bad(): u256 { return 5n; } }` })).toEqual([
      'JETH133',
    ]);
  });

  it('deployed bundle + UNRELATED abstract class with a bare-bodyless member: pre-pass still counts (no leak)', () => {
    // the abstract class with the bare-bodyless member does NOT suppress the deployed route's pre-pass
    const single =
      'type Bad = error<{ a: u256 }>;\nabstract class B { foo(): u256; }\n' +
      'class C { Bad(): u256 { return 5n; } g(): External<void> {} }';
    const entry = `import { Bad } from './d.jeth';\nimport { B } from './b.jeth';\nclass C { Bad(): u256 { return 5n; } g(): External<void> {} }`;
    expect(scodes(single)).toEqual(['JETH133']);
    expect(mcodes(entry, { 'd.jeth': DEP, 'b.jeth': 'export abstract class B { foo(): u256; }' })).toEqual(['JETH133']);
  });
});
