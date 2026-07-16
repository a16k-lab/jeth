// Regression: the multi-file value-member shadow fix (rewriteModuleScopes) must NOT rename an
// `extends` heritage-clause base identifier even when a value member shares the base's name. solc
// shadows a name only in expression/type positions, never in the `is X` heritage clause, so
// `class C extends ImportedBase { ImportedBase: u256 }` is valid and must resolve the base. A naive
// shadow-skip left the heritage reference unrenamed and broke base resolution (JETH370 over-rejection).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const codes = (entry: string, sources: Record<string, string>): string[] => {
  try {
    compile(entry, { fileName: 'main.jeth', sources });
    return [];
  } catch (e: any) {
    return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW'];
  }
};

describe('imported base extended by a contract whose member shares the base name', () => {
  const dep = { './b.jeth': `export abstract class Base { p: u256; }` };

  it('extends an imported Base while declaring a member named Base COMPILES (solc accepts; was JETH370)', () => {
    const entry = `import { Base } from './b.jeth';
      class C extends Base { Base: u256; g(x: u256): External<void> { this.Base = x; this.p = x + 1n; } get v(): External<u256> { return this.Base + this.p; } }`;
    expect(codes(entry, dep)).toEqual([]);
  });

  it('byte-identical to the same program with the base declared in the entry file', () => {
    const imported = compile(
      `import { Base } from './b.jeth';\nclass C extends Base { Base: u256; g(x: u256): External<void> { this.Base = x; } get v(): External<u256> { return this.Base + this.p; } }`,
      { fileName: 'main.jeth', sources: dep },
    ).creationBytecode;
    const inline = compile(
      `abstract class Base { p: u256; }\nclass C extends Base { Base: u256; g(x: u256): External<void> { this.Base = x; } get v(): External<u256> { return this.Base + this.p; } }`,
      { fileName: 'main.jeth' },
    ).creationBytecode;
    expect(imported).toBe(inline);
  });

  it('the value-member collision with an imported ERROR still rejects (OA stays closed; JETH133 == single-file)', () => {
    // USER RULING (2026-07-16): multi-file == single-file EXACTLY across the name-collision family. The
    // single-file twin rejects [JETH133] at the declaration (blanket cross-scope gate), so the bundle now
    // rejects the identical [JETH133] (decl-level, collectImportedMemberTypeCollisions) instead of the old
    // use-site JETH129 - the OA this test guarded stays closed, with the single-file code.
    const depE = { './e.jeth': `export type Bad = error<{ z: u256 }>;` };
    const entry = `import { Bad } from './e.jeth';\nclass C { Bad: u256; g(): External<void> { revert(Bad(1n)); } }`;
    expect(codes(entry, depE)).toEqual(['JETH133']);
  });
});
