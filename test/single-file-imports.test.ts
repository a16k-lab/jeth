// JETH compiles a SINGLE file (one compilation unit). Import statements were previously SILENTLY IGNORED
// (parsed, resolved to nothing) - the imported name then failed downstream with a misleading
// unknown-identifier error while the import itself looked legitimate. They are now a loud reject (JETH035)
// until a real multi-file import system lands. The `export` MODIFIER on a declaration stays allowed
// (harmless today; forward-compatible with export-means-importable once imports exist).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';

const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

describe('single-file compilation: imports reject loudly, export modifiers are tolerated', () => {
  it('import declarations reject (JETH035) instead of silently resolving to nothing', () => {
    expect(codes(`import { MathLib } from "./libs.jeth";\nclass C { get f(): External<u256> { return 1n; } }`)).toContain('JETH035');
    expect(codes(`import type { P } from "./types.jeth";\nclass C { get f(): External<u256> { return 1n; } }`)).toContain('JETH035');
    // re-export statement forms too.
    expect(codes(`class C { get f(): External<u256> { return 1n; } }\nexport { C };`)).toContain('JETH035');
  });

  it('the `export` modifier on declarations is allowed (forward-compatible)', () => {
    expect(codes(`export class C { get f(): External<u256> { return 1n; } }`)).toEqual([]);
    expect(codes(`export static class L { f(): u256 { return 1n; } } export class C { get g(): External<u256> { return L.f(); } }`)).toEqual([]);
    expect(codes(`export type P = { a: u256 }; export class C { get f(p: P): External<u256> { return p.a; } }`)).toEqual([]);
  });
});
