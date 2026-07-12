// Class-body enum modifier residue (the JETH476/479 silent-recovery family, JETH484/JETH485).
//
// hoistInClassEnums (src/parser.ts) deliberately hoists a class-body `enum Name { ... }` to file level
// before parsing (solc allows contract-scoped enums; TS does not allow enum class members). THE HOLE it
// left: the scanner matched only the `enum Name { ... }` text, so a PRECEDING modifier keyword
// (`const` / `export` / `declare` / `static` / ...) was stranded in the class body, where TS
// error-recovered it into (a) a modifier on the NEXT member (`static` would silently change its
// meaning) or (b) a keyword-named phantom PropertyDeclaration with no type and no initializer - and the
// analyzer silently ignored both. At base b725454 every reject shape below COMPILED with zero
// diagnostics (non-vacuity proven by probe before the fix).
//
// The fix, two prongs:
//   JETH484 (parser scanner + compile.ts): a class-body enum preceded by a modifier keyword is NOT
//           hoisted and rejects loudly, naming the fix.
//   JETH485 (validator.ts, beside the JETH479 walk): the GENERAL stray-token residue - a `const` /
//           `export` member modifier (never legal TS), a `declare` member modifier (legal TS, no
//           on-chain meaning, mirroring the JETH479 declare-on-let reject), and ANY typeless,
//           initializerless PropertyDeclaration (keyword-named or not) reject loudly.
//
// Controls: the designed hoist stays byte-identical to a solc contract-scoped-enum mirror (run+decode);
// file-level `export enum` (the multi-file import mechanism) stays legal; fields NAMED like keywords
// (`constant: u256`, even a typed `const: u256`) stay accepted.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

function rejects(jeth: string, sources?: Record<string, string>): { codes: string[]; messages: string[] } {
  try {
    compile(jeth, { fileName: 'C.jeth', ...(sources ? { sources } : {}) });
    return { codes: [], messages: [] };
  } catch (e: unknown) {
    const diags = (e as { diagnostics?: { code: string; message: string }[] })?.diagnostics ?? [];
    return { codes: diags.map((d) => d.code), messages: diags.map((d) => d.message) };
  }
}

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + (args ?? ''));
    const rs = await hs.call(as, sel(sig) + (args ?? ''));
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

const G = ' get g(): External<u256> { return 1n; } }';

describe('JETH484: a class-body enum cannot carry a modifier keyword', () => {
  it.each(['const', 'export', 'declare', 'static', 'abstract', 'readonly', 'public', 'accessor'])(
    'rejects `%s enum E { A, B }` in a class body',
    (mod) => {
      const r = rejects(`class C { ${mod} enum E { A, B }\n${G}`);
      expect(r.codes).toContain('JETH484');
    },
  );
  it('rejects a STACKED modifier run (`export const enum`) and names both words + the fix', () => {
    const r = rejects(`class C { export const enum E { A, B }\n${G}`);
    expect(r.codes).toEqual(['JETH484']);
    expect(r.messages[0]).toContain("'export const'");
    expect(r.messages[0]).toContain("plain 'enum E { ... }'");
    expect(r.messages[0]).toContain('file level');
  });
  it('rejects across line breaks and comments between the modifier and the enum', () => {
    expect(rejects(`class C { const\n enum E {\n A,\n B\n }\n${G}`).codes).toContain('JETH484');
    expect(rejects(`class C { const /* why */ enum E { A, B }\n${G}`).codes).toContain('JETH484');
  });
  it('rejects a modifier-preceded enum in an IMPORTED dep file class body too (loudly, via JETH476)', () => {
    // The dep is parsed for export discovery BEFORE the bundle reaches the JETH484 gate; with the
    // modifier-enum no longer hoisted, TS error-recovery there trips the pre-existing JETH476
    // import-robustness reject first. Either code is a loud, sound reject; assert it is not silent.
    const r = rejects('import { D } from "./d.jeth";\nclass C { d: D;' + G, {
      'd.jeth': 'export class D { const enum E { A, B }\n get f(): External<u256> { return 1n; } }',
    });
    expect(r.codes.length).toBeGreaterThan(0);
    expect(r.codes.some((c) => c === 'JETH484' || c === 'JETH476')).toBe(true);
  });
});

describe('JETH485: stray-keyword residue in a class body rejects loudly', () => {
  it('rejects a lone `const` token (ASI phantom property named const)', () => {
    expect(rejects(`class C { const\n${G}`).codes).toContain('JETH485');
  });
  it('rejects a lone `declare` token (ASI phantom property named declare)', () => {
    expect(rejects(`class C { declare\n${G}`).codes).toContain('JETH485');
  });
  it('rejects a stray `const` recovered as a member MODIFIER (same line as the next member)', () => {
    expect(rejects(`class C { const${G}`).codes).toContain('JETH485');
  });
  it('rejects a stray `export` recovered as a member MODIFIER', () => {
    expect(rejects(`class C { export${G}`).codes).toContain('JETH485');
    expect(rejects(`class C { export\n${G}`).codes).toContain('JETH485');
  });
  it("rejects a `declare` field (`declare x: u256`): TS ambient syntax with no on-chain meaning", () => {
    expect(rejects(`class C { declare x: u256;${G}`).codes).toContain('JETH485');
  });
  it('rejects ANY typeless, initializerless field (`x` / `x!`): it has no on-chain meaning', () => {
    expect(rejects(`class C { x\n${G}`).codes).toContain('JETH485');
    expect(rejects(`class C { x!\n${G}`).codes).toContain('JETH485');
  });
  it('a trailing stray keyword at the END of the class body rejects too', () => {
    expect(rejects('class C { get g(): External<u256> { return 1n; }\n const }').codes).toContain('JETH485');
  });
});

describe('controls: the designed hoist + keyword-adjacent legit shapes stay accepted', () => {
  it('a plain mid-class enum stays byte-equivalent to a solc contract-scoped enum (run+decode)', async () => {
    await eqCalls(
      'class C { enum E { A, B, Z }\n get g(): External<u8> { return u8(E.Z); } }',
      'contract C { enum E { A, B, Z }\n function g() external pure returns (uint8) { return uint8(E.Z); } }',
      [['g()', '']],
    );
  });
  it('file-level enum and file-level `export enum` (single file) stay accepted', () => {
    expect(rejects('enum E { A, B }\nclass C { get g(): External<u256> { return u256(E.B); } }').codes).toEqual([]);
    expect(rejects('export enum E { A, B }\nclass C { get g(): External<u256> { return u256(E.B); } }').codes).toEqual([]);
  });
  it('file-level `export enum` in a DEP file (the import mechanism) stays accepted', () => {
    const r = rejects('import { E } from "./d.jeth";\nclass C { get g(): External<u256> { return u256(E.B); } }', {
      'd.jeth': 'export enum E { A, B }',
    });
    expect(r.codes).toEqual([]);
  });
  it('`const` as an ordinary declaration inside a method body stays accepted', () => {
    expect(rejects('class C { get g(): External<u256> { const x: u256 = 5n; return x; } }').codes).toEqual([]);
  });
  it('fields NAMED like keywords stay accepted when typed (constant / exported / even const)', () => {
    expect(rejects('class C { constant: u256; get g(): External<u256> { return this.constant; } }').codes).toEqual([]);
    expect(rejects('class C { exported: u256; get g(): External<u256> { return this.exported; } }').codes).toEqual([]);
    expect(rejects(`class C { const: u256;${G}`).codes).toEqual([]);
  });
  it('a `static` class-level const (the legit static modifier) stays accepted', () => {
    expect(rejects('class C { static K: u256 = 5n; get g(): External<u256> { return C.K; } }').codes).toEqual([]);
  });
  it('a field name merely STARTING with a modifier word does not arm the scanner (`statics; enum` hoists)', () => {
    expect(
      rejects('class C { statics: u256;\n enum E { A, B }\n get g(): External<u256> { return u256(E.B); } }').codes,
    ).toEqual([]);
  });
  it('a typed field followed by an enum does not arm the scanner (`readonly: u256; enum E` hoists)', () => {
    expect(
      rejects('class C { readonly: u256;\n enum E { A, B }\n get g(): External<u256> { return u256(E.B); } }').codes,
    ).toEqual([]);
  });
});
