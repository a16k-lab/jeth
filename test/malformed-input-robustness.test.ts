// MALFORMED-INPUT ROBUSTNESS (group C): four ways a malformed or pathological source used to compile
// SILENTLY (running a TS-error-recovered program the user never wrote) or CRASH RAW (no diagnostics).
// Each is now a LOUD clean reject; a clean reject always beats wrong bytes or a raw throw.
//
//  C1 JETH476  a TS parse error in ANY original file of a multi-file compilation (a malformed import
//              line: missing comma / missing `from` / trailing garbage) rejects at bundleImports time,
//              positioned in the offending file. Previously the bundler blanked the import lines before
//              the bundle parse, so the entry-level guard (JETH003, f0f3ee0) never saw the malformation
//              and the RECOVERED program compiled and ran. The `abi.decode(b, T[])` TS-1011 recovery
//              stays exempt (mirroring compile.ts).
//  C2 JETH477  a pathologically deep expression (a 2000-term `1n + 1n + ...` chain) overflowed the JS
//              call stack in whichever recursive visitor ran first, escaping as a raw RangeError in a
//              COLD process (a warmed process masks the crash - V8 optimization deepens the usable
//              stack, so the child-process test below is the real gate). solc COMPILES the mirror, so
//              this is a documented SAFE over-rejection - but the reject must be clean, never a throw.
//  C3 JETH478  a non-ASCII identifier (`café`, `函数`) sailed through to codegen and ICEd as JETH901
//              ("backend rejected generated Yul: Illegal token"). solc rejects unicode identifiers at
//              the lexer (ParserError), so a targeted early reject is PARITY. REGULAR-string content is
//              now gated too (C5/JETH499); TEMPLATE literals stay byte-identical, `\u`/`\x` escapes are
//              the portable form.
//  C5 JETH499  a RAW non-printable-ASCII / non-ASCII code point inside a REGULAR "..." / '...' string was
//              silently accepted (mapped to solc unicode"..." bytes) while solc's regular-string lexer
//              rejects it (only printable ASCII 0x20-0x7E + escapes; arbitrary Unicode needs unicode"...").
//              An over-acceptance; now a clean JETH499 reject. Escapes and TEMPLATE literals stay accepted.
//  H1 JETH501  a top-level statement that is not a supported declaration (a stray identifier / expression /
//              `if`/`for`/`return`/`;` / non-const file `let`) was SILENTLY IGNORED while solc rejects the
//              file. Now a clean JETH501 reject; every valid top-level declaration form still accepts.
//  C4 JETH479  a decorator on a `let` VariableStatement (`@only(this.boom()) let x = 7n;`) was SILENTLY
//              DROPPED with its argument's side effects (a lost state write): TS stores the decorator in
//              node.modifiers with only a GRAMMAR-phase error (TS1206, not a parse diagnostic), so both
//              the JETH061 statement gate and the parse-diagnostics net missed it. `declare let` (TS
//              ambient syntax) was silently treated as a plain let. Both invalid in Solidity too -
//              nothing to mirror; both-reject is the target.
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);

const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; }
  catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['RAW-THROW']; }
};
const mfDiag = (entry: string, sources: Record<string, string>): string[] => {
  try { compile(entry, { fileName: 'entry.jeth', sources }); return []; }
  catch (e: any) { return e?.diagnostics?.map((d: any) => `${d.code}@${d.file}:${d.line}`) ?? ['RAW-THROW']; }
};
const solRejects = (src: string): boolean => {
  try { compileSolidity(SPDX + src, 'C'); return false; } catch { return true; }
};

// ---------------------------------------------------------------------------------------------------
// C1 (JETH476): malformed import lines reject loudly, positioned in the offending file
// ---------------------------------------------------------------------------------------------------

const DEP_AB = `export abstract class A { ka(): u256 { return 111n; } }
export abstract class B { kb(): u256 { return 222n; } }
`;

describe('JETH476: a TS parse error in any original file of a multi-file compilation rejects loudly', () => {
  it('missing comma (`import { A B }`, recovered as TWO specifiers) no longer compiles the recovered program', () => {
    // the user plausibly meant `import { A as B }` (f()=111); recovery bound the REAL B (f()=222) and RAN.
    expect(mfDiag(
      `import { A B } from "./a.jeth";\nclass C extends B { get f(): External<u256> { return this.kb(); } }`,
      { 'a.jeth': DEP_AB },
    )).toEqual(['JETH476@entry.jeth:1']);
  });

  it('missing `from` (`import { A } "./a.jeth";`) rejects', () => {
    expect(mfDiag(
      `import { A } "./a.jeth";\nclass C extends A { get f(): External<u256> { return this.ka(); } }`,
      { 'a.jeth': DEP_AB },
    )).toEqual(['JETH476@entry.jeth:1']);
  });

  it('trailing garbage after the clause rejects', () => {
    expect(mfDiag(
      `import { A } from "./a.jeth" garbage;\nclass C extends A { get f(): External<u256> { return this.ka(); } }`,
      { 'a.jeth': DEP_AB },
    )).toEqual(['JETH476@entry.jeth:1']);
  });

  it('a malformed import INSIDE A DEP names the dep file + line', () => {
    expect(mfDiag(
      `import { A } from "./a.jeth";\nclass C extends A { get f(): External<u256> { return this.ka(); } }`,
      { 'a.jeth': `import { B X } from "./b.jeth";\nexport abstract class A { ka(): u256 { return 1n; } }`,
        'b.jeth': `export abstract class B { }\nexport abstract class X { }` },
    )).toEqual(['JETH476@a.jeth:1']);
  });

  it('the solc mirror of a malformed import line is a ParserError too (both-reject)', () => {
    expect(solRejects(`import { A B } from "./a.sol";\ncontract C {}`)).toBe(true);
  });

  it('NON-VACUITY: the valid import still compiles and RUNS (f()=111, a seeded read-back)', async () => {
    const out = compile(
      `import { A } from "./a.jeth";\nclass C extends A { get f(): External<u256> { return this.ka(); } }`,
      { fileName: 'entry.jeth', sources: { 'a.jeth': DEP_AB } },
    );
    const h = await Harness.create();
    const addr = await h.deploy(out.creationBytecode);
    const r = await h.call(addr, sel('f()'));
    expect(r.success).toBe(true);
    expect(r.returnHex).toBe('0x' + pad32(111n));
  });

  it('the abi.decode(b, T[]) TS-1011 recovery stays EXEMPT in a dep (still compiles)', () => {
    expect(mfDiag(
      `import { D } from "./d.jeth";\nclass C { get f(b: bytes): External<u256> { return D.first(b); } }`,
      { 'd.jeth': `export static class D { first(b: bytes): u256 { let v: u256[] = abi.decode(b, u256[]); return v[0n]; } }` },
    )).toEqual([]);
  });

  it('import aliases (`import { A as X }`) stay unregressed', () => {
    expect(mfDiag(
      `import { A as Base } from "./a.jeth";\nclass C extends Base { get f(): External<u256> { return this.ka(); } }`,
      { 'a.jeth': DEP_AB },
    )).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------------
// C2 (JETH477): deep-expression stack overflow converts to a clean diagnostic
// ---------------------------------------------------------------------------------------------------

describe('JETH477: a too-deeply-nested source rejects CLEANLY instead of a raw RangeError', () => {
  it('a 2000-term `1n + ...` chain in a FRESH child process yields JETH477, not a raw throw', () => {
    // COLD process required: a warmed process (this vitest worker) has a deeper usable stack and can
    // mask the crash. The child imports the real src/compile.ts via the tsx loader.
    const compileUrl = pathToFileURL(path.resolve(__dirname, '../src/compile.ts')).href;
    const script = `
      const { compile } = await import(${JSON.stringify(compileUrl)});
      const chain = Array(2000).fill('1n').join(' + ');
      try {
        compile('class C { get f(): External<u256> { return ' + chain + '; } }', { fileName: 'C.jeth' });
        console.log('COMPILED');
      } catch (e) {
        console.log(e && e.diagnostics ? 'CLEAN:' + e.diagnostics.map((d) => d.code).join(',') : 'RAW:' + String(e && e.message));
      }
    `;
    const out = execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], {
      cwd: path.resolve(__dirname, '..'),
      encoding: 'utf8',
      timeout: 110_000,
    });
    expect(out).toContain('CLEAN:JETH477');
  }, 120_000);

  it('ANCHOR: a 1500-term chain compiles in a fresh process and RUNS byte-identical to solc (f() = 0x5dc)', async () => {
    // The usable JS stack depth is environment-dependent (a vitest worker's is shallower than a plain
    // node process, where 1500 terms compiles fine), so the JETH side runs in a FRESH child process -
    // the same environment the 2000-term crash was adjudicated in. The solc mirror runs here.
    // The child gets an EXPLICIT --stack-size: the 1500-term compile deterministically needs ~800KB of
    // V8 stack while node's default is ~984KB (only ~18% headroom); under heavy machine load V8 sits in
    // larger interpreter frames longer and the child intermittently tripped the JETH477 RangeError guard,
    // making this anchor flaky. 1968KB (~2.5x need) makes it deterministic. The 2000-term REJECT test
    // above keeps the DEFAULT stack on purpose - its meaning is "the guard fires in a stock process".
    const compileUrl = pathToFileURL(path.resolve(__dirname, '../src/compile.ts')).href;
    const evmUrl = pathToFileURL(path.resolve(__dirname, '../src/evm.ts')).href;
    const selectorsUrl = pathToFileURL(path.resolve(__dirname, '../src/selectors.ts')).href;
    const script = `
      const { compile } = await import(${JSON.stringify(compileUrl)});
      const { Harness } = await import(${JSON.stringify(evmUrl)});
      const { functionSelector } = await import(${JSON.stringify(selectorsUrl)});
      const chain = Array(1500).fill('1n').join(' + ');
      const out = compile('class C { get f(): External<u256> { return ' + chain + '; } }', { fileName: 'C.jeth' });
      const h = await Harness.create();
      const addr = await h.deploy(out.creationBytecode);
      const r = await h.call(addr, '0x' + functionSelector('f()'));
      console.log('RESULT:' + r.success + ':' + r.returnHex);
    `;
    const out = execFileSync(process.execPath, ['--stack-size=1968', '--import', 'tsx', '--input-type=module', '-e', script], {
      cwd: path.resolve(__dirname, '..'),
      encoding: 'utf8',
      timeout: 110_000,
    });
    const chainS = Array(1500).fill('1').join(' + ');
    const h = await Harness.create();
    const as = await h.deploy(compileSolidity(SPDX + `contract C { function f() external pure returns (uint256) { return ${chainS}; } }`, 'C').creation);
    const rs = await h.call(as, sel('f()'));
    expect(rs.success).toBe(true);
    expect(rs.returnHex).toBe('0x' + pad32(1500n)); // 0x5dc
    expect(out).toContain(`RESULT:true:${rs.returnHex}`);
  }, 120_000);

  it('in-process, a deep chain either compiles or rejects CLEANLY with JETH477 - never a raw throw', () => {
    // in THIS (vitest-worker) environment the threshold sits lower than a plain process; either outcome
    // is sound - the invariant under test is "no raw RangeError escapes compile()".
    const chain = Array(1500).fill('1n').join(' + ');
    const got = codes(`class C { get f(): External<u256> { return ${chain}; } }`);
    expect(got.length === 0 || got.includes('JETH477')).toBe(true);
    expect(got).not.toContain('RAW-THROW');
  });

  it('deep paren nesting also converts cleanly (no raw throw from any phase)', () => {
    const parens = '('.repeat(3000) + '1n' + ')'.repeat(3000);
    const got = codes(`class C { get f(): External<u256> { return ${parens}; } }`);
    expect(got.length === 0 || got.includes('JETH477')).toBe(true);
    expect(got).not.toContain('RAW-THROW');
  });
});

// ---------------------------------------------------------------------------------------------------
// C3 (JETH478): non-ASCII identifiers reject early and targeted (solc parity), strings untouched
// ---------------------------------------------------------------------------------------------------

describe('JETH478: unicode identifiers reject cleanly (no more JETH901 ICE); template strings untouched', () => {
  it('unicode LOCAL rejects with JETH478 (previously JETH901)', () => {
    const got = codes(`class C { get f(): External<u256> { let café: u256 = 41n; return café + 1n; } }`);
    expect(got).toContain('JETH478');
    expect(got).not.toContain('JETH901');
  });

  it('unicode PARAM rejects', () => {
    expect(codes(`class C { get f(café: u256): External<u256> { return café; } }`)).toContain('JETH478');
  });

  it('unicode METHOD reached via this.函数() rejects', () => {
    const got = codes(`class C { 函数(): u256 { return 7n; } get f(): External<u256> { return this.函数(); } }`);
    expect(got).toContain('JETH478');
    expect(got).not.toContain('JETH901');
  });

  it('unicode ENTRY CLASS NAME rejects', () => {
    expect(codes(`class Café { get f(): External<u256> { return 1n; } }`)).toContain('JETH478');
  });

  it('unicode FIELD rejects (previously compiled silently while solc rejects)', () => {
    expect(codes(`class C { café: u256; get f(): External<u256> { return this.café; } }`)).toContain('JETH478');
  });

  it('the solc mirror rejects a unicode identifier at the lexer (both-reject = parity)', () => {
    expect(solRejects(`contract C { function f() external pure returns (uint256) { uint256 café = 41; return café + 1; } }`)).toBe(true);
  });

  it('an ESCAPED unicode regular string is byte-identical to solc unicode"..." (return form)', async () => {
    const h = await Harness.create();
    // c-a-f-(U+00E9) + space + U+1F600 written with \u / \x escapes (the portable form both compilers accept as a
    // REGULAR string); byte-identical to solc's unicode"..." literal. A RAW non-ASCII char here now rejects
    // (JETH499, C5 below) - matching solc's regular-string lexer.
    const aj = await h.deploy(compile('class C { get f(): External<string> { return "caf\\u00e9 \\xf0\\x9f\\x98\\x80"; } }', { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + `contract C { function f() external pure returns (string memory) { return unicode"café \u{1F600}"; } }`, 'C').creation);
    const rj = await h.call(aj, sel('f()'));
    const rs = await h.call(as, sel('f()'));
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
  });

  it('raw unicode STRING content stays byte-identical (template-literal form, distinct seed)', async () => {
    const h = await Harness.create();
    const aj = await h.deploy(compile(`class C { get f(s: string): External<string> { return \`héllo \u{1F600} \${s}!\`; } }`, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + `contract C { function f(string calldata s) external pure returns (string memory) { return string.concat(unicode"héllo \u{1F600} ", s, "!"); } }`, 'C').creation);
    const argHi = pad32(0x20n) + pad32(2n) + Buffer.from('hi', 'utf8').toString('hex').padEnd(64, '0');
    const rj = await h.call(aj, sel('f(string)') + argHi);
    const rs = await h.call(as, sel('f(string)') + argHi);
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
  });

  it('ASCII `$` and `_` identifiers stay legal (control)', () => {
    expect(codes(`class C { get f($a: u256): External<u256> { let x_y: u256 = $a + 1n; let $z: u256 = x_y * 2n; return $z; } }`)).toEqual([]);
  });

  it('unicode in COMMENTS stays legal (comments are not identifiers)', () => {
    expect(codes(`// café 函数 \u{1F600}\nclass C { /* héllo */ get f(): External<u256> { return 1n; } }`)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------------
// C4 (JETH479): decorators / `declare` on a VariableStatement reject instead of silently dropping
// ---------------------------------------------------------------------------------------------------

describe('JETH479: a decorator or `declare` on a variable statement rejects loudly (was a silent drop)', () => {
  it('the adjudicated repro: @only(this.boom()) let - decorator AND its side-effecting argument no longer dropped', () => {
    // previously compiled silently and f() returned 7 (the this.boom() state write was LOST; 107 was never
    // reachable). Invalid in Solidity too - both-reject is the target.
    expect(codes(`class C {
      s: u256;
      boom(): u256 { this.s = 100n; return 0n; }
      get f(): External<u256> { @only(this.boom()) let x: u256 = 7n; return x + this.s; }
    }`)).toEqual(['JETH479']);
  });

  it('@zzz / @view on a let each reject', () => {
    expect(codes(`class C { get f(): External<u256> { @zzz let x: u256 = 7n; return x; } }`)).toEqual(['JETH479']);
    expect(codes(`class C { get f(): External<u256> { @view let x: u256 = 7n; return x; } }`)).toEqual(['JETH479']);
  });

  it('`declare let` rejects (annotated, no-init, and inferred forms)', () => {
    expect(codes(`class C { get f(): External<u256> { declare let x: u256 = 9n; return 1n; } }`)).toEqual(['JETH479']);
    expect(codes(`class C { get f(): External<u256> { declare let x: u256; return 1n; } }`)).toEqual(['JETH479']);
    // the inferred form additionally lacks the required annotation; JETH479 must be among the codes.
    expect(codes(`class C { get f(): External<u256> { declare let x = 9n; return 1n; } }`)).toContain('JETH479');
  });

  it('DECORATOR MODE is itself banned now: the legacy pragma source rejects at JETH480 (was the JETH479 drop)', () => {
    // Native mode is the only mode: the `// use @decorators` pragma is rejected up front (JETH480),
    // so the statement-decorator drop is now moot in this source. The native repro above is the live pin.
    expect(codes(`// use @decorators
@contract class C {
  @state s: u256;
  boom(): u256 { this.s = 100n; return 0n; }
  @external f(): u256 { @only(this.boom()) let x: u256 = 7n; return x + this.s; }
}`)).toEqual(['JETH480']);
  });

  it('decorators on return / if / expression statements still hit the JETH061 gate (unregressed)', () => {
    expect(codes(`class C { get f(): External<u256> { @zzz return 1n; } }`)).toContain('JETH061');
    expect(codes(`class C { get f(): External<u256> { @zzz if (1n == 1n) { return 1n; } return 0n; } }`)).toContain('JETH061');
    expect(codes(`class C { s: u256; setS(): External<void> { @zzz this.s = 1n; } }`)).toContain('JETH061');
  });

  it('legal MEMBER methods stay unregressed (native form compiles + runs)', async () => {
    const out = compile(`class C {
  s: u256;
  set(v: u256): External<void> { this.s = v; }
  get f(): External<u256> { return this.s + 1n; }
}`, { fileName: 'C.jeth' });
    const h = await Harness.create();
    const addr = await h.deploy(out.creationBytecode);
    await h.call(addr, sel('set(uint256)') + pad32(41n));
    const r = await h.call(addr, sel('f()'));
    expect(r.success).toBe(true);
    expect(r.returnHex).toBe('0x' + pad32(42n));
  });

  it('an ordinary let (and a const) in a body stays legal (control)', () => {
    expect(codes(`class C { get f(): External<u256> { let x: u256 = 3n; const y: u256 = 4n; return x + y; } }`)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------------
// C5 (JETH491): non-ASCII / format whitespace as a token SEPARATOR was an over-acceptance. TypeScript's
// scanner silently skips a dozen Unicode whitespace / format code points (NBSP, the U+2000-U+200A space
// family, OGHAM, NNBSP, MMSP, IDEOGRAPHIC, ZWSP, U+2028/2029, VT, FF) and a leading BOM as trivia, so a
// source using one between tokens compiled BYTE-IDENTICAL to the ASCII-clean mirror while solc's ASCII-only
// lexer rejects it. A pre-parse scan now rejects the first such separator (literal/comment contents are
// left untouched; Unicode IDENTIFIER letters still get the more specific JETH478).
// ---------------------------------------------------------------------------------------------------

describe('JETH491: only ASCII whitespace separates tokens (solc ASCII-only-lexer parity)', () => {
  const U = (cp: number) => String.fromCodePoint(cp);
  const NBSP = U(0x00a0);
  const IDSP = U(0x3000);
  const BOM = U(0xfeff);
  const WS: [string, number][] = [
    ['NBSP U+00A0', 0x00a0], ['OGHAM U+1680', 0x1680], ['EN-QUAD U+2000', 0x2000], ['THIN U+2009', 0x2009],
    ['NNBSP U+202F', 0x202f], ['MMSP U+205F', 0x205f], ['IDEOGRAPHIC U+3000', 0x3000], ['ZWSP U+200B', 0x200b],
    ['VT U+000B', 0x000b], ['FF U+000C', 0x000c], ['LS U+2028', 0x2028], ['PS U+2029', 0x2029],
  ];
  const base = (ws: string) => `class C {\n  x: u256 = 0n;\n  f(v: u256): External<void>${ws}{ this.x = v; }\n}\n`;

  for (const [name, cp] of WS) {
    it(`${name} as a separator rejects with JETH491`, () => {
      const got = codes(base(' ' + U(cp) + ' '));
      expect(got).toContain('JETH491');
      expect(got).not.toContain('RAW-THROW');
    });
  }

  it('a leading BOM (U+FEFF) rejects with JETH491', () => {
    expect(codes(BOM + base(' '))).toContain('JETH491');
  });

  it('a BOM (U+FEFF) in separator position rejects with JETH491', () => {
    expect(codes(base(' ' + BOM + ' '))).toContain('JETH491');
  });

  it('the solc mirror rejects a NBSP separator at the lexer (both-reject = parity)', () => {
    const src = `contract C {\n  function f(uint256${NBSP}v) public pure returns (uint256) { return v; }\n}\n`;
    expect(solRejects(src)).toBe(true);
  });

  it('a clean ASCII source stays byte-identical across space/tab/CRLF/newline separators (control)', () => {
    const ref = compile(base(' '), { fileName: 'C.jeth' }).creationBytecode;
    for (const ws of [' ', '\t', '\r\n  ', '\n\n  ', '   ']) {
      expect(compile(base(ws), { fileName: 'C.jeth' }).creationBytecode).toBe(ref);
    }
  });

  it('a Unicode whitespace INSIDE a template / comment is legal content; a REGULAR string is now JETH499 (H2)', () => {
    // A RAW non-ASCII char inside a REGULAR string is now a clean reject (JETH499) - solc's regular-string
    // lexer rejects it too. TEMPLATE literals (JETH sugar for string.concat) and COMMENTS stay legal content.
    expect(codes(`class C { get s(): External<string> { return "a${NBSP}b"; } }`)).toContain('JETH499');
    expect(codes(`class C { get s(): External<string> { return \`a${IDSP}b\`; } }`)).toEqual([]);
    expect(codes(`class C {\n  //${NBSP}note\n  x: u256 = 0n;\n  f(v: u256): External<void> { this.x = v; }\n}\n`)).toEqual([]);
    expect(codes(`class C {\n  /*${IDSP}block*/\n  x: u256 = 0n;\n  f(v: u256): External<void> { this.x = v; }\n}\n`)).toEqual([]);
  });

  it('a Unicode IDENTIFIER letter still gets the specific JETH478, not JETH491 (control)', () => {
    const got = codes(`class Caf${U(0x00e9)} { get f(): External<u256> { return 1n; } }`);
    expect(got).toContain('JETH478');
    expect(got).not.toContain('JETH491');
  });

  it('a non-ASCII separator in a multi-file DEPENDENCY rejects, positioned in that file', () => {
    const dep = `export type P = {\n  a: u256;${NBSP}b: u256;\n};\n`;
    const entry = `import { P } from "./dep";\nclass C {\n  get f(): External<u256> { let p: P = { a: 1n, b: 2n }; return p.a; }\n}\n`;
    const got = mfDiag(entry, { './dep': dep, 'entry.jeth': entry });
    expect(got.some((g) => g.startsWith('JETH491@./dep'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------------
// OA8b (JETH491, comment-terminator axis): the pre-parse separator scan tracked a `//` line comment by
// stopping ONLY at '\n', so a Unicode/control line-break inside a `//` comment - and any separator that
// followed a CR-terminated comment - was swallowed as "comment content" and never rejected, while solc
// ends the comment at that break and rejects the break char (or the next separator) as an "Invalid
// token". solc's `//` comment terminates at the FULL Unicode mandatory-break set: LF (U+000A), VT
// (U+000B), FF (U+000C), CR (U+000D), NEL (U+0085), LS (U+2028), PS (U+2029). The scan now stops at all
// seven, so the break char (or a post-CR separator) reaches the outer scan and gets JETH491 - parity
// with solc. NBSP / OGHAM / ZWSP / BOM / every other Unicode space and control stays legal comment
// CONTENT (does NOT terminate), and LF/CR remain benign terminators, so no valid program is newly
// rejected.
// ---------------------------------------------------------------------------------------------------

describe('JETH491 (OA8b): a Unicode/control line-break inside a // comment ends it, matching solc', () => {
  const U = (cp: number) => String.fromCodePoint(cp);
  // The five break chars that solc ends a `//` comment on AND then rejects as an invalid token
  // (LF and CR also terminate but are benign separators, tested as accept-controls below).
  const BAD_TERMS: [string, number][] = [
    ['VT U+000B', 0x000b], ['FF U+000C', 0x000c], ['NEL U+0085', 0x0085],
    ['LS U+2028', 0x2028], ['PS U+2029', 0x2029],
  ];
  // chars solc treats as ordinary comment CONTENT (never terminate a // comment)
  const CONTENT: [string, number][] = [
    ['NBSP U+00A0', 0x00a0], ['OGHAM U+1680', 0x1680], ['IDEOGRAPHIC U+3000', 0x3000],
    ['NNBSP U+202F', 0x202f], ['ZWSP U+200B', 0x200b], ['BOM U+FEFF', 0xfeff], ['NUL U+0000', 0x0000],
  ];
  const jGet = (body: string) => `class C { get v(): External<u256> {\n${body}\n} }`;
  const sGet = (body: string) => `contract C { function v() external pure returns (uint256) {\n${body}\n} }`;

  // (1) each terminator DIRECTLY inside a // comment rejects (JETH491) and solc rejects too (parity).
  for (const [name, cp] of BAD_TERMS) {
    it(`${name} directly after a // comment rejects with JETH491 (solc rejects too)`, () => {
      const jsrc = jGet(`  //x${U(cp)}return 7n;`);
      const got = codes(jsrc);
      expect(got).toContain('JETH491');
      expect(got).not.toContain('RAW-THROW');
      expect(solRejects(sGet(`  //x${U(cp)}return 7;`))).toBe(true);
    });
  }

  // (2) a CR ends the comment, then a non-ASCII SEPARATOR on the same physical line is exposed + rejected
  // (the char-after-terminator axis: the old scan swallowed it as comment content). solc rejects too.
  for (const [name, cp] of CONTENT) {
    if (cp === 0x0000) continue; // NUL is not a separator solc flags; the others are
    it(`a ${name} after a CR-terminated // comment rejects with JETH491 (solc rejects too)`, () => {
      const jsrc = jGet(`  //x\r${U(cp)}return 7n;`);
      const got = codes(jsrc);
      expect(got).toContain('JETH491');
      expect(solRejects(sGet(`  //x\r${U(cp)}return 7;`))).toBe(true);
    });
  }

  // (3) a terminator inside a // comment that is the LAST thing before EOF still rejects.
  it('a terminator in a // comment at end-of-file rejects with JETH491', () => {
    for (const [, cp] of BAD_TERMS) {
      const src = `class C { get v(): External<u256> { return 7n; } }\n//tail${U(cp)}`;
      expect(codes(src)).toContain('JETH491');
    }
  });

  // (4) the hole in a multi-file DEPENDENCY rejects, positioned in that file.
  it('a comment terminator in a DEPENDENCY source rejects, positioned in that file', () => {
    const dep = `export type P = { a: u256 }; //x${U(0x2028)}z\n`;
    const entry = `import { P } from "./dep";\nclass C { get f(): External<u256> { let p: P = { a: 1n }; return p.a; } }\n`;
    const got = mfDiag(entry, { './dep': dep, 'entry.jeth': entry });
    expect(got.some((g) => g.startsWith('JETH491@./dep'))).toBe(true);
  });

  // (5) CONTROL: every content char inside a // comment stays ACCEPTED (comment content, no diagnostics).
  for (const [name, cp] of CONTENT) {
    it(`${name} INSIDE a // comment is legal content and still compiles (control)`, () => {
      expect(codes(jGet(`  //h${U(cp)}i\n  return 7n;`))).toEqual([]);
    });
  }

  // (6) CONTROL: the break chars are legal inside a BLOCK comment (only `//` terminates on them).
  it('the break chars are legal content inside a /* block */ comment (control)', () => {
    for (const [, cp] of BAD_TERMS) {
      expect(codes(jGet(`  /* a${U(cp)}b */ return 7n;`))).toEqual([]);
    }
  });

  // (7) CONTROL: normal / CRLF / bare-CR comment terminators still ACCEPT and are byte-identical to the
  // no-comment baseline (the scan is validation-only, so an accepted comment cannot change codegen).
  it('LF / CRLF / bare-CR terminated // comments accept and are byte-identical to the baseline (control)', () => {
    const ref = compile(jGet(`  return 7n;`), { fileName: 'C.jeth' }).creationBytecode;
    for (const body of [`  //c\n  return 7n;`, `  //c\r\n  return 7n;`, `  //c\r  return 7n;`]) {
      const got = codes(jGet(body));
      expect(got).toEqual([]);
      expect(compile(jGet(body), { fileName: 'C.jeth' }).creationBytecode).toBe(ref);
    }
  });

  // (8) byte-identity vs solc: deploy+run a CRLF-commented and a bare-CR-commented getter, both return 7.
  it('a CRLF and a bare-CR // comment are behaviorally byte-identical to solc (deploy+run+decode)', async () => {
    for (const [jbody, sbody] of [
      [`  //c\r\n  return 7n;`, `  //c\r\n  return 7;`],
      [`  //c\r  return 7n;`, `  //c\r  return 7;`],
    ] as [string, string][]) {
      const jb = compile(jGet(jbody), { fileName: 'C.jeth' }).creationBytecode;
      const sb = compileSolidity(SPDX + sGet(sbody), 'C').creation;
      const hj = await Harness.create();
      const hs = await Harness.create();
      const aj = await hj.deploy(jb);
      const as = await hs.deploy(sb);
      const rj = await hj.call(aj, sel('v()'));
      const rs = await hs.call(as, sel('v()'));
      expect(rj.success).toBe(true);
      expect(rj.success).toBe(rs.success);
      expect(rj.returnHex).toBe(rs.returnHex);
      expect(BigInt(rj.returnHex)).toBe(7n);
    }
  });
});

// C5 (JETH499): a RAW non-printable-ASCII / non-ASCII code point inside a REGULAR "..." / '...' string
// literal rejects (solc parity). solc's regular-string lexer accepts ONLY printable ASCII 0x20-0x7E or
// escape sequences; a raw control char, DEL, C1 control, or any code point >= 0x80 is a TokenError, and
// arbitrary Unicode requires solc's unicode"..." literal (which JETH has no spelling for). The same char
// via a \n / \xNN / \uNNNN escape, and raw Unicode inside a TEMPLATE literal (JETH sugar for
// string.concat, whose solc mirror can spell each cooked part unicode"..."), STAY accepted + byte-identical.
// All non-ASCII test bytes are built with String.fromCodePoint (the source file stays ASCII-clean).
// ---------------------------------------------------------------------------------------------------

describe('JETH499: raw non-printable/non-ASCII content in a regular string literal rejects (solc parity)', () => {
  const BS = String.fromCharCode(92); // a single backslash
  const ch = (cp: number) => String.fromCodePoint(cp);
  const jethRaw = (cp: number) => `class C { get f(): External<string> { return "a${ch(cp)}b"; } }`;
  const solRaw = (cp: number) => `contract C { function f() external pure returns (string memory) { return "a${ch(cp)}b"; } }`;

  // The full raw-content axis: every code point solc lex-rejects in a regular string. 0x0A/0x0D are omitted
  // (a raw LF/CR terminates the string line in the TS lexer first, so they never reach the content gate -
  // both compilers already reject them as an unterminated string).
  const AXIS = [
    0x00, 0x01, 0x07, 0x08, 0x09, 0x0b, 0x0c, 0x1b, 0x1f, // C0 controls (NUL / BEL / BS / TAB / VT / FF / ESC / US)
    0x7f, // DEL
    0x80, 0x85, 0x9f, // C1 controls (incl. NEL U+0085)
    0xa0, // NBSP
    0xe9, // accented letter (U+00E9)
    0x2028, 0x2029, // LINE / PARAGRAPH SEPARATOR
    0x200b, // ZERO WIDTH SPACE
    0x3000, // IDEOGRAPHIC SPACE
    0x1f600, // emoji (astral plane, > 0xffff)
  ];

  it('every raw non-printable/non-ASCII code point in a "..." string is JETH499 (solc rejects the mirror too)', () => {
    for (const cp of AXIS) {
      expect(codes(jethRaw(cp)), `jeth U+${cp.toString(16)}`).toContain('JETH499');
      expect(solRejects(solRaw(cp)), `solc U+${cp.toString(16)}`).toBe(true);
    }
  });

  it('the same axis inside a SINGLE-quoted string is JETH499 too', () => {
    for (const cp of AXIS) {
      expect(codes(`class C { get f(): External<string> { return 'a${ch(cp)}b'; } }`), `U+${cp.toString(16)}`).toContain('JETH499');
    }
  });

  it('the same axis in NON-return positions (require msg, event arg, state init, bytesN) still rejects', () => {
    const X = ch(0xe9);
    expect(codes(`class C { fn(): void { require(false, "a${X}b"); } }`)).toContain('JETH499');
    expect(codes(`class C { fn(): void { revert("a${X}b"); } }`)).toContain('JETH499');
    expect(codes(`class C { s: string = "a${X}b"; }`)).toContain('JETH499');
    expect(codes(`class C { get f(): External<bytes32> { let b: bytes32 = "a${X}b"; return b; } }`)).toContain('JETH499');
    expect(codes(`class C { get f(): External<bytes> { return bytes("a${X}b"); } }`)).toContain('JETH499');
    expect(codes(`class C { get f(): External<bytes32> { return keccak256(bytes("a${X}b")); } }`)).toContain('JETH499');
  });

  it('a raw non-ASCII char in a DEPENDENCY-file regular string also rejects (JETH499)', () => {
    const entry = `import { L } from "./dep.jeth";\nclass C { get f(): External<string> { return L.g(); } }`;
    const dep = `export static class L { g(): string { return "a${ch(0xe9)}b"; } }`;
    expect(mfDiag(entry, { 'dep.jeth': dep }).map((c) => c.split('@')[0])).toContain('JETH499');
  });

  // ---- accept controls: valid regular strings stay accepted + byte-identical ----

  it('empty, printable-ASCII, and escaped regular strings all still ACCEPT (control)', () => {
    expect(codes(`class C { get f(): External<string> { return ""; } }`)).toEqual([]);
    expect(codes(`class C { get f(): External<string> { return "hello world!"; } }`)).toEqual([]);
    // every printable ASCII 0x20..0x7E raw, with " and \ escaped
    let printable = '';
    for (let c = 0x20; c <= 0x7e; c++) { const s = String.fromCharCode(c); printable += s === '"' ? BS + '"' : s === BS ? BS + BS : s; }
    expect(codes(`class C { get f(): External<string> { return "${printable}"; } }`)).toEqual([]);
    // \n \t \" \\ \xNN \uNNNN escapes are all valid regular-string content
    expect(codes(`class C { get f(): External<string> { return "x${BS}n${BS}t${BS}"${BS}${BS}${BS}x41${BS}u00e9"; } }`)).toEqual([]);
  });

  it('an ESCAPED control/non-ASCII char is byte-identical to solc (raw is rejected, the escape is portable)', async () => {
    const h = await Harness.create();
    // VT, NBSP, and U+4E16 written as escapes -> a valid regular string on BOTH sides.
    const src = 'a' + BS + 'x0b' + BS + 'u00a0' + BS + 'u4e16' + 'b';
    const aj = await h.deploy(compile(`class C { get f(): External<bytes> { return bytes("${src}"); } }`, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + `contract C { function f() external pure returns (bytes memory) { return bytes("${src}"); } }`, 'C').creation);
    const rj = await h.call(aj, sel('f()'));
    const rs = await h.call(as, sel('f()'));
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
  });

  it('raw Unicode in a TEMPLATE literal STAYS accepted + byte-identical (JETH sugar for string.concat)', async () => {
    const h = await Harness.create();
    const seed = ch(0x4e16) + ch(0x754c); // U+4E16 U+754C
    const aj = await h.deploy(compile(`class C { get f(s: string): External<string> { return \`${seed}\${s}\`; } }`, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + `contract C { function f(string calldata s) external pure returns (string memory) { return string.concat(unicode"${seed}", s); } }`, 'C').creation);
    const arg = pad32(0x20n) + pad32(2n) + Buffer.from('hi', 'utf8').toString('hex').padEnd(64, '0');
    const rj = await h.call(aj, sel('f(string)') + arg);
    const rs = await h.call(as, sel('f(string)') + arg);
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
  });
});

// H1 (JETH501): a TOP-LEVEL statement that is not a supported declaration was SILENTLY ACCEPTED. solc's
// top level admits only declarations (pragma / import / contract / interface / library / struct / enum /
// error / event / using / constant / function / type); TS instead parses a bare ExpressionStatement,
// stray identifier, literal, control-flow statement, block, a trailing `;` after a declaration, or a
// non-const file-level variable at the source-file top level, and the analyzer used to process only the
// declarations and ignore the junk while solc rejects the whole file. Now every non-declaration top-level
// statement rejects loudly (JETH501), matching solc across the full axis (position x kind). The check is
// TOP-LEVEL ONLY: the same shapes nested in a method body are ordinary control flow and stay legal.
// ---------------------------------------------------------------------------------------------------

describe('JETH501: a non-declaration top-level statement rejects (solc top-level-grammar parity)', () => {
  const JBASE = `class C { get f(): External<u256> { return 1n; } }`;
  const SBASE = `contract C { function f() external pure returns (uint256){ return 1; } }`;
  const JD = `class D { get g(): External<u256> { return 2n; } }`;
  const SD = `contract D { function g() external pure returns (uint256){ return 2; } }`;
  // [label, JETH stray, Solidity stray]
  const STRAYS: [string, string, string][] = [
    ['bare identifier', 'z', 'z'],
    ['expression statement', 'z;', 'z;'],
    ['integer literal', '5n;', '5;'],
    ['string literal', '"hi";', '"hi";'],
    ['binary expression', '1n + 2n;', '1 + 2;'],
    ['call expression', 'foo();', 'foo();'],
    ['if statement', 'if (true) {}', 'if (true) {}'],
    ['for statement', 'for (;;) {}', 'for (;;) {}'],
    ['while statement', 'while (false) {}', 'while (false) {}'],
    ['return statement', 'return 1n;', 'return 1;'],
    ['stray block', '{}', '{}'],
    ['empty statement', ';', ';'],
    ['labeled statement', 'lbl: z;', 'lbl: z;'],
    ['switch statement', 'switch (1n) {}', 'switch (1) {}'],
    ['try statement', 'try { z; } catch {}', 'try {} catch {}'],
    ['semicolon after enum decl', 'enum E { A }\n;', 'enum E { A }\n;'],
    ['multiple stray tokens', 'a; b; c;', 'a; b; c;'],
  ];
  // position each stray relative to the contract(s): trailing, leading, and between two contracts.
  const POSITIONS: [string, (j: string, s: string) => [string, string]][] = [
    ['trailing', (j, s) => [`${JBASE}\n${j}\n`, `${SBASE}\n${s}\n`]],
    ['leading', (j, s) => [`${j}\n${JBASE}\n`, `${s}\n${SBASE}\n`]],
    ['between', (j, s) => [`${JBASE}\n${j}\n${JD}\n`, `${SBASE}\n${s}\n${SD}\n`]],
  ];
  for (const [label, jstray, sstray] of STRAYS) {
    for (const [pname, mk] of POSITIONS) {
      it(`${label} (${pname}) rejects with JETH501, and solc rejects the mirror (parity)`, () => {
        const [jf, sf] = mk(jstray, sstray);
        const got = codes(jf);
        expect(got).toContain('JETH501');
        expect(got).not.toContain('RAW-THROW');
        expect(solRejects(sf)).toBe(true); // non-vacuous: solc rejects the equivalent
      });
    }
  }

  it('a non-const file-level variable (`let` / `var`) rejects with JETH501 (solc rejects too)', () => {
    expect(codes(`let x = 5n;\n${JBASE}`)).toContain('JETH501');
    expect(codes(`var x = 5n;\n${JBASE}`)).toContain('JETH501');
    expect(solRejects(`uint x = 5;\n${SBASE}`)).toBe(true);
  });

  it('a top-level `throw this.<error>()` (the one allowed raise shape in a body) rejects at file level', () => {
    // silently accepted before: the recursive validator whitelists `throw this.X({...})`, so at file
    // level nothing caught it. solc has no top-level throw at all.
    expect(codes(`type E = error<{}>;\n${JBASE}\nthrow this.E({});`)).toContain('JETH501');
  });

  // ---- CONTROLS: every valid top-level form must STILL compile (no new over-rejection) ----
  it('a single contract, two contracts, and a contract + struct / enum / interface / const all still accept', () => {
    expect(codes(JBASE)).toEqual([]);
    expect(codes(`${JBASE}\n${JD}`)).toEqual([]);
    expect(codes(`type P = { a: u256 };\n${JBASE}`)).toEqual([]);
    expect(codes(`enum E { A, B }\n${JBASE}`)).toEqual([]);
    expect(codes(`interface I { m(): View<u256> }\n${JBASE}`)).toEqual([]);
    expect(codes(`type T = Brand<u256>;\n${JBASE}`)).toEqual([]);
    expect(codes(`const N = 2n;\nclass C { xs: Arr<u256, N>; get f(): External<u256> { return this.xs[0n]; } }`)).toEqual([]);
    expect(codes(`abstract class A { get f(): External<u256> { return 1n; } }`)).toEqual([]);
  });

  it('export-modifier declaration forms (export class / type / const) still accept', () => {
    expect(codes(`export ${JBASE}`)).toEqual([]);
    expect(codes(`export type P = { a: u256 };\n${JBASE}`)).toEqual([]);
    expect(codes(`export const N = 2n;\nclass C { xs: Arr<u256, N>; get f(): External<u256> { return this.xs[0n]; } }`)).toEqual([]);
  });

  it('the SAME statement shapes nested in a method body stay legal (the gate is top-level only)', () => {
    expect(codes(`class C { get f(): External<u256> { let x: u256 = 0n; if (x == 0n) { x = 1n; } for (let i: u256 = 0n; i < 3n; i = i + 1n) { x = x + i; } { x = x + 1n; } return x; } }`)).toEqual([]);
  });

  it('a file-level const string / array-length const stays legal (const is the allowed variable form)', () => {
    expect(codes(`const N = 3n;\nclass C { xs: Arr<u256, N>; get f(): External<u256> { return this.xs[2n]; } }`)).toEqual([]);
  });

  // ---- multi-file: a stray statement in ANY original file rejects, positioned in that file ----
  it('a stray top-level statement in a multi-file DEPENDENCY rejects, positioned in that file', () => {
    const dep = `export abstract class A { ka(): u256 { return 5n; } }\nzzz;\n`;
    const entry = `import { A } from "./a.jeth";\nclass C extends A { get f(): External<u256> { return this.ka(); } }`;
    const got = mfDiag(entry, { './a.jeth': dep, 'entry.jeth': entry });
    expect(got.some((g) => g.startsWith('JETH501@a.jeth'))).toBe(true);
  });

  it('a stray top-level statement in the ENTRY of a multi-file program rejects, positioned in the entry', () => {
    const dep = `export abstract class A { ka(): u256 { return 5n; } }`;
    const entry = `import { A } from "./a.jeth";\nclass C extends A { get f(): External<u256> { return this.ka(); } }\nzzz;`;
    const got = mfDiag(entry, { './a.jeth': dep, 'entry.jeth': entry });
    expect(got.some((g) => g.startsWith('JETH501@entry.jeth'))).toBe(true);
  });

  it('a valid multi-file import program still compiles (control)', () => {
    const dep = `export abstract class A { ka(): u256 { return 5n; } }`;
    const entry = `import { A } from "./a.jeth";\nclass C extends A { get f(): External<u256> { return this.ka(); } }`;
    expect(mfDiag(entry, { './a.jeth': dep, 'entry.jeth': entry })).toEqual([]);
  });
});
