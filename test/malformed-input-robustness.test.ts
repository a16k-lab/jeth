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
//              the lexer (ParserError), so a targeted early reject is PARITY. String content is
//              untouched: raw unicode STRINGS stay byte-identical.
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
    const out = execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], {
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

describe('JETH478: unicode identifiers reject cleanly (no more JETH901 ICE); string content untouched', () => {
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

  it('raw unicode STRING content stays byte-identical (return form)', async () => {
    const h = await Harness.create();
    const aj = await h.deploy(compile(`class C { get f(): External<string> { return "café \u{1F600}"; } }`, { fileName: 'C.jeth' }).creationBytecode);
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

  it('DECORATOR MODE: the same statement-decorator drop rejects there too', () => {
    expect(codes(`// use @decorators
@contract class C {
  @state s: u256;
  boom(): u256 { this.s = 100n; return 0n; }
  @external f(): u256 { @only(this.boom()) let x: u256 = 7n; return x + this.s; }
}`)).toEqual(['JETH479']);
  });

  it('decorators on return / if / expression statements still hit the JETH061 gate (unregressed)', () => {
    expect(codes(`class C { get f(): External<u256> { @zzz return 1n; } }`)).toContain('JETH061');
    expect(codes(`class C { get f(): External<u256> { @zzz if (1n == 1n) { return 1n; } return 0n; } }`)).toContain('JETH061');
    expect(codes(`class C { s: u256; setS(): External<void> { @zzz this.s = 1n; } }`)).toContain('JETH061');
  });

  it('legal MEMBER decorators stay unregressed (decorator mode compiles + runs)', async () => {
    const out = compile(`// use @decorators
@contract class C {
  @state s: u256;
  @external set(v: u256): void { this.s = v; }
  @external @view f(): u256 { return this.s + 1n; }
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
