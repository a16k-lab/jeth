// STRING-FIELD-INIT (JETH048 lift): a `string`/`bytes` STATE field WITH a literal initializer
// (`s: string = "x"`, also the Visible<string> flavor) now compiles - desugared into the implicit-
// constructor assignment `this.s = "x"`, the exact byte-identical workaround twin. solc 0.8.35
// witnesses (all verified for this lift):
//   - `string public s = "x";` accepts (short/long/empty/bytes-from-string-literal/unicode);
//   - ALL state-var initializers run BEFORE any constructor body, ctor modifier, or base ctor body
//     across the WHOLE chain (a base ctor's virtual call sees a derived field's init; a ctor
//     modifier's pre-code sees the init) - so the desugared assignments sit at the very TOP of the
//     merged constructor, outside every modifier wrap;
//   - an initializer-only creation is non-payable (deploy value reverts);
//   - an invalid-UTF-8 string init rejects (JETH447, solc "Contains invalid UTF-8 sequence").
// ORACLE: bc(field-init) === bc(ctor-assignment twin) strictly per shape, plus a runtime differential
// vs the solc mirror on seeded values. Guards: constants (static K = ...), value-type inits, the
// @storage('ns') route, proxy/beacon state gates, and non-literal initializers are all UNCHANGED.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
const bc = (src: string): string => compile(src, { fileName: 'C.jeth' }).creationBytecode;

/** ABI-decode a single string/bytes return. */
const decStr = (hex: string): string => {
  const b = hex.slice(2);
  const len = parseInt(b.slice(64, 128), 16);
  return Buffer.from(b.slice(128, 128 + len * 2), 'hex').toString('utf8');
};

/** Deploy the JETH source and the solc mirror, compare every call byte-for-byte, and return the
 *  JETH returndata of the FIRST call (for the non-vacuous seeded-value assertion). */
async function eqRun(jeth: string, sol: string, calls: string[]): Promise<string> {
  const h = await Harness.create();
  const aj = await h.deploy(bc(jeth));
  const as = await h.deploy(compileSolidity(SPDX + sol, 'C').creation);
  let first = '';
  for (const sig of calls) {
    const rj = await h.call(aj, sel(sig));
    const rs = await h.call(as, sel(sig));
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
    if (!first) first = rj.returnHex;
  }
  return first;
}

const LONG = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'; // 44 bytes (long storage form)

describe('STRING-FIELD-INIT: string/bytes state-field initializers (JETH048 lift)', () => {
  it('short string init: byte-identical to the ctor-assignment twin + solc runtime match', async () => {
    const F = `class C {\n  s: string = "alpha7";\n  get out(): External<string> { return this.s; }\n}`;
    const T = `class C {\n  s: string;\n  constructor() { this.s = "alpha7"; }\n  get out(): External<string> { return this.s; }\n}`;
    expect(bc(F)).toBe(bc(T));
    const ret = await eqRun(F, `contract C { string s = "alpha7"; function out() public view returns (string memory) { return s; } }`, ['out()']);
    expect(decStr(ret)).toBe('alpha7'); // non-vacuous: the seeded value is read back
  });

  it('long (44B), empty, and 31/32-byte boundary strings: twin byte-eq + solc match', async () => {
    for (const seed of [LONG, '', 'x'.repeat(31), 'y'.repeat(32)]) {
      const F = `class C {\n  s: string = "${seed}";\n  get out(): External<string> { return this.s; }\n}`;
      const T = `class C {\n  s: string;\n  constructor() { this.s = "${seed}"; }\n  get out(): External<string> { return this.s; }\n}`;
      expect(bc(F), `twin for len ${seed.length}`).toBe(bc(T));
      const ret = await eqRun(F, `contract C { string s = "${seed}"; function out() public view returns (string memory) { return s; } }`, ['out()']);
      expect(decStr(ret)).toBe(seed);
    }
  });

  it('bytes init from a string literal (solc: literal -> bytes) + long form', async () => {
    for (const seed of ['zk9', LONG]) {
      const F = `class C {\n  b: bytes = "${seed}";\n  get out(): External<bytes> { return this.b; }\n}`;
      const T = `class C {\n  b: bytes;\n  constructor() { this.b = "${seed}"; }\n  get out(): External<bytes> { return this.b; }\n}`;
      expect(bc(F)).toBe(bc(T));
      const ret = await eqRun(F, `contract C { bytes b = "${seed}"; function out() public view returns (bytes memory) { return b; } }`, ['out()']);
      expect(decStr(ret)).toBe(seed);
    }
  });

  it('Visible<string> init (auto getter) + unicode + no-sub template literal', async () => {
    const F = `class C {\n  s: Visible<string> = "vis5";\n}`;
    const T = `class C {\n  s: Visible<string>;\n  constructor() { this.s = "vis5"; }\n}`;
    expect(bc(F)).toBe(bc(T));
    const ret = await eqRun(F, `contract C { string public s = "vis5"; }`, ['s()']);
    expect(decStr(ret)).toBe('vis5');

    const FU = `class C {\n  s: string = "h\\u00e9llo\\u26a1";\n  get out(): External<string> { return this.s; }\n}`;
    expect(bc(FU)).toBe(bc(`class C {\n  s: string;\n  constructor() { this.s = "h\\u00e9llo\\u26a1"; }\n  get out(): External<string> { return this.s; }\n}`));
    const retU = await eqRun(FU, `contract C { string s = unicode"héllo⚡"; function out() public view returns (string memory) { return s; } }`, ['out()']);
    expect(decStr(retU)).toBe('héllo⚡');

    const FT = 'class C {\n  s: string = `tpl2`;\n  get out(): External<string> { return this.s; }\n}';
    expect(bc(FT)).toBe(bc('class C {\n  s: string;\n  constructor() { this.s = `tpl2`; }\n  get out(): External<string> { return this.s; }\n}'));
  });

  it('mixed value + string inits, and two string inits in slot order', async () => {
    const F = `class C {\n  a: u256 = 5n;\n  s: string = "mix";\n  b: bool = true;\n  get out(): External<string> { return this.s; }\n  get aOut(): External<u256> { return this.a; }\n  get bOut(): External<bool> { return this.b; }\n}`;
    const T = `class C {\n  a: u256 = 5n;\n  s: string;\n  b: bool = true;\n  constructor() { this.s = "mix"; }\n  get out(): External<string> { return this.s; }\n  get aOut(): External<u256> { return this.a; }\n  get bOut(): External<bool> { return this.b; }\n}`;
    expect(bc(F)).toBe(bc(T));
    const ret = await eqRun(
      F,
      `contract C { uint a = 5; string s = "mix"; bool b = true; function out() public view returns (string memory) { return s; } function aOut() public view returns (uint) { return a; } function bOut() public view returns (bool) { return b; } }`,
      ['out()', 'aOut()', 'bOut()'],
    );
    expect(decStr(ret)).toBe('mix');

    const F2 = `class C {\n  s: string = "one";\n  t: string = "two";\n  get sOut(): External<string> { return this.s; }\n  get tOut(): External<string> { return this.t; }\n}`;
    const T2 = `class C {\n  s: string;\n  t: string;\n  constructor() { this.s = "one"; this.t = "two"; }\n  get sOut(): External<string> { return this.s; }\n  get tOut(): External<string> { return this.t; }\n}`;
    expect(bc(F2)).toBe(bc(T2));
    await eqRun(F2, `contract C { string s = "one"; string t = "two"; function sOut() public view returns (string memory) { return s; } function tOut() public view returns (string memory) { return t; } }`, ['sOut()', 'tOut()']);
  });

  it('ORDERING: the init runs before the ctor body (append), the ctor modifier, and every base ctor body', async () => {
    // init before the OWN ctor body
    const F1 = 'class C {\n  s: string = "pre";\n  constructor() { this.s = `${this.s}#post`; }\n  get out(): External<string> { return this.s; }\n}';
    const T1 = 'class C {\n  s: string;\n  constructor() { this.s = "pre"; this.s = `${this.s}#post`; }\n  get out(): External<string> { return this.s; }\n}';
    expect(bc(F1)).toBe(bc(T1));
    const r1 = await eqRun(F1, `contract C { string s = "pre"; constructor() { s = string.concat(s, "#post"); } function out() public view returns (string memory) { return s; } }`, ['out()']);
    expect(decStr(r1)).toBe('pre#post');

    // init before the ctor MODIFIER's pre-code (solc runs initializers before modifiers; NO twin
    // exists - an in-body assignment would run after the modifier in solc)
    const r2 = await eqRun(
      `class C {\n  s: string = "mod1";\n  seen: string;\n  @modifier m() { this.seen = this.s; _; }\n  @m constructor() {}\n  get seenOut(): External<string> { return this.seen; }\n}`,
      `contract C { string s = "mod1"; string seen; modifier m() { seen = s; _; } constructor() m() {} function seenOut() public view returns (string memory) { return seen; } }`,
      ['seenOut()'],
    );
    expect(decStr(r2)).toBe('mod1');

    // ALL-INITS-FIRST across the chain: a BASE ctor's virtual call sees the DERIVED field's init
    const r3 = await eqRun(
      `abstract class B {\n  seen: string;\n  @virtual f(): string { return this.seen; }\n  constructor() { this.seen = this.f(); }\n  get seenOut(): External<string> { return this.seen; }\n}\nclass C extends B {\n  s: string = "drv9";\n  @override f(): string { return this.s; }\n}`,
      `contract B { string seen; function f() public virtual view returns (string memory) { return seen; } constructor() { seen = f(); } function seenOut() public view returns (string memory) { return seen; } } contract C is B { string s = "drv9"; function f() public override view returns (string memory) { return s; } }`,
      ['seenOut()'],
    );
    expect(decStr(r3)).toBe('drv9');

    // base + derived inits + ctor bodies: inits all first, bodies most-base-first
    const r4 = await eqRun(
      'class B {\n  s: string = "b";\n  constructor() { this.s = `${this.s}B`; }\n  get sOut(): External<string> { return this.s; }\n}\nclass C extends B {\n  t: string = "d";\n  constructor() { this.t = `${this.t}${this.s}D`; }\n  get tOut(): External<string> { return this.t; }\n}',
      `contract B { string s = "b"; constructor() { s = string.concat(s, "B"); } function sOut() public view returns (string memory) { return s; } } contract C is B { string t = "d"; constructor() { t = string.concat(t, s, "D"); } function tOut() public view returns (string memory) { return t; } }`,
      ['tOut()', 'sOut()'],
    );
    expect(decStr(r4)).toBe('dbBD');
  });

  it('creation surface: initializer-only creation is non-payable; @payable ctor and ctor params keep the twin bytes', async () => {
    const F = `class C {\n  s: string = "x";\n  get out(): External<string> { return this.s; }\n}`;
    const h = await Harness.create();
    const { Address, hexToBytes } = await import('@ethereumjs/util');
    await h.fund(new Address(hexToBytes(('0x' + '11'.repeat(20)) as `0x${string}`)), 10n ** 18n);
    await expect(h.deploy(bc(F), { value: 1n })).rejects.toThrow(); // callvalue guard, like solc
    await expect(h.deploy(compileSolidity(SPDX + `contract C { string s = "x"; function out() public view returns (string memory) { return s; } }`, 'C').creation, { value: 1n })).rejects.toThrow();
    await h.deploy(bc(F)); // non-vacuous: deploys fine without a value

    const FP = `class C {\n  s: string = "pay3";\n  @payable constructor() {}\n  get out(): External<string> { return this.s; }\n}`;
    const TP = `class C {\n  s: string;\n  @payable constructor() { this.s = "pay3"; }\n  get out(): External<string> { return this.s; }\n}`;
    expect(bc(FP)).toBe(bc(TP));
    const ap = await h.deploy(bc(FP), { value: 5n }); // payable creation accepts the value
    const rp = await h.call(ap, sel('out()'));
    expect(decStr(rp.returnHex)).toBe('pay3');

    const FA = `class C {\n  s: string = "argA";\n  x: u256;\n  constructor(v: u256) { this.x = v; }\n  get out(): External<string> { return this.s; }\n  get xOut(): External<u256> { return this.x; }\n}`;
    const TA = `class C {\n  s: string;\n  x: u256;\n  constructor(v: u256) { this.s = "argA"; this.x = v; }\n  get out(): External<string> { return this.s; }\n  get xOut(): External<u256> { return this.x; }\n}`;
    expect(bc(FA)).toBe(bc(TA));
  });

  it('PRE-FIX PINS + guards: the lifted shapes accepted, everything adjacent unchanged', () => {
    // the lifted row shapes now accept (each REJECTED with JETH048 before this lift)
    expect(codes(`class C {\n  s: string = "x";\n}`)).toEqual([]);
    expect(codes(`class C {\n  s: Visible<string> = "x";\n}`)).toEqual([]);
    expect(codes(`class C {\n  b: bytes = "ab";\n}`)).toEqual([]);
    // FIELD-INIT-NS lift: a @storage(ns) field's string/bytes LITERAL init now routes through the same
    // implicit-ctor desugar (byte-identical to the ctor-assign twin), so it accepts too.
    expect(codes(`class C {\n  @storage('my.ns') s: string = "x";\n}`)).toEqual([]);
    // constants and value-type inits: unchanged accept (they never routed through the lift)
    expect(codes(`class C {\n  static K: string = "x";\n  get out(): External<string> { return C.K; }\n}`)).toEqual([]);
    expect(codes(`class C {\n  x: u256 = 7n;\n}`)).toEqual([]);
    // guards: exact reject codes preserved
    expect(codes(`class C {\n  static s: string;\n  constructor() { this.s = "x"; }\n}`)).toContain('JETH310'); // immutable string (solc rejects too)
    expect(codes(`class C {\n  a: string[] = ["x"];\n}`)).toContain('JETH048'); // array of strings (aggregate, unchanged)
    expect(codes(`@proxy\nclass P {\n  s: string = "x";\n}`)).toContain('JETH399'); // proxy state gate intact
    expect(codes(`class C {\n  s: string = "\\ud800";\n}`)).toContain('JETH447'); // invalid UTF-8 (solc rejects \xed\xa0\x80)
    expect(codes(`class C {\n  @state s: string = "x";\n}`)).toContain('JETH481'); // native-only ban intact
    // solc rejects the invalid-UTF-8 mirror too (witness kept honest)
    expect(() => compileSolidity(SPDX + `contract C { string s = "\\xed\\xa0\\x80"; }`, 'C')).toThrow();
  });
});
