// Multi-file import system (v1, bundling). `compile(entry, { sources })` resolves the entry's
// `import { A, B } from "./file.jeth"` statements against the sources map (paths relative to the importing
// file), splices the files into ONE compilation unit (deps first, entry last, imports blanked
// line-preservingly), and remaps diagnostics back into the ORIGINAL files. Rules: named imports only; only
// `export`-marked top-level declarations are importable; an imported file may declare libraries / types /
// interfaces / abstract bases but NOT a deployed contract (one contract per ENTRY file); all files share
// the entry's syntax mode; cycles reject; diamond imports dedupe. THE ORACLE: a multi-file program is
// byte-identical to the same program hand-flattened into a single file.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const diag = (src: string, sources: Record<string, string>, fn = 'vault.jeth'): string[] => {
  try { compile(src, { fileName: fn, sources }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => `${d.code}@${d.file}:${d.line}`) ?? ['THROW']; }
};

const LIBS = `// libs.jeth
export static class MathLib {
  min(a: u256, b: u256): u256 { return a < b ? a : b; }
}
export type Position = { size: u256; entry: u256 };
export abstract class Ownable {
  owner: address;
  constructor() { this.owner = msg.sender; }
  get getOwner(): External<address> { return this.owner; }
}
`;
const ENTRY = `import { MathLib, Position, Ownable } from "./libs.jeth";
class Vault extends Ownable {
  pos: Position;
  open(size: u256, entry: u256): External<void> { this.pos = Position(MathLib.min(size, 100n), entry); }
  get size(): External<u256> { return this.pos.size; }
}`;

describe('multi-file imports', () => {
  it('THE ORACLE: a multi-file program is byte-identical to the hand-flattened single file', () => {
    const flat = LIBS.replace('// libs.jeth', '') + '\n' + ENTRY.replace(/import .*\n/, '');
    const mf = compile(ENTRY, { fileName: 'vault.jeth', sources: { 'libs.jeth': LIBS } });
    const sf = compile(flat, { fileName: 'vault.jeth' });
    expect(mf.creationBytecode).toBe(sf.creationBytecode);
  });

  it('a multi-file project (library + type + abstract base imported) runs byte-identical to solc', async () => {
    const S = `library MathLib { function min(uint256 a, uint256 b) internal pure returns(uint256){ return a < b ? a : b; } }
      struct Position { uint256 size; uint256 entry; }
      abstract contract Ownable { address owner; constructor(){ owner = msg.sender; } function getOwner() external view returns(address){ return owner; } }
      contract Vault is Ownable {
        Position pos;
        function open(uint256 size, uint256 entry) external { pos = Position(MathLib.min(size, 100), entry); }
        function size() external view returns(uint256){ return pos.size; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(ENTRY, { fileName: 'vault.jeth', sources: { 'libs.jeth': LIBS } }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'Vault').creation);
    for (const [sg, args] of [['open(uint256,uint256)', W(250) + W(9)], ['size()', ''], ['getOwner()', '']] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('transitive imports resolve and diamond imports dedupe', () => {
    expect(diag(
      `import { A } from "./a.jeth";\nclass C { get f(): External<u256> { return A.one() + 1n; } }`,
      { 'a.jeth': `import { B } from "./b.jeth";\nexport static class A { one(): u256 { return B.zero() + 1n; } }`,
        'b.jeth': `export static class B { zero(): u256 { return 0n; } }` },
    )).toEqual([]);
    expect(diag(
      `import { A } from "./a.jeth";\nimport { B } from "./b.jeth";\nclass C { get f(): External<u256> { return A.fa() + B.fb(); } }`,
      { 'a.jeth': `import { S } from "./s.jeth";\nexport static class A { fa(): u256 { return S.s(); } }`,
        'b.jeth': `import { S } from "./s.jeth";\nexport static class B { fb(): u256 { return S.s(); } }`,
        's.jeth': `export static class S { s(): u256 { return 7n; } }` },
    )).toEqual([]);
  });

  it('rejects: unexported name, unknown path, cycle, contract-in-dep, mode mismatch - each at the right file:line', () => {
    expect(diag(`import { Hidden } from "./l.jeth";\nclass C { get f(): External<u256> { return 1n; } }`, { 'l.jeth': `static class Hidden { f(): u256 { return 1n; } }` }))
      .toEqual(['JETH036@vault.jeth:1']); // not exported
    expect(diag(`import { X } from "./nope.jeth";\nclass C { get f(): External<u256> { return 1n; } }`, { 'l.jeth': `export type T = { a: u256 };` }))
      .toEqual(['JETH036@vault.jeth:1']); // unresolvable path
    expect(diag(`import { A } from "./a.jeth";\nclass C { get f(): External<u256> { return 1n; } }`,
      { 'a.jeth': `import { B } from "./b.jeth";\nexport static class A { f(): u256 { return 1n; } }`,
        'b.jeth': `import { A } from "./a.jeth";\nexport static class B { f(): u256 { return 1n; } }` }))
      .toEqual(['JETH036@a.jeth:1']); // cycle
    expect(diag(`import { T } from "./d.jeth";\nclass C { get f(): External<u256> { return 1n; } }`, { 'd.jeth': `export type T = { a: u256 };\nclass Rogue { get g(): External<u256> { return 1n; } }` }))
      .toEqual(['JETH036@d.jeth:2']); // concrete contract in a dep
    expect(diag(`import { T } from "./d.jeth";\nclass C { get f(): External<u256> { return 1n; } }`, { 'd.jeth': `// use @decorators\nexport type T = Brand<u256>;` }))
      .toEqual(['JETH480@d.jeth:1']); // a dep carrying the removed `// use @decorators` pragma is banned (JETH480)
  });

  it('convenience import aliases: `import { A as B }` binds A under the local name B, byte-identically', () => {
    const LIB = `export static class SafeMathLibrary { min(a: u256, b: u256): u256 { return a < b ? a : b; } }`;
    // the aliased program compiles byte-identical to the unaliased one (the alias is renamed away post-parse).
    expect(compile(`import { SafeMathLibrary as Math } from "./l.jeth";\nclass V { get f(a: u256, b: u256): External<u256> { return Math.min(a, b); } }`, { fileName: 'vault.jeth', sources: { 'l.jeth': LIB } }).creationBytecode)
      .toBe(compile(`import { SafeMathLibrary } from "./l.jeth";\nclass V { get f(a: u256, b: u256): External<u256> { return SafeMathLibrary.min(a, b); } }`, { fileName: 'vault.jeth', sources: { 'l.jeth': LIB } }).creationBytecode);
    // an aliased library's `self`-convention attachments still work (visibility keys on the ORIGINAL name).
    expect(diag(`import { M as Math } from "./m.jeth";\nclass V { get f(x: u256, y: u256): External<u256> { return x.min(y); } }`,
      { 'm.jeth': `export static class M { min(self: u256, b: u256): u256 { return self < b ? self : b; } }` })).toEqual([]);
    // the alias must be a FREE name: colliding with an own declaration / a local binding / a primitive /
    // a builtin global all reject (the rewrite would hijack them).
    const L2 = { 'l.jeth': LIB };
    expect(diag(`import { SafeMathLibrary as V } from "./l.jeth";\nclass V { get f(): External<u256> { return 1n; } }`, L2)).toEqual(['JETH036@vault.jeth:1']);
    expect(diag(`import { SafeMathLibrary as Tmp } from "./l.jeth";\nclass V { get f(a: u256): External<u256> { let Tmp: u256 = a; return Tmp; } }`, L2)).toEqual(['JETH036@vault.jeth:1']);
    expect(diag(`import { SafeMathLibrary as u256 } from "./l.jeth";\nclass V { get f(): External<u256> { return 1n; } }`, L2)).toEqual(['JETH036@vault.jeth:1']);
    expect(diag(`import { SafeMathLibrary as msg } from "./l.jeth";\nclass V { get f(): External<u256> { return 1n; } }`, L2)).toEqual(['JETH036@vault.jeth:1']);
    // v3 per-file scoping: aliases DISAMBIGUATE two same-named exports - each binds its own file's
    // declaration, byte-identical to the same program with hand-uniquified names.
    const two = compile(`import { Utils as A } from "./a.jeth";\nimport { Utils as B } from "./b.jeth";\nclass V { get f(): External<u256> { return A.one() * 10n + B.two(); } }`,
      { fileName: 'vault.jeth', sources: { 'a.jeth': `export static class Utils { one(): u256 { return 1n; } }`, 'b.jeth': `export static class Utils { two(): u256 { return 2n; } }` } });
    const uniq = compile(`static class UtilsA { one(): u256 { return 1n; } }\nstatic class UtilsB { two(): u256 { return 2n; } }\nclass V { get f(): External<u256> { return UtilsA.one() * 10n + UtilsB.two(); } }`,
      { fileName: 'vault.jeth' });
    expect(two.creationBytecode).toBe(uniq.creationBytecode);
  });

  it('a semantic error INSIDE an imported file reports the dep file + its own line', () => {
    const d = diag(`import { L } from "./dep.jeth";\nclass C { get f(): External<u256> { return L.bad(); } }`,
      { 'dep.jeth': `export static class L {\n  bad(): u256 { return this.x; }\n}` });
    expect(d.some((x) => x.endsWith('@dep.jeth:2'))).toBe(true); // `this` in a library fn, at dep.jeth line 2
  });
});

// Hardening from the adversarial sweep (368 cases, 7 confirmed bar-violations, all closed). Three were
// PRE-EXISTING single-file holes that bundling amplified into silent cross-file wrong-binding.
describe('multi-file hardening (verification sweep)', () => {
  it('duplicate class names: SAME-file still JETH037; cross-file scopes per file and binds the IMPORT', () => {
    // v3 per-file scoping: a named import binds ITS target file's declaration even when another file
    // declares the same name - byte-identical to the program with only the imported declaration present.
    const mixed = compile(`import { Base } from "./a.jeth";\nimport { Other } from "./b.jeth";\nclass C extends Base { get f(): External<u256> { return this.v(); } }`,
      { fileName: 'c.jeth', sources: { 'a.jeth': `export abstract class Base { v(): u256 { return 1n; } }`, 'b.jeth': `export abstract class Base { v(): u256 { return 2n; } }\nexport abstract class Other { }` } });
    const clean = compile(`import { Base } from "./a.jeth";\nimport { Other } from "./b.jeth";\nclass C extends Base { get f(): External<u256> { return this.v(); } }`,
      { fileName: 'c.jeth', sources: { 'a.jeth': `export abstract class Base { v(): u256 { return 1n; } }`, 'b.jeth': `export abstract class Unrelated { v(): u256 { return 2n; } }\nexport abstract class Other { }` } });
    expect(mixed.creationBytecode).toBe(clean.creationBytecode);
    // the pre-existing single-file pairs (last silently won before): abstract+abstract, static+contract,
    // abstract+contract, static+abstract - all now "Identifier already declared" like solc.
    const codes = (src: string) => { try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e.diagnostics.map((d: any) => d.code); } };
    expect(codes(`abstract class B { v(): u256 { return 1n; } } abstract class B { v(): u256 { return 2n; } } class C extends B { get f(): External<u256> { return this.v(); } }`)).toContain('JETH037');
    expect(codes(`static class V { k(): u256 { return 1n; } } class V { get f(): External<u256> { return 1n; } }`)).toContain('JETH037');
    expect(codes(`abstract class V { } class V { get f(): External<u256> { return 1n; } }`)).toContain('JETH037');
  });

  it('a class shadowing a builtin global (msg/abi/block/tx) rejects (JETH038) - no split-brain binding', () => {
    const codes = (src: string) => { try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e.diagnostics.map((d: any) => d.code); } };
    expect(codes(`static class abi { encode(x: u256): u256 { return x; } } class C { get f(): External<u256> { return abi.encode(1n); } }`)).toContain('JETH038');
    expect(diag(`import { msg } from "./d.jeth";\nclass C { get f(): External<u256> { return 1n; } }`, { 'd.jeth': `export static class msg { sender(): u256 { return 7n; } }` }))
      .toContain('JETH038@d.jeth:1');
  });

  it('a block-wrapped contract in a dep is caught (recursive scan) - no silent artifact replacement', () => {
    expect(diag(`import { T } from "./dep.jeth";\nclass Vault { x: u256; get getX(): External<u256> { return this.x; } }`,
      { 'dep.jeth': `export type T = { a: u256 };\n{ class Rogue { get g(): External<u256> { return 99n; } } }` }))
      .toEqual(['JETH036@dep.jeth:2']);
  });

  it('v2 scoping: a cross-file reference requires an import edge; unexported declarations stay private', () => {
    const LIB = `export static class MathLib { min(a: u256, b: u256): u256 { return a < b ? a : b; } }\nexport static class Extra { calc(a: u256): u256 { return a + 1n; } }\nstatic class Hidden { leak(a: u256): u256 { return a * 2n; } }`;
    // the two v1 leaks, closed: an unimported exported sibling, and an unexported declaration.
    expect(diag(`import { MathLib } from "./libs.jeth";\nclass V { get f(a: u256): External<u256> { return Extra.calc(a); } }`, { 'libs.jeth': LIB }))
      .toEqual(['JETH039@vault.jeth:2']);
    expect(diag(`import { MathLib } from "./libs.jeth";\nclass V { get f(a: u256): External<u256> { return Hidden.leak(a); } }`, { 'libs.jeth': LIB }))
      .toEqual(['JETH039@vault.jeth:2']);
    // TYPE-position references, `extends`, @using(...) arguments, and DEP-to-DEP references are edges too.
    expect(diag(`import { MathLib } from "./libs.jeth";\nclass V { get f(p: P): External<u256> { return p.a; } }`, { 'libs.jeth': LIB + `\nexport type P = { a: u256 };` }))
      .toEqual(['JETH039@vault.jeth:2']);
    expect(diag(`import { MathLib } from "./libs.jeth";\nclass V extends Base { get f(): External<u256> { return 1n; } }`, { 'libs.jeth': LIB + `\nexport abstract class Base { }` }))
      .toEqual(['JETH039@vault.jeth:2']);
    expect(diag(`import { A } from "./a.jeth";\nclass V { get f(x: u256): External<u256> { return A.fa(x); } }`,
      { 'a.jeth': `import { B } from "./b.jeth";\nexport static class A { fa(x: u256): u256 { return B.fb(x) + Cfn.g(x); } }`, 'b.jeth': `export static class B { fb(x: u256): u256 { return x + 1n; } }\nexport static class Cfn { g(x: u256): u256 { return x; } }` }))
      .toEqual(['JETH039@a.jeth:2']); // Cfn used inside a.jeth without an import edge
  });

  it('v2 scoping covers self-convention ATTACHED calls: attaching needs an import edge for the library', () => {
    const M = `export static class M { min(self: u256, b: u256): u256 { return self < b ? self : b; } }`;
    // a transitively-bundled library's self-fns must NOT attach in a file that never imported it.
    expect(diag(`import { A } from "./a.jeth";\nclass V { get f(x: u256, y: u256): External<u256> { return x.min(y); } }`,
      { 'a.jeth': `import { M } from "./m.jeth";\nexport static class A { fa(x: u256): u256 { return M.min(x, 1n); } }`, 'm.jeth': M }))
      .toEqual(['JETH039@vault.jeth:2']);
    // with the import edge (or in the library's own file, or in a DEP that imported it) attachment works.
    expect(diag(`import { M } from "./m.jeth";\nclass V { get f(x: u256, y: u256): External<u256> { return x.min(y); } }`, { 'm.jeth': M })).toEqual([]);
    expect(diag(`import { A } from "./a.jeth";\nclass V { get f(x: u256): External<u256> { return A.fa(x); } }`,
      { 'a.jeth': `import { M } from "./m.jeth";\nexport static class A { fa(x: u256): u256 { return x.min(9n); } }`, 'm.jeth': M }))
      .toEqual([]);
  });

  it('v2 scoping has no false positives: shadowing locals, member names, and enum access all pass', () => {
    const LIB = `export static class Extra { calc(a: u256): u256 { return a + 1n; } }\nexport enum Color { Red, Blue }\nexport static class MathLib { min(a: u256, b: u256): u256 { return a < b ? a : b; } }`;
    // a LOCAL named like a cross-file declaration suppresses the check (conservative shadow set).
    expect(diag(`import { MathLib } from "./libs.jeth";\ntype P = { calc: u256 };\nclass V { get f(a: u256): External<u256> { let Extra: P = P(a); return Extra.calc; } }`, { 'libs.jeth': LIB }))
      .toEqual([]);
    // a STRUCT FIELD / property name matching a cross-file declaration is a member name, not a reference.
    expect(diag(`import { MathLib } from "./libs.jeth";\ntype Q = { Extra: u256 };\nclass V { get f(a: u256): External<u256> { let q: Q = Q(a); return q.Extra; } }`, { 'libs.jeth': LIB }))
      .toEqual([]);
    // an imported ENUM's members are reached through the imported name - fine.
    expect(diag(`import { Color } from "./libs.jeth";\nclass V { c: Color; get f(): External<bool> { return this.c == Color.Red; } }`, { 'libs.jeth': LIB }))
      .toEqual([]);
  });

  it('a lone-CR file ending does not shift later diagnostic mapping; ambiguous sources keys reject', () => {
    expect(diag(`import { A } from "./a.jeth";\nimport { B } from "./b.jeth";\nclass C { get f(): External<u256> { return A.fa() + B.fb(); } }`,
      { 'a.jeth': "export static class A { fa(): u256 { return 1n; } }\r", 'b.jeth': `export static class B {\n  fb(): u256 { return this.x; }\n}` })
      .some((x) => x.endsWith('@b.jeth:2'))).toBe(true);
    expect(diag(`import { T } from "./a.jeth";\nclass C { get f(p: T): External<u256> { return p.a; } }`,
      { 'a.jeth': `export type T = { a: u256 };`, './a.jeth': `export type T = { a: bool };` })
      .some((x) => x.startsWith('JETH036'))).toBe(true);
  });
});

// v3 PER-FILE DECLARATION SCOPING: each dep's top-level declarations are alpha-renamed to `$mN$` scoped
// names and every file's references rewrite per its own scope, so two files may declare the SAME name
// (aliases disambiguate) while hash-sensitive spellings (error/event selectors/topics, external-library
// link symbols, ABI names) demangle back to the SOURCE name. The entry file is never renamed.
describe('v3 per-file declaration scoping', () => {
  it('same-named UNEXPORTED helpers in two deps: each file binds its OWN, byte-identical to uniquified', async () => {
    const srcs = {
      'a.jeth': `static class Help { h(): u256 { return 1n; } }\nexport static class A { fa(): u256 { return Help.h(); } }`,
      'b.jeth': `static class Help { h(): u256 { return 20n; } }\nexport static class B { fb(): u256 { return Help.h(); } }`,
    };
    const r = compile(`import { A } from "./a.jeth";\nimport { B } from "./b.jeth";\nclass V { get f(): External<u256> { return A.fa() + B.fb(); } }`,
      { fileName: 'v.jeth', sources: srcs });
    const h = await Harness.create();
    const addr = await h.deploy(r.creationBytecode);
    const c = await h.call(addr, sel('f()'));
    expect(c.success).toBe(true);
    expect(BigInt(c.returnHex)).toBe(21n); // 1 + 20: each dep used ITS Help
  });

  it('a dep declaration and an entry declaration may share a name; the entry file is never renamed', async () => {
    const r = compile(`import { A } from "./a.jeth";\ntype P = { x: u256 };\nclass V { get f(): External<u256> { let p: P = P(5n); return p.x + A.fa(); } }`,
      { fileName: 'v.jeth', sources: { 'a.jeth': `export type P = { y: u256; z: u256 };\nexport static class A { fa(): u256 { let q: P = P(1n, 2n); return q.y + q.z; } }` } });
    const h = await Harness.create();
    const addr = await h.deploy(r.creationBytecode);
    const c = await h.call(addr, sel('f()'));
    expect(BigInt(c.returnHex)).toBe(8n); // entry P (1 field) and dep P (2 fields) coexist
  });

  it('HASH BOUNDARY: a dep-declared file-level error/event keeps its SOURCE selector/topic (== solc)', async () => {
    const mf = compile(
      `import { Insufficient, Moved } from "./defs.jeth";\nclass V {\n  x: u256;\n  f(a: u256): External<void> {\n    if (a == 0n) { revert(Insufficient(1n, a)); }\n    emit(Moved(msg.sender, a));\n    this.x = a;\n  }\n}`,
      { fileName: 'v.jeth', sources: { 'defs.jeth': `export type Insufficient = error<{ need: u256; have: u256 }>;\nexport type Moved = event<{ who: indexed<address>; amount: u256 }>;` } });
    const sc = compileSolidity(SPDX + `error Insufficient(uint256 need, uint256 have);\nevent Moved(address indexed who, uint256 amount);\ncontract V {\n  uint256 x;\n  function f(uint256 a) external {\n    if (a == 0) { revert Insufficient(1, a); }\n    emit Moved(msg.sender, a);\n    x = a;\n  }\n}`, 'V');
    const h = await Harness.create();
    const aj = await h.deploy(mf.creationBytecode);
    const as = await h.deploy(sc.creation);
    const [rj0, rs0] = [await h.call(aj, sel('f(uint256)') + W(0)), await h.call(as, sel('f(uint256)') + W(0))];
    expect(rj0.success).toBe(false);
    expect(rj0.returnHex).toBe(rs0.returnHex); // demangled selector in the revert data
    const [rj1, rs1] = [await h.call(aj, sel('f(uint256)') + W(7)), await h.call(as, sel('f(uint256)') + W(7))];
    expect(rj1.success).toBe(true);
    expect(JSON.stringify(rj1.logs ?? [])).toBe(JSON.stringify(rs1.logs ?? [])); // demangled topic0
    // ABI speaks source names too
    const abiNames = mf.abi.filter((x: any) => x.type === 'error' || x.type === 'event').map((x: any) => x.name);
    expect(abiNames.sort()).toEqual(['Insufficient', 'Moved']);
    // and the Error/Panic reserve sees THROUGH the mangle
    expect(diag(`import { Error as E } from "./d.jeth";\nclass C { f(): External<void> { revert(E()); } }`, { 'd.jeth': `export type Error = error<{}>;` })
      .some((x) => x.startsWith('JETH132'))).toBe(true);
  });

  it('HASH BOUNDARY: a dep-declared EXTERNAL library links by its SOURCE name; source-name clashes reject', () => {
    const dep = compile(`import { ExtLib } from "./l.jeth";\nclass C { f(a: u256): External<u256> { return ExtLib.double(a); } }`,
      { fileName: 'c.jeth', sources: { 'l.jeth': `export static class ExtLib { double(a: u256): External<u256> { return a + a; } }` } });
    const flat = compile(`static class ExtLib { double(a: u256): External<u256> { return a + a; } }\nclass C { f(a: u256): External<u256> { return ExtLib.double(a); } }`,
      { fileName: 'c.jeth' });
    expect((dep.libraries ?? []).map((l) => l.name)).toEqual(['ExtLib']); // demangled artifact name
    expect(dep.creationBytecode).toBe(flat.creationBytecode); // identical link placeholder
    expect(dep.libraries?.[0]?.creationBytecode).toBe(flat.libraries?.[0]?.creationBytecode);
    // two EXTERNAL libraries sharing a source name -> link symbols would collide -> JETH037
    expect(diag(`import { ExtLib as L1 } from "./a.jeth";\nimport { ExtLib as L2 } from "./b.jeth";\nclass C { f(a: u256): External<u256> { return L1.double(a) + L2.triple(a); } }`,
      { 'a.jeth': `export static class ExtLib { double(a: u256): External<u256> { return a + a; } }`,
        'b.jeth': `export static class ExtLib { triple(a: u256): External<u256> { return a + a + a; } }` })
      .some((x) => x.startsWith('JETH037'))).toBe(true);
    // two INTERNAL libraries sharing a source name are fine (nothing links)
    expect(diag(`import { M as M1 } from "./a.jeth";\nimport { M as M2 } from "./b.jeth";\nclass C { get f(a: u256): External<u256> { return M1.d(a) + M2.t(a); } }`,
      { 'a.jeth': `export static class M { d(a: u256): u256 { return a + a; } }`,
        'b.jeth': `export static class M { t(a: u256): u256 { return a + a + a; } }` })).toEqual([]);
  });

  it('rename hazards reject LOUDLY: import-vs-local, import-vs-decl, dual import, dep builtin, dep self-shadow, $mN$', () => {
    const M = `export static class M { min(self: u256, b: u256): u256 { return self < b ? self : b; } }`;
    expect(diag(`import { M } from "./m.jeth";\nclass V { get f(a: u256): External<u256> { let M: u256 = a; return M; } }`, { 'm.jeth': M })
      .some((x) => x.startsWith('JETH036'))).toBe(true); // a local may not shadow a (renamed) import
    expect(diag(`import { P } from "./p.jeth";\ntype P = { a: u256 };\nclass V { get f(): External<u256> { return 1n; } }`, { 'p.jeth': `export type P = { b: u256 };` })
      .some((x) => x.startsWith('JETH036'))).toBe(true); // importing a name you also declare
    expect(diag(`import { P } from "./a.jeth";\nimport { P } from "./b.jeth";\nclass V { get f(): External<u256> { return 1n; } }`,
      { 'a.jeth': `export type P = { a: u256 };`, 'b.jeth': `export type P = { b: u256 };` })
      .some((x) => x.startsWith('JETH036'))).toBe(true); // same local name from two files: alias one
    expect(diag(`import { T } from "./d.jeth";\nclass V { get f(): External<u256> { return 1n; } }`,
      { 'd.jeth': `export type T = { a: u256 };\nexport static class msg { s(): u256 { return 1n; } }` }))
      .toContain('JETH038@d.jeth:2'); // a dep top-level shadowing a builtin (the bundler-side JETH038)
    expect(diag(`import { A } from "./a.jeth";\nclass V { get f(): External<u256> { return A.fa(1n); } }`,
      { 'a.jeth': `export type T = { a: u256 };\nexport static class A { fa(T: u256): u256 { return T; } }` })
      .some((x) => x.startsWith('JETH036'))).toBe(true); // a dep local shadowing its own top-level
    expect(diag(`import { A } from "./a.jeth";\nclass V { get f(): External<u256> { return A.fa(); } }`,
      { 'a.jeth': `export static class A { fa(): u256 { return $m0$x(); } }` })
      .some((x) => x.startsWith('JETH036@a.jeth:1'))).toBe(true); // `$mN$` identifiers are reserved in a bundle
  });

  it('renamed-name machinery keeps working: attachments, static consts, # privates - and diagnostics demangle', async () => {
    const M = (v: string) => `export static class M { min(self: u256, b: u256): u256 { return self < b ? self : ${v}; } }`;
    // self-convention attachment on a renamed dep lib; TWO same-named self-libs -> the ambiguity reject
    expect(diag(`import { M } from "./m.jeth";\nclass V { get f(x: u256, y: u256): External<u256> { return x.min(y); } }`, { 'm.jeth': M('b') })).toEqual([]);
    expect(diag(`import { M as M1 } from "./a.jeth";\nimport { M as M2 } from "./b.jeth";\nclass V { get f(x: u256, y: u256): External<u256> { return x.min(y); } }`,
      { 'a.jeth': M('b'), 'b.jeth': M('0n') }).some((x) => x.startsWith('JETH393'))).toBe(true);
    // static const on a renamed dep base via the ClassName.K rewrite; # private inside a renamed base
    const r = compile(`import { Base } from "./b.jeth";\nclass C extends Base { get f(): External<u256> { return Base.K + this.pub(); } }`,
      { fileName: 'c.jeth', sources: { 'b.jeth': `export abstract class Base { static K: u256 = 40n; #inner(): u256 { return 2n; } pub(): u256 { return this.#inner(); } }` } });
    const h = await Harness.create();
    const addr = await h.deploy(r.creationBytecode);
    expect(BigInt((await h.call(addr, sel('f()'))).returnHex)).toBe(42n);
    // diagnostics never leak `$m` (module mangle) or `$p$` (private mangle) spellings
    const msgs = diag(`import { L } from "./dep.jeth";\nclass C { get f(): External<u256> { return L.bad(9n); } }`,
      { 'dep.jeth': `export static class L {\n  bad(a: u256): u256 { return this.x; }\n}` });
    expect(msgs.length).toBeGreaterThan(0);
    expect(msgs.some((x) => x.includes('$m') || x.includes('$p$'))).toBe(false);
  });
});
