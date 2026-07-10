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

  it('rejects: unexported name, unknown path, cycle, contract-in-dep, mode mismatch, alias - each at the right file:line', () => {
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
      .toEqual(['JETH036@d.jeth:1']); // cross-mode import
    expect(diag(`import { A as B } from "./a.jeth";\nclass C { get f(): External<u256> { return 1n; } }`, { 'a.jeth': `export static class A { f(): u256 { return 1n; } }` }))
      .toEqual(['JETH036@vault.jeth:1']); // alias (v1)
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
  it('duplicate contract/abstract/library class names reject (JETH037) - the last-wins hole is closed', () => {
    // cross-file: a named import must never silently bind to a DIFFERENT file's same-named declaration.
    expect(diag(`import { Base } from "./a.jeth";\nimport { Other } from "./b.jeth";\nclass C extends Base { get f(): External<u256> { return this.v(); } }`,
      { 'a.jeth': `export abstract class Base { v(): u256 { return 1n; } }`, 'b.jeth': `export abstract class Base { v(): u256 { return 2n; } }\nexport abstract class Other { }` }))
      .toEqual(['JETH037@b.jeth:1']);
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
      { 'dep.jeth': `export type T = { a: u256 };\n{ @contract class Rogue { @external @view g(): u256 { return 99n; } } }` }))
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
