// MEMBER-SHADOW-IMPORT: a contract VALUE MEMBER (state field / constant / immutable / mapping / struct-typed
// / public field, incl. one INHERITED via `extends` or declared in a LIBRARY body) SHADOWS a same-named
// IMPORTED file-level symbol (error / event / struct / enum / interface). solc resolves a bare `Bad(...)` /
// `revert(Bad(...))` / `emit(Bad(...))` / a type-position `Bad`/`Bad[]`/`mapping<_,Bad>` / an enum use
// `Bad.A` / an interface cast `Bad(a)` to the MEMBER, then rejects ("This expression is not callable" for an
// error/event ref, "Name has to refer to a user-defined type" for a type/enum/interface ref). Before the fix,
// the v3 module alpha-rename rewrote the bare reference to the imported `$mN$Bad` and routed AROUND the member
// (an over-acceptance family: JETH accepted, solc rejected). rewriteModuleScopes now leaves a reference
// shadowed by ANY value member (own or inherited) UNRENAMED, so resolution binds it to the member and the
// analyzer's existing member-shadow logic fires the SAME reject the single-file path gives (JETH129 for an
// error ref, JETH147 for an event ref, JETH013 for a type/enum/interface ref). METHOD members are out of
// scope for THIS (value-member reference-unrenaming) mechanism; a method that COLLIDES with an imported
// error/event/struct/enum/interface is instead a DECLARATION collision handled separately by
// collectImportedMethodTypeCollisions (JETH133) - see the METHOD-vs-IMPORTED-TYPE block at the bottom.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);

const DEP_E = `export type Bad = error<{ a: u256 }>;`;
const DEP_V = `export type Bad = event<{ a: u256 }>;`;
const DEP_S = `export type Bad = { a: u256 };`;
const DEP_EN = `export enum Bad { A, B }`;
const DEP_IF = `export interface Bad { z(): External<void>; }`;

const mcodes = (entry: string, sources: Record<string, string>): string[] => {
  try { compile(entry, { fileName: 'entry.jeth', sources }); return []; }
  catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};
const accepts = (entry: string, sources: Record<string, string>): boolean => {
  try { compile(entry, { fileName: 'entry.jeth', sources }); return true; } catch { return false; }
};

// value-member forms keyed by the shadowed name Bad
const MEMBER: Record<string, string> = {
  field:       `Bad: u256;`,
  constant:    `static Bad: u256 = 5n;`,
  immutable:   `static Bad: u256; constructor(){ this.Bad = 7n; }`,
  mapping:     `Bad: mapping<u256, u256>;`,
  structTyped: `Bad: S;`,
  public:      `Bad: Visible<u256>;`,
};

describe('MEMBER-SHADOW-IMPORT: an error-ref shadowed by each value-member kind REJECTS (JETH129, solc: not callable)', () => {
  for (const [kind, decl] of Object.entries(MEMBER)) {
    it(`error ref x member:${kind}`, () => {
      const structPre = kind === 'structTyped' ? `type S = { q: u256 };\n` : '';
      const entry = `import { Bad } from "./e.jeth";\n${structPre}class C { ${decl} f(): External<void> { revert(Bad(1n)); } }`;
      expect(mcodes(entry, { 'e.jeth': DEP_E })).toContain('JETH129');
    });
  }
});

describe('MEMBER-SHADOW-IMPORT: an event-ref shadowed by each value-member kind REJECTS (JETH147, solc: not callable)', () => {
  for (const [kind, decl] of Object.entries(MEMBER)) {
    it(`event ref x member:${kind}`, () => {
      const structPre = kind === 'structTyped' ? `type S = { q: u256 };\n` : '';
      const entry = `import { Bad } from "./e.jeth";\n${structPre}class C { ${decl} f(): External<void> { emit(Bad(1n)); } }`;
      expect(mcodes(entry, { 'e.jeth': DEP_V })).toContain('JETH147');
    });
  }
});

describe('MEMBER-SHADOW-IMPORT: a TYPE/ENUM/INTERFACE reference shadowed by a value member REJECTS (JETH013, solc: not a user-defined type)', () => {
  it('imported struct used as a field type (member field Bad)', () => {
    expect(mcodes(`import { Bad } from "./s.jeth";\nclass C { Bad: u256; y: Bad; f(): External<void> { this.Bad = 1n; } }`, { 's.jeth': DEP_S })).toContain('JETH013');
  });
  it('imported struct used as an array field type Bad[]', () => {
    expect(mcodes(`import { Bad } from "./s.jeth";\nclass C { Bad: u256; y: Bad[]; f(): External<void> { this.Bad = 1n; } }`, { 's.jeth': DEP_S })).toContain('JETH013');
  });
  it('imported struct used as a mapping value type mapping<_, Bad>', () => {
    expect(mcodes(`import { Bad } from "./s.jeth";\nclass C { Bad: u256; y: mapping<u256, Bad>; f(): External<void> { this.Bad = 1n; } }`, { 's.jeth': DEP_S })).toContain('JETH013');
  });
  it('imported enum used as a field type s: Bad', () => {
    expect(mcodes(`import { Bad } from "./n.jeth";\nclass C { Bad: u256; s: Bad; f(): External<void> { this.s = Bad.A; } }`, { 'n.jeth': DEP_EN })).toContain('JETH013');
  });
  it('imported enum used in value position Bad.A REJECTS (JETH074, solc: member A not found on uint256)', () => {
    expect(mcodes(`import { Bad } from "./n.jeth";\nclass C { Bad: u256; s: u8; f(): External<void> { this.s = u8(Bad.A); } }`, { 'n.jeth': DEP_EN })).toContain('JETH074');
  });
  it('imported interface used as a field type s: Bad', () => {
    expect(mcodes(`import { Bad } from "./i.jeth";\nclass C { Bad: u256; f(a: address): External<void> { let i: Bad = Bad(a); this.Bad = 1n; } }`, { 'i.jeth': DEP_IF })).toContain('JETH013');
  });
});

describe('MEMBER-SHADOW-IMPORT: an INHERITED / LIBRARY / ALIASED shadow REJECTS too', () => {
  it('INHERITED value member (base declared in the entry) shadows the imported error', () => {
    expect(mcodes(`import { Bad } from "./e.jeth";\nclass Base { Bad: u256; }\nclass C extends Base { f(): External<void> { revert(Bad(1n)); } }`, { 'e.jeth': DEP_E })).toContain('JETH129');
  });
  it('INHERITED value member (base IMPORTED from another file, abstract) shadows the imported error', () => {
    expect(mcodes(`import { Bad } from "./e.jeth";\nimport { Base } from "./b.jeth";\nclass C extends Base { f(): External<void> { revert(Bad(1n)); } }`, { 'e.jeth': DEP_E, 'b.jeth': `export abstract class Base { Bad: u256; }` })).toContain('JETH129');
  });
  it('a value member in a LIBRARY body shadows the imported error inside a library fn', () => {
    expect(mcodes(`import { Bad } from "./e.jeth";\nstatic class L { static Bad: u256 = 5n; g(): u256 { revert(Bad(1n)); return 0n; } }\nclass C { get f(): External<u256> { return L.g(); } }`, { 'e.jeth': DEP_E })).toContain('JETH129');
  });
  it('an ALIASED import (import { Bad as X }) is shadowed by a member named X', () => {
    expect(mcodes(`import { Bad as X } from "./e.jeth";\nclass C { X: u256; f(): External<void> { revert(X(1n)); } }`, { 'e.jeth': DEP_E })).toContain('JETH129');
  });
});

describe('MEMBER-SHADOW-IMPORT CONTROLS: over-rejection guards (must stay ACCEPTED / unchanged)', () => {
  it('NO-REFERENCE decl collision: an imported error + a same-named member never referenced still ACCEPTS (solc allows the shadow)', () => {
    expect(accepts(`import { Bad } from "./e.jeth";\nclass C { Bad: u256; f(): External<void> { this.Bad = 1n; } }`, { 'e.jeth': DEP_E })).toBe(true);
  });
  it('the SAME imported error, imported into a contract with NO member, still resolves the file-level import (fix did not change it)', () => {
    expect(accepts(`import { Bad } from "./e.jeth";\nclass C { f(): External<void> { revert(Bad(7n)); } }`, { 'e.jeth': DEP_E })).toBe(true);
  });
  it('a member ERROR shadowing a same-named imported error, raised to FIT the member, still ACCEPTS', () => {
    expect(accepts(`import { Bad } from "./e.jeth";\nclass C { Bad: error<{ a: u256 }>; f(): External<void> { revert(Bad(2n)); } }`, { 'e.jeth': DEP_E })).toBe(true);
  });
  it('NON-COLLIDING method + imported error: a differently-named method resolves the import unchanged (still ACCEPTS)', () => {
    // The value-member shadow mechanism (reference-unrenaming) never touches a method; a method whose name
    // does NOT collide with the import leaves the bare `Bad(1n)` bound to the import exactly as base.
    expect(accepts(`import { Bad } from "./e.jeth";\nclass C { gg(): u256 { return 1n; } f(): External<void> { revert(Bad(1n)); } }`, { 'e.jeth': DEP_E })).toBe(true);
  });
});

// METHOD-vs-IMPORTED-TYPE collision: a contract METHOD whose name equals a same-named IMPORTED file-level
// error / event / struct / enum / interface is a DECLARATION collision solc rejects (the member shadows the
// import, so any use resolves to the 0-arg method - "Wrong argument count" / "Name has to refer to a
// user-defined type"). The SINGLE-FILE analyzer already rejects it JETH133; the v3 rename mangled the import
// to `$mN$X` and routed the bundle around that gate (a pre-existing over-acceptance). collectImportedMethod-
// TypeCollisions (compile.ts) restores the SAME JETH133 for the cross-file (imported) case. This is a
// DELIBERATE reject (methods are camelCase, types/errors/events PascalCase) endorsed by the user, and it
// fires regardless of whether the name is USED - byte-consistent with the single-file path (which likewise
// rejects the no-use collision, even though solc accepts the pure no-use shadow).
describe('METHOD-vs-IMPORTED-TYPE collision REJECTS JETH133 (multi-file, mirrors the single-file gate)', () => {
  const USE: Record<string, { dep: string; body: string }> = {
    error:     { dep: DEP_E,  body: `f(): External<void> { revert(Bad(1n)); }` },
    event:     { dep: DEP_V,  body: `f(): External<void> { emit(Bad(1n)); }` },
    struct:    { dep: DEP_S,  body: `f(): External<void> { let s: Bad = { a: 1n }; }` },
    enum:      { dep: DEP_EN, body: `f(): External<void> { let s: Bad = Bad.A; }` },
    interface: { dep: DEP_IF, body: `f(a: address): External<void> { Bad(a).z(); }` },
  };
  for (const [kind, { dep, body }] of Object.entries(USE)) {
    it(`method collides with imported ${kind} (used) -> JETH133`, () => {
      const entry = `import { Bad } from "./d.jeth";\nclass C { Bad(): u256 { return 5n; } ${body} }`;
      expect(mcodes(entry, { 'd.jeth': dep })).toContain('JETH133');
    });
  }
  it('NO-USE collision: method Bad + imported error Bad, never used -> still JETH133 (matches single-file)', () => {
    expect(mcodes(`import { Bad } from "./d.jeth";\nclass C { Bad(): u256 { return 5n; } g(): External<void> {} }`, { 'd.jeth': DEP_E })).toContain('JETH133');
  });
  it('the multi-file JETH133 matches what the SINGLE-FILE analyzer emits for the same shape', () => {
    const single = (src: string): string[] => { try { compile(src, { fileName: 'entry.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; } };
    expect(single(`type Bad = error<{ a: u256 }>;\nclass C { Bad(): u256 { return 5n; } f(): External<void> { revert(Bad(1n)); } }`)).toContain('JETH133');
  });
});

// NON-VACUOUS run+decode: prove which symbol a member-bearing raise / a no-member raise binds to, byte-identical
// to solc. A wrong pick (imported Bad(uint256)=a2f43130 vs member Bad(address)=830c4ac2) would be decodable.
describe('MEMBER-SHADOW-IMPORT: member/import binding is byte-identical to solc (decode)', () => {
  async function raiseMF(entry: string, sources: Record<string, string>, S: string, callSig = 'f()', args = ''): Promise<{ j: any; s: any }> {
    const h = await Harness.create();
    const aj = await h.deploy(compile(entry, { fileName: 'entry.jeth', sources }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const shape = async (addr: typeof aj) => {
      const r = await h.call(addr, '0x' + sel(callSig) + args);
      return { success: r.success, ret: r.returnHex, topic0: r.logs[0]?.topics[0] ?? null };
    };
    return { j: await shape(aj), s: await shape(as) };
  }

  it('a member error/event fitting an address arg binds the MEMBER selector/topic0, not the imported uint256 one', async () => {
    const arg = '11'.padStart(64, '0');
    const err = await raiseMF(
      `import { Bad } from "./e.jeth";\nclass C { Bad: error<{ b: address }>; f(a: address): External<void> { revert(Bad(a)); } }`, { 'e.jeth': DEP_E },
      `error Bad(uint256 a);\ncontract C { error Bad(address b); function f(address a) external { revert Bad(a); } }`, 'f(address)', arg,
    );
    expect(err.j).toEqual(err.s);
    expect(err.j.success).toBe(false);
    expect(err.j.ret.slice(0, 10)).toBe('0x' + sel('Bad(address)').slice(0, 8));
    expect(err.j.ret.slice(0, 10)).not.toBe('0x' + sel('Bad(uint256)').slice(0, 8));
    const evt = await raiseMF(
      `import { Bad } from "./e.jeth";\nclass C { Bad: event<{ b: address }>; f(a: address): External<void> { emit(Bad(a)); } }`, { 'e.jeth': DEP_V },
      `event Bad(uint256 a);\ncontract C { event Bad(address b); function f(address a) external { emit Bad(a); } }`, 'f(address)', arg,
    );
    expect(evt.j).toEqual(evt.s);
    expect(evt.j.topic0!.slice(0, 10)).toBe('0x' + sel('Bad(address)').slice(0, 8));
    expect(evt.j.topic0!.slice(0, 10)).not.toBe('0x' + sel('Bad(uint256)').slice(0, 8));
  });

  it('the imported file-level error with NO member resolves to the IMPORT, byte-identical to solc', async () => {
    const err = await raiseMF(
      `import { Bad } from "./e.jeth";\nclass C { f(): External<void> { revert(Bad(7n)); } }`, { 'e.jeth': DEP_E },
      `error Bad(uint256 a);\ncontract C { function f() external { revert Bad(7); } }`,
    );
    expect(err.j).toEqual(err.s);
    expect(err.j.ret).toBe('0x' + sel('Bad(uint256)') + '0'.repeat(63) + '7'); // the IMPORTED file-level selector
  });
});
