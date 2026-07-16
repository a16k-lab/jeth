// MEMBER-vs-IMPORTED-TYPE collision, ALL member kinds. USER RULING (2026-07-16): multi-file behavior must
// equal single-file behavior EXACTLY - thrown code lists included - across the whole name-collision family.
// The single-file analyzer rejects a contract MEMBER of any single kind (state field / constant / immutable
// / mapping / struct-typed / Visible / getter / method / member error / member event / @modifier, own or
// inherited) sharing a name with a file-level error / event / struct / enum / interface / Brand at the
// DECLARATION, [JETH133], used or not (the blanket cross-scope gate is the language rule). The multi-file
// bundle previously diverged: the v3 alpha-rename hid the imported decl from that gate, so an UNUSED
// collision was ACCEPTED and a USED one rejected with use-site codes (JETH129 error-ref / JETH147 event-ref
// / JETH013 type-ref) instead of the single-file [JETH133]. collectImportedMemberTypeCollisions
// (src/compile.ts) now mirrors the single-file gate over imported declarations for the route contract's
// full `extends` chain and disables the value-member reference shadow for the fired names, so the
// multi-file code list equals the single-file twin's exactly. The ONLY single-kind coexistence exemptions
// (witnessed on the single-file path): member error<{}> x file error, member event<{}> x file event (the
// member shadows - the C2 lift), and @modifier x file type.
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
const DEP_IF = `export interface Bad { z(): void; }`;

const mcodes = (entry: string, sources: Record<string, string>): string[] => {
  try { compile(entry, { fileName: 'entry.jeth', sources }); return []; }
  catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};
const scodes = (src: string): string[] => {
  try { compile(src, { fileName: 'entry.jeth' }); return []; }
  catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};
const accepts = (entry: string, sources: Record<string, string>): boolean => {
  try { compile(entry, { fileName: 'entry.jeth', sources }); return true; } catch { return false; }
};

// value-member forms keyed by the colliding name Bad
const MEMBER: Record<string, string> = {
  field:       `Bad: u256;`,
  constant:    `static Bad: u256 = 5n;`,
  immutable:   `static Bad: u256; constructor(){ this.Bad = 7n; }`,
  mapping:     `Bad: mapping<u256, u256>;`,
  structTyped: `Bad: S;`,
  public:      `Bad: Visible<u256>;`,
};

describe('MEMBER-vs-IMPORTED-ERROR: each value-member kind rejects the DECL [JETH133], == single-file', () => {
  for (const [kind, decl] of Object.entries(MEMBER)) {
    it(`error x member:${kind} (used) -> [JETH133], the single-file code (was the use-site JETH129)`, () => {
      const structPre = kind === 'structTyped' ? `type S = { q: u256 };\n` : '';
      const body = `${decl} f(): External<void> { revert(Bad(1n)); }`;
      const entry = `import { Bad } from "./e.jeth";\n${structPre}class C { ${body} }`;
      const multi = mcodes(entry, { 'e.jeth': DEP_E });
      expect(multi).toEqual(['JETH133']);
      // the decisive oracle: the multi list equals the single-file twin's list EXACTLY
      expect(multi).toEqual(scodes(`type Bad = error<{ a: u256 }>;\n${structPre}class C { ${body} }`));
    });
  }
});

describe('MEMBER-vs-IMPORTED-EVENT: each value-member kind rejects the DECL [JETH133], == single-file', () => {
  for (const [kind, decl] of Object.entries(MEMBER)) {
    it(`event x member:${kind} (used) -> [JETH133], the single-file code (was the use-site JETH147)`, () => {
      const structPre = kind === 'structTyped' ? `type S = { q: u256 };\n` : '';
      const body = `${decl} f(): External<void> { emit(Bad(1n)); }`;
      const entry = `import { Bad } from "./e.jeth";\n${structPre}class C { ${body} }`;
      const multi = mcodes(entry, { 'e.jeth': DEP_V });
      expect(multi).toEqual(['JETH133']);
      expect(multi).toEqual(scodes(`type Bad = event<{ a: u256 }>;\n${structPre}class C { ${body} }`));
    });
  }
});

describe('MEMBER-vs-IMPORTED-TYPE (struct/enum/interface): the DECL rejects [JETH133], == single-file', () => {
  const cell = (entry: string, sources: Record<string, string>, single: string): void => {
    const multi = mcodes(entry, sources);
    expect(multi).toContain('JETH133');
    // compared as SORTED sets where a companion exists: the single-file bag lists analyzer codes before
    // the gate's JETH133 while the multi bag lists the pre-pass JETH133 first (the same pre-existing
    // collection-order difference the bare-bodyless parity suite documents; not a behavior difference).
    expect([...multi].sort()).toEqual([...scodes(single)].sort());
  };
  it('imported struct + member field, struct used as a field type', () => {
    cell(`import { Bad } from "./s.jeth";\nclass C { Bad: u256; y: Bad; f(): External<void> { this.Bad = 1n; } }`, { 's.jeth': DEP_S },
         `type Bad = { a: u256 };\nclass C { Bad: u256; y: Bad; f(): External<void> { this.Bad = 1n; } }`);
  });
  it('imported struct + member field, struct used as an array field type Bad[]', () => {
    cell(`import { Bad } from "./s.jeth";\nclass C { Bad: u256; y: Bad[]; f(): External<void> { this.Bad = 1n; } }`, { 's.jeth': DEP_S },
         `type Bad = { a: u256 };\nclass C { Bad: u256; y: Bad[]; f(): External<void> { this.Bad = 1n; } }`);
  });
  it('imported struct + member field, struct used as a mapping value type mapping<_, Bad>', () => {
    cell(`import { Bad } from "./s.jeth";\nclass C { Bad: u256; y: mapping<u256, Bad>; f(): External<void> { this.Bad = 1n; } }`, { 's.jeth': DEP_S },
         `type Bad = { a: u256 };\nclass C { Bad: u256; y: mapping<u256, Bad>; f(): External<void> { this.Bad = 1n; } }`);
  });
  it('imported enum + member field, enum used as a field type s: Bad', () => {
    cell(`import { Bad } from "./n.jeth";\nclass C { Bad: u256; s: Bad; f(): External<void> { this.s = Bad.A; } }`, { 'n.jeth': DEP_EN },
         `enum Bad { A, B }\nclass C { Bad: u256; s: Bad; f(): External<void> { this.s = Bad.A; } }`);
  });
  it('imported enum + member field, enum used in value position Bad.A', () => {
    cell(`import { Bad } from "./n.jeth";\nclass C { Bad: u256; s: u8; f(): External<void> { this.s = u8(Bad.A); } }`, { 'n.jeth': DEP_EN },
         `enum Bad { A, B }\nclass C { Bad: u256; s: u8; f(): External<void> { this.s = u8(Bad.A); } }`);
  });
  it('imported interface + member field (unused): [JETH133] both paths', () => {
    const multi = mcodes(`import { Bad } from "./i.jeth";\nclass C { Bad: u256; g(): External<void> {} }`, { 'i.jeth': DEP_IF });
    expect(multi).toEqual(['JETH133']);
    expect(multi).toEqual(scodes(`interface Bad { z(): void; }\nclass C { Bad: u256; g(): External<void> {} }`));
  });
  it('KNOWN RESIDUAL - interface CAST use `Bad(a)`: both paths reject with JETH133; single adds a JETH074', () => {
    // The single-file analyzer resolves a bare CALL `Bad(a)` member-first, so the already-JETH133-rejected
    // program gains an incidental use-site companion (JETH074 "unsupported expression") that the multi-file
    // path - which binds the fired name to the import, like every other position - does not reproduce.
    // Reproducing it would mean reimplementing the analyzer's callee-resolution order inside the renamer;
    // both paths reject and both lists carry the decisive JETH133, so the companion delta is accepted.
    const use = `f(a: address): External<void> { let i: Bad = Bad(a); i.z(); }`;
    const multi = mcodes(`import { Bad } from "./i.jeth";\nclass C { Bad: u256; g(): External<void> {} ${use} }`, { 'i.jeth': DEP_IF });
    const single = scodes(`interface Bad { z(): void; }\nclass C { Bad: u256; g(): External<void> {} ${use} }`);
    expect(multi).toEqual(['JETH133']);
    expect(single).toContain('JETH133');
  });
});

describe('MEMBER-vs-IMPORTED-TYPE: UNUSED collisions reject too ([JETH133] both paths - the blanket gate)', () => {
  for (const [kind, decl] of Object.entries(MEMBER)) {
    it(`unused error x member:${kind} -> [JETH133] == single-file (was ACCEPT in multi)`, () => {
      const structPre = kind === 'structTyped' ? `type S = { q: u256 };\n` : '';
      const body = `${decl} g(): External<void> {}`;
      const multi = mcodes(`import { Bad } from "./e.jeth";\n${structPre}class C { ${body} }`, { 'e.jeth': DEP_E });
      expect(multi).toEqual(['JETH133']);
      expect(multi).toEqual(scodes(`type Bad = error<{ a: u256 }>;\n${structPre}class C { ${body} }`));
    });
  }
});

describe('GET ACCESSOR + INHERITED / LIBRARY / ALIASED collisions', () => {
  it('get accessor colliding with the imported error (USED raise): [JETH133] both paths (was ACCEPT in multi)', () => {
    const body = `x: u256; get Bad(): External<u256> { return this.x; } f(): External<void> { revert(Bad(1n)); }`;
    const multi = mcodes(`import { Bad } from "./e.jeth";\nclass C { ${body} }`, { 'e.jeth': DEP_E });
    expect(multi).toEqual(['JETH133']);
    expect(multi).toEqual(scodes(`type Bad = error<{ a: u256 }>;\nclass C { ${body} }`));
  });
  it('INHERITED value member (base declared in the entry) colliding with the imported error: [JETH133]', () => {
    expect(mcodes(`import { Bad } from "./e.jeth";\nclass Base { Bad: u256; }\nclass C extends Base { f(): External<void> { revert(Bad(1n)); } }`, { 'e.jeth': DEP_E })).toEqual(['JETH133']);
  });
  it('INHERITED value member (base IMPORTED from another file, abstract) colliding with the imported error: [JETH133]', () => {
    expect(mcodes(`import { Bad } from "./e.jeth";\nimport { Base } from "./b.jeth";\nclass C extends Base { f(): External<void> { revert(Bad(1n)); } }`, { 'e.jeth': DEP_E, 'b.jeth': `export abstract class Base { Bad: u256; }` })).toEqual(['JETH133']);
  });
  it('INHERITED get accessor (imported abstract base) colliding with the imported error (USED): [JETH133]', () => {
    expect(mcodes(`import { Bad } from "./e.jeth";\nimport { B } from "./b.jeth";\nclass C extends B { f(): External<void> { revert(Bad(1n)); } }`, { 'e.jeth': DEP_E, 'b.jeth': `export abstract class B { x: u256; get Bad(): External<u256> { return this.x; } }` })).toEqual(['JETH133']);
  });
  it('LIBRARY body member shadowing the imported error keeps its use-site reject (JETH129, unchanged)', () => {
    // A library is OUTSIDE the contract-member gate (the single-file path even accepts this shape); the
    // multi-file use-site reject predates the ruling and REMOVING it would flip a reject to an accept,
    // which the ruling forbids - so the library axis keeps the reference-shadow JETH129 exactly as before.
    expect(mcodes(`import { Bad } from "./e.jeth";\nstatic class L { static Bad: u256 = 5n; g(): u256 { revert(Bad(1n)); return 0n; } }\nclass C { get f(): External<u256> { return L.g(); } }`, { 'e.jeth': DEP_E })).toContain('JETH129');
  });
  it('an ALIASED import (import { Bad as X }) colliding with a member named X: [JETH133]', () => {
    expect(mcodes(`import { Bad as X } from "./e.jeth";\nclass C { X: u256; f(): External<void> { revert(X(1n)); } }`, { 'e.jeth': DEP_E })).toEqual(['JETH133']);
  });
});

describe('CONTROLS: coexistence + non-colliding shapes stay ACCEPTED (no over-rejection added)', () => {
  it('the imported error with NO colliding member still resolves the file-level import', () => {
    expect(accepts(`import { Bad } from "./e.jeth";\nclass C { f(): External<void> { revert(Bad(7n)); } }`, { 'e.jeth': DEP_E })).toBe(true);
  });
  it('F4: a member ERROR sharing the imported error name (same-kind coexistence, member shadows) ACCEPTS', () => {
    expect(accepts(`import { Bad } from "./e.jeth";\nclass C { Bad: error<{ a: u256 }>; f(): External<void> { revert(Bad(2n)); } }`, { 'e.jeth': DEP_E })).toBe(true);
  });
  it('F4-event: a member EVENT sharing the imported event name ACCEPTS', () => {
    expect(accepts(`import { Bad } from "./e.jeth";\nclass C { Bad: event<{ b: address }>; f(a: address): External<void> { emit(Bad(a)); } }`, { 'e.jeth': DEP_V })).toBe(true);
  });
  it('@modifier sharing an imported STRUCT name ACCEPTS (modifier x type coexists, == single-file)', () => {
    expect(accepts(`import { Bad } from "./s.jeth";\nclass C { @modifier Bad() { _; } g(): External<void> {} }`, { 's.jeth': DEP_S })).toBe(true);
  });
  it('@modifier sharing an imported ERROR name rejects [JETH133] (== single-file; was ACCEPT in multi)', () => {
    const multi = mcodes(`import { Bad } from "./e.jeth";\nclass C { @modifier Bad() { _; } g(): External<void> {} }`, { 'e.jeth': DEP_E });
    expect(multi).toEqual(['JETH133']);
    expect(multi).toEqual(scodes(`type Bad = error<{ a: u256 }>;\nclass C { @modifier Bad() { _; } g(): External<void> {} }`));
  });
  it('NON-COLLIDING member + imported error: a differently-named member resolves the import unchanged', () => {
    expect(accepts(`import { Bad } from "./e.jeth";\nclass C { gg(): u256 { return 1n; } f(): External<void> { revert(Bad(1n)); } }`, { 'e.jeth': DEP_E })).toBe(true);
  });
});

// METHOD-vs-IMPORTED-TYPE collision (the original family, unchanged): a contract METHOD whose name equals a
// same-named IMPORTED file-level error / event / struct / enum / interface is the same DECLARATION collision
// - the single-file analyzer rejects it JETH133 and the pre-pass mirrors it. This is a DELIBERATE reject
// (methods are camelCase, types/errors/events PascalCase) endorsed by the user, firing regardless of use.
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
    expect(scodes(`type Bad = error<{ a: u256 }>;\nclass C { Bad(): u256 { return 5n; } f(): External<void> { revert(Bad(1n)); } }`)).toContain('JETH133');
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
