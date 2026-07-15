// CROSS-SCOPE-NAME: a FILE-LEVEL error/event (`type Bad = error<{...}>` / `event<{...}>`) and a same-named
// CONTRACT-MEMBER error/event are DIFFERENT scopes in solc (file scope vs contract scope), so they COEXIST -
// the member SHADOWS the file-level owner inside the contract, and a bare name with no member owner resolves
// to the file-level. Witnessed on solc 0.8.35:
//   - `revert Bad(...)` / `emit Bad(...)` / `this.Bad(...)` inside the contract -> the MEMBER (shadowing).
//   - the file-level overload is INVISIBLE once a member exists (a bare name with the file-level arg type
//     that the member cannot take is a compile error, NOT a silent file-level pick).
//   - a bare name in a contract with NO member owner -> the file-level.
//   - same-signature file-level + member is accepted (no duplicate error).
// solc rejects (kept here): two same-scope duplicates (two file-level `Bad`, two member `Bad`), a file-level
// type sharing the DEPLOYED-CONTRACT name (JETH272), and a member cross-kind clash (JETH133). Each cell below
// decodes the revert selector / event topic0 so a wrong symbol pick (different signature -> different
// selector/topic0) would be a decodable miscompile, not a silently-green "both accept".
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

// Deploy JETH + solc, call `f()`, and return the (success, revert-selector, event-topic0) triple for each.
async function raise(J: string, S: string, callSig = 'f()'): Promise<{ j: any; s: any }> {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  const shape = async (addr: typeof aj) => {
    const r = await h.call(addr, '0x' + sel(callSig));
    return { success: r.success, ret: r.returnHex, topic0: r.logs[0]?.topics[0] ?? null };
  };
  return { j: await shape(aj), s: await shape(as) };
}

describe('CROSS-SCOPE-NAME: file-level error/event vs same-named contract member (member shadows)', () => {
  it('ERROR this.Bad resolves to the MEMBER (member selector), byte-identical to solc', async () => {
    const { j, s } = await raise(
      `type Bad = error<{ a: u256 }>;\nclass C { Bad: error<{ b: address }>; f(): External<void> { throw this.Bad({ b: msg.sender }); } }`,
      `error Bad(uint256 a);\ncontract C { error Bad(address b); function f() external { revert Bad(msg.sender); } }`,
    );
    expect(j).toEqual(s);
    expect(j.success).toBe(false);
    expect(j.ret.slice(0, 10)).toBe('0x' + sel('Bad(address)').slice(0, 8)); // MEMBER, not file-level Bad(uint256)
    expect(j.ret.slice(0, 10)).not.toBe('0x' + sel('Bad(uint256)').slice(0, 8));
  });

  it('ERROR bare revert(Bad(...)) resolves to the MEMBER (shadowing), byte-identical to solc', async () => {
    const { j, s } = await raise(
      `type Bad = error<{ a: u256 }>;\nclass C { Bad: error<{ b: address }>; f(): External<void> { revert(Bad(msg.sender)); } }`,
      `error Bad(uint256 a);\ncontract C { error Bad(address b); function f() external { revert Bad(msg.sender); } }`,
    );
    expect(j).toEqual(s);
    expect(j.ret.slice(0, 10)).toBe('0x' + sel('Bad(address)').slice(0, 8));
  });

  it('EVENT this.Bad + bare emit both resolve to the MEMBER topic0, byte-identical to solc', async () => {
    const { j, s } = await raise(
      `type Bad = event<{ a: u256 }>;\nclass C { Bad: event<{ b: address }>; f(): External<void> { emit(this.Bad({ b: msg.sender })); } g(): External<void> { emit(Bad(msg.sender)); } }`,
      `event Bad(uint256 a);\ncontract C { event Bad(address b); function f() external { emit Bad(msg.sender); } function g() external { emit Bad(msg.sender); } }`,
    );
    expect(j).toEqual(s);
    expect(j.topic0!.slice(0, 10)).toBe('0x' + sel('Bad(address)').slice(0, 8)); // MEMBER topic0
    const g = await raise(
      `type Bad = event<{ a: u256 }>;\nclass C { Bad: event<{ b: address }>; g(): External<void> { emit(Bad(msg.sender)); } }`,
      `event Bad(uint256 a);\ncontract C { event Bad(address b); function g() external { emit Bad(msg.sender); } }`,
      'g()',
    );
    expect(g.j).toEqual(g.s);
    expect(g.j.topic0!.slice(0, 10)).toBe('0x' + sel('Bad(address)').slice(0, 8));
  });

  it('a bare name in a contract with NO member owner resolves to the FILE-LEVEL, byte-identical to solc', async () => {
    const errC = await raise(
      `type Bad = error<{ a: u256; c: address }>;\nclass C { f(): External<void> { revert(Bad(42n, msg.sender)); } }`,
      `error Bad(uint256 a, address c);\ncontract C { function f() external { revert Bad(42, msg.sender); } }`,
    );
    expect(errC.j).toEqual(errC.s);
    expect(errC.j.ret).toBe(errC.s.ret);
    expect(errC.j.ret.slice(0, 10)).toBe('0x' + sel('Bad(uint256,address)').slice(0, 8));
    const evtC = await raise(
      `type Bad = event<{ a: u256 }>;\nclass C { f(): External<void> { emit(Bad(8n)); } }`,
      `event Bad(uint256 a);\ncontract C { function f() external { emit Bad(8); } }`,
    );
    expect(evtC.j).toEqual(evtC.s);
    expect(evtC.j.topic0!.slice(0, 10)).toBe('0x' + sel('Bad(uint256)').slice(0, 8));
  });

  it('NAMED-arg this.Bad reorders to the MEMBER declaration order (scrambled keys), byte-identical', async () => {
    // The file-level Pair(uint256,uint256) and the member Pair(address,uint256) differ; the scrambled named
    // keys {y,x} must reorder to the MEMBER's (x,y) param order -> selector Pair(address,uint256).
    const { j, s } = await raise(
      `type Pair = error<{ a: u256; b: u256 }>;\nclass C { Pair: error<{ x: address; y: u256 }>; f(): External<void> { throw this.Pair({ y: 9n, x: msg.sender }); } }`,
      `error Pair(uint256 a, uint256 b);\ncontract C { error Pair(address x, uint256 y); function f() external { revert Pair(msg.sender, 9); } }`,
    );
    expect(j).toEqual(s);
    expect(j.ret.slice(0, 10)).toBe('0x' + sel('Pair(address,uint256)').slice(0, 8));
  });

  it('SAME-signature file-level + member is accepted (solc parity); resolves to the member', async () => {
    const err = await raise(
      `type Bad = error<{ a: u256 }>;\nclass C { Bad: error<{ a: u256 }>; f(): External<void> { revert(Bad(7n)); } }`,
      `error Bad(uint256 a);\ncontract C { error Bad(uint256 a); function f() external { revert Bad(7); } }`,
    );
    expect(err.j).toEqual(err.s);
    expect(err.j.ret).toBe('0x' + sel('Bad(uint256)') + '0'.repeat(63) + '7');
    const evt = await raise(
      `type Bad = event<{ a: u256 }>;\nclass C { Bad: event<{ a: u256 }>; f(): External<void> { emit(Bad(4n)); } }`,
      `event Bad(uint256 a);\ncontract C { event Bad(uint256 a); function f() external { emit Bad(4); } }`,
    );
    expect(evt.j).toEqual(evt.s);
  });

  it('MEMBER-SHADOWS: the file-level overload is invisible once a member exists - BOTH channels reject a file-only arg (positional + named)', () => {
    // POSITIONAL channel: member Bad(address); a bare emit/revert of a uint256 (which the member cannot take)
    // is a type error - the shadowed file-level Bad(uint256) must NOT be silently picked (solc rejects both).
    expect(codes(`type Bad = event<{ a: u256 }>;\nclass C { Bad: event<{ b: address }>; f(): External<void> { emit(Bad(123n)); } }`).length).toBeGreaterThan(0);
    expect(codes(`type Bad = error<{ a: u256 }>;\nclass C { Bad: error<{ b: address }>; f(): External<void> { revert(Bad(123n)); } }`).length).toBeGreaterThan(0);
    // member Bad(u256,u256), file-level Bad(u256); a bare arity-1 call has no member overload -> reject.
    expect(codes(`type Bad = event<{ a: u256 }>;\nclass C { Bad: event<{ x: u256; y: u256 }>; f(): External<void> { emit(Bad(1n)); } }`).length).toBeGreaterThan(0);
    // NAMED channel: `this.Bad({ a: ... })` uses the FILE-LEVEL key set the member cannot take -> the member
    // shadow makes the file-level invisible, so the named raise rejects (never silently reorders to file-level).
    expect(codes(`type Bad = event<{ a: u256 }>;\nclass C { Bad: event<{ b: address }>; f(): External<void> { emit(this.Bad({ a: 5n })); } }`).length).toBeGreaterThan(0);
    expect(codes(`type Bad = error<{ a: u256 }>;\nclass C { Bad: error<{ b: address }>; f(): External<void> { throw this.Bad({ a: 5n }); } }`).length).toBeGreaterThan(0);
    // bare NAMED raise of a same-named file-level error whose keys the member cannot take also rejects.
    expect(codes(`type Bad = error<{ a: u256 }>;\nclass C { Bad: error<{ b: address }>; f(): External<void> { revert(Bad({ a: 5n })); } }`).length).toBeGreaterThan(0);
  });

  it('MULTI-FILE: a file-level error imported from another file resolves + is byte-identical to solc (no member shadow present)', async () => {
    // The file-level `Bad` lives in errs.jeth and is imported; with NO contract member named Bad it resolves
    // to the file-level, byte-identical to solc's file-level error. Proves the file-level survives the
    // multi-file import boundary (a file-level name is still file-level where no member shadows it).
    const h = await Harness.create();
    const DEP = `export type Bad = error<{ a: u256; c: address }>;`;
    const aj = await h.deploy(compile(`import { Bad } from "./errs.jeth";\nclass C { f(): External<void> { revert(Bad(42n, msg.sender)); } }`, { fileName: 'C.jeth', sources: { 'errs.jeth': DEP } }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + `error Bad(uint256 a, address c);\ncontract C { function f() external view { revert Bad(42, msg.sender); } }`, 'C').creation);
    const shape = async (a: typeof aj) => { const r = await h.call(a, '0x' + sel('f()')); return { success: r.success, ret: r.returnHex }; };
    const j = await shape(aj), s = await shape(as);
    expect(j).toEqual(s);
    expect(j.ret.slice(0, 10)).toBe('0x' + sel('Bad(uint256,address)').slice(0, 8)); // file-level selector, byte-identical
  });

  it('OA GUARD: a file-level TYPE (struct/enum/interface) sharing a name with a contract member REJECTS (solc: the member shadows the type name -> "Name has to refer to a user-defined type" at the type use); only error/error and event/event coexist', () => {
    // The exact over-acceptance the cross-scope split must NOT reintroduce: a file-level STRUCT `Bad` + a
    // member EVENT `Bad` used as a TYPE (`store: Bad`). solc rejects "Name has to refer to a user-defined
    // type"; base 99a8b59 rejects JETH133. Keeping the whole struct-vs-member pair rejected is a SAFE proxy
    // (solc accepts only when the shadowed type is never used - a narrow over-rejection JETH keeps, never an
    // over-acceptance). Witnessed on 0.8.35: the used-as-type form REJECTS for every file-level type kind.
    expect(codes(`type Bad = { a: u256 };\nclass C { Bad: event<{ b: address }>; store: Bad; f(): External<void> { this.store = { a: 42n }; emit(this.Bad({ b: msg.sender })); } }`)).toContain('JETH133');
    expect(codes(`enum Bad { A, B }\nclass C { Bad: event<{ b: address }>; s: Bad; f(): External<void> { this.s = Bad.A; emit(this.Bad({ b: msg.sender })); } }`)).toContain('JETH133');
    // and the whole struct/enum/interface-vs-member family stays rejected (base parity, safe over-rejection).
    expect(codes(`type Bad = { a: u256 };\nclass C { Bad: error<{ b: address }>; f(): External<void> { throw this.Bad({ b: msg.sender }); } }`)).toContain('JETH133');
    expect(codes(`enum Bad { A, B }\nclass C { Bad: event<{ b: address }>; f(): External<void> { emit(this.Bad({ b: msg.sender })); } }`)).toContain('JETH133');
    expect(codes(`type Bad = { a: u256 };\nclass C { Bad: u256; f(): External<void> { this.Bad = 1n; } }`)).toContain('JETH133');
    expect(codes(`interface Bad { z(): External<void>; }\nclass C { Bad: event<{ b: address }>; f(): External<void> { emit(this.Bad({ b: msg.sender })); } }`)).toContain('JETH133');
    // CROSS-KIND error/event vs a member of the OTHER kind also stays rejected: solc's shadow makes a raise
    // of the file-level's name resolve to the shadowing member (a type error). Only matching error/error and
    // event/event coexist (proven byte-identical above).
    expect(codes(`type Bad = error<{ a: u256 }>;\nclass C { Bad: event<{ b: address }>; f(): External<void> { revert(Bad(1n)); } }`)).toContain('JETH133');
    expect(codes(`type Bad = event<{ a: u256 }>;\nclass C { Bad: error<{ b: address }>; f(): External<void> { emit(Bad(1n)); } }`)).toContain('JETH133');
    expect(codes(`type Bad = error<{ a: u256 }>;\nclass C { Bad: u256; f(): External<void> { revert(Bad(1n)); } }`)).toContain('JETH133');
  });

  it('GUARDS still reject at solc parity', () => {
    // two file-level `Bad` (same scope) -> JETH128
    expect(codes(`type Bad = error<{ a: u256 }>;\ntype Bad = error<{ b: address }>;\nclass C { f(): External<void> { revert(Bad(1n)); } }`)).toContain('JETH128');
    // two member `Bad` (same scope) -> JETH128
    expect(codes(`class C { Bad: error<{ a: u256 }>; Bad: error<{ b: address }>; f(): External<void> {} }`)).toEqual(['JETH128']);
    // file-level type sharing the DEPLOYED-CONTRACT name -> JETH272
    expect(codes(`type Boom = error<{ x: u256 }>;\nclass Boom { s: u256; } class C extends Boom { f(): External<u256> { return 7n; } }`)).toContain('JETH272');
    // a file-level `this.X` with NO member owner is still raised bare -> JETH353
    expect(codes(`type E = error<{ a: u256 }>;\nclass C { f(): External<void> { throw this.E({ a: 1n }); } }`)).toContain('JETH353');
    // a MEMBER cross-kind clash (function vs error) still rejects -> JETH133
    expect(codes(`class C { Bad(): External<void> {} Bad: error<{ a: u256 }>; }`)).toContain('JETH133');
    // two FILE-LEVEL declarations of different kinds (struct + error) still clash -> JETH133
    expect(codes(`type Bad = { a: u256 };\ntype Bad = error<{ b: u256 }>;\nclass C { f(): External<void> {} }`)).toContain('JETH133');
  });
});

// CROSS-SCOPE-NAME (multi-file): the member shadow must also WIN over an IMPORTED file-level error/event.
// The v3 per-file alpha-rename ($mN$Bad) used to mangle a bare `revert(Bad(...))` / `emit(Bad(...))` to the
// IMPORTED file-level Bad and route AROUND a same-named contract member (a pre-existing over-acceptance: a
// raise fitting the imported signature but not the member's was accepted, where solc rejects because the
// member shadows the import). rewriteModuleScopes now leaves a reference shadowed by a member error/event
// UNRENAMED, so resolution binds it to the member - matching solc. Each cell decodes the revert selector /
// event topic0 so a wrong pick (imported Bad(uint256)=a2f43130 vs member Bad(address)=830c4ac2) is decodable.
describe('CROSS-SCOPE-NAME multi-file: a contract MEMBER error/event shadows a same-named IMPORTED file-level one', () => {
  const DEP_E = `export type Bad = error<{ a: u256 }>;`;
  const DEP_V = `export type Bad = event<{ a: u256 }>;`;
  const mcodes = (src: string, sources: Record<string, string>): string[] => {
    try { compile(src, { fileName: 'entry.jeth', sources }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
  };
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

  it('OA CLOSED: import Bad(uint256) + member Bad(address); a bare raise fitting the IMPORT but not the member REJECTS (member shadows) - error + event', () => {
    // The exact over-acceptance: `revert(Bad(1n))` / `emit(Bad(1n))` used to route to the imported file-level
    // Bad(uint256), ignoring the member Bad(address). solc rejects (member shadows; 1 -> address fails).
    expect(mcodes(`import { Bad } from "./e.jeth";\nclass C { Bad: error<{ b: address }>; f(): External<void> { revert(Bad(1n)); } }`, { 'e.jeth': DEP_E })).toContain('JETH084');
    expect(mcodes(`import { Bad } from "./e.jeth";\nclass C { Bad: event<{ b: address }>; f(): External<void> { emit(Bad(1n)); } }`, { 'e.jeth': DEP_V })).toContain('JETH084');
  });

  it('NON-VACUOUS: the member-bearing raise resolves to the MEMBER selector/topic0 (not the import), byte-identical to solc', async () => {
    // member Bad(address) with a fitting address arg -> the MEMBER selector/topic0 830c4ac2 wins (decoded from
    // the revert data / event topic0). A wrong pick to the imported Bad(uint256) a2f43130 would be decodable.
    const arg = '11'.padStart(64, '0');
    const err = await raiseMF(
      `import { Bad } from "./e.jeth";\nclass C { Bad: error<{ b: address }>; f(a: address): External<void> { revert(Bad(a)); } }`, { 'e.jeth': DEP_E },
      `error Bad(uint256 a);\ncontract C { error Bad(address b); function f(address a) external { revert Bad(a); } }`, 'f(address)', arg,
    );
    expect(err.j).toEqual(err.s);
    expect(err.j.success).toBe(false);
    expect(err.j.ret.slice(0, 10)).toBe('0x' + sel('Bad(address)').slice(0, 8));
    expect(err.j.ret.slice(0, 10)).not.toBe('0x' + sel('Bad(uint256)').slice(0, 8)); // NOT the imported overload
    const evt = await raiseMF(
      `import { Bad } from "./e.jeth";\nclass C { Bad: event<{ b: address }>; f(a: address): External<void> { emit(Bad(a)); } }`, { 'e.jeth': DEP_V },
      `event Bad(uint256 a);\ncontract C { event Bad(address b); function f(address a) external { emit Bad(a); } }`, 'f(address)', arg,
    );
    expect(evt.j).toEqual(evt.s);
    expect(evt.j.topic0!.slice(0, 10)).toBe('0x' + sel('Bad(address)').slice(0, 8));
    expect(evt.j.topic0!.slice(0, 10)).not.toBe('0x' + sel('Bad(uint256)').slice(0, 8));
  });

  it('CONTROL: import WITHOUT a member still resolves the file-level import, byte-identical to solc (fix did not change it)', async () => {
    const err = await raiseMF(
      `import { Bad } from "./e.jeth";\nclass C { f(): External<void> { revert(Bad(7n)); } }`, { 'e.jeth': DEP_E },
      `error Bad(uint256 a);\ncontract C { function f() external { revert Bad(7); } }`,
    );
    expect(err.j).toEqual(err.s);
    expect(err.j.ret).toBe('0x' + sel('Bad(uint256)') + '0'.repeat(63) + '7'); // the IMPORTED file-level selector
    const evt = await raiseMF(
      `import { Bad } from "./e.jeth";\nclass C { f(): External<void> { emit(Bad(8n)); } }`, { 'e.jeth': DEP_V },
      `event Bad(uint256 a);\ncontract C { function f() external { emit Bad(8); } }`,
    );
    expect(evt.j).toEqual(evt.s);
    expect(evt.j.topic0!.slice(0, 10)).toBe('0x' + sel('Bad(uint256)').slice(0, 8));
  });
});
