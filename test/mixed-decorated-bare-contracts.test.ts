// MIXED DECORATED + BARE CONTRACTS IN ONE FILE (the silent-contract-drop fix).
//
// THE BUG: findContractClasses collected the decorated deployables (@contract - which the @diamond
// expansion SYNTHESIZES - @proxy/@beacon/@facet) and ran the native bare-class scan ONLY as a FALLBACK,
// behind `if (out.length === 0)`. Its rationale ("an existing decorated file may carry unrelated bare
// helper classes") died with native-only mode (JETH481): a user cannot write @contract, and a bare
// non-abstract unextended class IS a contract. So a file mixing a decorated deployable with a bare one
// SILENTLY DROPPED every bare contract - compile() SUCCEEDED and the artifact simply did not exist:
//   `@diamond('array') class D {}` + `class C {...}` -> ACCEPT name=D, contracts=undefined  (C GONE)
// The fix makes the routes the UNION of both, in DOCUMENT ORDER.
//
// *** WHY THESE TESTS LOOK THE WAY THEY DO - READ BEFORE EDITING ***
// Asserting only that `contracts` now lists the bare contract is NOT enough, and neither is "it compiles".
// The union alone SILENTLY MISCOMPILED the bare sibling: isDiamond/diamondVariant were read off the
// FILE-level @diamond expansion flag, so the sibling C - which is NOT a diamond - was emitted WITH a
// diamond fallback router. The 'solidstate' variant surfaced that loudly (internal JETH900: the router
// resolves a '_fallbackAddress' slot C never declares), but 'array' and 'packed' produced a silently WRONG
// C (verified: C's runtime bytecode diverged from its solo twin). Hence the twin tests below: a contract's
// artifact from a MIXED file must be byte-identical to the SAME contract compiled SOLO. A test that only
// checks `contracts.map(name)` is VACUOUS for that miscompile.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';

const BARE_C = `class C { get c(): External<u256> { return 2n; } }`;
const DECORATED: [string, string][] = [
  ['diamond array', `@diamond('array') class D { }`],
  ['diamond packed', `@diamond('packed') class D { }`],
  ['diamond solidstate', `@diamond('solidstate') class D { }`],
  ['proxy', `@proxy class P { }`],
  ['beacon', `@beacon class B { constructor(impl: address) {} }`],
  ['facet', `@facet class F { get f(): External<u256> { return 1n; } }`],
];
const names = (r: ReturnType<typeof compile>): string[] => (r.contracts ?? [r]).map((c) => c.contractName);
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return ['ACCEPT'];
  } catch (e: any) {
    return [...new Set<string>(e?.diagnostics?.map((d: any) => d.code) ?? ['THROW'])].sort();
  }
};

describe('mixed decorated + bare contracts: the bare contract is no longer dropped', () => {
  it.each(DECORATED)('%s + a bare contract emits BOTH artifacts (the bare one used to vanish)', (_label, dec) => {
    const r = compile(`${dec}\n${BARE_C}`, { fileName: 'C.jeth' });
    expect(r.contracts, 'contracts must exist: the file declares two deployables').toBeDefined();
    expect(names(r)).toContain('C'); // <-- the dropped contract
    expect(r.contracts!.length).toBe(2);
    for (const c of r.contracts!) expect(c.creationBytecode.length).toBeGreaterThan(0);
  });

  // *** THE ANTI-MISCOMPILE GUARD ***: the bare sibling is NOT a diamond/proxy/beacon. Its artifact must be
  // byte-identical to the same class compiled SOLO. Without route-scoping the @diamond flag, the 'array' and
  // 'packed' variants silently emitted a diamond router INTO C and this fails (solidstate throws JETH900).
  it.each(DECORATED)('%s: the bare sibling is byte-identical to its SOLO twin (no router leaks in)', (_label, dec) => {
    const solo = compile(BARE_C, { fileName: 'C.jeth' });
    const mixed = compile(`${dec}\n${BARE_C}`, { fileName: 'C.jeth' });
    const c = mixed.contracts!.find((x) => x.contractName === 'C')!;
    expect(c.runtimeBytecode, 'the bare sibling picked up the decorated contract`s behaviour').toBe(solo.runtimeBytecode);
    expect(c.creationBytecode).toBe(solo.creationBytecode);
    expect(c.abi).toEqual(solo.abi);
    expect(c.storageLayout).toEqual(solo.storageLayout);
  });

  // the DECORATED artifact must not shift at all: it is byte-identical to the decorated-ONLY file's.
  it.each(DECORATED)('%s: the decorated artifact is unchanged by the bare sibling`s presence', (_label, dec) => {
    const alone = compile(dec, { fileName: 'C.jeth' });
    const mixed = compile(`${dec}\n${BARE_C}`, { fileName: 'C.jeth' });
    expect(mixed.contracts![0]!.contractName).toBe(alone.contractName);
    expect(mixed.contracts![0]!.runtimeBytecode).toBe(alone.runtimeBytecode);
    expect(mixed.contracts![0]!.abi).toEqual(alone.abi);
  });

  it('the dropped contract DEPLOYS, RUNS and DECODES (the user-reported @diamond case)', async () => {
    const r = compile(`@diamond('array') class D { }\nclass C { get c(): External<u256> { return 2n; } }`, { fileName: 'C.jeth' });
    const c = r.contracts!.find((x) => x.contractName === 'C')!;
    const h = await Harness.create();
    const addr = await h.deploy(c.creationBytecode);
    const res = await h.call(addr, '0x' + functionSelector('c()'), {});
    expect(res.success).toBe(true);
    expect(BigInt(res.returnHex)).toBe(2n); // DECODED, not just "it compiled"
  });

  it('a diamond declared with TWO bare contracts emits all three, in document order', () => {
    const r = compile(
      `@diamond('array') class D { }\nclass C { get c(): External<u256> { return 2n; } }\nclass A { get a(): External<u256> { return 3n; } }`,
      { fileName: 'C.jeth' },
    );
    expect(names(r)).toEqual(['D', 'C', 'A']);
  });

  // *** RISK: a SYNTHESIZED helper must never become a route ***. Every @diamond variant appends
  // `@struct class __Diamond*` helpers; the @struct class-KIND decorator excludes them from the bare scan.
  it.each(DECORATED)('%s: no synthesized helper/struct leaks into contracts[]', (_label, dec) => {
    const r = compile(`${dec}\n${BARE_C}`, { fileName: 'C.jeth' });
    for (const n of names(r)) {
      expect(n.startsWith('__'), `synthesized helper '${n}' became a deployable route`).toBe(false);
      expect(/^__Diamond/.test(n)).toBe(false);
    }
    expect(names(r).sort()).toEqual([...names(r)].sort()); // only the two real user contracts
    expect(names(r).length).toBe(2);
  });

  // DOCUMENT ORDER decides the singular fields - so a BARE-FIRST file names the artifact after the bare
  // class. Such a file is currently BROKEN (it drops a contract), so there is no behaviour to preserve.
  it('document order decides contracts[0]: a bare class declared FIRST is route 0', async () => {
    const r = compile(`class C { get c(): External<u256> { return 42n; } }\n@facet class F { get f(): External<u256> { return 1n; } }`, {
      fileName: 'C.jeth',
    });
    expect(names(r)).toEqual(['C', 'F']);
    expect(r.contractName).toBe('C'); // the singular fields are route 0's = the BARE class
    expect(r.contracts![0]).toBe(r); // identity, per the multi-contract convention
    const h = await Harness.create();
    const addr = await h.deploy(r.creationBytecode);
    const res = await h.call(addr, '0x' + functionSelector('c()'), {});
    expect(BigInt(res.returnHex)).toBe(42n);
  });

  it('a decorated-ONLY file is completely unaffected (`contracts` stays undefined)', () => {
    for (const [, dec] of DECORATED) {
      const r = compile(dec, { fileName: 'C.jeth' });
      expect(r.contracts, `${r.contractName}: a single deployable must not gain a contracts[] list`).toBeUndefined();
    }
  });

  // ---- gates that must still fire -----------------------------------------------------------------
  it('two @diamond classes per file still reject JETH041', () => {
    expect(codes(`@diamond('array') class D { }\n@diamond('array') class E { }`)).toEqual(['JETH041']);
  });

  it('two bare abstract leaves produce two empty artifacts', () => {
    const r = compile(`abstract class A { get a(): External<u256> { return 1n; } }\nabstract class B { get b(): External<u256> { return 2n; } }`, { fileName: 'C.jeth' });
    expect(r.contracts?.map((c) => [c.contractName, c.creationBytecode])).toEqual([['A', ''], ['B', '']]);
  });

  it('a bare contract sharing the @diamond`s name still rejects JETH037', () => {
    expect(codes(`@diamond('array') class D { }\nclass D { get a(): External<u256> { return 1n; } }`)).toEqual(['JETH037']);
  });

  // The bare sibling is NOT a diamond, so the synthesis-only diamond builtins are out of scope there. This
  // used to "ACCEPT" only because C was dropped wholesale - the call was never analyzed.
  it('a diamond builtin called from a bare sibling rejects JETH414 (it used to be silently dropped)', () => {
    expect(codes(`@diamond('array') class D { }\nclass C { c(): External<void> { diamondInit(msg.sender); } }`)).toEqual(['JETH414']);
  });
});
