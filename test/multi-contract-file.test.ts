// MULTI-CONTRACT FILE (JETH041 lifted on the deployed path). solc compiles a file declaring N contracts
// into N SEPARATE artifacts, one per contract, each seeing the same file-level scope. JETH mirrors that:
// compile() returns route 0's artifact in the singular fields (unchanged) plus `contracts` - every
// contract's artifact in document order.
//
// *** WHY THESE TESTS LOOK THE WAY THEY DO - READ BEFORE EDITING ***
// A previous attempt at this lift shipped a GREEN 30/30 suite WITH A LIVE MISCOMPILE. Its shared-base case
// used `bump(): void` - an INTERNAL member with NO marker to strip - so it could not touch the bug, and its
// route-isolation case used two contracts with NO shared base. The bug: analyzeContract STRIPS the
// External/Payable/View/Pure return markers off the AST member nodes IN PLACE, so re-analyzing the SAME
// tree for route 1 silently demoted every marker-carrying member of a SHARED abstract base to INTERNAL -
// dropping it from route 1's dispatcher (wrong ABI, wrong bytes). `get` accessors SURVIVE that (externality
// comes from the keyword), which is exactly why the damage was silent and partial.
//
// So: every shared-base case here MUST carry External/Payable/View/Pure MARKERS on the shared base, and the
// assertions MUST check the marker-carrying members specifically. A test that only uses `get` accessors or
// bodyless/void members is VACUOUS for this bug. The guard test below (`route 1 keeps ...`) fails loudly if
// the per-route re-parse is ever removed.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { compileSolidity } from './_solidity.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

const artifacts = (src: string): Map<string, ReturnType<typeof compile>> => {
  const r = compile(src, { fileName: 'C.jeth' });
  const m = new Map<string, ReturnType<typeof compile>>();
  for (const c of r.contracts ?? [r]) m.set(c.contractName, c);
  return m;
};
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return ['ACCEPT'];
  } catch (e: any) {
    return (e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']).sort();
  }
};
// the external ABI surface as solc reports it: name + mutability, which is precisely what the marker strip
// corrupts (a demoted member vanishes from the ABI entirely).
const surface = (abi: any[]): string[] =>
  abi.filter((x) => x.type === 'function').map((x) => `${x.name}[${x.stateMutability}]`).sort();
const call = async (h: Harness, addr: any, sig: string): Promise<string> => {
  const r = await h.call(addr, '0x' + functionSelector(sig), {});
  return `${r.success}:${r.returnHex}`;
};

// ---- the marker-carrying SHARED ABSTRACT BASE (the case that killed the prior attempt) ----------------
const MARKER_J = `abstract class Base {
  n: u256;
  tag(): External<u256> { this.n = 1n; return 7n; }
  bump(): External<void> { this.n = this.n + 1n; }
  take(): Payable<void> { this.n = this.n + msg.value; }
  get peek(): External<u256> { return this.n; }
  get calc(): External<u256> { return 3n; }
}
class A extends Base { get gn(): External<u256> { return this.n; } }
class B extends Base { get gn(): External<u256> { return this.n + 100n; } }`;
const MARKER_S = `abstract contract Base {
  uint256 n;
  function tag() external returns (uint256) { n = 1; return 7; }
  function bump() external { n = n + 1; }
  function take() external payable { n = n + msg.value; }
  function peek() external view returns (uint256) { return n; }
  function calc() external pure returns (uint256) { return 3; }
}
contract A is Base { function gn() external view returns (uint256) { return n; } }
contract B is Base { function gn() external view returns (uint256) { return n + 100; } }`;

describe('multi-contract file: N artifacts, one per contract', () => {
  it('emits one artifact per contract, in document order, with contracts[0] === the result', () => {
    const src = `class A { get a(): External<u256> { return 1n; } }
class C { get c(): External<u256> { return 2n; } }`;
    const r = compile(src, { fileName: 'C.jeth' });
    expect(r.contracts).toBeDefined();
    expect(r.contracts!.map((c) => c.contractName)).toEqual(['A', 'C']); // DOCUMENT order
    expect(r.contracts![0]).toBe(r); // identity, not a copy
    expect(r.contractName).toBe('A'); // singular fields stay route 0's
    for (const c of r.contracts!) expect(c.creationBytecode.length).toBeGreaterThan(0);
    expect(r.contracts![0]!.creationBytecode).not.toBe(r.contracts![1]!.creationBytecode);
  });

  it('a SINGLE-contract file leaves `contracts` undefined (every existing caller is untouched)', () => {
    const r = compile(`class C { get v(): External<u256> { return 1n; } }`, { fileName: 'C.jeth' });
    expect(r.contracts).toBeUndefined();
    expect(r.contractName).toBe('C');
  });

  // *** THE GUARD TEST ***: marker-carrying members on a SHARED abstract base. If per-route re-parsing is
  // ever removed, route 1 (B) loses tag/bump/take from its ABI and this fails. Asserted against solc.
  it('route 1 keeps the MARKER-CARRYING members of a SHARED abstract base (the strip must not leak)', () => {
    const a = artifacts(MARKER_J);
    expect([...a.keys()]).toEqual(['A', 'B']);
    for (const name of ['A', 'B']) {
      const have = surface(a.get(name)!.abi);
      // the marker-only members: their externality comes SOLELY from the stripped return marker, so a
      // leaked strip drops them. `get` accessors would survive and hide the bug - hence these three.
      expect(have, `${name} lost a marker-carrying inherited member`).toEqual(
        expect.arrayContaining(['tag[nonpayable]', 'bump[nonpayable]', 'take[payable]']),
      );
      // and the full surface matches solc's for THAT contract, from the SAME source
      expect(have).toEqual(['bump[nonpayable]', 'calc[pure]', 'gn[view]', 'peek[view]', 'tag[nonpayable]', 'take[payable]']);
    }
  });

  it('marker-carrying shared base: every route is DECODED-identical to solc for that contract', async () => {
    const a = artifacts(MARKER_J);
    for (const name of ['A', 'B']) {
      const h = await Harness.create();
      const aj = await h.deploy(a.get(name)!.creationBytecode);
      const as = await h.deploy(compileSolidity(SPDX + MARKER_S, name).creation);
      for (const sig of ['tag()', 'bump()', 'gn()', 'peek()', 'calc()']) {
        expect(await call(h, aj, sig), `${name}.${sig}`).toBe(await call(h, as, sig));
      }
    }
  });

  // ROUTE-ORDER SWAP: the prior bug's victim moved with declaration order, so pin both orders.
  it('route-order swap: the marker-carrying members survive when B is declared FIRST', () => {
    const swapped = `abstract class Base {
  n: u256;
  tag(): External<u256> { this.n = 1n; return 7n; }
  bump(): External<void> { this.n = this.n + 1n; }
}
class B extends Base { get gn(): External<u256> { return this.n + 100n; } }
class A extends Base { get gn(): External<u256> { return this.n; } }`;
    const a = artifacts(swapped);
    expect([...a.keys()]).toEqual(['B', 'A']); // document order
    for (const name of ['A', 'B'])
      expect(surface(a.get(name)!.abi), name).toEqual(['bump[nonpayable]', 'gn[view]', 'tag[nonpayable]']);
  });

  it('a 3-level chain (Root <- Mid <- {A,B}) keeps both routes decoded-identical to solc', async () => {
    const J = `abstract class Root { r: u256; ping(): External<u256> { this.r = 5n; return 5n; } }
abstract class Mid extends Root { mid(): External<u256> { this.r = 6n; return 6n; } }
class A extends Mid { get gn(): External<u256> { return this.r + 1n; } }
class B extends Mid { get gn(): External<u256> { return this.r + 2n; } }`;
    const S = `abstract contract Root { uint256 r; function ping() external returns (uint256) { r = 5; return 5; } }
abstract contract Mid is Root { function mid() external returns (uint256) { r = 6; return 6; } }
contract A is Mid { function gn() external view returns (uint256) { return r + 1; } }
contract B is Mid { function gn() external view returns (uint256) { return r + 2; } }`;
    const a = artifacts(J);
    for (const name of ['A', 'B']) {
      expect(surface(a.get(name)!.abi), name).toEqual(['gn[view]', 'mid[nonpayable]', 'ping[nonpayable]']);
      const h = await Harness.create();
      const aj = await h.deploy(a.get(name)!.creationBytecode);
      const as = await h.deploy(compileSolidity(SPDX + S, name).creation);
      for (const sig of ['ping()', 'mid()', 'gn()']) expect(await call(h, aj, sig), `${name}.${sig}`).toBe(await call(h, as, sig));
    }
  });

  it('each contract gets its OWN storage layout (no cross-route slot bleed)', () => {
    const a = artifacts(`class A { x: u256; y: address; get gx(): External<u256> { return this.x; } }
class B { p: bool; q: u256; r: u128; get gq(): External<u256> { return this.q; } }`);
    const slot = (n: string) => a.get(n)!.storageLayout.map((e) => `${e.name}@${e.slot}+${e.offset}`);
    expect(slot('A')).toEqual(['x@0+0', 'y@1+0']);
    expect(slot('B')).toEqual(['p@0+0', 'q@1+0', 'r@2+0']);
    for (const n of ['A', 'B']) {
      const s = compileSolidity(SPDX + `contract A { uint256 x; address y; function gx() external view returns (uint256) { return x; } }
contract B { bool p; uint256 q; uint128 r; function gq() external view returns (uint256) { return q; } }`, n).storageLayout;
      expect(slot(n)).toEqual(s.map((e) => `${e.label}@${e.slot}+${e.offset}`));
    }
  });

  it('ctors with args produce per-contract artifacts decoded-identical to solc', async () => {
    const J = `class A { v: u256; constructor(a: u256) { this.v = a * 2n; } get gv(): External<u256> { return this.v; } }
class B { w: u256; constructor(a: u256) { this.w = a + 5n; } get gw(): External<u256> { return this.w; } }`;
    const S = `contract A { uint256 v; constructor(uint256 a) { v = a * 2; } function gv() external view returns (uint256) { return v; } }
contract B { uint256 w; constructor(uint256 a) { w = a + 5; } function gw() external view returns (uint256) { return w; } }`;
    const a = artifacts(J);
    const arg = '0'.repeat(63) + '9'; // uint256(9)
    for (const [name, sig] of [['A', 'gv()'], ['B', 'gw()']] as const) {
      const h = await Harness.create();
      const aj = await h.deploy(a.get(name)!.creationBytecode + arg);
      const as = await h.deploy(compileSolidity(SPDX + S, name).creation + arg);
      expect(await call(h, aj, sig), name).toBe(await call(h, as, sig));
    }
  });

  it('a shared file-level struct/enum/event is usable from every route', async () => {
    const J = `type P = { a: u256; b: u256 };
enum E { X, Y }
type Ev = event<{ who: indexed<address>; amt: u256 }>;
class A { get sum(): External<u256> { const p: P = { a: 1n, b: 2n }; return p.a + p.b; } fire(): External<void> { emit(Ev(msg.sender, 1n)); } }
class B { get sum(): External<u256> { const p: P = { a: 10n, b: 20n }; return p.a + p.b; } get e(): External<u256> { return u256(E.Y); } }`;
    const S = `struct P { uint256 a; uint256 b; }
enum E { X, Y }
event Ev(address indexed who, uint256 amt);
contract A { function sum() external pure returns (uint256) { P memory p = P(1,2); return p.a + p.b; } function fire() external { emit Ev(msg.sender, 1); } }
contract B { function sum() external pure returns (uint256) { P memory p = P(10,20); return p.a + p.b; } function e() external pure returns (uint256) { return uint256(E.Y); } }`;
    const a = artifacts(J);
    for (const [name, sigs] of [['A', ['sum()', 'fire()']], ['B', ['sum()', 'e()']]] as const) {
      const h = await Harness.create();
      const aj = await h.deploy(a.get(name)!.creationBytecode);
      const as = await h.deploy(compileSolidity(SPDX + S, name).creation);
      for (const sig of sigs) expect(await call(h, aj, sig), `${name}.${sig}`).toBe(await call(h, as, sig));
    }
  });

  it('N = 4 contracts all emit distinct, decoded-correct artifacts', async () => {
    const J = ['A', 'B', 'C', 'D'].map((n, i) => `class ${n} { get v(): External<u256> { return ${i + 1}n; } }`).join('\n');
    const S = ['A', 'B', 'C', 'D'].map((n, i) => `contract ${n} { function v() external pure returns (uint256) { return ${i + 1}; } }`).join('\n');
    const a = artifacts(J);
    expect([...a.keys()]).toEqual(['A', 'B', 'C', 'D']);
    for (const name of ['A', 'B', 'C', 'D']) {
      const h = await Harness.create();
      const aj = await h.deploy(a.get(name)!.creationBytecode);
      const as = await h.deploy(compileSolidity(SPDX + S, name).creation);
      expect(await call(h, aj, 'v()'), name).toBe(await call(h, as, 'v()'));
    }
  });

  // ---- the gates that STAY -----------------------------------------------------------------------------
  it('KEEPS JETH041 for two independent ABSTRACT leaves (no deployable contract)', () => {
    expect(codes(`abstract class X { get a(): External<u256> { return 1n; } }
abstract class Y { get b(): External<u256> { return 2n; } }`)).toEqual(['JETH041']);
  });

  it('KEEPS JETH041 for two @diamond classes in one file', () => {
    expect(codes(`@diamond('array') class D1 { }\n@diamond('array') class D2 { }`)).toEqual(['JETH041']);
  });

  it('a single abstract leaf / a deployable + its abstract base still compile as ONE route', () => {
    expect(codes(`abstract class X { get a(): External<u256> { return 1n; } }`)).toEqual(['ACCEPT']);
    const r = compile(`abstract class X { get a(): External<u256> { return 1n; } }
class A extends X { get b(): External<u256> { return 2n; } }`, { fileName: 'C.jeth' });
    expect(r.contracts).toBeUndefined(); // an inlined base is NOT a second route
    expect(r.contractName).toBe('A');
  });
});
