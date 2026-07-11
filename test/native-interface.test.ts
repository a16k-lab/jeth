// Item #6b: a native TS `interface` declaration is the native spelling of `@interface class`. Because
// every interface method is external + virtual by definition, those decorators vanish; per-method
// MUTABILITY rides on a marker return type - `View<T>` / `Pure<T>` / `Payable<T>` wrap the real return,
// and a bare return type is `nonpayable` (the default). The marker is stripped before the return type is
// resolved and never enters the signature, so selectors are byte-identical. A native interface builds the
// SAME InterfaceDecl IR as `@interface class`, so the caller's bytecode (selectors + STATICCALL-vs-CALL)
// is byte-identical to the decorator form - and to solc. A native interface is also an EXTENDABLE base
// (`class C extends I`, P0a) - see native-interface-extends.test.ts for that surface.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const A = (h: string | { toString(): string }) => pad32(BigInt(h.toString()));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW']; }
};

describe('native TS interfaces (item #6b)', () => {
  it('a native interface caller is byte-identical to the `@interface class` caller', () => {
    const native = `interface IToken { bal(o: address): View<u256>; total(): Pure<u256>; transfer(to: address, amt: u256): bool; deposit(): Payable<u256>; }
      class C {
        get getBal(t: address, o: address): External<u256> { return IToken(t).bal(o); }
        get tot(t: address): External<u256> { return IToken(t).total(); }
        send(t: address, to: address, amt: u256): External<bool> { return IToken(t).transfer(to, amt); } }`;
    const decor = `interface IToken { bal(o: address): View<u256>; total(): Pure<u256>; transfer(to: address, amt: u256): bool; deposit(): Payable<u256>; }
      class C {
        get getBal(t: address, o: address): External<u256> { return IToken(t).bal(o); }
        get tot(t: address): External<u256> { return IToken(t).total(); }
        send(t: address, to: address, amt: u256): External<bool> { return IToken(t).transfer(to, amt); } }`;
    expect(bc(native)).toBe(bc(decor));
  });

  it('view -> STATICCALL and nonpayable -> CALL run byte-identical to solc', async () => {
    const TGT = `contract T { uint256 v; function seed(uint256 x) external { v=x; } function get() external view returns(uint256){ return v; } function bump(uint256 d) external returns(uint256){ v=v+d; return v; } }`;
    const JCALL = `interface IT { get(): View<u256>; bump(d: u256): u256; }
      class C { get ask(t: address): External<u256> { return IT(t).get(); } doBump(t: address, d: u256): External<u256> { return IT(t).bump(d); } }`;
    const SCALL = `interface IT { function get() external view returns(uint256); function bump(uint256 d) external returns(uint256); }
      contract C { function ask(address t) external view returns(uint256){ return IT(t).get(); } function doBump(address t, uint256 d) external returns(uint256){ return IT(t).bump(d); } }`;
    const h = await Harness.create();
    const tj = await h.deploy(compileSolidity(SPDX + TGT, 'T').creation); await h.call(tj, sel('seed(uint256)') + W(100));
    const ts = await h.deploy(compileSolidity(SPDX + TGT, 'T').creation); await h.call(ts, sel('seed(uint256)') + W(100));
    const jc = await h.deploy(compile(JCALL, { fileName: 'C.jeth' }).creationBytecode);
    const sc = await h.deploy(compileSolidity(SPDX + SCALL, 'C').creation);
    for (const sg of ['ask(address)', 'doBump(address,uint256)', 'ask(address)']) {
      const argsJ = sg.includes('uint256') ? A(tj) + W(5) : A(tj);
      const argsS = sg.includes('uint256') ? A(ts) + W(5) : A(ts);
      const rj = await h.call(jc, sel(sg) + argsJ);
      const rs = await h.call(sc, sel(sg) + argsS);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('a tuple return + a struct param over a native interface runs byte-identical to solc', async () => {
    const TGT = `struct P { uint256 a; uint256 b; }
      contract T { function pair(uint256 x) external pure returns(uint256, address){ return (x*2, address(uint160(x))); } function sumP(P calldata p) external pure returns(uint256){ return p.a + p.b; } }`;
    const J = `type P = { a: u256; b: u256 };
      interface IT { pair(x: u256): View<[u256, address]>; sumP(p: P): View<u256>; }
      class C {
        get getPair(t: address, x: u256): External<u256> { let [f, s] = IT(t).pair(x); return f; }
        get addP(t: address, a: u256, b: u256): External<u256> { return IT(t).sumP(P(a, b)); } }`;
    const S = `struct P { uint256 a; uint256 b; }
      interface IT { function pair(uint256 x) external view returns(uint256, address); function sumP(P calldata p) external view returns(uint256); }
      contract C {
        function getPair(address t, uint256 x) external view returns(uint256){ (uint256 f,) = IT(t).pair(x); return f; }
        function addP(address t, uint256 a, uint256 b) external view returns(uint256){ return IT(t).sumP(P(a,b)); } }`;
    const h = await Harness.create();
    const tgt = await h.deploy(compileSolidity(SPDX + TGT, 'T').creation);
    const jc = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sc = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [sg, args] of [['getPair(address,uint256)', A(tgt) + W(21)], ['addP(address,uint256,uint256)', A(tgt) + W(7) + W(9)]] as [string, string][]) {
      const rj = await h.call(jc, sel(sg) + args);
      const rs = await h.call(sc, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
  });

  it('marker + shape errors reject cleanly', () => {
    const call = (iface: string) => `${iface} class C { get f(a: address): External<u256> { return I(a).m(); } }`;
    expect(codes(call(`interface I { m(): View; }`))).toContain('JETH350');            // marker needs one type arg
    expect(codes(`interface I { x: u256; m(): View<u256>; } ${''}class C { get f(a:address):External<u256>{ return I(a).m(); } }`)).toContain('JETH341'); // no fields
    expect(codes(`interface I { m?(): View<u256>; } class C { get f(a:address):External<u256>{ return I(a).m(); } }`)).toContain('JETH341'); // no optional
    expect(codes(`interface A { m(): View<u256>; } interface B extends A { n(): View<u256>; } class C { get f(a:address):External<u256>{ return B(a).n(); } }`)).toContain('JETH349'); // no interface inheritance yet
  });

  it('the `// use @decorators` pragma is banned in native-only mode (JETH480)', () => {
    // decorator mode was removed in stage 2; a `// use @decorators` file now hard-rejects (JETH480).
    expect(codes(`// use @decorators\ninterface I { m(): View<u256>; } class C { get f(a: address): External<u256> { return I(a).m(); } }`)).toContain('JETH480');
  });

  it('a type sharing the contract name is rejected (solc parity), both interface spellings', () => {
    // found by the verification sweep: solc rejects "Identifier already declared" when a file-level type
    // (interface/struct/enum) shares the deployed contract's name. This was a PRE-EXISTING hole in BOTH
    // spellings (the contract's own name was absent from the cross-kind collision namespace).
    expect(codes(`interface C { m(x: u256): View<u256>; } class C { get f(): External<u256> { return 1n; } }`)).toContain('JETH272');
    expect(codes(`interface C { m(x: u256): View<u256>; } class C { get f(): External<u256> { return 1n; } }`)).toContain('JETH272');
    expect(codes(`type C = { a: u256 }; class C { get f(): External<u256> { return 1n; } }`)).toContain('JETH272');
    expect(codes(`interface I { constructor(x: u256): View<u256>; } class C { get f(a: address): External<u256> { return I(a).constructor(1n); } }`)).toContain('JETH341');
    // a distinct interface/struct name alongside the contract stays fine.
    expect(codes(`interface IFoo { m(): View<u256>; } class C { get f(a: address): External<u256> { return IFoo(a).m(); } }`)).toEqual([]);
  });
});
