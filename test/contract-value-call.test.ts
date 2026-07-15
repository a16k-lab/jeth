// CONTRACT-VALUE-CALL (JETH074 lift): an external-method CALL on a contract/abstract-contract VALUE
// (`t.v()` where t is a field / param / local / struct field / array element / mapping element / a return
// of a call, typed by a `@contract`/`abstract class` name). solc treats a contract-typed value NOMINALLY:
// its callable surface is its EXTERNAL methods, and `t.v(...)` lowers to the SAME external message-call solc
// emits for `IFoo(addr).v(...)` on an interface value - encodeWithSelector(v.selector, ...args) -> STATICCALL
// (a view/pure method) or CALL (a nonpayable/payable method, {value} only on payable) -> bubble revert ->
// decode return. JETH previously rejected every such call with the JETH074 catch-all ("unsupported
// expression: CallExpression"); it now routes through the identical buildIfaceExtCall, so the bytecode is
// byte-identical to the `IFoo(addr).v()` interface twin of the same signature AND to solc.
//
// Each accept row deploys a JETH `C` and a solc `C` in one harness alongside a REAL deployed target answering
// the call, seeds state, and diffs success + returndata (ground-truth run+decode, distinct seeds). Byte
// identity to the interface twin is proven at the bytecode level. The negatives that must STILL reject (no
// over-acceptance: an internal/private/nonexistent method, value on a non-payable method, the raw-address
// gate, the mutability ladder) are pinned against solc reject-parity.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const A = (h: { toString(): string }) => pad32(BigInt(h.toString()));
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] | null => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return null;
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
const accepts = (src: string): boolean => codes(src) === null;
const solcRejects = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};
const bothReject = (j: string, s: string): boolean => !accepts(j) && solcRejects(s);

// abstract contract T (JETH) / T (solc). C never deploys T; it stores/receives T-typed addresses and calls
// their external methods on a REAL deployed target that implements the same ABI.
const JT =
  'abstract class T { @virtual v(): View<u256>; @virtual twice(x: u256): View<u256>; @virtual setx(x: u256): External<u256>; @virtual pair(x: u256): View<[u256, address]>; @virtual pay(): Payable<u256>; @virtual doVoid(x: u256): External<void>; }\n';
const ST =
  'abstract contract T { function v() external view virtual returns(uint256); function twice(uint256 x) external view virtual returns(uint256); function setx(uint256 x) external virtual returns(uint256); function pair(uint256 x) external view virtual returns(uint256,address); function pay() external payable virtual returns(uint256); function doVoid(uint256 x) external virtual; }\n';
// a REAL target implementing T's ABI (deployed once; both C's call into it).
const TGT =
  'contract Tgt { uint256 s; function seed(uint256 x) external { s = x; } function v() external view returns(uint256){ return s; } function twice(uint256 x) external view returns(uint256){ return x*2; } function setx(uint256 x) external returns(uint256){ s = x; return s; } function pair(uint256 x) external view returns(uint256,address){ return (x*3, address(uint160(x))); } function pay() external payable returns(uint256){ s = s + msg.value; return s; } function doVoid(uint256 x) external { s = x; } }';

/** Deploy Tgt (seeded), the JETH C and the solc C in one harness; run identical calls; diff success + bytes. */
async function diffInto(
  J: string,
  S: string,
  calls: [string, string][],
  opts: { value?: bigint; seed?: number } = {},
): Promise<void> {
  const h = await Harness.create();
  const tgt = await h.deploy(compileSolidity(SPDX + TGT, 'Tgt').creation);
  await h.call(tgt, sel('seed(uint256)') + W(opts.seed ?? 100));
  const aj = await h.deploy(bc(J));
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  const fill = (a: string) => a.replace(/TGT/g, A(tgt));
  const run = async (addr: Awaited<ReturnType<Harness['deploy']>>) => {
    const out: { success: boolean; returnHex: string }[] = [];
    for (const [sig, args] of calls) {
      const r = await h.call(addr, sel(sig) + fill(args), opts.value !== undefined ? { value: opts.value } : {});
      out.push({ success: r.success, returnHex: r.returnHex });
    }
    return out;
  };
  const rj = await run(aj);
  const rs = await run(as);
  for (let i = 0; i < calls.length; i++) {
    expect(rj[i]!.success, `${calls[i]![0]} success`).toBe(rs[i]!.success);
    expect(rj[i]!.returnHex, `${calls[i]![0]} return`).toBe(rs[i]!.returnHex);
  }
}

describe('CONTRACT-VALUE-CALL: an external-method call on a contract/abstract-typed value', () => {
  it('PIN: the JETH074 catch-all is gone - every source position now type-checks the call', () => {
    // Each of these was `JETH074: unsupported expression: CallExpression` before this lift.
    expect(
      accepts(JT + `class C { t: T; get f(): External<u256> { return this.t.v(); } }`),
    ).toBe(true); // field
    expect(accepts(JT + `class C { get f(t: T): External<u256> { return t.v(); } }`)).toBe(true); // param
    expect(
      accepts(JT + `class C { get f(t: T): External<u256> { let u: T = t; return u.v(); } }`),
    ).toBe(true); // local
    expect(
      accepts(JT + `class C { ts: T[]; get f(i: u256): External<u256> { return this.ts[i].v(); } }`),
    ).toBe(true); // array element
    expect(
      accepts(JT + `class C { m: mapping<address, T>; get f(k: address): External<u256> { return this.m[k].v(); } }`),
    ).toBe(true); // mapping element
    expect(
      accepts(
        `type S = { t: T; n: u256 };\n` +
          JT +
          `class C { s: S; get f(): External<u256> { return this.s.t.v(); } }`,
      ),
    ).toBe(true); // struct field
  });

  it('view -> STATICCALL, nonpayable -> CALL, payable{value} -> CALL, byte-identical to solc (run+decode)', async () => {
    // A single C: view getter (staticcall), nonpayable setter (call), payable pay (call+value), all into Tgt.
    const J =
      JT +
      `class C {
        t: T;
        setT(x: T): External<void> { this.t = x; }
        get vw(): External<u256> { return this.t.v(); }
        doset(x: u256): External<u256> { return this.t.setx(x); }
        dopay(): Payable<u256> { return this.t.pay({ value: 7n }); }
      }`;
    const S =
      ST +
      `contract C {
        T t;
        function setT(T x) external { t = x; }
        function vw() external view returns(uint256){ return t.v(); }
        function doset(uint256 x) external returns(uint256){ return t.setx(x); }
        function dopay() external payable returns(uint256){ return t.pay{value: 7}(); }
      }`;
    // seed Tgt=100: vw->100; doset(55)->55; dopay(value:7)->62; vw->62 (non-vacuous: state changed via CALLs).
    // Each C gets its OWN target so the two mutating call sequences do not interfere.
    const h = await Harness.create();
    const tgtJ = await h.deploy(compileSolidity(SPDX + TGT, 'Tgt').creation);
    const tgtS = await h.deploy(compileSolidity(SPDX + TGT, 'Tgt').creation);
    await h.call(tgtJ, sel('seed(uint256)') + W(100));
    await h.call(tgtS, sel('seed(uint256)') + W(100));
    const aj = await h.deploy(bc(J));
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, sel('setT(address)') + A(tgtJ));
    await h.call(as, sel('setT(address)') + A(tgtS));
    for (const [sig, args, value] of [
      ['vw()', '', undefined],
      ['doset(uint256)', W(55), undefined],
      ['dopay()', '', 7n],
      ['vw()', '', undefined],
    ] as [string, string, bigint | undefined][]) {
      const rj = await h.call(aj, sel(sig) + args, value !== undefined ? { value } : {});
      const rs = await h.call(as, sel(sig) + args, value !== undefined ? { value } : {});
      expect(rj.success, sig).toBe(rs.success);
      expect(rj.returnHex, sig).toBe(rs.returnHex);
    }
    // Ground-truth: after the two CALLs the target holds 62 (100 replaced by 55, then +7). Non-vacuous.
    expect((await h.call(aj, sel('vw()'))).returnHex).toBe('0x' + W(62));
  });

  it('a method WITH ARGS and a TUPLE return run byte-identical to solc', async () => {
    await diffInto(
      JT +
        `class C { t: T; setT(x: T): External<void> { this.t = x; } get f(x: u256): External<u256> { return this.t.twice(x); } get p(x: u256): External<u256> { let [a, b] = this.t.pair(x); return a; } }`,
      ST +
        `contract C { T t; function setT(T x) external { t = x; } function f(uint256 x) external view returns(uint256){ return t.twice(x); } function p(uint256 x) external view returns(uint256){ (uint256 a,) = t.pair(x); return a; } }`,
      [
        ['setT(address)', 'TGT'],
        ['f(uint256)', W(21)],
        ['p(uint256)', W(9)],
      ],
    );
  });

  it('array / mapping / struct-field receivers run byte-identical to solc', async () => {
    await diffInto(
      JT +
        `class C { ts: T[]; add(x: T): External<void> { this.ts.push(x); } get f(i: u256): External<u256> { return this.ts[i].v(); } }`,
      ST + `contract C { T[] ts; function add(T x) external { ts.push(x); } function f(uint256 i) external view returns(uint256){ return ts[i].v(); } }`,
      [
        ['add(address)', 'TGT'],
        ['f(uint256)', W(0)],
      ],
      { seed: 314 },
    );
    await diffInto(
      JT +
        `class C { m: mapping<address, T>; setm(k: address, x: T): External<void> { this.m[k] = x; } get f(k: address): External<u256> { return this.m[k].v(); } }`,
      ST +
        `contract C { mapping(address=>T) m; function setm(address k, T x) external { m[k] = x; } function f(address k) external view returns(uint256){ return m[k].v(); } }`,
      [
        ['setm(address,address)', 'TGT' + 'TGT'],
        ['f(address)', 'TGT'],
      ],
      { seed: 271 },
    );
    await diffInto(
      `type S = { t: T; n: u256 };\n` +
        JT +
        `class C { s: S; setS(x: T): External<void> { this.s = { t: x, n: 1n }; } get f(): External<u256> { return this.s.t.v(); } }`,
      ST +
        `contract C { struct S { T t; uint256 n; } S s; function setS(T x) external { s = S(x, 1); } function f() external view returns(uint256){ return s.t.v(); } }`,
      [
        ['setS(address)', 'TGT'],
        ['f()', ''],
      ],
      { seed: 141 },
    );
  });

  it('statement-position and void-returning calls run byte-identical; a void call as a value rejects', async () => {
    await diffInto(
      JT +
        `class C { t: T; setT(x: T): External<void> { this.t = x; } run(x: u256): External<void> { this.t.doVoid(x); } get g(): External<u256> { return this.t.v(); } }`,
      ST +
        `contract C { T t; function setT(T x) external { t = x; } function run(uint256 x) external { t.doVoid(x); } function g() external view returns(uint256){ return t.v(); } }`,
      [
        ['setT(address)', 'TGT'],
        ['run(uint256)', W(88)],
        ['g()', ''],
      ],
    );
    // a void method used as a value rejects in BOTH compilers.
    expect(
      bothReject(
        JT + `class C { t: T; get f(): External<u256> { return this.t.doVoid(1n); } }`,
        ST + `contract C { T t; function f() external view returns(uint256){ return t.doVoid(1); } }`,
      ),
    ).toBe(true);
  });

  it('a self-referential contract calling its OWN external method runs byte-identical (markers pre-stripping)', async () => {
    // T === C (the deployed contract). The External/View markers on C's own methods are stripped by
    // collectFunction DURING analysis, so the registry must have captured them in the earlier pre-pass.
    const J = `class C { c: C; x: u256; setC(o: C): External<void> { this.c = o; } setX(n: u256): External<void> { this.x = n; } get getv(): External<u256> { return this.x; } get viaC(): External<u256> { return this.c.getv(); } }`;
    const S = `contract C { C c; uint256 x; function setC(C o) external { c = o; } function setX(uint256 n) external { x = n; } function getv() external view returns(uint256){ return x; } function viaC() external view returns(uint256){ return c.getv(); } }`;
    for (const src of [bc(J), compileSolidity(SPDX + S, 'C').creation]) {
      const h = await Harness.create();
      const c1 = await h.deploy(src);
      const c2 = await h.deploy(src);
      await h.call(c2, sel('setX(uint256)') + W(777));
      await h.call(c1, sel('setC(address)') + A(c2));
      const r = await h.call(c1, sel('viaC()'));
      expect(r.success).toBe(true);
      expect(r.returnHex).toBe('0x' + W(777)); // non-vacuous: c1.viaC() STATICCALLs c2.getv() -> 777
    }
  });

  it('overloaded and inherited external methods dispatch byte-identical to solc', async () => {
    // overloads t.f(x) / t.f(x,y): distinct selectors, arg-dependent lookup.
    {
      const J =
        `abstract class T { @virtual f(a: u256): View<u256>; @virtual f(a: u256, b: u256): View<u256>; }\n` +
        `class C { get one(t: T, x: u256): External<u256> { return t.f(x); } get two(t: T, x: u256, y: u256): External<u256> { return t.f(x, y); } }`;
      const S =
        `abstract contract T { function f(uint256 a) external view virtual returns(uint256); function f(uint256 a, uint256 b) external view virtual returns(uint256); }\n` +
        `contract C { function one(T t, uint256 x) external view returns(uint256){ return t.f(x); } function two(T t, uint256 x, uint256 y) external view returns(uint256){ return t.f(x,y); } }`;
      const TF = `contract Tf { function f(uint256 a) external pure returns(uint256){ return a; } function f(uint256 a, uint256 b) external pure returns(uint256){ return a+b; } }`;
      const h = await Harness.create();
      const tf = await h.deploy(compileSolidity(SPDX + TF, 'Tf').creation);
      const aj = await h.deploy(bc(J));
      const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
      for (const [sig, args] of [
        ['one(address,uint256)', A(tf) + W(5)],
        ['two(address,uint256,uint256)', A(tf) + W(5) + W(6)],
      ] as [string, string][]) {
        const rj = await h.call(aj, sel(sig) + args);
        const rs = await h.call(as, sel(sig) + args);
        expect(rj.success, sig).toBe(rs.success);
        expect(rj.returnHex, sig).toBe(rs.returnHex);
      }
    }
    // inherited: abstract B extends A, call A's method through a B value.
    await diffInto(
      `abstract class A { @virtual v(): View<u256>; }\nabstract class B extends A { @virtual w(): View<u256>; }\nclass C { get f(b: B): External<u256> { return b.v(); } }`,
      `abstract contract A { function v() external view virtual returns(uint256); }\nabstract contract B is A { function w() external view virtual returns(uint256); }\ncontract C { function f(B b) external view returns(uint256){ return b.v(); } }`,
      [['f(address)', 'TGT']],
      { seed: 42 },
    );
  });

  it('is byte-identical to the interface `IT(addr).m()` twin of the same signature', () => {
    // The contract side sources the receiver from a T param (an ABI address); the interface side casts the
    // same address with IT(a). Both selectors are m(address,...), so the lowered call must be byte-identical.
    const IT = `interface IT { v(): View<u256>; setx(x: u256): u256; pair(x: u256): View<[u256, address]>; pay(): Payable<u256>; twice(x: u256): View<u256>; }`;
    const pairs: [string, string][] = [
      [
        JT + `class C { get f(t: T): External<u256> { return t.v(); } }`,
        IT + `class C { get f(a: address): External<u256> { return IT(a).v(); } }`,
      ],
      [
        JT + `class C { doset(t: T, x: u256): External<u256> { return t.setx(x); } }`,
        IT + `class C { doset(a: address, x: u256): External<u256> { return IT(a).setx(x); } }`,
      ],
      [
        JT + `class C { dopay(t: T): Payable<u256> { return t.pay({ value: 7n }); } }`,
        IT + `class C { dopay(a: address): Payable<u256> { return IT(a, { value: 7n }).pay(); } }`,
      ],
      [
        JT + `class C { get f(t: T, x: u256): External<u256> { let [p, q] = t.pair(x); return p; } }`,
        IT + `class C { get f(a: address, x: u256): External<u256> { let [p, q] = IT(a).pair(x); return p; } }`,
      ],
    ];
    for (const [ctr, iface] of pairs) expect(bc(ctr)).toBe(bc(iface));
  });

  it('GUARDS: an internal/private/nonexistent method, or a plain-address call, rejects at solc parity', () => {
    // an internal (bare, no marker) method is not externally visible.
    expect(
      bothReject(
        `abstract class T { iv(): u256 { return 1n; } @virtual v(): View<u256>; }\nclass C { get f(t: T): External<u256> { return t.iv(); } }`,
        `abstract contract T { function iv() internal pure returns(uint256){ return 1; } function v() external view virtual returns(uint256); }\ncontract C { function f(T t) external view returns(uint256){ return t.iv(); } }`,
      ),
    ).toBe(true);
    // a #-private method is not visible.
    expect(
      bothReject(
        `abstract class T { @virtual v(): View<u256>; #pv(): u256 { return 1n; } }\nclass C { get f(t: T): External<u256> { return t.pv(); } }`,
        `abstract contract T { function v() external view virtual returns(uint256); function pv() private pure returns(uint256){ return 1; } }\ncontract C { function f(T t) external view returns(uint256){ return t.pv(); } }`,
      ),
    ).toBe(true);
    // a nonexistent method.
    expect(
      bothReject(
        JT + `class C { get f(t: T): External<u256> { return t.nope(); } }`,
        ST + `contract C { function f(T t) external view returns(uint256){ return t.nope(); } }`,
      ),
    ).toBe(true);
    // a plain `address` value has no methods.
    expect(
      bothReject(
        `class C { get f(a: address): External<u256> { return a.v(); } }`,
        `contract C { function f(address a) external view returns(uint256){ return a.v(); } }`,
      ),
    ).toBe(true);
    // the internal-method reject is the contract-value-specific JETH491 (member not found/visible).
    expect(
      codes(JT + `class C { get f(t: T): External<u256> { return t.nope(); } }`),
    ).toContain('JETH491');
  });

  it('GUARDS: the mutability ladder rejects at solc parity (a view/pure caller cannot invoke a state-mutating CALL)', () => {
    // a `get` (view) invoking a nonpayable method is a CALL that modifies state -> solc rejects.
    expect(
      bothReject(
        JT + `class C { t: T; get f(): External<u256> { return this.t.setx(1n); } }`,
        ST + `contract C { T t; function f() external view returns(uint256){ return t.setx(1); } }`,
      ),
    ).toBe(true);
    // a pure caller invoking a view method is a STATICCALL that reads state -> solc rejects.
    expect(
      bothReject(
        JT + `class C { get f(t: T): Pure<u256> { return t.v(); } }`,
        ST + `contract C { function f(T t) external pure returns(uint256){ return t.v(); } }`,
      ),
    ).toBe(true);
  });

  it('GUARDS: `value` on a non-payable method rejects; the raw-address surface is unaffected', () => {
    // value on a non-payable (nonpayable) method.
    expect(
      bothReject(
        JT + `class C { doset(t: T, x: u256): External<u256> { return t.setx(x, { value: 1n }); } }`,
        ST + `contract C { function doset(T t, uint256 x) external returns(uint256){ return t.setx{value:1}(x); } }`,
      ),
    ).toBe(true);
    // value on a view method.
    expect(
      bothReject(
        JT + `class C { get f(t: T): External<u256> { return t.v({ value: 1n }); } }`,
        ST + `contract C { function f(T t) external view returns(uint256){ return t.v{value:1}(); } }`,
      ),
    ).toBe(true);
    // the == nominal-address gate (JETH083) still rejects T-vs-plain-address.
    expect(
      bothReject(
        JT + `class C { get f(t: T, a: address): External<bool> { return t == a; } }`,
        ST + `contract C { function f(T t, address a) external pure returns(bool){ return t == a; } }`,
      ),
    ).toBe(true);
    // the raw address surface still works AFTER unwrapping with address(t).
    expect(
      accepts(JT + `class C { get f(t: T): External<bytes> { return address(t).code; } }`),
    ).toBe(true);
  });
});
