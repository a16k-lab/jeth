// CTR-PUBFIELD-CALL (JETH491 lift): a `Visible<T>` PUBLIC-FIELD auto-getter CALLED on a contract/abstract
// VALUE (`t.pub()`, `t.m(k)`, `t.arr(i)`, `t.st()`). solc treats a public state var / constant / immutable as
// an EXTERNAL getter, callable on a contract-typed value exactly like a declared external method. JETH already
// routes an external-method call on a contract value through buildIfaceExtCall (CONTRACT-VALUE-CALL); this
// extends the callee registry (collectContractMethods -> buildContractCallMethod) to ALSO include the
// SYNTHESIZED auto-getter of every `Visible<T>` field, with the exact selector / signature solc generates for
// the getter (getterSignatureShape: mapping keys / array indices become params, the leaf value or a flattened
// struct tuple becomes the return; always view -> STATICCALL). So `t.pub()` lowers byte-identical to the
// interface twin `IT(addr).pub()` of the same getter signature AND to solc's own getter dispatch.
//
// Each accept row deploys a JETH `C` and a solc `C` alongside a REAL deployed target answering the getter
// selectors, seeds distinct values, and diffs success + returndata (run+decode ground truth). Byte identity to
// the interface twin is proven at the bytecode level. The negatives that must STILL reject (a bare/internal
// field called as a method -> JETH491; a mapping/array getter with the wrong arity; a getter on a plain
// address; a pure caller; a value option on a view getter) are pinned against solc reject-parity.
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

// The abstract type T (never deployed): its `Visible<T>` public fields are the callable auto-getters. A real
// solc `Tgt` with the SAME public fields (hence the same getter selectors) answers both C's calls.
const JT = `type Sp = { a: u256; b: address };
abstract class T {
  pub: Visible<u256>;
  m: Visible<mapping<address, u256>>;
  m2: Visible<mapping<address, mapping<address, u256>>>;
  arr: Visible<u256[]>;
  st: Visible<Sp>;
  static KON: Visible<u256> = 7n;
  sec: u256;
}
`;
const ST = `struct Sp { uint256 a; address b; }
abstract contract T {
  uint256 public pub;
  mapping(address=>uint256) public m;
  mapping(address=>mapping(address=>uint256)) public m2;
  uint256[] public arr;
  Sp public st;
  uint256 public constant KON = 7;
  uint256 sec;
}
`;
const TGT = `contract Tgt {
  uint256 public pub;
  mapping(address=>uint256) public m;
  mapping(address=>mapping(address=>uint256)) public m2;
  uint256[] public arr;
  struct Sp { uint256 a; address b; }
  Sp public st;
  uint256 public constant KON = 7;
  function seed(uint256 p, address k1, address k2, uint256 sa, address sb) external {
    pub = p;
    m[k1] = p + 1;
    m2[k1][k2] = p + 2;
    arr.push(sa); arr.push(sa + 1); arr.push(sa + 2);
    st = Sp(sa, sb);
  }
}`;

describe('CTR-PUBFIELD-CALL: a Visible<T> public-field auto-getter called on a contract value', () => {
  it('PIN: the base rejected `t.pub()` on a contract value with JETH491; it now accepts', () => {
    // The exact pinned shape (was JETH491 at base e6ce501).
    expect(
      accepts(`abstract class T { pub: Visible<u256>; }\nclass C { t: T; get f(): External<u256> { return this.t.pub(); } }`),
    ).toBe(true);
    // and every getter shape / receiver position type-checks now.
    expect(accepts(JT + `class C { get f(x: T, k: address): External<u256> { return x.m(k); } }`)).toBe(true);
    expect(accepts(JT + `class C { get f(x: T, i: u256): External<u256> { return x.arr(i); } }`)).toBe(true);
    expect(accepts(JT + `class C { get f(x: T): External<u256> { return x.KON(); } }`)).toBe(true);
    expect(accepts(JT + `class C { get f(x: T): External<u256> { let [a, b] = x.st(); return a; } }`)).toBe(true);
  });

  it('scalar / mapping / array / constant / struct getters run byte-identical to solc (run+decode)', async () => {
    const JC =
      JT +
      `class C {
        t: T;
        ts: T[];
        setT(x: T): External<void> { this.t = x; }
        addT(x: T): External<void> { this.ts.push(x); }
        get callPub(x: T): External<u256> { return x.pub(); }
        get callM(x: T, k: address): External<u256> { return x.m(k); }
        get callM2(x: T, a: address, b: address): External<u256> { return x.m2(a, b); }
        get callArr(x: T, i: u256): External<u256> { return x.arr(i); }
        get callKon(x: T): External<u256> { return x.KON(); }
        get callStA(x: T): External<u256> { let [a, b] = x.st(); return a; }
        get callStB(x: T): External<address> { let [a, b] = x.st(); return b; }
        get fldPub(): External<u256> { return this.t.pub(); }
        get elemPub(i: u256): External<u256> { return this.ts[i].pub(); }
      }`;
    const SC =
      ST +
      `contract C {
        T t;
        T[] ts;
        function setT(T x) external { t = x; }
        function addT(T x) external { ts.push(x); }
        function callPub(T x) external view returns (uint256) { return x.pub(); }
        function callM(T x, address k) external view returns (uint256) { return x.m(k); }
        function callM2(T x, address a, address b) external view returns (uint256) { return x.m2(a, b); }
        function callArr(T x, uint256 i) external view returns (uint256) { return x.arr(i); }
        function callKon(T x) external view returns (uint256) { return x.KON(); }
        function callStA(T x) external view returns (uint256) { (uint256 a,) = x.st(); return a; }
        function callStB(T x) external view returns (address) { (,address b) = x.st(); return b; }
        function fldPub() external view returns (uint256) { return t.pub(); }
        function elemPub(uint256 i) external view returns (uint256) { return ts[i].pub(); }
      }`;

    const h = await Harness.create();
    const tgt = await h.deploy(compileSolidity(SPDX + TGT, 'Tgt').creation);
    // distinct seeds: pub=0x2a=42, m[k1]=43, m2[k1][k2]=44, arr=[9,10,11], st=(9, 0x3333)
    const k1 = W(0x1111),
      k2 = W(0x2222),
      sb = 0x3333;
    await h.call(tgt, sel('seed(uint256,address,address,uint256,address)') + W(42) + k1 + k2 + W(9) + W(sb));
    const aj = await h.deploy(bc(JC));
    const as = await h.deploy(compileSolidity(SPDX + SC, 'C').creation);
    await h.call(aj, sel('setT(address)') + A(tgt));
    await h.call(as, sel('setT(address)') + A(tgt));
    await h.call(aj, sel('addT(address)') + A(tgt));
    await h.call(as, sel('addT(address)') + A(tgt));

    const calls: [string, string][] = [
      ['callPub(address)', A(tgt)],
      ['callM(address,address)', A(tgt) + k1],
      ['callM(address,address)', A(tgt) + W(0x9999)], // absent key -> 0
      ['callM2(address,address,address)', A(tgt) + k1 + k2],
      ['callArr(address,uint256)', A(tgt) + W(1)],
      ['callKon(address)', A(tgt)],
      ['callStA(address)', A(tgt)],
      ['callStB(address)', A(tgt)],
      ['fldPub()', ''],
      ['elemPub(uint256)', W(0)],
    ];
    for (const [sig, args] of calls) {
      const rj = await h.call(aj, sel(sig) + args);
      const rs = await h.call(as, sel(sig) + args);
      expect(rj.success, `${sig} success`).toBe(rs.success);
      expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
    }
    // Non-vacuous ground truth: the seeded values flow through the STATICCALLs.
    expect((await h.call(aj, sel('callPub(address)') + A(tgt))).returnHex).toBe('0x' + W(42));
    expect((await h.call(aj, sel('callM(address,address)') + A(tgt) + k1)).returnHex).toBe('0x' + W(43));
    expect((await h.call(aj, sel('callM2(address,address,address)') + A(tgt) + k1 + k2)).returnHex).toBe('0x' + W(44));
    expect((await h.call(aj, sel('callArr(address,uint256)') + A(tgt) + W(2))).returnHex).toBe('0x' + W(11));
    expect((await h.call(aj, sel('callStB(address)') + A(tgt))).returnHex).toBe('0x' + W(sb));
  });

  it('is byte-identical to the interface `IT(addr).getter()` twin of the same signature', () => {
    const IT = `interface IT { pub(): View<u256>; m(k: address): View<u256>; arr(i: u256): View<u256>; }`;
    const pairs: [string, string][] = [
      [
        JT + `class C { get f(t: T): External<u256> { return t.pub(); } }`,
        IT + `\nclass C { get f(a: address): External<u256> { return IT(a).pub(); } }`,
      ],
      [
        JT + `class C { get f(t: T, k: address): External<u256> { return t.m(k); } }`,
        IT + `\nclass C { get f(a: address, k: address): External<u256> { return IT(a).m(k); } }`,
      ],
      [
        JT + `class C { get f(t: T, i: u256): External<u256> { return t.arr(i); } }`,
        IT + `\nclass C { get f(a: address, i: u256): External<u256> { return IT(a).arr(i); } }`,
      ],
    ];
    for (const [ctr, iface] of pairs) expect(bc(ctr)).toBe(bc(iface));
  });

  it('GUARDS: a non-public field, wrong getter arity, a plain address, a pure caller, or a value option reject at solc parity', () => {
    // a bare (internal) field is not an external getter -> JETH491, both reject.
    expect(
      bothReject(
        JT + `class C { get f(t: T): External<u256> { return t.sec(); } }`,
        ST + `contract C { function f(T t) external view returns (uint256) { return t.sec(); } }`,
      ),
    ).toBe(true);
    expect(codes(JT + `class C { get f(t: T): External<u256> { return t.sec(); } }`)).toContain('JETH491');
    // a mapping getter with 0 args (wrong arity).
    expect(
      bothReject(
        JT + `class C { get f(t: T): External<u256> { return t.m(); } }`,
        ST + `contract C { function f(T t) external view returns (uint256) { return t.m(); } }`,
      ),
    ).toBe(true);
    // an array getter with 0 args (wrong arity).
    expect(
      bothReject(
        JT + `class C { get f(t: T): External<u256> { return t.arr(); } }`,
        ST + `contract C { function f(T t) external view returns (uint256) { return t.arr(); } }`,
      ),
    ).toBe(true);
    // a getter on a plain address value (no method surface).
    expect(
      bothReject(
        `class C { get f(a: address): External<u256> { return a.pub(); } }`,
        `contract C { function f(address a) external view returns (uint256) { return a.pub(); } }`,
      ),
    ).toBe(true);
    // a PURE caller invoking a getter is a STATICCALL that reads env -> solc requires view; both reject.
    expect(
      bothReject(
        JT + `class C { get f(t: T): Pure<u256> { return t.pub(); } }`,
        ST + `contract C { function f(T t) external pure returns (uint256) { return t.pub(); } }`,
      ),
    ).toBe(true);
    // a `value` option on a view getter (getters are never payable).
    expect(
      bothReject(
        JT + `class C { get f(t: T): External<u256> { return t.pub({ value: 1n }); } }`,
        ST + `contract C { function f(T t) external view returns (uint256) { return t.pub{value:1}(); } }`,
      ),
    ).toBe(true);
  });
});
