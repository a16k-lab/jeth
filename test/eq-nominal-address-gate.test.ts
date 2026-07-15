// EQ-NOMINAL-ADDRESS gate (JETH083, soundness OA closure): a contract/interface reference is a NOMINAL
// branded address. solc has NO implicit conversion between such a reference and a plain `address`, nor
// between two DIFFERENT nominal brands, so `==` / `!=` where exactly one side is a nominal address and the
// other is a plain address (either operand order), OR the two sides are different nominal brands, is a
// TYPE ERROR: "Built-in binary operator == cannot be applied to types address and contract T." JETH used to
// silently ACCEPT the LITERAL form (`address(0) == t`) because the address literal failed retypeLiteral
// quietly and the return-site error-recovery swallowed the undefined - an over-acceptance. This gate rejects
// every mismatch position (value / param / return / local / array-elem / mapping-elem / struct-field) while
// keeping SAME-nominal (t == t2), plain==plain, and the explicit `address(t)` cast ACCEPTED byte-identical.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const errCodes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
const accepts = (src: string): boolean => errCodes(src).length === 0;
const solcRejects = (s: string): boolean => {
  try {
    compileSolidity(SPDX + s, 'C');
    return false;
  } catch {
    return true;
  }
};

const T_j = `abstract class T { @virtual v(): External<u256>; }\n`;
const U_j = `abstract class U { @virtual w(): External<u256>; }\n`;
const T_s = `contract T { function v() external returns (uint256){ return 1; } }\n`;
const U_s = `contract U { function w() external returns (uint256){ return 2; } }\n`;
const A2 = (x: string, y: string) => pad32(BigInt('0x' + x)).slice(2) + pad32(BigInt('0x' + y)).slice(2);

describe('EQ-NOMINAL-ADDRESS: comparing a contract/interface reference to a plain address is a type error', () => {
  // ---- the pinned over-acceptance: it must now flip accept -> reject ----
  it('rejects the pinned OA `address(0) == this.t` with JETH083 (solc rejects too)', () => {
    const J = T_j + `class C { t: T; get f(): External<bool> { return address(0) == this.t; } }`;
    const S = T_s + `contract C { T t; function f() external view returns (bool){ return address(0) == t; } }`;
    expect(errCodes(J)).toContain('JETH083');
    expect(solcRejects(S)).toBe(true);
  });

  // ---- reject-parity matrix: every mismatch position, both operand orders, == and != ----
  it('rejects every nominal-vs-address / different-nominal comparison, byte-parity with solc reject', () => {
    const cases: Array<[string, string]> = [
      // field nominal, both orders
      [T_j + `class C { t: T; get f(): External<bool> { return this.t == address(0); } }`,
        T_s + `contract C { T t; function f() external view returns (bool){ return t == address(0); } }`],
      // param address vs param nominal, both orders
      [T_j + `class C { get f(a: address, t: T): External<bool> { return a == t; } }`,
        T_s + `contract C { function f(address a, T t) external pure returns (bool){ return a == t; } }`],
      [T_j + `class C { get f(a: address, t: T): External<bool> { return t == a; } }`,
        T_s + `contract C { function f(address a, T t) external pure returns (bool){ return t == a; } }`],
      // msg.sender vs nominal
      [T_j + `class C { t: T; get f(): External<bool> { return msg.sender == this.t; } }`,
        T_s + `contract C { T t; function f() external view returns (bool){ return msg.sender == t; } }`],
      // literal address vs nominal
      [T_j + `class C { t: T; get f(): External<bool> { return 0x0000000000000000000000000000000000000001 == this.t; } }`,
        T_s + `contract C { T t; function f() external view returns (bool){ return 0x0000000000000000000000000000000000000001 == t; } }`],
      // two DIFFERENT nominal brands (contract T vs contract U)
      [T_j + U_j + `class C { t: T; u: U; get f(): External<bool> { return this.t == this.u; } }`,
        T_s + U_s + `contract C { T t; U u; function f() external view returns (bool){ return t == u; } }`],
      // array element nominal vs address
      [T_j + `class C { xs: T[]; get f(a: address): External<bool> { return this.xs[0n] == a; } }`,
        T_s + `contract C { T[] xs; function f(address a) external view returns (bool){ return xs[0] == a; } }`],
      // mapping value nominal vs address
      [T_j + `class C { m: mapping<u256, T>; get f(a: address): External<bool> { return this.m[0n] == a; } }`,
        T_s + `contract C { mapping(uint256 => T) m; function f(address a) external view returns (bool){ return m[0] == a; } }`],
      // struct field nominal vs address
      [T_j + `type S = { t: T };\nclass C { s: S; get f(a: address): External<bool> { return this.s.t == a; } }`,
        T_s + `contract C { struct S { T t; } S s; function f(address a) external view returns (bool){ return s.t == a; } }`],
      // local nominal vs address
      [T_j + `class C { get f(t: T, a: address): External<bool> { let x: T = t; return x == a; } }`,
        T_s + `contract C { function f(T t, address a) external pure returns (bool){ T x = t; return x == a; } }`],
      // != mismatch (nominal != address)
      [T_j + `class C { get f(t: T, a: address): External<bool> { return t != a; } }`,
        T_s + `contract C { function f(T t, address a) external pure returns (bool){ return t != a; } }`],
      // return-position != with literal zero, other order
      [T_j + `class C { t: T; get f(): External<bool> { return address(0) != this.t; } }`,
        T_s + `contract C { T t; function f() external view returns (bool){ return address(0) != t; } }`],
    ];
    for (const [J, S] of cases) {
      expect(errCodes(J)).toContain('JETH083'); // JETH rejects with the binary-op mismatch code
      expect(solcRejects(S)).toBe(true); // solc rejects too -> BOTH-REJECT parity
    }
  });

  // ---- accept controls: must stay ACCEPTED and byte-identical to solc (non-vacuity: these do NOT flip) ----
  it('keeps plain==plain, SAME-nominal, and explicit address(t) cast ACCEPTED, byte-identical to solc', async () => {
    const h = await Harness.create();
    const pairs: Array<[string, string, string]> = [
      // plain address == plain address (pure)
      [`class C { get f(a: address, b: address): External<bool> { return a == b; } }`,
        `contract C { function f(address a, address b) external pure returns (bool){ return a == b; } }`,
        'f(address,address)'],
      // SAME nominal t == t2
      [T_j + `class C { get f(t: T, t2: T): External<bool> { return t == t2; } }`,
        T_s + `contract C { function f(T t, T t2) external pure returns (bool){ return t == t2; } }`,
        'f(address,address)'],
      // SAME nominal t != t2
      [T_j + `class C { get f(t: T, t2: T): External<bool> { return t != t2; } }`,
        T_s + `contract C { function f(T t, T t2) external pure returns (bool){ return t != t2; } }`,
        'f(address,address)'],
      // explicit cast address(t) == a
      [T_j + `class C { get f(t: T, a: address): External<bool> { return address(t) == a; } }`,
        T_s + `contract C { function f(T t, address a) external pure returns (bool){ return address(t) == a; } }`,
        'f(address,address)'],
      // SAME nominal via locals
      [T_j + `class C { get f(t: T, t2: T): External<bool> { let x: T = t; let y: T = t2; return x == y; } }`,
        T_s + `contract C { function f(T t, T t2) external pure returns (bool){ T x = t; T y = t2; return x == y; } }`,
        'f(address,address)'],
    ];
    for (const [J, S, fn] of pairs) {
      expect(accepts(J)).toBe(true);
      expect(solcRejects(S)).toBe(false);
      const cj = await h.deploy(bc(J));
      const cs = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
      for (const [x, y] of [['0a', '0a'], ['0a', '0b']] as const) {
        const data = sel(fn) + A2(x, y);
        const rj = await h.call(cj, data);
        const rs = await h.call(cs, data);
        expect(rj.success).toBe(rs.success);
        expect(rj.returnHex).toBe(rs.returnHex);
      }
    }
  });
});
