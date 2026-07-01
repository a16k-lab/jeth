// Phase 6: a contract IMPLEMENTING an @interface by listing it in its heritage clause
// (`@contract class C extends I { ... }`, mirroring solc `contract C is I { ... }`). An interface
// contributes NO storage/constructor/codegen; C declares+implements its methods as its own @external
// functions, so the existing dispatcher routes them. These tests are DIFFERENTIAL against solc 0.8.35:
//   POSITIVE cases deploy BOTH the JETH and the solc contract and diff success + returndata per call.
//   NEGATIVE cases assert JETH rejects (like solc) - a clean reject, never a crash or wrong bytes.
//   ORDERING cases pin the C3-of-interfaces behaviour (an interface is a first-class base node) so a
//   `is B, I` where B already implements I is a linearization error byte-for-byte with solc.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

/** Compile a JETH source; return the diagnostic codes on failure (or null on success). */
function jethCompile(src: string): { ok: boolean; codes: string[] } {
  try {
    compile(src, { fileName: 'C.jeth' });
    return { ok: true, codes: [] };
  } catch (e) {
    return { ok: false, codes: ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code) };
  }
}

/** Compile a solc source (SPDX auto-prepended); return whether it compiled. */
function solOk(src: string, name = 'C'): boolean {
  try {
    compileSolidity(SPDX + src, name);
    return true;
  } catch {
    return false;
  }
}

/** POSITIVE: deploy the JETH and solc contracts and assert every call is byte-identical (success +
 *  returndata). `calls` are [selectorSig, hexArgs] pairs; `value` is an optional call value. */
async function matchPositive(
  jeth: string,
  sol: string,
  calls: [string, string][],
  value?: bigint,
): Promise<void> {
  const cj = compile(jeth, { fileName: 'C.jeth' });
  const cs = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(cj.creationBytecode);
  const as = await hs.deploy(cs.creation);
  for (const [sig, args] of calls) {
    const data = '0x' + sel(sig) + (args ?? '');
    const rj = await hj.call(aj, data, value !== undefined ? { value } : {});
    const rs = await hs.call(as, data, value !== undefined ? { value } : {});
    expect(rj.success, `${sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${sig}: returndata`).toBe(rs.returnHex);
  }
}

/** NEGATIVE: assert BOTH JETH and solc reject the (equivalent) source with the expected JETH code. */
function bothReject(jeth: string, sol: string, expectCode: string): void {
  const j = jethCompile(jeth);
  expect(j.ok, `JETH must reject: ${jeth.slice(0, 60)}`).toBe(false);
  expect(j.codes, `JETH code`).toContain(expectCode);
  expect(solOk(sol), `solc must reject: ${sol.slice(0, 60)}`).toBe(false);
}

describe('contract implementing an @interface (heritage `extends I`): byte-identical vs solc', () => {
  // ---------------- POSITIVE ----------------
  it('positive: single interface, value + view methods, WITHOUT @override', async () => {
    await matchPositive(
      `@interface class I { @external f(x: u256): u256; @external @view g(): u256; }
       @contract class C extends I {
         @state s: u256;
         @external f(x: u256): u256 { this.s = x; return x + 1n; }
         @external @view g(): u256 { return this.s; }
       }`,
      `interface I { function f(uint256 x) external returns(uint256); function g() external view returns(uint256); }
       contract C is I {
         uint256 s;
         function f(uint256 x) external returns(uint256){ s = x; return x + 1; }
         function g() external view returns(uint256){ return s; }
       }`,
      [
        ['f(uint256)', W(41n)],
        ['g()', ''],
      ],
    );
  });

  it('positive: single interface WITH @override (optional under solc >= 0.8.8)', async () => {
    await matchPositive(
      `@interface class I { @external f(x: u256): u256; @external @view g(): u256; }
       @contract class C extends I {
         @state s: u256;
         @override @external f(x: u256): u256 { this.s = x; return x + 1n; }
         @override @external @view g(): u256 { return this.s; }
       }`,
      `interface I { function f(uint256 x) external returns(uint256); function g() external view returns(uint256); }
       contract C is I {
         uint256 s;
         function f(uint256 x) external override returns(uint256){ s = x; return x + 1; }
         function g() external view override returns(uint256){ return s; }
       }`,
      [
        ['f(uint256)', W(41n)],
        ['g()', ''],
      ],
    );
  });

  it('positive: a @payable and a @view method', async () => {
    await matchPositive(
      `@interface class I { @external @payable p(): u256; @external @view v(x: u256): u256; }
       @contract class C extends I {
         @external @payable p(): u256 { return msg.value; }
         @external @view v(x: u256): u256 { return x * 3n; }
       }`,
      `interface I { function p() external payable returns(uint256); function v(uint256 x) external view returns(uint256); }
       contract C is I {
         function p() external payable returns(uint256){ return msg.value; }
         function v(uint256 x) external view returns(uint256){ return x * 3; }
       }`,
      [
        ['p()', ''],
        ['v(uint256)', W(5n)],
      ],
      77n,
    );
  });

  it('positive: bytes / array / struct params + returns', async () => {
    await matchPositive(
      `@struct class P { a: u256; b: bool }
       @interface class I {
         @external @view sret(): string;
         @external @view aret(): u256[];
         @external @view stret(): P;
         @external bin(b: bytes): u256;
       }
       @contract class C extends I {
         @external @view sret(): string { return "hello world value here"; }
         @external @view aret(): u256[] { const a: u256[] = [1n, 2n, 3n]; return a; }
         @external @view stret(): P { const p: P = P(9n, true); return p; }
         @external bin(b: bytes): u256 { return b.length; }
       }`,
      `struct P { uint256 a; bool b; }
       interface I {
         function sret() external view returns(string memory);
         function aret() external view returns(uint256[] memory);
         function stret() external view returns(P memory);
         function bin(bytes calldata b) external returns(uint256);
       }
       contract C is I {
         function sret() external view returns(string memory){ return "hello world value here"; }
         function aret() external view returns(uint256[] memory){ uint256[] memory a = new uint256[](3); a[0]=1;a[1]=2;a[2]=3; return a; }
         function stret() external view returns(P memory){ P memory p = P(9, true); return p; }
         function bin(bytes calldata b) external returns(uint256){ return b.length; }
       }`,
      [
        ['sret()', ''],
        ['aret()', ''],
        ['stret()', ''],
        ['bin(bytes)', W(32n) + W(4n) + '11223344'.padEnd(64, '0')],
      ],
    );
  });

  it('positive: implements MULTIPLE interfaces', async () => {
    await matchPositive(
      `@interface class I { @external f(): u256; }
       @interface class J { @external @view g(): u256; }
       @contract class C extends I, J {
         @external f(): u256 { return 11n; }
         @external @view g(): u256 { return 22n; }
       }`,
      `interface I { function f() external returns(uint256); }
       interface J { function g() external view returns(uint256); }
       contract C is I, J {
         function f() external returns(uint256){ return 11; }
         function g() external view returns(uint256){ return 22; }
       }`,
      [
        ['f()', ''],
        ['g()', ''],
      ],
    );
  });

  it('positive: extends a base CONTRACT and an interface together', async () => {
    await matchPositive(
      `@interface class I { @external f(): u256; }
       @abstract class Base { @state s: u256; @external @view b(): u256 { return this.s + 5n; } }
       @contract class C extends Base, I {
         @external f(): u256 { this.s = 3n; return 99n; }
       }`,
      `interface I { function f() external returns(uint256); }
       abstract contract Base { uint256 s; function b() external view returns(uint256){ return s + 5; } }
       contract C is Base, I {
         function f() external returns(uint256){ s = 3; return 99; }
       }`,
      [
        ['f()', ''],
        ['b()', ''],
      ],
    );
  });

  it('positive: @abstract leaves an interface method open; a concrete contract completes it', async () => {
    await matchPositive(
      `@interface class I { @external f(): u256; @external @view g(): u256; }
       @abstract class A extends I { @external @view g(): u256 { return 7n; } }
       @contract class C extends A { @external f(): u256 { return 8n; } }`,
      `interface I { function f() external returns(uint256); function g() external view returns(uint256); }
       abstract contract A is I { function g() external view returns(uint256){ return 7; } }
       contract C is A { function f() external returns(uint256){ return 8; } }`,
      [
        ['f()', ''],
        ['g()', ''],
      ],
    );
  });

  it('positive: interface method inherited-implemented by a base contract', async () => {
    await matchPositive(
      `@interface class I { @external f(): u256; }
       @abstract class Base extends I { @external f(): u256 { return 42n; } }
       @contract class C extends Base { @external @view extra(): u256 { return 7n; } }`,
      `interface I { function f() external returns(uint256); }
       abstract contract Base is I { function f() external returns(uint256){ return 42; } }
       contract C is Base { function extra() external view returns(uint256){ return 7; } }`,
      [
        ['f()', ''],
        ['extra()', ''],
      ],
    );
  });

  it('positive: an interface method also @virtual in a base then overridden in C', async () => {
    await matchPositive(
      `@interface class I { @external f(): u256; }
       @abstract class Base extends I { @virtual @external f(): u256 { return 1n; } }
       @contract class C extends Base { @override @external f(): u256 { return 2n; } }`,
      `interface I { function f() external returns(uint256); }
       abstract contract Base is I { function f() external virtual returns(uint256){ return 1; } }
       contract C is Base { function f() external override returns(uint256){ return 2; } }`,
      [['f()', '']],
    );
  });

  it('positive: an interface extending another interface (`J is I`)', async () => {
    await matchPositive(
      `@interface class I { @external f(): u256; }
       @interface class J extends I { @external @view g(): u256; }
       @contract class C extends J {
         @external f(): u256 { return 3n; }
         @external @view g(): u256 { return 4n; }
       }`,
      `interface I { function f() external returns(uint256); }
       interface J is I { function g() external view returns(uint256); }
       contract C is J { function f() external returns(uint256){ return 3; } function g() external view returns(uint256){ return 4; } }`,
      [
        ['f()', ''],
        ['g()', ''],
      ],
    );
  });

  it('positive: impl may TIGHTEN mutability (interface nonpayable, impl view)', async () => {
    await matchPositive(
      `@interface class I { @external f(): u256; }
       @contract class C extends I { @external @view f(): u256 { return 5n; } }`,
      `interface I { function f() external returns(uint256); }
       contract C is I { function f() external view returns(uint256){ return 5; } }`,
      [['f()', '']],
    );
  });

  // ---------------- NEGATIVE (BOTH-REJECT) ----------------
  it('negative: a concrete contract leaves an interface method UNIMPLEMENTED', () => {
    bothReject(
      `@interface class I { @external f(): u256; @external @view g(): u256; }
       @contract class C extends I { @external f(): u256 { return 1n; } }`,
      `interface I { function f() external returns(uint256); function g() external view returns(uint256); }
       contract C is I { function f() external returns(uint256){ return 1; } }`,
      'JETH385',
    );
  });

  it('negative: impl with the WRONG parameter type', () => {
    bothReject(
      `@interface class I { @external f(x: u256): u256; }
       @contract class C extends I { @external f(x: bool): u256 { return 1n; } }`,
      `interface I { function f(uint256 x) external returns(uint256); }
       contract C is I { function f(bool x) external returns(uint256){ return 1; } }`,
      'JETH385',
    );
  });

  it('negative: impl with the WRONG return type', () => {
    bothReject(
      `@interface class I { @external f(): u256; }
       @contract class C extends I { @external f(): bool { return true; } }`,
      `interface I { function f() external returns(uint256); }
       contract C is I { function f() external returns(bool){ return true; } }`,
      'JETH386',
    );
  });

  it('negative: impl LOOSENS mutability (interface @view, impl writes state)', () => {
    bothReject(
      `@interface class I { @external @view f(): u256; }
       @contract class C extends I { @state s: u256; @external f(): u256 { this.s = 1n; return 2n; } }`,
      `interface I { function f() external view returns(uint256); }
       contract C is I { uint256 s; function f() external returns(uint256){ s = 1; return 2; } }`,
      'JETH387',
    );
  });

  it('negative: impl CROSSES payable (interface nonpayable, impl payable)', () => {
    bothReject(
      `@interface class I { @external f(): u256; }
       @contract class C extends I { @external @payable f(): u256 { return msg.value; } }`,
      `interface I { function f() external returns(uint256); }
       contract C is I { function f() external payable returns(uint256){ return msg.value; } }`,
      'JETH387',
    );
  });

  it('negative: an INTERNAL (non-@external) impl of an interface method', () => {
    bothReject(
      `@interface class I { @external f(): u256; }
       @contract class C extends I { f(): u256 { return 5n; } @external @view g(): u256 { return this.f(); } }`,
      `interface I { function f() external returns(uint256); }
       contract C is I { function f() internal returns(uint256){ return 5; } function g() external returns(uint256){ return f(); } }`,
      'JETH388',
    );
  });

  it('negative: giving an interface CONSTRUCTOR ARGUMENTS (`extends I(5)`)', () => {
    bothReject(
      `@interface class I { @external f(): u256; }
       @contract class C extends I(5) { @external f(): u256 { return 1n; } }`,
      `interface I { function f() external returns(uint256); }
       contract C is I(5) { function f() external returns(uint256){ return 1; } }`,
      'JETH384',
    );
  });

  it('negative: the SAME interface listed twice in one heritage clause', () => {
    bothReject(
      `@interface class I { @external f(): u256; }
       @contract class C extends I, I { @external f(): u256 { return 5n; } }`,
      `interface I { function f() external returns(uint256); }
       contract C is I, I { function f() external returns(uint256){ return 5; } }`,
      'JETH389',
    );
  });

  it('negative: interface method left open through a `J is I` chain', () => {
    bothReject(
      `@interface class I { @external f(): u256; }
       @interface class J extends I { @external @view g(): u256; }
       @contract class C extends J { @external @view g(): u256 { return 4n; } }`,
      `interface I { function f() external returns(uint256); }
       interface J is I { function g() external view returns(uint256); }
       contract C is J { function g() external view returns(uint256){ return 4; } }`,
      'JETH385',
    );
  });

  // ---------------- C3-OF-INTERFACES ORDERING (must match solc's linearization exactly) ----------------
  it('ordering: `is B, I` where B already implements I is a linearization error (JETH371), like solc', () => {
    bothReject(
      `@interface class I { @external f(): u256; }
       @abstract class B extends I { @external f(): u256 { return 2n; } }
       @contract class C extends B, I {}`,
      `interface I { function f() external returns(uint256); }
       abstract contract B is I { function f() external virtual returns(uint256){ return 2; } }
       contract C is B, I {}`,
      'JETH371',
    );
  });

  it('ordering: `is I, B` where B implements I is ACCEPTED (byte-identical to solc)', async () => {
    await matchPositive(
      `@interface class I { @external f(): u256; }
       @abstract class B extends I { @virtual @external f(): u256 { return 2n; } }
       @contract class C extends I, B {}`,
      `interface I { function f() external returns(uint256); }
       abstract contract B is I { function f() external virtual returns(uint256){ return 2; } }
       contract C is I, B {}`,
      [['f()', '']],
    );
  });
});
