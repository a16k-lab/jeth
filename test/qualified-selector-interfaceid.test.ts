// Phase 6: TYPE-qualified function `.selector` and EIP-165 `type(I).interfaceId`, byte-identical to
// solc 0.8.35. Two compile-time bytes4 folds that JETH previously rejected (JETH074):
//   - `I.g.selector` (I an @interface) / `T.g.selector` (T a @contract / @abstract) == keccak(sig)[:4],
//     resolving `g` among the type's DIRECTLY-declared @external methods (solc rejects an inherited one).
//   - `type(I).interfaceId` == the XOR of the selectors of interface I's OWN functions (solc EXCLUDES
//     inherited functions; an empty interface yields 0x00000000). Rejected on a contract type.
// POSITIVE cases deploy BOTH the JETH and solc contract and diff the returned bytes4; NEGATIVE cases
// assert BOTH reject (a clean reject, never a crash or wrong bytes).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);

function jethCompile(src: string): { ok: boolean; codes: string[] } {
  try {
    compile(src, { fileName: 'C.jeth' });
    return { ok: true, codes: [] };
  } catch (e) {
    return { ok: false, codes: ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code) };
  }
}
function solOk(src: string, name = 'C'): boolean {
  try {
    compileSolidity(SPDX + src, name);
    return true;
  } catch {
    return false;
  }
}

/** POSITIVE: deploy JETH + solc, diff the bytes4 returned by each `f()`-shaped selector-getter call. */
async function matchPositive(jeth: string, sol: string, calls: string[]): Promise<void> {
  const cj = compile(jeth, { fileName: 'C.jeth' });
  const cs = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(cj.creationBytecode);
  const as = await hs.deploy(cs.creation);
  for (const sig of calls) {
    const data = '0x' + sel(sig);
    const rj = await hj.call(aj, data, {});
    const rs = await hs.call(as, data, {});
    expect(rj.success, `${sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${sig}: returndata`).toBe(rs.returnHex);
  }
}
function bothReject(jeth: string, sol: string): void {
  expect(jethCompile(jeth).ok, `JETH must reject: ${jeth.slice(0, 60)}`).toBe(false);
  expect(solOk(sol), `solc must reject: ${sol.slice(0, 60)}`).toBe(false);
}

describe('type-qualified .selector and type(I).interfaceId: byte-identical vs solc', () => {
  it('positive: I.g.selector for interface methods', async () => {
    await matchPositive(
      `@interface class IFoo { @external g(x: u256): u256; @external @view h(a: address): bool; }
       @contract class C {
         @external f(): bytes4 { return IFoo.g.selector; }
         @external f2(): bytes4 { return IFoo.h.selector; }
       }`,
      `interface IFoo { function g(uint256 x) external returns(uint256); function h(address a) external view returns(bool); }
       contract C {
         function f() external pure returns(bytes4){ return IFoo.g.selector; }
         function f2() external pure returns(bytes4){ return IFoo.h.selector; }
       }`,
      ['f()', 'f2()'],
    );
  });

  it('positive: C.g.selector (self) and A.g.selector (abstract base)', async () => {
    await matchPositive(
      `@abstract class A { @external g(x: u256): u256 { return x; } }
       @contract class C extends A {
         @external m(a: address, b: bool): u256 { return 0n; }
         @external f(): bytes4 { return C.m.selector; }
         @external f2(): bytes4 { return A.g.selector; }
       }`,
      `abstract contract A { function g(uint256 x) external virtual pure returns(uint256){ return x; } }
       contract C is A {
         function m(address a, bool b) external pure returns(uint256){ return 0; }
         function f() external pure returns(bytes4){ return C.m.selector; }
         function f2() external pure returns(bytes4){ return A.g.selector; }
       }`,
      ['f()', 'f2()'],
    );
  });

  it('positive: selector with struct/array/bytes params uses the canonical tuple form', async () => {
    await matchPositive(
      `@struct class Pt { x: u256; y: address; }
       @interface class IFoo { @external g(p: Pt, arr: u256[], b: bytes): u256; }
       @contract class C { @external f(): bytes4 { return IFoo.g.selector; } }`,
      `struct Pt { uint256 x; address y; }
       interface IFoo { function g(Pt calldata p, uint256[] calldata arr, bytes calldata b) external returns(uint256); }
       contract C { function f() external pure returns(bytes4){ return IFoo.g.selector; } }`,
      ['f()'],
    );
  });

  it('positive: type(I).interfaceId single, multi, and the ERC165 value', async () => {
    await matchPositive(
      `@interface class ISingle { @external g(x: u256): u256; }
       @interface class IMulti { @external g(x: u256): u256; @external @view h(a: address): bool; @external setX(x: u256): void; }
       @interface class IERC165 { @external @view supportsInterface(id: bytes4): bool; }
       @contract class C {
         @external f(): bytes4 { return type(ISingle).interfaceId; }
         @external f2(): bytes4 { return type(IMulti).interfaceId; }
         @external f3(): bytes4 { return type(IERC165).interfaceId; }
       }`,
      `interface ISingle { function g(uint256 x) external returns(uint256); }
       interface IMulti { function g(uint256 x) external returns(uint256); function h(address a) external view returns(bool); function setX(uint256 x) external; }
       interface IERC165 { function supportsInterface(bytes4 interfaceId) external view returns (bool); }
       contract C {
         function f() external pure returns(bytes4){ return type(ISingle).interfaceId; }
         function f2() external pure returns(bytes4){ return type(IMulti).interfaceId; }
         function f3() external pure returns(bytes4){ return type(IERC165).interfaceId; }
       }`,
      ['f()', 'f2()', 'f3()'],
    );
  });

  it('positive: the EIP-165 supportsInterface pattern (interfaceId compared to a bytes4 arg)', async () => {
    await matchPositive(
      `@interface class IERC165 { @external @view supportsInterface(id: bytes4): bool; }
       @interface class IFoo { @external doit(x: u256): u256; }
       @contract class C {
         @external @view supportsInterface(id: bytes4): bool {
           return id == type(IERC165).interfaceId || id == type(IFoo).interfaceId;
         }
         @external f165(): bytes4 { return type(IERC165).interfaceId; }
       }`,
      `interface IERC165 { function supportsInterface(bytes4 interfaceId) external view returns (bool); }
       interface IFoo { function doit(uint256 x) external returns(uint256); }
       contract C {
         function supportsInterface(bytes4 id) external pure returns(bool) {
           return id == type(IERC165).interfaceId || id == type(IFoo).interfaceId;
         }
         function f165() external pure returns(bytes4){ return type(IERC165).interfaceId; }
       }`,
      ['f165()'],
    );
  });

  it('positive: interfaceId EXCLUDES inherited interface functions (only the interface\'s own)', async () => {
    await matchPositive(
      `@interface class IBase { @external g(x: u256): u256; }
       @interface class IFoo extends IBase { @external h(a: address): bool; }
       @interface class IEmpty extends IBase {}
       @contract class C extends IFoo {
         @external g(x: u256): u256 { return x; }
         @external h(a: address): bool { return true; }
         @external f(): bytes4 { return type(IFoo).interfaceId; }
         @external f2(): bytes4 { return type(IEmpty).interfaceId; }
       }`,
      `interface IBase { function g(uint256 x) external returns(uint256); }
       interface IFoo is IBase { function h(address a) external returns(bool); }
       interface IEmpty is IBase {}
       contract C is IFoo {
         function g(uint256 x) external pure returns(uint256){ return x; }
         function h(address a) external pure returns(bool){ return true; }
         function f() external pure returns(bytes4){ return type(IFoo).interfaceId; }
         function f2() external pure returns(bytes4){ return type(IEmpty).interfaceId; }
       }`,
      ['f()', 'f2()'],
    );
  });

  // ---------------- NEGATIVE (both reject) ----------------
  it('negative: type(C).interfaceId on a contract/abstract type', () => {
    bothReject(
      `@contract class C { @external f(): bytes4 { return type(C).interfaceId; } }`,
      `contract C { function f() external pure returns(bytes4){ return type(C).interfaceId; } }`,
    );
  });

  it('negative: type(uint/enum).interfaceId', () => {
    bothReject(
      `@contract class C { @external f(): bytes4 { return type(u256).interfaceId; } }`,
      `contract C { function f() external pure returns(bytes4){ return type(uint256).interfaceId; } }`,
    );
    bothReject(
      `enum Color { Red, Green }
       @contract class C { @external f(): bytes4 { return type(Color).interfaceId; } }`,
      `contract C { enum Color { Red, Green } function f() external pure returns(bytes4){ return type(Color).interfaceId; } }`,
    );
  });

  it('negative: I.missing.selector (unknown member)', () => {
    bothReject(
      `@interface class IFoo { @external g(x: u256): u256; }
       @contract class C { @external f(): bytes4 { return IFoo.nope.selector; } }`,
      `interface IFoo { function g(uint256 x) external returns(uint256); }
       contract C { function f() external pure returns(bytes4){ return IFoo.nope.selector; } }`,
    );
  });

  it('negative: C.internal.selector (an internal method has no ABI selector)', () => {
    bothReject(
      `@contract class C { g(x: u256): u256 { return x; } @external f(): bytes4 { return C.g.selector; } }`,
      `contract C { function g(uint256 x) internal pure returns(uint256){ return x; } function f() external pure returns(bytes4){ return C.g.selector; } }`,
    );
  });

  it('negative: Derived.inheritedFn.selector (qualified selector resolves DIRECT members only)', () => {
    bothReject(
      `@abstract class A { @external g(x: u256): u256 { return x; } }
       @contract class C extends A { @external f(): bytes4 { return C.g.selector; } }`,
      `abstract contract A { function g(uint256 x) external virtual pure returns(uint256){ return x; } }
       contract C is A { function f() external pure returns(bytes4){ return C.g.selector; } }`,
    );
  });

  it('negative: I.inheritedFn.selector (interface inherited member is not direct)', () => {
    bothReject(
      `@interface class IBase { @external g(x: u256): u256; }
       @interface class IFoo extends IBase { @external h(a: address): bool; }
       @contract class C extends IFoo {
         @external g(x: u256): u256 { return x; }
         @external h(a: address): bool { return true; }
         @external f(): bytes4 { return IFoo.g.selector; }
       }`,
      `interface IBase { function g(uint256 x) external returns(uint256); }
       interface IFoo is IBase { function h(address a) external returns(bool); }
       contract C is IFoo {
         function g(uint256 x) external pure returns(uint256){ return x; }
         function h(address a) external pure returns(bool){ return true; }
         function f() external pure returns(bytes4){ return IFoo.g.selector; }
       }`,
    );
  });

  it('negative: overloaded qualified selector is ambiguous', () => {
    bothReject(
      `@contract class C {
         @external g(x: u256): u256 { return x; }
         @external g(x: address): u256 { return 0n; }
         @external f(): bytes4 { return C.g.selector; }
       }`,
      `contract C {
         function g(uint256 x) external pure returns(uint256){ return x; }
         function g(address x) external pure returns(uint256){ return 0; }
         function f() external pure returns(bytes4){ return C.g.selector; }
       }`,
    );
  });
});
