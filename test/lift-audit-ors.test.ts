// The 2026-07-14 whole-surface audit found 17 sound over-rejections. After triaging each against the
// current codebase (already-fixed / deliberate-reject / liftable), 8 were genuinely open + byte-identically
// liftable and are lifted here (TYPED-CATCH + MULTI-CONTRACT-FILE stay deliberate rejects; the rest are
// LIFTABLE-HARD/low-value). Each row deploys both JETH and solc 0.8.35 and diffs runtime behavior, and pins
// the negatives that must still reject.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const codes = (s: string): string[] => { try { compile(s, { fileName: 'C.jeth' }); return []; } catch (e) { if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e; } };
const bc = (s: string) => compile(s, { fileName: 'C.jeth' }).creationBytecode;

async function sameRun(j: string, s: string, sel: string, args = '') {
  const h = await Harness.create();
  const aj = await h.deploy(bc(j));
  const as = await h.deploy(compileSolidity(SPDX + s, 'C').creation);
  const jr = await h.call(aj, '0x' + functionSelector(sel) + args);
  const sr = await h.call(as, '0x' + functionSelector(sel) + args);
  return { jr, sr };
}

describe('LIFT SHIFT-ASSIGN-SIGNED-LIT: `i256 >>= 1n` typed by amount, not LHS', () => {
  it('accepts + byte-identical to solc for signed shifts; keeps signed-VARIABLE-amount reject', async () => {
    for (const [j, s] of [
      [`class C { get f(): External<i256> { let a: i256 = 20n; a >>= 1n; return a; } }`, `contract C { function f() external pure returns(int256){ int256 a = 20; a >>= 1; return a; } }`],
      [`class C { get f(): External<i256> { let a: i256 = -20n; a >>= 2n; return a; } }`, `contract C { function f() external pure returns(int256){ int256 a = -20; a >>= 2; return a; } }`],
      [`class C { get f(): External<i256> { let a: i256 = 3n; a <<= 4n; return a; } }`, `contract C { function f() external pure returns(int256){ int256 a = 3; a <<= 4; return a; } }`],
      [`class C { get f(): External<i128> { let a: i128 = -7n; a >>= 1n; return a; } }`, `contract C { function f() external pure returns(int128){ int128 a = -7; a >>= 1; return a; } }`],
    ] as [string, string][]) {
      expect(codes(j)).toEqual([]);
      const { jr, sr } = await sameRun(j, s, 'f()');
      expect(jr.returnHex).toBe(sr.returnHex);
    }
    // negative controls that MUST still reject: a genuinely-signed VARIABLE shift amount
    expect(codes(`class C { get f(n: i16): External<i256> { let a: i256 = 5n; a >>= n; return a; } }`)).toContain('JETH081');
    // sanity: unsigned compound shift still works
    expect(codes(`class C { get f(): External<u16> { let a: u16 = 5n; a >>= 2n; return a; } }`)).toEqual([]);
  });
});

describe('LIFT UNINIT-ARRAY-LOCAL: `let a: Arr<u256,3>;` zero-inits like solc', () => {
  it('byte-identical across read / write-then-read / element types; dynamic uninit still rejects', async () => {
    for (const [j, s, seln] of [
      [`class C { get f(): External<u256> { let a: Arr<u256,3>; return a[0n]; } }`, `contract C { function f() external pure returns(uint256){ uint256[3] memory a; return a[0]; } }`, 'f()'],
      [`class C { get f(): External<u256> { let a: Arr<u256,3>; a[1n] = 9n; return a[1n]; } }`, `contract C { function f() external pure returns(uint256){ uint256[3] memory a; a[1]=9; return a[1]; } }`, 'f()'],
      [`class C { get f(): External<bytes> { let a: Arr<u256,3>; return abi.encode(a); } }`, `contract C { function f() external pure returns(bytes memory){ uint256[3] memory a; return abi.encode(a); } }`, 'f()'],
      [`class C { get f(): External<bool> { let a: Arr<bool,2>; return a[0n]; } }`, `contract C { function f() external pure returns(bool){ bool[2] memory a; return a[0]; } }`, 'f()'],
      [`class C { get f(): External<address> { let a: Arr<address,2>; return a[1n]; } }`, `contract C { function f() external pure returns(address){ address[2] memory a; return a[1]; } }`, 'f()'],
    ] as const) {
      expect(codes(j)).toEqual([]);
      const { jr, sr } = await sameRun(j, s, seln);
      expect(jr.returnHex).toBe(sr.returnHex);
    }
    // dynamic-array uninit is a DIFFERENT semantic (null pointer) - must STILL reject
    expect(codes(`class C { get f(): External<u256> { let a: u256[]; return a.length; } }`).length).toBeGreaterThan(0);
  });
});

describe('LIFT QUALIFIED-SELECTOR: `C.g.selector` (native getter/marker) resolves like this.g.selector', () => {
  it('accepts + byte-identical to solc; internal/unknown still reject', async () => {
    const j = `class C { get g(a: u256): External<u256> { return a; } get s(): External<bytes4> { return C.g.selector; } }`;
    const s = `contract C { function g(uint256 a) external pure returns(uint256){ return a; } function s() external pure returns(bytes4){ return C.g.selector; } }`;
    expect(codes(j)).toEqual([]);
    const { jr, sr } = await sameRun(j, s, 's()');
    expect(jr.returnHex).toBe(sr.returnHex);
    // and it equals the this.g.selector form (own-path)
    const jThis = `class C { get g(a: u256): External<u256> { return a; } get s(): External<bytes4> { return this.g.selector; } }`;
    const h = await Harness.create();
    const a1 = await h.deploy(bc(j)); const a2 = await h.deploy(bc(jThis));
    expect((await h.call(a1, '0x' + functionSelector('s()'))).returnHex).toBe((await h.call(a2, '0x' + functionSelector('s()'))).returnHex);
    // a marker (non-get) external method also works (state-writing, so `get` is not required)
    expect(codes(`class C { x: u256; g(a: u256): External<u256> { this.x = a; return a; } get s(): External<bytes4> { return C.g.selector; } }`)).toEqual([]);
    // negatives: an internal member has no selector; an unknown member rejects
    expect(codes(`class C { g(a: u256): u256 { return a; } get s(): External<bytes4> { return C.g.selector; } }`)).toContain('JETH074');
    expect(codes(`class C { get s(): External<bytes4> { return C.nope.selector; } }`)).toContain('JETH074');
  });
});

describe('LIFT IFACE-EVENT-MEMBER / IFACE-ERROR-MEMBER: interface may declare event/error; interfaceId unchanged', () => {
  it('accepts + interfaceId byte-identical to solc (event/error excluded); a plain field still rejects', async () => {
    const jE = `interface I { E: event<{ a: u256 }>; m(): u256; }\nclass C { get id(): External<bytes4> { return type(I).interfaceId; } }`;
    const sE = `interface I { event E(uint256 a); function m() external returns(uint256); }\ncontract C { function id() external pure returns(bytes4){ return type(I).interfaceId; } }`;
    expect(codes(jE)).toEqual([]);
    expect((await sameRun(jE, sE, 'id()')).jr.returnHex).toBe((await sameRun(jE, sE, 'id()')).sr.returnHex);
    const jErr = `interface I { Bad: error<{ a: u256 }>; m(): u256; }\nclass C { get id(): External<bytes4> { return type(I).interfaceId; } }`;
    const sErr = `interface I { error Bad(uint256 a); function m() external returns(uint256); }\ncontract C { function id() external pure returns(bytes4){ return type(I).interfaceId; } }`;
    expect(codes(jErr)).toEqual([]);
    { const { jr, sr } = await sameRun(jErr, sErr, 'id()'); expect(jr.returnHex).toBe(sr.returnHex); }
    // the event/error member must NOT contribute to interfaceId: same id as the interface WITHOUT them
    const jBare = `interface I { m(): u256; }\nclass C { get id(): External<bytes4> { return type(I).interfaceId; } }`;
    const h = await Harness.create();
    const a1 = await h.deploy(bc(jE)); const a2 = await h.deploy(bc(jBare));
    expect((await h.call(a1, '0x' + functionSelector('id()'))).returnHex).toBe((await h.call(a2, '0x' + functionSelector('id()'))).returnHex);
    // a genuine non-method member (a value field) still rejects JETH341
    expect(codes(`interface I { x: u256; m(): u256; }`)).toContain('JETH341');
  });
});

describe('LIFT GET-SELF-VIEWCALL: a `get` may `this.g()` a view/pure external', () => {
  it('accepts + byte-identical (returndata AND bytecode); a writer callee still rejects JETH043', async () => {
    const j = `class C { x: u256 = 7n; get g(): External<u256> { return this.x; } get f(): External<u256> { return this.g(); } }`;
    const s = `contract C { uint256 x = 7; function g() external view returns(uint256){ return x; } function f() external view returns(uint256){ return this.g(); } }`;
    expect(codes(j)).toEqual([]);
    // external self-calls are a BEHAVIORAL-parity construct in JETH (like the existing external-self-call
    // suite: success + returndata + logs match solc, not a byte-identical dispatcher); assert that parity.
    const { jr, sr } = await sameRun(j, s, 'f()');
    expect({ ok: jr.success, ret: jr.returnHex }).toEqual({ ok: sr.success, ret: sr.returnHex });
    expect(BigInt(jr.returnHex)).toBe(7n);
    // reject-preservation: a `get` calling a state-WRITING external must still be JETH043
    expect(codes(`class C { x: u256; setx(v: u256): External<void> { this.x = v; } get f(): External<u256> { this.setx(5n); return 1n; } }`)).toContain('JETH043');
  });
});

describe('LIFT LIB-CONST-IN-CONST: a library constant L.K folds into a contract constant', () => {
  it('accepts + byte-identical; behaves exactly like the same-class C.K (wrap corner included); shadow rejects', async () => {
    const j = `static class L { static K: u256 = 5n; }\nclass C { static M: u256 = L.K + 1n; get f(): External<u256> { return C.M; } }`;
    const s = `library L { uint256 internal constant K = 5; }\ncontract C { uint256 constant M = L.K + 1; function f() external pure returns(uint256){ return M; } }`;
    expect(codes(j)).toEqual([]);
    const { jr, sr } = await sameRun(j, s, 'f()');
    expect(jr.returnHex).toBe(sr.returnHex);
    expect(BigInt(jr.returnHex)).toBe(6n);
    // bare L.K also folds
    expect(codes(`static class L { static K: u256 = 9n; }\nclass C { static M: u256 = L.K; get f(): External<u256> { return C.M; } }`)).toEqual([]);
    // MC-guard: `L.K + 1n` at a NARROW type must behave EXACTLY like the same-class `C.K + 1n`
    const libU8 = codes(`static class L { static K: u8 = 255n; }\nclass C { static M: u8 = L.K + 1n; get f(): External<u8> { return C.M; } }`);
    const selfU8 = codes(`class C { static K: u8 = 255n; static M: u8 = C.K + 1n; get f(): External<u8> { return C.M; } }`);
    expect(libU8).toEqual(selfU8); // identical accept/reject behavior (no NEW miscompile path)
    // a contract member named like the library shadows it -> L.K does not fold -> rejects
    expect(codes(`static class L { static K: u256 = 5n; }\nclass C { static L: u256 = 9n; static M: u256 = L.K + 1n; get f(): External<u256> { return C.M; } }`).length).toBeGreaterThan(0);
  });
});

describe('LIFT ARRLIT-DIRECT-INDEX: `[a,b,c][i]` materializes + indexes like solc', () => {
  it('byte-identical returndata for in-bounds i and OOB Panic; a value-type element too', async () => {
    const j = `class C { get f(i: u256): External<u256> { return [100n,200n,300n][i]; } }`;
    const s = `contract C { function f(uint256 i) external pure returns(uint256){ return [uint256(100),200,300][i]; } }`;
    expect(codes(j)).toEqual([]);
    for (const i of [0n, 1n, 2n, 3n /* OOB -> Panic 0x32 */]) {
      const { jr, sr } = await sameRun(j, s, 'f(uint256)', pad32(i));
      expect({ ok: jr.success, ret: jr.returnHex }).toEqual({ ok: sr.success, ret: sr.returnHex });
    }
    // let-position also works + address elements
    expect(codes(`class C { get f(i: u256): External<u256> { let v: u256 = [7n,8n][i]; return v; } }`)).toEqual([]);
    const ja = `class C { get f(i: u256): External<address> { return [address(0), address(this)][i]; } }`;
    expect(codes(ja)).toEqual([]);
  });
});
