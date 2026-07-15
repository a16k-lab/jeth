// DUP-ID-ABSTRACT: solc's within-contract duplicate-identifier rules ("Identifier already declared." /
// "Function with same name and parameter types defined twice.") apply to EVERY contract in a file, not
// just the deployed one. The deployed contract and its C3 linearization are member-checked by
// analyzeContract; a top-level class NOT in that linearization - a stray / unextended abstract base, or a
// sibling abstract off the deployed chain - was never member-checked, so a duplicate field / field-vs-
// method / same-signature method on it silently ACCEPTED (solc rejects at the declaring contract
// regardless of whether it is used). checkStandaloneClassMemberDuplicates closes that over-acceptance,
// reusing the JETH373 (field+field) / JETH133 (field+method) / JETH044 (same-signature) code family.
//
// NON-VACUITY: each collision below is proven to ALSO reject under solc 0.8.35 (solcRejects); each GUARD
// is proven to compile on BOTH sides and to run BYTE-IDENTICAL (runBoth deploys the JETH artifact and its
// solc mirror side by side and asserts success + returnHex parity on seeded calls). The extended-base and
// deployed-contract dup paths are exercised to prove they are unregressed.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    const err = e as { diagnostics?: { code: string }[] };
    if (err.diagnostics) return err.diagnostics.map((d) => d.code);
    throw e;
  }
};
const solcRejects = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};
async function runBoth(
  J: string,
  S: string,
  calls: { data: string; value?: bigint }[],
): Promise<{ success: boolean; returnHex: string }[]> {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  const out: { success: boolean; returnHex: string }[] = [];
  for (const c of calls) {
    const opts = c.value !== undefined ? { value: c.value } : {};
    const rj = await h.call(aj, '0x' + c.data, opts);
    const rs = await h.call(as, '0x' + c.data, opts);
    expect(rj.success, `success parity for ${c.data || '<empty>'}`).toBe(rs.success);
    expect(rj.returnHex, `return parity for ${c.data || '<empty>'}`).toBe(rs.returnHex);
    out.push({ success: rj.success, returnHex: rj.returnHex });
  }
  return out;
}

// A deployable leaf that does NOT extend the stray base - a clean, writer-only contract so the ONLY issue
// in each COLLISION case is the duplicate on the un-analyzed base.
const DEP = `class C { z: u256; go(): External<u256> { this.z = 5n; return this.z; } }`;
const SDEP = `contract C { uint256 z; function go() external returns (uint256){ z=5; return z; } }`;

describe('DUP-ID-ABSTRACT: a duplicate identifier on an un-analyzed (stray/sibling) base now rejects at solc parity', () => {
  it('field + field on a stray abstract base -> JETH373 (solc: "Identifier already declared.")', () => {
    expect(codes(`abstract class T { a: u256; a: u256; } ${DEP}`)).toContain('JETH373');
    expect(solcRejects(`abstract contract T { uint256 a; uint256 a; } ${SDEP}`)).toBe(true);
  });

  it('field + method on a stray abstract base -> JETH133 (plain field)', () => {
    expect(codes(`abstract class T { pub: u256; @virtual pub(): External<u256>; } ${DEP}`)).toContain('JETH133');
    expect(
      solcRejects(`abstract contract T { uint256 pub; function pub() external virtual returns (uint256); } ${SDEP}`),
    ).toBe(true);
  });

  it('Visible field + method on a stray abstract base -> JETH133 (public field auto-getter clash)', () => {
    expect(codes(`abstract class T { pub: Visible<u256>; @virtual pub(): External<u256>; } ${DEP}`)).toContain('JETH133');
    expect(
      solcRejects(
        `abstract contract T { uint256 public pub; function pub() external virtual returns (uint256); } ${SDEP}`,
      ),
    ).toBe(true);
  });

  it('method + method with the SAME signature on a stray abstract base -> JETH044', () => {
    expect(
      codes(`abstract class T { @virtual m(): External<u256>; @virtual m(): External<u256>; } ${DEP}`),
    ).toContain('JETH044');
    expect(
      solcRejects(
        `abstract contract T { function m() external virtual returns (uint256); function m() external virtual returns (uint256); } ${SDEP}`,
      ),
    ).toBe(true);
  });

  it('static constant + method same name -> JETH133; immutable + field same name -> JETH373', () => {
    expect(codes(`abstract class T { static K: u256 = 1n; @virtual K(): External<u256>; } ${DEP}`)).toContain('JETH133');
    expect(codes(`abstract class T { static K: u256; K: u256; } ${DEP}`)).toContain('JETH373');
    expect(
      solcRejects(`abstract contract T { uint256 constant K = 1; function K() external virtual returns (uint256); } ${SDEP}`),
    ).toBe(true);
    expect(solcRejects(`abstract contract T { uint256 immutable K; uint256 K; } ${SDEP}`)).toBe(true);
  });

  it('field + get-accessor same name -> JETH133; two get-accessors same signature -> JETH044', () => {
    expect(codes(`abstract class T { g: u256; @virtual get g(): External<u256>; } ${DEP}`)).toContain('JETH133');
    expect(
      codes(`abstract class T { @virtual get g(): External<u256>; @virtual get g(): External<u256>; } ${DEP}`),
    ).toContain('JETH044');
  });

  it('a SIBLING abstract off the deployed chain is member-checked too -> JETH373', () => {
    expect(
      codes(
        `abstract class U { d: u256; d: u256; } abstract class T { a: u256; } class C extends T { z: u256; go(): External<u256> { this.z = 5n; return this.z; } }`,
      ),
    ).toContain('JETH373');
    expect(
      solcRejects(
        `abstract contract U { uint256 d; uint256 d; } abstract contract T { uint256 a; } contract C is T { uint256 z; function go() external returns (uint256){ z=5; return z; } }`,
      ),
    ).toBe(true);
  });
});

describe('DUP-ID-ABSTRACT guards: legit shapes still compile BYTE-IDENTICAL to the solc mirror', () => {
  it('a stray abstract base with DISTINCT members is accepted; the deployed contract runs identically', async () => {
    const J = `abstract class Helper { a: u256; b: u256; @virtual h(): External<u256>; } ${DEP}`;
    const S = `abstract contract Helper { uint256 a; uint256 b; function h() external virtual returns (uint256); } ${SDEP}`;
    expect(codes(J)).toEqual([]);
    expect(solcRejects(S)).toBe(false);
    const [r] = await runBoth(J, S, [{ data: sel('go()') }]);
    expect(r!.success).toBe(true);
    expect(r!.returnHex).toBe('0x' + W(5n));
  });

  it('DISTINCT-signature overloads on a stray abstract base stay accepted (not a duplicate)', async () => {
    const J = `abstract class T { @virtual m(): External<u256>; @virtual m(a: u256): External<u256>; } ${DEP}`;
    const S = `abstract contract T { function m() external virtual returns (uint256); function m(uint256 a) external virtual returns (uint256); } ${SDEP}`;
    expect(codes(J)).toEqual([]);
    const [r] = await runBoth(J, S, [{ data: sel('go()') }]);
    expect(r!.returnHex).toBe('0x' + W(5n));
  });

  it('a legit base-virtual + derived-@override (across two class bodies) is NOT a duplicate', async () => {
    const J = `abstract class T { @virtual m(): External<u256>; } class C extends T { z: u256; @override m(): External<u256> { this.z = 9n; return this.z; } }`;
    const S = `abstract contract T { function m() external virtual returns (uint256); } contract C is T { uint256 z; function m() external override returns (uint256){ z=9; return z; } }`;
    expect(codes(J)).toEqual([]);
    const [r] = await runBoth(J, S, [{ data: sel('m()') }]);
    expect(r!.returnHex).toBe('0x' + W(9n));
  });

  it('the deployed contract + an EXTENDED base dup path is unregressed (still rejects via the merged path)', () => {
    // T is in C's linearization, so the merged path (not the standalone pass) reports it - proving no double-report.
    expect(codes(`abstract class T { a: u256; a: u256; } class C extends T { z: u256; go(): External<u256> { this.z = 5n; return this.z; } }`)).toEqual(['JETH373']);
  });
});
