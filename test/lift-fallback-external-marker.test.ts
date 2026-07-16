// FALLBACK-EXTERNAL-MARKER lift: `External<T>` on a @receive / @fallback special entry is accepted as a
// REDUNDANT SYNONYM of the bare form (it used to be JETH386: "not an ABI function"). Rationale: solc
// REQUIRES `external` on both special entries (`fallback() external`, `receive() external payable` - a
// non-external one does not compile), so Solidity muscle memory reaches for the marker; JETH native mode
// is a permissive superset. The marker is UNWRAPPED to the bare return type and adds NOTHING else - no
// payability change (unlike Payable<T>), no dispatch change - so every accepted form is BYTE-IDENTICAL to
// its bare twin BY CONSTRUCTION, asserted directly below on creation bytecode.
//
// SCOPE: External<T> is accepted only where the BARE twin is legal, which is exactly where solc accepts
// the equivalent. Because the marker unwraps to the bare form, every guard falls out of the bare-form
// checks that already match solc 0.8.35 (each probed and pinned below): a RETURNING receive, a receive
// with parameters, a fallback arity/type mismatch, and External<Payable<void>> nesting all keep rejecting.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const bc = (src: string) => compile(src, { fileName: 'C.jeth' }).creationBytecode;
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics?.map((d: any) => d.code) ?? ['THROW'];
  }
};
const solRejects = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};

// Drive the REAL dispatch (raw calldata / a value transfer), not just a selector call.
async function runDiff(J: string, S: string, datas: string[], value?: bigint) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const d of datas) {
    const opts = value !== undefined ? { value } : {};
    const rj = await h.call(aj, d, opts);
    const rs = await h.call(as, d, opts);
    expect(rj.success, `success ${d.slice(0, 18)}`).toBe(rs.success);
    expect(rj.returnHex, `return ${d.slice(0, 18)}`).toBe(rs.returnHex);
  }
}

describe('FALLBACK-EXTERNAL-MARKER lift - External<T> on a special entry == the bare form', () => {
  // The core claim: the marker lowers through the IDENTICAL path, adding nothing.
  it('External<T> is byte-identical to the bare twin (fallback bytes / fallback void / receive void)', () => {
    expect(bc(`class C { fallback(input: bytes): External<bytes> { return input; } }`)).toBe(
      bc(`class C { fallback(input: bytes): bytes { return input; } }`),
    );
    expect(bc(`class C { t: u256; fallback(): External<void> { this.t = 7n; } }`)).toBe(
      bc(`class C { t: u256; fallback(): void { this.t = 7n; } }`),
    );
    expect(bc(`class C { t: u256; receive(): External<void> { this.t = 1n; } }`)).toBe(
      bc(`class C { t: u256; receive(): void { this.t = 1n; } }`),
    );
  });

  // The marker must NOT smuggle in payability the way Payable<T> does: a non-payable fallback stays
  // non-payable (a distinct bytecode from the payable twin, and it reverts on value - see below).
  it('External<void> does NOT add payability (differs from the Payable<void> twin)', () => {
    expect(bc(`class C { t: u256; fallback(): External<void> { this.t = 7n; } }`)).not.toBe(
      bc(`class C { t: u256; fallback(): Payable<void> { this.t = 7n; } }`),
    );
  });

  it('fallback(bytes): External<bytes> echoes raw calldata, byte-identical to solc', async () => {
    await runDiff(
      `class C { fallback(input: bytes): External<bytes> { return input; } }`,
      `contract C { fallback(bytes calldata i) external returns (bytes memory) { return i; } }`,
      ['0xdeadbeef', '0x', '0x' + 'ab'.repeat(40), '0x11223344556677889900'],
    );
  });

  it('receive(): External<void> takes ether and writes storage, byte-identical to solc', async () => {
    const J = `class C { t: u256; receive(): External<void> { this.t = 42n; } get g(): External<u256> { return this.t; } }`;
    const S = `contract C { uint256 t; receive() external payable { t = 42; } function g() public view returns (uint256) { return t; } }`;
    await runDiff(J, S, ['0x'], 1000n);
    await runDiff(J, S, [sel('g()')]);
  });

  it('fallback(): External<void> is reached by an unknown selector, byte-identical to solc', async () => {
    const J = `class C { t: u256; fallback(): External<void> { this.t = 7n; } get g(): External<u256> { return this.t; } }`;
    const S = `contract C { uint256 t; fallback() external { t = 7; } function g() public view returns (uint256) { return t; } }`;
    await runDiff(J, S, ['0x12345678', sel('g()')]);
  });

  it('fallback(): External<void> REVERTS on value like solc (non-payable, marker adds nothing)', async () => {
    await runDiff(
      `class C { t: u256; fallback(): External<void> { this.t = 7n; } }`,
      `contract C { uint256 t; fallback() external { t = 7; } }`,
      ['0x12345678'],
      5n,
    );
    // non-vacuity: that call really does revert (a passing parity check on two ACCEPTING contracts
    // would be a weaker claim).
    const h = await Harness.create();
    const a = await h.deploy(bc(`class C { t: u256; fallback(): External<void> { this.t = 7n; } }`));
    expect((await h.call(a, '0x12345678', { value: 5n })).success).toBe(false);
    expect((await h.call(a, '0x12345678')).success).toBe(true);
  });

  // OA GUARDS: solc's ONLY returning form is `fallback(bytes calldata) external returns (bytes memory)`,
  // and a receive can neither return nor take parameters. The marker must not open any of these.
  const GUARDS: [string, string, string][] = [
    [
      'a RETURNING receive (solc: "Receive ether function cannot return values")',
      `class C { receive(): External<u256> { return 1n; } }`,
      `contract C { receive() external payable returns (uint256) { return 1; } }`,
    ],
    [
      'a receive with parameters (solc: "Receive ether function cannot take parameters")',
      `class C { receive(x: u256): External<void> { x; } }`,
      `contract C { receive(uint256 x) external payable { x; } }`,
    ],
    [
      'fallback(bytes) with no return (solc: fallback taking bytes must return bytes)',
      `class C { fallback(input: bytes): External<void> { input; } }`,
      `contract C { fallback(bytes calldata i) external { i; } }`,
    ],
    [
      'fallback() returning a non-bytes type',
      `class C { fallback(): External<u256> { return 1n; } }`,
      `contract C { fallback() external returns (uint256) { return 1; } }`,
    ],
    [
      'fallback with a non-bytes parameter',
      `class C { fallback(x: u256): External<void> { x; } }`,
      `contract C { fallback(uint256 x) external { x; } }`,
    ],
  ];
  for (const [label, J, S] of GUARDS) {
    it(`keeps rejecting ${label} - solc parity`, () => {
      expect(solRejects(S), 'solc must reject: ' + label).toBe(true);
      expect(codes(J).length, 'JETH must reject: ' + label).toBeGreaterThan(0);
    });
  }

  // Forms solc accepts and the marker must too (the Payable interaction is orthogonal and unchanged:
  // a payable data-passing fallback is legal in solc, `fallback(bytes calldata) external payable
  // returns (bytes memory)` - probed).
  it('accepts the marker forms solc accepts (incl. the Payable data-passing fallback)', () => {
    expect(codes(`class C { fallback(input: bytes): External<bytes> { return input; } }`)).toEqual([]);
    expect(codes(`class C { fallback(): External<void> {} }`)).toEqual([]);
    expect(codes(`class C { t: u256; receive(): External<void> { this.t = 1n; } }`)).toEqual([]);
    expect(codes(`class C { fallback(input: bytes): Payable<bytes> { return input; } }`)).toEqual([]);
    expect(codes(`class C { fallback(): Payable<void> {} }`)).toEqual([]);
    expect(solRejects(`contract C { fallback(bytes calldata i) external payable returns (bytes memory) { return i; } }`)).toBe(
      false,
    );
  });

  it('a payable data-passing fallback stays distinct from the External/bare twin', () => {
    expect(bc(`class C { fallback(input: bytes): Payable<bytes> { return input; } }`)).not.toBe(
      bc(`class C { fallback(input: bytes): External<bytes> { return input; } }`),
    );
  });

  // Marker MISUSE that has no solc analogue must still reject (the lift is a synonym, not a blanket
  // "accept any marker" rule).
  it('rejects nonsense marker nesting and wrong marker arity', () => {
    expect(codes(`class C { fallback(): External<Payable<void>> {} }`).length).toBeGreaterThan(0);
    expect(codes(`class C { fallback(): Payable<External<void>> {} }`).length).toBeGreaterThan(0);
    expect(codes(`class C { fallback(): External {} }`)).toContain('JETH352');
    expect(codes(`class C { fallback(input: bytes): External<bytes, u256> { return input; } }`)).toContain('JETH352');
    // Payable<T> on a receive stays redundant-and-rejected (JETH385), ahead of any arity check.
    expect(codes(`class C { receive(): Payable<void> {} }`)).toContain('JETH385');
    expect(codes(`class C { receive(): Payable<void, u256> {} }`)).toContain('JETH385');
  });

  // The marker is orthogonal to the override machinery: a marked entry still obeys @virtual/@override.
  it('External<T> composes with the existing special-entry rules (@override with no base rejects)', () => {
    expect(codes(`class C { @override fallback(): External<void> {} }`)).toContain('JETH386');
  });
});
