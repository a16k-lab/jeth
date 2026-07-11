// Group A analyzer gates (solc accept/reject parity for special entries + the reentrancy guard):
//  - JETH471: msg.data inside a receive body is rejected (solc: '"msg.data" cannot be used inside of
//    "receive" function.'). Every msg.data form (.length, [i], .slice, keccak256(msg.data)) and every
//    mode (native, decorator, inherited-from-@abstract) rejects; msg.sig / msg.value / msg.sender stay
//    allowed in a receive, and a fallback keeps msg.data.
//  - JETH472: a BODYLESS receive/fallback declaration is rejected (solc: 'Contract "C" should be
//    marked as abstract.'). Previously native mode silently materialized an IMPLEMENTED empty entry
//    (a plain transfer SUCCEEDED on a mere declaration). The legal solc abstract idiom (bodyless
//    @virtual entry in an @abstract base + implemented @override in the deployed contract) stays
//    accepted and byte-identical.
//  - JETH473: @nonReentrant on a read-only function that BYPASSED the legacy JETH260 gate (a native
//    `get` accessor, or an inferred-@view/@pure method). The guard TSTOREs, so the ABI claimed view
//    while every staticcall/eth_call of the entry reverted on the mutex write. A @nonReentrant on a
//    WRITING method stays accepted byte-identical vs solc's transient-storage mutex mirror.
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
const solcRejects = (src: string, name = 'C'): boolean => {
  try {
    compileSolidity(SPDX + src, name);
    return false;
  } catch {
    return true;
  }
};

// ---------------------------------------------------------------------------------------------
// JETH471: msg.data inside receive
// ---------------------------------------------------------------------------------------------
describe('JETH471: msg.data is rejected inside a receive body (solc parity)', () => {
  it('msg.data.length in a native receive -> JETH471; solc mirror rejects', () => {
    expect(
      codes(`class C { l: u256; receive(): void { this.l = msg.data.length + 5n; } get g(): External<u256> { return this.l; } }`),
    ).toContain('JETH471');
    expect(
      solcRejects(`contract C { uint256 l; receive() external payable { l = msg.data.length + 5; } function g() external view returns (uint256) { return l; } }`),
    ).toBe(true);
  });

  it('keccak256(msg.data) in receive -> JETH471', () => {
    expect(codes(`class C { l: bytes32; receive(): void { this.l = keccak256(msg.data); } }`)).toContain('JETH471');
    expect(solcRejects(`contract C { bytes32 l; receive() external payable { l = keccak256(msg.data); } }`)).toBe(true);
  });

  it('msg.data.slice(...) in receive -> JETH471', () => {
    expect(codes(`class C { l: u256; receive(): void { this.l = msg.data.slice(0n, 4n).length; } }`)).toContain('JETH471');
    expect(solcRejects(`contract C { uint256 l; receive() external payable { l = msg.data[0:4].length; } }`)).toBe(true);
  });

  it('msg.data[i] in receive -> JETH471', () => {
    expect(codes(`class C { l: bytes1; receive(): void { this.l = msg.data[0n]; } }`)).toContain('JETH471');
    expect(solcRejects(`contract C { bytes1 l; receive() external payable { l = msg.data[0]; } }`)).toBe(true);
  });

  it('decorator-mode @receive with msg.data -> JETH471', () => {
    expect(
      codes(`// use @decorators
@contract class C { @state l: u256; @receive r(): void { this.l = msg.data.length + 5n; } @external @view g(): u256 { return this.l; } }`),
    ).toContain('JETH471');
  });

  it('receive declared in an @abstract base with msg.data -> JETH471', () => {
    expect(
      codes(`
abstract class B { l: u256; receive(): void { this.l = msg.data.length; } }
class C extends B { get g(): External<u256> { return this.l; } }`),
    ).toContain('JETH471');
    expect(
      solcRejects(`abstract contract B { uint256 l; receive() external payable virtual { l = msg.data.length; } }
contract C is B { function g() external view returns (uint256) { return l; } }`),
    ).toBe(true);
  });

  it('msg.sig in receive stays ACCEPTED, byte-identical to solc (non-vacuous: value seeded via transfer)', async () => {
    const J = `class C { l: bytes32; receive(): void { this.l = msg.sig; } get g(): External<bytes32> { return this.l; } }`;
    const S = `contract C { bytes32 l; receive() external payable { l = msg.sig; } function g() external view returns (bytes32) { return l; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const tj = await h.call(aj, '0x', { value: 3n });
    const ts = await h.call(as, '0x', { value: 3n });
    expect(tj.success).toBe(ts.success);
    expect(tj.success).toBe(true);
    const gj = await h.call(aj, '0x' + sel('g()'));
    const gs = await h.call(as, '0x' + sel('g()'));
    expect(gj.returnHex).toBe(gs.returnHex);
  });

  it('msg.value + msg.sender in receive stay ACCEPTED, byte-identical (distinct seed 7 wei)', async () => {
    const J = `class C { v: u256; s: address; receive(): void { this.v = msg.value; this.s = msg.sender; } get gv(): External<u256> { return this.v; } }`;
    const S = `contract C { uint256 v; address s; receive() external payable { v = msg.value; s = msg.sender; } function gv() external view returns (uint256) { return v; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, '0x', { value: 7n });
    await h.call(as, '0x', { value: 7n });
    const gj = await h.call(aj, '0x' + sel('gv()'));
    const gs = await h.call(as, '0x' + sel('gv()'));
    expect(gj.returnHex).toBe(gs.returnHex);
    expect(BigInt(gj.returnHex)).toBe(7n);
  });

  it('msg.data in a FALLBACK stays accepted + byte-identical (unknown selector stores calldata length)', async () => {
    const J = `class C { l: u256; fallback(): void { this.l = msg.data.length; } get g(): External<u256> { return this.l; } }`;
    const S = `contract C { uint256 l; fallback() external { l = msg.data.length; } function g() external view returns (uint256) { return l; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const data = '0x' + sel('nosuch(uint256)') + W(1n); // 36 bytes of calldata
    await h.call(aj, data);
    await h.call(as, data);
    const gj = await h.call(aj, '0x' + sel('g()'));
    const gs = await h.call(as, '0x' + sel('g()'));
    expect(gj.returnHex).toBe(gs.returnHex);
    expect(BigInt(gj.returnHex)).toBe(36n);
  });

  it('data-passing fallback(input: bytes): bytes echo stays byte-identical', async () => {
    const J = `class C { fallback(input: bytes): bytes { return input; } }`;
    const S = `contract C { fallback(bytes calldata input) external returns (bytes memory) { return input; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const data = '0x' + sel('echo(uint256)') + W(77n);
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
  });

  it('msg.data in a NORMAL function is unregressed (get accessor returns msg.data.length)', async () => {
    const J = `class C { get g(): External<u256> { return msg.data.length; } }`;
    const S = `contract C { function g() external pure returns (uint256) { return msg.data.length; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const gj = await h.call(aj, '0x' + sel('g()'));
    const gs = await h.call(as, '0x' + sel('g()'));
    expect(gj.returnHex).toBe(gs.returnHex);
    expect(BigInt(gj.returnHex)).toBe(4n);
  });
});

// ---------------------------------------------------------------------------------------------
// JETH472: bodyless receive / fallback declarations
// ---------------------------------------------------------------------------------------------
describe('JETH472: a bodyless receive/fallback declaration is rejected (solc parity)', () => {
  const cells: [string, string, string][] = [
    ['receive(): void;', `class C { receive(): void; }`, `contract C { receive() external payable; }`],
    ['fallback(): void;', `class C { fallback(): void; }`, `contract C { fallback() external; }`],
    [
      'fallback(input: bytes): bytes;',
      `class C { fallback(input: bytes): bytes; }`,
      `contract C { fallback(bytes calldata input) external returns (bytes memory); }`,
    ],
    ['fallback(): Payable<void>;', `class C { fallback(): Payable<void>; }`, `contract C { fallback() external payable; }`],
  ];
  for (const [label, jeth, sol] of cells) {
    it(`native bodyless \`${label}\` -> JETH472; solc mirror rejects`, () => {
      expect(codes(jeth)).toContain('JETH472');
      expect(solcRejects(sol)).toBe(true);
    });
  }

  it('decorator-mode bodyless @receive -> JETH472', () => {
    expect(codes(`// use @decorators
@contract class C { @receive r(): void; }`)).toContain('JETH472');
  });

  it('a bodyless @virtual receive in an @abstract base with NO derived implementation -> JETH472 (solc: abstract)', () => {
    expect(
      codes(`
abstract class B { @virtual receive(): void; }
class C extends B { get g(): External<u256> { return 1n; } }`),
    ).toContain('JETH472');
    expect(
      solcRejects(`abstract contract B { receive() external payable virtual; }
contract C is B { function g() external view returns (uint256) { return 1; } }`),
    ).toBe(true);
  });

  it('the legal abstract idiom (bodyless @virtual base + implemented @override in the deployed contract) stays accepted + runs byte-identical', async () => {
    const J = `
abstract class B { @virtual receive(): void; }
class C extends B { n: u256; @override receive(): void { this.n = this.n + 1n; } get g(): External<u256> { return this.n; } }`;
    const S = `abstract contract B { receive() external payable virtual; }
contract C is B { uint256 n; receive() external payable override { n = n + 1; } function g() external view returns (uint256) { return n; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, '0x', { value: 1n });
    await h.call(as, '0x', { value: 1n });
    const gj = await h.call(aj, '0x' + sel('g()'));
    const gs = await h.call(as, '0x' + sel('g()'));
    expect(gj.returnHex).toBe(gs.returnHex);
    expect(BigInt(gj.returnHex)).toBe(1n);
  });

  it('an IMPLEMENTED receive is unregressed: transfer succeeds, unknown selector reverts, counter parity', async () => {
    const J = `class C { n: u256; receive(): void { this.n = this.n + 1n; } get g(): External<u256> { return this.n; } }`;
    const S = `contract C { uint256 n; receive() external payable { n = n + 1; } function g() external view returns (uint256) { return n; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [data, value] of [['0x', 3n], ['0x' + sel('nosuch()'), 0n]] as const) {
      const rj = await h.call(aj, data, { value });
      const rs = await h.call(as, data, { value });
      expect(rj.success, `dispatch parity for ${data}`).toBe(rs.success);
    }
    const gj = await h.call(aj, '0x' + sel('g()'));
    const gs = await h.call(as, '0x' + sel('g()'));
    expect(gj.returnHex).toBe(gs.returnHex);
    expect(BigInt(gj.returnHex)).toBe(1n);
  });

  it('an IMPLEMENTED fallback is unregressed: value routing parity (non-payable fallback rejects value)', async () => {
    const J = `class C { n: u256; fallback(): void { this.n = this.n + 10n; } get g(): External<u256> { return this.n; } }`;
    const S = `contract C { uint256 n; fallback() external { n = n + 10; } function g() external view returns (uint256) { return n; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [data, value] of [['0x' + sel('nosuch()'), 0n], ['0x', 3n], ['0x', 0n]] as const) {
      const rj = await h.call(aj, data, { value });
      const rs = await h.call(as, data, { value });
      expect(rj.success, `dispatch parity for ${data} value=${value}`).toBe(rs.success);
    }
    const gj = await h.call(aj, '0x' + sel('g()'));
    const gs = await h.call(as, '0x' + sel('g()'));
    expect(gj.returnHex).toBe(gs.returnHex);
    expect(BigInt(gj.returnHex)).toBe(20n);
  });

  it('the plain-method bodyless gate (JETH380) is unregressed', () => {
    expect(codes(`class C { f(): void; @external g(): External<void> { this.f(); } }`)).toContain('JETH380');
  });
});

// ---------------------------------------------------------------------------------------------
// JETH473: @nonReentrant on a read-only (get / inferred view-pure) method
// ---------------------------------------------------------------------------------------------
describe('JETH473: @nonReentrant on a read-only method (native inference bypass of JETH260)', () => {
  it("@nonReentrant on a `get` accessor -> JETH473; solc's tstore-modifier-on-view twin rejects", () => {
    expect(
      codes(`class C { x: u256; set(v: u256): External<void> { this.x = v; } @nonReentrant get getX(): External<u256> { return this.x; } }`),
    ).toContain('JETH473');
    expect(
      solcRejects(`contract C { uint256 x;
  modifier nr() { assembly { tstore(0, 1) } _; assembly { tstore(0, 0) } }
  function set(uint256 v) external { x = v; }
  function getX() external view nr returns (uint256) { return x; } }`),
    ).toBe(true);
  });

  it('@nonReentrant floors an inferred method at NONPAYABLE (never view/pure): the ABI no longer lies', () => {
    // Before the fix these inferred view/pure while the Yul TSTOREd - every eth_call reverted against
    // a read-only ABI claim. The mutex IS a state write, so the honest ABI is nonpayable (exactly the
    // solc twin's: a tstore modifier on an undeclared-mutability function).
    const readBody = compile(
      `class C { x: u256; set(v: u256): External<void> { this.x = v; } @nonReentrant @external getX2(): u256 { return this.x; } }`,
      { fileName: 'C.jeth' },
    );
    const mutGet = readBody.abi.find((e) => e.type === 'function' && e.name === 'getX2') as { stateMutability?: string };
    expect(mutGet.stateMutability).toBe('nonpayable');
    const pureBody = compile(`class C { @nonReentrant @external p(): u256 { return 42n; } }`, { fileName: 'C.jeth' });
    const mutP = pureBody.abi.find((e) => e.type === 'function' && e.name === 'p') as { stateMutability?: string };
    expect(mutP.stateMutability).toBe('nonpayable');
  });

  it('the guarded inferred read-only-body method is byte-identical to the solc twin on CALL and STATICCALL', async () => {
    const J = `class C { x: u256; set(v: u256): External<void> { this.x = v; } @nonReentrant @external getX2(): u256 { return this.x; } }`;
    const S = `contract C { uint256 x;
  modifier nr() { assembly { if tload(0) { revert(0, 0) } tstore(0, 1) } _; assembly { tstore(0, 0) } }
  function set(uint256 v) external { x = v; }
  function getX2() external nr returns (uint256) { return x; } }`;
    const PROBER = `contract P {
  function stat(address t) external view returns (bool ok, bytes memory ret) { (ok, ret) = t.staticcall(abi.encodeWithSignature("getX2()")); }
  function reg(address t) external returns (bool ok, bytes memory ret) { (ok, ret) = t.call(abi.encodeWithSignature("getX2()")); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const ap = await h.deploy(compileSolidity(SPDX + PROBER, 'P').creation);
    const addrWord = (a: { toString(): string }) => W(BigInt(a.toString()));
    await h.call(aj, '0x' + sel('set(uint256)') + W(55n));
    await h.call(as, '0x' + sel('set(uint256)') + W(55n));
    for (const probe of ['stat(address)', 'reg(address)']) {
      const rj = await h.call(ap, '0x' + sel(probe) + addrWord(aj));
      const rs = await h.call(ap, '0x' + sel(probe) + addrWord(as));
      expect(rj.returnHex, `${probe} parity`).toBe(rs.returnHex);
    }
    // non-vacuity: the STATICCALL inner-ok flag is 0 on both (the mutex tstore reverts in a static
    // context), and the REGULAR call returns 55 on both.
    const stat = await h.call(ap, '0x' + sel('stat(address)') + addrWord(aj));
    expect(BigInt(stat.returnHex.slice(0, 66))).toBe(0n);
    const reg = await h.call(ap, '0x' + sel('reg(address)') + addrWord(aj));
    expect(BigInt(reg.returnHex.slice(0, 66))).toBe(1n);
    expect(reg.returnHex).toContain(W(55n));
  });

  it('the F4 adversarial shape (@nonReentrant empty-void body) stays accepted with a nonpayable ABI', () => {
    const out = compile(`class C { @nonReentrant emptyBody(): External<void> {} }`, { fileName: 'C.jeth' });
    const mut = out.abi.find((e) => e.type === 'function' && e.name === 'emptyBody') as { stateMutability?: string };
    expect(mut.stateMutability).toBe('nonpayable');
  });

  it('@nonReentrant on a WRITING method stays accepted, byte-identical vs the solc transient-mutex mirror', async () => {
    const J = `class C { x: u256; @nonReentrant set(v: u256): External<void> { this.x = v; } get getX(): External<u256> { return this.x; } }`;
    const S = `contract C { uint256 x;
  modifier nonReentrant() { assembly { if tload(0) { revert(0, 0) } tstore(0, 1) } _; assembly { tstore(0, 0) } }
  function set(uint256 v) external nonReentrant { x = v; }
  function getX() external view returns (uint256) { return x; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const setJ = await h.call(aj, '0x' + sel('set(uint256)') + W(1234n));
    const setS = await h.call(as, '0x' + sel('set(uint256)') + W(1234n));
    expect(setJ.success).toBe(setS.success);
    expect(setJ.success).toBe(true);
    const gj = await h.call(aj, '0x' + sel('getX()'));
    const gs = await h.call(as, '0x' + sel('getX()'));
    expect(gj.returnHex).toBe(gs.returnHex);
    expect(BigInt(gj.returnHex)).toBe(1234n);
  });

  it('the legacy explicit-decorator gate (JETH260) is unregressed for @view and @read', () => {
    expect(
      codes(`// use @decorators
@contract class C { @state x: u256; @nonReentrant @external @view getX(): u256 { return this.x; } }`),
    ).toContain('JETH260');
    expect(
      codes(`// use @decorators
@contract class C { @state x: u256; @nonReentrant @external @read getX(): u256 { return this.x; } }`),
    ).toContain('JETH260');
  });

  it('a plain `get` accessor (no @nonReentrant) is unregressed byte-identical', async () => {
    const J = `class C { x: u256; set(v: u256): External<void> { this.x = v; } get getX(): External<u256> { return this.x; } }`;
    const S = `contract C { uint256 x; function set(uint256 v) external { x = v; } function getX() external view returns (uint256) { return x; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, '0x' + sel('set(uint256)') + W(99n));
    await h.call(as, '0x' + sel('set(uint256)') + W(99n));
    const gj = await h.call(aj, '0x' + sel('getX()'));
    const gs = await h.call(as, '0x' + sel('getX()'));
    expect(gj.returnHex).toBe(gs.returnHex);
    expect(BigInt(gj.returnHex)).toBe(99n);
  });

  it('@nonReentrant + @payable writer stays accepted (control)', () => {
    expect(codes(`class C { x: u256; @nonReentrant dep(): Payable<void> { this.x = this.x + msg.value; } }`)).toEqual([]);
  });
});
