// Phase 5 - IMMUTABLES (@immutable). A value-type field assigned in the constructor and baked into
// the runtime code via setimmutable / read via loadimmutable. It consumes NO storage slot, so other
// @state vars keep solc's exact slot numbers. Constructor reads see the STAGED shadow (value so far);
// runtime reads load the baked value. Matches the solc-js 0.8.35 oracle: no definite-assignment
// checking (never-assigned = 0, last-write-wins, read-before-assign = staged 0). Verified
// byte-identical on raw storage slots + returndata; non-value/inline-init/public/outside-ctor gated.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const caller = new Address(Buffer.from('abababababababababababababababababababab', 'hex'));
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
async function dJ(src: string, args = '') {
  const h = await Harness.create();
  await h.fund(caller, 10n ** 20n);
  return { h, a: await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode + args, { caller }) };
}
async function dS(src: string, args = '') {
  const h = await Harness.create();
  await h.fund(caller, 10n ** 20n);
  return { h, a: await h.deploy(compileSolidity(SPDX + src, 'C').creation + args, { caller }) };
}
/** deploy J + S with the same args; assert one external getter returns byte-identical results. */
async function sameCall(J: string, S: string, sig: string, args = '', arg = '') {
  const j = await dJ(J, args),
    s = await dS(S, args);
  const rj = await j.h.call(j.a, '0x' + functionSelector(sig) + arg);
  const rs = await s.h.call(s.a, '0x' + functionSelector(sig) + arg);
  expect(rj.success).toBe(true);
  expect(rj.returnHex).toBe(rs.returnHex);
  return rj.returnHex;
}
async function sameSlots(J: string, S: string, args = '', n = 3) {
  const j = await dJ(J, args),
    s = await dS(S, args);
  const js: string[] = [],
    ss: string[] = [];
  for (let i = 0; i < n; i++) {
    js.push(await readSlot(j.h, j.a, BigInt(i)));
    ss.push(await readSlot(s.h, s.a, BigInt(i)));
  }
  expect(js).toEqual(ss);
}

describe('Phase 5 immutables (@immutable) vs solc 0.8.35', () => {
  it('consumes NO storage slot: @state/@immutable/@state keeps slots unshifted', () =>
    sameSlots(
      `class C { s0: u256; static a: u256; s1: u256; constructor(){ this.s0 = 11n; this.a = 7n; this.s1 = 22n; } }`,
      `contract C { uint256 s0; uint256 immutable a; uint256 s1; constructor(){ s0=11; a=7; s1=22; } }`,
      '',
      2,
    ));

  it('does not break packing or finish a slot (u8 / immutable u128 / u8 pack together)', () =>
    sameSlots(
      `class C { x: u8; static a: u128; y: u8; c: u256; constructor(){ this.x = 1n; this.a = 5n; this.y = 2n; this.c = 9n; } }`,
      `contract C { uint8 x; uint128 immutable a; uint8 y; uint256 c; constructor(){ x=1; a=5; y=2; c=9; } }`,
      '',
      2,
    ));

  it('bakes a constructor-arg immutable, read at runtime (-> 42)', async () => {
    expect(
      BigInt(
        await sameCall(
          `class C { static a: u256; get getA(): External<u256> { return this.a; } constructor(x: u256){ this.a = x; } }`,
          `contract C { uint256 immutable a; function getA() external view returns(uint256){return a;} constructor(uint256 x){ a=x; } }`,
          'getA()',
          pad32(42n),
        ),
      ),
    ).toBe(42n);
  });

  it('read-before-assign reads the staged 0 (constructor), not loadimmutable', async () => {
    expect(
      BigInt(
        await sameCall(
          `class C { s0: u256; static a: u256; get g0(): External<u256> { return this.s0; } constructor(){ this.s0 = this.a; this.a = 42n; } }`,
          `contract C { uint256 s0; uint256 immutable a; function g0() external view returns(uint256){return s0;} constructor(){ s0 = a; a = 42; } }`,
          'g0()',
        ),
      ),
    ).toBe(0n);
  });

  it('last-write-wins incl. compound assign (1, +=4, +100 -> 105)', async () => {
    expect(
      BigInt(
        await sameCall(
          `class C { static a: u256; get getA(): External<u256> { return this.a; } constructor(){ this.a = 1n; this.a += 4n; this.a = this.a + 100n; } }`,
          `contract C { uint256 immutable a; function getA() external view returns(uint256){return a;} constructor(){ a=1; a+=4; a=a+100; } }`,
          'getA()',
        ),
      ),
    ).toBe(105n);
  });

  it('never-assigned immutable reads as 0 (no definite-assignment, like solc-js)', async () => {
    expect(
      BigInt(
        await sameCall(
          `class C { static a: u256; get getA(): External<u256> { return this.a; } constructor(){} }`,
          `contract C { uint256 immutable a; function getA() external view returns(uint256){return a;} constructor(){} }`,
          'getA()',
        ),
      ),
    ).toBe(0n);
  });

  it('a contract with an immutable and NO constructor reads 0', async () => {
    expect(
      BigInt(
        await sameCall(
          `class C { static a: u256; get getA(): External<u256> { return this.a; } }`,
          `contract C { uint256 immutable a; function getA() external view returns(uint256){return a;} }`,
          'getA()',
        ),
      ),
    ).toBe(0n);
  });

  it('two packed-width immutables from args; surrounding @state slot intact', async () => {
    expect(
      BigInt(
        await sameCall(
          `class C { s: u256; static a: u64; static b: u64; get getB(): External<u64> { return this.b; } constructor(_a: u64, _b: u64){ this.s = 99n; this.a = _a; this.b = _b; } }`,
          `contract C { uint256 s; uint64 immutable a; uint64 immutable b; function getB() external view returns(uint64){return b;} constructor(uint64 _a,uint64 _b){ s=99; a=_a; b=_b; } }`,
          'getB()',
          pad32(7n) + pad32(9n),
        ),
      ),
    ).toBe(9n);
    await sameSlots(
      `class C { s: u256; static a: u64; static b: u64; constructor(_a: u64, _b: u64){ this.s = 99n; this.a = _a; this.b = _b; } }`,
      `contract C { uint256 s; uint64 immutable a; uint64 immutable b; constructor(uint64 _a,uint64 _b){ s=99; a=_a; b=_b; } }`,
      pad32(7n) + pad32(9n),
      1,
    );
  });

  it('chained immutable: b reads the just-staged a (a=x; b=a+1)', async () => {
    expect(
      BigInt(
        await sameCall(
          `class C { static a: u256; static b: u256; get getB(): External<u256> { return this.b; } constructor(x: u256){ this.a = x; this.b = this.a + 1n; } }`,
          `contract C { uint256 immutable a; uint256 immutable b; function getB() external view returns(uint256){return b;} constructor(uint256 x){ a=x; b=a+1; } }`,
          'getB()',
          pad32(41n),
        ),
      ),
    ).toBe(42n);
  });

  it('owner = msg.sender immutable round-trips', () =>
    sameCall(
      `class C { static owner: address; get o(): External<address> { return this.owner; } constructor(){ this.owner = msg.sender; } }`,
      `contract C { address immutable owner; function o() external view returns(address){return owner;} constructor(){ owner = msg.sender; } }`,
      'o()',
    ));

  describe('value-type bakes (sign-extension / left-alignment / brand)', () => {
    it('int64 = -5 sign-extends to a full word', () =>
      sameCall(
        `class C { static a: i64; get getA(): External<i64> { return this.a; } constructor(){ this.a = -5n; } }`,
        `contract C { int64 immutable a; function getA() external view returns(int64){return a;} constructor(){ a = -5; } }`,
        'getA()',
      ));
    it('bool = true', () =>
      sameCall(
        `class C { static f: bool; get getF(): External<bool> { return this.f; } constructor(){ this.f = true; } }`,
        `contract C { bool immutable f; function getF() external view returns(bool){return f;} constructor(){ f = true; } }`,
        'getF()',
      ));
    it('bytes32 from a constructor arg', () =>
      sameCall(
        `class C { static h: bytes32; get getH(): External<bytes32> { return this.h; } constructor(x: bytes32){ this.h = x; } }`,
        `contract C { bytes32 immutable h; function getH() external view returns(bytes32){return h;} constructor(bytes32 x){ h = x; } }`,
        'getH()',
        'ab'.repeat(32),
      ));
  });

  describe('mutability classification (immutable read needs @view, not @pure)', () => {
    it('@view reading an immutable is accepted (deploys + reads)', () =>
      sameCall(
        `class C { static a: u256; get getA(): External<u256> { return this.a; } constructor(){ this.a = 3n; } }`,
        `contract C { uint256 immutable a; function getA() external view returns(uint256){return a;} constructor(){ a=3; } }`,
        'getA()',
      ));
    it('@pure reading an immutable is rejected (JETH164), matching solc', () =>
      expect(
        codes(
          `@contract class C { @immutable a: u256; @external @pure getA(): u256 { return this.a; } constructor(){ this.a = 1n; } }`,
        ),
      ).toContain('JETH481'));
  });

  describe('clean gates', () => {
    it('a non-value-type immutable (string) -> JETH310 (parity: solc also rejects)', () =>
      expect(codes(`class C { static s: string; constructor(){ this.s = "x"; } }`)).toContain('JETH310'));
    it('an inline-initialized immutable is supported (staged at the start of the constructor)', () =>
      expect(codes(`@contract class C { @immutable a: u256 = 7n; constructor(){} }`)).toEqual([]));
    it('a @external @immutable synthesizes solc public-immutable view getter (accepted)', () =>
      expect(codes(`class C { static a: Visible<u256>; constructor(){ this.a = 1n; } }`)).toEqual([]));
    it('any OTHER visibility/mutability on an immutable still -> JETH312', () =>
      expect(codes(`class C { @view static a: u256; constructor(){ this.a = 1n; } }`)).toContain('JETH312'));
    it('assigning an immutable outside the constructor -> JETH313', () =>
      expect(
        codes(`class C { static a: u256; setit(): External<void> { this.a = 1n; } constructor(){} }`),
      ).toContain('JETH313'));
    it('@state and @immutable on the same field -> JETH052', () =>
      expect(codes(`@contract class C { @state @immutable a: u256; constructor(){ this.a = 1n; } }`)).toContain(
        'JETH052',
      ));
  });

  it('immutables contribute NO ABI getter (only a constructor entry / the explicit view fn)', () => {
    const r = compile(
      `class C { static a: u256; get getA(): External<u256> { return this.a; } constructor(x: u256){ this.a = x; } }`,
      { fileName: 'C.jeth' },
    );
    const names = r.abi.filter((x) => 'name' in x).map((x) => (x as { name: string }).name);
    expect(names).toEqual(['getA']); // no auto getter named 'a'
    expect(r.abi.some((x) => x.type === 'constructor')).toBe(true);
  });
});
