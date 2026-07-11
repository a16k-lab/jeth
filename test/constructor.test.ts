// Phase 5 - CONSTRUCTORS (open JETH042/the old gate). A TS `constructor(params){body}` inside an
// @contract class runs ONCE in creation code: it may write @state, read msg.sender / msg.value
// (@payable) / address(this), and take value-type params ABI-encoded + appended to the init code
// (decoded FROM MEMORY via datasize/codesize/codecopy). A non-payable ctor rejects deploy-time value.
// Every supported case is verified byte-identical to solc 0.8.35 on RAW STORAGE SLOTS + revert
// parity. Aggregate/dynamic params (JETH302) and ctor->internal-calls (JETH303) are now SUPPORTED
// (lifted to solc parity); see test/ctor-parity.test.ts for their byte-identity coverage.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const caller = new Address(Buffer.from('1234123412341234123412341234123412341234', 'hex'));
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};

async function deployJ(src: string, argsHex = '', value = 0n) {
  const h = await Harness.create();
  await h.fund(caller, 10n ** 20n);
  const a = await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode + argsHex, { caller, value });
  return { h, a };
}
async function deployS(src: string, argsHex = '', value = 0n) {
  const h = await Harness.create();
  await h.fund(caller, 10n ** 20n);
  const a = await h.deploy(compileSolidity(src, 'C').creation + argsHex, { caller, value });
  return { h, a };
}
async function slots(h: Harness, a: Address, n: number) {
  const r: string[] = [];
  for (let i = 0; i < n; i++) r.push(await readSlot(h, a, BigInt(i)));
  return r;
}
/** deploy J and S with the same appended args + value; assert raw storage slots 0..n are identical. */
async function sameSlots(J: string, S: string, argsHex = '', value = 0n, n = 3) {
  const j = await deployJ(J, argsHex, value);
  const s = await deployS(SPDX + S, argsHex, value);
  expect(await slots(j.h, j.a, n)).toEqual(await slots(s.h, s.a, n));
}
async function bothRevert(J: string, S: string, argsHex = '', value = 0n) {
  let jr = false,
    sr = false;
  try {
    await deployJ(J, argsHex, value);
  } catch {
    jr = true;
  }
  try {
    await deployS(SPDX + S, argsHex, value);
  } catch {
    sr = true;
  }
  expect({ jeth: jr, solc: sr }).toEqual({ jeth: true, solc: true });
}

describe('Phase 5 constructors vs solc 0.8.35', () => {
  it('value-arg write + constant field init (raw slots identical)', () =>
    sameSlots(
      `class C { x: u256; y: u256 = 42n; constructor(seed: u256) { this.x = seed; } }`,
      `contract C { uint256 x; uint256 y = 42; constructor(uint256 seed){ x = seed; } }`,
      pad32(7n),
    ));

  it('packed u128/u128 args land in one slot, byte-identical', () =>
    sameSlots(
      `class C { a: u128; b: u128; constructor(_a: u128, _b: u128) { this.a = _a; this.b = _b; } }`,
      `contract C { uint128 a; uint128 b; constructor(uint128 _a, uint128 _b){ a=_a; b=_b; } }`,
      pad32(0x11n) + pad32(0x22n),
    ));

  it('@payable constructor stores msg.value', () =>
    sameSlots(
      `class C { v: u256; @payable constructor() { this.v = msg.value; } }`,
      `contract C { uint256 v; constructor() payable { v = msg.value; } }`,
      '',
      1234n,
      1,
    ));

  it('non-payable constructor reverts when deployed with value (both)', () =>
    bothRevert(
      `class C { x: u256; constructor() { this.x = 1n; } }`,
      `contract C { uint256 x; constructor(){ x=1; } }`,
      '',
      5n,
    ));

  it('reads msg.sender and address(this)', () =>
    sameSlots(
      `class C { owner: address; self: address; constructor() { this.owner = msg.sender; this.self = address(this); } }`,
      `contract C { address owner; address self; constructor(){ owner = msg.sender; self = address(this); } }`,
    ));

  it('constant init runs BEFORE the body (x=7 then x=x+1 -> 8)', () =>
    sameSlots(
      `class C { x: u256 = 7n; constructor() { this.x = this.x + 1n; } }`,
      `contract C { uint256 x = 7; constructor(){ x = x + 1; } }`,
      '',
      0n,
      1,
    ));

  it('chained: b = a + 1 reads the just-written sibling', () =>
    sameSlots(
      `class C { a: u256; b: u256; constructor(x: u256) { this.a = x; this.b = this.a + 1n; } }`,
      `contract C { uint256 a; uint256 b; constructor(uint256 x){ a = x; b = a + 1; } }`,
      pad32(41n),
    ));

  it('free-memory pointer survives a body allocation (mapping write keccak scratch)', async () => {
    const J = `class C { bal: mapping<address,u256>; get get(a: address): External<u256> { return this.bal[a]; } constructor(amt: u256) { this.bal[msg.sender] = amt; } }`;
    const S = `contract C { mapping(address=>uint256) bal; function get(address a) external view returns(uint256){return bal[a];} constructor(uint256 amt){ bal[msg.sender]=amt; } }`;
    const j = await deployJ(J, pad32(999n));
    const s = await deployS(SPDX + S, pad32(999n));
    const data = '0x' + functionSelector('get(address)') + pad32(BigInt(caller.toString()));
    const rj = await j.h.call(j.a, data),
      rs = await s.h.call(s.a, data);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(BigInt(rj.returnHex)).toBe(999n);
  });

  describe('argument ABI-decode parity (decoded from memory)', () => {
    it('short / missing args revert (both)', () =>
      bothRevert(
        `class C { x: u256; constructor(a: u256) { this.x = a; } }`,
        `contract C { uint256 x; constructor(uint256 a){ x=a; } }`,
        '',
      ));
    it('trailing garbage after the args is ignored (both deploy, same slots)', () =>
      sameSlots(
        `class C { x: u256; constructor(a: u256) { this.x = a; } }`,
        `contract C { uint256 x; constructor(uint256 a){ x=a; } }`,
        pad32(111n) + pad32(0xdeadn),
        0n,
        1,
      ));
    it('dirty bool arg reverts (both)', () =>
      bothRevert(
        `class C { f: bool; constructor(b: bool) { this.f = b; } }`,
        `contract C { bool f; constructor(bool b){ f=b; } }`,
        pad32(5n),
      ));
    it('dirty address arg (high bits) reverts (both)', () =>
      bothRevert(
        `class C { o: address; constructor(a: address) { this.o = a; } }`,
        `contract C { address o; constructor(address a){ o=a; } }`,
        'ff'.repeat(12) + '00'.repeat(20),
      ));
    it('intN sign-extends: i64 = -1 stored full-word', () =>
      sameSlots(
        `class C { i: i64; constructor(v: i64) { this.i = v; } }`,
        `contract C { int64 i; constructor(int64 v){ i=v; } }`,
        'f'.repeat(64),
        0n,
        1,
      ));
    it('dirty intN arg (high bits beyond sign) reverts (both)', () =>
      bothRevert(
        `class C { i: i64; constructor(v: i64) { this.i = v; } }`,
        `contract C { int64 i; constructor(int64 v){ i=v; } }`,
        pad32(1n << 64n),
      ));
  });

  describe('clean gates (each a clean diagnostic; no crash)', () => {
    it('a second constructor -> JETH300', () =>
      expect(
        codes(`class C { x: u256; constructor(){this.x=1n;} constructor(a: u256){this.x=a;} }`),
      ).toContain('JETH300'));
    it('a return type on the constructor -> JETH301', () =>
      expect(codes(`class C { x: u256; constructor(): u256 { this.x=1n; } }`)).toContain('JETH301'));
    it('a @view constructor -> JETH301', () =>
      expect(codes(`class C { x: u256; @view constructor(){this.x=1n;} }`)).toContain('JETH301'));
    it('an aggregate (fixed-array) constructor param is now accepted (JETH302 lifted)', () =>
      expect(codes(`class C { x: u256; constructor(a: Arr<u256,3>){this.x=a[0n];} }`)).toEqual([]));
    it('calling an internal function from the constructor is now accepted (JETH303 lifted)', () =>
      expect(
        codes(`class C { x: u256; h(): u256 { return 5n; } constructor(){ this.x = this.h(); } }`),
      ).toEqual([]));
    it('msg.value in a non-payable constructor -> JETH162', () =>
      expect(codes(`class C { x: u256; constructor(){ this.x = msg.value; } }`)).toContain('JETH162'));
    it('a default value on a constructor param -> JETH304', () =>
      expect(codes(`class C { x: u256; constructor(a: u256 = 5n){ this.x = a; } }`)).toContain(
        'JETH304',
      ));
  });

  it('emits a Solidity-compatible constructor ABI entry', () => {
    const r = compile(
      `class C { x: u256; @payable constructor(seed: u256, who: address) { this.x = seed; } }`,
      { fileName: 'C.jeth' },
    );
    const ctor = r.abi.find((a) => a.type === 'constructor');
    expect(ctor).toMatchObject({
      type: 'constructor',
      stateMutability: 'payable',
      inputs: [
        { name: 'seed', type: 'uint256' },
        { name: 'who', type: 'address' },
      ],
    });
  });

  it('a no-constructor contract is unaffected (still deploys + reads state)', async () => {
    const h = await Harness.create();
    const a = await h.deploy(
      compile(`class C { x: u256 = 5n; get gx(): External<u256> { return this.x; } }`, {
        fileName: 'C.jeth',
      }).creationBytecode,
    );
    expect(BigInt(await readSlot(h, a, 0n))).toBe(5n);
  });

  // msg.value/callvalue payability (JETH162) is per-CONSTRUCTOR: a read must be checked against the
  // payability of the constructor whose body contains it, not the concrete/most-derived constructor.
  // Previously JETH keyed it off the merged concrete ctor, giving both an over-acceptance (msg.value in
  // a non-payable base allowed when the derived ctor is @payable) and the mirror over-rejection.
  describe('constructor msg.value payability is per-constructor (JETH162) vs solc 0.8.35', () => {
    it('over-acceptance closed: msg.value in a NON-payable base ctor rejects even when the derived ctor is @payable', () => {
      expect(
        codes('abstract class A { v: u256; constructor(){ this.v = msg.value; } } class C extends A { @payable constructor(){ } }'),
      ).toContain('JETH162');
      // 3 levels deep: a non-payable MIDDLE base reading msg.value, concrete ctor @payable
      expect(
        codes('abstract class A { v: u256; } abstract class B extends A { constructor(){ this.v = msg.value; } } class C extends B { @payable constructor(){ } }'),
      ).toContain('JETH162');
    });

    it('mirror over-rejection closed: msg.value in a @payable base ctor + a NON-payable derived ctor compiles and is byte-identical', async () => {
      // The @payable BASE reading msg.value now COMPILES (previously JETH162 over-rejected it). The
      // CONCRETE contract C is non-payable, so it cannot be deployed WITH value (the non-payable creation
      // guard reverts, matching solc); deployed value-less, the base ctor reads msg.value == 0 -> v == 0
      // on both, byte-identical.
      const J = 'abstract class A { v: u256; @payable constructor(){ this.v = msg.value; } } class C extends A { constructor(){ } }';
      const S = 'abstract contract A { uint256 v; constructor() payable { v=msg.value; } } contract C is A { constructor() {} }';
      expect(codes(J)).toEqual([]); // JETH accepts (over-rejection closed); solc also accepts
      await sameSlots(J, S, '', 0n, 1);
    });

    it('control: msg.sender in a non-payable base ctor + payable derived is accepted (not payability-gated) and byte-identical', () =>
      sameSlots(
        'abstract class A { o: address; constructor(){ this.o = msg.sender; } } class C extends A { @payable constructor(){ } }',
        'abstract contract A { address o; constructor(){ o=msg.sender; } } contract C is A { constructor() payable {} }',
        '',
        0n,
        1,
      ));

    it('control: msg.value in a non-payable base ctor + non-payable / absent derived ctor still rejects', () => {
      expect(
        codes('abstract class A { v: u256; constructor(){ this.v = msg.value; } } class C extends A { constructor(){ } }'),
      ).toContain('JETH162');
      expect(
        codes('abstract class A { v: u256; constructor(){ this.v = msg.value; } } class C extends A { }'),
      ).toContain('JETH162');
    });
  });

  // W2D: a base constructor BODY sees only its OWN ctor parameters, never an enclosing (more-derived)
  // constructor's - solc "Undeclared identifier". Previously JETH kept the whole recursion's bind scopes
  // live for every level (a scope leak / over-acceptance): a base ctor body could read a derived-only
  // ctor param and deploy. Also: heritage arguments given to a base that has NO constructor (or a
  // 0-param one) are "Wrong argument count" in solc; JETH previously dropped them silently. Both gated.
  describe('W2D ctor scope-leak + ctorless-base heritage args', () => {
    const solcRejects = (src: string): boolean => {
      try { compileSolidity(SPDX + src, 'C'); return false; } catch { return true; }
    };
    it('P0-22 bare-extends: a base ctor body reading a derived-only ctor param rejects (both)', () => {
      const J = 'abstract class A { x: u256; constructor(){ this.x = p; } } class C extends A { y: u256; constructor(p: u256){ this.y = p; } }';
      const S = 'abstract contract A { uint256 x; constructor(){ x = p; } } contract C is A { uint256 y; constructor(uint256 p){ y = p; } }';
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });
    it('P0-22 heritage-form: a base ctor body reading a derived-only ctor param rejects (both)', () => {
      const J = 'abstract class A { x: u256; constructor(a: u256){ this.x = p; } } class C extends A(1n) { constructor(p: u256){ } }';
      const S = 'abstract contract A { uint256 x; constructor(uint256 a){ x = p; } } contract C is A(1) { constructor(uint256 p){ } }';
      expect(codes(J).length).toBeGreaterThan(0);
      expect(solcRejects(S)).toBe(true);
    });
    it('P0-24 heritage args to a base with NO constructor reject (both, wrong arg count)', () => {
      const J = 'abstract class B { get ping(): External<u256> { return 1n; } } class C extends B(5n) { constructor(){ } }';
      const S = 'abstract contract B { function ping() external view returns (uint256) { return 1; } } contract C is B(5) { constructor(){ } }';
      expect(codes(J)).toContain('JETH379');
      expect(solcRejects(S)).toBe(true);
    });
    it('P0-24 mid-chain ctorless base given heritage args rejects (both, wrong arg count)', () => {
      const J = 'abstract class A { get pa(): External<u256> { return 1n; } } abstract class B extends A(3n) { get pb(): External<u256> { return 2n; } } class C extends B { constructor(){} }';
      const S = 'abstract contract A { function pa() external view returns (uint256) { return 1; } } abstract contract B is A(3) { function pb() external view returns (uint256) { return 2; } } contract C is B { constructor(){} }';
      expect(codes(J)).toContain('JETH379');
      expect(solcRejects(S)).toBe(true);
    });
    it('control: a base ctor reading its OWN param via heritage args still deploys byte-identical', () =>
      sameSlots(
        'abstract class A { x: u256; constructor(a: u256){ this.x = a; } } class C extends A(22n) {}',
        'abstract contract A { uint256 x; constructor(uint256 a){ x = a; } } contract C is A(22) {}',
        '',
        0n,
        1,
      ));
  });
});
