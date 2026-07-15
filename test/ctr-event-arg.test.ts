// CTR-EVENT-ARG (JETH013/085 lift): a contract/abstract-contract/interface VALUE passed directly as an
// EVENT or ERROR argument. Two gaps were closed vs the base:
//   (1) a contract/interface-typed member of a FILE-LEVEL `type Ev = event<{ t: T }>` alias now brands to
//       `address` (CONTRACT-TYPE-PARAM) exactly like the inline `E: event<{ t: T }>` field form. The
//       member types are resolved in a deferred pass (buildFileLevelErrorEvents) AFTER every contract /
//       interface name is registered, so contractRefNames() is complete when the member resolves.
//   (2) the emit/revert argument now accepts a BARE value already of the parameter's contract-ref type
//       (checkRaiseArg), not only the explicit wrapper cast `T(<address>)`. `emit Ev(t)` where `t` is a
//       T-typed param / field / local / array-elem / mapping-elem passes directly, like solc.
// Byte-identity is proven by deploy-both vs solc 0.8.35: topic0 (= keccak of the "address"-lowered
// signature), indexed topics, non-indexed log data, and error revert data all match. Sound rejects
// (a plain address, a non-contract value, a different contract type, a getter that emits) are preserved.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness, pad32 as pad } from '../src/evm.js';
import { functionSelector as sel, eventTopic0 } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const A = 0x00000000000000000000000000000000000000aan;
const B = 0x00000000000000000000000000000000000000bbn;

function jethRejects(src: string): string[] | null {
  try {
    compile(src, { fileName: 'C.jeth' });
    return null;
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}

/** Deploy J (JETH) and S (solc `contract C`) and assert each call's success + returndata + logs match. */
async function bothMatch(J: string, S: string, calls: [string, string][]): Promise<void> {
  const jb = compile(J, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + S, 'C');
  const jh = await Harness.create();
  const sh = await Harness.create();
  const aj = await jh.deploy(jb.creationBytecode);
  const as = await sh.deploy(sb.creation);
  for (const [sig, args] of calls) {
    const data = '0x' + sel(sig) + (args || '');
    const j = await jh.call(aj, data);
    const s = await sh.call(as, data);
    expect(j.success).toBe(s.success);
    expect(j.returnHex).toBe(s.returnHex);
    expect(j.logs).toEqual(s.logs);
  }
}

describe('CTR-EVENT-ARG: a contract/interface VALUE as an event/error argument (file-level form)', () => {
  it('non-indexed abstract-contract param: log data + topic0 "Ev(address)" match solc', async () => {
    const J = `abstract class T { @virtual v(): View<u256>; }
      type Ev = event<{ t: T }>;
      class C { f(t: T): External<void> { emit(Ev(t)); } }`;
    const S = `abstract contract T { function v() external view virtual returns (uint256); }
event Ev(T t);
contract C { function f(T t) external { emit Ev(t); } }`;
    const jb = compile(J, { fileName: 'C.jeth' });
    const ev = jb.abi.find((x: any) => x.type === 'event') as any;
    expect(ev.inputs.map((i: any) => i.type)).toEqual(['address']); // contract type lowers to address
    const jh = await Harness.create();
    const aj = await jh.deploy(jb.creationBytecode);
    const r = await jh.call(aj, '0x' + sel('f(address)') + pad(A));
    expect(r.logs[0]!.topics[0]).toBe('0x' + eventTopic0('Ev(address)'));
    await bothMatch(J, S, [['f(address)', pad(A)]]);
  });

  it('indexed interface param: the address topic matches solc', async () => {
    await bothMatch(
      `interface I { v(): View<u256>; }
       type Ev = event<{ t: indexed<I> }>;
       class C { f(t: I): External<void> { emit(Ev(t)); } }`,
      `interface I { function v() external view returns (uint256); }
event Ev(I indexed t);
contract C { function f(I t) external { emit Ev(t); } }`,
      [['f(address)', pad(A)]],
    );
  });

  it('mixed { u256, T, indexed T } event: data + topic match solc', async () => {
    await bothMatch(
      `interface I { v(): View<u256>; }
       type Ev = event<{ a: u256; t: I; k: indexed<I> }>;
       class C { f(a: u256, t: I, k: I): External<void> { emit(Ev(a, t, k)); } }`,
      `interface I { function v() external view returns (uint256); }
event Ev(uint256 a, I t, I indexed k);
contract C { function f(uint256 a, I t, I k) external { emit Ev(a, t, k); } }`,
      [['f(uint256,address,address)', pad(7n) + pad(A) + pad(B)]],
    );
  });

  it('error with a contract param: revert selector + data match solc (keccak "Bad(address)")', async () => {
    await bothMatch(
      `interface I { v(): View<u256>; }
       type Bad = error<{ t: I }>;
       class C { f(t: I): External<void> { revert(Bad(t)); } }`,
      `interface I { function v() external view returns (uint256); }
error Bad(I t);
contract C { function f(I t) external { revert Bad(t); } }`,
      [['f(address)', pad(A)]],
    );
  });

  it('the contract value is sourced from a field / local / array-elem / mapping-elem', async () => {
    // field
    await bothMatch(
      `interface I { v(): View<u256>; }
       type Ev = event<{ t: I }>;
       class C { s: I; setS(a: address): External<void> { this.s = I(a); } fire(): External<void> { emit(Ev(this.s)); } }`,
      `interface I { function v() external view returns (uint256); }
event Ev(I t);
contract C { I s; function setS(address a) external { s = I(a); } function fire() external { emit Ev(s); } }`,
      [['setS(address)', pad(A)], ['fire()', '']],
    );
    // local
    await bothMatch(
      `interface I { v(): View<u256>; }
       type Ev = event<{ t: I }>;
       class C { f(a: address): External<void> { let t: I = I(a); emit(Ev(t)); } }`,
      `interface I { function v() external view returns (uint256); }
event Ev(I t);
contract C { function f(address a) external { I t = I(a); emit Ev(t); } }`,
      [['f(address)', pad(A)]],
    );
    // array element
    await bothMatch(
      `interface I { v(): View<u256>; }
       type Ev = event<{ t: I }>;
       class C { arr: I[]; push(a: address): External<void> { this.arr.push(I(a)); } fire(): External<void> { emit(Ev(this.arr[0n])); } }`,
      `interface I { function v() external view returns (uint256); }
event Ev(I t);
contract C { I[] arr; function push(address a) external { arr.push(I(a)); } function fire() external { emit Ev(arr[0]); } }`,
      [['push(address)', pad(A)], ['fire()', '']],
    );
    // mapping element
    await bothMatch(
      `interface I { v(): View<u256>; }
       type Ev = event<{ t: I }>;
       class C { m: mapping<u256, I>; set(a: address): External<void> { this.m[0n] = I(a); } fire(): External<void> { emit(Ev(this.m[0n])); } }`,
      `interface I { function v() external view returns (uint256); }
event Ev(I t);
contract C { mapping(uint256 => I) m; function set(address a) external { m[0] = I(a); } function fire() external { emit Ev(m[0]); } }`,
      [['set(address)', pad(A)], ['fire()', '']],
    );
  });

  it('a struct with a contract-typed field as an event param matches solc', async () => {
    await bothMatch(
      `interface I { v(): View<u256>; }
       type P = { a: u256; t: I; };
       type Ev = event<{ p: P }>;
       class C { f(a: u256, t: I): External<void> { emit(Ev(P(a, t))); } }`,
      `interface I { function v() external view returns (uint256); }
struct P { uint256 a; I t; }
event Ev(P p);
contract C { function f(uint256 a, I t) external { emit Ev(P(a, t)); } }`,
      [['f(uint256,address)', pad(9n) + pad(A)]],
    );
  });

  it('the file-level contract-type event lowers to the SAME bytecode as a plain-address event', () => {
    const jCtref = compile(
      `interface I { }
       type Ev = event<{ x: u256; d: I; y: bool }>;
       class C { f(a: address): External<void> { emit(Ev(7n, I(a), true)); } }`,
      { fileName: 'C.jeth' },
    ).creationBytecode;
    const jAddr = compile(
      `type Ev = event<{ x: u256; d: address; y: bool }>;
       class C { f(a: address): External<void> { emit(Ev(7n, address(a), true)); } }`,
      { fileName: 'C.jeth' },
    ).creationBytecode;
    expect(jCtref).toBe(jAddr);
  });

  it('SOUND rejections (no over-acceptance) - solc rejects each too', () => {
    // a plain address (no wrapper) - solc rejects the implicit address->contract conversion.
    expect(jethRejects(`interface I { }
      type Ev = event<{ t: I }>;
      class C { f(a: address): External<void> { emit(Ev(a)); } }`)).not.toBe(null);
    // a non-contract value in a contract-typed member slot.
    expect(jethRejects(`interface I { }
      type Ev = event<{ t: I }>;
      class C { f(a: u256): External<void> { emit(Ev(a)); } }`)).not.toBe(null);
    // a DIFFERENT contract type value - solc rejects (no implicit contract->contract conversion).
    expect(jethRejects(`interface I { }
      interface J { }
      type Ev = event<{ t: I }>;
      class C { f(t: J): External<void> { emit(Ev(t)); } }`)).not.toBe(null);
    // a getter that emits - a `get` accessor is read-only (JETH043), independent of the contract arg.
    expect(jethRejects(`abstract class T { @virtual v(): View<u256>; }
      type Ev = event<{ t: T }>;
      class C { get f(t: T): External<void> { emit(Ev(t)); } }`)).toContain('JETH043');
  });
});
