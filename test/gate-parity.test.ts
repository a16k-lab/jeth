// Gate parity (the last two SAFE over-rejections lifted, byte-identical to solc 0.8.35):
//  - JETH312: an `@external @immutable` field now synthesizes solc's `public immutable` auto-getter
//    (`name() view returns (T)`, reading the immutable via loadimmutable - NO storage slot). The
//    getter's selector = keccak(name+"()")[:4] and its returndata = the immutable value, identical to
//    solc. Other visibility/mutability decorators on an immutable stay gated JETH312.
//  - JETH321: a `@modifier` with the single `_` placeholder nested in a conditional (the 0-or-N-times
//    shape, e.g. `if (c) { _; }`) is now supported. The wrapped body is lowered as a synthesized
//    userfn called by a {modifierBody} marker placed INSIDE the conditional, so the body runs 0-or-N
//    times; a 0-times path leaves the buffered `ret` at its zero-init = solc's zero value.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const caller = new Address(Buffer.from('cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd', 'hex'));
const sel = (s: string) => functionSelector(s);
const boolWord = (b: boolean) => pad32(b ? 1n : 0n);

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

describe('JETH312 - @external @immutable view getter (byte-identical to solc public immutable)', () => {
  it('a u256 immutable getter: selector dispatches + returndata == the immutable value == solc', async () => {
    const J = `class C { static x: Visible<u256>; constructor(v: u256){ this.x = v; } }`;
    const S = `contract C { uint256 public immutable x; constructor(uint256 v){ x = v; } }`;
    const args = pad32(0xdeadbeefn);
    const j = await dJ(J, args),
      s = await dS(S, args);
    const rj = await j.h.call(j.a, '0x' + sel('x()'));
    const rs = await s.h.call(s.a, '0x' + sel('x()'));
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex); // returndata = the immutable value
    expect(rj.returnHex).toBe('0x' + pad32(0xdeadbeefn)); // and it IS the value set in the ctor
  });

  it('a bytes32 immutable getter is byte-identical to solc', async () => {
    const J = `class C { static h: Visible<bytes32>; constructor(v: bytes32){ this.h = v; } }`;
    const S = `contract C { bytes32 public immutable h; constructor(bytes32 v){ h = v; } }`;
    const args = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
    const j = await dJ(J, args),
      s = await dS(S, args);
    const rj = await j.h.call(j.a, '0x' + sel('h()'));
    const rs = await s.h.call(s.a, '0x' + sel('h()'));
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(rj.returnHex).toBe('0x' + args);
  });

  it('an address immutable getter is byte-identical to solc', async () => {
    const J = `class C { static owner: Visible<address>; constructor(){ this.owner = msg.sender; } }`;
    const S = `contract C { address public immutable owner; constructor(){ owner = msg.sender; } }`;
    const j = await dJ(J),
      s = await dS(S);
    const rj = await j.h.call(j.a, '0x' + sel('owner()'));
    const rs = await s.h.call(s.a, '0x' + sel('owner()'));
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(rj.returnHex).toBe('0x' + pad32(BigInt('0x' + caller.toString().slice(2))));
  });

  it('the immutable consumes NO storage slot (slot 0 stays zero, like solc)', async () => {
    const J = `class C { static x: Visible<u256>; constructor(v: u256){ this.x = v; } }`;
    const S = `contract C { uint256 public immutable x; constructor(uint256 v){ x = v; } }`;
    const args = pad32(7n);
    const j = await dJ(J, args),
      s = await dS(S, args);
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
  });
});

describe('JETH321 - @modifier with a conditional _ placeholder (0-or-N-times) vs solc 0.8.35', () => {
  // maybe(c) { if (c) { _; } } on a VALUE-returning f(): c=true runs the body (returns 42), c=false
  // skips it (returns the zero value 0), byte-identical to solc; the @state write also happens iff c.
  const Jf = `class C { n: u256; @modifier maybe(c: bool) { if (c) { _; } } @maybe(c) f(c: bool): External<u256> { this.n = 99n; return 42n; } }`;
  const Sf = `contract C { uint256 n; modifier maybe(bool c){ if (c) { _; } } function f(bool c) external maybe(c) returns (uint256) { n = 99; return 42; } }`;

  it('value return, c=true: body runs (42 returned, slot written) byte-identical to solc', async () => {
    const j = await dJ(Jf),
      s = await dS(Sf);
    const rj = await j.h.call(j.a, '0x' + sel('f(bool)') + boolWord(true));
    const rs = await s.h.call(s.a, '0x' + sel('f(bool)') + boolWord(true));
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(rj.returnHex).toBe('0x' + pad32(42n));
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n)); // n = 99
    expect(await readSlot(j.h, j.a, 0n)).toBe('0x' + pad32(99n));
  });

  it('value return, c=false: body SKIPPED -> zero value (0) returned + no slot write, == solc', async () => {
    const j = await dJ(Jf),
      s = await dS(Sf);
    const rj = await j.h.call(j.a, '0x' + sel('f(bool)') + boolWord(false));
    const rs = await s.h.call(s.a, '0x' + sel('f(bool)') + boolWord(false));
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(rj.returnHex).toBe('0x' + pad32(0n)); // the function's zero value
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n)); // n untouched = 0
    expect(await readSlot(j.h, j.a, 0n)).toBe('0x' + pad32(0n));
  });

  // maybe(c) on a VOID g(): c=true writes the slot, c=false leaves it; both empty-return, == solc.
  const Jg = `class C { n: u256; @modifier maybe(c: bool) { if (c) { _; } } @maybe(c) g(c: bool): External<void> { this.n = 7n; } }`;
  const Sg = `contract C { uint256 n; modifier maybe(bool c){ if (c) { _; } } function g(bool c) external maybe(c) { n = 7; } }`;

  it('void return, c=true: body runs (slot written, empty return) == solc', async () => {
    const j = await dJ(Jg),
      s = await dS(Sg);
    const rj = await j.h.call(j.a, '0x' + sel('g(bool)') + boolWord(true));
    const rs = await s.h.call(s.a, '0x' + sel('g(bool)') + boolWord(true));
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    expect(await readSlot(j.h, j.a, 0n)).toBe('0x' + pad32(7n));
  });

  it('void return, c=false: body SKIPPED (no slot write, empty return) == solc', async () => {
    const j = await dJ(Jg),
      s = await dS(Sg);
    const rj = await j.h.call(j.a, '0x' + sel('g(bool)') + boolWord(false));
    const rs = await s.h.call(s.a, '0x' + sel('g(bool)') + boolWord(false));
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(await readSlot(j.h, j.a, 0n)).toBe(await readSlot(s.h, s.a, 0n));
    expect(await readSlot(j.h, j.a, 0n)).toBe('0x' + pad32(0n));
  });

  // `pre; if (c) { _; } post;`: surrounding code runs in BOTH branches (pre -> slot p, post -> slot q),
  // only the BODY (slot b) is conditional. Verifies the recursive marker placement keeps pre/post.
  const Jw = `class C { p: u256; b: u256; q: u256; @modifier wrap(c: bool) { this.p = 1n; if (c) { _; } this.q = 3n; } @wrap(c) f(c: bool): External<void> { this.b = 2n; } }`;
  const Sw = `contract C { uint256 p; uint256 b; uint256 q; modifier wrap(bool c){ p = 1; if (c) { _; } q = 3; } function f(bool c) external wrap(c) { b = 2; } }`;

  it('pre/post around a conditional placeholder run in BOTH branches (c=true), == solc slots', async () => {
    const j = await dJ(Jw),
      s = await dS(Sw);
    const rj = await j.h.call(j.a, '0x' + sel('f(bool)') + boolWord(true));
    const rs = await s.h.call(s.a, '0x' + sel('f(bool)') + boolWord(true));
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    for (const slot of [0n, 1n, 2n]) {
      expect(await readSlot(j.h, j.a, slot)).toBe(await readSlot(s.h, s.a, slot));
    }
    expect(await readSlot(j.h, j.a, 0n)).toBe('0x' + pad32(1n)); // p (pre)
    expect(await readSlot(j.h, j.a, 1n)).toBe('0x' + pad32(2n)); // b (body, ran)
    expect(await readSlot(j.h, j.a, 2n)).toBe('0x' + pad32(3n)); // q (post)
  });

  it('pre/post run but the body is SKIPPED (c=false), == solc slots', async () => {
    const j = await dJ(Jw),
      s = await dS(Sw);
    const rj = await j.h.call(j.a, '0x' + sel('f(bool)') + boolWord(false));
    const rs = await s.h.call(s.a, '0x' + sel('f(bool)') + boolWord(false));
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
    for (const slot of [0n, 1n, 2n]) {
      expect(await readSlot(j.h, j.a, slot)).toBe(await readSlot(s.h, s.a, slot));
    }
    expect(await readSlot(j.h, j.a, 0n)).toBe('0x' + pad32(1n)); // p (pre, ran)
    expect(await readSlot(j.h, j.a, 1n)).toBe('0x' + pad32(0n)); // b (body, SKIPPED)
    expect(await readSlot(j.h, j.a, 2n)).toBe('0x' + pad32(3n)); // q (post, ran)
  });
});
