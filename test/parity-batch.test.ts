// Parity batch (A-E): close the remaining tractable accept/reject + codegen divergences from the broad
// JETH-vs-solc-0.8.35 sweep. A/B are analyzer GATES (over-acceptances now rejected, with a companion
// non-colliding/value case that still ACCEPTS). C/D/E are codegen LIFTS verified BYTE-IDENTICAL to a solc
// 0.8.35 mirror (returndata + raw storage where relevant); E also pins the bytes4 selector value.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness, encodeCall, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n';

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};

async function pair(jethSrc: string, solSrc: string) {
  const jb = compile(jethSrc, { fileName: 'C.jeth' });
  const sb = compileSolidity(solSrc, 'C');
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  return { jeth, sol, aj, as };
}

// ===========================================================================
// (A) OVER-ACCEPTANCE closed: an uninitialized `mapping` local is rejected
// (JETH340), matching solc ("Uninitialized mapping. Mappings cannot be created
// dynamically"). A value-type / struct-without-mapping local still ACCEPTS.
// ===========================================================================
describe('(A) uninitialized mapping local -> JETH340 (solc rejects)', () => {
  it('a bare mapping local rejects', () => {
    const src = `class C { get f(): External<u256> { let m: mapping<u256,u256>; return 0n; } }`;
    expect(codes(src)).toContain('JETH340');
  });
  it('a mapping-valued mapping local rejects', () => {
    const src = `class C { get f(): External<u256> { let m: mapping<u256, mapping<u256,u256>>; return 0n; } }`;
    expect(codes(src)).toContain('JETH340');
  });
  it('a struct local CONTAINING a mapping rejects', () => {
    const src = `type S = { m: mapping<u256,u256>; x: u256; };
class C { get f(): External<u256> { let s: S; return 0n; } }`;
    expect(codes(src)).toContain('JETH340');
  });
  it('a value-type local still ACCEPTS (no over-rejection)', () => {
    const src = `class C { get f(): External<u256> { let x: u256 = 5n; return x; } }`;
    expect(codes(src)).toEqual([]);
  });
  it('a struct local WITHOUT a mapping still ACCEPTS', () => {
    const src = `type P = { a: u256; b: u256; };
class C { get f(): External<u256> { let p: P; p.a = 7n; return p.a; } }`;
    expect(codes(src)).toEqual([]);
  });
});

// ===========================================================================
// (B) OVER-ACCEPTANCE closed: an @using attached-fn name that collides with a
// genuine BUILT-IN member of the SAME receiver type is ambiguous -> JETH341
// (matches solc's "Member ... not unique after argument-dependent lookup").
// A non-colliding name, or a collision on a DIFFERENT type, still ACCEPTS.
// ===========================================================================
describe('(B) @using fn vs built-in member collision -> JETH341 (solc rejects)', () => {
  it('length on a dynamic array vs built-in .length rejects', () => {
    const src = `static class Bad { length(a: u256[]): u256 { return 7n; } }
@using(Bad) class C { get f(): External<u256> { let a: u256[] = [1n,2n,3n]; return a.length(); } }`;
    expect(codes(src)).toContain('JETH341');
  });
  it('push on a storage dynamic array vs built-in push rejects', () => {
    const src = `static class Bad { push(a: u256[]): u256 { return 7n; } }
@using(Bad) class C { xs: u256[]; get f(): External<u256> { return this.xs.push(); } }`;
    expect(codes(src)).toContain('JETH341');
  });
  it('balance on address vs built-in .balance rejects', () => {
    const src = `static class Bad { balance(a: address): u256 { return 7n; } }
@using(Bad) class C { get f(x: address): External<u256> { return x.balance(); } }`;
    expect(codes(src)).toContain('JETH341');
  });
  it('code on address vs built-in .code rejects', () => {
    const src = `static class Bad { code(a: address): u256 { return 7n; } }
@using(Bad) class C { get f(x: address): External<u256> { return x.code(); } }`;
    expect(codes(src)).toContain('JETH341');
  });
  it('a NON-colliding attached fn name still ACCEPTS (no over-rejection)', () => {
    const src = `static class Good { sum(a: u256[]): u256 { return 7n; } }
@using(Good) class C { get f(): External<u256> { let a: u256[] = [1n,2n,3n]; return a.sum(); } }`;
    expect(codes(src)).toEqual([]);
  });
  it('a collision on a DIFFERENT type than the receiver still ACCEPTS', () => {
    // `length` attached to address (not the u256[] receiver) is not a collision for a.length().
    const src = `static class L { length(a: address): u256 { return 7n; } }
@using(L) class C { get f(): External<u256> { let a: u256[] = [1n,2n,3n]; return a.length; } }`;
    expect(codes(src)).toEqual([]);
  });
  // The PROPERTY form (a.length, addr.balance) is ambiguous in solc just like the call form a.length();
  // independent verification caught that the call-only gate missed it. These pin the property path.
  it('PROPERTY form a.length (not just a.length()) rejects the collision', () => {
    const src = `static class Bad { length(a: u256[]): u256 { return 7n; } }
@using(Bad) class C { get f(a: u256[]): External<u256> { return a.length; } }`;
    expect(codes(src)).toContain('JETH341');
  });
  it('PROPERTY form addr.balance and addr.code reject the collision', () => {
    const bal = `static class Bad { balance(a: address): u256 { return 7n; } }
@using(Bad) class C { get f(x: address): External<u256> { return x.balance; } }`;
    expect(codes(bal)).toContain('JETH341');
    const cod = `static class Bad { code(a: address): bytes { return bytes(""); } }
@using(Bad) class C { get f(x: address): External<bytes> { return x.code; } }`;
    expect(codes(cod)).toContain('JETH341');
  });
});

// ===========================================================================
// (C) OVER-REJECTION lifted: a default-initialized struct memory local
// `let p: P;` (zero-init), byte-identical to solc's `P memory p;`.
// ===========================================================================
describe('(C) default-init struct memory local (byte-identical to solc)', () => {
  it('let p: P; field write/read matches solc (returndata + raw storage)', async () => {
    const JETH = `type P = { a: u256; b: bool; c: address; };
class C {
  sa: u256;
  sb: bool;
  f(): External<u256> {
    let p: P;
    let z: u256 = p.a;
    p.a = 42n;
    p.b = true;
    this.sa = p.a;
    this.sb = p.b;
    return z + p.a + (p.b ? 1n : 0n);
  }
}`;
    const SOL = `${SPDX}
contract C {
  struct P { uint256 a; bool b; address c; }
  uint256 sa; bool sb;
  function f() external returns (uint256) {
    P memory p;
    uint256 z = p.a;
    p.a = 42; p.b = true;
    sa = p.a; sb = p.b;
    return z + p.a + (p.b ? 1 : 0);
  }
}`;
    const H = await pair(JETH, SOL);
    const data = encodeCall(sel('f()'), []);
    const j = await H.jeth.call(H.aj, data);
    const s = await H.sol.call(H.as, data);
    expect({ ok: j.success, ret: j.returnHex }).toEqual({ ok: s.success, ret: s.returnHex });
    // raw storage: sa (slot 0) and sb (slot 1) must match byte-for-byte.
    expect(await readSlot(H.jeth, H.aj, 0n)).toEqual(await readSlot(H.sol, H.as, 0n));
    expect(await readSlot(H.jeth, H.aj, 1n)).toEqual(await readSlot(H.sol, H.as, 1n));
  });

  it('a struct with a nested static struct + fixed array zero-inits identically', async () => {
    const JETH = `type Inner = { u: u256; v: bool; };
type P = { a: u256; inner: Inner; xs: Arr<u256,3>; };
class C {
  get f(): External<u256> {
    let p: P;
    return p.a + p.inner.u + (p.inner.v ? 1n : 0n) + p.xs[0n] + p.xs[2n];
  }
}`;
    const SOL = `${SPDX}
contract C {
  struct Inner { uint256 u; bool v; }
  struct P { uint256 a; Inner inner; uint256[3] xs; }
  function f() external pure returns (uint256) {
    P memory p;
    return p.a + p.inner.u + (p.inner.v ? 1 : 0) + p.xs[0] + p.xs[2];
  }
}`;
    const H = await pair(JETH, SOL);
    const data = encodeCall(sel('f()'), []);
    const j = await H.jeth.call(H.aj, data);
    const s = await H.sol.call(H.as, data);
    expect({ ok: j.success, ret: j.returnHex }).toEqual({ ok: s.success, ret: s.returnHex });
  });
});

// ===========================================================================
// (D) OVER-REJECTION lifted: member access on a struct-returning internal call
// `this.mk(a).x`, byte-identical to solc.
// ===========================================================================
describe('(D) member access on a struct-returning call (byte-identical to solc)', () => {
  it('this.mk(a).x / .y matches solc', async () => {
    const JETH = `type P = { x: u256; y: u256; };
class C {
  mk(a: u256): P { return P(a, a + 1n); }
  get f(a: u256): External<u256> { return this.mk(a).x + this.mk(a).y; }
}`;
    const SOL = `${SPDX}
contract C {
  struct P { uint256 x; uint256 y; }
  function mk(uint256 a) internal pure returns (P memory) { return P(a, a + 1); }
  function f(uint256 a) external pure returns (uint256) { return mk(a).x + mk(a).y; }
}`;
    const H = await pair(JETH, SOL);
    for (const a of [0n, 5n, 1000n]) {
      const data = encodeCall(sel('f(uint256)'), [a]);
      const j = await H.jeth.call(H.aj, data);
      const s = await H.sol.call(H.as, data);
      expect({ a, ok: j.success, ret: j.returnHex }).toEqual({ a, ok: s.success, ret: s.returnHex });
    }
  });

  it('a narrow value field (bool / u8) reads identically', async () => {
    const JETH = `type P = { f: bool; n: u8; };
class C {
  mk(b: bool): P { return P(b, 200n); }
  get g(b: bool): External<u256> { return (this.mk(b).f ? 1n : 0n) + u256(this.mk(b).n); }
}`;
    const SOL = `${SPDX}
contract C {
  struct P { bool f; uint8 n; }
  function mk(bool b) internal pure returns (P memory) { return P(b, 200); }
  function g(bool b) external pure returns (uint256) { return (mk(b).f ? 1 : 0) + uint256(mk(b).n); }
}`;
    const H = await pair(JETH, SOL);
    for (const b of [true, false]) {
      const data = encodeCall(sel('g(bool)'), [b ? 1n : 0n]);
      const j = await H.jeth.call(H.aj, data);
      const s = await H.sol.call(H.as, data);
      expect({ b, ok: j.success, ret: j.returnHex }).toEqual({ b, ok: s.success, ret: s.returnHex });
    }
  });
});

// ===========================================================================
// (E) OVER-REJECTION lifted: function `.selector` -> the compile-time bytes4
// selector. Byte-identical to solc's f.selector value.
// ===========================================================================
describe('(E) function .selector (byte-identical to solc)', () => {
  it('this.g.selector returns the 4-byte selector, matching solc', async () => {
    const JETH = `class C {
  get g(x: u256): External<u256> { return x; }
  get sel(): External<bytes4> { return this.g.selector; }
}`;
    const SOL = `${SPDX}
contract C {
  function g(uint256 x) external pure returns (uint256) { return x; }
  function sel() external pure returns (bytes4) { return this.g.selector; }
}`;
    const H = await pair(JETH, SOL);
    const data = encodeCall(sel('sel()'), []);
    const j = await H.jeth.call(H.aj, data);
    const s = await H.sol.call(H.as, data);
    expect({ ok: j.success, ret: j.returnHex }).toEqual({ ok: s.success, ret: s.returnHex });
    // the bytes4 selector value equals functionSelector("g(uint256)"), left-aligned in the high 4 bytes.
    const want = ('0x' + sel('g(uint256)').replace(/^0x/, '')).padEnd(66, '0');
    expect(j.returnHex.toLowerCase()).toEqual(want.toLowerCase());
  });

  it('a bare function-name .selector (public) also works and matches solc', async () => {
    const JETH = `class C {
  get h(a: u256, b: u256): External<u256> { return a + b; }
  get s(): External<bytes4> { return h.selector; }
}`;
    const SOL = `${SPDX}
contract C {
  function h(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }
  function s() external pure returns (bytes4) { return this.h.selector; }
}`;
    const H = await pair(JETH, SOL);
    const data = encodeCall(sel('s()'), []);
    const j = await H.jeth.call(H.aj, data);
    const s2 = await H.sol.call(H.as, data);
    expect({ ok: j.success, ret: j.returnHex }).toEqual({ ok: s2.success, ret: s2.returnHex });
    const want = ('0x' + sel('h(uint256,uint256)').replace(/^0x/, '')).padEnd(66, '0');
    expect(j.returnHex.toLowerCase()).toEqual(want.toLowerCase());
  });

  it('.selector on an internal function is rejected (no ABI selector)', () => {
    const src = `class C {
  @internal p(x: u256): u256 { return x; }
  get s(): External<bytes4> { return this.p.selector; }
}`;
    expect(codes(src)).toContain('JETH074');
  });
});
