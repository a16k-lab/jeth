// LEXICAL @using scoping (solc parity): a `using L for T` directive is in scope ONLY inside the
// contract body that declares it - it is NOT inherited by a child and NOT projected from the
// deployed contract into base/mid/library bodies (solc 0.7.0+). Three axes:
//   AXIS 1 (the USING-ON-ABSTRACT lift): `@using(L)` on an `@abstract` base is consumed for the
//     base's OWN bodies (methods + constructor), either decorator order.
//   AXIS 2 (lexical boundaries): an attachment is served exclusively from the body-owner class's
//     own @using map - a base/mid body without its own @using cannot use the DEPLOYED contract's
//     map (R1/R2), a library body cannot either (R5), and a base with its own @using still cannot
//     reach a key only the deployed contract attaches (MIN-R4).
//   AXIS 3 (modifier bodies): a @modifier body resolves attachments in its DECLARING class's scope
//     (pre-only, post-code, conditional-placeholder, and ctor-modifier shapes alike).
// The native `self` convention (first param literally named `self`) is FILE-WIDE by design and is
// NOT subject to the lexical scoping - it keeps working in base and library bodies.
// Every accept cell is verified run+decode byte-identical to solc 0.8.35 with distinct non-zero
// seeds; every reject cell is verified a both-reject (solc rejects the mirror).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const codes = (src: string): string[] => {
  try { compile(src, { fileName: 'C.jeth' }); return []; }
  catch (e) { if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e; }
};
const solcRejects = (src: string): boolean => { try { compileSolidity(SPDX + src, 'C'); return false; } catch { return true; } };
async function dJ(s: string) { const h = await Harness.create(); return { h, a: await h.deploy(compile(s, { fileName: 'C.jeth' }).creationBytecode) }; }
async function dS(s: string) { const h = await Harness.create(); return { h, a: await h.deploy(compileSolidity(SPDX + s, 'C').creation) }; }
/** Deploy J + S; assert each call's success + returndata byte-identical, plus the first `nslots` raw
 *  storage slots (constructor-write parity). Calls run in order on BOTH sides (state carries). */
async function same(J: string, S: string, calls: { sig: string; arg?: string; value?: bigint }[], nslots = 0) {
  const j = await dJ(J), s = await dS(S);
  for (const c of calls) {
    const d = '0x' + sel(c.sig) + (c.arg ?? '');
    const opts = c.value !== undefined ? { value: c.value } : {};
    const rj = await j.h.call(j.a, d, opts), rs = await s.h.call(s.a, d, opts);
    expect(rj.success, `${c.sig} success`).toBe(rs.success);
    expect(rj.returnHex, c.sig).toBe(rs.returnHex);
  }
  const js: string[] = [], ss: string[] = [];
  for (let i = 0; i < nslots; i++) { js.push(await readSlot(j.h, j.a, BigInt(i))); ss.push(await readSlot(s.h, s.a, BigInt(i))); }
  expect(js).toEqual(ss);
  return { j, s };
}

const JL = `
@library
class L {
  half(v: u256): u256 { return v / 2n; }
}
`;
const SL = `
library L {
  function half(uint256 v) internal pure returns (uint256) { return v / 2; }
}
`;
const JM = `
@library
class M {
  deca(v: u256): u256 { return v * 10n; }
}
`;
const SM = `
library M {
  function deca(uint256 v) internal pure returns (uint256) { return v * 10; }
}
`;
// three same-name tag libraries for the shadowing anchors: L1 = +1000, L2 = +2000, L3 = +3000
const JT = `
@library
class L1 { tag(v: u256): u256 { return v + 1000n; } }
@library
class L2 { tag(v: u256): u256 { return v + 2000n; } }
@library
class L3 { tag(v: u256): u256 { return v + 3000n; } }
`;
const ST = `
library L1 { function tag(uint256 v) internal pure returns (uint256) { return v + 1000; } }
library L2 { function tag(uint256 v) internal pure returns (uint256) { return v + 2000; } }
library L3 { function tag(uint256 v) internal pure returns (uint256) { return v + 3000; } }
`;

describe('AXIS 1: @using(L) on an @abstract base serves the base OWN bodies', () => {
  it('canonical: inherited helper uses the attachment, child calls the helper (decoded f(10)=5)', async () => {
    const J = JL + `
@using(L) @abstract
class Base { cap(x: u256): u256 { return x.half(); } }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`;
    const S = SL + `
abstract contract Base { using L for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.half(); } }
contract C is Base { function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`;
    const { j } = await same(J, S, [{ sig: 'f(uint256)', arg: pad32(10n) }]);
    // non-vacuous: the decoded value is exactly half(10) = 5
    const r = await j.h.call(j.a, '0x' + sel('f(uint256)') + pad32(10n));
    expect(r.returnHex).toBe('0x' + pad32(5n));
  });

  it('reversed decorator order (@abstract then @using) lifts identically (f(26)=13)', async () => {
    const J = JL + `
@abstract @using(L)
class Base { cap(x: u256): u256 { return x.half(); } }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`;
    const S = SL + `
abstract contract Base { using L for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.half(); } }
contract C is Base { function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`;
    const { j } = await same(J, S, [{ sig: 'f(uint256)', arg: pad32(26n) }]);
    const r = await j.h.call(j.a, '0x' + sel('f(uint256)') + pad32(26n));
    expect(r.returnHex).toBe('0x' + pad32(13n));
  });

  it('diamond/C3: two abstract mids over the @using-abstract root', async () => {
    const J = JL + `
@using(L) @abstract
class Base { cap(x: u256): u256 { return x.half(); } }
@abstract
class A1 extends Base { g1(x: u256): u256 { return this.cap(x) + 1n; } }
@abstract
class A2 extends Base { g2(x: u256): u256 { return this.cap(x) + 2n; } }
@contract
class C extends A1, A2 {
  @external @pure f1(x: u256): u256 { return this.g1(x); }
  @external @pure f2(x: u256): u256 { return this.g2(x); }
}
`;
    const S = SL + `
abstract contract Base { using L for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.half(); } }
abstract contract A1 is Base { function g1(uint256 x) internal pure returns (uint256) { return cap(x) + 1; } }
abstract contract A2 is Base { function g2(uint256 x) internal pure returns (uint256) { return cap(x) + 2; } }
contract C is A1, A2 {
  function f1(uint256 x) external pure returns (uint256) { return g1(x); }
  function f2(uint256 x) external pure returns (uint256) { return g2(x); }
}
`;
    await same(J, S, [
      { sig: 'f1(uint256)', arg: pad32(10n) },
      { sig: 'f2(uint256)', arg: pad32(30n) },
    ]);
  });

  it('a base method calling ANOTHER base method that uses the attachment (f(10)=20)', async () => {
    const J = JL + `
@using(L) @abstract
class Base {
  inner(x: u256): u256 { return x.half(); }
  outer(x: u256): u256 { return this.inner(x) * 3n + x.half(); }
}
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.outer(x); } }
`;
    const S = SL + `
abstract contract Base {
  using L for uint256;
  function inner(uint256 x) internal pure returns (uint256) { return x.half(); }
  function outer(uint256 x) internal pure returns (uint256) { return inner(x) * 3 + x.half(); }
}
contract C is Base { function f(uint256 x) external pure returns (uint256) { return outer(x); } }
`;
    const { j } = await same(J, S, [{ sig: 'f(uint256)', arg: pad32(10n) }]);
    const r = await j.h.call(j.a, '0x' + sel('f(uint256)') + pad32(10n));
    expect(r.returnHex).toBe('0x' + pad32(20n));
  });

  it('abstract base with state + ctor chain: attached call in the BASE constructor body', async () => {
    const J = JL + `
@using(L) @abstract
class Base {
  @state total: u256;
  constructor(seed: u256) { this.total = seed.half(); }
}
@contract
class C extends Base {
  constructor() { super(14n); }
  @external @view f(): u256 { return this.total; }
}
`;
    const S = SL + `
abstract contract Base {
  using L for uint256;
  uint256 total;
  constructor(uint256 seed) { total = seed.half(); }
}
contract C is Base {
  constructor() Base(14) {}
  function f() external view returns (uint256) { return total; }
}
`;
    const { j } = await same(J, S, [{ sig: 'f()' }], 1);
    const r = await j.h.call(j.a, '0x' + sel('f()'));
    expect(r.returnHex).toBe('0x' + pad32(7n)); // half(14) written by the BASE ctor
  });

  it('base CTOR under same-name shadowing writes the BASE library flavor (slot-checked 2005)', async () => {
    const { j } = await same(JT + `
@using(L2) @abstract
class Base { @state acc: u256; constructor(seed: u256) { this.acc = seed.tag(); } }
@using(L1) @contract
class C extends Base { constructor() { super(5n); } @external @view getAcc(): u256 { return this.acc; } }
`, ST + `
abstract contract Base { using L2 for uint256; uint256 acc; constructor(uint256 seed) { acc = seed.tag(); } }
contract C is Base { using L1 for uint256; constructor() Base(5) {} function getAcc() external view returns (uint256) { return acc; } }
`, [{ sig: 'getAcc()' }], 1);
    const r = await j.h.call(j.a, '0x' + sel('getAcc()'));
    expect(r.returnHex).toBe('0x' + pad32(2005n)); // Base's L2 (+2000), not the deployed L1 (+1000)
  });

  it('struct + bytes receivers mirror the @using-on-contract surface', async () => {
    // struct receiver
    await same(`
@struct
class P { x: u256; y: u256; }
@library
class LS { sum(p: P): u256 { return p.x + p.y; } }
@using(LS) @abstract
class Base { cap(p: P): u256 { return p.sum(); } }
@contract
class C extends Base { @external @pure f(a: u256, b: u256): u256 { let p: P = P(a, b); return this.cap(p); } }
`, `
struct P { uint256 x; uint256 y; }
library LS { function sum(P memory p) internal pure returns (uint256) { return p.x + p.y; } }
abstract contract Base { using LS for P; function cap(P memory p) internal pure returns (uint256) { return p.sum(); } }
contract C is Base { function f(uint256 a, uint256 b) external pure returns (uint256) { P memory p = P(a, b); return cap(p); } }
`, [{ sig: 'f(uint256,uint256)', arg: pad32(3n) + pad32(9n) }]);
    // bytes receiver
    await same(`
@library
class LB { len2(b: bytes): u256 { return b.length * 2n; } }
@using(LB) @abstract
class Base { cap(b: bytes): u256 { return b.len2(); } }
@contract
class C extends Base { @external @pure f(b: bytes): u256 { return this.cap(b); } }
`, `
library LB { function len2(bytes memory b) internal pure returns (uint256) { return b.length * 2; } }
abstract contract Base { using LB for bytes; function cap(bytes memory b) internal pure returns (uint256) { return b.len2(); } }
contract C is Base { function f(bytes memory b) external pure returns (uint256) { return cap(b); } }
`, [{ sig: 'f(bytes)', arg: pad32(32n) + pad32(3n) + 'aabbcc' + '0'.repeat(58) }]);
  });

  it('scoping: a same-name attachment in base and child resolves LEXICALLY (2001 vs 1001)', async () => {
    const J = JT + `
@using(L2) @abstract
class Base { cap(x: u256): u256 { return x.tag(); } }
@using(L1) @contract
class C extends Base {
  @external @pure f(x: u256): u256 { return this.cap(x); }
  @external @pure g(x: u256): u256 { return x.tag(); }
}
`;
    const S = ST + `
abstract contract Base { using L2 for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.tag(); } }
contract C is Base {
  using L1 for uint256;
  function f(uint256 x) external pure returns (uint256) { return cap(x); }
  function g(uint256 x) external pure returns (uint256) { return x.tag(); }
}
`;
    const { j } = await same(J, S, [
      { sig: 'f(uint256)', arg: pad32(1n) },
      { sig: 'g(uint256)', arg: pad32(1n) },
    ]);
    const rf = await j.h.call(j.a, '0x' + sel('f(uint256)') + pad32(1n));
    const rg = await j.h.call(j.a, '0x' + sel('g(uint256)') + pad32(1n));
    expect(rf.returnHex).toBe('0x' + pad32(2001n)); // Base's L2 wins inside the base body
    expect(rg.returnHex).toBe('0x' + pad32(1001n)); // C's L1 wins inside the child body
  });

  it('@using(L, M), stacked @using, and a @payable base fn', async () => {
    await same(JL + JM + `
@using(L, M) @abstract
class Base { cap(x: u256): u256 { return x.half() + x.deca(); } }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`, SL + SM + `
abstract contract Base { using L for uint256; using M for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.half() + x.deca(); } }
contract C is Base { function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`, [{ sig: 'f(uint256)', arg: pad32(9n) }]);
    await same(JL + JM + `
@using(L) @using(M) @abstract
class Base { cap(x: u256): u256 { return x.half() + x.deca(); } }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`, SL + SM + `
abstract contract Base { using L for uint256; using M for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.half() + x.deca(); } }
contract C is Base { function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`, [{ sig: 'f(uint256)', arg: pad32(12n) }]);
    await same(JL + `
@using(L) @abstract
class Base { @external @payable buy(): u256 { return msg.value.half(); } }
@contract
class C extends Base { }
`, SL + `
abstract contract Base { using L for uint256; function buy() external payable virtual returns (uint256) { return msg.value.half(); } }
contract C is Base { }
`, [{ sig: 'buy()', value: 10n }]);
  });

  it('super with @virtual/@override markers: each body uses its OWN class attachment (3002)', async () => {
    const { j } = await same(JT + `
@using(L2) @abstract
class Base { @virtual tagit(x: u256): u256 { return x.tag(); } }
@using(L1) @contract
class C extends Base {
  @override tagit(x: u256): u256 { return super.tagit(x) + x.tag(); }
  @external @pure f(x: u256): u256 { return this.tagit(x); }
}
`, ST + `
abstract contract Base { using L2 for uint256; function tagit(uint256 x) internal pure virtual returns (uint256) { return x.tag(); } }
contract C is Base {
  using L1 for uint256;
  function tagit(uint256 x) internal pure override returns (uint256) { return super.tagit(x) + x.tag(); }
  function f(uint256 x) external pure returns (uint256) { return tagit(x); }
}
`, [{ sig: 'f(uint256)', arg: pad32(1n) }]);
    const r = await j.h.call(j.a, '0x' + sel('f(uint256)') + pad32(1n));
    expect(r.returnHex).toBe('0x' + pad32(3002n)); // super body 2001 (Base's L2) + child body 1001 (C's L1)
  });

  it('a GENERIC function body resolves attachments in its declaring class (deployed and base)', async () => {
    await same(JL + `
@using(L) @contract
class C {
  twice<T>(v: T, k: u256): u256 { return k.half() + k.half(); }
  @external @pure f(x: u256): u256 { return this.twice(x, x); }
}
`, SL + `
contract C { using L for uint256; function twice(uint256 v, uint256 k) internal pure returns (uint256) { return k.half() + k.half(); } function f(uint256 x) external pure returns (uint256) { return twice(x, x); } }
`, [{ sig: 'f(uint256)', arg: pad32(10n) }]);
    await same(JL + `
@using(L) @abstract
class Base { gh<T>(v: T, k: u256): u256 { return k.half(); } }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.gh(x, x); } }
`, SL + `
abstract contract Base { using L for uint256; function gh(uint256 v, uint256 k) internal pure returns (uint256) { return k.half(); } }
contract C is Base { function f(uint256 x) external pure returns (uint256) { return gh(x, x); } }
`, [{ sig: 'f(uint256)', arg: pad32(18n) }]);
  });
});

describe('AXIS 2: lexical boundaries - no fall-through to the deployed contract map', () => {
  it('MIN-R4: a base with its OWN @using cannot reach a key only the DEPLOYED @using attaches', () => {
    const J = JL + JM + `
@using(M) @abstract
class Base { cap(x: u256): u256 { return x.half() + x.deca(); } }
@using(L) @contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`;
    expect(codes(J)).toContain('JETH074');
    expect(solcRejects(SL + SM + `
abstract contract Base { using M for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.half() + x.deca(); } }
contract C is Base { using L for uint256; function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`)).toBe(true);
  });

  it('MIN-R4 3-level variant: a MID with its own @using cannot reach the deployed key either', () => {
    const J = JL + JM + `
@abstract
class Base { }
@using(M) @abstract
class Mid extends Base { cap(x: u256): u256 { return x.half() + x.deca(); } }
@using(L) @contract
class C extends Mid { @external @pure f(x: u256): u256 { return this.cap(x); } }
`;
    expect(codes(J)).toContain('JETH074');
    expect(solcRejects(SL + SM + `
abstract contract Base { }
abstract contract Mid is Base { using M for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.half() + x.deca(); } }
contract C is Mid { using L for uint256; function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`)).toBe(true);
  });

  it('corrected mirror: adding the lib to the base OWN @using turns MIN-R4 into an accept (105)', async () => {
    const { j } = await same(JL + JM + `
@using(M, L) @abstract
class Base { cap(x: u256): u256 { return x.half() + x.deca(); } }
@using(L) @contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`, SL + SM + `
abstract contract Base { using M for uint256; using L for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.half() + x.deca(); } }
contract C is Base { using L for uint256; function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`, [{ sig: 'f(uint256)', arg: pad32(10n) }]);
    const r = await j.h.call(j.a, '0x' + sel('f(uint256)') + pad32(10n));
    expect(r.returnHex).toBe('0x' + pad32(105n)); // half(10) + deca(10)
  });

  it('R1: a base body with NO @using cannot use the deployed contract attachment', () => {
    expect(codes(JL + `
@abstract
class Base { cap(x: u256): u256 { return x.half(); } }
@using(L) @contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`)).toContain('JETH074');
    expect(solcRejects(SL + `
abstract contract Base { function cap(uint256 x) internal pure returns (uint256) { return x.half(); } }
contract C is Base { using L for uint256; function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`)).toBe(true);
  });

  it('R2: a MID body with no @using cannot use the deployed contract attachment', () => {
    expect(codes(JL + `
@abstract
class Base { }
@abstract
class Mid extends Base { cap(x: u256): u256 { return x.half(); } }
@using(L) @contract
class C extends Mid { @external @pure f(x: u256): u256 { return this.cap(x); } }
`)).toContain('JETH074');
    expect(solcRejects(SL + `
abstract contract Base { }
abstract contract Mid is Base { function cap(uint256 x) internal pure returns (uint256) { return x.half(); } }
contract C is Mid { using L for uint256; function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`)).toBe(true);
  });

  it('R5: a LIBRARY body cannot use the deployed contract attachment', () => {
    expect(codes(JL + `
@library
class K { quarter(v: u256): u256 { return v.half(); } }
@using(L) @contract
class C { @external @pure f(x: u256): u256 { return K.quarter(x); } }
`)).toContain('JETH074');
    expect(solcRejects(SL + `
library K { function quarter(uint256 v) internal pure returns (uint256) { return v.half(); } }
contract C { using L for uint256; function f(uint256 x) external pure returns (uint256) { return K.quarter(x); } }
`)).toBe(true);
  });

  it('control: the CHILD writing the attached call directly stays both-reject (both spellings)', () => {
    for (const decs of ['@using(L) @abstract', '@abstract @using(L)']) {
      const J = JL + `
${decs}
class Base { }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return x.half(); } }
`;
      expect(codes(J)).toContain('JETH074');
    }
    expect(solcRejects(SL + `
abstract contract Base { using L for uint256; }
contract C is Base { function f(uint256 x) external pure returns (uint256) { return x.half(); } }
`)).toBe(true);
  });

  it('control: no-@using attachment, wrong arity, bad @using arg, base-own-ambiguous', () => {
    // no @using anywhere
    expect(codes(JL + `
@abstract
class Base { cap(x: u256): u256 { return x.half(); } }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`)).toContain('JETH074');
    // wrong arity through the lifted base attachment (half takes just the receiver)
    expect(codes(JL + `
@using(L) @abstract
class Base { cap(x: u256): u256 { return x.half(3n); } }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`)).toContain('JETH148');
    // a bad @using argument on the abstract is validated like the deployed form
    expect(codes(JL + `
@using(NotALib) @abstract
class Base { cap(x: u256): u256 { return x.half(); } }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`)).toContain('JETH391');
    // two of the base's OWN @using libs attach the same key -> ambiguous at the call site
    expect(codes(JT + `
@using(L1, L2) @abstract
class Base { cap(x: u256): u256 { return x.tag(); } }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`)).toContain('JETH393');
    expect(solcRejects(ST + `
abstract contract Base { using L1 for uint256; using L2 for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.tag(); } }
contract C is Base { function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`)).toBe(true);
  });

  it('built-in collision (JETH341) is lexical too: fires in the @using base body, not the child', async () => {
    // in the base's own body the attached `length` collides with the built-in -> both reject
    expect(codes(`
@library
class LL { length(xs: u256[]): u256 { return 999n; } }
@using(LL) @abstract
class Base { cap(xs: u256[]): u256 { return xs.length; } }
@contract
class C extends Base { @external @pure f(xs: u256[]): u256 { return this.cap(xs); } }
`)).toContain('JETH341');
    expect(solcRejects(`
library LL { function length(uint256[] memory xs) internal pure returns (uint256) { return 999; } }
abstract contract Base { using LL for uint256[]; function cap(uint256[] memory xs) internal pure returns (uint256) { return xs.length; } }
contract C is Base { function f(uint256[] memory xs) external pure returns (uint256) { return cap(xs); } }
`)).toBe(true);
    // the child body is OUTSIDE the directive's scope: the built-in resolves fine on both sides
    await same(`
@library
class LL { length(xs: u256[]): u256 { return 999n; } }
@using(LL) @abstract
class Base { }
@contract
class C extends Base { @external @pure f(xs: u256[]): u256 { return xs.length; } }
`, `
library LL { function length(uint256[] memory xs) internal pure returns (uint256) { return 999; } }
abstract contract Base { using LL for uint256[]; }
contract C is Base { function f(uint256[] memory xs) external pure returns (uint256) { return xs.length; } }
`, [{ sig: 'f(uint256[])', arg: pad32(32n) + pad32(2n) + pad32(7n) + pad32(8n) }]);
  });

  it('control unchanged: @using on @contract, the self convention (file-wide), qualified L.f', async () => {
    const { j } = await same(JL + `
@using(L) @contract
class C {
  @external @pure f(x: u256): u256 { return x.half(); }
  @external @pure g(x: u256): u256 { return L.half(x) + 1n; }
}
`, SL + `
contract C {
  using L for uint256;
  function f(uint256 x) external pure returns (uint256) { return x.half(); }
  function g(uint256 x) external pure returns (uint256) { return L.half(x) + 1; }
}
`, [{ sig: 'f(uint256)', arg: pad32(10n) }, { sig: 'g(uint256)', arg: pad32(10n) }]);
    const r = await j.h.call(j.a, '0x' + sel('f(uint256)') + pad32(10n));
    expect(r.returnHex).toBe('0x' + pad32(5n));
    // the native `self` convention is FILE-WIDE by design: it serves a base body with no @using
    // anywhere, and a LIBRARY body (solc mirrors carry the using directive inside the consumer)
    await same(`
@library
class S { double(self: u256): u256 { return self * 2n; } }
@abstract
class Base { cap(x: u256): u256 { return x.double(); } }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`, `
library S { function double(uint256 self) internal pure returns (uint256) { return self * 2; } }
abstract contract Base { using S for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.double(); } }
contract C is Base { function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`, [{ sig: 'f(uint256)', arg: pad32(21n) }]);
    await same(`
@library
class S { double(self: u256): u256 { return self * 2n; } }
@library
class K { quad(v: u256): u256 { return v.double().double(); } }
@contract
class C { @external @pure f(x: u256): u256 { return K.quad(x); } }
`, `
library S { function double(uint256 self) internal pure returns (uint256) { return self * 2; } }
library K { using S for uint256; function quad(uint256 v) internal pure returns (uint256) { return v.double().double(); } }
contract C { function f(uint256 x) external pure returns (uint256) { return K.quad(x); } }
`, [{ sig: 'f(uint256)', arg: pad32(7n) }]);
    // a self-convention lib and a base @using lib side by side in one base body
    await same(`
@library
class S { double(self: u256): u256 { return self * 2n; } }
` + JL + `
@using(L) @abstract
class Base { cap(x: u256): u256 { return x.half() + x.double(); } }
@contract
class C extends Base { @external @pure f(x: u256): u256 { return this.cap(x); } }
`, `
library S { function double(uint256 self) internal pure returns (uint256) { return self * 2; } }
` + SL + `
abstract contract Base { using S for uint256; using L for uint256; function cap(uint256 x) internal pure returns (uint256) { return x.half() + x.double(); } }
contract C is Base { function f(uint256 x) external pure returns (uint256) { return cap(x); } }
`, [{ sig: 'f(uint256)', arg: pad32(10n) }]);
  });
});

describe('AXIS 3: a @modifier body resolves attachments in its DECLARING class', () => {
  it('MOD1 (shadowing): base-declared modifier uses the BASE library, not the deployed one (2007)', async () => {
    const { j } = await same(JT + `
@using(L2) @abstract
class Base { @state acc: u256; @modifier mark(x: u256) { this.acc = x.tag(); _; } }
@using(L1) @contract
class C extends Base {
  @external @mark(7n) poke(): void { }
  @external @view getAcc(): u256 { return this.acc; }
}
`, ST + `
abstract contract Base { uint256 acc; using L2 for uint256; modifier mark(uint256 x) { acc = x.tag(); _; } }
contract C is Base {
  using L1 for uint256;
  function poke() external mark(7) { }
  function getAcc() external view returns (uint256) { return acc; }
}
`, [{ sig: 'poke()' }, { sig: 'getAcc()' }]);
    await j.h.call(j.a, '0x' + sel('poke()'));
    const r = await j.h.call(j.a, '0x' + sel('getAcc()'));
    expect(r.returnHex).toBe('0x' + pad32(2007n)); // the base's L2 (+2000), NOT the deployed L1 (1007)
  });

  it('MOD2 (no shadowing): only the base has @using - the modifier body still resolves (2009)', async () => {
    const { j } = await same(JT + `
@using(L2) @abstract
class Base { @state acc: u256; @modifier mark(x: u256) { this.acc = x.tag(); _; } }
@contract
class C extends Base {
  @external @mark(9n) poke(): void { }
  @external @view getAcc(): u256 { return this.acc; }
}
`, ST + `
abstract contract Base { uint256 acc; using L2 for uint256; modifier mark(uint256 x) { acc = x.tag(); _; } }
contract C is Base {
  function poke() external mark(9) { }
  function getAcc() external view returns (uint256) { return acc; }
}
`, [{ sig: 'poke()' }, { sig: 'getAcc()' }]);
    await j.h.call(j.a, '0x' + sel('poke()'));
    const r = await j.h.call(j.a, '0x' + sel('getAcc()'));
    expect(r.returnHex).toBe('0x' + pad32(2009n));
  });

  it('a modifier declared in the DEPLOYED class uses its own map (unchanged, 1007)', async () => {
    const { j } = await same(JT + `
@using(L1) @contract
class C {
  @state acc: u256;
  @modifier mark(x: u256) { this.acc = x.tag(); _; }
  @external @mark(7n) poke(): void { }
  @external @view getAcc(): u256 { return this.acc; }
}
`, ST + `
contract C {
  uint256 acc;
  using L1 for uint256;
  modifier mark(uint256 x) { acc = x.tag(); _; }
  function poke() external mark(7) { }
  function getAcc() external view returns (uint256) { return acc; }
}
`, [{ sig: 'poke()' }, { sig: 'getAcc()' }]);
    await j.h.call(j.a, '0x' + sel('poke()'));
    const r = await j.h.call(j.a, '0x' + sel('getAcc()'));
    expect(r.returnHex).toBe('0x' + pad32(1007n));
  });

  it('a CTOR modifier declared in the base resolves via the base (slot-checked 2005)', async () => {
    const { j } = await same(JT + `
@using(L2) @abstract
class Base { @state acc: u256; @modifier mark(x: u256) { this.acc = x.tag(); _; } }
@using(L1) @contract
class C extends Base {
  @mark(5n) constructor() { }
  @external @view getAcc(): u256 { return this.acc; }
}
`, ST + `
abstract contract Base { uint256 acc; using L2 for uint256; modifier mark(uint256 x) { acc = x.tag(); _; } }
contract C is Base {
  using L1 for uint256;
  constructor() mark(5) { }
  function getAcc() external view returns (uint256) { return acc; }
}
`, [{ sig: 'getAcc()' }], 1);
    const r = await j.h.call(j.a, '0x' + sel('getAcc()'));
    expect(r.returnHex).toBe('0x' + pad32(2005n)); // written at deploy time by the BASE modifier body
  });

  it('3-level chain: grandchild applies the BASE modifier; a MID-declared modifier uses MID', async () => {
    // modifier declared in Base (L2), applied by the grandchild C past a @using(L3) Mid -> 2007
    const a = await same(JT + `
@using(L2) @abstract
class Base { @state acc: u256; @modifier mark(x: u256) { this.acc = x.tag(); _; } }
@using(L3) @abstract
class Mid extends Base { }
@using(L1) @contract
class C extends Mid {
  @external @mark(7n) poke(): void { }
  @external @view getAcc(): u256 { return this.acc; }
}
`, ST + `
abstract contract Base { uint256 acc; using L2 for uint256; modifier mark(uint256 x) { acc = x.tag(); _; } }
abstract contract Mid is Base { using L3 for uint256; }
contract C is Mid {
  using L1 for uint256;
  function poke() external mark(7) { }
  function getAcc() external view returns (uint256) { return acc; }
}
`, [{ sig: 'poke()' }, { sig: 'getAcc()' }]);
    await a.j.h.call(a.j.a, '0x' + sel('poke()'));
    expect((await a.j.h.call(a.j.a, '0x' + sel('getAcc()'))).returnHex).toBe('0x' + pad32(2007n));
    // modifier declared in Mid with Mid's own @using(L3) -> 3007
    const b = await same(JT + `
@abstract
class Base { @state acc: u256; }
@using(L3) @abstract
class Mid extends Base { @modifier mark(x: u256) { this.acc = x.tag(); _; } }
@using(L1) @contract
class C extends Mid {
  @external @mark(7n) poke(): void { }
  @external @view getAcc(): u256 { return this.acc; }
}
`, ST + `
abstract contract Base { uint256 acc; }
abstract contract Mid is Base { using L3 for uint256; modifier mark(uint256 x) { acc = x.tag(); _; } }
contract C is Mid {
  using L1 for uint256;
  function poke() external mark(7) { }
  function getAcc() external view returns (uint256) { return acc; }
}
`, [{ sig: 'poke()' }, { sig: 'getAcc()' }]);
    await b.j.h.call(b.j.a, '0x' + sel('poke()'));
    expect((await b.j.h.call(b.j.a, '0x' + sel('getAcc()'))).returnHex).toBe('0x' + pad32(3007n));
  });

  it('POST-code and CONDITIONAL-placeholder modifier shapes route the same way', async () => {
    // post-placeholder code (the buffered userfn path): both the pre and post writes use Base's L2
    const a = await same(JT + `
@using(L2) @abstract
class Base { @state acc: u256; @modifier mark(x: u256) { this.acc = x.tag(); _; this.acc = this.acc + x.tag(); } }
@using(L1) @contract
class C extends Base {
  @external @mark(7n) poke(): u256 { return 1n; }
  @external @view getAcc(): u256 { return this.acc; }
}
`, ST + `
abstract contract Base { uint256 acc; using L2 for uint256; modifier mark(uint256 x) { acc = x.tag(); _; acc = acc + x.tag(); } }
contract C is Base {
  using L1 for uint256;
  function poke() external mark(7) returns (uint256) { return 1; }
  function getAcc() external view returns (uint256) { return acc; }
}
`, [{ sig: 'poke()' }, { sig: 'getAcc()' }]);
    await a.j.h.call(a.j.a, '0x' + sel('poke()'));
    expect((await a.j.h.call(a.j.a, '0x' + sel('getAcc()'))).returnHex).toBe('0x' + pad32(4014n)); // 2007 + 2007
    // conditional placeholder (whole-body lowering)
    const b = await same(JT + `
@using(L2) @abstract
class Base { @state acc: u256; @modifier mark(x: u256) { if (x > 1n) { this.acc = x.tag(); _; } } }
@using(L1) @contract
class C extends Base {
  @external @mark(7n) poke(): u256 { return 1n; }
  @external @view getAcc(): u256 { return this.acc; }
}
`, ST + `
abstract contract Base { uint256 acc; using L2 for uint256; modifier mark(uint256 x) { if (x > 1) { acc = x.tag(); _; } } }
contract C is Base {
  using L1 for uint256;
  function poke() external mark(7) returns (uint256) { return 1; }
  function getAcc() external view returns (uint256) { return acc; }
}
`, [{ sig: 'poke()' }, { sig: 'getAcc()' }]);
    await b.j.h.call(b.j.a, '0x' + sel('poke()'));
    expect((await b.j.h.call(b.j.a, '0x' + sel('getAcc()'))).returnHex).toBe('0x' + pad32(2007n));
  });
});
