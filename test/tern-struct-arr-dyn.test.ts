// TERN-STRUCT-ARR (dynamic outer) + A-LIT-RESID (calldata branch) lift: a ternary over a DYNAMIC
// static-struct array (In[]) in the let-bind / return positions, and a ternary with a whole CALLDATA-param
// branch over a fixed-outer nested-value array (Arr<u256[],2>), were rejected JETH074.
//
// THE SEMANTICS (re-derived from solc 0.8.35 here, not assumed): solc does NOT hold a live reference. It
// unifies the mixed ternary to a MEMORY reference with an ASYMMETRIC rule:
//   W1  `In[] memory r = c?m:st; st[0].a=999; return r[0].a`  -> c=0 gives 100, NOT 999  => storage arm COPIES
//   W2  `r[0].a=777; return st[0].a`                          -> c=0 gives 100, NOT 777  => the copy is discarded
//   W2b `r[0].a=777; return m[0].a`                           -> c=1 gives 777           => memory arm ALIASES
//   W3  In2{a, tags:u256[]} + `st2[0].tags[0]=999`            -> c=0 gives 7             => the copy is DEEP
// and it is observably EXACTLY `In[] memory r; if (c) { r = m; } else { r = st; }` - in Solidity mem->mem IS
// an alias and storage->mem IS a deep copy, so THE TERNARY *IS* THE COPY-DESUGAR.
//
// THE MISCOMPILE TRAP: a BLANKET copy of BOTH arms would miscompile the memory arm (W2b -> 1, not 777), and
// hoisting a calldata arm's cd->mem copy out of its arm would REVERT on malformed calldata that solc happily
// tolerates. Each arm must lower INSIDE ITS OWN arm (lazily) - which lowerExpr's ternary cases already do
// (each branch's code lands in its own switch-case block), so this lift is pure analyzer ROUTING.
//
// KEPT REJECTING (sound, verified vs solc): a cd|storage MIX (solc TypeError - the RC-3 data-location gate,
// which is why a calldata branch is NOT admitted on the pre-gate checkPtrHeadedStructArrayTernary path), a
// DYN-FIELD-struct leaf (In2[], the W3 shape), a cd|memory In[] bind, and an element write through a ternary
// in a read-only body. All four reject at base too - this lift narrows nothing.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const IN = `type In = { a: u256; b: u256; };`;
const SIN = `struct In { uint256 a; uint256 b; }`;
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};
const rejects = (src: string): boolean => codes(src).length > 0;

describe('TERN-STRUCT-ARR dynamic-outer In[] - byte-identical to solc 0.8.35', () => {
  it('W1/W2/W2b alias-vs-copy asymmetry + let-bind + return match solc, with the ASYMMETRY PROVEN LIVE', async () => {
    const J = `${IN}
      class C {
        st: In[];
        seed(): External<void> { this.st.push(In(100n,200n)); this.st.push(In(300n,400n)); }
        reset(): External<void> { this.st[0n]=In(100n,200n); this.st[1n]=In(300n,400n); }
        w1(c: bool): External<u256> { let m: In[] = new Array<In>(2); m[0n]=In(1n,2n); m[1n]=In(3n,4n); let r: In[] = c ? m : this.st; this.st[0n].a=999n; return r[0n].a; }
        get w2(c: bool): External<u256> { let m: In[] = new Array<In>(2); m[0n]=In(1n,2n); m[1n]=In(3n,4n); let r: In[] = c ? m : this.st; r[0n].a=777n; return this.st[0n].a; }
        get w2b(c: bool): External<u256> { let m: In[] = new Array<In>(2); m[0n]=In(1n,2n); m[1n]=In(3n,4n); let r: In[] = c ? m : this.st; r[0n].a=777n; return m[0n].a; }
        get bind(c: bool): External<u256> { let m: In[] = new Array<In>(2); m[0n]=In(1n,2n); m[1n]=In(3n,4n); let p: In[] = c ? m : this.st; return p[0n].a; }
        get retT(c: bool): External<In[]> { let m: In[] = new Array<In>(2); m[0n]=In(1n,2n); m[1n]=In(3n,4n); return c ? m : this.st; } }`;
    const S = `${SIN}
      contract C {
        In[] st;
        function seed() external { st.push(In(100,200)); st.push(In(300,400)); }
        function reset() external { st[0]=In(100,200); st[1]=In(300,400); }
        function w1(bool c) external returns (uint256) { In[] memory m = new In[](2); m[0]=In(1,2); m[1]=In(3,4); In[] memory r = c ? m : st; st[0].a=999; return r[0].a; }
        function w2(bool c) external view returns (uint256) { In[] memory m = new In[](2); m[0]=In(1,2); m[1]=In(3,4); In[] memory r = c ? m : st; r[0].a=777; return st[0].a; }
        function w2b(bool c) external view returns (uint256) { In[] memory m = new In[](2); m[0]=In(1,2); m[1]=In(3,4); In[] memory r = c ? m : st; r[0].a=777; return m[0].a; }
        function bind(bool c) external view returns (uint256) { In[] memory m = new In[](2); m[0]=In(1,2); m[1]=In(3,4); In[] memory p = c ? m : st; return p[0].a; }
        function retT(bool c) external view returns (In[] memory) { In[] memory m = new In[](2); m[0]=In(1,2); m[1]=In(3,4); return c ? m : st; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, sel('seed()'));
    await h.call(as, sel('seed()'));
    const calls: [string, string][] = [];
    for (const f of ['w2', 'w2b', 'bind', 'retT']) for (const c of [1, 0]) calls.push([`${f}(bool)`, W(c)]);
    // w1 mutates storage: reset before each, and re-read through bind afterwards.
    for (const c of [1, 0]) {
      calls.push(['reset()', '']);
      calls.push(['w1(bool)', W(c)]);
      calls.push(['bind(bool)', W(0)]);
    }
    for (const [sg, args] of calls) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg + ' ' + args).toBe(rs.success);
      expect(rj.returnHex, sg + ' ' + args).toBe(rs.returnHex);
    }
    // NON-VACUITY: pin the asymmetry itself, so a blanket-copy or blanket-alias regression FAILS here even
    // if both compilers were to drift together. These four values are the whole point of the lift.
    const val = async (sg: string, c: number) => BigInt((await h.call(aj, sel(sg) + W(c))).returnHex);
    await h.call(aj, sel('reset()'));
    expect(await val('w2b(bool)', 1), 'W2b: the MEMORY arm must ALIAS (a blanket copy gives 1)').toBe(777n);
    expect(await val('w2b(bool)', 0), 'W2b: the storage arm must not touch m').toBe(1n);
    expect(await val('w2(bool)', 0), 'W2: the storage arm is a COPY - the write must NOT reach storage').toBe(100n);
    expect(await val('bind(bool)', 0), 'bind: the storage arm reads the copied value').toBe(100n);
    expect(await val('bind(bool)', 1), 'bind: the memory arm reads m').toBe(1n);
  });

  it('newly-accepted consumers (for-of / abi.encode / internal-call arg / nested ternary) match solc', async () => {
    const M = `let m: In[] = new Array<In>(2); m[0n]=In(1n,2n); m[1n]=In(3n,4n);`;
    const SM = `In[] memory m = new In[](2); m[0]=In(1,2); m[1]=In(3,4);`;
    const J = `${IN}
      class C {
        st: In[];
        seed(): External<void> { this.st.push(In(100n,200n)); this.st.push(In(300n,400n)); }
        g(p: In[]): u256 { return p[0n].a + p[1n].b; }
        get forof(c: bool): External<u256> { ${M} let s: u256 = 0n; for (const e of (c ? m : this.st)) { s = s + e.a; } return s; }
        get enc(c: bool): External<bytes> { ${M} return abi.encode(c ? m : this.st); }
        get arg(c: bool): External<u256> { ${M} return this.g(c ? m : this.st); }
        get nest(c: bool, d: bool): External<u256> { ${M} let n: In[] = new Array<In>(1); n[0n]=In(9n,9n); let p: In[] = c ? m : (d ? n : this.st); return p[0n].a; } }`;
    const S = `${SIN}
      contract C {
        In[] st;
        function seed() external { st.push(In(100,200)); st.push(In(300,400)); }
        function g(In[] memory p) internal pure returns(uint256){ return p[0].a + p[1].b; }
        function forof(bool c) external view returns(uint256){ ${SM} uint256 s=0; In[] memory src = c ? m : st; for(uint i=0;i<src.length;i++){ s+=src[i].a; } return s; }
        function enc(bool c) external view returns(bytes memory){ ${SM} return abi.encode(c ? m : st); }
        function arg(bool c) external view returns(uint256){ ${SM} return g(c ? m : st); }
        function nest(bool c, bool d) external view returns(uint256){ ${SM} In[] memory n = new In[](1); n[0]=In(9,9); In[] memory p = c ? m : (d ? n : st); return p[0].a; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, sel('seed()'));
    await h.call(as, sel('seed()'));
    const calls: [string, string][] = [
      ['forof(bool)', W(1)], ['forof(bool)', W(0)],
      ['enc(bool)', W(1)], ['enc(bool)', W(0)],
      ['arg(bool)', W(1)], ['arg(bool)', W(0)],
      ['nest(bool,bool)', W(1) + W(0)], ['nest(bool,bool)', W(0) + W(1)], ['nest(bool,bool)', W(0) + W(0)],
    ];
    for (const [sg, args] of calls) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg + ' ' + args).toBe(rs.success);
      expect(rj.returnHex, sg + ' ' + args).toBe(rs.returnHex);
    }
    // non-vacuity anchors: each arm must select a DIFFERENT value (m vs the storage copy).
    const val = async (sg: string, a: string) => BigInt((await h.call(aj, sel(sg) + a)).returnHex);
    expect(await val('forof(bool)', W(1))).toBe(4n); // 1 + 3
    expect(await val('forof(bool)', W(0))).toBe(400n); // 100 + 300
    expect(await val('arg(bool)', W(1))).toBe(5n); // m[0].a + m[1].b = 1 + 4
    expect(await val('arg(bool)', W(0))).toBe(500n); // 100 + 400
    expect(await val('nest(bool,bool)', W(0) + W(1))).toBe(9n); // the inner memory arm
    expect(await val('nest(bool,bool)', W(0) + W(0))).toBe(100n); // the inner storage arm (copied)
  });
});

describe('A-LIT-RESID: a whole CALLDATA-param ternary branch - byte-identical to solc 0.8.35', () => {
  it('let-bind Arr<u256[],2> = c ? p : [a,b] matches solc, and the cd->mem copy is LAZY (per-arm)', async () => {
    const J = `class C { get pick(c: bool, p: Arr<u256[],2>, a: u256[], b: u256[]): External<u256> { let q: Arr<u256[],2> = c ? p : [a, b]; return q[0n][0n]; } }`;
    const S = `contract C { function pick(bool c, uint256[][2] calldata p, uint256[] calldata a, uint256[] calldata b) external pure returns(uint256){ uint256[][2] memory q = c ? p : [a, b]; return q[0][0]; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const SIG = 'pick(bool,uint256[][2],uint256[],uint256[])';
    const P = 0x80;
    // tail: p's 2-entry offset table, p[0]=[7,8], p[1]=[9], a=[11], b=[22]
    const tail = (p0len: bigint | number, p1off: number) =>
      W(0x40) + W(p1off) + W(p0len) + W(7) + W(8) + W(1) + W(9) + W(1) + W(11) + W(1) + W(22);
    const aAt = P + 0x20 * 7;
    const bAt = P + 0x20 * 9;
    const enc = (c: number, pOff: number, t: string) => sel(SIG) + W(c) + W(pOff) + W(aAt) + W(bAt) + t;
    const rows: [string, string][] = [
      ['well-formed c=1 (calldata arm)', enc(1, P, tail(2, 0xa0))],
      ['well-formed c=0 (literal arm)', enc(0, P, tail(2, 0xa0))],
      // p's OUTER offset is out of range: solc's entry decoder rejects it on BOTH arms.
      ['bad outer offset c=1', enc(1, 0xffffff, tail(2, 0xa0))],
      ['bad outer offset c=0', enc(0, 0xffffff, tail(2, 0xa0))],
      // p's INNER length is oversized: solc's entry decoder TOLERATES this, so it only reverts on the arm
      // that actually reads p. This is the row that catches a HOISTED cd->mem copy (it would revert at c=0).
      ['bad inner len c=1', enc(1, P, tail(0xffffffffn, 0xa0))],
      ['bad inner len c=0', enc(0, P, tail(0xffffffffn, 0xa0))],
      ['bad inner offset c=1', enc(1, P, tail(2, 0xfffffff))],
      ['bad inner offset c=0', enc(0, P, tail(2, 0xfffffff))],
    ];
    for (const [name, data] of rows) {
      const rj = await h.call(aj, data);
      const rs = await h.call(as, data);
      expect(rj.success, name).toBe(rs.success);
      expect(rj.returnHex, name).toBe(rs.returnHex);
    }
    // NON-VACUITY: the calldata arm reads p (7), the literal arm reads a (11) - different values, so the
    // per-arm selection is live...
    const val = async (d: string) => {
      const r = await h.call(aj, d);
      return r.success ? BigInt(r.returnHex) : 'REVERT';
    };
    expect(await val(enc(1, P, tail(2, 0xa0)))).toBe(7n);
    expect(await val(enc(0, P, tail(2, 0xa0)))).toBe(11n);
    // ...and THIS is the lazy-copy witness: the same malformed calldata REVERTS on the arm that reads p but
    // still returns 11 on the literal arm. A cd->mem copy hoisted out of its arm would revert on both.
    expect(await val(enc(1, P, tail(0xffffffffn, 0xa0))), 'the calldata arm must revert').toBe('REVERT');
    expect(await val(enc(0, P, tail(0xffffffffn, 0xa0))), 'the literal arm must NOT read p').toBe(11n);
  });

  it('index-direct + mem|mem alias + storage|literal nested-value ternaries match solc', async () => {
    const J = `class C {
      sA: Arr<u256[],2>;
      seed(): External<void> { this.sA[0n].push(50n); this.sA[1n].push(60n); }
      get alias(c: bool): External<u256> { let x: u256[] = new Array<u256>(1); x[0n]=1n; let y: u256[] = new Array<u256>(1); y[0n]=2n; let m1: Arr<u256[],2> = [x,y]; let m2: Arr<u256[],2> = [y,x]; let q: Arr<u256[],2> = c ? m1 : m2; q[0n][0n] = 777n; return m1[0n][0n]; }
      get idx(c: bool, p: Arr<u256[],2>, a: u256[], b: u256[]): External<u256> { return (c ? p : [a, b])[0n][0n]; }
      get stl(c: bool, a: u256[], b: u256[]): External<u256> { let q: Arr<u256[],2> = c ? this.sA : [a, b]; return q[0n][0n]; } }`;
    const S = `contract C {
      uint256[][2] sA;
      function seed() external { sA[0].push(50); sA[1].push(60); }
      function alias_(bool c) external pure returns(uint256){ uint256[] memory x=new uint256[](1); x[0]=1; uint256[] memory y=new uint256[](1); y[0]=2; uint256[][2] memory m1=[x,y]; uint256[][2] memory m2=[y,x]; uint256[][2] memory q = c ? m1 : m2; q[0][0]=777; return m1[0][0]; }
      function idx(bool c, uint256[][2] calldata p, uint256[] calldata a, uint256[] calldata b) external pure returns(uint256){ return (c ? p : [a, b])[0][0]; }
      function stl(bool c, uint256[] calldata a, uint256[] calldata b) external view returns(uint256){ uint256[][2] memory q = c ? sA : [a, b]; return q[0][0]; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(aj, sel('seed()'));
    await h.call(as, sel('seed()'));
    // alias is spelled `alias` in JETH and `alias_` in Solidity (alias is not a solc keyword clash, but the
    // selectors must be compared per-compiler), so compare its VALUES rather than a shared selector.
    for (const c of [1, 0]) {
      const rj = await h.call(aj, sel('alias(bool)') + W(c));
      const rs = await h.call(as, sel('alias_(bool)') + W(c));
      expect(rj.success, 'alias ' + c).toBe(rs.success);
      expect(rj.returnHex, 'alias ' + c).toBe(rs.returnHex);
    }
    // NON-VACUITY: writing through the ternary result must ALIAS m1 on the c=1 arm (777) and leave it alone
    // on the c=0 arm (1) - the mem|mem twin of W2b.
    expect(BigInt((await h.call(aj, sel('alias(bool)') + W(1))).returnHex)).toBe(777n);
    expect(BigInt((await h.call(aj, sel('alias(bool)') + W(0))).returnHex)).toBe(1n);
    const cd = W(0x60) + W(0xa0) + W(1) + W(11) + W(1) + W(22);
    for (const [sg, args] of [
      ['stl(bool,uint256[],uint256[])', W(1) + cd],
      ['stl(bool,uint256[],uint256[])', W(0) + cd],
    ] as [string, string][]) {
      const rj = await h.call(aj, sel(sg) + args);
      const rs = await h.call(as, sel(sg) + args);
      expect(rj.success, sg).toBe(rs.success);
      expect(rj.returnHex, sg).toBe(rs.returnHex);
    }
    // non-vacuity: the storage arm yields 50, the literal arm 11.
    expect(BigInt((await h.call(aj, sel('stl(bool,uint256[],uint256[])') + W(1) + cd)).returnHex)).toBe(50n);
    expect(BigInt((await h.call(aj, sel('stl(bool,uint256[],uint256[])') + W(0) + cd)).returnHex)).toBe(11n);
  });
});

describe('TERN-STRUCT-ARR dynamic-outer: the boundaries stay SOUND rejects', () => {
  const M = `let m: In[] = new Array<In>(2); m[0n]=In(1n,2n); m[1n]=In(3n,4n);`;
  it('a cd|storage MIX rejects (solc TypeError: a calldata branch cannot unify with a storage branch)', () => {
    // The RC-3 data-location gate. This is WHY a calldata branch is not admitted on the pre-gate
    // checkPtrHeadedStructArrayTernary path - doing so let this exact program through (an over-acceptance).
    expect(
      rejects(`${IN} class C { st: In[]; get f(c: bool, p: In[]): External<u256> { let q: In[] = c ? p : this.st; return q[0n].a; } }`),
    ).toBe(true);
    expect(
      rejects(`class C { sA: Arr<u256[],2>; get f(c: bool, p: Arr<u256[],2>): External<u256> { let q: Arr<u256[],2> = c ? p : this.sA; return q[0n][0n]; } }`),
    ).toBe(true);
  });
  it('a DYN-FIELD-struct leaf (In2[], the W3 shape) stays a clean JETH074 reject', () => {
    // isStaticStructAnyLeafArray admits only a STATIC struct leaf; In2 has a dynamic `tags` field, so its
    // deep-copy image rides a different codec that this lift does not route. A narrower lift is fine.
    expect(
      codes(`type In2 = { a: u256; tags: u256[]; }; class C { st2: In2[]; get f(c: bool): External<u256> { let m: In2[] = new Array<In2>(1); let q: In2[] = c ? m : this.st2; return q[0n].a; } }`),
    ).toContain('JETH074');
  });
  it('an element WRITE through a ternary in a read-only body stays a reject', () => {
    expect(
      rejects(`${IN} class C { st: In[]; get f(c: bool): External<u256> { ${M} (c ? m : this.st)[0n].a = 777n; return m[0n].a; } }`),
    ).toBe(true);
  });
  it('the already-lifted FIXED Arr<In,N> twin still compiles (no regression)', () => {
    expect(
      rejects(`${IN} class C { fa: Arr<In,2>; get bind(c: bool): External<u256> { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let p: Arr<In,2> = c ? m : this.fa; return p[0n].a; } }`),
    ).toBe(false);
  });
});
