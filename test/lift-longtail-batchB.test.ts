// Long-tail batch B lifts (docs/OR-CATALOGUE.md row A-LIT: array-literal crosses), byte-identical
// to solc 0.8.35:
// B1   ternary over ref-element array literals, both spellings: abi.encode(c ? [a, b] : [b, a]) and
//      let m: Arr<u256[],2> = c ? [a, b] : [b, a] (a/b u256[] locals/params). The ternary lit|lit
//      self-typing now types each branch via the general literal self-typing (selfTypeArrayLit);
//      the fixed-array ternary LOWERING routes each pointer-headed nested-value branch through
//      aggArgToMemPtr (canonical image: literal fresh, memory ALIAS, storage deep-copy) instead of
//      the flat aggToMemPtr; materializeArrayArg gained the ternary->abiEncFromMem tail branch.
//      Closure lifts riding the same machinery: memAggregate-local branches (c ? m1 : m2, aliased),
//      nested ternary chains, STORAGE branches (deep copy, witness-verified), direct indexing
//      (c ? .. : ..)[i][j] and the write-through (c ? m1 : m2)[0n][0n] = v.
// B2   tuple-return of a ref-element literal: g(): [Arr<u256[],2>, u256] { return [[a, b], 5n] }
//      with let [m, n] = this.g(). resolveTupleCall now admits nested value-word array components
//      and flat fixed value arrays (Arr<u256,N>); bindDestructure already registered both. The
//      `return this.g()` tuple FORWARD registers/reads the new component kinds, and
//      encodeReturnTupleInner materializes a DYNAMIC-type array memAggregate component (the
//      forwarded local) as a producer (aggArgToMemPtr alias + abiEncFromMem).
// B3   DYN-outer cd+storage element mix: let m: u256[][] = [a, this.s1]. The Tier-3 L9 cd|storage
//      literal-mix parity gate now fires for the FIXED-outer literal ONLY (the direct solc-literal
//      equivalent, which TypeErrors); the dyn-outer literal is JETH sugar whose verified solc
//      equivalent (new+assign) deep-copies each element by source location - the mix runs.
// B4   cast-typed value-literal self-typing: abi.encode([u256(1n), u256(2n)]) and its ternary.
//      checkExpr's no-expected arrayLit path self-types from INTRINSICALLY typed elements
//      (explicit casts via the literalInt explicitCast flag / bytesN- and address-typed folded
//      literals, typed vars, struct ctors, bool literals); same-family integer casts unify to the
//      WIDEST width ([u8(1n), u256(x)] -> uint256[2], probed at 0.8.35).
// PARITY GATES kept (probed both-reject or deliberate over-rejection):
//  - FIXED-outer cd+storage literal mix rejects (solc "Unable to deduce common type").
//  - bare int-literal elements keep rejecting (L2-MOBILE: solc's mobile uint8 typing not mirrored);
//    the cast+bare mix ([u256(1n), 2n]) stays a deliberate reject for the same reason.
//  - cross-family int casts ([u8(1n), i16(2n)]) both-reject; per-branch length/type mismatch in the
//    literal ternary both-rejects (solc "True expression's type ... does not match").
//  - mixed bytesN widths and enum elements stay deliberate rejects (unverified encode/coerce paths).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const run = async (J: string, S: string, calls: ReadonlyArray<readonly [string, string]>) => {
  const h = await Harness.create();
  await h.fund(me, 10n ** 20n);
  const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
  const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
  for (const [sg, args] of calls) {
    const jr = await h.call(ja, sel(sg) + args);
    const sr = await h.call(sa, sel(sg) + args);
    expect(jr.returnHex, `${sg} ${args.slice(0, 12)}`).toBe(sr.returnHex);
    expect(jr.success, sg).toBe(sr.success);
  }
};
const rejects = (src: string): boolean => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
};

describe('long-tail batch B: array-literal crosses (B1-B4) byte-identical to solc 0.8.35', () => {
  it('B1: ternary over ref-element literals - encode/bind/emit/internal-arg/return, aliasing witnesses', async () => {
    const J = `class C {
  E: event<{ m: Arr<u256[], 2> }>;
  h(m: Arr<u256[], 2>): u256 { return m[0n][0n] * 100n + m[1n].length; }
  get enc(c: bool): External<bytes> {
    let a: u256[] = [1n, 2n]; let b: u256[] = [3n];
    return abi.encode(c ? [a, b] : [b, a]);
  }
  get bind(c: bool): External<u256> {
    let a: u256[] = [1n, 2n]; let b: u256[] = [3n];
    let m: Arr<u256[], 2> = c ? [a, b] : [b, a];
    return m[0n][0n] * 100n + m[1n].length;
  }
  get alias(c: bool): External<u256> {
    let a: u256[] = [1n, 2n]; let b: u256[] = [3n];
    let m: Arr<u256[], 2> = c ? [a, b] : [b, a];
    m[0n][0n] = 99n;
    return a[0n] * 1000n + b[0n];
  }
  get locals(c: bool): External<u256> {
    let a: u256[] = [1n]; let b: u256[] = [2n];
    let m1: Arr<u256[], 2> = [a, a]; let m2: Arr<u256[], 2> = [b, b];
    let m: Arr<u256[], 2> = c ? m1 : m2;
    m[0n][0n] = 88n;
    return m1[0n][0n] * 100n + m2[0n][0n];
  }
  ev(c: bool): External<void> {
    let a: u256[] = [1n, 2n]; let b: u256[] = [3n];
    emit(E(c ? [a, b] : [b, a]));
  }
  get iarg(c: bool): External<u256> {
    let a: u256[] = [7n]; let b: u256[] = [8n, 9n];
    return this.h(c ? [a, b] : [b, a]);
  }
  get ret(c: bool): External<Arr<u256[], 2>> {
    let a: u256[] = [7n]; let b: u256[] = [8n, 9n];
    return c ? [a, b] : [b, a];
  }
  get nest(c: bool, d: bool): External<bytes> {
    let a: u256[] = [1n]; let b: u256[] = [2n];
    return abi.encode(c ? [a, b] : (d ? [b, a] : [a, a]));
  }
  get didx(c: bool): External<u256> {
    let a: u256[] = [11n, 12n]; let b: u256[] = [13n];
    return (c ? [a, b] : [b, a])[0n][0n];
  }
  get twr(c: bool): External<u256> {
    let a: u256[] = [1n]; let b: u256[] = [2n];
    let m1: Arr<u256[], 2> = [a, a]; let m2: Arr<u256[], 2> = [b, b];
    (c ? m1 : m2)[0n][0n] = 66n;
    return m1[0n][0n] * 100n + m2[0n][0n];
  }
  get oob(c: bool, i: u256): External<u256> {
    let a: u256[] = [1n]; let b: u256[] = [2n];
    let m: Arr<u256[], 2> = c ? [a, b] : [b, a];
    return m[i][0n];
  } }`;
    const S = `contract C {
  event E(uint256[][2] m);
  function h(uint256[][2] memory m) internal pure returns (uint256) { return m[0][0] * 100 + m[1].length; }
  function enc(bool c) external pure returns (bytes memory) {
    uint256[] memory a = new uint256[](2); a[0]=1; a[1]=2;
    uint256[] memory b = new uint256[](1); b[0]=3;
    return abi.encode(c ? [a, b] : [b, a]);
  }
  function bind(bool c) external pure returns (uint256) {
    uint256[] memory a = new uint256[](2); a[0]=1; a[1]=2;
    uint256[] memory b = new uint256[](1); b[0]=3;
    uint256[][2] memory m = c ? [a, b] : [b, a];
    return m[0][0] * 100 + m[1].length;
  }
  function alias_(bool c) external pure returns (uint256) {
    uint256[] memory a = new uint256[](2); a[0]=1; a[1]=2;
    uint256[] memory b = new uint256[](1); b[0]=3;
    uint256[][2] memory m = c ? [a, b] : [b, a];
    m[0][0] = 99;
    return a[0] * 1000 + b[0];
  }
  function locals(bool c) external pure returns (uint256) {
    uint256[] memory a = new uint256[](1); a[0]=1;
    uint256[] memory b = new uint256[](1); b[0]=2;
    uint256[][2] memory m1 = [a, a]; uint256[][2] memory m2 = [b, b];
    uint256[][2] memory m = c ? m1 : m2;
    m[0][0] = 88;
    return m1[0][0] * 100 + m2[0][0];
  }
  function ev(bool c) external {
    uint256[] memory a = new uint256[](2); a[0]=1; a[1]=2;
    uint256[] memory b = new uint256[](1); b[0]=3;
    emit E(c ? [a, b] : [b, a]);
  }
  function iarg(bool c) external pure returns (uint256) {
    uint256[] memory a = new uint256[](1); a[0]=7;
    uint256[] memory b = new uint256[](2); b[0]=8; b[1]=9;
    return h(c ? [a, b] : [b, a]);
  }
  function ret(bool c) external pure returns (uint256[][2] memory) {
    uint256[] memory a = new uint256[](1); a[0]=7;
    uint256[] memory b = new uint256[](2); b[0]=8; b[1]=9;
    return c ? [a, b] : [b, a];
  }
  function nest(bool c, bool d) external pure returns (bytes memory) {
    uint256[] memory a = new uint256[](1); a[0]=1;
    uint256[] memory b = new uint256[](1); b[0]=2;
    return abi.encode(c ? [a, b] : (d ? [b, a] : [a, a]));
  }
  function didx(bool c) external pure returns (uint256) {
    uint256[] memory a = new uint256[](2); a[0]=11; a[1]=12;
    uint256[] memory b = new uint256[](1); b[0]=13;
    return (c ? [a, b] : [b, a])[0][0];
  }
  function twr(bool c) external pure returns (uint256) {
    uint256[] memory a = new uint256[](1); a[0]=1;
    uint256[] memory b = new uint256[](1); b[0]=2;
    uint256[][2] memory m1 = [a, a]; uint256[][2] memory m2 = [b, b];
    (c ? m1 : m2)[0][0] = 66;
    return m1[0][0] * 100 + m2[0][0];
  }
  function oob(bool c, uint256 i) external pure returns (uint256) {
    uint256[] memory a = new uint256[](1); a[0]=1;
    uint256[] memory b = new uint256[](1); b[0]=2;
    uint256[][2] memory m = c ? [a, b] : [b, a];
    return m[i][0];
  } }`;
    // JETH `alias` vs solc `alias_` share no selector; compare per-side pairs instead.
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    const pairs: ReadonlyArray<readonly [string, string, string]> = [
      ['enc(bool)', 'enc(bool)', W(1)],
      ['enc(bool)', 'enc(bool)', W(0)],
      ['bind(bool)', 'bind(bool)', W(1)],
      ['bind(bool)', 'bind(bool)', W(0)],
      ['alias(bool)', 'alias_(bool)', W(1)],
      ['alias(bool)', 'alias_(bool)', W(0)],
      ['locals(bool)', 'locals(bool)', W(1)],
      ['locals(bool)', 'locals(bool)', W(0)],
      ['ev(bool)', 'ev(bool)', W(1)],
      ['ev(bool)', 'ev(bool)', W(0)],
      ['iarg(bool)', 'iarg(bool)', W(1)],
      ['iarg(bool)', 'iarg(bool)', W(0)],
      ['ret(bool)', 'ret(bool)', W(1)],
      ['ret(bool)', 'ret(bool)', W(0)],
      ['nest(bool,bool)', 'nest(bool,bool)', W(0) + W(1)],
      ['nest(bool,bool)', 'nest(bool,bool)', W(0) + W(0)],
      ['didx(bool)', 'didx(bool)', W(1)],
      ['didx(bool)', 'didx(bool)', W(0)],
      ['twr(bool)', 'twr(bool)', W(1)],
      ['twr(bool)', 'twr(bool)', W(0)],
      ['oob(bool,uint256)', 'oob(bool,uint256)', W(1) + W(5)], // runtime OOB -> Panic 0x32 parity
    ];
    for (const [jsig, ssig, args] of pairs) {
      const jr = await h.call(ja, sel(jsig) + args);
      const sr = await h.call(sa, sel(ssig) + args);
      expect(jr.returnHex, `${jsig} ${args.slice(0, 12)}`).toBe(sr.returnHex);
      expect(jr.success, jsig).toBe(sr.success);
      // event LOG parity (topics + data) for the emit spelling
      if (jsig.startsWith('ev(')) {
        expect(JSON.stringify(jr.logs), jsig).toBe(JSON.stringify(sr.logs));
      }
    }
    // parity gates: cd|storage mix inside a branch literal both-reject; per-branch length mismatch rejects
    expect(
      rejects(`class C { s1: u256[]; get f(c: bool, a: u256[]): External<bytes> { let b: u256[] = [1n]; return abi.encode(c ? [a, this.s1] : [b, b]); } }`),
    ).toBe(true);
    expect(
      rejects(`class C { get f(c: bool): External<bytes> { let a: u256[] = [1n]; let b: u256[] = [2n]; return abi.encode(c ? [a, b] : [a]); } }`),
    ).toBe(true);
  });

  it('B1 closure: storage branches (deep-copy witness, storage|storage) + storage-WRITE consumer', async () => {
    const J = `class C {
  sA: Arr<u256[], 2>;
  sB: Arr<u256[], 2>;
  v: Arr<u256, 2>;
  seed(): External<void> { this.sA[0n].push(5n); this.sA[1n].push(6n); this.sB[0n].push(7n); this.sB[1n].push(8n); this.sB[1n].push(9n); }
  get stw(c: bool): External<u256> {
    let a: u256[] = [1n]; let b: u256[] = [2n];
    let m: Arr<u256[], 2> = c ? this.sA : [a, b];
    m[0n][0n] = 99n;
    return this.sA[0n][0n] * 1000n + m[0n][0n];
  }
  get stst(c: bool): External<bytes> { return abi.encode(c ? this.sA : this.sB); }
  wr(c: bool): External<void> {
    let a: u256[] = [1n]; let b: u256[] = [2n, 3n];
    this.sA = c ? [a, b] : [b, a];
  }
  wrst(c: bool): External<void> {
    let a: u256[] = [1n];
    this.sA = c ? this.sB : [a, a];
  }
  wrv(c: bool, x: u256): External<void> { this.v = c ? [u256(1n), u256(x)] : [u256(3n), u256(4n)]; }
  get rd(): External<u256> { return this.sA[0n].length * 1000n + this.sA[1n].length * 100n + this.sA[0n][0n] * 10n + this.sA[1n][0n]; }
  get rdv(): External<u256> { return this.v[0n] * 100n + this.v[1n]; } }`;
    const S = `contract C {
  uint256[][2] sA; uint256[][2] sB; uint256[2] v;
  function seed() external { sA[0].push(5); sA[1].push(6); sB[0].push(7); sB[1].push(8); sB[1].push(9); }
  function stw(bool c) external view returns (uint256) {
    uint256[] memory a = new uint256[](1); a[0]=1;
    uint256[] memory b = new uint256[](1); b[0]=2;
    uint256[][2] memory m = c ? sA : [a, b];
    m[0][0] = 99;
    return sA[0][0] * 1000 + m[0][0];
  }
  function stst(bool c) external view returns (bytes memory) { return abi.encode(c ? sA : sB); }
  function wr(bool c) external {
    uint256[] memory a = new uint256[](1); a[0]=1;
    uint256[] memory b = new uint256[](2); b[0]=2; b[1]=3;
    sA = c ? [a, b] : [b, a];
  }
  function wrst(bool c) external {
    uint256[] memory a = new uint256[](1); a[0]=1;
    sA = c ? sB : [a, a];
  }
  function wrv(bool c, uint256 x) external { v = c ? [uint256(1), uint256(x)] : [uint256(3), uint256(4)]; }
  function rd() external view returns (uint256) { return sA[0].length * 1000 + sA[1].length * 100 + sA[0][0] * 10 + sA[1][0]; }
  function rdv() external view returns (uint256) { return v[0] * 100 + v[1]; } }`;
    await run(J, S, [
      ['seed()', ''],
      ['stw(bool)', W(1)],
      ['stw(bool)', W(0)],
      ['stst(bool)', W(1)],
      ['stst(bool)', W(0)],
      ['wr(bool)', W(1)],
      ['rd()', ''],
      ['wr(bool)', W(0)],
      ['rd()', ''],
      ['wrst(bool)', W(1)], // storage branch overwrite (incl. shrink semantics)
      ['rd()', ''],
      ['wrst(bool)', W(0)],
      ['rd()', ''],
      ['wrv(bool,uint256)', W(1) + W(9)],
      ['rdv()', ''],
      ['wrv(bool,uint256)', W(0) + W(9)],
      ['rdv()', ''],
    ] as const);
  });

  it('B1 closure: PUSH consumers (nested element + ternary source, OOB Panic parity)', async () => {
    const J = `class C {
  st: u256[][];
  pe(c: bool): External<u256> {
    let a: u256[] = [1n]; let b: u256[] = [2n, 3n];
    let m: Arr<u256[], 2> = c ? [a, b] : [b, a];
    this.st.push(m[1n]);
    return this.st[0n].length * 10n + this.st[0n][0n];
  }
  pt(c: bool): External<u256> {
    let a: u256[] = [1n]; let b: u256[] = [2n, 3n];
    this.st.push(c ? a : b);
    return this.st[0n].length * 10n + this.st[0n][0n];
  }
  po(i: u256): External<u256> {
    let a: u256[] = [1n]; let b: u256[] = [2n];
    let m: Arr<u256[], 2> = [a, b];
    this.st.push(m[i]);
    return this.st.length;
  } }`;
    const S = `contract C {
  uint256[][] st;
  function pe(bool c) external returns (uint256) {
    uint256[] memory a = new uint256[](1); a[0]=1;
    uint256[] memory b = new uint256[](2); b[0]=2; b[1]=3;
    uint256[][2] memory m = c ? [a, b] : [b, a];
    st.push(m[1]);
    return st[0].length * 10 + st[0][0];
  }
  function pt(bool c) external returns (uint256) {
    uint256[] memory a = new uint256[](1); a[0]=1;
    uint256[] memory b = new uint256[](2); b[0]=2; b[1]=3;
    st.push(c ? a : b);
    return st[0].length * 10 + st[0][0];
  }
  function po(uint256 i) external returns (uint256) {
    uint256[] memory a = new uint256[](1); a[0]=1;
    uint256[] memory b = new uint256[](1); b[0]=2;
    uint256[][2] memory m = [a, b];
    st.push(m[i]);
    return st.length;
  } }`;
    await run(J, S, [
      ['pe(bool)', W(1)],
      ['pe(bool)', W(0)],
      ['pt(bool)', W(1)],
      ['pt(bool)', W(0)],
      ['po(uint256)', W(1)],
      ['po(uint256)', W(7)], // runtime OOB element -> Panic 0x32 parity
    ] as const);
  });

  it('B2: tuple-return of ref-element literals - destructure, forward, external tuple, mutate, internal-arg', async () => {
    const J = `class C {
  g(): [Arr<u256[], 2>, u256] {
    let a: u256[] = [7n, 8n]; let b: u256[] = [9n];
    return [[a, b], 5n];
  }
  gd(): [u256[][], u256] {
    let a: u256[] = [7n, 8n]; let b: u256[] = [9n];
    let m: u256[][] = [a, b];
    return [m, 4n];
  }
  gf(): [Arr<u256, 2>, u256] { return [[7n, 8n], 4n]; }
  h(m: Arr<u256[], 2>, x: u256): u256 { return m[0n][0n] * 100n + m[1n][0n] + x; }
  get f(): External<u256> {
    let [m, n] = this.g();
    return m[0n][1n] * 1000n + m[1n][0n] * 10n + n;
  }
  get fd(): External<u256> {
    let [m, n] = this.gd();
    return m[0n][1n] * 100n + m[1n][0n] * 10n + n;
  }
  get ff(): External<u256> {
    let [m, n] = this.gf();
    return m[0n] * 100n + m[1n] * 10n + n;
  }
  get fw(): External<[Arr<u256[], 2>, u256]> { return this.g(); }
  get fx(): External<[Arr<u256[], 2>, u256]> {
    let a: u256[] = [7n, 8n]; let b: u256[] = [9n];
    return [[a, b], 5n];
  }
  get fm(): External<u256> {
    let [m, n] = this.g();
    m[1n][0n] = 42n;
    return m[0n][0n] * 100n + m[1n][0n] + n;
  }
  get fe(): External<bytes> {
    let [m, n] = this.g();
    return abi.encode(m, n);
  }
  get fh(): External<u256> {
    let a: u256[] = [7n]; let b: u256[] = [9n];
    return this.h([a, b], 3n);
  } }`;
    const S = `contract C {
  function g() internal pure returns (uint256[][2] memory, uint256) {
    uint256[] memory a = new uint256[](2); a[0]=7; a[1]=8;
    uint256[] memory b = new uint256[](1); b[0]=9;
    return ([a, b], 5);
  }
  function gd() internal pure returns (uint256[][] memory, uint256) {
    uint256[] memory a = new uint256[](2); a[0]=7; a[1]=8;
    uint256[] memory b = new uint256[](1); b[0]=9;
    uint256[][] memory m = new uint256[][](2); m[0]=a; m[1]=b;
    return (m, 4);
  }
  function gf() internal pure returns (uint256[2] memory, uint256) { return ([uint256(7), uint256(8)], 4); }
  function h(uint256[][2] memory m, uint256 x) internal pure returns (uint256) { return m[0][0] * 100 + m[1][0] + x; }
  function f() external pure returns (uint256) {
    (uint256[][2] memory m, uint256 n) = g();
    return m[0][1] * 1000 + m[1][0] * 10 + n;
  }
  function fd() external pure returns (uint256) {
    (uint256[][] memory m, uint256 n) = gd();
    return m[0][1] * 100 + m[1][0] * 10 + n;
  }
  function ff() external pure returns (uint256) {
    (uint256[2] memory m, uint256 n) = gf();
    return m[0] * 100 + m[1] * 10 + n;
  }
  function fw() external pure returns (uint256[][2] memory, uint256) { return g(); }
  function fx() external pure returns (uint256[][2] memory, uint256) {
    uint256[] memory a = new uint256[](2); a[0]=7; a[1]=8;
    uint256[] memory b = new uint256[](1); b[0]=9;
    return ([a, b], 5);
  }
  function fm() external pure returns (uint256) {
    (uint256[][2] memory m, uint256 n) = g();
    m[1][0] = 42;
    return m[0][0] * 100 + m[1][0] + n;
  }
  function fe() external pure returns (bytes memory) {
    (uint256[][2] memory m, uint256 n) = g();
    return abi.encode(m, n);
  }
  function fh() external pure returns (uint256) {
    uint256[] memory a = new uint256[](1); a[0]=7;
    uint256[] memory b = new uint256[](1); b[0]=9;
    return h([a, b], 3);
  } }`;
    await run(J, S, [
      ['f()', ''],
      ['fd()', ''],
      ['ff()', ''],
      ['fw()', ''],
      ['fx()', ''],
      ['fm()', ''],
      ['fe()', ''],
      ['fh()', ''],
    ] as const);
  });

  it('B3: dyn-outer cd+storage element mix (deep-copy witness) + fixed-outer gate holds', async () => {
    const J = `class C {
  s1: u256[];
  sb: bytes;
  seed(): External<void> { this.s1.push(11n); this.s1.push(22n); this.sb = bytes("st"); }
  get mix(a: u256[]): External<u256> {
    let m: u256[][] = [a, this.s1];
    return m[0n][0n] * 1000n + m[1n][1n];
  }
  get wit(a: u256[]): External<u256> {
    let m: u256[][] = [a, this.s1];
    m[0n][0n] = 77n; m[1n][0n] = 88n;
    return this.s1[0n] * 10000n + m[0n][0n] * 100n + m[1n][0n];
  }
  get bmix(b: bytes): External<u256> {
    let m: bytes[] = [b, this.sb];
    return m[0n].length * 100n + m[1n].length;
  } }`;
    const S = `contract C {
  uint256[] s1;
  bytes sb;
  function seed() external { s1.push(11); s1.push(22); sb = "st"; }
  function mix(uint256[] calldata a) external view returns (uint256) {
    uint256[][] memory m = new uint256[][](2);
    m[0] = a; m[1] = s1;
    return m[0][0] * 1000 + m[1][1];
  }
  function wit(uint256[] calldata a) external view returns (uint256) {
    uint256[][] memory m = new uint256[][](2);
    m[0] = a; m[1] = s1;
    m[0][0] = 77; m[1][0] = 88;
    return s1[0] * 10000 + m[0][0] * 100 + m[1][0];
  }
  function bmix(bytes calldata b) external view returns (uint256) {
    bytes[] memory m = new bytes[](2);
    m[0] = b; m[1] = sb;
    return m[0].length * 100 + m[1].length;
  } }`;
    await run(J, S, [
      ['seed()', ''],
      ['mix(uint256[])', W(0x20) + W(1) + W(5)],
      ['wit(uint256[])', W(0x20) + W(1) + W(5)],
      ['bmix(bytes)', W(0x20) + W(3) + 'aabbcc' + '0'.repeat(58)],
    ] as const);
    // the FIXED-outer cd+storage literal mix stays rejected (solc TypeErrors the direct literal)
    expect(
      rejects(`class C { s1: u256[]; get f(a: u256[]): External<u256> { let m: Arr<u256[], 2> = [a, this.s1]; return m[0n][0n]; } }`),
    ).toBe(true);
  });

  it('B4: cast-typed literal self-typing - widths, families, ternary, runtime truncation, gates', async () => {
    const J = `class C {
  get base(): External<bytes> { return abi.encode([u256(1n), u256(2n)]); }
  get tern(c: bool, x: u256): External<bytes> { return abi.encode(c ? [u256(1n), u256(x)] : [u256(3n), u256(0n)]); }
  get u8s(): External<bytes> { return abi.encode([u8(1n), u8(200n)]); }
  get mixw(): External<bytes> { return abi.encode([u8(1n), u256(2n)]); }
  get i8w(x: i256): External<bytes> { return abi.encode([i8(-1n), i256(x)]); }
  get addrs(a: address): External<bytes> { return abi.encode([address(a), address(0x1111111111111111111111111111111111111111)]); }
  get bools(): External<bytes> { return abi.encode([true, false]); }
  get rt(x: u256): External<bytes> { return abi.encode([u8(x), u8(7n)]); }
  get strs(): External<bytes> { let a: string = "ab"; let b: string = "cde"; return abi.encode([a, b]); }
  get bnd(c: bool, x: u256): External<u256> { let m: Arr<u256, 2> = c ? [u256(1n), u256(x)] : [u256(3n), u256(0n)]; return m[0n] * 1000n + m[1n]; }
  get pck(): External<bytes> { return abi.encodePacked([u8(1n), u8(2n)]); } }`;
    const S = `contract C {
  function base() external pure returns (bytes memory) { return abi.encode([uint256(1), uint256(2)]); }
  function tern(bool c, uint256 x) external pure returns (bytes memory) { return abi.encode(c ? [uint256(1), uint256(x)] : [uint256(3), uint256(0)]); }
  function u8s() external pure returns (bytes memory) { return abi.encode([uint8(1), uint8(200)]); }
  function mixw() external pure returns (bytes memory) { return abi.encode([uint8(1), uint256(2)]); }
  function i8w(int256 x) external pure returns (bytes memory) { return abi.encode([int8(-1), int256(x)]); }
  function addrs(address a) external pure returns (bytes memory) { return abi.encode([address(a), address(0x1111111111111111111111111111111111111111)]); }
  function bools() external pure returns (bytes memory) { return abi.encode([true, false]); }
  function rt(uint256 x) external pure returns (bytes memory) { return abi.encode([uint8(x), uint8(7)]); }
  function strs() external pure returns (bytes memory) { string memory a = "ab"; string memory b = "cde"; return abi.encode([a, b]); }
  function bnd(bool c, uint256 x) external pure returns (uint256) { uint256[2] memory m = c ? [uint256(1), uint256(x)] : [uint256(3), uint256(0)]; return m[0] * 1000 + m[1]; }
  function pck() external pure returns (bytes memory) { return abi.encodePacked([uint8(1), uint8(2)]); } }`;
    await run(J, S, [
      ['base()', ''],
      ['tern(bool,uint256)', W(1) + W(77)],
      ['tern(bool,uint256)', W(0) + W(77)],
      ['u8s()', ''],
      ['mixw()', ''],
      ['i8w(int256)', 'f'.repeat(64)],
      ['i8w(int256)', W(7)],
      ['addrs(address)', W(0x2222)],
      ['bools()', ''],
      ['rt(uint256)', W(300)], // runtime u8(x) truncation parity
      ['rt(uint256)', W(255)],
      ['strs()', ''],
      ['bnd(bool,uint256)', W(1) + W(9)],
      ['bnd(bool,uint256)', W(0) + W(9)],
      ['pck()', ''],
    ] as const);
    // OR cluster 4 lifted both bare-literal and mixed-bytesN self-typing. BARE integer-literal arrays
    // now self-type to solc's mobile common type (all-nonneg -> u256, all-neg -> i256): abi.encode and
    // encodePacked pad every element to a 32-byte word regardless of width, so the encoding is
    // width-independent and byte-identical to solc's uint8[2]/etc. Mixed bytesN widths widen (A-LIT-RESID).
    // Still rejected: the cast+BARE MIX (a cast fixes one width, a bare literal is mobile - no common
    // type), CROSS-FAMILY casts (u8|i16, no common type), and MIXED-SIGN bare literals. Enum elements
    // now self-type to the enum's fixed array (see the enum gate below) - byte-identical to solc.
    expect(rejects(`class C { get f(): External<bytes> { return abi.encode([1n, 2n]); } }`)).toBe(false);
    expect(rejects(`class C { get f(): External<bytes> { return abi.encode([u256(1n), 2n]); } }`)).toBe(true);
    expect(rejects(`class C { get f(): External<bytes> { return abi.encode([u8(1n), i16(2n)]); } }`)).toBe(true);
    expect(rejects(`class C { get f(): External<bytes> { return abi.encode([1n, -1n]); } }`)).toBe(true);
    expect(
      rejects(`class C { get f(): External<bytes> { return abi.encode([bytes4(0x11223344n), bytes8(0x1122334455667788n)]); } }`),
    ).toBe(false);
    // A-LIT-RESID(enum) LIFTED: a same-enum literal self-types to the enum's fixed array (Color[N]) and
    // encodes byte-identical to solc (an enum is a value word); two DIFFERENT enums have no common type
    // so JETH keeps rejecting (parity). Full byte-identity is pinned in lift-enum-array-literal.test.ts.
    expect(
      rejects(`enum Color { Red, Green, Blue } class C { get f(): External<bytes> { return abi.encode([Color.Green, Color.Blue]); } }`),
    ).toBe(false);
    expect(
      rejects(`enum Color { Red, Green, Blue } enum St { Off, On } class C { get f(): External<bytes> { return abi.encode([Color.Green, St.On]); } }`),
    ).toBe(true);
  });
});
