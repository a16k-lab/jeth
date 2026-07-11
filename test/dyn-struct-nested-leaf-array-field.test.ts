// Cat C: a DYNAMIC-field struct whose field is itself a NESTED-DYNAMIC-LEAF array (bytes[]/string[]/
// T[][]). The field's head word holds an absolute pointer to the SAME B4 pointer-headed image a
// standalone such array uses, so build/read/encode/return/decode delegate to the existing B4 codec.
// Byte-identical to solc 0.8.35. Construction from a constructor (typed array arg) and a struct-
// returning call; reads p.f / p.f[j] / p.f.length; abi.encode / return; abi.decode round-trip
// (well-formed + malformed revert); P[] of such a struct; element writes; storage-struct encode/return.
// Building a memory LOCAL from a storage OR a whole calldata struct source is now lifted byte-identically
// (see test/calldata-leaf-array-struct-bind.test.ts for the calldata-source coverage).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};

async function diff(J: string, S: string, sigs: string[]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const sg of sigs) {
    const rj = await h.call(aj, sel(sg));
    const rs = await h.call(as, sel(sg));
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
  }
}

describe('Cat C: dyn-struct with a nested-dynamic-leaf-array field - byte-identical to solc 0.8.35', () => {
  it('bytes[] field: construct / read / encode / return / call-source / empty / long', async () => {
    const J = `type P = { a: u256; tags: bytes[]; };
    class C {
      get enc(): External<bytes> { let t: bytes[] = [bytes("x"), bytes("yy")]; let p: P = P(1n, t); return abi.encode(p); }
      get read(): External<u256> { let t: bytes[] = [bytes("x"), bytes("yy")]; let p: P = P(1n, t); return p.a + p.tags.length + p.tags[1n].length; }
      get long(): External<bytes> { let t: bytes[] = [bytes("a-much-longer-leaf-past-32-bytes-boundary!!"), bytes("")]; let p: P = P(5n, t); return abi.encode(p); }
      get empty(): External<bytes> { let t: bytes[] = []; let p: P = P(4n, t); return abi.encode(p); }
      mk(): P { let t: bytes[] = [bytes("z")]; return P(8n, t); }
      get fromcall(): External<u256> { let p: P = this.mk(); return p.a + p.tags[0n].length; } }`;
    const S = `struct P { uint256 a; bytes[] tags; }
    contract C {
      function enc() external pure returns(bytes memory){ bytes[] memory t=new bytes[](2); t[0]=bytes("x"); t[1]=bytes("yy"); P memory p=P(1,t); return abi.encode(p); }
      function read() external pure returns(uint256){ bytes[] memory t=new bytes[](2); t[0]=bytes("x"); t[1]=bytes("yy"); P memory p=P(1,t); return p.a + p.tags.length + p.tags[1].length; }
      function long() external pure returns(bytes memory){ bytes[] memory t=new bytes[](2); t[0]=bytes("a-much-longer-leaf-past-32-bytes-boundary!!"); t[1]=bytes(""); P memory p=P(5,t); return abi.encode(p); }
      function empty() external pure returns(bytes memory){ bytes[] memory t=new bytes[](0); P memory p=P(4,t); return abi.encode(p); }
      function mk() internal pure returns(P memory){ bytes[] memory t=new bytes[](1); t[0]=bytes("z"); return P(8,t); }
      function fromcall() external pure returns(uint256){ P memory p=mk(); return p.a + p.tags[0].length; } }`;
    await diff(J, S, ['enc()', 'read()', 'long()', 'empty()', 'fromcall()']);
  });

  it('string[] / u256[][] field + mixed multi-dynamic-field struct + field ordering', async () => {
    const J = `type P = { tags: bytes[]; a: u256; names: string[]; };
    type G = { a: u256; grid: u256[][]; };
    type M = { a: u256; t1: bytes[]; s: bytes; nums: u256[]; t2: string[]; };
    class C {
      get leadenc(): External<bytes> { let t: bytes[] = [bytes("p")]; let n: string[] = ["hi", "yo"]; let p: P = P(t, 3n, n); return abi.encode(p); }
      get leadread(): External<u256> { let t: bytes[] = [bytes("p")]; let n: string[] = ["hi", "yo"]; let p: P = P(t, 3n, n); return p.a + p.tags.length + p.names.length + p.tags[0n].length; }
      get grid(): External<bytes> { let g: u256[][] = [[1n, 2n], [3n]]; let p: G = G(5n, g); return abi.encode(p); }
      get gridread(): External<u256> { let g: u256[][] = [[1n, 2n], [3n]]; let p: G = G(5n, g); return p.grid[0n][1n] + p.grid[1n][0n]; }
      get allkinds(): External<bytes> { let x: bytes[] = [bytes("a"), bytes("bb")]; let nm: u256[] = [5n, 6n, 7n]; let y: string[] = ["q"]; let m: M = M(1n, x, bytes("scalar"), nm, y); return abi.encode(m); }
      get strelem(): External<bytes> { let z: bytes[] = [bytes("z")]; let n: string[] = ["alpha", "beta-longer-than-32-bytes-for-sure-yes!"]; let p: P = P(z, 2n, n); return abi.encode(p.names[1n]); } }`;
    const S = `struct P { bytes[] tags; uint256 a; string[] names; }
    struct G { uint256 a; uint256[][] grid; }
    struct M { uint256 a; bytes[] t1; bytes s; uint256[] nums; string[] t2; }
    contract C {
      function leadenc() external pure returns(bytes memory){ bytes[] memory t=new bytes[](1); t[0]=bytes("p"); string[] memory n=new string[](2); n[0]="hi"; n[1]="yo"; P memory p=P(t,3,n); return abi.encode(p); }
      function leadread() external pure returns(uint256){ bytes[] memory t=new bytes[](1); t[0]=bytes("p"); string[] memory n=new string[](2); n[0]="hi"; n[1]="yo"; P memory p=P(t,3,n); return p.a + p.tags.length + p.names.length + p.tags[0].length; }
      function grid() external pure returns(bytes memory){ uint256[][] memory g=new uint256[][](2); g[0]=new uint256[](2); g[0][0]=1; g[0][1]=2; g[1]=new uint256[](1); g[1][0]=3; G memory p=G(5,g); return abi.encode(p); }
      function gridread() external pure returns(uint256){ uint256[][] memory g=new uint256[][](2); g[0]=new uint256[](2); g[0][0]=1; g[0][1]=2; g[1]=new uint256[](1); g[1][0]=3; G memory p=G(5,g); return p.grid[0][1] + p.grid[1][0]; }
      function allkinds() external pure returns(bytes memory){ bytes[] memory x=new bytes[](2); x[0]=bytes("a"); x[1]=bytes("bb"); uint256[] memory nm=new uint256[](3); nm[0]=5; nm[1]=6; nm[2]=7; string[] memory y=new string[](1); y[0]="q"; M memory m=M(1,x,bytes("scalar"),nm,y); return abi.encode(m); }
      function strelem() external pure returns(bytes memory){ bytes[] memory z=new bytes[](1); z[0]=bytes("z"); string[] memory n=new string[](2); n[0]="alpha"; n[1]="beta-longer-than-32-bytes-for-sure-yes!"; P memory p=P(z,2,n); return abi.encode(p.names[1]); } }`;
    await diff(J, S, ['leadenc()', 'leadread()', 'grid()', 'gridread()', 'allkinds()', 'strelem()']);
  });

  it('P[] of a nested-leaf-field struct: build / element read / encode / new zero-init / element write', async () => {
    const J = `type P = { a: u256; tags: bytes[]; };
    class C {
      get enc(): External<bytes> { let t0: bytes[] = [bytes("x")]; let xs: P[] = new Array<P>(2n); xs[0n] = P(1n, t0); let t1: bytes[] = [bytes("aa"), bytes("bbb")]; xs[1n] = P(2n, t1); return abi.encode(xs); }
      get read(): External<u256> { let t1: bytes[] = [bytes("aa"), bytes("bbb")]; let xs: P[] = new Array<P>(2n); xs[1n] = P(2n, t1); return xs[1n].tags[1n].length + xs[1n].a; }
      get zero(): External<bytes> { let xs: P[] = new Array<P>(2n); return abi.encode(xs); }
      get zeroread(): External<u256> { let xs: P[] = new Array<P>(2n); return xs[0n].tags.length; }
      get ewrite(): External<bytes> { let t: bytes[] = [bytes("x"), bytes("yy")]; let xs: P[] = new Array<P>(1n); xs[0n] = P(1n, t); xs[0n].tags[0n] = bytes("ZZZ"); return abi.encode(xs[0n].tags[0n]); }
      get repoint(): External<bytes> { let t: bytes[] = [bytes("x")]; let xs: P[] = new Array<P>(1n); xs[0n] = P(1n, t); let t2: bytes[] = [bytes("Q"), bytes("RR")]; xs[0n] = P(2n, t2); return abi.encode(xs); } }`;
    const S = `struct P { uint256 a; bytes[] tags; }
    contract C {
      function enc() external pure returns(bytes memory){ bytes[] memory t0=new bytes[](1); t0[0]=bytes("x"); P[] memory xs=new P[](2); xs[0]=P(1,t0); bytes[] memory t1=new bytes[](2); t1[0]=bytes("aa"); t1[1]=bytes("bbb"); xs[1]=P(2,t1); return abi.encode(xs); }
      function read() external pure returns(uint256){ bytes[] memory t1=new bytes[](2); t1[0]=bytes("aa"); t1[1]=bytes("bbb"); P[] memory xs=new P[](2); xs[1]=P(2,t1); return xs[1].tags[1].length + xs[1].a; }
      function zero() external pure returns(bytes memory){ P[] memory xs=new P[](2); return abi.encode(xs); }
      function zeroread() external pure returns(uint256){ P[] memory xs=new P[](2); return xs[0].tags.length; }
      function ewrite() external pure returns(bytes memory){ bytes[] memory t=new bytes[](2); t[0]=bytes("x"); t[1]=bytes("yy"); P[] memory xs=new P[](1); xs[0]=P(1,t); xs[0].tags[0]=bytes("ZZZ"); return abi.encode(xs[0].tags[0]); }
      function repoint() external pure returns(bytes memory){ bytes[] memory t=new bytes[](1); t[0]=bytes("x"); P[] memory xs=new P[](1); xs[0]=P(1,t); bytes[] memory t2=new bytes[](2); t2[0]=bytes("Q"); t2[1]=bytes("RR"); xs[0]=P(2,t2); return abi.encode(xs); } }`;
    await diff(J, S, ['enc()', 'read()', 'zero()', 'zeroread()', 'ewrite()', 'repoint()']);
  });

  it('abi.decode(b, P) round-trip + malformed reverts byte-identical', async () => {
    const J = `type P = { a: u256; tags: bytes[]; };
    class C {
      get dec(d: bytes): External<bytes> { let p: P = abi.decode(d, P); return abi.encode(p); }
      get mk(): External<bytes> { let t: bytes[] = [bytes("aa"), bytes("bbbb")]; let p: P = P(9n, t); return abi.encode(p); } }`;
    const S = `struct P { uint256 a; bytes[] tags; }
    contract C {
      function dec(bytes calldata d) external pure returns(bytes memory){ P memory p=abi.decode(d,(P)); return abi.encode(p); }
      function mk() external pure returns(bytes memory){ bytes[] memory t=new bytes[](2); t[0]=bytes("aa"); t[1]=bytes("bbbb"); P memory p=P(9,t); return abi.encode(p); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const enc = await h.call(as, sel('mk()'));
    const ret = enc.returnHex.slice(2);
    const blen = parseInt(ret.slice(64, 128), 16);
    const blob = ret.slice(128, 128 + blen * 2);
    const eb = (hx: string) => { const len = hx.length / 2; return pad32(BigInt(len)) + hx + '00'.repeat((32 - (len % 32)) % 32); };
    const cases: [string, string][] = [
      ['well-formed', pad32(0x20n) + eb(blob)],
      ['truncated', pad32(0x20n) + eb(blob.slice(0, blob.length - 64))],
      ['tampered-top-offset', pad32(0x20n) + eb(pad32(0x40n) + blob.slice(64))],
    ];
    for (const [label, payload] of cases) {
      const data = sel('dec(bytes)') + payload;
      const rj = await h.call(aj, data);
      const rs = await h.call(as, data);
      expect(rj.success, label).toBe(rs.success);
      expect(rj.returnHex, label).toBe(rs.returnHex);
    }
  });

  it('storage struct with a bytes[]/u256[][] field: abi.encode(this.s) + return this.s', async () => {
    const J = `type P = { a: u256; tags: bytes[]; };
    class C { s: P;
      setup(): External<void> { this.s.a = 7n; this.s.tags.push(bytes("aa")); this.s.tags.push(bytes("bbbb")); }
      get enc(): External<bytes> { return abi.encode(this.s); }
      get ret(): External<P> { return this.s; } }`;
    const S = `struct P { uint256 a; bytes[] tags; }
    contract C { P s;
      function setup() external { s.a=7; s.tags.push(bytes("aa")); s.tags.push(bytes("bbbb")); }
      function enc() external view returns(bytes memory){ return abi.encode(s); }
      function ret() external view returns(P memory){ return s; } }`;
    await diff(J, S, ['setup()', 'enc()', 'ret()']);
  });

  it('W3-Y2c P1-9b: build a memory LOCAL from a STORAGE struct source with a nested-leaf field', async () => {
    // let p: P = this.s / this.recs[i] / this.m[k] (P has a bytes[]/string[]/T[][] field) now COPIES the
    // storage struct into a fresh pointer-headed image (buildDynStructFromStorage builds the field's B4
    // image via abiDecFromStorageToImage). Byte-identical to solc's storage->memory copy.
    const J = `type P = { a: u256; tags: bytes[]; };
    class C { s: P; recs: P[]; m: mapping<address, P>;
      setup(): External<void> { this.s.a = 7n; this.s.tags.push(bytes("aa")); this.s.tags.push(bytes("a-leaf-well-past-the-32-byte-boundary-for-sure!!"));
        this.recs.push(); this.recs[0n].a = 9n; this.recs[0n].tags.push(bytes("rr")); }
      get cA(): External<u256> { let p: P = this.s; return p.a; }
      get cL(): External<u256> { let p: P = this.s; return p.tags.length; }
      get cT(i: u256): External<bytes> { let p: P = this.s; return p.tags[i]; }
      get cW(): External<bytes> { let p: P = this.s; return abi.encode(p); }
      get rA(): External<u256> { let p: P = this.recs[0n]; return p.a + p.tags.length; }
      get rT(): External<bytes> { let p: P = this.recs[0n]; return p.tags[0n]; } }`;
    const S = `struct P { uint256 a; bytes[] tags; }
    contract C { P s; P[] recs; mapping(address => P) m;
      function setup() external { s.a = 7; s.tags.push(bytes("aa")); s.tags.push(bytes("a-leaf-well-past-the-32-byte-boundary-for-sure!!"));
        recs.push(); recs[0].a = 9; recs[0].tags.push(bytes("rr")); }
      function cA() external view returns(uint256){ P memory p = s; return p.a; }
      function cL() external view returns(uint256){ P memory p = s; return p.tags.length; }
      function cT(uint256 i) external view returns(bytes memory){ P memory p = s; return p.tags[i]; }
      function cW() external view returns(bytes memory){ P memory p = s; return abi.encode(p); }
      function rA() external view returns(uint256){ P memory p = recs[0]; return p.a + p.tags.length; }
      function rT() external view returns(bytes memory){ P memory p = recs[0]; return p.tags[0]; } }`;
    await diff(J, S, ['setup()', 'cA()', 'cL()', 'cT(uint256)', 'cW()', 'rA()', 'rT()']);
  });

  it('lifted: calldata whole-param local-binding now compiles; literal-ctor stays a clean reject', () => {
    // building a memory LOCAL from a whole CALLDATA struct PARAM with a nested-leaf field is NOW lifted
    // (byte-identical calldata->memory deep copy via buildDynStructFromCalldataBase's Edge-F branch, the
    // same builder the direct p.tags[i] reads use). Full byte-identical coverage (reads / OOB / malformed
    // flavor / bytes[]/u256[][] leaves / mixed fields / storage + memory sources) lives in
    // test/calldata-leaf-array-struct-bind.test.ts. Here we only assert it no longer clean-rejects.
    const T = 'type P = { a: u256; tags: bytes[]; };\n';
    expect(codes(T + 'class C { get f(q: P): External<u256> { let p: P = q; return p.a; } }')).toEqual([]);
    // an array LITERAL as the constructor arg STILL rejects (JETH226), exactly as solc rejects it.
    expect(codes(T + 'class C { get f(): External<u256> { let p: P = P(1n, [bytes("x")]); return p.a; } }')).toContain('JETH226');
  });
});
