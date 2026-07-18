// W5C: a dynamic-field struct with a FIXED-outer DYNAMIC-element array FIELD (Arr<string,N>,
// Arr<bytes,N>, Arr<u256[],N>, nested Arr<Arr<string,2>,2> / Arr<string[],2>), lifted byte-identical
// to solc 0.8.35 across every codec mirror site: construction (literal + fixed-array-value args),
// memory field read/write/re-point, whole-struct re-encode (return / abi.encode / internal arg),
// storage round-trips (slot-level, incl. long->short overwrite + delete), calldata param decode +
// LAZY field reads (solc's signed access_calldata_tail semantics, probe-verified), abi.decode,
// events (data + packed-padded indexed topics, incl. a P[]-element topic), custom errors, P[]
// arrays of such structs (literal / element field ops / push / new Array zero-init), nested
// dyn-struct fields carrying the family, and the @external @state struct getter.
//
// Family-wide lifts landed alongside (previously JETH900 for EVERY dyn-struct field kind):
// tupleSrc 'call' (return this.mk(c) directly), writeDynStructFromMem nested-dyn-struct recursion
// (this.g = v with a nested dynamic struct), P[] literals of struct VALUES ([a, b] aliasing), and
// double-indexing a leaf-array field (m.g[i][j], also for Cat-C string[][] fields).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => BigInt(n).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const strData = (s: string) => {
  const hex = Buffer.from(s, 'utf8').toString('hex');
  return W(s.length) + (s.length ? hex.padEnd(Math.ceil(hex.length / 64) * 64, '0') : '');
};

async function eqCalls(jeth: string, sol: string, calls: [string, string][], slots: bigint[] = []) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
    expect(JSON.stringify(rj.logs.map((l) => ({ t: l.topics, d: l.data })))).toBe(
      JSON.stringify(rs.logs.map((l) => ({ t: l.topics, d: l.data }))),
    );
  }
  for (const s of slots) {
    expect(await readSlot(hj, aj, s), `slot ${s}`).toBe(await readSlot(hs, as, s));
  }
}

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};

const JP = 'type P = { xs: Arr<string,2>; n: u256 };';
const SP = 'struct P { string[2] xs; uint256 n; }';
const LONG = 'a-long-string-that-certainly-exceeds-31-bytes-for-storage-tail-tests';

describe('W5C: dyn-struct with a fixed-outer dynamic-element array field - byte-identical to solc 0.8.35', () => {
  it('construction + element read/write + whole return + abi.encode + internal pass', async () => {
    await eqCalls(
      `${JP} class C {
        get go(): External<string> { let m: P = P(["aa","bb"], 5n); m.xs[1n] = "zz"; return m.xs[1n]; }
        get re(): External<P> { let m: P = P(["aa","${LONG}"], 5n); return m; }
        get ge(): External<bytes> { let m: P = P(["a","${LONG}"], 7n); return abi.encode(m); }
        bump(p: P): P { p.n = p.n + 1n; p.xs[0n] = "B"; return p; }
        get gi(): External<P> { let m: P = P(["x","y"], 9n); return this.bump(m); }
        get aliasF(): External<string> { let m: P = P(["a","b"], 1n); this.bump(m); return m.xs[0n]; }
        get ln(): External<u256> { let m: P = P(["a","b"], 9n); return m.xs.length; }
        get rp(): External<string> { let m: P = P(["a","b"], 1n); let t: Arr<string,2> = ["e","fff"]; m.xs = t; t[0n] = "MUT"; return m.xs[0n]; } }`,
      `${SP} contract C {
        function go() external pure returns(string memory){ P memory m = P(["aa","bb"], 5); m.xs[1] = "zz"; return m.xs[1]; }
        function re() external pure returns(P memory){ P memory m = P(["aa","${LONG}"], 5); return m; }
        function ge() external pure returns(bytes memory){ P memory m = P(["a","${LONG}"], 7); return abi.encode(m); }
        function bump(P memory p) internal pure returns(P memory){ p.n = p.n + 1; p.xs[0] = "B"; return p; }
        function gi() external pure returns(P memory){ P memory m = P(["x","y"], 9); return bump(m); }
        function alias_() external pure returns(string memory){ P memory m = P(["a","b"], 1); bump(m); return m.xs[0]; }
        function ln() external pure returns(uint256){ P memory m = P(["a","b"], 9); return m.xs.length; }
        function rp() external pure returns(string memory){ P memory m = P(["a","b"], 1); string[2] memory t = ["e","fff"]; m.xs = t; t[0] = "MUT"; return m.xs[0]; } }`,
      [['go()', ''], ['re()', ''], ['ge()', ''], ['gi()', ''], ['ln()', ''], ['rp()', '']],
    );
  });

  it('storage round-trip + long->short overwrite + delete + whole-field assign (slot-level)', async () => {
    await eqCalls(
      `${JP} class C { g: P;
        setLong(): External<void> { this.g = P(["${LONG}","${LONG}2"], 1n); }
        setShort(): External<void> { this.g = P(["s","t"], 2n); }
        fld(): External<void> { this.g.xs = ["${LONG}", "w"]; this.g.n = 3n; }
        del(): External<void> { delete this.g; }
        rt(): External<u256> { let m: P = this.g; m.xs[0n] = "changed"; this.g = m; return this.g.n; }
        get rd(): External<P> { return this.g; }
        get rx(): External<string> { return this.g.xs[0n]; } }`,
      `${SP} contract C { P g;
        function setLong() external { g = P(["${LONG}","${LONG}2"], 1); }
        function setShort() external { g = P(["s","t"], 2); }
        function fld() external { g.xs = ["${LONG}", "w"]; g.n = 3; }
        function del() external { delete g; }
        function rt() external returns(uint256){ P memory m = g; m.xs[0] = "changed"; g = m; return g.n; }
        function rd() external view returns(P memory){ return g; }
        function rx() external view returns(string memory){ return g.xs[0]; } }`,
      [
        ['setLong()', ''], ['rd()', ''], ['setShort()', ''], ['rd()', ''], ['rx()', ''],
        ['fld()', ''], ['rd()', ''], ['rt()', ''], ['rd()', ''], ['setLong()', ''], ['del()', ''], ['rd()', ''],
      ],
      [0n, 1n, 2n],
    );
  });

  it('calldata param: lazy field reads (.length const, element via signed tail access) + decode + echo', async () => {
    const tail = W(0x40) + W(0x80) + strData('abc') + strData('de');
    const args = W(0x20) + W(0x40) + W(11) + tail;
    await eqCalls(
      `${JP} class C {
        get fn(p: P): External<u256> { return p.n; }
        get fx(p: P): External<string> { return p.xs[1n]; }
        get ln(p: P): External<u256> { return p.xs.length; }
        get fd(p: P): External<u256> { let m: P = p; return m.n; }
        get fe(p: P): External<P> { return p; }
        get ff(p: P): External<Arr<string,2>> { return p.xs; }
        get fb(p: P): External<string> { let t: Arr<string,2> = p.xs; return t[0n]; }
        get fw(p: P): External<bytes> { return abi.encode(p); } }`,
      `${SP} contract C {
        function fn(P calldata p) external pure returns(uint256){ return p.n; }
        function fx(P calldata p) external pure returns(string memory){ return p.xs[1]; }
        function ln(P calldata p) external pure returns(uint256){ return p.xs.length; }
        function fd(P calldata p) external pure returns(uint256){ P memory m = p; return m.n; }
        function fe(P calldata p) external pure returns(P memory){ return p; }
        function ff(P calldata p) external pure returns(string[2] memory){ return p.xs; }
        function fb(P calldata p) external pure returns(string memory){ string[2] memory t = p.xs; return t[0]; }
        function fw(P calldata p) external pure returns(bytes memory){ return abi.encode(p); } }`,
      [
        ['fn((string[2],uint256))', args], ['fx((string[2],uint256))', args], ['ln((string[2],uint256))', args],
        ['fd((string[2],uint256))', args], ['fe((string[2],uint256))', args], ['ff((string[2],uint256))', args],
        ['fb((string[2],uint256))', args], ['fw((string[2],uint256))', args],
      ],
    );
  });

  it('malformed calldata: huge/negative field offset (solc signed tail access), truncation, oversized lengths', async () => {
    const MAX = 'f'.repeat(64);
    const mk = (xsOff: string) => W(0x20) + xsOff + W(11) + W(0x40) + W(0x80) + strData('abc') + strData('de');
    const J = `${JP} class C { get fx(p: P): External<string> { return p.xs[1n]; } get fe(p: P): External<P> { return p; } }`;
    const S = `${SP} contract C { function fx(P calldata p) external pure returns(string memory){ return p.xs[1]; } function fe(P calldata p) external pure returns(P memory){ return p; } }`;
    const calls: [string, string][] = [];
    for (const off of [W(0x40), MAX, '8' + '0'.repeat(63), W(2n ** 64n), W(0x10000), W(0)]) {
      calls.push(['fx((string[2],uint256))', mk(off)]);
      calls.push(['fe((string[2],uint256))', mk(off)]);
    }
    // truncated after the table, and a string length running past calldatasize
    calls.push(['fe((string[2],uint256))', W(0x20) + W(0x40) + W(11) + W(0x40) + W(0x80)]);
    calls.push(['fx((string[2],uint256))', W(0x20) + W(0x40) + W(11) + W(0x40) + W(0x80) + W(0x300) + 'aa'.padEnd(64, '0')]);
    await eqCalls(J, S, calls);
  });

  it('abi.decode(b, P) well-formed + malformed', async () => {
    const tail = W(0x40) + W(0x80) + strData('xyz') + strData('w');
    const good = W(0x20) + W(0x40) + W(77) + tail;
    const wrap = (blob: string) => W(0x20) + W(blob.length / 2) + blob;
    await eqCalls(
      `${JP} class C { get go(b: bytes): External<P> { let m: P = abi.decode(b, P); return m; } }`,
      `${SP} contract C { function go(bytes calldata b) external pure returns(P memory){ P memory m = abi.decode(b, (P)); return m; } }`,
      [
        ['go(bytes)', wrap(good)],
        ['go(bytes)', wrap(W(0x20) + W(0x40) + W(77) + W(0x40) + W(0x80))], // truncated tails
        ['go(bytes)', wrap(W(0x20) + 'f'.repeat(64) + W(77) + tail)], // huge field offset
      ],
    );
  });

  it('events: data event + indexed packed-padded topic + P[]-element topic; custom errors', async () => {
    await eqCalls(
      `${JP} class C {
        DataEv: event<{ p: P; tag: u256 }>;
        TopEv: event<{ p: indexed<P>; tag: u256 }>;
        ArrEv: event<{ ps: indexed<P[]> }>;
        Bad: error<{ p: P; code: u256 }>;
        e1(): External<void> { let m: P = P(["aa","${LONG}"], 5n); emit(DataEv(m, 1n)); }
        e2(): External<void> { let m: P = P(["aa","${LONG}"], 5n); emit(TopEv(m, 2n)); }
        e3(): External<void> { let a: P = P(["u","v"], 1n); let b: P = P(["w","${LONG}"], 2n); let ps: P[] = [a, b]; emit(ArrEv(ps)); }
        bo(): External<void> { let m: P = P(["x","y"], 1n); revert(Bad(m, 2n)); } }`,
      `${SP} contract C {
        event DataEv(P p, uint256 tag);
        event TopEv(P indexed p, uint256 tag);
        event ArrEv(P[] indexed ps);
        error Bad(P p, uint256 code);
        function e1() external { P memory m = P(["aa","${LONG}"], 5); emit DataEv(m, 1); }
        function e2() external { P memory m = P(["aa","${LONG}"], 5); emit TopEv(m, 2); }
        function e3() external { P[] memory ps = new P[](2); ps[0] = P(["u","v"], 1); ps[1] = P(["w","${LONG}"], 2); emit ArrEv(ps); }
        function bo() external { P memory m = P(["x","y"], 1); revert Bad(m, 2); } }`,
      [['e1()', ''], ['e2()', ''], ['e3()', ''], ['bo()', '']],
    );
  });

  it('P[] of such structs: literal (value aliasing), element field ops, push/pop/delete, new Array zero-init', async () => {
    await eqCalls(
      `${JP} class C { arr: P[];
        get lit(): External<string> { let a: P = P(["a","b"], 1n); let b: P = P(["c","d"], 2n); let xs: P[] = [a, b]; xs[0n].xs[1n] = "W"; return xs[0n].xs[1n]; }
        ps(): External<void> { this.arr.push(P(["p0","${LONG}"], 7n)); }
        pz(): External<void> { this.arr.push(); }
        pp(): External<void> { this.arr.pop(); }
        dl(): External<void> { delete this.arr; }
        get rd(i: u256): External<P> { return this.arr[i]; }
        get na(): External<P> { let xs: P[] = new Array<P>(2n); return xs[1n]; } }`,
      `${SP} contract C { P[] arr;
        function lit() external pure returns(string memory){ P memory a = P(["a","b"], 1); P memory b = P(["c","d"], 2); P[] memory xs = new P[](2); xs[0]=a; xs[1]=b; xs[0].xs[1] = "W"; return xs[0].xs[1]; }
        function ps() external { arr.push(P(["p0","${LONG}"], 7)); }
        function pz() external { arr.push(); }
        function pp() external { arr.pop(); }
        function dl() external { delete arr; }
        function rd(uint256 i) external view returns(P memory){ return arr[i]; }
        function na() external pure returns(P memory){ P[] memory xs = new P[](2); return xs[1]; } }`,
      [
        ['lit()', ''], ['ps()', ''], ['rd(uint256)', W(0)], ['pz()', ''], ['rd(uint256)', W(1)],
        ['pp()', ''], ['ps()', ''], ['dl()', ''], ['rd(uint256)', W(0)], ['na()', ''],
      ],
      [0n],
    );
  });

  it('nested dyn-struct carrying the family: deep reads/writes, whole re-encode, storage write (recursion lift)', async () => {
    const JN = 'type T = { xs: Arr<string,2>; k: u256 }; type S = { a: u256; t: T };';
    const SN = 'struct T { string[2] xs; uint256 k; } struct S { uint256 a; T t; }';
    await eqCalls(
      `${JN} class C { g: S;
        get rd(): External<string> { let v: S = S(1n, T(["aa","bb"], 7n)); return v.t.xs[1n]; }
        get wr(): External<string> { let v: S = S(1n, T(["aa","bb"], 7n)); v.t.xs[0n] = "zz"; return v.t.xs[0n]; }
        get re(): External<T> { let v: S = S(1n, T(["cc","dd"], 8n)); return v.t; }
        set(): External<void> { let v: S = S(2n, T(["${LONG}","w"], 3n)); this.g = v; }
        get rs(): External<S> { return this.g; }
        get cp(): External<u256> { let v: S = this.g; return v.t.k; } }`,
      `${SN} contract C { S g;
        function rd() external pure returns(string memory){ S memory v = S(1, T(["aa","bb"], 7)); return v.t.xs[1]; }
        function wr() external pure returns(string memory){ S memory v = S(1, T(["aa","bb"], 7)); v.t.xs[0] = "zz"; return v.t.xs[0]; }
        function re() external pure returns(T memory){ S memory v = S(1, T(["cc","dd"], 8)); return v.t; }
        function set() external { S memory v = S(2, T(["${LONG}","w"], 3)); g = v; }
        function rs() external view returns(S memory){ return g; }
        function cp() external returns(uint256){ S memory v = g; return v.t.k; } }`,
      [['rd()', ''], ['wr()', ''], ['re()', ''], ['set()', ''], ['rs()', ''], ['cp()', '']],
      [0n, 1n, 2n, 3n],
    );
  });

  it('deeper nesting: Arr<Arr<string,2>,2> and Arr<string[],2> fields incl double-index reads', async () => {
    await eqCalls(
      `type D = { g: Arr<Arr<string,2>,2>; n: u256 }; type E2 = { g: Arr<string[],2>; n: u256 };
       class C { d: D;
        set(): External<void> { let m: D = D([["a","${LONG}"],["c","d"]], 5n); this.d = m; }
        get rd(): External<D> { return this.d; }
        get rx(): External<string> { return this.d.g[0n][1n]; }
        get mrd(): External<string> { let m: D = D([["a","b"],["c","dd"]], 5n); return m.g[1n][1n]; }
        get mk(): External<E2> { let a: string[] = ["p","qq"]; let b: string[] = []; let m: E2 = E2([a,b], 4n); return m; }
        get el(): External<string> { let a: string[] = ["p","qq"]; let b: string[] = ["r"]; let m: E2 = E2([a,b], 4n); return m.g[0n][1n]; } }`,
      `struct D { string[2][2] g; uint256 n; } struct E2 { string[][2] g; uint256 n; }
       contract C { D d;
        function set() external { D memory m = D([["a","${LONG}"],["c","d"]], 5); d = m; }
        function rd() external view returns(D memory){ return d; }
        function rx() external view returns(string memory){ return d.g[0][1]; }
        function mrd() external pure returns(string memory){ D memory m = D([["a","b"],["c","dd"]], 5); return m.g[1][1]; }
        function mk() external pure returns(E2 memory){ string[] memory a = new string[](2); a[0]="p"; a[1]="qq"; string[] memory b = new string[](0); E2 memory m = E2([a,b], 4); return m; }
        function el() external pure returns(string memory){ string[] memory a = new string[](2); a[0]="p"; a[1]="qq"; string[] memory b = new string[](1); b[0]="r"; E2 memory m = E2([a,b], 4); return m.g[0][1]; } }`,
      [['set()', ''], ['rd()', ''], ['rx()', ''], ['mrd()', ''], ['mk()', ''], ['el()', '']],
      [0n, 1n, 2n, 3n, 4n],
    );
  });

  it('value-leaf Arr<u256[],N> field + mapping values + ternary + zero return via internal call', async () => {
    await eqCalls(
      `type V = { vs: Arr<u256[],2>; n: u256 }; ${JP}
       class C { m: mapping<u256, P>;
        get vv(): External<u256> { let a: u256[] = [1n,2n]; let b: u256[] = [3n]; let m: V = V([a,b], 9n); m.vs[1n][0n] = 42n; return m.vs[0n][1n] + m.vs[1n][0n]; }
        set(k: u256): External<void> { this.m[k] = P(["mk","${LONG}"], k); }
        get rd(k: u256): External<P> { return this.m[k]; }
        get tn(c: bool): External<string> { let a: P = P(["t0","t1"], 1n); let b: P = P(["f0","f1"], 2n); let m: P = c ? a : b; return m.xs[0n]; }
        mk(c: bool): P { if (c) { return P(["y","z"], 3n); } return P(["",""], 0n); }
        get zr(c: bool): External<P> { return this.mk(c); } }`,
      `struct V { uint256[][2] vs; uint256 n; } ${SP}
       contract C { mapping(uint256 => P) m;
        function vv() external pure returns(uint256){ uint256[] memory a = new uint256[](2); a[0]=1;a[1]=2; uint256[] memory b = new uint256[](1); b[0]=3; V memory m = V([a,b], 9); m.vs[1][0] = 42; return m.vs[0][1] + m.vs[1][0]; }
        function set(uint256 k) external { m[k] = P(["mk","${LONG}"], k); }
        function rd(uint256 k) external view returns(P memory){ return m[k]; }
        function tn(bool c) external pure returns(string memory){ P memory a = P(["t0","t1"], 1); P memory b = P(["f0","f1"], 2); P memory m = c ? a : b; return m.xs[0]; }
        function mk(bool c) internal pure returns(P memory){ if (c) { return P(["y","z"], 3); } return P(["",""], 0); }
        function zr(bool c) external pure returns(P memory){ return mk(c); } }`,
      [
        ['vv()', ''], ['set(uint256)', W(7)], ['rd(uint256)', W(7)],
        ['tn(bool)', W(1)], ['tn(bool)', W(0)], ['zr(bool)', W(1)], ['zr(bool)', W(0)],
      ],
      [0n],
    );
  });

  it('@external @state struct getter (array members omitted, like solc)', async () => {
    await eqCalls(
      `${JP} class C { g: Visible<P>; set(): External<void> { this.g = P(["a","b"], 7n); } }`,
      `${SP} contract C { P public g; function set() external { g = P(["a","b"], 7); } }`,
      [['set()', ''], ['g()', '']],
    );
  });

  it('KEPT rejects: const-OOB element index (JETH211), wrong-arity literal, dynamic-array mismatch (both reject)', () => {
    expect(
      codes(`${JP} class C { get go(): External<string> { let m: P = P(["a","b"], 1n); return m.xs[2n]; } }`),
    ).toContain('JETH211');
    expect(
      codes(`${JP} class C { get go(): External<u256> { let m: P = P(["a","b","c"], 1n); return m.n; } }`),
    ).toContain('JETH226');
    expect(
      codes(
        `${JP} class C { get go(): External<u256> { let t: string[] = ["a","b"]; let m: P = P(t, 1n); return m.n; } }`,
      ),
    ).toContain('JETH226');
    // RESIDUAL over-rejection (solc accepts; documented): direct LAZY access to an inner array of an
    // Arr<u256[],N> CALLDATA field has no calldata sub-array codec yet - bind the struct or the whole
    // field to a local first (both byte-identical). The whole-inner read rejects JETH230 at the element
    // dispatch; the double-index form falls to the generic resolver (JETH151). Both clean rejects.
    expect(
      codes(
        `type V = { vs: Arr<u256[],2>; n: u256 }; class C { get go(p: V): External<u256[]> { return p.vs[0n]; } }`,
      ),
    ).toContain('JETH230');
    expect(
      codes(
        `type V = { vs: Arr<u256[],2>; n: u256 }; class C { get go(p: V): External<u256> { return p.vs[0n][0n]; } }`,
      ),
    ).toContain('JETH151');
  });
});
