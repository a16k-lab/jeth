// @external auto-generated getters: parameterized mapping/array getters and struct-flattening
// getters, byte-identical to solc 0.8.35. (Bucket-A "what's left" #4 over-rejection fix.)
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);
const A1 = '00'.repeat(12) + '1111111111111111111111111111111111111111';
const A2 = '00'.repeat(12) + '2222222222222222222222222222222222222222';

async function diff(jeth: string, sol: string, calls: { sig: string; args?: string }[]) {
  const jb = compile(jeth, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jb.creationBytecode);
  const as = await hs.deploy(sb.creation);
  for (const c of calls) {
    const data = '0x' + sel(c.sig) + (c.args ?? '');
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig}: returndata`).toBe(rs.returnHex);
  }
}

function jethRejects(jeth: string): boolean {
  try {
    compile(jeth, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
}
function solcAccepts(sol: string): boolean {
  try {
    compileSolidity(SPDX + sol, 'C');
    return true;
  } catch {
    return false;
  }
}

describe('@external parameterized getters vs Solidity', () => {
  it('mapping(address=>uint256) getter', async () => {
    await diff(
      `class C { balances: Visible<mapping<address,u256>>; set(k: address, v: u256): External<void> { this.balances[k] = v; } }`,
      `contract C { mapping(address=>uint256) public balances; function set(address k, uint256 v) external { balances[k] = v; } }`,
      [
        { sig: 'set(address,uint256)', args: A1 + W(42n) },
        { sig: 'balances(address)', args: A1 },
        { sig: 'balances(address)', args: A2 },
      ],
    );
  });

  it('nested mapping getter (two key params)', async () => {
    await diff(
      `class C { allowance: Visible<mapping<address,mapping<address,u256>>>; set(a: address, b: address, v: u256): External<void> { this.allowance[a][b] = v; } }`,
      `contract C { mapping(address=>mapping(address=>uint256)) public allowance; function set(address a, address b, uint256 v) external { allowance[a][b] = v; } }`,
      [
        { sig: 'set(address,address,uint256)', args: A1 + A2 + W(99n) },
        { sig: 'allowance(address,address)', args: A1 + A2 },
        { sig: 'allowance(address,address)', args: A2 + A1 },
      ],
    );
  });

  it('mapping with a small (uint8/int8) value masks correctly', async () => {
    await diff(
      `class C { u: Visible<mapping<u256,u8>>; s: Visible<mapping<u256,i8>>; setu(k: u256, v: u8): External<void> { this.u[k] = v; } sets(k: u256, v: i8): External<void> { this.s[k] = v; } }`,
      `contract C { mapping(uint256=>uint8) public u; mapping(uint256=>int8) public s; function setu(uint256 k, uint8 v) external { u[k]=v; } function sets(uint256 k, int8 v) external { s[k]=v; } }`,
      [
        { sig: 'setu(uint256,uint8)', args: W(1n) + W(200n) },
        { sig: 'u(uint256)', args: W(1n) },
        { sig: 'u(uint256)', args: W(9n) },
        { sig: 'sets(uint256,int8)', args: W(1n) + W((1n << 256n) - 5n) },
        { sig: 's(uint256)', args: W(1n) },
      ],
    );
  });

  it('mapping(address=>bytes) getter', async () => {
    await diff(
      `class C { blobs: Visible<mapping<address,bytes>>; set(k: address, v: bytes): External<void> { this.blobs[k] = v; } }`,
      `contract C { mapping(address=>bytes) public blobs; function set(address k, bytes calldata v) external { blobs[k] = v; } }`,
      [
        { sig: 'set(address,bytes)', args: A1 + W(0x40n) + W(3n) + 'aabbcc'.padEnd(64, '0') },
        { sig: 'blobs(address)', args: A1 },
        { sig: 'blobs(address)', args: A2 },
      ],
    );
  });

  it('mapping(uint=>uint[]) getter (key + index params)', async () => {
    await diff(
      `class C { m2: Visible<mapping<u256,u256[]>>; push(k: u256, v: u256): External<void> { this.m2[k].push(v); } }`,
      `contract C { mapping(uint256=>uint256[]) public m2; function push(uint256 k, uint256 v) external { m2[k].push(v); } }`,
      [
        { sig: 'push(uint256,uint256)', args: W(5n) + W(111n) },
        { sig: 'push(uint256,uint256)', args: W(5n) + W(222n) },
        { sig: 'm2(uint256,uint256)', args: W(5n) + W(0n) },
        { sig: 'm2(uint256,uint256)', args: W(5n) + W(1n) },
        { sig: 'm2(uint256,uint256)', args: W(5n) + W(9n) },
      ],
    );
  });

  it('dynamic array getter (out-of-bounds Panic parity)', async () => {
    await diff(
      `class C { arr: Visible<u256[]>; push(v: u256): External<void> { this.arr.push(v); } }`,
      `contract C { uint256[] public arr; function push(uint256 v) external { arr.push(v); } }`,
      [
        { sig: 'push(uint256)', args: W(7n) },
        { sig: 'push(uint256)', args: W(8n) },
        { sig: 'arr(uint256)', args: W(0n) },
        { sig: 'arr(uint256)', args: W(1n) },
        { sig: 'arr(uint256)', args: W(5n) },
      ],
    );
  });

  it('fixed array getter (out-of-bounds Panic parity)', async () => {
    await diff(
      `class C { fa: Visible<Arr<u256,3>>; set(i: u256, v: u256): External<void> { this.fa[i] = v; } }`,
      `contract C { uint256[3] public fa; function set(uint256 i, uint256 v) external { fa[i] = v; } }`,
      [
        { sig: 'set(uint256,uint256)', args: W(1n) + W(55n) },
        { sig: 'fa(uint256)', args: W(0n) },
        { sig: 'fa(uint256)', args: W(1n) },
        { sig: 'fa(uint256)', args: W(3n) },
      ],
    );
  });

  it('string[] getter (element returned)', async () => {
    await diff(
      `class C { names: Visible<string[]>; push(s: string): External<void> { this.names.push(s); } }`,
      `contract C { string[] public names; function push(string calldata s) external { names.push(s); } }`,
      [
        { sig: 'push(string)', args: W(0x20n) + W(2n) + '7878'.padEnd(64, '0') },
        { sig: 'names(uint256)', args: W(0n) },
      ],
    );
  });
});

describe('@external struct-flattening getters vs Solidity', () => {
  it('value + packed fields', async () => {
    await diff(
      `type P = { a: u8; b: u16; c: u32; owner: address; flag: bool; x: u256; }; class C { p: Visible<P>; set(): External<void> { this.p.a = 200n; this.p.b = 50000n; this.p.c = 4000000000n; this.p.owner = msg.sender; this.p.flag = true; this.p.x = 42n; } }`,
      `struct P { uint8 a; uint16 b; uint32 c; address owner; bool flag; uint256 x; } contract C { P public p; function set() external { p.a=200; p.b=50000; p.c=4000000000; p.owner=msg.sender; p.flag=true; p.x=42; } }`,
      [{ sig: 'set()' }, { sig: 'p()' }],
    );
  });

  it('bytes/string fields (dynamic members in the returned tuple)', async () => {
    await diff(
      `type P = { x: u256; name: string; y: u256; data: bytes; }; class C { p: Visible<P>; set(): External<void> { this.p.x = 7n; this.p.name = "hi"; this.p.y = 9n; this.p.data = msg.data; } }`,
      `struct P { uint256 x; string name; uint256 y; bytes data; } contract C { P public p; function set() external { p.x=7; p.name="hi"; p.y=9; p.data=msg.data; } }`,
      [{ sig: 'set()' }, { sig: 'p()' }],
    );
  });

  it('omits array and mapping members (declaration order preserved)', async () => {
    await diff(
      `type P = { x: u256; arr: u256[]; y: u256; }; class C { p: Visible<P>; set(): External<void> { this.p.x = 11n; this.p.y = 22n; this.p.arr.push(5n); } }`,
      `struct P { uint256 x; uint256[] arr; uint256 y; } contract C { P public p; function set() external { p.x=11; p.y=22; p.arr.push(5); } }`,
      [{ sig: 'set()' }, { sig: 'p()' }],
    );
    await diff(
      `type P = { x: u256; m: mapping<u256,u256>; y: u256; }; class C { p: Visible<P>; set(): External<void> { this.p.x = 11n; this.p.y = 22n; this.p.m[3n] = 9n; } }`,
      `struct P { uint256 x; mapping(uint256=>uint256) m; uint256 y; } contract C { P public p; function set() external { p.x=11; p.y=22; p.m[3]=9; } }`,
      [{ sig: 'set()' }, { sig: 'p()' }],
    );
  });
});

describe('@external struct getters reached via mapping/array + nested structs vs Solidity', () => {
  it('mapping(K=>Struct) getter (present + absent key -> zero struct, no revert)', async () => {
    await diff(
      `type P = { x: u256; o: address; }; class C { m: Visible<mapping<u256,P>>; set(k: u256): External<void> { this.m[k].x = 7n; this.m[k].o = address(0x111n); } }`,
      `struct P { uint256 x; address o; } contract C { mapping(uint256=>P) public m; function set(uint256 k) external { m[k].x=7; m[k].o=address(0x111); } }`,
      [
        { sig: 'set(uint256)', args: W(5n) },
        { sig: 'm(uint256)', args: W(5n) },
        { sig: 'm(uint256)', args: W(9n) },
      ],
    );
  });

  it('Struct[] getter (in-bounds + OOB empty revert) and Arr<Struct,N>', async () => {
    await diff(
      `type P = { x: u256; o: address; }; class C { a: Visible<P[]>; push(x: u256): External<void> { this.a.push(P(x, address(0x222n))); } }`,
      `struct P { uint256 x; address o; } contract C { P[] public a; function push(uint256 x) external { a.push(P(x, address(0x222))); } }`,
      [
        { sig: 'push(uint256)', args: W(7n) },
        { sig: 'a(uint256)', args: W(0n) },
        { sig: 'a(uint256)', args: W(5n) },
      ],
    );
    await diff(
      `type P = { x: u256; o: address; }; class C { a: Visible<Arr<P,3>>; set(i: u256, x: u256): External<void> { this.a[i] = P(x, address(0x555n)); } }`,
      `struct P { uint256 x; address o; } contract C { P[3] public a; function set(uint256 i, uint256 x) external { a[i] = P(x, address(0x555)); } }`,
      [
        { sig: 'set(uint256,uint256)', args: W(1n) + W(8n) },
        { sig: 'a(uint256)', args: W(1n) },
        { sig: 'a(uint256)', args: W(5n) },
      ],
    );
  });

  it('mapping(K=>Struct[]) getter (key + index params)', async () => {
    await diff(
      `type P = { x: u256; o: address; }; class C { m: Visible<mapping<u256,P[]>>; push(k: u256, x: u256): External<void> { this.m[k].push(P(x, address(0x444n))); } }`,
      `struct P { uint256 x; address o; } contract C { mapping(uint256=>P[]) public m; function push(uint256 k, uint256 x) external { m[k].push(P(x, address(0x444))); } }`,
      [
        { sig: 'push(uint256,uint256)', args: W(1n) + W(9n) },
        { sig: 'm(uint256,uint256)', args: W(1n) + W(0n) },
        { sig: 'm(uint256,uint256)', args: W(1n) + W(7n) },
      ],
    );
  });

  it('nested static struct is flattened inline (dynamic array + mapping members omitted)', async () => {
    await diff(
      `type I = { a: u256; b: address; }; type O = { x: u256; inner: I; z: u256; }; class C { o: Visible<O>; set(): External<void> { this.o.x = 1n; this.o.inner.a = 2n; this.o.inner.b = address(0x333n); this.o.z = 4n; } }`,
      `struct I { uint256 a; address b; } struct O { uint256 x; I inner; uint256 z; } contract C { O public o; function set() external { o.x=1; o.inner.a=2; o.inner.b=address(0x333); o.z=4; } }`,
      [{ sig: 'set()' }, { sig: 'o()' }],
    );
  });

  it('string/bytes-key mapping getters', async () => {
    await diff(
      `class C { m: Visible<mapping<string,u256>>; set(k: string, v: u256): External<void> { this.m[k] = v; } }`,
      `contract C { mapping(string=>uint256) public m; function set(string calldata k, uint256 v) external { m[k] = v; } }`,
      [
        { sig: 'set(string,uint256)', args: W(0x40n) + W(42n) + W(2n) + '6869'.padEnd(64, '0') },
        { sig: 'm(string)', args: W(0x20n) + W(2n) + '6869'.padEnd(64, '0') },
      ],
    );
    await diff(
      `class C { m: Visible<mapping<bytes,address>>; set(k: bytes, v: address): External<void> { this.m[k] = v; } }`,
      `contract C { mapping(bytes=>address) public m; function set(bytes calldata k, address v) external { m[k] = v; } }`,
      [
        { sig: 'set(bytes,address)', args: W(0x40n) + W(0x111n) + W(3n) + 'aabbcc'.padEnd(64, '0') },
        { sig: 'm(bytes)', args: W(0x20n) + W(3n) + 'aabbcc'.padEnd(64, '0') },
      ],
    );
  });
});

describe('@external nested-array / fixed-array getters vs Solidity', () => {
  it('nested array T[][] (and T[][][]) value getter, incl OOB empty-revert', async () => {
    await diff(
      `class C { d: Visible<u256[][]>; nr(): External<void> { this.d.push(); } add(i: u256, v: u256): External<void> { this.d[i].push(v); } }`,
      `contract C { uint256[][] public d; function nr() external { d.push(); } function add(uint256 i, uint256 v) external { d[i].push(v); } }`,
      [
        { sig: 'nr()' },
        { sig: 'add(uint256,uint256)', args: W(0n) + W(7n) },
        { sig: 'add(uint256,uint256)', args: W(0n) + W(8n) },
        { sig: 'd(uint256,uint256)', args: W(0n) + W(0n) },
        { sig: 'd(uint256,uint256)', args: W(0n) + W(1n) },
        { sig: 'd(uint256,uint256)', args: W(0n) + W(5n) },
        { sig: 'd(uint256,uint256)', args: W(3n) + W(0n) },
      ],
    );
    await diff(
      `class C { d: Visible<u256[][][]>; seed(): External<void> { this.d.push(); this.d[0n].push(); this.d[0n][0n].push(77n); } }`,
      `contract C { uint256[][][] public d; function seed() external { d.push(); d[0].push(); d[0][0].push(77); } }`,
      [
        { sig: 'seed()' },
        { sig: 'd(uint256,uint256,uint256)', args: W(0n) + W(0n) + W(0n) },
        { sig: 'd(uint256,uint256,uint256)', args: W(0n) + W(0n) + W(9n) },
      ],
    );
  });

  it('packed nested array u8[][] value getter', async () => {
    await diff(
      `class C { d: Visible<u8[][]>; nr(): External<void> { this.d.push(); } add(i: u256, v: u8): External<void> { this.d[i].push(v); } }`,
      `contract C { uint8[][] public d; function nr() external { d.push(); } function add(uint256 i, uint8 v) external { d[i].push(v); } }`,
      [
        { sig: 'nr()' },
        { sig: 'add(uint256,uint8)', args: W(0n) + W(200n) },
        { sig: 'add(uint256,uint8)', args: W(0n) + W(99n) },
        { sig: 'd(uint256,uint256)', args: W(0n) + W(0n) },
        { sig: 'd(uint256,uint256)', args: W(0n) + W(1n) },
        { sig: 'd(uint256,uint256)', args: W(0n) + W(9n) },
      ],
    );
  });

  it('mapping(K=>Arr<T,N>) value getter (whole-slot + packed)', async () => {
    await diff(
      `class C { m: Visible<mapping<u256,Arr<u256,3>>>; set(k: u256, i: u256, v: u256): External<void> { this.m[k][i] = v; } }`,
      `contract C { mapping(uint256=>uint256[3]) public m; function set(uint256 k, uint256 i, uint256 v) external { m[k][i]=v; } }`,
      [
        { sig: 'set(uint256,uint256,uint256)', args: W(5n) + W(1n) + W(42n) },
        { sig: 'm(uint256,uint256)', args: W(5n) + W(1n) },
        { sig: 'm(uint256,uint256)', args: W(5n) + W(0n) },
        { sig: 'm(uint256,uint256)', args: W(5n) + W(3n) },
      ],
    );
    await diff(
      `class C { m: Visible<mapping<u256,Arr<u8,4>>>; set(k: u256, i: u256, v: u8): External<void> { this.m[k][i] = v; } }`,
      `contract C { mapping(uint256=>uint8[4]) public m; function set(uint256 k, uint256 i, uint8 v) external { m[k][i]=v; } }`,
      [
        { sig: 'set(uint256,uint256,uint8)', args: W(2n) + W(3n) + W(123n) },
        { sig: 'm(uint256,uint256)', args: W(2n) + W(3n) },
        { sig: 'm(uint256,uint256)', args: W(2n) + W(0n) },
        { sig: 'm(uint256,uint256)', args: W(2n) + W(4n) },
      ],
    );
  });

  it('struct fixed-array member: TOP struct omits it; a NESTED struct includes it', async () => {
    // top-level: fixed array omitted (solc returns only x, y)
    await diff(
      `type P = { x: u256; arr: Arr<u256,3>; y: address; }; class C { p: Visible<P>; set(): External<void> { this.p.x = 1n; this.p.arr[0n] = 10n; this.p.y = address(0x111n); } }`,
      `struct P { uint256 x; uint256[3] arr; address y; } contract C { P public p; function set() external { p.x=1; p.arr[0]=10; p.y=address(0x111); } }`,
      [{ sig: 'set()' }, { sig: 'p()' }],
    );
    // nested static struct: its fixed array IS included (solc returns x, a, arr[0..2])
    await diff(
      `type I = { a: u256; arr: Arr<u256,3>; }; type O = { x: u256; inner: I; }; class C { o: Visible<O>; set(): External<void> { this.o.x = 1n; this.o.inner.a = 2n; this.o.inner.arr[0n] = 7n; this.o.inner.arr[2n] = 9n; } }`,
      `struct I { uint256 a; uint256[3] arr; } struct O { uint256 x; I inner; } contract C { O public o; function set() external { o.x=1; o.inner.a=2; o.inner.arr[0]=7; o.inner.arr[2]=9; } }`,
      [{ sig: 'set()' }, { sig: 'o()' }],
    );
  });
});

describe('@external getters with a nested DYNAMIC struct member vs Solidity', () => {
  it('struct var with a nested struct that has a string member', async () => {
    await diff(
      `type Meta = { name: string; ts: u256; }; type Item = { id: u256; meta: Meta; active: bool; }; class C { item: Visible<Item>; set(): External<void> { this.item.id = 7n; this.item.meta.name = "alice"; this.item.meta.ts = 99n; this.item.active = true; } }`,
      `struct Meta { string name; uint256 ts; } struct Item { uint256 id; Meta meta; bool active; } contract C { Item public item; function set() external { item.id=7; item.meta.name="alice"; item.meta.ts=99; item.active=true; } }`,
      [{ sig: 'set()' }, { sig: 'item()' }],
    );
  });

  it('nested struct with bytes + a dynamic array member', async () => {
    await diff(
      `type I = { data: bytes; xs: u256[]; }; type O = { x: u256; inner: I; y: address; }; class C { o: Visible<O>; set(): External<void> { this.o.x = 1n; this.o.inner.data = msg.data; this.o.inner.xs.push(5n); this.o.inner.xs.push(6n); this.o.y = address(0xabn); } }`,
      `struct I { bytes data; uint256[] xs; } struct O { uint256 x; I inner; address y; } contract C { O public o; function set() external { o.x=1; o.inner.data=msg.data; o.inner.xs.push(5); o.inner.xs.push(6); o.y=address(0xab); } }`,
      [{ sig: 'set()' }, { sig: 'o()' }],
    );
  });

  it('triple-nested dynamic struct', async () => {
    await diff(
      `type D3 = { s: string; }; type D2 = { m: u256; c: D3; }; type D1 = { n: u256; b: D2; }; class C { a: Visible<D1>; set(): External<void> { this.a.n = 1n; this.a.b.m = 2n; this.a.b.c.s = "deep"; } }`,
      `struct D3 { string s; } struct D2 { uint256 m; D3 c; } struct D1 { uint256 n; D2 b; } contract C { D1 public a; function set() external { a.n=1; a.b.m=2; a.b.c.s="deep"; } }`,
      [{ sig: 'set()' }, { sig: 'a()' }],
    );
  });

  it('dynamic nested struct reached THROUGH a mapping / array (runtime slot)', async () => {
    await diff(
      `type I = { s: string; }; type O = { x: u256; inner: I; y: address; }; class C { m: Visible<mapping<u256,O>>; set(k: u256): External<void> { this.m[k].x = 7n; this.m[k].inner.s = "hey"; this.m[k].y = address(0x9n); } }`,
      `struct I { string s; } struct O { uint256 x; I inner; address y; } contract C { mapping(uint256=>O) public m; function set(uint256 k) external { m[k].x=7; m[k].inner.s="hey"; m[k].y=address(0x9); } }`,
      [
        { sig: 'set(uint256)', args: W(3n) },
        { sig: 'm(uint256)', args: W(3n) },
        { sig: 'm(uint256)', args: W(8n) },
      ],
    );
    await diff(
      `type I = { s: string; }; type O = { x: u256; inner: I; }; class C { a: Visible<O[]>; push(x: u256, s: string): External<void> { let i: u256 = this.a.length; this.a.push(); this.a[i].x = x; this.a[i].inner.s = s; } }`,
      `struct I { string s; } struct O { uint256 x; I inner; } contract C { O[] public a; function push(uint256 x, string calldata s) external { a.push(); a[a.length-1].x=x; a[a.length-1].inner.s=s; } }`,
      [
        { sig: 'push(uint256,string)', args: W(0x40n) + W(11n) + W(2n) + '7a7a'.padEnd(64, '0') },
        { sig: 'a(uint256)', args: W(0n) },
        { sig: 'a(uint256)', args: W(5n) },
      ],
    );
  });
});

describe('@external bytes/string multi-level array getters vs Solidity', () => {
  it('string[][] (and bytes element), incl OOB empty-revert', async () => {
    await diff(
      `class C { d: Visible<string[][]>; nr(): External<void> { this.d.push(); } add(i: u256, s: string): External<void> { this.d[i].push(s); } }`,
      `contract C { string[][] public d; function nr() external { d.push(); } function add(uint256 i, string calldata s) external { d[i].push(s); } }`,
      [
        { sig: 'nr()' },
        { sig: 'add(uint256,string)', args: W(0x40n) + W(0n) + W(3n) + '616263'.padEnd(64, '0') },
        { sig: 'd(uint256,uint256)', args: W(0n) + W(0n) },
        { sig: 'd(uint256,uint256)', args: W(0n) + W(5n) },
      ],
    );
  });

  it('mapping(K=>Arr<string,N>) element getter', async () => {
    await diff(
      `class C { m: Visible<mapping<u256,Arr<string,2>>>; set(k: u256, i: u256, s: string): External<void> { this.m[k][i] = s; } }`,
      `contract C { mapping(uint256=>string[2]) public m; function set(uint256 k, uint256 i, string calldata s) external { m[k][i]=s; } }`,
      [
        { sig: 'set(uint256,uint256,string)', args: W(1n) + W(0n) + W(0x60n) + W(2n) + '7878'.padEnd(64, '0') },
        { sig: 'm(uint256,uint256)', args: W(1n) + W(0n) },
        { sig: 'm(uint256,uint256)', args: W(1n) + W(2n) },
      ],
    );
  });
});

describe('@external getter parity is limited only by unsupported STORAGE TYPES (not getters)', () => {
  // Every getter shape whose storage TYPE JETH supports now matches solc. The only @external state vars
  // solc accepts that JETH rejects are ones whose underlying STORAGE TYPE is itself unimplemented
  // (rejected for manual getters and writes too), e.g. `string[3][]` (a dynamic array of fixed arrays
  // of a dynamic type). The getter rejection there is consistent, not a getter-specific over-rejection.
  it('string[3][] storage type: manual element access AND its @external (i,j) auto-getter are supported', () => {
    // a bare @state Arr<string,3>[] with manual element access now compiles (byte-identical to solc,
    // verified incl. push/pop deep-clear in fix-all-divergences.test.ts).
    expect(
      jethRejects(
        `class C { d: Arr<string,3>[]; get g(i: u256, j: u256): External<string> { return this.d[i][j]; } }`,
      ),
    ).toBe(false);
    // the @external auto-getter d(uint256,uint256) -> string now compiles too (byte-identical to solc).
    expect(jethRejects(`class C { d: Visible<Arr<string,3>[]>; }`)).toBe(false);
    expect(solcAccepts(`contract C { string[3][] public d; }`)).toBe(true);
  });
});
