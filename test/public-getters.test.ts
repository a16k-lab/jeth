// @public auto-generated getters: parameterized mapping/array getters and struct-flattening
// getters, byte-identical to solc 0.8.35. (Bucket-A "what's left" #4 over-rejection fix.)
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n).slice(2);
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
  try { compile(jeth, { fileName: 'C.jeth' }); return false; } catch { return true; }
}
function solcAccepts(sol: string): boolean {
  try { compileSolidity(SPDX + sol, 'C'); return true; } catch { return false; }
}

describe('@public parameterized getters vs Solidity', () => {
  it('mapping(address=>uint256) getter', async () => {
    await diff(
      `@contract class C { @public @state balances: mapping<address,u256>; @external set(k: address, v: u256): void { this.balances[k] = v; } }`,
      `contract C { mapping(address=>uint256) public balances; function set(address k, uint256 v) external { balances[k] = v; } }`,
      [{ sig: 'set(address,uint256)', args: A1 + W(42n) }, { sig: 'balances(address)', args: A1 }, { sig: 'balances(address)', args: A2 }],
    );
  });

  it('nested mapping getter (two key params)', async () => {
    await diff(
      `@contract class C { @public @state allowance: mapping<address,mapping<address,u256>>; @external set(a: address, b: address, v: u256): void { this.allowance[a][b] = v; } }`,
      `contract C { mapping(address=>mapping(address=>uint256)) public allowance; function set(address a, address b, uint256 v) external { allowance[a][b] = v; } }`,
      [{ sig: 'set(address,address,uint256)', args: A1 + A2 + W(99n) }, { sig: 'allowance(address,address)', args: A1 + A2 }, { sig: 'allowance(address,address)', args: A2 + A1 }],
    );
  });

  it('mapping with a small (uint8/int8) value masks correctly', async () => {
    await diff(
      `@contract class C { @public @state u: mapping<u256,u8>; @public @state s: mapping<u256,i8>; @external setu(k: u256, v: u8): void { this.u[k] = v; } @external sets(k: u256, v: i8): void { this.s[k] = v; } }`,
      `contract C { mapping(uint256=>uint8) public u; mapping(uint256=>int8) public s; function setu(uint256 k, uint8 v) external { u[k]=v; } function sets(uint256 k, int8 v) external { s[k]=v; } }`,
      [
        { sig: 'setu(uint256,uint8)', args: W(1n) + W(200n) }, { sig: 'u(uint256)', args: W(1n) }, { sig: 'u(uint256)', args: W(9n) },
        { sig: 'sets(uint256,int8)', args: W(1n) + W((1n << 256n) - 5n) }, { sig: 's(uint256)', args: W(1n) },
      ],
    );
  });

  it('mapping(address=>bytes) getter', async () => {
    await diff(
      `@contract class C { @public @state blobs: mapping<address,bytes>; @external set(k: address, v: bytes): void { this.blobs[k] = v; } }`,
      `contract C { mapping(address=>bytes) public blobs; function set(address k, bytes calldata v) external { blobs[k] = v; } }`,
      [{ sig: 'set(address,bytes)', args: A1 + W(0x40n) + W(3n) + 'aabbcc'.padEnd(64, '0') }, { sig: 'blobs(address)', args: A1 }, { sig: 'blobs(address)', args: A2 }],
    );
  });

  it('mapping(uint=>uint[]) getter (key + index params)', async () => {
    await diff(
      `@contract class C { @public @state m2: mapping<u256,u256[]>; @external push(k: u256, v: u256): void { this.m2[k].push(v); } }`,
      `contract C { mapping(uint256=>uint256[]) public m2; function push(uint256 k, uint256 v) external { m2[k].push(v); } }`,
      [{ sig: 'push(uint256,uint256)', args: W(5n) + W(111n) }, { sig: 'push(uint256,uint256)', args: W(5n) + W(222n) }, { sig: 'm2(uint256,uint256)', args: W(5n) + W(0n) }, { sig: 'm2(uint256,uint256)', args: W(5n) + W(1n) }, { sig: 'm2(uint256,uint256)', args: W(5n) + W(9n) }],
    );
  });

  it('dynamic array getter (out-of-bounds Panic parity)', async () => {
    await diff(
      `@contract class C { @public @state arr: u256[]; @external push(v: u256): void { this.arr.push(v); } }`,
      `contract C { uint256[] public arr; function push(uint256 v) external { arr.push(v); } }`,
      [{ sig: 'push(uint256)', args: W(7n) }, { sig: 'push(uint256)', args: W(8n) }, { sig: 'arr(uint256)', args: W(0n) }, { sig: 'arr(uint256)', args: W(1n) }, { sig: 'arr(uint256)', args: W(5n) }],
    );
  });

  it('fixed array getter (out-of-bounds Panic parity)', async () => {
    await diff(
      `@contract class C { @public @state fa: Arr<u256,3>; @external set(i: u256, v: u256): void { this.fa[i] = v; } }`,
      `contract C { uint256[3] public fa; function set(uint256 i, uint256 v) external { fa[i] = v; } }`,
      [{ sig: 'set(uint256,uint256)', args: W(1n) + W(55n) }, { sig: 'fa(uint256)', args: W(0n) }, { sig: 'fa(uint256)', args: W(1n) }, { sig: 'fa(uint256)', args: W(3n) }],
    );
  });

  it('string[] getter (element returned)', async () => {
    await diff(
      `@contract class C { @public @state names: string[]; @external push(s: string): void { this.names.push(s); } }`,
      `contract C { string[] public names; function push(string calldata s) external { names.push(s); } }`,
      [{ sig: 'push(string)', args: W(0x20n) + W(2n) + '7878'.padEnd(64, '0') }, { sig: 'names(uint256)', args: W(0n) }],
    );
  });
});

describe('@public struct-flattening getters vs Solidity', () => {
  it('value + packed fields', async () => {
    await diff(
      `@struct class P { a: u8; b: u16; c: u32; owner: address; flag: bool; x: u256; } @contract class C { @public @state p: P; @external set(): void { this.p.a = 200n; this.p.b = 50000n; this.p.c = 4000000000n; this.p.owner = msg.sender; this.p.flag = true; this.p.x = 42n; } }`,
      `struct P { uint8 a; uint16 b; uint32 c; address owner; bool flag; uint256 x; } contract C { P public p; function set() external { p.a=200; p.b=50000; p.c=4000000000; p.owner=msg.sender; p.flag=true; p.x=42; } }`,
      [{ sig: 'set()' }, { sig: 'p()' }],
    );
  });

  it('bytes/string fields (dynamic members in the returned tuple)', async () => {
    await diff(
      `@struct class P { x: u256; name: string; y: u256; data: bytes; } @contract class C { @public @state p: P; @external set(): void { this.p.x = 7n; this.p.name = "hi"; this.p.y = 9n; this.p.data = msg.data; } }`,
      `struct P { uint256 x; string name; uint256 y; bytes data; } contract C { P public p; function set() external { p.x=7; p.name="hi"; p.y=9; p.data=msg.data; } }`,
      [{ sig: 'set()' }, { sig: 'p()' }],
    );
  });

  it('omits array and mapping members (declaration order preserved)', async () => {
    await diff(
      `@struct class P { x: u256; arr: u256[]; y: u256; } @contract class C { @public @state p: P; @external set(): void { this.p.x = 11n; this.p.y = 22n; this.p.arr.push(5n); } }`,
      `struct P { uint256 x; uint256[] arr; uint256 y; } contract C { P public p; function set() external { p.x=11; p.y=22; p.arr.push(5); } }`,
      [{ sig: 'set()' }, { sig: 'p()' }],
    );
    await diff(
      `@struct class P { x: u256; m: mapping<u256,u256>; y: u256; } @contract class C { @public @state p: P; @external set(): void { this.p.x = 11n; this.p.y = 22n; this.p.m[3n] = 9n; } }`,
      `struct P { uint256 x; mapping(uint256=>uint256) m; uint256 y; } contract C { P public p; function set() external { p.x=11; p.y=22; p.m[3]=9; } }`,
      [{ sig: 'set()' }, { sig: 'p()' }],
    );
  });
});

describe('@public getter shapes still deferred reject cleanly (honest gaps vs solc)', () => {
  const cases: { name: string; jeth: string; sol: string }[] = [
    { name: 'nested-struct member', jeth: `@struct class I { a: u256; } @struct class P { x: u256; inner: I; } @contract class C { @public @state p: P; }`, sol: `struct I { uint256 a; } struct P { uint256 x; I inner; } contract C { P public p; }` },
    { name: 'mapping-reached struct', jeth: `@struct class P { x: u256; y: u256; } @contract class C { @public @state accounts: mapping<address,P>; }`, sol: `struct P { uint256 x; uint256 y; } contract C { mapping(address=>P) public accounts; }` },
    { name: 'array-reached struct', jeth: `@struct class P { x: u256; y: u256; } @contract class C { @public @state list: P[]; }`, sol: `struct P { uint256 x; uint256 y; } contract C { P[] public list; }` },
    { name: 'nested array', jeth: `@contract class C { @public @state dd: u256[][]; }`, sol: `contract C { uint256[][] public dd; }` },
    { name: 'mapping to fixed array', jeth: `@contract class C { @public @state m: mapping<u256,Arr<u256,3>>; }`, sol: `contract C { mapping(uint256=>uint256[3]) public m; }` },
  ];
  for (const c of cases) {
    it(`${c.name}: JETH rejects cleanly, solc accepts`, () => {
      expect(jethRejects(c.jeth), 'JETH should reject').toBe(true);
      expect(solcAccepts(c.sol), 'solc should accept').toBe(true);
    });
  }
});
