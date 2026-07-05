// NF-1: whole-array STORE into a @state fixed-outer / dynamic-leaf array (Arr<string,N>, Arr<bytes,N>,
// Arr<u256[],N>, nested Arr<Arr<string,N>,M>, Arr<string[],N>) and its struct-field / mapping-value
// variants. Before this fix `this.fa = xs` wrote the MEMORY POINTER words into the N base slots instead
// of transcoding each dynamic element into its own storage slot - a silent storage MISCOMPILE - and the
// array-literal source (`this.fa = ["a","b"]`) crashed (JETH900). solc lays these out as N CONSECUTIVE
// base slots, each a normal storage dynamic (string/bytes header short-inline / long-at-keccak, or a
// dynamic-array length slot). Each case SEEDS via the whole store, then compares element getters + a broad
// set of RAW slots (base + computed keccak data slots) byte-for-byte vs solc, incl. the long->short
// OVERWRITE (the freed keccak data region must be zeroed exactly like solc).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const M = 1n << 256n;
const b32 = (v: bigint) => Buffer.from((((v % M) + M) % M).toString(16).padStart(64, '0'), 'hex');
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
// keccak(slot) - the long-string data / dynamic-array data region base of `slot`.
const kecSlot = (n: bigint) => BigInt('0x' + toHex(keccak(b32(n))));
// keccak(key . base) - the mapping value base slot for `m[key]`.
const mapSlot = (key: bigint, base: bigint) => BigInt('0x' + toHex(keccak(Buffer.concat([b32(key), b32(base)]))));

const LONG = 'this string is definitely longer than thirty-two bytes so it uses keccak data slots__';
const LONG2 = 'another long payload exceeding the thirty-two byte short-string inline cutoff for sure!';

interface Pair {
  jeth: Harness;
  sol: Harness;
  aj: Address;
  as: Address;
}
async function build(jethSrc: string, solSrc: string): Promise<Pair> {
  const jb = compile(jethSrc, { fileName: 'C.jeth' });
  const sb = compileSolidity(solSrc, 'C');
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  return { jeth, sol, aj, as };
}
// Encode a call and compare success + returndata + every raw slot byte-for-byte vs solc.
async function cmp(p: Pair, label: string, data: string, slots: bigint[]) {
  const j = await p.jeth.call(p.aj, data);
  const s = await p.sol.call(p.as, data);
  expect(j.success, `${label}: success (jeth err=${j.exceptionError})`).toBe(s.success);
  expect(j.returnHex, `${label}: returndata`).toBe(s.returnHex);
  for (const slot of slots) {
    expect(await readSlot(p.jeth, p.aj, slot), `${label}: slot 0x${slot.toString(16)}`).toBe(
      await readSlot(p.sol, p.as, slot),
    );
  }
}
const noArg = (s: string) => '0x' + sel(s);
const uintArg = (s: string, ...vs: bigint[]) => '0x' + sel(s) + vs.map(pad).join('');

describe('NF-1: @state Arr<string,N> whole-array store', () => {
  let p: Pair;
  // slots to compare: base slots 0,1 + their keccak long-data slots (a few words each).
  const slots = [0n, 1n, kecSlot(0n), kecSlot(0n) + 1n, kecSlot(0n) + 2n, kecSlot(1n), kecSlot(1n) + 1n, kecSlot(1n) + 2n];
  beforeAll(async () => {
    p = await build(
      `@contract class C {
        @state fa: Arr<string,2>;
        @external fromMem(): void { let xs: Arr<string,2> = ["${LONG}","short"]; this.fa = xs; }
        @external fromLit(): void { this.fa = ["aa","bbbb"]; }
        @external shrink(): void { let xs: Arr<string,2> = ["a","b"]; this.fa = xs; }
        @external @view g(i: u256): string { return this.fa[i]; }
        @external @view whole(): Arr<string,2> { return this.fa; }
      }`,
      `contract C {
        string[2] fa;
        function fromMem() external { string[2] memory xs = ["${LONG}","short"]; fa = xs; }
        function fromLit() external { fa = ["aa","bbbb"]; }
        function shrink() external { string[2] memory xs = ["a","b"]; fa = xs; }
        function g(uint256 i) external view returns (string memory) { return fa[i]; }
        function whole() external view returns (string[2] memory) { return fa; }
      }`,
    );
  });

  it('mem-local source (long + short elements)', async () => {
    await cmp(p, 'fromMem', noArg('fromMem()'), slots);
    await cmp(p, 'g[0] long', uintArg('g(uint256)', 0n), slots);
    await cmp(p, 'g[1] short', uintArg('g(uint256)', 1n), slots);
    await cmp(p, 'whole return', noArg('whole()'), slots);
    // non-vacuity: element 0 is the LONG value, so the base slot holds len*2+1 and data lives at keccak(0).
    expect(await readSlot(p.jeth, p.aj, 0n)).toBe('0x' + pad(BigInt(LONG.length) * 2n + 1n));
    expect(await readSlot(p.jeth, p.aj, kecSlot(0n))).not.toBe('0x' + '0'.repeat(64));
  });

  it('array-literal source (was JETH900)', async () => {
    await cmp(p, 'fromLit', noArg('fromLit()'), slots);
    await cmp(p, 'g[0] aa', uintArg('g(uint256)', 0n), slots);
    await cmp(p, 'g[1] bbbb', uintArg('g(uint256)', 1n), slots);
  });

  it('OVERWRITE long->short frees the keccak data region', async () => {
    await cmp(p, 're-seed long', noArg('fromMem()'), slots);
    // now element 0 is long; keccak(0) is populated. Shrink to short and confirm freed slots zero out.
    await cmp(p, 'shrink', noArg('shrink()'), slots);
    expect(await readSlot(p.jeth, p.aj, kecSlot(0n)), 'freed keccak slot zeroed').toBe('0x' + '0'.repeat(64));
    await cmp(p, 'g[0] after shrink', uintArg('g(uint256)', 0n), slots);
  });
});

describe('NF-1: @state Arr<bytes,N> whole-array store', () => {
  let p: Pair;
  const slots = [0n, 1n, kecSlot(0n), kecSlot(0n) + 1n, kecSlot(0n) + 2n, kecSlot(1n)];
  beforeAll(async () => {
    p = await build(
      `@contract class C {
        @state fa: Arr<bytes,2>;
        @external fromMem(): void { let xs: Arr<bytes,2> = [bytes("${LONG}"),bytes("hi")]; this.fa = xs; }
        @external fromLit(): void { this.fa = [bytes("aa"),bytes("bbbb")]; }
        @external @view g(i: u256): bytes { return this.fa[i]; }
      }`,
      `contract C {
        bytes[2] fa;
        function fromMem() external { bytes[2] memory xs = [bytes("${LONG}"),bytes("hi")]; fa = xs; }
        function fromLit() external { fa = [bytes("aa"),bytes("bbbb")]; }
        function g(uint256 i) external view returns (bytes memory) { return fa[i]; }
      }`,
    );
  });
  it('mem-local + array-literal sources', async () => {
    await cmp(p, 'fromMem', noArg('fromMem()'), slots);
    await cmp(p, 'g[0] long', uintArg('g(uint256)', 0n), slots);
    await cmp(p, 'g[1] short', uintArg('g(uint256)', 1n), slots);
    await cmp(p, 'fromLit', noArg('fromLit()'), slots);
    await cmp(p, 'g[0] aa', uintArg('g(uint256)', 0n), slots);
  });
});

describe('NF-1: nested + value-leaf fixed dynamic-leaf arrays', () => {
  it('Arr<Arr<string,2>,2>', async () => {
    const p = await build(
      `@contract class C {
        @state fa: Arr<Arr<string,2>,2>;
        @external s(): void { let xs: Arr<Arr<string,2>,2> = [["aa","${LONG}"],["cc","dd"]]; this.fa = xs; }
        @external @view g(i: u256, j: u256): string { return this.fa[i][j]; }
      }`,
      `contract C {
        string[2][2] fa;
        function s() external { string[2][2] memory xs = [["aa","${LONG}"],["cc","dd"]]; fa = xs; }
        function g(uint256 i, uint256 j) external view returns (string memory) { return fa[i][j]; }
      }`,
    );
    const slots = [0n, 1n, 2n, 3n, kecSlot(1n), kecSlot(1n) + 1n];
    await cmp(p, 's', noArg('s()'), slots);
    await cmp(p, 'g[0][1] long', uintArg('g(uint256,uint256)', 0n, 1n), slots);
    await cmp(p, 'g[1][0]', uintArg('g(uint256,uint256)', 1n, 0n), slots);
  });

  it('Arr<u256[],2> (value leaf behind a dynamic level)', async () => {
    const p = await build(
      `@contract class C {
        @state fa: Arr<u256[],2>;
        @external s(): void { let xs: Arr<u256[],2> = [[1n,2n,3n],[9n]]; this.fa = xs; }
        @external shrink(): void { let xs: Arr<u256[],2> = [[7n],[8n]]; this.fa = xs; }
        @external @view g(i: u256, j: u256): u256 { return this.fa[i][j]; }
        @external @view len(i: u256): u256 { return this.fa[i].length; }
      }`,
      `contract C {
        uint256[][2] fa;
        function s() external { uint256[] memory a=new uint256[](3); a[0]=1;a[1]=2;a[2]=3; uint256[] memory b=new uint256[](1); b[0]=9; uint256[][2] memory xs=[a,b]; fa=xs; }
        function shrink() external { uint256[] memory a=new uint256[](1); a[0]=7; uint256[] memory b=new uint256[](1); b[0]=8; uint256[][2] memory xs=[a,b]; fa=xs; }
        function g(uint256 i, uint256 j) external view returns (uint256) { return fa[i][j]; }
        function len(uint256 i) external view returns (uint256) { return fa[i].length; }
      }`,
    );
    const slots = [0n, 1n, kecSlot(0n), kecSlot(0n) + 1n, kecSlot(0n) + 2n, kecSlot(0n) + 3n, kecSlot(1n)];
    await cmp(p, 's', noArg('s()'), slots);
    await cmp(p, 'len[0]=3', uintArg('len(uint256)', 0n), slots);
    await cmp(p, 'g[0][2]=3', uintArg('g(uint256,uint256)', 0n, 2n), slots);
    // OVERWRITE shrink: the freed inner-array data slots must zero out exactly like solc.
    await cmp(p, 'shrink', noArg('shrink()'), slots);
    expect(await readSlot(p.jeth, p.aj, kecSlot(0n) + 2n), 'freed inner data slot zeroed').toBe('0x' + '0'.repeat(64));
    await cmp(p, 'g[0][0]=7', uintArg('g(uint256,uint256)', 0n, 0n), slots);
  });

  it('Arr<string[],2> (bytes leaf behind a dynamic level)', async () => {
    const p = await build(
      `@contract class C {
        @state fa: Arr<string[],2>;
        @external s(): void { let xs: Arr<string[],2> = [["a","${LONG}"],["z"]]; this.fa = xs; }
        @external @view g(i: u256, j: u256): string { return this.fa[i][j]; }
      }`,
      `contract C {
        string[][2] fa;
        function s() external { string[] memory a=new string[](2); a[0]="a"; a[1]="${LONG}"; string[] memory b=new string[](1); b[0]="z"; string[][2] memory xs=[a,b]; fa=xs; }
        function g(uint256 i, uint256 j) external view returns (string memory) { return fa[i][j]; }
      }`,
    );
    const slots = [0n, 1n, kecSlot(0n), kecSlot(1n)];
    await cmp(p, 's', noArg('s()'), slots);
    await cmp(p, 'g[0][1] long', uintArg('g(uint256,uint256)', 0n, 1n), slots);
    await cmp(p, 'g[1][0]', uintArg('g(uint256,uint256)', 1n, 0n), slots);
  });
});

describe('NF-1: struct-field + mapping-value targets', () => {
  it('struct field this.st.xs = xs', async () => {
    const p = await build(
      `@struct class S { a: u256; xs: Arr<string,2>; }
      @contract class C {
        @state st: S;
        @external s(): void { let xs: Arr<string,2> = ["${LONG}","short"]; this.st.xs = xs; }
        @external @view g(i: u256): string { return this.st.xs[i]; }
      }`,
      `contract C {
        struct S { uint256 a; string[2] xs; }
        S st;
        function s() external { string[2] memory xs = ["${LONG}","short"]; st.xs = xs; }
        function g(uint256 i) external view returns (string memory) { return st.xs[i]; }
      }`,
    );
    // st.a @ slot 0; st.xs @ slots 1,2.
    const slots = [0n, 1n, 2n, kecSlot(1n), kecSlot(1n) + 1n, kecSlot(2n)];
    await cmp(p, 's', noArg('s()'), slots);
    await cmp(p, 'g[0] long', uintArg('g(uint256)', 0n), slots);
    await cmp(p, 'g[1] short', uintArg('g(uint256)', 1n), slots);
  });

  it('mapping value this.m[k] = xs', async () => {
    const p = await build(
      `@contract class C {
        @state m: mapping<u256, Arr<string,2>>;
        @external s(k: u256): void { let xs: Arr<string,2> = ["${LONG2}","short"]; this.m[k] = xs; }
        @external @view g(k: u256, i: u256): string { return this.m[k][i]; }
      }`,
      `contract C {
        mapping(uint256 => string[2]) m;
        function s(uint256 k) external { string[2] memory xs = ["${LONG2}","short"]; m[k] = xs; }
        function g(uint256 k, uint256 i) external view returns (string memory) { return m[k][i]; }
      }`,
    );
    const K = 5n;
    const base = mapSlot(K, 0n);
    const slots = [base, base + 1n, kecSlot(base), kecSlot(base) + 1n, kecSlot(base + 1n)];
    await cmp(p, 's', uintArg('s(uint256)', K), slots);
    await cmp(p, 'g[k][0] long', uintArg('g(uint256,uint256)', K, 0n), slots);
    await cmp(p, 'g[k][1] short', uintArg('g(uint256,uint256)', K, 1n), slots);
  });
});
