// SHAPE S6: constructing a struct from a STORAGE bytes/string field and RETURNING it
// (or otherwise ABI-tail-encoding the constructed struct): `return Pair(k, this.name)`.
//
// Root cause: yul.ts collectTupleDyn pre-materialized ONLY a `memory` source; a `storage`
// source (this.name resolving to dynStateRead -> { src:'storage', slot }) fell through
// unchanged, and encodeDynFieldInto's bytes/string arm had only calldata + memory branches,
// so its else threw UnsupportedError (surfaced as JETH900). abi.encode(Pair(k,this.name))
// ALREADY matched because buildAbiEncode materializes each dyn arg to memory first.
//
// Fix: widen collectTupleDyn's pre-materialize condition to ALSO include a `storage` source,
// calling toMemory(ref) (the SAME storage-string->memory copy via loadStr that abi.encode
// uses). encodeDynFieldInto's existing memory mcopy arm then handles it byte-identically and
// the storage else-throw is never reached. Byte-identical to solc 0.8.35.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => BigInt(n).toString(16).padStart(64, '0');

// ABI-encode a single string/bytes argument as calldata tail: [0x20 offset][len][padded data].
const strArg = (s: string): string => {
  const b = Buffer.from(s, 'utf8');
  const len = b.length;
  const data = b.toString('hex');
  const padded = data + '00'.repeat((32 - (len % 32)) % 32);
  return W(0x20) + W(len) + (len === 0 ? '' : padded);
};
// two dynamic args f(string,string): [off1=0x40][off2][tail1][tail2] where each tail = [len][data].
const twoStrArgs = (a: string, b: string): string => {
  const t1 = strArg(a).slice(64); // drop the leading 0x20 offset word -> [len][data]
  const t2 = strArg(b).slice(64);
  const off1 = 0x40;
  const off2 = 0x40 + t1.length / 2;
  return W(off1) + W(off2) + t1 + t2;
};
// expected returndata for Pair{ k, name }: [0x20][k][0x40][len][padded name]
const expectPair = (k: bigint | number, name: string): string => {
  const b = Buffer.from(name, 'utf8');
  const len = b.length;
  const padded = b.toString('hex') + '00'.repeat((32 - (len % 32)) % 32);
  return '0x' + W(0x20) + W(k) + W(0x40) + W(len) + (len === 0 ? '' : padded);
};

const N40 = 'A'.repeat(40); // a >32-byte (multi-word) name

describe('S6: return a struct constructed from a storage bytes/string field', () => {
  it('make(k) = Pair(k, this.name) is byte-identical to solc across "", "hi", and a 40-byte name', async () => {
    const J = `type Pair = { k: u256; name: string };
class C {
  name: string;
  setName(s: string): External<void> { this.name = s; }
  get make(k: u256): External<Pair> { return Pair(k, this.name); }
}`;
    const S = `struct Pair { uint256 k; string name; }
contract C {
  string name;
  function setName(string calldata s) external { name = s; }
  function make(uint256 k) external view returns (Pair memory) { return Pair(k, name); }
}`;
    const h = await Harness.create();
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    for (const [nm, k] of [['', 7], ['hi', 42], [N40, 99]] as const) {
      await h.call(ja, sel('setName(string)') + strArg(nm));
      await h.call(sa, sel('setName(string)') + strArg(nm));
      const cd = sel('make(uint256)') + W(k);
      const jr = await h.call(ja, cd);
      const sr = await h.call(sa, cd);
      // dispatch is on the plain uint256 selector; the returned name field is the seeded storage value.
      expect(jr.success, `make ${nm}`).toBe(true);
      expect(jr.returnHex, `make ${nm} vs solc`).toBe(sr.returnHex);
      expect(jr.returnHex, `make ${nm} vs expected`).toBe(expectPair(k, nm));
    }
  });

  it('mid-position T(9, this.name, 9) is byte-identical to solc', async () => {
    const J = `type T = { a: u256; name: string; b: u256 };
class C {
  name: string;
  setName(s: string): External<void> { this.name = s; }
  get mk(): External<T> { return T(9n, this.name, 9n); }
}`;
    const S = `struct T { uint256 a; string name; uint256 b; }
contract C {
  string name;
  function setName(string calldata s) external { name = s; }
  function mk() external view returns (T memory) { return T(9, name, 9); }
}`;
    const h = await Harness.create();
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(ja, sel('setName(string)') + strArg(N40));
    await h.call(sa, sel('setName(string)') + strArg(N40));
    const jr = await h.call(ja, sel('mk()'));
    const sr = await h.call(sa, sel('mk()'));
    // expected: [0x20][9][name-offset=0x60][9][len][padded]
    const b = Buffer.from(N40, 'utf8');
    const padded = b.toString('hex') + '00'.repeat((32 - (b.length % 32)) % 32);
    const expected = '0x' + W(0x20) + W(9) + W(0x60) + W(9) + W(b.length) + padded;
    expect(jr.success).toBe(true);
    expect(jr.returnHex).toBe(sr.returnHex);
    expect(jr.returnHex).toBe(expected);
  });

  it('two storage strings T2(this.a, this.b) is byte-identical to solc', async () => {
    const J = `type T2 = { a: string; b: string };
class C {
  a: string;
  b: string;
  setAB(x: string, y: string): External<void> { this.a = x; this.b = y; }
  get mk(): External<T2> { return T2(this.a, this.b); }
}`;
    const S = `struct T2 { string a; string b; }
contract C {
  string a; string b;
  function setAB(string calldata x, string calldata y) external { a = x; b = y; }
  function mk() external view returns (T2 memory) { return T2(a, b); }
}`;
    const h = await Harness.create();
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(ja, sel('setAB(string,string)') + twoStrArgs(N40, 'bar'));
    await h.call(sa, sel('setAB(string,string)') + twoStrArgs(N40, 'bar'));
    const jr = await h.call(ja, sel('mk()'));
    const sr = await h.call(sa, sel('mk()'));
    // expected: [0x20][off-a=0x40][off-b][a-len][a-data(padded)][b-len][b-data(padded)]
    const ab = Buffer.from(N40, 'utf8');
    const bb = Buffer.from('bar', 'utf8');
    const pad = (buf: Buffer) => buf.toString('hex') + '00'.repeat((32 - (buf.length % 32)) % 32);
    const aTail = W(ab.length) + pad(ab);
    const offB = 0x40 + aTail.length / 2;
    const bTail = W(bb.length) + pad(bb);
    const expected = '0x' + W(0x20) + W(0x40) + W(offB) + aTail + bTail;
    expect(jr.success).toBe(true);
    expect(jr.returnHex).toBe(sr.returnHex);
    expect(jr.returnHex).toBe(expected);
  });

  it('nested Outer(k, Inner(this.name)) is byte-identical to solc', async () => {
    const J = `type Inner = { name: string };
type Outer = { k: u256; inner: Inner };
class C {
  name: string;
  setName(s: string): External<void> { this.name = s; }
  get mk(k: u256): External<Outer> { return Outer(k, Inner(this.name)); }
}`;
    const S = `struct Inner { string name; }
struct Outer { uint256 k; Inner inner; }
contract C {
  string name;
  function setName(string calldata s) external { name = s; }
  function mk(uint256 k) external view returns (Outer memory) { return Outer(k, Inner(name)); }
}`;
    const h = await Harness.create();
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(ja, sel('setName(string)') + strArg(N40));
    await h.call(sa, sel('setName(string)') + strArg(N40));
    const jr = await h.call(ja, sel('mk(uint256)') + W(5));
    const sr = await h.call(sa, sel('mk(uint256)') + W(5));
    expect(jr.success).toBe(true);
    expect(jr.returnHex).toBe(sr.returnHex);
    // outer: [0x20][k=5][inner-off=0x40] ; inner tuple: [name-off=0x20][len][padded]
    const b = Buffer.from(N40, 'utf8');
    const padded = b.toString('hex') + '00'.repeat((32 - (b.length % 32)) % 32);
    const expected = '0x' + W(0x20) + W(5) + W(0x40) + W(0x20) + W(b.length) + padded;
    expect(jr.returnHex).toBe(expected);
  });

  it('storage bytes field PairB(k, this.blob) is byte-identical to solc', async () => {
    const J = `type PairB = { k: u256; blob: bytes };
class C {
  blob: bytes;
  setBlob(b: bytes): External<void> { this.blob = b; }
  get make(k: u256): External<PairB> { return PairB(k, this.blob); }
}`;
    const S = `struct PairB { uint256 k; bytes blob; }
contract C {
  bytes blob;
  function setBlob(bytes calldata b) external { blob = b; }
  function make(uint256 k) external view returns (PairB memory) { return PairB(k, blob); }
}`;
    const h = await Harness.create();
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    // seed with a >32-byte blob so the length spans two words
    const blob = 'de'.repeat(40);
    const blobArg = W(0x20) + W(40) + blob + '00'.repeat(32 - (40 % 32));
    await h.call(ja, sel('setBlob(bytes)') + blobArg);
    await h.call(sa, sel('setBlob(bytes)') + blobArg);
    const jr = await h.call(ja, sel('make(uint256)') + W(3));
    const sr = await h.call(sa, sel('make(uint256)') + W(3));
    expect(jr.success).toBe(true);
    expect(jr.returnHex).toBe(sr.returnHex);
    const expected = '0x' + W(0x20) + W(3) + W(0x40) + W(40) + blob + '00'.repeat(32 - (40 % 32));
    expect(jr.returnHex).toBe(expected);
  });

  // CONTROL 1: abi.encode(Pair(k, this.name)) must STILL match (unregressed - the fix mirrors it).
  it('CONTROL: abi.encode(Pair(k, this.name)) stays byte-identical to solc', async () => {
    const J = `type Pair = { k: u256; name: string };
class C {
  name: string;
  setName(s: string): External<void> { this.name = s; }
  get enc(k: u256): External<bytes> { return abi.encode(Pair(k, this.name)); }
}`;
    const S = `struct Pair { uint256 k; string name; }
contract C {
  string name;
  function setName(string calldata s) external { name = s; }
  function enc(uint256 k) external view returns (bytes memory) { return abi.encode(Pair(k, name)); }
}`;
    const h = await Harness.create();
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(ja, sel('setName(string)') + strArg(N40));
    await h.call(sa, sel('setName(string)') + strArg(N40));
    const jr = await h.call(ja, sel('enc(uint256)') + W(3));
    const sr = await h.call(sa, sel('enc(uint256)') + W(3));
    expect(jr.success).toBe(true);
    expect(jr.returnHex).toBe(sr.returnHex);
  });

  // CONTROL 2: a dyn VALUE-array field ctor V(k, this.tags) must STILL match (untouched arm).
  it('CONTROL: V(k, this.tags) with a storage u256[] field stays byte-identical to solc', async () => {
    const J = `type V = { k: u256; tags: u256[] };
class C {
  tags: u256[];
  push(x: u256): External<void> { this.tags.push(x); }
  get mk(k: u256): External<V> { return V(k, this.tags); }
}`;
    const S = `struct V { uint256 k; uint256[] tags; }
contract C {
  uint256[] tags;
  function push(uint256 x) external { tags.push(x); }
  function mk(uint256 k) external view returns (V memory) { return V(k, tags); }
}`;
    const h = await Harness.create();
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    await h.call(ja, sel('push(uint256)') + W(11));
    await h.call(sa, sel('push(uint256)') + W(11));
    await h.call(ja, sel('push(uint256)') + W(22));
    await h.call(sa, sel('push(uint256)') + W(22));
    const jr = await h.call(ja, sel('mk(uint256)') + W(7));
    const sr = await h.call(sa, sel('mk(uint256)') + W(7));
    expect(jr.success).toBe(true);
    expect(jr.returnHex).toBe(sr.returnHex);
    const expected = '0x' + W(0x20) + W(7) + W(0x40) + W(2) + W(11) + W(22);
    expect(jr.returnHex).toBe(expected);
  });

  // CONTROL 3 (still-reject): emit E(Pair(k, this.name)) with a storage-string struct payload must
  // STILL reject at the analyzer BEFORE codegen (JETH072/074) - the fix must not open the emit/topic
  // path. This is a pre-existing SAFE over-rejection of the emit-of-dynamic-struct family, unchanged.
  it('CONTROL (still-reject): emit E(Pair(k, this.name)) is rejected before codegen', () => {
    const J = `@struct class Pair { k: u256; name: string }
@event class E { p: Pair }
@contract class C {
  @state name: string;
  @external setName(s: string): void { this.name = s; }
  @external fire(k: u256): void { emit E(Pair(k, this.name)); }
}`;
    let codes: string[] = [];
    try {
      compile(J, { fileName: 'C.jeth' });
      throw new Error('expected a diagnostic reject, but compile succeeded');
    } catch (e: any) {
      codes = (e?.diagnostics ?? []).map((d: any) => d.code);
    }
    expect(codes).toContain('JETH481');
    expect(codes).toContain('JETH074');
  });
});
