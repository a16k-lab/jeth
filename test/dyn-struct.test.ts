// Phase 4e-6: dynamic structs (a @struct with >=1 dynamic field) as a calldata
// PARAM and as a RETURN, byte-identical to Solidity. A tuple with a dynamic field
// is itself dynamic: static fields stay INLINE in the tuple head (declaration
// order), each dynamic field gets a head OFFSET word based at the TUPLE START
// (spec section 3). Covers: read d.a / d.s / e.name / e.name.length / e.name[i];
// echo a D / E / Multi / Outer (head/tail re-encode); construct + return a D /
// Outer; nested Outer{x; D inner; y}; short/empty/long string; OOB Panic(0x32);
// malformed-layout EMPTY reverts; the asymmetric tuple-start base (decode + encode).
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
// right-pad an ASCII string to a 32-byte multiple (the ABI string/bytes payload).
const enc = (s: string) => {
  const hex = Buffer.from(s, 'utf8').toString('hex');
  const padded = hex.padEnd(Math.ceil(hex.length / 64) * 64, '0');
  return padded;
};
const words = (s: string) => Math.ceil(Buffer.from(s, 'utf8').length / 32); // payload word count

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract DynStruct {
  struct D { uint256 a; string s; }
  struct E { uint64 id; bytes name; }
  struct Outer { uint256 x; D inner; uint256 y; }
  struct Multi { uint256 a; string s; bytes b; uint256 z; }
  function getA(D calldata d) external pure returns (uint256){ return d.a; }
  function getS(D calldata d) external pure returns (string memory){ return d.s; }
  function getName(E calldata e) external pure returns (bytes memory){ return e.name; }
  function getNameLen(E calldata e) external pure returns (uint256){ return e.name.length; }
  function nameByte(E calldata e, uint256 i) external pure returns (bytes1){ return e.name[i]; }
  function echo(D calldata d) external pure returns (D memory){ return d; }
  function echoE(E calldata e) external pure returns (E memory){ return e; }
  function echoMulti(Multi calldata m) external pure returns (Multi memory){ return m; }
  function mk(uint256 a, string calldata s) external pure returns (D memory){ return D(a, s); }
  function mkLit() external pure returns (D memory){ return D(7, "hello"); }
  function innerA(Outer calldata o) external pure returns (uint256){ return o.inner.a; }
  function innerS(Outer calldata o) external pure returns (string memory){ return o.inner.s; }
  function outerX(Outer calldata o) external pure returns (uint256){ return o.x; }
  function outerY(Outer calldata o) external pure returns (uint256){ return o.y; }
  function echoOuter(Outer calldata o) external pure returns (Outer memory){ return o; }
  function mkOuter(uint256 x, uint256 a, string calldata s, uint256 y) external pure returns (Outer memory){ return Outer(x, D(a, s), y); }
}`;

describe('dynamic struct (calldata param + return) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  // D{uint256 a; string s} as a SOLE calldata param. Canonical layout:
  //   head = [off=0x20]; tuple @0x20: [a][off_s=0x40][s.len][s payload]
  const Dsig = '(uint256,string)';
  const dCalldata = (selSig: string, a: bigint, s: string, extraHead = '') => {
    const tuple = pad(a) + pad(0x40n) + pad(BigInt(Buffer.from(s, 'utf8').length)) + enc(s);
    // sole D param: head word = offset to tuple = 0x20 (one head word).
    return '0x' + sel(selSig) + pad(0x20n) + extraHead + tuple;
  };
  // E{uint64 id; bytes name} sole param, canonical.
  const eCalldata = (selSig: string, id: bigint, name: string, tail = '') => {
    const tuple = pad(id) + pad(0x40n) + pad(BigInt(Buffer.from(name, 'utf8').length)) + enc(name);
    return '0x' + sel(selSig) + pad(0x20n) + tuple + tail;
  };

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'DynStruct.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'DynStruct.jeth' });
    const sb = compileSolidity(SOL, 'DynStruct');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('reads d.a and d.s (short / 32 / 33 / empty string)', async () => {
    for (const s of ['', 'hi', 'x'.repeat(31), 'y'.repeat(32), 'z'.repeat(33), 'hello world this is a longer string!!']) {
      const r = await eq(`getA s.len=${s.length}`, dCalldata(`getA(${Dsig})`, 0xdeadn, s));
      expect(decodeUint(r.j.returnHex)).toBe(0xdeadn);
      await eq(`getS s.len=${s.length}`, dCalldata(`getS(${Dsig})`, 1n, s));
    }
  });

  it('reads e.name / e.name.length / e.name[i] (bytes field)', async () => {
    const Esig = '(uint64,bytes)';
    await eq('getName', eCalldata(`getName(${Esig})`, 0x42n, 'abcdef'));
    let r = await eq('getNameLen', eCalldata(`getNameLen(${Esig})`, 0x42n, 'abcdef'));
    expect(decodeUint(r.j.returnHex)).toBe(6n);
    // e.name[i] needs an extra head word for i; rebuild with i appended in the head.
    const eWithI = (i: bigint, name: string) => {
      const tuple = pad(0x42n) + pad(0x40n) + pad(BigInt(Buffer.from(name, 'utf8').length)) + enc(name);
      // head = [off_e=0x40][i]; tuple follows at byte 0x40.
      return '0x' + sel(`nameByte(${Esig},uint256)`) + pad(0x40n) + pad(i) + tuple;
    };
    r = await eq('nameByte i=2', eWithI(2n, 'ABCDEF'));
    expect(r.j.returnHex.slice(2, 4)).toBe('43'); // 'C'
    // OOB i=6 (len 6) -> Panic(0x32)
    r = await eq('nameByte OOB', eWithI(6n, 'ABCDEF'));
    expect(r.j.success).toBe(false);
  });

  it('echoes D byte-identically (head/tail re-encode; short/32/33/empty)', async () => {
    for (const s of ['', 'ab', 'x'.repeat(32), 'y'.repeat(33), 'the quick brown fox jumps over xyz']) {
      await eq(`echo s.len=${s.length}`, dCalldata(`echo(${Dsig})`, 0x1234n, s));
    }
  });

  it('echoes E (bytes field) and validates the static id (dirty -> EMPTY)', async () => {
    const Esig = '(uint64,bytes)';
    await eq('echoE', eCalldata(`echoE(${Esig})`, 0x99n, 'payload-bytes'));
    // dirty id (high bits set beyond uint64) -> the echo decodes+validates -> EMPTY.
    const dirty = '0x' + sel(`echoE(${Esig})`) + pad(0x20n) +
      pad(1n << 200n) + pad(0x40n) + pad(3n) + enc('abc');
    const r = await eq('echoE dirty id', dirty);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('echoes Multi{a; string s; bytes b; z} (two dynamic fields, mixed order)', async () => {
    const Msig = '(uint256,string,bytes,uint256)';
    const s = 'first-dynamic';
    const b = 'second-dyn-bytes-longer-than-thirtytwo-bytes!!';
    // tuple: [a][off_s][off_b][z][s.len][s pad][b.len][b pad]
    const offS = 0x80n; // 4 head words
    const offB = offS + 0x20n + BigInt(words(s)) * 0x20n;
    const tuple = pad(11n) + pad(offS) + pad(offB) + pad(22n) +
      pad(BigInt(Buffer.from(s, 'utf8').length)) + enc(s) +
      pad(BigInt(Buffer.from(b, 'utf8').length)) + enc(b);
    const data = '0x' + sel(`echoMulti(${Msig})`) + pad(0x20n) + tuple;
    await eq('echoMulti', data);
  });

  it('constructs + returns a D (mk / mkLit)', async () => {
    // mk(a, s): plain (uint256, string) params -> returns D.
    const mkData = (a: bigint, s: string) =>
      '0x' + sel('mk(uint256,string)') + pad(a) + pad(0x40n) +
      pad(BigInt(Buffer.from(s, 'utf8').length)) + enc(s);
    for (const s of ['', 'mk-string', 'q'.repeat(40)]) {
      await eq(`mk s.len=${s.length}`, mkData(0xabcn, s));
    }
    await eq('mkLit', '0x' + sel('mkLit()'));
  });

  it('nested Outer{x; D inner; y}: field reads + echo + construct', async () => {
    const Osig = '(uint256,(uint256,string),uint256)';
    // Outer canonical: head=[off=0x20]; @0x20: [x][off_inner=0x60][y]
    //   inner @ 0x20+0x60: [a][off_s=0x40][s.len][s pad]
    const outer = (x: bigint, a: bigint, s: string, y: bigint) => {
      const inner = pad(a) + pad(0x40n) + pad(BigInt(Buffer.from(s, 'utf8').length)) + enc(s);
      const tuple = pad(x) + pad(0x60n) + pad(y) + inner;
      return tuple;
    };
    const call = (fn: string, x: bigint, a: bigint, s: string, y: bigint) =>
      '0x' + sel(`${fn}(${Osig})`) + pad(0x20n) + outer(x, a, s, y);
    let r = await eq('innerA', call('innerA', 1n, 0xaa11n, 'inner-string', 2n));
    expect(decodeUint(r.j.returnHex)).toBe(0xaa11n);
    await eq('innerS', call('innerS', 1n, 5n, 'deep dynamic value here', 2n));
    r = await eq('outerX', call('outerX', 0x7777n, 5n, 'ss', 0x8888n));
    expect(decodeUint(r.j.returnHex)).toBe(0x7777n);
    r = await eq('outerY', call('outerY', 0x7777n, 5n, 'ss', 0x8888n));
    expect(decodeUint(r.j.returnHex)).toBe(0x8888n);
    for (const s of ['', 'mid', 'r'.repeat(33)]) {
      await eq(`echoOuter s.len=${s.length}`, call('echoOuter', 0x1111n, 0x2222n, s, 0x3333n));
    }
    // mkOuter(x, a, s, y) -> Outer
    const mko = (x: bigint, a: bigint, s: string, y: bigint) =>
      '0x' + sel('mkOuter(uint256,uint256,string,uint256)') + pad(x) + pad(a) + pad(0x80n) + pad(y) +
      pad(BigInt(Buffer.from(s, 'utf8').length)) + enc(s);
    await eq('mkOuter', mko(0x1111n, 0x2222n, 'built nested', 0x3333n));
    await eq('mkOuter empty', mko(0x1111n, 0x2222n, '', 0x3333n));
  });

  it('the tuple-start base is asymmetric (decode): a wrong-base off_s -> EMPTY', async () => {
    const Dsig2 = '(uint256,string)';
    // Place the tuple at args byte 0x60 (head off=0x60 + 1 pad word). off_s relative
    // to the TUPLE START (0x40) succeeds; off_s = 0x40 + 0x40 (measured from args
    // start, the wrong base) lands OOB -> EMPTY (spec section 3.2).
    const s = 'beef';
    const slen = pad(BigInt(s.length)) + enc(s);
    const okTuple = pad(7n) + pad(0x40n) + slen; // off_s=0x40 rel tuple start
    const ok = '0x' + sel(`getS(${Dsig2})`) + pad(0x40n) + pad(0n) + okTuple; // off=0x40, 1 pad
    await eq('off base ok', ok);
    const badTuple = pad(7n) + pad(0x80n) + slen; // off_s=0x80 (wrong base) -> OOB
    const bad = '0x' + sel(`getS(${Dsig2})`) + pad(0x40n) + pad(0n) + badTuple;
    const r = await eq('off base wrong -> EMPTY', bad);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('malformed layout faults -> EMPTY revert (offset past end, len past end, truncation)', async () => {
    const Dsig3 = '(uint256,string)';
    // top-level offset past calldata
    let r = await eq('off past end', '0x' + sel(`getA(${Dsig3})`) + pad(0x1000n));
    expect(r.j.success).toBe(false);
    // off_s past calldata (declares off_s huge)
    const t = pad(1n) + pad(0x1000n);
    r = await eq('off_s past end', '0x' + sel(`getS(${Dsig3})`) + pad(0x20n) + t);
    expect(r.j.success).toBe(false);
    // s.len implies payload past end
    const t2 = pad(1n) + pad(0x40n) + pad(0x40n) /* len=64 but no payload */;
    r = await eq('s.len past end', '0x' + sel(`getS(${Dsig3})`) + pad(0x20n) + t2);
    expect(r.j.success).toBe(false);
    // truncated tuple head (only the head word, no tuple)
    r = await eq('truncated tuple', '0x' + sel(`getA(${Dsig3})`) + pad(0x20n));
    expect(r.j.success).toBe(false);
  });

  it('LAZY field validation: getA ignores a malformed UNREAD s (matches solc)', async () => {
    const Dsig4 = '(uint256,string)';
    // a valid `a`, but off_s points past calldata. getA only reads d.a, so the
    // dynamic field is never decoded -> both jeth and solc SUCCEED (lazy access).
    let r = await eq('getA huge off_s unread', '0x' + sel(`getA(${Dsig4})`) + pad(0x20n) + pad(0xabcn) + pad(0x1000n));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0xabcn);
    // off_s in head bounds, but s.len huge (never read): still ignored -> SUCCESS.
    r = await eq('getA huge s.len unread', '0x' + sel(`getA(${Dsig4})`) + pad(0x20n) + pad(0xabcn) + pad(0x40n) + pad(1n << 200n));
    expect(r.j.success).toBe(true);
  });
});
