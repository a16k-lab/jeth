// #7: abi.encode of a FIXED-outer dynamic byte-sequence-leaf FIELD of a MEMORY struct
// (abi.encode(d.tags) where tags: Arr<string,N> / Arr<bytes,N>, isDynBytesFixedLeafArray).
// This was a CONFIRMED MISCOMPILE: the encode-arg materialization treated the field read (an
// arrayValue with a memArrayExpr base wrapping the head-word LOAD of the field's N-pointer image)
// as a [len][elems] value array, double-dereffing the pointer and emitting a runaway blob with
// bogus 0x1840/0x1860 offsets (JETH returned ~6272 bytes for e() where solc returns 384).
//
// The fix adds isDynBytesFixedLeafArray to prepArrayComponent's codecSourced set, so the field read
// rides the SAME nestedMemImagePtr + abiEncFromMem encoder the return path (return d.tags) and the
// aliased-local form (let ys = d.tags; abi.encode(ys)) already use byte-identically.
//
// Every assertion pins a CONCRETE hard-coded solc blob (the >31-byte / empty / mixed-position and
// keccak anchors are non-vacuous: a wrong encoding fails the exact-bytes compare, and a both-revert
// cannot pass a non-empty success blob).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => BigInt(n).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function deployPair(jeth: string, sol: string) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { hj, hs, aj, as };
}

// Every success case asserts a CONCRETE hard-coded return value so a vacuous both-revert cannot pass.
async function eqCalls(jeth: string, sol: string, calls: [string, string, string?][]) {
  const { hj, hs, aj, as } = await deployPair(jeth, sol);
  for (const [sig, args, expectHex] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} jeth vs solc success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} jeth vs solc return`).toBe(rs.returnHex);
    if (expectHex !== undefined) expect(rj.returnHex, `${sig} concrete anchor`).toBe(expectHex);
  }
}

describe('mem-struct fixed-of-dynamic field abi.encode (#7 miscompile)', () => {
  it('Arr<string,2> mem-built local: encode(field) / mixed-position / keccak, exact solc bytes', async () => {
    const J = `
@struct class D { tags: Arr<string,2>; k: u256 }
@contract class C {
  @external @pure e(): bytes { let d: D = D(["ab","cdcd"], 3n); return abi.encode(d.tags); }
  @external @pure eKF(): bytes { let d: D = D(["ab","cdcd"], 3n); return abi.encode(d.k, d.tags); }
  @external @pure eFK(): bytes { let d: D = D(["ab","cdcd"], 3n); return abi.encode(d.tags, d.k); }
  @external @pure kh(): u256 { let d: D = D(["ab","cdcd"], 3n); return u256(keccak256(abi.encode(d.tags))); }
}`;
    const S = `
contract C {
  struct D { string[2] tags; uint256 k; }
  function e() external pure returns (bytes memory) { D memory d = D([string("ab"),string("cdcd")], 3); return abi.encode(d.tags); }
  function eKF() external pure returns (bytes memory) { D memory d = D([string("ab"),string("cdcd")], 3); return abi.encode(d.k, d.tags); }
  function eFK() external pure returns (bytes memory) { D memory d = D([string("ab"),string("cdcd")], 3); return abi.encode(d.tags, d.k); }
  function kh() external pure returns (uint256) { D memory d = D([string("ab"),string("cdcd")], 3); return uint256(keccak256(abi.encode(d.tags))); }
}`;
    // exact solc blobs (generated from solc 0.8.35). e() is 384 bytes (12 words) NOT the 6272-byte runaway.
    const eHex =
      '0x' +
      W(0x20) + W(0xe0) + W(0x20) + W(0x40) + W(0x80) + W(2) +
      '6162'.padEnd(64, '0') + W(4) + '63646364'.padEnd(64, '0');
    const eKFHex =
      '0x' +
      W(0x20) + W(0x100) + W(3) + W(0x40) + W(0x40) + W(0x80) + W(2) +
      '6162'.padEnd(64, '0') + W(4) + '63646364'.padEnd(64, '0');
    const eFKHex =
      '0x' +
      W(0x20) + W(0x100) + W(0x40) + W(3) + W(0x40) + W(0x80) + W(2) +
      '6162'.padEnd(64, '0') + W(4) + '63646364'.padEnd(64, '0');
    await eqCalls(J, S, [
      ['e()', '', eHex],
      ['eKF()', '', eKFHex],
      ['eFK()', '', eFKHex],
      ['kh()', ''], // differential (a wrong blob would hash differently -> a wrong word vs solc)
    ]);
  });

  it('Arr<string,3> with empty / >31-byte elements: differential + first-element anchor', async () => {
    const long = 'this-is-a-string-that-is-longer-than-thirty-two-bytes-here';
    const J = `
@struct class D { tags: Arr<string,3>; k: u256 }
@contract class C {
  @external @pure e(): bytes { let d: D = D(["", "x", "${long}"], 9n); return abi.encode(d.tags); }
  @external @pure eM(): bytes { let d: D = D(["", "x", "${long}"], 9n); return abi.encode(d.k, d.tags); }
}`;
    const S = `
contract C {
  struct D { string[3] tags; uint256 k; }
  function e() external pure returns (bytes memory) { D memory d = D([string(""), "x", "${long}"], 9); return abi.encode(d.tags); }
  function eM() external pure returns (bytes memory) { D memory d = D([string(""), "x", "${long}"], 9); return abi.encode(d.k, d.tags); }
}`;
    await eqCalls(J, S, [
      ['e()', ''],
      ['eM()', ''],
    ]);
  });

  it('Arr<bytes,2> mem-built local: encode(field) exact solc bytes', async () => {
    const J = `
@struct class B { blobs: Arr<bytes,2>; k: u256 }
@contract class C {
  strToBytes(s: string): bytes { return abi.encodePacked(s); }
  @external @pure eb(): bytes { let b: B = B([strToBytes("ab"), strToBytes("cdcd")], 5n); return abi.encode(b.blobs); }
}`;
    const S = `
contract C {
  struct B { bytes[2] blobs; uint256 k; }
  function eb() external pure returns (bytes memory) { B memory b = B([bytes("ab"), bytes("cdcd")], 5); return abi.encode(b.blobs); }
}`;
    const ebHex =
      '0x' +
      W(0x20) + W(0xe0) + W(0x20) + W(0x40) + W(0x80) + W(2) +
      '6162'.padEnd(64, '0') + W(4) + '63646364'.padEnd(64, '0');
    await eqCalls(J, S, [['eb()', '', ebHex]]);
  });

  it('field sources: internal param / nested sub-struct / P[]-element, all differential', async () => {
    const J = `
@struct class D { tags: Arr<string,2>; k: u256 }
@struct class In { tags: Arr<string,2>; z: u256 }
@struct class Ou { t: In; k: u256 }
@struct class P { tags: Arr<string,2>; k: u256 }
@contract class C {
  enc(d: D): bytes { return abi.encode(d.tags); }
  @external @pure param(): bytes { let d: D = D(["aa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"], 1n); return this.enc(d); }
  @external @pure nested(): bytes { let v: Ou = Ou(In(["nn","mmmm"], 4n), 9n); return abi.encode(v.t.tags); }
  @external @pure elem(): bytes { let xs: P[] = [P(["a0","b0"], 1n), P(["a1","b1"], 2n)]; return abi.encode(xs[1n].tags); }
  @external @pure elemM(): bytes { let xs: P[] = [P(["a0","b0"], 1n), P(["a1","b1"], 2n)]; return abi.encode(xs[1n].k, xs[1n].tags); }
}`;
    const S = `
contract C {
  struct D { string[2] tags; uint256 k; }
  struct In { string[2] tags; uint256 z; }
  struct Ou { In t; uint256 k; }
  struct P { string[2] tags; uint256 k; }
  function enc(D memory d) internal pure returns (bytes memory) { return abi.encode(d.tags); }
  function param() external pure returns (bytes memory) { D memory d = D([string("aa"),string("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")], 1); return enc(d); }
  function nested() external pure returns (bytes memory) { Ou memory v = Ou(In([string("nn"),string("mmmm")], 4), 9); return abi.encode(v.t.tags); }
  function mk() internal pure returns (P[] memory) { P[] memory xs = new P[](2); xs[0] = P([string("a0"),string("b0")], 1); xs[1] = P([string("a1"),string("b1")], 2); return xs; }
  function elem() external pure returns (bytes memory) { P[] memory xs = mk(); return abi.encode(xs[1].tags); }
  function elemM() external pure returns (bytes memory) { P[] memory xs = mk(); return abi.encode(xs[1].k, xs[1].tags); }
}`;
    await eqCalls(J, S, [
      ['param()', ''],
      ['nested()', ''],
      ['elem()', ''],
      ['elemM()', ''],
    ]);
  });

  it('UNREGRESSED: Arr<u256[],2> value-leaf twin encode stays byte-identical', async () => {
    const J = `
@struct class D { g: Arr<u256[],2>; k: u256 }
@contract class C {
  @external @pure e(): bytes { let d: D = D([[11n,22n,33n],[44n]], 9n); return abi.encode(d.g); }
  @external @pure eM(): bytes { let d: D = D([[11n,22n,33n],[44n]], 9n); return abi.encode(d.k, d.g); }
}`;
    const S = `
contract C {
  struct D { uint256[][2] g; uint256 k; }
  function mk() internal pure returns (uint256[][2] memory) { uint256[] memory a = new uint256[](3); a[0]=11;a[1]=22;a[2]=33; uint256[] memory b = new uint256[](1); b[0]=44; return [a,b]; }
  function e() external pure returns (bytes memory) { D memory d = D(mk(), 9); return abi.encode(d.g); }
  function eM() external pure returns (bytes memory) { D memory d = D(mk(), 9); return abi.encode(d.k, d.g); }
}`;
    await eqCalls(J, S, [
      ['e()', ''],
      ['eM()', ''],
    ]);
  });

  it('UNREGRESSED: abi.encodePacked(field) rejects on BOTH sides (solc: type not supported in packed mode)', async () => {
    const J = `
@struct class D { tags: Arr<string,2>; k: u256 }
@contract class C {
  @external @pure ep(): bytes { let d: D = D(["ab","cd"], 3n); return abi.encodePacked(d.tags); }
}`;
    // JETH must REJECT (a clean compile error), matching solc's "Type not supported in packed mode".
    expect(() => compile(J, { fileName: 'C.jeth' })).toThrow();
    const S = `
contract C {
  struct D { string[2] tags; uint256 k; }
  function ep() external pure returns (bytes memory) { D memory d = D([string("ab"),string("cd")], 3); return abi.encodePacked(d.tags); }
}`;
    expect(() => compileSolidity(SPDX + S, 'C')).toThrow();
  });
});
