// Phase 6: calldata slicing - `<calldata bytes>.slice(start[, end])`, byte-identical to solc's
// `data[start:end]`. JETH uses a `.slice` method (Solidity's `[start:end]` does not parse in the TS
// subset). A slice is a zero-copy calldata sub-view (dataPtr+start, len = end-start); the bounds check
// reverts EMPTY iff !(start <= end <= baseLen). Only a CALLDATA bytes value is sliceable (a bytes
// parameter, msg.data, or another slice); memory/storage bytes and signed indices are rejected, matching
// solc. Each behavioural case is diffed against the equivalent solc `d[start:end]` contract.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

async function deployJeth(src: string) {
  const h = await Harness.create();
  return { h, a: await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode) };
}
async function deploySol(src: string) {
  const h = await Harness.create();
  return { h, a: await h.deploy(compileSolidity(SPDX + src, 'C').creation) };
}
function jethAccepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
function solAccepts(src: string): boolean {
  try {
    compileSolidity(SPDX + src, 'C');
    return true;
  } catch {
    return false;
  }
}

// a 12-byte calldata bytes argument, ABI-encoded as the single dynamic arg
const D = '00112233445566778899aabb';
const DLEN = BigInt(D.length / 2);
const DPAD = D + '00'.repeat((32 - (D.length / 2) % 32) % 32);
const oneBytesArg = W(0x20n) + W(DLEN) + DPAD;

const J = `@contract class C {
  @external @view tail(data: bytes): bytes { return data.slice(4n); }
  @external @view mid(data: bytes): bytes { return data.slice(2n, 5n); }
  @external @view dyn(data: bytes, s: u256, e: u256): bytes { return data.slice(s, e); }
  @external @view slen(data: bytes, s: u256, e: u256): u256 { return data.slice(s, e).length; }
  @external @view ss(data: bytes): bytes { return data.slice(1n).slice(2n); }
  @external @view u8s(data: bytes, i: u8): bytes { return data.slice(i); }
  @external @view selSkip(): bytes { return msg.data.slice(4n); }
  @external @view oob(): bytes { return msg.data.slice(1000n); }
  @external @view kc(data: bytes): bytes32 { return keccak256(data.slice(2n)); }
  @external @view enc(data: bytes): bytes { return abi.encode(data.slice(2n)); }
  @external @view encp(data: bytes): bytes { return abi.encodePacked(data.slice(2n)); }
  @external @view bind(data: bytes): bytes { const x: bytes = data.slice(2n); return x; }
  @external @pure purep(data: bytes): bytes { return data.slice(4n); }
  @external @view dec(blob: bytes): u256 { return abi.decode(blob.slice(4n), u256); }
  @external @view dec2(blob: bytes): [u256, address] { const [a, b] = abi.decode(blob.slice(4n), [u256, address]); return [a, b]; }
}`;
const S = `contract C {
  function tail(bytes calldata d) external view returns(bytes memory){ return d[4:]; }
  function mid(bytes calldata d) external view returns(bytes memory){ return d[2:5]; }
  function dyn(bytes calldata d, uint s, uint e) external view returns(bytes memory){ return d[s:e]; }
  function slen(bytes calldata d, uint s, uint e) external view returns(uint){ bytes calldata x=d[s:e]; return x.length; }
  function ss(bytes calldata d) external view returns(bytes memory){ return d[1:][2:]; }
  function u8s(bytes calldata d, uint8 i) external view returns(bytes memory){ return d[i:]; }
  function selSkip() external view returns(bytes memory){ return msg.data[4:]; }
  function oob() external view returns(bytes memory){ return msg.data[1000:]; }
  function kc(bytes calldata d) external view returns(bytes32){ return keccak256(d[2:]); }
  function enc(bytes calldata d) external view returns(bytes memory){ return abi.encode(d[2:]); }
  function encp(bytes calldata d) external view returns(bytes memory){ return abi.encodePacked(d[2:]); }
  function bind(bytes calldata d) external view returns(bytes memory){ bytes calldata x=d[2:]; return x; }
  function purep(bytes calldata d) external pure returns(bytes memory){ return d[4:]; }
  function dec(bytes calldata blob) external view returns(uint){ return abi.decode(blob[4:], (uint256)); }
  function dec2(bytes calldata blob) external view returns(uint,address){ return abi.decode(blob[4:], (uint256,address)); }
}`;

async function diff(calldata: string) {
  const j = await deployJeth(J);
  const s = await deploySol(S);
  const rj = await j.h.call(j.a, '0x' + calldata);
  const rs = await s.h.call(s.a, '0x' + calldata);
  expect(rj.success).toBe(rs.success);
  expect(rj.returnHex).toBe(rs.returnHex);
  return rj;
}
const dynCall = (s: bigint, e: bigint) => sel('dyn(bytes,uint256,uint256)') + W(0x60n) + W(s) + W(e) + W(DLEN) + DPAD;

describe('calldata slicing - byte-identical to solc data[start:end]', () => {
  it('tail d[4:]', () => diff(sel('tail(bytes)') + oneBytesArg));
  it('mid d[2:5]', () => diff(sel('mid(bytes)') + oneBytesArg));
  it('slice of slice d[1:][2:]', () => diff(sel('ss(bytes)') + oneBytesArg));
  it('uint8 start index', () => diff(sel('u8s(bytes,uint8)') + W(0x40n) + W(3n) + W(DLEN) + DPAD));
  it('.length of a slice', () => diff(sel('slen(bytes,uint256,uint256)') + W(0x60n) + W(3n) + W(7n) + W(DLEN) + DPAD));
  it('local bind', () => diff(sel('bind(bytes)') + oneBytesArg));
  it('@pure param slice', () => diff(sel('purep(bytes)') + oneBytesArg));
  it('keccak256(d[2:])', () => diff(sel('kc(bytes)') + oneBytesArg));
  it('abi.encode(d[2:])', () => diff(sel('enc(bytes)') + oneBytesArg));
  it('abi.encodePacked(d[2:])', () => diff(sel('encp(bytes)') + oneBytesArg));
  it('msg.data[4:]', () => diff(sel('selSkip()')));
  it('msg.data[1000:] out of range reverts', async () => {
    const r = await diff(sel('oob()'));
    expect(r.success).toBe(false);
  });

  describe('dynamic bounds', () => {
    it('[3:7] ok', () => diff(dynCall(3n, 7n)));
    it('[0:12] whole', () => diff(dynCall(0n, 12n)));
    it('[12:12] empty at end', () => diff(dynCall(12n, 12n)));
    it('[5:5] empty interior', () => diff(dynCall(5n, 5n)));
    it('[7:3] start>end reverts', async () => {
      expect((await diff(dynCall(7n, 3n))).success).toBe(false);
    });
    it('[3:13] end>length reverts', async () => {
      expect((await diff(dynCall(3n, 13n))).success).toBe(false);
    });
  });

  describe('abi.decode of a slice (selector-skip pattern)', () => {
    it('single uint', () => diff(sel('dec(bytes)') + W(0x20n) + W(36n) + 'deadbeef' + W(0x99n) + '00'.repeat(28)));
    it('tuple [uint, address]', () =>
      diff(sel('dec2(bytes)') + W(0x20n) + W(68n) + 'deadbeef' + W(0x99n) + W(0xabcn) + '00'.repeat(28)));
  });
});

// Extended calldata sources (verified byte-identical via the adversarial workflow): string calldata,
// a bytes/string field of a calldata struct param, the zero-arg whole-slice form. A bytes[]/string[]
// calldata ELEMENT slice is NOT supported - blocked by a pre-existing, non-slice gap (JETH has no
// standalone bytes[]/string[] calldata element access in any context; solc's arr[0][1:] cannot be
// mirrored until element access exists).
describe('calldata slicing - extended sources', () => {
  const EJ = `@struct class P { a: u256; data: bytes; }
@struct class Q { a: u256; s: string; }
@contract class C {
  @external @view str1(s: string): string { return s.slice(1n); }
  @external @view str2(s: string): string { return s.slice(1n, 4n); }
  @external @view fld(p: P): bytes { return p.data.slice(1n); }
  @external @view sfld(q: Q): string { return q.s.slice(1n); }
  @external @view whole(d: bytes): bytes { return d.slice(); }
}`;
  const ES = `contract C {
  struct P { uint a; bytes data; }
  struct Q { uint a; string s; }
  function str1(string calldata s) external pure returns(string memory){ return s[1:]; }
  function str2(string calldata s) external pure returns(string memory){ return s[1:4]; }
  function fld(P calldata p) external pure returns(bytes memory){ return p.data[1:]; }
  function sfld(Q calldata q) external pure returns(string memory){ return q.s[1:]; }
  function whole(bytes calldata d) external pure returns(bytes memory){ return d[:]; }
}`;
  const PAD = (h: string) => h + '00'.repeat((32 - (h.length / 2) % 32) % 32);
  async function ediff(calldata: string) {
    const j = await deployJeth(EJ);
    const s = await deploySol(ES);
    const rj = await j.h.call(j.a, '0x' + calldata);
    const rs = await s.h.call(s.a, '0x' + calldata);
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
  }
  const strArg = W(0x20n) + W(5n) + PAD('4142434445'); // "ABCDE"
  it('string param s[1:]', () => ediff(sel('str1(string)') + strArg));
  it('string param s[1:4]', () => ediff(sel('str2(string)') + strArg));
  it('calldata struct bytes field p.data[1:]', () =>
    ediff(sel('fld((uint256,bytes))') + W(0x20n) + W(7n) + W(0x40n) + W(5n) + PAD('aabbccddee')));
  it('calldata struct string field q.s[1:]', () =>
    ediff(sel('sfld((uint256,string))') + W(0x20n) + W(7n) + W(0x40n) + W(5n) + PAD('aabbccddee')));
  it('zero-arg whole slice d[:]', () => ediff(sel('whole(bytes)') + W(0x20n) + W(DLEN) + DPAD));
  it('bytes[] calldata element slice stays rejected (pre-existing element-access gap, not slice-specific)', () => {
    expect(
      jethAccepts(`@contract class C { @external @view f(arr: bytes[]): bytes { return arr[0].slice(1n); } }`),
    ).toBe(false);
    // and the gap is general: plain element access is rejected too, so this is not a slice regression
    expect(jethAccepts(`@contract class C { @external @view f(arr: bytes[]): bytes { return arr[0]; } }`)).toBe(false);
  });
});

describe('calldata slicing - accept/reject parity with solc', () => {
  const cases: { label: string; j: string; s: string }[] = [
    {
      label: 'memory bytes is not sliceable',
      j: `@contract class C { @external @pure f(): bytes { const m: bytes = abi.encodePacked(1n); return m.slice(0n); } }`,
      s: `contract C { function f() external pure returns(bytes memory){ bytes memory m=abi.encodePacked(uint8(1)); return m[0:]; } }`,
    },
    {
      label: 'storage bytes is not sliceable',
      j: `@contract class C { @state s: bytes; @external @view f(): bytes { return this.s.slice(0n); } }`,
      s: `contract C { bytes s; function f() external view returns(bytes memory){ return s[0:]; } }`,
    },
    {
      label: 'signed start index is rejected',
      j: `@contract class C { @external @view f(data: bytes, i: i256): bytes { return data.slice(i); } }`,
      s: `contract C { function f(bytes calldata d, int i) external pure returns(bytes memory){ return d[i:]; } }`,
    },
  ];
  for (const c of cases) {
    it(c.label, () => {
      expect(jethAccepts(c.j)).toBe(solAccepts(c.s));
      expect(jethAccepts(c.j)).toBe(false);
    });
  }
  it('uint8 index is accepted (matches solc)', () => {
    const j = `@contract class C { @external @view f(data: bytes, i: u8): bytes { return data.slice(i); } }`;
    const s = `contract C { function f(bytes calldata d, uint8 i) external pure returns(bytes memory){ return d[i:]; } }`;
    expect(jethAccepts(j)).toBe(true);
    expect(solAccepts(s)).toBe(true);
  });
});
