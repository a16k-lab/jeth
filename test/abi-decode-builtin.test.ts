// Phase 6: abi.decode(data, T) / abi.decode(data, [T1, ...]) and the chained `<bytes>.decode(T)`
// method sugar. Differential tests vs solc 0.8.35: a JETH decoder and a solc decoder are deployed,
// given the SAME ABI-encoded bytes blob (as a calldata bytes param, or produced by abi.encode on
// both sides), and the decoded result (re-encoded with abi.encode) is diffed byte-for-byte, including
// the malformed-input revert behavior (Panic 0x41 on an oversized length / memory-alloc cap, empty
// revert on an out-of-bounds offset / a length past the blob). The headline `addr.call(...).decode(T)`
// is exercised cross-contract.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const P = (n: bigint) => pad32(n); // 32-byte big-endian word, NO 0x prefix
const PANIC41 = '0x4e487b71' + P(0x41n);

function jethAccepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
function jethRejects(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
}

/** Build calldata for a `fn(bytes)` selector with `payloadHex` (no 0x) as the bytes argument value:
 *  offset(0x20) | len | data (right-padded to a word boundary). */
function cdBytes(fnsig: string, payloadHex: string): string {
  const len = payloadHex.length / 2;
  const padded = payloadHex.padEnd(Math.ceil(payloadHex.length / 64) * 64, '0');
  return '0x' + sel(fnsig) + P(0x20n) + P(BigInt(len)) + padded;
}

/** Deploy a JETH decoder + a solc decoder, then for each (sig, payload) feed the same calldata and
 *  diff success + returndata. The two contracts must expose the SAME external signatures. */
async function rtDecode(jeth: string, sol: string, cases: { sig: string; payload: string; label: string }[]) {
  const jb = compile(jeth, { fileName: 'D.jeth' });
  const sb = compileSolidity(SPDX + sol, 'D');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jb.creationBytecode);
  const as = await hs.deploy(sb.creation);
  for (const c of cases) {
    const d = cdBytes(c.sig, c.payload);
    const rj = await hj.call(aj, d);
    const rs = await hs.call(as, d);
    expect(rj.success, `${c.label}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.label}: returndata`).toBe(rs.returnHex);
  }
}

describe('abi.decode: byte-identical vs solc', () => {
  it('step 1: single value types (uintN/intN/bool/address/bytesN), incl dirty-bit validation', async () => {
    const J = `class D {
      get dU(b: bytes): External<u256> { return abi.decode(b, u256); }
      get dU8(b: bytes): External<u8> { return abi.decode(b, u8); }
      get dI(b: bytes): External<i128> { return abi.decode(b, i128); }
      get dA(b: bytes): External<address> { return abi.decode(b, address); }
      get dBool(b: bytes): External<bool> { return abi.decode(b, bool); }
      get dB4(b: bytes): External<bytes4> { return abi.decode(b, bytes4); }
    }`;
    const S = `contract D {
      function dU(bytes calldata b) external pure returns (uint256){ return abi.decode(b,(uint256)); }
      function dU8(bytes calldata b) external pure returns (uint8){ return abi.decode(b,(uint8)); }
      function dI(bytes calldata b) external pure returns (int128){ return abi.decode(b,(int128)); }
      function dA(bytes calldata b) external pure returns (address){ return abi.decode(b,(address)); }
      function dBool(bytes calldata b) external pure returns (bool){ return abi.decode(b,(bool)); }
      function dB4(bytes calldata b) external pure returns (bytes4){ return abi.decode(b,(bytes4)); }
    }`;
    await rtDecode(J, S, [
      { sig: 'dU(bytes)', payload: P(42n), label: 'u256=42' },
      { sig: 'dU8(bytes)', payload: P(200n), label: 'u8=200' },
      { sig: 'dU8(bytes)', payload: P(300n), label: 'u8=300 dirty -> revert' },
      { sig: 'dI(bytes)', payload: P((1n << 256n) - 5n), label: 'i128=-5' },
      { sig: 'dI(bytes)', payload: P(1n << 200n), label: 'i128 dirty -> revert' },
      { sig: 'dA(bytes)', payload: P(0x1234567890abcdef1234567890abcdef12345678n), label: 'address' },
      { sig: 'dA(bytes)', payload: P((1n << 200n) | 0x12n), label: 'address dirty -> revert' },
      { sig: 'dBool(bytes)', payload: P(1n), label: 'bool=true' },
      { sig: 'dBool(bytes)', payload: P(2n), label: 'bool dirty -> revert' },
      { sig: 'dB4(bytes)', payload: P(0xdeadbeefn << 224n), label: 'bytes4' },
      { sig: 'dU(bytes)', payload: 'aabb', label: 'short blob -> revert' },
    ]);
  });

  it('step 2: dynamic single string / bytes (well-formed + truncated Panic41 + oob offset)', async () => {
    const J = `class D {
      get dS(b: bytes): External<string> { return abi.decode(b, string); }
      get dB(b: bytes): External<bytes> { return abi.decode(b, bytes); }
    }`;
    const S = `contract D {
      function dS(bytes calldata b) external pure returns (string memory){ return abi.decode(b,(string)); }
      function dB(bytes calldata b) external pure returns (bytes memory){ return abi.decode(b,(bytes)); }
    }`;
    const hi = Buffer.from('hello world!').toString('hex');
    const big = 'ab'.repeat(40);
    await rtDecode(J, S, [
      { sig: 'dS(bytes)', payload: P(0x20n) + P(12n) + hi.padEnd(64, '0'), label: 'string ok' },
      { sig: 'dS(bytes)', payload: P(0x20n) + P(0n), label: 'empty string' },
      { sig: 'dB(bytes)', payload: P(0x20n) + P(3n) + 'aabbcc'.padEnd(64, '0'), label: 'bytes ok' },
      { sig: 'dS(bytes)', payload: P(0x20n) + P(40n) + big.padEnd(128, '0'), label: 'string 40B (multi-word)' },
      { sig: 'dS(bytes)', payload: P(0x20n) + P(1n << 65n), label: 'oversized inner len -> Panic41' },
      { sig: 'dS(bytes)', payload: P(0x1000n), label: 'oob offset -> empty revert' },
      {
        sig: 'dS(bytes)',
        payload: P(0x20n) + P(100n) + 'aabb'.padEnd(64, '0'),
        label: 'len past blob -> empty revert',
      },
      { sig: 'dS(bytes)', payload: P(1n << 70n), label: 'huge offset -> empty revert' },
    ]);
  });

  it('step 3: tuple form (static / mixed / dynamic-first / 3-element) via destructuring', async () => {
    const J = `class D {
      get t2(b: bytes): External<bytes> { let [a, c]: [u256, address] = abi.decode(b, [u256, address]); return abi.encode(a, c); }
      get tm(b: bytes): External<bytes> { let [n, s]: [u256, string] = abi.decode(b, [u256, string]); return abi.encode(n, s); }
      get tsn(b: bytes): External<bytes> { let [s, n]: [string, u256] = abi.decode(b, [string, u256]); return abi.encode(s, n); }
      get t3(b: bytes): External<bytes> { let [a, s, c]: [u256, string, bool] = abi.decode(b, [u256, string, bool]); return abi.encode(a, s, c); }
    }`;
    const S = `contract D {
      function t2(bytes calldata b) external pure returns (bytes memory){ (uint256 a, address c)=abi.decode(b,(uint256,address)); return abi.encode(a,c); }
      function tm(bytes calldata b) external pure returns (bytes memory){ (uint256 n, string memory s)=abi.decode(b,(uint256,string)); return abi.encode(n,s); }
      function tsn(bytes calldata b) external pure returns (bytes memory){ (string memory s, uint256 n)=abi.decode(b,(string,uint256)); return abi.encode(s,n); }
      function t3(bytes calldata b) external pure returns (bytes memory){ (uint256 a, string memory s, bool c)=abi.decode(b,(uint256,string,bool)); return abi.encode(a,s,c); }
    }`;
    const str = Buffer.from('mixed!').toString('hex');
    await rtDecode(J, S, [
      { sig: 't2(bytes)', payload: P(7n) + P(0xabcdef1234567890abcdef1234567890abcdef12n), label: '(uint,address)' },
      { sig: 'tm(bytes)', payload: P(99n) + P(0x40n) + P(6n) + str.padEnd(64, '0'), label: '(uint,string)' },
      { sig: 'tsn(bytes)', payload: P(0x40n) + P(123n) + P(6n) + str.padEnd(64, '0'), label: '(string,uint)' },
      {
        sig: 't3(bytes)',
        payload: P(5n) + P(0x60n) + P(1n) + P(6n) + str.padEnd(64, '0'),
        label: '(uint,string,bool)',
      },
      {
        sig: 't3(bytes)',
        payload: P(5n) + P(0x60n) + P(2n) + P(6n) + str.padEnd(64, '0'),
        label: '(uint,string,bool) dirty bool -> revert',
      },
      { sig: 'tm(bytes)', payload: P(99n) + P(0x40n) + P(1n << 65n), label: 'tuple oversized inner -> Panic41' },
      { sig: 'tm(bytes)', payload: P(99n) + P(0x1000n), label: 'tuple oob offset -> empty revert' },
    ]);
  });

  it('step 3b: multi-value abi.decode in DIRECT-RETURN position (byte-identical to solc + to the bind-first twin)', async () => {
    // `return abi.decode(b, [T, U, ...])` forwards its components through the SAME abiDecode-tuple
    // source + tupleDecl/returnTuple machinery the bind-first twin already uses.
    const J = `class D {
      get t2(b: bytes): External<[u256, address]> { return abi.decode(b, [u256, address]); }
      get t3(b: bytes): External<[u256, bool, bytes32]> { return abi.decode(b, [u256, bool, bytes32]); }
      get td(b: bytes): External<[bytes, u256]> { return abi.decode(b, [bytes, u256]); }
      get tsa(b: bytes): External<[string, address]> { return abi.decode(b, [string, address]); }
      get tna(b: bytes): External<[u256[], address]> { return abi.decode(b, [u256[], address]); }
      get tmem(b: bytes): External<[u256, address]> { let m: bytes = b; return abi.decode(m, [u256, address]); }
      get tsug(b: bytes): External<[u256, address]> { return b.decode([u256, address]); }
    }`;
    const S = `contract D {
      function t2(bytes calldata b) external pure returns (uint256, address){ return abi.decode(b,(uint256,address)); }
      function t3(bytes calldata b) external pure returns (uint256, bool, bytes32){ return abi.decode(b,(uint256,bool,bytes32)); }
      function td(bytes calldata b) external pure returns (bytes memory, uint256){ return abi.decode(b,(bytes,uint256)); }
      function tsa(bytes calldata b) external pure returns (string memory, address){ return abi.decode(b,(string,address)); }
      function tna(bytes calldata b) external pure returns (uint256[] memory, address){ return abi.decode(b,(uint256[],address)); }
      function tmem(bytes calldata b) external pure returns (uint256, address){ bytes memory m = b; return abi.decode(m,(uint256,address)); }
      function tsug(bytes calldata b) external pure returns (uint256, address){ return abi.decode(b,(uint256,address)); }
    }`;
    const addr = 0xabcdef1234567890abcdef1234567890abcdef12n;
    const b32 = 'ab'.repeat(32);
    const str = Buffer.from('hello').toString('hex');
    await rtDecode(J, S, [
      { sig: 't2(bytes)', payload: P(7n) + P(addr), label: 'direct [u256,address]' },
      { sig: 't3(bytes)', payload: P(42n) + P(1n) + b32, label: 'direct [u256,bool,bytes32]' },
      { sig: 'td(bytes)', payload: P(0x40n) + P(99n) + P(4n) + 'deadbeef'.padEnd(64, '0'), label: 'direct [bytes,u256] dyn' },
      { sig: 'tsa(bytes)', payload: P(0x40n) + P(addr) + P(5n) + str.padEnd(64, '0'), label: 'direct [string,address] dyn' },
      { sig: 'tna(bytes)', payload: P(0x40n) + P(addr) + P(3n) + P(1n) + P(2n) + P(3n), label: 'direct [u256[],address] nested' },
      { sig: 'tmem(bytes)', payload: P(7n) + P(addr), label: 'direct memory-source' },
      { sig: 'tsug(bytes)', payload: P(9n) + P(addr), label: 'direct <bytes>.decode sugar' },
    ]);

    // internal-consistency: the DIRECT-RETURN form lowers BYTE-IDENTICALLY to the bind-first twin.
    const twin = `class D {
      get t2(b: bytes): External<[u256, address]> { let [x, y]: [u256, address] = abi.decode(b, [u256, address]); return [x, y]; }
      get t3(b: bytes): External<[u256, bool, bytes32]> { let [x, y, z]: [u256, bool, bytes32] = abi.decode(b, [u256, bool, bytes32]); return [x, y, z]; }
      get td(b: bytes): External<[bytes, u256]> { let [x, y]: [bytes, u256] = abi.decode(b, [bytes, u256]); return [x, y]; }
      get tsa(b: bytes): External<[string, address]> { let [x, y]: [string, address] = abi.decode(b, [string, address]); return [x, y]; }
      get tna(b: bytes): External<[u256[], address]> { let [x, y]: [u256[], address] = abi.decode(b, [u256[], address]); return [x, y]; }
      get tmem(b: bytes): External<[u256, address]> { let m: bytes = b; let [x, y]: [u256, address] = abi.decode(m, [u256, address]); return [x, y]; }
      get tsug(b: bytes): External<[u256, address]> { let [x, y]: [u256, address] = b.decode([u256, address]); return [x, y]; }
    }`;
    const direct = compile(J, { fileName: 'D.jeth' }).creationBytecode;
    const bindFirst = compile(twin, { fileName: 'D.jeth' }).creationBytecode;
    expect(direct, 'direct-return lowers byte-identically to bind-first twin').toBe(bindFirst);

    // GUARDS (no over-acceptance): arity / type mismatch vs the declared tuple return still rejects.
    expect(
      jethRejects(`class D { get d(b: bytes): External<[u256, address]> { return abi.decode(b, [u256, address, bool]); } }`),
    ).toBe(true);
    expect(
      jethRejects(`class D { get d(b: bytes): External<[u256, address, bool]> { return abi.decode(b, [u256, address]); } }`),
    ).toBe(true);
    expect(
      jethRejects(`class D { get d(b: bytes): External<[u256, address]> { return abi.decode(b, [u256, u256]); } }`),
    ).toBe(true);
    // a single-type decode into a multi-value return rejects (not silently accepted).
    expect(
      jethRejects(`class D { get d(b: bytes): External<[u256, address]> { return abi.decode(b, u256); } }`),
    ).toBe(true);
  });

  it('step 3c: SINGLE-element decode-list [T] in single-value return (byte-identical to solc + to the abi.decode(b, T) twin)', async () => {
    // DECODE-SINGLE-RETURN: `return abi.decode(b, [T])` (a 1-element type-list) in a SINGLE-VALUE return
    // is exact sugar for `return abi.decode(b, T)` (solc's `return abi.decode(b, (T));`; a 1-element
    // parenthesized type is one value). Previously rejected JETH323 (the multi-value return path never ran
    // for a single-value return type, so it fell to the value-position tuple-decode reject). Both calldata
    // and memory decode sources, across value / address / bytes32 / dynamic-bytes / struct targets.
    const J = `type P = { a: u256; b: address };
    class D {
      get c_u256(b: bytes): External<u256> { return abi.decode(b, [u256]); }
      get c_addr(b: bytes): External<address> { return abi.decode(b, [address]); }
      get c_b32(b: bytes): External<bytes32> { return abi.decode(b, [bytes32]); }
      get c_struct(b: bytes): External<P> { return abi.decode(b, [P]); }
      get c_bytes(b: bytes): External<bytes> { return abi.decode(b, [bytes]); }
      get m_u256(x: u256): External<u256> { let m: bytes = abi.encode(x); return abi.decode(m, [u256]); }
      get m_bytes(x: bytes): External<bytes> { let m: bytes = abi.encode(x); return abi.decode(m, [bytes]); }
      get m_struct(a: u256, bb: address): External<P> { let p: P = { a: a, b: bb }; let m: bytes = abi.encode(p); return abi.decode(m, [P]); }
      get sug(b: bytes): External<u256> { return b.decode([u256]); }
    }`;
    const S = `contract D {
      struct P { uint256 a; address b; }
      function c_u256(bytes calldata b) external pure returns (uint256) { return abi.decode(b, (uint256)); }
      function c_addr(bytes calldata b) external pure returns (address) { return abi.decode(b, (address)); }
      function c_b32(bytes calldata b) external pure returns (bytes32) { return abi.decode(b, (bytes32)); }
      function c_struct(bytes calldata b) external pure returns (P memory) { return abi.decode(b, (P)); }
      function c_bytes(bytes calldata b) external pure returns (bytes memory) { return abi.decode(b, (bytes)); }
      function m_u256(uint256 x) external pure returns (uint256) { bytes memory m = abi.encode(x); return abi.decode(m, (uint256)); }
      function m_bytes(bytes calldata x) external pure returns (bytes memory) { bytes memory m = abi.encode(x); return abi.decode(m, (bytes)); }
      function m_struct(uint256 a, address bb) external pure returns (P memory) { P memory p = P(a, bb); bytes memory m = abi.encode(p); return abi.decode(m, (P)); }
      function sug(bytes calldata b) external pure returns (uint256) { return abi.decode(b, (uint256)); }
    }`;
    const addr = 0xabcdef1234567890abcdef1234567890abcdef12n;
    const b32 = 'ab'.repeat(32);
    const innerBytes = P(0x20n) + P(2n) + '1234'.padEnd(64, '0'); // abi.encode(bytes 0x1234)
    await rtDecode(J, S, [
      { sig: 'c_u256(bytes)', payload: P(42n), label: '[u256] calldata' },
      { sig: 'c_addr(bytes)', payload: P(addr), label: '[address] calldata' },
      { sig: 'c_b32(bytes)', payload: b32, label: '[bytes32] calldata' },
      { sig: 'c_struct(bytes)', payload: P(7n) + P(addr), label: '[P] struct calldata' },
      { sig: 'c_bytes(bytes)', payload: innerBytes, label: '[bytes] dynamic calldata' },
      { sig: 'm_u256(uint256)', payload: P(99n), label: '[u256] memory-source' },
      { sig: 'm_bytes(bytes)', payload: P(0x20n) + P(2n) + '1234'.padEnd(64, '0'), label: '[bytes] memory-source' },
      { sig: 'm_struct(uint256,address)', payload: P(5n) + P(addr), label: '[P] struct memory-source' },
      { sig: 'sug(bytes)', payload: P(123n), label: '<bytes>.decode([u256]) sugar' },
    ]);

    // internal-consistency: the [T] list form lowers BYTE-IDENTICALLY to the canonical abi.decode(b, T) twin.
    const twin = J
      .replace(/\[u256\]/g, 'u256')
      .replace(/\[address\]/g, 'address')
      .replace(/\[bytes32\]/g, 'bytes32')
      .replace(/\[P\]/g, 'P')
      .replace(/\[bytes\]/g, 'bytes');
    const list = compile(J, { fileName: 'D.jeth' }).creationBytecode;
    const single = compile(twin, { fileName: 'D.jeth' }).creationBytecode;
    expect(list, 'single-element [T] return lowers byte-identically to the abi.decode(b, T) twin').toBe(single);

    // GUARDS (no over-acceptance): a genuine type mismatch [u256] into External<address> rejects; a
    // NON-return single-element decode (value position) stays a JETH323 reject; a 2+-element list into a
    // single-value return stays a JETH323 arity reject.
    expect(
      jethRejects(`class D { get d(b: bytes): External<address> { return abi.decode(b, [u256]); } }`),
    ).toBe(true);
    expect(
      jethRejects(`class D { get d(b: bytes): External<u256> { let x: u256 = abi.decode(b, [u256]); return x; } }`),
    ).toBe(true);
    expect(
      jethRejects(`class D { get d(b: bytes): External<u256> { return abi.decode(b, [u256, address]); } }`),
    ).toBe(true);
  });

  it('step 4: <bytes>.decode(T) / <bytes>.decode([...]) sugar equals abi.decode', async () => {
    const J = `class D {
      get m1(b: bytes): External<string> { return b.decode(string); }
      get m2(b: bytes): External<u256> { return b.decode(u256); }
      get mt(b: bytes): External<bytes> { let [a, s]: [u256, string] = b.decode([u256, string]); return abi.encode(a, s); }
    }`;
    const S = `contract D {
      function m1(bytes calldata b) external pure returns (string memory){ return abi.decode(b,(string)); }
      function m2(bytes calldata b) external pure returns (uint256){ return abi.decode(b,(uint256)); }
      function mt(bytes calldata b) external pure returns (bytes memory){ (uint256 a, string memory s)=abi.decode(b,(uint256,string)); return abi.encode(a,s); }
    }`;
    const str = Buffer.from('sugar test').toString('hex');
    await rtDecode(J, S, [
      { sig: 'm1(bytes)', payload: P(0x20n) + P(10n) + str.padEnd(64, '0'), label: '.decode(string)' },
      { sig: 'm2(bytes)', payload: P(777n), label: '.decode(u256)' },
      { sig: 'mt(bytes)', payload: P(5n) + P(0x40n) + P(10n) + str.padEnd(64, '0'), label: '.decode([u256,string])' },
    ]);
  });

  it('step 4b: HEADLINE addr.staticcall({...}).decode(T) cross-contract', async () => {
    const TJ = `class T {
      get getStr(): External<string> { return "hello from target"; }
      get getU(): External<u256> { return 0xcafen; }
    }`;
    const TS = `contract T {
      function getStr() external pure returns (string memory){ return "hello from target"; }
      function getU() external pure returns (uint256){ return 0xcafe; }
    }`;
    const CJ = `class C {
      get callStr(t: address): External<string> {
        return t.staticcall({ data: abi.encodeWithSignature("getStr()"), success: { condition: this.ok, revert: "f" } }).decode(string);
      }
      get callU(t: address): External<u256> {
        return t.staticcall({ data: abi.encodeWithSignature("getU()"), success: { condition: this.ok, revert: "f" } }).decode(u256);
      }
    }`;
    const CS = `contract C {
      function callStr(address t) external view returns (string memory){
        (bool ok, bytes memory r) = t.staticcall(abi.encodeWithSignature("getStr()")); require(ok,"f");
        return abi.decode(r,(string));
      }
      function callU(address t) external view returns (uint256){
        (bool ok, bytes memory r) = t.staticcall(abi.encodeWithSignature("getU()")); require(ok,"f");
        return abi.decode(r,(uint256));
      }
    }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const tj = await hj.deploy(compile(TJ, { fileName: 'T.jeth' }).creationBytecode);
    const ts = await hs.deploy(compileSolidity(SPDX + TS, 'T').creation);
    const cj = await hj.deploy(compile(CJ, { fileName: 'C.jeth' }).creationBytecode);
    const cs = await hs.deploy(compileSolidity(SPDX + CS, 'C').creation);
    for (const sig of ['callStr(address)', 'callU(address)']) {
      const rj = await hj.call(cj, '0x' + sel(sig) + P(BigInt(tj.toString())));
      const rs = await hs.call(cs, '0x' + sel(sig) + P(BigInt(ts.toString())));
      expect(rj.success, `${sig}: success`).toBe(rs.success);
      expect(rj.returnHex, `${sig}: returndata`).toBe(rs.returnHex);
    }
  });

  it('step 5: dynamic value-array T[] and static Arr<T,N> (well-formed + bounds)', async () => {
    const J = `class D {
      get dArr(b: bytes): External<bytes> { let xs: u256[] = abi.decode(b, u256[]); return abi.encode(xs); }
      get dArr8(b: bytes): External<bytes> { let xs: u8[] = abi.decode(b, u8[]); return abi.encode(xs); }
      get dFix(b: bytes): External<bytes> { let xs: Arr<u256, 3> = abi.decode(b, Arr<u256, 3>); return abi.encode(xs); }
      get tFix(b: bytes): External<bytes> { let [a, n]: [Arr<u256, 2>, u256] = abi.decode(b, [Arr<u256, 2>, u256]); return abi.encode(a, n); }
    }`;
    const S = `contract D {
      function dArr(bytes calldata b) external pure returns (bytes memory){ uint256[] memory xs=abi.decode(b,(uint256[])); return abi.encode(xs); }
      function dArr8(bytes calldata b) external pure returns (bytes memory){ uint8[] memory xs=abi.decode(b,(uint8[])); return abi.encode(xs); }
      function dFix(bytes calldata b) external pure returns (bytes memory){ uint256[3] memory xs=abi.decode(b,(uint256[3])); return abi.encode(xs); }
      function tFix(bytes calldata b) external pure returns (bytes memory){ (uint256[2] memory a, uint256 n)=abi.decode(b,(uint256[2],uint256)); return abi.encode(a,n); }
    }`;
    await rtDecode(J, S, [
      { sig: 'dArr(bytes)', payload: P(0x20n) + P(3n) + P(10n) + P(20n) + P(30n), label: 'u256[] ok' },
      { sig: 'dArr(bytes)', payload: P(0x20n) + P(0n), label: 'u256[] empty' },
      { sig: 'dArr8(bytes)', payload: P(0x20n) + P(2n) + P(5n) + P(300n), label: 'u8[] dirty elem -> revert' },
      { sig: 'dArr8(bytes)', payload: P(0x20n) + P(2n) + P(5n) + P(7n), label: 'u8[] ok' },
      { sig: 'dArr(bytes)', payload: P(0x20n) + P(1n << 64n), label: 'u256[] oversized len -> Panic41' },
      { sig: 'dArr(bytes)', payload: P(0x20n) + P(5n) + P(1n), label: 'u256[] truncated -> empty revert' },
      { sig: 'dFix(bytes)', payload: P(1n) + P(2n) + P(3n), label: 'Arr<u256,3> ok' },
      { sig: 'dFix(bytes)', payload: P(1n) + P(2n), label: 'Arr<u256,3> truncated -> empty revert' },
      { sig: 'tFix(bytes)', payload: P(7n) + P(8n) + P(99n), label: '(Arr<u256,2>,u256) ok' },
      { sig: 'tFix(bytes)', payload: P(7n) + P(8n), label: '(Arr<u256,2>,u256) truncated -> empty revert' },
    ]);
  });

  it('step 5b: enum and branded-newtype targets (incl out-of-range enum -> empty revert)', async () => {
    const J = `type Tok = Brand<u256>;
    enum Color { Red, Green, Blue }
    class D {
      get dTok(b: bytes): External<u256> { let t: Tok = abi.decode(b, Tok); return u256(t); }
      get dEnum(b: bytes): External<u8> { let c: Color = abi.decode(b, Color); return u8(c); }
    }`;
    const jb = compile(J, { fileName: 'D.jeth' });
    // solc mirror: a plain uint256 decode for the brand, and a Color enum decode in a second contract.
    const STok = `contract D { function dTok(bytes calldata b) external pure returns (uint256){ return abi.decode(b,(uint256)); } }`;
    const SEnum = `contract E { enum Color { Red, Green, Blue } function dEnum(bytes calldata b) external pure returns (uint8){ return uint8(abi.decode(b,(Color))); } }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(jb.creationBytecode);
    const asTok = await hs.deploy(compileSolidity(SPDX + STok, 'D').creation);
    const asEnum = await hs.deploy(compileSolidity(SPDX + SEnum, 'E').creation);
    const rjT = await hj.call(aj, cdBytes('dTok(bytes)', P(12345n)));
    const rsT = await hs.call(asTok, cdBytes('dTok(bytes)', P(12345n)));
    expect(rjT.success).toBe(rsT.success);
    expect(rjT.returnHex).toBe(rsT.returnHex);
    for (const v of [0n, 1n, 2n, 3n, 5n]) {
      const rj = await hj.call(aj, cdBytes('dEnum(bytes)', P(v)));
      const rs = await hs.call(asEnum, cdBytes('dEnum(bytes)', P(v)));
      expect(rj.success, `enum=${v}: success`).toBe(rs.success);
      expect(rj.returnHex, `enum=${v}: returndata`).toBe(rs.returnHex);
    }
  });

  it('round-trips a well-formed mixed-dynamic tuple (u256[], string) byte-identically', async () => {
    const J = `class D {
      get mk(): External<bytes> { let xs: u256[] = [11n, 22n, 33n]; return abi.encode(xs, "round trip!"); }
      get rt(b: bytes): External<bytes> { let [xs, s]: [u256[], string] = abi.decode(b, [u256[], string]); return abi.encode(xs, s); }
    }`;
    const S = `contract D {
      function mk() external pure returns (bytes memory){ uint256[] memory xs = new uint256[](3); xs[0]=11; xs[1]=22; xs[2]=33; return abi.encode(xs, "round trip!"); }
      function rt(bytes calldata b) external pure returns (bytes memory){ (uint256[] memory xs, string memory s)=abi.decode(b,(uint256[],string)); return abi.encode(xs,s); }
    }`;
    const jb = compile(J, { fileName: 'D.jeth' });
    const sb = compileSolidity(SPDX + S, 'D');
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(jb.creationBytecode);
    const as = await hs.deploy(sb.creation);
    const mkj = await hj.call(aj, '0x' + sel('mk()'));
    const mks = await hs.call(as, '0x' + sel('mk()'));
    expect(mkj.returnHex).toBe(mks.returnHex);
    // extract the inner bytes payload (skip the 0x20 offset + len wrapper)
    const h = mkj.returnHex.slice(2);
    const innerLen = parseInt(h.slice(64, 128), 16);
    const payload = h.slice(128, 128 + innerLen * 2);
    const d = cdBytes('rt(bytes)', payload);
    const rj = await hj.call(aj, d);
    const rs = await hs.call(as, d);
    expect(rj.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex);
  });

  it('accepts the supported decode targets', () => {
    expect(jethAccepts(`class C { get f(b: bytes): External<u256> { return abi.decode(b, u256); } }`)).toBe(
      true,
    );
    expect(
      jethAccepts(`class C { get f(b: bytes): External<string> { return abi.decode(b, string); } }`),
    ).toBe(true);
    expect(
      jethAccepts(`class C { get f(b: bytes): External<bytes> { return abi.decode(b, bytes); } }`),
    ).toBe(true);
    expect(jethAccepts(`class C { get f(b: bytes): External<u256> { return b.decode(u256); } }`)).toBe(
      true,
    );
    expect(
      jethAccepts(
        `class C { get f(b: bytes): External<bytes> { let xs: u256[] = abi.decode(b, u256[]); return abi.encode(xs); } }`,
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        `class C { get f(b: bytes): External<bytes> { let xs: Arr<u256,3> = abi.decode(b, Arr<u256,3>); return abi.encode(xs); } }`,
      ),
    ).toBe(true);
  });

  it('cleanly rejects (no crash) the unsupported decode targets', () => {
    // a struct target is now SUPPORTED: buildDynStructFromMemBlob builds the pointer-headed image from the
    // decode blob (the decoder the constructor aggregate-param path uses); see arch-abi-decode-aggregate.test.ts
    expect(
      jethAccepts(
        `type P = { a: u256; s: string; }; class C { get f(b: bytes): External<u256> { let p: P = abi.decode(b, P); return p.a; } }`,
      ),
    ).toBe(true);
    // Residual C lifted a bytes/string-element array (string[]/bytes[]) as a decode target + Residual B
    // memory-array local: now ACCEPTED (the decode + re-encode round-trip compiles; byte-identical decode is
    // verified in arch-residual-c-decode-array.test.ts).
    expect(
      jethAccepts(
        `class C { get f(b: bytes): External<bytes> { let xs: string[] = abi.decode(b, string[]); return abi.encode(xs); } }`,
      ),
    ).toBe(true);
    // a non-bytes source
    expect(jethRejects(`class C { get f(n: u256): External<u256> { return abi.decode(n, u256); } }`)).toBe(
      true,
    );
    // wrong arity
    expect(jethRejects(`class C { get f(b: bytes): External<u256> { return abi.decode(b); } }`)).toBe(true);
    // a tuple form used in value position (must be a destructuring)
    expect(
      jethRejects(`class C { get f(b: bytes): External<u256> { return abi.decode(b, [u256, address]); } }`),
    ).toBe(true);
    // an unknown type name
    expect(
      jethRejects(`class C { get f(b: bytes): External<u256> { return abi.decode(b, NotAType); } }`),
    ).toBe(true);
  });
});
