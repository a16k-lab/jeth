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
    const J = `@contract class D {
      @external @pure dU(b: bytes): u256 { return abi.decode(b, u256); }
      @external @pure dU8(b: bytes): u8 { return abi.decode(b, u8); }
      @external @pure dI(b: bytes): i128 { return abi.decode(b, i128); }
      @external @pure dA(b: bytes): address { return abi.decode(b, address); }
      @external @pure dBool(b: bytes): bool { return abi.decode(b, bool); }
      @external @pure dB4(b: bytes): bytes4 { return abi.decode(b, bytes4); }
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
    const J = `@contract class D {
      @external @pure dS(b: bytes): string { return abi.decode(b, string); }
      @external @pure dB(b: bytes): bytes { return abi.decode(b, bytes); }
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
    const J = `@contract class D {
      @external @pure t2(b: bytes): bytes { let [a, c]: [u256, address] = abi.decode(b, [u256, address]); return abi.encode(a, c); }
      @external @pure tm(b: bytes): bytes { let [n, s]: [u256, string] = abi.decode(b, [u256, string]); return abi.encode(n, s); }
      @external @pure tsn(b: bytes): bytes { let [s, n]: [string, u256] = abi.decode(b, [string, u256]); return abi.encode(s, n); }
      @external @pure t3(b: bytes): bytes { let [a, s, c]: [u256, string, bool] = abi.decode(b, [u256, string, bool]); return abi.encode(a, s, c); }
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

  it('step 4: <bytes>.decode(T) / <bytes>.decode([...]) sugar equals abi.decode', async () => {
    const J = `@contract class D {
      @external @pure m1(b: bytes): string { return b.decode(string); }
      @external @pure m2(b: bytes): u256 { return b.decode(u256); }
      @external @pure mt(b: bytes): bytes { let [a, s]: [u256, string] = b.decode([u256, string]); return abi.encode(a, s); }
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
    const TJ = `@contract class T {
      @external @view getStr(): string { return "hello from target"; }
      @external @view getU(): u256 { return 0xcafen; }
    }`;
    const TS = `contract T {
      function getStr() external pure returns (string memory){ return "hello from target"; }
      function getU() external pure returns (uint256){ return 0xcafe; }
    }`;
    const CJ = `@contract class C {
      @external @view callStr(t: address): string {
        return t.staticcall({ data: abi.encodeWithSignature("getStr()"), success: { condition: this.ok, revert: "f" } }).decode(string);
      }
      @external @view callU(t: address): u256 {
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
    const J = `@contract class D {
      @external @pure dArr(b: bytes): bytes { let xs: u256[] = abi.decode(b, u256[]); return abi.encode(xs); }
      @external @pure dArr8(b: bytes): bytes { let xs: u8[] = abi.decode(b, u8[]); return abi.encode(xs); }
      @external @pure dFix(b: bytes): bytes { let xs: Arr<u256, 3> = abi.decode(b, Arr<u256, 3>); return abi.encode(xs); }
      @external @pure tFix(b: bytes): bytes { let [a, n]: [Arr<u256, 2>, u256] = abi.decode(b, [Arr<u256, 2>, u256]); return abi.encode(a, n); }
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
    @contract class D {
      @external @pure dTok(b: bytes): u256 { let t: Tok = abi.decode(b, Tok); return u256(t); }
      @external @pure dEnum(b: bytes): u8 { let c: Color = abi.decode(b, Color); return u8(c); }
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
    const J = `@contract class D {
      @external @pure mk(): bytes { let xs: u256[] = [11n, 22n, 33n]; return abi.encode(xs, "round trip!"); }
      @external @pure rt(b: bytes): bytes { let [xs, s]: [u256[], string] = abi.decode(b, [u256[], string]); return abi.encode(xs, s); }
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
    expect(jethAccepts(`@contract class C { @external @pure f(b: bytes): u256 { return abi.decode(b, u256); } }`)).toBe(
      true,
    );
    expect(
      jethAccepts(`@contract class C { @external @pure f(b: bytes): string { return abi.decode(b, string); } }`),
    ).toBe(true);
    expect(
      jethAccepts(`@contract class C { @external @pure f(b: bytes): bytes { return abi.decode(b, bytes); } }`),
    ).toBe(true);
    expect(jethAccepts(`@contract class C { @external @pure f(b: bytes): u256 { return b.decode(u256); } }`)).toBe(
      true,
    );
    expect(
      jethAccepts(
        `@contract class C { @external @pure f(b: bytes): bytes { let xs: u256[] = abi.decode(b, u256[]); return abi.encode(xs); } }`,
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        `@contract class C { @external @pure f(b: bytes): bytes { let xs: Arr<u256,3> = abi.decode(b, Arr<u256,3>); return abi.encode(xs); } }`,
      ),
    ).toBe(true);
  });

  it('cleanly rejects (no crash) the unsupported decode targets', () => {
    // a struct target is now SUPPORTED: buildDynStructFromMemBlob builds the pointer-headed image from the
    // decode blob (the decoder the constructor aggregate-param path uses); see arch-abi-decode-aggregate.test.ts
    expect(
      jethAccepts(
        `@struct class P { a: u256; s: string; } @contract class C { @external @pure f(b: bytes): u256 { let p: P = abi.decode(b, P); return p.a; } }`,
      ),
    ).toBe(true);
    // a bytes/string-element array (no JETH memory-local representation)
    expect(
      jethRejects(
        `@contract class C { @external @pure f(b: bytes): bytes { let xs: string[] = abi.decode(b, string[]); return abi.encode(xs); } }`,
      ),
    ).toBe(true);
    // a non-bytes source
    expect(jethRejects(`@contract class C { @external @pure f(n: u256): u256 { return abi.decode(n, u256); } }`)).toBe(
      true,
    );
    // wrong arity
    expect(jethRejects(`@contract class C { @external @pure f(b: bytes): u256 { return abi.decode(b); } }`)).toBe(true);
    // a tuple form used in value position (must be a destructuring)
    expect(
      jethRejects(`@contract class C { @external @pure f(b: bytes): u256 { return abi.decode(b, [u256, address]); } }`),
    ).toBe(true);
    // an unknown type name
    expect(
      jethRejects(`@contract class C { @external @pure f(b: bytes): u256 { return abi.decode(b, NotAType); } }`),
    ).toBe(true);
  });
});
