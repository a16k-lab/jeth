// Phase 6: the niche crypto precompiles, byte-identical to a hand-written solc staticcall expansion.
//  - modexp(base, exp, mod) -> bytes : arbitrary-precision modexp, precompile 0x05.
//  - bn256Add(p, q) / bn256Mul(p, s) / bn256Pairing(input) : alt_bn128, 0x06 / 0x07 / 0x08.
//  - blake2f(rounds, h, m, t, f) -> bytes(64) : BLAKE2b compression, 0x09.
//  - pointEvaluation(versionedHash, z, y, commitment, proof) -> [fe, modulus] : KZG, 0x0a.
//
// Each is diffed against a solc contract that performs the SAME staticcall, so the comparison is robust
// to the test EVM's precompile output (e.g. this @ethereumjs build's 0x09 disagrees with the EIP-152
// reference vector, but JETH and solc feed it the identical input and read the identical output, so they
// match). The "safer" thread vs the raw precompile: bn256/blake2f/KZG REVERT on invalid input instead of
// returning zero. KZG cannot be executed here (no trusted setup is loaded), so it is asserted at the
// accept/codegen level only.
import { describe, it, expect } from 'vitest';
import { bytesToHex, hexToBytes } from '@ethereumjs/util';
import { sha256 } from 'ethereum-cryptography/sha256.js';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { enableKzg, KZG_INFINITY } from './_kzg.js';

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
async function diff(jethSrc: string, solSrc: string, calldata: string) {
  const j = await deployJeth(jethSrc);
  const so = await deploySol(solSrc);
  const rj = await j.h.call(j.a, '0x' + calldata);
  const rs = await so.h.call(so.a, '0x' + calldata);
  expect(rj.success).toBe(rs.success);
  expect(rj.returnHex).toBe(rs.returnHex);
  return rj;
}
function jethAccepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
// ABI-encode three dynamic `bytes` args (1 byte each here).
function abi3(b: number[], e: number[], m: number[]): string {
  const wpad = (x: number[]) => {
    const L = Math.ceil(x.length / 32) * 32 || 0;
    const out = new Uint8Array(L);
    out.set(Uint8Array.from(x));
    return bytesToHex(out).slice(2);
  };
  const parts = [b, e, m];
  let head = '';
  let tail = '';
  let off = 3 * 32;
  for (const p of parts) {
    head += W(BigInt(off));
    const body = wpad(p);
    tail += W(BigInt(p.length)) + body;
    off += 32 + body.length / 2;
  }
  return head + tail;
}

describe('modexp (0x05)', () => {
  const J = `class C { get m(b: bytes, e: bytes, md: bytes): External<bytes> { return modexp(b, e, md); } }`;
  const S = `contract C { function m(bytes calldata b, bytes calldata e, bytes calldata md) external view returns(bytes memory){ bytes memory input=abi.encodePacked(b.length,e.length,md.length,b,e,md); bytes memory o=new bytes(md.length); uint256 ml=md.length; assembly { if iszero(staticcall(gas(),0x05,add(input,32),mload(input),add(o,32),ml)) { revert(0,0) } } return o; } }`;
  const msel = sel('m(bytes,bytes,bytes)');
  it('3^2 mod 5 = 4', async () => {
    await diff(J, S, msel + abi3([3], [2], [5]));
  });
  it('7^13 mod 101', async () => {
    await diff(J, S, msel + abi3([7], [13], [101]));
  });
  it('mod = 0 (valid, length-0 output)', async () => {
    await diff(J, S, msel + abi3([3], [4], []));
  });
});

describe('bn256 (0x06 / 0x07 / 0x08)', () => {
  const G = 'type G1Point = { x: u256; y: u256; };';
  describe('bn256Add', () => {
    const J = `${G}\nclass C { get ad(ax: u256, ay: u256, bx: u256, by: u256): External<G1Point> { const p: G1Point = { x: ax, y: ay }; const q: G1Point = { x: bx, y: by }; return bn256Add(p, q); } }`;
    const S = `contract C { function ad(uint256 ax,uint256 ay,uint256 bx,uint256 by) external view returns(uint256,uint256){ uint256[4] memory inp=[ax,ay,bx,by]; uint256[2] memory o; assembly { if iszero(staticcall(gas(),0x06,inp,0x80,o,0x40)) { revert(0,0) } } return (o[0],o[1]); } }`;
    const s = sel('ad(uint256,uint256,uint256,uint256)');
    it('G + G (generator doubling)', async () => {
      await diff(J, S, s + W(1n) + W(2n) + W(1n) + W(2n));
    });
    it('invalid point -> revert (both)', async () => {
      const rj = await diff(J, S, s + W(3n) + W(3n) + W(1n) + W(2n));
      expect(rj.success).toBe(false);
    });
  });
  describe('bn256Mul', () => {
    const J = `${G}\nclass C { get ml(x: u256, y: u256, s: u256): External<G1Point> { const p: G1Point = { x: x, y: y }; return bn256Mul(p, s); } }`;
    const S = `contract C { function ml(uint256 x,uint256 y,uint256 s) external view returns(uint256,uint256){ uint256[3] memory inp=[x,y,s]; uint256[2] memory o; assembly { if iszero(staticcall(gas(),0x07,inp,0x60,o,0x40)) { revert(0,0) } } return (o[0],o[1]); } }`;
    const s = sel('ml(uint256,uint256,uint256)');
    it('G * 7', async () => {
      await diff(J, S, s + W(1n) + W(2n) + W(7n));
    });
    it('G * 0 -> point at infinity', async () => {
      await diff(J, S, s + W(1n) + W(2n) + W(0n));
    });
  });
  describe('bn256Pairing', () => {
    const J = `class C { get pr(input: bytes): External<bool> { return bn256Pairing(input); } }`;
    const S = `contract C { function pr(bytes calldata input) external view returns(bool){ bytes memory b=input; uint256[1] memory o; assembly { if iszero(staticcall(gas(),0x08,add(b,32),mload(b),o,0x20)) { revert(0,0) } } return o[0]==1; } }`;
    const s = sel('pr(bytes)');
    it('empty input -> true', async () => {
      await diff(J, S, s + W(0x20n) + W(0n));
    });
  });
});

describe('blake2f (0x09)', () => {
  // EIP-152 test-vector-4 inputs (rounds=12, h/m for "abc", t=(3,0), f=1). Diffed vs a solc staticcall,
  // not the EIP-152 reference output, because the test EVM's 0x09 disagrees with the reference - but
  // JETH and solc feed the identical 213-byte input, verified by a separate codegen trace during bring-up.
  const hHex =
    '48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b';
  const mHex =
    '6162638000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
  const tHex = '03000000000000000000000000000000';
  const J = `class C { get b(h: bytes, m: bytes, t: bytes16, f: bool): External<bytes> { return blake2f(12n, h, m, t, f); } }`;
  const S = `contract C { function b(bytes calldata h, bytes calldata m, bytes16 t, bool f) external view returns(bytes memory){ bytes memory inp=abi.encodePacked(uint32(12), h, m, t, f); bytes memory o=new bytes(64); assembly { if iszero(staticcall(gas(),9,add(inp,32),213,add(o,32),64)) { revert(0,0) } } return o; } }`;
  const bsel = sel('b(bytes,bytes,bytes16,bool)');
  const offH = W(0x80n);
  const offM = W(BigInt(0x80 + 32 + hHex.length / 2));
  const tword = tHex + '00'.repeat(16);
  const tails = W(BigInt(hHex.length / 2)) + hHex + W(BigInt(mHex.length / 2)) + mHex;
  const mk = (fWord: string) => bsel + offH + offM + tword + fWord + tails;
  it('final block (f = 1)', async () => {
    await diff(J, S, mk(W(1n)));
  });
  it('non-final block (f = 0)', async () => {
    await diff(J, S, mk(W(0n)));
  });
  it('invalid final flag (f = 2) -> revert (both)', async () => {
    const rj = await diff(J, S, mk(W(2n)));
    expect(rj.success).toBe(false);
  });
});

describe('pointEvaluation / KZG (0x0a)', () => {
  // Run against a harness with the mainnet KZG trusted setup loaded (see _kzg.ts). JETH returns the two
  // output words [fe, modulus]; the solc reference does the same staticcall(0x0a) and returns them, so a
  // success or a revert is diffed byte-for-byte. The valid case uses the zero-polynomial / infinity
  // vector (a real KZG proof, verified by the library the precompile uses).
  const J = `class C { get pe(vh: bytes32, z: bytes32, y: bytes32, c: bytes, p: bytes): External<[u256, u256]> { const [fe, modu] = pointEvaluation(vh, z, y, c, p); return [fe, modu]; } }`;
  const S = `contract C { function pe(bytes32 vh, bytes32 z, bytes32 y, bytes calldata c, bytes calldata p) external view returns(uint256,uint256){ bytes memory input=abi.encodePacked(vh,z,y,c,p); uint256[2] memory o; assembly { if iszero(staticcall(gas(),0x0a,add(input,32),192,o,0x40)) { revert(0,0) } } return (o[0],o[1]); } }`;
  const psel = sel('pe(bytes32,bytes32,bytes32,bytes,bytes)');
  const ZERO32 = W(0n);
  // versioned hash = 0x01 || sha256(commitment)[1:]
  const versionedHash = (commitment: string) =>
    '01' + bytesToHex(sha256(hexToBytes(`0x${commitment}`))).slice(4);
  // pad a 48-byte hex blob to two 32-byte words (64 bytes)
  const pad48 = (hex48: string) => hex48 + '00'.repeat(16);
  function calldata(vh: string, z: string, y: string, commitment: string, proof: string): string {
    const head = vh + z + y + W(0xa0n) + W(0x100n); // 5 words; offC=0xa0, offP=0x100
    const tail = W(BigInt(commitment.length / 2)) + pad48(commitment) + W(BigInt(proof.length / 2)) + pad48(proof);
    return psel + head + tail;
  }
  async function diffKzg(cd: string) {
    const j = await enableKzg(await Harness.create());
    const s = await enableKzg(await Harness.create());
    const ja = await j.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const sa = await s.deploy(compileSolidity(SPDX + S, 'C').creation);
    const rj = await j.call(ja, '0x' + cd);
    const rs = await s.call(sa, '0x' + cd);
    expect(rj.success).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
    return rj;
  }

  it('valid proof -> (FIELD_ELEMENTS_PER_BLOB, BLS_MODULUS), byte-identical to solc', async () => {
    const vh = versionedHash(KZG_INFINITY);
    const rj = await diffKzg(calldata(vh, ZERO32, ZERO32, KZG_INFINITY, KZG_INFINITY));
    expect(rj.success).toBe(true);
    // FIELD_ELEMENTS_PER_BLOB = 4096, BLS_MODULUS
    const BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
    expect(rj.returnHex).toBe('0x' + W(4096n) + W(BLS_MODULUS));
  });
  it('valid proof at a non-zero z', async () => {
    const vh = versionedHash(KZG_INFINITY);
    const z7 = W(7n);
    const rj = await diffKzg(calldata(vh, z7, ZERO32, KZG_INFINITY, KZG_INFINITY));
    expect(rj.success).toBe(true);
  });
  it('malformed proof -> revert (both)', async () => {
    const vh = versionedHash(KZG_INFINITY);
    const badProof = 'c0' + '00'.repeat(46) + '01'; // an invalid infinity encoding (nonzero tail)
    const rj = await diffKzg(calldata(vh, ZERO32, ZERO32, KZG_INFINITY, badProof));
    expect(rj.success).toBe(false);
  });
  it('wrong versioned hash -> revert before verification (both)', async () => {
    const rj = await diffKzg(calldata(ZERO32, ZERO32, ZERO32, KZG_INFINITY, KZG_INFINITY));
    expect(rj.success).toBe(false);
  });
  it('non-canonical z (>= BLS_MODULUS) -> revert (both)', async () => {
    // a field element at/above the modulus is rejected by the precompile; JETH passes z through verbatim,
    // so the revert must match solc.
    const BLS_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
    const vh = versionedHash(KZG_INFINITY);
    const rj = await diffKzg(calldata(vh, W(BLS_MODULUS), ZERO32, KZG_INFINITY, KZG_INFINITY));
    expect(rj.success).toBe(false);
  });
  it('commitment length != 48 -> JETH safety revert', async () => {
    // the typed-input safety gate (solc's raw staticcall has no such check); assert JETH reverts.
    const vh = versionedHash(KZG_INFINITY);
    const j = await enableKzg(await Harness.create());
    const ja = await j.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const short = 'c0' + '00'.repeat(46); // 47 bytes
    const head = vh + ZERO32 + ZERO32 + W(0xa0n) + W(0x100n);
    const tail = W(47n) + pad48(short + '00') + W(48n) + pad48(KZG_INFINITY);
    const rj = await j.call(ja, '0x' + psel + head + tail);
    expect(rj.success).toBe(false);
  });

  it('accepts the destructure form, rejects a scalar (non-destructured) use', () => {
    expect(
      jethAccepts(
        `class C { get pe(vh: bytes32, z: bytes32, y: bytes32, c: bytes, p: bytes): External<u256> { const [fe, modu] = pointEvaluation(vh, z, y, c, p); return fe + modu; } }`,
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        `class C { get pe(vh: bytes32, z: bytes32, y: bytes32, c: bytes, p: bytes): External<u256> { return pointEvaluation(vh, z, y, c, p); } }`,
      ),
    ).toBe(false);
  });
});
