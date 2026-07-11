// Phase 6: signature recovery. Three surfaces, all differential vs solc 0.8.35:
//  - ecrecover(hash, v, r, s) -> address: the RAW solc builtin (staticcall 0x01). address(0) on any
//    failure, NEVER reverts, NO malleability check. Diffed against solc's own `ecrecover`.
//  - recover(hash, sig) / recover(hash, v, r, s) -> address: the SAFE OZ-5.x ECDSA.recover. Diffed
//    against a hand-written copy of the OZ expansion (the s>HALF_ORDER strict check, the bytes-form
//    length!=65 check, the signer==0 reject, with the exact ECDSAInvalid* custom-error selectors).
//  - tryRecover(hash, sig) -> [bool, address]: the never-reverting form. Diffed against the OZ tryRecover.
//
// A real secp256k1 signature is produced for a fixed (private key, message) so the valid-recovery path
// returns a real signer; the high-s mate and a bad recovery id exercise the reject paths.
//
// NOTE: this surface caught a real miscompile during bring-up: the staticcall-success guard was written
// `and(staticcall(...), eq(returndatasize(), 0x20))`, but Yul evaluates an `and`'s arguments
// right-to-left, so `returndatasize()` was read BEFORE the call ran (stale 0) and every recovery was
// silently discarded to address(0). The fix binds the success bool to a variable first (as solc does).
import { describe, it, expect } from 'vitest';
import { setLengthLeft, bigIntToBytes, bytesToHex } from '@ethereumjs/util';
import { secp256k1 } from 'ethereum-cryptography/secp256k1.js';
import { keccak256 } from 'ethereum-cryptography/keccak.js';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);
const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// Fixed signature vector (deterministic across runs).
const priv = setLengthLeft(bigIntToBytes(0x1234567890abcdefn), 32);
const msgHash = keccak256(Buffer.from('jeth ecrecover vector'));
const sigObj = secp256k1.sign(msgHash, priv);
const v = 27 + sigObj.recovery;
const r = bytesToHex(setLengthLeft(bigIntToBytes(sigObj.r), 32)).slice(2);
const s = bytesToHex(setLengthLeft(bigIntToBytes(sigObj.s), 32)).slice(2);
const hh = bytesToHex(msgHash).slice(2);
// the high-s mate (N - s) with the flipped recovery id: a valid recovery, but malleable
const highS = (SECP_N - sigObj.s).toString(16).padStart(64, '0');
const highV = v === 27 ? 28 : 27;

async function deployJeth(src: string): Promise<{ h: Harness; a: import('@ethereumjs/util').Address }> {
  const h = await Harness.create();
  const a = await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode);
  return { h, a };
}
async function deploySol(src: string): Promise<{ h: Harness; a: import('@ethereumjs/util').Address }> {
  const h = await Harness.create();
  const a = await h.deploy(compileSolidity(SPDX + src, 'C').creation);
  return { h, a };
}
async function diff(jethSrc: string, solSrc: string, calldata: string) {
  const j = await deployJeth(jethSrc);
  const so = await deploySol(solSrc);
  const rj = await j.h.call(j.a, '0x' + calldata);
  const rs = await so.h.call(so.a, '0x' + calldata);
  expect(rj.success, 'success parity').toBe(rs.success);
  expect(rj.returnHex, 'returndata parity').toBe(rs.returnHex);
  return rj;
}

// the OZ 5.x ECDSA expansion, hand-copied as the solc reference.
const OZ_ERRORS = `error ECDSAInvalidSignature(); error ECDSAInvalidSignatureLength(uint256 length); error ECDSAInvalidSignatureS(bytes32 s);`;
const OZ_HALF = '0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0';
const OZ_REC_SPLIT = `function rec(bytes32 h, uint8 vv, bytes32 rr, bytes32 ss) internal pure returns(address){ if(uint256(ss) > ${OZ_HALF}) revert ECDSAInvalidSignatureS(ss); address a=ecrecover(h,vv,rr,ss); if(a==address(0)) revert ECDSAInvalidSignature(); return a; }`;
const OZ_REC_BYTES = `function recb(bytes32 h, bytes calldata sig) internal pure returns(address){ if(sig.length!=65) revert ECDSAInvalidSignatureLength(sig.length); bytes32 rr; bytes32 ss; uint8 vv; assembly { rr:=calldataload(sig.offset) ss:=calldataload(add(sig.offset,0x20)) vv:=byte(0,calldataload(add(sig.offset,0x40))) } return rec(h,vv,rr,ss); }`;
const OZ_TRY = `function tryr(bytes32 h, bytes calldata sig) internal pure returns(bool,address){ if(sig.length!=65) return (false,address(0)); bytes32 rr; bytes32 ss; uint8 vv; assembly { rr:=calldataload(sig.offset) ss:=calldataload(add(sig.offset,0x20)) vv:=byte(0,calldataload(add(sig.offset,0x40))) } if(uint256(ss) > ${OZ_HALF}) return (false,address(0)); address a=ecrecover(h,vv,rr,ss); if(a==address(0)) return (false,address(0)); return (true,a); }`;

describe('ecrecover (raw builtin)', () => {
  const J = `class C { get ec(h: bytes32, v: u8, r: bytes32, s: bytes32): External<address> { return ecrecover(h,v,r,s); } }`;
  const S = `contract C { function ec(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns(address){ return ecrecover(h,v,r,s); } }`;
  const esel = sel('ec(bytes32,uint8,bytes32,bytes32)');

  it('recovers the correct signer for a valid signature (the eval-order regression)', async () => {
    const rj = await diff(J, S, esel + hh + W(BigInt(v)) + r + s);
    // and it is actually the signer, not address(0)
    expect(BigInt(rj.returnHex)).not.toBe(0n);
  });
  it('returns address(0) for a bad recovery id (v=29)', async () => {
    await diff(J, S, esel + hh + W(29n) + r + s);
  });
  it('recovers (no malleability check) for the high-s mate', async () => {
    await diff(J, S, esel + hh + W(BigInt(highV)) + r + highS);
  });
});

describe('recover (safe OZ ECDSA)', () => {
  const SLIB = `contract C { ${OZ_ERRORS} ${OZ_REC_SPLIT} ${OZ_REC_BYTES} function rc(bytes32 h, uint8 v, bytes32 r, bytes32 s) external pure returns(address){ return rec(h,v,r,s); } function rb(bytes32 h, bytes calldata sig) external pure returns(address){ return recb(h,sig); } }`;

  describe('split form recover(hash, v, r, s)', () => {
    const J = `class C { get rc(h: bytes32, v: u8, r: bytes32, s: bytes32): External<address> { return recover(h,v,r,s); } }`;
    const rsel = sel('rc(bytes32,uint8,bytes32,bytes32)');
    it('valid -> signer', async () => {
      await diff(J, SLIB, rsel + hh + W(BigInt(v)) + r + s);
    });
    it('high-s -> revert ECDSAInvalidSignatureS', async () => {
      await diff(J, SLIB, rsel + hh + W(BigInt(highV)) + r + highS);
    });
    it('bad v -> revert ECDSAInvalidSignature', async () => {
      await diff(J, SLIB, rsel + hh + W(29n) + r + s);
    });
  });

  describe('bytes form recover(hash, sig)', () => {
    const J = `class C { get rb(h: bytes32, sig: bytes): External<address> { return recover(h, sig); } }`;
    const rbsel = sel('rb(bytes32,bytes)');
    const OFF = W(0x40n);
    const sig65 = r + s + v.toString(16).padStart(2, '0') + '00'.repeat(31);
    it('valid 65-byte sig -> signer', async () => {
      await diff(J, SLIB, rbsel + hh + OFF + W(65n) + sig65);
    });
    it('length != 65 -> revert ECDSAInvalidSignatureLength', async () => {
      await diff(J, SLIB, rbsel + hh + OFF + W(64n) + r + s);
    });
    it('high-s -> revert ECDSAInvalidSignatureS', async () => {
      const hsig = r + highS + highV.toString(16).padStart(2, '0') + '00'.repeat(31);
      await diff(J, SLIB, rbsel + hh + OFF + W(65n) + hsig);
    });
  });
});

describe('tryRecover (never reverts)', () => {
  const J = `class C { get tr(h: bytes32, sig: bytes): External<[bool, address]> { const [ok, a] = tryRecover(h, sig); return [ok, a]; } }`;
  const S = `contract C { ${OZ_TRY} function tr(bytes32 h, bytes calldata sig) external pure returns(bool,address){ return tryr(h,sig); } }`;
  const trsel = sel('tr(bytes32,bytes)');
  const OFF = W(0x40n);
  const sig65 = r + s + v.toString(16).padStart(2, '0') + '00'.repeat(31);
  it('valid -> (true, signer)', async () => {
    const rj = await diff(J, S, trsel + hh + OFF + W(65n) + sig65);
    expect(rj.returnHex.slice(0, 66)).toBe('0x' + W(1n)); // first word = true
  });
  it('bad length -> (false, address(0))', async () => {
    await diff(J, S, trsel + hh + OFF + W(64n) + r + s);
  });
});
