// DELIBERATE SAFE BOUNDARY (JETH stricter-than-solc on MALFORMED calldata) - documented, not a bug.
//
// solc 0.8.35's lazy `abi.encode(<calldata dynamic ref>)` (its abi_encode_..._calldata path) reads each
// dynamic element through SIGNED offset arithmetic (access_calldata_tail sign-extends the offset word) with
// `calldataload` returning 0 past the end of calldata. So when an attacker supplies a dynamic element offset
// with the sign bit set (0x80..00, 0xff..e0, ...), solc does NOT reject it: it reads whatever adjacent / out-of
// -bounds / wrapped calldata that (possibly negative) offset points at and re-encodes those bytes, SUCCEEDING.
//
// JETH instead validates the offset as an unsigned, in-bounds value and REVERTS (empty) on such input. This is
// a SAFE-DIRECTION divergence: JETH never returns wrong bytes; it only refuses to silently process attacker-
// controlled OOB calldata reads that solc tolerates. It is NOT a soundness-bar violation (no miscompile, no
// over-acceptance), and matching solc byte-for-byte would require reproducing its arbitrary signed-tail
// calldata reads - trading a guaranteed-safe revert for a byte-perfect success path over adversarial input.
// Decision: keep JETH's stricter revert; lock it here. Well-formed calldata is byte-identical to solc.
//
// Compared example (bytes[2] param, off0 corrupted to the sign bit):
//   [00] 0x..20 offset to a | [01] 0x80..00 off0 (was 0x40, CORRUPTED) | [02] 0x..80 off1 | [03..] "aa","bb"
//   solc: SUCCESS, elem0 wraps OOB -> calldataload=0 -> empty -> returns abi.encode(["","bb"])
//   JETH: REVERT (empty 0x)
//
// If this test ever fails because JETH now SUCCEEDS here, that means the boundary was changed (e.g. a lazy
// signed-tail encode-from-calldata path was added). That is a conscious decision point: update this file only
// after verifying JETH's success output is byte-identical to solc across the full corruption fuzz.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => (((BigInt(n) % (1n << 256n)) + (1n << 256n)) % (1n << 256n)).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const setWord = (hex: string, i: number, v: bigint) => { const a = hex.match(/.{64}/g)!; a[i] = W(v); return a.join(''); };

const JETH = '@contract class C { @external @pure fw(a: Arr<bytes,2>): bytes { return abi.encode(a); } }';
const SOL = 'contract C { function fw(bytes[2] calldata a) external pure returns(bytes memory){ return abi.encode(a); } }';
// well-formed a = ["aa","bb"]: [off_a=0x20][off0=0x40][off1=0x80][len2,"aa"][len2,"bb"]
const WF = W(0x20) + W(0x40) + W(0x80) + W(2) + '6161'.padEnd(64, '0') + W(2) + '6262'.padEnd(64, '0');

describe('deliberate boundary: signed/OOB calldata offset in lazy abi.encode(<calldata ref>)', () => {
  it('well-formed calldata is byte-identical to solc (proves the divergence is malformed-only)', async () => {
    const hj = await Harness.create(); const hs = await Harness.create();
    const aj: Address = await hj.deploy(compile(JETH, { fileName: 'C.jeth' }).creationBytecode);
    const as: Address = await hs.deploy(compileSolidity(SPDX + SOL, 'C').creation);
    const rj = await hj.call(aj, sel('fw(bytes[2])') + WF);
    const rs = await hs.call(as, sel('fw(bytes[2])') + WF);
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    expect(rj.returnHex).toBe(rs.returnHex); // byte-identical on good input
  });

  it('sign-bit / OOB element offset: JETH safely reverts where solc succeeds (documented boundary)', async () => {
    const hj = await Harness.create(); const hs = await Harness.create();
    const aj: Address = await hj.deploy(compile(JETH, { fileName: 'C.jeth' }).creationBytecode);
    const as: Address = await hs.deploy(compileSolidity(SPDX + SOL, 'C').creation);
    const corruptions: [string, string][] = [
      ['off0 = 0x80..00', setWord(WF, 1, 1n << 255n)],
      ['off0 = 0xff..e0 (= -0x20)', setWord(WF, 1, (1n << 256n) - 0x20n)],
      ['off1 = 0x80..00', setWord(WF, 2, 1n << 255n)],
    ];
    for (const [label, args] of corruptions) {
      const rj = await hj.call(aj, sel('fw(bytes[2])') + args);
      const rs = await hs.call(as, sel('fw(bytes[2])') + args);
      // JETH: stricter - refuses the pathological signed/OOB offset with an empty revert.
      expect(rj.success, `${label}: JETH should revert`).toBe(false);
      expect(rj.returnHex, `${label}: JETH revert is empty (not wrong bytes)`).toBe('0x');
      // solc: tolerant - succeeds by reading the wrapped/OOB calldata via signed access_calldata_tail.
      expect(rs.success, `${label}: solc tolerates it (documents the divergence)`).toBe(true);
    }
  });
});
