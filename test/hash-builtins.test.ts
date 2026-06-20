// Differential tests for the hash builtins (Phase 6): sha256 / ripemd160 precompiles, plus the
// keccak256/sha256/ripemd160 arg-type rule (a single `bytes`; string/bytesN are rejected like solc).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);
const cdBytes = (hex: string) => W(0x20n) + W(BigInt(hex.length / 2)) + (hex || '').padEnd(Math.ceil(Math.max(hex.length / 2, 1) / 32) * 64, '0');

function jOk(src: string): boolean { try { compile(src, { fileName: 'C.jeth' }); return true; } catch { return false; } }
function sOk(src: string): boolean { try { compileSolidity(SPDX + src, 'C'); return true; } catch { return false; } }

async function diff(jeth: string, sol: string, calls: { sig: string; args?: string }[]) {
  const jb = compile(jeth, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jb.creationBytecode);
  const as = await hs.deploy(sb.creation);
  for (const c of calls) {
    const data = '0x' + sel(c.sig) + (c.args ?? '');
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig}: returndata`).toBe(rs.returnHex);
  }
}

describe('hash builtins vs Solidity', () => {
  it('sha256 / ripemd160 over bytes (empty, short, long)', async () => {
    const J = `@contract class C { @external @pure s(x: bytes): bytes32 { return sha256(x); } @external @pure r(x: bytes): bytes20 { return ripemd160(x); } }`;
    const S = `contract C { function s(bytes calldata x) external pure returns (bytes32){ return sha256(x); } function r(bytes calldata x) external pure returns (bytes20){ return ripemd160(x); } }`;
    await diff(J, S, [
      { sig: 's(bytes)', args: cdBytes('616263') },
      { sig: 's(bytes)', args: cdBytes('') },
      { sig: 's(bytes)', args: cdBytes('ab'.repeat(50)) },
      { sig: 'r(bytes)', args: cdBytes('616263') },
      { sig: 'r(bytes)', args: cdBytes('') },
    ]);
  });

  it('keccak256/sha256 require a bytes arg (string/bytesN rejected, like solc)', () => {
    for (const fn of ['keccak256', 'sha256', 'ripemd160']) {
      const retTy = fn === 'ripemd160' ? 'bytes20' : 'bytes32';
      const sRetTy = fn === 'ripemd160' ? 'bytes20' : 'bytes32';
      // string arg -> both reject
      const js = `@contract class C { @external @pure f(s: string): ${retTy} { return ${fn}(s); } }`;
      const ss = `contract C { function f(string calldata s) external pure returns (${sRetTy}){ return ${fn}(s); } }`;
      expect(jOk(js), `${fn}(string) JETH`).toBe(false);
      expect(sOk(ss), `${fn}(string) solc`).toBe(false);
    }
  });

  it('hashing a string via abi.encodePacked matches solc', async () => {
    await diff(
      `@contract class C { @external @pure f(s: string): bytes32 { return keccak256(abi.encodePacked(s)); } }`,
      `contract C { function f(string calldata s) external pure returns (bytes32){ return keccak256(abi.encodePacked(s)); } }`,
      [{ sig: 'f(string)', args: cdBytes('68656c6c6f') }],
    );
  });
});
