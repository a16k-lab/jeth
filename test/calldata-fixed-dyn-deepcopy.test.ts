// W5B shape 1: a CALLDATA fixed-of-dynamic PARAM deep-copied to a MEMORY local
// (`let ys: Arr<string,2> = p` with p: Arr<string,2> calldata), byte-identical to solc's
// `string[2] memory ys = p` calldata->memory copy - Arr<string,N>, Arr<bytes,N>, Arr<u256[],N>
// and the 2-level Arr<string[],N>. ALSO the regression for a pre-existing MISCOMPILE this fix
// closed: forwarding such a param as an INTERNAL-call argument read the per-element offset
// table one word early (aggArgToMemPtr applied the dynamic-outer `[len]` rebase, sub(offset,
// 0x20), to a fixed-outer array that has NO length word), returning wrong element bytes /
// spuriously reverting. Every case is diffed against the equivalent solc 0.8.35 contract.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint | string) => (typeof n === 'string' ? BigInt(n) : BigInt(n)).toString(16).padStart(64, '0');

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  const out: { success: boolean; returnHex: string }[] = [];
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
    out.push(rj);
  }
  return out;
}

// ---- ABI helpers ------------------------------------------------------------------
const encStr = (s: string): string => {
  const h = Buffer.from(s, 'utf8').toString('hex');
  return W(h.length / 2) + (h.length ? h.padEnd(Math.ceil(h.length / 64) * 64, '0') : '');
};
const encU256Arr = (vals: (number | bigint)[]): string => W(vals.length) + vals.map((v) => W(v)).join('');
// heads (relative to the tuple start) then tails
const dynTuple = (tails: string[]): string => {
  let head = '';
  let off = tails.length * 32;
  for (const t of tails) {
    head += W(off);
    off += t.length / 2;
  }
  return head + tails.join('');
};
const LONG = 'a much longer string that exceeds thirty-one bytes!!!';

describe('W5B: calldata fixed-of-dynamic param -> memory local deep copy (byte-identical to solc 0.8.35)', () => {
  const J = `@contract class C {
    @external go(p: Arr<string,2>): bytes {
      let ys: Arr<string,2> = p;
      ys[0n] = "MUT";
      return abi.encode(ys[0n], ys[1n], p[0n], p[1n]);
    }
    @external ret(p: Arr<string,2>): Arr<string,2> { let ys: Arr<string,2> = p; return ys; }
  }`;
  const S = `contract C {
    function go(string[2] calldata p) external pure returns (bytes memory) {
      string[2] memory ys = p;
      ys[0] = "MUT";
      return abi.encode(ys[0], ys[1], p[0], p[1]);
    }
    function ret(string[2] calldata p) external pure returns (string[2] memory) { string[2] memory ys = p; return ys; }
  }`;
  const strArg = (a: string, b: string) => W(32) + dynTuple([encStr(a), encStr(b)]);

  it('Arr<string,2>: deep copy (mutating ys does NOT touch p), empty/short/>31-byte values', async () => {
    const [r] = await eqCalls(J, S, [['go(string[2])', strArg('hi', LONG)]]);
    // non-vacuous: the returned blob carries BOTH the mutated copy ("MUT") and the ORIGINAL p[0] ("hi")
    const hex = r!.returnHex;
    expect(hex).toContain(Buffer.from('MUT', 'utf8').toString('hex'));
    expect(hex).toContain(Buffer.from('hi', 'utf8').toString('hex'));
    await eqCalls(J, S, [
      ['go(string[2])', strArg('', '')],
      ['ret(string[2])', strArg(LONG, 'x')],
      ['ret(string[2])', strArg('', LONG)],
    ]);
  });

  it('Arr<bytes,3> and Arr<u256[],2> (deep copy: ys[0][0]=99 leaves p[0][0] intact)', async () => {
    const J2 = `@contract class C {
      @external b3(p: Arr<bytes,3>): bytes { let ys: Arr<bytes,3> = p; return abi.encode(ys[0n], ys[1n], ys[2n]); }
      @external u2(p: Arr<u256[],2>): bytes { let ys: Arr<u256[],2> = p; ys[0n][0n] = 99n; return abi.encode(ys[0n], ys[1n], p[0n][0n]); }
    }`;
    const S2 = `contract C {
      function b3(bytes[3] calldata p) external pure returns (bytes memory) { bytes[3] memory ys = p; return abi.encode(ys[0], ys[1], ys[2]); }
      function u2(uint256[][2] calldata p) external pure returns (bytes memory) { uint256[][2] memory ys = p; ys[0][0] = 99; return abi.encode(ys[0], ys[1], p[0][0]); }
    }`;
    const encB = (hex: string) => W(hex.length / 2) + (hex.length ? hex.padEnd(Math.ceil(hex.length / 64) * 64, '0') : '');
    await eqCalls(J2, S2, [['b3(bytes[3])', W(32) + dynTuple([encB(''), encB('aabb'), encB('cc'.repeat(40))])]]);
    const [r] = await eqCalls(J2, S2, [['u2(uint256[][2])', W(32) + dynTuple([encU256Arr([7, 8]), encU256Arr([1])])]]);
    expect(r!.returnHex).toContain(W(99)); // the mutated copy
    expect(r!.returnHex).toContain(W(7)); // the untouched calldata original p[0][0]
    await eqCalls(J2, S2, [['u2(uint256[][2])', W(32) + dynTuple([encU256Arr([]), encU256Arr([1])])]]); // OOB write Panic parity
  });

  it('2-level Arr<string[],2> deep copy', async () => {
    const J5 = `@contract class C { @external go(p: Arr<string[],2>): string { let ys: Arr<string[],2> = p; return ys[0n][0n]; } }`;
    const S5 = `contract C { function go(string[][2] calldata p) external pure returns (string memory) { string[][2] memory ys = p; return ys[0][0]; } }`;
    const sArr = (xs: string[]) => W(xs.length) + dynTuple(xs.map(encStr));
    await eqCalls(J5, S5, [['go(string[][2])', W(32) + dynTuple([sArr([LONG]), sArr([])])]]);
  });

  it('malformed calldata reverts byte-identically (huge offset / huge length / truncated tail)', async () => {
    await eqCalls(J, S, [
      ['go(string[2])', W(32) + W('0xffffffffffffffffff') + W(64) + encStr('a')],
      ['go(string[2])', W(32) + W(64) + W(160) + W('0xffffffffffffffffffffff') + 'aa'.repeat(32) + encStr('b')],
      ['go(string[2])', (W(32) + dynTuple([encStr('hi'), encStr('yo')])).slice(0, 64 * 4)],
      ['go(string[2])', W(32) + W(64) + W('0x10000') + encStr('a')],
      ['go(string[2])', W(32) + W(64) + W(128) + W(0x1000) + 'aa'.repeat(32)],
    ]);
  });

  it('MISCOMPILE regression: internal-call arg forwarding of a fixed-of-dynamic calldata param', async () => {
    const J6 = `@contract class C {
      f(x: Arr<string,2>): string { return x[1n]; }
      g(x: Arr<u256[],2>): u256 { return x[1n][0n]; }
      @external go(p: Arr<string,2>): string { return this.f(p); }
      @external gu(p: Arr<u256[],2>): u256 { return this.g(p); }
    }`;
    const S6 = `contract C {
      function f(string[2] memory x) internal pure returns (string memory) { return x[1]; }
      function g(uint256[][2] memory x) internal pure returns (uint256) { return x[1][0]; }
      function go(string[2] calldata p) external pure returns (string memory) { return f(p); }
      function gu(uint256[][2] calldata p) external pure returns (uint256) { return g(p); }
    }`;
    const [r1] = await eqCalls(J6, S6, [['go(string[2])', W(32) + dynTuple([encStr('hi'), encStr(LONG)])]]);
    // non-vacuous: x[1] must be the SECOND element (the old bug returned bytes read one word early)
    expect(r1!.success).toBe(true);
    expect(r1!.returnHex).toContain(Buffer.from(LONG, 'utf8').toString('hex'));
    const [r2] = await eqCalls(J6, S6, [['gu(uint256[][2])', W(32) + dynTuple([encU256Arr([7]), encU256Arr([8, 9])])]]);
    expect(r2!.success).toBe(true); // the old bug spuriously reverted here
    expect(r2!.returnHex).toBe('0x' + pad32(8n));
  });
});
