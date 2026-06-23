// AUDIT: random calldata fuzz over aggregate-param functions, JETH vs solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const JETH = `
@struct class P { x: u128; y: u128; }
@struct class Acct { bal: u128; nonce: u64; active: bool; }
@struct class Outer { p: u64; inner: P; q: u64; }
@struct class WithArr { id: u64; data: Arr<u256, 2>; }
@contract
class A {
  @external @pure sumTriple(a: Arr<u256, 3>): u256 { return a[0n] + a[1n] + a[2n]; }
  @external @pure pick(a: Arr<u8, 4>, i: u256): u8 { return a[i]; }
  @external @pure acctNonce(a: Acct): u64 { return a.nonce; }
  @external @pure outerQ(o: Outer): u64 { return o.q; }
  @external @pure dataAt(t: WithArr, j: u256): u256 { return t.data[j]; }
  @external @pure ptsX(ps: Arr<P, 2>, i: u256): u128 { return ps[i].x; }
  @external @pure aggThenArr(a: Arr<u256, 3>, b: u256[], i: u256): u256 { return b[i]; }
  @external @pure arrAt(b: u256[], i: u256): u256 { return b[i]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct P { uint128 x; uint128 y; }
  struct Acct { uint128 bal; uint64 nonce; bool active; }
  struct Outer { uint64 p; P inner; uint64 q; }
  struct WithArr { uint64 id; uint256[2] data; }
  function sumTriple(uint256[3] calldata a) external pure returns (uint256){ return a[0]+a[1]+a[2]; }
  function pick(uint8[4] calldata a, uint256 i) external pure returns (uint8){ return a[i]; }
  function acctNonce(Acct calldata a) external pure returns (uint64){ return a.nonce; }
  function outerQ(Outer calldata o) external pure returns (uint64){ return o.q; }
  function dataAt(WithArr calldata t, uint256 j) external pure returns (uint256){ return t.data[j]; }
  function ptsX(P[2] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].x; }
  function aggThenArr(uint256[3] calldata a, uint256[] calldata b, uint256 i) external pure returns (uint256){ return b[i]; }
  function arrAt(uint256[] calldata b, uint256 i) external pure returns (uint256){ return b[i]; }
}`;

const SIGS: Record<string, string> = {
  sumTriple: 'sumTriple(uint256[3])',
  pick: 'pick(uint8[4],uint256)',
  acctNonce: 'acctNonce((uint128,uint64,bool))',
  outerQ: 'outerQ((uint64,(uint128,uint128),uint64))',
  dataAt: 'dataAt((uint64,uint256[2]),uint256)',
  ptsX: 'ptsX((uint128,uint128)[2],uint256)',
  aggThenArr: 'aggThenArr(uint256[3],uint256[],uint256)',
  arrAt: 'arrAt(uint256[],uint256)',
};

let jeth: Harness, sol: Harness, aj: Address, as: Address;
beforeAll(async () => {
  const jb = compile(JETH, { fileName: 'A.jeth' });
  const sb = compileSolidity(SOL, 'A');
  jeth = await Harness.create();
  sol = await Harness.create();
  aj = await jeth.deploy(jb.creationBytecode);
  as = await sol.deploy(sb.creation);
});

// deterministic xorshift RNG for reproducibility
function makeRng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s;
  };
}

function randWord(rng: () => number): string {
  // bias toward small values, 0, all-ones, and powers of two for boundary coverage
  const r = rng() % 10;
  if (r === 0) return '00'.repeat(32);
  if (r === 1) return 'ff'.repeat(32);
  if (r === 2) return (rng() % 8).toString(16).padStart(64, '0');
  if (r === 3) {
    const k = rng() % 256;
    const v = 1n << BigInt(k);
    return v.toString(16).padStart(64, '0').slice(-64);
  }
  // small-ish offsets/lengths
  if (r === 4) return (rng() % 0x200).toString(16).padStart(64, '0');
  // full random
  let h = '';
  for (let k = 0; k < 8; k++) h += (rng() >>> 0).toString(16).padStart(8, '0');
  return h;
}

describe('random calldata fuzz: JETH must equal solc on every input', () => {
  it('fuzz all 8 functions x many random calldatas', async () => {
    const rng = makeRng(0xc0ffee);
    let diverged = 0;
    const examples: string[] = [];
    for (const [name, sig] of Object.entries(SIGS)) {
      const selHex = functionSelector(sig);
      for (let iter = 0; iter < 200; iter++) {
        // random number of words 0..12
        const nwords = rng() % 13;
        let body = '';
        for (let w = 0; w < nwords; w++) body += randWord(rng);
        // occasionally chop a few bytes off to test sub-word truncation
        if (rng() % 4 === 0 && body.length >= 8) body = body.slice(0, body.length - 2 * (1 + (rng() % 4)));
        const data = '0x' + selHex + body;
        const j = await jeth.call(aj, data);
        const s = await sol.call(as, data);
        if (j.success !== s.success || j.returnHex !== s.returnHex) {
          diverged++;
          if (examples.length < 8) {
            examples.push(
              `${name} data=${data}\n   jeth=${j.success}/${j.returnHex} (${j.exceptionError})\n   sol =${s.success}/${s.returnHex}`,
            );
          }
        }
      }
    }
    if (diverged) console.log(`DIVERGENCES (${diverged}):\n` + examples.join('\n'));
    expect(diverged, examples.join('\n')).toBe(0);
  }, 120000);
});
