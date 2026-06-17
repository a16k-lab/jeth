// Tier-1: whole FIXED-array storage copy `this.g = this.src` (was JETH900). Static-element arrays
// copy their slot footprint verbatim; packed elements preserve packing; dynamic-element fixed arrays
// (Arr<string,N>) deep-copy per element. Also `this.g = [a, b, c]` (array literal). Byte-identical to
// solc on returndata AND raw storage slots (incl. keccak data slots for strings).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const b32 = (v: bigint) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex');
const kecSlot = (n: bigint) => BigInt('0x' + toHex(keccak(b32(n))));

const JETH = `@struct class P { a: u256; b: u8; }
@contract class C {
  @state vg: Arr<u256,3>; @state vs: Arr<u256,3>;
  @state pg: Arr<u8,5>;   @state ps: Arr<u8,5>;
  @state sg: Arr<P,2>;    @state ss: Arr<P,2>;
  @state strg: Arr<string,2>; @state strs: Arr<string,2>;
  @state guard: u256;
  @external seed(x: string): void {
    this.vs[0n] = 111n; this.vs[1n] = 222n; this.vs[2n] = 333n;
    this.ps[0n] = 1n; this.ps[1n] = 2n; this.ps[2n] = 3n; this.ps[3n] = 4n; this.ps[4n] = 5n;
    this.ss[0n] = P(7n, 8n); this.ss[1n] = P(9n, 10n);
    this.strs[0n] = x; this.strs[1n] = x;
    this.guard = 0xdeadn;
    // pre-dirty the destinations so a correct copy must overwrite
    this.vg[0n] = 999n; this.pg[0n] = 99n; this.sg[0n] = P(1n,1n); this.strg[0n] = x;
  }
  @external cpVal(): void { this.vg = this.vs; }
  @external cpPacked(): void { this.pg = this.ps; }
  @external cpStruct(): void { this.sg = this.ss; }
  @external cpStr(): void { this.strg = this.strs; }
  @external cpLit(a: u256, b: u256, c: u256): void { this.vg = [a, b, c]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; }
  uint256[3] vg; uint256[3] vs;
  uint8[5] pg; uint8[5] ps;
  P[2] sg; P[2] ss;
  string[2] strg; string[2] strs;
  uint256 guard;
  function seed(string calldata x) external {
    vs[0]=111; vs[1]=222; vs[2]=333;
    ps[0]=1; ps[1]=2; ps[2]=3; ps[3]=4; ps[4]=5;
    ss[0]=P(7,8); ss[1]=P(9,10);
    strs[0]=x; strs[1]=x;
    guard=0xdead;
    vg[0]=999; pg[0]=99; sg[0]=P(1,1); strg[0]=x;
  }
  function cpVal() external { vg = vs; }
  function cpPacked() external { pg = ps; }
  function cpStruct() external { sg = ss; }
  function cpStr() external { strg = strs; }
  function cpLit(uint256 a, uint256 b, uint256 c) external { vg = [a, b, c]; }
}`;

describe('whole fixed-array storage copy vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  // direct slots 0..18 + keccak data slots for the two string arrays (strg @ slot 13, strs @ 15 if layout matches; compare a broad set)
  const SLOTS: bigint[] = [];
  for (let i = 0n; i <= 18n; i++) SLOTS.push(i);
  for (const base of [13n, 14n, 15n, 16n]) { SLOTS.push(kecSlot(base), kecSlot(base) + 1n, kecSlot(kecSlot(base)), kecSlot(kecSlot(base) + 1n)); }
  async function seedBoth(x: string) {
    const data = '0x' + sel('seed(string)') + b32(0x20n).toString('hex') + b32(BigInt(Buffer.byteLength(x))).toString('hex') +
      Buffer.from(x, 'utf8').toString('hex').padEnd(Math.ceil(x.length / 32) * 64, '0');
    await jeth.call(aj, data); await sol.call(as, data);
  }
  async function run(label: string, data: string, x: string) {
    await seedBoth(x);
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
    for (const slot of SLOTS) expect(await readSlot(jeth, aj, slot), `${label} slot ${slot.toString(16)}`).toBe(await readSlot(sol, as, slot));
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  for (const x of ['hi', 'a string longer than thirty-two bytes to exercise the keccak long-data slots']) {
    it(`copy value/packed/struct/string fixed arrays + literal (${x.length <= 2 ? 'short' : 'long'})`, async () => {
      await run('cpVal', encodeCall(sel('cpVal()'), []), x);
      await run('cpPacked', encodeCall(sel('cpPacked()'), []), x);
      await run('cpStruct', encodeCall(sel('cpStruct()'), []), x);
      await run('cpStr', encodeCall(sel('cpStr()'), []), x);
      await run('cpLit', encodeCall(sel('cpLit(uint256,uint256,uint256)'), [5n, 6n, 7n]), x);
    });
  }
});
