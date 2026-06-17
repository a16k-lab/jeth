// AUDIT: dynamic struct param mixed with static aggregates / other dynamic params.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = (1n << 256n);
function pad(v: bigint): string { return (((v % M) + M) % M).toString(16).padStart(64, '0'); }
const W = (v: bigint) => pad(v);

const JETH = `
@struct class D { a: u256; s: bytes; }
@contract
class A {
  @external @pure aggThenD(p: Arr<u256,3>, d: D): u256 { return d.a; }
  @external @pure aggThenDlen(p: Arr<u256,3>, d: D): u256 { return d.s.length; }
  @external @pure arrThenD(b: u256[], d: D, i: u256): u256 { return d.a; }
  @external @pure dThenArr(d: D, b: u256[], i: u256): u256 { return b[i]; }
  @external @pure dThenArrA(d: D, b: u256[], i: u256): u256 { return d.a; }
  @external @pure twoD(d: D, e: D): u256 { return d.a; }
  @external @pure twoDe(d: D, e: D): u256 { return e.a; }
  @external @pure valDval(x: u256, d: D, y: u256): u256 { return d.a; }
  @external @pure valDvalY(x: u256, d: D, y: u256): u256 { return y; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct D { uint256 a; bytes s; }
  function aggThenD(uint256[3] calldata p, D calldata d) external pure returns (uint256){ return d.a; }
  function aggThenDlen(uint256[3] calldata p, D calldata d) external pure returns (uint256){ return d.s.length; }
  function arrThenD(uint256[] calldata b, D calldata d, uint256 i) external pure returns (uint256){ return d.a; }
  function dThenArr(D calldata d, uint256[] calldata b, uint256 i) external pure returns (uint256){ return b[i]; }
  function dThenArrA(D calldata d, uint256[] calldata b, uint256 i) external pure returns (uint256){ return d.a; }
  function twoD(D calldata d, D calldata e) external pure returns (uint256){ return d.a; }
  function twoDe(D calldata d, D calldata e) external pure returns (uint256){ return e.a; }
  function valDval(uint256 x, D calldata d, uint256 y) external pure returns (uint256){ return d.a; }
  function valDvalY(uint256 x, D calldata d, uint256 y) external pure returns (uint256){ return y; }
}`;

let jeth: Harness, sol: Harness, aj: Address, as: Address;
beforeAll(async () => {
  const jb = compile(JETH, { fileName: 'A.jeth' });
  const sb = compileSolidity(SOL, 'A');
  jeth = await Harness.create(); sol = await Harness.create();
  aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
});
async function eq(label: string, data: string) {
  const j = await jeth.call(aj, data); const s = await sol.call(as, data);
  expect(j.success, `${label}: jeth=${j.success}(${j.exceptionError}) sol=${s.success}`).toBe(s.success);
  expect(j.returnHex, `${label}: rd jeth=${j.returnHex} sol=${s.returnHex}`).toBe(s.returnHex);
  return { j, s };
}

// D tuple encoding given tuple start byte: [a][off_s rel tuple = 0x40][s.len][payload]
function encD(a: bigint, s: string): string {
  const bytes = s.length / 2;
  const words = Math.ceil(bytes / 32);
  const payload = (s + '0'.repeat(words * 64)).slice(0, words * 64);
  return [W(a), W(0x40n), W(BigInt(bytes)), payload].join('');
}

describe('dyn struct mixed positions', () => {
  it('aggThenD: static[3] head then offset to D', async () => {
    // head: p(3) + off_d = 4 words = 0x80. D tuple at 0x80.
    const sel = functionSelector('aggThenD(uint256[3],(uint256,bytes))');
    const head = [W(1n), W(2n), W(3n), W(0x80n)].join('');
    const d = encD(0xaaa1n, '6869'); // "hi"
    await eq('aggThenD', '0x' + sel + head + d);
    const selL = functionSelector('aggThenDlen(uint256[3],(uint256,bytes))');
    await eq('aggThenDlen', '0x' + selL + head + d);
  });

  it('arrThenD: dyn array head, then D; tails sequential', async () => {
    const sel = functionSelector('arrThenD(uint256[],(uint256,bytes),uint256)');
    // head: off_b, off_d, i = 3 words = 0x60. b tail at 0x60 (len1=0x40 bytes). d at 0xA0.
    const head = [W(0x60n), W(0xa0n), W(0n)].join('');
    const bTail = [W(1n), W(0x77n)].join('');
    const d = encD(0xbeefn, '414243'); // "ABC"
    await eq('arrThenD', '0x' + sel + head + bTail + d);
  });

  it('dThenArr: D head then dyn array', async () => {
    const selA = functionSelector('dThenArrA((uint256,bytes),uint256[],uint256)');
    const selB = functionSelector('dThenArr((uint256,bytes),uint256[],uint256)');
    // head: off_d, off_b, i = 3 words = 0x60. d tail at 0x60 (a + off_s + len + payload).
    // "hi" => a(1) + off_s(1) + len(1) + payload(1) = 4 words = 0x80 bytes. b at 0x60+0x80=0xE0.
    const head = [W(0x60n), W(0xe0n), W(0n)].join('');
    const d = encD(0x1234n, '6869');
    const bTail = [W(1n), W(0x88n)].join('');
    await eq('dThenArrA', '0x' + selA + head + d + bTail);
    await eq('dThenArr (b[0])', '0x' + selB + head + d + bTail);
  });

  it('twoD: two dynamic structs, both tails present', async () => {
    const selD = functionSelector('twoD((uint256,bytes),(uint256,bytes))');
    const selE = functionSelector('twoDe((uint256,bytes),(uint256,bytes))');
    // head: off_d, off_e = 2 words = 0x40. d at 0x40 ("x"=4 words=0x80). e at 0xC0.
    const head = [W(0x40n), W(0xc0n)].join('');
    const d = encD(0xd00dn, '78'); // "x"
    const e = encD(0xe11en, '79'); // "y"
    await eq('twoD d.a', '0x' + selD + head + d + e);
    await eq('twoDe e.a', '0x' + selE + head + d + e);
  });

  it('valDval: value, D, value; head cursor + tail', async () => {
    const selA = functionSelector('valDval(uint256,(uint256,bytes),uint256)');
    const selY = functionSelector('valDvalY(uint256,(uint256,bytes),uint256)');
    // head: x, off_d, y = 3 words = 0x60. D at 0x60.
    const head = [W(0xf00dn), W(0x60n), W(0x5151n)].join('');
    const d = encD(0xc0den, '6162636465'); // "abcde" 5 bytes
    await eq('valDval d.a', '0x' + selA + head + d);
    await eq('valDvalY y', '0x' + selY + head + d);
  });
});
