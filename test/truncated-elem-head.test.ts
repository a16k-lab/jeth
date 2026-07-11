// Phase 4 final-audit bugs #1/#2/#3 regression: when decoding/echoing a calldata
// dynamic-struct element (D[], Arr<D,N>, or a dynamic-struct field), the FULL element
// tuple head (headWords*32 bytes) must be calldata-readable before recursing. A
// truncated element head must revert EMPTY exactly like solc, never silently over-read.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const pad = (v: bigint) => v.toString(16).padStart(64, '0');

// D = { uint256 a; string s } -> tuple head = 2 words (a, offset-to-s) = 64 bytes.
const JETH = `type D = { a: u256; s: string; };
class T {
  get echo(xs: D[]): External<D[]> { return xs; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract T {
  struct D { uint256 a; string s; }
  function echo(D[] calldata xs) external pure returns (D[] memory){ return xs; }
}`;

describe('truncated dynamic-struct element head reverts like solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const selHex = functionSelector('echo((uint256,string)[])');
  async function both(data: string, label: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label}: success parity (jeth=${j.success}/${j.exceptionError}, sol=${s.success})`).toBe(
      s.success,
    );
    expect(j.returnHex, `${label}: returndata parity`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'T.jeth' });
    const sb = compileSolidity(SOL, 'T');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('element head truncated to one word (a present, offset-to-s missing) reverts EMPTY in both', async () => {
    // selector | 0x20 (arr offset) | 1 (len) | 0x20 (elem0 offset) | a=0xaa...  <-- ends here.
    // tuple at +0x60 needs a 64-byte head; only 32 bytes follow -> not readable.
    const data = '0x' + selHex + pad(0x20n) + pad(1n) + pad(0x20n) + pad(0xaan);
    await both(data, 'truncated-head');
  });

  it('element head fully present but string body truncated reverts EMPTY in both', async () => {
    // full 64-byte head, s-offset points just past the head, but the length word of s is missing.
    const data = '0x' + selHex + pad(0x20n) + pad(1n) + pad(0x20n) + pad(0xaan) + pad(0x40n);
    await both(data, 'truncated-string-len');
  });

  it('a well-formed single-element D[] still round-trips (fix did not over-reject)', async () => {
    // selector | 0x20 | 1 | 0x20 | [a=7][s-offset=0x40][s-len=2]["hi"padded]
    const sBody = pad(2n) + Buffer.concat([Buffer.from('hi'), Buffer.alloc(30)]).toString('hex');
    const data = '0x' + selHex + pad(0x20n) + pad(1n) + pad(0x20n) + pad(7n) + pad(0x40n) + sBody;
    await both(data, 'well-formed');
  });
});
