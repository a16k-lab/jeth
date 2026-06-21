// Phase 4e-7: custom errors with dynamic (string/bytes) args, revert data
// byte-identical to Solidity (selector + head/tail encode).
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const WHO = BigInt('0x' + 'ab'.repeat(20));
const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract DynErrors {
  error Unauthorized(address caller, string reason);
  error TwoStr(string a, string b);
  error Mixed(uint256 code, string note, bool flag);
  error JustStr(string msg);
  function check(uint256 x, address who, string calldata s) external pure {
    if (x == 0) revert Unauthorized(who, "not allowed here");
    if (x == 1) revert Mixed(42, s, true);
    if (x == 2) revert TwoStr("first", "second longer string value goes here for padding test ok");
    if (x == 3) revert JustStr(s);
    revert JustStr("");
  }
}`;

describe('dynamic custom-error args vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = functionSelector('check(uint256,address,string)');
  // build calldata: head [x][who][offset=0x60], tail = string s
  function call(x: bigint, s: string): string {
    const bytes = Buffer.from(s, 'utf8');
    const len = BigInt(bytes.length);
    const nwords = Math.ceil(bytes.length / 32);
    let dataWords = '';
    for (let i = 0; i < nwords; i++) {
      dataWords += Buffer.concat([bytes.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)]).subarray(0, 32).toString('hex');
    }
    return '0x' + sel + pad(x) + pad(WHO) + pad(0x60n) + pad(len) + dataWords;
  }
  async function eqRevert(label: string, x: bigint, s: string) {
    const data = call(x, s);
    const j = await jeth.call(aj, data);
    const r = await sol.call(as, data);
    expect(j.success, `${label} both revert`).toBe(false);
    expect(r.success).toBe(false);
    expect(j.returnHex, `${label} revert data`).toBe(r.returnHex);
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'DynErrors.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'DynErrors.jeth' });
    const sb = compileSolidity(SOL, 'DynErrors');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('Unauthorized(address, string literal) revert data identical', async () => {
    await eqRevert('Unauthorized', 0n, 'ignored');
  });
  it('Mixed(uint, string param, bool) - dynamic arg from calldata, short + long', async () => {
    await eqRevert('Mixed short', 1n, 'hi');
    await eqRevert('Mixed long', 1n, 'this string is definitely longer than thirty-two bytes to force multi-word padding');
    await eqRevert('Mixed empty', 1n, '');
    await eqRevert('Mixed exact32', 1n, 'abcdefghijklmnopqrstuvwxyz012345'); // exactly 32 bytes
  });
  it('TwoStr(string literal, string literal) - two dynamic args', async () => {
    await eqRevert('TwoStr', 2n, 'ignored');
  });
  it('JustStr(string param) and JustStr("")', async () => {
    await eqRevert('JustStr param', 3n, 'a passthrough string value');
    await eqRevert('JustStr empty', 9n, 'ignored'); // x>3 -> revert JustStr("")
  });
});
