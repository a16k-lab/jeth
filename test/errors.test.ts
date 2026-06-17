// require / revert / Error(string) / custom errors differential vs Solidity.
// Asserts byte-identical returndata (selectors, ABI offsets, lengths, padding,
// custom-error arg layout, eager-eval Panic) for success and revert.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const U256_MAX = (1n << 256n) - 1n;
const ADDR = BigInt('0x' + 'de'.repeat(20));

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Errors {
  error Insufficient(uint256 available, uint256 required);
  error Unauthorized(address who);
  error Flag(bool ok);
  error Three(uint256 a, address b, bool c);
  error Narrow(uint8 a, int8 b);
  error NoArgs();
  function reqTrue(uint256 a) external pure returns (uint256){ require(a > 0); return a; }
  function reqTrueMsg(uint256 a) external pure returns (uint256){ require(a > 0, "must be positive"); return a; }
  function reqFalseShort() external pure { require(false, "hello"); }
  function reqFalseExact32() external pure { require(false, "abcdefghijklmnopqrstuvwxyz012345"); }
  function reqFalseLong() external pure { require(false, "this string is definitely longer than thirty-two bytes for testing"); }
  function revertShort() external pure { revert("hello"); }
  function revertEmptyStr() external pure { revert(""); }
  function revertBare() external pure { revert(); }
  function r1(uint256 a, uint256 b) external pure { revert Insufficient(a, b); }
  function r2(address w) external pure { revert Unauthorized(w); }
  function r3(bool ok) external pure { revert Flag(ok); }
  function r4(uint256 a, address b, bool c) external pure { revert Three(a, b, c); }
  function r5(uint8 a, int8 b) external pure { revert Narrow(a, b); }
  function r7() external pure { revert NoArgs(); }
  function rq(uint256 a, uint256 b) external pure returns (uint256){ require(a > b, Insufficient(a, b)); return a; }
  function rqEager(uint256 a, uint256 b) external pure returns (uint256){ require(true, Insufficient(a, 10 / b)); return a; }
  function reqThenAdd(uint256 a) external pure returns (uint256){ require(a > 0, "nz"); return a + 1; }
}`;

interface Case { sig: string; args: bigint[]; }
function c(sig: string, args: bigint[] = []): Case { return { sig, args }; }

const CASES: Case[] = [
  c('reqTrue(uint256)', [7n]), c('reqTrue(uint256)', [0n]),
  c('reqTrueMsg(uint256)', [5n]), c('reqTrueMsg(uint256)', [0n]),
  c('reqFalseShort()'), c('reqFalseExact32()'), c('reqFalseLong()'),
  c('revertShort()'), c('revertEmptyStr()'), c('revertBare()'),
  c('r1(uint256,uint256)', [5n, 9n]), c('r1(uint256,uint256)', [U256_MAX, 0n]),
  c('r2(address)', [ADDR]),
  c('r3(bool)', [1n]), c('r3(bool)', [0n]),
  c('r4(uint256,address,bool)', [7n, ADDR, 1n]),
  c('r5(uint8,int8)', [255n, -1n]), c('r5(uint8,int8)', [0n, 127n]),
  c('r7()'),
  c('rq(uint256,uint256)', [9n, 3n]), c('rq(uint256,uint256)', [3n, 9n]),
  c('rqEager(uint256,uint256)', [7n, 0n]), // Panic 0x12 despite cond true
  c('rqEager(uint256,uint256)', [7n, 2n]),
  c('reqThenAdd(uint256)', [0n]), c('reqThenAdd(uint256)', [5n]), c('reqThenAdd(uint256)', [U256_MAX]), // overflow Panic
];

describe('require/revert/custom errors vs Solidity', () => {
  let jeth: Harness, sol: Harness, jethAddr: any, solAddr: any;
  let jb: ReturnType<typeof compile>;

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'Errors.jeth'), 'utf8');
    jb = compile(src, { fileName: 'Errors.jeth' });
    const sb = compileSolidity(SOL, 'Errors');
    jeth = await Harness.create();
    sol = await Harness.create();
    jethAddr = await jeth.deploy(jb.creationBytecode);
    solAddr = await sol.deploy(sb.creation);
  });

  it('matches Solidity returndata byte-for-byte on every case', async () => {
    for (const tc of CASES) {
      const data = encodeCall(functionSelector(tc.sig), tc.args);
      const r1 = await jeth.call(jethAddr, data);
      const r2 = await sol.call(solAddr, data);
      const label = `${tc.sig} [${tc.args.join(', ')}]`;
      expect(r1.success, `${label}: success`).toBe(r2.success);
      expect(r1.returnHex, `${label}: returndata`).toBe(r2.returnHex);
    }
  });

  it('emits error entries in the ABI with the right selectors', () => {
    const errs = jb.abi.filter((a: any) => a.type === 'error');
    expect(errs.map((e: any) => e.name).sort()).toEqual(
      ['Flag', 'Insufficient', 'Narrow', 'NoArgs', 'Three', 'Unauthorized'].sort(),
    );
    const sel = (s: string) => functionSelector(s);
    expect(jb.ir.errors.find((e) => e.name === 'Insufficient')!.selector).toBe(sel('Insufficient(uint256,uint256)'));
    expect(jb.ir.errors.find((e) => e.name === 'NoArgs')!.selector).toBe(sel('NoArgs()'));
  });
});
