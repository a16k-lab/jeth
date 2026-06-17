// Events / logs differential vs Solidity: asserts the emitted logs (topic array
// + data bytes) are byte-identical, across indexed/non-indexed mixes, declaration
// order, LOGn selection, sign-extended int topics, and left-aligned bytesN.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, type LogEntry } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const A = BigInt('0x' + 'aa'.repeat(20));
const B = BigInt('0x' + 'bb'.repeat(20));
const BYTES4 = BigInt('0xdeadbeef' + '00'.repeat(28)); // left-aligned bytes4
const U256_MAX = (1n << 256n) - 1n;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Events {
  event NoIdx(uint256 value);
  event OneIdx(uint256 indexed key, uint256 value);
  event Transfer(address indexed from, address indexed to, uint256 value);
  event ThreeIdx(uint256 indexed a, uint256 indexed b, uint256 indexed c, uint256 d);
  event Bare();
  event OneIdxNoData(address indexed who);
  event Mixed(uint8 indexed flag, int16 indexed s, bool indexed ok, address who, bytes4 sig);
  event Order(uint256 a, uint256 indexed b, uint256 c, uint256 indexed d, uint256 e);
  function noIdx(uint256 v) external { emit NoIdx(v); }
  function oneIdx(uint256 k, uint256 v) external { emit OneIdx(k, v); }
  function transfer(address f, address t, uint256 v) external { emit Transfer(f, t, v); }
  function threeIdx(uint256 a, uint256 b, uint256 c, uint256 d) external { emit ThreeIdx(a,b,c,d); }
  function bare() external { emit Bare(); }
  function oneIdxNoData(address w) external { emit OneIdxNoData(w); }
  function mixed(uint8 fl, int16 s, bool ok, address w, bytes4 sig) external { emit Mixed(fl,s,ok,w,sig); }
  function order() external { emit Order(1,2,3,4,5); }
  function twice(uint256 v) external { emit NoIdx(v); emit NoIdx(v); }
}`;

interface Case { sig: string; args: bigint[]; }
function c(sig: string, args: bigint[] = []): Case { return { sig, args }; }

const CASES: Case[] = [
  c('noIdx(uint256)', [0n]), c('noIdx(uint256)', [U256_MAX]),
  c('oneIdx(uint256,uint256)', [5n, 99n]),
  c('transfer(address,address,uint256)', [A, B, 1000n]),
  c('transfer(address,address,uint256)', [0n, 0n, 0n]),
  c('threeIdx(uint256,uint256,uint256,uint256)', [7n, 8n, 9n, 42n]),
  c('bare()'),
  c('oneIdxNoData(address)', [A]),
  c('mixed(uint8,int16,bool,address,bytes4)', [255n, -3n, 1n, A, BYTES4]),
  c('mixed(uint8,int16,bool,address,bytes4)', [0n, -32768n, 0n, 0n, 0n]),
  c('order()'),
  c('twice(uint256)', [7n]),
];

function eqLogs(a: LogEntry[], b: LogEntry[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics));
}

describe('events vs Solidity', () => {
  let jeth: Harness, sol: Harness, jethAddr: any, solAddr: any;
  let jb: ReturnType<typeof compile>;

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'Events.jeth'), 'utf8');
    jb = compile(src, { fileName: 'Events.jeth' });
    const sb = compileSolidity(SOL, 'Events');
    jeth = await Harness.create();
    sol = await Harness.create();
    jethAddr = await jeth.deploy(jb.creationBytecode);
    solAddr = await sol.deploy(sb.creation);
  });

  it('emits byte-identical logs to Solidity on every case', async () => {
    for (const tc of CASES) {
      const data = encodeCall(functionSelector(tc.sig), tc.args);
      const r1 = await jeth.call(jethAddr, data);
      const r2 = await sol.call(solAddr, data);
      const label = `${tc.sig} [${tc.args.join(', ')}]`;
      expect(r1.success, `${label}: success`).toBe(true);
      expect(r2.success, `${label}: sol success`).toBe(true);
      expect(eqLogs(r1.logs, r2.logs), `${label}: logs\n jeth=${JSON.stringify(r1.logs)}\n sol =${JSON.stringify(r2.logs)}`).toBe(true);
    }
  });

  it('emits event ABI entries with indexed flags', () => {
    const evs = jb.abi.filter((a: any) => a.type === 'event');
    expect(evs.length).toBe(8);
    const transfer = evs.find((e: any) => e.name === 'Transfer') as any;
    expect(transfer.anonymous).toBe(false);
    expect(transfer.inputs.map((i: any) => [i.type, i.indexed])).toEqual([
      ['address', true], ['address', true], ['uint256', false],
    ]);
  });
});
