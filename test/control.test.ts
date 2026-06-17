// Control flow differential vs Solidity: loops, branches, break/continue, early
// return, fall-through, short-circuit, nested loops. Asserts byte-identical
// results AND revert parity (overflow inside loops, INT_MIN negation).
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));

const I256_MIN = -(1n << 255n);
const I256_MAX = (1n << 255n) - 1n;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Control {
  function sumTo(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ s+=i; } return s; }
  function factorial(uint256 n) external pure returns (uint256){ uint256 r=1; for(uint256 i=1;i<=n;i+=1){ r*=i; } return r; }
  function whileCountdown(uint256 n) external pure returns (uint256){ uint256 c=n; uint256 steps=0; while(c>0){ c-=1; steps+=1; } return steps; }
  function breakAt(uint256 n, uint256 k) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ if(i==k){break;} s+=i; } return s; }
  function skipEven(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ if(i%2==0){continue;} s+=i; } return s; }
  function whileContinue(uint256 n) external pure returns (uint256){ uint256 s=0; uint256 i=0; while(i<n){ i+=1; if(i%2==1){continue;} s+=i; } return s; }
  function absI256(int256 x) external pure returns (int256){ int256 r=0; if(x<0){ r=-x; } else { r=x; } return r; }
  function classify(uint256 x) external pure returns (uint256){ if(x<10){ return 1; } else if(x<20){ return 2; } else { return 3; } }
  function earlyReturnInLoop(uint256 n, uint256 k) external pure returns (uint256){ for(uint256 i=0;i<n;i+=1){ if(i==k){ return i; } } return 999; }
  function fallThroughZero(uint256 x) external pure returns (uint256){ if(x>0){ return 7; } }
  function nestedLoops(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ for(uint256 j=0;j<n;j+=1){ if(j==i){break;} s+=1; } } return s; }
  function shortCircuit(uint256 a) external pure returns (bool){ return (a>0) && ((10/a)>0); }
}`;

interface Case { sig: string; args: bigint[]; }
function pairs(sig: string, sets: bigint[][]): Case[] { return sets.map((args) => ({ sig, args })); }

const CASES: Case[] = [
  ...pairs('sumTo(uint256)', [[0n], [1n], [2n], [10n], [100n]]),
  ...pairs('factorial(uint256)', [[0n], [1n], [5n], [10n], [20n], [57n], [100n]]), // 57! overflows -> revert parity
  ...pairs('whileCountdown(uint256)', [[0n], [1n], [50n]]),
  ...pairs('breakAt(uint256,uint256)', [[10n, 3n], [10n, 100n], [0n, 0n], [5n, 0n]]),
  ...pairs('skipEven(uint256)', [[0n], [1n], [2n], [5n], [10n]]),
  ...pairs('whileContinue(uint256)', [[0n], [1n], [2n], [3n], [6n], [7n]]),
  ...pairs('absI256(int256)', [[5n], [-5n], [0n], [I256_MAX], [I256_MIN]]), // I256_MIN negation reverts
  ...pairs('classify(uint256)', [[0n], [9n], [10n], [19n], [20n], [1000n]]),
  ...pairs('earlyReturnInLoop(uint256,uint256)', [[10n, 3n], [10n, 100n], [0n, 0n]]),
  ...pairs('fallThroughZero(uint256)', [[0n], [5n]]),
  ...pairs('nestedLoops(uint256)', [[0n], [1n], [3n], [5n]]),
  ...pairs('shortCircuit(uint256)', [[0n], [1n], [3n]]), // a==0 must NOT divide -> false, not revert
];

describe('control flow vs Solidity', () => {
  let jeth: Harness, sol: Harness, jethAddr: any, solAddr: any;

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'Control.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'Control.jeth' });
    const sb = compileSolidity(SOL, 'Control');
    jeth = await Harness.create();
    sol = await Harness.create();
    jethAddr = await jeth.deploy(jb.creationBytecode);
    solAddr = await sol.deploy(sb.creation);
  });

  it('matches Solidity result/revert on every control-flow case', async () => {
    for (const c of CASES) {
      const data = encodeCall(functionSelector(c.sig), c.args);
      const r1 = await jeth.call(jethAddr, data);
      const r2 = await sol.call(solAddr, data);
      const label = `${c.sig} [${c.args.join(', ')}]`;
      expect(r1.success, `${label}: success (jeth err=${r1.exceptionError})`).toBe(r2.success);
      expect(r1.returnHex, `${label}: returndata`).toBe(r2.returnHex);
    }
  });
});
