// Environment globals differential vs Solidity, under a custom env (distinct
// caller/origin/value/chainId and a custom block) so each opcode is observable.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, customCommon, makeBlock } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const CALLER = new Address(hexToBytes(('0x' + 'ca'.repeat(20)) as `0x${string}`));
const ORIGIN = new Address(hexToBytes(('0x' + 'be'.repeat(20)) as `0x${string}`));
const COINBASE = new Address(hexToBytes(('0x' + 'cc'.repeat(20)) as `0x${string}`));
const RANDAO = hexToBytes(('0x' + 'ab'.repeat(32)) as `0x${string}`);
const CHAIN_ID = 1337;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Globals {
  function sender()   external view    returns (address) { return msg.sender; }
  function origin()   external view    returns (address) { return tx.origin; }
  function self()     external view    returns (address) { return address(this); }
  function coinbase() external view    returns (address) { return block.coinbase; }
  function ts()       external view    returns (uint256) { return block.timestamp; }
  function num()      external view    returns (uint256) { return block.number; }
  function cid()      external view    returns (uint256) { return block.chainid; }
  function fee()      external view    returns (uint256) { return block.basefee; }
  function glimit()   external view    returns (uint256) { return block.gaslimit; }
  function rand()     external view    returns (uint256) { return block.prevrandao; }
  function sig()      external view    returns (bytes4)  { return msg.sig; }
  function val()      external payable returns (uint256) { return msg.value; }
}`;

describe('environment globals vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  let block: ReturnType<typeof makeBlock>;

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'Globals.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'Globals.jeth' });
    const sb = compileSolidity(SOL, 'Globals');
    const common = customCommon(CHAIN_ID);
    jeth = await Harness.create(common);
    sol = await Harness.create(common);
    // Deploy from the same caller/nonce on fresh EVMs -> identical address (so self() matches).
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
    expect(aj.toString()).toBe(as.toString());
    block = makeBlock(
      { number: 12345678n, timestamp: 1700000000n, coinbase: COINBASE, gasLimit: 30000000n, baseFeePerGas: 7n, prevRandao: RANDAO },
      common,
    );
  });

  const VIEW_FNS = ['sender()', 'origin()', 'self()', 'coinbase()', 'ts()', 'num()', 'cid()', 'fee()', 'glimit()', 'rand()', 'sig()'];

  it('returns identical values to Solidity for every global', async () => {
    for (const sig of VIEW_FNS) {
      const data = encodeCall(functionSelector(sig));
      const j = await jeth.call(aj, data, { caller: CALLER, origin: ORIGIN, block });
      const s = await sol.call(as, data, { caller: CALLER, origin: ORIGIN, block });
      expect(j.success, `${sig} jeth err=${j.exceptionError}`).toBe(true);
      expect(j.returnHex, `${sig} mismatch`).toBe(s.returnHex);
    }
    // payable msg.value
    const data = encodeCall(functionSelector('val()'));
    const j = await jeth.call(aj, data, { caller: CALLER, value: 123456789n, block });
    const s = await sol.call(as, data, { caller: CALLER, value: 123456789n, block });
    expect(j.returnHex).toBe(s.returnHex);
    expect(BigInt(j.returnHex)).toBe(123456789n);
  });

  it('observes the distinct env values (not all zero)', async () => {
    const get = async (sig: string) =>
      (await jeth.call(aj, encodeCall(functionSelector(sig)), { caller: CALLER, origin: ORIGIN, block })).returnHex;
    expect(BigInt(await get('ts()'))).toBe(1700000000n);
    expect(BigInt(await get('num()'))).toBe(12345678n);
    expect(BigInt(await get('cid()'))).toBe(BigInt(CHAIN_ID));
    expect(BigInt(await get('fee()'))).toBe(7n);
    expect(BigInt(await get('glimit()'))).toBe(30000000n);
    expect(BigInt(await get('rand()'))).toBe(BigInt('0x' + 'ab'.repeat(32)));
    expect((await get('sender()')).toLowerCase()).toContain('ca'.repeat(20));
    expect((await get('origin()')).toLowerCase()).toContain('be'.repeat(20));
    expect((await get('coinbase()')).toLowerCase()).toContain('cc'.repeat(20));
  });
});
