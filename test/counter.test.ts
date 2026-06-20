// Phase 1 milestone: compile Counter to real bytecode, deploy on @ethereumjs/evm,
// exercise it, assert on-chain state. This is the "is it possible -> you can run
// it" proof.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compile, type CompileResult } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';

const here = dirname(fileURLToPath(import.meta.url));
const COUNTER = readFileSync(join(here, '..', 'examples', 'Counter.jeth'), 'utf8');

const SEL = {
  increment: functionSelector('increment()'),
  add: functionSelector('add(uint256)'),
  current: functionSelector('current()'),
};

describe('Counter end-to-end', () => {
  let result: CompileResult;

  beforeAll(() => {
    result = compile(COUNTER, { fileName: 'Counter.jeth' });
  });

  it('produces non-empty creation and runtime bytecode', () => {
    expect(result.creationBytecode.length).toBeGreaterThan(0);
    expect(result.runtimeBytecode.length).toBeGreaterThan(0);
    expect(result.creationBytecode).toMatch(/^[0-9a-f]+$/);
  });

  it('puts count at slot 0, offset 0', () => {
    expect(result.storageLayout).toEqual([{ name: 'count', type: 'u256', slot: 0, offset: 0 }]);
  });

  it('emits a Solidity-compatible ABI', () => {
    const inc = result.abi.find((a) => 'name' in a && a.name === 'increment');
    expect(inc).toMatchObject({ type: 'function', stateMutability: 'nonpayable', inputs: [], outputs: [] });
    const cur = result.abi.find((a) => 'name' in a && a.name === 'current');
    expect(cur).toMatchObject({ stateMutability: 'view', outputs: [{ type: 'uint256' }] });
    const add = result.abi.find((a) => 'name' in a && a.name === 'add');
    expect(add?.inputs).toEqual([{ name: 'delta', type: 'uint256', internalType: 'uint256' }]);
  });

  it('deploys, increments, and reads back state', async () => {
    const h = await Harness.create();
    const addr = await h.deploy(result.creationBytecode);

    // current() == 0
    let r = await h.call(addr, encodeCall(SEL.current));
    expect(r.success).toBe(true);
    expect(decodeUint(r.returnHex)).toBe(0n);

    // increment(); current() == 1
    r = await h.call(addr, encodeCall(SEL.increment));
    expect(r.success).toBe(true);
    r = await h.call(addr, encodeCall(SEL.current));
    expect(decodeUint(r.returnHex)).toBe(1n);

    // increment() again -> 2
    await h.call(addr, encodeCall(SEL.increment));
    r = await h.call(addr, encodeCall(SEL.current));
    expect(decodeUint(r.returnHex)).toBe(2n);

    // add(40) -> 42
    r = await h.call(addr, encodeCall(SEL.add, [40n]));
    expect(r.success).toBe(true);
    r = await h.call(addr, encodeCall(SEL.current));
    expect(decodeUint(r.returnHex)).toBe(42n);
  });

  it('rejects ETH sent to a non-payable function', async () => {
    const h = await Harness.create();
    const addr = await h.deploy(result.creationBytecode);
    const r = await h.call(addr, encodeCall(SEL.increment), { value: 1n });
    expect(r.success).toBe(false);
  });

  it('reverts with Panic(0x11) on checked-add overflow', async () => {
    const h = await Harness.create();
    const addr = await h.deploy(result.creationBytecode);
    const MAX = (1n << 256n) - 1n;
    // count = MAX
    let r = await h.call(addr, encodeCall(SEL.add, [MAX]));
    expect(r.success).toBe(true);
    r = await h.call(addr, encodeCall(SEL.current));
    expect(decodeUint(r.returnHex)).toBe(MAX);
    // increment() overflows -> revert with Panic(0x11)
    r = await h.call(addr, encodeCall(SEL.increment));
    expect(r.success).toBe(false);
    // returndata = Panic selector 0x4e487b71 + 0x11
    expect(r.returnHex.slice(0, 10)).toBe('0x4e487b71');
    expect(decodeUint('0x' + r.returnHex.slice(10))).toBe(0x11n);
  });

  it('reverts on unknown selector', async () => {
    const h = await Harness.create();
    const addr = await h.deploy(result.creationBytecode);
    const r = await h.call(addr, '0xdeadbeef');
    expect(r.success).toBe(false);
  });
});
