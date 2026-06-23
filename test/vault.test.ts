// The Phase 3 milestone: the Vault contract (mappings + msg.sender/value + payable +
// events) byte-identical to Solidity, including raw keccak-derived storage slots.
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint, type LogEntry } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const A = new Address(hexToBytes(('0x' + 'aa'.repeat(20)) as `0x${string}`));
const B = new Address(hexToBytes(('0x' + 'bb'.repeat(20)) as `0x${string}`));

function addrWord(a: Address): bigint {
  return BigInt('0x' + Buffer.from(a.bytes).toString('hex'));
}
function pad32(v: bigint): Uint8Array {
  return hexToBytes(('0x' + (v % (1n << 256n)).toString(16).padStart(64, '0')) as `0x${string}`);
}
/** mapping element slot = keccak256(keyWord . baseSlot). */
function mapSlot(keyWord: bigint, baseSlot: bigint): bigint {
  const buf = new Uint8Array(64);
  buf.set(pad32(keyWord), 0);
  buf.set(pad32(baseSlot), 32);
  return BigInt('0x' + toHex(keccak(buf)));
}

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
  mapping(address => uint256) balances;
  uint256 total;
  event Deposited(address indexed account, uint256 amount);
  function deposit() external payable { balances[msg.sender] += msg.value; total += msg.value; emit Deposited(msg.sender, msg.value); }
  function withdraw(uint256 amount) external { require(balances[msg.sender] >= amount, "insufficient"); balances[msg.sender] -= amount; total -= amount; }
  function transfer(address to, uint256 amount) external payable { require(to != address(0), "zero address"); require(balances[msg.sender] >= amount, "insufficient"); balances[msg.sender] -= amount; balances[to] += amount; }
  function balanceOf(address account) external view returns (uint256){ return balances[account]; }
  function totalSupply() external view returns (uint256){ return total; }
}`;

const SEL = {
  deposit: functionSelector('deposit()'),
  withdraw: functionSelector('withdraw(uint256)'),
  transfer: functionSelector('transfer(address,uint256)'),
  balanceOf: functionSelector('balanceOf(address)'),
  totalSupply: functionSelector('totalSupply()'),
};

function eqLogs(a: LogEntry[], b: LogEntry[]): boolean {
  return (
    a.length === b.length &&
    a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics))
  );
}

describe('Vault (mappings + msg.* + payable) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'Vault.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'Vault.jeth' });
    const sb = compileSolidity(SOL, 'Vault');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  async function both(data: string, opts: { caller?: Address; value?: bigint } = {}) {
    return { j: await jeth.call(aj, data, opts), s: await sol.call(as, data, opts) };
  }

  it('accumulates per-caller balances identically and emits identical events', async () => {
    let r = await both(encodeCall(SEL.deposit), { caller: A, value: 100n });
    expect(r.j.success).toBe(true);
    expect(eqLogs(r.j.logs, r.s.logs)).toBe(true);
    await both(encodeCall(SEL.deposit), { caller: A, value: 50n });
    await both(encodeCall(SEL.deposit), { caller: B, value: 30n });

    // balanceOf via call, both compilers
    r = await both(encodeCall(SEL.balanceOf, [addrWord(A)]));
    expect(decodeUint(r.j.returnHex)).toBe(150n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    r = await both(encodeCall(SEL.balanceOf, [addrWord(B)]));
    expect(decodeUint(r.j.returnHex)).toBe(30n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    r = await both(encodeCall(SEL.totalSupply));
    expect(decodeUint(r.j.returnHex)).toBe(180n);
  });

  it('stores into Solidity-identical raw slots (keccak-derived + fixed)', async () => {
    const slotA = mapSlot(addrWord(A), 0n);
    const slotB = mapSlot(addrWord(B), 0n);
    expect(await readSlot(jeth, aj, slotA)).toBe(await readSlot(sol, as, slotA));
    expect(await readSlot(jeth, aj, slotB)).toBe(await readSlot(sol, as, slotB));
    expect(decodeUint(await readSlot(jeth, aj, slotA))).toBe(150n);
    // total at slot 1
    expect(await readSlot(jeth, aj, 1n)).toBe(await readSlot(sol, as, 1n));
    expect(decodeUint(await readSlot(jeth, aj, 1n))).toBe(180n);
  });

  it('handles withdraw with an insufficient-balance require, identically', async () => {
    // B has 30; withdrawing 100 must revert Error("insufficient") on both
    let r = await both(encodeCall(SEL.withdraw, [100n]), { caller: B });
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe(r.s.returnHex);
    // withdraw 10 succeeds
    r = await both(encodeCall(SEL.withdraw, [10n]), { caller: B });
    expect(r.j.success).toBe(true);
    r = await both(encodeCall(SEL.balanceOf, [addrWord(B)]));
    expect(decodeUint(r.j.returnHex)).toBe(20n);
    expect(r.j.returnHex).toBe(r.s.returnHex);
  });

  it('enforces the zero-address guard in transfer, identically', async () => {
    const ZERO = 0n;
    let r = await both(encodeCall(SEL.transfer, [ZERO, 10n]), { caller: A });
    expect(r.j.success).toBe(false); // require(to != address(0))
    expect(r.j.returnHex).toBe(r.s.returnHex);
    // valid transfer A -> B
    r = await both(encodeCall(SEL.transfer, [addrWord(B), 40n]), { caller: A });
    expect(r.j.success).toBe(true);
    r = await both(encodeCall(SEL.balanceOf, [addrWord(B)]));
    expect(r.j.returnHex).toBe(r.s.returnHex);
  });

  it('rejects ETH sent to non-payable withdraw, identically', async () => {
    const r = await both(encodeCall(SEL.withdraw, [1n]), { caller: A, value: 1n });
    expect(r.j.success).toBe(false);
    expect(r.s.success).toBe(false);
  });
});
