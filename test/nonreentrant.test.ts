// F4: @nonReentrant desugars to a transient-storage (EIP-1153 TSTORE/TLOAD) mutex on the external
// entry, reverting with OpenZeppelin's ReentrancyGuardReentrantCall() (0x3ee5aeb5) on re-entry and
// resetting on every normal exit (a revert auto-rolls-back transient storage). We verify it against
// a Solidity transient-ReentrancyGuard twin.
//
// NOTE on scope: JETH has no external-call primitive yet, so a guarded JETH function never yields
// control mid-execution; a TRUE nested re-entry cannot be triggered against a JETH contract today.
// What we CAN (and do) verify behaviorally vs the twin: (1) normal operation is transparent, (2) the
// mutex SETs and RESETs correctly across many guarded entries in one transaction (a missing reset
// would make the 2nd entry revert), and (3) a reverting guarded call auto-rolls-back the transient
// slot so a later entry in the same transaction still succeeds. The block-path revert constant is
// asserted structurally (the guard + OZ selector are embedded in the runtime bytecode).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => v.toString(16).padStart(64, '0');

const JETH = `@contract class V {
  @state x: u256;
  @nonReentrant @external bump(): void { this.x = this.x + 1n; }
  @nonReentrant @external bumpBy(n: u256): u256 { this.x = this.x + n; return this.x; }
  @nonReentrant @external bumpThenRevert(): void { this.x = this.x + 1n; revert("boom"); }
  @external @view get(): u256 { return this.x; }
}`;

// Twin vault: identical bodies guarded by a transient-storage ReentrancyGuard, plus a Solidity
// Attacker that drives multi-entry / revert-then-reenter in a single transaction.
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
contract V {
  uint256 x;                 // storage slot 0 (matches JETH)
  uint256 transient _lock;   // transient mutex
  error ReentrancyGuardReentrantCall();
  modifier nonReentrant() {
    if (_lock != 0) revert ReentrancyGuardReentrantCall();
    _lock = 1;
    _;
    _lock = 0;
  }
  function bump() external nonReentrant { x = x + 1; }
  function bumpBy(uint256 n) external nonReentrant returns (uint256) { x = x + n; return x; }
  function bumpThenRevert() external nonReentrant { x = x + 1; revert("boom"); }
  function get() external view returns (uint256) { return x; }
}
interface IV { function bump() external; function bumpThenRevert() external; }
contract Attacker {
  // n guarded entries in ONE transaction: shared transient storage, so a missing reset would make
  // entry #2 revert ReentrancyGuardReentrantCall().
  function hammer(address v, uint256 n) external { for (uint256 i = 0; i < n; i++) { IV(v).bump(); } }
  // a reverting guarded call (transient slot rolled back by EIP-1153) then a succeeding one.
  function failThenOk(address v) external {
    (bool ok, ) = v.call(abi.encodeWithSignature("bumpThenRevert()"));
    require(!ok, "expected the guarded call to revert");
    IV(v).bump();
  }
}`;

describe('F4 @nonReentrant vs Solidity transient ReentrancyGuard', () => {
  let h: Harness, jv: Address, sv: Address, atk: Address;
  beforeAll(async () => {
    h = await Harness.create();
    jv = await h.deploy(compile(JETH, { fileName: 'V.jeth' }).creationBytecode);
    sv = await h.deploy(compileSolidity(SOL, 'V').creation);
    atk = await h.deploy(compileSolidity(SOL, 'Attacker').creation);
  });

  it('normal (non-reentrant) operation is transparent: identical returns + storage vs the twin', async () => {
    for (const [label, data] of [
      ['bump', encodeCall(sel('bump()'), [])] as const,
      ['bumpBy(7)', encodeCall(sel('bumpBy(uint256)'), [7n])] as const,
      ['bump2', encodeCall(sel('bump()'), [])] as const,
    ]) {
      const j = await h.call(jv, data); const s = await h.call(sv, data);
      expect(j.success, `${label} jeth=${j.exceptionError}`).toBe(s.success);
      expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    }
    expect(await readSlot(h, jv, 0n), 'x slot after bumps').toBe(await readSlot(h, sv, 0n));
    // a direct guarded view of state matches
    expect((await h.call(jv, encodeCall(sel('get()'), []))).returnHex).toBe((await h.call(sv, encodeCall(sel('get()'), []))).returnHex);
  });

  it('mutex resets between guarded entries in one tx (hammer x5 succeeds on both)', async () => {
    const data = '0x' + sel('hammer(address,uint256)') + pad(BigInt(jv.toString())) + pad(5n);
    const dataS = '0x' + sel('hammer(address,uint256)') + pad(BigInt(sv.toString())) + pad(5n);
    const j = await h.call(atk, data); const s = await h.call(atk, dataS);
    expect(j.success, `jeth hammer err=${j.exceptionError}`).toBe(true);
    expect(s.success, `sol hammer err=${s.exceptionError}`).toBe(true);
    // 5 successful guarded bumps each; x advanced identically (started at the post-prev-test value).
    expect(await readSlot(h, jv, 0n)).toBe(await readSlot(h, sv, 0n));
  });

  it('a reverting guarded call rolls back the transient slot (EIP-1153); the next entry still succeeds', async () => {
    const xj0 = decodeUint(await readSlot(h, jv, 0n));
    const xs0 = decodeUint(await readSlot(h, sv, 0n));
    const j = await h.call(atk, '0x' + sel('failThenOk(address)') + pad(BigInt(jv.toString())));
    const s = await h.call(atk, '0x' + sel('failThenOk(address)') + pad(BigInt(sv.toString())));
    expect(j.success, `jeth failThenOk err=${j.exceptionError}`).toBe(true);
    expect(s.success, `sol failThenOk err=${s.exceptionError}`).toBe(true);
    // the reverting bump rolled back (x unchanged by it); the succeeding bump added exactly 1.
    expect(decodeUint(await readSlot(h, jv, 0n))).toBe(xj0 + 1n);
    expect(decodeUint(await readSlot(h, sv, 0n))).toBe(xs0 + 1n);
    expect(await readSlot(h, jv, 0n)).toBe(await readSlot(h, sv, 0n));
  });

  it('the block path embeds OZ ReentrancyGuardReentrantCall() (0x3ee5aeb5) in the runtime bytecode', () => {
    // The selector JETH reverts with on re-entry IS keccak("ReentrancyGuardReentrantCall()")[0:4],
    // OpenZeppelin's transient-guard error. A true nested re-entry is not yet expressible in JETH
    // (no external-call primitive), so the block-path revert constant is asserted structurally; the
    // set / reset / rollback machinery that surrounds it is verified behaviorally above.
    expect(functionSelector('ReentrancyGuardReentrantCall()')).toBe('3ee5aeb5');
    const rt = compile(JETH, { fileName: 'V.jeth' }).runtimeBytecode.toLowerCase();
    expect(rt.includes('3ee5aeb5'), 'OZ ReentrancyGuardReentrantCall selector present in the guard').toBe(true);
  });
});
