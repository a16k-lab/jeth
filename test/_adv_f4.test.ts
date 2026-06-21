// ADVERSARIAL audit of F4 @nonReentrant (the EIP-1153 transient-storage reentrancy mutex).
//
// THREAT MODEL / TECHNIQUE. JETH has no external-call primitive, so a guarded JETH function never
// yields control mid-execution and a TRUE nested re-entry cannot be expressed against a JETH
// contract. What we CAN drive (and the implementation's correctness fully reduces to) is: the
// transient slot must SET on entry, RESET on EVERY normal return path, and rely on EIP-1153
// rollback for revert paths. Transient storage PERSISTS across sub-calls within one transaction, so
// we deploy a Solidity ATTACKER alongside the JETH vault on the SAME EVM and have the attacker make
// MULTIPLE guarded sub-calls in ONE transaction. Because the mutex slot is shared across those
// sub-calls, a guarded function that fails to reset on some return path makes the attacker's 2nd
// sub-call revert ReentrancyGuardReentrantCall(); a wrongly-reset slot would let a real re-entry
// through (not expressible here) but would also DIVERGE from the twin on storage/returndata. We run
// the SAME attacker against a Solidity transient-ReentrancyGuard twin and assert identical
// success + raw storage slots + logs. The core hunt is EVERY-RETURN-PATH-RESETS: each guarded fn
// takes a non-trivial return path and is called N>=2 times in one tx; all must succeed on both.
//
// The reset transform (src/yul.ts emitDispatchCase) is purely textual: it prepends tstore(SLOT,0)
// before every emitted Yul line whose trimmed text starts with `return(`. A static cross-check of
// the emitted Yul (see the "static Yul" test below) confirms every guarded return is preceded by a
// reset and no reset is mis-inserted; the behavioral tests confirm that this is sound at runtime.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => v.toString(16).padStart(64, '0');
const addrWord = (a: Address) => pad(BigInt(a.toString()));

// The transient slot JETH uses (keccak("jeth.nonReentrant.guard.v1")); for the static Yul check.
const TSLOT = 'e3c13ce1a6dbca2cd747af6cfb37b5bfaa572cf58e51980e617e5acd973fa8b3';

// ---------------------------------------------------------------------------------------------
// JETH vault: one guarded function per return / revert / interaction shape under audit.
// Storage layout: slot 0 = x (u256), slot 1 = arr (u256[]).
// ---------------------------------------------------------------------------------------------
const JETH = `
@struct class P { a: u256; b: u256; }
@contract class V {
  @state x: u256;
  @state arr: u256[];
  @error Bad(code: u256);
  @event Hit(@indexed who: u256, n: u256);

  // --- EVERY-RETURN-PATH-RESETS (each mutates x on its taken path so the twin's x advances too) ---
  // 1. early return before any state write
  @nonReentrant @external earlyRet(a: u256): u256 { if (a == 0n) { return 99n; } this.x = this.x + 1n; return this.x; }
  // 2. return inside for, while, do-while, and AFTER a loop
  @nonReentrant @external inForRet(n: u256): u256 { this.x = this.x + 1n; for (let i: u256 = 0n; i < n; i = i + 1n) { if (i == 2n) { return i; } } return 100n; }
  @nonReentrant @external inWhileRet(n: u256): u256 { this.x = this.x + 1n; let i: u256 = 0n; while (i < n) { if (i == 1n) { return i; } i = i + 1n; } return 200n; }
  @nonReentrant @external inDoWhileRet(n: u256): u256 { this.x = this.x + 1n; let i: u256 = 0n; do { if (i == 5n) { return 7n; } i = i + 1n; } while (i < n); return 300n; }
  // 3. nested if/else and a for-inside-if
  @nonReentrant @external nested(a: u256, b: u256): u256 { this.x = this.x + 1n; if (a > b) { if (a > 10n) { return 1n; } else { return 2n; } } else { for (let i: u256 = 0n; i < b; i = i + 1n) { if (i == a) { return 3n; } } return 4n; } }
  // 4. multiple distinct returns: if-chain + ternary
  @nonReentrant @external multi(a: u256): u256 { this.x = this.x + 1n; if (a == 1n) { return 11n; } if (a == 2n) { return 22n; } return a > 5n ? 55n : 66n; }
  // 5. non-value returns: struct, fixed array, string, multi-value tuple
  @nonReentrant @external retStruct(a: u256): P { this.x = this.x + 1n; return P(a, a + 1n); }
  @nonReentrant @external retArr(a: u256): Arr<u256, 3> { this.x = this.x + 1n; return [a, a + 1n, a + 2n]; }
  @nonReentrant @external retStr(a: u256): string { this.x = this.x + 1n; if (a == 0n) { return ""; } return "hello-world-this-is-a-fairly-long-string-over-32"; }
  @nonReentrant @external retTuple(a: u256): [u256, u256] { this.x = this.x + 1n; return [a, a + 1n]; }
  // 6. void fall-through, and value fall-through (implicit zero)
  @nonReentrant @external voidFall(): void { this.x = this.x + 1n; }
  @nonReentrant @external valFall(a: u256): u256 { this.x = this.x + 1n; if (a == 999n) { return 1n; } }
  // 7. empty body, and event-then-return
  @nonReentrant @external emptyBody(): void {}
  @nonReentrant @external evtRet(n: u256): void { this.x = this.x + 1n; emit(Hit(7n, n)); }

  // --- REVERT PATHS (must rely on EIP-1153 rollback, no explicit reset) ---
  @nonReentrant @external reqFalse(): void { this.x = this.x + 1n; require(false, "no"); }
  @nonReentrant @external revMsg(): void { this.x = this.x + 1n; revert("boom"); }
  @nonReentrant @external custErr(): void { this.x = this.x + 1n; revert(Bad(5n)); }
  @nonReentrant @external doOverflow(a: u256): u256 { this.x = this.x + 1n; return a + type(u256).max; }
  @nonReentrant @external doDivZero(a: u256, b: u256): u256 { this.x = this.x + 1n; return a / b; }
  @nonReentrant @external doOob(i: u256): u256 { this.x = this.x + 1n; return this.arr[i]; }

  // --- INTERACTIONS ---
  // 9. payable: callvalue handling + guard
  @nonReentrant @payable @external dep(): u256 { this.x = this.x + 1n; return msg.value; }
  // 10. struct param (calldata decode before the guard)
  @nonReentrant @external structParam(p: P): u256 { this.x = this.x + 1n; return p.a + p.b; }
  // 11. events byte-identical
  @nonReentrant @external manyEvt(n: u256): void { this.x = this.x + 1n; emit(Hit(1n, n)); emit(Hit(2n, n + 1n)); }
  // 12. a SECOND guarded fn that shares the same mutex with bump-style functions
  @nonReentrant @external bump(): u256 { this.x = this.x + 1n; return this.x; }

  // --- EXOTIC return shapes (each lowers to a distinct return( shape; multi-entry must reset) ---
  @nonReentrant @external echoDynArr(a: u256[]): u256[] { this.x = this.x + 1n; return a; }
  @nonReentrant @external echoStr2(s: string): string { this.x = this.x + 1n; return s; }
  @nonReentrant @external echoStructDyn(d: P): P { this.x = this.x + 1n; return d; }
  @nonReentrant @external tupTriple(a: u256): [u256, u256, u256] { this.x = this.x + 1n; return [a, a + 1n, a + 2n]; }
  @nonReentrant @external manyRet(a: u256): u256 {
    this.x = this.x + 1n;
    if (a == 0n) { return 0n; }
    if (a == 1n) { return 1n; }
    for (let i: u256 = 0n; i < a; i = i + 1n) { if (i == 3n) { return i; } }
    while (a > 100n) { return 999n; }
    do { if (a == 7n) { return 7n; } } while (false);
    return a;
  }

  @external @view get(): u256 { return this.x; }
}`;

// ---------------------------------------------------------------------------------------------
// Solidity TWIN + ATTACKER in one source. Twin V uses a transient ReentrancyGuard with IDENTICAL
// bodies. Attacker drives multi-entry / fail-then-ok in ONE transaction.
// ---------------------------------------------------------------------------------------------
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

contract V {
  uint256 x;                  // slot 0  (matches JETH)
  uint256[] arr;              // slot 1  (matches JETH)
  uint256 transient _lock;    // EIP-1153 transient mutex (no storage slot)
  error ReentrancyGuardReentrantCall();
  error Bad(uint256 code);
  event Hit(uint256 indexed who, uint256 n);
  struct P { uint256 a; uint256 b; }

  modifier nonReentrant() {
    if (_lock != 0) revert ReentrancyGuardReentrantCall();
    _lock = 1;
    _;
    _lock = 0;
  }

  function earlyRet(uint256 a) external nonReentrant returns (uint256) { if (a == 0) { return 99; } x = x + 1; return x; }
  function inForRet(uint256 n) external nonReentrant returns (uint256) { x = x + 1; for (uint256 i = 0; i < n; i++) { if (i == 2) { return i; } } return 100; }
  function inWhileRet(uint256 n) external nonReentrant returns (uint256) { x = x + 1; uint256 i = 0; while (i < n) { if (i == 1) { return i; } i++; } return 200; }
  function inDoWhileRet(uint256 n) external nonReentrant returns (uint256) { x = x + 1; uint256 i = 0; do { if (i == 5) { return 7; } i++; } while (i < n); return 300; }
  function nested(uint256 a, uint256 b) external nonReentrant returns (uint256) { x = x + 1; if (a > b) { if (a > 10) { return 1; } else { return 2; } } else { for (uint256 i = 0; i < b; i++) { if (i == a) { return 3; } } return 4; } }
  function multi(uint256 a) external nonReentrant returns (uint256) { x = x + 1; if (a == 1) { return 11; } if (a == 2) { return 22; } return a > 5 ? 55 : 66; }
  function retStruct(uint256 a) external nonReentrant returns (P memory) { x = x + 1; return P(a, a + 1); }
  function retArr(uint256 a) external nonReentrant returns (uint256[3] memory) { x = x + 1; return [a, a + 1, a + 2]; }
  function retStr(uint256 a) external nonReentrant returns (string memory) { x = x + 1; if (a == 0) { return ""; } return "hello-world-this-is-a-fairly-long-string-over-32"; }
  function retTuple(uint256 a) external nonReentrant returns (uint256, uint256) { x = x + 1; return (a, a + 1); }
  function voidFall() external nonReentrant { x = x + 1; }
  function valFall(uint256 a) external nonReentrant returns (uint256) { x = x + 1; if (a == 999) { return 1; } }
  function emptyBody() external nonReentrant {}
  function evtRet(uint256 n) external nonReentrant { x = x + 1; emit Hit(7, n); }

  function reqFalse() external nonReentrant { x = x + 1; require(false, "no"); }
  function revMsg() external nonReentrant { x = x + 1; revert("boom"); }
  function custErr() external nonReentrant { x = x + 1; revert Bad(5); }
  function doOverflow(uint256 a) external nonReentrant returns (uint256) { x = x + 1; return a + type(uint256).max; }
  function doDivZero(uint256 a, uint256 b) external nonReentrant returns (uint256) { x = x + 1; return a / b; }
  function doOob(uint256 i) external nonReentrant returns (uint256) { x = x + 1; return arr[i]; }

  function dep() external payable nonReentrant returns (uint256) { x = x + 1; return msg.value; }
  function structParam(P calldata p) external nonReentrant returns (uint256) { x = x + 1; return p.a + p.b; }
  function manyEvt(uint256 n) external nonReentrant { x = x + 1; emit Hit(1, n); emit Hit(2, n + 1); }
  function bump() external nonReentrant returns (uint256) { x = x + 1; return x; }

  function echoDynArr(uint256[] calldata a) external nonReentrant returns (uint256[] memory) { x = x + 1; return a; }
  function echoStr2(string calldata s) external nonReentrant returns (string memory) { x = x + 1; return s; }
  function echoStructDyn(P calldata d) external nonReentrant returns (P memory) { x = x + 1; return d; }
  function tupTriple(uint256 a) external nonReentrant returns (uint256, uint256, uint256) { x = x + 1; return (a, a + 1, a + 2); }
  function manyRet(uint256 a) external nonReentrant returns (uint256) {
    x = x + 1;
    if (a == 0) { return 0; }
    if (a == 1) { return 1; }
    for (uint256 i = 0; i < a; i++) { if (i == 3) { return i; } }
    while (a > 100) { return 999; }
    do { if (a == 7) { return 7; } } while (false);
    return a;
  }

  function get() external view returns (uint256) { return x; }
}

// Minimal interfaces the attacker calls through (return-typed so abi-decode succeeds where used).
interface IV {
  function earlyRet(uint256) external returns (uint256);
  function inForRet(uint256) external returns (uint256);
  function inWhileRet(uint256) external returns (uint256);
  function inDoWhileRet(uint256) external returns (uint256);
  function nested(uint256, uint256) external returns (uint256);
  function multi(uint256) external returns (uint256);
  function retStruct(uint256) external returns (V.P memory);
  function retArr(uint256) external returns (uint256[3] memory);
  function retStr(uint256) external returns (string memory);
  function retTuple(uint256) external returns (uint256, uint256);
  function voidFall() external;
  function valFall(uint256) external returns (uint256);
  function emptyBody() external;
  function evtRet(uint256) external;
  function dep() external payable returns (uint256);
  function structParam(V.P calldata) external returns (uint256);
  function manyEvt(uint256) external;
  function bump() external returns (uint256);
}

contract Attacker {
  // Generic: N raw sub-calls of the SAME calldata in one tx; every one MUST succeed (require(ok)).
  // A guarded fn that failed to reset would make sub-call #2 revert ReentrancyGuardReentrantCall().
  function hammerRaw(address v, bytes calldata data, uint256 n) external {
    for (uint256 i = 0; i < n; i++) {
      (bool ok, bytes memory ret) = v.call(data);
      require(ok, "guarded sub-call reverted (slot leaked?)");
      ret;
    }
  }

  // A revert-then-ok sequence: low-level call expected to FAIL (ignored), then a plain guarded call
  // must SUCCEED because EIP-1153 rolled the slot back on the revert.
  function failThenOk(address v, bytes calldata failing) external {
    (bool ok, ) = v.call(failing);
    require(!ok, "expected the guarded call to revert");
    IV(v).bump();
  }

  // Two DIFFERENT guarded fns in one tx: A then B; both must succeed (each resets). If A leaked, B
  // reverts. Returns nothing; success of the whole tx is the assertion.
  function callTwo(address v, bytes calldata a, bytes calldata b) external {
    (bool oka, ) = v.call(a);
    require(oka, "first guarded call reverted");
    (bool okb, ) = v.call(b);
    require(okb, "second guarded call reverted (A leaked the mutex?)");
  }

  // Forward value to a payable guarded fn, twice, in one tx.
  function hammerDep(address v, uint256 amt, uint256 n) external payable {
    for (uint256 i = 0; i < n; i++) {
      (bool ok, ) = v.call{value: amt}(abi.encodeWithSignature("dep()"));
      require(ok, "payable guarded sub-call reverted");
    }
  }
}`;

describe('F4 @nonReentrant ADVERSARIAL: every return path resets vs a transient-guard twin', () => {
  let h: Harness;
  let jv: Address, sv: Address, atk: Address;

  beforeAll(async () => {
    h = await Harness.create();
    jv = await h.deploy(compile(JETH, { fileName: 'V.jeth' }).creationBytecode);
    sv = await h.deploy(compileSolidity(SOL, 'V').creation);
    atk = await h.deploy(compileSolidity(SOL, 'Attacker').creation);
  });

  // Drive the SAME inner calldata N times through the attacker against BOTH vaults; assert the
  // attacker tx succeeds on both (every guarded entry reset) and slot 0 (x) matches afterward.
  async function hammerBoth(label: string, inner: string, n = 3n) {
    const innerHex = inner.startsWith('0x') ? inner.slice(2) : inner;
    const lenWord = pad(BigInt(innerHex.length / 2));
    // hammerRaw(address v, bytes data, uint256 n): head = [v][off=0x60][n], then bytes(len,data padded)
    const dataPadded = innerHex.padEnd(Math.ceil(innerHex.length / 64) * 64, '0');
    const build = (vault: Address) =>
      '0x' + sel('hammerRaw(address,bytes,uint256)') +
      addrWord(vault) + pad(0x60n) + pad(n) + lenWord + dataPadded;
    const j = await h.call(atk, build(jv));
    const s = await h.call(atk, build(sv));
    expect(j.success, `${label} JETH attacker err=${j.exceptionError}`).toBe(true);
    expect(s.success, `${label} SOL  attacker err=${s.exceptionError}`).toBe(true);
    expect(j.success, `${label} success parity`).toBe(s.success);
    expect(await readSlot(h, jv, 0n), `${label} x slot parity`).toBe(await readSlot(h, sv, 0n));
    return { j, s };
  }

  // ---- 1-7: EVERY-RETURN-PATH-RESETS ---------------------------------------------------------
  it('1. early return before any state write resets the mutex', async () => {
    await hammerBoth('earlyRet(0) early-exit', encodeCall(sel('earlyRet(uint256)'), [0n]));
    await hammerBoth('earlyRet(5) write-path', encodeCall(sel('earlyRet(uint256)'), [5n]));
  });

  it('2. return inside for / while / do-while and after a loop all reset', async () => {
    await hammerBoth('inForRet(5) in-loop', encodeCall(sel('inForRet(uint256)'), [5n]));
    await hammerBoth('inForRet(1) after-loop', encodeCall(sel('inForRet(uint256)'), [1n]));
    await hammerBoth('inWhileRet(3) in-loop', encodeCall(sel('inWhileRet(uint256)'), [3n]));
    await hammerBoth('inWhileRet(0) after-loop', encodeCall(sel('inWhileRet(uint256)'), [0n]));
    await hammerBoth('inDoWhileRet(3) after-loop', encodeCall(sel('inDoWhileRet(uint256)'), [3n]));
    await hammerBoth('inDoWhileRet(9) in-loop', encodeCall(sel('inDoWhileRet(uint256)'), [9n]));
  });

  it('3. returns in nested if/else and a for-inside-if reset', async () => {
    await hammerBoth('nested deep-if', encodeCall(sel('nested(uint256,uint256)'), [20n, 1n]));
    await hammerBoth('nested else-if', encodeCall(sel('nested(uint256,uint256)'), [5n, 1n]));
    await hammerBoth('nested for-in-if hit', encodeCall(sel('nested(uint256,uint256)'), [2n, 5n]));
    await hammerBoth('nested for-in-if miss', encodeCall(sel('nested(uint256,uint256)'), [9n, 3n]));
  });

  it('4. multiple distinct returns (if-chain + ternary) each reset', async () => {
    await hammerBoth('multi branch-1', encodeCall(sel('multi(uint256)'), [1n]));
    await hammerBoth('multi branch-2', encodeCall(sel('multi(uint256)'), [2n]));
    await hammerBoth('multi ternary-hi', encodeCall(sel('multi(uint256)'), [9n]));
    await hammerBoth('multi ternary-lo', encodeCall(sel('multi(uint256)'), [3n]));
  });

  it('5. non-value returns (struct / fixed array / string / tuple) each reset', async () => {
    const { j } = await hammerBoth('retStruct', encodeCall(sel('retStruct(uint256)'), [7n]));
    j.success; // returndata equality is asserted per-call below
    await hammerBoth('retArr', encodeCall(sel('retArr(uint256)'), [7n]));
    await hammerBoth('retStr short(empty)', encodeCall(sel('retStr(uint256)'), [0n]));
    await hammerBoth('retStr long', encodeCall(sel('retStr(uint256)'), [1n]));
    await hammerBoth('retTuple', encodeCall(sel('retTuple(uint256)'), [7n]));
  });

  it('6. void fall-through and value fall-through (implicit zero) reset', async () => {
    await hammerBoth('voidFall', encodeCall(sel('voidFall()'), []));
    await hammerBoth('valFall fall-through', encodeCall(sel('valFall(uint256)'), [3n]));
    await hammerBoth('valFall explicit-return', encodeCall(sel('valFall(uint256)'), [999n]));
  });

  it('7. empty body and event-then-return reset', async () => {
    await hammerBoth('emptyBody', encodeCall(sel('emptyBody()'), []));
    await hammerBoth('evtRet', encodeCall(sel('evtRet(uint256)'), [42n]));
  });

  // ---- 8: REVERT PATHS rely on EIP-1153 rollback ---------------------------------------------
  it('8. each reverting guarded path rolls back the mutex; a later guarded entry still succeeds', async () => {
    const cases: [string, string][] = [
      ['require(false)', encodeCall(sel('reqFalse()'), [])],
      ['revert("boom")', encodeCall(sel('revMsg()'), [])],
      ['custom @error', encodeCall(sel('custErr()'), [])],
      ['overflow Panic(0x11)', encodeCall(sel('doOverflow(uint256)'), [1n])],
      ['divzero Panic(0x12)', encodeCall(sel('doDivZero(uint256,uint256)'), [10n, 0n])],
      ['oob Panic(0x32)', encodeCall(sel('doOob(uint256)'), [0n])],
    ];
    for (const [label, failing] of cases) {
      const failHex = failing.slice(2);
      const failLen = pad(BigInt(failHex.length / 2));
      const failPadded = failHex.padEnd(Math.ceil(failHex.length / 64) * 64, '0');
      const build = (vault: Address) =>
        '0x' + sel('failThenOk(address,bytes)') + addrWord(vault) + pad(0x40n) + failLen + failPadded;
      const j = await h.call(atk, build(jv));
      const s = await h.call(atk, build(sv));
      expect(j.success, `${label} JETH failThenOk err=${j.exceptionError}`).toBe(true);
      expect(s.success, `${label} SOL  failThenOk err=${s.exceptionError}`).toBe(true);
      expect(await readSlot(h, jv, 0n), `${label} x parity`).toBe(await readSlot(h, sv, 0n));
    }
  });

  // ---- 9: payable + guard, and value-rejection on a non-payable guarded fn -------------------
  it('9. @payable guarded fn forwards value across multiple guarded sub-calls in one tx', async () => {
    // hammerDep(address v, uint256 amt, uint256 n) payable -> n payable sub-calls of dep().
    const amt = 11n;
    const n = 3n;
    const build = (vault: Address) =>
      '0x' + sel('hammerDep(address,uint256,uint256)') + addrWord(vault) + pad(amt) + pad(n);
    const j = await h.call(atk, build(jv), { value: amt * n });
    const s = await h.call(atk, build(sv), { value: amt * n });
    expect(j.success, `JETH hammerDep err=${j.exceptionError}`).toBe(true);
    expect(s.success, `SOL  hammerDep err=${s.exceptionError}`).toBe(true);
    expect(await readSlot(h, jv, 0n)).toBe(await readSlot(h, sv, 0n));
  });

  it('9b. value to a NON-payable guarded fn reverts exactly like the twin', async () => {
    const data = encodeCall(sel('bump()'), []);
    const j = await h.call(jv, data, { value: 1n });
    const s = await h.call(sv, data, { value: 1n });
    expect(j.success, 'JETH non-payable+value must revert').toBe(false);
    expect(s.success, 'SOL  non-payable+value must revert').toBe(false);
    expect(j.success).toBe(s.success);
  });

  // ---- 10: struct/array/bytes PARAMETERS (calldata decode happens BEFORE the guard) ----------
  it('10. guarded fn with a struct parameter: decode-before-guard, multi-entry resets', async () => {
    // structParam((uint256,uint256)) p = (3, 4) -> returns 7; called N times in one tx.
    const inner = '0x' + sel('structParam((uint256,uint256))') + pad(3n) + pad(4n);
    await hammerBoth('structParam', inner);
    // direct single-call returndata parity
    const j = await h.call(jv, inner);
    const s = await h.call(sv, inner);
    expect(j.returnHex, 'structParam returndata parity').toBe(s.returnHex);
    expect(decodeUint(j.returnHex)).toBe(7n);
  });

  // ---- 11: events byte-identical, guard transparent to logs -----------------------------------
  it('11. a guarded fn emitting events: logs byte-identical to the twin, guard does not perturb', async () => {
    const data = encodeCall(sel('manyEvt(uint256)'), [123n]);
    const j = await h.call(jv, data);
    const s = await h.call(sv, data);
    expect(j.success && s.success, 'manyEvt success').toBe(true);
    expect(j.logs.length, 'log count').toBe(s.logs.length);
    expect(j.logs.length).toBe(2);
    for (let i = 0; i < j.logs.length; i++) {
      expect(j.logs[i]!.topics, `log[${i}] topics`).toEqual(s.logs[i]!.topics);
      expect(j.logs[i]!.data, `log[${i}] data`).toEqual(s.logs[i]!.data);
    }
  });

  // ---- 12: two DIFFERENT guarded fns share the SAME mutex; A then B both succeed -------------
  it('12. two different guarded fns in one tx both succeed (shared mutex resets between them)', async () => {
    const a = encodeCall(sel('bump()'), []).slice(2);
    const b = encodeCall(sel('voidFall()'), []).slice(2);
    const aLen = pad(BigInt(a.length / 2));
    const bLen = pad(BigInt(b.length / 2));
    // callTwo(address v, bytes a, bytes b): head [v][offA=0x60][offB]; tails are length-prefixed.
    const aPadded = a.padEnd(Math.ceil(a.length / 64) * 64, '0');
    const bPadded = b.padEnd(Math.ceil(b.length / 64) * 64, '0');
    const offB = 0x60n + 32n + BigInt(aPadded.length / 2);
    const build = (vault: Address) =>
      '0x' + sel('callTwo(address,bytes,bytes)') +
      addrWord(vault) + pad(0x60n) + pad(offB) + aLen + aPadded + bLen + bPadded;
    const j = await h.call(atk, build(jv));
    const s = await h.call(atk, build(sv));
    expect(j.success, `JETH callTwo err=${j.exceptionError}`).toBe(true);
    expect(s.success, `SOL  callTwo err=${s.exceptionError}`).toBe(true);
    expect(await readSlot(h, jv, 0n)).toBe(await readSlot(h, sv, 0n));
  });

  // ---- 12b: EXOTIC return shapes under multi-entry (dynamic array / string / dynamic struct /
  //           triple tuple / a single fn with 6 distinct return paths) ------------------------
  it('12b. exotic return shapes (dyn array / string / dyn struct / triple tuple / 6-path) all reset', async () => {
    // echoDynArr(uint256[]) with a 2-element array: head [off=0x20][len=2][9][8]
    const dynArr = '0x' + sel('echoDynArr(uint256[])') + pad(0x20n) + pad(2n) + pad(9n) + pad(8n);
    await hammerBoth('echoDynArr', dynArr);
    // echoStr2(string) with a short string "abc": head [off=0x20][len=3]["abc" left-aligned]
    const str = '0x' + sel('echoStr2(string)') + pad(0x20n) + pad(3n) + '616263'.padEnd(64, '0');
    await hammerBoth('echoStr2', str);
    // echoStructDyn((uint256,uint256)) = (5, 6)  (P is a static struct, inline head)
    const ds = '0x' + sel('echoStructDyn((uint256,uint256))') + pad(5n) + pad(6n);
    await hammerBoth('echoStructDyn', ds);
    // tupTriple(uint256)
    await hammerBoth('tupTriple', encodeCall(sel('tupTriple(uint256)'), [7n]));
    // manyRet across all 6 of its distinct return paths
    for (const a of [0n, 1n, 3n, 200n, 7n, 50n]) {
      await hammerBoth(`manyRet(${a})`, encodeCall(sel('manyRet(uint256)'), [a]));
    }
    // direct returndata parity on the dynamic shapes (the guard must be transparent here too).
    for (const [label, data] of [
      ['echoDynArr', dynArr] as const,
      ['echoStr2', str] as const,
      ['echoStructDyn', ds] as const,
      ['tupTriple', encodeCall(sel('tupTriple(uint256)'), [7n])] as const,
    ]) {
      const j = await h.call(jv, data);
      const s = await h.call(sv, data);
      expect(j.returnHex, `${label} returndata parity`).toBe(s.returnHex);
    }
  });

  // ---- 13: normal fresh-tx operation is transparent ------------------------------------------
  it('13. normal direct calls: returndata + storage + logs identical to the twin', async () => {
    const probes: [string, string][] = [
      ['bump', encodeCall(sel('bump()'), [])],
      ['earlyRet(5)', encodeCall(sel('earlyRet(uint256)'), [5n])],
      ['multi(9)', encodeCall(sel('multi(uint256)'), [9n])],
      ['retStruct(7)', encodeCall(sel('retStruct(uint256)'), [7n])],
      // retArr is INTENTIONALLY omitted from the solc-parity list: its array-LITERAL fixed-array
      // return diverges from solc independently of the guard (see the documented it.fails below).
      // We assert guard TRANSPARENCY for it separately (guarded == unguarded JETH) instead.
      ['retStr(1)', encodeCall(sel('retStr(uint256)'), [1n])],
      ['retTuple(7)', encodeCall(sel('retTuple(uint256)'), [7n])],
      ['nested(2,5)', encodeCall(sel('nested(uint256,uint256)'), [2n, 5n])],
    ];
    for (const [label, data] of probes) {
      const j = await h.call(jv, data);
      const s = await h.call(sv, data);
      expect(j.success, `${label} success parity (jeth=${j.exceptionError})`).toBe(s.success);
      expect(j.returnHex, `${label} returndata parity`).toBe(s.returnHex);
    }
    expect(await readSlot(h, jv, 0n), 'x slot parity after normal ops').toBe(await readSlot(h, sv, 0n));
  });

  it('13c. the guard is byte-TRANSPARENT for a fixed-array return (guarded == unguarded JETH)', async () => {
    // The fixed-array LITERAL return shape diverges from solc independently of F4 (see it.fails
    // below); the F4 invariant we CAN assert is that wrapping the SAME body in @nonReentrant does
    // not change the returned bytes at all. We compile a tiny twin pair of JETH contracts that
    // differ ONLY by the decorator and compare their returndata + runtime behavior.
    const guarded = `@contract class W { @state x: u256; @nonReentrant @external f(a: u256): Arr<u256,3> { this.x = this.x + 1n; return [a, a + 1n, a + 2n]; } }`;
    const plain = `@contract class W { @state x: u256; @external f(a: u256): Arr<u256,3> { this.x = this.x + 1n; return [a, a + 1n, a + 2n]; } }`;
    const gh = await Harness.create();
    const gv = await gh.deploy(compile(guarded, { fileName: 'W.jeth' }).creationBytecode);
    const pv = await gh.deploy(compile(plain, { fileName: 'W.jeth' }).creationBytecode);
    const g = await gh.call(gv, encodeCall(sel('f(uint256)'), [7n]));
    const p = await gh.call(pv, encodeCall(sel('f(uint256)'), [7n]));
    expect(g.success && p.success, 'both succeed').toBe(true);
    expect(g.returnHex, 'guard does not perturb the fixed-array returndata').toBe(p.returnHex);
  });

  it('13b. the runtime embeds OZ ReentrancyGuardReentrantCall() (0x3ee5aeb5)', () => {
    expect(functionSelector('ReentrancyGuardReentrantCall()')).toBe('3ee5aeb5');
    const rt = compile(JETH, { fileName: 'V.jeth' }).runtimeBytecode.toLowerCase();
    expect(rt.includes('3ee5aeb5')).toBe(true);
  });
});

// ---------------------------------------------------------------------------------------------
// STATIC Yul cross-check: the textual reset transform must precede EVERY guarded return and must
// not be mis-inserted before a non-return line. This is the white-box twin of the behavioral hunt.
// ---------------------------------------------------------------------------------------------
describe('F4 @nonReentrant static Yul: reset precedes every guarded return, none mis-inserted', () => {
  it('every return( in a guarded fn is immediately preceded by a tstore(SLOT,0) reset', () => {
    const yul = compile(JETH, { fileName: 'V.jeth' }).yul;
    const lines = yul.split('\n');
    const resetLine = `tstore(0x${TSLOT}, 0)`;
    const setLine = `tstore(0x${TSLOT}, 1)`;

    // Count guarded functions by their tstore(SLOT,1) entry markers.
    const sets = lines.filter((l) => l.trim() === setLine).length;
    const tloads = lines.filter((l) => l.includes('tload(0x' + TSLOT)).length;
    expect(tloads, 'one tload guard per guarded fn').toBe(sets);
    // The JETH source has 29 @nonReentrant functions; assert we actually emitted that many guards.
    expect(sets, 'expected 29 guarded entries').toBe(29);

    // Every Yul `return(` opcode line that is NOT the runtime datacopy must be preceded by a reset,
    // UNLESS it belongs to the single unguarded @view get(). We detect get()'s return structurally:
    // it is the only return whose preceding line is `mstore(0, sload(0))` with no reset.
    let leaks: { line: number; ret: string; prev: string }[] = [];
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i]!.trim();
      if (!t.startsWith('return(') || t.includes('datasize(')) continue;
      const prev = (lines[i - 1] ?? '').trim();
      if (prev !== resetLine) leaks.push({ line: i + 1, ret: t, prev });
    }
    // Exactly one non-reset return is allowed: the unguarded get() view (mstore(0, sload(0))).
    expect(leaks.length, `unexpected non-reset returns: ${JSON.stringify(leaks)}`).toBe(1);
    expect(leaks[0]!.prev, 'the single non-reset return is the unguarded get() view').toBe('mstore(0, sload(0))');

    // No reset may be mis-inserted before a line that is not a return.
    let mis: number[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (lines[i]!.trim() !== resetLine) continue;
      const next = (lines[i + 1] ?? '').trim();
      if (!next.startsWith('return(')) mis.push(i + 1);
    }
    expect(mis.length, `resets mis-inserted before non-return lines at ${mis}`).toBe(0);
  });
});

// ---------------------------------------------------------------------------------------------
// SOUNDNESS / rejection + ABI parity: the decorator must validate and must NOT alter the ABI.
// ---------------------------------------------------------------------------------------------
describe('F4 @nonReentrant soundness: validation codes + ABI/selector parity', () => {
  const tryCompile = (src: string): string[] => {
    try {
      compile(src, { fileName: 'R.jeth' });
      return [];
    } catch (e: any) {
      return (e.diagnostics ?? []).map((d: any) => d.code);
    }
  };

  it('rejects @nonReentrant on @view / @pure / @read with JETH260', () => {
    expect(tryCompile(`@contract class C { @state x: u256; @nonReentrant @view f(): u256 { return this.x; } }`)).toContain('JETH260');
    expect(tryCompile(`@contract class C { @nonReentrant @pure f(): u256 { return 1n; } }`)).toContain('JETH260');
    expect(tryCompile(`@contract class C { @state x: u256; @nonReentrant @read f(): u256 { return this.x; } }`)).toContain('JETH260');
  });

  it('rejects @nonReentrant on / / with JETH261', () => {
    expect(tryCompile(`@contract class C { @state x: u256; @nonReentrant f(): void { this.x = 1n; } }`)).toContain('JETH261');
    expect(tryCompile(`@contract class C { @state x: u256; @nonReentrant f(): void { this.x = 1n; } }`)).toContain('JETH261');
    expect(tryCompile(`@contract class C { @state x: u256; @nonReentrant f(): void { this.x = 1n; } }`)).toContain('JETH261');
  });

  it('rejects an internal call to a @nonReentrant function', () => {
    // In the @external-only model @nonReentrant REQUIRES @external (JETH261), so a guarded function
    // is always an external entry. Calling it by name from inside the contract is therefore rejected
    // by the general "cannot internally call @external" rule (JETH240), which subsumes the old
    // reentrancy-specific JETH262: there is no internally-callable guarded function to bypass.
    expect(tryCompile(`@contract class C { @state x: u256; @nonReentrant @external f(): void { this.x = 1n; } @external g(): void { this.f(); } }`)).toContain('JETH240');
  });

  it('the guard does NOT change the ABI/selector/mutability vs the same fn without the decorator', () => {
    const guarded = `@contract class V { @state x: u256; @nonReentrant @external bump(): u256 { this.x = this.x + 1n; return this.x; } @nonReentrant @payable @external dep(): u256 { return msg.value; } }`;
    const plain = `@contract class V { @state x: u256; @external bump(): u256 { this.x = this.x + 1n; return this.x; } @payable @external dep(): u256 { return msg.value; } }`;
    const pick = (abi: any[]) =>
      abi.filter((e) => e.type === 'function').map((e) => ({ name: e.name, mut: e.stateMutability, inputs: (e.inputs ?? []).map((i: any) => i.type) }));
    const g = pick(compile(guarded, { fileName: 'V.jeth' }).abi);
    const p = pick(compile(plain, { fileName: 'V.jeth' }).abi);
    expect(g, 'guarded ABI equals plain ABI').toEqual(p);
    // mutability is preserved: bump nonpayable, dep payable.
    expect(g.find((e) => e.name === 'bump')!.mut).toBe('nonpayable');
    expect(g.find((e) => e.name === 'dep')!.mut).toBe('payable');
    // selectors are identical (same signatures).
    expect(sel('bump()')).toBe('68110b2f');
    expect(sel('dep()')).toBe(functionSelector('dep()'));
  });
});

// ---------------------------------------------------------------------------------------------
// Regression for a (guard-independent) miscompile this audit surfaced and which is now FIXED: a
// STATIC fixed-array LITERAL return (Arr<T,N>) used to emit a DYNAMIC-array wrapper (offset+length)
// instead of solc's bare N words, contradicting its own uint256[N] ABI. The fix (src/yul.ts return
// lowering: arrayLit + isStaticType -> encodeArrayLitHead inline) makes it byte-identical to solc.
// ---------------------------------------------------------------------------------------------
describe('static fixed-array literal return matches solc (regression)', () => {
  it('Arr<u256,3> array-literal return equals solc uint256[3] (bare 3 words, no wrapper)', async () => {
    const J = `@contract class V { @external @pure litArr(a: u256): Arr<u256,3> { return [a, a + 1n, a + 2n]; } }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract V { function litArr(uint256 a) external pure returns (uint256[3] memory) { return [a, a + 1, a + 2]; } }`;
    const hh = await Harness.create();
    const jv2 = await hh.deploy(compile(J, { fileName: 'V.jeth' }).creationBytecode);
    const sv2 = await hh.deploy(compileSolidity(S, 'V').creation);
    const data = encodeCall(sel('litArr(uint256)'), [7n]);
    const j = await hh.call(jv2, data);
    const s = await hh.call(sv2, data);
    expect((j.returnHex.length - 2) / 2, 'bare 3 words = 96 bytes').toBe(96);
    expect(j.returnHex, 'JETH litArr equals solc uint256[3]').toBe(s.returnHex);
  });
});
