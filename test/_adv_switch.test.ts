// ADVERSARIAL audit of the F5 `switch` -> nested-if/else DESUGAR. The HARD invariant is ZERO
// miscompiles: a JETH `switch` must behave byte-identically (returndata + raw storage slots + event
// logs + revert data) to the EQUIVALENT hand-written if/else chain under solc. Solidity has no
// `switch`, so every twin uses the if/else chain the desugar is supposed to produce.
//
// Where a desugar bug hides, and what each section hunts:
//  (1) the discriminant must be evaluated EXACTLY ONCE (side effect + expression discriminant)
//  (2) consecutive empty case labels must route to the right shared body (fall-through grouping)
//  (3) every discriminant value type (enum/u256/u8/i256-negative/address/bytes32/bool)
//  (4) every terminator form (return / revert / custom-error revert / continue / break / if-else / block)
//  (5) nesting: switch in a loop (break ends the case, continue continues the loop), switch in switch
//  (6) temp non-collision: two switches in one fn, sibling locals, switch in a hot loop
//  (7) return shapes: struct / fixed array / tuple / bytes through the switch
//  (8) exhaustive enum switch with no default (and a redundant default)
//  (9) soundness: the JETH281..286 rejections, plus the ACTUAL behavior of duplicate labels,
//      non-constant case labels, empty switch, and default-only switch.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';
import type { LogEntry } from '../src/evm.js';

const sel = (s: string) => functionSelector(s);

function codes(src: string): string[] {
  try { compile(src, { fileName: 'C.jeth' }); return []; }
  catch (e) { if (e instanceof CompileError) return e.diagnostics.map((d) => d.code); throw e; }
}
function eqLogs(a: LogEntry[], b: LogEntry[]) {
  expect(a.map((l) => ({ t: l.topics, d: l.data }))).toEqual(b.map((l) => ({ t: l.topics, d: l.data })));
}

// One big JETH contract + the equivalent Solidity if/else twin. Function selectors must match (same
// ABI signature) so a call lands on the same method in both.
const J = `enum Color { Red, Green, Blue }
enum Big { A, B, C, D, E }
@struct class P { a: u256; b: u256; }
@contract class C {
  @state n: u256;          // slot 0: side-effect counter for the single-evaluation probe
  @state hits: u256;       // slot 1: loop accumulator

  @error Boom(code: u256);
  @event Ping(@indexed k: u256, v: u256);

  // --- (1) single evaluation: bumpAndGet() increments n and returns the NEW n; the switch must call
  // it exactly once no matter which arm matches. Mutates storage, so a double-eval shows up in slot 0.
  bumpAndGet(): u256 { this.n = this.n + 1n; return this.n; }
  @external bumpSwitch(): u256 {
    let r: u256 = 0n;
    switch (this.bumpAndGet()) {
      case 1n: r = 100n; break;
      case 2n: r = 200n; break;
      default: r = 999n;
    }
    return r;
  }
  // discriminant that is a compound expression (must be computed once, value used by every arm).
  @external @pure exprDisc(a: u256, b: u256): u256 {
    switch (a + b) { case 5n: return 50n; case 6n: return 60n; default: return 0n; }
  }
  // single-eval where the matching arm is an EMPTY-LABEL GROUP: the desugar reads the temp in EVERY
  // OR term (__sw == 2 || __sw == 3). The temp is a const, so re-reading must NOT re-bump n.
  @external bumpGroup(): u256 {
    let r: u256 = 0n;
    switch (this.bumpAndGet()) {
      case 1n: case 2n: case 3n: r = 230n; break;   // reads the temp up to 3 times for one match
      default: r = 0n;
    }
    return r;
  }

  // --- (2) fall-through grouping: many empty labels share one body; an empty group right before default.
  @external @pure group(x: u256): u256 {
    switch (x) {
      case 1n: case 2n: case 3n: return 100n;     // 3 empty labels share one body
      case 4n: return 40n;                        // a lone non-empty case in the middle
      case 5n: case 6n: return 560n;              // group right before default
      default: return 0n;
    }
  }
  // interleaved empty/non-empty with NO default (uint, falls off the end to the trailing return)
  @external @pure inter(x: u256): u256 {
    switch (x) {
      case 1n: return 1n;
      case 2n: case 3n: return 23n;
      case 4n: return 4n;
    }
    return 99n;
  }

  // --- (3) every discriminant value type ---
  @external @pure dEnum(c: Color): u256 { switch (c) { case Color.Red: return 1n; case Color.Green: case Color.Blue: return 2n; } return 0n; }
  // exhaustive enum switch with NO default and NO trailing return: an empty-label GROUP (Green+Blue)
  // must count toward exhaustiveness AND route both members to the shared body.
  @external @pure enumGroupExhaust(c: Color): u256 { switch (c) { case Color.Red: return 1n; case Color.Green: case Color.Blue: return 2n; } }
  @external @pure dU8(x: u8): u256 { switch (x) { case 0n: return 1n; case 255n: return 2n; default: return 0n; } }
  @external @pure dI256(x: i256): u256 { switch (x) { case -5n: return 1n; case -1n: return 2n; case 0n: return 3n; case 7n: return 4n; default: return 0n; } }
  @external @pure dAddr(x: address): u256 { switch (x) { case address(0n): return 1n; case address(0xaan): return 2n; default: return 0n; } }
  @external @pure dB32(x: bytes32): u256 { switch (x) { case bytes32(0n): return 1n; case bytes32(0xffn): return 2n; default: return 0n; } }
  @external @pure dBool(b: bool): u256 { switch (b) { case true: return 7n; case false: return 8n; } }

  // --- (4) every terminator form ---
  @external @pure tReturn(x: u256): u256 { switch (x) { case 1n: return 11n; default: return 0n; } }
  @external @pure tRevertStr(x: u256): u256 { switch (x) { case 1n: revert("nope"); default: return 0n; } }
  @external @pure tRevertErr(x: u256): u256 { switch (x) { case 1n: revert(Boom(x)); default: return 0n; } }
  @external tContinue(x: u256): u256 {        // continue inside a loop terminates the case for that turn
    let s: u256 = 0n; let i: u256 = 0n;
    for (i = 0n; i < x; i = i + 1n) {
      switch (i) { case 2n: continue; default: s = s + 1n; }
      s = s + 10n;
    }
    return s;
  }
  @external tBreak(x: u256): u256 {           // plain break: case ends, control falls past the switch
    let s: u256 = 0n;
    switch (x) { case 1n: s = 1n; break; default: s = 9n; }
    return s + 1000n;
  }
  @external @pure tIfElse(x: u256): u256 {    // case body is an if-else where BOTH branches return
    switch (x) { case 1n: if (x > 0n) { return 5n; } else { return 6n; } default: return 0n; }
  }
  @external @pure tBlock(x: u256): u256 {     // case body is a block whose last stmt returns
    switch (x) { case 1n: { let y: u256 = x + 1n; return y; } default: return 0n; }
  }

  // --- (5) nesting & loops ---
  @external loopBreak(x: u256): u256 {        // break ends the CASE, never the loop -> loop runs x times
    let i: u256 = 0n;
    for (i = 0n; i < x; i = i + 1n) {
      switch (i) { case 0n: this.hits = this.hits + 1n; break; case 5n: continue; default: this.hits = this.hits + 10n; }
      this.hits = this.hits + 100n;
    }
    return this.hits;
  }
  @external @pure whileSwitch(x: u256): u256 {
    let s: u256 = 0n; let i: u256 = 0n;
    while (i < x) { switch (i) { case 1n: s = s + 7n; break; default: s = s + 1n; } i = i + 1n; }
    return s;
  }
  @external @pure switchInSwitch(x: u256, c: Color): u256 {   // nested switch with required trailing break
    let r: u256 = 0n;
    switch (x) {
      case 1n:
        switch (c) { case Color.Red: r = 10n; break; case Color.Green: r = 20n; break; default: r = 30n; }
        break;
      default: r = 0n;
    }
    return r;
  }
  @external @pure switchInIf(x: u256, y: u256): u256 {
    if (y > 0n) { switch (x) { case 1n: return 1n; default: return 2n; } }
    return 3n;
  }

  // --- (6) temp non-collision ---
  @external @pure twoSwitch(x: u256, y: u256): u256 {   // two sequential switches in one fn
    let r: u256 = 0n;
    switch (x) { case 1n: r = r + 1n; break; default: r = r + 2n; }
    switch (y) { case 1n: r = r + 10n; break; default: r = r + 20n; }
    return r;
  }
  @external @pure siblingLocal(x: u256): u256 {         // a local named the same in disjoint sibling cases
    switch (x) {
      case 1n: { let v: u256 = 100n; return v; }
      case 2n: { let v: u256 = 200n; return v; }
      default: { let v: u256 = 300n; return v; }
    }
  }
  @external @pure hotLoop(x: u256): u256 {              // a switch inside a many-iteration loop
    let s: u256 = 0n; let i: u256 = 0n;
    for (i = 0n; i < x; i = i + 1n) { switch (i % 3n) { case 0n: s = s + 1n; break; case 1n: s = s + 2n; break; default: s = s + 3n; } }
    return s;
  }

  // --- (7) return shapes through the switch ---
  @external @pure rStruct(x: u256): P { switch (x) { case 1n: return P(1n, 2n); default: return P(3n, 4n); } }
  @external @pure rFixed(x: u256): Arr<u256,3> { switch (x) { case 1n: return [1n, 2n, 3n]; default: return [4n, 5n, 6n]; } }
  @external @pure rTuple(x: u256): [u256, u256] { switch (x) { case 1n: return [10n, 11n]; default: return [20n, 21n]; } }
  @external @pure rString(x: u256): string { switch (x) { case 1n: return "alpha"; default: return "this string is comfortably longer than thirty-two bytes total!"; } }

  // --- (8) exhaustive enum switch, no default; and a redundant default ---
  @external @pure exhaust(b: Big): u256 {
    switch (b) { case Big.A: return 10n; case Big.B: return 20n; case Big.C: return 30n; case Big.D: return 40n; case Big.E: return 50n; }
  }
  @external @pure exhaustDef(b: Big): u256 {  // same coverage but with a redundant default
    switch (b) { case Big.A: return 10n; case Big.B: return 20n; case Big.C: return 30n; case Big.D: return 40n; case Big.E: return 50n; default: return 999n; }
  }

  // --- (9) characterize ACTUAL behavior of non-constant case labels (duplicate CONSTANT labels are
  // now a JETH287 compile error, asserted separately below) ---
  @external @pure varLabel(x: u256, y: u256): u256 {   // case label is a runtime variable
    switch (x) { case y: return 1n; case 5n: return 2n; default: return 0n; }
  }
  @external @pure defOnly(x: u256): u256 { switch (x) { default: return 42n; } }
  @external @pure emptySwitch(x: u256): u256 { switch (x) {} return 7n; }

  // --- event through a switch arm (logs parity) ---
  @external evSwitch(x: u256): void { switch (x) { case 1n: emit(Ping(x, 100n)); break; default: emit(Ping(x, 999n)); } }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  enum Color { Red, Green, Blue }
  enum Big { A, B, C, D, E }
  struct P { uint256 a; uint256 b; }
  uint256 n;     // slot 0
  uint256 hits;  // slot 1

  error Boom(uint256 code);
  event Ping(uint256 indexed k, uint256 v);

  function bumpAndGet() internal returns (uint256) { n = n + 1; return n; }
  function bumpSwitch() external returns (uint256) {
    uint256 r = 0;
    uint256 __sw = bumpAndGet();
    if (__sw == 1) { r = 100; } else if (__sw == 2) { r = 200; } else { r = 999; }
    return r;
  }
  function exprDisc(uint256 a, uint256 b) external pure returns (uint256) {
    uint256 __sw = a + b;
    if (__sw == 5) return 50; if (__sw == 6) return 60; return 0;
  }
  function bumpGroup() external returns (uint256) {
    uint256 r = 0;
    uint256 __sw = bumpAndGet();
    if (__sw == 1 || __sw == 2 || __sw == 3) { r = 230; } else { r = 0; }
    return r;
  }

  function group(uint256 x) external pure returns (uint256) {
    if (x == 1 || x == 2 || x == 3) return 100;
    if (x == 4) return 40;
    if (x == 5 || x == 6) return 560;
    return 0;
  }
  function inter(uint256 x) external pure returns (uint256) {
    if (x == 1) return 1;
    if (x == 2 || x == 3) return 23;
    if (x == 4) return 4;
    return 99;
  }

  function dEnum(Color c) external pure returns (uint256) { if (c == Color.Red) return 1; if (c == Color.Green || c == Color.Blue) return 2; return 0; }
  function enumGroupExhaust(Color c) external pure returns (uint256) { if (c == Color.Red) { return 1; } else { return 2; } }
  function dU8(uint8 x) external pure returns (uint256) { if (x == 0) return 1; if (x == 255) return 2; return 0; }
  function dI256(int256 x) external pure returns (uint256) { if (x == -5) return 1; if (x == -1) return 2; if (x == 0) return 3; if (x == 7) return 4; return 0; }
  function dAddr(address x) external pure returns (uint256) { if (x == address(0)) return 1; if (x == address(0xaa)) return 2; return 0; }
  function dB32(bytes32 x) external pure returns (uint256) { if (x == bytes32(uint256(0))) return 1; if (x == bytes32(uint256(0xff))) return 2; return 0; }
  function dBool(bool b) external pure returns (uint256) { if (b == true) return 7; if (b == false) return 8; revert(); }

  function tReturn(uint256 x) external pure returns (uint256) { if (x == 1) return 11; return 0; }
  function tRevertStr(uint256 x) external pure returns (uint256) { if (x == 1) revert("nope"); return 0; }
  function tRevertErr(uint256 x) external pure returns (uint256) { if (x == 1) revert Boom(x); return 0; }
  function tContinue(uint256 x) external pure returns (uint256) {
    uint256 s = 0;
    for (uint256 i = 0; i < x; i = i + 1) {
      if (i == 2) { continue; } else { s = s + 1; }
      s = s + 10;
    }
    return s;
  }
  function tBreak(uint256 x) external pure returns (uint256) {
    uint256 s = 0;
    if (x == 1) { s = 1; } else { s = 9; }
    return s + 1000;
  }
  function tIfElse(uint256 x) external pure returns (uint256) {
    if (x == 1) { if (x > 0) { return 5; } else { return 6; } } else { return 0; }
  }
  function tBlock(uint256 x) external pure returns (uint256) {
    if (x == 1) { uint256 y = x + 1; return y; } else { return 0; }
  }

  function loopBreak(uint256 x) external returns (uint256) {
    for (uint256 i = 0; i < x; i = i + 1) {
      if (i == 0) { hits = hits + 1; } else if (i == 5) { continue; } else { hits = hits + 10; }
      hits = hits + 100;
    }
    return hits;
  }
  function whileSwitch(uint256 x) external pure returns (uint256) {
    uint256 s = 0; uint256 i = 0;
    while (i < x) { if (i == 1) { s = s + 7; } else { s = s + 1; } i = i + 1; }
    return s;
  }
  function switchInSwitch(uint256 x, Color c) external pure returns (uint256) {
    uint256 r = 0;
    if (x == 1) {
      if (c == Color.Red) { r = 10; } else if (c == Color.Green) { r = 20; } else { r = 30; }
    } else { r = 0; }
    return r;
  }
  function switchInIf(uint256 x, uint256 y) external pure returns (uint256) {
    if (y > 0) { if (x == 1) { return 1; } else { return 2; } }
    return 3;
  }

  function twoSwitch(uint256 x, uint256 y) external pure returns (uint256) {
    uint256 r = 0;
    if (x == 1) { r = r + 1; } else { r = r + 2; }
    if (y == 1) { r = r + 10; } else { r = r + 20; }
    return r;
  }
  function siblingLocal(uint256 x) external pure returns (uint256) {
    if (x == 1) { uint256 v = 100; return v; } else if (x == 2) { uint256 v = 200; return v; } else { uint256 v = 300; return v; }
  }
  function hotLoop(uint256 x) external pure returns (uint256) {
    uint256 s = 0;
    for (uint256 i = 0; i < x; i = i + 1) { uint256 m = i % 3; if (m == 0) { s = s + 1; } else if (m == 1) { s = s + 2; } else { s = s + 3; } }
    return s;
  }

  function rStruct(uint256 x) external pure returns (P memory) { if (x == 1) return P(1, 2); return P(3, 4); }
  function rFixed(uint256 x) external pure returns (uint256[3] memory) { if (x == 1) return [uint256(1), 2, 3]; return [uint256(4), 5, 6]; }
  function rTuple(uint256 x) external pure returns (uint256, uint256) { if (x == 1) return (10, 11); return (20, 21); }
  function rString(uint256 x) external pure returns (string memory) { if (x == 1) return "alpha"; return "this string is comfortably longer than thirty-two bytes total!"; }

  function exhaust(Big b) external pure returns (uint256) {
    if (b == Big.A) return 10; if (b == Big.B) return 20; if (b == Big.C) return 30; if (b == Big.D) return 40; if (b == Big.E) return 50; revert();
  }
  function exhaustDef(Big b) external pure returns (uint256) {
    if (b == Big.A) return 10; else if (b == Big.B) return 20; else if (b == Big.C) return 30; else if (b == Big.D) return 40; else if (b == Big.E) return 50; else return 999;
  }

  function varLabel(uint256 x, uint256 y) external pure returns (uint256) {
    if (x == y) return 1; else if (x == 5) return 2; else return 0;
  }
  function defOnly(uint256 x) external pure returns (uint256) { return 42; }
  function emptySwitch(uint256 x) external pure returns (uint256) { return 7; }

  function evSwitch(uint256 x) external { if (x == 1) { emit Ping(x, 100); } else { emit Ping(x, 999); } }
}`;

describe('ADV switch: byte-identical to the if/else twin under solc', () => {
  let h: Harness, hs: Harness, jv: Address, sv: Address;
  // full parity for one read-only call: success + returndata + logs.
  async function eq(label: string, data: string) {
    const j = await h.call(jv, data); const s = await hs.call(sv, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    eqLogs(j.logs, s.logs);
  }
  beforeAll(async () => {
    h = await Harness.create(); hs = await Harness.create();
    jv = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    sv = await hs.deploy(compileSolidity(SOL, 'C').creation);
  });

  it('(1) discriminant with a side effect is evaluated EXACTLY ONCE (raw slot 0 vs twin)', async () => {
    // call bumpSwitch a few times: each call bumps n by exactly 1 (never 2). Compare returndata AND
    // the raw counter slot after every call. A double-eval would make n race ahead of the twin.
    for (let i = 0; i < 5; i++) {
      await eq(`bumpSwitch #${i}`, encodeCall(sel('bumpSwitch()')));
      expect(await readSlot(h, jv, 0n), `n after bumpSwitch #${i}`).toBe(await readSlot(hs, sv, 0n));
    }
  });
  it('(1) compound-expression discriminant computed once', async () => {
    for (const [a, b] of [[2n, 3n], [1n, 5n], [3n, 3n], [0n, 0n]] as const)
      await eq(`exprDisc(${a},${b})`, encodeCall(sel('exprDisc(uint256,uint256)'), [a, b]));
  });
  it('(1) empty-label-group match reads the temp N times but bumps n ONCE (slot 0 vs twin)', async () => {
    // Each call bumps n: 1,2,3,4,... When n hits 2 or 3 the match needs 2-3 `__sw==` reads of the
    // temp; n must still advance by exactly 1. A re-evaluation in the || chain would corrupt slot 0.
    for (let i = 0; i < 5; i++) {
      await eq(`bumpGroup #${i}`, encodeCall(sel('bumpGroup()')));
      expect(await readSlot(h, jv, 0n), `n after bumpGroup #${i}`).toBe(await readSlot(hs, sv, 0n));
    }
  });

  it('(2) fall-through grouping routes every label to the right shared body', async () => {
    for (const v of [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n]) await eq(`group(${v})`, encodeCall(sel('group(uint256)'), [v]));
    for (const v of [0n, 1n, 2n, 3n, 4n, 5n]) await eq(`inter(${v})`, encodeCall(sel('inter(uint256)'), [v]));
  });

  it('(3) all discriminant value types match the if/else twin', async () => {
    for (const v of [0n, 1n, 2n]) await eq(`dEnum(${v})`, encodeCall(sel('dEnum(uint8)'), [v]));
    for (const v of [0n, 1n, 2n]) await eq(`enumGroupExhaust(${v})`, encodeCall(sel('enumGroupExhaust(uint8)'), [v]));
    for (const v of [0n, 1n, 254n, 255n]) await eq(`dU8(${v})`, encodeCall(sel('dU8(uint8)'), [v]));
    for (const v of [-6n, -5n, -1n, 0n, 1n, 7n, 8n]) await eq(`dI256(${v})`, encodeCall(sel('dI256(int256)'), [v]));
    // absolute pin (not just twin-equality): the NEGATIVE label -5 routes to arm 1, independent of the twin.
    const neg5 = await h.call(jv, encodeCall(sel('dI256(int256)'), [-5n]));
    expect(neg5.returnHex, 'dI256(-5) routes to the -5 arm').toBe('0x' + pad32(1n));
    for (const v of [0n, 0xaan, 0xbbn]) await eq(`dAddr(${v})`, encodeCall(sel('dAddr(address)'), [v]));
    for (const v of [0n, 0xffn, 0x100n]) await eq(`dB32(${v})`, encodeCall(sel('dB32(bytes32)'), [v]));
    await eq('dBool(true)', encodeCall(sel('dBool(bool)'), [1n]));
    await eq('dBool(false)', encodeCall(sel('dBool(bool)'), [0n]));
  });

  it('(4) all terminator forms (return/revert-str/custom-error/continue/break/if-else/block)', async () => {
    for (const v of [0n, 1n]) await eq(`tReturn(${v})`, encodeCall(sel('tReturn(uint256)'), [v]));
    for (const v of [0n, 1n]) await eq(`tRevertStr(${v})`, encodeCall(sel('tRevertStr(uint256)'), [v]));  // revert("nope") data
    for (const v of [0n, 1n, 42n]) await eq(`tRevertErr(${v})`, encodeCall(sel('tRevertErr(uint256)'), [v])); // Boom(x) data
    for (const v of [0n, 1n, 2n, 3n, 5n]) await eq(`tContinue(${v})`, encodeCall(sel('tContinue(uint256)'), [v]));
    for (const v of [0n, 1n, 2n]) await eq(`tBreak(${v})`, encodeCall(sel('tBreak(uint256)'), [v]));
    for (const v of [0n, 1n]) await eq(`tIfElse(${v})`, encodeCall(sel('tIfElse(uint256)'), [v]));
    for (const v of [0n, 1n]) await eq(`tBlock(${v})`, encodeCall(sel('tBlock(uint256)'), [v]));
  });

  it('(5) switch in loop: break ends the case, continue continues the loop (raw slot vs twin)', async () => {
    for (const v of [0n, 1n, 6n, 8n]) {
      await eq(`loopBreak(${v})`, encodeCall(sel('loopBreak(uint256)'), [v]));
      expect(await readSlot(h, jv, 1n), `hits after loopBreak(${v})`).toBe(await readSlot(hs, sv, 1n));
    }
    for (const v of [0n, 1n, 2n, 5n]) await eq(`whileSwitch(${v})`, encodeCall(sel('whileSwitch(uint256)'), [v]));
  });
  it('(5) switch nested in switch / switch nested in if', async () => {
    for (const x of [0n, 1n]) for (const c of [0n, 1n, 2n]) await eq(`switchInSwitch(${x},${c})`, encodeCall(sel('switchInSwitch(uint256,uint8)'), [x, c]));
    for (const x of [0n, 1n, 2n]) for (const y of [0n, 1n]) await eq(`switchInIf(${x},${y})`, encodeCall(sel('switchInIf(uint256,uint256)'), [x, y]));
  });

  it('(6) temp non-collision: two switches, sibling locals, hot loop', async () => {
    for (const x of [0n, 1n]) for (const y of [0n, 1n]) await eq(`twoSwitch(${x},${y})`, encodeCall(sel('twoSwitch(uint256,uint256)'), [x, y]));
    for (const v of [0n, 1n, 2n, 3n]) await eq(`siblingLocal(${v})`, encodeCall(sel('siblingLocal(uint256)'), [v]));
    for (const v of [0n, 1n, 7n, 100n]) await eq(`hotLoop(${v})`, encodeCall(sel('hotLoop(uint256)'), [v]));
  });

  it('(7) return shapes through a switch (struct / fixed array / tuple / bytes)', async () => {
    for (const v of [0n, 1n]) await eq(`rStruct(${v})`, encodeCall(sel('rStruct(uint256)'), [v]));
    for (const v of [0n, 1n]) await eq(`rFixed(${v})`, encodeCall(sel('rFixed(uint256)'), [v]));
    for (const v of [0n, 1n]) await eq(`rTuple(${v})`, encodeCall(sel('rTuple(uint256)'), [v]));
    for (const v of [0n, 1n]) await eq(`rString(${v})`, encodeCall(sel('rString(uint256)'), [v]));
  });

  it('(8) exhaustive enum switch (no default) and redundant default behave identically', async () => {
    for (const v of [0n, 1n, 2n, 3n, 4n]) await eq(`exhaust(${v})`, encodeCall(sel('exhaust(uint8)'), [v]));
    for (const v of [0n, 1n, 2n, 3n, 4n]) await eq(`exhaustDef(${v})`, encodeCall(sel('exhaustDef(uint8)'), [v]));
  });

  it('(9) duplicate labels route to the first arm; non-const label, default-only, empty switch', async () => {
    // varLabel: `case y:` is a runtime comparison `__sw == y`. Twin: if (x == y) ... Probe the
    // precedence vs the constant arm `case 5n:` (when y==5 the FIRST arm should win, matching solc).
    for (const [x, y] of [[3n, 3n], [5n, 9n], [5n, 5n], [9n, 9n], [0n, 1n]] as const)
      await eq(`varLabel(${x},${y})`, encodeCall(sel('varLabel(uint256,uint256)'), [x, y]));
    for (const v of [0n, 1n, 7n]) await eq(`defOnly(${v})`, encodeCall(sel('defOnly(uint256)'), [v]));
    for (const v of [0n, 1n, 7n]) await eq(`emptySwitch(${v})`, encodeCall(sel('emptySwitch(uint256)'), [v]));
  });

  it('event emitted from a switch arm: topics + data identical', async () => {
    for (const v of [0n, 1n, 2n]) await eq(`evSwitch(${v})`, encodeCall(sel('evSwitch(uint256)'), [v]));
  });
});

// ---- compile-time soundness: the desugar must REJECT what solc/the spec rejects --------------
describe('ADV switch: soundness / rejections (no crash, right diagnostic)', () => {
  const wrap = (b: string) =>
    `enum Color { Red, Green, Blue }\n@struct class S { a: u256; }\n@contract class C { @external @pure f(c: Color, x: u256, s: string): u256 {\n${b}\nreturn 0n; } }`;

  it('JETH281: non-value discriminant (string / array / struct)', () => {
    expect(codes(wrap('switch (s) { case "a": return 1n; default: return 0n; }'))).toContain('JETH281');
    expect(codes(`@contract class C { @external @pure f(a: u256[]): u256 { switch (a) { default: return 0n; } } }`)).toContain('JETH281');
    expect(codes(`@struct class S { a: u256; }\n@contract class C { @external @pure f(s: S): u256 { switch (s) { default: return 0n; } } }`)).toContain('JETH281');
  });
  it('JETH282: default not last', () => {
    expect(codes(wrap('switch (x) { default: return 0n; case 1n: return 1n; }'))).toContain('JETH282');
  });
  it('JETH283: a case label falling into default (no body before default)', () => {
    expect(codes(wrap('switch (x) { case 1n: default: return 5n; }'))).toContain('JETH283');
    // a trailing bare case label with no body (falls off the end)
    expect(codes(wrap('switch (x) { case 1n: return 1n; case 2n: }'))).toContain('JETH283');
  });
  it('JETH284: implicit fall-through from a non-empty case', () => {
    expect(codes(wrap('switch (x) { case 1n: { let y: u256 = x; } case 2n: return 2n; default: return 0n; }'))).toContain('JETH284');
  });
  it('JETH284: a trailing nested switch is NOT auto-diverting (needs an explicit break)', () => {
    expect(codes(
      `enum E { A, B }\n@contract class C { @external @pure f(x: u256, c: E): u256 {\nswitch (x) { case 1n: switch (c) { case E.A: return 1n; case E.B: return 2n; } default: return 0n; }\nreturn 9n; } }`,
    )).toContain('JETH284');
  });
  it('JETH285: an early/stray break mid-case', () => {
    expect(codes(wrap('switch (x) { case 1n: if (x > 0n) break; return 5n; default: return 0n; }'))).toContain('JETH285');
  });
  it('JETH286: non-exhaustive enum switch with no default', () => {
    expect(codes(wrap('switch (c) { case Color.Red: return 1n; case Color.Green: return 2n; }'))).toContain('JETH286');
  });

  it('accepts: exhaustive enum (no default), redundant default, empty switch, default-only', () => {
    expect(codes(wrap('switch (c) { case Color.Red: return 1n; case Color.Green: return 2n; case Color.Blue: return 3n; }'))).toEqual([]);
    expect(codes(wrap('switch (c) { case Color.Red: return 1n; default: return 9n; }'))).toEqual([]);
    expect(codes(wrap('switch (x) {}'))).toEqual([]);
    expect(codes(wrap('switch (x) { default: return 5n; }'))).toEqual([]);
  });

  it('a duplicate CONSTANT case label is rejected (JETH287 stricter lint)', () => {
    // A duplicate constant label is a dead arm (the first match wins) and almost always a bug, so
    // JETH now rejects it rather than silently accepting it.
    expect(codes(wrap('switch (x) { case 1n: return 1n; case 1n: return 2n; default: return 0n; }'))).toContain('JETH287');
  });
  it('CHARACTERIZE: a non-constant (variable) case label is accepted (runtime ==)', () => {
    // `case y:` (y a parameter) compiles: the desugar makes it a runtime `__sw == y`. This is a
    // SUPERSET of solc/TS, where a `case` is required to be... (TS allows non-const too; solc has no
    // switch). The if/else twin `if (x == y)` is exactly equivalent, so it is NOT a miscompile.
    expect(codes(wrap('switch (x) { case x: return 1n; default: return 0n; }'))).toEqual([]);
  });
  it('SOUNDNESS: a user local that spells the synthesized temp is NOT hijacked (the temp is renamed)', async () => {
    // The desugar names its discriminant temp `__jeth_sw_<n>`, which lives in the user-reachable
    // namespace. Cross-scope shadowing is now allowed (matching solc), so naively the synth const in
    // the switch block would SHADOW the user's `__jeth_sw_0` and `return __jeth_sw_0` would return the
    // discriminant (x), not 42. `freshSynthName` defends against exactly this: it bumps the counter
    // past every visible user name, so the synth temp becomes `__jeth_sw_1` and the user's
    // `__jeth_sw_0` (= 42) is preserved. The contract compiles AND returns 42, byte-identically to the
    // hand-written `let v = 42; if (x == 1) return v; return 0;` twin.
    const src = `@contract class C { @external @pure f(x: u256): u256 {
      let __jeth_sw_0: u256 = 42n;
      switch (x) { case 1n: return __jeth_sw_0; default: return 0n; }
    } }`;
    expect(codes(src)).toEqual([]);
    const h = await Harness.create();
    const a = await h.deploy(compile(src, { fileName: 'C.jeth' }).creationBytecode);
    const call1 = await h.call(a, '0x' + sel('f(uint256)') + pad32(1n));
    const call9 = await h.call(a, '0x' + sel('f(uint256)') + pad32(9n));
    expect(call1.returnHex).toBe('0x' + pad32(42n)); // case 1 returns the USER's 42, not the discriminant
    expect(call9.returnHex).toBe('0x' + pad32(0n));  // default returns 0
  });
});
