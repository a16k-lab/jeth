// Adversarial differential test: MIXED calldata composite array element access
// (JETH151 + JETH210, the new `cdSubElem` resolver in src/yul.ts lowerArrayRef).
//   dynamic-of-fixed  uint256[2][]   a[i][j]  (Arr<u256,2>[])
//   fixed-of-dynamic  uint256[][2]   a[i][j]  (Arr<u256[],2>)
//   + a[i].length (fod), whole-param echo `return a`, a.length (outer).
//
// INVARIANT: byte-identical to solc on returndata AND success/revert/Panic parity.
// We hand-encode malformed calldata to attack offset/length/bounds/element-type
// edges RUTHLESSLY and assert jeth == solc on (success, returnHex) for every case.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

// ---- A single contract exercising every shape / element type under test. -----
const JETH = `@contract class C {
  @external @pure dof(a: Arr<u256,2>[], i: u256, j: u256): u256 { return a[i][j]; }
  @external @pure dofLen(a: Arr<u256,2>[]): u256 { return a.length; }
  @external @pure dofEcho(a: Arr<u256,2>[]): Arr<u256,2>[] { return a; }

  @external @pure fod(a: Arr<u256[],2>, i: u256, j: u256): u256 { return a[i][j]; }
  @external @pure fodLen(a: Arr<u256[],2>, i: u256): u256 { return a[i].length; }
  @external @pure fodEcho(a: Arr<u256[],2>): Arr<u256[],2> { return a; }

  @external @pure dofU8(a: Arr<u8,3>[], i: u256, j: u256): u8 { return a[i][j]; }
  @external @pure dofI128(a: Arr<i128,2>[], i: u256, j: u256): i128 { return a[i][j]; }
  @external @pure dofAddr(a: Arr<address,2>[], i: u256, j: u256): address { return a[i][j]; }
  @external @pure dofB4(a: Arr<bytes4,2>[], i: u256, j: u256): bytes4 { return a[i][j]; }

  @external @pure fodU8(a: Arr<u8[],2>, i: u256, j: u256): u8 { return a[i][j]; }
  @external @pure fodI256(a: Arr<i256[],2>, i: u256, j: u256): i256 { return a[i][j]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function dof(uint256[2][] calldata a, uint256 i, uint256 j) external pure returns (uint256) { return a[i][j]; }
  function dofLen(uint256[2][] calldata a) external pure returns (uint256) { return a.length; }
  function dofEcho(uint256[2][] calldata a) external pure returns (uint256[2][] memory) { return a; }

  function fod(uint256[][2] calldata a, uint256 i, uint256 j) external pure returns (uint256) { return a[i][j]; }
  function fodLen(uint256[][2] calldata a, uint256 i) external pure returns (uint256) { return a[i].length; }
  function fodEcho(uint256[][2] calldata a) external pure returns (uint256[][2] memory) { return a; }

  function dofU8(uint8[3][] calldata a, uint256 i, uint256 j) external pure returns (uint8) { return a[i][j]; }
  function dofI128(int128[2][] calldata a, uint256 i, uint256 j) external pure returns (int128) { return a[i][j]; }
  function dofAddr(address[2][] calldata a, uint256 i, uint256 j) external pure returns (address) { return a[i][j]; }
  function dofB4(bytes4[2][] calldata a, uint256 i, uint256 j) external pure returns (bytes4) { return a[i][j]; }

  function fodU8(uint8[][2] calldata a, uint256 i, uint256 j) external pure returns (uint8) { return a[i][j]; }
  function fodI256(int256[][2] calldata a, uint256 i, uint256 j) external pure returns (int256) { return a[i][j]; }
}`;

// ---- Encoders -----------------------------------------------------------------
// dynamic-of-fixed uint256[N][]: [len][e0w0..e0w(N-1)][e1w0..]...  (contiguous)
const encDof = (rows: bigint[][]) =>
  pad(BigInt(rows.length)) + rows.map((r) => r.map(pad).join('')).join('');
// raw inner uint-array body: [len][x0][x1]...
const encU256Arr = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');
// fixed-of-dynamic uint256[][N]: [off0..off(N-1)][inner0][inner1]...  offsets rel. to array start
const encFod = (rows: bigint[][]) => {
  const inners = rows.map(encU256Arr);
  let off = rows.length * 32;
  const offs: string[] = [];
  for (const e of inners) {
    offs.push(pad(BigInt(off)));
    off += e.length / 2;
  }
  return offs.join('') + inners.join('');
};

describe('adversarial: MIXED calldata composite element access vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  let nCases = 0;
  let divergences: string[] = [];

  async function eq(label: string, data: string) {
    nCases++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    const ok = j.success === s.success && j.returnHex === s.returnHex;
    if (!ok) {
      divergences.push(
        `DIVERGENCE [${label}]\n  data=${data}\n` +
          `  jeth: success=${j.success} err=${j.exceptionError} ret=${j.returnHex}\n` +
          `  sol : success=${s.success} ret=${s.returnHex}`,
      );
    }
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // ============================ DYNAMIC-OF-FIXED ============================

  it('dof in-range + OOB i/j across boundary index values', async () => {
    const rows = [
      [1n, 2n],
      [3n, 4n],
      [5n, 6n],
      [M - 1n, 7n],
    ];
    const sl = sel('dof(uint256[2][],uint256,uint256)');
    const head = (i: bigint, j: bigint) => '0x' + sl + pad(0x60n) + pad(i) + pad(j) + encDof(rows);
    // valid grid
    for (let i = 0n; i < 4n; i++) for (let j = 0n; j < 2n; j++) await eq(`dof[${i}][${j}]`, head(i, j));
    // i OOB
    for (const [nm, v] of [
      ['justPast', 4n],
      ['2^64', 1n << 64n],
      ['2^64-1', (1n << 64n) - 1n],
      ['2^128', 1n << 128n],
      ['2^255', 1n << 255n],
      ['max', M - 1n],
    ] as const)
      await eq(`dof i OOB ${nm}`, head(v, 0n));
    // j OOB (j only ranges 0..N-1=1)
    for (const [nm, v] of [
      ['justPast', 2n],
      ['2^64', 1n << 64n],
      ['2^255', 1n << 255n],
      ['max', M - 1n],
    ] as const)
      await eq(`dof j OOB ${nm}`, head(0n, v));
    // both OOB
    await eq('dof both OOB', head(9n, 9n));
    await eq('dof both max', head(M - 1n, M - 1n));
  });

  it('dof empty outer array (len 0): any i is OOB', async () => {
    const sl = sel('dof(uint256[2][],uint256,uint256)');
    const head = (i: bigint, j: bigint) => '0x' + sl + pad(0x60n) + pad(i) + pad(j) + encDof([]);
    await eq('dof empty [0][0]', head(0n, 0n));
    await eq('dof empty [max]', head(M - 1n, 0n));
    // a.length on empty
    await eq('dofLen empty', '0x' + sel('dofLen(uint256[2][])') + pad(0x20n) + encDof([]));
  });

  it('dof a.length and echo', async () => {
    for (const rows of [[], [[1n, 2n]], [[1n, 2n], [3n, 4n]], [[9n, 8n], [7n, 6n], [5n, 4n]]] as bigint[][][]) {
      await eq(`dofLen n=${rows.length}`, '0x' + sel('dofLen(uint256[2][])') + pad(0x20n) + encDof(rows));
      await eq(`dofEcho n=${rows.length}`, '0x' + sel('dofEcho(uint256[2][])') + pad(0x20n) + encDof(rows));
    }
  });

  it('dof malformed outer length: huge / 2^64 / 2^64-1 / truncated payload', async () => {
    const sl = sel('dof(uint256[2][],uint256,uint256)');
    // declared len huge but payload short -> payload-fits check
    const body = (len: bigint, payloadRows: bigint[][]) =>
      pad(len) + payloadRows.map((r) => r.map(pad).join('')).join('');
    const mk = (len: bigint, payloadRows: bigint[][], i: bigint, j: bigint) =>
      '0x' + sl + pad(0x60n) + pad(i) + pad(j) + body(len, payloadRows);
    await eq('dof len 2^64', mk(1n << 64n, [[1n, 2n]], 0n, 0n));
    await eq('dof len 2^64-1', mk((1n << 64n) - 1n, [[1n, 2n]], 0n, 0n));
    await eq('dof len 2^256-1', mk(M - 1n, [[1n, 2n]], 0n, 0n));
    await eq('dof len=3 payload=1row (truncated)', mk(3n, [[1n, 2n]], 0n, 0n));
    await eq('dof len=3 payload=1row read[2]', mk(3n, [[1n, 2n]], 2n, 0n));
    await eq('dof len=2 payload=2rows read[1][1]', mk(2n, [[1n, 2n], [3n, 4n]], 1n, 1n));
    // length word present but data offset (0x60) made dirty/oob below
  });

  it('dof dirty outer param offset word', async () => {
    const sl = sel('dof(uint256[2][],uint256,uint256)');
    const tail = encDof([[1n, 2n], [3n, 4n]]);
    const mk = (off: bigint) => '0x' + sl + pad(off) + pad(0n) + pad(0n) + tail;
    await eq('dof off 0x60 ok', mk(0x60n));
    await eq('dof off 2^64', mk(1n << 64n));
    await eq('dof off 2^64-1', mk((1n << 64n) - 1n));
    await eq('dof off 2^255', mk(1n << 255n));
    await eq('dof off 2^256-1', mk(M - 1n));
    await eq('dof off 0', mk(0n));
    await eq('dof off 0x61 mid-word', mk(0x61n));
    await eq('dof off pastEnd', mk(0xfffn));
    await eq('dof off 0x5f', mk(0x5fn));
  });

  it('dof truncated tail: missing length word / partial element rows', async () => {
    const sl = sel('dof(uint256[2][],uint256,uint256)');
    const headOnly = '0x' + sl + pad(0x60n) + pad(0n) + pad(0n);
    await eq('dof no length word at all', headOnly);
    await eq('dof length word only, no rows', headOnly + pad(2n));
    await eq('dof length=2, 1.5 rows', headOnly + pad(2n) + pad(1n) + pad(2n) + pad(3n));
    await eq('dof length=1, half row', headOnly + pad(1n) + pad(1n));
  });

  // ============================ FIXED-OF-DYNAMIC ============================

  it('fod in-range + OOB i/j across boundary values', async () => {
    const rows = [
      [1n, 2n, 3n],
      [4n, 5n],
    ];
    const slf = sel('fod(uint256[][2],uint256,uint256)');
    const sll = sel('fodLen(uint256[][2],uint256)');
    const fod = (i: bigint, j: bigint) => '0x' + slf + pad(0x60n) + pad(i) + pad(j) + encFod(rows);
    const fodLen = (i: bigint) => '0x' + sll + pad(0x40n) + pad(i) + encFod(rows);
    for (const [i, n] of [[0n, 3n], [1n, 2n]] as const) {
      await eq(`fodLen[${i}]`, fodLen(i));
      for (let j = 0n; j < n; j++) await eq(`fod[${i}][${j}]`, fod(i, j));
      await eq(`fod[${i}] j justPast`, fod(i, n));
      await eq(`fod[${i}] j 2^64`, fod(i, 1n << 64n));
      await eq(`fod[${i}] j 2^255`, fod(i, 1n << 255n));
      await eq(`fod[${i}] j max`, fod(i, M - 1n));
    }
    // i OOB (N=2, so i>=2). length and element.
    for (const [nm, v] of [
      ['justPast', 2n],
      ['2^64', 1n << 64n],
      ['2^255', 1n << 255n],
      ['max', M - 1n],
    ] as const) {
      await eq(`fod i OOB ${nm}`, fod(v, 0n));
      await eq(`fodLen i OOB ${nm}`, fodLen(v));
    }
  });

  it('fod inner arrays of length 0 -> any j OOB', async () => {
    const rows = [[], [42n]];
    const slf = sel('fod(uint256[][2],uint256,uint256)');
    const sll = sel('fodLen(uint256[][2],uint256)');
    const fod = (i: bigint, j: bigint) => '0x' + slf + pad(0x60n) + pad(i) + pad(j) + encFod(rows);
    const fodLen = (i: bigint) => '0x' + sll + pad(0x40n) + pad(i) + encFod(rows);
    await eq('fodLen[0] empty', fodLen(0n));
    await eq('fod[0][0] empty inner', fod(0n, 0n));
    await eq('fod[0][max] empty inner', fod(0n, M - 1n));
    await eq('fodLen[1]', fodLen(1n));
    await eq('fod[1][0]', fod(1n, 0n));
    await eq('fod[1][1] OOB', fod(1n, 1n));
  });

  it('fod echo (whole param) regression', async () => {
    for (const rows of [
      [[], []],
      [[1n], [2n, 3n]],
      [[1n, 2n, 3n], [4n, 5n]],
      [[M - 1n], []],
    ] as bigint[][][]) {
      await eq(`fodEcho ${JSON.stringify(rows.map((r) => r.length))}`, '0x' + sel('fodEcho(uint256[][2])') + pad(0x20n) + encFod(rows));
    }
  });

  it('fod malformed inner-array offset table words', async () => {
    const slf = sel('fod(uint256[][2],uint256,uint256)');
    const sll = sel('fodLen(uint256[][2],uint256)');
    // base body = 2 offset words + payloads. We corrupt offset word 0 (for a[0]).
    // valid inners: a[0]=[10,11], a[1]=[20]
    const inner0 = encU256Arr([10n, 11n]); // 3 words
    const inner1 = encU256Arr([20n]); // 2 words
    const off1Valid = BigInt(64 + inner0.length / 2); // byte offset of inner1
    const build = (off0: bigint) =>
      pad(off0) + pad(off1Valid) + inner0 + inner1;
    const fod = (off0: bigint, i: bigint, j: bigint) =>
      '0x' + slf + pad(0x60n) + pad(i) + pad(j) + build(off0);
    const fodLen = (off0: bigint, i: bigint) =>
      '0x' + sll + pad(0x40n) + pad(i) + build(off0);
    const OFF0 = 64n; // valid byte offset of inner0
    // sanity: valid
    await eq('fod valid a[0][0]', fod(OFF0, 0n, 0n));
    await eq('fod valid a[0][1]', fod(OFF0, 0n, 1n));
    await eq('fod valid a[1][0]', fod(OFF0, 1n, 0n));
    // corrupt off0 -> reading a[0] should behave identically
    for (const [nm, v] of [
      ['1<<200', 1n << 200n],
      ['0xffffffff', 0xffffffffn],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['0', 0n],
      ['midword', OFF0 + 1n],
      ['nearCdsize', 0xfffn],
      ['2^64', 1n << 64n],
      ['2^64-1', (1n << 64n) - 1n],
    ] as const) {
      await eq(`fod off0=${nm} a[0][0]`, fod(v, 0n, 0n));
      await eq(`fodLen off0=${nm} a[0]`, fodLen(v, 0n));
      // a[1] should still be readable through the untouched off1
      await eq(`fod off0=${nm} a[1][0]`, fod(v, 1n, 0n));
    }
  });

  it('fod aliased inner offsets (two inner arrays point at same data)', async () => {
    const slf = sel('fod(uint256[][2],uint256,uint256)');
    // both offsets -> same inner body at byte 64
    const inner = encU256Arr([7n, 8n, 9n]);
    const body = pad(64n) + pad(64n) + inner;
    const fod = (i: bigint, j: bigint) => '0x' + slf + pad(0x60n) + pad(i) + pad(j) + body;
    await eq('fod alias a[0][2]', fod(0n, 2n));
    await eq('fod alias a[1][2]', fod(1n, 2n));
    await eq('fod alias a[0][3] OOB', fod(0n, 3n));
    await eq('fod alias echo', '0x' + sel('fodEcho(uint256[][2])') + pad(0x20n) + body);
  });

  it('fod malformed inner LENGTH: 2^64-1 / 2^64 / exceeds calldatasize / truncated tail', async () => {
    const slf = sel('fod(uint256[][2],uint256,uint256)');
    // inner0 declared length = LEN, no/short payload. inner1 valid [20].
    const inner1 = encU256Arr([20n]);
    const build = (len: bigint, payload: bigint[]) => {
      const inner0 = pad(len) + payload.map(pad).join('');
      const off1 = BigInt(64 + inner0.length / 2);
      return pad(64n) + pad(off1) + inner0 + inner1;
    };
    const fod = (len: bigint, payload: bigint[], i: bigint, j: bigint) =>
      '0x' + slf + pad(0x60n) + pad(i) + pad(j) + build(len, payload);
    await eq('fod inner len 2^64-1', fod((1n << 64n) - 1n, [], 0n, 0n));
    await eq('fod inner len 2^64', fod(1n << 64n, [], 0n, 0n));
    await eq('fod inner len 2^256-1', fod(M - 1n, [], 0n, 0n));
    await eq('fod inner len=4 payload=2 (past end)', fod(4n, [1n, 2n], 0n, 0n));
    await eq('fod inner len=4 payload=2 read[3]', fod(4n, [1n, 2n], 0n, 3n));
    await eq('fod inner len=4 payload=4 ok', fod(4n, [1n, 2n, 3n, 4n], 0n, 3n));
    // a[1] still ok regardless
    await eq('fod inner0 corrupt, read a[1][0]', fod(M - 1n, [], 1n, 0n));
  });

  it('fod dirty outer param offset word (agreeing region)', async () => {
    const slf = sel('fod(uint256[][2],uint256,uint256)');
    const tail = encFod([[1n, 2n], [3n]]);
    const mk = (off: bigint) => '0x' + slf + pad(off) + pad(0n) + pad(0n) + tail;
    await eq('fod off 0x60 ok', mk(0x60n));
    await eq('fod off 2^64', mk(1n << 64n));
    await eq('fod off 2^64-1', mk((1n << 64n) - 1n));
    await eq('fod off 2^255', mk(1n << 255n)); // wraps to a huge ptr -> both EMPTY-revert
    await eq('fod off 2^255+0x60', mk((1n << 255n) + 0x60n));
    await eq('fod off 0', mk(0n));
    await eq('fod off 0x61 mid', mk(0x61n));
    await eq('fod off pastEnd', mk(0xfffn));
  });

  // ===================== CONFIRMED MISCOMPILE (fixed-of-dynamic) =====================
  // The Arr<dyn,N> (uint256[][2]) outer-param offset is validated with a SIGNED check
  // at src/yul.ts:254:
  //     if iszero(slt(off, sub(sub(calldatasize(), 4), 0x1f))) { revert(0, 0) }
  // A high-bit "small negative" offset (off == 2^256-1, 2^256-4, ...) is < the positive
  // bound under slt, so the check PASSES; then dataPtr = add(4, off) WRAPS to a small,
  // in-bounds pointer. The length is the fixed N (=2), so the i<N bound passes, and
  // calldataInnerArray reverts with Panic(0x32). solc validates this top-level dynamic
  // param offset with an UNSIGNED bound (like jeth's own calldataArray/calldataDynArray/
  // calldataTuple, which all use `gt(off, 0xffffffffffffffff)`), and reverts EMPTY.
  //   jeth: success=false ret=0x4e487b71...0032  (Panic 0x32)
  //   sol : success=false ret=0x                  (EMPTY revert)
  // Both fail, but returndata is NOT byte-identical => miscompile.
  // The sibling dynamic-of-fixed (uint256[2][]) param routes through calldataArray and is
  // CORRECT at the same offsets (see the "dof dirty outer param offset word" test above).
  // This test asserts the OBSERVED divergent behavior so the suite stays green while the
  // bug is unmissable; flip to `eq(...)` once src/yul.ts:254 uses an unsigned bound.
  // FIXED: the Arr<dyn,N> param binding now uses an UNSIGNED offset cap (src/yul.ts), so a
  // high-bit "small negative" outer offset EMPTY-reverts byte-identically to solc (was Panic 0x32).
  it('fod outer offset high-bit -> EMPTY revert parity', async () => {
    const slf = sel('fod(uint256[][2],uint256,uint256)');
    const tail = encFod([[1n, 2n], [3n]]);
    const mk = (off: bigint) => '0x' + slf + pad(off) + pad(0n) + pad(0n) + tail;
    for (const [nm, off] of [
      ['2^256-1', M - 1n],
      ['2^256-4', M - 4n],
      ['2^256-0x60', M - 0x60n],
      ['2^255', 1n << 255n],
      ['2^64', 1n << 64n],
    ] as const) {
      await eq(`fod high-bit off ${nm}`, mk(off));
    }
  });

  it('fod truncated tail: missing offset table / missing inner payload', async () => {
    const slf = sel('fod(uint256[][2],uint256,uint256)');
    const headOnly = '0x' + slf + pad(0x60n) + pad(0n) + pad(0n);
    await eq('fod no body', headOnly);
    await eq('fod only 1 offset word', headOnly + pad(64n));
    await eq('fod 2 offsets, no payload', headOnly + pad(64n) + pad(96n));
    // offset table present pointing into nothing
    await eq('fod offsets point past end', headOnly + pad(0x1000n) + pad(0x2000n));
  });

  // ====================== NARROW / SIGNED / bytesN ELEMENTS =====================
  // Lazy element access of a narrow type: solc validates (reverts) on dirty bits.
  // We feed a DIRTY high-word element and check jeth matches solc's leaf read.

  it('dof narrow uint8[3][]: clean and dirty elements', async () => {
    const slu8 = sel('dofU8(uint8[3][],uint256,uint256)');
    // each element word holds a uint8; high bits dirty -> validate-revert expected.
    const mk = (rows: bigint[][], i: bigint, j: bigint) =>
      '0x' + slu8 + pad(0x60n) + pad(i) + pad(j) + encDof(rows);
    // clean
    await eq('dofU8 clean [0][0]', mk([[1n, 2n, 3n], [4n, 5n, 6n]], 0n, 0n));
    await eq('dofU8 clean [1][2]', mk([[1n, 2n, 3n], [4n, 5n, 6n]], 1n, 2n));
    await eq('dofU8 max 0xff', mk([[0xffn, 0n, 0n]], 0n, 0n));
    // dirty: high bit set
    await eq('dofU8 dirty 0x100', mk([[0x100n, 0n, 0n]], 0n, 0n));
    await eq('dofU8 dirty top word', mk([[M - 1n, 0n, 0n]], 0n, 0n));
    await eq('dofU8 dirty 0x1ff', mk([[0x1ffn, 0n, 0n]], 0n, 0n));
    // dirty element NOT read (j picks a clean one) -> should NOT revert
    await eq('dofU8 dirty[0] read[1]', mk([[M - 1n, 5n, 6n]], 0n, 1n));
    // OOB with dirty data
    await eq('dofU8 dirty OOB i', mk([[M - 1n, 0n, 0n]], 5n, 0n));
  });

  it('dof signed int128[2][]: clean and dirty (bad sign-extension)', async () => {
    const sli = sel('dofI128(int128[2][],uint256,uint256)');
    const mk = (rows: bigint[][], i: bigint, j: bigint) =>
      '0x' + sli + pad(0x60n) + pad(i) + pad(j) + encDof(rows);
    const neg = M - 5n; // -5 as int128 sign-extended into 256 bits -> all high bits 1 (valid)
    await eq('dofI128 +ve', mk([[7n, 8n]], 0n, 0n));
    await eq('dofI128 -ve valid', mk([[neg, 0n]], 0n, 0n)); // 2^256-5: valid int128 sign-ext
    await eq('dofI128 min', mk([[M - (1n << 127n), 0n]], 0n, 0n)); // -2^127 sign-extended
    await eq('dofI128 max', mk([[(1n << 127n) - 1n, 0n]], 0n, 0n));
    // dirty: not a valid sign-extension (bit 127 = 0 but high bits set)
    await eq('dofI128 dirty highbits', mk([[(1n << 200n) | 5n, 0n]], 0n, 0n));
    await eq('dofI128 dirty 2^128', mk([[1n << 128n, 0n]], 0n, 0n));
    await eq('dofI128 dirty all1 low0', mk([[M - 1n - ((1n << 127n) - 1n) + 1n, 0n]], 0n, 0n));
  });

  it('dof address[2][] and bytes4[2][]: dirty validation', async () => {
    const sla = sel('dofAddr(address[2][],uint256,uint256)');
    const slb = sel('dofB4(bytes4[2][],uint256,uint256)');
    const mka = (rows: bigint[][], i: bigint, j: bigint) =>
      '0x' + sla + pad(0x60n) + pad(i) + pad(j) + encDof(rows);
    const mkb = (rows: bigint[][], i: bigint, j: bigint) =>
      '0x' + slb + pad(0x60n) + pad(i) + pad(j) + encDof(rows);
    const A = 0x1234567890abcdef1234567890abcdef12345678n;
    await eq('dofAddr clean', mka([[A, 0n]], 0n, 0n));
    await eq('dofAddr dirty high96', mka([[(1n << 200n) | A, 0n]], 0n, 0n));
    await eq('dofAddr dirty top', mka([[M - 1n, 0n]], 0n, 0n));
    // bytes4 is LEFT-aligned: low 28 bytes must be zero
    const b4 = 0xdeadbeefn << (28n * 8n);
    await eq('dofB4 clean', mkb([[b4, 0n]], 0n, 0n));
    await eq('dofB4 dirty low', mkb([[b4 | 0x1n, 0n]], 0n, 0n));
    await eq('dofB4 dirty allset', mkb([[M - 1n, 0n]], 0n, 0n));
  });

  it('fod narrow uint8[][2] and int256[][2]: dirty validation', async () => {
    const slu8 = sel('fodU8(uint8[][2],uint256,uint256)');
    const sli = sel('fodI256(int256[][2],uint256,uint256)');
    const mk = (slf: string, rows: bigint[][], i: bigint, j: bigint) =>
      '0x' + slf + pad(0x60n) + pad(i) + pad(j) + encFod(rows);
    await eq('fodU8 clean', mk(slu8, [[1n, 2n], [3n]], 0n, 1n));
    await eq('fodU8 dirty 0x100', mk(slu8, [[0x100n, 2n], [3n]], 0n, 0n));
    await eq('fodU8 dirty top', mk(slu8, [[M - 1n], [3n]], 0n, 0n));
    await eq('fodU8 dirty not-read', mk(slu8, [[M - 1n, 5n], [3n]], 0n, 1n));
    // int256 element: no narrow validation (full width) -> any bits valid
    await eq('fodI256 -ve', mk(sli, [[M - 1n], [2n]], 0n, 0n));
    await eq('fodI256 +ve', mk(sli, [[1n << 200n], [2n]], 0n, 0n));
    await eq('fodI256 OOB j', mk(sli, [[1n], [2n]], 0n, 1n));
  });

  // ====================== CROSS-CHECK: element vs echo consistency ============
  it('dof element reads match echo for the same payload', async () => {
    const rows = [[11n, 22n], [33n, 44n], [55n, 66n]];
    await eq('dofEcho xcheck', '0x' + sel('dofEcho(uint256[2][])') + pad(0x20n) + encDof(rows));
    const slf = sel('dof(uint256[2][],uint256,uint256)');
    for (let i = 0n; i < 3n; i++)
      for (let j = 0n; j < 2n; j++)
        await eq(`dof xcheck[${i}][${j}]`, '0x' + slf + pad(0x60n) + pad(i) + pad(j) + encDof(rows));
  });

  it('REPORT: case count + any divergences', () => {
    if (divergences.length) {
      throw new Error(`\n${divergences.length} DIVERGENCE(S):\n` + divergences.join('\n\n'));
    }
    // eslint-disable-next-line no-console
    console.log(`adv_cdcomposite: ${nCases} differential cases, all jeth==solc`);
  });
});
