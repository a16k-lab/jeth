// Phase 4d scenario "all-elem-types-fixed-array": one fixed-array param getter per
// value element type (T[5] and T[3]) returning a[i] (runtime index). For each type we
// probe a CLEAN in-range read (incl type max and, for intN, a negative two's-complement
// value), a DIRTY read (non-canonical encoding) expecting EMPTY revert, an UNREAD dirty
// element expecting OK, and a runtime OOB index expecting Panic(0x32). Every probe must
// be byte-identical to Solidity (the oracle): success + returndata, '0x' for empty
// reverts, 0x4e487b71 + 0x32 word for panics.
import { describe, it, expect, beforeAll } from 'vitest';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}

// JETH source (one T[5] and one T[3] getter per element type).
const JETH = `// generated
@contract
class AllElemTypesFixedArray {
  @external @pure u8_5(a: Arr<u8, 5>, i: u256): u8 { return a[i]; }
  @external @pure u8_3(a: Arr<u8, 3>, i: u256): u8 { return a[i]; }
  @external @pure u16_5(a: Arr<u16, 5>, i: u256): u16 { return a[i]; }
  @external @pure u16_3(a: Arr<u16, 3>, i: u256): u16 { return a[i]; }
  @external @pure u32_5(a: Arr<u32, 5>, i: u256): u32 { return a[i]; }
  @external @pure u32_3(a: Arr<u32, 3>, i: u256): u32 { return a[i]; }
  @external @pure u64_5(a: Arr<u64, 5>, i: u256): u64 { return a[i]; }
  @external @pure u64_3(a: Arr<u64, 3>, i: u256): u64 { return a[i]; }
  @external @pure u128_5(a: Arr<u128, 5>, i: u256): u128 { return a[i]; }
  @external @pure u128_3(a: Arr<u128, 3>, i: u256): u128 { return a[i]; }
  @external @pure i8_5(a: Arr<i8, 5>, i: u256): i8 { return a[i]; }
  @external @pure i8_3(a: Arr<i8, 3>, i: u256): i8 { return a[i]; }
  @external @pure i16_5(a: Arr<i16, 5>, i: u256): i16 { return a[i]; }
  @external @pure i16_3(a: Arr<i16, 3>, i: u256): i16 { return a[i]; }
  @external @pure i64_5(a: Arr<i64, 5>, i: u256): i64 { return a[i]; }
  @external @pure i64_3(a: Arr<i64, 3>, i: u256): i64 { return a[i]; }
  @external @pure i128_5(a: Arr<i128, 5>, i: u256): i128 { return a[i]; }
  @external @pure i128_3(a: Arr<i128, 3>, i: u256): i128 { return a[i]; }
  @external @pure i256_5(a: Arr<i256, 5>, i: u256): i256 { return a[i]; }
  @external @pure i256_3(a: Arr<i256, 3>, i: u256): i256 { return a[i]; }
  @external @pure bool_5(a: Arr<bool, 5>, i: u256): bool { return a[i]; }
  @external @pure bool_3(a: Arr<bool, 3>, i: u256): bool { return a[i]; }
  @external @pure addr_5(a: Arr<address, 5>, i: u256): address { return a[i]; }
  @external @pure addr_3(a: Arr<address, 3>, i: u256): address { return a[i]; }
  @external @pure b1_5(a: Arr<bytes1, 5>, i: u256): bytes1 { return a[i]; }
  @external @pure b1_3(a: Arr<bytes1, 3>, i: u256): bytes1 { return a[i]; }
  @external @pure b4_5(a: Arr<bytes4, 5>, i: u256): bytes4 { return a[i]; }
  @external @pure b4_3(a: Arr<bytes4, 3>, i: u256): bytes4 { return a[i]; }
  @external @pure b20_5(a: Arr<bytes20, 5>, i: u256): bytes20 { return a[i]; }
  @external @pure b20_3(a: Arr<bytes20, 3>, i: u256): bytes20 { return a[i]; }
  @external @pure b32_5(a: Arr<bytes32, 5>, i: u256): bytes32 { return a[i]; }
  @external @pure b32_3(a: Arr<bytes32, 3>, i: u256): bytes32 { return a[i]; }
}`;

function solFn(jethBase: string, sol: string, n: number): string {
  return `function ${jethBase}(${sol}[${n}] calldata a, uint256 i) external pure returns (${sol}){ return a[i]; }`;
}

// Element-type table. For each: canonical Solidity name, JETH fn base, several CLEAN
// in-range values (one is the type max; for intN one is a negative two's-complement
// value), and a DIRTY encoding (the 256-bit ABI word that is non-canonical for the type).
interface Elem {
  sol: string; // solidity type name (canonical leaf)
  base: string; // jeth/solidity fn base name
  clean: bigint[]; // canonical ABI words to test as clean reads (already padded to 256b)
  dirty: bigint; // a non-canonical ABI word for this type (read -> EMPTY revert)
}

// helper: left-align an M-byte value into a 256-bit word (bytesM ABI layout).
const left = (mBytes: number, lowVal: bigint) => lowVal << BigInt((32 - mBytes) * 8);

const TYPES: Elem[] = [
  // unsigned: canonical = high bits above N must be 0. clean incl max = 2^N-1. dirty = bit N set.
  { sol: 'uint8', base: 'u8', clean: [0n, 1n, (1n << 8n) - 1n], dirty: 1n << 8n },
  { sol: 'uint16', base: 'u16', clean: [0n, 0x1234n, (1n << 16n) - 1n], dirty: 1n << 16n },
  { sol: 'uint32', base: 'u32', clean: [0n, 0xdeadn, (1n << 32n) - 1n], dirty: 1n << 32n },
  { sol: 'uint64', base: 'u64', clean: [0n, 0xfeedn, (1n << 64n) - 1n], dirty: 1n << 64n },
  { sol: 'uint128', base: 'u128', clean: [0n, 0xcafen, (1n << 128n) - 1n], dirty: 1n << 128n },
  // signed: canonical = word == signextend(low N bits). clean incl max (2^(N-1)-1), min, and a
  //   negative two's-complement value. dirty = a value whose top bits disagree with the sign bit.
  { sol: 'int8', base: 'i8', clean: [0n, 0x7fn /*max*/, M - 1n /*-1*/, M - 5n /*-5*/, M - (1n << 7n) /*min -128*/], dirty: 0x80n /*=128 unsigned, not signextended -> dirty for int8*/ },
  { sol: 'int16', base: 'i16', clean: [0n, (1n << 15n) - 1n, M - 1n, M - 0x1234n, M - (1n << 15n)], dirty: 1n << 15n },
  { sol: 'int64', base: 'i64', clean: [0n, (1n << 63n) - 1n, M - 1n, M - 0xfeedn, M - (1n << 63n)], dirty: 1n << 63n },
  { sol: 'int128', base: 'i128', clean: [0n, (1n << 127n) - 1n, M - 1n, M - 0xcafen, M - (1n << 127n)], dirty: 1n << 127n },
  // int256: every 256-bit word is canonical, so there is NO dirty form. We will skip the
  //   dirty/unread probes for it (handled specially below). clean incl max, min, -1.
  { sol: 'int256', base: 'i256', clean: [0n, (1n << 255n) - 1n, M - 1n, M - 0x12345678n, 1n << 255n /*min*/], dirty: -1n /*sentinel: none*/ },
  // bool: canonical in {0,1}. dirty = 2.
  { sol: 'bool', base: 'bool', clean: [0n, 1n], dirty: 2n },
  // address: canonical high 96 bits 0. clean incl all-FF low 160 bits. dirty = bit 160 set.
  { sol: 'address', base: 'addr', clean: [0n, BigInt('0x' + '11'.repeat(20)), (1n << 160n) - 1n], dirty: 1n << 160n },
  // bytesM: left-aligned; low (256-8M) bits must be 0. dirty = a low bit set.
  { sol: 'bytes1', base: 'b1', clean: [0n, left(1, 0xabn), left(1, 0xffn)], dirty: left(1, 0xabn) | 1n },
  { sol: 'bytes4', base: 'b4', clean: [0n, left(4, 0xdeadbeefn), left(4, 0xffffffffn)], dirty: left(4, 0xdeadbeefn) | 1n },
  { sol: 'bytes20', base: 'b20', clean: [0n, left(20, BigInt('0x' + 'aa'.repeat(20))), left(20, (1n << 160n) - 1n)], dirty: left(20, BigInt('0x' + 'aa'.repeat(20))) | 1n },
  { sol: 'bytes32', base: 'b32', clean: [BigInt('0x' + 'ab'.repeat(32)), 0n, (1n << 256n) - 1n], dirty: -1n /*sentinel: none (full word canonical)*/ },
];

// Build Solidity mirror contract from the same table (both T[5] and T[3] getters).
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AllElemTypesFixedArray {
${TYPES.map((t) => '  ' + solFn(t.base + '_5', t.sol, 5) + '\n  ' + solFn(t.base + '_3', t.sol, 3)).join('\n')}
}`;

const PANIC = '0x4e487b71' + pad(0x32n);

describe('all element types in a fixed-array param vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);

  // signature uses the canonical leaf type name, e.g. u8_5(uint8[5],uint256)
  function sig(base: string, solType: string, n: number): string {
    return `${base}_${n}(${solType}[${n}],uint256)`;
  }
  function raw(base: string, solType: string, n: number, elems: bigint[], i: bigint): string {
    if (elems.length !== n) throw new Error(`bad elem count ${elems.length} != ${n}`);
    return '0x' + sel(sig(base, solType, n)) + [...elems, i].map(pad).join('');
  }
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  // assert JETH == Solidity byte-for-byte (success + returndata).
  async function eq(label: string, data: string) {
    const { j, s } = await both(data);
    expect(j.success, `${label}: success (jeth err=${j.exceptionError}, sol err=${s.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label}: returndata (sol=${s.returnHex})`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    // Compile JETH from a temp file (so CompileError diagnostics carry a fileName).
    const f = join(tmpdir(), `AllElemTypesFixedArray_${process.pid}.jeth`);
    writeFileSync(f, JETH, 'utf8');
    const jb = compile(JETH, { fileName: 'AllElemTypesFixedArray.jeth' });
    const sb = compileSolidity(SOL, 'AllElemTypesFixedArray');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // For both array lengths (5 and 3), run the full probe battery per element type.
  for (const n of [5, 3]) {
    for (const t of TYPES) {
      describe(`${t.sol}[${n}] (${t.base}_${n})`, () => {
        // a deterministic clean filler for the "other" positions (canonical 0 is always clean).
        const fill = (over: Map<number, bigint>): bigint[] =>
          Array.from({ length: n }, (_, k) => over.get(k) ?? 0n);

        it('CLEAN in-range reads (incl type max / negatives)', async () => {
          // For each clean value, place it at index 0 and at the last index, read it back.
          for (const cv of t.clean) {
            for (const idx of [0, n - 1]) {
              const elems = fill(new Map([[idx, cv]]));
              const r = await eq(`${t.base}_${n} clean v=0x${cv.toString(16)} @${idx}`, raw(t.base, t.sol, n, elems, BigInt(idx)));
              // a successful read must return exactly the canonical ABI word.
              expect(r.j.success, 'clean read should succeed').toBe(true);
              expect(r.j.returnHex).toBe('0x' + pad(cv));
            }
          }
        });

        // int256 / bytes32 have NO non-canonical encoding (every 256-bit word is valid),
        // so there is no "dirty" input to construct. For them these two probes instead
        // assert the correct behavior: a full would-be-dirty word reads back VERBATIM and
        // never reverts (byte-identical to solc). All types run; nothing is skipped.
        const hasDirty = t.dirty >= 0n;
        // a full 256-bit word that IS dirty for narrow types but canonical for full-word ones.
        const fullWord = t.base === 'b32' ? (1n << 256n) - 1n : M - 1n;
        it('DIRTY read reverts EMPTY (or, for full-word types, reads verbatim)', async () => {
          // place the (would-be-)dirty word at index d and READ index d.
          for (const d of [0, n - 1]) {
            if (hasDirty) {
              const elems = fill(new Map([[d, t.dirty]]));
              const r = await eq(`${t.base}_${n} dirty read @${d}`, raw(t.base, t.sol, n, elems, BigInt(d)));
              expect(r.j.success, 'dirty read must revert').toBe(false);
              expect(r.j.returnHex, 'dirty read returndata must be empty').toBe('0x');
            } else {
              const elems = fill(new Map([[d, fullWord]]));
              const r = await eq(`${t.base}_${n} full-word read @${d}`, raw(t.base, t.sol, n, elems, BigInt(d)));
              expect(r.j.success, 'full-word read of a canonical-everything type must succeed').toBe(true);
              expect(r.j.returnHex).toBe('0x' + pad(fullWord));
            }
          }
        });

        it('UNREAD (would-be-)dirty element does not affect a clean read elsewhere', async () => {
          // (would-be-)dirty word at index d1, but READ a different clean index d2 -> both OK.
          const d1 = 0;
          const d2 = n - 1; // distinct because n>=3
          const other = hasDirty ? t.dirty : fullWord;
          const cleanVal = t.clean.find((v) => v !== other) ?? 0n;
          const elems = fill(new Map([[d1, other], [d2, cleanVal]]));
          const r = await eq(`${t.base}_${n} unread @${d2}`, raw(t.base, t.sol, n, elems, BigInt(d2)));
          expect(r.j.success, 'reading a clean index past a dirty/full-word one must succeed').toBe(true);
          expect(r.j.returnHex).toBe('0x' + pad(cleanVal));
        });

        it('runtime OOB index -> Panic(0x32)', async () => {
          // index == n (one past the end), and a large index, both -> Panic(0x32).
          for (const oob of [BigInt(n), BigInt(n) + 7n, 1n << 200n]) {
            const elems = fill(new Map()); // all clean zeros
            const r = await eq(`${t.base}_${n} OOB i=${oob}`, raw(t.base, t.sol, n, elems, oob));
            expect(r.j.success, 'OOB read must revert').toBe(false);
            expect(r.j.returnHex, 'OOB must be Panic(0x32)').toBe(PANIC);
          }
        });
      });
    }
  }

  // int256 / bytes32 have no non-canonical form: confirm that any 256-bit word reads back
  // verbatim (no masking, no revert) at an in-range index.
  it('int256 / bytes32: every 256-bit word is canonical (read verbatim, never reverts)', async () => {
    const probes: bigint[] = [0n, 1n, M - 1n, 1n << 255n, BigInt('0x' + 'a5'.repeat(32))];
    for (const n of [5, 3]) {
      for (const base of ['i256', 'b32']) {
        const solType = base === 'i256' ? 'int256' : 'bytes32';
        for (const p of probes) {
          for (const idx of [0, n - 1]) {
            const elems = Array.from({ length: n }, (_, k) => (k === idx ? p : 0n));
            const r = await eq(`${base}_${n} verbatim 0x${p.toString(16)} @${idx}`, raw(base, solType, n, elems, BigInt(idx)));
            expect(r.j.success).toBe(true);
            expect(r.j.returnHex).toBe('0x' + pad(p));
          }
        }
      }
    }
  });

  // Cross-check: a dirty element at a DIFFERENT position from the read index never affects
  // a clean read even when the clean read is the type max (boundary canonical value).
  it('dirty neighbour does not corrupt a clean max-value read', async () => {
    for (const t of TYPES) {
      if (t.dirty < 0n) continue;
      const maxClean = t.clean[t.clean.length - 1]!; // last entry is the max / min boundary
      const elems = [maxClean, t.dirty, 0n, 0n, 0n].slice(0, 5);
      const r = await eq(`${t.base}_5 clean-max@0 dirty@1 read@0`, raw(t.base, t.sol, 5, elems as bigint[], 0n));
      expect(r.j.success).toBe(true);
      expect(r.j.returnHex).toBe('0x' + pad(maxClean));
    }
  });
});
