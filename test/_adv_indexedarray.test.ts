// ADVERSARIAL (JETH207): indexed DYNAMIC value-element array event param.
// The indexed topic = keccak256 of the concatenated 32-byte element words (no length,
// no offset). This suite hunts for any divergence from solc on TOPICS + DATA +
// success/revert parity, across: narrow element types (u8/u16/u128/int8/int128/int256/
// bool/address/bytesN), DIRTY calldata elements (high-bit garbage), array sizes
// (empty/1/2/many/100), topic position (only/first/last/3-indexed), arrays alongside
// non-indexed dynamic data, multiple emits / emit-in-loop, a regression for the
// non-indexed value array in the data section, and confirmation that fixed-array /
// struct indexed params are still rejected by the JETH207 gate.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
// ABI dynamic-array tail: [len][e0][e1]... Each element padded as a raw 32-byte word
// (so callers can inject DIRTY high bits by passing values that exceed the narrow type).
const arr = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');
type LogEntry = { topics: string[]; data: string };
const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
  a.length === b.length &&
  a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics));

// One contract per language exercising every shape under test.
const JETH = `@contract class C {
  @event Eu(@indexed a: u256[]);
  @event E8(@indexed a: u8[]);
  @event E16(@indexed a: u16[]);
  @event E128(@indexed a: u128[]);
  @event Ei8(@indexed a: i8[]);
  @event Ei128(@indexed a: i128[]);
  @event Ei256(@indexed a: i256[]);
  @event Eb(@indexed a: bool[]);
  @event Ead(@indexed a: address[]);
  @event Eb1(@indexed a: bytes1[]);
  @event Eb4(@indexed a: bytes4[]);
  @event Eb32(@indexed a: bytes32[]);
  @event Efirst(@indexed a: u256[], v: u256);
  @event Elast(k: u256, @indexed a: u256[]);
  @event Ethree(@indexed k: u256, @indexed a: u256[], @indexed b: address[]);
  @event Emixdata(@indexed a: u256[], s: string, v: u256);
  @event Emulti(@indexed a: u256[], @indexed b: u8[]);
  @event Edata(a: u256[], v: u256);
  @external eu(a: u256[]): void { emit(Eu(a)); }
  @external e8(a: u8[]): void { emit(E8(a)); }
  @external e16(a: u16[]): void { emit(E16(a)); }
  @external e128(a: u128[]): void { emit(E128(a)); }
  @external ei8(a: i8[]): void { emit(Ei8(a)); }
  @external ei128(a: i128[]): void { emit(Ei128(a)); }
  @external ei256(a: i256[]): void { emit(Ei256(a)); }
  @external eb(a: bool[]): void { emit(Eb(a)); }
  @external ead(a: address[]): void { emit(Ead(a)); }
  @external eb1(a: bytes1[]): void { emit(Eb1(a)); }
  @external eb4(a: bytes4[]): void { emit(Eb4(a)); }
  @external eb32(a: bytes32[]): void { emit(Eb32(a)); }
  @external efirst(a: u256[], v: u256): void { emit(Efirst(a, v)); }
  @external elast(k: u256, a: u256[]): void { emit(Elast(k, a)); }
  @external ethree(k: u256, a: u256[], b: address[]): void { emit(Ethree(k, a, b)); }
  @external emixdata(a: u256[], s: string, v: u256): void { emit(Emixdata(a, s, v)); }
  @external emulti(a: u256[], b: u8[]): void { emit(Emulti(a, b)); }
  @external etwice(a: u256[], b: u256[]): void { emit(Eu(a)); emit(Eu(b)); }
  @external eloop(a: u256[]): void {
    let i: u256 = 0n;
    while (i < 3n) { emit(Eu(a)); i = i + 1n; }
  }
  @external edata(a: u256[], v: u256): void { emit(Edata(a, v)); }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  event Eu(uint256[] indexed a);
  event E8(uint8[] indexed a);
  event E16(uint16[] indexed a);
  event E128(uint128[] indexed a);
  event Ei8(int8[] indexed a);
  event Ei128(int128[] indexed a);
  event Ei256(int256[] indexed a);
  event Eb(bool[] indexed a);
  event Ead(address[] indexed a);
  event Eb1(bytes1[] indexed a);
  event Eb4(bytes4[] indexed a);
  event Eb32(bytes32[] indexed a);
  event Efirst(uint256[] indexed a, uint256 v);
  event Elast(uint256 k, uint256[] indexed a);
  event Ethree(uint256 indexed k, uint256[] indexed a, address[] indexed b);
  event Emixdata(uint256[] indexed a, string s, uint256 v);
  event Emulti(uint256[] indexed a, uint8[] indexed b);
  event Edata(uint256[] a, uint256 v);
  function eu(uint256[] calldata a) external { emit Eu(a); }
  function e8(uint8[] calldata a) external { emit E8(a); }
  function e16(uint16[] calldata a) external { emit E16(a); }
  function e128(uint128[] calldata a) external { emit E128(a); }
  function ei8(int8[] calldata a) external { emit Ei8(a); }
  function ei128(int128[] calldata a) external { emit Ei128(a); }
  function ei256(int256[] calldata a) external { emit Ei256(a); }
  function eb(bool[] calldata a) external { emit Eb(a); }
  function ead(address[] calldata a) external { emit Ead(a); }
  function eb1(bytes1[] calldata a) external { emit Eb1(a); }
  function eb4(bytes4[] calldata a) external { emit Eb4(a); }
  function eb32(bytes32[] calldata a) external { emit Eb32(a); }
  function efirst(uint256[] calldata a, uint256 v) external { emit Efirst(a, v); }
  function elast(uint256 k, uint256[] calldata a) external { emit Elast(k, a); }
  function ethree(uint256 k, uint256[] calldata a, address[] calldata b) external { emit Ethree(k, a, b); }
  function emixdata(uint256[] calldata a, string calldata s, uint256 v) external { emit Emixdata(a, s, v); }
  function emulti(uint256[] calldata a, uint8[] calldata b) external { emit Emulti(a, b); }
  function etwice(uint256[] calldata a, uint256[] calldata b) external { emit Eu(a); emit Eu(b); }
  function eloop(uint256[] calldata a) external {
    for (uint256 i = 0; i < 3; i++) { emit Eu(a); }
  }
  function edata(uint256[] calldata a, uint256 v) external { emit Edata(a, v); }
}`;

const encStr = (s: string) => {
  const hex = Buffer.from(s, 'utf8').toString('hex');
  return pad(BigInt(hex.length / 2)) + hex.padEnd(Math.ceil(hex.length / 64) * 64 || 0, '0');
};

describe('ADVERSARIAL indexed value-array event topic (JETH207) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  let cases = 0;
  async function eq(label: string, data: string) {
    cases++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError}, sol err=${s.exceptionError})`).toBe(s.success);
    expect(
      eqLogs(j.logs as LogEntry[], s.logs as LogEntry[]),
      `${label} logs\n jeth=${JSON.stringify(j.logs)}\n sol =${JSON.stringify(s.logs)}`,
    ).toBe(true);
  }
  // For an indexed value-element array with DIRTY narrow calldata elements (high garbage
  // bits), solc VALIDATES every element when it ABI-decodes the calldata array for the hash
  // and REVERTS. JETH now matches (the @event/@error materialization forces validation via
  // echoParam(forceValidate=true)): both revert on dirty input. (Was a miscompile where JETH
  // cleaned + emitted; fixed.)
  async function divergesSolReverts(label: string, data: string) {
    cases++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(s.success, `${label}: expected solc to REVERT on dirty element`).toBe(false);
    expect(j.success, `${label}: JETH must also REVERT (parity)`).toBe(s.success);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // ---- 1. narrow element types: clean values -----------------------------
  it('u256[] sizes: empty / 1 / 2 / many / 100', async () => {
    const big = Array.from({ length: 100 }, (_, i) => BigInt(i) * 7n + 1n);
    for (const xs of [
      [],
      [0n],
      [M - 1n],
      [1n, 2n],
      [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n],
      big,
    ] as bigint[][]) {
      await eq(`eu([${xs.length}])`, '0x' + sel('eu(uint256[])') + pad(0x20n) + arr(xs));
    }
  });

  it('narrow uint element types (clean): u8 / u16 / u128', async () => {
    for (const xs of [[], [0n], [255n], [1n, 255n, 128n, 0n]] as bigint[][])
      await eq(`e8([${xs}])`, '0x' + sel('e8(uint8[])') + pad(0x20n) + arr(xs));
    for (const xs of [[], [0n], [65535n], [1n, 65535n, 256n]] as bigint[][])
      await eq(`e16([${xs}])`, '0x' + sel('e16(uint16[])') + pad(0x20n) + arr(xs));
    for (const xs of [[], [0n], [(1n << 128n) - 1n], [1n, (1n << 128n) - 1n]] as bigint[][])
      await eq(`e128([${xs}])`, '0x' + sel('e128(uint128[])') + pad(0x20n) + arr(xs));
  });

  it('signed element types (clean, incl. negatives): int8 / int128 / int256', async () => {
    for (const xs of [[], [0n], [127n], [-1n], [-128n], [127n, -128n, -1n, 5n]] as bigint[][])
      await eq(`ei8([${xs}])`, '0x' + sel('ei8(int8[])') + pad(0x20n) + arr(xs));
    for (const xs of [[], [-1n], [(1n << 127n) - 1n], [-(1n << 127n)]] as bigint[][])
      await eq(`ei128([${xs}])`, '0x' + sel('ei128(int128[])') + pad(0x20n) + arr(xs));
    for (const xs of [[], [-1n], [(1n << 255n) - 1n], [-(1n << 255n)]] as bigint[][])
      await eq(`ei256([${xs}])`, '0x' + sel('ei256(int256[])') + pad(0x20n) + arr(xs));
  });

  it('bool[] / address[] / bytesN[] (clean)', async () => {
    for (const xs of [[], [0n], [1n], [1n, 0n, 1n, 1n]] as bigint[][])
      await eq(`eb([${xs}])`, '0x' + sel('eb(bool[])') + pad(0x20n) + arr(xs));
    for (const xs of [[], [0xa1n], [0xa1n, 0xb2n, 0xc3n], [(1n << 160n) - 1n]] as bigint[][])
      await eq(`ead([${xs}])`, '0x' + sel('ead(address[])') + pad(0x20n) + arr(xs));
    // bytesN are LEFT-aligned: word = value << (32-size)*8.
    const b1 = (v: bigint) => v << (31n * 8n);
    const b4 = (v: bigint) => v << (28n * 8n);
    for (const xs of [[], [b1(0xffn)], [b1(0x00n), b1(0x12n)]] as bigint[][])
      await eq(`eb1([${xs}])`, '0x' + sel('eb1(bytes1[])') + pad(0x20n) + arr(xs));
    for (const xs of [[], [b4(0xdeadbeefn)], [b4(0x0n), b4(0x11223344n)]] as bigint[][])
      await eq(`eb4([${xs}])`, '0x' + sel('eb4(bytes4[])') + pad(0x20n) + arr(xs));
    for (const xs of [[], [0n], [M - 1n], [0x1234n, M - 5n]] as bigint[][])
      await eq(`eb32([${xs}])`, '0x' + sel('eb32(bytes32[])') + pad(0x20n) + arr(xs));
  });

  // ---- 2. DIRTY calldata elements (THE BUG) ------------------------------
  // Pass words with garbage bits in narrow elements. EMPIRICAL TRUTH: solc validates
  // EVERY element of a calldata value-element array when it ABI-decodes the array (for
  // the indexed-topic hash here) and REVERTS on any dirty bits, for u<256, i<256, bool,
  // address, and bytes<32. JETH instead MASKS/CLEANS the element and emits a topic
  // (success). => a success/revert MISCOMPILE plus, where solc reverts, no topic at all.
  // Root cause: lowerEmit's indexed-array branch (yul.ts ~1075) -> materializeArrayArg ->
  // echoParam, where `topClean` (yul.ts ~3051) feeds validate=false into abiEncFromCd, so
  // every dirty leaf is cleaned via cleanCalldataElem instead of validated via
  // validateInput. These tests assert the CURRENT divergent behavior (see divergesSolReverts).
  const DIRTY = M - 1n; // all 256 bits set
  it('MISCOMPILE: DIRTY u8[] elements -> solc reverts, JETH emits', async () => {
    for (const xs of [[DIRTY], [0x1ffn], [255n, 0x100n], [DIRTY, 0n, 0x3ffn]] as bigint[][])
      await divergesSolReverts(
        `e8 dirty [${xs.map((x) => x.toString(16))}]`,
        '0x' + sel('e8(uint8[])') + pad(0x20n) + arr(xs),
      );
  });
  it('MISCOMPILE: DIRTY u16[] / u128[] elements', async () => {
    for (const xs of [[DIRTY], [0x1ffffn], [65535n, 0x10000n]] as bigint[][])
      await divergesSolReverts(`e16 dirty`, '0x' + sel('e16(uint16[])') + pad(0x20n) + arr(xs));
    for (const xs of [[DIRTY], [1n << 128n], [(1n << 128n) - 1n, 1n << 200n]] as bigint[][])
      await divergesSolReverts(`e128 dirty`, '0x' + sel('e128(uint128[])') + pad(0x20n) + arr(xs));
  });
  it('MISCOMPILE: DIRTY int8[] / int128[] elements (bad sign-extension)', async () => {
    // 0x...0080 raw is +128, not a valid int8 sign-extension of -128 (which is 0xff..80).
    // 0xff..ff is -1 (well-formed) and is NOT dirty, so it is excluded here.
    for (const xs of [[0x80n], [0x17fn], [0xff00n]] as bigint[][])
      await divergesSolReverts(
        `ei8 dirty [${xs.map((x) => x.toString(16))}]`,
        '0x' + sel('ei8(int8[])') + pad(0x20n) + arr(xs),
      );
    for (const xs of [[1n << 127n], [1n << 128n]] as bigint[][])
      await divergesSolReverts(`ei128 dirty`, '0x' + sel('ei128(int128[])') + pad(0x20n) + arr(xs));
  });
  it('MISCOMPILE: DIRTY bool[] elements (only 0/1 valid)', async () => {
    for (const xs of [[2n], [DIRTY], [1n, 2n], [0n, 0xffn]] as bigint[][])
      await divergesSolReverts(
        `eb dirty [${xs.map((x) => x.toString(16))}]`,
        '0x' + sel('eb(bool[])') + pad(0x20n) + arr(xs),
      );
  });
  it('MISCOMPILE: DIRTY address[] elements (high 96 bits garbage)', async () => {
    for (const xs of [[DIRTY], [1n << 160n], [0xa1n, (1n << 200n) | 0xb2n]] as bigint[][])
      await divergesSolReverts(`ead dirty`, '0x' + sel('ead(address[])') + pad(0x20n) + arr(xs));
  });
  it('MISCOMPILE: DIRTY bytes1[] / bytes4[] elements (dirty low bytes)', async () => {
    // bytesN<32 is left-aligned; any nonzero low (32-N) bytes are dirty and solc reverts.
    for (const xs of [[DIRTY], [(0xabn << 248n) | 1n]] as bigint[][])
      await divergesSolReverts(`eb1 dirty`, '0x' + sel('eb1(bytes1[])') + pad(0x20n) + arr(xs));
    for (const xs of [[DIRTY], [(0xdeadbeefn << 224n) | 1n]] as bigint[][])
      await divergesSolReverts(`eb4 dirty`, '0x' + sel('eb4(bytes4[])') + pad(0x20n) + arr(xs));
  });

  // ---- 3. topic position --------------------------------------------------
  it('array topic FIRST (with trailing non-indexed value)', async () => {
    for (const xs of [[], [9n], [1n, 2n, 3n]] as bigint[][])
      await eq(`efirst([${xs.length}])`, '0x' + sel('efirst(uint256[],uint256)') + pad(0x40n) + pad(7n) + arr(xs));
  });
  it('array topic LAST (after a non-indexed value)', async () => {
    for (const xs of [[], [9n], [1n, 2n, 3n]] as bigint[][])
      await eq(`elast([${xs.length}])`, '0x' + sel('elast(uint256,uint256[])') + pad(42n) + pad(0x40n) + arr(xs));
  });
  it('THREE indexed topics: uint, uint256[], address[]', async () => {
    // head: k, offset(a), offset(b). a tail then b tail.
    for (const [a, b] of [
      [[], []],
      [[1n], [0xa1n]],
      [
        [1n, 2n, 3n],
        [0xa1n, 0xb2n],
      ],
    ] as [bigint[], bigint[]][]) {
      const headWords = 3;
      const offA = headWords * 32;
      const aTail = arr(a);
      const offB = offA + aTail.length / 2;
      const data =
        '0x' +
        sel('ethree(uint256,uint256[],address[])') +
        pad(5n) +
        pad(BigInt(offA)) +
        pad(BigInt(offB)) +
        aTail +
        arr(b);
      await eq(`ethree(a=${a.length},b=${b.length})`, data);
    }
  });
  it('multiple indexed arrays in one event: u256[] + u8[]', async () => {
    for (const [a, b] of [
      [[], []],
      [[7n], [255n]],
      [
        [1n, 2n],
        [1n, 0n, 9n],
      ],
    ] as [bigint[], bigint[]][]) {
      const offA = 2 * 32;
      const aTail = arr(a);
      const offB = offA + aTail.length / 2;
      const data = '0x' + sel('emulti(uint256[],uint8[])') + pad(BigInt(offA)) + pad(BigInt(offB)) + aTail + arr(b);
      await eq(`emulti(a=${a.length},b=${b.length})`, data);
    }
  });

  // ---- 4. indexed array + non-indexed dynamic DATA together --------------
  it('indexed u256[] topic alongside non-indexed string + value in data', async () => {
    const strs = ['', 'hi', 'this string is longer than thirty-two bytes for the data section test!!'];
    for (const xs of [[], [1n, 2n, 3n]] as bigint[][]) {
      for (const s of strs) {
        // head: offset(a-topic placeholder? NO — a is indexed so it is NOT in the data tuple).
        // Solidity calldata for emixdata(uint256[] a, string s, uint256 v): a, s are dynamic.
        // calldata layout (selector then): offset(a), offset(s), v.
        const offA = 3 * 32;
        const aTail = arr(xs);
        const offS = offA + aTail.length / 2;
        const data =
          '0x' +
          sel('emixdata(uint256[],string,uint256)') +
          pad(BigInt(offA)) +
          pad(BigInt(offS)) +
          pad(123n) +
          aTail +
          encStr(s);
        await eq(`emixdata(a=${xs.length},s="${s.slice(0, 6)}")`, data);
      }
    }
  });

  // ---- 5. multiple emits / loop ------------------------------------------
  it('two emits in one call (different arrays)', async () => {
    const a = [1n, 2n],
      b = [9n, 8n, 7n];
    const offA = 2 * 32;
    const aTail = arr(a);
    const offB = offA + aTail.length / 2;
    const data = '0x' + sel('etwice(uint256[],uint256[])') + pad(BigInt(offA)) + pad(BigInt(offB)) + aTail + arr(b);
    await eq('etwice', data);
  });
  it('emit in a loop (3x same array)', async () => {
    for (const xs of [[], [5n, 6n]] as bigint[][])
      await eq(`eloop([${xs.length}])`, '0x' + sel('eloop(uint256[])') + pad(0x20n) + arr(xs));
  });

  // ---- 6. regression: NON-indexed value array in DATA section ------------
  it('regression: non-indexed u256[] goes in the data section correctly', async () => {
    for (const xs of [[], [1n], [1n, 2n, 3n, 4n]] as bigint[][])
      await eq(`edata([${xs.length}])`, '0x' + sel('edata(uint256[],uint256)') + pad(0x40n) + pad(77n) + arr(xs));
  });

  // ---- 7. an indexed STATIC fixed-array / struct param is now SUPPORTED (keccak topic) -----
  it('fixed-array indexed event param now compiles (keccak topic, JETH207 lifted)', () => {
    expect(() =>
      compile(`@contract class C { @event E(@indexed a: Arr<u256, 3>); @external f(): void {} }`, {
        fileName: 'C.jeth',
      }),
    ).not.toThrow();
  });
  it('struct indexed event param now compiles (keccak topic, JETH207 lifted)', () => {
    const src = `@struct class S { x: u256; }
@contract class C { @event E(@indexed s: S); @external f(): void {} }`;
    expect(() => compile(src, { fileName: 'C.jeth' })).not.toThrow();
    // a supported DYNAMIC struct (value + bytes/string + dyn value-array fields) indexed param now
    // compiles too (topic = keccak of the flattened payload; verified byte-identical in
    // fix-all-divergences.test.ts).
    const dyn = `@struct class D { s: string; }
@contract class C { @event E(@indexed d: D); @external f(): void {} }`;
    expect(() => compile(dyn, { fileName: 'C.jeth' })).not.toThrow();
    // a dynamic struct with a NESTED dynamic struct field is now supported too (topic = keccak of the
    // recursively flattened payload; byte-identical to solc, verified in fix-all-divergences.test.ts).
    const nested = `@struct class Inner { p: u256; s: string; }
@struct class D2 { x: u256; inner: Inner; }
@contract class C { @event E(@indexed d: D2); @external f(): void {} }`;
    expect(() => compile(nested, { fileName: 'C.jeth' })).not.toThrow();
  });
  it('nested dynamic array (u256[][]) indexed event param is now ACCEPTED (packed-padded topic)', () => {
    // Previously a sound reject; the packed-padded topic codec lifts it byte-identical to solc
    // (verified on the harness in event-dynamic-aggregate-params.test.ts).
    let threw = false;
    try {
      compile(`@contract class C { @event E(@indexed a: u256[][]); @external f(): void {} }`, { fileName: 'C.jeth' });
    } catch (e: any) {
      threw = true;
    }
    expect(threw, 'u256[][] indexed param is now accepted').toBe(false);
  });

  it('reports total case count', () => {
    // eslint-disable-next-line no-console
    console.log(`\n[adv-indexedarray] differential cases compared vs solc: ${cases}`);
    expect(cases).toBeGreaterThan(60);
  });
});
