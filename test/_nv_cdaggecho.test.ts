import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const w = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
// build calldata: selector + flat inline words. `extra` lets us append/omit raw hex.
const call = (sig: string, words: bigint[], extra = '') => '0x' + sel(sig) + words.map(w).join('') + extra;
// left-aligned bytesN word from a bigint of the low bytes (n bytes)
const bytesNword = (loBytes: bigint, n: number) => ((loBytes % (1n << BigInt(8 * n))) << BigInt(8 * (32 - n))) % M;

const JETH = `type P = { a: u256; b: u8; c: address; };
type Mixed = { a: u128; b: u64; c: bool; d: address; e: bytes8; f: i40; };
type WithArr = { id: u64; data: Arr<u256, 3>; tag: bytes4; };
class C {
  // nested value fixed-arrays (leaves clean/maskable by solc)
  get echo2(a: Arr<Arr<u256, 2>, 2>): External<Arr<Arr<u256, 2>, 2>> { return a; }
  get echo3(a: Arr<Arr<Arr<u256, 2>, 2>, 2>): External<Arr<Arr<Arr<u256, 2>, 2>, 2>> { return a; }
  get echo4(a: Arr<Arr<Arr<Arr<u256, 2>, 2>, 2>, 2>): External<Arr<Arr<Arr<Arr<u256, 2>, 2>, 2>, 2>> { return a; }
  // packed narrow value arrays (solc CLEANS dirty high bits -> succeeds)
  get echoU8(a: Arr<Arr<u8, 4>, 3>): External<Arr<Arr<u8, 4>, 3>> { return a; }
  get echoI64(a: Arr<i64, 5>): External<Arr<i64, 5>> { return a; }
  get echoB4(a: Arr<bytes4, 3>): External<Arr<bytes4, 3>> { return a; }
  get echoBool(a: Arr<bool, 8>): External<Arr<bool, 8>> { return a; }
  get echoU16(a: Arr<u16, 4>): External<Arr<u16, 4>> { return a; }
  get echoAddr(a: Arr<address, 3>): External<Arr<address, 3>> { return a; }
  get echoI8(a: Arr<i8, 4>): External<Arr<i8, 4>> { return a; }
  // structs (solc VALIDATES narrow fields -> dirty reverts)
  get echoStruct(p: P): External<P> { return p; }
  get echoMixed(p: Mixed): External<Mixed> { return p; }
  get echoStructArr(a: Arr<P, 2>): External<Arr<P, 2>> { return a; }
  get echoMixedArr(a: Arr<Mixed, 2>): External<Arr<Mixed, 2>> { return a; }
  // struct with a fixed-array field
  get echoWithArr(p: WithArr): External<WithArr> { return p; }
  get echoWithArrArr(a: Arr<WithArr, 2>): External<Arr<WithArr, 2>> { return a; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; address c; }
  struct Mixed { uint128 a; uint64 b; bool c; address d; bytes8 e; int40 f; }
  struct WithArr { uint64 id; uint256[3] data; bytes4 tag; }
  function echo2(uint256[2][2] calldata a) external pure returns (uint256[2][2] memory){ return a; }
  function echo3(uint256[2][2][2] calldata a) external pure returns (uint256[2][2][2] memory){ return a; }
  function echo4(uint256[2][2][2][2] calldata a) external pure returns (uint256[2][2][2][2] memory){ return a; }
  function echoU8(uint8[4][3] calldata a) external pure returns (uint8[4][3] memory){ return a; }
  function echoI64(int64[5] calldata a) external pure returns (int64[5] memory){ return a; }
  function echoB4(bytes4[3] calldata a) external pure returns (bytes4[3] memory){ return a; }
  function echoBool(bool[8] calldata a) external pure returns (bool[8] memory){ return a; }
  function echoU16(uint16[4] calldata a) external pure returns (uint16[4] memory){ return a; }
  function echoAddr(address[3] calldata a) external pure returns (address[3] memory){ return a; }
  function echoI8(int8[4] calldata a) external pure returns (int8[4] memory){ return a; }
  function echoStruct(P calldata p) external pure returns (P memory){ return p; }
  function echoMixed(Mixed calldata p) external pure returns (Mixed memory){ return p; }
  function echoStructArr(P[2] calldata a) external pure returns (P[2] memory){ return a; }
  function echoMixedArr(Mixed[2] calldata a) external pure returns (Mixed[2] memory){ return a; }
  function echoWithArr(WithArr calldata p) external pure returns (WithArr memory){ return p; }
  function echoWithArrArr(WithArr[2] calldata a) external pure returns (WithArr[2] memory){ return a; }
}`;

describe('probe', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(
        label +
          ': jeth{ok=' +
          j.success +
          ',ret=' +
          j.returnHex +
          ',err=' +
          j.exceptionError +
          '} sol{ok=' +
          s.success +
          ',ret=' +
          s.returnHex +
          '}',
      );
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('runs', async () => {
    const MAX = M - 1n;
    const DIRTY = (1n << 255n) | (1n << 200n) | 0xabn; // arbitrary high+low

    // ---- nested value fixed-arrays: clean ----
    await eq('echo2 clean', call('echo2(uint256[2][2])', [1n, 2n, 3n, 4n]));
    await eq('echo2 zeros', call('echo2(uint256[2][2])', [0n, 0n, 0n, 0n]));
    await eq('echo2 max', call('echo2(uint256[2][2])', [MAX, MAX, MAX, MAX]));
    await eq('echo3 clean', call('echo3(uint256[2][2][2])', [10n, 11n, 12n, 13n, 20n, 21n, 22n, 23n]));
    await eq('echo3 max/zero', call('echo3(uint256[2][2][2])', [MAX, 0n, MAX, 0n, 0n, MAX, 0n, MAX]));
    await eq(
      'echo4 clean',
      call(
        'echo4(uint256[2][2][2][2])',
        Array.from({ length: 16 }, (_, i) => BigInt(i) + 100n),
      ),
    );
    await eq(
      'echo4 dirty(noop,u256 no mask)',
      call(
        'echo4(uint256[2][2][2][2])',
        Array.from({ length: 16 }, () => DIRTY),
      ),
    );

    // ---- packed narrow value arrays: CLEAN values ----
    const u8clean = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n];
    await eq('echoU8 clean', call('echoU8(uint8[4][3])', u8clean));
    await eq(
      'echoU8 maxbyte',
      call(
        'echoU8(uint8[4][3])',
        u8clean.map(() => 0xffn),
      ),
    );
    await eq('echoI64 clean', call('echoI64(int64[5])', [0n, 1n, 2n, 3n, 4n]));
    await eq(
      'echoI64 neg',
      call(
        'echoI64(int64[5])',
        [-1n, -2n, (1n << 63n) - 1n, -(1n << 63n), 0n].map((x) => ((x % M) + M) % M),
      ),
    );
    await eq(
      'echoB4 clean',
      call('echoB4(bytes4[3])', [bytesNword(0x11223344n, 4), bytesNword(0xaabbccddn, 4), bytesNword(0xdeadbeefn, 4)]),
    );
    await eq('echoBool clean', call('echoBool(bool[8])', [1n, 0n, 1n, 0n, 1n, 1n, 0n, 0n]));
    await eq('echoU16 clean', call('echoU16(uint16[4])', [0n, 0xffffn, 0x1234n, 0x8000n]));
    await eq('echoAddr clean', call('echoAddr(address[3])', [0x1234n, BigInt('0x' + 'aa'.repeat(20)), 0n]));
    await eq('echoI8 clean', call('echoI8(int8[4])', [0n, 0x7fn, ((-1n % M) + M) % M, ((-128n % M) + M) % M]));

    // ---- packed narrow value arrays: DIRTY high bits (solc MASKS -> success, cleaned return) ----
    // u8[4][3]: dirty each leaf in turn
    for (let i = 0; i < 12; i++) {
      const d = [...u8clean];
      d[i] = (DIRTY << 8n) | 0x42n; // high bits set, low byte 0x42
      await eq('echoU8 dirty[' + i + ']', call('echoU8(uint8[4][3])', d));
    }
    await eq(
      'echoU8 all-dirty',
      call(
        'echoU8(uint8[4][3])',
        u8clean.map((_, i) => (MAX << 8n) | BigInt(i)),
      ),
    );
    // i64[5]: dirty high bits above bit 63 -> solc masks/signextends from bit 63
    for (let i = 0; i < 5; i++) {
      const base = [0n, 1n, 2n, 3n, 4n];
      const d = base.map((x) => ((x % M) + M) % M);
      d[i] = (DIRTY << 64n) | 0x55n; // dirty above 64 bits, low value 0x55 (positive sign bit clear)
      await eq('echoI64 dirty+[' + i + ']', call('echoI64(int64[5])', d));
      const d2 = base.map((x) => ((x % M) + M) % M);
      d2[i] = (DIRTY << 64n) | ((1n << 63n) | 0x7n); // sign bit set within 64 -> negative
      await eq('echoI64 dirty-[' + i + ']', call('echoI64(int64[5])', d2));
    }
    // bytes4[3]: dirty LOW bits (solc cleans the right-side bytes -> success, masked)
    for (let i = 0; i < 3; i++) {
      const d = [bytesNword(0x11223344n, 4), bytesNword(0xaabbccddn, 4), bytesNword(0xdeadbeefn, 4)];
      d[i] = bytesNword(0x11223344n, 4) | 0xffffffffffffffn; // dirty low 7 bytes
      await eq('echoB4 dirtylow[' + i + ']', call('echoB4(bytes4[3])', d));
    }
    // bool[8]: dirty (non 0/1) -> solc bool value arrays mask to 0/1? Actually solc bool in
    // value array CLEANS via iszero(iszero(x)). Compare directly.
    for (let i = 0; i < 8; i++) {
      const d = [1n, 0n, 1n, 0n, 1n, 1n, 0n, 0n];
      d[i] = (DIRTY << 1n) | 1n; // odd high-dirty
      await eq('echoBool dirtyodd[' + i + ']', call('echoBool(bool[8])', d));
      const d2 = [1n, 0n, 1n, 0n, 1n, 1n, 0n, 0n];
      d2[i] = DIRTY << 1n; // even high-dirty (low bit 0)
      await eq('echoBool dirtyeven[' + i + ']', call('echoBool(bool[8])', d2));
      const d3 = [1n, 0n, 1n, 0n, 1n, 1n, 0n, 0n];
      d3[i] = 2n; // exactly 2 -> non-canonical bool
      await eq('echoBool two[' + i + ']', call('echoBool(bool[8])', d3));
    }
    // u16[4]: dirty high
    for (let i = 0; i < 4; i++) {
      const d = [0n, 0xffffn, 0x1234n, 0x8000n];
      d[i] = (DIRTY << 16n) | 0x9999n;
      await eq('echoU16 dirty[' + i + ']', call('echoU16(uint16[4])', d));
    }
    // address[3]: dirty above 160 bits
    for (let i = 0; i < 3; i++) {
      const d = [0x1234n, BigInt('0x' + 'aa'.repeat(20)), 0n];
      d[i] = (DIRTY << 160n) | BigInt('0x' + 'cc'.repeat(20));
      await eq('echoAddr dirty[' + i + ']', call('echoAddr(address[3])', d));
    }
    // i8[4]: dirty above 8 bits
    for (let i = 0; i < 4; i++) {
      const d = [0n, 0x7fn, ((-1n % M) + M) % M, ((-128n % M) + M) % M];
      d[i] = (DIRTY << 8n) | 0x80n; // negative within 8 bits
      await eq('echoI8 dirty[' + i + ']', call('echoI8(int8[4])', d));
    }

    // ---- structs: CLEAN ----
    await eq('echoStruct clean', call('echoStruct((uint256,uint8,address))', [42n, 7n, 0x1234n]));
    await eq('echoStruct zeros', call('echoStruct((uint256,uint8,address))', [0n, 0n, 0n]));
    await eq(
      'echoStruct max-ok',
      call('echoStruct((uint256,uint8,address))', [MAX, 0xffn, BigInt('0x' + 'ff'.repeat(20))]),
    );
    await eq(
      'echoStructArr clean',
      call('echoStructArr((uint256,uint8,address)[2])', [1n, 2n, 0xaaaan, 3n, 4n, 0xbbbbn]),
    );

    // Mixed { u128 a; u64 b; bool c; address d; bytes8 e; i40 f; }
    const mixedClean = [
      0x1122n, // a u128
      0x33n, // b u64
      1n, // c bool
      BigInt('0x' + 'a1'.repeat(20)), // d address
      bytesNword(0xdeadbeefcafef00dn, 8), // e bytes8 (left aligned)
      0x1234n, // f i40 (positive)
    ];
    await eq('echoMixed clean', call('echoMixed((uint128,uint64,bool,address,bytes8,int40))', mixedClean));
    const mixedNeg = [...mixedClean];
    mixedNeg[5] = ((-5n % M) + M) % M; // i40 negative (sign-extended to 256)
    await eq('echoMixed negF', call('echoMixed((uint128,uint64,bool,address,bytes8,int40))', mixedNeg));
    const mixedMax = [
      (1n << 128n) - 1n,
      (1n << 64n) - 1n,
      1n,
      BigInt('0x' + 'ff'.repeat(20)),
      bytesNword((1n << 64n) - 1n, 8),
      (1n << 39n) - 1n,
    ];
    await eq('echoMixed maxF', call('echoMixed((uint128,uint64,bool,address,bytes8,int40))', mixedMax));
    const mixedMinI40 = [...mixedClean];
    mixedMinI40[5] = ((-(1n << 39n) % M) + M) % M;
    await eq('echoMixed minI40', call('echoMixed((uint128,uint64,bool,address,bytes8,int40))', mixedMinI40));
    await eq(
      'echoMixedArr clean',
      call('echoMixedArr((uint128,uint64,bool,address,bytes8,int40)[2])', [...mixedClean, ...mixedNeg]),
    );

    // ---- structs: DIRTY field high bits -> solc VALIDATES -> REVERT (jeth must match) ----
    // P.b (uint8) dirty
    await eq('echoStruct dirty b', call('echoStruct((uint256,uint8,address))', [42n, (1n << 9n) | 7n, 0x1234n]));
    await eq(
      'echoStruct dirty b high',
      call('echoStruct((uint256,uint8,address))', [42n, (DIRTY << 8n) | 7n, 0x1234n]),
    );
    // P.c (address) dirty above 160
    await eq('echoStruct dirty c', call('echoStruct((uint256,uint8,address))', [42n, 7n, (1n << 200n) | 0x1234n]));
    await eq('echoStruct dirty c top', call('echoStruct((uint256,uint8,address))', [42n, 7n, (1n << 255n) | 0x1234n]));
    // P.a (u256) cannot be dirty - full width; sanity that it still succeeds
    await eq('echoStruct a=max', call('echoStruct((uint256,uint8,address))', [MAX, 7n, 0x1234n]));

    // Mixed field-by-field dirty
    const dirtyField = (idx: number, sig: string, base: bigint[], dval: bigint, label: string) => {
      const d = [...base];
      d[idx] = dval;
      return eq(label, call(sig, d));
    };
    const MSIG = '((uint128,uint64,bool,address,bytes8,int40))';
    const MARR = '((uint128,uint64,bool,address,bytes8,int40)[2])';
    await dirtyField(0, 'echoMixed' + MSIG, mixedClean, (1n << 128n) | 0x1122n, 'echoMixed dirty a(u128)');
    await dirtyField(1, 'echoMixed' + MSIG, mixedClean, (1n << 64n) | 0x33n, 'echoMixed dirty b(u64)');
    await dirtyField(2, 'echoMixed' + MSIG, mixedClean, 2n, 'echoMixed dirty c(bool=2)');
    await dirtyField(2, 'echoMixed' + MSIG, mixedClean, DIRTY, 'echoMixed dirty c(bool=high)');
    await dirtyField(
      3,
      'echoMixed' + MSIG,
      mixedClean,
      (1n << 160n) | BigInt('0x' + 'a1'.repeat(20)),
      'echoMixed dirty d(addr)',
    );
    await dirtyField(
      4,
      'echoMixed' + MSIG,
      mixedClean,
      bytesNword(0xdeadbeefcafef00dn, 8) | 0xffn,
      'echoMixed dirty e(bytes8 low)',
    );
    await dirtyField(5, 'echoMixed' + MSIG, mixedClean, (1n << 40n) | 0x1234n, 'echoMixed dirty f(i40 above40)');
    // i40 sign-extension validity: a value that is NOT a clean sign-extension of 40 bits
    await dirtyField(5, 'echoMixed' + MSIG, mixedClean, (1n << 39n) | 0x1n, 'echoMixed f(i40 signbit, no ext) bad');
    await dirtyField(
      5,
      'echoMixed' + MSIG,
      mixedClean,
      (MAX ^ ((1n << 39n) - 1n)) | (1n << 39n),
      'echoMixed f(i40 neg properly ext)',
    );

    // struct array dirty element field
    await eq(
      'echoStructArr dirty[1].b',
      call('echoStructArr((uint256,uint8,address)[2])', [1n, 2n, 0xaaaan, 3n, (1n << 8n) | 4n, 0xbbbbn]),
    );
    await eq(
      'echoStructArr dirty[0].c',
      call('echoStructArr((uint256,uint8,address)[2])', [1n, 2n, (1n << 161n) | 0xaaaan, 3n, 4n, 0xbbbbn]),
    );

    // ---- struct with fixed-array field: WithArr { u64 id; u256[3] data; bytes4 tag; } ----
    const waClean = [0x99n, 0x11n, 0x22n, 0x33n, bytesNword(0xcafebaben, 4)];
    await eq('echoWithArr clean', call('echoWithArr((uint64,uint256[3],bytes4))', waClean));
    await eq(
      'echoWithArrArr clean',
      call('echoWithArrArr((uint64,uint256[3],bytes4)[2])', [
        ...waClean,
        0xaan,
        0xbbn,
        0xccn,
        0xddn,
        bytesNword(0xdeadn, 4),
      ]),
    );
    // dirty id(u64) field -> validates -> revert
    await eq(
      'echoWithArr dirty id',
      call('echoWithArr((uint64,uint256[3],bytes4))', [
        (1n << 64n) | 0x99n,
        0x11n,
        0x22n,
        0x33n,
        bytesNword(0xcafebaben, 4),
      ]),
    );
    // dirty bytes4 tag low bytes -> validates -> revert
    await eq(
      'echoWithArr dirty tag',
      call('echoWithArr((uint64,uint256[3],bytes4))', [0x99n, 0x11n, 0x22n, 0x33n, bytesNword(0xcafebaben, 4) | 0x1n]),
    );
    // data leaves are u256 -> full width, can't be dirty; sanity max
    await eq(
      'echoWithArr data=max',
      call('echoWithArr((uint64,uint256[3],bytes4))', [0x99n, MAX, MAX, MAX, bytesNword(0xcafebaben, 4)]),
    );

    // ---- TRUNCATED calldata: too few words -> must revert like solc ----
    await eq('echo2 trunc(3w)', call('echo2(uint256[2][2])', [1n, 2n, 3n]));
    await eq('echo2 trunc(0w)', call('echo2(uint256[2][2])', []));
    await eq('echo3 trunc(7w)', call('echo3(uint256[2][2][2])', [1n, 2n, 3n, 4n, 5n, 6n, 7n]));
    await eq('echoU8 trunc(11w)', call('echoU8(uint8[4][3])', u8clean.slice(0, 11)));
    await eq('echoStruct trunc(2w)', call('echoStruct((uint256,uint8,address))', [42n, 7n]));
    await eq(
      'echoMixed trunc(5w)',
      call('echoMixed((uint128,uint64,bool,address,bytes8,int40))', mixedClean.slice(0, 5)),
    );
    await eq('echoWithArr trunc(4w)', call('echoWithArr((uint64,uint256[3],bytes4))', waClean.slice(0, 4)));
    await eq('echoStructArr trunc(5w)', call('echoStructArr((uint256,uint8,address)[2])', [1n, 2n, 0xaaaan, 3n, 4n]));
    // truncated mid-word (not a multiple of 32) -> solc zero-pads tail; compare
    await eq('echo2 trunc(half word)', call('echo2(uint256[2][2])', [1n, 2n, 3n], 'abcdef'));
    await eq('echoStruct trunc(half last)', call('echoStruct((uint256,uint8,address))', [42n, 7n], 'ff'));

    // ---- TRAILING extra calldata: solc ignores -> echo unchanged ----
    await eq('echo2 trailing', call('echo2(uint256[2][2])', [1n, 2n, 3n, 4n], '00'.repeat(32) + 'ff'.repeat(8)));
    await eq('echoStruct trailing', call('echoStruct((uint256,uint8,address))', [42n, 7n, 0x1234n], 'de'.repeat(64)));
    await eq('echoU8 trailing', call('echoU8(uint8[4][3])', u8clean, 'ab'.repeat(40)));

    // ---- empty calldata / wrong-selector style ----
    await eq('echo2 noselector', '0x');

    // ==== WAVE 2: signed-field sign-extension validation boundaries (struct VALIDATES) ====
    // i40 field f in Mixed. Solc requires the 256-bit word be the exact sign-extension
    // of the low 40 bits. Probe both valid and invalid encodings around the boundary.
    const i40min = -(1n << 39n),
      i40max = (1n << 39n) - 1n;
    const se40 = (v: bigint) => ((v % M) + M) % M; // proper two's-complement 256-bit
    // valid encodings (should succeed, echo unchanged):
    for (const v of [0n, 1n, -1n, i40max, i40min, -2n, i40min + 1n, i40max - 1n]) {
      const d = [...mixedClean];
      d[5] = se40(v);
      await eq('echoMixed i40 valid(' + v + ')', call('echoMixed' + MSIG, d));
    }
    // invalid encodings (NOT a clean sign-extension) -> solc reverts:
    // positive low-40 value but high bits set
    await eq(
      'echoMixed i40 inv +highbit',
      call(
        'echoMixed' + MSIG,
        (() => {
          const d = [...mixedClean];
          d[5] = (1n << 40n) | 0x10n;
          return d;
        })(),
      ),
    );
    // value with bit39 set (negative) but bits 40..255 zero (should be all ones)
    await eq(
      'echoMixed i40 inv bit39 no-ext',
      call(
        'echoMixed' + MSIG,
        (() => {
          const d = [...mixedClean];
          d[5] = (1n << 39n) | 0x3n;
          return d;
        })(),
      ),
    );
    // bit39 clear (positive) but bits 40..255 all ones
    await eq(
      'echoMixed i40 inv pos allones',
      call(
        'echoMixed' + MSIG,
        (() => {
          const d = [...mixedClean];
          d[5] = (M - 1n) ^ ((1n << 40n) - 1n);
          return d;
        })(),
      ),
    );
    // top bit only set
    await eq(
      'echoMixed i40 inv topbit',
      call(
        'echoMixed' + MSIG,
        (() => {
          const d = [...mixedClean];
          d[5] = 1n << 255n;
          return d;
        })(),
      ),
    );

    // i8/i64 IN VALUE ARRAYS: solc only sign-extends-from-leaf-bit (masks), no revert.
    // Confirm the cleaned/masked result matches solc for adversarial sign patterns.
    for (const v of [1n << 7n, (1n << 8n) | 0x7fn, M - 1n, (1n << 255n) | 0x80n, 1n << 64n]) {
      const d = [0n, 0x7fn, se40(-1n), se40(-128n)];
      d[1] = v;
      await eq('echoI8 valarr signext(' + v.toString(16) + ')', call('echoI8(int8[4])', d));
    }
    for (const v of [1n << 63n, (1n << 64n) | (1n << 63n), M - 1n, 1n << 255n]) {
      const d = [0n, 1n, 2n, 3n, 4n].map(se40);
      d[2] = v;
      await eq('echoI64 valarr signext(' + v.toString(16) + ')', call('echoI64(int64[5])', d));
    }

    // ==== WAVE 2: bytesN trailing-byte validation in struct field vs masking in array ====
    // Mixed.e is bytes8 (struct field): solc requires unused low 24 bytes == 0. Dirty -> revert.
    for (let b = 1; b <= 8; b++) {
      const d = [...mixedClean];
      d[4] = bytesNword(0xdeadbeefcafef00dn, 8) | (1n << BigInt(8 * (24 - 1) + b)); // set a bit in unused region
      await eq('echoMixed bytes8 dirty(b' + b + ')', call('echoMixed' + MSIG, d));
    }
    // bytes4[3] VALUE array: solc MASKS the unused low bytes (no revert). Already tested low-dirty;
    // add a case where ALL low bytes dirty across all elements.
    await eq(
      'echoB4 all dirtylow',
      call('echoB4(bytes4[3])', [
        bytesNword(0x11223344n, 4) | ((1n << 224n) - 1n),
        bytesNword(0xaabbccddn, 4) | ((1n << 224n) - 1n),
        bytesNword(0xdeadbeefn, 4) | ((1n << 224n) - 1n),
      ]),
    );

    // ==== WAVE 2: u128/u64 struct field high-bit validation (revert) at exact boundary ====
    await eq(
      'echoMixed a u128 exact-max ok',
      call(
        'echoMixed' + MSIG,
        (() => {
          const d = [...mixedClean];
          d[0] = (1n << 128n) - 1n;
          return d;
        })(),
      ),
    );
    await eq(
      'echoMixed a u128 +1bit bad',
      call(
        'echoMixed' + MSIG,
        (() => {
          const d = [...mixedClean];
          d[0] = 1n << 128n;
          return d;
        })(),
      ),
    );
    await eq(
      'echoMixed b u64 exact-max ok',
      call(
        'echoMixed' + MSIG,
        (() => {
          const d = [...mixedClean];
          d[1] = (1n << 64n) - 1n;
          return d;
        })(),
      ),
    );
    await eq(
      'echoMixed b u64 +1bit bad',
      call(
        'echoMixed' + MSIG,
        (() => {
          const d = [...mixedClean];
          d[1] = 1n << 64n;
          return d;
        })(),
      ),
    );

    // ==== WAVE 2: struct-array element-field validation at multiple positions ====
    await eq(
      'echoMixedArr dirty[0].c bool',
      call(
        'echoMixedArr' + MARR,
        (() => {
          const d = [...mixedClean, ...mixedClean];
          d[2] = 5n;
          return d;
        })(),
      ),
    );
    await eq(
      'echoMixedArr dirty[1].f i40',
      call(
        'echoMixedArr' + MARR,
        (() => {
          const d = [...mixedClean, ...mixedClean];
          d[6 + 5] = (1n << 40n) | 1n;
          return d;
        })(),
      ),
    );
    await eq(
      'echoMixedArr dirty[1].e bytes8',
      call(
        'echoMixedArr' + MARR,
        (() => {
          const d = [...mixedClean, ...mixedClean];
          d[6 + 4] = bytesNword(0xdeadbeefcafef00dn, 8) | 0x7n;
          return d;
        })(),
      ),
    );
    await eq('echoMixedArr all-clean', call('echoMixedArr' + MARR, [...mixedClean, ...mixedMax]));

    // ==== WAVE 2: WithArr fixed-array-field with u256 leaves at boundary + dirty id/tag combos ====
    await eq(
      'echoWithArrArr dirty[1].id',
      call('echoWithArrArr((uint64,uint256[3],bytes4)[2])', [
        ...waClean,
        (1n << 64n) | 0xaan,
        0xbbn,
        0xccn,
        0xddn,
        bytesNword(0xdeadn, 4),
      ]),
    );
    await eq(
      'echoWithArrArr dirty[0].tag',
      call('echoWithArrArr((uint64,uint256[3],bytes4)[2])', [
        0x99n,
        0x11n,
        0x22n,
        0x33n,
        bytesNword(0xcafebaben, 4) | 0xffn,
        0xaan,
        0xbbn,
        0xccn,
        0xddn,
        bytesNword(0xdeadn, 4),
      ]),
    );
    await eq(
      'echoWithArrArr both-clean-max',
      call('echoWithArrArr((uint64,uint256[3],bytes4)[2])', [
        (1n << 64n) - 1n,
        MAX,
        MAX,
        MAX,
        bytesNword(0xffffffffn, 4),
        0n,
        0n,
        0n,
        0n,
        bytesNword(0n, 4),
      ]),
    );

    // truncated within the fixed-array field of a struct (data needs 3 words; give 2)
    await eq('echoWithArr trunc in data', call('echoWithArr((uint64,uint256[3],bytes4))', [0x99n, 0x11n, 0x22n]));

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
