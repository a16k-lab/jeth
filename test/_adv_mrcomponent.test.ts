// Adversarial differential test for JETH213: a whole DYNAMIC calldata param (a calldata array
// or a dynamic struct) used as a COMPONENT of a multi-value return. The component is echoed via
// the recursive calldata encoder (offset word + tail; a flat value array CLEANS dirty elements,
// everything else VALIDATES). We attack the ABI offset/length/validation edges hard and demand
// byte-identical (success + returndata) parity with solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const wrap = (v: bigint) => ((v % M) + M) % M;
const pad = (v: bigint) => wrap(v).toString(16).padStart(64, '0');
// raw hex of a word from a bigint (for crafted out-of-band offsets/lengths)
const W = pad;
// bytes/string tail: [len][right-padded data]
const encBytesHex = (hexData: string) => {
  const lenBytes = hexData.length / 2;
  return pad(BigInt(lenBytes)) + hexData.padEnd(Math.ceil(hexData.length / 64) * 64, '0');
};
const encStr = (s: string) => encBytesHex(Buffer.from(s, 'utf8').toString('hex'));
const encU256Arr = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');
// dynamic array of dynamic elements (string[]/bytes[]): [len][offset table][element tails]
const encDynElemArr = (elems: string[]) => {
  let off = elems.length * 32;
  const offs: string[] = [];
  for (const e of elems) {
    offs.push(pad(BigInt(off)));
    off += e.length / 2;
  }
  return pad(BigInt(elems.length)) + offs.join('') + elems.join('');
};
const encStrArr = (ss: string[]) => encDynElemArr(ss.map(encStr));
const encBytesArr = (bs: string[]) => encDynElemArr(bs.map(encBytesHex));
// dynamic struct D{ uint256 a; string s } tail: [a][offset=0x40][string tail]
const encD = (a: bigint, s: string) => pad(a) + pad(0x40n) + encStr(s);
// D[] tail: [len][offset table][D tails]
const encDArr = (ds: [bigint, string][]) => encDynElemArr(ds.map(([a, s]) => encD(a, s)));
// dynamic struct E{ uint8 a; string s } tail: [a-word][offset=0x40][string tail] -- a is a
// NARROW field that solc VALIDATES (high bits must be zero) on decode-to-memory.
const encE = (a: bigint, s: string) => pad(a) + pad(0x40n) + encStr(s);
const encEArr = (es: [bigint, string][]) => encDynElemArr(es.map(([a, s]) => encE(a, s)));
// uint256[][] tail: [len][offset table][inner-array tails]
const encNestedU256 = (rows: bigint[][]) => encDynElemArr(rows.map(encU256Arr));
// bytesN left-aligned word
const bytesNword = (loBytes: bigint, n: number) => (wrap(loBytes % (1n << BigInt(8 * n))) << BigInt(8 * (32 - n))) % M;

// All contracts under test. One contract keeps the harness simple.
const JETH = `@struct class D { a: u256; s: string; }
@struct class E { a: u8; s: string; }
@contract class C {
  @state sn: u256 = 77n;
  // narrow-field dynamic struct (solc VALIDATES the u8 field -> dirty reverts) as component
  @external @pure aEstruct(e: E): [E, u256] { return [e, 1n]; }
  @external @pure aEarr(es: E[]): [E[], u256] { return [es, 1n]; }
  @external @pure pEsecond(n: u256, e: E): [u256, E] { return [n, e]; }
  // --- element-type variety, calldata array as SOLE-position component ---
  @external @pure aU256(xs: u256[]): [u256[], u256] { return [xs, 5n]; }
  @external @pure aU8(xs: u8[]): [u8[], u256] { return [xs, 5n]; }
  @external @pure aBool(xs: bool[]): [bool[], u256] { return [xs, 5n]; }
  @external @pure aAddr(xs: address[]): [address[], u256] { return [xs, 5n]; }
  @external @pure aI128(xs: i128[]): [i128[], u256] { return [xs, 5n]; }
  @external @pure aI40(xs: i40[]): [i40[], u256] { return [xs, 5n]; }
  @external @pure aB32(xs: bytes32[]): [bytes32[], u256] { return [xs, 5n]; }
  @external @pure aB4(xs: bytes4[]): [bytes4[], u256] { return [xs, 5n]; }
  @external @pure aStr(xs: string[]): [string[], u256] { return [xs, 5n]; }
  @external @pure aBytes(xs: bytes[]): [bytes[], u256] { return [xs, 5n]; }
  @external @pure aDarr(xs: D[]): [D[], u256] { return [xs, 5n]; }
  @external @pure aNested(xs: u256[][]): [u256[][], u256] { return [xs, 5n]; }
  @external @pure aFixedOfDyn(xs: Arr<u256,2>[]): [Arr<u256,2>[], u256] { return [xs, 5n]; }
  @external @pure aDstruct(d: D): [D, u256] { return [d, 9n]; }
  // --- component POSITION variety ---
  @external @pure pSecond(ss: string[]): [u256, string[]] { return [3n, ss]; }
  @external @pure pMid(a: u256, xs: u256[], b: u256): [u256, u256[], u256] { return [a, xs, b]; }
  @external @pure pTwoArr(xs: u256[], ys: u256[]): [u256[], u256[]] { return [xs, ys]; }
  @external @pure pTwoStruct(d1: D, d2: D): [D, D] { return [d1, d2]; }
  @external @pure pArrThenStruct(xs: u256[], d: D): [u256[], D] { return [xs, d]; }
  @external @pure pStructThenArr(d: D, xs: u256[]): [D, u256[]] { return [d, xs]; }
  @external @pure pBytesThenArr(b: bytes, xs: u256[]): [bytes, u256[]] { return [b, xs]; }
  @external @pure pArrThenBytes(xs: u256[], b: bytes): [u256[], bytes] { return [xs, b]; }
  @external @pure pStrThenArr(s: string, xs: u256[]): [string, u256[]] { return [s, xs]; }
  // interleave value / calldata-array / bytes / string / storage components
  @external @view pAll(n: u256, xs: u256[], b: bytes, s: string): [u256, u256[], bytes, string, u256] { return [n, xs, b, s, this.sn]; }
  // --- consistency: same array returned as SOLE component (existing echo) ---
  @external @pure soleArr(xs: u256[]): u256[] { return xs; }
  @external @pure soleStr(xs: string[]): string[] { return xs; }
  @external @pure soleD(d: D): D { return d; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct D { uint256 a; string s; }
  struct E { uint8 a; string s; }
  uint256 sn = 77;
  function aEstruct(E calldata e) external pure returns (E memory, uint256){ return (e, 1); }
  function aEarr(E[] calldata es) external pure returns (E[] memory, uint256){ return (es, 1); }
  function pEsecond(uint256 n, E calldata e) external pure returns (uint256, E memory){ return (n, e); }
  function aU256(uint256[] calldata xs) external pure returns (uint256[] memory, uint256){ return (xs, 5); }
  function aU8(uint8[] calldata xs) external pure returns (uint8[] memory, uint256){ return (xs, 5); }
  function aBool(bool[] calldata xs) external pure returns (bool[] memory, uint256){ return (xs, 5); }
  function aAddr(address[] calldata xs) external pure returns (address[] memory, uint256){ return (xs, 5); }
  function aI128(int128[] calldata xs) external pure returns (int128[] memory, uint256){ return (xs, 5); }
  function aI40(int40[] calldata xs) external pure returns (int40[] memory, uint256){ return (xs, 5); }
  function aB32(bytes32[] calldata xs) external pure returns (bytes32[] memory, uint256){ return (xs, 5); }
  function aB4(bytes4[] calldata xs) external pure returns (bytes4[] memory, uint256){ return (xs, 5); }
  function aStr(string[] calldata xs) external pure returns (string[] memory, uint256){ return (xs, 5); }
  function aBytes(bytes[] calldata xs) external pure returns (bytes[] memory, uint256){ return (xs, 5); }
  function aDarr(D[] calldata xs) external pure returns (D[] memory, uint256){ return (xs, 5); }
  function aNested(uint256[][] calldata xs) external pure returns (uint256[][] memory, uint256){ return (xs, 5); }
  function aFixedOfDyn(uint256[2][] calldata xs) external pure returns (uint256[2][] memory, uint256){ return (xs, 5); }
  function aDstruct(D calldata d) external pure returns (D memory, uint256){ return (d, 9); }
  function pSecond(string[] calldata ss) external pure returns (uint256, string[] memory){ return (3, ss); }
  function pMid(uint256 a, uint256[] calldata xs, uint256 b) external pure returns (uint256, uint256[] memory, uint256){ return (a, xs, b); }
  function pTwoArr(uint256[] calldata xs, uint256[] calldata ys) external pure returns (uint256[] memory, uint256[] memory){ return (xs, ys); }
  function pTwoStruct(D calldata d1, D calldata d2) external pure returns (D memory, D memory){ return (d1, d2); }
  function pArrThenStruct(uint256[] calldata xs, D calldata d) external pure returns (uint256[] memory, D memory){ return (xs, d); }
  function pStructThenArr(D calldata d, uint256[] calldata xs) external pure returns (D memory, uint256[] memory){ return (d, xs); }
  function pBytesThenArr(bytes calldata b, uint256[] calldata xs) external pure returns (bytes memory, uint256[] memory){ return (b, xs); }
  function pArrThenBytes(uint256[] calldata xs, bytes calldata b) external pure returns (uint256[] memory, bytes memory){ return (xs, b); }
  function pStrThenArr(string calldata s, uint256[] calldata xs) external pure returns (string memory, uint256[] memory){ return (s, xs); }
  function pAll(uint256 n, uint256[] calldata xs, bytes calldata b, string calldata s) external view returns (uint256, uint256[] memory, bytes memory, string memory, uint256){ return (n, xs, b, s, sn); }
  function soleArr(uint256[] calldata xs) external pure returns (uint256[] memory){ return xs; }
  function soleStr(string[] calldata xs) external pure returns (string[] memory){ return xs; }
  function soleD(D calldata d) external pure returns (D memory){ return d; }
}`;

describe('JETH213 adversarial: calldata-aggregate multi-return component vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex) {
      mism.push(
        `${label}: jeth{ok=${j.success},err=${j.exceptionError},ret=${j.returnHex}} sol{ok=${s.success},ret=${s.returnHex}}`,
      );
    }
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runs the adversarial battery', async () => {
    const MAX = M - 1n;
    const DIRTY = (1n << 255n) | (1n << 200n) | (1n << 99n) | 0xabn;

    // =====================================================================
    // 1. ELEMENT-TYPE VARIETY (sizes 0/1/2/large), CLEAN inputs.
    // =====================================================================
    const u256sizes: bigint[][] = [
      [],
      [1n],
      [1n, 2n],
      [MAX, 0n, 42n, MAX - 7n],
      Array.from({ length: 20 }, (_, i) => BigInt(i) * 11n),
    ];
    for (const xs of u256sizes)
      await eq(`aU256[${xs.length}]`, '0x' + sel('aU256(uint256[])') + W(0x20n) + encU256Arr(xs));

    // u8[] CLEAN values then DIRTY high bits (solc value-array CLEANS -> success masked)
    for (const xs of [[], [0n], [0n, 0xffn], [1n, 2n, 3n, 0xffn]])
      await eq(`aU8 clean[${xs.length}]`, '0x' + sel('aU8(uint8[])') + W(0x20n) + encU256Arr(xs));
    await eq(
      'aU8 dirty',
      '0x' + sel('aU8(uint8[])') + W(0x20n) + W(3n) + W((DIRTY << 8n) | 0x42n) + W((MAX << 8n) | 0x01n) + W(DIRTY),
    );
    await eq('aU8 alldirty1', '0x' + sel('aU8(uint8[])') + W(0x20n) + W(1n) + W(MAX));

    // bool[]: solc value-array CLEANS via iszero(iszero) -> non-canonical succeeds masked to 0/1
    await eq('aBool clean', '0x' + sel('aBool(bool[])') + W(0x20n) + W(4n) + W(1n) + W(0n) + W(1n) + W(0n));
    await eq('aBool dirty2', '0x' + sel('aBool(bool[])') + W(0x20n) + W(3n) + W(2n) + W(DIRTY) + W(DIRTY << 1n));
    await eq('aBool high', '0x' + sel('aBool(bool[])') + W(0x20n) + W(2n) + W(1n << 255n) + W((1n << 255n) | 1n));

    // address[]: solc value-array CLEANS top 96 bits
    await eq(
      'aAddr clean',
      '0x' + sel('aAddr(address[])') + W(0x20n) + W(2n) + W(0x1234n) + W(BigInt('0x' + 'aa'.repeat(20))),
    );
    await eq('aAddr dirty', '0x' + sel('aAddr(address[])') + W(0x20n) + W(2n) + W((1n << 200n) | 0x99n) + W(DIRTY));

    // int128[] / int40[]: solc value-array sign-extends from the element bit (no revert)
    await eq(
      'aI128 clean',
      '0x' + sel('aI128(int128[])') + W(0x20n) + W(3n) + W(0n) + W(wrap(-1n)) + W((1n << 127n) - 1n),
    );
    await eq(
      'aI128 dirty',
      '0x' + sel('aI128(int128[])') + W(0x20n) + W(2n) + W((DIRTY << 128n) | (1n << 127n)) + W((DIRTY << 128n) | 0x7n),
    );
    await eq('aI40 clean', '0x' + sel('aI40(int40[])') + W(0x20n) + W(3n) + W(0n) + W(wrap(-1n)) + W((1n << 39n) - 1n));
    await eq(
      'aI40 dirty',
      '0x' + sel('aI40(int40[])') + W(0x20n) + W(2n) + W((DIRTY << 40n) | (1n << 39n)) + W((DIRTY << 40n) | 0x3n),
    );

    // bytes32[] (full width, no cleaning) / bytes4[] (solc CLEANS low 28 bytes)
    await eq('aB32', '0x' + sel('aB32(bytes32[])') + W(0x20n) + W(2n) + W(MAX) + W(0n));
    await eq(
      'aB4 clean',
      '0x' + sel('aB4(bytes4[])') + W(0x20n) + W(2n) + W(bytesNword(0x11223344n, 4)) + W(bytesNword(0xdeadbeefn, 4)),
    );
    await eq(
      'aB4 dirtylow',
      '0x' + sel('aB4(bytes4[])') + W(0x20n) + W(2n) + W(bytesNword(0x11223344n, 4) | ((1n << 224n) - 1n)) + W(MAX),
    );

    // string[] (validates dynamic elements; cleaning N/A) - sizes incl long + empty
    for (const ss of [
      [],
      [''],
      ['a'],
      ['', ''],
      ['short', 'a much longer element exceeding thirty-two bytes for sure here ok'],
      ['x'.repeat(64)],
    ]) {
      await eq(`aStr[${ss.length}]`, '0x' + sel('aStr(string[])') + W(0x20n) + encStrArr(ss));
    }
    // bytes[]
    for (const bs of [[], ['deadbeef'], ['', 'ff'.repeat(40)], ['ab'.repeat(33)]]) {
      await eq(`aBytes[${bs.length}]`, '0x' + sel('aBytes(bytes[])') + W(0x20n) + encBytesArr(bs));
    }
    // D[] dynamic-struct array
    for (const ds of [
      [],
      [[1n, 'hi']],
      [
        [7n, ''],
        [MAX, 'a longer struct string field over thirty-two bytes total length'],
      ],
    ] as [bigint, string][][]) {
      await eq(`aDarr[${ds.length}]`, '0x' + sel('aDarr((uint256,string)[])') + W(0x20n) + encDArr(ds));
    }
    // uint256[][] nested
    for (const rows of [[], [[]], [[1n], [2n, 3n]], [[MAX], [], [0n, 0n, 0n]]]) {
      await eq(`aNested[${rows.length}]`, '0x' + sel('aNested(uint256[][])') + W(0x20n) + encNestedU256(rows));
    }
    // uint256[2][] : dynamic array of static fixed-array elements
    for (const rows of [
      [],
      [[1n, 2n]],
      [
        [1n, 2n],
        [3n, 4n],
        [MAX, 0n],
      ],
    ]) {
      const body = pad(BigInt(rows.length)) + rows.map((r) => pad(r[0]!) + pad(r[1]!)).join('');
      await eq(`aFixedOfDyn[${rows.length}]`, '0x' + sel('aFixedOfDyn(uint256[2][])') + W(0x20n) + body);
    }
    // dynamic struct D as component
    for (const [a, s] of [
      [7n, 'hi'],
      [MAX, 'a field over thirty-two bytes long for the struct echo path'],
      [0n, ''],
    ] as [bigint, string][]) {
      await eq(`aDstruct(${s.length})`, '0x' + sel('aDstruct((uint256,string))') + W(0x20n) + encD(a, s));
    }

    // =====================================================================
    // 2. COMPONENT POSITION variety.
    // =====================================================================
    await eq('pSecond', '0x' + sel('pSecond(string[])') + W(0x20n) + encStrArr(['a', 'bb']));
    // pMid: a, offset(xs), b ; then xs tail
    {
      const a = 11n,
        b = 22n;
      const xs = [9n, 8n, 7n];
      const data = '0x' + sel('pMid(uint256,uint256[],uint256)') + W(a) + W(0x60n) + W(b) + encU256Arr(xs);
      await eq('pMid', data);
    }
    // pTwoArr: two calldata-array components
    {
      const xs = [1n, 2n],
        ys = [3n, 4n, 5n];
      const xsT = encU256Arr(xs),
        ysT = encU256Arr(ys);
      const off2 = 0x40 + xsT.length / 2;
      const data = '0x' + sel('pTwoArr(uint256[],uint256[])') + W(0x40n) + W(BigInt(off2)) + xsT + ysT;
      await eq('pTwoArr', data);
    }
    // pTwoStruct: two dynamic-struct components
    {
      const d1 = encD(1n, 'aa'),
        d2 = encD(2n, 'bbbb');
      const off2 = 0x40 + d1.length / 2;
      const data = '0x' + sel('pTwoStruct((uint256,string),(uint256,string))') + W(0x40n) + W(BigInt(off2)) + d1 + d2;
      await eq('pTwoStruct', data);
    }
    // pArrThenStruct / pStructThenArr
    {
      const xsT = encU256Arr([7n, 8n]);
      const dT = encD(9n, 'zz');
      await eq(
        'pArrThenStruct',
        '0x' +
          sel('pArrThenStruct(uint256[],(uint256,string))') +
          W(0x40n) +
          W(BigInt(0x40 + xsT.length / 2)) +
          xsT +
          dT,
      );
      await eq(
        'pStructThenArr',
        '0x' +
          sel('pStructThenArr((uint256,string),uint256[])') +
          W(0x40n) +
          W(BigInt(0x40 + dT.length / 2)) +
          dT +
          xsT,
      );
    }
    // bytes + array mixed
    {
      const bT = encBytesHex('cafe' + 'ab'.repeat(40));
      const xsT = encU256Arr([1n, 2n, 3n]);
      await eq(
        'pBytesThenArr',
        '0x' + sel('pBytesThenArr(bytes,uint256[])') + W(0x40n) + W(BigInt(0x40 + bT.length / 2)) + bT + xsT,
      );
      await eq(
        'pArrThenBytes',
        '0x' + sel('pArrThenBytes(uint256[],bytes)') + W(0x40n) + W(BigInt(0x40 + xsT.length / 2)) + xsT + bT,
      );
    }
    // string + array
    {
      const sT = encStr('a string longer than thirty-two bytes goes right here yes');
      const xsT = encU256Arr([4n, 5n]);
      await eq(
        'pStrThenArr',
        '0x' + sel('pStrThenArr(string,uint256[])') + W(0x40n) + W(BigInt(0x40 + sT.length / 2)) + sT + xsT,
      );
    }
    // pAll: n, off(xs), off(b), off(s), then tails; returns storage sn=77 too
    {
      const n = 100n;
      const xs = [1n, 2n];
      const b = 'beef';
      const s = 'hello world';
      const xsT = encU256Arr(xs),
        bT = encBytesHex(b),
        sT = encStr(s);
      const o1 = 0x80,
        o2 = o1 + xsT.length / 2,
        o3 = o2 + bT.length / 2;
      const data =
        '0x' +
        sel('pAll(uint256,uint256[],bytes,string)') +
        W(n) +
        W(BigInt(o1)) +
        W(BigInt(o2)) +
        W(BigInt(o3)) +
        xsT +
        bT +
        sT;
      await eq('pAll', data);
    }

    // =====================================================================
    // 3. CONSISTENCY: sole-return echo vs component echo for same input.
    // =====================================================================
    {
      const xs = [MAX, 0n, 42n];
      const soleHex = '0x' + sel('soleArr(uint256[])') + W(0x20n) + encU256Arr(xs);
      const compHex = '0x' + sel('aU256(uint256[])') + W(0x20n) + encU256Arr(xs);
      const soleJ = await jeth.call(aj, soleHex);
      const compJ = await jeth.call(aj, compHex);
      // the array tail (after the component's leading offset + the trailing u256) must agree.
      // sole return: [0x20][len][...]; component: [0x20][off1=0x40][off?..] -> just sanity both succeed.
      if (!soleJ.success || !compJ.success) mism.push(`consistency: sole=${soleJ.success} comp=${compJ.success}`);
      await eq('consistency soleArr', soleHex);
      await eq('consistency soleStr', '0x' + sel('soleStr(string[])') + W(0x20n) + encStrArr(['p', 'qq']));
      await eq('consistency soleD', '0x' + sel('soleD((uint256,string))') + W(0x20n) + encD(3n, 'hey'));
    }

    // =====================================================================
    // 4. DIRTY-INPUT VALIDATION PARITY (CRITICAL).
    //    D[] / string[] / bytes[] / D component VALIDATE narrow fields -> revert on dirty.
    //    Flat value arrays CLEAN -> succeed.
    // =====================================================================
    // E{ uint8 a; string s } HAS a narrow field: solc VALIDATES it on decode-to-memory, so a
    // dirty high-bit `a` MUST revert identically. This is the core validation-parity case.
    await eq('aEstruct clean', '0x' + sel('aEstruct((uint8,string))') + W(0x20n) + encE(0xffn, 'hi'));
    await eq(
      'aEstruct dirty a (revert)',
      '0x' + sel('aEstruct((uint8,string))') + W(0x20n) + W((1n << 8n) | 0x7n) + W(0x40n) + encStr('hi'),
    );
    await eq(
      'aEstruct dirty a high (revert)',
      '0x' + sel('aEstruct((uint8,string))') + W(0x20n) + W(DIRTY << 8n) + W(0x40n) + encStr('hi'),
    );
    await eq('aEstruct a=max ok', '0x' + sel('aEstruct((uint8,string))') + W(0x20n) + encE(0xffn, ''));
    // pEsecond: narrow struct as the LAST component
    await eq('pEsecond clean', '0x' + sel('pEsecond(uint256,(uint8,string))') + W(9n) + W(0x40n) + encE(0x7fn, 'z'));
    await eq(
      'pEsecond dirty a (revert)',
      '0x' + sel('pEsecond(uint256,(uint8,string))') + W(9n) + W(0x40n) + W(0x100n) + W(0x40n) + encStr('z'),
    );
    // E[] element with dirty narrow field -> solc validates each element -> revert
    await eq(
      'aEarr clean',
      '0x' +
        sel('aEarr((uint8,string)[])') +
        W(0x20n) +
        encEArr([
          [1n, 'a'],
          [0xffn, 'bb'],
        ]),
    );
    await eq(
      'aEarr dirty[1].a (revert)',
      '0x' +
        sel('aEarr((uint8,string)[])') +
        W(0x20n) +
        W(2n) +
        W(0x40n) +
        W(BigInt(0x40 + encE(1n, 'a').length / 2)) +
        encE(1n, 'a') +
        (W((1n << 8n) | 2n) + W(0x40n) + encStr('bb')),
    );
    await eq('aEarr empty', '0x' + sel('aEarr((uint8,string)[])') + W(0x20n) + W(0n));

    // D{ uint256 a; string s } has no narrow fields; we confirm the COMPONENT path matches on
    // dirty DYNAMIC inner offsets/lengths (below).
    // string element with a non-multiple length is fine (right-padded); test a string whose
    // length word is huge (Panic 0x41 region) inside string[].
    {
      // string[] with element length = 2^64 -> solc Panic(0x41) on the inner length
      const big = 1n << 64n;
      const arr = W(1n) + W(0x20n) /*offset to elem*/ + W(big) /*len*/ + W(0n);
      await eq('aStr inner-len 2^64', '0x' + sel('aStr(string[])') + W(0x20n) + arr);
    }
    {
      // bytes[] element length 2^64-1 (boundary, but tail truncated -> revert)
      const big = (1n << 64n) - 1n;
      const arr = W(1n) + W(0x20n) + W(big) + W(0n);
      await eq('aBytes inner-len huge trunc', '0x' + sel('aBytes(bytes[])') + W(0x20n) + arr);
    }

    // =====================================================================
    // 5. MALFORMED CALLDATA: top-level component OFFSET adversarial.
    // =====================================================================
    const goodTail = encU256Arr([1n, 2n, 3n]);
    // (a) offset 1<<200 -> out of bounds -> revert
    await eq('aU256 off 1<<200', '0x' + sel('aU256(uint256[])') + W(1n << 200n) + goodTail);
    // (b) offset 0xffffffff -> OOB -> revert
    await eq('aU256 off 0xffffffff', '0x' + sel('aU256(uint256[])') + W(0xffffffffn) + goodTail);
    // (c) high-bit offset >= 2^255 (negative under slt). solc's calldata bound also uses
    //     unsigned compare for the param head -> revert. JETH uses slt: a negative off PASSES
    //     the slt check then add(4,off) wraps; the subsequent length read is OOB. Must match.
    await eq('aU256 off 2^255', '0x' + sel('aU256(uint256[])') + W(1n << 255n) + goodTail);
    await eq('aU256 off 2^255+32', '0x' + sel('aU256(uint256[])') + W((1n << 255n) | 0x20n) + goodTail);
    await eq('aU256 off max', '0x' + sel('aU256(uint256[])') + W(MAX) + goodTail);
    // (d) offset exactly at calldatasize-ish boundary (points past end so length read OOB)
    {
      // total calldata = 4 + 1(off) + 4 words tail = 4 + 160 bytes. point off at 0xa0 (last word)
      await eq('aU256 off near-end', '0x' + sel('aU256(uint256[])') + W(0xa0n) + goodTail);
      // off exactly = calldatasize-4 (one past) -> len read OOB -> revert
      await eq('aU256 off = size-4', '0x' + sel('aU256(uint256[])') + W(0xa0n) + goodTail); // 0x20+0x80 tail = 0xa0; size-4 = 0xa0
    }
    // (e) offset 0 -> points at itself (len = the offset word = 0x.. ) -> compare
    await eq('aU256 off 0', '0x' + sel('aU256(uint256[])') + W(0n) + goodTail);
    // (f) offset not 0x20 but valid into the tail region (points at first elem as len)
    await eq('aU256 off 0x40', '0x' + sel('aU256(uint256[])') + W(0x40n) + goodTail);

    // length adversarial (offset good, length word crafted)
    // (g) declared length 2^64 -> Panic(0x41)
    await eq('aU256 len 2^64', '0x' + sel('aU256(uint256[])') + W(0x20n) + W(1n << 64n) + W(1n));
    // (h) declared length 2^64-1 -> huge alloc, tail truncated -> Panic/revert (match solc)
    await eq('aU256 len 2^64-1', '0x' + sel('aU256(uint256[])') + W(0x20n) + W((1n << 64n) - 1n) + W(1n));
    // (i) declared length exceeds available words -> revert (truncated tail)
    await eq('aU256 len 5 have 2', '0x' + sel('aU256(uint256[])') + W(0x20n) + W(5n) + W(1n) + W(2n));
    // (j) length 0 with no further data -> empty array echo
    await eq('aU256 len 0', '0x' + sel('aU256(uint256[])') + W(0x20n) + W(0n));
    // (k) exact-fit length
    await eq('aU256 len 3 exact', '0x' + sel('aU256(uint256[])') + W(0x20n) + W(3n) + W(1n) + W(2n) + W(3n));
    // (l) truncated length word itself (offset points where < 32 bytes remain)
    await eq('aU256 len-word trunc', '0x' + sel('aU256(uint256[])') + W(0x20n) + 'abcd');

    // dynamic-struct component: bad top offset and inner string offset
    await eq('aDstruct off OOB', '0x' + sel('aDstruct((uint256,string))') + W(1n << 200n) + encD(1n, 'x'));
    await eq('aDstruct off 2^255', '0x' + sel('aDstruct((uint256,string))') + W(1n << 255n) + encD(1n, 'x'));
    {
      // inner string offset OOB inside the struct
      const dBad = pad(1n) + W(1n << 64n) + encStr('x'); // string-field offset = 2^64
      await eq('aDstruct inner-off 2^64', '0x' + sel('aDstruct((uint256,string))') + W(0x20n) + dBad);
      const dBad2 = pad(1n) + W(1n << 200n) + encStr('x');
      await eq('aDstruct inner-off 1<<200', '0x' + sel('aDstruct((uint256,string))') + W(0x20n) + dBad2);
      const dBad3 = pad(1n) + W(0n) + encStr('x'); // string offset 0 -> points at field a as len
      await eq('aDstruct inner-off 0', '0x' + sel('aDstruct((uint256,string))') + W(0x20n) + dBad3);
    }

    // string[] / D[] / nested: inner element offset adversarial
    {
      // string[] len 2 but second element offset OOB
      const arr = W(2n) + W(0x40n) + W(1n << 200n) + encStr('aa');
      await eq('aStr inner-off OOB', '0x' + sel('aStr(string[])') + W(0x20n) + arr);
      // string[] inner offset >= 2^64 -> revert
      const arr2 = W(1n) + W(1n << 64n) + encStr('aa');
      await eq('aStr inner-off 2^64', '0x' + sel('aStr(string[])') + W(0x20n) + arr2);
      // string[] inner offset 2^255 (high bit)
      const arr3 = W(1n) + W(1n << 255n) + encStr('aa');
      await eq('aStr inner-off 2^255', '0x' + sel('aStr(string[])') + W(0x20n) + arr3);
      // D[] element offset OOB
      const darr = W(1n) + W(1n << 200n) + encD(1n, 'x');
      await eq('aDarr inner-off OOB', '0x' + sel('aDarr((uint256,string)[])') + W(0x20n) + darr);
      // nested uint256[][] inner array offset OOB + inner length huge
      const narr = W(1n) + W(1n << 200n) + encU256Arr([1n]);
      await eq('aNested inner-off OOB', '0x' + sel('aNested(uint256[][])') + W(0x20n) + narr);
      const narr2 = W(1n) + W(0x20n) + W(1n << 64n) + W(1n); // inner len 2^64
      await eq('aNested inner-len 2^64', '0x' + sel('aNested(uint256[][])') + W(0x20n) + narr2);
    }

    // truncated tail for dynamic-elem arrays
    await eq(
      'aStr len 3 have 1',
      '0x' + sel('aStr(string[])') + W(0x20n) + W(3n) + W(0x60n) + W(0x80n) + W(0xa0n) + encStr('a'),
    );
    await eq('aDarr len 2 trunc', '0x' + sel('aDarr((uint256,string)[])') + W(0x20n) + W(2n) + W(0x40n));

    // zero-length variants for every dynamic-elem array
    await eq('aStr empty', '0x' + sel('aStr(string[])') + W(0x20n) + W(0n));
    await eq('aBytes empty', '0x' + sel('aBytes(bytes[])') + W(0x20n) + W(0n));
    await eq('aDarr empty', '0x' + sel('aDarr((uint256,string)[])') + W(0x20n) + W(0n));
    await eq('aNested empty', '0x' + sel('aNested(uint256[][])') + W(0x20n) + W(0n));

    // trailing extra calldata (solc ignores) + no-selector
    await eq('aU256 trailing', '0x' + sel('aU256(uint256[])') + W(0x20n) + encU256Arr([1n, 2n]) + 'ff'.repeat(64));
    await eq('aU256 noselector', '0x');
    await eq('aU256 short selector', '0x' + sel('aU256(uint256[])'));

    // two-array with the SECOND offset adversarial
    {
      const xsT = encU256Arr([1n]);
      // second offset 2^255 -> revert
      await eq('pTwoArr off2 2^255', '0x' + sel('pTwoArr(uint256[],uint256[])') + W(0x40n) + W(1n << 255n) + xsT);
      // second offset OOB
      await eq('pTwoArr off2 OOB', '0x' + sel('pTwoArr(uint256[],uint256[])') + W(0x40n) + W(1n << 200n) + xsT);
      // both offsets point at the SAME tail (aliasing) -> solc allows (decodes twice)
      const xsT2 = encU256Arr([9n, 8n]);
      await eq('pTwoArr alias', '0x' + sel('pTwoArr(uint256[],uint256[])') + W(0x40n) + W(0x40n) + xsT2);
    }

    // =====================================================================
    // 6. mid/last position offset adversarial for pMid (offset is the MIDDLE component)
    // =====================================================================
    await eq(
      'pMid off 2^255',
      '0x' + sel('pMid(uint256,uint256[],uint256)') + W(1n) + W(1n << 255n) + W(2n) + encU256Arr([7n]),
    );
    await eq(
      'pMid off OOB',
      '0x' + sel('pMid(uint256,uint256[],uint256)') + W(1n) + W(1n << 200n) + W(2n) + encU256Arr([7n]),
    );
    await eq(
      'pMid off=0x60 ok',
      '0x' + sel('pMid(uint256,uint256[],uint256)') + W(1n) + W(0x60n) + W(2n) + encU256Arr([7n]),
    );

    if (mism.length) {
      console.log(`MISMATCHES ${mism.length}/${count}`);
      for (const m of mism.slice(0, 60)) console.log(m);
    } else {
      console.log(`ALL ${count} cases byte-identical`);
    }
    expect(mism, mism.slice(0, 20).join('\n')).toEqual([]);
  });
});
