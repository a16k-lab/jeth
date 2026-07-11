// Tier-1: `delete x` (Solidity storage reset). A value target lowers to `= 0` (packed-aware);
// bytes/string/struct/array targets clear their full storage footprint; a whole mapping is a
// no-op. Verified byte-identical to solc on BOTH returndata AND raw storage slots (including the
// keccak data slots of dynamic arrays / strings / mappings, so freed tails are provably zeroed).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const b32 = (v: bigint) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex');
const kecSlot = (n: bigint) => BigInt('0x' + toHex(keccak(b32(n))));
const mapSlot = (key: bigint, base: bigint) => BigInt('0x' + toHex(keccak(Buffer.concat([b32(key), b32(base)]))));
const A = 0xa11ce0000000000000000000000000000000n; // a sample address key

const JETH = `type P = { a: u256; b: u8; c: address; };
type D = { n: u256; s: string; };
class C {
  pa: u8; pb: u8; pc: u8;
  count: u256;
  addr: address;
  p: P;
  d: D;
  fa: Arr<u256,3>;
  xs: u256[];
  ss: string[];
  s: string;
  bal: mapping<address, u256>;
  mp: mapping<address, P>;
  mb: mapping<address, string>;

  seed(str: string): External<void> {
    this.pa = 11n; this.pb = 22n; this.pc = 33n;
    this.count = 999n; this.addr = address(0x1234n);
    this.p = P(7n, 8n, address(0x9n));
    this.d = D(5n, str);
    this.fa[0n] = 100n; this.fa[1n] = 200n; this.fa[2n] = 300n;
    this.xs.push(1n); this.xs.push(2n); this.xs.push(3n);
    this.ss.push(str); this.ss.push(str);
    this.s = str;
    this.bal[address(0xa11ce0000000000000000000000000000000n)] = 555n;
    this.mp[address(0xa11ce0000000000000000000000000000000n)] = P(1n, 2n, address(0x3n));
    this.mb[address(0xa11ce0000000000000000000000000000000n)] = str;
  }
  delPacked(): External<void> { delete this.pb; }
  delCount(): External<void> { delete this.count; }
  delAddr(): External<void> { delete this.addr; }
  delStruct(): External<void> { delete this.p; }
  delDynStruct(): External<void> { delete this.d; }
  delFixed(): External<void> { delete this.fa; }
  delDynArr(): External<void> { delete this.xs; }
  delStrArr(): External<void> { delete this.ss; }
  delStr(): External<void> { delete this.s; }
  delMapVal(): External<void> { delete this.bal[address(0xa11ce0000000000000000000000000000000n)]; }
  delMapStruct(): External<void> { delete this.mp[address(0xa11ce0000000000000000000000000000000n)]; }
  delMapStructField(): External<void> { delete this.mp[address(0xa11ce0000000000000000000000000000000n)].a; }
  delMapBytes(): External<void> { delete this.mb[address(0xa11ce0000000000000000000000000000000n)]; }
  delStructField(): External<void> { delete this.p.c; }
  delFixedElem(): External<void> { delete this.fa[1n]; }
  get delLocal(x: u256): External<u256> { let y: u256 = x; delete y; return y; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; address c; }
  struct D { uint256 n; string s; }
  uint8 pa; uint8 pb; uint8 pc;
  uint256 count;
  address addr;
  P p;
  D d;
  uint256[3] fa;
  uint256[] xs;
  string[] ss;
  string s;
  mapping(address => uint256) bal;
  mapping(address => P) mp;
  mapping(address => string) mb;

  function seed(string calldata str) external {
    pa = 11; pb = 22; pc = 33;
    count = 999; addr = address(0x1234);
    p = P(7, 8, address(0x9));
    d = D(5, str);
    fa[0] = 100; fa[1] = 200; fa[2] = 300;
    xs.push(1); xs.push(2); xs.push(3);
    ss.push(str); ss.push(str);
    s = str;
    bal[address(0xa11ce0000000000000000000000000000000)] = 555;
    mp[address(0xa11ce0000000000000000000000000000000)] = P(1, 2, address(0x3));
    mb[address(0xa11ce0000000000000000000000000000000)] = str;
  }
  function delPacked() external { delete pb; }
  function delCount() external { delete count; }
  function delAddr() external { delete addr; }
  function delStruct() external { delete p; }
  function delDynStruct() external { delete d; }
  function delFixed() external { delete fa; }
  function delDynArr() external { delete xs; }
  function delStrArr() external { delete ss; }
  function delStr() external { delete s; }
  function delMapVal() external { delete bal[address(0xa11ce0000000000000000000000000000000)]; }
  function delMapStruct() external { delete mp[address(0xa11ce0000000000000000000000000000000)]; }
  function delMapStructField() external { delete mp[address(0xa11ce0000000000000000000000000000000)].a; }
  function delMapBytes() external { delete mb[address(0xa11ce0000000000000000000000000000000)]; }
  function delStructField() external { delete p.c; }
  function delFixedElem() external { delete fa[1]; }
  function delLocal(uint256 x) external pure returns (uint256) { uint256 y = x; delete y; return y; }
}`;

describe('delete x vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const STR_SLOTS = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n, 13n, 14n, 15n, 16n];
  // dynamic data slots: xs data (slot 11), s data (slot 13), ss element headers (slot 12), mappings
  const DATA = [
    kecSlot(11n),
    kecSlot(11n) + 1n,
    kecSlot(11n) + 2n, // xs[0..2]
    kecSlot(13n), // s long-data
    kecSlot(12n),
    kecSlot(12n) + 1n, // ss[0],ss[1] headers
    kecSlot(kecSlot(12n)),
    kecSlot(kecSlot(12n) + 1n), // ss element long-data
    mapSlot(A, 14n), // bal[A]
    mapSlot(A, 15n),
    mapSlot(A, 15n) + 1n, // mp[A] fields
    mapSlot(A, 16n),
    kecSlot(mapSlot(A, 16n)), // mb[A] header + long-data
  ];
  const ALL = [...STR_SLOTS, ...DATA];

  async function reseed(h: Harness, a: Address, str: string) {
    const data =
      '0x' +
      sel('seed(string)') +
      b32(0x20n).toString('hex') +
      b32(BigInt(Buffer.byteLength(str))).toString('hex') +
      Buffer.from(str, 'utf8')
        .toString('hex')
        .padEnd(Math.ceil(str.length / 32) * 64, '0');
    await h.call(a, data);
  }
  async function runDelete(label: string, fnSig: string, str: string) {
    await reseed(jeth, aj, str);
    await reseed(sol, as, str);
    const j = await jeth.call(aj, encodeCall(sel(fnSig), []));
    const s = await sol.call(as, encodeCall(sel(fnSig), []));
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    for (const slot of ALL) {
      expect(await readSlot(jeth, aj, slot), `${label} slot ${slot.toString(16)}`).toBe(await readSlot(sol, as, slot));
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

  const SHORT = 'hi';
  const LONG = 'this string is definitely longer than thirty-two bytes so it uses keccak data slots';
  for (const [str, tag] of [
    [SHORT, 'short'],
    [LONG, 'long'],
  ] as const) {
    it(`delete (${tag} dynamic payloads): all 17 cases, returndata + raw slots`, async () => {
      for (const [label, sig] of [
        ['packed-neighbor', 'delPacked()'],
        ['value-u256', 'delCount()'],
        ['value-address', 'delAddr()'],
        ['static-struct', 'delStruct()'],
        ['dynamic-struct', 'delDynStruct()'],
        ['fixed-array', 'delFixed()'],
        ['dynamic-array', 'delDynArr()'],
        ['string-array', 'delStrArr()'],
        ['bytes-string', 'delStr()'],
        ['mapping-value', 'delMapVal()'],
        ['mapping-struct', 'delMapStruct()'],
        ['mapping-struct-field', 'delMapStructField()'],
        ['mapping-bytes', 'delMapBytes()'],
        ['struct-field', 'delStructField()'],
        ['fixed-elem', 'delFixedElem()'],
      ] as const) {
        await runDelete(`${label}/${tag}`, sig, str);
      }
    });
  }

  it('rejects delete of a whole mapping (parity: solc also rejects)', () => {
    const src = `class C { bal: mapping<address, u256>; f(): External<void> { delete this.bal; } }`;
    expect(() => compile(src, { fileName: 'C.jeth' })).toThrow();
  });

  it('delete a local value variable', async () => {
    for (const x of [0n, 1n, 123456789n, 1n << 255n]) {
      const data = encodeCall(sel('delLocal(uint256)'), [x]);
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(j.success).toBe(s.success);
      expect(j.returnHex, `delLocal(${x})`).toBe(s.returnHex);
    }
  });
});
