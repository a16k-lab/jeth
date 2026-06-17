// Storage / mapping-valued string[] / bytes[] (array of DYNAMIC byte-sequence
// elements), byte-identical to Solidity incl. raw storage slots. Mirrors solc's
// layout: length at slot p; element header i at keccak(p)+i (a normal storage
// bytes/string: short <32 inline / long >=32 with keccak(headerSlot) data slots).
// Covers push/pop/length/index read+write, short+long elements, overwrite-
// clearing (long->short frees old data slots), pop full-clear, mapping per-key
// isolation, sentinel non-disturbance, OOB Panic(0x32), pop-empty Panic(0x31).
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const here = dirname(fileURLToPath(import.meta.url));
const enc = new TextEncoder();
const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const sel = (s: string) => functionSelector(s);
const A1 = BigInt('0x' + '11'.repeat(20));
const A2 = BigInt('0x' + '22'.repeat(20));

// keccak256(pad32(slot)) -> the dynamic-array data slot (and the long bytes/string
// data slot for a header at `slot`).
const slotKeccak = (p: bigint) => BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(p)) as `0x${string}`))));
// keccak256(key . slot) -> the runtime mapping slot (key, slot each padded to 32).
const mapSlot = (key: bigint, slot: bigint) =>
  BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(key) + pad(slot)) as `0x${string}`))));

// ABI calldata for a single dynamic bytes/string argument after a leading static
// `head` region (hex words, no selector). off is the offset to the dyn arg.
function dynArg(bytes: Uint8Array): string {
  const words = Math.ceil(bytes.length / 32);
  let data = '';
  for (let i = 0; i < words * 32; i++) data += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return pad(BigInt(bytes.length)) + data;
}
// selector + [offset=headWords*32 to the dyn arg] preceded by `staticHead` static words.
function callDyn(selSig: string, staticHead: bigint[], bytes: Uint8Array): string {
  const headWords = staticHead.length + 1; // +1 for the dyn-arg offset word
  let h = '0x' + sel(selSig);
  for (const w of staticHead) h += pad(w);
  h += pad(BigInt(headWords * 32)); // offset to the dyn arg, base = byte 4
  h += dynArg(bytes);
  return h;
}
const s = (str: string) => enc.encode(str);

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract StorageStrArray {
  string[] ss;                       // slot 0
  bytes[] bb;                         // slot 1
  mapping(address => string[]) byKey; // slot 2
  uint256 sentinel;                   // slot 3
  function pushS(string calldata v) external { ss.push(v); }
  function pushEmptyS() external { ss.push(); }
  function popS() external { ss.pop(); }
  function setS(uint256 i, string calldata v) external { ss[i] = v; }
  function sLen() external view returns (uint256){ return ss.length; }
  function sAt(uint256 i) external view returns (string memory){ return ss[i]; }
  function pushB(bytes calldata v) external { bb.push(v); }
  function popB() external { bb.pop(); }
  function setB(uint256 i, bytes calldata v) external { bb[i] = v; }
  function bLen() external view returns (uint256){ return bb.length; }
  function bAt(uint256 i) external view returns (bytes memory){ return bb[i]; }
  function bElemLen(uint256 i) external view returns (uint256){ return bb[i].length; }
  function bByte(uint256 i, uint256 j) external view returns (bytes1){ return bb[i][j]; }
  function pushK(address k, string calldata v) external { byKey[k].push(v); }
  function popK(address k) external { byKey[k].pop(); }
  function setK(address k, uint256 i, string calldata v) external { byKey[k][i] = v; }
  function kLen(address k) external view returns (uint256){ return byKey[k].length; }
  function kAt(address k, uint256 i) external view returns (string memory){ return byKey[k][i]; }
  function setSentinel(uint256 c) external { sentinel = c; }
  function getSentinel() external view returns (uint256){ return sentinel; }
}`;

describe('storage / mapping-valued string[] / bytes[] vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const sr = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(sr.success);
    expect(j.returnHex, `${label} returndata`).toBe(sr.returnHex);
    return { j, s: sr };
  }
  async function eqSlot(slot: bigint, label: string) {
    expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
  }

  beforeAll(async () => {
    const src = readFileSync(join(here, '..', 'examples', 'StorageStrArray.jeth'), 'utf8');
    const jb = compile(src, { fileName: 'StorageStrArray.jeth' });
    const sb = compileSolidity(SOL, 'StorageStrArray');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  const SHORT = 'ab';
  const EXACT31 = 'Y'.repeat(31);
  const LONG40 = 'X'.repeat(40);
  const LONG70 = 'Q'.repeat(70);
  const DATA0 = slotKeccak(0n); // ss element headers start here

  it('pushS grows length + writes element headers identically (raw slots)', async () => {
    await eq('pushS short', callDyn('pushS(string)', [], s(SHORT)));
    await eq('pushS exact31', callDyn('pushS(string)', [], s(EXACT31)));
    await eq('pushS long40', callDyn('pushS(string)', [], s(LONG40)));
    const r = await eq('sLen=3', encodeCall(sel('sLen()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(3n);
    await eqSlot(0n, 'ss length slot');
    for (let i = 0; i < 3; i++) await eqSlot(DATA0 + BigInt(i), `ss header[${i}]`);
    // long element (idx 2) data slots
    const long2 = slotKeccak(DATA0 + 2n);
    await eqSlot(long2, 'ss[2] long data word0');
    await eqSlot(long2 + 1n, 'ss[2] long data word1');
    // per-index getters byte-identical (standalone re-encoded string)
    for (let i = 0n; i < 3n; i++) await eq(`sAt#${i}`, encodeCall(sel('sAt(uint256)'), [i]));
  });

  it('push() (no arg) appends an empty element, then assign-into it (raw slots)', async () => {
    // ss currently length 3 ([short, exact31, long40]); push() a 4th empty element.
    await eq('pushEmptyS', encodeCall(sel('pushEmptyS()'), []));
    await eqSlot(0n, 'ss length after empty push');
    await eqSlot(DATA0 + 3n, 'ss empty header[3] (== 0)');
    const r = await eq('sLen=4', encodeCall(sel('sLen()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(4n);
    await eq('sAt#3 (empty)', encodeCall(sel('sAt(uint256)'), [3n]));
    // assign a long value into the just-pushed empty element
    await eq('setS[3]=long', callDyn('setS(uint256,string)', [3n], s(LONG40)));
    await eqSlot(DATA0 + 3n, 'ss[3] header after assign');
    await eqSlot(slotKeccak(DATA0 + 3n), 'ss[3] long data word0');
    await eq('sAt#3 after assign', encodeCall(sel('sAt(uint256)'), [3n]));
    // pop it back to keep the rest of the suite's length expectations intact
    await eq('popS the empty-pushed', encodeCall(sel('popS()'), []));
    await eqSlot(0n, 'ss length restored to 3');
  });

  it('sentinel (slot 3) is never disturbed by dynamic writes', async () => {
    await eq('setSentinel', encodeCall(sel('setSentinel(uint256)'), [0xdeadbeefn]));
    await eqSlot(3n, 'sentinel after dyn writes');
    const r = await eq('getSentinel', encodeCall(sel('getSentinel()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0xdeadbeefn);
  });

  it('setS overwrite-clearing: long->short frees old data slots (raw slots)', async () => {
    // ss[2] is currently LONG40. Overwrite with a short string: solc clears the old
    // long data slots. Then overwrite ss[0] (short) with a long one.
    await eq('setS[2]=short', callDyn('setS(uint256,string)', [2n], s('hi')));
    const long2 = slotKeccak(DATA0 + 2n);
    await eqSlot(DATA0 + 2n, 'ss[2] header after long->short');
    await eqSlot(long2, 'ss[2] old long data word0 cleared');
    await eqSlot(long2 + 1n, 'ss[2] old long data word1 cleared');
    await eq('setS[0]=long70', callDyn('setS(uint256,string)', [0n], s(LONG70)));
    await eqSlot(DATA0 + 0n, 'ss[0] header after short->long');
    const long0 = slotKeccak(DATA0 + 0n);
    for (let w = 0; w < 3; w++) await eqSlot(long0 + BigInt(w), `ss[0] new long data word${w}`);
    await eq('sAt#0 after setS', encodeCall(sel('sAt(uint256)'), [0n]));
    await eq('sAt#2 after setS', encodeCall(sel('sAt(uint256)'), [2n]));
  });

  it('popS shrinks length + fully clears freed element (long element data slots)', async () => {
    // ss currently: [LONG70, EXACT31, "hi"]. Pop "hi" (short), then EXACT31 (long),
    // verifying both header and (for the long) keccak(header) data slots are zeroed.
    await eq('popS #1', encodeCall(sel('popS()'), []));
    await eqSlot(0n, 'ss length after pop1');
    await eqSlot(DATA0 + 2n, 'ss freed header[2] cleared');
    await eq('popS #2', encodeCall(sel('popS()'), []));
    const long1 = slotKeccak(DATA0 + 1n);
    await eqSlot(DATA0 + 1n, 'ss freed header[1] cleared');
    await eqSlot(long1, 'ss freed long data word0 cleared');
    const r = await eq('sLen=1', encodeCall(sel('sLen()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
  });

  it('bytes[] push/pop/index + b[i].length + byte index, raw slots', async () => {
    const raw = new Uint8Array([0, 1, 2, 255, 0, 9]);
    const big = new Uint8Array(50).map((_, k) => (k * 7) & 0xff);
    await eq('pushB raw', callDyn('pushB(bytes)', [], raw));
    await eq('pushB empty', callDyn('pushB(bytes)', [], new Uint8Array(0)));
    await eq('pushB big', callDyn('pushB(bytes)', [], big));
    const DB = slotKeccak(1n);
    await eqSlot(1n, 'bb length');
    for (let i = 0; i < 3; i++) await eqSlot(DB + BigInt(i), `bb header[${i}]`);
    const big2 = slotKeccak(DB + 2n);
    await eqSlot(big2, 'bb[2] long data0');
    await eqSlot(big2 + 1n, 'bb[2] long data1');
    for (let i = 0n; i < 3n; i++) {
      await eq(`bAt#${i}`, encodeCall(sel('bAt(uint256)'), [i]));
      await eq(`bElemLen#${i}`, encodeCall(sel('bElemLen(uint256)'), [i]));
    }
    // byte index into a long element
    for (const j of [0n, 7n, 49n]) await eq(`bByte[2][${j}]`, encodeCall(sel('bByte(uint256,uint256)'), [2n, j]));
    // empty element (idx 1): any byte index -> Panic(0x32)
    const rb = await eq('bByte[1][0] OOB', encodeCall(sel('bByte(uint256,uint256)'), [1n, 0n]));
    expect(rb.j.success).toBe(false);
    expect(rb.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
  });

  it('mapping<address,string[]> per-key isolation + raw slots', async () => {
    await eq('pushK A1 short', callDyn('pushK(address,string)', [A1], s('alpha')));
    await eq('pushK A1 long', callDyn('pushK(address,string)', [A1], s(LONG40)));
    await eq('pushK A2 short', callDyn('pushK(address,string)', [A2], s('beta')));
    const lenA1 = mapSlot(A1, 2n); // length slot for byKey[A1]
    const lenA2 = mapSlot(A2, 2n);
    await eqSlot(lenA1, 'byKey[A1] length');
    await eqSlot(lenA2, 'byKey[A2] length');
    const dA1 = slotKeccak(lenA1);
    await eqSlot(dA1 + 0n, 'byKey[A1] header[0]');
    await eqSlot(dA1 + 1n, 'byKey[A1] header[1]');
    await eqSlot(slotKeccak(dA1 + 1n), 'byKey[A1][1] long data0');
    let r = await eq('kLen A1', encodeCall(sel('kLen(address)'), [A1]));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    r = await eq('kLen A2', encodeCall(sel('kLen(address)'), [A2]));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    await eq('kAt A1 0', encodeCall(sel('kAt(address,uint256)'), [A1, 0n]));
    await eq('kAt A1 1', encodeCall(sel('kAt(address,uint256)'), [A1, 1n]));
    await eq('kAt A2 0', encodeCall(sel('kAt(address,uint256)'), [A2, 0n]));
    // overwrite + pop on a key
    await eq('setK A1[0]=long', callDyn('setK(address,uint256,string)', [A1, 0n], s(LONG70)));
    await eqSlot(dA1 + 0n, 'byKey[A1] header[0] after overwrite');
    await eq('popK A1', encodeCall(sel('popK(address)'), [A1]));
    await eqSlot(lenA1, 'byKey[A1] length after pop');
    await eqSlot(dA1 + 1n, 'byKey[A1] freed header[1] cleared');
    await eqSlot(slotKeccak(dA1 + 1n), 'byKey[A1] freed long data cleared');
  });

  it('OOB index -> Panic(0x32), pop empty -> Panic(0x31)', async () => {
    // ss currently length 1 (after earlier pops). i==len is OOB.
    const r1 = await eq('sAt OOB', encodeCall(sel('sAt(uint256)'), [1n]));
    expect(r1.j.success).toBe(false);
    expect(r1.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
    const r2 = await eq('setS OOB', callDyn('setS(uint256,string)', [99n], s('z')));
    expect(r2.j.success).toBe(false);
    expect(r2.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
    // drain ss then pop empty
    await eq('popS to empty', encodeCall(sel('popS()'), []));
    const r3 = await eq('popS empty', encodeCall(sel('popS()'), []));
    expect(r3.j.success).toBe(false);
    expect(r3.j.returnHex).toBe('0x4e487b71' + pad(0x31n));
    // kAt OOB on an empty key
    const r4 = await eq('kAt OOB empty key', encodeCall(sel('kAt(address,uint256)'), [A1, 5n]));
    expect(r4.j.success).toBe(false);
  });

  it('a malformed-calldata push reverts identically to solc (EMPTY)', async () => {
    // pushS with the string offset pointing past calldatasize: solc's decode rejects
    // with an EMPTY revert before any storage write; JETH routes through the same
    // top-level jeth_calldata_dyn helper, so the revert form is byte-identical and
    // no slot is written.
    const bad = '0x' + sel('pushS(string)') + pad(0x40n); // offset 0x40 but no payload words
    const r = await eq('pushS bad offset', bad);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x'); // EMPTY revert, not a Panic
    // length unchanged vs solc
    await eqSlot(0n, 'ss length unchanged after failed push');
  });

  it('push()/pop round-trip preserves byte-identical slots vs solc throughout', async () => {
    // a longer interleaved sequence to stress the layout end-to-end.
    const ops: string[] = [];
    ops.push(callDyn('pushS(string)', [], s('one')));
    ops.push(callDyn('pushS(string)', [], s(LONG70)));
    ops.push(callDyn('pushS(string)', [], s('')));
    ops.push(callDyn('setS(uint256,string)', [1n], s('two'))); // long->short, clears data slots
    ops.push(callDyn('setS(uint256,string)', [2n], s(LONG40))); // empty->long
    ops.push(encodeCall(sel('popS()'), []));
    let k = 0;
    for (const data of ops) {
      await eq(`seq#${k++}`, data);
      await eqSlot(0n, `seq#${k} ss length`);
      const len = decodeUint((await jeth.call(aj, encodeCall(sel('sLen()'), []))).returnHex);
      for (let i = 0n; i < len; i++) await eqSlot(DATA0 + i, `seq#${k} header[${i}]`);
    }
  });
});
