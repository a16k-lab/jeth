// W6C REGRESSION (was a both-accept behavioral divergence, now FIXED): JETH validated a bound /
// sliced enum array EAGERLY at bind time, while solc's calldata->memory convert is a RAW copy
// (calldatacopy semantics) that validates LAZILY at the element read (Panic 0x21). On ABI-invalid
// calldata (an out-of-range enum element), reading a CLEAN element beside the dirty one succeeds
// in solc but Panicked 0x21 in JETH. The same sweep also caught:
//   - `return a.slice(s)` / `return d.tags` MASKED dirty enum words into the returndata (a
//     wrong-bytes miscompile) where solc Panics 0x21 during the re-encode;
//   - the fixed-array bind (`const b: Arr<Color,3> = a`) eagerly EMPTY-reverted (u8 too);
//   - the dyn-of-dyn bind (`Color[][] / u8[][]`) used the wrong flavor (Panic vs solc's
//     eager EMPTY decode-validation).
// FIX (src/yul.ts): the contiguous calldata->memory BIND copies store enum words RAW
// (abiEncFromCd/abiDecFromCdToImage enumRaw, cdSliceToMem, allocAggFromCalldataBase bindContext);
// every consumer of a possibly-dirty memory image validates like solc - the element read
// (lowerArrayGet memory / memElem, Panic 0x21), whole-array encodes (encodeMemArrayReturn,
// materializeArrayArg, abiEncFromMem, encodeReturnTuple, encodeDynFieldInto, topicEncodeDynField,
// buildAbiEncodeStd/lowerEmit inline, materializeStaticAggToMem), the mem->storage copies
// (copyMemArrayIntoStorage, storeStaticAggFromMem), and the offset-table (dyn-of-dyn) bind levels
// force eager EMPTY validation (abiDecFromCdToImage forceValidate). Every shape below is asserted
// byte-identical against a live-compiled solc 0.8.35 twin AND against concrete expectations
// (non-vacuous: clean reads return the seeded member; dirty reads carry the exact Panic payload).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32, type LogEntry } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => pad32(v);
const dyn = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');
const PANIC21 = '0x4e487b71' + pad(0x21n);
const PRAGMA = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

const J = `enum Color { Red, Green, Blue }
type D = { tags: Color[]; n: u256; };
class C {
  Ev: event<{ a: Color[] }>;
  Bad: error<{ a: Arr<Color,3> }>;
  st: Color[];
  fixErr(a: Arr<Color,3>): External<void> { const b: Arr<Color,3> = a; revert(Bad(b)); }
  g(xs: Color[], i: u256): Color { return xs[i]; }
  get bindRead(a: Color[], i: u256): External<Color> { const b: Color[] = a; return b[i]; }
  get sliceRead(a: Color[], s: u256, i: u256): External<Color> { const b: Color[] = a.slice(s); return b[i]; }
  get bindLen(a: Color[]): External<u256> { const b: Color[] = a; return b.length; }
  get bindForOf(a: Color[]): External<u256> { const b: Color[] = a; let n: u256 = 0n; for (const c of b) { n = n + u256(c); } return n; }
  get bindReturn(a: Color[]): External<Color[]> { const b: Color[] = a; return b; }
  get sliceReturn(a: Color[], s: u256): External<Color[]> { return a.slice(s); }
  get bindEncode(a: Color[]): External<bytes> { const b: Color[] = a; return abi.encode(b); }
  get viaInternal(a: Color[], i: u256): External<Color> { return this.g(a, i); }
  emitBind(a: Color[]): External<void> { const b: Color[] = a; emit(Ev(b)); }
  bindStore(a: Color[], i: u256): External<Color> { const b: Color[] = a; this.st = b; return this.st[i]; }
  get fixBindRead(a: Arr<Color,3>, i: u256): External<Color> { const b: Arr<Color,3> = a; return b[i]; }
  get fixBindReturn(a: Arr<Color,3>): External<Arr<Color,3>> { const b: Arr<Color,3> = a; return b; }
  get u8FixBindRead(a: Arr<u8,3>, i: u256): External<u8> { const b: Arr<u8,3> = a; return b[i]; }
  get nestBindRead(a: Arr<Color,2>[], i: u256, j: u256): External<Color> { const b: Arr<Color,2>[] = a; return b[i][j]; }
  get dynDynBind(a: Color[][], i: u256): External<Color> { const b: Color[][] = a; return b[0n][i]; }
  get fieldBind(d: D, i: u256): External<Color> { const t: Color[] = d.tags; return t[i]; }
  get fieldReturn(d: D): External<Color[]> { return d.tags; }
  get tupleRet(a: Color[], i: u256): External<[Color[], u256]> { const b: Color[] = a; return [b, i]; }
  get structRet(a: Color[], i: u256): External<D> { const b: Color[] = a; return D(b, i); }
}`;

const SOL = `${PRAGMA}contract C {
  enum Color { Red, Green, Blue }
  struct D { Color[] tags; uint256 n; }
  event Ev(Color[] a);
  error Bad(Color[3] a);
  Color[] st;
  function fixErr(Color[3] calldata a) external pure { Color[3] memory b = a; revert Bad(b); }
  function g(Color[] memory xs, uint256 i) internal pure returns (Color) { return xs[i]; }
  function bindRead(Color[] calldata a, uint256 i) external pure returns (Color) { Color[] memory b = a; return b[i]; }
  function sliceRead(Color[] calldata a, uint256 s, uint256 i) external pure returns (Color) { Color[] memory b = a[s:]; return b[i]; }
  function bindLen(Color[] calldata a) external pure returns (uint256) { Color[] memory b = a; return b.length; }
  function bindForOf(Color[] calldata a) external pure returns (uint256) { Color[] memory b = a; uint256 n = 0; for (uint256 k = 0; k < b.length; k++) { n = n + uint256(b[k]); } return n; }
  function bindReturn(Color[] calldata a) external pure returns (Color[] memory) { Color[] memory b = a; return b; }
  function sliceReturn(Color[] calldata a, uint256 s) external pure returns (Color[] memory) { return a[s:]; }
  function bindEncode(Color[] calldata a) external pure returns (bytes memory) { Color[] memory b = a; return abi.encode(b); }
  function viaInternal(Color[] calldata a, uint256 i) external pure returns (Color) { return g(a, i); }
  function emitBind(Color[] calldata a) external { Color[] memory b = a; emit Ev(b); }
  function bindStore(Color[] calldata a, uint256 i) external returns (Color) { Color[] memory b = a; st = b; return st[i]; }
  function fixBindRead(Color[3] calldata a, uint256 i) external pure returns (Color) { Color[3] memory b = a; return b[i]; }
  function fixBindReturn(Color[3] calldata a) external pure returns (Color[3] memory) { Color[3] memory b = a; return b; }
  function u8FixBindRead(uint8[3] calldata a, uint256 i) external pure returns (uint8) { uint8[3] memory b = a; return b[i]; }
  function nestBindRead(Color[2][] calldata a, uint256 i, uint256 j) external pure returns (Color) { Color[2][] memory b = a; return b[i][j]; }
  function dynDynBind(Color[][] calldata a, uint256 i) external pure returns (Color) { Color[][] memory b = a; return b[0][i]; }
  function fieldBind(D calldata d, uint256 i) external pure returns (Color) { Color[] memory t = d.tags; return t[i]; }
  function fieldReturn(D calldata d) external pure returns (Color[] memory) { return d.tags; }
  function tupleRet(Color[] calldata a, uint256 i) external pure returns (Color[] memory, uint256) { Color[] memory b = a; return (b, i); }
  function structRet(Color[] calldata a, uint256 i) external pure returns (D memory) { Color[] memory b = a; return D(b, i); }
}`;

// dirty element sets: index 1 carries the poison
const CLEAN = [2n, 1n, 0n];
const OOR = [2n, 3n, 1n]; // 3 >= memberCount(3)
const DIRTYVALID = [2n, 258n, 1n]; // 0x102: dirty high bits, VALID low byte (a mask would hide it)

describe('W6C enum bind/slice lazy validation: byte-identical to solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
    expect(a.map((l) => ({ t: l.topics, d: l.data }))).toEqual(b.map((l) => ({ t: l.topics, d: l.data })));
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    eqLogs(j.logs, s.logs);
    return j;
  }
  beforeAll(async () => {
    const jb = compile(J, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('bind copies RAW: a clean element read beside a dirty one SUCCEEDS (was eager Panic 0x21)', async () => {
    const s = sel('bindRead(uint8[],uint256)');
    // non-vacuous: the clean reads return the seeded members.
    let r = await eq('bindRead OOR i=0', '0x' + s + pad(0x40n) + pad(0n) + dyn(OOR));
    expect(r.success).toBe(true);
    expect(r.returnHex).toBe('0x' + pad(2n));
    r = await eq('bindRead OOR i=2', '0x' + s + pad(0x40n) + pad(2n) + dyn(OOR));
    expect(r.returnHex).toBe('0x' + pad(1n));
    r = await eq('bindRead DIRTYVALID i=0', '0x' + s + pad(0x40n) + pad(0n) + dyn(DIRTYVALID));
    expect(r.returnHex).toBe('0x' + pad(2n));
    for (const i of [0n, 1n, 2n]) await eq(`bindRead CLEAN i=${i}`, '0x' + s + pad(0x40n) + pad(i) + dyn(CLEAN));
  });

  it('reading the DIRTY element from the bound copy Panics 0x21 (raw word survives, no mask)', async () => {
    const s = sel('bindRead(uint8[],uint256)');
    let r = await eq('bindRead OOR i=1', '0x' + s + pad(0x40n) + pad(1n) + dyn(OOR));
    expect(r.success).toBe(false);
    expect(r.returnHex).toBe(PANIC21);
    // 258 has a VALID low byte: a masking copy would return Green(2) - the raw copy must Panic.
    r = await eq('bindRead DIRTYVALID i=1', '0x' + s + pad(0x40n) + pad(1n) + dyn(DIRTYVALID));
    expect(r.success).toBe(false);
    expect(r.returnHex).toBe(PANIC21);
  });

  it('slice bind: clean-in-window reads succeed, dirty reads Panic 0x21, exactly like solc', async () => {
    const s = sel('sliceRead(uint8[],uint256,uint256)');
    const args = (xs: bigint[], st: bigint, i: bigint) => '0x' + s + pad(0x60n) + pad(st) + pad(i) + dyn(xs);
    const ok = await eq('sliceRead OOR s=0 i=0', args(OOR, 0n, 0n));
    expect(ok.success).toBe(true);
    expect(ok.returnHex).toBe('0x' + pad(2n));
    await eq('sliceRead OOR s=0 i=1 (dirty)', args(OOR, 0n, 1n));
    await eq('sliceRead OOR s=1 i=0 (dirty first)', args(OOR, 1n, 0n));
    const past = await eq('sliceRead OOR s=2 i=0 (window past dirty)', args(OOR, 2n, 0n));
    expect(past.success).toBe(true);
    await eq('sliceRead OOB slice', args(OOR, 9n, 0n));
    await eq('sliceRead CLEAN', args(CLEAN, 1n, 1n));
  });

  it('length / for-of / whole-return / abi.encode / emit / storage-store over the bound copy match solc', async () => {
    // length touches no element -> succeeds with a dirty element present.
    const len = await eq('bindLen OOR', '0x' + sel('bindLen(uint8[])') + pad(0x20n) + dyn(OOR));
    expect(len.success).toBe(true);
    expect(len.returnHex).toBe('0x' + pad(3n));
    // every whole-array consumer Panics 0x21 on the dirty word (solc's validator_assert).
    for (const fn of ['bindForOf(uint8[])', 'bindReturn(uint8[])', 'bindEncode(uint8[])', 'emitBind(uint8[])']) {
      const r = await eq(`${fn} OOR`, '0x' + sel(fn) + pad(0x20n) + dyn(OOR));
      expect(r.success).toBe(false);
      expect(r.returnHex).toBe(PANIC21);
      await eq(`${fn} DIRTYVALID`, '0x' + sel(fn) + pad(0x20n) + dyn(DIRTYVALID));
      const clean = await eq(`${fn} CLEAN`, '0x' + sel(fn) + pad(0x20n) + dyn(CLEAN));
      expect(clean.success).toBe(true);
    }
    // mem -> storage copy Panics on the dirty word; the clean store round-trips.
    const st = sel('bindStore(uint8[],uint256)');
    const dirty = await eq('bindStore OOR', '0x' + st + pad(0x40n) + pad(1n) + dyn(OOR));
    expect(dirty.returnHex).toBe(PANIC21);
    const clean = await eq('bindStore CLEAN', '0x' + st + pad(0x40n) + pad(1n) + dyn(CLEAN));
    expect(clean.returnHex).toBe('0x' + pad(1n));
  });

  it('sliceReturn / fieldReturn re-encode Panics 0x21 eagerly (was a MASKED wrong-bytes success)', async () => {
    const sl = sel('sliceReturn(uint8[],uint256)');
    const r = await eq('sliceReturn OOR', '0x' + sl + pad(0x40n) + pad(0n) + dyn(OOR));
    expect(r.success).toBe(false);
    expect(r.returnHex).toBe(PANIC21);
    await eq('sliceReturn DIRTYVALID', '0x' + sl + pad(0x40n) + pad(0n) + dyn(DIRTYVALID));
    const cleanPast = await eq('sliceReturn window past dirty', '0x' + sl + pad(0x40n) + pad(2n) + dyn(OOR));
    expect(cleanPast.success).toBe(true);
    const fr = sel('fieldReturn((uint8[],uint256))');
    const fd = (xs: bigint[]) => '0x' + fr + pad(0x20n) + pad(0x40n) + pad(7n) + dyn(xs);
    const fdirty = await eq('fieldReturn OOR', fd(OOR));
    expect(fdirty.returnHex).toBe(PANIC21);
    const fclean = await eq('fieldReturn CLEAN', fd(CLEAN));
    expect(fclean.success).toBe(true);
  });

  it('internal-call arg copies RAW; the callee element read validates lazily', async () => {
    const s = sel('viaInternal(uint8[],uint256)');
    const ok = await eq('viaInternal OOR i=0', '0x' + s + pad(0x40n) + pad(0n) + dyn(OOR));
    expect(ok.success).toBe(true);
    expect(ok.returnHex).toBe('0x' + pad(2n));
    const bad = await eq('viaInternal OOR i=1', '0x' + s + pad(0x40n) + pad(1n) + dyn(OOR));
    expect(bad.returnHex).toBe(PANIC21);
  });

  it('FIXED Arr<Color,3> bind is raw + lazy; Arr<u8,3> bind masks like solc (was eager EMPTY revert)', async () => {
    const fx = sel('fixBindRead(uint8[3],uint256)');
    const args = (xs: bigint[], i: bigint) => '0x' + fx + xs.map(pad).join('') + pad(i);
    const ok = await eq('fixBindRead OOR i=0', args(OOR, 0n));
    expect(ok.success).toBe(true);
    expect(ok.returnHex).toBe('0x' + pad(2n));
    const bad = await eq('fixBindRead OOR i=1', args(OOR, 1n));
    expect(bad.returnHex).toBe(PANIC21);
    await eq('fixBindRead DIRTYVALID i=1', args(DIRTYVALID, 1n));
    // whole fixed return: Panic on dirty, identical bytes on clean.
    const fr = sel('fixBindReturn(uint8[3])');
    const dirty = await eq('fixBindReturn OOR', '0x' + fr + OOR.map(pad).join(''));
    expect(dirty.returnHex).toBe(PANIC21);
    await eq('fixBindReturn CLEAN', '0x' + fr + CLEAN.map(pad).join(''));
    // u8[3]: solc masks the dirty word at the memory read - a clean 2 comes back for 258.
    const u8 = sel('u8FixBindRead(uint8[3],uint256)');
    const masked = await eq('u8FixBindRead DIRTYVALID i=1', '0x' + u8 + DIRTYVALID.map(pad).join('') + pad(1n));
    expect(masked.success).toBe(true);
    expect(masked.returnHex).toBe('0x' + pad(2n));
  });

  it('custom-error arg from a raw-bound fixed enum array Panics 0x21 (was raw revert data)', async () => {
    const fe = sel('fixErr(uint8[3])');
    const dirty = await eq('fixErr OOR', '0x' + fe + OOR.map(pad).join(''));
    expect(dirty.success).toBe(false);
    expect(dirty.returnHex).toBe(PANIC21); // NOT Bad(...) with the dirty word
    const clean = await eq('fixErr CLEAN', '0x' + fe + CLEAN.map(pad).join(''));
    expect(clean.success).toBe(false);
    expect(clean.returnHex.startsWith('0x' + functionSelector('Bad(uint8[3])'))).toBe(true);
  });

  it('nested Arr<Color,2>[] bind is raw + lazy at the leaf read', async () => {
    const s = sel('nestBindRead(uint8[2][],uint256,uint256)');
    const args = (flat: bigint[], i: bigint, jj: bigint) =>
      '0x' + s + pad(0x60n) + pad(i) + pad(jj) + pad(BigInt(flat.length / 2)) + flat.map(pad).join('');
    const ok = await eq('nestBind clean-beside-dirty', args([2n, 3n, 1n, 0n], 1n, 0n));
    expect(ok.success).toBe(true);
    expect(ok.returnHex).toBe('0x' + pad(1n));
    const bad = await eq('nestBind dirty leaf', args([2n, 3n, 1n, 0n], 0n, 1n));
    expect(bad.returnHex).toBe(PANIC21);
  });

  it('dyn-of-dyn Color[][] bind validates EAGERLY with EMPTY revert (decode flavor), like solc', async () => {
    const s = sel('dynDynBind(uint8[][],uint256)');
    const args = (row: bigint[], i: bigint) => '0x' + s + pad(0x40n) + pad(i) + pad(1n) + pad(0x20n) + dyn(row);
    const bad = await eq('dynDynBind dirty row', args(OOR, 0n));
    expect(bad.success).toBe(false);
    expect(bad.returnHex).toBe('0x'); // EMPTY, not Panic - the offset-table level is decode-validated
    const ok = await eq('dynDynBind clean row', args(CLEAN, 2n));
    expect(ok.success).toBe(true);
    expect(ok.returnHex).toBe('0x' + pad(0n));
  });

  it('struct-field bind (const t = d.tags) is raw + lazy; tuple/struct returns validate on encode', async () => {
    const fb = sel('fieldBind((uint8[],uint256),uint256)');
    const fargs = (xs: bigint[], i: bigint) => '0x' + fb + pad(0x40n) + pad(i) + pad(0x40n) + pad(7n) + dyn(xs);
    const ok = await eq('fieldBind OOR i=0', fargs(OOR, 0n));
    expect(ok.success).toBe(true);
    expect(ok.returnHex).toBe('0x' + pad(2n));
    const bad = await eq('fieldBind OOR i=1', fargs(OOR, 1n));
    expect(bad.returnHex).toBe(PANIC21);
    for (const fn of ['tupleRet(uint8[],uint256)', 'structRet(uint8[],uint256)']) {
      const dirty = await eq(`${fn} OOR`, '0x' + sel(fn) + pad(0x40n) + pad(5n) + dyn(OOR));
      expect(dirty.success).toBe(false);
      expect(dirty.returnHex).toBe(PANIC21);
      const clean = await eq(`${fn} CLEAN`, '0x' + sel(fn) + pad(0x40n) + pad(5n) + dyn(CLEAN));
      expect(clean.success).toBe(true);
    }
  });
});
