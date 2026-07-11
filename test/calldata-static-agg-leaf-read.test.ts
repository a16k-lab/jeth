// S4: reading a WHOLE STATIC-AGGREGATE LEAF (a nested static struct, or a static fixed array)
// from a FULLY-STATIC outer struct / fixed-array CALLDATA param, as an aggregate value:
//   abi.encode(n.inner) / return n.inner / return n.arr / return n.inner.d.
// The leaf is COPIED from its calldata head into a fresh memory image THROUGH per-word
// validation (validateInput on each constituent static word), byte-identical to a memory-local
// static-aggregate image. The DIRTY-WORD trap is load-bearing: a bool word != 0/1 or an address
// word with dirty high 12 bytes EMPTY-reverts on BOTH sides (solc validates lazily on access), so
// a blind calldatacopy would over-accept = MISCOMPILE. Static-aggregate calldata is the selector
// followed by flat inline words, so we hand-craft it directly (VACUOUS-SELECTOR TRAP: a struct
// param dispatches on the EXPANDED-TUPLE selector; each test also reads a scalar field n.k -> a
// known value to PROVE the selector routes non-vacuously).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { CompileError } from '../src/diagnostics.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const w = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const raw = (h: string) => h.replace(/^0x/, '').toLowerCase().padStart(64, '0');
const call = (sig: string, words: (bigint | string)[]) =>
  sel(sig) + words.map((x) => (typeof x === 'bigint' ? w(x) : raw(x))).join('');

function jethCodes(src: string): string[] | null {
  try {
    compile(src, { fileName: 'C.jeth' });
    return null;
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.filter((d) => d.severity === 'error').map((d) => d.code);
    throw e;
  }
}

const JETH = `type Inner = { a: u256; b: u256 };
type D = { x: u256; y: u256 };
type Deep = { d: D; z: u256 };
type Flags = { on: bool; who: address; n: u256 };
type Nest = { inner: Inner; k: u256 };
type NestArr = { arr: Arr<u256, 2>; k: u256 };
type NestArr2 = { g: Arr<Arr<u256, 2>, 2>; k: u256 };
type NestDeep = { inner: Deep; k: u256 };
type NestFlags = { fl: Flags; k: u256 };
type NestBoolArr = { bs: Arr<bool, 3>; k: u256 };
type NestStructArr = { fa: Arr<Flags, 2>; k: u256 };
class C {
  get encBools(n: NestBoolArr): External<bytes> { return abi.encode(n.bs); }
  get retBools(n: NestBoolArr): External<Arr<bool, 3>> { return n.bs; }
  get kBools(n: NestBoolArr): External<u256> { return n.k; }
  get retStructArr(n: NestStructArr): External<Arr<Flags, 2>> { return n.fa; }
  get encStructArr(n: NestStructArr): External<bytes> { return abi.encode(n.fa); }
  get kStructArr(n: NestStructArr): External<u256> { return n.k; }

  get encInner(n: Nest): External<bytes> { return abi.encode(n.inner); }
  get retInner(n: Nest): External<Inner> { return n.inner; }
  get kNest(n: Nest): External<u256> { return n.k; }

  get encArr(n: NestArr): External<bytes> { return abi.encode(n.arr); }
  get retArr(n: NestArr): External<Arr<u256, 2>> { return n.arr; }
  get kArr(n: NestArr): External<u256> { return n.k; }

  get encArr2(n: NestArr2): External<bytes> { return abi.encode(n.g); }
  get retArr2(n: NestArr2): External<Arr<Arr<u256, 2>, 2>> { return n.g; }
  get kArr2(n: NestArr2): External<u256> { return n.k; }

  get encDeep(n: NestDeep): External<bytes> { return abi.encode(n.inner.d); }
  get retDeep(n: NestDeep): External<D> { return n.inner.d; }
  get encDeepWhole(n: NestDeep): External<bytes> { return abi.encode(n.inner); }
  get kDeep(n: NestDeep): External<u256> { return n.k; }

  get encFlags(n: NestFlags): External<bytes> { return abi.encode(n.fl); }
  get retFlags(n: NestFlags): External<Flags> { return n.fl; }
  get kFlags(n: NestFlags): External<u256> { return n.k; }

  // fixed-array OUTER param root: read a whole static struct element ps[1]
  get encElem(ps: Arr<Inner, 3>): External<bytes> { return abi.encode(ps[1n]); }
  get retElem(ps: Arr<Inner, 3>): External<Inner> { return ps[1n]; }
  get kElem(ps: Arr<Inner, 3>): External<u256> { return ps[2n].b; }

  // control: memory-local n.inner (MATCH, unregressed)
  get encMemLocal(n: Nest): External<bytes> { let m: Nest = n; return abi.encode(m.inner); }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Inner { uint256 a; uint256 b; }
  struct D { uint256 x; uint256 y; }
  struct Deep { D d; uint256 z; }
  struct Flags { bool on; address who; uint256 n; }
  struct Nest { Inner inner; uint256 k; }
  struct NestArr { uint256[2] arr; uint256 k; }
  struct NestArr2 { uint256[2][2] g; uint256 k; }
  struct NestDeep { Deep inner; uint256 k; }
  struct NestFlags { Flags fl; uint256 k; }
  struct NestBoolArr { bool[3] bs; uint256 k; }
  struct NestStructArr { Flags[2] fa; uint256 k; }
  function encBools(NestBoolArr calldata n) external pure returns (bytes memory){ return abi.encode(n.bs); }
  function retBools(NestBoolArr calldata n) external pure returns (bool[3] memory){ return n.bs; }
  function kBools(NestBoolArr calldata n) external pure returns (uint256){ return n.k; }
  function retStructArr(NestStructArr calldata n) external pure returns (Flags[2] memory){ return n.fa; }
  function encStructArr(NestStructArr calldata n) external pure returns (bytes memory){ return abi.encode(n.fa); }
  function kStructArr(NestStructArr calldata n) external pure returns (uint256){ return n.k; }
  function encInner(Nest calldata n) external pure returns (bytes memory){ return abi.encode(n.inner); }
  function retInner(Nest calldata n) external pure returns (Inner memory){ return n.inner; }
  function kNest(Nest calldata n) external pure returns (uint256){ return n.k; }
  function encArr(NestArr calldata n) external pure returns (bytes memory){ return abi.encode(n.arr); }
  function retArr(NestArr calldata n) external pure returns (uint256[2] memory){ return n.arr; }
  function kArr(NestArr calldata n) external pure returns (uint256){ return n.k; }
  function encArr2(NestArr2 calldata n) external pure returns (bytes memory){ return abi.encode(n.g); }
  function retArr2(NestArr2 calldata n) external pure returns (uint256[2][2] memory){ return n.g; }
  function kArr2(NestArr2 calldata n) external pure returns (uint256){ return n.k; }
  function encDeep(NestDeep calldata n) external pure returns (bytes memory){ return abi.encode(n.inner.d); }
  function retDeep(NestDeep calldata n) external pure returns (D memory){ return n.inner.d; }
  function encDeepWhole(NestDeep calldata n) external pure returns (bytes memory){ return abi.encode(n.inner); }
  function kDeep(NestDeep calldata n) external pure returns (uint256){ return n.k; }
  function encFlags(NestFlags calldata n) external pure returns (bytes memory){ return abi.encode(n.fl); }
  function retFlags(NestFlags calldata n) external pure returns (Flags memory){ return n.fl; }
  function kFlags(NestFlags calldata n) external pure returns (uint256){ return n.k; }
  function encElem(Inner[3] calldata ps) external pure returns (bytes memory){ return abi.encode(ps[1]); }
  function retElem(Inner[3] calldata ps) external pure returns (Inner memory){ return ps[1]; }
  function kElem(Inner[3] calldata ps) external pure returns (uint256){ return ps[2].b; }
  function encMemLocal(Nest calldata n) external pure returns (bytes memory){ Nest memory m = n; return abi.encode(m.inner); }
}`;

const ADDR = 'aabbccddeeff00112233445566778899aabbccdd';

describe('S4: whole static-aggregate LEAF read from a fully-static calldata param vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, sig: string, words: (bigint | string)[], expected?: string) {
    const data = call(sig, words);
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label}: success parity (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label}: returndata parity`).toBe(s.returnHex);
    if (expected !== undefined) expect(j.returnHex, `${label}: expected value`).toBe(expected);
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('nested static struct leaf: abi.encode(n.inner) + return n.inner (byte-identical to expected)', async () => {
    const args = [7n, 9n, 42n]; // inner.a=7, inner.b=9, k=42
    // abi.encode(Inner{7,9}) = [0x20][0x40][7][9]
    await eq('encInner', 'encInner(((uint256,uint256),uint256))', args, '0x' + w(0x20n) + w(0x40n) + w(7n) + w(9n));
    // return n.inner (Inner memory) = flat [7][9], no wrapper
    await eq('retInner', 'retInner(((uint256,uint256),uint256))', args, '0x' + w(7n) + w(9n));
    // NON-VACUITY: n.k must route to 42
    await eq('kNest', 'kNest(((uint256,uint256),uint256))', args, '0x' + w(42n));
  });

  it('static fixed-array leaf: abi.encode(n.arr) + return n.arr', async () => {
    const args = [11n, 22n, 33n]; // arr=[11,22], k=33
    await eq('encArr', 'encArr((uint256[2],uint256))', args, '0x' + w(0x20n) + w(0x40n) + w(11n) + w(22n));
    await eq('retArr', 'retArr((uint256[2],uint256))', args, '0x' + w(11n) + w(22n));
    await eq('kArr', 'kArr((uint256[2],uint256))', args, '0x' + w(33n));
  });

  it('nested static fixed array leaf Arr<Arr<u256,2>,2>: encode + return', async () => {
    const args = [1n, 2n, 3n, 4n, 55n];
    await eq('encArr2', 'encArr2((uint256[2][2],uint256))', args, '0x' + w(0x20n) + w(0x80n) + w(1n) + w(2n) + w(3n) + w(4n));
    await eq('retArr2', 'retArr2((uint256[2][2],uint256))', args, '0x' + w(1n) + w(2n) + w(3n) + w(4n));
    await eq('kArr2', 'kArr2((uint256[2][2],uint256))', args, '0x' + w(55n));
  });

  it('2-level nested static struct leaf n.inner.d + whole n.inner', async () => {
    const args = [5n, 6n, 7n, 8n]; // d.x=5, d.y=6, inner.z=7, k=8
    await eq('encDeep', 'encDeep((((uint256,uint256),uint256),uint256))', args, '0x' + w(0x20n) + w(0x40n) + w(5n) + w(6n));
    await eq('retDeep', 'retDeep((((uint256,uint256),uint256),uint256))', args, '0x' + w(5n) + w(6n));
    // whole n.inner (Deep = {D d; uint256 z}) flat inline = [5][6][7]
    await eq('encDeepWhole', 'encDeepWhole((((uint256,uint256),uint256),uint256))', args, '0x' + w(0x20n) + w(0x60n) + w(5n) + w(6n) + w(7n));
    await eq('kDeep', 'kDeep((((uint256,uint256),uint256),uint256))', args, '0x' + w(8n));
  });

  it('static struct with a bool + address field (CLEAN words -> byte-identical)', async () => {
    const clean = [1n, ADDR, 77n, 88n]; // on=1, who=ADDR, n=77, k=88
    await eq('encFlags', 'encFlags(((bool,address,uint256),uint256))', clean,
      '0x' + w(0x20n) + w(0x60n) + w(1n) + raw(ADDR) + w(77n));
    await eq('retFlags', 'retFlags(((bool,address,uint256),uint256))', clean,
      '0x' + w(1n) + raw(ADDR) + w(77n));
    await eq('kFlags', 'kFlags(((bool,address,uint256),uint256))', clean, '0x' + w(88n));
  });

  it('DIRTY-WORD trap: a bool != 0/1 word EMPTY-reverts on BOTH sides (encode + return)', async () => {
    const dirtyBool = [2n, ADDR, 77n, 88n]; // on=2 (not 0/1)
    const jE = await jeth.call(aj, call('encFlags(((bool,address,uint256),uint256))', dirtyBool));
    const sE = await sol.call(as, call('encFlags(((bool,address,uint256),uint256))', dirtyBool));
    expect(jE.success, 'dirty bool: jeth reverts').toBe(false);
    expect(sE.success, 'dirty bool: solc reverts').toBe(false);
    expect(jE.returnHex, 'dirty bool: empty revert (encode)').toBe(sE.returnHex);
    expect(jE.returnHex).toBe('0x');
    const jR = await jeth.call(aj, call('retFlags(((bool,address,uint256),uint256))', dirtyBool));
    const sR = await sol.call(as, call('retFlags(((bool,address,uint256),uint256))', dirtyBool));
    expect(jR.success).toBe(false);
    expect(sR.success).toBe(false);
    expect(jR.returnHex, 'dirty bool: empty revert (return)').toBe(sR.returnHex);
    expect(jR.returnHex).toBe('0x');
  });

  it('DIRTY-WORD trap: an address word with dirty high 12 bytes EMPTY-reverts on BOTH sides', async () => {
    const dirtyAddr = 'ffffffffffff000000000000' + ADDR; // dirty high bytes
    const args = [1n, dirtyAddr, 77n, 88n];
    const jE = await jeth.call(aj, call('encFlags(((bool,address,uint256),uint256))', args));
    const sE = await sol.call(as, call('encFlags(((bool,address,uint256),uint256))', args));
    expect(jE.success, 'dirty addr: jeth reverts').toBe(false);
    expect(sE.success, 'dirty addr: solc reverts').toBe(false);
    expect(jE.returnHex, 'dirty addr: empty revert parity').toBe(sE.returnHex);
    expect(jE.returnHex).toBe('0x');
  });

  it('fixed-array OUTER param root: whole static struct element ps[1]', async () => {
    const args = [10n, 11n, 20n, 21n, 30n, 31n];
    await eq('encElem', 'encElem((uint256,uint256)[3])', args, '0x' + w(0x20n) + w(0x40n) + w(20n) + w(21n));
    await eq('retElem', 'retElem((uint256,uint256)[3])', args, '0x' + w(20n) + w(21n));
    await eq('kElem', 'kElem((uint256,uint256)[3])', args, '0x' + w(31n)); // ps[2].b = 31
  });

  it('VALUE-LEAF fixed-array leaf bool[3]: return MASKS a dirty bool, abi.encode VALIDATES (reverts)', async () => {
    // solc decode-to-MEMORY of a value-leaf fixed array (`return n.bs`) CLEANS/masks dirty leaf words
    // (no revert), byte-identical to a memory-local return; but abi.encode reads from calldata and
    // VALIDATES each element (a dirty bool EMPTY-reverts). This asymmetry is load-bearing: a blind
    // validate-on-return would OVER-REJECT; a blind mask-on-encode would be a MISCOMPILE.
    const cleanArgs = [1n, 0n, 1n, 5n]; // bs=[1,0,1], k=5
    await eq('retBools-clean', 'retBools((bool[3],uint256))', cleanArgs, '0x' + w(1n) + w(0n) + w(1n));
    await eq('encBools-clean', 'encBools((bool[3],uint256))', cleanArgs, '0x' + w(0x20n) + w(0x60n) + w(1n) + w(0n) + w(1n));
    await eq('kBools', 'kBools((bool[3],uint256))', cleanArgs, '0x' + w(5n));

    // dirty third bool word = 0x60 (not 0/1).
    const dirty = call('retBools((bool[3],uint256))', [1n, 0n, 0x60n, 5n]);
    const jR = await jeth.call(aj, dirty);
    const sR = await sol.call(as, dirty);
    expect(jR.success, 'return: jeth masks (no revert)').toBe(true);
    expect(sR.success, 'return: solc masks (no revert)').toBe(true);
    expect(jR.returnHex, 'return: masked bytes parity').toBe(sR.returnHex);
    // 0x60 masked to a bool -> element reads as 1 (solc's convert-to-memory clean is bit-0? no: solc
    // reads the raw word and the ABI re-encode of a bool cleans to (word != 0) -> 1). Assert parity + shape.
    expect(jR.returnHex).toBe('0x' + w(1n) + w(0n) + w(1n));

    const dirtyEnc = call('encBools((bool[3],uint256))', [1n, 0n, 0x60n, 5n]);
    const jE = await jeth.call(aj, dirtyEnc);
    const sE = await sol.call(as, dirtyEnc);
    expect(jE.success, 'encode: jeth validates (reverts)').toBe(false);
    expect(sE.success, 'encode: solc validates (reverts)').toBe(false);
    expect(jE.returnHex, 'encode: empty-revert parity').toBe(sE.returnHex);
    expect(jE.returnHex).toBe('0x');
  });

  it('STATIC-STRUCT-leaf fixed-array leaf Arr<Flags,2>: return AND encode both VALIDATE dirty struct-field words', async () => {
    // A fixed array whose element is a STRUCT (not a value word) always validates each struct-field
    // word on both `return` and `abi.encode` (dirty bool/address EMPTY-reverts) - distinct from the
    // value-leaf array which masks on return. Proves the validate rule keys on the ARRAY LEAF type.
    // Flags = {bool on; address who; uint256 n} (3 fields) -> element tuple (bool,address,uint256).
    const sig = '(((bool,address,uint256)[2],uint256))';
    // fa=[{1,ADDR,10},{0,ADDR,20}], k=7
    const clean = [1n, ADDR, 10n, 0n, ADDR, 20n, 7n];
    const elemsInline = w(1n) + raw(ADDR) + w(10n) + w(0n) + raw(ADDR) + w(20n);
    // return Flags[2] memory: flat inline (no wrapper), byte-identical to the expected element words.
    await eq('retStructArr-clean', 'retStructArr' + sig, clean, '0x' + elemsInline);
    // abi.encode(Flags[2]) wraps as a one-element tuple with the inline body; assert JETH==solc parity
    // (the exact head-offset layout is solc's to define; the return + non-vacuity cells pin the value).
    await eq('encStructArr-clean', 'encStructArr' + sig, clean);
    await eq('kStructArr', 'kStructArr' + sig, clean, '0x' + w(7n));

    // dirty bool in element 0 -> BOTH revert empty on return AND encode.
    const dirty = [2n, ADDR, 10n, 0n, ADDR, 20n, 7n];
    for (const fn of ['retStructArr', 'encStructArr']) {
      const jD = await jeth.call(aj, call(fn + sig, dirty));
      const sD = await sol.call(as, call(fn + sig, dirty));
      expect(jD.success, `${fn} dirty bool: jeth reverts`).toBe(false);
      expect(sD.success, `${fn} dirty bool: solc reverts`).toBe(false);
      expect(jD.returnHex, `${fn} dirty bool: empty-revert parity`).toBe(sD.returnHex);
      expect(jD.returnHex).toBe('0x');
    }
  });

  it('memory-local n.inner still MATCH (unregressed)', async () => {
    const args = [7n, 9n, 42n];
    await eq('encMemLocal', 'encMemLocal(((uint256,uint256),uint256))', args, '0x' + w(0x20n) + w(0x40n) + w(7n) + w(9n));
  });

  // ---- KEPT rejects / read-only (compile-time) ----
  it('assignment to n.inner is read-only -> JETH214', () => {
    const src = `type Inner = { a: u256; b: u256 };
type Nest = { inner: Inner; k: u256 };
class C { get f(n: Nest): External<u256> { n.inner = n.inner; return 1n; } }`;
    expect(jethCodes(src)).toContain('JETH214');
  });

  it('const-OOB fixed-array leaf index still rejects (JETH211)', () => {
    const src = `type NestArr2 = { g: Arr<Arr<u256,2>,2>; k: u256 };
class C { get f(n: NestArr2): External<bytes> { return abi.encode(n.g[5n]); } }`;
    expect(jethCodes(src)).toContain('JETH211');
  });

  it('a funcref-containing aggregate leaf still rejects (isStaticType excludes funcref)', () => {
    const src = `type F = { cb: (x: u256) => u256; n: u256 };
type Nest = { f: F; k: u256 };
class C { f(n: Nest): External<bytes> { return abi.encode(n.f); } }`;
    expect(jethCodes(src)).not.toBeNull();
  });
});
