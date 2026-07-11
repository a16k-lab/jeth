// LIFT: cd-to-mem-copy. Copy a CALLDATA reference-element array (bytes[] / string[] / u256[][] /
// P[] static struct) into a MEMORY value, in two positions:
//   (A) a local binding              let row: bytes[] = a;   (a is `bytes[] calldata`)
//   (B) a struct-constructor field    P(7n, t)               (P = {a:u256; tags:bytes[]}, t is `bytes[] calldata`)
//
// solc DEEP-COPIES the calldata array into a fresh pointer-headed memory image. JETH now does the same
// via abiDecFromCdToImage with the MEMORY allocation cap (Panic 0x41), matching solc's calldata->memory
// copy revert semantics: an oversized inner length / alloc overflow Panics 0x41 (the memory allocation
// guard, NOT the calldata-decode empty revert), while a truncated / OOB source EMPTY-reverts.
//
// INVARIANT: byte-identical to solc on (success, returnHex) for honest AND malformed calldata. A
// value-element copy (let row: u256[] = a) and a value-element constructor field (Q(7n, valArr)) are
// UNCHANGED (they already worked, via echoParam / aggArgToMemPtr); we re-assert them as a no-regression
// guard. The storage-source reference-element copy is now LIFTED too (its own suite is
// test/_storage_to_mem_copy.test.ts); a DYNAMIC-struct-element array (D[]) calldata copy stays a clean
// reject (deferred); we assert it still rejects loudly (never a miscompile).
import { describe, it, expect, beforeAll } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const P = (v: bigint | number) => pad32(BigInt(v));

function compileJeth(src: string): { ok: boolean; bytecode: string | null; codes: string[] } {
  try {
    return { ok: true, bytecode: compile(src, { fileName: 'C.jeth' }).creationBytecode, codes: [] };
  } catch (e: any) {
    return { ok: false, bytecode: null, codes: (e?.diagnostics ?? []).map((d: any) => d.code) };
  }
}

// ---- DATA-REGION encoders (no outer offset word) -----------------------------
const elemBody = (hex: string): string => {
  const len = hex.length / 2;
  const words = Math.ceil(len / 32);
  return P(len) + hex.padEnd(words * 64, '0');
};
// bytes[] / string[]: [len][offset table][payloads]; offsets relative to table start.
function dynBytesArrayRegion(items: string[]): string {
  const L = items.length;
  const payloads = items.map(elemBody);
  let off = L * 32;
  let table = '';
  for (const p of payloads) {
    table += P(off);
    off += p.length / 2;
  }
  return P(L) + table + payloads.join('');
}
// u256[] data region: [len][elems].
const dynValRegion = (xs: number[]): string => P(xs.length) + xs.map((x) => P(x)).join('');
// u256[][] region: [outerLen][inner offset table][inner regions]; inner offs rel. table start.
function nested2Region(rows: number[][]): string {
  const L = rows.length;
  const inner = rows.map(dynValRegion);
  let off = L * 32;
  let table = '';
  for (const ir of inner) {
    table += P(off);
    off += ir.length / 2;
  }
  return P(L) + table + inner.join('');
}
// P[] (static struct P = {a:u256;b:u256}): [len][P0..Pn] inline, no offset table.
function staticStructArrRegion(rows: [number, number][]): string {
  return P(rows.length) + rows.map(([a, b]) => P(a) + P(b)).join('');
}
// Wrap a data region as a single top-level dynamic arg: [0x20][region].
const arg = (region: string): string => P(0x20) + region;

// ---- twin programs -----------------------------------------------------------
// (A) local binding: echo the whole copied array (proves full-data deep copy).
const echoJeth = (jty: string) => `
class C {
  get f(a: ${jty}): External<${jty}> {
    let row: ${jty} = a;
    return row;
  }
}`;
const echoSol = (sty: string) => `
contract C {
  function f(${sty} calldata a) external pure returns (${sty} memory) {
    ${sty} memory row = a;
    return row;
  }
}`;

// (B) constructor field from a calldata leaf-array: build P(7, t) then echo the whole struct.
const ctorJeth = (jty: string) => `
type P = { a: u256; tags: ${jty}; };
class C {
  get f(t: ${jty}): External<P> {
    let p: P = P(7n, t);
    return p;
  }
}`;
const ctorSol = (sty: string) => `
struct P { uint256 a; ${sty} tags; }
contract C {
  function f(${sty} calldata t) external pure returns (P memory) {
    P memory p = P(7, t);
    return p;
  }
}`;

describe('lift: cd-to-mem-copy (calldata reference-element array -> memory)', () => {
  let h: Harness;
  beforeAll(async () => {
    h = await Harness.create();
  });

  async function diffCall(
    jSrc: string,
    sSrc: string,
    sig: string,
    args: string,
    name = 'C',
  ): Promise<{ j: { success: boolean; returnHex: string }; s: { success: boolean; returnHex: string } }> {
    const cj = compileJeth(jSrc);
    const cs = compileSolidity(SPDX + sSrc, name);
    expect(cj.ok, `JETH should compile; got ${cj.codes.join(',')}`).toBe(true);
    const aj = await h.deploy(cj.bytecode!);
    const as = await h.deploy(cs.creation);
    const data = '0x' + sel(sig) + args;
    const j = await h.call(aj, data);
    const s = await h.call(as, data);
    return { j: { success: j.success, returnHex: j.returnHex }, s: { success: s.success, returnHex: s.returnHex } };
  }

  // ---------------------------------------------------------------------------------------------
  // (A) LOCAL BINDING - bytes[] / string[] / u256[][] / P[]   honest data, byte-for-byte echo
  // ---------------------------------------------------------------------------------------------
  it('bytes[] local copy echoes byte-identically (incl empty, empty element, multi-word)', async () => {
    const J = echoJeth('bytes[]');
    const S = echoSol('bytes[]');
    const cases = [
      arg(dynBytesArrayRegion([])),
      arg(dynBytesArrayRegion([''])),
      arg(dynBytesArrayRegion(['6162'])),
      arg(dynBytesArrayRegion(['6162', '63646566', ''])),
      arg(dynBytesArrayRegion(['00', 'ff'.repeat(33)])),
    ];
    for (const a of cases) {
      const { j, s } = await diffCall(J, S, 'f(bytes[])', a);
      expect(j).toEqual(s);
    }
  });

  it('string[] local copy echoes byte-identically', async () => {
    const J = echoJeth('string[]');
    const S = echoSol('string[]');
    const cases = [arg(dynBytesArrayRegion(['68656c6c6f', '776f726c6421'])), arg(dynBytesArrayRegion([]))];
    for (const a of cases) {
      const { j, s } = await diffCall(J, S, 'f(string[])', a);
      expect(j).toEqual(s);
    }
  });

  it('u256[][] local copy echoes byte-identically (jagged, empty rows)', async () => {
    const J = echoJeth('u256[][]');
    const S = echoSol('uint256[][]');
    const cases = [arg(nested2Region([[1, 2, 3], [], [42]])), arg(nested2Region([]))];
    for (const a of cases) {
      const { j, s } = await diffCall(J, S, 'f(uint256[][])', a);
      expect(j).toEqual(s);
    }
  });

  it('P[] (static struct) local copy echoes byte-identically', async () => {
    const J = `
type P = { a: u256; b: u256; };
class C { get f(a: P[]): External<P[]> { let row: P[] = a; return row; } }`;
    const S = `
struct P { uint256 a; uint256 b; }
contract C { function f(P[] calldata a) external pure returns (P[] memory) { P[] memory row = a; return row; } }`;
    const cases = [arg(staticStructArrRegion([[1, 2], [3, 4]])), arg(staticStructArrRegion([]))];
    for (const a of cases) {
      const { j, s } = await diffCall(J, S, 'f((uint256,uint256)[])', a);
      expect(j).toEqual(s);
    }
  });

  it('bytes[][] local copy echoes byte-identically (deeper nesting)', async () => {
    const J = echoJeth('bytes[][]');
    const S = echoSol('bytes[][]');
    // outer [len][offtable] each row -> a bytes[] data region.
    const rows = [['6162', '63'], [] as string[]];
    const inner = rows.map(dynBytesArrayRegion);
    let off = rows.length * 32;
    let table = '';
    for (const ir of inner) {
      table += P(off);
      off += ir.length / 2;
    }
    const region = P(rows.length) + table + inner.join('');
    const { j, s } = await diffCall(J, S, 'f(bytes[][])', arg(region));
    expect(j).toEqual(s);
  });

  it('copied array is a real DEEP copy: usable as an abi.encode arg', async () => {
    const J = `
class C { get f(a: u256[][]): External<bytes> { let row: u256[][] = a; return abi.encode(row); } }`;
    const S = `
contract C { function f(uint256[][] calldata a) external pure returns (bytes memory) { uint256[][] memory row = a; return abi.encode(row); } }`;
    const { j, s } = await diffCall(J, S, 'f(uint256[][])', arg(nested2Region([[1, 2, 3], [], [9]])));
    expect(j).toEqual(s);
  });

  // ---------------------------------------------------------------------------------------------
  // (A) MALFORMED calldata - revert KIND parity (Panic 0x41 on oversized inner len; empty on truncated/OOB)
  // ---------------------------------------------------------------------------------------------
  it('bytes[] copy: oversized inner length -> Panic 0x41 (matches solc deep-copy allocation cap)', async () => {
    const J = echoJeth('bytes[]');
    const S = echoSol('bytes[]');
    // 1 element, inner length = 2^64-1 (the memory allocation rounds up and overflows the 2^64-1 cap).
    const bad = arg(P(1) + P(0x20) + P(0xffffffffffffffffn));
    const { j, s } = await diffCall(J, S, 'f(bytes[])', bad);
    expect(s.success).toBe(false);
    expect(s.returnHex.startsWith('0x4e487b71')).toBe(true); // Panic(...)
    expect(s.returnHex.endsWith('41')).toBe(true); // 0x41
    expect(j).toEqual(s);
  });

  it('bytes[] copy: truncated payload -> empty revert (matches solc)', async () => {
    const J = echoJeth('bytes[]');
    const S = echoSol('bytes[]');
    const bad = arg(P(1) + P(0x20) + P(10)); // claims 10 data bytes but supplies none
    const { j, s } = await diffCall(J, S, 'f(bytes[])', bad);
    expect(s.success).toBe(false);
    expect(s.returnHex).toBe('0x');
    expect(j).toEqual(s);
  });

  it('bytes[] copy: oversized OUTER length / OOB offset -> empty revert (matches solc)', async () => {
    const J = echoJeth('bytes[]');
    const S = echoSol('bytes[]');
    for (const bad of [arg(P(0xffffffffffffffffn)), P(0xffffffffffffffffn)]) {
      const { j, s } = await diffCall(J, S, 'f(bytes[])', bad);
      expect(s.success).toBe(false);
      expect(j).toEqual(s);
    }
  });

  it('u256[][] copy: oversized inner length -> Panic 0x41 (matches solc)', async () => {
    const J = echoJeth('u256[][]');
    const S = echoSol('uint256[][]');
    const bad = arg(P(1) + P(0x20) + P(0xffffffffffffffffn));
    const { j, s } = await diffCall(J, S, 'f(uint256[][])', bad);
    expect(s.success).toBe(false);
    expect(j).toEqual(s);
  });

  // ---------------------------------------------------------------------------------------------
  // (B) CONSTRUCTOR FIELD from a calldata leaf-array - bytes[] / string[] / u256[][]
  // ---------------------------------------------------------------------------------------------
  it('P(7n, t) builds a memory struct from a calldata bytes[] field byte-identically', async () => {
    const J = ctorJeth('bytes[]');
    const S = ctorSol('bytes[]');
    const cases = [
      arg(dynBytesArrayRegion([])),
      arg(dynBytesArrayRegion(['6162', '63646566'])),
      arg(dynBytesArrayRegion(['', 'ff'.repeat(40)])),
    ];
    for (const a of cases) {
      const { j, s } = await diffCall(J, S, 'f(bytes[])', a);
      expect(j).toEqual(s);
    }
  });

  it('constructor field: string[] and u256[][] match solc', async () => {
    {
      const { j, s } = await diffCall(
        ctorJeth('string[]'),
        ctorSol('string[]'),
        'f(string[])',
        arg(dynBytesArrayRegion(['68656c6c6f', '7878'])),
      );
      expect(j).toEqual(s);
    }
    {
      const { j, s } = await diffCall(
        ctorJeth('u256[][]'),
        ctorSol('uint256[][]'),
        'f(uint256[][])',
        arg(nested2Region([[1, 2], [3]])),
      );
      expect(j).toEqual(s);
    }
  });

  it('constructor field: malformed (oversized inner len -> Panic 0x41; truncated -> empty) matches solc', async () => {
    const J = ctorJeth('bytes[]');
    const S = ctorSol('bytes[]');
    {
      const { j, s } = await diffCall(J, S, 'f(bytes[])', arg(P(1) + P(0x20) + P(0xffffffffffffffffn)));
      expect(s.success).toBe(false);
      expect(j).toEqual(s);
    }
    {
      const { j, s } = await diffCall(J, S, 'f(bytes[])', arg(P(1) + P(0x20) + P(10)));
      expect(s.success).toBe(false);
      expect(s.returnHex).toBe('0x');
      expect(j).toEqual(s);
    }
  });

  // ---------------------------------------------------------------------------------------------
  // NO-REGRESSION: value-element copy + value-element constructor field are UNCHANGED.
  // ---------------------------------------------------------------------------------------------
  it('value-element copy (u256[]) unchanged', async () => {
    const J = echoJeth('u256[]');
    const S = echoSol('uint256[]');
    for (const a of [arg(dynValRegion([7, 8, 9])), arg(dynValRegion([]))]) {
      const { j, s } = await diffCall(J, S, 'f(uint256[])', a);
      expect(j).toEqual(s);
    }
  });

  it('value-element constructor field (Q(7n, valArr)) unchanged', async () => {
    const J = `
type Q = { a: u256; xs: u256[]; };
class C { get f(t: u256[]): External<Q> { let q: Q = Q(7n, t); return q; } }`;
    const S = `
struct Q { uint256 a; uint256[] xs; }
contract C { function f(uint256[] calldata t) external pure returns (Q memory) { Q memory q = Q(7, t); return q; } }`;
    for (const a of [arg(dynValRegion([1, 2, 3])), arg(dynValRegion([]))]) {
      const { j, s } = await diffCall(J, S, 'f(uint256[])', a);
      expect(j).toEqual(s);
    }
  });

  // ---------------------------------------------------------------------------------------------
  // LIFTED (storage twin): a STORAGE-source reference-element copy now DEEP-COPIES into a fresh
  // pointer-headed memory image (abiDecFromStorageToImage), byte-identical to solc - see the dedicated
  // suite test/_storage_to_mem_copy.test.ts for the full differential matrix. Here we just assert it now
  // COMPILES (the over-rejection is gone). A DYNAMIC-struct-element array (D[]) calldata copy stays a
  // clean reject (deferred); we assert it still rejects loudly (never a miscompile).
  // ---------------------------------------------------------------------------------------------
  it('storage-source reference-element copy now compiles (lifted)', () => {
    const r = compileJeth(`
class C {
  blobs: bytes[];
  get f(): External<u256> { let row: bytes[] = this.blobs; return u256(row.length); }
}`);
    expect(r.ok).toBe(true);
  });

  it('dynamic-struct-element array (D[]) calldata copy now COMPILES (lifted byte-identical, see _lift_cd_aggregate_copy.test.ts)', () => {
    // cd-whole-and-dynstruct-copy LIFT #5: a dyn-struct-element calldata array deep-copies into a pointer-headed
    // memory image via buildDynStructFromCdBase, byte-identical to solc. No longer a JETH900 reject.
    const r = compileJeth(`
type D = { a: u256; tag: bytes; };
class C { get f(a: D[]): External<D[]> { let row: D[] = a; return row; } }`);
    expect(r.ok).toBe(true);
  });
});
