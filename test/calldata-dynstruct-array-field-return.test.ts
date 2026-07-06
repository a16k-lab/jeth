// S5-B: DIRECT return of a whole DYNAMIC-outer dyn-struct-ARRAY field of a CALLDATA dyn-struct param
// (`@external go(o: O): St[] { return o.xs; }`, O{xs:St[]; k}). The direct return mirrors the already-
// matching two-step form `let ys: St[] = o.xs; return ys`: DEEP-COPY the field from its resolved calldata
// header into a fresh pointer-headed memory image (aggArgToMemPtr's cdDynArrayField branch ->
// cdFieldArrayHeader + abiDecFromCdToImage), then ABI-encode that image with the SAME encoder the
// memArray-local return uses (encodeNestedMemReturn). Gated to isAggregateLeafArray (the EXACT
// element-shape predicate the let-bound localDecl gate uses): it admits an St element whose fields are
// value / bytes/string / dynamic-value-array / static-struct-or-fixed-array, and REJECTS a
// NESTED-DYNAMIC-STRUCT-leaf element (St{inner:In}) or a struct-element-array field (St{ps:P[]}) - exactly
// the shapes abiDecFromCdToImage cannot build and where the let-bound path itself rejects. An unsupported
// element stays a CLEAN JETH900 reject (byte-parallel to the let form), never truncated/dangling bytes.
// Byte-identical to solc 0.8.35 for the supported element shapes (string+value, bytes, dyn-value-array,
// static-struct field) across empty/single/3 elements and a >32-byte string, with a non-vacuous gk() reading
// o.k. CONTROLS: nested-In + struct-element-array direct returns are clean JETH900 rejects; the let-bound
// and abi.encode(o.xs) forms still MATCH; o.xs[999n] const-OOB is a runtime Panic 0x32.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const PANIC32 = '0x4e487b71' + pad32(0x32n);

function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}

// ---------- ABI calldata builders ----------
function encString(s: string): string {
  const b = Buffer.from(s, 'utf8');
  const padded = Math.ceil(b.length / 32) * 32;
  return W(b.length) + b.toString('hex').padEnd(padded * 2, '0');
}
function encBytes(hexNo0x: string): string {
  const len = hexNo0x.length / 2;
  const padded = Math.ceil(len / 32) * 32;
  return W(len) + hexNo0x.padEnd(padded * 2, '0');
}
type Comp = { static: string } | { dyn: string };
function tuple(components: Comp[]): string {
  const headWords = components.length;
  let heads = '';
  let tails = '';
  let running = headWords * 32;
  for (const c of components) {
    if ('static' in c) heads += c.static;
    else {
      heads += W(running);
      tails += c.dyn;
      running += c.dyn.length / 2;
    }
  }
  return heads + tails;
}
function dynArr(elemBodies: string[]): string {
  const n = elemBodies.length;
  let heads = '';
  let tails = '';
  let running = n * 32;
  for (const e of elemBodies) {
    heads += W(running);
    tails += e;
    running += e.length / 2;
  }
  return W(n) + heads + tails;
}
// O{xs:St[]; k}: outer dynamic tuple, passed behind a 0x20 top-level offset word.
const encO = (arrBody: string, k: bigint | number) => W(0x20) + tuple([{ dyn: arrBody }, { static: W(k) }]);

// element bodies
const eStrval = (s: string, n: bigint | number) => tuple([{ dyn: encString(s) }, { static: W(n) }]);
const eBytes = (n: bigint | number, hx: string) => tuple([{ static: W(n) }, { dyn: encBytes(hx) }]);
const eDynarr = (n: bigint | number, arr: bigint[]) =>
  tuple([{ static: W(n) }, { dyn: W(arr.length) + arr.map((x) => W(x)).join('') }]);
const eStrStat = (s: string, a: bigint, b: bigint, n: bigint) =>
  tuple([{ dyn: encString(s) }, { static: W(a) + W(b) }, { static: W(n) }]);

async function diff(J: string, S: string, calls: [string, string][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  const out: { success: boolean; returnHex: string }[] = [];
  for (const [sig, args] of calls) {
    const data = sel(sig) + args;
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sig + ' ' + args.slice(0, 12) + ' success').toBe(rs.success);
    expect(rj.returnHex, sig + ' ' + args.slice(0, 12) + ' bytes').toBe(rs.returnHex);
    out.push(rj);
  }
  return out;
}

// ---- JETH/solc source pairs (direct return o.xs) ----
const J = {
  strval: `@struct class St { s: string; n: u256 } @struct class O { xs: St[]; k: u256 } @contract class C { @external @pure go(o: O): St[] { return o.xs; } @external @pure gk(o: O): u256 { return o.k; } }`,
  bytes: `@struct class St { n: u256; b: bytes } @struct class O { xs: St[]; k: u256 } @contract class C { @external @pure go(o: O): St[] { return o.xs; } @external @pure gk(o: O): u256 { return o.k; } }`,
  dynarr: `@struct class St { n: u256; ns: u256[] } @struct class O { xs: St[]; k: u256 } @contract class C { @external @pure go(o: O): St[] { return o.xs; } @external @pure gk(o: O): u256 { return o.k; } }`,
  strstat: `@struct class Pt { a: u256; b: u256 } @struct class St { s: string; p: Pt; n: u256 } @struct class O { xs: St[]; k: u256 } @contract class C { @external @pure go(o: O): St[] { return o.xs; } @external @pure gk(o: O): u256 { return o.k; } }`,
};
const S = {
  strval: `struct St { string s; uint256 n; } struct O { St[] xs; uint256 k; } contract C { function go(O calldata o) external pure returns (St[] memory) { return o.xs; } function gk(O calldata o) external pure returns (uint256) { return o.k; } }`,
  bytes: `struct St { uint256 n; bytes b; } struct O { St[] xs; uint256 k; } contract C { function go(O calldata o) external pure returns (St[] memory) { return o.xs; } function gk(O calldata o) external pure returns (uint256) { return o.k; } }`,
  dynarr: `struct St { uint256 n; uint256[] ns; } struct O { St[] xs; uint256 k; } contract C { function go(O calldata o) external pure returns (St[] memory) { return o.xs; } function gk(O calldata o) external pure returns (uint256) { return o.k; } }`,
  strstat: `struct Pt { uint256 a; uint256 b; } struct St { string s; Pt p; uint256 n; } struct O { St[] xs; uint256 k; } contract C { function go(O calldata o) external pure returns (St[] memory) { return o.xs; } function gk(O calldata o) external pure returns (uint256) { return o.k; } }`,
};
const SIG = {
  strval: ['go(((string,uint256)[],uint256))', 'gk(((string,uint256)[],uint256))'],
  bytes: ['go(((uint256,bytes)[],uint256))', 'gk(((uint256,bytes)[],uint256))'],
  dynarr: ['go(((uint256,uint256[])[],uint256))', 'gk(((uint256,uint256[])[],uint256))'],
  strstat: [
    'go(((string,(uint256,uint256),uint256)[],uint256))',
    'gk(((string,(uint256,uint256),uint256)[],uint256))',
  ],
} as const;

describe('S5-B: direct return of a calldata dyn-struct-array field o.xs vs solc 0.8.35', () => {
  it('string+value element St{s;n}: empty / single / 3 / >32-byte string, non-vacuous gk', async () => {
    const [go, gk] = SIG.strval;
    const two = encO(dynArr([eStrval('hi', 7), eStrval('yo', 9)]), 42);
    const out = await diff(J.strval, S.strval, [
      [go, encO(dynArr([]), 3)], // empty xs
      [go, encO(dynArr([eStrval('x', 1)]), 5)], // single
      [go, encO(dynArr([eStrval('a', 1), eStrval('bb', 2), eStrval('ccc', 3)]), 100)], // three
      [go, encO(dynArr([eStrval('this string is definitely more than thirty two bytes long!!', 77)]), 8)], // >32B
      [go, two],
      [gk, two], // non-vacuity: reads o.k = 42
    ]);
    // gk returns k=42 (proves the selector dispatches on the real O, not a vacuous shape)
    expect(BigInt(out[5]!.returnHex)).toBe(42n);
    // go two-element return: solc's St[] blob starts with a 0x20 offset then len=2
    expect(BigInt('0x' + out[4]!.returnHex.slice(2, 66))).toBe(0x20n);
    expect(BigInt('0x' + out[4]!.returnHex.slice(66, 130))).toBe(2n);
  });

  it('bytes element St{n;b}: empty / single / two / >32-byte bytes', async () => {
    const [go] = SIG.bytes;
    await diff(J.bytes, S.bytes, [
      [go, encO(dynArr([]), 3)],
      [go, encO(dynArr([eBytes(11, 'deadbeef')]), 5)],
      [go, encO(dynArr([eBytes(1, 'aa'), eBytes(2, 'bbccdd')]), 9)],
      [go, encO(dynArr([eBytes(9, 'ab'.repeat(40))]), 4)],
    ]);
  });

  it('dynamic-value-array element St{n;ns:u256[]}: empty / single / mixed inner lengths', async () => {
    const [go] = SIG.dynarr;
    await diff(J.dynarr, S.dynarr, [
      [go, encO(dynArr([]), 2)],
      [go, encO(dynArr([eDynarr(1, [10n, 20n, 30n])]), 6)],
      [go, encO(dynArr([eDynarr(1, []), eDynarr(2, [99n]), eDynarr(3, [1n, 2n, 3n, 4n])]), 7)],
    ]);
  });

  it('static-struct field element St{s;p:Pt;n}: single / two (dynamic via string, plus inline Pt)', async () => {
    const [go, gk] = SIG.strstat;
    const cd = encO(dynArr([eStrStat('foo', 1n, 2n, 3n), eStrStat('barbarbar', 4n, 5n, 6n)]), 88);
    const out = await diff(J.strstat, S.strstat, [
      [go, encO(dynArr([eStrStat('x', 11n, 22n, 33n)]), 8)],
      [go, cd],
      [gk, cd],
    ]);
    expect(BigInt(out[2]!.returnHex)).toBe(88n);
  });

  it('const-OOB o.xs[999n].n is a runtime Panic 0x32 (both)', async () => {
    const Joob = `@struct class St { s: string; n: u256 } @struct class O { xs: St[]; k: u256 } @contract class C { @external @pure go(o: O): u256 { return o.xs[999n].n; } }`;
    const Soob = `struct St { string s; uint256 n; } struct O { St[] xs; uint256 k; } contract C { function go(O calldata o) external pure returns (uint256) { return o.xs[999].n; } }`;
    const out = await diff(Joob, Soob, [
      ['go(((string,uint256)[],uint256))', encO(dynArr([eStrval('hi', 7)]), 1)],
    ]);
    expect(out[0]!.success).toBe(false);
    expect(out[0]!.returnHex).toBe(PANIC32);
  });

  it('CONTROL: abi.encode(o.xs) and let-bound `let ys=o.xs; return ys` still MATCH solc', async () => {
    const cd = encO(dynArr([eStrval('hi', 7), eStrval('yo', 9)]), 42);
    const Jenc = `@struct class St { s: string; n: u256 } @struct class O { xs: St[]; k: u256 } @contract class C { @external @pure go(o: O): bytes { return abi.encode(o.xs); } }`;
    const Senc = `struct St { string s; uint256 n; } struct O { St[] xs; uint256 k; } contract C { function go(O calldata o) external pure returns (bytes memory) { return abi.encode(o.xs); } }`;
    await diff(Jenc, Senc, [['go(((string,uint256)[],uint256))', cd]]);

    const Jlet = `@struct class St { s: string; n: u256 } @struct class O { xs: St[]; k: u256 } @contract class C { @external @pure go(o: O): St[] { let ys: St[] = o.xs; return ys; } }`;
    const Slet = `struct St { string s; uint256 n; } struct O { St[] xs; uint256 k; } contract C { function go(O calldata o) external pure returns (St[] memory) { St[] memory ys = o.xs; return ys; } }`;
    await diff(Jlet, Slet, [['go(((string,uint256)[],uint256))', cd]]);
  });

  it('CONTROL: nested-dyn-struct-leaf element St{inner:In;n} DIRECT return is a CLEAN JETH900 reject (no truncated bytes)', () => {
    // solc returns 448 bytes of full nested bodies for this shape; the tight gate keeps it rejecting,
    // BYTE-PARALLEL to the let-bound form which itself rejects (JETH200). A wrong-bytes accept (the
    // attempt-1 miscompile: 128 bytes with dangling offsets) is FAR WORSE than this clean reject.
    const Jn = `@struct class In { s: string } @struct class St { inner: In; n: u256 } @struct class O { xs: St[]; k: u256 } @contract class C { @external @pure go(o: O): St[] { return o.xs; } @external @pure gk(o: O): u256 { return o.k; } }`;
    expect(codes(Jn)).toContain('JETH900');
    // parity: the let-bound form of the SAME shape also rejects (analyzer JETH200).
    const JnLet = `@struct class In { s: string } @struct class St { inner: In; n: u256 } @struct class O { xs: St[]; k: u256 } @contract class C { @external @pure go(o: O): St[] { let ys: St[] = o.xs; return ys; } @external @pure gk(o: O): u256 { return o.k; } }`;
    expect(codes(JnLet)).toContain('JETH200');
  });

  it('CONTROL: struct-element-array field St{n;ps:Pt[]} DIRECT return is a CLEAN JETH900 reject', () => {
    const Jp = `@struct class Pt { a: u256; b: u256 } @struct class St { n: u256; ps: Pt[] } @struct class O { xs: St[]; k: u256 } @contract class C { @external @pure go(o: O): St[] { return o.xs; } @external @pure gk(o: O): u256 { return o.k; } }`;
    expect(codes(Jp)).toContain('JETH900');
    const JpLet = `@struct class Pt { a: u256; b: u256 } @struct class St { n: u256; ps: Pt[] } @struct class O { xs: St[]; k: u256 } @contract class C { @external @pure go(o: O): St[] { let ys: St[] = o.xs; return ys; } @external @pure gk(o: O): u256 { return o.k; } }`;
    expect(codes(JpLet)).toContain('JETH200');
  });
});
