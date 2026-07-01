// Phase B: EXTERNAL (delegatecall) libraries. A `@library class L { @external f(...) {...} }` is an
// external library function: it is deployed in L's OWN bytecode object and called via DELEGATECALL to a
// link-time address. The contract carries a `linkersymbol("L")` -> solc emits a `__$..$__` placeholder +
// `evm.bytecode.linkReferences`; a deployer substitutes the deployed library's 20-byte address. These
// tests deploy each JETH library object, link it into the contract, deploy, call, and compare returndata
// + REVERT data byte-for-byte against the solc external-library mirror
// (`library L { function f(...) public ... } contract C { ... L.f(...) }`), plus the accept/reject gates.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidityLinked, deploySolLinked } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n';

/** ABI-encode `(string)` calldata with a 4-byte selector. */
function stringCall(selector: string, s: string): string {
  const hex = Buffer.from(s, 'utf8').toString('hex');
  const len = hex.length / 2;
  const words = Math.ceil(len / 32);
  return '0x' + selector.replace(/^0x/, '') + pad32(32n) + pad32(BigInt(len)) + hex.padEnd(words * 64, '0');
}
/** ABI-encode `(uint256[])` calldata with a 4-byte selector. */
function arrCall(selector: string, xs: bigint[]): string {
  return '0x' + selector.replace(/^0x/, '') + pad32(32n) + pad32(BigInt(xs.length)) + xs.map(pad32).join('');
}

// ---------------------------------------------------------------------------
// Differential harness: deploy+link the JETH contract & its external library
// objects, deploy+link the solc mirror, then compare each call byte-for-byte
// (success + returndata, which is the revert data on failure).
// ---------------------------------------------------------------------------
async function pairLinked(jethSrc: string, solSrc: string, libNames: string[]) {
  const jb = compile(jethSrc, { fileName: 'C.jeth' });
  const sb = compileSolidityLinked(solSrc, 'C', libNames);
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = (await jeth.deployLinked(jb)).address;
  const as = await deploySolLinked(sol, sb);
  return { jeth, sol, aj, as, jb, sb };
}

/** Call BOTH deployments with the same calldata; assert success + returndata are byte-identical. */
async function expectSame(ctx: Awaited<ReturnType<typeof pairLinked>>, data: string) {
  const jr = await ctx.jeth.call(ctx.aj, data);
  const sr = await ctx.sol.call(ctx.as, data);
  expect({ success: jr.success, ret: jr.returnHex }).toEqual({ success: sr.success, ret: sr.returnHex });
  return jr;
}

describe('Phase B: external (delegatecall) libraries', () => {
  it('a pure-math external library, qualified L.f(...) and attached x.f(...), is byte-identical to solc', async () => {
    const jeth = `
@library class Math {
  @external @pure add(a: u256, b: u256): u256 { return a + b + 1n; }
  @external @pure dbl(self: u256): u256 { return self * 2n; }
}
@contract @using(Math) class C {
  @external @pure g(a: u256, b: u256): u256 { return Math.add(a, b); }
  @external @pure d(x: u256): u256 { return x.dbl(); }
}`;
    const sol = `${SPDX}
library Math {
  function add(uint256 a, uint256 b) public pure returns (uint256) { return a + b + 1; }
  function dbl(uint256 self) public pure returns (uint256) { return self * 2; }
}
contract C {
  using Math for uint256;
  function g(uint256 a, uint256 b) external pure returns (uint256) { return Math.add(a, b); }
  function d(uint256 x) external pure returns (uint256) { return x.dbl(); }
}`;
    const ctx = await pairLinked(jeth, sol, ['Math']);
    // sanity: the JETH build is actually a linked build (a library object + a link reference).
    expect(ctx.jb.libraries?.map((l) => l.name)).toEqual(['Math']);
    expect(Object.keys(ctx.jb.linkReferences![''] ?? {})).toEqual(['Math']);
    const r = await expectSame(ctx, encodeCall(sel('g(uint256,uint256)'), [3n, 4n]));
    expect(BigInt(r.returnHex)).toBe(8n); // 3 + 4 + 1
    const r2 = await expectSame(ctx, encodeCall(sel('d(uint256)'), [21n]));
    expect(BigInt(r2.returnHex)).toBe(42n);
  });

  it('an external library fn returning string / bytes is byte-identical to solc', async () => {
    const jeth = `
@library class Str {
  @external @pure echo(s: string): string { return s; }
  @external @pure raw(b: bytes): bytes { return b; }
}
@contract class C {
  @external @pure es(s: string): string { return Str.echo(s); }
  @external @pure eb(b: bytes): bytes { return Str.raw(b); }
}`;
    const sol = `${SPDX}
library Str {
  function echo(string memory s) public pure returns (string memory) { return s; }
  function raw(bytes memory b) public pure returns (bytes memory) { return b; }
}
contract C {
  function es(string memory s) external pure returns (string memory) { return Str.echo(s); }
  function eb(bytes memory b) external pure returns (bytes memory) { return Str.raw(b); }
}`;
    const ctx = await pairLinked(jeth, sol, ['Str']);
    await expectSame(ctx, stringCall(sel('es(string)'), 'hello external library'));
    await expectSame(ctx, stringCall(sel('es(string)'), '')); // empty string
    await expectSame(ctx, stringCall(sel('eb(bytes)'), 'deadbeefcafe'));
  });

  it('an external library fn taking + returning a struct / an array is byte-identical to solc', async () => {
    const jeth = `
@struct class P { x: u256; y: u256; }
@library class G {
  @external @pure scale(p: P, k: u256): P { return P(p.x * k, p.y * k); }
  @external @pure sum(a: u256[]): u256 { let s: u256 = 0n; let i: u256 = 0n; while (i < a.length) { s = s + a[i]; i = i + 1n; } return s; }
}
@contract class C {
  @external @pure doScale(x: u256, y: u256, k: u256): u256 { let r: P = G.scale(P(x, y), k); return r.x + r.y; }
  @external @pure doSum(a: u256[]): u256 { return G.sum(a); }
}`;
    const sol = `${SPDX}
struct P { uint256 x; uint256 y; }
library G {
  function scale(P memory p, uint256 k) public pure returns (P memory) { return P(p.x * k, p.y * k); }
  function sum(uint256[] memory a) public pure returns (uint256) { uint256 s; for (uint256 i; i < a.length; i++) { s += a[i]; } return s; }
}
contract C {
  function doScale(uint256 x, uint256 y, uint256 k) external pure returns (uint256) { P memory r = G.scale(P(x, y), k); return r.x + r.y; }
  function doSum(uint256[] memory a) external pure returns (uint256) { return G.sum(a); }
}`;
    const ctx = await pairLinked(jeth, sol, ['G']);
    const r = await expectSame(ctx, '0x' + sel('doScale(uint256,uint256,uint256)') + pad32(3n) + pad32(4n) + pad32(5n));
    expect(BigInt(r.returnHex)).toBe(35n); // (3*5) + (4*5)
    await expectSame(ctx, arrCall(sel('doSum(uint256[])'), [10n, 20n, 30n]));
    await expectSame(ctx, arrCall(sel('doSum(uint256[])'), [])); // empty array
  });

  it("a string revert in an external library fn BUBBLES byte-identically (revert data + success=false)", async () => {
    const jeth = `
@library class Guard {
  @external @pure mustBig(x: u256): u256 { require(x >= 10n, "too small"); return x; }
}
@contract class C {
  @external @pure run(x: u256): u256 { return Guard.mustBig(x); }
}`;
    const sol = `${SPDX}
library Guard {
  function mustBig(uint256 x) public pure returns (uint256) { require(x >= 10, "too small"); return x; }
}
contract C {
  function run(uint256 x) external pure returns (uint256) { return Guard.mustBig(x); }
}`;
    const ctx = await pairLinked(jeth, sol, ['Guard']);
    const fail = await expectSame(ctx, encodeCall(sel('run(uint256)'), [3n]));
    expect(fail.success).toBe(false);
    expect(fail.returnHex.startsWith('0x08c379a0')).toBe(true); // Error(string) selector
    await expectSame(ctx, encodeCall(sel('run(uint256)'), [42n])); // success path
  });

  it('a CUSTOM-ERROR revert in an external library fn bubbles byte-identically', async () => {
    const jeth = `
@library class Guard {
  @external @pure mustBig(x: u256): u256 { require(x >= 10n, TooSmall(10n, x)); return x; }
}
@contract class C {
  @error TooSmall(min: u256, got: u256);
  @external @pure run(x: u256): u256 { return Guard.mustBig(x); }
}`;
    const sol = `${SPDX}
error TooSmall(uint256 min, uint256 got);
library Guard {
  function mustBig(uint256 x) public pure returns (uint256) { if (x < 10) revert TooSmall(10, x); return x; }
}
contract C {
  function run(uint256 x) external pure returns (uint256) { return Guard.mustBig(x); }
}`;
    const ctx = await pairLinked(jeth, sol, ['Guard']);
    const fail = await expectSame(ctx, encodeCall(sel('run(uint256)'), [5n]));
    expect(fail.success).toBe(false);
    expect(fail.returnHex.startsWith('0x' + sel('TooSmall(uint256,uint256)'))).toBe(true);
    await expectSame(ctx, encodeCall(sel('run(uint256)'), [11n])); // success path
  });

  it('a contract using TWO external libraries (two placeholders / two links) is byte-identical to solc', async () => {
    const jeth = `
@library class A { @external @pure addOne(x: u256): u256 { return x + 1n; } }
@library class B { @external @pure mul2(x: u256): u256 { return x * 2n; } }
@contract class C {
  @external @pure combo(x: u256): u256 { return B.mul2(A.addOne(x)); }
}`;
    const sol = `${SPDX}
library A { function addOne(uint256 x) public pure returns (uint256) { return x + 1; } }
library B { function mul2(uint256 x) public pure returns (uint256) { return x * 2; } }
contract C { function combo(uint256 x) external pure returns (uint256) { return B.mul2(A.addOne(x)); } }`;
    const ctx = await pairLinked(jeth, sol, ['A', 'B']);
    expect(ctx.jb.libraries?.map((l) => l.name).sort()).toEqual(['A', 'B']);
    expect(Object.keys(ctx.jb.linkReferences![''] ?? {}).sort()).toEqual(['A', 'B']);
    const r = await expectSame(ctx, encodeCall(sel('combo(uint256)'), [10n]));
    expect(BigInt(r.returnHex)).toBe(22n); // (10 + 1) * 2
  });

  it('a library MIXING an internal (inlined) and an external (delegatecall) function is byte-identical', async () => {
    // `inc` is an INTERNAL library fn: inlined into the contract (Phase A) AND into the library object
    // (called by the external `addOne`). `addOne`/`triple` are EXTERNAL (delegatecall, in the lib object).
    const jeth = `
@library class L {
  inc(x: u256): u256 { return x + 1n; }
  @external @pure addOne(x: u256): u256 { return L.inc(x); }
  @external @pure triple(x: u256): u256 { return L.inc(L.inc(x)) + x; }
}
@contract class C {
  @external @pure viaExternal(x: u256): u256 { return L.addOne(x); }
  @external @pure viaInternal(x: u256): u256 { return L.inc(x) + L.inc(x); }
  @external @pure viaTriple(x: u256): u256 { return L.triple(x); }
}`;
    const sol = `${SPDX}
library L {
  function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
  function addOne(uint256 x) public pure returns (uint256) { return inc(x); }
  function triple(uint256 x) public pure returns (uint256) { return inc(inc(x)) + x; }
}
contract C {
  function viaExternal(uint256 x) external pure returns (uint256) { return L.addOne(x); }
  function viaInternal(uint256 x) external pure returns (uint256) { return L.inc(x) + L.inc(x); }
  function viaTriple(uint256 x) external pure returns (uint256) { return L.triple(x); }
}`;
    const ctx = await pairLinked(jeth, sol, ['L']);
    expect(ctx.jb.libraries?.map((l) => l.name)).toEqual(['L']);
    const re = await expectSame(ctx, encodeCall(sel('viaExternal(uint256)'), [5n]));
    expect(BigInt(re.returnHex)).toBe(6n);
    const ri = await expectSame(ctx, encodeCall(sel('viaInternal(uint256)'), [5n]));
    expect(BigInt(ri.returnHex)).toBe(12n); // (5+1)+(5+1)
    const rt = await expectSame(ctx, encodeCall(sel('viaTriple(uint256)'), [5n]));
    expect(BigInt(rt.returnHex)).toBe(12n); // ((5+1)+1) + 5
  });

  it('@using attachment over an EXTERNAL library fn (x.f() -> delegatecall L.f(x)) is byte-identical', async () => {
    const jeth = `
@library class U {
  @external @pure squared(self: u256): u256 { return self * self; }
  @external @pure plus(self: u256, b: u256): u256 { return self + b; }
}
@contract @using(U) class C {
  @external @pure sq(x: u256): u256 { return x.squared(); }
  @external @pure pl(x: u256, y: u256): u256 { return x.plus(y); }
}`;
    const sol = `${SPDX}
library U {
  function squared(uint256 self) public pure returns (uint256) { return self * self; }
  function plus(uint256 self, uint256 b) public pure returns (uint256) { return self + b; }
}
contract C {
  using U for uint256;
  function sq(uint256 x) external pure returns (uint256) { return x.squared(); }
  function pl(uint256 x, uint256 y) external pure returns (uint256) { return x.plus(y); }
}`;
    const ctx = await pairLinked(jeth, sol, ['U']);
    const r = await expectSame(ctx, encodeCall(sel('sq(uint256)'), [9n]));
    expect(BigInt(r.returnHex)).toBe(81n);
    const r2 = await expectSame(ctx, encodeCall(sel('pl(uint256,uint256)'), [40n, 2n]));
    expect(BigInt(r2.returnHex)).toBe(42n);
  });

  it('a state-mutating contract caller of an external library fn observes the same storage', async () => {
    // The contract method that consumes the library result WRITES storage; verify the stored value and
    // the runtime are byte-identical to solc (the library fn is pure; the write is the contract's).
    const jeth = `
@library class Math { @external @pure add(a: u256, b: u256): u256 { return a + b; } }
@contract class C {
  @state total: u256;
  @external accumulate(a: u256, b: u256): void { this.total = this.total + Math.add(a, b); }
  @external @view getTotal(): u256 { return this.total; }
}`;
    const sol = `${SPDX}
library Math { function add(uint256 a, uint256 b) public pure returns (uint256) { return a + b; } }
contract C {
  uint256 total;
  function accumulate(uint256 a, uint256 b) external { total = total + Math.add(a, b); }
  function getTotal() external view returns (uint256) { return total; }
}`;
    const ctx = await pairLinked(jeth, sol, ['Math']);
    await expectSame(ctx, encodeCall(sel('accumulate(uint256,uint256)'), [3n, 4n]));
    await expectSame(ctx, encodeCall(sel('accumulate(uint256,uint256)'), [10n, 20n]));
    const tot = await expectSame(ctx, encodeCall(sel('getTotal()'), []));
    expect(BigInt(tot.returnHex)).toBe(37n);
  });

  // ---- accept / reject gates (parity vs solc) ----
  function jethRejectsWith(src: string, code: string): boolean {
    try {
      compile(src, { fileName: 'C.jeth' });
      return false;
    } catch (e: any) {
      return ((e?.diagnostics ?? []) as { code: string }[]).some((d) => d.code === code);
    }
  }

  it('GATE: a @payable external library fn -> JETH390 (solc also rejects: library functions cannot be payable)', () => {
    const jeth = `@library class L { @external @payable f(a: u256): u256 { return a; } }
@contract class C { @external @pure g(a: u256): u256 { return L.f(a); } }`;
    expect(jethRejectsWith(jeth, 'JETH390')).toBe(true);
  });

  it('GATE: a storage-ref param is not expressible (JETH has no storage-reference parameter type)', () => {
    // solc `using For` over a storage type that mutates caller storage (e.g. EnumerableSet's
    // `function add(Set storage s, ...)`) needs a STORAGE-reference parameter. JETH function params are
    // always value/memory/calldata - there is no `storage` parameter syntax - so this pattern simply
    // cannot be written. A struct param is always a memory copy (no caller-storage mutation), so a
    // mapping-bearing struct param is rejected (no by-value copy possible), matching the deferral.
    const jeth = `@struct class S { items: u256[]; flag: bool; }
@library class Set { @external add(s: S, x: u256): void { } }
@contract class C { @external f(): void { } }`;
    // The library compiles (S is a memory-copy param), but it cannot mutate caller storage - there is no
    // storage-ref surface. This documents the deferral; a memory-struct param is a copy, never aliased.
    expect(() => compile(jeth, { fileName: 'C.jeth' })).not.toThrow();
  });

  it('an UNREFERENCED external library fn does NOT become a contract dispatcher entry (no selector leak)', () => {
    // A library declaring @external f, but with no L.f call site, must not add f to the contract's ABI /
    // dispatcher (it lives only in its own object, which is not even emitted when unreferenced).
    const jeth = `@library class L { @external @pure f(a: u256): u256 { return a; } }
@contract class C { @external @pure g(a: u256): u256 { return a; } }`;
    const build = compile(jeth, { fileName: 'C.jeth' });
    expect(build.libraries).toBeUndefined(); // not referenced -> no library object emitted
    expect(build.abi.some((i: any) => i.name === 'f')).toBe(false); // f is not a contract entry
    expect(build.abi.some((i: any) => i.name === 'g')).toBe(true);
  });

  it('an ordinary single-contract compile keeps the legacy result shape (no library fields)', () => {
    const build = compile(`@contract class C { @external @pure id(a: u256): u256 { return a; } }`, { fileName: 'C.jeth' });
    expect(build.libraries).toBeUndefined();
    expect(build.linkReferences).toBeUndefined();
    expect(/__\$/.test(build.creationBytecode)).toBe(false); // no link placeholder
  });

  it('a NESTED external library (a library that delegatecalls another library) links + runs byte-identical to solc', async () => {
    // High.step delegatecalls Low.base, so High's OWN creation bytecode carries a `__$..$__` placeholder
    // for Low. The deployer must link+deploy Low FIRST, substitute its address into High, deploy High,
    // then link High into the contract. Exercises the bottom-up topological deploy in Harness.deployLinked
    // (and its solc mirror deploySolLinked). run(x) = (x + 10) * 2 + 100 = 2x + 120.
    const jeth = `
@library class Low {
  @external @pure base(x: u256): u256 { return x + 10n; }
}
@library class High {
  @external @pure step(x: u256): u256 { return Low.base(x) * 2n; }
}
@contract class C {
  @external @pure run(x: u256): u256 { return High.step(x) + 100n; }
}`;
    const sol = `${SPDX}
library Low {
  function base(uint256 x) public pure returns (uint256) { return x + 10; }
}
library High {
  function step(uint256 x) public pure returns (uint256) { return Low.base(x) * 2; }
}
contract C {
  function run(uint256 x) external pure returns (uint256) { return High.step(x) + 100; }
}`;
    const ctx = await pairLinked(jeth, sol, ['Low', 'High']);
    // sanity: High carries a link reference to Low in its OWN creation bytecode (the nested case), and the
    // contract carries a link reference to High. Low references nothing.
    const highLib = ctx.jb.libraries!.find((l) => l.name === 'High')!;
    const lowLib = ctx.jb.libraries!.find((l) => l.name === 'Low')!;
    expect(Object.keys(highLib.linkReferences?.[''] ?? {})).toEqual(['Low']);
    expect(Object.keys(lowLib.linkReferences?.[''] ?? {})).toEqual([]);
    expect(Object.keys(ctx.jb.linkReferences![''] ?? {})).toEqual(['High']);
    for (const [x, expected] of [
      [5n, 130n],
      [0n, 120n],
      [7n, 134n],
    ] as const) {
      const r = await expectSame(ctx, encodeCall(sel('run(uint256)'), [x]));
      expect(BigInt(r.returnHex)).toBe(expected);
    }
  });
});
