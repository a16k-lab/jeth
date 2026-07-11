// Long-tail batch D lifts (docs/OR-CATALOGUE.md rows MOD-GEN + the F-RESID stretch), byte-identical
// to solc 0.8.35:
// D1   GENERIC @modifier instantiated at AGGREGATE/DYNAMIC/FUNCREF types: the L15 monomorphization
//      previously gated every type argument through the generic-FUNCTION value-type gate
//      (gateGenericTypeArg, JETH291), so `@ne(bytes("ab"))` on `@modifier ne<T>(v: T)` over-rejected
//      while the hand-written bytes-param modifier MATCHed. The lift is a modifier-specific gate
//      (gateModifierGenericTypeArg): a type argument may be ANY type a concrete @modifier parameter
//      may be (value, bytes/string, array, struct, funcref) - the monomorph is collected through the
//      normal concrete-modifier pipeline (collectModifier + registerAggregateModifierParam + the
//      per-shape materialization gates), so every shape accepts or re-rejects exactly where a
//      hand-written modifier would. Only never-passable types keep the JETH291 gate reject: void and
//      mapping-bearing types.
//      The specialization mangle (cache key) gained an INJECTIVE tag for non-value types: structs
//      tag by NAME (JETH structs are nominal; canonicalName's structural tuple would alias
//      same-layout structs), arrays/funcrefs serialize recursively, and the whole form escapes to
//      identifier chars uniquely (`$`-free, so the outer name$t1$t2 join stays one-to-one). Value
//      types keep their original tag byte-for-byte.
// KEPT REJECTS (deliberate, all clean):
//  - INFERENCE from a BARE literal / method reference (`@ne([2n, 3n])`, `@chk(this.inc)`) rejects
//    (JETH213/JETH065/JETH074) exactly like every other no-context position in the language
//    (`let x = [2n, 3n]` rejects the same way); the explicit form (`@ne<u256[]>([2n, 3n])`) and any
//    TYPED source (state read, param) infer and lift.
//  - a generic FUNCTION type argument stays value-only (JETH291) - a separate catalogue row.
//  - mapping/void type args (JETH291), funcref-ARRAY instantiation (JETH900, matching the
//    non-generic funcref-array modifier param class), and instantiation-type/arg mismatches
//    (JETH084; the monomorphized solc mirror rejects too).
// F-RESID stretch: Arr<Fd,2> (a FIXED array of funcref-bearing dyn structs) as a MEMORY LOCAL - the
//      fixed-outer twin of batch C's Fd[] lift, pure routing: types.isFuncrefDynStructFixedLeafArray
//      (kept SEPARATE from isDynStructFixedLeafArray so ABI codec routes keep rejecting) OR'd at the
//      localDecl gate, resolveArrayExpr's fixed memAggregate branch, nestedMemArrayElemAccess, and
//      yul's fixed pointer-headed localDecl route. Literal / element read / o[i].f(v) dispatch /
//      whole-element write / element-to-local / for-of / alias / OOB Panic 0x32 all byte-identical.
//      GUARD added with the lift: the JETH467 mem->storage copy gates gained the funcref twin (the
//      newly-reachable `this.g = o` would have OVER-ACCEPTED; solc legacy rejects with
//      UnimplementedFeatureError). Deeper nestings (Arr<Arr<Fd,2>,2>, Arr<Fd,2>[]) keep JETH427;
//      a funcref-FIELD write through an element chain (o[i].f = g) keeps the family JETH200 reject
//      (the dyn-outer Fd[] rejects identically); every ABI boundary still rejects independently.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const run = async (J: string, S: string, calls: ReadonlyArray<readonly [string, string]>) => {
  const h = await Harness.create();
  const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, args] of calls) {
    const jr = await h.call(ja, sel(sg) + args);
    const sr = await h.call(sa, sel(sg) + args);
    expect(jr.returnHex, `${sg} ${args.slice(0, 12)}`).toBe(sr.returnHex);
    expect(jr.success, sg).toBe(sr.success);
  }
};
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};

describe('long-tail batch D: generic @modifier at aggregate/dynamic types (MOD-GEN) byte-identical to solc 0.8.35', () => {
  it('D1: bytes (inferred) + string (explicit and state-read inferred) + u256[]/Arr<u256,2> (explicit)', async () => {
    const J = `class C {
  nm: string;
  constructor() { this.nm = "hi"; }
  @modifier ne<T>(v: T) { require(v.length > 0n, "e"); _; }
  @modifier ok<T>(v: T) { require(keccak256(abi.encode(v)) != keccak256(abi.encode("")), "k"); _; }
  @ne(bytes("ab")) get f(x: u256): External<u256> { return x + 1n; }
  @ok<string>("hi") get g(x: u256): External<u256> { return x + 2n; }
  @ok(this.nm) get g2(x: u256): External<u256> { return x + 3n; }
  @ne<u256[]>([2n, 3n]) get h(x: u256): External<u256> { return x + 4n; }
  @ne(bytes("")) get bad(x: u256): External<u256> { return x + 5n; }
}`;
    const S = `contract C {
  string nm;
  constructor() { nm = "hi"; }
  modifier neB(bytes memory v) { require(v.length > 0, "e"); _; }
  modifier neA(uint256[] memory v) { require(v.length > 0, "e"); _; }
  modifier ok(string memory v) { require(keccak256(abi.encode(v)) != keccak256(abi.encode("")), "k"); _; }
  function f(uint256 x) external neB(bytes("ab")) returns (uint256) { return x + 1; }
  function g(uint256 x) external ok("hi") returns (uint256) { return x + 2; }
  function g2(uint256 x) external ok(nm) returns (uint256) { return x + 3; }
  function h(uint256 x) external neA(two()) returns (uint256) { return x + 4; }
  function bad(uint256 x) external neB(bytes("")) returns (uint256) { return x + 5; }
  function two() internal pure returns (uint256[] memory a) { a = new uint256[](2); a[0] = 2; a[1] = 3; }
}`;
    await run(J, S, [
      ['f(uint256)', W(5)],
      ['g(uint256)', W(5)],
      ['g2(uint256)', W(5)],
      ['h(uint256)', W(5)],
      ['bad(uint256)', W(5)], // reverts "e" byte-identically (non-vacuous: the bytes guard evaluated)
    ] as const);
    // Arr<u256,2> explicit, element reads in the body
    await run(
      `class C {
  @modifier ne<T>(v: T) { require(v[0n] + v[1n] > 4n, "e"); _; }
  @ne<Arr<u256, 2>>([2n, 3n]) get f(x: u256): External<u256> { return x + 1n; }
}`,
      `contract C {
  modifier ne(uint256[2] memory v) { require(v[0] + v[1] > 4, "e"); _; }
  function f(uint256 x) external ne([uint256(2), 3]) returns (uint256) { return x + 1; }
}`,
      [['f(uint256)', W(5)]] as const,
    );
  });

  it('D1: struct instantiations - static (field reads), dynamic (bytes field), same-layout nominal split', async () => {
    const J = `type P = { a: u256; b: u256; };
type D = { a: u256; b: bytes; };
type P1 = { a: u256; };
type P2 = { a: u256; };
class C {
  @modifier gt<T>(v: T) { require(v.a > v.b, "e"); _; }
  @modifier dy<T>(v: T) { require(v.a > 0n && v.b.length > 0n, "e"); _; }
  @modifier pos<T>(v: T) { require(v.a > 0n, "e"); _; }
  @gt(P(5n, 2n)) get f(x: u256): External<u256> { return x + 1n; }
  @dy(D(3n, bytes("xy"))) get g(x: u256): External<u256> { return x + 2n; }
  @pos(P1(3n)) get h1(x: u256): External<u256> { return x + 3n; }
  @pos(P2(0n)) get h2(x: u256): External<u256> { return x + 4n; }
}`;
    const S = `struct P { uint256 a; uint256 b; }
struct D { uint256 a; bytes b; }
struct P1 { uint256 a; }
struct P2 { uint256 a; }
contract C {
  modifier gt(P memory v) { require(v.a > v.b, "e"); _; }
  modifier dy(D memory v) { require(v.a > 0 && v.b.length > 0, "e"); _; }
  modifier pos1(P1 memory v) { require(v.a > 0, "e"); _; }
  modifier pos2(P2 memory v) { require(v.a > 0, "e"); _; }
  function f(uint256 x) external gt(P(5, 2)) returns (uint256) { return x + 1; }
  function g(uint256 x) external dy(D(3, bytes("xy"))) returns (uint256) { return x + 2; }
  function h1(uint256 x) external pos1(P1(3)) returns (uint256) { return x + 3; }
  function h2(uint256 x) external pos2(P2(0)) returns (uint256) { return x + 4; }
}`;
    await run(J, S, [
      ['f(uint256)', W(5)],
      ['g(uint256)', W(5)],
      ['h1(uint256)', W(5)],
      ['h2(uint256)', W(5)], // reverts "e" (P2 monomorph really evaluated 0 > 0 - the nominal tags kept the two same-layout monomorphs apart)
    ] as const);
  });

  it('D1: multi-instantiation dispatch (bytes + u256 + u256[] of ONE modifier), dedup, T-used-twice', async () => {
    const J = `class C {
  @modifier ne<T>(v: T, min: u256) { require(abi.encode(v).length >= min, "e"); _; }
  @modifier tw<T>(v: T, w: T) { require(v.length + w.length > 3n, "e"); _; }
  @ne(bytes("ab"), 96n) get f(x: u256): External<u256> { return x + 1n; }
  @ne(7n, 32n) get g(x: u256): External<u256> { return x + 2n; }
  @ne<u256[]>([2n, 3n], 128n) get h(x: u256): External<u256> { return x + 3n; }
  @ne(7n, 33n) get bad(x: u256): External<u256> { return x + 4n; }
  @ne(bytes("cd"), 96n) get f2(x: u256): External<u256> { return x + 5n; }
  @tw(bytes("ab"), bytes("cd")) get t(x: u256): External<u256> { return x + 6n; }
}`;
    const S = `contract C {
  modifier neB(bytes memory v, uint256 min) { require(abi.encode(v).length >= min, "e"); _; }
  modifier neU(uint256 v, uint256 min) { require(abi.encode(v).length >= min, "e"); _; }
  modifier neA(uint256[] memory v, uint256 min) { require(abi.encode(v).length >= min, "e"); _; }
  modifier tw(bytes memory v, bytes memory w) { require(v.length + w.length > 3, "e"); _; }
  function f(uint256 x) external neB(bytes("ab"), 96) returns (uint256) { return x + 1; }
  function g(uint256 x) external neU(7, 32) returns (uint256) { return x + 2; }
  function h(uint256 x) external neA(two(), 128) returns (uint256) { return x + 3; }
  function bad(uint256 x) external neU(7, 33) returns (uint256) { return x + 4; }
  function f2(uint256 x) external neB(bytes("cd"), 96) returns (uint256) { return x + 5; }
  function t(uint256 x) external tw(bytes("ab"), bytes("cd")) returns (uint256) { return x + 6; }
  function two() internal pure returns (uint256[] memory a) { a = new uint256[](2); a[0] = 2; a[1] = 3; }
}`;
    await run(J, S, [
      ['f(uint256)', W(5)],
      ['g(uint256)', W(5)],
      ['h(uint256)', W(5)],
      ['bad(uint256)', W(5)], // reverts (encode(u256).length = 32 < 33) - each mono-instance dispatched to its own type
      ['f2(uint256)', W(5)], // dedup: reuses the bytes monomorph
      ['t(uint256)', W(5)],
    ] as const);
  });

  it('D1: post-placeholder body, eval order of side-effecting args, storage/calldata arg sources, ctor, nested generics', async () => {
    // post-placeholder (buffered path) with a generic bytes param
    await run(
      `class C {
  count: u256;
  @modifier tick<T>(v: T) { require(v.length > 0n, "e"); _; this.count = this.count + v.length; }
  @tick(bytes("abc")) f(x: u256): External<u256> { return x + this.count; }
  get peek(): External<u256> { return this.count; }
}`,
      `contract C {
  uint256 count;
  modifier tick(bytes memory v) { require(v.length > 0, "e"); _; count = count + v.length; }
  function f(uint256 x) external tick(bytes("abc")) returns (uint256) { return x + count; }
  function peek() external view returns (uint256) { return count; }
}`,
      [
        ['f(uint256)', W(5)],
        ['peek()', ''],
      ] as const,
    );
    // eval order: args of stacked generic modifiers evaluate outermost-first, before the body (counter)
    await run(
      `class C {
  log: u256;
  mk(k: u256): bytes { this.log = this.log * 10n + k; return bytes("ab"); }
  @modifier m1<T>(v: T) { require(v.length > 0n, "a"); this.log = this.log * 10n + 8n; _; }
  @modifier m2<T>(v: T) { require(v.length > 1n, "b"); this.log = this.log * 10n + 9n; _; }
  @m1(this.mk(1n)) @m2(this.mk(2n)) f(x: u256): External<u256> { return this.log * 100n + x; }
}`,
      `contract C {
  uint256 log;
  function mk(uint256 k) internal returns (bytes memory) { log = log * 10 + k; return bytes("ab"); }
  modifier m1(bytes memory v) { require(v.length > 0, "a"); log = log * 10 + 8; _; }
  modifier m2(bytes memory v) { require(v.length > 1, "b"); log = log * 10 + 9; _; }
  function f(uint256 x) external m1(mk(1)) m2(mk(2)) returns (uint256) { return log * 100 + x; }
}`,
      [['f(uint256)', W(5)]] as const,
    );
    // arg sources: a storage read and the wrapped function's own calldata param (in-range + reverting)
    await run(
      `class C {
  sb: bytes;
  constructor() { this.sb = bytes("ab"); }
  @modifier ne<T>(v: T) { require(v.length > 1n, "e"); _; }
  @ne(this.sb) get f(x: u256): External<u256> { return x + 1n; }
  @ne(b) get g(b: bytes, x: u256): External<u256> { return x + b.length; }
}`,
      `contract C {
  bytes sb;
  constructor() { sb = bytes("ab"); }
  modifier ne(bytes memory v) { require(v.length > 1, "e"); _; }
  function f(uint256 x) external ne(sb) returns (uint256) { return x + 1; }
  function g(bytes memory b, uint256 x) external ne(b) returns (uint256) { return x + b.length; }
}`,
      [
        ['f(uint256)', W(5)],
        ['g(bytes,uint256)', W(64) + W(5) + W(2) + '6162' + '0'.repeat(60)],
        ['g(bytes,uint256)', W(64) + W(5) + W(1) + '61' + '0'.repeat(62)], // 1-byte arg -> reverts "e"
      ] as const,
    );
    // constructor + nested generics (the modifier monomorph calls a generic fn at a value leaf)
    await run(
      `class C {
  s: u256;
  gid<U>(x: U): U { return x; }
  @modifier ne<T>(v: T) { require(this.gid(v.length) > 1n, "e"); _; }
  @ne(bytes("ab")) constructor() { this.s = 7n; }
  @ne(bytes("cd")) get f(x: u256): External<u256> { return x + this.s; }
}`,
      `contract C {
  uint256 s;
  function gid(uint256 x) internal pure returns (uint256) { return x; }
  modifier ne(bytes memory v) { require(gid(v.length) > 1, "e"); _; }
  constructor() ne(bytes("ab")) { s = 7; }
  function f(uint256 x) external ne(bytes("cd")) returns (uint256) { return x + s; }
}`,
      [['f(uint256)', W(5)]] as const,
    );
  });

  it('D1 neighbor: funcref instantiation (explicit + state-read inferred) matches the non-generic funcref-param modifier', async () => {
    await run(
      `class C {
  fp: (x: u256) => u256;
  inc(x: u256): u256 { return x + 1n; }
  constructor() { this.fp = this.inc; }
  @modifier chk<T>(f: T) { require(f(1n) == 2n, "e"); _; }
  @chk<(x: u256) => u256>(this.inc) get g(x: u256): External<u256> { return x + 10n; }
  @chk(this.fp) get h(x: u256): External<u256> { return x + 20n; }
}`,
      `contract C {
  function(uint256) pure returns (uint256) fp;
  function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
  constructor() { fp = inc; }
  modifier chk(function(uint256) pure returns (uint256) f) { require(f(1) == 2, "e"); _; }
  function g(uint256 x) external chk(inc) returns (uint256) { return x + 10; }
  function h(uint256 x) external chk(fp) returns (uint256) { return x + 20; }
}`,
      [
        ['g(uint256)', W(5)],
        ['h(uint256)', W(5)],
      ] as const,
    );
  });

  it('KEPT REJECTS: mapping/void gate, bare-literal inference, generic-fn gate, funcref-array, mismatch', () => {
    // mapping-bearing and void type args keep the JETH291 gate reject
    expect(
      codes(`class C {
  @modifier ne<T>(v: T) { require(true, "e"); _; }
  @ne<mapping<u256, u256>>(0n) get f(x: u256): External<u256> { return x + 1n; }
}`),
    ).toContain('JETH291');
    expect(
      codes(`class C {
  @modifier ne<T>(v: T) { require(true, "e"); _; }
  @ne<void>(0n) get f(x: u256): External<u256> { return x + 1n; }
}`),
    ).toContain('JETH291');
    // A BARE integer-literal array now self-types to its mobile common type (L2-MOBILE, OR cluster 4):
    // @ne([2n, 3n]) instantiates the generic modifier at u256[2] and compiles, byte-identical to solc's
    // monomorphized uint8[2] mirror (the body reads only v.length, which is width-independent - verified
    // MATCH vs both uint8[2] and uint256[2]). A METHOD reference in the same no-context position (below)
    // still rejects.
    expect(
      codes(`class C {
  @modifier ne<T>(v: T) { require(v.length > 0n, "e"); _; }
  @ne([2n, 3n]) get f(x: u256): External<u256> { return x + 1n; }
}`),
    ).toEqual([]);
    expect(
      codes(`class C {
  inc(x: u256): u256 { return x + 1n; }
  @modifier chk<T>(f: T) { require(f(1n) == 2n, "e"); _; }
  @chk(this.inc) get g(x: u256): External<u256> { return x + 10n; }
}`),
    ).toContain('JETH065');
    // a generic FUNCTION type argument stays value-only (separate catalogue row)
    expect(
      codes(`class C {
  gid<U>(x: U): U { return x; }
  get f(x: u256): External<u256> { let b: bytes = this.gid(bytes("ab")); return x + b.length; }
}`),
    ).toContain('JETH291');
    // funcref-ARRAY instantiation matches the non-generic funcref-array modifier param class
    expect(
      codes(`class C {
  inc(x: u256): u256 { return x + 1n; }
  @modifier m<T>(fs: T) { require(fs.length > 0n, "e"); _; }
  @m<((x: u256) => u256)[]>([this.inc]) get g(x: u256): External<u256> { return x + 10n; }
}`),
    ).toContain('JETH900');
    // an instantiation whose body is ill-typed at that T rejects with the BODY error (solc mirror
    // rejects too: string > int comparison)
    expect(
      codes(`class C {
  @modifier lim<T>(v: T) { require(v > 0n, "z"); _; }
  @lim<string>("a") get f(x: u256): External<u256> { return x + 1n; }
}`),
    ).toContain('JETH084');
    // explicit type arg + mismatched arg is a clean reject (solc mirror: no int_const -> bytes conversion)
    expect(
      codes(`class C {
  @modifier ne<T>(v: T) { require(v.length > 0n, "e"); _; }
  @ne<bytes>(5n) get f(x: u256): External<u256> { return x + 1n; }
}`),
    ).toContain('JETH084');
  });
});

// ---------------------------------------------------------------------------------------------------
// F-RESID stretch - Arr<Fd,2> fixed array of funcref-bearing dyn structs (memory local)
// ---------------------------------------------------------------------------------------------------
const FD_J = `type Fd = { f: (x: u256) => u256; s: string; };`;
const FD_S = `struct Fd { function(uint256) pure returns (uint256) f; string s; }`;

describe('long-tail batch D stretch: Arr<Fd,2> fixed funcref-struct array (F-RESID) byte-identical to solc 0.8.35', () => {
  it('literal, o[i].f(v) dispatch, OOB Panic, whole-element write, string-field read', async () => {
    const J = `${FD_J}
class C {
  inc(x: u256): u256 { return x + 1n; }
  dbl(x: u256): u256 { return x * 2n; }
  get go(i: u256, v: u256): External<u256> {
    let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.dbl, "b")];
    return o[i].f(v);
  }
  get w(v: u256): External<u256> {
    let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.dbl, "b")];
    o[0n] = Fd(this.dbl, "zz");
    return o[0n].f(v) + o[1n].f(v);
  }
  get sr(): External<u256> {
    let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.dbl, "bb")];
    return bytes(o[1n].s).length;
  }
}`;
    const S = `${FD_S}
contract C {
  function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
  function dbl(uint256 x) internal pure returns (uint256) { return x * 2; }
  function go(uint256 i, uint256 v) external returns (uint256) {
    Fd[2] memory o = [Fd(inc, "a"), Fd(dbl, "b")];
    return o[i].f(v);
  }
  function w(uint256 v) external returns (uint256) {
    Fd[2] memory o = [Fd(inc, "a"), Fd(dbl, "b")];
    o[0] = Fd(dbl, "zz");
    return o[0].f(v) + o[1].f(v);
  }
  function sr() external pure returns (uint256) {
    Fd[2] memory o = [Fd(inc, "a"), Fd(dbl, "bb")];
    return bytes(o[1].s).length;
  }
}`;
    await run(J, S, [
      ['go(uint256,uint256)', W(0) + W(10)], // inc -> 11
      ['go(uint256,uint256)', W(1) + W(10)], // dbl -> 20 (per-element dispatch is non-vacuous)
      ['go(uint256,uint256)', W(2) + W(10)], // OOB -> Panic 0x32 parity
      ['w(uint256)', W(10)],
      ['sr()', ''],
    ] as const);
  });

  it('element-to-local, for-of, alias write-through', async () => {
    const J = `${FD_J}
class C {
  inc(x: u256): u256 { return x + 1n; }
  dbl(x: u256): u256 { return x * 2n; }
  get el(i: u256, v: u256): External<u256> {
    let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.dbl, "b")];
    let e: Fd = o[i];
    return e.f(v);
  }
  get fo(v: u256): External<u256> {
    let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.dbl, "b")];
    let acc: u256 = 0n;
    for (const e of o) { acc = acc + e.f(v); }
    return acc;
  }
  get al(v: u256): External<u256> {
    let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.dbl, "b")];
    let p: Arr<Fd, 2> = o;
    p[0n] = Fd(this.dbl, "z");
    return o[0n].f(v) + p[1n].f(v);
  }
}`;
    const S = `${FD_S}
contract C {
  function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
  function dbl(uint256 x) internal pure returns (uint256) { return x * 2; }
  function el(uint256 i, uint256 v) external returns (uint256) {
    Fd[2] memory o = [Fd(inc, "a"), Fd(dbl, "b")];
    Fd memory e = o[i];
    return e.f(v);
  }
  function fo(uint256 v) external returns (uint256) {
    Fd[2] memory o = [Fd(inc, "a"), Fd(dbl, "b")];
    uint256 acc = 0;
    for (uint256 i = 0; i < 2; i++) { acc = acc + o[i].f(v); }
    return acc;
  }
  function al(uint256 v) external returns (uint256) {
    Fd[2] memory o = [Fd(inc, "a"), Fd(dbl, "b")];
    Fd[2] memory p = o;
    p[0] = Fd(dbl, "z");
    return o[0].f(v) + p[1].f(v);
  }
}`;
    await run(J, S, [
      ['el(uint256,uint256)', W(0) + W(10)],
      ['el(uint256,uint256)', W(1) + W(10)],
      ['fo(uint256)', W(10)],
      ['al(uint256)', W(10)], // alias is a reference: the write through p is visible through o
    ] as const);
  });

  it('ABI-leak matrix + kept rejects: every boundary and unverified consumer stays a clean reject', () => {
    const H = `${FD_J}
class C {
  inc(x: u256): u256 { return x + 1n; }`;
    // return / abi.encode / event / error / getter / external param: ABI boundaries all reject
    expect(codes(`${H}
  @external f(): Arr<Fd, 2> { let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.inc, "b")]; return o; }
}`).length).toBeGreaterThan(0);
    expect(codes(`${H}
  @external f(): bytes { let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.inc, "b")]; return abi.encode(o); }
}`)).toContain('JETH173');
    expect(codes(`${H}
  @event E(o: Arr<Fd, 2>): void;
  @external f(): u256 { let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.inc, "b")]; emit(this.E(o)); return 1n; }
}`)).toContain('JETH229');
    expect(codes(`${H}
  @error Bad(o: Arr<Fd, 2>): void;
  @external f(): u256 { let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.inc, "b")]; revert(this.Bad(o)); return 1n; }
}`)).toContain('JETH229');
    expect(codes(`${H}
  @external @state g: Arr<Fd, 2>;
  @external f(): u256 { return 1n; }
}`)).toContain('JETH057');
    expect(codes(`${H}
  @external f(o: Arr<Fd, 2>): u256 { return 1n; }
}`)).toContain('JETH210');
    // GUARD: the whole mem->storage copy rejects (solc legacy UnimplementedFeatureError = JETH467);
    // without this gate the newly-reachable local would have made `this.g = o` an OVER-ACCEPTANCE.
    expect(codes(`${H}
  @state g: Arr<Fd, 2>;
  @external f(v: u256): u256 { let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.inc, "b")]; this.g = o; return 1n; }
}`)).toContain('JETH467');
    // deeper nestings keep the JETH427 reject (single fixed outer only)
    expect(codes(`${H}
  @external f(v: u256): u256 { let o: Arr<Arr<Fd, 2>, 2> = [[Fd(this.inc, "a"), Fd(this.inc, "b")], [Fd(this.inc, "c"), Fd(this.inc, "d")]]; return o[0n][0n].f(v); }
}`)).toContain('JETH427');
    expect(codes(`${H}
  @external f(v: u256): u256 { let o: Arr<Fd, 2>[] = [[Fd(this.inc, "a"), Fd(this.inc, "b")]]; return o[0n][0n].f(v); }
}`)).toContain('JETH427');
    // a funcref-FIELD write through an element chain keeps the family JETH200 reject (the dyn-outer
    // Fd[] form rejects identically - family-consistent, clean)
    expect(codes(`${H}
  @external f(v: u256): u256 { let o: Arr<Fd, 2> = [Fd(this.inc, "a"), Fd(this.inc, "b")]; o[1n].f = this.inc; return o[1n].f(v); }
}`)).toContain('JETH200');
    // storage-source bind matches the dyn-outer class (clean reject)
    expect(codes(`${H}
  @state g: Arr<Fd, 2>;
  @external f(v: u256): u256 { let o: Arr<Fd, 2> = this.g; return o[0n].f(v); }
}`)).toContain('JETH200');
  });
});
