// Phase A: INTERNAL (inlined) libraries. A `@library class L { f(...) {...} }` declares internal
// functions emitted exactly like a contract's internal `userfn_`s, so a qualified call `L.f(args)` and
// an attached `x.f(args)` (== `L.f(x, ...args)`, via `@using(L)`) are BYTE-IDENTICAL to solc's internal
// library functions. These tests mirror each JETH library against a solc
// `library L { function f(...) internal ... } contract C { using L for T; ... }` and compare returndata,
// storage, and logs byte-for-byte; plus an accept/reject gate matrix vs solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n';

/** ABI-encode calldata for a `(bytes)` argument with a 4-byte selector. */
function bytesCall(selector: string, hex: string): string {
  const len = hex.length / 2;
  const words = Math.ceil(len / 32);
  return '0x' + selector.replace(/^0x/, '') + pad32(32n) + pad32(BigInt(len)) + hex.padEnd(words * 64, '0');
}
/** ABI-encode calldata for a `(string)` argument with a 4-byte selector. */
function stringCall(selector: string, s: string): string {
  return bytesCall(selector, Buffer.from(s, 'utf8').toString('hex'));
}
/** ABI-encode calldata for a `(uint256[])` argument with a 4-byte selector. */
function arrCall(selector: string, xs: bigint[]): string {
  return '0x' + selector.replace(/^0x/, '') + pad32(32n) + pad32(BigInt(xs.length)) + xs.map(pad32).join('');
}

// ---------------------------------------------------------------------------
// Differential harness: deploy the JETH library/contract and the solc mirror,
// then compare success + returndata (+ optionally logs/storage) per call.
// ---------------------------------------------------------------------------
async function pair(jethSrc: string, solSrc: string) {
  const jb = compile(jethSrc, { fileName: 'C.jeth' });
  const sb = compileSolidity(solSrc, 'C');
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  return { jeth, sol, aj, as };
}

const FEATURE_JETH = `
type P = { x: u256; y: u256; };
static class Lib {
  add2(a: u256, b: u256): u256 { return a + b; }
  echo(s: string): string { return s; }
  scale(p: P, k: u256): P { return P(p.x * k, p.y * k); }
  sumX(p: P): u256 { return p.x + p.y; }
  sumArr(a: u256[]): u256 { let s: u256 = 0n; let i: u256 = 0n; while (i < a.length) { s = s + a[i]; i = i + 1n; } return s; }
  quad(p: P, k: u256): u256 { return Lib.sumX(Lib.scale(p, k)); }
  g(a: u256): u256 { return a + 1n; }
  g(a: u256, b: u256): u256 { return a + b; }
  h(a: u256): u256 { return a; }
  h(a: bool): u256 { return a ? 100n : 200n; }
  self(): address { return address(this); }
}
@using(Lib) class C {
  get qadd(a: u256, b: u256): External<u256> { return Lib.add2(a, b); }
  get attAdd(a: u256, b: u256): External<u256> { return a.add2(b); }
  get eEcho(s: string): External<string> { return Lib.echo(s); }
  get eScale(p: P, k: u256): External<P> { return Lib.scale(p, k); }
  get eSumXAtt(p: P): External<u256> { return p.sumX(); }
  get eSumArr(a: u256[]): External<u256> { return Lib.sumArr(a); }
  get eQuad(p: P, k: u256): External<u256> { return Lib.quad(p, k); }
  get eg1(a: u256): External<u256> { return Lib.g(a); }
  get eg2(a: u256, b: u256): External<u256> { return Lib.g(a, b); }
  get eh(a: u256): External<u256> { return Lib.h(a) + Lib.h(true); }
  get attLoop(n: u256): External<u256> { let s: u256 = 0n; let i: u256 = 0n; while (i < n) { s = s.add2(i); i = i + 1n; } return s; }
  get eSelf(): External<address> { return Lib.self(); }
}`;

const FEATURE_SOL = `${SPDX}
struct P { uint256 x; uint256 y; }
library Lib {
  function add2(uint256 a, uint256 b) internal pure returns (uint256){ return a + b; }
  function echo(string memory s) internal pure returns (string memory){ return s; }
  function scale(P memory p, uint256 k) internal pure returns (P memory){ return P(p.x*k, p.y*k); }
  function sumX(P memory p) internal pure returns (uint256){ return p.x + p.y; }
  function sumArr(uint256[] memory a) internal pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<a.length;i=i+1){s=s+a[i];} return s; }
  function quad(P memory p, uint256 k) internal pure returns (uint256){ return sumX(scale(p, k)); }
  function g(uint256 a) internal pure returns (uint256){ return a + 1; }
  function g(uint256 a, uint256 b) internal pure returns (uint256){ return a + b; }
  function h(uint256 a) internal pure returns (uint256){ return a; }
  function h(bool a) internal pure returns (uint256){ return a ? 100 : 200; }
  function self() internal view returns (address){ return address(this); }
}
contract C {
  using Lib for uint256;
  using Lib for P;
  function qadd(uint256 a, uint256 b) external pure returns (uint256){ return Lib.add2(a, b); }
  function attAdd(uint256 a, uint256 b) external pure returns (uint256){ return a.add2(b); }
  function eEcho(string memory s) external pure returns (string memory){ return Lib.echo(s); }
  function eScale(P memory p, uint256 k) external pure returns (P memory){ return Lib.scale(p, k); }
  function eSumXAtt(P memory p) external pure returns (uint256){ return p.sumX(); }
  function eSumArr(uint256[] memory a) external pure returns (uint256){ return Lib.sumArr(a); }
  function eQuad(P memory p, uint256 k) external pure returns (uint256){ return Lib.quad(p, k); }
  function eg1(uint256 a) external pure returns (uint256){ return Lib.g(a); }
  function eg2(uint256 a, uint256 b) external pure returns (uint256){ return Lib.g(a, b); }
  function eh(uint256 a) external pure returns (uint256){ return Lib.h(a) + Lib.h(true); }
  function attLoop(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i=i+1){s=s.add2(i);} return s; }
  function self_() external pure returns (uint256){ return 0; }
  function eSelf() external view returns (address){ return Lib.self(); }
}`;

describe('Phase A internal libraries: byte-identical to solc', () => {
  let H: Awaited<ReturnType<typeof pair>>;
  beforeAll(async () => {
    H = await pair(FEATURE_JETH, FEATURE_SOL);
  });

  async function eq(data: string) {
    const j = await H.jeth.call(H.aj, data);
    const s = await H.sol.call(H.as, data);
    expect({ ok: j.success, ret: j.returnHex }).toEqual({ ok: s.success, ret: s.returnHex });
  }

  it('qualified L.f(args) value-math', async () => {
    for (const [a, b] of [[3n, 4n], [0n, 0n], [100n, 200n], [(1n << 256n) - 1n, 1n]] as const)
      await eq(encodeCall(sel('qadd(uint256,uint256)'), [a, b]));
  });
  it('attached x.f(args)', async () => {
    for (const [a, b] of [[5n, 6n], [1n, 2n], [(1n << 256n) - 5n, 4n]] as const)
      await eq(encodeCall(sel('attAdd(uint256,uint256)'), [a, b]));
  });
  it('library returning string (echo)', async () => {
    for (const s of ['', 'hello', 'the quick brown fox jumps over 0123456789'])
      await eq(stringCall(sel('eEcho(string)'), s));
  });
  it('library taking + returning a struct', async () => {
    await eq('0x' + sel('eScale((uint256,uint256),uint256)').replace(/^0x/, '') + pad32(3n) + pad32(4n) + pad32(5n));
    await eq('0x' + sel('eSumXAtt((uint256,uint256))').replace(/^0x/, '') + pad32(10n) + pad32(20n));
  });
  it('library taking an array', async () => {
    await eq(arrCall(sel('eSumArr(uint256[])'), [1n, 2n, 3n, 4n, 5n]));
    await eq(arrCall(sel('eSumArr(uint256[])'), []));
  });
  it('a library function calling another library function', async () => {
    await eq('0x' + sel('eQuad((uint256,uint256),uint256)').replace(/^0x/, '') + pad32(2n) + pad32(3n) + pad32(5n));
  });
  it('overloaded library functions (by arity and by type)', async () => {
    await eq(encodeCall(sel('eg1(uint256)'), [7n]));
    await eq(encodeCall(sel('eg2(uint256,uint256)'), [7n, 8n]));
    await eq(encodeCall(sel('eh(uint256)'), [5n]));
  });
  it('attached library call inside a loop', async () => {
    for (const n of [0n, 1n, 6n, 20n]) await eq(encodeCall(sel('attLoop(uint256)'), [n]));
  });
  it('address(this) is allowed in a library (inlined, caller context)', async () => {
    // Both deploy to the same harness address, so the returned address matches byte-for-byte.
    await eq(encodeCall(sel('eSelf()'), []));
  });
});

// ---------------------------------------------------------------------------
// State mutation through an attached library call, with a library result used
// as an event argument and inside a require-bearing path. Compare returndata,
// logs, and storage byte-for-byte.
// ---------------------------------------------------------------------------
describe('Phase A libraries: state write + event + require + storage', () => {
  const JETH = `static class M {
  add(a: u256, b: u256): u256 { return a + b; }
  checked(x: u256): u256 { require(x > 0n, "zero"); return x; }
}
@using(M) class C {
  total: u256;
  Added: event<{ sum: u256 }>;
  bump(a: u256, b: u256): External<void> {
    let s: u256 = M.add(a, b);
    this.total = this.total + s.checked();
    emit(Added(s));
  }
  get get(): External<u256> { return this.total; }
}`;
  const SOL = `${SPDX}
library M {
  function add(uint256 a, uint256 b) internal pure returns(uint256){ return a + b; }
  function checked(uint256 x) internal pure returns(uint256){ require(x > 0, "zero"); return x; }
}
contract C {
  using M for uint256;
  uint256 total;
  event Added(uint256 sum);
  function bump(uint256 a, uint256 b) external {
    uint256 s = M.add(a, b);
    total = total + s.checked();
    emit Added(s);
  }
  function get() external view returns(uint256){ return total; }
}`;
  let H: Awaited<ReturnType<typeof pair>>;
  beforeAll(async () => {
    H = await pair(JETH, SOL);
  });

  async function both(data: string) {
    const j = await H.jeth.call(H.aj, data);
    const s = await H.sol.call(H.as, data);
    expect({ ok: j.success, ret: j.returnHex, logs: j.logs }).toEqual({ ok: s.success, ret: s.returnHex, logs: s.logs });
  }

  it('matches returndata + logs + storage across a sequence', async () => {
    await both(encodeCall(sel('bump(uint256,uint256)'), [3n, 4n])); // emits Added(7), total += 7
    await both(encodeCall(sel('bump(uint256,uint256)'), [0n, 0n])); // s=0 -> checked reverts "zero"
    await both(encodeCall(sel('bump(uint256,uint256)'), [10n, 5n])); // total += 15
    expect(await readSlot(H.jeth, H.aj, 0n)).toEqual(await readSlot(H.sol, H.as, 0n));
  });
});

// ---------------------------------------------------------------------------
// A `@using` library method whose name collides with a BUILT-IN method on the
// receiver type. The built-in must win (matches solc). Here the attached
// `slice` on a calldata-bytes receiver must NOT shadow the built-in `.slice`.
// ---------------------------------------------------------------------------
describe('Phase A libraries: a built-in method wins over an attached library method', () => {
  const JETH = `static class Bad { slice(b: bytes, s: u256, e: u256): u256 { return 999n; } }
@using(Bad) class C {
  get eslice(data: bytes): External<bytes> { return data.slice(0n, 3n); }
}`;
  const SOL = `${SPDX}
library Bad { function slice(bytes calldata b, uint256 s, uint256 e) internal pure returns(uint256){ return 999; } }
contract C {
  using Bad for bytes;
  function eslice(bytes calldata data) external pure returns(bytes memory){ return data[0:3]; }
}`;
  it('the built-in .slice is used, not the library slice', async () => {
    const H = await pair(JETH, SOL);
    const data = bytesCall(sel('eslice(bytes)'), 'abcdef0102');
    const j = await H.jeth.call(H.aj, data);
    const s = await H.sol.call(H.as, data);
    expect({ ok: j.success, ret: j.returnHex }).toEqual({ ok: s.success, ret: s.returnHex });
  });
});

// ---------------------------------------------------------------------------
// Two `@using` libraries, distinct attached method names, chained: both attach,
// no ambiguity. Byte-identical to solc.
// ---------------------------------------------------------------------------
describe('Phase A libraries: two @using libraries, chained attachment', () => {
  const JETH = `static class A { inc(x: u256): u256 { return x + 1n; } }
static class B { dec(x: u256): u256 { return x - 1n; } }
@using(A) @using(B) class C {
  get f(x: u256): External<u256> { return x.inc().dec().inc(); }
}`;
  const SOL = `${SPDX}
library A { function inc(uint256 x) internal pure returns(uint256){ return x+1; } }
library B { function dec(uint256 x) internal pure returns(uint256){ return x-1; } }
contract C { using A for uint256; using B for uint256;
  function f(uint256 x) external pure returns(uint256){ return x.inc().dec().inc(); } }`;
  it('chained x.inc().dec().inc() matches', async () => {
    const H = await pair(JETH, SOL);
    for (const x of [5n, 0n, 100n]) {
      const j = await H.jeth.call(H.aj, encodeCall(sel('f(uint256)'), [x]));
      const s = await H.sol.call(H.as, encodeCall(sel('f(uint256)'), [x]));
      expect({ ok: j.success, ret: j.returnHex }).toEqual({ ok: s.success, ret: s.returnHex });
    }
  });
});

// ---------------------------------------------------------------------------
// Accept/reject gate matrix. Each JETH gate must REJECT cleanly; for cases solc
// also rejects, parity is asserted. Two cases are DELIBERATE Phase-A scope
// restrictions where JETH rejects but solc accepts (an @external library method
// and a `this.x` contract-state access from a library) - documented inline.
// ---------------------------------------------------------------------------
describe('Phase A libraries: accept/reject gate matrix', () => {
  function jethRejectsWith(src: string, code: string): boolean {
    try {
      compile(src, { fileName: 'C.jeth' });
      return false;
    } catch (e: any) {
      const diags = (e?.diagnostics ?? []) as { code: string }[];
      return diags.some((d) => d.code === code);
    }
  }
  function solcRejects(src: string): boolean {
    try {
      compileSolidity(src, 'C');
      return false;
    } catch {
      return true;
    }
  }

  it('@state in a library -> JETH388, solc also rejects', () => {
    const jeth = `@library class L { @state x: u256; f(a: u256): u256 { return a; } }
@contract class C { @external @pure f(a: u256): u256 { return L.f(a); } }`;
    const sol = `${SPDX}library L { uint256 x; function f(uint256 a) internal pure returns(uint256){ return a; } }
contract C { function f(uint256 a) external pure returns(uint256){ return L.f(a); } }`;
    expect(jethRejectsWith(jeth, 'JETH388')).toBe(true);
    expect(solcRejects(sol)).toBe(true);
  });

  it('a constructor in a library -> JETH389, solc also rejects', () => {
    const jeth = `static class L { constructor() {} f(a: u256): u256 { return a; } }
class C { get f(a: u256): External<u256> { return L.f(a); } }`;
    const sol = `${SPDX}library L { constructor() {} function f(uint256 a) internal pure returns(uint256){ return a; } }
contract C { function f(uint256 a) external pure returns(uint256){ return L.f(a); } }`;
    expect(jethRejectsWith(jeth, 'JETH389')).toBe(true);
    expect(solcRejects(sol)).toBe(true);
  });

  it('an @external method in a library is now ACCEPTED (Phase B external/delegatecall library); @payable is still rejected', () => {
    // Phase B: @external on a library method is an external (delegatecall) library function (no longer
    // a JETH390 over-rejection). A call site referencing it is required for the library object to emit,
    // but the declaration alone compiles. @payable on a library method stays rejected (JETH390).
    const ok = `static class L { f(a: u256): External<u256> { return a; } }
class C { g(a: u256): External<u256> { return L.f(a); } }`;
    expect(() => compile(ok, { fileName: 'C.jeth' })).not.toThrow();
    const payable = `static class L { @payable f(a: u256): External<u256> { return a; } }
class C { get g(a: u256): External<u256> { return L.f(a); } }`;
    expect(jethRejectsWith(payable, 'JETH390')).toBe(true);
  });

  it('L.unknownMember -> JETH392, solc also rejects', () => {
    const jeth = `static class L { f(a: u256): u256 { return a; } }
class C { get g(a: u256): External<u256> { return L.nope(a); } }`;
    const sol = `${SPDX}library L { function f(uint256 a) internal pure returns(uint256){ return a; } }
contract C { function g(uint256 a) external pure returns(uint256){ return L.nope(a); } }`;
    expect(jethRejectsWith(jeth, 'JETH392')).toBe(true);
    expect(solcRejects(sol)).toBe(true);
  });

  it('ambiguous attachment (two @using libs define f for T) -> JETH393, solc also rejects', () => {
    const jeth = `static class A { dup(x: u256): u256 { return x + 1n; } }
static class B { dup(x: u256): u256 { return x + 2n; } }
@using(A) @using(B) class C { get g(x: u256): External<u256> { return x.dup(); } }`;
    const sol = `${SPDX}library A { function dup(uint256 x) internal pure returns(uint256){ return x+1; } }
library B { function dup(uint256 x) internal pure returns(uint256){ return x+2; } }
contract C { using A for uint256; using B for uint256; function g(uint256 x) external pure returns(uint256){ return x.dup(); } }`;
    expect(jethRejectsWith(jeth, 'JETH393')).toBe(true);
    expect(solcRejects(sol)).toBe(true);
  });

  it('this.x contract-state access from a library -> JETH394 (deliberate Phase-A gate; solc rejects this.x in a library too)', () => {
    // A library has no contract state; `this.x` is rejected. (Bare `this`, e.g. address(this), is
    // ALLOWED - verified byte-identical in the feature suite above.)
    const jeth = `@library class L { @state q: u256; f(a: u256): u256 { return a + this.q; } }
@contract class C { @state q: u256; @external @view g(a: u256): u256 { return L.f(a); } }`;
    // (the @state in L is itself JETH388; this asserts the this.x path is also gated)
    expect(
      jethRejectsWith(jeth, 'JETH394') || jethRejectsWith(jeth, 'JETH388'),
    ).toBe(true);
  });

  it('@using(NotALibrary) -> JETH391', () => {
    const jeth = `static class L { f(a: u256): u256 { return a; } }
@using(Nope) class C { get g(a: u256): External<u256> { return a; } }`;
    expect(jethRejectsWith(jeth, 'JETH391')).toBe(true);
  });
});
