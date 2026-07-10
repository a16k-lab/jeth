// ICE-LIB-SIG: an EXTERNAL (delegatecall) library whose own @external fn shares a SIGNATURE with an
// external-library fn it CALLS in another external library used to die in the Yul backend with
// `DeclarationError: Duplicate case "0x.."` (surfaced as JETH901): partitionExternalLibraries pulled
// the CALLEE library's @external fn into the CALLER library's object through the purity call-graph
// edge, and emitRuntime dispatched it as a SECOND case of the same selector. A call to an @external
// library fn is ALWAYS a delegatecall executed in the callee's OWN object, so the partition BFS now
// skips delegatecall entries entirely (they are purity edges, not internal-call edges). These tests
// pin the lifted chain byte-identical against the solc external-library mirror (deploy + link both
// sides, run + DECODE, including DIRECT calls on the library addresses - where the old stray case
// also answered a selector solc's library never had), plus the unchanged controls and the
// still-reject gates.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidityLinked, deploySolLinked, compileSolidity } from './_solidity.js';
import type { Address } from '@ethereumjs/util';

const sel = (s: string) => functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n';

/** Deploy + link BOTH sides; also keep each side's deployed LIBRARY addresses so a test can call a
 *  library object directly (the surface where the stray duplicate-selector case used to live). */
async function pairLinked(jethSrc: string, solSrc: string, libNames: string[]) {
  const jb = compile(jethSrc, { fileName: 'C.jeth' });
  const sb = compileSolidityLinked(solSrc, 'C', libNames);
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const dj = await jeth.deployLinked(jb);
  const aj = dj.address;
  const jlibs = dj.libraries;
  // solc side: deploy libs bottom-up (deploySolLinked does this but keeps no addresses; redo inline).
  const slibs = new Map<string, Address>();
  const link = (hex0: string, refs: Record<string, Record<string, { start: number; length: number }[]>>) => {
    let hex = hex0.startsWith('0x') ? hex0.slice(2) : hex0;
    for (const byLib of Object.values(refs ?? {})) {
      for (const [libName, positions] of Object.entries(byLib)) {
        const addrHex = slibs.get(libName)!.toString().slice(2).padStart(40, '0');
        for (const { start } of positions) hex = hex.slice(0, start * 2) + addrHex + hex.slice(start * 2 + 40);
      }
    }
    return hex;
  };
  const depsOf = (refs: Record<string, Record<string, unknown>>) => {
    const s = new Set<string>();
    for (const byLib of Object.values(refs ?? {})) for (const n of Object.keys(byLib)) s.add(n);
    return [...s];
  };
  const pending = [...sb.libraries];
  while (pending.length) {
    const before = pending.length;
    for (let i = 0; i < pending.length; i++) {
      const lib = pending[i]!;
      if (depsOf(lib.linkReferences).every((d) => slibs.has(d))) {
        slibs.set(lib.name, await sol.deploy(link(lib.creation, lib.linkReferences)));
        pending.splice(i, 1);
        i--;
      }
    }
    if (pending.length === before) throw new Error('unresolved sol lib deps');
  }
  const as = await sol.deploy(link(sb.contractCreation, sb.linkReferences));
  return { jeth, sol, aj, as, jlibs, slibs, jb, sb };
}

type Ctx = Awaited<ReturnType<typeof pairLinked>>;

/** Call BOTH contracts with the same calldata; assert byte-identical success + returndata. */
async function expectSame(ctx: Ctx, data: string) {
  const jr = await ctx.jeth.call(ctx.aj, data);
  const sr = await ctx.sol.call(ctx.as, data);
  expect({ success: jr.success, ret: jr.returnHex }).toEqual({ success: sr.success, ret: sr.returnHex });
  return jr;
}

/** Call the same-named deployed LIBRARY object directly on both sides; assert byte-identical. */
async function expectSameOnLib(ctx: Ctx, lib: string, data: string) {
  const jr = await ctx.jeth.call(ctx.jlibs.get(lib)!, data);
  const sr = await ctx.sol.call(ctx.slibs.get(lib)!, data);
  expect({ success: jr.success, ret: jr.returnHex }).toEqual({ success: sr.success, ret: sr.returnHex });
  return jr;
}

const jethCodes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};
const solRejects = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};

describe('ICE-LIB-SIG: cross-library delegatecall with a SHARED signature (lifted over-rejection)', () => {
  it('canonical same-sig chain High.m -> Low.m is byte-identical, on the contract AND both library objects', async () => {
    const jeth = `
@library class Low { @external @pure m(x: u256): u256 { return x + 1n; } }
@library class High { @external @pure m(x: u256): u256 { return Low.m(x) * 2n; } }
@contract class C { @external @pure f(x: u256): u256 { return High.m(x); } }`;
    const sol = `${SPDX}
library Low { function m(uint256 x) public pure returns (uint256) { return x + 1; } }
library High { function m(uint256 x) public pure returns (uint256) { return Low.m(x) * 2; } }
contract C { function f(uint256 x) external pure returns (uint256) { return High.m(x); } }`;
    const ctx = await pairLinked(jeth, sol, ['Low', 'High']);
    // sanity: a real linked build (two library objects; High carries Low's placeholder).
    expect(ctx.jb.libraries?.map((l) => l.name).sort()).toEqual(['High', 'Low']);
    const r = await expectSame(ctx, encodeCall(sel('f(uint256)'), [5n]));
    expect(BigInt(r.returnHex)).toBe(12n); // (5+1)*2
    const r2 = await expectSame(ctx, encodeCall(sel('f(uint256)'), [9n]));
    expect(BigInt(r2.returnHex)).toBe(20n); // (9+1)*2
    // DIRECT library calls: each object dispatches exactly its OWN m.
    const rh = await expectSameOnLib(ctx, 'High', encodeCall(sel('m(uint256)'), [5n]));
    expect(BigInt(rh.returnHex)).toBe(12n);
    const rl = await expectSameOnLib(ctx, 'Low', encodeCall(sel('m(uint256)'), [5n]));
    expect(BigInt(rl.returnHex)).toBe(6n);
  });

  it('a 3-level same-sig chain (Top.m -> High.m -> Low.m) and each library object are byte-identical', async () => {
    const jeth = `
@library class Low { @external @pure m(x: u256): u256 { return x + 1n; } }
@library class High { @external @pure m(x: u256): u256 { return Low.m(x) * 2n; } }
@library class Top { @external @pure m(x: u256): u256 { return High.m(x) + 10n; } }
@contract class C { @external @pure f(x: u256): u256 { return Top.m(x); } }`;
    const sol = `${SPDX}
library Low { function m(uint256 x) public pure returns (uint256) { return x + 1; } }
library High { function m(uint256 x) public pure returns (uint256) { return Low.m(x) * 2; } }
library Top { function m(uint256 x) public pure returns (uint256) { return High.m(x) + 10; } }
contract C { function f(uint256 x) external pure returns (uint256) { return Top.m(x); } }`;
    const ctx = await pairLinked(jeth, sol, ['Low', 'High', 'Top']);
    const r = await expectSame(ctx, encodeCall(sel('f(uint256)'), [5n]));
    expect(BigInt(r.returnHex)).toBe(22n); // (5+1)*2+10
    expect(BigInt((await expectSameOnLib(ctx, 'Top', encodeCall(sel('m(uint256)'), [5n]))).returnHex)).toBe(22n);
    expect(BigInt((await expectSameOnLib(ctx, 'High', encodeCall(sel('m(uint256)'), [5n]))).returnHex)).toBe(12n);
    expect(BigInt((await expectSameOnLib(ctx, 'Low', encodeCall(sel('m(uint256)'), [5n]))).returnHex)).toBe(6n);
  });

  it('a DIAMOND (A.m and B.k both delegatecall Low.m; the contract calls both) is byte-identical', async () => {
    const jeth = `
@library class Low { @external @pure m(x: u256): u256 { return x + 1n; } }
@library class A { @external @pure m(x: u256): u256 { return Low.m(x) * 3n; } }
@library class B { @external @pure k(x: u256): u256 { return Low.m(x) * 5n; } }
@contract class C { @external @pure f(x: u256): u256 { return A.m(x) + B.k(x); } }`;
    const sol = `${SPDX}
library Low { function m(uint256 x) public pure returns (uint256) { return x + 1; } }
library A { function m(uint256 x) public pure returns (uint256) { return Low.m(x) * 3; } }
library B { function k(uint256 x) public pure returns (uint256) { return Low.m(x) * 5; } }
contract C { function f(uint256 x) external pure returns (uint256) { return A.m(x) + B.k(x); } }`;
    const ctx = await pairLinked(jeth, sol, ['Low', 'A', 'B']);
    const r = await expectSame(ctx, encodeCall(sel('f(uint256)'), [5n]));
    expect(BigInt(r.returnHex)).toBe(48n); // 6*3 + 6*5
    expect(BigInt((await expectSameOnLib(ctx, 'A', encodeCall(sel('m(uint256)'), [5n]))).returnHex)).toBe(18n);
    expect(BigInt((await expectSameOnLib(ctx, 'B', encodeCall(sel('k(uint256)'), [5n]))).returnHex)).toBe(30n);
  });

  it('the caller lib keeps its own fns + internal and #-private helpers next to the same-sig delegatecall', async () => {
    const jeth = `
@library class Low { @external @pure m(x: u256): u256 { return x + 1n; } helper(x: u256): u256 { return x + 3n; } }
@library class High {
  #boost(y: u256): u256 { return y + 100n; }
  @external @pure m(x: u256): u256 { return High.#boost(Low.m(x)) + Low.helper(x); }
  @external @pure g(x: u256): u256 { return x * 7n; }
}
@contract class C { @external @pure f(x: u256): u256 { return High.m(x) + High.g(x); } }`;
    const sol = `${SPDX}
library Low { function m(uint256 x) public pure returns (uint256) { return x + 1; } function helper(uint256 x) internal pure returns (uint256) { return x + 3; } }
library High {
  function boost(uint256 y) private pure returns (uint256) { return y + 100; }
  function m(uint256 x) public pure returns (uint256) { return boost(Low.m(x)) + Low.helper(x); }
  function g(uint256 x) public pure returns (uint256) { return x * 7; }
}
contract C { function f(uint256 x) external pure returns (uint256) { return High.m(x) + High.g(x); } }`;
    const ctx = await pairLinked(jeth, sol, ['Low', 'High']);
    const r = await expectSame(ctx, encodeCall(sel('f(uint256)'), [5n]));
    expect(BigInt(r.returnHex)).toBe(149n); // (6+100) + (5+3) + 35
    expect(BigInt((await expectSameOnLib(ctx, 'High', encodeCall(sel('m(uint256)'), [5n]))).returnHex)).toBe(114n);
    expect(BigInt((await expectSameOnLib(ctx, 'High', encodeCall(sel('g(uint256)'), [5n]))).returnHex)).toBe(35n);
  });

  it('a same-sig chain over a DYNAMIC type (echo(string) -> echo(string)) is byte-identical', async () => {
    const stringCall = (selector: string, s: string): string => {
      const hex = Buffer.from(s, 'utf8').toString('hex');
      const words = Math.ceil(hex.length / 2 / 32);
      return '0x' + selector + pad32(32n) + pad32(BigInt(hex.length / 2)) + hex.padEnd(words * 64, '0');
    };
    const jeth = `
@library class Low { @external @pure echo(s: string): string { return s; } }
@library class High { @external @pure echo(s: string): string { return Low.echo(s); } }
@contract class C { @external @pure es(s: string): string { return High.echo(s); } }`;
    const sol = `${SPDX}
library Low { function echo(string memory s) public pure returns (string memory) { return s; } }
library High { function echo(string memory s) public pure returns (string memory) { return Low.echo(s); } }
contract C { function es(string memory s) external pure returns (string memory) { return High.echo(s); } }`;
    const ctx = await pairLinked(jeth, sol, ['Low', 'High']);
    const r = await expectSame(ctx, stringCall(sel('es(string)'), 'ice lib sig'));
    expect(r.returnHex).toContain(Buffer.from('ice lib sig', 'utf8').toString('hex'));
    await expectSame(ctx, stringCall(sel('es(string)'), ''));
    await expectSameOnLib(ctx, 'High', stringCall(sel('echo(string)'), 'direct hi'));
  });

  it('the NATIVE spelling (static class + External<T>) of the same-sig chain is byte-identical (mode parity)', async () => {
    const jeth = `
static class Low { m(x: u256): External<u256> { return x + 1n; } }
static class High { m(x: u256): External<u256> { return Low.m(x) * 2n; } }
class C { f(x: u256): External<u256> { return High.m(x); } }`;
    const sol = `${SPDX}
library Low { function m(uint256 x) public pure returns (uint256) { return x + 1; } }
library High { function m(uint256 x) public pure returns (uint256) { return Low.m(x) * 2; } }
contract C { function f(uint256 x) external pure returns (uint256) { return High.m(x); } }`;
    const ctx = await pairLinked(jeth, sol, ['Low', 'High']);
    const r = await expectSame(ctx, encodeCall(sel('f(uint256)'), [5n]));
    expect(BigInt(r.returnHex)).toBe(12n);
    expect(BigInt((await expectSameOnLib(ctx, 'High', encodeCall(sel('m(uint256)'), [5n]))).returnHex)).toBe(12n);
  });
});

describe('ICE-LIB-SIG: unchanged controls', () => {
  it('DISTINCT names (High.h -> Low.m): works, and the callee selector is NOT dispatched by the caller object', async () => {
    const jeth = `
@library class Low { @external @pure m(x: u256): u256 { return x + 1n; } }
@library class High { @external @pure h(x: u256): u256 { return Low.m(x) * 2n; } }
@contract class C { @external @pure f(x: u256): u256 { return High.h(x); } }`;
    const sol = `${SPDX}
library Low { function m(uint256 x) public pure returns (uint256) { return x + 1; } }
library High { function h(uint256 x) public pure returns (uint256) { return Low.m(x) * 2; } }
contract C { function f(uint256 x) external pure returns (uint256) { return High.h(x); } }`;
    const ctx = await pairLinked(jeth, sol, ['Low', 'High']);
    const r = await expectSame(ctx, encodeCall(sel('f(uint256)'), [5n]));
    expect(BigInt(r.returnHex)).toBe(12n);
    expect(BigInt((await expectSameOnLib(ctx, 'High', encodeCall(sel('h(uint256)'), [5n]))).returnHex)).toBe(12n);
    // High's object must NOT answer Low's selector m(uint256): solc's High has no such case (revert on
    // both sides). Before this fix JETH's High carried a stray m-case executing Low.m's body.
    const stray = await expectSameOnLib(ctx, 'High', encodeCall(sel('m(uint256)'), [5n]));
    expect(stray.success).toBe(false);
  });

  it('same-sig but UNCALLED, and a contract calling two same-sig libraries, stay byte-identical', async () => {
    const jeth = `
@library class Low { @external @pure m(x: u256): u256 { return x + 1n; } }
@library class High { @external @pure m(x: u256): u256 { return x * 3n; } }
@contract class C { @external @pure f(x: u256): u256 { return High.m(x) + Low.m(x); } }`;
    const sol = `${SPDX}
library Low { function m(uint256 x) public pure returns (uint256) { return x + 1; } }
library High { function m(uint256 x) public pure returns (uint256) { return x * 3; } }
contract C { function f(uint256 x) external pure returns (uint256) { return High.m(x) + Low.m(x); } }`;
    const ctx = await pairLinked(jeth, sol, ['Low', 'High']);
    const r = await expectSame(ctx, encodeCall(sel('f(uint256)'), [5n]));
    expect(BigInt(r.returnHex)).toBe(21n); // 15 + 6
  });

  it('the contract declaring its OWN same-sig fn keeps its own dispatcher case', async () => {
    const jeth = `
@library class Low { @external @pure m(x: u256): u256 { return x + 1n; } }
@library class High { @external @pure m(x: u256): u256 { return Low.m(x) * 2n; } }
@contract class C { @external @pure m(x: u256): u256 { return x * 100n; } @external @pure f(x: u256): u256 { return High.m(x); } }`;
    const sol = `${SPDX}
library Low { function m(uint256 x) public pure returns (uint256) { return x + 1; } }
library High { function m(uint256 x) public pure returns (uint256) { return Low.m(x) * 2; } }
contract C { function m(uint256 x) external pure returns (uint256) { return x * 100; } function f(uint256 x) external pure returns (uint256) { return High.m(x); } }`;
    const ctx = await pairLinked(jeth, sol, ['Low', 'High']);
    expect(BigInt((await expectSame(ctx, encodeCall(sel('m(uint256)'), [5n]))).returnHex)).toBe(500n);
    expect(BigInt((await expectSame(ctx, encodeCall(sel('f(uint256)'), [5n]))).returnHex)).toBe(12n);
  });
});

describe('ICE-LIB-SIG: still-reject gates', () => {
  it('two external libraries sharing one source name stay rejected (JETH037; solc duplicate declaration)', () => {
    const jeth = `
@library class Low { @external @pure m(x: u256): u256 { return x + 1n; } }
@library class Low { @external @pure m(x: u256): u256 { return x + 2n; } }
@contract class C { @external @pure f(x: u256): u256 { return Low.m(x); } }`;
    const sol = `
library Low { function m(uint256 x) public pure returns (uint256) { return x + 1; } }
library Low { function m(uint256 x) public pure returns (uint256) { return x + 2; } }
contract C { function f(uint256 x) external pure returns (uint256) { return Low.m(x); } }`;
    expect(jethCodes(jeth).length).toBeGreaterThan(0);
    expect(solRejects(sol)).toBe(true);
  });

  it('calling a fn the callee library does not declare stays rejected (JETH392; solc member lookup)', () => {
    const jeth = `
@library class Low { @external @pure m(x: u256): u256 { return x + 1n; } }
@library class High { @external @pure m(x: u256): u256 { return Low.q(x) * 2n; } }
@contract class C { @external @pure f(x: u256): u256 { return High.m(x); } }`;
    const sol = `
library Low { function m(uint256 x) public pure returns (uint256) { return x + 1; } }
library High { function m(uint256 x) public pure returns (uint256) { return Low.q(x) * 2; } }
contract C { function f(uint256 x) external pure returns (uint256) { return High.m(x); } }`;
    expect(jethCodes(jeth)).toContain('JETH392');
    expect(solRejects(sol)).toBe(true);
  });
});
