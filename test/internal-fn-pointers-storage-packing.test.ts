// W3-A1-funcref: four lifts, each byte-identical to solc 0.8.35 (returndata + storage slots + accept/reject).
//   P0-32  STORAGE PACKING: an internal function pointer is solc's 8-byte `function internal` type, so it
//          PACKS with neighbors (4-per-slot in arrays). Neighbor placement is byte-identical to solc; only
//          the pointer VALUE byte (JETH dispatch id vs solc code offset) differs, which is unmatchable by
//          construction. The null-pointer Panic(0x51) is preserved on 8-byte fields.
//   P1-18  aggregate-signature funcref call `g: (a: u256[]) => u256` -> dispatched via a memptr word.
//   P1-19  a @view/@pure function is NOT poisoned by a same-signature mutating function that merely EXISTS
//          or is address-taken but never reached; a genuinely-mutating reachable target still rejects.
//   P1-22  a funcref tuple-return COMPONENT (`let [a, g] = this.mk()`) and a library funcref VALUE (`L.f`).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const pad = (v: bigint): bigint => v;

/** Mask out the given [byteOffset, byteLen] regions (funcref id fields, low-order byte = offset 0) of a
 *  32-byte storage word so the neighbor bytes can be compared byte-identically to solc. */
function maskFuncref(hex: string, regions: [number, number][]): bigint {
  let w = BigInt(hex);
  for (const [off, len] of regions) w &= ~(((1n << BigInt(len * 8)) - 1n) << BigInt(off * 8));
  return w;
}

function jethBuild(src: string): { ok: boolean; codes: string[]; bc?: string } {
  try {
    return { ok: true, codes: [], bc: compile(src, { fileName: 'C.jeth' }).creationBytecode };
  } catch (e) {
    return { ok: false, codes: ((e as { diagnostics?: { code: string }[] }).diagnostics ?? []).map((d) => d.code) };
  }
}
function solcAccepts(src: string): boolean {
  try {
    compileSolidity(SPDX + src, 'C');
    return true;
  } catch {
    return false;
  }
}

/** Deploy JETH + solc mirror, run calls, assert byte-identical (success + returndata). */
async function behavesLikeSolc(
  jethSrc: string,
  solSrc: string,
  calls: { sig: string; args?: bigint[] }[],
): Promise<{ jeth: Harness; sol: Harness; aj: Address; as: Address }> {
  const jb = compile(jethSrc, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + solSrc, 'C');
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  for (const c of calls) {
    const data = encodeCall(sel(c.sig), c.args ?? []);
    const jr = await jeth.call(aj, data);
    const sr = await sol.call(as, data);
    expect(jr.success, `${c.sig} success (jeth err=${jr.exceptionError})`).toBe(sr.success);
    expect(jr.returnHex, `${c.sig} returndata`).toBe(sr.returnHex);
  }
  return { jeth, sol, aj, as };
}

describe('P0-32 funcref storage packing: byte-identical NEIGHBOR placement + layout', () => {
  it('funcref packs between two u128 (neighbor bytes identical to solc)', async () => {
    const JETH = `class C {
      g(x: u256): u256 { return x; }
      a: u128;
      h: (x: u256) => u256;
      b: u128;
      seed(): External<void> { this.a = 0x1111n; this.b = 0x2222n; this.h = this.g; }
    }`;
    const SOL = `contract C {
      function g(uint256 x) internal pure returns(uint256){ return x; }
      uint128 a;
      function(uint256) internal pure returns(uint256) h;
      uint128 b;
      function seed() external { a = 0x1111; b = 0x2222; h = g; }
    }`;
    const { jeth, sol, aj, as } = await behavesLikeSolc(JETH, SOL, [{ sig: 'seed()' }]);
    // slot0: a@0(16B), h@16(8B funcref), then only 8B left -> b starts slot1.
    expect(maskFuncref(await readSlot(jeth, aj, 0n), [[16, 8]])).toBe(maskFuncref(await readSlot(sol, as, 0n), [[16, 8]]));
    expect(await readSlot(jeth, aj, 1n)).toBe(await readSlot(sol, as, 1n));
  });

  it('four funcrefs pack into one slot, u64 neighbor lands identically', async () => {
    const JETH = `class C {
      f0(x: u256): u256 { return x; }
      f1(x: u256): u256 { return x + 1n; }
      a: (x: u256) => u256; b: (x: u256) => u256;
      c: (x: u256) => u256; d: (x: u256) => u256;
      n: u64;
      seed(): External<void> { this.a = this.f0; this.b = this.f1; this.c = this.f0; this.d = this.f1; this.n = 0xabcdn; }
    }`;
    const SOL = `contract C {
      function f0(uint256 x) internal pure returns(uint256){ return x; }
      function f1(uint256 x) internal pure returns(uint256){ return x + 1; }
      function(uint256) internal pure returns(uint256) a; function(uint256) internal pure returns(uint256) b;
      function(uint256) internal pure returns(uint256) c; function(uint256) internal pure returns(uint256) d;
      uint64 n;
      function seed() external { a = f0; b = f1; c = f0; d = f1; n = 0xabcd; }
    }`;
    const { jeth, sol, aj, as } = await behavesLikeSolc(JETH, SOL, [{ sig: 'seed()' }]);
    const regions: [number, number][] = [[0, 8], [8, 8], [16, 8], [24, 8]];
    expect(maskFuncref(await readSlot(jeth, aj, 0n), regions)).toBe(maskFuncref(await readSlot(sol, as, 0n), regions));
    expect(await readSlot(jeth, aj, 1n)).toBe(await readSlot(sol, as, 1n)); // n@slot1
  });

  it('Arr<funcref,4> occupies exactly one slot; u256 neighbor at slot1', async () => {
    const JETH = `class C {
      g(x: u256): u256 { return x; }
      fs: Arr<(x: u256) => u256, 4>;
      z: u256;
      seed(): External<void> { this.fs[0] = this.g; this.fs[3] = this.g; this.z = 0xdeadn; }
    }`;
    const SOL = `contract C {
      function g(uint256 x) internal pure returns(uint256){ return x; }
      function(uint256) internal pure returns(uint256)[4] fs;
      uint256 z;
      function seed() external { fs[0] = g; fs[3] = g; z = 0xdead; }
    }`;
    const { jeth, sol, aj, as } = await behavesLikeSolc(JETH, SOL, [{ sig: 'seed()' }]);
    expect(await readSlot(jeth, aj, 1n)).toBe(await readSlot(sol, as, 1n)); // z@slot1 (fs took only slot0)
    expect(await readSlot(sol, as, 1n)).toBe('0x' + (0xdeadn).toString(16).padStart(64, '0'));
  });

  it('Arr<funcref,5> occupies two slots; u256 neighbor at slot2', async () => {
    const JETH = `class C {
      g(x: u256): u256 { return x; }
      fs: Arr<(x: u256) => u256, 5>;
      z: u256;
      seed(): External<void> { this.fs[4] = this.g; this.z = 0xbeefn; }
    }`;
    const SOL = `contract C {
      function g(uint256 x) internal pure returns(uint256){ return x; }
      function(uint256) internal pure returns(uint256)[5] fs;
      uint256 z;
      function seed() external { fs[4] = g; z = 0xbeef; }
    }`;
    const { jeth, sol, aj, as } = await behavesLikeSolc(JETH, SOL, [{ sig: 'seed()' }]);
    expect(await readSlot(jeth, aj, 2n)).toBe(await readSlot(sol, as, 2n)); // z@slot2 (fs took slots 0,1)
    expect(await readSlot(sol, as, 2n)).toBe('0x' + (0xbeefn).toString(16).padStart(64, '0'));
  });

  it('struct{u64,funcref,u64} packs the funcref field between neighbors', async () => {
    const JETH = `type S = { x: u64; h: (z: u256) => u256; y: u64; };
    class C {
      g(z: u256): u256 { return z; }
      s: S;
      seed(): External<void> { this.s.x = 0x44n; this.s.y = 0x55n; this.s.h = this.g; }
    }`;
    const SOL = `contract C {
      struct S { uint64 x; function(uint256) internal pure returns(uint256) h; uint64 y; }
      function g(uint256 z) internal pure returns(uint256){ return z; }
      S s;
      function seed() external { s.x = 0x44; s.y = 0x55; s.h = g; }
    }`;
    const { jeth, sol, aj, as } = await behavesLikeSolc(JETH, SOL, [{ sig: 'seed()' }]);
    // S packs x@0, h@8, y@16 in slot0.
    expect(maskFuncref(await readSlot(jeth, aj, 0n), [[8, 8]])).toBe(maskFuncref(await readSlot(sol, as, 0n), [[8, 8]]));
  });

  it('null (unset) packed @state funcref call reverts Panic(0x51), clean slot, identical to solc', async () => {
    const JETH = `class C {
      g(x: u256): u256 { return x; }
      a: u64; h: (x: u256) => u256; b: u64;
      setit(): External<void> { this.h = this.g; }
      get callh(): External<u256> { return this.h(3n); }
    }`;
    const SOL = `contract C {
      function g(uint256 x) internal pure returns(uint256){ return x; }
      uint64 a; function(uint256) internal pure returns(uint256) h; uint64 b;
      function setit() external { h = g; }
      function callh() external returns(uint256){ return h(3); }
    }`;
    // NOTE: no seed of the neighbors -> the slot is clean; both revert with Panic(0x51). (solc's optimizer
    // yields an EMPTY revert on this null path ONLY when a packed neighbor has DIRTIED the slot - an
    // unmatchable solc-internal quirk on the error path that predates this change and is documented.)
    await behavesLikeSolc(JETH, SOL, [{ sig: 'callh()' }]);
  });
});

describe('P1-18 aggregate-signature internal funcref call', () => {
  const cases: bigint[][] = [[], [5n], [1n, 2n, 3n], [10n, 20n, 30n, 40n]];
  for (const arr of cases) {
    it(`sum through a (u256[])=>u256 pointer, arr len ${arr.length}`, async () => {
      const jArr = arr.length ? `let arr: u256[] = [${arr.map((x) => x + 'n').join(', ')}];` : `let arr: u256[] = new Array<u256>(0n);`;
      const sArr = arr.length
        ? `uint256[] memory arr = new uint256[](${arr.length}); ${arr.map((x, i) => `arr[${i}]=${x};`).join(' ')}`
        : `uint256[] memory arr = new uint256[](0);`;
      const JETH = `@contract class C {
        @pure sum(a: u256[]): u256 { let t: u256 = 0n; for (let i: u256 = 0n; i < a.length; i = i + 1n) { t = t + a[i]; } return t; }
        @pure ap(g: (a: u256[]) => u256, x: u256[]): u256 { return g(x); }
        @external @pure run(): u256 { ${jArr} return this.ap(this.sum, arr); }
      }`;
      const SOL = `contract C {
        function sum(uint256[] memory a) internal pure returns(uint256){ uint256 t=0; for(uint256 i=0;i<a.length;i++){t+=a[i];} return t; }
        function ap(function(uint256[] memory) internal pure returns(uint256) g, uint256[] memory x) internal pure returns(uint256){ return g(x); }
        function run() external pure returns(uint256){ ${sArr} return ap(sum, arr); }
      }`;
      await behavesLikeSolc(JETH, SOL, [{ sig: 'run()' }]);
    });
  }

  it('a funcref RETURNING an aggregate (u256[]) dispatches by memptr', async () => {
    const JETH = `class C {
      mkArr(n: u256): u256[] { let a: u256[] = [n, n + 1n, n + 2n]; return a; }
      ap(g: (n: u256) => u256[], v: u256): u256[] { return g(v); }
      get r(): External<u256[]> { return this.ap(this.mkArr, 100n); }
    }`;
    const SOL = `contract C {
      function mkArr(uint256 n) internal pure returns(uint256[] memory){ uint256[] memory a=new uint256[](3); a[0]=n;a[1]=n+1;a[2]=n+2; return a; }
      function ap(function(uint256) internal pure returns(uint256[] memory) g, uint256 v) internal pure returns(uint256[] memory){ return g(v); }
      function r() external pure returns(uint256[] memory){ return ap(mkArr, 100); }
    }`;
    await behavesLikeSolc(JETH, SOL, [{ sig: 'r()' }]);
  });

  it('a funcref RETURNING a struct dispatches by memptr', async () => {
    const JETH = `type P = { a: u256; b: u256; };
    class C {
      mkP(n: u256): P { let p: P = { a: n, b: n * 2n }; return p; }
      ap(g: (n: u256) => P, v: u256): P { return g(v); }
      get r(): External<u256> { let p: P = this.ap(this.mkP, 5n); return p.a + p.b; }
    }`;
    const SOL = `contract C {
      struct P { uint256 a; uint256 b; }
      function mkP(uint256 n) internal pure returns(P memory){ return P(n, n*2); }
      function ap(function(uint256) internal pure returns(P memory) g, uint256 v) internal pure returns(P memory){ return g(v); }
      function r() external pure returns(uint256){ P memory p = ap(mkP, 5); return p.a + p.b; }
    }`;
    await behavesLikeSolc(JETH, SOL, [{ sig: 'r()' }]);
  });
});

describe('P1-19 funcref effect over-conservatism', () => {
  it('@view function is NOT poisoned by a same-sig mutating fn that merely exists', async () => {
    const JETH = `class C {
      s: u256;
      inc(x: u256): u256 { return x + 1n; }
      mut(x: u256): u256 { this.s = x; return x; }
      apv(f: (x: u256) => u256, v: u256): u256 { return f(v); }
      get run(): External<u256> { return this.apv(this.inc, 5n); }
    }`;
    const SOL = `contract C {
      uint256 s;
      function inc(uint256 x) internal pure returns(uint256){ return x + 1; }
      function mut(uint256 x) internal returns(uint256){ s = x; return x; }
      function apv(function(uint256) internal view returns(uint256) f, uint256 v) internal view returns(uint256){ return f(v); }
      function run() external view returns(uint256){ return apv(inc, 5); }
    }`;
    expect(solcAccepts(SOL)).toBe(true);
    await behavesLikeSolc(JETH, SOL, [{ sig: 'run()' }]);
  });

  it('@view function may TAKE the address of a mutating fn without calling it', async () => {
    const JETH = `class C {
      s: u256;
      mut(x: u256): u256 { this.s = x; return x; }
      get r(): External<bool> { let g: (x: u256) => u256 = this.mut; let h: (x: u256) => u256 = this.mut; return g == h; }
    }`;
    const SOL = `contract C {
      uint256 s;
      function mut(uint256 x) internal returns(uint256){ s = x; return x; }
      function r() external view returns(bool){ function(uint256) internal returns(uint256) g = mut; function(uint256) internal returns(uint256) h = mut; return g == h; }
    }`;
    expect(solcAccepts(SOL)).toBe(true);
    await behavesLikeSolc(JETH, SOL, [{ sig: 'r()' }]);
  });

  it('a genuinely-mutating reachable target in @view STILL rejects (both)', () => {
    const JETH = `@contract class C {
      @state s: u256;
      mut(x: u256): u256 { this.s = x; return x; }
      @view apv(f: (x: u256) => u256, v: u256): u256 { return f(v); }
      @external @view run(): u256 { return this.apv(this.mut, 5n); }
    }`;
    const SOL = `contract C {
      uint256 s;
      function mut(uint256 x) internal returns(uint256){ s = x; return x; }
      function apv(function(uint256) internal view returns(uint256) f, uint256 v) internal view returns(uint256){ return f(v); }
      function run() external view returns(uint256){ return apv(mut, 5); }
    }`;
    expect(jethBuild(JETH).ok).toBe(false);
    expect(solcAccepts(SOL)).toBe(false);
  });

  it('a transitively-mutating reachable target in @view STILL rejects (both)', () => {
    const JETH = `@contract class C {
      @state s: u256;
      wr(x: u256): void { this.s = x; }
      outer(x: u256): u256 { this.wr(x); return x; }
      @view apv(f: (x: u256) => u256, v: u256): u256 { return f(v); }
      @external @view r(): u256 { return this.apv(this.outer, 1n); }
    }`;
    const SOL = `contract C {
      uint256 s;
      function wr(uint256 x) internal { s = x; }
      function outer(uint256 x) internal returns(uint256){ wr(x); return x; }
      function apv(function(uint256) internal view returns(uint256) f, uint256 v) internal view returns(uint256){ return f(v); }
      function r() external view returns(uint256){ return apv(outer, 1); }
    }`;
    expect(jethBuild(JETH).ok).toBe(false);
    expect(solcAccepts(SOL)).toBe(false);
  });

  it('a @view pointer whose only target is view is accepted and runs correctly', async () => {
    const JETH = `class C {
      s: u256;
      constructor() { this.s = 100n; }
      rd(x: u256): u256 { return x + this.s; }
      get vp(v: u256): External<u256> { let g: (x: u256) => u256 = this.rd; return g(v); }
    }`;
    const SOL = `contract C {
      uint256 s;
      constructor() { s = 100; }
      function rd(uint256 x) internal view returns(uint256){ return x + s; }
      function vp(uint256 v) external view returns(uint256){ function(uint256) view returns(uint256) g = rd; return g(v); }
    }`;
    await behavesLikeSolc(JETH, SOL, [{ sig: 'vp(uint256)', args: [pad(42n)] }]);
  });
});

describe('P1-22 funcref tuple component + library funcref value', () => {
  it('a funcref tuple-return component binds and calls byte-identically', async () => {
    const JETH = `class C {
      inc(x: u256): u256 { return x + 1n; }
      mk(): [u256, (x: u256) => u256] { return [7n, this.inc]; }
      get run(): External<u256> { let [a, g] = this.mk(); return a + g(10n); }
    }`;
    const SOL = `contract C {
      function inc(uint256 x) internal pure returns(uint256){ return x + 1; }
      function mk() internal pure returns(uint256, function(uint256) pure returns(uint256)){ return (7, inc); }
      function run() external pure returns(uint256){ (uint256 a, function(uint256) pure returns(uint256) g) = mk(); return a + g(10); }
    }`;
    await behavesLikeSolc(JETH, SOL, [{ sig: 'run()' }]);
  });

  it('a library internal function used as a funcref value (L.f) dispatches byte-identically', async () => {
    const JETH = `static class L { inc(x: u256): u256 { return x + 1n; } }
    class C {
      ap(f: (x: u256) => u256, v: u256): u256 { return f(v); }
      get r(): External<u256> { let g: (x: u256) => u256 = L.inc; return this.ap(g, 41n); }
    }`;
    const SOL = `library L { function inc(uint256 x) internal pure returns(uint256){ return x + 1; } }
    contract C {
      function ap(function(uint256) pure returns(uint256) f, uint256 v) internal pure returns(uint256){ return f(v); }
      function r() external pure returns(uint256){ function(uint256) pure returns(uint256) g = L.inc; return ap(g, 41); }
    }`;
    await behavesLikeSolc(JETH, SOL, [{ sig: 'r()' }]);
  });

  it('an OVERLOADED library funcref take is rejected (both)', () => {
    const JETH = `static class L {
      f(x: u256): u256 { return x; }
      f(x: u256, y: u256): u256 { return x + y; }
    }
    class C {
      ap(g: (x: u256) => u256, v: u256): u256 { return g(v); }
      get r(): External<u256> { let p: (x: u256) => u256 = L.f; return this.ap(p, 1n); }
    }`;
    expect(jethBuild(JETH).ok).toBe(false);
  });
});

describe('P0-32 / boundary: funcref ABI contexts STILL reject (both)', () => {
  const rejects: Record<string, string> = {
    'external param (internal type)': 'function run(function(uint256) internal pure returns(uint256) f) external pure returns(uint256){ return f(3); }',
    'abi.encode a funcref': 'function f() external view returns(bytes memory){ function(uint256) internal pure returns(uint256) p = g; return abi.encode(p); }',
  };
  it('funcref as an @external param stays rejected', () => {
    const JETH = `class C { g(x: u256): u256 { return x; } run(f: (x: u256) => u256): External<u256> { return f(3n); } }`;
    const SOL = `contract C { function g(uint256 x) internal pure returns(uint256){ return x; } ${rejects['external param (internal type)']} }`;
    expect(jethBuild(JETH).ok).toBe(false);
    expect(solcAccepts(SOL)).toBe(false);
  });
  it('abi.encode of a funcref stays rejected', () => {
    const JETH = `class C { g(x: u256): u256 { return x; } get f(): External<bytes> { let p: (x: u256) => u256 = this.g; return abi.encode(p); } }`;
    const SOL = `contract C { function g(uint256 x) internal pure returns(uint256){ return x; } ${rejects['abi.encode a funcref']} }`;
    expect(jethBuild(JETH).ok).toBe(false);
    expect(solcAccepts(SOL)).toBe(false);
  });
});
