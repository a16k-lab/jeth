// Lifts of the last funcref over-rejections around AGGREGATE funcref values crossing an INTERNAL call
// boundary, and a struct FIELD that is itself a fixed-array-of-funcref. Each is byte-identical to solc
// 0.8.35 (returndata + storage + accept/reject). The lifted forms:
//   FIX A  an aggregate param whose value words include a funcref, passed to an @internal/@private fn:
//          Arr<(x)=>R,N> (fixed), ((x)=>R)[] (dynamic), passed / indexed / indexed-called / multi-target.
//   FIX B  a STRUCT with a funcref field (incl. a nested value-word struct) as an @internal param:
//          field read / call / mutation.
//   FIX C  a struct FIELD that is a fixed-array-of-funcref (H{ fs: Arr<(x)=>R,N> }): construct, fs[i] read,
//          fs[i]=this.g write, fs[i](v) call, .length, ternary-bind - in memory AND storage (state / map).
// HARD CONSTRAINT (a funcref is NOT ABI-encodable): every ABI path with such an aggregate STILL rejects,
// exactly like solc's "internal type cannot be in the ABI" error. The rejects block below pins that.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

/** Deploy a JETH source and its solc mirror, then assert each call returns byte-identical
 *  (success + returndata). Storage is checked via read-back calls in the call list. */
async function behavesLikeSolc(
  jethSrc: string,
  solSrc: string,
  calls: { sig: string; args?: (bigint | boolean)[] }[],
): Promise<void> {
  const jb = compile(jethSrc, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + solSrc, 'C');
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  for (const c of calls) {
    const args = (c.args ?? []).map((a) => (typeof a === 'boolean' ? (a ? 1n : 0n) : a));
    const data = encodeCall(sel(c.sig), args);
    const jr = await jeth.call(aj, data);
    const sr = await sol.call(as, data);
    expect(jr.success, `${c.sig} success (jeth err=${jr.exceptionError})`).toBe(sr.success);
    expect(jr.returnHex, `${c.sig} returndata`).toBe(sr.returnHex);
  }
}

describe('funcref lift FIX A: a funcref AGGREGATE as an @internal param', () => {
  it('fixed Arr<funcref,N> param: pass, index, indexed-call, multi-target, OOB, 2-hop', async () => {
    const JETH = `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @pure sq(x: u256): u256 { return x * x; }
      @pure pick(fns: Arr<(x: u256) => u256, 3>, i: u256, v: u256): u256 { return fns[i](v); }
      @pure applyAll(fns: Arr<(x: u256) => u256, 3>, v: u256): u256 { return fns[0n](v) + fns[1n](v) + fns[2n](v); }
      @pure inner(fns: Arr<(x: u256) => u256, 3>, i: u256, v: u256): u256 { return this.pick(fns, i, v) + 1000n; }
      @external callPick(i: u256, v: u256): u256 { return this.pick([this.inc, this.dec, this.sq], i, v); }
      @external callAll(v: u256): u256 { return this.applyAll([this.inc, this.dec, this.sq], v); }
      @external twoHop(i: u256, v: u256): u256 { return this.inner([this.inc, this.dec, this.sq], i, v); }
    }`;
    const SOL = `contract C {
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      function sq(uint256 x) internal pure returns(uint256){ return x*x; }
      function pick(function(uint256) pure returns(uint256)[3] memory fns, uint256 i, uint256 v) internal pure returns(uint256){ return fns[i](v); }
      function applyAll(function(uint256) pure returns(uint256)[3] memory fns, uint256 v) internal pure returns(uint256){ return fns[0](v)+fns[1](v)+fns[2](v); }
      function inner(function(uint256) pure returns(uint256)[3] memory fns, uint256 i, uint256 v) internal pure returns(uint256){ return pick(fns, i, v) + 1000; }
      function callPick(uint256 i, uint256 v) external pure returns(uint256){ return pick([inc, dec, sq], i, v); }
      function callAll(uint256 v) external pure returns(uint256){ return applyAll([inc, dec, sq], v); }
      function twoHop(uint256 i, uint256 v) external pure returns(uint256){ return inner([inc, dec, sq], i, v); }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'callPick(uint256,uint256)', args: [0n, 5n] }, // inc(5)=6
      { sig: 'callPick(uint256,uint256)', args: [1n, 5n] }, // dec(5)=4
      { sig: 'callPick(uint256,uint256)', args: [2n, 5n] }, // sq(5)=25
      { sig: 'callPick(uint256,uint256)', args: [3n, 5n] }, // OOB Panic(0x32)
      { sig: 'callAll(uint256)', args: [4n] }, // 5+3+16
      { sig: 'twoHop(uint256,uint256)', args: [2n, 4n] }, // sq(4)+1000
    ]);
  });

  it('dynamic ((x)=>R)[] param: index, indexed-call, OOB, mutating callee', async () => {
    const JETH = `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @pure sq(x: u256): u256 { return x * x; }
      @pure use(fns: ((x: u256) => u256)[], i: u256, v: u256): u256 { return fns[i](v); }
      @pure swap(fns: Arr<(x: u256) => u256, 2>): u256 { fns[0n] = this.sq; return fns[0n](6n); }
      @external run(i: u256, v: u256): u256 { let fns: ((x: u256) => u256)[] = [this.inc, this.dec, this.sq]; return this.use(fns, i, v); }
      @external mut(): u256 { return this.swap([this.inc, this.dec]); }
    }`;
    const SOL = `contract C {
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      function sq(uint256 x) internal pure returns(uint256){ return x*x; }
      function use(function(uint256) pure returns(uint256)[] memory fns, uint256 i, uint256 v) internal pure returns(uint256){ return fns[i](v); }
      function swap(function(uint256) pure returns(uint256)[2] memory fns) internal pure returns(uint256){ fns[0] = sq; return fns[0](6); }
      function run(uint256 i, uint256 v) external pure returns(uint256){ function(uint256) pure returns(uint256)[] memory fns = new function(uint256) pure returns(uint256)[](3); fns[0]=inc; fns[1]=dec; fns[2]=sq; return use(fns, i, v); }
      function mut() external pure returns(uint256){ return swap([inc, dec]); }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'run(uint256,uint256)', args: [0n, 7n] }, // inc(7)=8
      { sig: 'run(uint256,uint256)', args: [2n, 7n] }, // sq(7)=49
      { sig: 'run(uint256,uint256)', args: [3n, 7n] }, // OOB Panic
      { sig: 'mut()' }, // sq(6)=36
    ]);
  });
});

describe('funcref lift FIX B: a STRUCT with a funcref field as an @internal param', () => {
  it('field read/call, value field alongside, mutating, nested struct', async () => {
    const JETH = `@struct class H { f: (x: u256) => u256; k: u256; }
    @struct class I { f: (x: u256) => u256; }
    @struct class O { inner: I; k: u256; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @pure use(h: H, v: u256): u256 { return h.f(v) + h.k; }
      @pure mutate(h: H, v: u256): u256 { h.f = this.dec; return h.f(v); }
      @pure useNested(o: O, v: u256): u256 { return o.inner.f(v) + o.k; }
      @external callUse(v: u256): u256 { return this.use(H(this.inc, 100n), v); }
      @external callMut(v: u256): u256 { return this.mutate(H(this.inc, 0n), v); }
      @external callNested(v: u256): u256 { return this.useNested(O(I(this.inc), 500n), v); }
    }`;
    const SOL = `contract C {
      struct H { function(uint256) pure returns(uint256) f; uint256 k; }
      struct I { function(uint256) pure returns(uint256) f; }
      struct O { I inner; uint256 k; }
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      function use(H memory h, uint256 v) internal pure returns(uint256){ return h.f(v) + h.k; }
      function mutate(H memory h, uint256 v) internal pure returns(uint256){ h.f = dec; return h.f(v); }
      function useNested(O memory o, uint256 v) internal pure returns(uint256){ return o.inner.f(v) + o.k; }
      function callUse(uint256 v) external pure returns(uint256){ return use(H(inc, 100), v); }
      function callMut(uint256 v) external pure returns(uint256){ return mutate(H(inc, 0), v); }
      function callNested(uint256 v) external pure returns(uint256){ return useNested(O(I(inc), 500), v); }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'callUse(uint256)', args: [41n] }, // inc(41)+100 = 142
      { sig: 'callMut(uint256)', args: [41n] }, // dec(41) = 40
      { sig: 'callNested(uint256)', args: [41n] }, // inc(41)+500 = 542
    ]);
  });
});

describe('funcref lift FIX C: a struct FIELD that is a fixed-array-of-funcref', () => {
  it('memory: construct, fs[i] read, fs[i]=this.g write, fs[i](v) call, .length, ternary-bind, OOB', async () => {
    const JETH = `@struct class H { fs: Arr<(x: u256) => u256, 2>; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @pure sq(x: u256): u256 { return x * x; }
      @external readCall(i: u256, v: u256): u256 { let h: H = H([this.inc, this.dec]); return h.fs[i](v); }
      @external writeCall(v: u256): u256 { let h: H = H([this.inc, this.dec]); h.fs[0n] = this.sq; return h.fs[0n](v); }
      @external len(): u256 { let h: H = H([this.inc, this.dec]); return h.fs.length; }
      @external bind(c: bool, v: u256): u256 { let h: H = H([this.inc, this.dec]); let g: (x: u256) => u256 = c ? h.fs[0n] : h.fs[1n]; return g(v); }
    }`;
    const SOL = `contract C {
      struct H { function(uint256) pure returns(uint256)[2] fs; }
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      function sq(uint256 x) internal pure returns(uint256){ return x*x; }
      function readCall(uint256 i, uint256 v) external pure returns(uint256){ H memory h = H([inc, dec]); return h.fs[i](v); }
      function writeCall(uint256 v) external pure returns(uint256){ H memory h = H([inc, dec]); h.fs[0] = sq; return h.fs[0](v); }
      function len() external pure returns(uint256){ H memory h = H([inc, dec]); return h.fs.length; }
      function bind(bool c, uint256 v) external pure returns(uint256){ H memory h = H([inc, dec]); function(uint256) pure returns(uint256) g = c ? h.fs[0] : h.fs[1]; return g(v); }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'readCall(uint256,uint256)', args: [0n, 41n] }, // inc(41)=42
      { sig: 'readCall(uint256,uint256)', args: [1n, 41n] }, // dec(41)=40
      { sig: 'readCall(uint256,uint256)', args: [2n, 41n] }, // OOB Panic
      { sig: 'writeCall(uint256)', args: [6n] }, // sq(6)=36
      { sig: 'len()' }, // 2
      { sig: 'bind(bool,uint256)', args: [true, 9n] }, // inc(9)=10
      { sig: 'bind(bool,uint256)', args: [false, 9n] }, // dec(9)=8
    ]);
  });

  it('storage: @state struct{funcref[2]} set/read/call/rewire, read-back', async () => {
    const JETH = `@struct class H { fs: Arr<(x: u256) => u256, 2>; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @pure sq(x: u256): u256 { return x * x; }
      @state h: H;
      @external setup() { this.h.fs[0n] = this.inc; this.h.fs[1n] = this.dec; }
      @external callH(i: u256, v: u256): u256 { return this.h.fs[i](v); }
      @external rewire() { this.h.fs[0n] = this.sq; }
    }`;
    const SOL = `contract C {
      struct H { function(uint256) pure returns(uint256)[2] fs; }
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      function sq(uint256 x) internal pure returns(uint256){ return x*x; }
      H h;
      function setup() external { h.fs[0]=inc; h.fs[1]=dec; }
      function callH(uint256 i, uint256 v) external view returns(uint256){ return h.fs[i](v); }
      function rewire() external { h.fs[0]=sq; }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'setup()' },
      { sig: 'callH(uint256,uint256)', args: [0n, 10n] }, // inc(10)=11
      { sig: 'callH(uint256,uint256)', args: [1n, 10n] }, // dec(10)=9
      { sig: 'callH(uint256,uint256)', args: [2n, 10n] }, // OOB Panic
      { sig: 'rewire()' },
      { sig: 'callH(uint256,uint256)', args: [0n, 10n] }, // sq(10)=100
    ]);
  });

  it('storage: mapping(uint=>struct{funcref[2]}) set/read/call', async () => {
    const JETH = `@struct class H { fs: Arr<(x: u256) => u256, 2>; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @state m: mapping<u256, H>;
      @external setup(k: u256) { this.m[k].fs[0n] = this.inc; this.m[k].fs[1n] = this.dec; }
      @external callM(k: u256, i: u256, v: u256): u256 { return this.m[k].fs[i](v); }
    }`;
    const SOL = `contract C {
      struct H { function(uint256) pure returns(uint256)[2] fs; }
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      mapping(uint256 => H) m;
      function setup(uint256 k) external { m[k].fs[0]=inc; m[k].fs[1]=dec; }
      function callM(uint256 k, uint256 i, uint256 v) external view returns(uint256){ return m[k].fs[i](v); }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'setup(uint256)', args: [7n] },
      { sig: 'callM(uint256,uint256,uint256)', args: [7n, 0n, 50n] }, // inc(50)=51
      { sig: 'callM(uint256,uint256,uint256)', args: [7n, 1n, 50n] }, // dec(50)=49
      { sig: 'callM(uint256,uint256,uint256)', args: [7n, 2n, 50n] }, // OOB Panic
    ]);
  });
});

describe('funcref lift FIX A/B/C: the ABI boundary STILL rejects (a funcref is not ABI-encodable)', () => {
  const rejects: Record<string, string> = {
    'funcref fixed-array as an @external param': `@contract class C {
      @external run(a: Arr<(x: u256) => u256, 2>, v: u256): u256 { return a[0n](v); }
    }`,
    'dynamic funcref array as an @external param': `@contract class C {
      @external run(a: ((x: u256) => u256)[], i: u256, v: u256): u256 { return a[i](v); }
    }`,
    'struct-with-funcref-field as an @external param': `@struct class H { f: (x: u256) => u256; }
    @contract class C {
      @external run(h: H, v: u256): u256 { return h.f(v); }
    }`,
    'struct-with-funcref-array-field as an @external param': `@struct class H { fs: Arr<(x: u256) => u256, 2>; }
    @contract class C {
      @external run(h: H, i: u256, v: u256): u256 { return h.fs[i](v); }
    }`,
    'return a funcref fixed-array from an @external fn': `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @external mk(): Arr<(x: u256) => u256, 2> { return [this.inc, this.inc]; }
    }`,
    'return a struct-with-funcref-array from an @external fn': `@struct class H { fs: Arr<(x: u256) => u256, 2>; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @external mk(): H { return H([this.inc, this.inc]); }
    }`,
    'abi.encode a struct-with-funcref-array': `@struct class H { fs: Arr<(x: u256) => u256, 2>; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @external run(): bytes { let h: H = H([this.inc, this.inc]); return abi.encode(h); }
    }`,
    'event with a struct-with-funcref-field param': `@struct class H { f: (x: u256) => u256; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @event E(h: H);
      @external run() { emit E(H(this.inc)); }
    }`,
    '@public getter of a struct-with-funcref-array field': `@struct class H { fs: Arr<(x: u256) => u256, 2>; }
    @contract class C {
      @public h: H;
    }`,
  };
  for (const [name, src] of Object.entries(rejects)) {
    it(`rejects: ${name}`, () => {
      expect(() => compile(src, { fileName: 'C.jeth' })).toThrow();
    });
  }
});
