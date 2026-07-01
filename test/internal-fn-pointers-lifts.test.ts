// Lifts of 4 narrow over-rejections in internal function-pointer support, each byte-identical to solc
// 0.8.35 (returndata + storage + accept/reject). The lifted forms:
//   FIX 1  a direct call of a @state funcref FIELD: `this.p(v)`.
//   FIX 2  an address-take used DIRECTLY as a `==`/`!=` operand: `g == this.inc`, `inc == dec`.
//   FIX 3  a memory/storage ARRAY of funcrefs (Arr<(x)=>R,N> / ((x)=>R)[]).
//   FIX 4  a STRUCT with a funcref FIELD (incl. a nested value-word struct field).
// The HARD CONSTRAINT (a funcref is NOT ABI-encodable) is preserved: an ABI/event/getter/return context
// with a funcref-containing aggregate STILL rejects, exactly like solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
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
  calls: { sig: string; args?: bigint[] }[],
): Promise<void> {
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
}

describe('funcref lift FIX 1: direct call of a @state funcref field this.p(v)', () => {
  it('pure target, mutating target (state), null-field Panic(0x51), void field statement', async () => {
    const JETH = `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @state s: u256;
      setS(x: u256): u256 { this.s = x * 3n; return this.s; }
      wr(x: u256) { this.s = x + 1n; }
      @state p: (x: u256) => u256;
      @state m: (x: u256) => u256;
      @state w: (x: u256) => void;
      constructor() { this.p = this.inc; this.s = 100n; }
      @external setDec() { this.p = this.dec; }
      @external run(v: u256): u256 { return this.p(v); }
      @external setMut() { this.m = this.setS; }
      @external runMut(v: u256): u256 { return this.m(v); }
      @external nullCall(v: u256): u256 { return this.m(v); }
      @external setW() { this.w = this.wr; }
      @external runW(v: u256) { this.w(v); }
      @external @view getS(): u256 { return this.s; }
    }`;
    const SOL = `contract C {
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      uint256 s;
      function setS(uint256 x) internal returns(uint256){ s = x*3; return s; }
      function wr(uint256 x) internal { s = x+1; }
      function(uint256) pure returns(uint256) p;
      function(uint256) returns(uint256) m;
      function(uint256) w;
      constructor(){ p = inc; s = 100; }
      function setDec() external { p = dec; }
      function run(uint256 v) external view returns(uint256){ return p(v); }
      function setMut() external { m = setS; }
      function runMut(uint256 v) external returns(uint256){ return m(v); }
      function nullCall(uint256 v) external returns(uint256){ return m(v); }
      function setW() external { w = wr; }
      function runW(uint256 v) external { w(v); }
      function getS() external view returns(uint256){ return s; }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'run(uint256)', args: [41n] }, // inc -> 42
      { sig: 'setDec()' },
      { sig: 'run(uint256)', args: [41n] }, // dec -> 40
      { sig: 'nullCall(uint256)', args: [5n] }, // null pointer -> Panic(0x51)
      { sig: 'setMut()' },
      { sig: 'runMut(uint256)', args: [7n] }, // setS(7) -> s=21, returns 21
      { sig: 'getS()' }, // 21
      { sig: 'setW()' },
      { sig: 'runW(uint256)', args: [9n] }, // wr(9) -> s=10 (result discarded)
      { sig: 'getS()' }, // 10
    ]);
  });
});

describe('funcref lift FIX 2: an address-take used directly as a == / != operand', () => {
  it('g == this.inc / this.inc == g / != / both-address-take inc == dec, both branches', async () => {
    const JETH = `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @external eqL(c: bool): bool { let g: (x: u256) => u256 = c ? this.inc : this.dec; return g == this.inc; }
      @external eqR(c: bool): bool { let g: (x: u256) => u256 = c ? this.inc : this.dec; return this.inc == g; }
      @external neL(c: bool): bool { let g: (x: u256) => u256 = c ? this.inc : this.dec; return g != this.inc; }
      @external bothEq(): bool { return this.inc == this.inc; }
      @external bothNe(): bool { return this.inc == this.dec; }
      @external bothBang(): bool { return this.inc != this.dec; }
      @external branch(c: bool): u256 { let g: (x: u256) => u256 = c ? this.inc : this.dec; if (g == this.inc) { return 111n; } return 222n; }
    }`;
    const SOL = `contract C {
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      function eqL(bool c) external pure returns(bool){ function(uint256) pure returns(uint256) g = c ? inc : dec; return g == inc; }
      function eqR(bool c) external pure returns(bool){ function(uint256) pure returns(uint256) g = c ? inc : dec; return inc == g; }
      function neL(bool c) external pure returns(bool){ function(uint256) pure returns(uint256) g = c ? inc : dec; return g != inc; }
      function bothEq() external pure returns(bool){ return inc == inc; }
      function bothNe() external pure returns(bool){ return inc == dec; }
      function bothBang() external pure returns(bool){ return inc != dec; }
      function branch(bool c) external pure returns(uint256){ function(uint256) pure returns(uint256) g = c ? inc : dec; if (g == inc) { return 111; } return 222; }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'eqL(bool)', args: [1n] }, { sig: 'eqL(bool)', args: [0n] },
      { sig: 'eqR(bool)', args: [1n] }, { sig: 'eqR(bool)', args: [0n] },
      { sig: 'neL(bool)', args: [1n] }, { sig: 'neL(bool)', args: [0n] },
      { sig: 'bothEq()' }, { sig: 'bothNe()' }, { sig: 'bothBang()' },
      { sig: 'branch(bool)', args: [1n] }, { sig: 'branch(bool)', args: [0n] },
    ]);
  });
});

describe('funcref lift FIX 3: a memory / storage array of funcrefs', () => {
  it('fixed + dynamic memory array: literal, arr[i](v), arr[i]=this.f, .length, element read, OOB Panic', async () => {
    const JETH = `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @pure sq(x: u256): u256 { return x * x; }
      @external fixedCall(i: u256, v: u256): u256 { let fs: Arr<(x: u256) => u256, 2> = [this.inc, this.dec]; return fs[i](v); }
      @external dynCall(i: u256, v: u256): u256 { let fs: ((x: u256) => u256)[] = [this.inc, this.dec, this.sq]; return fs[i](v); }
      @external dynLen(): u256 { let fs: ((x: u256) => u256)[] = [this.inc, this.dec, this.sq]; return fs.length; }
      @external writeElem(v: u256): u256 { let fs: Arr<(x: u256) => u256, 2> = [this.inc, this.dec]; fs[0] = this.sq; return fs[0](v); }
      @external readElem(c: bool, v: u256): u256 { let fs: Arr<(x: u256) => u256, 2> = [this.inc, this.dec]; let g: (x: u256) => u256 = c ? fs[0] : fs[1]; return g(v); }
    }`;
    const SOL = `contract C {
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      function sq(uint256 x) internal pure returns(uint256){ return x*x; }
      function fixedCall(uint256 i, uint256 v) external pure returns(uint256){ function(uint256) pure returns(uint256)[2] memory fs = [inc, dec]; return fs[i](v); }
      function dynCall(uint256 i, uint256 v) external pure returns(uint256){ function(uint256) pure returns(uint256)[] memory fs = new function(uint256) pure returns(uint256)[](3); fs[0]=inc; fs[1]=dec; fs[2]=sq; return fs[i](v); }
      function dynLen() external pure returns(uint256){ function(uint256) pure returns(uint256)[] memory fs = new function(uint256) pure returns(uint256)[](3); fs[0]=inc; fs[1]=dec; fs[2]=sq; return fs.length; }
      function writeElem(uint256 v) external pure returns(uint256){ function(uint256) pure returns(uint256)[2] memory fs = [inc, dec]; fs[0] = sq; return fs[0](v); }
      function readElem(bool c, uint256 v) external pure returns(uint256){ function(uint256) pure returns(uint256)[2] memory fs = [inc, dec]; function(uint256) pure returns(uint256) g = c ? fs[0] : fs[1]; return g(v); }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'fixedCall(uint256,uint256)', args: [0n, 41n] }, // inc(41)=42
      { sig: 'fixedCall(uint256,uint256)', args: [1n, 41n] }, // dec(41)=40
      { sig: 'fixedCall(uint256,uint256)', args: [2n, 41n] }, // OOB Panic(0x32)
      { sig: 'dynCall(uint256,uint256)', args: [2n, 5n] }, // sq(5)=25
      { sig: 'dynCall(uint256,uint256)', args: [3n, 5n] }, // OOB Panic
      { sig: 'dynLen()' }, // 3
      { sig: 'writeElem(uint256)', args: [4n] }, // sq(4)=16
      { sig: 'readElem(bool,uint256)', args: [1n, 9n] }, // inc(9)=10
      { sig: 'readElem(bool,uint256)', args: [0n, 9n] }, // dec(9)=8
    ]);
  });

  it('@state fixed + dynamic funcref array: write, push, indexed call, .length, OOB, storage read-back', async () => {
    const JETH = `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @pure sq(x: u256): u256 { return x * x; }
      @state fa: Arr<(x: u256) => u256, 2>;
      @state da: ((x: u256) => u256)[];
      @external setFa() { this.fa[0] = this.inc; this.fa[1] = this.dec; }
      @external callFa(i: u256, v: u256): u256 { return this.fa[i](v); }
      @external pushDa() { this.da.push(this.inc); this.da.push(this.sq); }
      @external callDa(i: u256, v: u256): u256 { return this.da[i](v); }
      @external daLen(): u256 { return this.da.length; }
    }`;
    const SOL = `contract C {
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      function sq(uint256 x) internal pure returns(uint256){ return x*x; }
      function(uint256) pure returns(uint256)[2] fa;
      function(uint256) pure returns(uint256)[] da;
      function setFa() external { fa[0]=inc; fa[1]=dec; }
      function callFa(uint256 i, uint256 v) external view returns(uint256){ return fa[i](v); }
      function pushDa() external { da.push(inc); da.push(sq); }
      function callDa(uint256 i, uint256 v) external view returns(uint256){ return da[i](v); }
      function daLen() external view returns(uint256){ return da.length; }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'setFa()' },
      { sig: 'callFa(uint256,uint256)', args: [0n, 10n] }, // inc(10)=11
      { sig: 'callFa(uint256,uint256)', args: [1n, 10n] }, // dec(10)=9
      { sig: 'callFa(uint256,uint256)', args: [2n, 10n] }, // OOB Panic
      { sig: 'pushDa()' },
      { sig: 'callDa(uint256,uint256)', args: [0n, 6n] }, // inc(6)=7
      { sig: 'callDa(uint256,uint256)', args: [1n, 6n] }, // sq(6)=36
      { sig: 'callDa(uint256,uint256)', args: [5n, 6n] }, // OOB Panic
      { sig: 'daLen()' }, // 2
    ]);
  });
});

describe('funcref lift FIX 4: a struct with a funcref field', () => {
  it('memory: construct, field read, field write, indexed call; value field alongside', async () => {
    const JETH = `@struct class Ops { a: (x: u256) => u256; b: u256; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @external callMem(v: u256): u256 { let o: Ops = Ops(this.inc, 7n); return o.a(v); }
      @external writeMem(v: u256): u256 { let o: Ops = Ops(this.inc, 7n); o.a = this.dec; return o.a(v); }
      @external readB(): u256 { let o: Ops = Ops(this.inc, 7n); return o.b; }
    }`;
    const SOL = `contract C {
      struct Ops { function(uint256) pure returns(uint256) a; uint256 b; }
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      function callMem(uint256 v) external pure returns(uint256){ Ops memory o = Ops(inc, 7); return o.a(v); }
      function writeMem(uint256 v) external pure returns(uint256){ Ops memory o = Ops(inc, 7); o.a = dec; return o.a(v); }
      function readB() external pure returns(uint256){ Ops memory o = Ops(inc, 7); return o.b; }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'callMem(uint256)', args: [41n] }, // inc(41)=42
      { sig: 'writeMem(uint256)', args: [41n] }, // dec(41)=40
      { sig: 'readB()' }, // 7
    ]);
  });

  it('@state struct with a funcref field: write field, indexed call, null Panic, value field, read-back', async () => {
    const JETH = `@struct class Ops { a: (x: u256) => u256; b: u256; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure dec(x: u256): u256 { return x - 1n; }
      @state o: Ops;
      @external setInc() { this.o.a = this.inc; this.o.b = 5n; }
      @external setDec() { this.o.a = this.dec; }
      @external call(v: u256): u256 { return this.o.a(v); }
      @external getB(): u256 { return this.o.b; }
    }`;
    const SOL = `contract C {
      struct Ops { function(uint256) pure returns(uint256) a; uint256 b; }
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function dec(uint256 x) internal pure returns(uint256){ return x-1; }
      Ops o;
      function setInc() external { o.a = inc; o.b = 5; }
      function setDec() external { o.a = dec; }
      function call(uint256 v) external view returns(uint256){ return o.a(v); }
      function getB() external view returns(uint256){ return o.b; }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'call(uint256)', args: [3n] }, // null pointer -> Panic(0x51)
      { sig: 'setInc()' },
      { sig: 'call(uint256)', args: [3n] }, // inc(3)=4
      { sig: 'getB()' }, // 5
      { sig: 'setDec()' },
      { sig: 'call(uint256)', args: [3n] }, // dec(3)=2
    ]);
  });

  it('nested value-word struct (struct-in-struct with a funcref leaf)', async () => {
    const JETH = `@struct class Inner { fn: (x: u256) => u256; k: u256; }
    @struct class Outer { inner: Inner; tag: u256; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @external run(v: u256): u256 { let o: Outer = Outer(Inner(this.inc, 9n), 3n); return o.inner.fn(v) + o.inner.k + o.tag; }
    }`;
    const SOL = `contract C {
      struct Inner { function(uint256) pure returns(uint256) fn; uint256 k; }
      struct Outer { Inner inner; uint256 tag; }
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function run(uint256 v) external pure returns(uint256){ Outer memory o = Outer(Inner(inc, 9), 3); return o.inner.fn(v) + o.inner.k + o.tag; }
    }`;
    await behavesLikeSolc(JETH, SOL, [{ sig: 'run(uint256)', args: [5n] }]); // inc(5)=6 +9 +3 = 18
  });
});

describe('funcref lift adversarial: multi-target dispatch through array/struct/state, cross', () => {
  it('mutating pointers dispatched through a @state array (multi-target, writes state)', async () => {
    const JETH = `@contract class C {
      @state s: u256;
      setA(x: u256): u256 { this.s = x + 1n; return this.s; }
      setB(x: u256): u256 { this.s = x * 2n; return this.s; }
      @state fns: ((x: u256) => u256)[];
      @external init() { this.fns.push(this.setA); this.fns.push(this.setB); }
      @external run(i: u256, v: u256): u256 { return this.fns[i](v); }
      @external @view getS(): u256 { return this.s; }
    }`;
    const SOL = `contract C {
      uint256 s;
      function setA(uint256 x) internal returns(uint256){ s = x+1; return s; }
      function setB(uint256 x) internal returns(uint256){ s = x*2; return s; }
      function(uint256) returns(uint256)[] fns;
      function init() external { fns.push(setA); fns.push(setB); }
      function run(uint256 i, uint256 v) external returns(uint256){ return fns[i](v); }
      function getS() external view returns(uint256){ return s; }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'init()' },
      { sig: 'run(uint256,uint256)', args: [0n, 10n] }, // setA(10) -> s=11
      { sig: 'getS()' }, // 11
      { sig: 'run(uint256,uint256)', args: [1n, 10n] }, // setB(10) -> s=20
      { sig: 'getS()' }, // 20
    ]);
  });

  it('cross dispatch: write an array element from a struct field, then dispatch both', async () => {
    const JETH = `@struct class Box { f: (x: u256) => u256; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @pure sq(x: u256): u256 { return x * x; }
      @external run(v: u256): u256 { let arr: Arr<(x: u256) => u256, 2> = [this.inc, this.inc]; let b: Box = Box(this.sq); arr[1] = b.f; return arr[0](v) + arr[1](v); }
    }`;
    const SOL = `contract C {
      struct Box { function(uint256) pure returns(uint256) f; }
      function inc(uint256 x) internal pure returns(uint256){ return x+1; }
      function sq(uint256 x) internal pure returns(uint256){ return x*x; }
      function run(uint256 v) external pure returns(uint256){ function(uint256) pure returns(uint256)[2] memory arr = [inc, inc]; Box memory b = Box(sq); arr[1] = b.f; return arr[0](v) + arr[1](v); }
    }`;
    await behavesLikeSolc(JETH, SOL, [{ sig: 'run(uint256)', args: [4n] }]); // inc(4)+sq(4)=5+16=21
  });
});

// The HARD CONSTRAINT: a funcref (or an aggregate containing one) must STAY a clean reject in every ABI
// context, exactly like solc's "Internal type cannot be used ... in this context".
describe('funcref lift: ABI contexts with a funcref aggregate STAY rejected (soundness)', () => {
  const rejects: Record<string, string> = {
    'return a funcref array from an @external fn': `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @external run(): ((x: u256) => u256)[] { let fs: ((x: u256) => u256)[] = [this.inc]; return fs; }
    }`,
    'abi.encode a funcref array': `@contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @external run(): bytes { let fs: Arr<(x: u256) => u256, 1> = [this.inc]; return abi.encode(fs); }
    }`,
    'funcref array as an @external param': `@contract class C {
      @external run(fs: ((x: u256) => u256)[], i: u256, v: u256): u256 { return fs[i](v); }
    }`,
    '@public getter of a funcref array': `@contract class C {
      @public fa: Arr<(x: u256) => u256, 1>;
    }`,
    'abi.encode a funcref struct': `@struct class Ops { a: (x: u256) => u256; b: u256; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @external run(): bytes { let o: Ops = Ops(this.inc, 1n); return abi.encode(o); }
    }`,
    'return a funcref struct from an @external fn': `@struct class Ops { a: (x: u256) => u256; b: u256; }
    @contract class C {
      @pure inc(x: u256): u256 { return x + 1n; }
      @external run(): Ops { return Ops(this.inc, 1n); }
    }`,
    'funcref struct as an @external param': `@struct class Ops { a: (x: u256) => u256; b: u256; }
    @contract class C {
      @external run(o: Ops, v: u256): u256 { return o.a(v); }
    }`,
    '@public getter of a funcref struct': `@struct class Ops { a: (x: u256) => u256; b: u256; }
    @contract class C {
      @public o: Ops;
    }`,
  };
  for (const [name, src] of Object.entries(rejects)) {
    it(`rejects: ${name}`, () => {
      expect(() => compile(src, { fileName: 'C.jeth' })).toThrow();
    });
  }
});
