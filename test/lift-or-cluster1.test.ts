// OR cluster 1: ternary over a static-struct fixed-leaf array Arr<In,N> unifying MEMORY|STORAGE.
// solc unifies such a ternary to a MEMORY reference: a memory-local branch is ALIASED (a mutation
// through the ternary result writes through), a storage branch is DEEP-COPIED to a fresh memory image
// (a mutation lands in the copy and is discarded). Two shapes lifted byte-identical:
//   TERN-STRUCT-ARR:  let p: Arr<In,2> = c ? this.A : m
//   TERN-LV-MIX (struct): (c ? this.A : m)[0].x = v   (storage write discarded, memory write persists)
// The bare ternary VALUE in a WHOLE-STATEMENT read-only consumer (return / abi.encode arg 0) now
// bind-hoists to a synth const first (byte-identical, no pointer-word leak - verified below); event
// data / internal-call arg / deeper positions stay clean rejects pending the parameter-effect analysis.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

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
const rejects = (src: string): boolean => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
};

describe('OR cluster 1: ternary mem|storage static-struct array copy-or-alias', () => {
  it('TERN-STRUCT-ARR: let p = c ? A : m aliases m (c=false) / copies A (c=true), byte-identical', async () => {
    await run(
      `type In = {x:u256};
class C{ A:Arr<In,2>;
  seed():External<void>{ this.A[0n].x=5n; this.A[1n].x=6n; }
  get f(c:bool):External<Arr<u256,2>>{ let m:Arr<In,2>=[In(10n),In(20n)]; let p:Arr<In,2>=c?this.A:m; p[0n].x=77n; return [m[0n].x, this.A[0n].x]; } }`,
      `contract C{ struct In{uint256 x;} In[2] A;
  function seed() external { A[0].x=5; A[1].x=6; }
  function f(bool c) external returns(uint256[2] memory){ In[2] memory m; m[0].x=10; m[1].x=20; In[2] memory p=c?A:m; p[0].x=77; return [m[0].x, A[0].x]; } }`,
      [['seed()', ''], ['f(bool)', W(0)], ['f(bool)', W(1)]] as const,
    );
  });

  it('TERN-STRUCT-ARR: memory|memory (c ? m : n) and memory|storage (c ? m : A) aliasing, byte-identical', async () => {
    await run(
      `type In = {x:u256};
class C{ A:Arr<In,2>;
  seed():External<void>{ this.A[0n].x=5n; }
  get mm(c:bool):External<Arr<u256,2>>{ let m:Arr<In,2>=[In(10n),In(20n)]; let n:Arr<In,2>=[In(30n),In(40n)]; let p:Arr<In,2>=c?m:n; p[0n].x=77n; return [m[0n].x, n[0n].x]; }
  get ms(c:bool):External<Arr<u256,2>>{ let m:Arr<In,2>=[In(10n),In(20n)]; let p:Arr<In,2>=c?m:this.A; p[0n].x=77n; return [m[0n].x, this.A[0n].x]; } }`,
      `contract C{ struct In{uint256 x;} In[2] A;
  function seed() external { A[0].x=5; }
  function mm(bool c) external returns(uint256[2] memory){ In[2] memory m; m[0].x=10; In[2] memory n; n[0].x=30; In[2] memory p=c?m:n; p[0].x=77; return [m[0].x, n[0].x]; }
  function ms(bool c) external returns(uint256[2] memory){ In[2] memory m; m[0].x=10; m[1].x=20; In[2] memory p=c?m:A; p[0].x=77; return [m[0].x, A[0].x]; } }`,
      [['seed()', ''], ['mm(bool)', W(1)], ['mm(bool)', W(0)], ['ms(bool)', W(1)], ['ms(bool)', W(0)]] as const,
    );
  });

  it('TERN-LV-MIX (struct): (c ? A : m)[0].x = v discards the storage write, persists the memory write', async () => {
    await run(
      `type In = {x:u256};
class C{ A:Arr<In,2>;
  seed():External<void>{ this.A[0n].x=5n; }
  f(c:bool,v:u256):External<Arr<u256,2>>{ let m:Arr<In,2>=[In(10n),In(20n)]; (c?this.A:m)[0n].x=v; return [m[0n].x, this.A[0n].x]; }
  whole(c:bool,v:u256):External<Arr<u256,2>>{ let m:Arr<In,2>=[In(10n),In(20n)]; (c?this.A:m)[0n]=In(v); return [m[0n].x, this.A[0n].x]; } }`,
      `contract C{ struct In{uint256 x;} In[2] A;
  function seed() external { A[0].x=5; }
  function f(bool c,uint256 v) external returns(uint256[2] memory){ In[2] memory m; m[0].x=10; m[1].x=20; (c?A:m)[0].x=v; return [m[0].x, A[0].x]; }
  function whole(bool c,uint256 v) external returns(uint256[2] memory){ In[2] memory m; m[0].x=10; m[1].x=20; (c?A:m)[0]=In(v); return [m[0].x, A[0].x]; } }`,
      [['seed()', ''],
       ['f(bool,uint256)', W(1) + W(99)], ['f(bool,uint256)', W(0) + W(9)],
       ['whole(bool,uint256)', W(1) + W(99)], ['whole(bool,uint256)', W(0) + W(9)]] as const,
    );
  });

  it('TERN-LV-MIX (value): the value-array mixed ternary lvalue (=, +=) stays byte-identical', async () => {
    await run(
      `class C{ A:Arr<u256,2>;
  seed():External<void>{ this.A[0n]=5n; }
  eq(c:bool,v:u256):External<Arr<u256,2>>{ let m:Arr<u256,2>=[10n,20n]; (c?this.A:m)[0n]=v; return [m[0n], this.A[0n]]; }
  pe(c:bool,v:u256):External<Arr<u256,2>>{ let m:Arr<u256,2>=[10n,20n]; (c?this.A:m)[0n]+=v; return [m[0n], this.A[0n]]; } }`,
      `contract C{ uint256[2] A;
  function seed() external { A[0]=5; }
  function eq(bool c,uint256 v) external returns(uint256[2] memory){ uint256[2] memory m=[uint256(10),20]; (c?A:m)[0]=v; return [m[0], A[0]]; }
  function pe(bool c,uint256 v) external returns(uint256[2] memory){ uint256[2] memory m=[uint256(10),20]; (c?A:m)[0]+=v; return [m[0], A[0]]; } }`,
      [['seed()', ''],
       ['eq(bool,uint256)', W(1) + W(99)], ['eq(bool,uint256)', W(0) + W(9)],
       ['pe(bool,uint256)', W(1) + W(7)], ['pe(bool,uint256)', W(0) + W(7)]] as const,
    );
  });

  it('storage|storage struct-array ternary abi.encode + let-bind still byte-identical (no regression)', async () => {
    await run(
      `type In = {x:u256};
class C{ A:Arr<In,2>; B2:Arr<In,2>;
  seed():External<void>{ this.A[0n].x=5n; this.B2[0n].x=8n; }
  get enc(c:bool):External<bytes>{ return abi.encode(c?this.A:this.B2); }
  get bind(c:bool):External<u256>{ let p:Arr<In,2>=c?this.A:this.B2; return p[0n].x; } }`,
      `contract C{ struct In{uint256 x;} In[2] A; In[2] B2;
  function seed() external { A[0].x=5; B2[0].x=8; }
  function enc(bool c) external view returns(bytes memory){ return abi.encode(c?A:B2); }
  function bind(bool c) external returns(uint256){ In[2] memory p=c?A:B2; return p[0].x; } }`,
      [['seed()', ''], ['enc(bool)', W(1)], ['enc(bool)', W(0)], ['bind(bool)', W(1)], ['bind(bool)', W(0)]] as const,
    );
  });

  it('SOUNDNESS: a bare memory-branch struct-array ternary VALUE (abi.encode / return) now lifts byte-identical (bind-hoist, no pointer-word leak)', async () => {
    // Previously a clean JETH074 reject: a flat consumer of a pointer-headed memory branch would leak the
    // N element-pointer words into the ABI payload (MC-2..6). The value-consumer bind-hoist materializes
    // the ternary to a synth const FIRST, so the ABI encoding carries the element bytes, not the pointer
    // words. Verified byte-identical to solc here - this is the live MC-family regression guard.
    await run(
      `type In = {x:u256};
class C{ A:Arr<In,2>;
  seed():External<void>{ this.A[0n].x=11n; this.A[1n].x=22n; }
  get enc(c:bool):External<bytes>{ let m:Arr<In,2>=[In(10n),In(20n)]; return abi.encode(c?this.A:m); }
  get ret(c:bool):External<Arr<In,2>>{ let m:Arr<In,2>=[In(10n),In(20n)]; return c?this.A:m; } }`,
      `contract C{ struct In{uint256 x;} In[2] A;
  function seed() external { A[0].x=11; A[1].x=22; }
  function enc(bool c) external view returns(bytes memory){ In[2] memory m=[In(10),In(20)]; return abi.encode(c?A:m); }
  function ret(bool c) external view returns(In[2] memory){ In[2] memory m=[In(10),In(20)]; return c?A:m; } }`,
      [['seed()', ''], ['enc(bool)', W(1)], ['enc(bool)', W(0)], ['ret(bool)', W(1)], ['ret(bool)', W(0)]] as const,
    );
    // A funcref-bearing struct-array ternary is NOT covered by this lift (not isStaticStructFixedLeafArray)
    // and still rejects at the ABI boundary (see the funcref test below).
  });

  it('funcref static-struct fixed-array ternary let-bind + call byte-identical; ABI boundary rejects', async () => {
    await run(
      `type Fd = {f:(v:u256)=>u256};
class C{ h(v:u256):u256{return v+1n;} g(v:u256):u256{return v+100n;}
  get run(c:bool):External<u256>{ let a:Arr<Fd,2>=[Fd(this.h),Fd(this.h)]; let b:Arr<Fd,2>=[Fd(this.g),Fd(this.g)]; let p:Arr<Fd,2>=c?a:b; return p[0n].f(41n); } }`,
      `contract C{ struct Fd{function(uint256) internal returns(uint256) f;} function h(uint256 v) internal returns(uint256){return v+1;} function g(uint256 v) internal returns(uint256){return v+100;}
  function run(bool c) external returns(uint256){ Fd[2] memory a=[Fd(h),Fd(h)]; Fd[2] memory b=[Fd(g),Fd(g)]; Fd[2] memory p=c?a:b; return p[0].f(41); } }`,
      [['run(bool)', W(1)], ['run(bool)', W(0)]] as const,
    );
    // funcref ternary must never reach an ABI boundary.
    expect(
      rejects(`type Fd = {f:(v:u256)=>u256};
class C{ h(v:u256):u256{return v;}
  get run(c:bool):External<bytes>{ let a:Arr<Fd,2>=[Fd(this.h),Fd(this.h)]; let b:Arr<Fd,2>=[Fd(this.h),Fd(this.h)]; return abi.encode(c?a:b); } }`),
    ).toBe(true);
  });
});
