// OR cluster 3: funcref-struct-array element values + calldata struct-array element byte access.
//   FUNCREF-BIND:  let e: Fd = a[i]; e.f(v)       (Fd{f:(v)=>u256}, Arr<Fd,N>)
//   FUNCREF-TERN:  (c ? a[0n] : a[1n]).f(v)
//     Both dispatch identically to the already-lifted direct a[i].f(v).
//   CD-STRUCTARR-BYTE:  xs[i].b[j]  (bytes field of a calldata dyn-struct-array element) READ,
//     byte-identical to the bind-a-local workaround incl OOB Panic 0x32. A calldata WRITE stays a
//     both-reject (calldata is read-only).
//   MEM-STRUCTARR-BYTESARR-BYTE:  xs[i].tags[j][k]  (bytes[]-field byte access on a MEMORY struct-array
//     element) READ + WRITE - already supported, pinned here.
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
// build calldata for f(S[]{S{b,n},S{b,n}}, i, j) with S{bytes b; uint256 n}
function cdStructArr(iVal: number, jVal: number): string {
  const enc = (bhex: string, n: number) => {
    const blen = bhex.length / 2;
    const data = blen ? (bhex + '0'.repeat(64)).slice(0, Math.ceil(blen / 32) * 64) : '';
    return W(0x40) + W(n) + W(blen) + data;
  };
  const e0 = enc('5758595a', 7); // WXYZ
  const e1 = enc('4142', 9); // AB
  const off0 = 2 * 32;
  const off1 = off0 + e0.length / 2;
  const arr = W(2) + W(off0) + W(off1) + e0 + e1;
  return W(0x60) + W(iVal) + W(jVal) + arr;
}

describe('OR cluster 3: funcref element values + calldata/nested byte access', () => {
  it('FUNCREF-BIND: let e: Fd = a[i]; e.f(v) dispatches like the direct a[i].f(v), byte-identical', async () => {
    await run(
      `@struct class Fd{f:(v:u256)=>u256}
@contract class C{ h(v:u256):u256{return v+1n;} g(v:u256):u256{return v+100n;}
  @external run(i:u256):u256{ let a:Arr<Fd,2>=[Fd(this.h),Fd(this.g)]; let e:Fd=a[i]; return e.f(41n); } }`,
      `contract C{ struct Fd{function(uint256) internal returns(uint256) f;} function h(uint256 v) internal returns(uint256){return v+1;} function g(uint256 v) internal returns(uint256){return v+100;}
  function run(uint256 i) external returns(uint256){ Fd[2] memory a=[Fd(h),Fd(g)]; Fd memory e=a[i]; return e.f(41); } }`,
      [['run(uint256)', W(0)], ['run(uint256)', W(1)], ['run(uint256)', W(2)]] as const, // 42, 141, Panic 0x32
    );
  });

  it('FUNCREF-TERN: (c ? a[0] : a[1]).f(v) dispatches identically, byte-identical', async () => {
    await run(
      `@struct class Fd{f:(v:u256)=>u256}
@contract class C{ h(v:u256):u256{return v+1n;} g(v:u256):u256{return v+100n;}
  @external run(c:bool):u256{ let a:Arr<Fd,2>=[Fd(this.h),Fd(this.g)]; return (c?a[0n]:a[1n]).f(41n); } }`,
      `contract C{ struct Fd{function(uint256) internal returns(uint256) f;} function h(uint256 v) internal returns(uint256){return v+1;} function g(uint256 v) internal returns(uint256){return v+100;}
  function run(bool c) external returns(uint256){ Fd[2] memory a=[Fd(h),Fd(g)]; return (c?a[0]:a[1]).f(41); } }`,
      [['run(bool)', W(1)], ['run(bool)', W(0)]] as const, // 42, 141
    );
  });

  it('CD-STRUCTARR-BYTE: xs[i].b[j] calldata struct-array element byte read byte-identical incl OOB Panic', async () => {
    await run(
      `@struct class S{b:bytes;n:u256}
@contract class C{ @external @pure f(xs:S[],i:u256,j:u256):u256{ return u256(u8(xs[i].b[j])); } }`,
      `contract C{ struct S{bytes b;uint256 n;} function f(S[] calldata xs,uint256 i,uint256 j) external pure returns(uint256){ return uint256(uint8(xs[i].b[j])); } }`,
      [
        ['f((bytes,uint256)[],uint256,uint256)', cdStructArr(0, 0)], // 0x57
        ['f((bytes,uint256)[],uint256,uint256)', cdStructArr(0, 3)], // 0x5a
        ['f((bytes,uint256)[],uint256,uint256)', cdStructArr(1, 1)], // 0x42
        ['f((bytes,uint256)[],uint256,uint256)', cdStructArr(0, 4)], // OOB byte -> Panic 0x32
        ['f((bytes,uint256)[],uint256,uint256)', cdStructArr(1, 2)], // OOB byte -> Panic 0x32
        ['f((bytes,uint256)[],uint256,uint256)', cdStructArr(2, 0)], // OOB elem -> Panic 0x32
      ] as const,
    );
  });

  it('SOUNDNESS: a calldata byte WRITE xs[i].b[j] = v stays a reject (calldata is read-only)', () => {
    expect(
      rejects(`@struct class S{b:bytes;n:u256}
@contract class C{ @external f(xs:S[],i:u256,j:u256,v:u8):void{ xs[i].b[j]=bytes1(v); } }`),
    ).toBe(true);
  });

  it('MEM-STRUCTARR-BYTESARR-BYTE: xs[i].tags[j][k] memory bytes[]-field byte read+write byte-identical', async () => {
    await run(
      `@struct class S{tags:bytes[]}
@contract class C{
  @external @pure rd(i:u256,j:u256,k:u256):u256{ let t:bytes[]=[bytes("abc"),bytes("de")]; let xs:Arr<S,1>=[S(t)]; return u256(u8(xs[i].tags[j][k])); }
  @external @pure wr(j:u256,k:u256,v:u8):u256{ let t:bytes[]=[bytes("abc"),bytes("de")]; let xs:Arr<S,1>=[S(t)]; xs[0n].tags[j][k]=bytes1(v); return u256(u8(xs[0n].tags[j][k])); } }`,
      `contract C{ struct S{bytes[] tags;}
  function mk() internal pure returns(S[1] memory xs){ bytes[] memory t=new bytes[](2); t[0]=bytes("abc"); t[1]=bytes("de"); xs=[S(t)]; }
  function rd(uint256 i,uint256 j,uint256 k) external pure returns(uint256){ S[1] memory xs=mk(); return uint256(uint8(xs[i].tags[j][k])); }
  function wr(uint256 j,uint256 k,uint8 v) external pure returns(uint256){ S[1] memory xs=mk(); xs[0].tags[j][k]=bytes1(v); return uint256(uint8(xs[0].tags[j][k])); } }`,
      [
        ['rd(uint256,uint256,uint256)', W(0) + W(0) + W(0)], // 97
        ['rd(uint256,uint256,uint256)', W(0) + W(1) + W(1)], // 101
        ['rd(uint256,uint256,uint256)', W(0) + W(0) + W(3)], // OOB byte -> Panic 0x32
        ['rd(uint256,uint256,uint256)', W(0) + W(2) + W(0)], // OOB tags idx -> Panic 0x32
        ['wr(uint256,uint256,uint8)', W(0) + W(0) + W(0x5a)], // 90
        ['wr(uint256,uint256,uint8)', W(1) + W(1) + W(0x51)], // 81
        ['wr(uint256,uint256,uint8)', W(0) + W(5) + W(0x51)], // OOB write -> Panic 0x32
      ] as const,
    );
  });
});
