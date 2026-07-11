// Fix 1a: a fixed VALUE-leaf array (Arr<u256,N>, Arr<address,N>, nested static Arr<Arr<u256,2>,M>, ...)
// returned DIRECTLY from an external self-call `return this.mk()` or an @interface call
// `return IFoo(t).mk()` was MISCOMPILED. Such a call is analyzed as abiDecode(extCall, T); the decoded
// memory image is the flat inline ABI blob (abiHeadWords(T) words, NO [len] header), but the return
// handler classified it as a DYNAMIC array and ran encodeMemArrayReturn, which reads the first element as
// a length and emits a spurious [0x20] offset word + a length-scaled body (wrong bytes, not a revert).
// The fix returns the flat image inline for a STATIC array target - byte-identical to the let-bound form
// (`let r: Arr<u256,N> = this.mk(); return r;`, which already matched via the verbatim static-image path).
// Regressions locked: the let-bound form, abi.encode(this.mk()), a genuine DYNAMIC array return (u256[]),
// a plain fixed-array LITERAL return, a static-STRUCT fixed array (Arr<P,N>, routed by the other branch),
// and a direct abi.decode of a static fixed array all stay byte-identical.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);
const wrapBytes = (blob: string) => {
  const b = blob.startsWith('0x') ? blob.slice(2) : blob;
  const len = BigInt(b.length / 2);
  return W(0x20n) + W(len) + b;
};

/** Deploy a JETH and a solc contract, call each with identical calldata, assert byte-identical. */
async function bothMatch(J: string, S: string, calls: [string, string?][], name = 'C') {
  const h = await Harness.create();
  const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const sa = await h.deploy(compileSolidity(SPDX + S, name).creation);
  for (const [sig, args] of calls) {
    const cd = '0x' + sel(sig) + (args ?? '');
    const jr = await h.call(ja, cd);
    const sr = await h.call(sa, cd);
    expect(jr.success, `${sig}: success`).toBe(sr.success);
    expect(jr.returnHex, `${sig}: returndata`).toBe(sr.returnHex);
  }
}

describe('Fix 1a: fixed value-leaf array returned directly from an external call', () => {
  it('self-call return this.mk() : u256[N] and address[N], N=1..4, + let-bound + abi.encode', async () => {
    for (const N of [1, 2, 3, 4]) {
      const jU = Array.from({ length: N }, (_, i) => `${i + 5}n`).join(',');
      const sU = 'uint256(5)' + Array.from({ length: N - 1 }, (_, i) => `,${i + 6}`).join('');
      await bothMatch(
        `@contract class C {
          @external @pure mk(): Arr<u256,${N}> { let xs: Arr<u256,${N}> = [${jU}]; return xs; }
          @external go(): Arr<u256,${N}> { return this.mk(); }
          @external goLet(): Arr<u256,${N}> { let r: Arr<u256,${N}> = this.mk(); return r; }
          @external goEnc(): bytes { return abi.encode(this.mk()); }
        }`,
        `contract C {
          function mk() external pure returns(uint256[${N}] memory){ uint256[${N}] memory xs=[${sU}]; return xs; }
          function go() external returns(uint256[${N}] memory){ return this.mk(); }
          function goLet() external returns(uint256[${N}] memory){ uint256[${N}] memory r=this.mk(); return r; }
          function goEnc() external returns(bytes memory){ return abi.encode(this.mk()); }
        }`,
        [['go()'], ['goLet()'], ['goEnc()']],
      );
    }
    for (const N of [2, 3]) {
      const jA = Array.from({ length: N }, (_, i) => `address(0x${(i + 1).toString(16).padStart(40, '0')}n)`).join(',');
      const sA = Array.from({ length: N }, (_, i) => `address(0x${(i + 1).toString(16).padStart(40, '0')})`).join(',');
      await bothMatch(
        `@contract class C {
          @external @pure mk(): Arr<address,${N}> { let xs: Arr<address,${N}> = [${jA}]; return xs; }
          @external go(): Arr<address,${N}> { return this.mk(); }
          @external goEnc(): bytes { return abi.encode(this.mk()); }
        }`,
        `contract C {
          function mk() external pure returns(address[${N}] memory){ address[${N}] memory xs=[${sA}]; return xs; }
          function go() external returns(address[${N}] memory){ return this.mk(); }
          function goEnc() external returns(bytes memory){ return abi.encode(this.mk()); }
        }`,
        [['go()'], ['goEnc()']],
      );
    }
  });

  it('self-call return this.mk() : nested static Arr<Arr<u256,2>,2>, Arr<bytes4,3>, Arr<bool,3>', async () => {
    await bothMatch(
      `@contract class C {
        @external @pure mk(): Arr<Arr<u256,2>,2> { let xs: Arr<Arr<u256,2>,2> = [[1n,2n],[3n,4n]]; return xs; }
        @external go(): Arr<Arr<u256,2>,2> { return this.mk(); }
        @external goEnc(): bytes { return abi.encode(this.mk()); }
      }`,
      `contract C {
        function mk() external pure returns(uint256[2][2] memory){ uint256[2][2] memory xs=[[uint256(1),2],[uint256(3),4]]; return xs; }
        function go() external returns(uint256[2][2] memory){ return this.mk(); }
        function goEnc() external returns(bytes memory){ return abi.encode(this.mk()); }
      }`,
      [['go()'], ['goEnc()']],
    );
    await bothMatch(
      `@contract class C {
        @external @pure mk(): Arr<bytes4,3> { let xs: Arr<bytes4,3> = [bytes4(0x11223344n), bytes4(0x55667788n), bytes4(0x99aabbccn)]; return xs; }
        @external go(): Arr<bytes4,3> { return this.mk(); }
      }`,
      `contract C {
        function mk() external pure returns(bytes4[3] memory){ bytes4[3] memory xs=[bytes4(0x11223344),bytes4(0x55667788),bytes4(0x99aabbcc)]; return xs; }
        function go() external returns(bytes4[3] memory){ return this.mk(); }
      }`,
      [['go()']],
    );
    await bothMatch(
      `@contract class C {
        @external @pure mk(): Arr<bool,3> { let xs: Arr<bool,3> = [true, false, true]; return xs; }
        @external go(): Arr<bool,3> { return this.mk(); }
      }`,
      `contract C {
        function mk() external pure returns(bool[3] memory){ bool[3] memory xs=[true,false,true]; return xs; }
        function go() external returns(bool[3] memory){ return this.mk(); }
      }`,
      [['go()']],
    );
  });

  it('interface call return IFoo(t).mk() : u256[N] and address[N] via a separate target', async () => {
    const target = `contract T {
      function mkU() external pure returns(uint256[3] memory){ uint256[3] memory xs=[uint256(5),6,7]; return xs; }
      function mkA() external pure returns(address[2] memory){ address[2] memory xs=[address(0x11),address(0x22)]; return xs; }
    }`;
    const callerJ = `interface IFoo { mkU(): View<Arr<u256,3>>; mkA(): View<Arr<address,2>>; }
      class C {
        get goU(t: address): External<Arr<u256,3>> { return IFoo(t).mkU(); }
        get goA(t: address): External<Arr<address,2>> { return IFoo(t).mkA(); }
        get goUEnc(t: address): External<bytes> { return abi.encode(IFoo(t).mkU()); }
      }`;
    const callerS = `interface IFoo { function mkU() external view returns(uint256[3] memory); function mkA() external view returns(address[2] memory); }
      contract C {
        function goU(address t) external view returns(uint256[3] memory){ return IFoo(t).mkU(); }
        function goA(address t) external view returns(address[2] memory){ return IFoo(t).mkA(); }
        function goUEnc(address t) external view returns(bytes memory){ return abi.encode(IFoo(t).mkU()); }
      }`;
    const tsb = compileSolidity(SPDX + target, 'T');
    const hj = await Harness.create();
    const hs = await Harness.create();
    const cj = await hj.deploy(compile(callerJ, { fileName: 'C.jeth' }).creationBytecode);
    const cs = await hs.deploy(compileSolidity(SPDX + callerS, 'C').creation);
    for (const sig of ['goU(address)', 'goA(address)', 'goUEnc(address)']) {
      const tj = await hj.deploy(tsb.creation);
      const ts = await hs.deploy(tsb.creation);
      const dj = '0x' + sel(sig) + W(BigInt(tj.toString()));
      const ds = '0x' + sel(sig) + W(BigInt(ts.toString()));
      const rj = await hj.call(cj, dj);
      const rs = await hs.call(cs, ds);
      expect(rj.success, `${sig}: success`).toBe(rs.success);
      expect(rj.returnHex, `${sig}: returndata`).toBe(rs.returnHex);
    }
  });

  it('REGRESSION: dynamic array, fixed-lit, static-struct fixed array, and direct decode still match', async () => {
    // genuine DYNAMIC array return this.mk() (must keep the [0x20][len] wrapper).
    await bothMatch(
      `@contract class C {
        @external @pure mk(): u256[] { let xs: u256[] = [7n,8n,9n]; return xs; }
        @external go(): u256[] { return this.mk(); }
      }`,
      `contract C {
        function mk() external pure returns(uint256[] memory){ uint256[] memory xs=new uint256[](3); xs[0]=7;xs[1]=8;xs[2]=9; return xs; }
        function go() external returns(uint256[] memory){ return this.mk(); }
      }`,
      [['go()']],
    );
    // plain fixed-array literal return (no call).
    await bothMatch(
      `class C { get go(): External<Arr<u256,3>> { return [1n,2n,3n]; } }`,
      `contract C { function go() external returns(uint256[3] memory){ return [uint256(1),2,3]; } }`,
      [['go()']],
    );
    // a static-STRUCT fixed array Arr<P,N> self-call (routed by the isStaticStructFixedLeafArray branch).
    await bothMatch(
      `@struct class P { a: u256; b: u256; }
       @contract class C {
        @external @pure mk(): Arr<P,2> { let xs: Arr<P,2> = [P(1n,2n), P(3n,4n)]; return xs; }
        @external go(): Arr<P,2> { return this.mk(); }
      }`,
      `contract C {
        struct P { uint256 a; uint256 b; }
        function mk() external pure returns(P[2] memory){ P[2] memory xs=[P(1,2),P(3,4)]; return xs; }
        function go() external returns(P[2] memory){ return this.mk(); }
      }`,
      [['go()']],
    );
    // a DIRECT abi.decode of a static fixed array (also flows through the new branch).
    await bothMatch(
      `class C { get dec(b: bytes): External<Arr<u256,2>> { return abi.decode(b, Arr<u256,2>); } }`,
      `contract C { function dec(bytes calldata b) external returns(uint256[2] memory){ return abi.decode(b,(uint256[2])); } }`,
      [['dec(bytes)', wrapBytes(W(42n) + W(43n))]],
    );
  });
});
