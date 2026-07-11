// Lift of the LAST funcref over-rejection: a NESTED (2D+) array of internal function pointers used
// INTERNALLY - `function(...)[N][M]` (Solidity) / `Arr<Arr<(x)=>R,N>,M>` (JETH) - byte-identical to
// solc 0.8.35 (returndata + storage + accept/reject). A funcref is one value word (its stable id), so a
// nested funcref array's memory/storage layout is identical to the same shape with each funcref replaced
// by uint256; the nested-value-array codec was threaded to admit a funcref LEAF (isNestedValueWordArray /
// isValueWordLeafArray / isInlineValueWordElem). Covered INTERNAL positions:
//   - 2D fixed memory local Arr<Arr<(x)=>R,2>,2>: build-from-literal, m[i][j] read, m[i][j]=f write,
//     m[i][j](v) indexed call, m.length / m[i].length, OOB Panic 0x32.
//   - @internal PARAM of a nested funcref array, passed through 2 internal fns.
//   - 3D fixed Arr<Arr<Arr<(x)=>R,2>,2>,2>.
//   - DYNAMIC nesting ((x)=>R)[][], mixed fixed/dynamic (Arr<((x)=>R)[],N>, Arr<(x)=>R,2>[]), new Array.
//   - a nested funcref array as a STRUCT FIELD (G{ grid: Arr<Arr<(x)=>R,2>,2> }).
//   - @state STORAGE: fixed Arr<Arr<(x)=>R,2>,2> and dynamic ((x)=>R)[][] (push), set/read/call/rewire.
// HARD CONSTRAINT (a funcref is NOT ABI-encodable at ANY nesting): every ABI path with a nested funcref
// array STILL rejects, byte-identical to solc's "internal type cannot be in the ABI" error. The rejects
// block below pins that (external param/return, abi.encode, event, @public getter).
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

describe('nested funcref array: 2D fixed memory local', () => {
  it('build / m[i][j] read / m[i][j]=f write / m[i][j](v) call / .length / OOB', async () => {
    const JETH = `class C {
      a(x: u256): u256 { return x + 1n; }
      b(x: u256): u256 { return x + 2n; }
      c(x: u256): u256 { return x + 3n; }
      d(x: u256): u256 { return x + 4n; }
      z(x: u256): u256 { return x * 10n; }
      get cell(i: u256, j: u256, v: u256): External<u256> {
        let m: Arr<Arr<(x: u256) => u256, 2>, 2> = [[this.a, this.b], [this.c, this.d]];
        return m[i][j](v);
      }
      get all(v: u256): External<u256> {
        let m: Arr<Arr<(x: u256) => u256, 2>, 2> = [[this.a, this.b], [this.c, this.d]];
        return m[0n][0n](v) + m[0n][1n](v) + m[1n][0n](v) + m[1n][1n](v);
      }
      get rewire(i: u256, j: u256, v: u256): External<u256> {
        let m: Arr<Arr<(x: u256) => u256, 2>, 2> = [[this.a, this.b], [this.c, this.d]];
        m[i][j] = this.z;
        return m[i][j](v) + m[0n][0n](v);
      }
      get lens(): External<u256> {
        let m: Arr<Arr<(x: u256) => u256, 3>, 2> = [[this.a, this.a, this.a], [this.a, this.a, this.a]];
        return m.length * 100n + m[0n].length;
      }
    }`;
    const SOL = `contract C {
      function a(uint256 x) internal pure returns(uint256){ return x+1; }
      function b(uint256 x) internal pure returns(uint256){ return x+2; }
      function c(uint256 x) internal pure returns(uint256){ return x+3; }
      function d(uint256 x) internal pure returns(uint256){ return x+4; }
      function z(uint256 x) internal pure returns(uint256){ return x*10; }
      function cell(uint256 i, uint256 j, uint256 v) external pure returns(uint256){
        function(uint256) pure returns(uint256)[2][2] memory m = [[a,b],[c,d]];
        return m[i][j](v);
      }
      function all(uint256 v) external pure returns(uint256){
        function(uint256) pure returns(uint256)[2][2] memory m = [[a,b],[c,d]];
        return m[0][0](v)+m[0][1](v)+m[1][0](v)+m[1][1](v);
      }
      function rewire(uint256 i, uint256 j, uint256 v) external pure returns(uint256){
        function(uint256) pure returns(uint256)[2][2] memory m = [[a,b],[c,d]];
        m[i][j] = z;
        return m[i][j](v) + m[0][0](v);
      }
      function lens() external pure returns(uint256){
        function(uint256) pure returns(uint256)[3][2] memory m = [[a,a,a],[a,a,a]];
        return m.length*100 + m[0].length;
      }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'cell(uint256,uint256,uint256)', args: [0n, 0n, 10n] }, // a(10)=11
      { sig: 'cell(uint256,uint256,uint256)', args: [0n, 1n, 10n] }, // b(10)=12
      { sig: 'cell(uint256,uint256,uint256)', args: [1n, 0n, 10n] }, // c(10)=13
      { sig: 'cell(uint256,uint256,uint256)', args: [1n, 1n, 10n] }, // d(10)=14
      { sig: 'cell(uint256,uint256,uint256)', args: [2n, 0n, 10n] }, // OOB outer Panic 0x32
      { sig: 'cell(uint256,uint256,uint256)', args: [0n, 2n, 10n] }, // OOB inner Panic 0x32
      { sig: 'all(uint256)', args: [100n] }, // 101+102+103+104
      { sig: 'rewire(uint256,uint256,uint256)', args: [0n, 0n, 5n] }, // z(5)+z(5)=100
      { sig: 'rewire(uint256,uint256,uint256)', args: [1n, 1n, 5n] }, // z(5)+a(5)=50+6
      { sig: 'rewire(uint256,uint256,uint256)', args: [2n, 0n, 5n] }, // OOB write Panic 0x32
      { sig: 'lens()' }, // 2*100+3
    ]);
  });
});

describe('nested funcref array: @internal param, passed through 2 internal fns', () => {
  it('Arr<Arr<(x)=>R,2>,2> param, m[i][j](v) through pick -> outer', async () => {
    const JETH = `class C {
      a(x: u256): u256 { return x + 1n; }
      b(x: u256): u256 { return x - 1n; }
      pick(m: Arr<Arr<(x: u256) => u256, 2>, 2>, i: u256, j: u256, v: u256): u256 { return m[i][j](v); }
      outer(m: Arr<Arr<(x: u256) => u256, 2>, 2>, i: u256, j: u256, v: u256): u256 { return this.pick(m, i, j, v) + 1000n; }
      get run(i: u256, j: u256, v: u256): External<u256> {
        let m: Arr<Arr<(x: u256) => u256, 2>, 2> = [[this.a, this.b], [this.b, this.a]];
        return this.outer(m, i, j, v);
      }
    }`;
    const SOL = `contract C {
      function a(uint256 x) internal pure returns(uint256){ return x+1; }
      function b(uint256 x) internal pure returns(uint256){ return x-1; }
      function pick(function(uint256) pure returns(uint256)[2][2] memory m, uint256 i, uint256 j, uint256 v) internal pure returns(uint256){ return m[i][j](v); }
      function outer(function(uint256) pure returns(uint256)[2][2] memory m, uint256 i, uint256 j, uint256 v) internal pure returns(uint256){ return pick(m,i,j,v)+1000; }
      function run(uint256 i, uint256 j, uint256 v) external pure returns(uint256){
        function(uint256) pure returns(uint256)[2][2] memory m = [[a,b],[b,a]];
        return outer(m,i,j,v);
      }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'run(uint256,uint256,uint256)', args: [0n, 0n, 5n] }, // a(5)+1000=1006
      { sig: 'run(uint256,uint256,uint256)', args: [0n, 1n, 5n] }, // b(5)+1000=1004
      { sig: 'run(uint256,uint256,uint256)', args: [1n, 1n, 5n] }, // a(5)+1000=1006
      { sig: 'run(uint256,uint256,uint256)', args: [2n, 0n, 5n] }, // OOB Panic 0x32
    ]);
  });
});

describe('nested funcref array: 3D fixed', () => {
  it('Arr<Arr<Arr<(x)=>R,2>,2>,2> build + m[i][j][k](v) dispatch every cell + OOB', async () => {
    const JETH = `class C {
      a(x: u256): u256 { return x + 1n; }
      b(x: u256): u256 { return x + 2n; }
      get run(i: u256, j: u256, k: u256, v: u256): External<u256> {
        let m: Arr<Arr<Arr<(x: u256) => u256, 2>, 2>, 2> =
          [[[this.a, this.b], [this.b, this.a]], [[this.a, this.a], [this.b, this.b]]];
        return m[i][j][k](v);
      }
    }`;
    const SOL = `contract C {
      function a(uint256 x) internal pure returns(uint256){ return x+1; }
      function b(uint256 x) internal pure returns(uint256){ return x+2; }
      function run(uint256 i, uint256 j, uint256 k, uint256 v) external pure returns(uint256){
        function(uint256) pure returns(uint256)[2][2][2] memory m =
          [[[a,b],[b,a]],[[a,a],[b,b]]];
        return m[i][j][k](v);
      }
    }`;
    const calls: { sig: string; args?: bigint[] }[] = [];
    for (let i = 0; i < 2; i++)
      for (let j = 0; j < 2; j++)
        for (let k = 0; k < 2; k++)
          calls.push({ sig: 'run(uint256,uint256,uint256,uint256)', args: [BigInt(i), BigInt(j), BigInt(k), 7n] });
    calls.push({ sig: 'run(uint256,uint256,uint256,uint256)', args: [2n, 0n, 0n, 7n] }); // OOB
    await behavesLikeSolc(JETH, SOL, calls);
  });
});

describe('nested funcref array: dynamic and mixed nesting', () => {
  it('dynamic ((x)=>R)[][] via new Array, cell write + dispatch + .length', async () => {
    const JETH = `class C {
      a(x: u256): u256 { return x + 1n; }
      b(x: u256): u256 { return x + 2n; }
      get run(i: u256, j: u256, v: u256): External<u256> {
        let m: ((x: u256) => u256)[][] = new Array<((x: u256) => u256)[]>(2n);
        m[0n] = new Array<(x: u256) => u256>(2n);
        m[0n][0n] = this.a; m[0n][1n] = this.b;
        m[1n] = new Array<(x: u256) => u256>(1n);
        m[1n][0n] = this.b;
        return m[i][j](v);
      }
      get lens(i: u256): External<u256> {
        let m: ((x: u256) => u256)[][] = new Array<((x: u256) => u256)[]>(2n);
        m[0n] = new Array<(x: u256) => u256>(2n);
        m[1n] = new Array<(x: u256) => u256>(1n);
        return m.length * 100n + m[i].length;
      }
    }`;
    const SOL = `contract C {
      function a(uint256 x) internal pure returns(uint256){ return x+1; }
      function b(uint256 x) internal pure returns(uint256){ return x+2; }
      function run(uint256 i, uint256 j, uint256 v) external pure returns(uint256){
        function(uint256) pure returns(uint256)[][] memory m = new function(uint256) pure returns(uint256)[][](2);
        m[0] = new function(uint256) pure returns(uint256)[](2);
        m[0][0]=a; m[0][1]=b;
        m[1] = new function(uint256) pure returns(uint256)[](1);
        m[1][0]=b;
        return m[i][j](v);
      }
      function lens(uint256 i) external pure returns(uint256){
        function(uint256) pure returns(uint256)[][] memory m = new function(uint256) pure returns(uint256)[][](2);
        m[0] = new function(uint256) pure returns(uint256)[](2);
        m[1] = new function(uint256) pure returns(uint256)[](1);
        return m.length*100 + m[i].length;
      }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'run(uint256,uint256,uint256)', args: [0n, 0n, 5n] }, // a(5)=6
      { sig: 'run(uint256,uint256,uint256)', args: [0n, 1n, 5n] }, // b(5)=7
      { sig: 'run(uint256,uint256,uint256)', args: [1n, 0n, 5n] }, // b(5)=7
      { sig: 'run(uint256,uint256,uint256)', args: [1n, 1n, 5n] }, // OOB inner Panic 0x32
      { sig: 'lens(uint256)', args: [0n] }, // 2*100+2
      { sig: 'lens(uint256)', args: [1n] }, // 2*100+1
    ]);
  });

  it('mixed fixed-of-dynamic Arr<((x)=>R)[],2> literal, m[i][j](v)', async () => {
    const JETH = `class C {
      a(x: u256): u256 { return x + 1n; }
      b(x: u256): u256 { return x + 2n; }
      get run(i: u256, j: u256, v: u256): External<u256> {
        let m: Arr<((x: u256) => u256)[], 2> = [[this.a, this.b], [this.b, this.a, this.a]];
        return m[i][j](v);
      }
    }`;
    const SOL = `contract C {
      function a(uint256 x) internal pure returns(uint256){ return x+1; }
      function b(uint256 x) internal pure returns(uint256){ return x+2; }
      function run(uint256 i, uint256 j, uint256 v) external pure returns(uint256){
        function(uint256) pure returns(uint256)[][2] memory m;
        m[0] = new function(uint256) pure returns(uint256)[](2);
        m[0][0]=a; m[0][1]=b;
        m[1] = new function(uint256) pure returns(uint256)[](3);
        m[1][0]=b; m[1][1]=a; m[1][2]=a;
        return m[i][j](v);
      }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'run(uint256,uint256,uint256)', args: [0n, 0n, 5n] }, // a(5)=6
      { sig: 'run(uint256,uint256,uint256)', args: [0n, 1n, 5n] }, // b(5)=7
      { sig: 'run(uint256,uint256,uint256)', args: [1n, 2n, 5n] }, // a(5)=6
      { sig: 'run(uint256,uint256,uint256)', args: [0n, 2n, 5n] }, // OOB inner Panic 0x32
    ]);
  });

  it('mixed dynamic-of-fixed Arr<(x)=>R,2>[] literal, m[i][j](v) + .length', async () => {
    const JETH = `class C {
      a(x: u256): u256 { return x + 1n; }
      b(x: u256): u256 { return x + 2n; }
      get run(i: u256, j: u256, v: u256): External<u256> {
        let m: Arr<(x: u256) => u256, 2>[] = [[this.a, this.b], [this.b, this.a], [this.a, this.a]];
        return m[i][j](v);
      }
      get len(): External<u256> {
        let m: Arr<(x: u256) => u256, 2>[] = [[this.a, this.b], [this.b, this.a], [this.a, this.a]];
        return m.length;
      }
    }`;
    const SOL = `contract C {
      function a(uint256 x) internal pure returns(uint256){ return x+1; }
      function b(uint256 x) internal pure returns(uint256){ return x+2; }
      function run(uint256 i, uint256 j, uint256 v) external pure returns(uint256){
        function(uint256) pure returns(uint256)[2][] memory m = new function(uint256) pure returns(uint256)[2][](3);
        m[0]=[a,b]; m[1]=[b,a]; m[2]=[a,a];
        return m[i][j](v);
      }
      function len() external pure returns(uint256){
        function(uint256) pure returns(uint256)[2][] memory m = new function(uint256) pure returns(uint256)[2][](3);
        return m.length;
      }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'run(uint256,uint256,uint256)', args: [0n, 0n, 5n] }, // a(5)=6
      { sig: 'run(uint256,uint256,uint256)', args: [2n, 1n, 5n] }, // a(5)=6
      { sig: 'run(uint256,uint256,uint256)', args: [3n, 0n, 5n] }, // OOB outer Panic 0x32
      { sig: 'len()' }, // 3
    ]);
  });
});

describe('nested funcref array: as a struct field', () => {
  it('G{ grid: Arr<Arr<(x)=>R,2>,2> } build / grid[i][j](v) / leaf rewire', async () => {
    const JETH = `type G = { grid: Arr<Arr<(x: u256) => u256, 2>, 2>; };
    class C {
      a(x: u256): u256 { return x + 1n; }
      b(x: u256): u256 { return x + 2n; }
      get run(i: u256, j: u256, v: u256): External<u256> {
        let g: G = G([[this.a, this.b], [this.b, this.a]]);
        return g.grid[i][j](v);
      }
      get rewire(v: u256): External<u256> {
        let g: G = G([[this.a, this.b], [this.b, this.a]]);
        g.grid[0n][0n] = this.b;
        return g.grid[0n][0n](v);
      }
    }`;
    const SOL = `contract C {
      struct G { function(uint256) pure returns(uint256)[2][2] grid; }
      function a(uint256 x) internal pure returns(uint256){ return x+1; }
      function b(uint256 x) internal pure returns(uint256){ return x+2; }
      function run(uint256 i, uint256 j, uint256 v) external pure returns(uint256){
        G memory g = G([[a,b],[b,a]]);
        return g.grid[i][j](v);
      }
      function rewire(uint256 v) external pure returns(uint256){
        G memory g = G([[a,b],[b,a]]);
        g.grid[0][0] = b;
        return g.grid[0][0](v);
      }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'run(uint256,uint256,uint256)', args: [0n, 0n, 5n] }, // a(5)=6
      { sig: 'run(uint256,uint256,uint256)', args: [0n, 1n, 5n] }, // b(5)=7
      { sig: 'run(uint256,uint256,uint256)', args: [1n, 1n, 5n] }, // a(5)=6
      { sig: 'run(uint256,uint256,uint256)', args: [2n, 0n, 5n] }, // OOB Panic 0x32
      { sig: 'rewire(uint256)', args: [5n] }, // b(5)=7
    ]);
  });
});

describe('nested funcref array: @state storage', () => {
  it('fixed Arr<Arr<(x)=>R,2>,2> storage: set/read/call/rewire, read-back', async () => {
    const JETH = `class C {
      a(x: u256): u256 { return x + 1n; }
      b(x: u256): u256 { return x + 2n; }
      g: Arr<Arr<(x: u256) => u256, 2>, 2>;
      setup(): External<void> {
        this.g[0n][0n] = this.a; this.g[0n][1n] = this.b;
        this.g[1n][0n] = this.b; this.g[1n][1n] = this.a;
      }
      get callG(i: u256, j: u256, v: u256): External<u256> { return this.g[i][j](v); }
      rewire(): External<void> { this.g[0n][0n] = this.b; }
    }`;
    const SOL = `contract C {
      function a(uint256 x) internal pure returns(uint256){ return x+1; }
      function b(uint256 x) internal pure returns(uint256){ return x+2; }
      function(uint256) pure returns(uint256)[2][2] g;
      function setup() external { g[0][0]=a; g[0][1]=b; g[1][0]=b; g[1][1]=a; }
      function callG(uint256 i, uint256 j, uint256 v) external view returns(uint256){ return g[i][j](v); }
      function rewire() external { g[0][0]=b; }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'setup()' },
      { sig: 'callG(uint256,uint256,uint256)', args: [0n, 0n, 5n] }, // a(5)=6
      { sig: 'callG(uint256,uint256,uint256)', args: [0n, 1n, 5n] }, // b(5)=7
      { sig: 'callG(uint256,uint256,uint256)', args: [1n, 0n, 5n] }, // b(5)=7
      { sig: 'callG(uint256,uint256,uint256)', args: [1n, 1n, 5n] }, // a(5)=6
      { sig: 'callG(uint256,uint256,uint256)', args: [2n, 0n, 5n] }, // OOB Panic 0x32
      { sig: 'rewire()' },
      { sig: 'callG(uint256,uint256,uint256)', args: [0n, 0n, 5n] }, // b(5)=7 after rewire
    ]);
  });

  it('dynamic ((x)=>R)[][] storage: push inner rows, read/call, OOB', async () => {
    const JETH = `class C {
      a(x: u256): u256 { return x + 1n; }
      b(x: u256): u256 { return x + 2n; }
      g: ((x: u256) => u256)[][];
      setup(): External<void> { this.g.push([this.a, this.b]); this.g.push([this.b]); }
      get callG(i: u256, j: u256, v: u256): External<u256> { return this.g[i][j](v); }
    }`;
    const SOL = `contract C {
      function a(uint256 x) internal pure returns(uint256){ return x+1; }
      function b(uint256 x) internal pure returns(uint256){ return x+2; }
      function(uint256) pure returns(uint256)[][] g;
      function setup() external {
        function(uint256) pure returns(uint256)[] memory r0 = new function(uint256) pure returns(uint256)[](2);
        r0[0]=a; r0[1]=b; g.push(r0);
        function(uint256) pure returns(uint256)[] memory r1 = new function(uint256) pure returns(uint256)[](1);
        r1[0]=b; g.push(r1);
      }
      function callG(uint256 i, uint256 j, uint256 v) external view returns(uint256){ return g[i][j](v); }
    }`;
    await behavesLikeSolc(JETH, SOL, [
      { sig: 'setup()' },
      { sig: 'callG(uint256,uint256,uint256)', args: [0n, 0n, 5n] }, // a(5)=6
      { sig: 'callG(uint256,uint256,uint256)', args: [0n, 1n, 5n] }, // b(5)=7
      { sig: 'callG(uint256,uint256,uint256)', args: [1n, 0n, 5n] }, // b(5)=7
      { sig: 'callG(uint256,uint256,uint256)', args: [1n, 1n, 5n] }, // OOB inner Panic 0x32
      { sig: 'callG(uint256,uint256,uint256)', args: [2n, 0n, 5n] }, // OOB outer Panic 0x32
    ]);
  });
});

describe('nested funcref array: the ABI boundary STILL rejects (not ABI-encodable at any nesting)', () => {
  const rejects: Record<string, string> = {
    'nested funcref array as an @external param': `class C {
      run(m: Arr<Arr<(x: u256) => u256, 2>, 2>, i: u256, j: u256, v: u256): External<u256> { return m[i][j](v); }
    }`,
    'dynamic nested funcref array as an @external param': `class C {
      run(m: ((x: u256) => u256)[][], i: u256, j: u256, v: u256): External<u256> { return m[i][j](v); }
    }`,
    'return a nested funcref array from an @external fn': `class C {
      a(x: u256): u256 { return x + 1n; }
      mk(): External<Arr<Arr<(x: u256) => u256, 2>, 2>> { return [[this.a, this.a], [this.a, this.a]]; }
    }`,
    'abi.encode a nested funcref array': `class C {
      a(x: u256): u256 { return x + 1n; }
      get run(): External<bytes> {
        let m: Arr<Arr<(x: u256) => u256, 2>, 2> = [[this.a, this.a], [this.a, this.a]];
        return abi.encode(m);
      }
    }`,
    'event with a nested funcref array param': `class C {
      a(x: u256): u256 { return x + 1n; }
      E: event<{ m: Arr<Arr<(x: u256) => u256, 2>, 2> }>;
      run(): External<void> {
        let m: Arr<Arr<(x: u256) => u256, 2>, 2> = [[this.a, this.a], [this.a, this.a]];
        emit E(m);
      }
    }`,
    '@public getter of a nested funcref array state var': `class C {
      @public g: Arr<Arr<(x: u256) => u256, 2>, 2>;
    }`,
  };
  for (const [name, src] of Object.entries(rejects)) {
    it(`rejects: ${name}`, () => {
      expect(() => compile(src, { fileName: 'C.jeth' })).toThrow();
    });
  }
});
