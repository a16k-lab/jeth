// SOUNDNESS (JETH470): copying a WHOLE aggregate whose top-level (or a nested member) is a FIXED array
// WHOSE DIRECT ELEMENT IS A STATIC STRUCT (Arr<In,N>, a struct/fixed-array-of-struct transitively holding
// such a field) from a MEMORY or CALLDATA source INTO STORAGE (this.s = a) is UNIMPLEMENTED in solc's
// LEGACY pipeline (UnimplementedFeatureError: "Copying of type struct In memory[N] ... to storage is not
// supported in legacy"). JETH previously ACCEPTED it (an OVER-ACCEPTANCE) and the CONSTRUCTOR form
// this.s = a MISCOMPILED - the generic fixed-array store flattened the N-pointer memory image into the
// first slots (raw pointer words + only element 0's payload, DROPPING later elements). JETH now REJECTS
// the exact shapes solc-legacy rejects (JETH470), matching accept/reject byte-for-byte.
//
// This file pins BOTH sides of the gate:
//   REJECT  (JETH470, solc-legacy also rejects -> BOTH-REJECT): a whole Arr<In,N> (static In) from a
//           constructor param, a calldata param, or a memory local; Arr<In,3>; a 3-field Arr<In3,2>; a
//           @state struct whose field is Arr<In,2> from a memory local; a fixed array whose element is a
//           struct (Box[2]). PLUS a SAFE over-rejection: a nested Arr<Arr<In,N>,M> from a MEMORY source
//           (solc accepts it, but JETH would MISCOMPILE the nested memory image -> a clean reject beats
//           wrong bytes; the CALLDATA nested form is byte-identical and stays ACCEPTED below).
//   ACCEPT  (byte-identical to solc): a value fixed array Arr<u256,N>; a single struct; a struct with a
//           value-array field; a nested Arr<Arr<In,N>,M> from CALLDATA; a whole calldata-struct->storage
//           copy (Box calldata); a storage->storage struct-array copy (this.dst = this.src); a scalar.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

function codes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
}
function jethAccepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
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

// Each MUST-REJECT case: JETH emits JETH470 AND solc-legacy also rejects (so accept/reject is byte-identical).
const REJECT: { name: string; jeth: string; sol: string }[] = [
  {
    name: 'constructor(a: Arr<In,2>) { this.s = a }',
    jeth: `type In = { x: u256; y: u256 };
class C { s: Arr<In,2>; constructor(a: Arr<In,2>) { this.s = a; } get g(): External<u256> { return this.s[0].x; } }`,
    sol: `struct In { uint256 x; uint256 y; } contract C { In[2] s; constructor(In[2] memory a){ s=a; } function g() external view returns(uint256){return s[0].x;} }`,
  },
  {
    name: 'runtime f(a: Arr<In,2> calldata) { this.s = a }',
    jeth: `type In = { x: u256; y: u256 };
class C { s: Arr<In,2>; set(a: Arr<In,2>): External<void> { this.s = a; } get g(): External<u256> { return this.s[0].x; } }`,
    sol: `struct In { uint256 x; uint256 y; } contract C { In[2] s; function set(In[2] calldata a) external { s=a; } function g() external view returns(uint256){return s[0].x;} }`,
  },
  {
    name: 'runtime memory-local src (let m: Arr<In,2>; this.s = m)',
    jeth: `type In = { x: u256; y: u256 };
class C { s: Arr<In,2>; set(): External<void> { let m: Arr<In,2> = [In(1n,2n),In(3n,4n)]; this.s = m; } get g(): External<u256> { return this.s[0].x; } }`,
    sol: `struct In { uint256 x; uint256 y; } contract C { In[2] s; function set() external { In[2] memory m=[In(1,2),In(3,4)]; s=m; } function g() external view returns(uint256){return s[0].x;} }`,
  },
  {
    name: 'Arr<In,3>',
    jeth: `type In = { x: u256; y: u256 };
class C { s: Arr<In,3>; set(a: Arr<In,3>): External<void> { this.s = a; } get g(): External<u256> { return this.s[2].x; } }`,
    sol: `struct In { uint256 x; uint256 y; } contract C { In[3] s; function set(In[3] calldata a) external { s=a; } function g() external view returns(uint256){return s[2].x;} }`,
  },
  {
    name: 'Arr<In3,2> (3-field struct)',
    jeth: `type In3 = { a: u256; b: u256; c: u256 };
class C { s: Arr<In3,2>; set(a: Arr<In3,2>): External<void> { this.s = a; } get g(): External<u256> { return this.s[1].c; } }`,
    sol: `struct In3 { uint256 a; uint256 b; uint256 c; } contract C { In3[2] s; function set(In3[2] calldata a) external { s=a; } function g() external view returns(uint256){return s[1].c;} }`,
  },
  {
    name: '@state struct with an Arr<In,2> field, from a memory local',
    jeth: `type In = { x: u256; y: u256 };
type Box = { arr: Arr<In,2> };
class C { b: Box; set(): External<void> { let m: Box = Box([In(1n,2n),In(3n,4n)]); this.b = m; } get g(): External<u256> { return this.b.arr[1].y; } }`,
    sol: `struct In { uint256 x; uint256 y; } struct Box { In[2] arr; } contract C { Box b; function set() external { Box memory m=Box([In(1,2),In(3,4)]); b=m; } function g() external view returns(uint256){return b.arr[1].y;} }`,
  },
  {
    name: 'a fixed array whose element is a struct (Box[2]) from memory local',
    jeth: `type In = { x: u256; y: u256 };
type Box = { arr: Arr<In,2> };
class C { s: Arr<Box,2>; set(): External<void> { let m: Arr<Box,2> = [Box([In(1n,2n),In(3n,4n)]),Box([In(5n,6n),In(7n,8n)])]; this.s = m; } get g(): External<u256> { return this.s[1].arr[1].y; } }`,
    sol: `struct In { uint256 x; uint256 y; } struct Box { In[2] arr; } contract C { Box[2] s; function set() external { Box[2] memory m=[Box([In(1,2),In(3,4)]),Box([In(5,6),In(7,8)])]; s=m; } function g() external view returns(uint256){return s[1].arr[1].y;} }`,
  },
];

// The nested Arr<Arr<In,N>,M> from a MEMORY source is a SAFE OVER-REJECTION (solc ACCEPTS it, but JETH
// would MISCOMPILE the nested memory->storage image); JETH470 is the clean reject. Verified separately so
// the "solc also rejects" assertion above is not applied to it.
const OVER_REJECT_MEM_NESTED = {
  name: 'nested Arr<Arr<In,2>,2> from a memory local (safe over-rejection; closes a miscompile)',
  jeth: `type In = { x: u256; y: u256 };
class C { s: Arr<Arr<In,2>,2>; set(): External<void> { let m: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)]]; this.s = m; } get g(): External<u256> { return this.s[1][1].y; } }`,
  sol: `struct In { uint256 x; uint256 y; } contract C { In[2][2] s; function set() external { In[2][2] memory m=[[In(1,2),In(3,4)],[In(5,6),In(7,8)]]; s=m; } function g() external view returns(uint256){return s[1][1].y;} }`,
};

describe('JETH470: whole struct-array / static-struct-leaf aggregate memory|calldata -> storage copy rejects (matches solc legacy)', () => {
  for (const c of REJECT) {
    it(`rejects with JETH470 and solc-legacy also rejects: ${c.name}`, () => {
      expect(codes(c.jeth)).toContain('JETH470');
      // solc's LEGACY pipeline rejects the same copy (UnimplementedFeatureError) -> accept/reject parity.
      expect(solcAccepts(c.sol)).toBe(false);
    });
  }

  it('over-rejects (JETH470) the nested Arr<Arr<In,2>,2> memory copy that solc accepts (a clean reject beats a miscompile)', () => {
    expect(codes(OVER_REJECT_MEM_NESTED.jeth)).toContain('JETH470');
    // solc-legacy ACCEPTS this one (nested array-of-array), so this is a deliberate SAFE over-rejection.
    expect(solcAccepts(OVER_REJECT_MEM_NESTED.sol)).toBe(true);
  });
});

// MUST-STAY-ACCEPTED: these must keep compiling in BOTH JETH and solc, AND run byte-identically.
describe('JETH470 scope: value arrays / single struct / calldata struct / storage->storage stay ACCEPTED and byte-identical', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `type In = { x: u256; y: u256 };
type Box = { arr: Arr<In,2> };
type BoxV = { v: Arr<u256,2> };
class C {
  va: Arr<u256,2>;
  one: In;
  bv: BoxV;
  nc: Arr<Arr<In,2>,2>;
  bc: Box;
  src: Arr<In,2>;
  dst: Arr<In,2>;
  setVal(a: Arr<u256,2>): External<void> { this.va = a; }
  get gVal(i: u256): External<u256> { return this.va[i]; }
  setOne(a: In): External<void> { this.one = a; }
  get gOne(): External<u256> { return this.one.y; }
  setBoxV(a: BoxV): External<void> { this.bv = a; }
  get gBoxV(i: u256): External<u256> { return this.bv.v[i]; }
  setNestCd(a: Arr<Arr<In,2>,2>): External<void> { this.nc = a; }
  get gNest(i: u256, j: u256): External<u256> { return this.nc[i][j].y; }
  setBoxCd(a: Box): External<void> { this.bc = a; }
  get gBox(i: u256): External<u256> { return this.bc.arr[i].y; }
  seed(): External<void> { this.src[0n].x = 11n; this.src[1n].y = 22n; }
  copy(): External<void> { this.dst = this.src; }
  get gDst0x(): External<u256> { return this.dst[0n].x; }
  get gDst1y(): External<u256> { return this.dst[1n].y; }
}`;
  const So = `${SPDX}
struct In { uint256 x; uint256 y; }
struct Box { In[2] arr; }
struct BoxV { uint256[2] v; }
contract C {
  uint256[2] va;
  In one;
  BoxV bv;
  In[2][2] nc;
  Box bc;
  In[2] src;
  In[2] dst;
  function setVal(uint256[2] calldata a) external { va = a; }
  function gVal(uint256 i) external view returns (uint256) { return va[i]; }
  function setOne(In calldata a) external { one = a; }
  function gOne() external view returns (uint256) { return one.y; }
  function setBoxV(BoxV calldata a) external { bv = a; }
  function gBoxV(uint256 i) external view returns (uint256) { return bv.v[i]; }
  function setNestCd(In[2][2] calldata a) external { nc = a; }
  function gNest(uint256 i, uint256 j) external view returns (uint256) { return nc[i][j].y; }
  function setBoxCd(Box calldata a) external { bc = a; }
  function gBox(uint256 i) external view returns (uint256) { return bc.arr[i].y; }
  function seed() external { src[0].x = 11; src[1].y = 22; }
  function copy() external { dst = src; }
  function gDst0x() external view returns (uint256) { return dst[0].x; }
  function gDst1y() external view returns (uint256) { return dst[1].y; }
}`;

  beforeAll(async () => {
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(So, 'C').creation);
  });

  async function eq(sig: string, args = '') {
    const data = '0x' + sel(sig) + args;
    const rj = await jeth.call(aj, data);
    const rs = await sol.call(as, data);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }

  it('value fixed array Arr<u256,2> -> storage is byte-identical', async () => {
    await eq('setVal(uint256[2])', W(101n) + W(202n));
    await eq('gVal(uint256)', W(0n));
    await eq('gVal(uint256)', W(1n));
  });
  it('single struct -> storage is byte-identical', async () => {
    await eq('setOne((uint256,uint256))', W(5n) + W(9n));
    await eq('gOne()');
  });
  it('struct with a value-array field -> storage is byte-identical', async () => {
    await eq('setBoxV((uint256[2]))', W(7n) + W(8n));
    await eq('gBoxV(uint256)', W(0n));
    await eq('gBoxV(uint256)', W(1n));
  });
  it('nested Arr<Arr<In,2>,2> from CALLDATA -> storage is byte-identical', async () => {
    await eq('setNestCd((uint256,uint256)[2][2])', W(1n) + W(2n) + W(3n) + W(4n) + W(5n) + W(6n) + W(7n) + W(8n));
    await eq('gNest(uint256,uint256)', W(1n) + W(1n));
    await eq('gNest(uint256,uint256)', W(0n) + W(0n));
  });
  it('whole calldata-struct (Box{In[2]}) -> storage is byte-identical', async () => {
    await eq('setBoxCd(((uint256,uint256)[2]))', W(10n) + W(20n) + W(30n) + W(40n));
    await eq('gBox(uint256)', W(0n));
    await eq('gBox(uint256)', W(1n));
  });
  it('storage -> storage struct-array copy (this.dst = this.src) is byte-identical', async () => {
    await eq('seed()');
    await eq('copy()');
    await eq('gDst0x()');
    await eq('gDst1y()');
  });
});
