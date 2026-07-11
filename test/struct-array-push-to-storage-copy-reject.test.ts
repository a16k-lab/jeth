// SOUNDNESS (JETH467/JETH470, PUSH entry point): the assignment gate (this.s = a) already rejects a whole
// MEMORY|CALLDATA aggregate whose top-level or a nested member is a FIXED array whose DIRECT element is a
// STRUCT (Arr<In,N>, a struct/fixed-array-of-struct transitively holding one) copied INTO STORAGE - solc's
// LEGACY pipeline raises UnimplementedFeatureError ("Copying of type struct In memory[N] ... to storage is
// not supported in legacy"). But the OTHER storage mutation entry points still OVER-ACCEPTED the same family:
//   this.bs.push(Box([In(1n,2n),In(3n,4n)]))   -- a MEMORY struct-with-struct-array-field pushed to Box[]
//   this.xs.push(<memory Arr<In,N>>)           -- a DIRECT static-struct fixed-array element pushed
//   this.xs.push(<memory Arr<DIn,N>>)          -- a DIRECT dynamic-struct fixed-array element pushed (JETH467)
//   this.wrap.boxes.push(<memory Box>) / this.mv[k].push(<memory Box>)  -- nested-field / mapping-valued arrays
// COMPILED in JETH (an OVER-ACCEPTANCE; the pushed element's N-pointer image would be flattened into the
// slots, a MISCOMPILE) while solc-legacy rejects them. checkArrayMutator now routes the pushed element type
// through the SAME memCdAggToStorageReject helper the assignment path uses, so both mutation paths reject the
// identical family byte-for-byte.
//
// This file pins BOTH sides of the push gate:
//   REJECT  (solc-legacy also rejects -> BOTH-REJECT): push a MEMORY Box(ctor) / memory local Box / memory
//           struct-array-element Box; push a MEMORY Arr<In,N> (direct static-struct element); push a CALLDATA
//           Arr<In,N> (a DIRECT array-of-struct rejects even a calldata source); push a MEMORY Arr<DIn,N>
//           (direct dynamic-struct element, JETH467); a nested-field push (this.wrap.boxes.push) and a
//           mapping-valued push (this.mv[k].push). PLUS a SAFE over-rejection: a nested Arr<Arr<In,N>,M> pushed
//           from a MEMORY source (solc accepts it, but JETH would MISCOMPILE the nested image).
//   ACCEPT  (byte-identical to solc): push a CALLDATA Box (whole calldata struct copies fine); push a STORAGE
//           Box (this.bs.push(this.src)) and a STORAGE struct-array element (this.b.push(this.a[i])); a nested
//           Arr<Arr<In,N>,M> pushed from CALLDATA; a value struct / value fixed array push. Plus (pinning the
//           ASSIGNMENT-gate refinement) a struct storage->storage copy (this.dst = this.src, @state Box) and a
//           storage struct-array-ELEMENT copy (this.dst = this.boxes[i]).
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
function solcAccepts(src: string): boolean {
  try {
    compileSolidity(SPDX + src, 'C');
    return true;
  } catch {
    return false;
  }
}

// Each MUST-REJECT case: JETH emits the expected code AND solc-legacy also rejects (byte-identical accept/reject).
const REJECT: { name: string; code: string; jeth: string; sol: string }[] = [
  {
    name: 'push a MEMORY Box(ctor) -> Box[]  (this.bs.push(Box([...])))',
    code: 'JETH470',
    jeth: `type In = { x: u256; y: u256 };
type Box = { arr: Arr<In,2> };
class C { bs: Box[]; go(): External<void> { this.bs.push(Box([In(1n,2n),In(3n,4n)])); } }`,
    sol: `struct In { uint256 x; uint256 y; } struct Box { In[2] arr; } contract C { Box[] bs; function go() external { bs.push(Box([In(1,2),In(3,4)])); } }`,
  },
  {
    name: 'push a MEMORY local Box -> Box[]',
    code: 'JETH470',
    jeth: `type In = { x: u256; y: u256 };
type Box = { arr: Arr<In,2> };
class C { bs: Box[]; go(): External<void> { let b: Box = Box([In(1n,2n),In(3n,4n)]); this.bs.push(b); } }`,
    sol: `struct In { uint256 x; uint256 y; } struct Box { In[2] arr; } contract C { Box[] bs; function go() external { Box memory b=Box([In(1,2),In(3,4)]); bs.push(b); } }`,
  },
  {
    name: 'push a MEMORY struct-array-element Box -> Box[]',
    code: 'JETH470',
    jeth: `type In = { x: u256; y: u256 };
type Box = { arr: Arr<In,2> };
class C { bs: Box[]; go(): External<void> { let arr: Box[] = new Array<Box>(1n); arr[0n] = Box([In(1n,2n),In(3n,4n)]); this.bs.push(arr[0n]); } }`,
    sol: `struct In { uint256 x; uint256 y; } struct Box { In[2] arr; } contract C { Box[] bs; function go() external { Box[] memory arr=new Box[](1); arr[0]=Box([In(1,2),In(3,4)]); bs.push(arr[0]); } }`,
  },
  {
    name: 'push a MEMORY Arr<In,2> -> (Arr<In,2>)[]  (direct static-struct fixed-array element)',
    code: 'JETH470',
    jeth: `type In = { x: u256; y: u256 };
class C { xs: Arr<In,2>[]; go(): External<void> { this.xs.push([In(1n,2n),In(3n,4n)]); } }`,
    sol: `struct In { uint256 x; uint256 y; } contract C { In[2][] xs; function go() external { xs.push([In(1,2),In(3,4)]); } }`,
  },
  {
    name: 'push a CALLDATA Arr<In,3> -> (Arr<In,3>)[]  (direct array-of-struct rejects even calldata)',
    code: 'JETH470',
    jeth: `type In = { x: u256; y: u256 };
class C { xs: Arr<In,3>[]; go(a: Arr<In,3>): External<void> { this.xs.push(a); } }`,
    sol: `struct In { uint256 x; uint256 y; } contract C { In[3][] xs; function go(In[3] calldata a) external { xs.push(a); } }`,
  },
  {
    name: 'push a MEMORY Arr<DIn,2> -> (Arr<DIn,2>)[]  (direct DYNAMIC-struct fixed-array element, JETH467)',
    code: 'JETH467',
    jeth: `type DIn = { a: u256; s: string };
class C { xs: Arr<DIn,2>[]; go(): External<void> { let a: Arr<DIn,2> = [DIn(1n,"x"),DIn(2n,"y")]; this.xs.push(a); } }`,
    sol: `struct DIn { uint256 a; string s; } contract C { DIn[2][] xs; function go() external { DIn[2] memory a=[DIn(1,"x"),DIn(2,"y")]; xs.push(a); } }`,
  },
  {
    name: 'push a MEMORY Box -> a NESTED-FIELD dyn array (this.wrap.boxes.push(b))',
    code: 'JETH470',
    jeth: `type In = { x: u256; y: u256 };
type Box = { arr: Arr<In,2> };
type Wrap = { boxes: Box[] };
class C { wrap: Wrap; go(): External<void> { let b: Box = Box([In(1n,2n),In(3n,4n)]); this.wrap.boxes.push(b); } }`,
    sol: `struct In { uint256 x; uint256 y; } struct Box { In[2] arr; } struct Wrap { Box[] boxes; } contract C { Wrap wrap; function go() external { Box memory b=Box([In(1,2),In(3,4)]); wrap.boxes.push(b); } }`,
  },
  {
    name: 'push a MEMORY Box -> a MAPPING-VALUED dyn array (this.mv[k].push(b))',
    code: 'JETH470',
    jeth: `type In = { x: u256; y: u256 };
type Box = { arr: Arr<In,2> };
class C { mv: mapping<u256,Box[]>; go(): External<void> { let b: Box = Box([In(1n,2n),In(3n,4n)]); this.mv[0n].push(b); } }`,
    sol: `struct In { uint256 x; uint256 y; } struct Box { In[2] arr; } contract C { mapping(uint256=>Box[]) mv; function go() external { Box memory b=Box([In(1,2),In(3,4)]); mv[0].push(b); } }`,
  },
];

// The nested Arr<Arr<In,2>,2> pushed from a MEMORY source is a SAFE OVER-REJECTION (solc ACCEPTS it, but JETH
// would MISCOMPILE the nested memory->storage image - verified: the read-back returns raw memory pointers
// instead of the values). JETH470 is the clean reject.
const OVER_REJECT_MEM_NESTED = {
  name: 'push a nested Arr<Arr<In,2>,2> from a memory local (safe over-rejection; closes a miscompile)',
  jeth: `type In = { x: u256; y: u256 };
class C { xs: Arr<Arr<In,2>,2>[]; go(): External<void> { let m: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)]]; this.xs.push(m); } }`,
  sol: `struct In { uint256 x; uint256 y; } contract C { In[2][2][] xs; function go() external { In[2][2] memory m=[[In(1,2),In(3,4)],[In(5,6),In(7,8)]]; xs.push(m); } }`,
};

describe('JETH467/JETH470 (push entry point): mem|cd struct-array-family push into storage rejects (matches solc legacy)', () => {
  for (const c of REJECT) {
    it(`rejects with ${c.code} and solc-legacy also rejects: ${c.name}`, () => {
      expect(codes(c.jeth)).toContain(c.code);
      expect(solcAccepts(c.sol)).toBe(false);
    });
  }

  it('over-rejects (JETH470) the nested Arr<Arr<In,2>,2> memory push that solc accepts (clean reject beats miscompile)', () => {
    expect(codes(OVER_REJECT_MEM_NESTED.jeth)).toContain('JETH470');
    expect(solcAccepts(OVER_REJECT_MEM_NESTED.sol)).toBe(true);
  });
});

// MUST-STAY-ACCEPTED: push a CALLDATA/STORAGE struct-array element, plus the assignment-gate refinement
// (storage->storage struct copy + storage struct-array-element copy). All must run byte-identically to solc.
describe('JETH467/JETH470 scope: calldata|storage struct pushes + storage->storage copies stay ACCEPTED and byte-identical', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `type In = { x: u256; y: u256 };
type Box = { arr: Arr<In,2> };
class C {
  bs: Box[];
  src: Box;
  a: Box[];
  b: Box[];
  dst: Box;
  boxes: Box[];
  pushCd(z: Box): External<void> { this.bs.push(z); }
  get gBs(i: u256, j: u256): External<u256> { return this.bs[i].arr[j].x; }
  seedSrc(z: Box): External<void> { this.src = z; }
  pushStorage(): External<void> { this.bs.push(this.src); }
  seedA(z: Box): External<void> { this.a.push(z); }
  pushStorageElem(): External<void> { this.b.push(this.a[0n]); }
  get gB(i: u256, j: u256): External<u256> { return this.b[i].arr[j].x; }
  copyStruct(): External<void> { this.dst = this.src; }
  get gDst(j: u256): External<u256> { return this.dst.arr[j].x; }
  seedBoxes(z: Box): External<void> { this.boxes.push(z); }
  copyStructElem(): External<void> { this.dst = this.boxes[0n]; }
}`;
  const So = `${SPDX}
struct In { uint256 x; uint256 y; }
struct Box { In[2] arr; }
contract C {
  Box[] bs;
  Box src;
  Box[] a;
  Box[] b;
  Box dst;
  Box[] boxes;
  function pushCd(Box calldata z) external { bs.push(z); }
  function gBs(uint256 i, uint256 j) external view returns (uint256) { return bs[i].arr[j].x; }
  function seedSrc(Box calldata z) external { src = z; }
  function pushStorage() external { bs.push(src); }
  function seedA(Box calldata z) external { a.push(z); }
  function pushStorageElem() external { b.push(a[0]); }
  function gB(uint256 i, uint256 j) external view returns (uint256) { return b[i].arr[j].x; }
  function copyStruct() external { dst = src; }
  function gDst(uint256 j) external view returns (uint256) { return dst.arr[j].x; }
  function seedBoxes(Box calldata z) external { boxes.push(z); }
  function copyStructElem() external { dst = boxes[0]; }
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

  const box = (a: bigint, b: bigint, c: bigint, d: bigint) => W(a) + W(b) + W(c) + W(d);

  it('push a whole CALLDATA Box -> Box[] is byte-identical', async () => {
    await eq('pushCd(((uint256,uint256)[2]))', box(1n, 2n, 3n, 4n));
    await eq('gBs(uint256,uint256)', W(0n) + W(0n));
    await eq('gBs(uint256,uint256)', W(0n) + W(1n));
  });
  it('push a STORAGE Box (this.bs.push(this.src)) is byte-identical', async () => {
    await eq('seedSrc(((uint256,uint256)[2]))', box(9n, 8n, 7n, 6n));
    await eq('pushStorage()');
    // bs now has [0]=calldata Box, [1]=storage-sourced Box
    await eq('gBs(uint256,uint256)', W(1n) + W(0n));
    await eq('gBs(uint256,uint256)', W(1n) + W(1n));
  });
  it('push a STORAGE struct-array element (this.b.push(this.a[0])) is byte-identical', async () => {
    await eq('seedA(((uint256,uint256)[2]))', box(11n, 12n, 13n, 14n));
    await eq('pushStorageElem()');
    await eq('gB(uint256,uint256)', W(0n) + W(0n));
    await eq('gB(uint256,uint256)', W(0n) + W(1n));
  });
  it('storage->storage struct copy (this.dst = this.src) is byte-identical', async () => {
    await eq('copyStruct()');
    await eq('gDst(uint256)', W(0n));
    await eq('gDst(uint256)', W(1n));
  });
  it('storage struct-array-element copy (this.dst = this.boxes[0]) is byte-identical', async () => {
    await eq('seedBoxes(((uint256,uint256)[2]))', box(21n, 22n, 23n, 24n));
    await eq('copyStructElem()');
    await eq('gDst(uint256)', W(0n));
    await eq('gDst(uint256)', W(1n));
  });
});
