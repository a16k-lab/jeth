// Binding a whole VALUE-leaf inner array element of a calldata array-of-array to a memory local:
//   let row: u256[] = xs[i];  (u256[][] / address[][] / Arr<u256,N>[])
// Previously this crashed JETH900 ("reference value 'cdAggArrayElem' used in a non-reference
// context"); the inner element is now materialized into a fresh memory image via the calldata->memory
// codec (value leaves MASKED, the same as solc's copy). Consumers: row.length / row[k] / for-of /
// return row. Verified byte-identical incl OOB (Panic 0x32) and malformed calldata (oversized inner
// length / truncated -> EMPTY revert: a value-element array can never overflow memory before failing
// the calldatasize bound).
import { describe, it, expect, beforeAll } from 'vitest';
import type { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const M = 1n << 256n;
const W = (v: bigint | number) => (((BigInt(v) % M) + M) % M).toString(16).padStart(64, '0');
const valArr = (vs: (bigint | number)[]) => W(vs.length) + vs.map(W).join('');
function arrTab(items: string[]) {
  let off = items.length * 32;
  const offs: number[] = [];
  for (const it of items) {
    offs.push(off);
    off += it.length / 2;
  }
  return W(items.length) + offs.map((o) => W(o)).join('') + items.join('');
}

let h: Harness;
beforeAll(async () => {
  h = await Harness.create();
});

async function pair(jeth: string, sol: string) {
  const aj = await h.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { aj, as };
}
async function callOne(addr: Address, sig: string, cd: string) {
  const r = await h.call(addr, ('0x' + sel(sig) + cd) as `0x${string}`, {});
  return { success: r.success, ret: r.returnHex };
}
async function same(a: { aj: Address; as: Address }, label: string, sig: string, cd: string) {
  const j = await callOne(a.aj, sig, cd);
  const s = await callOne(a.as, sig, cd);
  expect(j, label).toEqual(s);
}

describe('calldata-2d-value-bind: u256[][]', () => {
  let a: { aj: Address; as: Address };
  beforeAll(async () => {
    a = await pair(
      `class C{
  get len(xs:u256[][],i:u256):External<u256>{ let row:u256[]=xs[i]; return row.length; }
  get idx(xs:u256[][],i:u256,k:u256):External<u256>{ let row:u256[]=xs[i]; return row[k]; }
  get sum(xs:u256[][],i:u256):External<u256>{ let row:u256[]=xs[i]; let t:u256=0n; for(const v of row){ t=t+v; } return t; }
  get ret(xs:u256[][],i:u256):External<u256[]>{ let row:u256[]=xs[i]; return row; }
}`,
      `contract C{
  function len(uint256[][] calldata xs,uint256 i)external pure returns(uint256){ uint256[] memory row=xs[i]; return row.length; }
  function idx(uint256[][] calldata xs,uint256 i,uint256 k)external pure returns(uint256){ uint256[] memory row=xs[i]; return row[k]; }
  function sum(uint256[][] calldata xs,uint256 i)external pure returns(uint256){ uint256[] memory row=xs[i]; uint256 t=0; for(uint256 z=0;z<row.length;z++){t+=row[z];} return t; }
  function ret(uint256[][] calldata xs,uint256 i)external pure returns(uint256[] memory){ uint256[] memory row=xs[i]; return row; }
}`,
    );
  });
  const xs = arrTab([valArr([10n, 20n]), valArr([30n, 40n, 50n]), valArr([])]);
  it('row.length', async () => {
    await same(a, 'len i=0', 'len(uint256[][],uint256)', W(0x40) + W(0) + xs);
    await same(a, 'len i=1', 'len(uint256[][],uint256)', W(0x40) + W(1) + xs);
    await same(a, 'len i=2 empty', 'len(uint256[][],uint256)', W(0x40) + W(2) + xs);
  });
  it('row[k] incl OOB k', async () => {
    await same(a, 'idx[1][2]', 'idx(uint256[][],uint256,uint256)', W(0x60) + W(1) + W(2) + xs);
    await same(a, 'idx OOB k=3', 'idx(uint256[][],uint256,uint256)', W(0x60) + W(1) + W(3) + xs);
    await same(a, 'idx empty row OOB', 'idx(uint256[][],uint256,uint256)', W(0x60) + W(2) + W(0) + xs);
  });
  it('for-of sum', async () => {
    await same(a, 'sum i=0', 'sum(uint256[][],uint256)', W(0x40) + W(0) + xs);
    await same(a, 'sum i=1', 'sum(uint256[][],uint256)', W(0x40) + W(1) + xs);
    await same(a, 'sum i=2 empty', 'sum(uint256[][],uint256)', W(0x40) + W(2) + xs);
  });
  it('return row (whole inner array)', async () => {
    await same(a, 'ret i=0', 'ret(uint256[][],uint256)', W(0x40) + W(0) + xs);
    await same(a, 'ret i=1', 'ret(uint256[][],uint256)', W(0x40) + W(1) + xs);
    await same(a, 'ret i=2 empty', 'ret(uint256[][],uint256)', W(0x40) + W(2) + xs);
  });
  it('OOB outer i -> Panic 0x32', async () => {
    await same(a, 'len OOB i=3', 'len(uint256[][],uint256)', W(0x40) + W(3) + xs);
    await same(a, 'ret OOB i=3', 'ret(uint256[][],uint256)', W(0x40) + W(3) + xs);
  });
  it('malformed calldata: oversized / truncated inner -> EMPTY revert parity', async () => {
    const sig = 'len(uint256[][],uint256)';
    // inner length 2^64 (unsigned overflow guard)
    await same(a, 'inner len 2^64', sig, W(0x40) + W(0) + (W(1) + W(0x20) + W(1n << 64n)));
    // inner length huge-but-<2^64 -> calldatasize bound fails
    await same(a, 'inner len 1e6 truncated', sig, W(0x40) + W(0) + (W(1) + W(0x20) + W(1000000n)));
    // claims 3 elements, only 1 provided
    await same(a, 'inner data truncated', sig, W(0x40) + W(0) + (W(1) + W(0x20) + W(3) + W(7n)));
  });
});

describe('calldata-2d-value-bind: address[][] (value-leaf masking)', () => {
  let a: { aj: Address; as: Address };
  beforeAll(async () => {
    a = await pair(
      `class C{
  get idx(xs:address[][],i:u256,k:u256):External<address>{ let row:address[]=xs[i]; return row[k]; }
  get len(xs:address[][],i:u256):External<u256>{ let row:address[]=xs[i]; return row.length; }
  get ret(xs:address[][],i:u256):External<address[]>{ let row:address[]=xs[i]; return row; }
}`,
      `contract C{
  function idx(address[][] calldata xs,uint256 i,uint256 k)external pure returns(address){ address[] memory row=xs[i]; return row[k]; }
  function len(address[][] calldata xs,uint256 i)external pure returns(uint256){ address[] memory row=xs[i]; return row.length; }
  function ret(address[][] calldata xs,uint256 i)external pure returns(address[] memory){ address[] memory row=xs[i]; return row; }
}`,
    );
  });
  it('honest reads', async () => {
    const xs = arrTab([valArr([0x1111n, 0x2222n]), valArr([0x3333n])]);
    await same(a, 'addr idx[0][1]', 'idx(address[][],uint256,uint256)', W(0x60) + W(0) + W(1) + xs);
    await same(a, 'addr len i=1', 'len(address[][],uint256)', W(0x40) + W(1) + xs);
  });
  it('dirty high bits MASKED (solc copy semantics, not revert)', async () => {
    // inner array of one element with dirty upper bits above the 20-byte address
    const inner = W(1) + W((1n << 200n) | 0xabcdn);
    const xs = arrTab([inner]);
    await same(a, 'addr dirty masked', 'idx(address[][],uint256,uint256)', W(0x60) + W(0) + W(0) + xs);
  });
  it('return row (masking carries to the whole returned array)', async () => {
    const xs = arrTab([valArr([0x1111n, 0x2222n]), valArr([0x3333n])]);
    await same(a, 'addr ret i=0', 'ret(address[][],uint256)', W(0x40) + W(0) + xs);
    const inner = W(1) + W((1n << 200n) | 0xabcdn);
    await same(a, 'addr ret dirty', 'ret(address[][],uint256)', W(0x40) + W(0) + arrTab([inner]));
  });
});

describe('calldata-2d-value-bind: Arr<u256,2>[] (fixed inner)', () => {
  let a: { aj: Address; as: Address };
  beforeAll(async () => {
    a = await pair(
      `class C{
  get idx(xs:Arr<u256,2>[],i:u256,k:u256):External<u256>{ let row:Arr<u256,2>=xs[i]; return row[k]; }
}`,
      `contract C{
  function idx(uint256[2][] calldata xs,uint256 i,uint256 k)external pure returns(uint256){ uint256[2] memory row=xs[i]; return row[k]; }
}`,
    );
  });
  const xs = W(2) + W(11n) + W(12n) + W(21n) + W(22n); // outer dyn, 2 contiguous static elements
  it('honest reads incl both leaves', async () => {
    await same(a, 'fixed[0][0]', 'idx(uint256[2][],uint256,uint256)', W(0x60) + W(0) + W(0) + xs);
    await same(a, 'fixed[0][1]', 'idx(uint256[2][],uint256,uint256)', W(0x60) + W(0) + W(1) + xs);
    await same(a, 'fixed[1][1]', 'idx(uint256[2][],uint256,uint256)', W(0x60) + W(1) + W(1) + xs);
  });
  it('OOB outer i -> Panic 0x32', async () => {
    await same(a, 'fixed OOB i=2', 'idx(uint256[2][],uint256,uint256)', W(0x60) + W(2) + W(0) + xs);
  });
});
