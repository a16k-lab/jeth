// Two storage-aggregate fixes, byte-identical to solc 0.8.35:
//  (A) abi.encode / return of a FIXED-size storage struct array Arr<D,N> whose element struct D
//      has a DYNAMIC field (used to crash JETH900 in materializeArrayArg: the fixedArray storage
//      source was unhandled). The element head/tail (N-word offset table + per-element tails) is
//      now emitted by abiEncFromStorage's fixed-array-of-dynamic branch.
//  (B) reading a WHOLE element of a D[] dyn-struct-array FIELD of an OUTER storage struct
//      (this.b.items[i], items: D[]) - used to over-reject JETH151; the placeArray-rooted struct
//      element now resolves to structArrayElem (materialized via the storage dyn-struct codec).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const pad = (v: bigint) => v.toString(16).padStart(64, '0');

async function diff(J: string, S: string, calls: [string, string][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, args] of calls) {
    const data = sel(sg) + (args || '');
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
  }
}

describe('storage aggregate crash + nesting fixes - byte-identical to solc 0.8.35', () => {
  it('(A) abi.encode + return of Arr<D,2> (fixed array, dynamic-field element)', async () => {
    const J = `type D = { id: u256; tags: u256[]; };
    class C {
      vals: Arr<D,2>;
      seed(): External<void> {
        let a: u256[]=[1n,2n]; let b: u256[]=[3n,4n,5n];
        this.vals[0n]=D(7n,a); this.vals[1n]=D(8n,b);
      }
      get enc(): External<bytes> { return abi.encode(this.vals); }
      get get(): External<Arr<D,2>> { return this.vals; } }`;
    const S = `contract C {
      struct D { uint256 id; uint256[] tags; }
      D[2] vals;
      function seed() external {
        vals[0].id=7; vals[0].tags.push(1); vals[0].tags.push(2);
        vals[1].id=8; vals[1].tags.push(3); vals[1].tags.push(4); vals[1].tags.push(5);
      }
      function enc() external view returns (bytes memory) { return abi.encode(vals); }
      function get() external view returns (D[2] memory) { return vals; } }`;
    await diff(J, S, [['seed()', ''], ['enc()', ''], ['get()', '']]);
  });

  it('(B) read a whole D[] dyn-struct-array element FIELD of an outer struct (this.b.items[i])', async () => {
    const J = `type D = { id: u256; name: string; };
    type Box = { tag: u256; items: D[]; };
    class C {
      b: Box;
      seed(): External<void> { this.b.items.push(D(1n,"old")); this.b.items.push(D(2n,"two")); }
      get get(i: u256): External<D> { return this.b.items[i]; }
      get getName(i: u256): External<string> { return this.b.items[i].name; }
      get bind(i: u256): External<D> { let p: D = this.b.items[i]; return p; }
      get enc(i: u256): External<bytes> { return abi.encode(this.b.items[i]); } }`;
    const S = `contract C {
      struct D { uint256 id; string name; }
      struct Box { uint256 tag; D[] items; }
      Box b;
      function seed() external { b.items.push(D(1,"old")); b.items.push(D(2,"two")); }
      function get(uint256 i) external view returns (D memory) { return b.items[i]; }
      function getName(uint256 i) external view returns (string memory) { return b.items[i].name; }
      function bind(uint256 i) external view returns (D memory) { D memory p = b.items[i]; return p; }
      function enc(uint256 i) external view returns (bytes memory) { return abi.encode(b.items[i]); } }`;
    const calls: [string, string][] = [['seed()', '']];
    for (const i of [0n, 1n, 2n, 5n]) {
      calls.push(['get(uint256)', pad(i)]);
      calls.push(['getName(uint256)', pad(i)]);
      calls.push(['bind(uint256)', pad(i)]);
      calls.push(['enc(uint256)', pad(i)]);
    }
    await diff(J, S, calls);
  });
});
