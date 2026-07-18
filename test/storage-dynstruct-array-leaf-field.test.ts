// A STORAGE dynamic-struct ARRAY `D[]` (also Arr<D,N>, a D[] field of an outer struct, mapping-valued)
// whose element struct D has a NESTED-DYNAMIC-LEAF field (an array field whose own element is dynamic:
// bytes[] / string[] / T[][]). Reading / encoding / returning such an array (return this.vals,
// abi.encode(this.vals), return this.vals[i]) used to SILENTLY MISCOMPILE: the storage write of the
// nested-leaf field stored the memory pointer as the array length (never deep-copying), and the array
// return encoder used a static-inline transcode (fixed abiHeadWords stride) instead of head/tail.
//
// FIX (byte-identical lift, not a reject): the write deep-copies the leaf-array field into storage via
// the same copyMemAggArrayIntoStorage path `this.field = arr` uses; the whole-array return/encode route
// through abiEncFromStorage's head/tail dynamic-element branch; the single-element read builds the
// element's pointer-headed B4 image (abiDecFromStorageToImage) inside buildDynStructFromStorage. All
// byte-identical to solc 0.8.35, verified below. WORKING shapes (single-bytes/value-array-field D[],
// static-struct P[], single struct) are guarded to confirm no regression.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => pad32(n).replace(/^0x/, '');
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};

// calls: [sig, argsHex?] tuples. Asserts JETH and solc agree (success + returnHex) on every call.
async function diff(J: string, S: string, calls: [string, string?][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, args] of calls) {
    const data = sel(sg) + (args ?? '');
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sg + ' success').toBe(rs.success);
    expect(rj.returnHex, sg + ' returnHex').toBe(rs.returnHex);
  }
}

describe('storage dyn-struct array with a nested-dynamic-leaf field - byte-identical to solc 0.8.35', () => {
  it('D{id;tags:bytes[]}[]: return / abi.encode / single element (was a miscompile)', async () => {
    const J = `type D = { id: u256; tags: bytes[]; };
    class C { vals: D[];
      seed(): External<void> { let a: bytes[] = [bytes("aa"), bytes("bb")]; this.vals.push(D(1n, a)); let b: bytes[] = [bytes("ccc")]; this.vals.push(D(2n, b)); }
      get getAll(): External<D[]> { return this.vals; }
      get getOne(i: u256): External<D> { return this.vals[i]; }
      get enc(): External<bytes> { return abi.encode(this.vals); }
      get encOne(i: u256): External<bytes> { return abi.encode(this.vals[i]); } }`;
    const S = `struct D { uint256 id; bytes[] tags; }
    contract C { D[] vals;
      function seed() external { bytes[] memory a=new bytes[](2); a[0]="aa"; a[1]="bb"; vals.push(D(1,a)); bytes[] memory b=new bytes[](1); b[0]="ccc"; vals.push(D(2,b)); }
      function getAll() external view returns (D[] memory) { return vals; }
      function getOne(uint256 i) external view returns (D memory) { return vals[i]; }
      function enc() external view returns (bytes memory) { return abi.encode(vals); }
      function encOne(uint256 i) external view returns (bytes memory) { return abi.encode(vals[i]); } }`;
    await diff(J, S, [
      ['seed()'],
      ['getAll()'],
      ['getOne(uint256)', W(0n)],
      ['getOne(uint256)', W(1n)],
      ['enc()'],
      ['encOne(uint256)', W(0n)],
      ['encOne(uint256)', W(1n)],
    ]);
  });

  it('string[] / u256[][] leaf-field, multi-field, long + empty leaves, empty outer', async () => {
    const J = `type D = { id: u256; tags: bytes[]; names: string[]; grid: u256[][]; };
    class C { vals: D[];
      seed(): External<void> {
        let t: bytes[] = [bytes("a-much-longer-leaf-past-32-bytes-boundary!!!"), bytes("")];
        let n: string[] = ["hi"];
        let r0: u256[] = [1n, 2n]; let r1: u256[] = [3n]; let g: u256[][] = [r0, r1];
        this.vals.push(D(1n, t, n, g));
        let t2: bytes[] = [];
        let n2: string[] = ["alpha", "beta-longer-than-thirty-two-bytes-for-sure!"];
        let g2: u256[][] = [];
        this.vals.push(D(2n, t2, n2, g2));
      }
      get getAll(): External<D[]> { return this.vals; }
      get getOne(i: u256): External<D> { return this.vals[i]; }
      get enc(): External<bytes> { return abi.encode(this.vals); } }`;
    const S = `struct D { uint256 id; bytes[] tags; string[] names; uint256[][] grid; }
    contract C { D[] vals;
      function seed() external {
        bytes[] memory t=new bytes[](2); t[0]="a-much-longer-leaf-past-32-bytes-boundary!!!"; t[1]="";
        string[] memory n=new string[](1); n[0]="hi";
        uint256[][] memory g=new uint256[][](2); g[0]=new uint256[](2); g[0][0]=1; g[0][1]=2; g[1]=new uint256[](1); g[1][0]=3;
        vals.push(D(1,t,n,g));
        bytes[] memory t2=new bytes[](0);
        string[] memory n2=new string[](2); n2[0]="alpha"; n2[1]="beta-longer-than-thirty-two-bytes-for-sure!";
        uint256[][] memory g2=new uint256[][](0);
        vals.push(D(2,t2,n2,g2));
      }
      function getAll() external view returns (D[] memory) { return vals; }
      function getOne(uint256 i) external view returns (D memory) { return vals[i]; }
      function enc() external view returns (bytes memory) { return abi.encode(vals); } }`;
    await diff(J, S, [
      ['getAll()'], // empty outer first
      ['enc()'],
      ['seed()'],
      ['getAll()'],
      ['getOne(uint256)', W(0n)],
      ['getOne(uint256)', W(1n)],
      ['enc()'],
    ]);
  });

  it('leading nested-leaf field (offset 0) + stale-slot reuse deep-clear', async () => {
    const J = `type D = { tags: bytes[]; id: u256; };
    class C { vals: D[];
      seed(): External<void> {
        let a: bytes[] = [bytes("very-long-leaf-bytes-well-past-32-boundary!!"), bytes("xx")]; this.vals.push(D(a, 1n));
        let b: bytes[] = [bytes("yy")]; this.vals.push(D(b, 2n));
        this.vals.pop();
        let c: bytes[] = [bytes("z")]; this.vals.push(D(c, 3n));
      }
      get getAll(): External<D[]> { return this.vals; }
      get getOne(): External<D> { return this.vals[1n]; } }`;
    const S = `struct D { bytes[] tags; uint256 id; }
    contract C { D[] vals;
      function seed() external {
        bytes[] memory a=new bytes[](2); a[0]="very-long-leaf-bytes-well-past-32-boundary!!"; a[1]="xx"; vals.push(D(a, 1));
        bytes[] memory b=new bytes[](1); b[0]="yy"; vals.push(D(b, 2));
        vals.pop();
        bytes[] memory c=new bytes[](1); c[0]="z"; vals.push(D(c, 3));
      }
      function getAll() external view returns (D[] memory) { return vals; }
      function getOne() external view returns (D memory) { return vals[1]; } }`;
    await diff(J, S, [['seed()'], ['getAll()'], ['getOne()']]);
  });

  it('Arr<D,N> fixed outer + an outer struct with a D[] field + mapping-valued D[]', async () => {
    // mapping-valued D[]
    const Jm = `type D = { id: u256; tags: bytes[]; };
    class C { m: mapping<u256, D[]>;
      seed(): External<void> { let a: bytes[] = [bytes("xx"), bytes("yy")]; this.m[5n].push(D(1n, a)); let b: bytes[] = [bytes("z")]; this.m[5n].push(D(2n, b)); }
      get getAll(k: u256): External<D[]> { return this.m[k]; } }`;
    const Sm = `struct D { uint256 id; bytes[] tags; }
    contract C { mapping(uint256 => D[]) m;
      function seed() external { bytes[] memory a=new bytes[](2); a[0]="xx"; a[1]="yy"; m[5].push(D(1,a)); bytes[] memory b=new bytes[](1); b[0]="z"; m[5].push(D(2,b)); }
      function getAll(uint256 k) external view returns (D[] memory) { return m[k]; } }`;
    await diff(Jm, Sm, [['seed()'], ['getAll(uint256)', W(5n)]]);

    // outer struct with a D[] field, returned whole (return this.o)
    const Jo = `type D = { id: u256; tags: bytes[]; };
    type Outer = { tag: u256; ds: D[]; };
    class C { o: Outer;
      seed(): External<void> { this.o.tag = 7n; let a: bytes[] = [bytes("aa"), bytes("bb")]; this.o.ds.push(D(1n, a)); let b: bytes[] = [bytes("ccc")]; this.o.ds.push(D(2n, b)); }
      get getit(): External<Outer> { return this.o; } }`;
    const So = `struct D { uint256 id; bytes[] tags; }
    struct Outer { uint256 tag; D[] ds; }
    contract C { Outer o;
      function seed() external { o.tag=7; bytes[] memory a=new bytes[](2); a[0]="aa"; a[1]="bb"; o.ds.push(D(1,a)); bytes[] memory b=new bytes[](1); b[0]="ccc"; o.ds.push(D(2,b)); }
      function getit() external view returns (Outer memory) { return o; } }`;
    await diff(Jo, So, [['seed()'], ['getit()']]);

    // Arr<D,N> fixed outer (seed the id via per-element field set; tags seeded through the whole-element D(...) is JETH200, so id-only here)
    const Ja = `type D = { id: u256; tags: bytes[]; };
    class C { vals: Arr<D,2>;
      seed(): External<void> { this.vals[0n].id = 11n; this.vals[1n].id = 22n; }
      get getAll(): External<Arr<D,2>> { return this.vals; } }`;
    const Sa = `struct D { uint256 id; bytes[] tags; }
    contract C { D[2] vals;
      function seed() external { vals[0].id=11; vals[1].id=22; }
      function getAll() external view returns (D[2] memory) { return vals; } }`;
    await diff(Ja, Sa, [['seed()'], ['getAll()']]);
  });

  it('REGRESSION GUARD: working shapes stay byte-identical', async () => {
    // static struct array P[] (untouched static-inline path)
    await diff(
      `type P = { a: u256; b: u256; };
       class C { vals: P[];
         seed(): External<void> { this.vals.push(P(1n, 2n)); this.vals.push(P(3n, 4n)); }
         get getAll(): External<P[]> { return this.vals; }
         get enc(): External<bytes> { return abi.encode(this.vals); }
         get getOne(): External<P> { return this.vals[1n]; } }`,
      `struct P { uint256 a; uint256 b; }
       contract C { P[] vals;
         function seed() external { vals.push(P(1,2)); vals.push(P(3,4)); }
         function getAll() external view returns (P[] memory) { return vals; }
         function enc() external view returns (bytes memory) { return abi.encode(vals); }
         function getOne() external view returns (P memory) { return vals[1]; } }`,
      [['seed()'], ['getAll()'], ['enc()'], ['getOne()']],
    );

    // single-bytes-field D[] (dynamic struct, single dynamic leaf - the documented WORKING case)
    await diff(
      `type D = { id: u256; s: bytes; };
       class C { vals: D[];
         seed(): External<void> { this.vals.push(D(1n, bytes("hi"))); this.vals.push(D(2n, bytes("world!"))); }
         get getAll(): External<D[]> { return this.vals; }
         get getOne(): External<D> { return this.vals[0n]; } }`,
      `struct D { uint256 id; bytes s; }
       contract C { D[] vals;
         function seed() external { vals.push(D(1,"hi")); vals.push(D(2,"world!")); }
         function getAll() external view returns (D[] memory) { return vals; }
         function getOne() external view returns (D memory) { return vals[0]; } }`,
      [['seed()'], ['getAll()'], ['getOne()']],
    );

    // dynamic VALUE-array-field D[] (D{id; ns:u256[]})
    await diff(
      `type D = { id: u256; ns: u256[]; };
       class C { vals: D[];
         seed(): External<void> { let a: u256[] = [10n, 20n]; this.vals.push(D(1n, a)); let b: u256[] = [30n]; this.vals.push(D(2n, b)); }
         get getAll(): External<D[]> { return this.vals; }
         get getOne(): External<D> { return this.vals[1n]; } }`,
      `struct D { uint256 id; uint256[] ns; }
       contract C { D[] vals;
         function seed() external { uint256[] memory a=new uint256[](2); a[0]=10; a[1]=20; vals.push(D(1,a)); uint256[] memory b=new uint256[](1); b[0]=30; vals.push(D(2,b)); }
         function getAll() external view returns (D[] memory) { return vals; }
         function getOne() external view returns (D memory) { return vals[1]; } }`,
      [['seed()'], ['getAll()'], ['getOne()']],
    );

    // single storage struct with a bytes[] field (per-field push seed; the documented WORKING case)
    await diff(
      `type P = { a: u256; tags: bytes[]; };
       class C { s: P;
         setup(): External<void> { this.s.a = 7n; this.s.tags.push(bytes("aa")); this.s.tags.push(bytes("bbbb")); }
         get enc(): External<bytes> { return abi.encode(this.s); }
         get ret(): External<P> { return this.s; } }`,
      `struct P { uint256 a; bytes[] tags; }
       contract C { P s;
         function setup() external { s.a=7; s.tags.push("aa"); s.tags.push("bbbb"); }
         function enc() external view returns(bytes memory){ return abi.encode(s); }
         function ret() external view returns(P memory){ return s; } }`,
      [['setup()'], ['enc()'], ['ret()']],
    );
  });

  it('LIFTED: a direct array-literal constructor arg for a nested-leaf field now accepts (byte-identical to new+fill); Arr<T,N>[] stays rejected', async () => {
    // solc rejects the literal spelling (fixed [N] -> dynamic), so this is a documented JETH superset; the
    // built image is byte-identical to `D(1, <newArrayValue>)`. A FIXED-inner value array (Arr<T,N>[])
    // literal STAYS a clean JETH226 reject (its mem->storage copy hits a pre-existing payload-drop bug).
    const J = `type D = { id: u256; tags: bytes[]; };
      class C { vals: D[]; f(): External<void> { this.vals.push(D(1n, [bytes("xy"),bytes("z")])); } get bl(): External<u256> { return this.vals[0n].tags[0n].length; } get n(): External<u256> { return this.vals.length; } }`;
    const S = `struct D { uint256 id; bytes[] tags; }
      contract C { D[] vals; function f() external { bytes[] memory t = new bytes[](2); t[0]="xy"; t[1]="z"; vals.push(D(1, t)); } function bl() external view returns(uint256){ return vals[0].tags[0].length; } function n() external view returns(uint256){ return vals.length; } }`;
    await diff(J, S, [['f()'], ['bl()'], ['n()']]);
    expect(
      codes(`type D = { id: u256; g: Arr<u256,2>[]; }; class C { vals: D[]; f(): External<void> { this.vals.push(D(1n, [[u256(1n),2n]])); } }`),
    ).toContain('JETH226');
  });
});
