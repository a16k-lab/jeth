// Two CONFIRMED abi.encode-of-a-struct-field MISCOMPILES (both compiled + succeeded, JETH emitted
// WRONG BYTES), now byte-identical to solc 0.8.35. Twins of the earlier Arr<string,N>/Arr<bytes,N>
// field fix, but for field kinds that fix did not cover:
//
//   V1: abi.encode(d.items) where d.items is Arr<In,N> - a FIXED array of DYNAMIC structs
//       (In = { s: string; n: u256 }) - a field of a MEMORY struct D. JETH returned a fixed garbage
//       blob with bogus 0x1040 offsets (same shape regardless of contents). FIX: route the field read
//       through the SAME nestedMemImagePtr + abiEncFromMem encoder the alias-out / whole-struct / return
//       paths already use (isDynStructFixedLeafArray added to prepArrayComponent's codecSourced).
//
//   V2: abi.encode(o.inner) where o.inner is a WHOLE nested DYNAMIC struct field
//       (Inner = { xs: u256[]; label: string }) read off a CALLDATA parent struct
//       (Outer = { name: string; inner: Inner; k: u256 }). JETH spliced in the adjacent `name` field
//       instead of inner. Same root corrupted the let-m copy, emit, revert, encodeWithSignature and
//       keccak256(abi.encode) consumers. FIX: the calldata nested-dyn-struct FIELD copy/encode now
//       resolves the FIELD's own tuple-start (cdDynStructFieldTupleStart, the same base the
//       `return o.inner` echo uses) instead of the PARENT param's tuple start.
//
// Non-vacuity: hard-coded solc 0.8.35 golden blobs, cross-checked against a live solc compile.
import { describe, it, expect } from 'vitest';
import type { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function pair(jeth: string, sol: string): Promise<{ h: Harness; aj: Address; as: Address }> {
  const h = await Harness.create();
  const aj: Address = await h.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await h.deploy(compileSolidity(SPDX + sol, 'C').creation);
  return { h, aj, as };
}

// V1: abi.encode(Arr<In,2>) field of a memory struct, In = {string s; uint256 n}.
const V1_J = `
type In = { s: string; n: u256 };
type D = { items: Arr<In, 2>; tag: u256 };
class C {
  Ev: event<{ items: Arr<In, 2> }>;
  get f(): External<bytes> { let a: In = In("hello", 7n); let b: In = In("world!", 9n); let d: D = D([a, b], 42n); return abi.encode(d.items); }
  get whole(): External<bytes> { let a: In = In("hello", 7n); let b: In = In("world!", 9n); let d: D = D([a, b], 42n); return abi.encode(d); }
  get aliasout(): External<bytes> { let a: In = In("hello", 7n); let b: In = In("world!", 9n); let d: D = D([a, b], 42n); let t: Arr<In, 2> = d.items; return abi.encode(t); }
  get kk(): External<bytes32> { let a: In = In("hello", 7n); let b: In = In("world!", 9n); let d: D = D([a, b], 42n); return keccak256(abi.encode(d.items)); }
  get sig(): External<bytes> { let a: In = In("hello", 7n); let b: In = In("world!", 9n); let d: D = D([a, b], 42n); return abi.encodeWithSignature("g(uint256)", d.items); }
  ev(): External<void> { let a: In = In("hello", 7n); let b: In = In("world!", 9n); let d: D = D([a, b], 42n); emit(Ev(d.items)); }
}
`;
const V1_S = `
struct In { string s; uint256 n; }
struct D { In[2] items; uint256 tag; }
contract C {
  event Ev(In[2] items);
  function f() external pure returns (bytes memory) { In memory a = In("hello",7); In memory b = In("world!",9); D memory d = D([a,b], 42); return abi.encode(d.items); }
  function whole() external pure returns (bytes memory) { In memory a = In("hello",7); In memory b = In("world!",9); D memory d = D([a,b], 42); return abi.encode(d); }
  function aliasout() external pure returns (bytes memory) { In memory a = In("hello",7); In memory b = In("world!",9); D memory d = D([a,b], 42); In[2] memory t = d.items; return abi.encode(t); }
  function kk() external pure returns (bytes32) { In memory a = In("hello",7); In memory b = In("world!",9); D memory d = D([a,b], 42); return keccak256(abi.encode(d.items)); }
  function sig() external pure returns (bytes memory) { In memory a = In("hello",7); In memory b = In("world!",9); D memory d = D([a,b], 42); return abi.encodeWithSignature("g(uint256)", d.items); }
  function ev() external { In memory a = In("hello",7); In memory b = In("world!",9); D memory d = D([a,b], 42); emit Ev(d.items); }
}
`;
// solc 0.8.35 abi.encode(d.items): [0x20][tuple offset 0x160][ In[2] head/tail: two element offsets
// 0x40/0xc0, then In("hello",7) and In("world!",9) each as (string offset 0x40, n, len, data) ].
const V1_GOLDEN =
  '0x0000000000000000000000000000000000000000000000000000000000000020' +
  '0000000000000000000000000000000000000000000000000000000000000160' +
  '0000000000000000000000000000000000000000000000000000000000000020' +
  '0000000000000000000000000000000000000000000000000000000000000040' +
  '00000000000000000000000000000000000000000000000000000000000000c0' +
  '0000000000000000000000000000000000000000000000000000000000000040' +
  '0000000000000000000000000000000000000000000000000000000000000007' +
  '0000000000000000000000000000000000000000000000000000000000000005' +
  '68656c6c6f000000000000000000000000000000000000000000000000000000' +
  '0000000000000000000000000000000000000000000000000000000000000040' +
  '0000000000000000000000000000000000000000000000000000000000000009' +
  '0000000000000000000000000000000000000000000000000000000000000006' +
  '776f726c64210000000000000000000000000000000000000000000000000000';

describe('V1: abi.encode of a Arr<In,N> (fixed array of dynamic structs) field of a memory struct - byte-identical to solc 0.8.35', () => {
  it('the miscompiled field-access arg now matches solc AND the hard-coded golden blob', async () => {
    const { h, aj, as } = await pair(V1_J, V1_S);
    const rj = await h.call(aj, sel('f()'));
    const rs = await h.call(as, sel('f()'));
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    // non-vacuity: the golden blob decodes to In("hello",7)+In("world!",9), NOT a repeated garbage word.
    expect(rj.returnHex).toBe(V1_GOLDEN);
    expect(rj.returnHex).toBe(rs.returnHex);
  });

  it('all consumer contexts match solc (whole-struct, alias-out, keccak, encodeWithSignature, emit)', async () => {
    const { h, aj, as } = await pair(V1_J, V1_S);
    for (const sig of ['whole()', 'aliasout()', 'kk()', 'sig()', 'ev()']) {
      const rj = await h.call(aj, sel(sig));
      const rs = await h.call(as, sel(sig));
      expect(rj.success, `${sig} success`).toBe(rs.success);
      expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
    }
  });
});

// V2: abi.encode(o.inner) - a whole nested dynamic struct field off a CALLDATA parent.
const V2_J = `
type Inner = { xs: u256[]; label: string };
type Outer = { name: string; inner: Inner; k: u256 };
class C {
  Er: error<{ inner: Inner }>;
  Ev: event<{ inner: Inner }>;
  get f(o: Outer): External<bytes> { return abi.encode(o.inner); }
  get ret(o: Outer): External<Inner> { return o.inner; }
  get copyenc(o: Outer): External<bytes> { let m: Inner = o.inner; return abi.encode(m); }
  get kk(o: Outer): External<bytes32> { return keccak256(abi.encode(o.inner)); }
  get sig(o: Outer): External<bytes> { return abi.encodeWithSignature("g(uint256)", o.inner); }
  rv(o: Outer): External<void> { revert(Er(o.inner)); }
  ev(o: Outer): External<void> { emit(Ev(o.inner)); }
}
`;
const V2_S = `
struct Inner { uint256[] xs; string label; }
struct Outer { string name; Inner inner; uint256 k; }
contract C {
  error Er(Inner inner);
  event Ev(Inner inner);
  function f(Outer calldata o) external pure returns (bytes memory) { return abi.encode(o.inner); }
  function ret(Outer calldata o) external pure returns (Inner memory) { return o.inner; }
  function copyenc(Outer calldata o) external pure returns (bytes memory) { Inner memory m = o.inner; return abi.encode(m); }
  function kk(Outer calldata o) external pure returns (bytes32) { return keccak256(abi.encode(o.inner)); }
  function sig(Outer calldata o) external pure returns (bytes memory) { return abi.encodeWithSignature("g(uint256)", o.inner); }
  function rv(Outer calldata o) external { revert Er(o.inner); }
  function ev(Outer calldata o) external { emit Ev(o.inner); }
}
`;
// Canonical calldata for f(Outer o) = abi.encode(Outer{name:"nm", inner:{xs:[1,2,3], label:"hello"}, k:42}).
const V2_CALLDATA =
  '0000000000000000000000000000000000000000000000000000000000000020' + // off(Outer)
  '0000000000000000000000000000000000000000000000000000000000000060' + // off(name)
  '00000000000000000000000000000000000000000000000000000000000000a0' + // off(inner)
  '000000000000000000000000000000000000000000000000000000000000002a' + // k = 42
  '0000000000000000000000000000000000000000000000000000000000000002' + // len(name)
  '6e6d000000000000000000000000000000000000000000000000000000000000' + // "nm"
  '0000000000000000000000000000000000000000000000000000000000000040' + // off(xs)
  '00000000000000000000000000000000000000000000000000000000000000c0' + // off(label)
  '0000000000000000000000000000000000000000000000000000000000000003' + // len(xs)
  '0000000000000000000000000000000000000000000000000000000000000001' + // xs[0]
  '0000000000000000000000000000000000000000000000000000000000000002' + // xs[1]
  '0000000000000000000000000000000000000000000000000000000000000003' + // xs[2]
  '0000000000000000000000000000000000000000000000000000000000000005' + // len(label)
  '68656c6c6f000000000000000000000000000000000000000000000000000000'; // "hello"
// The struct param dispatches on the EXPANDED tuple; the function's arg list adds one more paren pair.
const V2_SEL = '((string,(uint256[],string),uint256))';
// solc 0.8.35 abi.encode(o.inner): a bytes-return [0x20] wrapper, then the Inner tuple encoded as a
// dynamic component ([0x120 tuple offset][Inner tuple: off(xs)=0x40, off(label)=0xc0, xs[len 3;1,2,3],
// label[len 5;"hello"]]). The label "hello" (0x68656c6c6f) is present; the sibling name "nm" (0x6e6d) is NOT.
const V2_GOLDEN =
  '0x0000000000000000000000000000000000000000000000000000000000000020' +
  '0000000000000000000000000000000000000000000000000000000000000120' +
  '0000000000000000000000000000000000000000000000000000000000000020' +
  '0000000000000000000000000000000000000000000000000000000000000040' +
  '00000000000000000000000000000000000000000000000000000000000000c0' +
  '0000000000000000000000000000000000000000000000000000000000000003' +
  '0000000000000000000000000000000000000000000000000000000000000001' +
  '0000000000000000000000000000000000000000000000000000000000000002' +
  '0000000000000000000000000000000000000000000000000000000000000003' +
  '0000000000000000000000000000000000000000000000000000000000000005' +
  '68656c6c6f000000000000000000000000000000000000000000000000000000';

describe('V2: abi.encode of a whole nested dynamic-struct field off a calldata parent - byte-identical to solc 0.8.35', () => {
  it('the miscompiled encode no longer splices the sibling name field (matches golden + solc)', async () => {
    const { h, aj, as } = await pair(V2_J, V2_S);
    const data = sel('f' + V2_SEL) + V2_CALLDATA;
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success).toBe(true);
    expect(rs.success).toBe(true);
    // non-vacuity: the label "hello" (0x68656c6c6f) is present and the sibling "nm" (0x6e6d) is NOT spliced in.
    expect(rj.returnHex).toBe(V2_GOLDEN);
    expect(rj.returnHex).toBe(rs.returnHex);
    expect(rj.returnHex.includes('68656c6c6f')).toBe(true);
  });

  it('all consumer contexts match solc (return, let-m copy, keccak, encodeWithSignature, revert, emit)', async () => {
    const { h, aj, as } = await pair(V2_J, V2_S);
    for (const fn of ['ret', 'copyenc', 'kk', 'sig', 'rv', 'ev']) {
      const data = sel(fn + V2_SEL) + V2_CALLDATA;
      const rj = await h.call(aj, data);
      const rs = await h.call(as, data);
      expect(rj.success, `${fn} success`).toBe(rs.success);
      expect(rj.returnHex, `${fn} return`).toBe(rs.returnHex);
    }
  });
});
