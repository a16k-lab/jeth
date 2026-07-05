// W3-Y1: the pointer-headed FIXED-outer array-of-DYNAMIC-elements codec lifts, byte-identical to solc
// 0.8.35. A `Arr<string,N>` / `Arr<bytes,N>` / `Arr<u256[],N>` memory value is N absolute-pointer words
// (no [len] header), each pointing to a [len][data] / [len][elems] blob. These tests exercise the four
// lifted boundaries:
//   P0-33: abi.encode / keccak256(abi.encode) / mixed abi.encode(n, x) of such a value.
//   P0-34/P0-38: a custom @error whose parameter is such a type (the FULL recursive revert data, not the
//     36-byte pointer-word miscompile the old static-agg fallthrough emitted).
//   P1-7: an @internal function parameter/return of such a type, and abi.decode(b, Arr<...>).
// Every assertion compares JETH returndata (incl. revert data) against solc's for the same input.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint | number) => BigInt(n).toString(16).padStart(64, '0');
const strBlob = (s: string) => {
  const hx = Buffer.from(s, 'utf8').toString('hex');
  const len = Buffer.from(s, 'utf8').length;
  return W(len) + (len ? hx.padEnd(Math.ceil(hx.length / 64) * 64, '0') : '');
};
// abi tail of a string[2]/bytes[2] value passed as two dynamic calldata params s, t (a head of two offsets
// then the two blobs) - the exact calldata JETH's `f(string s, string t)` param decoder consumes.
const twoStr = (a: string, b: string) => {
  const b0 = strBlob(a);
  return W(0x40) + W(0x40 + b0.length / 2) + b0 + strBlob(b);
};
const uintArr = (xs: bigint[]) => W(xs.length) + xs.map(W).join('');
const twoUintArr = (a: bigint[], b: bigint[]) => {
  const b0 = uintArr(a);
  return W(0x40) + W(0x40 + b0.length / 2) + b0 + uintArr(b);
};

async function pair(jethSrc: string, solSrc: string, name = 'C') {
  const jb = compile(jethSrc, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + solSrc, name);
  const jeth = await Harness.create();
  const solh = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await solh.deploy(sb.creation);
  return { jeth, solh, aj, as };
}
async function cmp(
  h: { jeth: Harness; solh: Harness; aj: Address; as: Address },
  sig: string,
  args: string,
) {
  const data = '0x' + sel(sig) + args;
  const j = await h.jeth.call(h.aj, data);
  const s = await h.solh.call(h.as, data);
  expect(j.success, `success (jeth err=${(j as { exceptionError?: unknown }).exceptionError})`).toBe(s.success);
  expect(j.returnHex, 'returndata').toBe(s.returnHex);
  return { j, s };
}

const STR_SETS: [string, string][] = [
  ['ab', 'hello'],
  ['', ''],
  ['x'.repeat(70), 'y'],
  ['', 'z'.repeat(40)],
  ['a'.repeat(32), 'b'.repeat(33)],
];

describe('P0-33: abi.encode of a fixed-outer dynamic-element array', () => {
  it('abi.encode(Arr<string,2>) byte-identical across value sets', async () => {
    const h = await pair(
      `@contract class C { @external @pure f(s: string, t: string): bytes { let x: Arr<string,2> = [s,t]; return abi.encode(x); } }`,
      `contract C { function f(string calldata s, string calldata t) external pure returns (bytes memory) { string[2] memory x=[s,t]; return abi.encode(x);} }`,
    );
    for (const [a, b] of STR_SETS) await cmp(h, 'f(string,string)', twoStr(a, b));
  });

  it('abi.encode(Arr<bytes,2>) byte-identical', async () => {
    const h = await pair(
      `@contract class C { @external @pure f(s: bytes, t: bytes): bytes { let x: Arr<bytes,2> = [s,t]; return abi.encode(x); } }`,
      `contract C { function f(bytes calldata s, bytes calldata t) external pure returns (bytes memory) { bytes[2] memory x=[s,t]; return abi.encode(x);} }`,
    );
    for (const [a, b] of STR_SETS) await cmp(h, 'f(bytes,bytes)', twoStr(a, b));
  });

  it('abi.encode(Arr<u256[],2>) from memory-source inner arrays byte-identical', async () => {
    const h = await pair(
      `@contract class C { @external @pure f(a: u256[], b: u256[]): bytes { let p: u256[] = a; let q: u256[] = b; let x: Arr<u256[],2> = [p,q]; return abi.encode(x); } }`,
      `contract C { function f(uint256[] calldata a, uint256[] calldata b) external pure returns (bytes memory) { uint256[] memory p=a; uint256[] memory q=b; uint256[][2] memory x=[p,q]; return abi.encode(x);} }`,
    );
    for (const [a, b] of [[[1n, 2n], [3n]], [[], []], [[9n, 8n, 7n], []]] as [bigint[], bigint[]][])
      await cmp(h, 'f(uint256[],uint256[])', twoUintArr(a, b));
  });

  it('keccak256(abi.encode(Arr<string,2>)) and mixed abi.encode(n, x, m) byte-identical', async () => {
    const hk = await pair(
      `@contract class C { @external @pure f(s: string, t: string): bytes32 { let x: Arr<string,2> = [s,t]; return keccak256(abi.encode(x)); } }`,
      `contract C { function f(string calldata s, string calldata t) external pure returns (bytes32) { string[2] memory x=[s,t]; return keccak256(abi.encode(x));} }`,
    );
    for (const [a, b] of STR_SETS) await cmp(hk, 'f(string,string)', twoStr(a, b));

    const hm = await pair(
      `@contract class C { @external @pure f(n: u256, s: string, t: string, m: u256): bytes { let x: Arr<string,2> = [s,t]; return abi.encode(n, x, m); } }`,
      `contract C { function f(uint256 n, string calldata s, string calldata t, uint256 m) external pure returns (bytes memory) { string[2] memory x=[s,t]; return abi.encode(n, x, m);} }`,
    );
    // head: n, off(x)=0x80, m; then the string[2] tail at 0x80.
    const b0 = strBlob('aa');
    const args = W(7n) + W(0x80) + W(99n) + W(0x80) + W(0x80 + 0x40 + b0.length / 2) + b0 + strBlob('bbb');
    await cmp(hm, 'f(uint256,string,string,uint256)', args);
  });

  it('abi.encodeWithSelector / encodeWithSignature of Arr<string,2> byte-identical', async () => {
    const hs = await pair(
      `@contract class C { @external @pure f(sel: bytes4, s: string, t: string): bytes { let x: Arr<string,2> = [s,t]; return abi.encodeWithSelector(sel, x); } }`,
      `contract C { function f(bytes4 sel, string calldata s, string calldata t) external pure returns (bytes memory) { string[2] memory x=[s,t]; return abi.encodeWithSelector(sel, x);} }`,
    );
    const b0 = strBlob('ab');
    const args = '12345678'.padEnd(64, '0') + W(0x60) + W(0x60 + 0x40 + b0.length / 2) + b0 + strBlob('cd');
    await cmp(hs, 'f(bytes4,string,string)', args);
  });
});

describe('P0-34/P0-38: custom @error with a fixed-outer dynamic-element array parameter (full revert data)', () => {
  it('memory-local source: FULL recursive revert data (not the 36-byte pointer-word miscompile)', async () => {
    const h = await pair(
      `@contract class C { @error Er(xs: Arr<string,2>); @external @pure f(s: string, t: string): void { let x: Arr<string,2> = [s,t]; revert(Er(x)); } }`,
      `contract C { error Er(string[2] xs); function f(string calldata s, string calldata t) external pure { string[2] memory x=[s,t]; revert Er(x);} }`,
    );
    for (const [a, b] of STR_SETS) {
      const { j } = await cmp(h, 'f(string,string)', twoStr(a, b));
      expect(j.success).toBe(false);
      // guard against the old miscompile: revert data must be far longer than 36 bytes.
      expect(j.returnHex.length).toBeGreaterThan(2 + 36 * 2);
    }
  });

  it('calldata-param source and inline-literal source byte-identical', async () => {
    const hc = await pair(
      `@contract class C { @error Er(xs: Arr<string,2>); @external @pure f(xs: Arr<string,2>): void { revert(Er(xs)); } }`,
      `contract C { error Er(string[2] xs); function f(string[2] calldata xs) external pure { revert Er(xs);} }`,
    );
    for (const [a, b] of STR_SETS) await cmp(hc, 'f(string[2])', W(0x20) + twoStr(a, b));

    const hi = await pair(
      `@contract class C { @error Er(xs: Arr<string,2>); @external @pure f(s: string, t: string): void { revert(Er([s,t])); } }`,
      `contract C { error Er(string[2] xs); function f(string calldata s, string calldata t) external pure { revert Er([s,t]);} }`,
    );
    await cmp(hi, 'f(string,string)', twoStr('hi', 'world'));
  });

  it('Arr<bytes,2> and Arr<u256[],2> error parameters byte-identical', async () => {
    const hb = await pair(
      `@contract class C { @error Er(xs: Arr<bytes,2>); @external @pure f(s: bytes, t: bytes): void { let x: Arr<bytes,2> = [s,t]; revert(Er(x)); } }`,
      `contract C { error Er(bytes[2] xs); function f(bytes calldata s, bytes calldata t) external pure { bytes[2] memory x=[s,t]; revert Er(x);} }`,
    );
    for (const [a, b] of STR_SETS) await cmp(hb, 'f(bytes,bytes)', twoStr(a, b));

    const hu = await pair(
      `@contract class C { @error Er(xs: Arr<u256[],2>); @external @pure f(a: u256[], b: u256[]): void { let p: u256[] = a; let q: u256[] = b; let x: Arr<u256[],2> = [p,q]; revert(Er(x)); } }`,
      `contract C { error Er(uint256[][2] xs); function f(uint256[] calldata a, uint256[] calldata b) external pure { uint256[] memory p=a; uint256[] memory q=b; uint256[][2] memory x=[p,q]; revert Er(x);} }`,
    );
    for (const [a, b] of [[[1n, 2n], [3n]], [[], []]] as [bigint[], bigint[]][])
      await cmp(hu, 'f(uint256[],uint256[])', twoUintArr(a, b));
  });
});

describe('P1-7: internal-fn parameter/return and abi.decode of a fixed-outer dynamic-element array', () => {
  it('internal g(Arr<string,2>): element read / .length / literal arg byte-identical', async () => {
    const he = await pair(
      `@contract class C { g(xs: Arr<string,2>): string { return xs[0n]; } @external @pure f(s: string, t: string): string { let x: Arr<string,2> = [s,t]; return this.g(x); } }`,
      `contract C { function g(string[2] memory xs) internal pure returns (string memory) { return xs[0]; } function f(string calldata s, string calldata t) external pure returns (string memory) { string[2] memory x=[s,t]; return g(x);} }`,
    );
    for (const [a, b] of STR_SETS) await cmp(he, 'f(string,string)', twoStr(a, b));

    const hl = await pair(
      `@contract class C { g(xs: Arr<string,2>): u256 { return xs.length; } @external @pure f(s: string, t: string): u256 { let x: Arr<string,2> = [s,t]; return this.g(x); } }`,
      `contract C { function g(string[2] memory xs) internal pure returns (uint256) { return xs.length; } function f(string calldata s, string calldata t) external pure returns (uint256) { string[2] memory x=[s,t]; return g(x);} }`,
    );
    await cmp(hl, 'f(string,string)', twoStr('aa', 'bbbb'));

    const hlit = await pair(
      `@contract class C { g(xs: Arr<string,2>): string { return xs[1n]; } @external @pure f(s: string, t: string): string { return this.g([s,t]); } }`,
      `contract C { function g(string[2] memory xs) internal pure returns (string memory) { return xs[1]; } function f(string calldata s, string calldata t) external pure returns (string memory) { return g([s,t]);} }`,
    );
    await cmp(hlit, 'f(string,string)', twoStr('aa', 'bbbbbb'));
  });

  it('internal g returning Arr<string,2>: bind the result + read / direct return byte-identical', async () => {
    const hb = await pair(
      `@contract class C { g(xs: Arr<string,2>): Arr<string,2> { return xs; } @external @pure f(s: string, t: string): string { let x: Arr<string,2> = [s,t]; let y: Arr<string,2> = this.g(x); return y[1n]; } }`,
      `contract C { function g(string[2] memory xs) internal pure returns (string[2] memory) { return xs; } function f(string calldata s, string calldata t) external pure returns (string memory) { string[2] memory x=[s,t]; string[2] memory y=g(x); return y[1];} }`,
    );
    for (const [a, b] of STR_SETS) await cmp(hb, 'f(string,string)', twoStr(a, b));

    const hd = await pair(
      `@contract class C { g(xs: Arr<string,2>): Arr<string,2> { return xs; } @external @pure f(s: string, t: string): Arr<string,2> { let x: Arr<string,2> = [s,t]; return this.g(x); } }`,
      `contract C { function g(string[2] memory xs) internal pure returns (string[2] memory) { return xs; } function f(string calldata s, string calldata t) external pure returns (string[2] memory) { string[2] memory x=[s,t]; return g(x);} }`,
    );
    for (const [a, b] of STR_SETS) await cmp(hd, 'f(string,string)', twoStr(a, b));
  });

  it('internal g(Arr<u256[],2>): re-encode inside callee byte-identical', async () => {
    const h = await pair(
      `@contract class C { g(xs: Arr<u256[],2>): bytes { return abi.encode(xs); } @external @pure f(a: u256[], b: u256[]): bytes { let p: u256[] = a; let q: u256[] = b; let x: Arr<u256[],2> = [p,q]; return this.g(x); } }`,
      `contract C { function g(uint256[][2] memory xs) internal pure returns (bytes memory) { return abi.encode(xs); } function f(uint256[] calldata a, uint256[] calldata b) external pure returns (bytes memory) { uint256[] memory p=a; uint256[] memory q=b; uint256[][2] memory x=[p,q]; return g(x);} }`,
    );
    for (const [a, b] of [[[1n, 2n, 3n], [9n]], [[], []]] as [bigint[], bigint[]][])
      await cmp(h, 'f(uint256[],uint256[])', twoUintArr(a, b));
  });

  it('abi.decode(b, Arr<string,2>) element read + roundtrip re-encode byte-identical', async () => {
    const wrap = (hex: string) => W(0x20) + W(hex.length / 2) + hex.padEnd(Math.ceil(hex.length / 64) * 64, '0');
    const payload = (a: string, b: string) => {
      const b0 = strBlob(a);
      return W(0x40) + W(0x40 + b0.length / 2) + b0 + strBlob(b);
    };
    const h0 = await pair(
      `@contract class C { @external @pure f(b: bytes): string { let x: Arr<string,2> = abi.decode(b, Arr<string,2>); return x[0n]; } }`,
      `contract C { function f(bytes calldata b) external pure returns (string memory) { string[2] memory x=abi.decode(b,(string[2])); return x[0]; } }`,
    );
    for (const [a, b] of STR_SETS) await cmp(h0, 'f(bytes)', wrap(payload(a, b)));

    const hr = await pair(
      `@contract class C { @external @pure f(b: bytes): bytes { let x: Arr<string,2> = abi.decode(b, Arr<string,2>); return abi.encode(x); } }`,
      `contract C { function f(bytes calldata b) external pure returns (bytes memory) { string[2] memory x=abi.decode(b,(string[2])); return abi.encode(x); } }`,
    );
    await cmp(hr, 'f(bytes)', wrap(payload('hi', 'there')));
  });

  it('malformed abi.decode(b, Arr<string,2>) reverts identically to solc', async () => {
    const wrap = (hex: string) => W(0x20) + W(hex.length / 2) + hex.padEnd(Math.ceil((hex.length || 1) / 64) * 64, '0');
    const h = await pair(
      `@contract class C { @external @pure f(b: bytes): string { let x: Arr<string,2> = abi.decode(b, Arr<string,2>); return x[0n]; } }`,
      `contract C { function f(bytes calldata b) external pure returns (string memory) { string[2] memory x=abi.decode(b,(string[2])); return x[0]; } }`,
    );
    const bads = [
      '',
      W(0x40) + W(0x1000) + W(2) + '6162'.padEnd(64, '0'),
      W(0x40) + W(0x80) + W(BigInt('0xffffffffffffffffffff')),
      W(0x40),
    ];
    for (const p of bads) await cmp(h, 'f(bytes)', wrap(p));
  });
});

describe('adjacency: shapes solc rejects (or JETH cannot lift safely) still reject', () => {
  const rejects = (src: string) => {
    let ok = true;
    try {
      compile(src, { fileName: 'C.jeth' });
    } catch {
      ok = false;
    }
    return !ok;
  };
  it('abi.encodePacked(Arr<string,2>) rejects (solc rejects nested arrays in packed)', () => {
    expect(
      rejects(
        `@contract class C { @external @pure f(s: string): bytes { let x: Arr<string,2> = [s,s]; return abi.encodePacked(x); } }`,
      ),
    ).toBe(true);
  });
  it('a funcref-bearing fixed array is never ABI-encodable', () => {
    expect(
      rejects(
        `@contract class C { @external @pure f(): bytes { let x: Arr<((x:u256)=>u256)[],2> = [new Array<(x:u256)=>u256>(0n), new Array<(x:u256)=>u256>(0n)]; return abi.encode(x); } }`,
      ),
    ).toBe(true);
  });
  it('a dynamic-field-STRUCT fixed array (Arr<D,2>) is still rejected (unsupported dyn-struct-element codec)', () => {
    expect(
      rejects(
        `@struct class D { a: u256; s: string; } @contract class C { @external @pure f(): bytes { let d: D = D(1n, "x"); let x: Arr<D,2> = [d,d]; return abi.encode(x); } }`,
      ),
    ).toBe(true);
  });
});
