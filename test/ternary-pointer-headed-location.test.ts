// Round-2/3 of the pointer-headed coverage proof: the TERNARY channel (3 root causes).
// RC-1: an abi.decode-sourced branch (literal abi.decode(b,T) or an external self-call result)
//   materializes the POINTER-HEADED image while the flat ternary consumers assumed inline words -
//   pointer words leaked into abi.encode / return / topics / event data / error payloads (MC-2..6).
//   Fixed: 'abiDecode' added to the analyzer's ptrHeaded ternary gate (the third mirror of the
//   pointer-headed kind list) - now a clean JETH074 reject.
// RC-2: an ACCEPTED all-flat ternary (storage/storage or literal/storage branches) passed its FLAT
//   image as an internal-call arg while the callee binds Arr<In,N> params POINTER-HEADED - the callee
//   misread element words as pointers and returned garbage/zero (MC-1a/1b). Fixed: aggArgToMemPtr
//   gained a ternary case that transcodes flat -> pointer-headed via abiDecFromMemToImage.
// RC-3: solc's uniform ternary DATA-LOCATION rule (a calldata branch cannot unify with a storage
//   branch) was not enforced - JETH accepted + ran the mix for EVERY reference family (OA-1, an
//   over-acceptance). Fixed: a general cd|storage location gate after unification (JETH074).
//   cd|cd and cd|memory stay accepted (solc accepts both).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};
const In = `@struct class In { x: u256; y: u256 }`;
const SIn = `struct In { uint256 x; uint256 y; }`;

describe('ternary over pointer-headed Arr<In,N>: internal-arg transcode (RC-2) byte-identical', () => {
  it('storage/storage and literal/storage ternary internal-call args + return controls match solc', async () => {
    const J = `${In} @contract class C {
  @state sx: Arr<In,2>; @state sy: Arr<In,2>;
  @external seed(): void { this.sx[0n]=In(11n,12n); this.sx[1n]=In(13n,14n); this.sy[0n]=In(21n,22n); this.sy[1n]=In(23n,24n); }
  @pure sum(a: Arr<In,2>): u256 { return a[0n].x + a[1n].y; }
  @external @view arg(c: bool): u256 { return this.sum(c ? this.sx : this.sy); }
  @external @view argL(c: bool): u256 { return this.sum(c ? [In(41n,42n),In(43n,44n)] : this.sx); }
  @external @view ret(c: bool): Arr<In,2> { return c ? this.sx : this.sy; }
  @external @view retL(c: bool): Arr<In,2> { return c ? [In(41n,42n),In(43n,44n)] : this.sx; } }`;
    const S = `${SIn} contract C {
  In[2] sx; In[2] sy;
  function seed() external { sx[0]=In(11,12); sx[1]=In(13,14); sy[0]=In(21,22); sy[1]=In(23,24); }
  function sum(In[2] memory a) internal pure returns(uint256){ return a[0].x + a[1].y; }
  function arg(bool c) external view returns(uint256){ return sum(c ? sx : sy); }
  function argL(bool c) external view returns(uint256){ In[2] memory L = [In(41,42),In(43,44)]; return sum(c ? L : sx); }
  function ret(bool c) external view returns(In[2] memory){ return c ? sx : sy; }
  function retL(bool c) external view returns(In[2] memory){ In[2] memory L = [In(41,42),In(43,44)]; return c ? L : sx; } }`;
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    for (const [sg, args] of [
      ['seed()', ''], ['arg(bool)', W(1)], ['arg(bool)', W(0)], ['argL(bool)', W(1)], ['argL(bool)', W(0)],
      ['ret(bool)', W(1)], ['ret(bool)', W(0)], ['retL(bool)', W(1)], ['retL(bool)', W(0)],
    ] as const) {
      const jr = await h.call(ja, sel(sg) + args);
      const sr = await h.call(sa, sel(sg) + args);
      expect(jr.returnHex, `${sg} ${args.slice(0, 10)}`).toBe(sr.returnHex);
      expect(jr.success, sg).toBe(sr.success);
    }
    // non-vacuity anchor: arg(true) = sx[0].x + sx[1].y = 11 + 14 = 25.
    expect(BigInt((await h.call(ja, sel('arg(bool)') + W(1))).returnHex)).toBe(25n);
  });

  it('cd|cd ternary stays accepted and byte-identical (clean + dirty calldata)', async () => {
    const J = `@struct class Pk { a: u8; b: u256 }
@contract class C { @external @pure f(c: bool, p: Arr<Pk,2>, q: Arr<Pk,2>): Arr<Pk,2> { return c ? p : q; } }`;
    const S = `struct Pk { uint8 a; uint256 b; }
contract C { function f(bool c, Pk[2] calldata p, Pk[2] calldata q) external pure returns(Pk[2] memory){ return c ? p : q; } }`;
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    const sg = 'f(bool,(uint8,uint256)[2],(uint8,uint256)[2])';
    const clean = (c: number) => W(c) + W(7) + W(100) + W(8) + W(200) + W(9) + W(300) + W(10) + W(400);
    const dirty = (c: number) =>
      W(c) + '00000000000000000000000000000000000000000000000000000000000001ff' + W(100) + W(8) + W(200) + W(9) + W(300) + W(10) + W(400);
    for (const args of [clean(1), clean(0), dirty(1), dirty(0)]) {
      const jr = await h.call(ja, sel(sg) + args);
      const sr = await h.call(sa, sel(sg) + args);
      expect(jr.returnHex).toBe(sr.returnHex);
      expect(jr.success).toBe(sr.success);
    }
  });
});

describe('ternary rejects: abiDecode branches (RC-1) and cd|storage location mixes (RC-3)', () => {
  const base = `${In} @contract class C { @state sx: Arr<In,2>;
  @external @pure produce(): Arr<In,2> { let a: Arr<In,2> = [In(31n,32n),In(33n,34n)]; return a; }`;

  it('an abi.decode / external-call-result ternary branch is a clean JETH074 reject (was MC-2..6)', () => {
    expect(codes(`${base} @external @view f(c: bool): bytes { return abi.encode(c ? this.produce() : this.sx); } }`)).toContain('JETH074');
    expect(codes(`${base} @external @view f(c: bool): Arr<In,2> { return c ? this.produce() : this.sx; } }`)).toContain('JETH074');
    expect(codes(`${base} @event E(@indexed v: Arr<In,2>, t: u256); @external f(c: bool): void { emit(E(c ? this.produce() : this.sx, 9n)); } }`)).toContain('JETH074');
    expect(codes(`${base} @external @view f(c: bool): Arr<In,2> { return c ? this.produce() : this.produce(); } }`)).toContain('JETH074');
    expect(codes(`${base} @external @pure g(b: bytes): Arr<In,2> { return abi.decode(b, Arr<In,2>); } @external @view f(c: bool, b: bytes): Arr<In,2> { return c ? abi.decode(b, Arr<In,2>) : this.sx; } }`)).toContain('JETH074');
  });

  it('a calldata|storage ternary mix rejects across every reference family (was OA-1)', () => {
    expect(codes(`${In} @contract class C { @state sx: Arr<In,2>; @external @view f(c: bool, p: Arr<In,2>): Arr<In,2> { return c ? p : this.sx; } }`)).toContain('JETH074');
    expect(codes(`@contract class C { @state sx: Arr<u256,2>; @external @view f(c: bool, p: Arr<u256,2>): Arr<u256,2> { return c ? p : this.sx; } }`)).toContain('JETH074');
    expect(codes(`${In} @contract class C { @state sx: In; @external @view f(c: bool, p: In): In { return c ? p : this.sx; } }`)).toContain('JETH074');
    expect(codes(`@contract class C { @state sb: bytes; @external @view f(c: bool, b: bytes): bytes { return c ? b : this.sb; } }`)).toContain('JETH074');
    expect(codes(`@struct class Q { a: u256; t: bytes } @contract class C { @state sq: Q; @external @view f(c: bool, p: Q): u256 { let v: Q = c ? p : this.sq; return v.a; } }`)).toContain('JETH074');
  });

  it('bytes memory|storage ternary stays accepted and byte-identical', async () => {
    const J = `@contract class C { @state sb: bytes;
  @external seed(): void { this.sb = bytes("stor"); }
  @external @view bmem(c: bool): bytes { let m: bytes = bytes("memv"); return c ? m : this.sb; } }`;
    const S = `contract C { bytes sb;
  function seed() external { sb = "stor"; }
  function bmem(bool c) external view returns(bytes memory){ bytes memory m = "memv"; return c ? m : sb; } }`;
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    for (const [sg, args] of [['seed()', ''], ['bmem(bool)', W(1)], ['bmem(bool)', W(0)]] as const) {
      const jr = await h.call(ja, sel(sg) + args);
      const sr = await h.call(sa, sel(sg) + args);
      expect(jr.returnHex, sg).toBe(sr.returnHex);
      expect(jr.success, sg).toBe(sr.success);
    }
  });
});
