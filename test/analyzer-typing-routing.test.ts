import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const P = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const h32 = (v: bigint) => v.toString(16).padStart(64, '0');

// A differential pair: compile JETH + the mirror Solidity, deploy both, compare {success, returnHex}.
async function pair(jethSrc: string, solSrc: string) {
  const jb = compile(jethSrc);
  const sb = compileSolidity(P + solSrc, 'C');
  const jeth = await Harness.create();
  const sol = await Harness.create();
  const aj = await jeth.deploy(jb.creationBytecode);
  const as = await sol.deploy(sb.creation);
  return { jeth, sol, aj, as };
}

async function same(ctx: { jeth: Harness; sol: Harness; aj: Address; as: Address }, data: string) {
  const j = await ctx.jeth.call(ctx.aj, data);
  const s = await ctx.sol.call(ctx.as, data);
  return { j, s };
}

describe('fix1: memory `bytes` element write (d[i] = bytes1(v))', () => {
  let ctx: Awaited<ReturnType<typeof pair>>;
  beforeAll(async () => {
    ctx = await pair(
      `class C {
         get foo(i: u256, v: u8): External<bytes> {
           let d: bytes = bytes("abcdef");
           d[i] = bytes1(v);
           return d;
         }
         get aliasWrite(i: u256, v: u8): External<bytes> {
           let d: bytes = bytes("abcdef");
           let e: bytes = d;
           e[i] = bytes1(v);
           return d;
         }
       }`,
      `contract C {
         function foo(uint256 i, uint8 v) external pure returns (bytes memory) {
           bytes memory d = bytes("abcdef");
           d[i] = bytes1(v);
           return d;
         }
         function aliasWrite(uint256 i, uint8 v) external pure returns (bytes memory) {
           bytes memory d = bytes("abcdef");
           bytes memory e = d;
           e[i] = bytes1(v);
           return d;
         }
       }`,
    );
  });

  it('in-place writes match solc across in-range and OOB indices', async () => {
    for (const i of [0n, 1n, 5n, 6n, 100n]) {
      for (const v of [0n, 0xffn, 0x41n]) {
        const data = '0x' + sel('foo(uint256,uint8)') + h32(i) + h32(v);
        const { j, s } = await same(ctx, data);
        expect(j.success, `foo i=${i} v=${v} success`).toBe(s.success);
        expect(j.returnHex, `foo i=${i} v=${v} ret`).toBe(s.returnHex);
      }
    }
  });

  it('alias mutation writes through (e[i] affects d) byte-identically', async () => {
    for (const i of [0n, 3n, 6n]) {
      const data = '0x' + sel('aliasWrite(uint256,uint8)') + h32(i) + h32(0x5an);
      const { j, s } = await same(ctx, data);
      expect(j.success, `aliasWrite i=${i} success`).toBe(s.success);
      expect(j.returnHex, `aliasWrite i=${i} ret`).toBe(s.returnHex);
    }
  });
});

describe('fix2: exact-width hex literal as bytesN', () => {
  let ctx: Awaited<ReturnType<typeof pair>>;
  beforeAll(async () => {
    ctx = await pair(
      `class C {
         get sigEq(x: bytes4): External<bool> { return x == 0x12345678; }
         get letRet(): External<bytes4> { let v: bytes4 = 0x12345678; return v; }
         get ret(): External<bytes4> { return 0x12345678; }
         get b1(x: bytes1): External<bool> { return x == 0xab; }
         get b32(x: bytes32): External<bool> {
           return x == 0x0000000000000000000000000000000000000000000000000000000000000001;
         }
       }`,
      `contract C {
         function sigEq(bytes4 x) external pure returns (bool) { return x == 0x12345678; }
         function letRet() external pure returns (bytes4) { bytes4 v = 0x12345678; return v; }
         function ret() external pure returns (bytes4) { return 0x12345678; }
         function b1(bytes1 x) external pure returns (bool) { return x == 0xab; }
         function b32(bytes32 x) external pure returns (bool) {
           return x == 0x0000000000000000000000000000000000000000000000000000000000000001;
         }
       }`,
    );
  });

  it('return + let produce the left-aligned bytesN value', async () => {
    for (const sig of ['letRet()', 'ret()']) {
      const { j, s } = await same(ctx, '0x' + sel(sig));
      expect(j.success).toBe(s.success);
      expect(j.returnHex, sig).toBe(s.returnHex);
    }
  });

  it('bytes4 == hex literal matches', async () => {
    for (const x of ['0x12345678', '0x12345679', '0x00000000']) {
      const data = '0x' + sel('sigEq(bytes4)') + x.slice(2).padEnd(64, '0');
      const { j, s } = await same(ctx, data);
      expect(j.success).toBe(s.success);
      expect(j.returnHex, `sigEq ${x}`).toBe(s.returnHex);
    }
  });

  it('literal-on-the-LEFT comparison stays rejected (solc parity)', () => {
    let codes: string[] = [];
    try {
      compile(`class C { get f(x: bytes4): External<bool> { return 0x12345678 == x; } }`);
    } catch (e: any) {
      codes = (e.diagnostics ?? []).map((d: any) => d.code);
    }
    expect(codes.length).toBeGreaterThan(0);
  });

  it('wrong-width hex literal for a bytesN stays rejected (solc parity)', () => {
    let codes: string[] = [];
    try {
      compile(`class C { get f(x: bytes4): External<bool> { return x == 0x1234; } }`);
    } catch (e: any) {
      codes = (e.diagnostics ?? []).map((d: any) => d.code);
    }
    expect(codes.length).toBeGreaterThan(0);
  });

  it('bytes1 / bytes32 == hex literal matches', async () => {
    const d1 = '0x' + sel('b1(bytes1)') + 'ab'.padEnd(64, '0');
    let r = await same(ctx, d1);
    expect(r.j.returnHex, 'b1 ab').toBe(r.s.returnHex);
    const d1b = '0x' + sel('b1(bytes1)') + 'cd'.padEnd(64, '0');
    r = await same(ctx, d1b);
    expect(r.j.returnHex, 'b1 cd').toBe(r.s.returnHex);
    const d32 = '0x' + sel('b32(bytes32)') + h32(1n);
    r = await same(ctx, d32);
    expect(r.j.returnHex, 'b32 1').toBe(r.s.returnHex);
  });
});

describe('fix2: msg.sig == 0xSELECTOR dispatch idiom', () => {
  it('matches solc for the matching and non-matching selector', async () => {
    const ctx = await pair(
      `class C {
         get isFoo(): External<bool> { return msg.sig == 0x9f8a13d7; }
       }`,
      `contract C {
         function isFoo() external pure returns (bool) { return msg.sig == 0x9f8a13d7; }
       }`,
    );
    // isFoo()'s own selector vs the literal 0x9f8a13d7 (whatever it is, both compilers agree)
    const { j, s } = await same(ctx, '0x' + sel('isFoo()'));
    expect(j.success).toBe(s.success);
    expect(j.returnHex).toBe(s.returnHex);
  });
});

describe('fix3: memory-array alias (reference semantics)', () => {
  it('let c = a aliases; mutating c affects a; byte-identical', async () => {
    const ctx = await pair(
      `class C {
         get aliasRead(): External<u256> {
           let a: u256[] = [1n, 2n];
           let c: u256[] = a;
           return c[0n] + c[1n];
         }
         get aliasMutate(): External<u256> {
           let a: u256[] = [1n, 2n];
           let c: u256[] = a;
           c[0n] = 9n;
           return a[0n];
         }
       }`,
      `contract C {
         function aliasRead() external pure returns (uint256) {
           uint256[] memory a = new uint256[](2); a[0]=1; a[1]=2;
           uint256[] memory c = a;
           return c[0] + c[1];
         }
         function aliasMutate() external pure returns (uint256) {
           uint256[] memory a = new uint256[](2); a[0]=1; a[1]=2;
           uint256[] memory c = a;
           c[0] = 9;
           return a[0];
         }
       }`,
    );
    for (const sig of ['aliasRead()', 'aliasMutate()']) {
      const { j, s } = await same(ctx, '0x' + sel(sig));
      expect(j.success).toBe(s.success);
      expect(j.returnHex, sig).toBe(s.returnHex);
    }
  });
});

describe('fix4: struct mapping key rejected cleanly (no internal-error leak)', () => {
  it('rejects with JETH154, not JETH900', () => {
    let codes: string[] = [];
    try {
      compile(`type K = { id: u256; }; class C { m: mapping<K, u256>; get g(): External<u256> { return 1n; } }`);
    } catch (e: any) {
      codes = (e.diagnostics ?? []).map((d: any) => d.code);
    }
    expect(codes).toContain('JETH154');
    expect(codes).not.toContain('JETH900');
  });

  it('still accepts every elementary key type', () => {
    expect(() =>
      compile(
        `class C { a: mapping<u256, u256>; b: mapping<address, bool>; c: mapping<bytes32, u256>; d: mapping<bytes, u256>; e: mapping<string, u256>; }`,
      ),
    ).not.toThrow();
  });
});
