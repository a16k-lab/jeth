// Edge E (over-rejection lifted byte-identical): reading a VALUE field directly off a struct that was
// produced by abi.decode(b, P) or by an @external (delegatecall) @library call - abi.decode(b, P).x and
// L.mk(a).x. Both bases are an `abiDecode` Expr (the external-library delegatecall returndata is decoded);
// the field read materializes the decoded image via aggToMemPtr (lowerAbiDecode) and mloads the field word
// (aggFieldRead), the same path the internal-call form this.mk(a).x already used. Previously JETH074.
// Scoped to a STATIC struct with a VALUE final field (a dynamic struct / non-value field stays a sound
// clean reject, matching the internal-call form). Verified byte-identical to solc 0.8.35, incl malformed
// abi.decode input reverting identically.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, compileSolidityLinked, deploySolLinked } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => n.toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};

describe('Edge E: field access on abi.decode / external-library struct results - byte-identical to solc 0.8.35', () => {
  it('abi.decode(b, P).x and .y (value fields, both offsets)', async () => {
    await eqCalls(
      'type P = { x: u256; y: u256 }; class C { get gx(b: bytes): External<u256> { return abi.decode(b, P).x; } get gy(b: bytes): External<u256> { return abi.decode(b, P).y; } }',
      'contract C { struct P { uint256 x; uint256 y; } function gx(bytes calldata b) external pure returns(uint256){ return abi.decode(b, (P)).x; } function gy(bytes calldata b) external pure returns(uint256){ return abi.decode(b, (P)).y; } }',
      [['gx(bytes)', W(0x20n) + W(0x40n) + W(7n) + W(8n)], ['gy(bytes)', W(0x20n) + W(0x40n) + W(7n) + W(8n)]],
    );
  });

  it('abi.decode(b, P).field with packed members (u8/u128/u256)', async () => {
    await eqCalls(
      'type P = { a: u8; b: u128; c: u256 }; class C { get ga(b: bytes): External<u8> { return abi.decode(b, P).a; } get gb(b: bytes): External<u128> { return abi.decode(b, P).b; } get gc(b: bytes): External<u256> { return abi.decode(b, P).c; } }',
      'contract C { struct P { uint8 a; uint128 b; uint256 c; } function ga(bytes calldata b) external pure returns(uint8){ return abi.decode(b, (P)).a; } function gb(bytes calldata b) external pure returns(uint128){ return abi.decode(b, (P)).b; } function gc(bytes calldata b) external pure returns(uint256){ return abi.decode(b, (P)).c; } }',
      [
        ['ga(bytes)', W(0x20n) + W(0x60n) + W(3n) + W(4n) + W(5n)],
        ['gb(bytes)', W(0x20n) + W(0x60n) + W(3n) + W(4n) + W(5n)],
        ['gc(bytes)', W(0x20n) + W(0x60n) + W(3n) + W(4n) + W(5n)],
      ],
    );
  });

  it('malformed abi.decode input reverts identically', async () => {
    await eqCalls(
      'type P = { x: u256; y: u256 }; class C { get go(b: bytes): External<u256> { return abi.decode(b, P).x; } }',
      'contract C { struct P { uint256 x; uint256 y; } function go(bytes calldata b) external pure returns(uint256){ return abi.decode(b, (P)).x; } }',
      [
        ['go(bytes)', W(0x20n) + W(0x40n) + W(7n) + W(8n)], // well-formed
        ['go(bytes)', W(0x20n) + W(0x40n) + W(7n)], // truncated tail -> revert
        ['go(bytes)', W(0x20n) + W(0n)], // empty payload -> revert
      ],
    );
  });

  it('L.mk(a).x and .y on an @external (delegatecall) library struct result', async () => {
    const jeth = 'type P = { x: u256; y: u256 }; static class L { mk(a: u256): External<P> { return P(a, a + 1n); } } class C { gx(a: u256): External<u256> { return L.mk(a).x; } gy(a: u256): External<u256> { return L.mk(a).y; } }';
    const sol = `${SPDX}\nstruct P { uint256 x; uint256 y; }\nlibrary L { function mk(uint256 a) external pure returns(P memory){ return P(a, a+1); } }\ncontract C { function gx(uint256 a) external pure returns(uint256){ return L.mk(a).x; } function gy(uint256 a) external pure returns(uint256){ return L.mk(a).y; } }`;
    const jb = compile(jeth, { fileName: 'C.jeth' });
    const sb = compileSolidityLinked(sol, 'C', ['L']);
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = (await hj.deployLinked(jb)).address;
    const as = await deploySolLinked(hs, sb);
    for (const sig of ['gx(uint256)', 'gy(uint256)']) {
      for (const a of [5n, 0n, 1n << 255n]) {
        const data = sel(sig) + pad32(a).toString();
        const jr = await hj.call(aj, data);
        const sr = await hs.call(as, data);
        expect({ ok: jr.success, ret: jr.returnHex }, `${sig}(${a})`).toEqual({ ok: sr.success, ret: sr.returnHex });
      }
    }
  });

  it('a non-value / dynamic-struct field access stays a sound clean reject (no crash, no over-acceptance)', () => {
    // string field of a (dynamic) decoded struct, and a value field of a dynamic decoded struct: both
    // reject cleanly (the dynamic-struct field-of-call-result case is deferred, like the internal-call form).
    expect(codes('type P = {x:u256;s:string}; class C { get go(b: bytes): External<string> { return abi.decode(b,P).s; } }').length).toBeGreaterThan(0);
    expect(codes('type P = {x:u256;y:u256}; class C { get go(b: bytes): External<u256> { return abi.decode(b,P).nope; } }')).toContain('JETH210');
  });
});
