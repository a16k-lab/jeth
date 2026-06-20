// Differential tests for a DYNAMIC-field struct (bytes/string field) assigned from a memory local
// or calldata param into storage (Phase 6). Byte-identical to solc incl. raw slots, packing, and
// overwrite (old-tail clearing).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

function jOk(src: string): boolean { try { compile(src, { fileName: 'C.jeth' }); return true; } catch { return false; } }

async function diff(jeth: string, sol: string, calls: { sig: string; args?: string }[], slots: bigint[] = []) {
  const jb = compile(jeth, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jb.creationBytecode);
  const as = await hs.deploy(sb.creation);
  for (const c of calls) {
    const data = '0x' + sel(c.sig) + (c.args ?? '');
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig}: returndata`).toBe(rs.returnHex);
  }
  for (const s of slots) expect(await readSlot(hj, aj, s), `slot ${s}`).toBe(await readSlot(hs, as, s));
}

describe('dynamic-field struct -> storage assignment vs Solidity', () => {
  it('memory local (u256 + string) -> storage (raw slots)', async () => {
    await diff(
      `@struct class D { a: u256; s: string; } @contract class C { @state d: D; @external set(a: u256, s: string): void { let m: D = D(a, s); this.d = m; } @external @view geta(): u256 { return this.d.a; } @external @view gets(): string { return this.d.s; } }`,
      `struct D { uint256 a; string s; } contract C { D d; function set(uint256 a, string calldata s) external { D memory m = D(a,s); d = m; } function geta() external view returns (uint256){ return d.a; } function gets() external view returns (string memory){ return d.s; } }`,
      [{ sig: 'set(uint256,string)', args: W(42n) + W(0x40n) + W(5n) + '68656c6c6f'.padEnd(64, '0') }, { sig: 'geta()' }, { sig: 'gets()' }],
      [0n, 1n, 2n],
    );
  });

  it('calldata struct param -> storage', async () => {
    await diff(
      `@struct class D { a: u256; s: string; } @contract class C { @state d: D; @external set(p: D): void { this.d = p; } @external @view geta(): u256 { return this.d.a; } @external @view gets(): string { return this.d.s; } }`,
      `struct D { uint256 a; string s; } contract C { D d; function set(D calldata p) external { d = p; } function geta() external view returns (uint256){ return d.a; } function gets() external view returns (string memory){ return d.s; } }`,
      [{ sig: 'set((uint256,string))', args: W(0x20n) + W(99n) + W(0x40n) + W(4n) + '61626364'.padEnd(64, '0') }, { sig: 'geta()' }, { sig: 'gets()' }],
      [0n, 1n],
    );
  });

  it('overwrite long->short string (old tail cleared) + packed value fields', async () => {
    await diff(
      `@struct class D { a: u8; b: u16; bs: bytes; } @contract class C { @state d: D; @external set(a: u8, b: u16, bs: bytes): void { let m: D = D(a, b, bs); this.d = m; } @external @view geta(): u8 { return this.d.a; } @external @view getbs(): bytes { return this.d.bs; } }`,
      `struct D { uint8 a; uint16 b; bytes bs; } contract C { D d; function set(uint8 a, uint16 b, bytes calldata bs) external { D memory m = D(a,b,bs); d = m; } function geta() external view returns (uint8){ return d.a; } function getbs() external view returns (bytes memory){ return d.bs; } }`,
      [
        { sig: 'set(uint8,uint16,bytes)', args: W(200n) + W(5000n) + W(0x60n) + W(40n) + 'ab'.repeat(40).padEnd(128, '0') },
        { sig: 'set(uint8,uint16,bytes)', args: W(7n) + W(9n) + W(0x60n) + W(3n) + 'aabbcc'.padEnd(64, '0') },
        { sig: 'geta()' },
        { sig: 'getbs()' },
      ],
      [0n],
    );
  });

  it('a struct with a dynamic value-array field, from a memory source (overwrite + mixed fields)', async () => {
    await diff(
      `@struct class D { a: u8; s: string; xs: u256[]; } @contract class C { @state d: D; @external set(a: u8, s: string, p: u256[]): void { let m: D = D(a, s, p); this.d = m; } @external @view geta(): u8 { return this.d.a; } @external @view gets(): string { return this.d.s; } @external @view len(): u256 { return this.d.xs.length; } @external @view get(i: u256): u256 { return this.d.xs[i]; } }`,
      `struct D { uint8 a; string s; uint256[] xs; } contract C { D d; function set(uint8 a, string calldata s, uint256[] calldata p) external { D memory m = D(a, s, p); d = m; } function geta() external view returns (uint8){ return d.a; } function gets() external view returns (string memory){ return d.s; } function len() external view returns (uint256){ return d.xs.length; } function get(uint256 i) external view returns (uint256){ return d.xs[i]; } }`,
      [
        { sig: 'set(uint8,string,uint256[])', args: W(200n) + W(0x60n) + W(0xa0n) + W(3n) + '616263'.padEnd(64, '0') + W(4n) + W(1n) + W(2n) + W(3n) + W(4n) },
        { sig: 'set(uint8,string,uint256[])', args: W(7n) + W(0x60n) + W(0xa0n) + W(2n) + '7a7a'.padEnd(64, '0') + W(2n) + W(99n) + W(88n) },
        { sig: 'geta()' },
        { sig: 'gets()' },
        { sig: 'len()' },
        { sig: 'get(uint256)', args: W(0n) },
      ],
    );
  });
});
