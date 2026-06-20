// Differential tests for string[]/bytes[] element access (read + write) where the array is reached
// via a placeArray base: a struct field (this.d.xs[i]), a nested array (this.dd[i][j]), or deeper
// (this.o.inner.xs[i]). Previously over-rejected (JETH151/JETH217); now byte-identical to solc.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

async function diff(jeth: string, sol: string, calls: { sig: string; args?: string }[]) {
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
}

describe('string[]/bytes[] element via a placeArray base vs Solidity', () => {
  it('struct string[] field: push, element read, element write', async () => {
    await diff(
      `@struct class D { xs: string[]; } @contract class C { @state d: D; @external add(s: string): void { this.d.xs.push(s); } @external set(i: u256, s: string): void { this.d.xs[i] = s; } @external @view get(i: u256): string { return this.d.xs[i]; } @external @view len(): u256 { return this.d.xs.length; } }`,
      `struct D { string[] xs; } contract C { D d; function add(string calldata s) external { d.xs.push(s); } function set(uint256 i, string calldata s) external { d.xs[i] = s; } function get(uint256 i) external view returns (string memory){ return d.xs[i]; } function len() external view returns (uint256){ return d.xs.length; } }`,
      [
        { sig: 'add(string)', args: W(0x20n) + W(3n) + '616263'.padEnd(64, '0') },
        { sig: 'add(string)', args: W(0x20n) + W(2n) + '7a7a'.padEnd(64, '0') },
        { sig: 'len()' },
        { sig: 'get(uint256)', args: W(0n) },
        { sig: 'set(uint256,string)', args: W(0n) + W(0x40n) + W(5n) + '68656c6c6f'.padEnd(64, '0') },
        { sig: 'get(uint256)', args: W(0n) },
        { sig: 'get(uint256)', args: W(1n) },
      ],
    );
  });

  it('bytes[] struct field element read, and a deeper nested struct field', async () => {
    await diff(
      `@struct class D { bs: bytes[]; } @contract class C { @state d: D; @external add(b: bytes): void { this.d.bs.push(b); } @external @view get(i: u256): bytes { return this.d.bs[i]; } }`,
      `struct D { bytes[] bs; } contract C { D d; function add(bytes calldata b) external { d.bs.push(b); } function get(uint256 i) external view returns (bytes memory){ return d.bs[i]; } }`,
      [{ sig: 'add(bytes)', args: W(0x20n) + W(3n) + 'aabbcc'.padEnd(64, '0') }, { sig: 'get(uint256)', args: W(0n) }],
    );
    await diff(
      `@struct class I { xs: string[]; } @struct class O { inner: I; n: u256; } @contract class C { @state o: O; @external add(s: string): void { this.o.inner.xs.push(s); } @external @view get(i: u256): string { return this.o.inner.xs[i]; } }`,
      `struct I { string[] xs; } struct O { I inner; uint256 n; } contract C { O o; function add(string calldata s) external { o.inner.xs.push(s); } function get(uint256 i) external view returns (string memory){ return o.inner.xs[i]; } }`,
      [{ sig: 'add(string)', args: W(0x20n) + W(3n) + '616263'.padEnd(64, '0') }, { sig: 'get(uint256)', args: W(0n) }],
    );
  });

  it('nested string[][] element read + write (this.dd[i][j])', async () => {
    // populate via a pushed empty row + inner pushes (pushing a whole calldata string[] to
    // string[][] is unimplemented in solc's old codegen too, so that route is parity-rejected).
    await diff(
      `@contract class C { @state dd: string[][]; @external newrow(): void { this.dd.push(); } @external add(i: u256, s: string): void { this.dd[i].push(s); } @external set(i: u256, j: u256, s: string): void { this.dd[i][j] = s; } @external @view get(i: u256, j: u256): string { return this.dd[i][j]; } }`,
      `contract C { string[][] dd; function newrow() external { dd.push(); } function add(uint256 i, string calldata s) external { dd[i].push(s); } function set(uint256 i, uint256 j, string calldata s) external { dd[i][j] = s; } function get(uint256 i, uint256 j) external view returns (string memory){ return dd[i][j]; } }`,
      [
        { sig: 'newrow()' },
        { sig: 'add(uint256,string)', args: W(0n) + W(0x40n) + W(1n) + '61'.padEnd(64, '0') },
        { sig: 'add(uint256,string)', args: W(0n) + W(0x40n) + W(1n) + '62'.padEnd(64, '0') },
        { sig: 'get(uint256,uint256)', args: W(0n) + W(1n) },
        { sig: 'set(uint256,uint256,string)', args: W(0n) + W(1n) + W(0x60n) + W(3n) + '7a7a7a'.padEnd(64, '0') },
        { sig: 'get(uint256,uint256)', args: W(0n) + W(1n) },
        { sig: 'get(uint256,uint256)', args: W(0n) + W(0n) },
      ],
    );
  });
});
