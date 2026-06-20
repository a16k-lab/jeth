// Regression tests for the "fix all divergences" sweep (vs solc 0.8.35). Soundness fixes
// (miscompiles + over-acceptances) and over-rejection bug fixes, all verified byte-identical /
// accept-reject-parity to solc. Calldata uses pad32(n) (64 hex, no slice) so calls are non-vacuous.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

function jethRejects(src: string): boolean {
  try { compile(src, { fileName: 'C.jeth' }); return false; } catch { return true; }
}
function solcRejects(src: string): boolean {
  try { compileSolidity(SPDX + src, 'C'); return false; } catch { return true; }
}
async function rt(jeth: string, sol: string, calls: { sig: string; args?: string }[]) {
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
    expect(JSON.stringify(rj.logs), `${c.sig}: logs`).toBe(JSON.stringify(rs.logs));
  }
}

describe('sweep soundness fixes (miscompiles + over-acceptances)', () => {
  it('@anonymous event: no topic0, LOG(n) byte-identical', async () => {
    await rt(
      `@contract class C { @anonymous @event E(@indexed a: u256, b: u256); @external f(): void { emit(E(7n, 9n)); } }`,
      `contract C { event E(uint256 indexed a, uint256 b) anonymous; function f() external { emit E(7,9); } }`,
      [{ sig: 'f()' }],
    );
  });

  it('over-acceptances now rejected (match solc)', () => {
    // addmod/mulmod with a compile-time zero modulus
    expect(jethRejects(`@contract class C { @external @pure f(a: u256, b: u256): u256 { return addmod(a, b, 0n); } }`)).toBe(true);
    expect(jethRejects(`@contract class C { @external @pure f(a: u256, b: u256): u256 { return mulmod(a, b, 1n - 1n); } }`)).toBe(true);
    // @internal/@private @payable
    expect(jethRejects(`@contract class C { @internal @payable g(): void {} @external f(): void { this.g(); } }`)).toBe(true);
    // nested unchecked
    expect(jethRejects(`@contract class C { @external @pure f(): u256 { let x: u256 = 0n; unchecked: { unchecked: { x = x + 1n; } } return x; } }`)).toBe(true);
    // stray decorators on event / error param
    expect(jethRejects(`@contract class C { @view @event E(a: u256); @external f(): void { emit(E(1n)); } }`)).toBe(true);
    expect(jethRejects(`@contract class C { @error Bad(@indexed a: u256); @external f(): void { revert(Bad(1n)); } }`)).toBe(true);
  });

  it('non-zero runtime modulus still reverts Panic(0x12) byte-identical', async () => {
    await rt(
      `@contract class C { @external @pure f(a: u256, b: u256, m: u256): u256 { return addmod(a, b, m); } }`,
      `contract C { function f(uint256 a, uint256 b, uint256 m) external pure returns(uint256){ return addmod(a,b,m); } }`,
      [{ sig: 'f(uint256,uint256,uint256)', args: W(10n) + W(20n) + W(0n) }, { sig: 'f(uint256,uint256,uint256)', args: W(10n) + W(20n) + W(7n) }],
    );
  });
});

describe('sweep over-rejection fixes (cheap)', () => {
  it('tx.gasprice', async () => {
    await rt(
      `@contract class C { @external @view f(): u256 { return tx.gasprice; } }`,
      `contract C { function f() external view returns(uint256){ return tx.gasprice; } }`,
      [{ sig: 'f()' }],
    );
  });

  it('keccak256 / sha256 / ripemd160 of a string literal', async () => {
    await rt(
      `@contract class C { @external @pure k(): bytes32 { return keccak256("abc"); } @external @pure s(): bytes32 { return sha256("abc"); } @external @pure r(): bytes20 { return ripemd160("abc"); } }`,
      `contract C { function k() external pure returns(bytes32){ return keccak256("abc"); } function s() external pure returns(bytes32){ return sha256("abc"); } function r() external pure returns(bytes20){ return ripemd160("abc"); } }`,
      [{ sig: 'k()' }, { sig: 's()' }, { sig: 'r()' }],
    );
  });

  it('var-left literal widening (varN OP bigLit) computes at the common type', async () => {
    await rt(
      `@contract class C {
        @external @pure add(a: u8): u16 { return a + 1000n; }
        @external @pure cast(a: u8): u16 { return u16(a + 1000n); }
        @external @pure mul(a: u8): u16 { return a * 1000n; }
        @external @pure fits(a: u8): u8 { return a + 1n; }
      }`,
      `contract C {
        function add(uint8 a) external pure returns(uint16){ return a + 1000; }
        function cast(uint8 a) external pure returns(uint16){ return uint16(a + 1000); }
        function mul(uint8 a) external pure returns(uint16){ return a * 1000; }
        function fits(uint8 a) external pure returns(uint8){ return a + 1; }
      }`,
      [
        { sig: 'add(uint8)', args: W(255n) },
        { sig: 'cast(uint8)', args: W(200n) },
        { sig: 'mul(uint8)', args: W(255n) }, // overflow Panic at u16
        { sig: 'mul(uint8)', args: W(1n) },
        { sig: 'fits(uint8)', args: W(200n) }, // 201, ok at u8
        { sig: 'fits(uint8)', args: W(255n) }, // overflow Panic at u8
      ],
    );
  });
});
