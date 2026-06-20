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

function jethAccepts(src: string): boolean {
  try { compile(src, { fileName: 'C.jeth' }); return true; } catch { return false; }
}
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

describe('sweep @constant folder enhancements', () => {
  // Each must produce a byte-identical runtime value to solc (read the constant back through a getter).
  it('references, type(T).max/min, ~, bool exprs, ternary', async () => {
    await rt(
      `@contract class C {
        @constant A: u256 = 10n;
        @constant B: u256 = A * 2n;
        @constant M: u256 = type(u256).max;
        @constant H: u8 = type(u8).max;
        @constant N: i8 = type(i8).min;
        @constant MASK: u8 = ~0n;
        @constant FLAG: bool = 5n > 3n;
        @constant FLAG2: bool = A == 10n;
        @constant T: u256 = FLAG ? 100n : 200n;
        @external @pure b(): u256 { return this.B; }
        @external @pure m(): u256 { return this.M; }
        @external @pure h(): u8 { return this.H; }
        @external @pure n(): i8 { return this.N; }
        @external @pure mask(): u8 { return this.MASK; }
        @external @pure flag(): bool { return this.FLAG; }
        @external @pure flag2(): bool { return this.FLAG2; }
        @external @pure t(): u256 { return this.T; }
      }`,
      `contract C {
        uint256 constant A = 10;
        uint256 constant B = A * 2;
        uint256 constant M = type(uint256).max;
        uint8 constant H = type(uint8).max;
        int8 constant N = type(int8).min;
        uint8 constant MASK = ~uint8(0);
        bool constant FLAG = 5 > 3;
        bool constant FLAG2 = A == 10;
        uint256 constant T = FLAG ? 100 : 200;
        function b() external pure returns(uint256){ return B; }
        function m() external pure returns(uint256){ return M; }
        function h() external pure returns(uint8){ return H; }
        function n() external pure returns(int8){ return N; }
        function mask() external pure returns(uint8){ return MASK; }
        function flag() external pure returns(bool){ return FLAG; }
        function flag2() external pure returns(bool){ return FLAG2; }
        function t() external pure returns(uint256){ return T; }
      }`,
      [{ sig: 'b()' }, { sig: 'm()' }, { sig: 'h()' }, { sig: 'n()' }, { sig: 'mask()' }, { sig: 'flag()' }, { sig: 'flag2()' }, { sig: 't()' }],
    );
  });
});

describe('sweep cast fixes', () => {
  it('bytesN(<int literal>) left-aligns into the high N bytes', async () => {
    await rt(
      `@contract class C { @external @pure a(): bytes4 { return bytes4(0x12345678n); } @external @pure b(): bytes1 { return bytes1(0xabn); } }`,
      `contract C { function a() external pure returns(bytes4){ return bytes4(0x12345678); } function b() external pure returns(bytes1){ return bytes1(0xab); } }`,
      [{ sig: 'a()' }, { sig: 'b()' }],
    );
  });
});

describe('sweep batch D (moderate over-rejections)', () => {
  it('@modifier on a multi-value-return function', async () => {
    await rt(
      `@contract class C { @modifier m() { _; } @external @m @pure f(): [u256, u256] { return [1n, 2n]; } }`,
      `contract C { modifier m() { _; } function f() external pure m returns (uint256,uint256) { return (1,2); } }`,
      [{ sig: 'f()' }],
    );
  });

  it('bytes<->string reinterpret and bytesN(bytes)', async () => {
    await rt(
      `@contract class C { @external @pure k(s: string): bytes32 { return keccak256(bytes(s)); } @external @pure e(b: bytes): string { return string(b); } @external @pure n4(b: bytes): bytes4 { return bytes4(b); } @external @pure n32(b: bytes): bytes32 { return bytes32(b); } }`,
      `contract C { function k(string calldata s) external pure returns(bytes32){ return keccak256(bytes(s)); } function e(bytes calldata b) external pure returns(string memory){ return string(b); } function n4(bytes calldata b) external pure returns(bytes4){ return bytes4(b); } function n32(bytes calldata b) external pure returns(bytes32){ return bytes32(b); } }`,
      [
        { sig: 'k(string)', args: W(0x20n) + W(3n) + '616263'.padEnd(64, '0') },
        { sig: 'e(bytes)', args: W(0x20n) + W(5n) + '68656c6c6f'.padEnd(64, '0') },
        { sig: 'n4(bytes)', args: W(0x20n) + W(8n) + '1122334455667788'.padEnd(64, '0') },
        { sig: 'n4(bytes)', args: W(0x20n) + W(2n) + 'aabb'.padEnd(64, '0') },
        { sig: 'n4(bytes)', args: W(0x20n) + W(0n) },
        { sig: 'n32(bytes)', args: W(0x20n) + W(4n) + 'deadbeef'.padEnd(64, '0') },
      ],
    );
  });
});

describe('sweep @immutable inline initialization', () => {
  it('inline init (no ctor, with ctor, and an expression) byte-identical', async () => {
    await rt(
      `@contract class C { @immutable a: u256 = 5n; @immutable b: address = msg.sender; @external @view ga(): u256 { return this.a; } @external @view gb(): address { return this.b; } }`,
      `contract C { uint256 immutable a = 5; address immutable b = msg.sender; function ga() external view returns(uint256){ return a; } function gb() external view returns(address){ return b; } }`,
      [{ sig: 'ga()' }, { sig: 'gb()' }],
    );
    await rt(
      `@contract class C { @constant K: u256 = 3n; @immutable a: u256 = this.K * 7n; @external @view ga(): u256 { return this.a; } }`,
      `contract C { uint256 constant K = 3; uint256 immutable a = K * 7; function ga() external view returns(uint256){ return a; } }`,
      [{ sig: 'ga()' }],
    );
  });
});
