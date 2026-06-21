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
    // @internal/@payable
    expect(jethRejects(`@contract class C { @payable g(): void {} @external f(): void { this.g(); } }`)).toBe(true);
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

describe('sweep keccak256 in a @constant initializer', () => {
  it('folds keccak256 of a constant string / encodePacked / bytes() at compile time', async () => {
    await rt(
      `@contract class C { @constant H: bytes32 = keccak256("Permit(address owner,uint256 value)"); @constant D: bytes32 = keccak256(abi.encodePacked("EIP712Domain")); @constant B: bytes32 = keccak256(bytes("abc")); @external @pure h(): bytes32 { return this.H; } @external @pure d(): bytes32 { return this.D; } @external @pure b(): bytes32 { return this.B; } }`,
      `contract C { bytes32 constant H = keccak256("Permit(address owner,uint256 value)"); bytes32 constant D = keccak256(abi.encodePacked("EIP712Domain")); bytes32 constant B = keccak256(bytes("abc")); function h() external pure returns(bytes32){ return H; } function d() external pure returns(bytes32){ return D; } function b() external pure returns(bytes32){ return B; } }`,
      [{ sig: 'h()' }, { sig: 'd()' }, { sig: 'b()' }],
    );
  });
});

describe('constant arithmetic accept/reject parity vs solc (already solc-accurate)', () => {
  // solc folds pure constant subexpressions in arbitrary precision, then rejects div/mod-by-zero and
  // any result that does not fit the inferred/expected type. JETH must match (NOT over-accept).
  const reject: [string, string][] = [
    ['overflow vs return type', `@contract class C { @external @pure f(): u8 { return 255n + 1n; } }`],
    ['div by zero', `@contract class C { @external @pure f(): u8 { return 5n / 0n; } }`],
    ['mod by zero', `@contract class C { @external @pure f(): u8 { return 5n % 0n; } }`],
    ['exponent overflow', `@contract class C { @external @pure f(): u256 { return 2n ** 256n; } }`],
  ];
  for (const [name, src] of reject) {
    it(`rejects: ${name}`, () => expect(jethRejects(src)).toBe(true));
  }
  const accept: [string, string][] = [
    ['200n + 55n fits u8', `@contract class C { @external @pure f(): u8 { return 200n + 55n; } }`],
    ['2n ** 255n fits u256', `@contract class C { @external @pure f(): u256 { return 2n ** 255n; } }`],
  ];
  for (const [name, src] of accept) {
    it(`accepts: ${name}`, () => expect(jethAccepts(src)).toBe(true));
  }
});

describe('@payable on internal/private/hidden is rejected (solc parity)', () => {
  // solc: "internal" and "private" functions cannot be payable. is an explicitly-internal fn.
  const reject: [string, string][] = [
    ['@payable', `@contract class C { @payable v(): u256 { return msg.value; } @external @payable f(): u256 { return this.v(); } }`],
    ['@payable', `@contract class C { @payable v(): u256 { return 1n; } @external f(): void { this.v(); } }`],
    ['@payable', `@contract class C { @payable v(): u256 { return 1n; } @external f(): void { this.v(); } }`],
  ];
  for (const [name, src] of reject) {
    it(`rejects ${name}`, () => expect(jethRejects(src)).toBe(true));
  }
  // external/public payable must still be accepted.
  it('accepts @external/@external @payable', () => {
    expect(jethAccepts(`@contract class C { @external @payable f(): u256 { return msg.value; } }`)).toBe(true);
    expect(jethAccepts(`@contract class C { @external @payable f(): u256 { return msg.value; } }`)).toBe(true);
  });
});

describe('fixed-array field of a memory struct local (p.a[i]) read/write vs solc', () => {
  it('value, packed-element, and nested-struct fixed-array fields', async () => {
    await rt(
      `@struct class P { x: u256; a: Arr<u256,3>; y: u256; } @contract class C { @external @pure f(i: u256, v: u256): u256 { let p: P = P(7n, [10n, 20n, 30n], 9n); p.a[i] = v; return p.a[i] + p.x + p.y; } }`,
      `struct P { uint256 x; uint256[3] a; uint256 y; } contract C { function f(uint256 i, uint256 v) external pure returns(uint256){ P memory p = P(7, [uint256(10),20,30], 9); p.a[i] = v; return p.a[i] + p.x + p.y; } }`,
      [{ sig: 'f(uint256,uint256)', args: W(1n) + W(99n) }, { sig: 'f(uint256,uint256)', args: W(0n) + W(5n) }, { sig: 'f(uint256,uint256)', args: W(3n) + W(1n) }],
    );
    await rt(
      `@struct class P { a: Arr<u8,4>; n: u256; } @contract class C { @external @pure f(i: u256): u256 { let p: P = P([1n, 2n, 3n, 4n], 0n); p.a[i] = 200n; return u256(p.a[0n]) + u256(p.a[i]); } }`,
      `struct P { uint8[4] a; uint256 n; } contract C { function f(uint256 i) external pure returns(uint256){ P memory p = P([uint8(1),2,3,4], 0); p.a[i] = 200; return uint256(p.a[0]) + uint256(p.a[i]); } }`,
      [{ sig: 'f(uint256)', args: W(2n) }, { sig: 'f(uint256)', args: W(0n) }],
    );
    await rt(
      `@struct class I { a: Arr<u256,2>; } @struct class O { x: u256; inner: I; } @contract class C { @external @pure f(i: u256, v: u256): u256 { let o: O = O(5n, I([1n, 2n])); o.inner.a[i] = v; return o.inner.a[i] + o.x; } }`,
      `struct I { uint256[2] a; } struct O { uint256 x; I inner; } contract C { function f(uint256 i, uint256 v) external pure returns(uint256){ O memory o = O(5, I([uint256(1),2])); o.inner.a[i] = v; return o.inner.a[i] + o.x; } }`,
      [{ sig: 'f(uint256,uint256)', args: W(1n) + W(77n) }, { sig: 'f(uint256,uint256)', args: W(0n) + W(8n) }],
    );
  });
});

describe('whole storage fixed-array copy via element/mapping/struct-field vs solc', () => {
  it('dyn-array element, mapping value, nested element, and struct field', async () => {
    await rt(
      `@contract class C { @state a: Arr<u256,2>[]; @external seed(): void { this.a.push(); this.a.push(); this.a[0n][0n]=11n; this.a[0n][1n]=22n; this.a[1n][0n]=33n; } @external cp(): void { this.a[1n] = this.a[0n]; } @external @view g(i: u256, j: u256): u256 { return this.a[i][j]; } }`,
      `contract C { uint256[2][] a; function seed() external { a.push(); a.push(); a[0][0]=11; a[0][1]=22; a[1][0]=33; } function cp() external { a[1] = a[0]; } function g(uint256 i, uint256 j) external view returns(uint256){ return a[i][j]; } }`,
      [{ sig: 'seed()' }, { sig: 'cp()' }, { sig: 'g(uint256,uint256)', args: W(1n) + W(0n) }, { sig: 'g(uint256,uint256)', args: W(1n) + W(1n) }],
    );
    await rt(
      `@contract class C { @state m: mapping<u256,Arr<u256,2>>; @external seed(): void { this.m[0n][0n]=5n; this.m[0n][1n]=6n; } @external cp(): void { this.m[1n] = this.m[0n]; } @external @view g(k: u256, j: u256): u256 { return this.m[k][j]; } }`,
      `contract C { mapping(uint256=>uint256[2]) m; function seed() external { m[0][0]=5; m[0][1]=6; } function cp() external { m[1] = m[0]; } function g(uint256 k, uint256 j) external view returns(uint256){ return m[k][j]; } }`,
      [{ sig: 'seed()' }, { sig: 'cp()' }, { sig: 'g(uint256,uint256)', args: W(1n) + W(0n) }, { sig: 'g(uint256,uint256)', args: W(1n) + W(1n) }],
    );
    await rt(
      `@struct class S { x: u256; arr: Arr<u256,2>; } @contract class C { @state e: S; @state g: S; @external seed(): void { this.g.arr[0n]=11n; this.g.arr[1n]=22n; } @external cp(): void { this.e.arr = this.g.arr; } @external @view ge(j: u256): u256 { return this.e.arr[j]; } }`,
      `struct S { uint256 x; uint256[2] arr; } contract C { S e; S g; function seed() external { g.arr[0]=11; g.arr[1]=22; } function cp() external { e.arr = g.arr; } function ge(uint256 j) external view returns(uint256){ return e.arr[j]; } }`,
      [{ sig: 'seed()' }, { sig: 'cp()' }, { sig: 'ge(uint256)', args: W(0n) }, { sig: 'ge(uint256)', args: W(1n) }],
    );
  });
});

describe('delete of a memory aggregate local (rebind to fresh zeroed instance) vs solc', () => {
  it('struct, fixed array, and aliasing semantics', async () => {
    await rt(
      `@struct class S { x: u256; y: u256; } @contract class C { @external @pure f(): u256 { let a: S = S(5n, 6n); delete a; return a.x + a.y; } }`,
      `struct S { uint256 x; uint256 y; } contract C { function f() external pure returns(uint256){ S memory a = S(5,6); delete a; return a.x + a.y; } }`,
      [{ sig: 'f()' }],
    );
    await rt(
      `@contract class C { @external @pure f(): u256 { let a: Arr<u256,3> = [5n, 6n, 7n]; delete a; return a[0n] + a[1n] + a[2n]; } }`,
      `contract C { function f() external pure returns(uint256){ uint256[3] memory a = [uint256(5),6,7]; delete a; return a[0] + a[1] + a[2]; } }`,
      [{ sig: 'f()' }],
    );
    await rt(
      `@struct class S { x: u256; } @contract class C { @external @pure f(): [u256, u256] { let a: S = S(5n); let b: S = a; delete a; return [a.x, b.x]; } }`,
      `struct S { uint256 x; } contract C { function f() external pure returns(uint256,uint256){ S memory a = S(5); S memory b = a; delete a; return (a.x, b.x); } }`,
      [{ sig: 'f()' }],
    );
  });
});

describe('multi-return with a MEMORY/constructed struct component vs solc', () => {
  it('constructed, local, packed, and mixed-with-dynamic', async () => {
    await rt(
      `@struct class P { a: u256; b: address; } @contract class C { @external @pure f(): [u256, P, bool] { return [9n, P(1n, address(0x7n)), true]; } }`,
      `struct P { uint256 a; address b; } contract C { function f() external pure returns (uint256, P memory, bool){ return (9, P(1, address(0x7)), true); } }`,
      [{ sig: 'f()' }],
    );
    await rt(
      `@struct class P { a: u256; b: u256; } @contract class C { @external @pure f(): [u256, P] { let p: P = P(3n, 4n); return [9n, p]; } }`,
      `struct P { uint256 a; uint256 b; } contract C { function f() external pure returns (uint256, P memory){ P memory p = P(3, 4); return (9, p); } }`,
      [{ sig: 'f()' }],
    );
    await rt(
      `@struct class P { a: u8; b: u16; c: address; } @contract class C { @external @pure f(): [P, u256] { return [P(200n, 50000n, address(0x1n)), 7n]; } }`,
      `struct P { uint8 a; uint16 b; address c; } contract C { function f() external pure returns (P memory, uint256){ return (P(200, 50000, address(0x1)), 7); } }`,
      [{ sig: 'f()' }],
    );
    await rt(
      `@struct class P { a: u256; } @contract class C { @external @pure f(): [P, u256, string] { return [P(5n), 8n, "hi"]; } }`,
      `struct P { uint256 a; } contract C { function f() external pure returns (P memory, uint256, string memory){ return (P(5), 8, "hi"); } }`,
      [{ sig: 'f()' }],
    );
  });
});

describe('event overloading by signature vs solc', () => {
  it('resolves overloads by arity and by type; exact-dup still rejected', async () => {
    await rt(
      `@contract class C { @event L(a: u256); @event L(a: u256, b: u256); @event L(a: address); @external f(): void { emit(L(1n)); emit(L(2n, 3n)); emit(L(msg.sender)); } }`,
      `contract C { event L(uint256 a); event L(uint256 a, uint256 b); event L(address a); function f() external { emit L(1); emit L(2,3); emit L(msg.sender); } }`,
      [{ sig: 'f()' }],
    );
    expect(jethRejects(`@contract class C { @event L(a: u256); @event L(a: u256); }`)).toBe(true); // exact-sig duplicate
  });
});

describe('storage bytes index write b[i] = x vs solc', () => {
  const B1 = (h: string) => h.padEnd(64, '0');
  it('short and long bytes, with OOB Panic parity', async () => {
    await rt(
      `@contract class C { @state b: bytes; @external init(v: bytes): void { this.b = v; } @external set(i: u256, x: bytes1): void { this.b[i] = x; } @external @view get(i: u256): bytes1 { return this.b[i]; } @external @view all(): bytes { return this.b; } }`,
      `contract C { bytes b; function init(bytes calldata v) external { b = v; } function set(uint256 i, bytes1 x) external { b[i] = x; } function get(uint256 i) external view returns(bytes1){ return b[i]; } function all() external view returns(bytes memory){ return b; } }`,
      [{ sig: 'init(bytes)', args: W(0x20n) + W(5n) + B1('aabbccddee') }, { sig: 'set(uint256,bytes1)', args: W(2n) + B1('ff') }, { sig: 'get(uint256)', args: W(2n) }, { sig: 'all()' }, { sig: 'set(uint256,bytes1)', args: W(9n) + B1('11') }],
    );
    await rt(
      `@contract class C { @state b: bytes; @external init(v: bytes): void { this.b = v; } @external set(i: u256, x: bytes1): void { this.b[i] = x; } @external @view all(): bytes { return this.b; } }`,
      `contract C { bytes b; function init(bytes calldata v) external { b = v; } function set(uint256 i, bytes1 x) external { b[i] = x; } function all() external view returns(bytes memory){ return b; } }`,
      [{ sig: 'init(bytes)', args: W(0x20n) + W(40n) + '00'.repeat(40).padEnd(128, '0') }, { sig: 'set(uint256,bytes1)', args: W(35n) + B1('ab') }, { sig: 'set(uint256,bytes1)', args: W(0n) + B1('cd') }, { sig: 'all()' }],
    );
  });
});

describe('storage bytes .push / .pop vs solc (short<->long transitions)', () => {
  const B1 = (h: string) => h.padEnd(64, '0');
  it('push across 31->32, pop across 32->31, push(), and pop-empty Panic', async () => {
    const calls: { sig: string; args?: string }[] = [{ sig: 'init(bytes)', args: W(0x20n) + W(30n) + 'aa'.repeat(30).padEnd(64, '0') }];
    for (let i = 0; i < 5; i++) calls.push({ sig: 'pb(bytes1)', args: B1((0x10 + i).toString(16).padStart(2, '0')) }); // 30 -> 35 (crosses 31->32)
    calls.push({ sig: 'all()' }, { sig: 'len()' }, { sig: 'at(uint256)', args: W(34n) }, { sig: 'at(uint256)', args: W(0n) });
    for (let i = 0; i < 5; i++) calls.push({ sig: 'pop()' }); // 35 -> 30 (crosses 32->31)
    calls.push({ sig: 'all()' }, { sig: 'len()' });
    calls.push({ sig: 'p0()' }, { sig: 'all()' }); // push() zero byte
    await rt(
      `@contract class C { @state b: bytes; @external init(v: bytes): void { this.b = v; } @external pb(x: bytes1): void { this.b.push(x); } @external p0(): void { this.b.push(); } @external pop(): void { this.b.pop(); } @external @view all(): bytes { return this.b; } @external @view len(): u256 { return this.b.length; } @external @view at(i: u256): bytes1 { return this.b[i]; } }`,
      `contract C { bytes b; function init(bytes calldata v) external { b = v; } function pb(bytes1 x) external { b.push(x); } function p0() external { b.push(); } function pop() external { b.pop(); } function all() external view returns(bytes memory){ return b; } function len() external view returns(uint256){ return b.length; } function at(uint256 i) external view returns(bytes1){ return b[i]; } }`,
      calls,
    );
    // pop on empty -> Panic(0x31) on both
    await rt(
      `@contract class C { @state b: bytes; @external pop(): void { this.b.pop(); } }`,
      `contract C { bytes b; function pop() external { b.pop(); } }`,
      [{ sig: 'pop()' }],
    );
  });
});

describe('indexed DYNAMIC-struct event param: topic = keccak(flattened payload) vs solc', () => {
  const L36 = 'abcdefghijklmnopqrstuvwxyz0123456789'; // 36 bytes (> 32, multi-word)
  const L32 = 'abcdefghijklmnopqrstuvwxyz012345'; // exactly 32 (word boundary)
  it('value + string fields (struct literal)', () =>
    rt(
      `@struct class D { x: u256; s: string; } @contract class C { @event E(@indexed d: D, n: u256); @external f(): void { emit(E(D(7n,"hi"), 9n)); } }`,
      `struct D { uint256 x; string s; } contract C { event E(D indexed d, uint256 n); function f() external { emit E(D(7,"hi"), 9); } }`,
      [{ sig: 'f()' }],
    ));
  it('long string + bytes + trailing static (multi-word, two dynamic fields)', () =>
    rt(
      `@struct class D { x: u256; s: string; b: bytes; y: u256; } @contract class C { @event E(@indexed d: D); @external f(): void { emit(E(D(7n,"${L36}","deadbeef",9n))); } }`,
      `struct D { uint256 x; string s; bytes b; uint256 y; } contract C { event E(D indexed d); function f() external { emit E(D(7,"${L36}","deadbeef",9)); } }`,
      [{ sig: 'f()' }],
    ));
  it('two strings, one empty, one exactly 32 bytes (padding boundary)', () =>
    rt(
      `@struct class D { a: string; b: string; } @contract class C { @event E(@indexed d: D); @external f(): void { emit(E(D("","${L32}"))); } }`,
      `struct D { string a; string b; } contract C { event E(D indexed d); function f() external { emit E(D("","${L32}")); } }`,
      [{ sig: 'f()' }],
    ));
  it('dynamic value-array field (struct literal)', () =>
    rt(
      `@struct class D { x: u256; a: u256[]; } @contract class C { @event E(@indexed d: D); @external f(): void { emit(E(D(4n, [5n,6n,7n]))); } }`,
      `struct D { uint256 x; uint256[] a; } contract C { event E(D indexed d); function f() external { uint256[] memory m=new uint256[](3); m[0]=5;m[1]=6;m[2]=7; emit E(D(4, m)); } }`,
      [{ sig: 'f()' }],
    ));
  it('memory-source struct local', () =>
    rt(
      `@struct class D { x: u256; s: string; } @contract class C { @event E(@indexed d: D); @external f(): void { let d: D = D(7n,"${L36}"); emit(E(d)); } }`,
      `struct D { uint256 x; string s; } contract C { event E(D indexed d); function f() external { D memory d = D(7,"${L36}"); emit E(d); } }`,
      [{ sig: 'f()' }],
    ));
  it('calldata-source struct param', () =>
    rt(
      `@struct class D { x: u256; s: string; } @contract class C { @event E(@indexed d: D); @external g(d: D): void { emit(E(d)); } }`,
      `struct D { uint256 x; string s; } contract C { event E(D indexed d); function g(D calldata d) external { emit E(d); } }`,
      [{ sig: 'g((uint256,string))', args: W(7n) + W(0x20n) + W(2n) + Buffer.from('hi').toString('hex').padEnd(64, '0') }],
    ));
  it('mixed: indexed static + indexed dyn struct + non-indexed data word', () =>
    rt(
      `@struct class D { x: u256; s: string; } @contract class C { @event E(@indexed k: u256, @indexed d: D, v: u256); @external f(): void { emit(E(99n, D(7n,"hi"), 123n)); } }`,
      `struct D { uint256 x; string s; } contract C { event E(uint256 indexed k, D indexed d, uint256 v); function f() external { emit E(99, D(7,"hi"), 123); } }`,
      [{ sig: 'f()' }],
    ));
});

describe('re-sweep over-acceptance fixes (solc rejects, JETH must too)', () => {
  it('a fixed-array literal with the wrong element count is rejected (no silent pad/truncate)', () => {
    expect(jethRejects(`@contract class C { @external @pure f(): Arr<u256,3> { let a: Arr<u256,3> = [1n,2n,3n,4n,5n]; return a; } }`)).toBe(true);
    expect(jethRejects(`@contract class C { @external @pure f(): Arr<u256,3> { let a: Arr<u256,3> = [1n,2n]; return a; } }`)).toBe(true);
    expect(jethAccepts(`@contract class C { @external @pure f(): Arr<u256,3> { let a: Arr<u256,3> = [1n,2n,3n]; return a; } }`)).toBe(true);
  });
  it('enum -> intN cast is rejected for every width (runtime value and member literal)', () => {
    expect(jethRejects(`enum Color { Red, Green, Blue } @contract class C { @external @pure f(c: Color): i8 { return i8(c); } }`)).toBe(true);
    expect(jethRejects(`enum Color { Red, Green, Blue } @contract class C { @external @pure f(): i8 { return i8(Color.Blue); } }`)).toBe(true);
    expect(jethAccepts(`enum Color { Red, Green, Blue } @contract class C { @external @pure f(c: Color): u8 { return u8(c); } }`)).toBe(true);
    expect(jethAccepts(`enum Color { Red, Green, Blue } @contract class C { @external @pure f(c: Color): u256 { return u256(c); } }`)).toBe(true);
  });
  it('@error named Error or Panic is rejected (reserved); a same-named @event is fine', () => {
    expect(jethRejects(`@contract class C { @error Panic(code: u256); @external f(): void { revert(Panic(1n)); } }`)).toBe(true);
    expect(jethRejects(`@contract class C { @error Error(s: string); @external f(): void { revert(Error("x")); } }`)).toBe(true);
    expect(jethAccepts(`@contract class C { @event Panic(code: u256); @external f(): void { emit(Panic(1n)); } }`)).toBe(true);
  });
  it('cross-kind identifier collisions are rejected; function/event overloading is allowed', () => {
    expect(jethRejects(`@contract class C { @error X(a: u256); @event X(a: u256); @external f(): void { revert(X(1n)); } }`)).toBe(true);
    expect(jethRejects(`@struct class X { a: u256; } @contract class C { @external X(): void {} }`)).toBe(true);
    expect(jethRejects(`@contract class C { @state x: u256; @external x(): void {} }`)).toBe(true);
    expect(jethRejects(`enum X { A, B } @contract class C { @event X(a: u256); @external f(): void {} }`)).toBe(true);
    expect(jethAccepts(`@contract class C { @external f(): void {} @external f(a: u256): void {} }`)).toBe(true);
    expect(jethAccepts(`@contract class C { @event E(a: u256); @event E(b: bool); @external f(): void { emit(E(1n)); } }`)).toBe(true);
  });
});

describe('re-sweep over-rejection fixes: hex literal -> bytesN + rational @constant', () => {
  it('an exact-width hex literal converts to bytesN (left-aligned), byte-identical to solc', () =>
    rt(
      `@contract class C { @constant B: bytes4 = 0x12345678n; @external @pure f(): bytes4 { return 0x12345678n; } @external @pure g(): bytes4 { return this.B; } @external @pure h(x: bytes4): bool { return x == 0x12345678n; } @external @pure e(a: u256): bytes { return abi.encodeWithSelector(0x12345678n, a); } }`,
      `contract C { bytes4 constant B=0x12345678; function f() external pure returns(bytes4){ return 0x12345678; } function g() external pure returns(bytes4){ return B; } function h(bytes4 x) external pure returns(bool){ return x==0x12345678; } function e(uint256 a) external pure returns(bytes memory){ return abi.encodeWithSelector(0x12345678, a); } }`,
      [{ sig: 'f()' }, { sig: 'g()' }, { sig: 'h(bytes4)', args: '12345678'.padEnd(64, '0') }, { sig: 'e(uint256)', args: W(99n) }],
    ));
  it('a wrong-width hex literal still needs an explicit cast (parity: both reject)', () => {
    expect(jethRejects(`@contract class C { @external @pure f(): bytes4 { return 0x1234n; } }`)).toBe(true);
    expect(solcRejects(`contract C { function f() external pure returns(bytes4){ return 0x1234; } }`)).toBe(true);
  });
  it('a @constant / @state with a fractional intermediate folds rationally (byte-identical to solc)', () =>
    rt(
      `@contract class C { @constant K: u256 = (10n/4n)*4n; @state x: u256 = ((3n/2n)*2n)**3n; @external @view a(): u256 { return this.K; } @external @view b(): u256 { return this.x; } }`,
      `contract C { uint256 constant K=(10/4)*4; uint256 x=((3/2)*2)**3; function a() external view returns(uint256){ return K; } function b() external view returns(uint256){ return x; } }`,
      [{ sig: 'a()' }, { sig: 'b()' }],
    ));
  it('constant div/mod by zero and a fractional final value are rejected (parity)', () => {
    expect(jethRejects(`@contract class C { @constant K: u256 = 5n/0n; @external @pure f(): u256 { return this.K; } }`)).toBe(true);
    expect(jethRejects(`@contract class C { @constant K: u256 = 7n/2n; @external @pure f(): u256 { return this.K; } }`)).toBe(true);
  });
});

describe('re-sweep batch 2: storage-bytes mutators through any base vs solc', () => {
  const B1 = (h: string) => h.padEnd(64, '0');
  const initB = (n: number) => W(0x20n) + W(BigInt(n)) + 'aa'.repeat(n).padEnd(Math.ceil(n / 32) * 64, '0');
  it('struct.bytes .push (31->32) / .pop (32->31) / [i]=x byte-identical', async () => {
    const c: { sig: string; args?: string }[] = [{ sig: 'init(bytes)', args: initB(30) }];
    for (let i = 0; i < 5; i++) c.push({ sig: 'p(bytes1)', args: B1((0x10 + i).toString(16).padStart(2, '0')) });
    c.push({ sig: 'get()' }, { sig: 's(uint256,bytes1)', args: W(33n) + B1('ee') }, { sig: 'get()' });
    for (let i = 0; i < 4; i++) c.push({ sig: 'pop()' });
    c.push({ sig: 'get()' });
    await rt(
      `@struct class D { x: u256; data: bytes; } @contract class C { @state d: D; @external init(v: bytes): void { this.d.data = v; } @external p(b: bytes1): void { this.d.data.push(b); } @external pop(): void { this.d.data.pop(); } @external s(i: u256, x: bytes1): void { this.d.data[i] = x; } @external @view get(): bytes { return this.d.data; } }`,
      `contract C { struct D{uint256 x;bytes data;} D d; function init(bytes calldata v) external { d.data=v; } function p(bytes1 b) external { d.data.push(b); } function pop() external { d.data.pop(); } function s(uint256 i,bytes1 x) external { d.data[i]=x; } function get() external view returns(bytes memory){ return d.data; } }`,
      c,
    );
  });
  it('mapping(u256=>bytes) value .push / [i]=x byte-identical', async () => {
    const c: { sig: string; args?: string }[] = [{ sig: 'init(uint256,bytes)', args: W(7n) + W(0x40n) + W(30n) + 'bb'.repeat(30).padEnd(64, '0') }];
    for (let i = 0; i < 4; i++) c.push({ sig: 'p(uint256,bytes1)', args: W(7n) + B1((0x20 + i).toString(16).padStart(2, '0')) });
    c.push({ sig: 's(uint256,uint256,bytes1)', args: W(7n) + W(2n) + B1('ff') }, { sig: 'get(uint256)', args: W(7n) });
    await rt(
      `@contract class C { @state m: mapping<u256, bytes>; @external init(k: u256, v: bytes): void { this.m[k] = v; } @external p(k: u256, b: bytes1): void { this.m[k].push(b); } @external s(k: u256, i: u256, x: bytes1): void { this.m[k][i] = x; } @external @view get(k: u256): bytes { return this.m[k]; } }`,
      `contract C { mapping(uint256=>bytes) m; function init(uint256 k,bytes calldata v) external { m[k]=v; } function p(uint256 k,bytes1 b) external { m[k].push(b); } function s(uint256 k,uint256 i,bytes1 x) external { m[k][i]=x; } function get(uint256 k) external view returns(bytes memory){ return m[k]; } }`,
      c,
    );
  });
  it('bytes[] element and Arr<bytes,N> element .push byte-identical', async () => {
    const c: { sig: string; args?: string }[] = [{ sig: 'init(bytes)', args: initB(30) }];
    for (let i = 0; i < 4; i++) c.push({ sig: 'p(uint256,bytes1)', args: W(0n) + B1((0x30 + i).toString(16).padStart(2, '0')) });
    c.push({ sig: 'get(uint256)', args: W(0n) });
    await rt(
      `@contract class C { @state a: bytes[]; @external init(v: bytes): void { this.a.push(v); } @external p(i: u256, b: bytes1): void { this.a[i].push(b); } @external @view get(i: u256): bytes { return this.a[i]; } }`,
      `contract C { bytes[] a; function init(bytes calldata v) external { a.push(v); } function p(uint256 i,bytes1 b) external { a[i].push(b); } function get(uint256 i) external view returns(bytes memory){ return a[i]; } }`,
      c,
    );
  });
  it('pop on empty struct.bytes Panics (0x31) like solc', () =>
    rt(
      `@struct class D { x: u256; data: bytes; } @contract class C { @state d: D; @external pop(): void { this.d.data.pop(); } }`,
      `contract C { struct D{uint256 x;bytes data;} D d; function pop() external { d.data.pop(); } }`,
      [{ sig: 'pop()' }],
    ));
});

describe('re-sweep batch 2: bytes(string)[i] / nested ctor / fixed-array copy / @error aggregates vs solc', () => {
  const strArg = (s: string) => W(0x20n) + W(BigInt(s.length)) + Buffer.from(s).toString('hex').padEnd(64, '0');
  it('bytes(string)[i] byte-indexes the reinterpreted value (calldata / storage / memory)', () =>
    rt(
      `@contract class C { @state s: string; @external set(v: string): void { this.s = v; } @external @view atStore(i: u256): bytes1 { return bytes(this.s)[i]; } @external @pure atCd(t: string, i: u256): bytes1 { return bytes(t)[i]; } @external @pure atMem(t: string, i: u256): bytes1 { let m: string = t; return bytes(m)[i]; } }`,
      `contract C { string s; function set(string calldata v) external { s=v; } function atStore(uint256 i) external view returns(bytes1){ return bytes(s)[i]; } function atCd(string calldata t,uint256 i) external pure returns(bytes1){ return bytes(t)[i]; } function atMem(string calldata t,uint256 i) external pure returns(bytes1){ string memory m=t; return bytes(m)[i]; } }`,
      [{ sig: 'set(string)', args: strArg('hello world') }, { sig: 'atStore(uint256)', args: W(4n) }, { sig: 'atCd(string,uint256)', args: strArg('abcdef') + '' }, { sig: 'atCd(string,uint256)', args: strArg('abcdef') }, { sig: 'atMem(string,uint256)', args: strArg('xyz123') }],
    ));
  it('nested inline struct constructor in a return position (positional), incl. deep nesting', () =>
    rt(
      `@struct class Inner { c: u8; v: u32; } @struct class Outer { id: u16; inner: Inner; } @struct class A { x: u8; } @struct class B { a: A; y: u16; } @struct class D { b: B; z: u32; } @contract class C { @external @pure f(id: u16, c: u8, v: u32): Outer { return Outer(id, Inner(c, v)); } @external @pure g(): D { return D(B(A(5n), 6n), 7n); } }`,
      `struct Inner{uint8 c;uint32 v;} struct Outer{uint16 id;Inner inner;} struct A{uint8 x;} struct B{A a;uint16 y;} struct D{B b;uint32 z;} contract C { function f(uint16 id,uint8 c,uint32 v) external pure returns(Outer memory){ return Outer(id,Inner(c,v)); } function g() external pure returns(D memory){ return D(B(A(5),6),7); } }`,
      [{ sig: 'f(uint16,uint8,uint32)', args: W(0x102n) + W(7n) + W(0xcafen) }, { sig: 'g()' }],
    ));
  it('whole memory / calldata fixed-array -> storage assignment (incl. packed elements)', () =>
    rt(
      `@contract class C { @state g: Arr<u256,3>; @state h: Arr<u64,4>; @external a(): u256 { let m: Arr<u256,3> = [111n,222n,333n]; this.g = m; return this.g[2n]; } @external b(x: Arr<u256,3>): u256 { this.g = x; return this.g[1n]; } @external c(): u64 { let m: Arr<u64,4> = [1n,2n,3n,4n]; this.h = m; return this.h[3n]; } }`,
      `contract C { uint256[3] g; uint64[4] h; function a() external returns(uint256){ uint256[3] memory m=[uint256(111),222,333]; g=m; return g[2]; } function b(uint256[3] calldata x) external returns(uint256){ g=x; return g[1]; } function c() external returns(uint64){ uint64[4] memory m=[uint64(1),2,3,4]; h=m; return h[3]; } }`,
      [{ sig: 'a()' }, { sig: 'b(uint256[3])', args: W(5n) + W(6n) + W(7n) }, { sig: 'c()' }],
    ));
  it('@error with static struct / fixed-array / mixed params reverts byte-identically', () =>
    rt(
      `@struct class P { x: u256; y: bool; } @contract class C { @error BadS(p: P); @error BadA(a: Arr<u256, 2>); @error BadMix(n: u256, p: P, s: bytes); @external fs(): void { revert(BadS(P(42n, true))); } @external fa(): void { let x: Arr<u256,2> = [5n,6n]; revert(BadA(x)); } @external fm(): void { revert(BadMix(9n, P(1n, true), "hello")); } }`,
      `contract C { struct P{uint256 x;bool y;} error BadS(P p); error BadA(uint256[2] a); error BadMix(uint256 n, P p, bytes s); function fs() external { revert BadS(P(42,true)); } function fa() external { uint256[2] memory x=[uint256(5),6]; revert BadA(x); } function fm() external { revert BadMix(9, P(1,true), "hello"); } }`,
      [{ sig: 'fs()' }, { sig: 'fa()' }, { sig: 'fm()' }],
    ));
});

describe('re-sweep batch 3: object literals, internal aggregate params, Arr<dynElem,N>[] vs solc', () => {
  const strArg = (s: string) => W(0x20n) + W(BigInt(s.length)) + Buffer.from(s).toString('hex').padEnd(Math.ceil(s.length / 32) * 64 || 64, '0');
  const LONG = 'abcdefghijklmnopqrstuvwxyz0123456789';
  it('object-literal struct construction with nested struct / bytes / fixed-array fields', () =>
    rt(
      `@struct class In { c: u8; v: u32; } @struct class O { id: u16; inner: In; } @struct class Db { x: u256; s: bytes; } @struct class Da { x: u256; a: Arr<u256,2>; } @contract class C { @external @pure f(): O { return { id: 1n, inner: In(2n, 3n) }; } @external @pure gb(): Db { return { x: 9n, s: "hi" }; } @external @pure ga(): Da { return { x: 7n, a: [4n, 5n] }; } }`,
      `struct In{uint8 c;uint32 v;} struct O{uint16 id;In inner;} struct Db{uint256 x;bytes s;} struct Da{uint256 x;uint256[2] a;} contract C { function f() external pure returns(O memory){ return O({id:1, inner:In(2,3)}); } function gb() external pure returns(Db memory){ return Db({x:9, s:"hi"}); } function ga() external pure returns(Da memory){ return Da({x:7, a:[uint256(4),5]}); } }`,
      [{ sig: 'f()' }, { sig: 'gb()' }, { sig: 'ga()' }],
    ));
  it('object-literal spread keeps value fields; a non-value field must be explicit (not spread)', () => {
    expect(jethAccepts(`@struct class P { a: u256; b: u256; } @contract class C { @external @pure f(p: P): P { return { ...p, a: 9n }; } }`)).toBe(true);
    expect(jethRejects(`@struct class In { c: u8; } @struct class O { id: u256; inner: In; } @contract class C { @external @pure f(o: O): O { return { ...o, id: 1n }; } }`)).toBe(true);
  });
  it('internal call: struct + fixed-array params/return + calldata aggregate forwarding (byte-identical)', () =>
    rt(
      `@struct class P { a: u8; b: u32; } @contract class C { @pure gs(p: P): u32 { return p.b; } @pure ga(a: Arr<u256,3>): u256 { return a[2n]; } @pure mk(): Arr<u256,2> { return [9n, 8n]; } @external @pure fs(x: u8, y: u32): u32 { return gs(P(x, y)); } @external @pure fa(): u256 { return ga([10n,20n,30n]); } @external @pure fr(): u256 { let a: Arr<u256,2> = mk(); return a[0n] + a[1n]; } @external @pure fwd(x: P): u32 { return gs(x); } }`,
      `contract C { struct P{uint8 a;uint32 b;} function gs(P memory p) internal pure returns(uint32){return p.b;} function ga(uint256[3] memory a) internal pure returns(uint256){return a[2];} function mk() internal pure returns(uint256[2] memory){return [uint256(9),8];} function fs(uint8 x,uint32 y) external pure returns(uint32){ return gs(P(x,y)); } function fa() external pure returns(uint256){ return ga([uint256(10),20,30]); } function fr() external pure returns(uint256){ uint256[2] memory a=mk(); return a[0]+a[1]; } function fwd(P calldata x) external pure returns(uint32){ return gs(x); } }`,
      [{ sig: 'fs(uint8,uint32)', args: W(7n) + W(0xcafen) }, { sig: 'fa()' }, { sig: 'fr()' }, { sig: 'fwd((uint8,uint32))', args: W(1n) + W(2n) }],
    ));
  it('@external aggregate internal call stays a clean rejection (broader dual-entry feature)', () => {
    expect(jethRejects(`@struct class P { a: u8; } @contract class C { @external @pure g(p: P): u8 { return p.a; } @external @pure f(): u8 { return g(P(5n)); } }`)).toBe(true);
  });
  it('bare @state Arr<string,N>[] / Arr<bytes,N>[]: push/set/get/pop deep-clear/delete byte-identical', async () => {
    const calls: { sig: string; args?: string }[] = [{ sig: 'grow()' }, { sig: 'grow()' }, { sig: 'len()' }];
    calls.push({ sig: 's(uint256,uint256,string)', args: W(0n) + W(1n) + strArg('hi') });
    calls.push({ sig: 's(uint256,uint256,string)', args: W(1n) + W(0n) + strArg(LONG) });
    calls.push({ sig: 'g(uint256,uint256)', args: W(0n) + W(1n) }, { sig: 'g(uint256,uint256)', args: W(1n) + W(0n) });
    calls.push({ sig: 'pop()' }, { sig: 'grow()' }, { sig: 'g(uint256,uint256)', args: W(1n) + W(0n) }); // re-grown -> empty (deep-clear)
    calls.push({ sig: 'del()' }, { sig: 'len()' });
    await rt(
      `@contract class C { @state a: Arr<string,3>[]; @external grow(): void { this.a.push(); } @external pop(): void { this.a.pop(); } @external del(): void { delete this.a; } @external s(i: u256, j: u256, v: string): void { this.a[i][j] = v; } @external @view g(i: u256, j: u256): string { return this.a[i][j]; } @external @view len(): u256 { return this.a.length; } }`,
      `contract C { string[3][] a; function grow() external { a.push(); } function pop() external { a.pop(); } function del() external { delete a; } function s(uint256 i,uint256 j,string calldata v) external { a[i][j]=v; } function g(uint256 i,uint256 j) external view returns(string memory){ return a[i][j]; } function len() external view returns(uint256){ return a.length; } }`,
      calls,
    );
  });
});

describe('remaining over-rejections R1/R3/R5 vs solc (byte-identical)', () => {
  it('R3: a dynamic struct with a static fixed-array field (return + storage roundtrip)', () =>
    rt(
      `@struct class D { x: u256; s: bytes; a: Arr<u256,2>; } @contract class C { @state d: D; @external @pure f(): D { return D(9n, "hello", [4n,5n]); } @external set(): void { this.d = D(1n, "stored value here, fairly long!!", [7n,8n]); } @external @view ga(i: u256): u256 { return this.d.a[i]; } @external @view gs(): bytes { return this.d.s; } }`,
      `struct D{uint256 x;bytes s;uint256[2] a;} contract C { D d; function f() external pure returns(D memory){ return D(9,"hello",[uint256(4),5]); } function set() external { d=D(1,"stored value here, fairly long!!",[uint256(7),8]); } function ga(uint256 i) external view returns(uint256){ return d.a[i]; } function gs() external view returns(bytes memory){ return d.s; } }`,
      [{ sig: 'f()' }, { sig: 'set()' }, { sig: 'ga(uint256)', args: W(0n) }, { sig: 'ga(uint256)', args: W(1n) }, { sig: 'gs()' }],
    ));
  it('R1: struct/fixed-array field from a non-inline source (local/param/storage) in return/let/storage', () =>
    rt(
      `@struct class I { a: u256; b: u32; } @struct class O { i: I; y: u256; } @struct class A { x: u256; arr: Arr<u256,2>; } @contract class C { @state o: O; @state src: I; @external @pure fLocal(y: u256): O { let z: I = I(7n, 8n); return O(z, y); } @external @pure fParam(z: I, y: u256): O { return O(z, y); } @external @pure fArr(x: u256): A { let z: Arr<u256,2> = [1n,2n]; return A(x, z); } @external seed(): void { this.src = I(11n, 22n); } @external setO(): void { let z: I = I(3n, 4n); this.o = O(z, 99n); } @external @view ga(): u256 { return this.o.i.a; } @external @view fStore(y: u256): O { return O(this.src, y); } }`,
      `struct I{uint256 a;uint32 b;} struct O{I i;uint256 y;} struct A{uint256 x;uint256[2] arr;} contract C { O o; I src; function fLocal(uint256 y) external pure returns(O memory){ I memory z=I(7,8); return O(z,y); } function fParam(I calldata z,uint256 y) external pure returns(O memory){ return O(z,y); } function fArr(uint256 x) external pure returns(A memory){ uint256[2] memory z=[uint256(1),2]; return A(x,z); } function seed() external { src=I(11,22); } function setO() external { I memory z=I(3,4); o=O(z,99); } function ga() external view returns(uint256){ return o.i.a; } function fStore(uint256 y) external view returns(O memory){ return O(src,y); } }`,
      [{ sig: 'fLocal(uint256)', args: W(5n) }, { sig: 'fParam((uint256,uint32),uint256)', args: W(1n) + W(2n) + W(5n) }, { sig: 'fArr(uint256)', args: W(9n) }, { sig: 'seed()' }, { sig: 'setO()' }, { sig: 'ga()' }, { sig: 'fStore(uint256)', args: W(7n) }],
    ));
  it('R5: msg.value in an internal function is allowed (forwarded byte-identical); externally requires @payable', () => {
    expect(jethAccepts(`@contract class C { @view h(): u256 { return msg.value; } @external @payable f(): u256 { return this.h(); } }`)).toBe(true);
    expect(jethAccepts(`@contract class C { @view h(): u256 { return msg.value; } @external @payable f(): u256 { return this.h(); } }`)).toBe(true);
    // internal (unmarked) reading msg.value directly is allowed (forwarded byte-identical)
    expect(jethAccepts(`@contract class C { @read bad(): u256 { return msg.value; } }`)).toBe(true);
    // external non-payable reading msg.value directly still requires @payable -> rejected
    expect(jethRejects(`@contract class C { @external @read bad(): u256 { return msg.value; } }`)).toBe(true);
    // external non-payable reading msg.value rejected; @pure internal rejected (env read)
    expect(jethRejects(`@contract class C { @external f(): u256 { return msg.value; } }`)).toBe(true);
    expect(jethRejects(`@contract class C { @pure h(): u256 { return msg.value; } @external f(): u256 { return this.h(); } }`)).toBe(true);
  });
});

describe('R4: Arr<dynElem,N>[] as a calldata param / whole-array return vs solc', () => {
  const strArg = (s: string) => W(0x20n) + W(BigInt(s.length)) + Buffer.from(s).toString('hex').padEnd(Math.ceil(s.length / 32) * 64 || 64, '0');
  const strBlk = (s: string) => W(BigInt(s.length)) + Buffer.from(s).toString('hex').padEnd(Math.ceil(s.length / 32) * 64 || 64, '0');
  it('calldata string[3][] param: length + a[i][j] byte-identical', async () => {
    // a = [["a","bb","ccc"]] : outer [off=0x20][len=1][elemOff=0x20] then elem [3 offsets][3 blocks]
    const elem = W(0x60n) + W(0x120n) + W(0x180n) + strBlk('a') + strBlk('bb') + strBlk('ccc');
    const cd = W(0x20n) + W(1n) + W(0x20n) + elem;
    await rt(
      `@contract class C { @external @pure len(a: Arr<string,3>[]): u256 { return a.length; } @external @pure at(a: Arr<string,3>[], i: u256, j: u256): string { return a[i][j]; } }`,
      `contract C { function len(string[3][] calldata a) external pure returns(uint256){ return a.length; } function at(string[3][] calldata a,uint256 i,uint256 j) external pure returns(string memory){ return a[i][j]; } }`,
      [{ sig: 'len(string[3][])', args: cd }, { sig: 'at(string[3][],uint256,uint256)', args: W(0x60n) + W(0n) + W(2n) + cd.slice(2) }],
    );
  });
  it('whole storage Arr<string,3>[] / Arr<bytes,2>[] return byte-identical', async () => {
    await rt(
      `@contract class C { @state a: Arr<string,3>[]; @external grow(): void { this.a.push(); } @external s(i: u256, j: u256, v: string): void { this.a[i][j] = v; } @external @view r(): Arr<string,3>[] { return this.a; } }`,
      `contract C { string[3][] a; function grow() external { a.push(); } function s(uint256 i,uint256 j,string calldata v) external { a[i][j]=v; } function r() external view returns(string[3][] memory){ return a; } }`,
      [{ sig: 'grow()' }, { sig: 'grow()' }, { sig: 's(uint256,uint256,string)', args: W(0n) + W(1n) + strArg('hi') }, { sig: 's(uint256,uint256,string)', args: W(1n) + W(0n) + strArg('a fairly long string crossing 32!!') }, { sig: 'r()' }],
    );
  });
  // VARIABLE-LENGTH nested string arrays via calldata. (A prior version navigated outer elements with a
  // CONTIGUOUS stride - correct only for equal-length elements - which silently miscompiled; these use
  // intentionally unequal lengths so contiguous-vs-offset-table navigation must differ.)
  const encStr = (s: string) => W(BigInt(s.length)) + Buffer.from(s).toString('hex').padEnd((Math.ceil(s.length / 32) || 0) * 64, '0');
  const block = (parts: string[]) => { const offs: string[] = []; let cur = parts.length * 32; for (const p of parts) { offs.push(W(BigInt(cur))); cur += p.length / 2; } return offs.join('') + parts.join(''); };
  it('string[3][] (single-level) variable-length a[i][j] + OOB byte-identical', async () => {
    const aBody = W(2n) + block([block(['aa', 'b', 'cccccc'].map(encStr)), block(['d', 'this-one-is-quite-a-bit-longer!!!', 'f'].map(encStr))]); // [len][offset table + tails]
    const at = (i: bigint, j: bigint) => ({ sig: 'at(string[3][],uint256,uint256)', args: W(0x60n) + W(i) + W(j) + aBody }); // head: [off_a=0x60][i][j]
    await rt(
      `@contract class C { @external @pure at(a: Arr<string,3>[], i: u256, j: u256): string { return a[i][j]; } @external @pure len(a: Arr<string,3>[]): u256 { return a.length; } }`,
      `contract C { function at(string[3][] calldata a,uint256 i,uint256 j) external pure returns(string memory){ return a[i][j]; } function len(string[3][] calldata a) external pure returns(uint256){ return a.length; } }`,
      [at(0n, 0n), at(1n, 1n), at(0n, 2n), at(1n, 0n), at(0n, 3n), at(2n, 0n), { sig: 'len(string[3][])', args: W(0x20n) + aBody }],
    );
  });
  it('string[2][3][] (double-level) variable-length a[i][j][k] + OOB + whole-array echo byte-identical', async () => {
    const enc23 = (a: string[][]) => block(a.map((p) => block(p.map(encStr)))); // string[2][3]
    const val = [[['a0', 'b1longer'], ['c2', 'd3'], ['e4', 'f5']], [['g6', ''], ['', 'k10longeryes'], ['l11', 'm12']]];
    const aBody = W(BigInt(val.length)) + block(val.map(enc23)); // [len][table + per-element string[2][3] blocks]
    const at = (i: bigint, j: bigint, k: bigint) => ({ sig: 'at(string[2][3][],uint256,uint256,uint256)', args: W(0x80n) + W(i) + W(j) + W(k) + aBody });
    await rt(
      `@contract class C { @external @pure at(a: Arr<Arr<string,2>,3>[], i: u256, j: u256, k: u256): string { return a[i][j][k]; } @external @pure len(a: Arr<Arr<string,2>,3>[]): u256 { return a.length; } @external @pure echo(a: Arr<Arr<string,2>,3>[]): Arr<Arr<string,2>,3>[] { return a; } }`,
      `contract C { function at(string[2][3][] calldata a,uint256 i,uint256 j,uint256 k) external pure returns(string memory){ return a[i][j][k]; } function len(string[2][3][] calldata a) external pure returns(uint256){ return a.length; } function echo(string[2][3][] calldata a) external pure returns(string[2][3][] memory){ return a; } }`,
      [at(0n, 0n, 1n), at(1n, 1n, 1n), at(1n, 2n, 0n), at(0n, 2n, 0n), at(0n, 3n, 0n), at(0n, 0n, 2n), { sig: 'len(string[2][3][])', args: W(0x20n) + aBody }, { sig: 'echo(string[2][3][])', args: W(0x20n) + aBody }],
    );
  });
});

describe('dynamic nested struct field from a non-inline (side-effect-free) source vs solc', () => {
  it('local / calldata-param / bytes-field dynamic struct copied into a parent struct (byte-identical)', () =>
    rt(
      `@struct class Inner { p: u256; s: string; } @struct class Outer { x: u256; inner: Inner; }
       @struct class IB { a: u256; b: bytes; c: u256; } @struct class OB { inner: IB; tail: u256; }
       @contract class C {
         @external @pure fLocal(): Outer { let z: Inner = Inner(1n, "a fairly long string value here!!"); return Outer(2n, z); }
         @external @pure fParam(z: Inner): Outer { return Outer(2n, z); }
         @external @pure fBytes(): OB { let z: IB = IB(9n, "deadbeefdeadbeef", 8n); return OB(z, 5n); }
       }`,
      `struct Inner { uint256 p; string s; } struct Outer { uint256 x; Inner inner; }
       struct IB { uint256 a; bytes b; uint256 c; } struct OB { IB inner; uint256 tail; }
       contract C {
         function fLocal() external pure returns(Outer memory){ Inner memory z = Inner(1, "a fairly long string value here!!"); return Outer(2, z); }
         function fParam(Inner calldata z) external pure returns(Outer memory){ return Outer(2, z); }
         function fBytes() external pure returns(OB memory){ IB memory z = IB(9, "deadbeefdeadbeef", 8); return OB(z, 5); }
       }`,
      [{ sig: 'fLocal()' }, { sig: 'fParam((uint256,string))', args: W(0x20n) + W(7n) + W(0x40n) + W(2n) + Buffer.from('hi').toString('hex').padEnd(64, '0') }, { sig: 'fBytes()' }],
    ));
  it('a function-call source (side-effecting) is still rejected (no double-eval)', () => {
    // a non-inline source that is a CALL is rejected (would re-evaluate); must bind to a local first.
    expect(jethRejects(`@struct class I { p: u256; s: string; } @struct class O { i: I; } @contract class C { @pure mk(): I { return I(1n,"x"); } @external @pure f(): O { return O(mk()); } }`)).toBe(true);
  });
});
