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
  // solc: "internal" and "private" functions cannot be payable. @hidden is an explicitly-internal fn.
  const reject: [string, string][] = [
    ['@internal @payable', `@contract class C { @internal @payable v(): u256 { return msg.value; } @external @payable f(): u256 { return this.v(); } }`],
    ['@private @payable', `@contract class C { @private @payable v(): u256 { return 1n; } @external f(): void { this.v(); } }`],
    ['@hidden @payable', `@contract class C { @hidden @payable v(): u256 { return 1n; } @external f(): void { this.v(); } }`],
  ];
  for (const [name, src] of reject) {
    it(`rejects ${name}`, () => expect(jethRejects(src)).toBe(true));
  }
  // external/public payable must still be accepted.
  it('accepts @external/@public @payable', () => {
    expect(jethAccepts(`@contract class C { @external @payable f(): u256 { return msg.value; } }`)).toBe(true);
    expect(jethAccepts(`@contract class C { @public @payable f(): u256 { return msg.value; } }`)).toBe(true);
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
