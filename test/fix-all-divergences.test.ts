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
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
function jethRejects(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
}
function solcRejects(src: string): boolean {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
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
      `class C { @anonymous E: event<{ a: indexed<u256>; b: u256 }>; f(): External<void> { emit(E(7n, 9n)); } }`,
      `contract C { event E(uint256 indexed a, uint256 b) anonymous; function f() external { emit E(7,9); } }`,
      [{ sig: 'f()' }],
    );
  });

  it('over-acceptances now rejected (match solc)', () => {
    // addmod/mulmod with a compile-time zero modulus
    expect(
      jethRejects(`class C { get f(a: u256, b: u256): External<u256> { return addmod(a, b, 0n); } }`),
    ).toBe(true);
    expect(
      jethRejects(`class C { get f(a: u256, b: u256): External<u256> { return mulmod(a, b, 1n - 1n); } }`),
    ).toBe(true);
    // @internal/@payable
    expect(jethRejects(`@contract class C { @payable g(): void {} @external f(): void { this.g(); } }`)).toBe(true);
    // nested unchecked
    expect(
      jethRejects(
        `class C { get f(): External<u256> { let x: u256 = 0n; unchecked: { unchecked: { x = x + 1n; } } return x; } }`,
      ),
    ).toBe(true);
    // stray decorators on event / error param
    expect(jethRejects(`@contract class C { @view @event E(a: u256); @external f(): void { emit(E(1n)); } }`)).toBe(
      true,
    );
    expect(
      jethRejects(`@contract class C { @error Bad(@indexed a: u256); @external f(): void { revert(Bad(1n)); } }`),
    ).toBe(true);
  });

  it('non-zero runtime modulus still reverts Panic(0x12) byte-identical', async () => {
    await rt(
      `class C { get f(a: u256, b: u256, m: u256): External<u256> { return addmod(a, b, m); } }`,
      `contract C { function f(uint256 a, uint256 b, uint256 m) external pure returns(uint256){ return addmod(a,b,m); } }`,
      [
        { sig: 'f(uint256,uint256,uint256)', args: W(10n) + W(20n) + W(0n) },
        { sig: 'f(uint256,uint256,uint256)', args: W(10n) + W(20n) + W(7n) },
      ],
    );
  });
});

describe('sweep over-rejection fixes (cheap)', () => {
  it('tx.gasprice', async () => {
    await rt(
      `class C { get f(): External<u256> { return tx.gasprice; } }`,
      `contract C { function f() external view returns(uint256){ return tx.gasprice; } }`,
      [{ sig: 'f()' }],
    );
  });

  it('keccak256 / sha256 / ripemd160 of a string literal', async () => {
    await rt(
      `class C { get k(): External<bytes32> { return keccak256("abc"); } get s(): External<bytes32> { return sha256("abc"); } get r(): External<bytes20> { return ripemd160("abc"); } }`,
      `contract C { function k() external pure returns(bytes32){ return keccak256("abc"); } function s() external pure returns(bytes32){ return sha256("abc"); } function r() external pure returns(bytes20){ return ripemd160("abc"); } }`,
      [{ sig: 'k()' }, { sig: 's()' }, { sig: 'r()' }],
    );
  });

  it('var-left literal widening (varN OP bigLit) computes at the common type', async () => {
    await rt(
      `class C {
        get add(a: u8): External<u16> { return a + 1000n; }
        get cast(a: u8): External<u16> { return u16(a + 1000n); }
        get mul(a: u8): External<u16> { return a * 1000n; }
        get fits(a: u8): External<u8> { return a + 1n; }
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
      `class C {
        static A: u256 = 10n;
        static B: u256 = A * 2n;
        static M: u256 = type(u256).max;
        static H: u8 = type(u8).max;
        static N: i8 = type(i8).min;
        static MASK: u8 = (~1n) & 0xFFn;
        static NEG: i256 = ~5n;
        static FLAG: bool = 5n > 3n;
        static FLAG2: bool = A == 10n;
        static T: u256 = FLAG ? 100n : 200n;
        get b(): External<u256> { return this.B; }
        get m(): External<u256> { return this.M; }
        get h(): External<u8> { return this.H; }
        get n(): External<i8> { return this.N; }
        get mask(): External<u8> { return this.MASK; }
        get neg(): External<i256> { return this.NEG; }
        get flag(): External<bool> { return this.FLAG; }
        get flag2(): External<bool> { return this.FLAG2; }
        get t(): External<u256> { return this.T; }
      }`,
      `contract C {
        uint256 constant A = 10;
        uint256 constant B = A * 2;
        uint256 constant M = type(uint256).max;
        uint8 constant H = type(uint8).max;
        int8 constant N = type(int8).min;
        uint8 constant MASK = (~1) & 0xFF;
        int256 constant NEG = ~5;
        bool constant FLAG = 5 > 3;
        bool constant FLAG2 = A == 10;
        uint256 constant T = FLAG ? 100 : 200;
        function b() external pure returns(uint256){ return B; }
        function m() external pure returns(uint256){ return M; }
        function h() external pure returns(uint8){ return H; }
        function n() external pure returns(int8){ return N; }
        function mask() external pure returns(uint8){ return MASK; }
        function neg() external pure returns(int256){ return NEG; }
        function flag() external pure returns(bool){ return FLAG; }
        function flag2() external pure returns(bool){ return FLAG2; }
        function t() external pure returns(uint256){ return T; }
      }`,
      [
        { sig: 'b()' },
        { sig: 'm()' },
        { sig: 'h()' },
        { sig: 'n()' },
        { sig: 'mask()' },
        { sig: 'neg()' },
        { sig: 'flag()' },
        { sig: 'flag2()' },
        { sig: 't()' },
      ],
    );
  });

  it('rejects a bare top-level ~N into an UNSIGNED constant (solc parity: int_const -N-1 not convertible)', () => {
    // ~0n is the signed int_const -1; assigning it to an unsigned type is a solc TypeError
    // ("Cannot implicitly convert signed literal to unsigned type"). JETH must reject too, NOT
    // width-mask to a positive value. The sub-expression form (~1n)&0xFFn above stays valid.
    for (const src of [
      `class C { static K: u256 = ~1n; get f(): External<u256> { return this.K; } }`,
      `class C { static K: u8 = ~0n; get f(): External<u8> { return this.K; } }`,
      `class C { static K: u128 = ~7n; get f(): External<u128> { return this.K; } }`,
    ]) {
      expect(jethRejects(src), src).toBe(true);
    }
  });
});

describe('sweep cast fixes', () => {
  it('bytesN(<int literal>) left-aligns into the high N bytes', async () => {
    await rt(
      `class C { get a(): External<bytes4> { return bytes4(0x12345678n); } get b(): External<bytes1> { return bytes1(0xabn); } }`,
      `contract C { function a() external pure returns(bytes4){ return bytes4(0x12345678); } function b() external pure returns(bytes1){ return bytes1(0xab); } }`,
      [{ sig: 'a()' }, { sig: 'b()' }],
    );
  });
});

describe('sweep batch D (moderate over-rejections)', () => {
  it('@modifier on a multi-value-return function', async () => {
    await rt(
      `class C { @modifier m() { _; } @m get f(): External<[u256, u256]> { return [1n, 2n]; } }`,
      `contract C { modifier m() { _; } function f() external pure m returns (uint256,uint256) { return (1,2); } }`,
      [{ sig: 'f()' }],
    );
  });

  it('bytes<->string reinterpret and bytesN(bytes)', async () => {
    await rt(
      `class C { get k(s: string): External<bytes32> { return keccak256(bytes(s)); } get e(b: bytes): External<string> { return string(b); } get n4(b: bytes): External<bytes4> { return bytes4(b); } get n32(b: bytes): External<bytes32> { return bytes32(b); } }`,
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
      `class C { static H: bytes32 = keccak256("Permit(address owner,uint256 value)"); static D: bytes32 = keccak256(abi.encodePacked("EIP712Domain")); static B: bytes32 = keccak256(bytes("abc")); get h(): External<bytes32> { return this.H; } get d(): External<bytes32> { return this.D; } get b(): External<bytes32> { return this.B; } }`,
      `contract C { bytes32 constant H = keccak256("Permit(address owner,uint256 value)"); bytes32 constant D = keccak256(abi.encodePacked("EIP712Domain")); bytes32 constant B = keccak256(bytes("abc")); function h() external pure returns(bytes32){ return H; } function d() external pure returns(bytes32){ return D; } function b() external pure returns(bytes32){ return B; } }`,
      [{ sig: 'h()' }, { sig: 'd()' }, { sig: 'b()' }],
    );
  });
});

describe('constant arithmetic accept/reject parity vs solc (already solc-accurate)', () => {
  // solc folds pure constant subexpressions in arbitrary precision, then rejects div/mod-by-zero and
  // any result that does not fit the inferred/expected type. JETH must match (NOT over-accept).
  const reject: [string, string][] = [
    ['overflow vs return type', `class C { get f(): External<u8> { return 255n + 1n; } }`],
    ['div by zero', `class C { get f(): External<u8> { return 5n / 0n; } }`],
    ['mod by zero', `class C { get f(): External<u8> { return 5n % 0n; } }`],
    ['exponent overflow', `class C { get f(): External<u256> { return 2n ** 256n; } }`],
  ];
  for (const [name, src] of reject) {
    it(`rejects: ${name}`, () => expect(jethRejects(src)).toBe(true));
  }
  const accept: [string, string][] = [
    ['200n + 55n fits u8', `class C { get f(): External<u8> { return 200n + 55n; } }`],
    ['2n ** 255n fits u256', `class C { get f(): External<u256> { return 2n ** 255n; } }`],
  ];
  for (const [name, src] of accept) {
    it(`accepts: ${name}`, () => expect(jethAccepts(src)).toBe(true));
  }
});

describe('@payable on internal/private/hidden is rejected (solc parity)', () => {
  // solc: "internal" and "private" functions cannot be payable. is an explicitly-internal fn.
  const reject: [string, string][] = [
    [
      '@payable',
      `@contract class C { @payable v(): u256 { return msg.value; } @external @payable f(): u256 { return this.v(); } }`,
    ],
    ['@payable', `@contract class C { @payable v(): u256 { return 1n; } @external f(): void { this.v(); } }`],
    ['@payable', `@contract class C { @payable v(): u256 { return 1n; } @external f(): void { this.v(); } }`],
  ];
  for (const [name, src] of reject) {
    it(`rejects ${name}`, () => expect(jethRejects(src)).toBe(true));
  }
  // external/public payable must still be accepted.
  it('accepts @external/@external @payable', () => {
    expect(jethAccepts(`class C { f(): Payable<u256> { return msg.value; } }`)).toBe(true);
    expect(jethAccepts(`class C { f(): Payable<u256> { return msg.value; } }`)).toBe(true);
  });
});

describe('fixed-array field of a memory struct local (p.a[i]) read/write vs solc', () => {
  it('value, packed-element, and nested-struct fixed-array fields', async () => {
    await rt(
      `type P = { x: u256; a: Arr<u256,3>; y: u256; }; class C { get f(i: u256, v: u256): External<u256> { let p: P = P(7n, [10n, 20n, 30n], 9n); p.a[i] = v; return p.a[i] + p.x + p.y; } }`,
      `struct P { uint256 x; uint256[3] a; uint256 y; } contract C { function f(uint256 i, uint256 v) external pure returns(uint256){ P memory p = P(7, [uint256(10),20,30], 9); p.a[i] = v; return p.a[i] + p.x + p.y; } }`,
      [
        { sig: 'f(uint256,uint256)', args: W(1n) + W(99n) },
        { sig: 'f(uint256,uint256)', args: W(0n) + W(5n) },
        { sig: 'f(uint256,uint256)', args: W(3n) + W(1n) },
      ],
    );
    await rt(
      `type P = { a: Arr<u8,4>; n: u256; }; class C { get f(i: u256): External<u256> { let p: P = P([1n, 2n, 3n, 4n], 0n); p.a[i] = 200n; return u256(p.a[0n]) + u256(p.a[i]); } }`,
      `struct P { uint8[4] a; uint256 n; } contract C { function f(uint256 i) external pure returns(uint256){ P memory p = P([uint8(1),2,3,4], 0); p.a[i] = 200; return uint256(p.a[0]) + uint256(p.a[i]); } }`,
      [
        { sig: 'f(uint256)', args: W(2n) },
        { sig: 'f(uint256)', args: W(0n) },
      ],
    );
    await rt(
      `type I = { a: Arr<u256,2>; }; type O = { x: u256; inner: I; }; class C { get f(i: u256, v: u256): External<u256> { let o: O = O(5n, I([1n, 2n])); o.inner.a[i] = v; return o.inner.a[i] + o.x; } }`,
      `struct I { uint256[2] a; } struct O { uint256 x; I inner; } contract C { function f(uint256 i, uint256 v) external pure returns(uint256){ O memory o = O(5, I([uint256(1),2])); o.inner.a[i] = v; return o.inner.a[i] + o.x; } }`,
      [
        { sig: 'f(uint256,uint256)', args: W(1n) + W(77n) },
        { sig: 'f(uint256,uint256)', args: W(0n) + W(8n) },
      ],
    );
  });
});

describe('whole storage fixed-array copy via element/mapping/struct-field vs solc', () => {
  it('dyn-array element, mapping value, nested element, and struct field', async () => {
    await rt(
      `class C { a: Arr<u256,2>[]; seed(): External<void> { this.a.push(); this.a.push(); this.a[0n][0n]=11n; this.a[0n][1n]=22n; this.a[1n][0n]=33n; } cp(): External<void> { this.a[1n] = this.a[0n]; } get g(i: u256, j: u256): External<u256> { return this.a[i][j]; } }`,
      `contract C { uint256[2][] a; function seed() external { a.push(); a.push(); a[0][0]=11; a[0][1]=22; a[1][0]=33; } function cp() external { a[1] = a[0]; } function g(uint256 i, uint256 j) external view returns(uint256){ return a[i][j]; } }`,
      [
        { sig: 'seed()' },
        { sig: 'cp()' },
        { sig: 'g(uint256,uint256)', args: W(1n) + W(0n) },
        { sig: 'g(uint256,uint256)', args: W(1n) + W(1n) },
      ],
    );
    await rt(
      `class C { m: mapping<u256,Arr<u256,2>>; seed(): External<void> { this.m[0n][0n]=5n; this.m[0n][1n]=6n; } cp(): External<void> { this.m[1n] = this.m[0n]; } get g(k: u256, j: u256): External<u256> { return this.m[k][j]; } }`,
      `contract C { mapping(uint256=>uint256[2]) m; function seed() external { m[0][0]=5; m[0][1]=6; } function cp() external { m[1] = m[0]; } function g(uint256 k, uint256 j) external view returns(uint256){ return m[k][j]; } }`,
      [
        { sig: 'seed()' },
        { sig: 'cp()' },
        { sig: 'g(uint256,uint256)', args: W(1n) + W(0n) },
        { sig: 'g(uint256,uint256)', args: W(1n) + W(1n) },
      ],
    );
    await rt(
      `type S = { x: u256; arr: Arr<u256,2>; }; class C { e: S; g: S; seed(): External<void> { this.g.arr[0n]=11n; this.g.arr[1n]=22n; } cp(): External<void> { this.e.arr = this.g.arr; } get ge(j: u256): External<u256> { return this.e.arr[j]; } }`,
      `struct S { uint256 x; uint256[2] arr; } contract C { S e; S g; function seed() external { g.arr[0]=11; g.arr[1]=22; } function cp() external { e.arr = g.arr; } function ge(uint256 j) external view returns(uint256){ return e.arr[j]; } }`,
      [{ sig: 'seed()' }, { sig: 'cp()' }, { sig: 'ge(uint256)', args: W(0n) }, { sig: 'ge(uint256)', args: W(1n) }],
    );
  });
});

describe('delete of a memory aggregate local (rebind to fresh zeroed instance) vs solc', () => {
  it('struct, fixed array, and aliasing semantics', async () => {
    await rt(
      `type S = { x: u256; y: u256; }; class C { get f(): External<u256> { let a: S = S(5n, 6n); delete a; return a.x + a.y; } }`,
      `struct S { uint256 x; uint256 y; } contract C { function f() external pure returns(uint256){ S memory a = S(5,6); delete a; return a.x + a.y; } }`,
      [{ sig: 'f()' }],
    );
    await rt(
      `class C { get f(): External<u256> { let a: Arr<u256,3> = [5n, 6n, 7n]; delete a; return a[0n] + a[1n] + a[2n]; } }`,
      `contract C { function f() external pure returns(uint256){ uint256[3] memory a = [uint256(5),6,7]; delete a; return a[0] + a[1] + a[2]; } }`,
      [{ sig: 'f()' }],
    );
    await rt(
      `type S = { x: u256; }; class C { get f(): External<[u256, u256]> { let a: S = S(5n); let b: S = a; delete a; return [a.x, b.x]; } }`,
      `struct S { uint256 x; } contract C { function f() external pure returns(uint256,uint256){ S memory a = S(5); S memory b = a; delete a; return (a.x, b.x); } }`,
      [{ sig: 'f()' }],
    );
  });
});

describe('multi-return with a MEMORY/constructed struct component vs solc', () => {
  it('constructed, local, packed, and mixed-with-dynamic', async () => {
    await rt(
      `type P = { a: u256; b: address; }; class C { get f(): External<[u256, P, bool]> { return [9n, P(1n, address(0x7n)), true]; } }`,
      `struct P { uint256 a; address b; } contract C { function f() external pure returns (uint256, P memory, bool){ return (9, P(1, address(0x7)), true); } }`,
      [{ sig: 'f()' }],
    );
    await rt(
      `type P = { a: u256; b: u256; }; class C { get f(): External<[u256, P]> { let p: P = P(3n, 4n); return [9n, p]; } }`,
      `struct P { uint256 a; uint256 b; } contract C { function f() external pure returns (uint256, P memory){ P memory p = P(3, 4); return (9, p); } }`,
      [{ sig: 'f()' }],
    );
    await rt(
      `type P = { a: u8; b: u16; c: address; }; class C { get f(): External<[P, u256]> { return [P(200n, 50000n, address(0x1n)), 7n]; } }`,
      `struct P { uint8 a; uint16 b; address c; } contract C { function f() external pure returns (P memory, uint256){ return (P(200, 50000, address(0x1)), 7); } }`,
      [{ sig: 'f()' }],
    );
    await rt(
      `type P = { a: u256; }; class C { get f(): External<[P, u256, string]> { return [P(5n), 8n, "hi"]; } }`,
      `struct P { uint256 a; } contract C { function f() external pure returns (P memory, uint256, string memory){ return (P(5), 8, "hi"); } }`,
      [{ sig: 'f()' }],
    );
  });
});

describe('event overloading by signature vs solc', () => {
  it('resolves overloads by arity and by type; exact-dup still rejected', async () => {
    await rt(
      `class C { L: event<{ a: u256 }>; L: event<{ a: u256; b: u256 }>; L: event<{ a: address }>; f(): External<void> { emit(L(1n)); emit(L(2n, 3n)); emit(L(msg.sender)); } }`,
      `contract C { event L(uint256 a); event L(uint256 a, uint256 b); event L(address a); function f() external { emit L(1); emit L(2,3); emit L(msg.sender); } }`,
      [{ sig: 'f()' }],
    );
    expect(jethRejects(`class C { L: event<{ a: u256 }>; L: event<{ a: u256 }>; }`)).toBe(true); // exact-sig duplicate
  });
});

describe('storage bytes index write b[i] = x vs solc', () => {
  const B1 = (h: string) => h.padEnd(64, '0');
  it('short and long bytes, with OOB Panic parity', async () => {
    await rt(
      `class C { b: bytes; init(v: bytes): External<void> { this.b = v; } set(i: u256, x: bytes1): External<void> { this.b[i] = x; } get get(i: u256): External<bytes1> { return this.b[i]; } get all(): External<bytes> { return this.b; } }`,
      `contract C { bytes b; function init(bytes calldata v) external { b = v; } function set(uint256 i, bytes1 x) external { b[i] = x; } function get(uint256 i) external view returns(bytes1){ return b[i]; } function all() external view returns(bytes memory){ return b; } }`,
      [
        { sig: 'init(bytes)', args: W(0x20n) + W(5n) + B1('aabbccddee') },
        { sig: 'set(uint256,bytes1)', args: W(2n) + B1('ff') },
        { sig: 'get(uint256)', args: W(2n) },
        { sig: 'all()' },
        { sig: 'set(uint256,bytes1)', args: W(9n) + B1('11') },
      ],
    );
    await rt(
      `class C { b: bytes; init(v: bytes): External<void> { this.b = v; } set(i: u256, x: bytes1): External<void> { this.b[i] = x; } get all(): External<bytes> { return this.b; } }`,
      `contract C { bytes b; function init(bytes calldata v) external { b = v; } function set(uint256 i, bytes1 x) external { b[i] = x; } function all() external view returns(bytes memory){ return b; } }`,
      [
        { sig: 'init(bytes)', args: W(0x20n) + W(40n) + '00'.repeat(40).padEnd(128, '0') },
        { sig: 'set(uint256,bytes1)', args: W(35n) + B1('ab') },
        { sig: 'set(uint256,bytes1)', args: W(0n) + B1('cd') },
        { sig: 'all()' },
      ],
    );
  });
});

describe('storage bytes .push / .pop vs solc (short<->long transitions)', () => {
  const B1 = (h: string) => h.padEnd(64, '0');
  it('push across 31->32, pop across 32->31, push(), and pop-empty Panic', async () => {
    const calls: { sig: string; args?: string }[] = [
      { sig: 'init(bytes)', args: W(0x20n) + W(30n) + 'aa'.repeat(30).padEnd(64, '0') },
    ];
    for (let i = 0; i < 5; i++) calls.push({ sig: 'pb(bytes1)', args: B1((0x10 + i).toString(16).padStart(2, '0')) }); // 30 -> 35 (crosses 31->32)
    calls.push(
      { sig: 'all()' },
      { sig: 'len()' },
      { sig: 'at(uint256)', args: W(34n) },
      { sig: 'at(uint256)', args: W(0n) },
    );
    for (let i = 0; i < 5; i++) calls.push({ sig: 'pop()' }); // 35 -> 30 (crosses 32->31)
    calls.push({ sig: 'all()' }, { sig: 'len()' });
    calls.push({ sig: 'p0()' }, { sig: 'all()' }); // push() zero byte
    await rt(
      `class C { b: bytes; init(v: bytes): External<void> { this.b = v; } pb(x: bytes1): External<void> { this.b.push(x); } p0(): External<void> { this.b.push(); } pop(): External<void> { this.b.pop(); } get all(): External<bytes> { return this.b; } get len(): External<u256> { return this.b.length; } get at(i: u256): External<bytes1> { return this.b[i]; } }`,
      `contract C { bytes b; function init(bytes calldata v) external { b = v; } function pb(bytes1 x) external { b.push(x); } function p0() external { b.push(); } function pop() external { b.pop(); } function all() external view returns(bytes memory){ return b; } function len() external view returns(uint256){ return b.length; } function at(uint256 i) external view returns(bytes1){ return b[i]; } }`,
      calls,
    );
    // pop on empty -> Panic(0x31) on both
    await rt(
      `class C { b: bytes; pop(): External<void> { this.b.pop(); } }`,
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
      `type D = { x: u256; s: string; }; class C { E: event<{ d: indexed<D>; n: u256 }>; f(): External<void> { emit(E(D(7n,"hi"), 9n)); } }`,
      `struct D { uint256 x; string s; } contract C { event E(D indexed d, uint256 n); function f() external { emit E(D(7,"hi"), 9); } }`,
      [{ sig: 'f()' }],
    ));
  it('long string + bytes + trailing static (multi-word, two dynamic fields)', () =>
    rt(
      `type D = { x: u256; s: string; b: bytes; y: u256; }; class C { E: event<{ d: indexed<D> }>; f(): External<void> { emit(E(D(7n,"${L36}","deadbeef",9n))); } }`,
      `struct D { uint256 x; string s; bytes b; uint256 y; } contract C { event E(D indexed d); function f() external { emit E(D(7,"${L36}","deadbeef",9)); } }`,
      [{ sig: 'f()' }],
    ));
  it('two strings, one empty, one exactly 32 bytes (padding boundary)', () =>
    rt(
      `type D = { a: string; b: string; }; class C { E: event<{ d: indexed<D> }>; f(): External<void> { emit(E(D("","${L32}"))); } }`,
      `struct D { string a; string b; } contract C { event E(D indexed d); function f() external { emit E(D("","${L32}")); } }`,
      [{ sig: 'f()' }],
    ));
  it('dynamic value-array field (struct literal)', () =>
    rt(
      `type D = { x: u256; a: u256[]; }; class C { E: event<{ d: indexed<D> }>; f(a: u256[]): External<void> { emit(E(D(4n, a))); } }`,
      `struct D { uint256 x; uint256[] a; } contract C { event E(D indexed d); function f(uint256[] calldata a) external { emit E(D(4, a)); } }`,
      [{ sig: 'f(uint256[])', args: W(0x20n) + W(3n) + W(5n) + W(6n) + W(7n) }],
    ));
  it('memory-source struct local', () =>
    rt(
      `type D = { x: u256; s: string; }; class C { E: event<{ d: indexed<D> }>; f(): External<void> { let d: D = D(7n,"${L36}"); emit(E(d)); } }`,
      `struct D { uint256 x; string s; } contract C { event E(D indexed d); function f() external { D memory d = D(7,"${L36}"); emit E(d); } }`,
      [{ sig: 'f()' }],
    ));
  it('calldata-source struct param', () =>
    rt(
      `type D = { x: u256; s: string; }; class C { E: event<{ d: indexed<D> }>; g(d: D): External<void> { emit(E(d)); } }`,
      `struct D { uint256 x; string s; } contract C { event E(D indexed d); function g(D calldata d) external { emit E(d); } }`,
      [
        {
          sig: 'g((uint256,string))',
          args: W(7n) + W(0x20n) + W(2n) + Buffer.from('hi').toString('hex').padEnd(64, '0'),
        },
      ],
    ));
  it('mixed: indexed static + indexed dyn struct + non-indexed data word', () =>
    rt(
      `type D = { x: u256; s: string; }; class C { E: event<{ k: indexed<u256>; d: indexed<D>; v: u256 }>; f(): External<void> { emit(E(99n, D(7n,"hi"), 123n)); } }`,
      `struct D { uint256 x; string s; } contract C { event E(uint256 indexed k, D indexed d, uint256 v); function f() external { emit E(99, D(7,"hi"), 123); } }`,
      [{ sig: 'f()' }],
    ));
});

describe('re-sweep over-acceptance fixes (solc rejects, JETH must too)', () => {
  it('a fixed-array literal with the wrong element count is rejected (no silent pad/truncate)', () => {
    expect(
      jethRejects(
        `class C { get f(): External<Arr<u256,3>> { let a: Arr<u256,3> = [1n,2n,3n,4n,5n]; return a; } }`,
      ),
    ).toBe(true);
    expect(
      jethRejects(`class C { get f(): External<Arr<u256,3>> { let a: Arr<u256,3> = [1n,2n]; return a; } }`),
    ).toBe(true);
    expect(
      jethAccepts(
        `class C { get f(): External<Arr<u256,3>> { let a: Arr<u256,3> = [1n,2n,3n]; return a; } }`,
      ),
    ).toBe(true);
  });
  it('enum -> intN cast is rejected for every width (runtime value and member literal)', () => {
    expect(
      jethRejects(
        `enum Color { Red, Green, Blue } class C { get f(c: Color): External<i8> { return i8(c); } }`,
      ),
    ).toBe(true);
    expect(
      jethRejects(
        `enum Color { Red, Green, Blue } class C { get f(): External<i8> { return i8(Color.Blue); } }`,
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        `enum Color { Red, Green, Blue } class C { get f(c: Color): External<u8> { return u8(c); } }`,
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        `enum Color { Red, Green, Blue } class C { get f(c: Color): External<u256> { return u256(c); } }`,
      ),
    ).toBe(true);
  });
  it('@error named Error or Panic is rejected (reserved); a same-named @event is fine', () => {
    expect(
      jethRejects(`class C { Panic: error<{ code: u256 }>; f(): External<void> { revert(Panic(1n)); } }`),
    ).toBe(true);
    expect(
      jethRejects(`class C { Error: error<{ s: string }>; f(): External<void> { revert(Error("x")); } }`),
    ).toBe(true);
    expect(
      jethAccepts(`class C { Panic: event<{ code: u256 }>; f(): External<void> { emit(Panic(1n)); } }`),
    ).toBe(true);
  });
  it('cross-kind identifier collisions are rejected; function/event overloading is allowed', () => {
    expect(
      jethRejects(`class C { X: error<{ a: u256 }>; X: event<{ a: u256 }>; f(): External<void> { revert(X(1n)); } }`),
    ).toBe(true);
    expect(jethRejects(`type X = { a: u256; }; class C { X(): External<void> {} }`)).toBe(true);
    expect(jethRejects(`class C { x: u256; x(): External<void> {} }`)).toBe(true);
    expect(jethRejects(`enum X { A, B } class C { X: event<{ a: u256 }>; f(): External<void> {} }`)).toBe(true);
    expect(jethAccepts(`class C { f(): External<void> {} f(a: u256): External<void> {} }`)).toBe(true);
    expect(
      jethAccepts(`class C { E: event<{ a: u256 }>; E: event<{ b: bool }>; f(): External<void> { emit(E(1n)); } }`),
    ).toBe(true);
  });
});

describe('re-sweep over-rejection fixes: hex literal -> bytesN + rational @constant', () => {
  it('an exact-width hex literal converts to bytesN (left-aligned), byte-identical to solc', () =>
    rt(
      `class C { static B: bytes4 = 0x12345678n; get f(): External<bytes4> { return 0x12345678n; } get g(): External<bytes4> { return this.B; } get h(x: bytes4): External<bool> { return x == 0x12345678n; } get e(a: u256): External<bytes> { return abi.encodeWithSelector(0x12345678n, a); } }`,
      `contract C { bytes4 constant B=0x12345678; function f() external pure returns(bytes4){ return 0x12345678; } function g() external pure returns(bytes4){ return B; } function h(bytes4 x) external pure returns(bool){ return x==0x12345678; } function e(uint256 a) external pure returns(bytes memory){ return abi.encodeWithSelector(0x12345678, a); } }`,
      [
        { sig: 'f()' },
        { sig: 'g()' },
        { sig: 'h(bytes4)', args: '12345678'.padEnd(64, '0') },
        { sig: 'e(uint256)', args: W(99n) },
      ],
    ));
  it('a wrong-width hex literal still needs an explicit cast (parity: both reject)', () => {
    expect(jethRejects(`class C { get f(): External<bytes4> { return 0x1234n; } }`)).toBe(true);
    expect(solcRejects(`contract C { function f() external pure returns(bytes4){ return 0x1234; } }`)).toBe(true);
  });
  it('a @constant / @state with a fractional intermediate folds rationally (byte-identical to solc)', () =>
    rt(
      `class C { static K: u256 = (10n/4n)*4n; x: u256 = ((3n/2n)*2n)**3n; get a(): External<u256> { return this.K; } get b(): External<u256> { return this.x; } }`,
      `contract C { uint256 constant K=(10/4)*4; uint256 x=((3/2)*2)**3; function a() external view returns(uint256){ return K; } function b() external view returns(uint256){ return x; } }`,
      [{ sig: 'a()' }, { sig: 'b()' }],
    ));
  it('constant div/mod by zero and a fractional final value are rejected (parity)', () => {
    expect(
      jethRejects(`class C { static K: u256 = 5n/0n; get f(): External<u256> { return this.K; } }`),
    ).toBe(true);
    expect(
      jethRejects(`class C { static K: u256 = 7n/2n; get f(): External<u256> { return this.K; } }`),
    ).toBe(true);
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
      `type D = { x: u256; data: bytes; }; class C { d: D; init(v: bytes): External<void> { this.d.data = v; } p(b: bytes1): External<void> { this.d.data.push(b); } pop(): External<void> { this.d.data.pop(); } s(i: u256, x: bytes1): External<void> { this.d.data[i] = x; } get get(): External<bytes> { return this.d.data; } }`,
      `contract C { struct D{uint256 x;bytes data;} D d; function init(bytes calldata v) external { d.data=v; } function p(bytes1 b) external { d.data.push(b); } function pop() external { d.data.pop(); } function s(uint256 i,bytes1 x) external { d.data[i]=x; } function get() external view returns(bytes memory){ return d.data; } }`,
      c,
    );
  });
  it('mapping(u256=>bytes) value .push / [i]=x byte-identical', async () => {
    const c: { sig: string; args?: string }[] = [
      { sig: 'init(uint256,bytes)', args: W(7n) + W(0x40n) + W(30n) + 'bb'.repeat(30).padEnd(64, '0') },
    ];
    for (let i = 0; i < 4; i++)
      c.push({ sig: 'p(uint256,bytes1)', args: W(7n) + B1((0x20 + i).toString(16).padStart(2, '0')) });
    c.push({ sig: 's(uint256,uint256,bytes1)', args: W(7n) + W(2n) + B1('ff') }, { sig: 'get(uint256)', args: W(7n) });
    await rt(
      `class C { m: mapping<u256, bytes>; init(k: u256, v: bytes): External<void> { this.m[k] = v; } p(k: u256, b: bytes1): External<void> { this.m[k].push(b); } s(k: u256, i: u256, x: bytes1): External<void> { this.m[k][i] = x; } get get(k: u256): External<bytes> { return this.m[k]; } }`,
      `contract C { mapping(uint256=>bytes) m; function init(uint256 k,bytes calldata v) external { m[k]=v; } function p(uint256 k,bytes1 b) external { m[k].push(b); } function s(uint256 k,uint256 i,bytes1 x) external { m[k][i]=x; } function get(uint256 k) external view returns(bytes memory){ return m[k]; } }`,
      c,
    );
  });
  it('bytes[] element and Arr<bytes,N> element .push byte-identical', async () => {
    const c: { sig: string; args?: string }[] = [{ sig: 'init(bytes)', args: initB(30) }];
    for (let i = 0; i < 4; i++)
      c.push({ sig: 'p(uint256,bytes1)', args: W(0n) + B1((0x30 + i).toString(16).padStart(2, '0')) });
    c.push({ sig: 'get(uint256)', args: W(0n) });
    await rt(
      `class C { a: bytes[]; init(v: bytes): External<void> { this.a.push(v); } p(i: u256, b: bytes1): External<void> { this.a[i].push(b); } get get(i: u256): External<bytes> { return this.a[i]; } }`,
      `contract C { bytes[] a; function init(bytes calldata v) external { a.push(v); } function p(uint256 i,bytes1 b) external { a[i].push(b); } function get(uint256 i) external view returns(bytes memory){ return a[i]; } }`,
      c,
    );
  });
  it('pop on empty struct.bytes Panics (0x31) like solc', () =>
    rt(
      `type D = { x: u256; data: bytes; }; class C { d: D; pop(): External<void> { this.d.data.pop(); } }`,
      `contract C { struct D{uint256 x;bytes data;} D d; function pop() external { d.data.pop(); } }`,
      [{ sig: 'pop()' }],
    ));
});

describe('re-sweep batch 2: bytes(string)[i] / nested ctor / fixed-array copy / @error aggregates vs solc', () => {
  const strArg = (s: string) => W(0x20n) + W(BigInt(s.length)) + Buffer.from(s).toString('hex').padEnd(64, '0');
  it('bytes(string)[i] byte-indexes the reinterpreted value (calldata / storage / memory)', () =>
    rt(
      `class C { s: string; set(v: string): External<void> { this.s = v; } get atStore(i: u256): External<bytes1> { return bytes(this.s)[i]; } get atCd(t: string, i: u256): External<bytes1> { return bytes(t)[i]; } get atMem(t: string, i: u256): External<bytes1> { let m: string = t; return bytes(m)[i]; } }`,
      `contract C { string s; function set(string calldata v) external { s=v; } function atStore(uint256 i) external view returns(bytes1){ return bytes(s)[i]; } function atCd(string calldata t,uint256 i) external pure returns(bytes1){ return bytes(t)[i]; } function atMem(string calldata t,uint256 i) external pure returns(bytes1){ string memory m=t; return bytes(m)[i]; } }`,
      [
        { sig: 'set(string)', args: strArg('hello world') },
        { sig: 'atStore(uint256)', args: W(4n) },
        { sig: 'atCd(string,uint256)', args: strArg('abcdef') + '' },
        { sig: 'atCd(string,uint256)', args: strArg('abcdef') },
        { sig: 'atMem(string,uint256)', args: strArg('xyz123') },
      ],
    ));
  it('nested inline struct constructor in a return position (positional), incl. deep nesting', () =>
    rt(
      `type Inner = { c: u8; v: u32; }; type Outer = { id: u16; inner: Inner; }; type A = { x: u8; }; type B = { a: A; y: u16; }; type D = { b: B; z: u32; }; class C { get f(id: u16, c: u8, v: u32): External<Outer> { return Outer(id, Inner(c, v)); } get g(): External<D> { return D(B(A(5n), 6n), 7n); } }`,
      `struct Inner{uint8 c;uint32 v;} struct Outer{uint16 id;Inner inner;} struct A{uint8 x;} struct B{A a;uint16 y;} struct D{B b;uint32 z;} contract C { function f(uint16 id,uint8 c,uint32 v) external pure returns(Outer memory){ return Outer(id,Inner(c,v)); } function g() external pure returns(D memory){ return D(B(A(5),6),7); } }`,
      [{ sig: 'f(uint16,uint8,uint32)', args: W(0x102n) + W(7n) + W(0xcafen) }, { sig: 'g()' }],
    ));
  it('whole memory / calldata fixed-array -> storage assignment (incl. packed elements)', () =>
    rt(
      `class C { g: Arr<u256,3>; h: Arr<u64,4>; a(): External<u256> { let m: Arr<u256,3> = [111n,222n,333n]; this.g = m; return this.g[2n]; } b(x: Arr<u256,3>): External<u256> { this.g = x; return this.g[1n]; } c(): External<u64> { let m: Arr<u64,4> = [1n,2n,3n,4n]; this.h = m; return this.h[3n]; } }`,
      `contract C { uint256[3] g; uint64[4] h; function a() external returns(uint256){ uint256[3] memory m=[uint256(111),222,333]; g=m; return g[2]; } function b(uint256[3] calldata x) external returns(uint256){ g=x; return g[1]; } function c() external returns(uint64){ uint64[4] memory m=[uint64(1),2,3,4]; h=m; return h[3]; } }`,
      [{ sig: 'a()' }, { sig: 'b(uint256[3])', args: W(5n) + W(6n) + W(7n) }, { sig: 'c()' }],
    ));
  it('@error with static struct / fixed-array / mixed params reverts byte-identically', () =>
    rt(
      `type P = { x: u256; y: bool; }; class C { BadS: error<{ p: P }>; BadA: error<{ a: Arr<u256, 2> }>; BadMix: error<{ n: u256; p: P; s: bytes }>; fs(): External<void> { revert(BadS(P(42n, true))); } fa(): External<void> { let x: Arr<u256,2> = [5n,6n]; revert(BadA(x)); } fm(): External<void> { revert(BadMix(9n, P(1n, true), "hello")); } }`,
      `contract C { struct P{uint256 x;bool y;} error BadS(P p); error BadA(uint256[2] a); error BadMix(uint256 n, P p, bytes s); function fs() external { revert BadS(P(42,true)); } function fa() external { uint256[2] memory x=[uint256(5),6]; revert BadA(x); } function fm() external { revert BadMix(9, P(1,true), "hello"); } }`,
      [{ sig: 'fs()' }, { sig: 'fa()' }, { sig: 'fm()' }],
    ));
});

describe('re-sweep batch 3: object literals, internal aggregate params, Arr<dynElem,N>[] vs solc', () => {
  const strArg = (s: string) =>
    W(0x20n) +
    W(BigInt(s.length)) +
    Buffer.from(s)
      .toString('hex')
      .padEnd(Math.ceil(s.length / 32) * 64 || 64, '0');
  const LONG = 'abcdefghijklmnopqrstuvwxyz0123456789';
  it('object-literal struct construction with nested struct / bytes / fixed-array fields', () =>
    rt(
      `type In = { c: u8; v: u32; }; type O = { id: u16; inner: In; }; type Db = { x: u256; s: bytes; }; type Da = { x: u256; a: Arr<u256,2>; }; class C { get f(): External<O> { return { id: 1n, inner: In(2n, 3n) }; } get gb(): External<Db> { return { x: 9n, s: "hi" }; } get ga(): External<Da> { return { x: 7n, a: [4n, 5n] }; } }`,
      `struct In{uint8 c;uint32 v;} struct O{uint16 id;In inner;} struct Db{uint256 x;bytes s;} struct Da{uint256 x;uint256[2] a;} contract C { function f() external pure returns(O memory){ return O({id:1, inner:In(2,3)}); } function gb() external pure returns(Db memory){ return Db({x:9, s:"hi"}); } function ga() external pure returns(Da memory){ return Da({x:7, a:[uint256(4),5]}); } }`,
      [{ sig: 'f()' }, { sig: 'gb()' }, { sig: 'ga()' }],
    ));
  it('object-literal spread keeps value fields; a non-value field must be explicit (not spread)', () => {
    expect(
      jethAccepts(
        `type P = { a: u256; b: u256; }; class C { get f(p: P): External<P> { return { ...p, a: 9n }; } }`,
      ),
    ).toBe(true);
    expect(
      jethRejects(
        `type In = { c: u8; }; type O = { id: u256; inner: In; }; class C { get f(o: O): External<O> { return { ...o, id: 1n }; } }`,
      ),
    ).toBe(true);
  });
  it('internal call: struct + fixed-array params/return + calldata aggregate forwarding (byte-identical)', () =>
    rt(
      `type P = { a: u8; b: u32; }; class C { gs(p: P): u32 { return p.b; } ga(a: Arr<u256,3>): u256 { return a[2n]; } mk(): Arr<u256,2> { return [9n, 8n]; } get fs(x: u8, y: u32): External<u32> { return gs(P(x, y)); } get fa(): External<u256> { return ga([10n,20n,30n]); } get fr(): External<u256> { let a: Arr<u256,2> = mk(); return a[0n] + a[1n]; } get fwd(x: P): External<u32> { return gs(x); } }`,
      `contract C { struct P{uint8 a;uint32 b;} function gs(P memory p) internal pure returns(uint32){return p.b;} function ga(uint256[3] memory a) internal pure returns(uint256){return a[2];} function mk() internal pure returns(uint256[2] memory){return [uint256(9),8];} function fs(uint8 x,uint32 y) external pure returns(uint32){ return gs(P(x,y)); } function fa() external pure returns(uint256){ return ga([uint256(10),20,30]); } function fr() external pure returns(uint256){ uint256[2] memory a=mk(); return a[0]+a[1]; } function fwd(P calldata x) external pure returns(uint32){ return gs(x); } }`,
      [
        { sig: 'fs(uint8,uint32)', args: W(7n) + W(0xcafen) },
        { sig: 'fa()' },
        { sig: 'fr()' },
        { sig: 'fwd((uint8,uint32))', args: W(1n) + W(2n) },
      ],
    ));
  it('@external aggregate internal call stays a clean rejection (broader dual-entry feature)', () => {
    expect(
      jethRejects(
        `type P = { a: u8; }; class C { get g(p: P): External<u8> { return p.a; } get f(): External<u8> { return g(P(5n)); } }`,
      ),
    ).toBe(true);
  });
  it('bare @state Arr<string,N>[] / Arr<bytes,N>[]: push/set/get/pop deep-clear/delete byte-identical', async () => {
    const calls: { sig: string; args?: string }[] = [{ sig: 'grow()' }, { sig: 'grow()' }, { sig: 'len()' }];
    calls.push({ sig: 's(uint256,uint256,string)', args: W(0n) + W(1n) + strArg('hi') });
    calls.push({ sig: 's(uint256,uint256,string)', args: W(1n) + W(0n) + strArg(LONG) });
    calls.push({ sig: 'g(uint256,uint256)', args: W(0n) + W(1n) }, { sig: 'g(uint256,uint256)', args: W(1n) + W(0n) });
    calls.push({ sig: 'pop()' }, { sig: 'grow()' }, { sig: 'g(uint256,uint256)', args: W(1n) + W(0n) }); // re-grown -> empty (deep-clear)
    calls.push({ sig: 'del()' }, { sig: 'len()' });
    await rt(
      `class C { a: Arr<string,3>[]; grow(): External<void> { this.a.push(); } pop(): External<void> { this.a.pop(); } del(): External<void> { delete this.a; } s(i: u256, j: u256, v: string): External<void> { this.a[i][j] = v; } get g(i: u256, j: u256): External<string> { return this.a[i][j]; } get len(): External<u256> { return this.a.length; } }`,
      `contract C { string[3][] a; function grow() external { a.push(); } function pop() external { a.pop(); } function del() external { delete a; } function s(uint256 i,uint256 j,string calldata v) external { a[i][j]=v; } function g(uint256 i,uint256 j) external view returns(string memory){ return a[i][j]; } function len() external view returns(uint256){ return a.length; } }`,
      calls,
    );
  });
});

describe('remaining over-rejections R1/R3/R5 vs solc (byte-identical)', () => {
  it('R3: a dynamic struct with a static fixed-array field (return + storage roundtrip)', () =>
    rt(
      `type D = { x: u256; s: bytes; a: Arr<u256,2>; }; class C { d: D; get f(): External<D> { return D(9n, "hello", [4n,5n]); } set(): External<void> { this.d = D(1n, "stored value here, fairly long!!", [7n,8n]); } get ga(i: u256): External<u256> { return this.d.a[i]; } get gs(): External<bytes> { return this.d.s; } }`,
      `struct D{uint256 x;bytes s;uint256[2] a;} contract C { D d; function f() external pure returns(D memory){ return D(9,"hello",[uint256(4),5]); } function set() external { d=D(1,"stored value here, fairly long!!",[uint256(7),8]); } function ga(uint256 i) external view returns(uint256){ return d.a[i]; } function gs() external view returns(bytes memory){ return d.s; } }`,
      [
        { sig: 'f()' },
        { sig: 'set()' },
        { sig: 'ga(uint256)', args: W(0n) },
        { sig: 'ga(uint256)', args: W(1n) },
        { sig: 'gs()' },
      ],
    ));
  it('R1: struct/fixed-array field from a non-inline source (local/param/storage) in return/let/storage', () =>
    rt(
      `type I = { a: u256; b: u32; }; type O = { i: I; y: u256; }; type A = { x: u256; arr: Arr<u256,2>; }; class C { o: O; src: I; get fLocal(y: u256): External<O> { let z: I = I(7n, 8n); return O(z, y); } get fParam(z: I, y: u256): External<O> { return O(z, y); } get fArr(x: u256): External<A> { let z: Arr<u256,2> = [1n,2n]; return A(x, z); } seed(): External<void> { this.src = I(11n, 22n); } setO(): External<void> { let z: I = I(3n, 4n); this.o = O(z, 99n); } get ga(): External<u256> { return this.o.i.a; } get fStore(y: u256): External<O> { return O(this.src, y); } }`,
      `struct I{uint256 a;uint32 b;} struct O{I i;uint256 y;} struct A{uint256 x;uint256[2] arr;} contract C { O o; I src; function fLocal(uint256 y) external pure returns(O memory){ I memory z=I(7,8); return O(z,y); } function fParam(I calldata z,uint256 y) external pure returns(O memory){ return O(z,y); } function fArr(uint256 x) external pure returns(A memory){ uint256[2] memory z=[uint256(1),2]; return A(x,z); } function seed() external { src=I(11,22); } function setO() external { I memory z=I(3,4); o=O(z,99); } function ga() external view returns(uint256){ return o.i.a; } function fStore(uint256 y) external view returns(O memory){ return O(src,y); } }`,
      [
        { sig: 'fLocal(uint256)', args: W(5n) },
        { sig: 'fParam((uint256,uint32),uint256)', args: W(1n) + W(2n) + W(5n) },
        { sig: 'fArr(uint256)', args: W(9n) },
        { sig: 'seed()' },
        { sig: 'setO()' },
        { sig: 'ga()' },
        { sig: 'fStore(uint256)', args: W(7n) },
      ],
    ));
  it('R5: msg.value in an internal function is allowed (forwarded byte-identical); externally requires @payable', () => {
    expect(
      jethAccepts(
        `class C { h(): u256 { return msg.value; } f(): Payable<u256> { return this.h(); } }`,
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        `class C { h(): u256 { return msg.value; } f(): Payable<u256> { return this.h(); } }`,
      ),
    ).toBe(true);
    // internal (unmarked) reading msg.value directly is allowed (forwarded byte-identical)
    expect(jethAccepts(`class C { bad(): u256 { return msg.value; } }`)).toBe(true);
    // external non-payable reading msg.value directly still requires @payable -> rejected
    expect(jethRejects(`class C { get bad(): External<u256> { return msg.value; } }`)).toBe(true);
    // external non-payable reading msg.value rejected; @pure internal rejected (env read)
    expect(jethRejects(`class C { get f(): External<u256> { return msg.value; } }`)).toBe(true);
    expect(
      jethRejects(
        `@contract class C { @pure h(): u256 { return msg.value; } @external f(): u256 { return this.h(); } }`,
      ),
    ).toBe(true);
  });
});

describe('R4: Arr<dynElem,N>[] as a calldata param / whole-array return vs solc', () => {
  const strArg = (s: string) =>
    W(0x20n) +
    W(BigInt(s.length)) +
    Buffer.from(s)
      .toString('hex')
      .padEnd(Math.ceil(s.length / 32) * 64 || 64, '0');
  const strBlk = (s: string) =>
    W(BigInt(s.length)) +
    Buffer.from(s)
      .toString('hex')
      .padEnd(Math.ceil(s.length / 32) * 64 || 64, '0');
  it('calldata string[3][] param: length + a[i][j] byte-identical', async () => {
    // a = [["a","bb","ccc"]] : outer [off=0x20][len=1][elemOff=0x20] then elem [3 offsets][3 blocks]
    const elem = W(0x60n) + W(0x120n) + W(0x180n) + strBlk('a') + strBlk('bb') + strBlk('ccc');
    const cd = W(0x20n) + W(1n) + W(0x20n) + elem;
    await rt(
      `class C { get len(a: Arr<string,3>[]): External<u256> { return a.length; } get at(a: Arr<string,3>[], i: u256, j: u256): External<string> { return a[i][j]; } }`,
      `contract C { function len(string[3][] calldata a) external pure returns(uint256){ return a.length; } function at(string[3][] calldata a,uint256 i,uint256 j) external pure returns(string memory){ return a[i][j]; } }`,
      [
        { sig: 'len(string[3][])', args: cd },
        { sig: 'at(string[3][],uint256,uint256)', args: W(0x60n) + W(0n) + W(2n) + cd.slice(2) },
      ],
    );
  });
  it('whole storage Arr<string,3>[] / Arr<bytes,2>[] return byte-identical', async () => {
    await rt(
      `class C { a: Arr<string,3>[]; grow(): External<void> { this.a.push(); } s(i: u256, j: u256, v: string): External<void> { this.a[i][j] = v; } get r(): External<Arr<string,3>[]> { return this.a; } }`,
      `contract C { string[3][] a; function grow() external { a.push(); } function s(uint256 i,uint256 j,string calldata v) external { a[i][j]=v; } function r() external view returns(string[3][] memory){ return a; } }`,
      [
        { sig: 'grow()' },
        { sig: 'grow()' },
        { sig: 's(uint256,uint256,string)', args: W(0n) + W(1n) + strArg('hi') },
        { sig: 's(uint256,uint256,string)', args: W(1n) + W(0n) + strArg('a fairly long string crossing 32!!') },
        { sig: 'r()' },
      ],
    );
  });
  // VARIABLE-LENGTH nested string arrays via calldata. (A prior version navigated outer elements with a
  // CONTIGUOUS stride - correct only for equal-length elements - which silently miscompiled; these use
  // intentionally unequal lengths so contiguous-vs-offset-table navigation must differ.)
  const encStr = (s: string) =>
    W(BigInt(s.length)) +
    Buffer.from(s)
      .toString('hex')
      .padEnd((Math.ceil(s.length / 32) || 0) * 64, '0');
  const block = (parts: string[]) => {
    const offs: string[] = [];
    let cur = parts.length * 32;
    for (const p of parts) {
      offs.push(W(BigInt(cur)));
      cur += p.length / 2;
    }
    return offs.join('') + parts.join('');
  };
  it('string[3][] (single-level) variable-length a[i][j] + OOB byte-identical', async () => {
    const aBody =
      W(2n) +
      block([
        block(['aa', 'b', 'cccccc'].map(encStr)),
        block(['d', 'this-one-is-quite-a-bit-longer!!!', 'f'].map(encStr)),
      ]); // [len][offset table + tails]
    const at = (i: bigint, j: bigint) => ({
      sig: 'at(string[3][],uint256,uint256)',
      args: W(0x60n) + W(i) + W(j) + aBody,
    }); // head: [off_a=0x60][i][j]
    await rt(
      `class C { get at(a: Arr<string,3>[], i: u256, j: u256): External<string> { return a[i][j]; } get len(a: Arr<string,3>[]): External<u256> { return a.length; } }`,
      `contract C { function at(string[3][] calldata a,uint256 i,uint256 j) external pure returns(string memory){ return a[i][j]; } function len(string[3][] calldata a) external pure returns(uint256){ return a.length; } }`,
      [
        at(0n, 0n),
        at(1n, 1n),
        at(0n, 2n),
        at(1n, 0n),
        at(0n, 3n),
        at(2n, 0n),
        { sig: 'len(string[3][])', args: W(0x20n) + aBody },
      ],
    );
  });
  it('string[2][3][] (double-level) variable-length a[i][j][k] + OOB + whole-array echo byte-identical', async () => {
    const enc23 = (a: string[][]) => block(a.map((p) => block(p.map(encStr)))); // string[2][3]
    const val = [
      [
        ['a0', 'b1longer'],
        ['c2', 'd3'],
        ['e4', 'f5'],
      ],
      [
        ['g6', ''],
        ['', 'k10longeryes'],
        ['l11', 'm12'],
      ],
    ];
    const aBody = W(BigInt(val.length)) + block(val.map(enc23)); // [len][table + per-element string[2][3] blocks]
    const at = (i: bigint, j: bigint, k: bigint) => ({
      sig: 'at(string[2][3][],uint256,uint256,uint256)',
      args: W(0x80n) + W(i) + W(j) + W(k) + aBody,
    });
    await rt(
      `class C { get at(a: Arr<Arr<string,2>,3>[], i: u256, j: u256, k: u256): External<string> { return a[i][j][k]; } get len(a: Arr<Arr<string,2>,3>[]): External<u256> { return a.length; } get echo(a: Arr<Arr<string,2>,3>[]): External<Arr<Arr<string,2>,3>[]> { return a; } }`,
      `contract C { function at(string[2][3][] calldata a,uint256 i,uint256 j,uint256 k) external pure returns(string memory){ return a[i][j][k]; } function len(string[2][3][] calldata a) external pure returns(uint256){ return a.length; } function echo(string[2][3][] calldata a) external pure returns(string[2][3][] memory){ return a; } }`,
      [
        at(0n, 0n, 1n),
        at(1n, 1n, 1n),
        at(1n, 2n, 0n),
        at(0n, 2n, 0n),
        at(0n, 3n, 0n),
        at(0n, 0n, 2n),
        { sig: 'len(string[2][3][])', args: W(0x20n) + aBody },
        { sig: 'echo(string[2][3][])', args: W(0x20n) + aBody },
      ],
    );
  });
});

describe('dynamic nested struct field from a non-inline (side-effect-free) source vs solc', () => {
  it('local / calldata-param / bytes-field dynamic struct copied into a parent struct (byte-identical)', () =>
    rt(
      `type Inner = { p: u256; s: string; }; type Outer = { x: u256; inner: Inner; };
       type IB = { a: u256; b: bytes; c: u256; }; type OB = { inner: IB; tail: u256; };
       class C {
         get fLocal(): External<Outer> { let z: Inner = Inner(1n, "a fairly long string value here!!"); return Outer(2n, z); }
         get fParam(z: Inner): External<Outer> { return Outer(2n, z); }
         get fBytes(): External<OB> { let z: IB = IB(9n, "deadbeefdeadbeef", 8n); return OB(z, 5n); }
       }`,
      `struct Inner { uint256 p; string s; } struct Outer { uint256 x; Inner inner; }
       struct IB { uint256 a; bytes b; uint256 c; } struct OB { IB inner; uint256 tail; }
       contract C {
         function fLocal() external pure returns(Outer memory){ Inner memory z = Inner(1, "a fairly long string value here!!"); return Outer(2, z); }
         function fParam(Inner calldata z) external pure returns(Outer memory){ return Outer(2, z); }
         function fBytes() external pure returns(OB memory){ IB memory z = IB(9, "deadbeefdeadbeef", 8); return OB(z, 5); }
       }`,
      [
        { sig: 'fLocal()' },
        {
          sig: 'fParam((uint256,string))',
          args: W(0x20n) + W(7n) + W(0x40n) + W(2n) + Buffer.from('hi').toString('hex').padEnd(64, '0'),
        },
        { sig: 'fBytes()' },
      ],
    ));
  it('a function-call source (side-effecting) is still rejected (no double-eval)', () => {
    // a non-inline source that is a CALL is rejected (would re-evaluate); must bind to a local first.
    expect(
      jethRejects(
        `type I = { p: u256; s: string; }; type O = { i: I; }; class C { mk(): I { return I(1n,"x"); } get f(): External<O> { return O(mk()); } }`,
      ),
    ).toBe(true);
  });
});

describe('all-issues sweep: miscompile + over-accepts + easy over-rejects vs solc', () => {
  it('[1] pop() deep-clears a popped dynamic-array element (no stale inner data) - raw slots byte-identical', async () => {
    // unequal inner lengths so a header-only clear leaves distinct stale data; re-grow must read 0.
    const seq: { sig: string; args?: string }[] = [
      { sig: 'grow()' },
      { sig: 'grow()' },
      { sig: 'add(uint256,uint256)', args: W(0n) + W(1n) },
      { sig: 'add(uint256,uint256)', args: W(0n) + W(2n) },
      { sig: 'add(uint256,uint256)', args: W(0n) + W(3n) },
      { sig: 'add(uint256,uint256)', args: W(1n) + W(4n) },
      { sig: 'add(uint256,uint256)', args: W(1n) + W(5n) },
      { sig: 'pop()' },
      { sig: 'grow()' },
      { sig: 'ilen(uint256)', args: W(1n) },
    ];
    await rt(
      `class C { xs: u256[][]; grow(): External<void> { this.xs.push(); } add(i: u256, v: u256): External<void> { this.xs[i].push(v); } pop(): External<void> { this.xs.pop(); } get ilen(i: u256): External<u256> { return this.xs[i].length; } get at(i: u256, j: u256): External<u256> { return this.xs[i][j]; } }`,
      `contract C { uint256[][] xs; function grow() external { xs.push(); } function add(uint256 i,uint256 v) external { xs[i].push(v); } function pop() external { xs.pop(); } function ilen(uint256 i) external view returns(uint256){ return xs[i].length; } function at(uint256 i,uint256 j) external view returns(uint256){ return xs[i][j]; } }`,
      seq,
    );
  });
  it('over-accepts now rejected (match solc): ternary dead-arm error, duplicate names, duplicate signature', () => {
    expect(
      jethRejects(
        `class C { static K: u256 = false ? (1n/0n) : 5n; get k(): External<u256> { return this.K; } }`,
      ),
    ).toBe(true); // [2]
    expect(
      jethRejects(
        `class C { static K: u8 = false ? 9999n : 5n; get k(): External<u8> { return this.K; } }`,
      ),
    ).toBe(true); // [2] dead-arm overflow
    expect(
      jethAccepts(
        `class C { static K: u256 = true ? 5n : 6n; get k(): External<u256> { return this.K; } }`,
      ),
    ).toBe(true); // [2] control
    expect(
      jethRejects(`class C { E: event<{ a: u256; a: u256 }>; f(): External<void> { emit(E(1n,2n)); } }`),
    ).toBe(true); // [3]
    expect(
      jethRejects(`class C { E: error<{ a: u256; a: u256 }>; f(): External<void> { revert(E(1n,2n)); } }`),
    ).toBe(true); // [3]
    expect(
      jethRejects(
        `type D = { a: u256; a: u256 }; class C { get f(): External<u256> { return D(1n,2n).a; } }`,
      ),
    ).toBe(true); // [3]
    expect(
      jethRejects(
        `class C { f(x: u256): u256 { return x; } f(x: u256): u256 { return x+1n; } get g(): External<u256> { return 0n; } }`,
      ),
    ).toBe(true); // [4]
    expect(
      jethAccepts(
        `class C { a(x: u256): u256 { return x; } a(x: u256, y: u256): u256 { return x+y; } get g(): External<u256> { return a(1n)+a(2n,3n); } }`,
      ),
    ).toBe(true); // [4] valid overload
  });
  it('[14] bytes/string of a string literal; [17] bytesN.length is the constant N (byte-identical)', async () => {
    await rt(
      `class C { get b(): External<bytes> { return bytes("abc"); } get s(): External<string> { return string("hello world"); } get l32(v: bytes32): External<u256> { return v.length; } get l4(v: bytes4): External<u256> { return v.length; } }`,
      `contract C { function b() external pure returns(bytes memory){ return bytes("abc"); } function s() external pure returns(string memory){ return string("hello world"); } function l32(bytes32 v) external pure returns(uint256){ return v.length; } function l4(bytes4 v) external pure returns(uint256){ return v.length; } }`,
      [{ sig: 'b()' }, { sig: 's()' }, { sig: 'l32(bytes32)', args: W(0xabn) }, { sig: 'l4(bytes4)', args: W(0n) }],
    );
  });
});

describe('sweep batch 2 over-rejections (byte-identical to solc)', () => {
  it('#9 ternary over a dynamic-field struct, bound to a local (return whole struct)', async () => {
    await rt(
      `type P = { a: u256; s: string; }; class C { get pick(b: bool): External<P> { let x: P = P(1n,"xx"); let y: P = P(2n,"yyyyyyyyyyyy"); let p: P = b ? x : y; return p; } }`,
      `contract C { struct P { uint256 a; string s; } function pick(bool b) external pure returns(P memory){ P memory x=P(1,"xx"); P memory y=P(2,"yyyyyyyyyyyy"); P memory p=b?x:y; return p; } }`,
      [
        { sig: 'pick(bool)', args: W(0n) },
        { sig: 'pick(bool)', args: W(1n) },
      ],
    );
  });

  it('#8 emit a STORAGE dynamic value-array argument (log data byte-identical)', async () => {
    await rt(
      `class C { nums: u256[]; E: event<{ a: u256[] }>; add(v: u256): External<void> { this.nums.push(v); } fire(): External<void> { emit(E(this.nums)); } }`,
      `contract C { uint256[] nums; event E(uint256[] a); function add(uint256 v) external { nums.push(v); } function fire() external { emit E(nums); } }`,
      [
        { sig: 'add(uint256)', args: W(11n) },
        { sig: 'add(uint256)', args: W(22n) },
        { sig: 'add(uint256)', args: W(33n) },
        { sig: 'fire()' },
      ],
    );
  });

  it('#15 emit a MEMORY-local dynamic array argument (log data byte-identical)', async () => {
    await rt(
      `class C { E: event<{ a: u256[] }>; f(p: u256[]): External<void> { const a: u256[] = p; emit(E(a)); } }`,
      `contract C { event E(uint256[] a); function f(uint256[] calldata p) external { uint256[] memory a = p; emit E(a); } }`,
      [{ sig: 'f(uint256[])', args: W(0x20n) + W(3n) + W(11n) + W(22n) + W(33n) }],
    );
  });

  it('#10 memory dynamic-struct local as a multi-return tuple component', async () => {
    await rt(
      `type P = { a: u256; s: string; }; class C { get f(): External<[u256, P]> { let p: P = P(7n, "hello world!!"); return [9n, p]; } }`,
      `contract C { struct P { uint256 a; string s; } function f() external pure returns(uint256, P memory){ P memory p=P(7,"hello world!!"); return (9, p); } }`,
      [{ sig: 'f()' }],
    );
  });

  it('#19 inline dynamic-array literal as a multi-return tuple component', async () => {
    await rt(
      `class C { get f(): External<[u256, u256[]]> { return [1n, [7n, 8n, 9n]]; } }`,
      `contract C { function f() external pure returns(uint256, uint256[] memory){ uint256[] memory a = new uint256[](3); a[0]=7;a[1]=8;a[2]=9; return (1, a); } }`,
      [{ sig: 'f()' }],
    );
  });

  it('calldata struct-array-element access cluster now ACCEPTS (byte-identity in dyn-struct-array fuzz suites)', () => {
    // #5 field through an indexed struct-array FIELD; #6 fixed-array field of a dyn-struct param;
    // #7 whole struct element returned; #11 emit a storage struct with a dynamic field; #17/#18
    // byte-index of a calldata bytes[] element / a bytesN value. Each was over-rejected before.
    const srcs = [
      // #5 p.pts[i].x (Pt[] field of a calldata struct)
      `type Pt = { x: u256; y: u256; }; type Poly = { name: string; pts: Pt[]; }; class C { get f(p: Poly, i: u256): External<u256> { return p.pts[i].x; } }`,
      // #6 d.xs[j] (fixed-array field of a calldata dynamic-struct param)
      `type D = { a: u256; s: string; xs: Arr<u256, 3>; }; class C { get f(d: D, j: u256): External<u256> { return d.xs[j]; } }`,
      // #7 return ps[i] (whole struct element of a calldata struct array)
      `type P = { x: u128; s: string; }; class C { get f(ps: P[], i: u256): External<P> { return ps[i]; } }`,
      // #11 emit a storage struct with a dynamic field
      `type D = { id: u256; name: string }; class C { d: D; E: event<{ x: D }>; f(): External<void> { emit(E(this.d)); } }`,
      // #17 a[i][j] byte-index into a calldata bytes[] element
      `class C { get f(a: bytes[], i: u256, j: u256): External<bytes1> { return a[i][j]; } }`,
      // #18 byte-index of a bytesN VALUE expression
      `class C { get f(x: u256, i: u256): External<bytes1> { return bytes32(x)[i]; } }`,
    ];
    for (const s of srcs) expect(jethAccepts(s), s).toBe(true);
  });

  it('#19 struct-array field (Q[]) in a dynamic-struct constructor (static + dynamic element)', async () => {
    // static struct element Q{m}: P(9, qs) re-encodes the whole [len][m0][m1] array tail
    await rt(
      `type Q = { m: u256 }; type P = { a: u256; qs: Q[] }; class C { get f(qs: Q[]): External<P> { return P(9n, qs); } }`,
      `contract C { struct Q { uint256 m; } struct P { uint256 a; Q[] qs; } function f(Q[] calldata qs) external pure returns(P memory){ return P(9, qs); } }`,
      [
        { sig: 'f((uint256)[])', args: W(0x20n) + W(2n) + W(11n) + W(22n) },
        { sig: 'f((uint256)[])', args: W(0x20n) + W(0n) },
      ],
    );
    // dynamic struct element Q{m,s}: offset table + variable-length string payloads (q0="ab", q1="this-one-is-longer!!")
    await rt(
      `type Q = { m: u256; s: string }; type P = { a: u256; qs: Q[] }; class C { get f(qs: Q[]): External<P> { return P(9n, qs); } }`,
      `contract C { struct Q { uint256 m; string s; } struct P { uint256 a; Q[] qs; } function f(Q[] calldata qs) external pure returns(P memory){ return P(9, qs); } }`,
      [
        {
          sig: 'f((uint256,string)[])',
          args:
            W(0x20n) +
            W(2n) +
            W(0x40n) +
            W(0xc0n) +
            W(1n) +
            W(0x40n) +
            W(2n) +
            '6162'.padEnd(64, '0') +
            W(2n) +
            W(0x40n) +
            W(20n) +
            Buffer.from('this-one-is-longer!!', 'utf8').toString('hex').padEnd(64, '0'),
        },
      ],
    );
  });
});

describe('pre-Phase-6 sweep: soundness + over-rejection fixes (byte-identical to solc)', () => {
  it('rejects the over-acceptances the sweep found (match solc)', () => {
    const rej = [
      `class C { get f(): External<bytes4> { return bytes4(255n); } }`, // #0 decimal -> bytesN
      `class C { get f(): External<bytes32> { return bytes32(0x1122n); } }`, // #0 wrong-width hex -> bytesN
      `class C { get f(x: bytes): External<string> { let y: string = x; return y; } }`, // #1 implicit bytes<->string
      `class C { static A: u16 = 300n; static K: u8 = A & 0xFFn; get f(): External<u8> { return this.K; } }`, // #4 typed result u16 -> u8
      `class C { static K: u16 = type(u8).max * 2n; get f(): External<u16> { return this.K; } }`, // #3 typed-overflow constant (safe reject)
      `class C { get f(): External<u256> { let a: Arr<u256,3> = [10n,20n,30n]; return a[3n]; } }`, // #15 const-OOB memory fixed-array
      // (#16 side-effecting compound key `m[i++] += v` is no longer a reject: it is now lifted and
      //  byte-identical to solc - the index is hoisted to a temp evaluated once. See the positive
      //  check below and test/compound-assign-side-effecting-index.test.ts.)
      `class C { get f(): External<u256> { return 0x12__34n; } }`, // #31 bad underscores
      `class C { get f(): External<u256> { return 0o17n; } }`, // #32 octal
      `class C { get f(): External<u256> { return 0xn; } }`, // #33 empty hex
    ];
    for (const s of rej) expect(jethRejects(s), s).toBe(true);
  });

  it('#16 side-effecting compound key m[i++] += v is now accepted (was a sound reject)', () => {
    // Previously rejected (JETH331) to avoid the double-eval miscompile; now the index is hoisted to
    // a temp evaluated exactly once, so it is accepted and byte-identical to solc (verified on the
    // EVM harness in test/compound-assign-side-effecting-index.test.ts).
    expect(
      jethRejects(`class C { m: mapping<u256,u256>; i: u256; go(v: u256): External<void> { this.m[this.i++] += v; } }`),
    ).toBe(false);
  });

  it('#2 typed-operand @constant shift truncates to the type (254, not 510)', async () => {
    await rt(
      `class C { static K: u16 = type(u8).max << 1n; static A: u8 = 255n; static J: u16 = A << 1n; get k(): External<u16> { return this.K; } get j(): External<u16> { return this.J; } }`,
      `contract C { uint16 constant K = type(uint8).max << 1; uint8 constant A = 255; uint16 constant J = A << 1; function k() external pure returns(uint16){ return K; } function j() external pure returns(uint16){ return J; } }`,
      [{ sig: 'k()' }, { sig: 'j()' }],
    );
  });

  it('bytesN(uintM) same-size cast is byte-identical (the #0 companion)', async () => {
    await rt(
      `class C { get a(): External<bytes32> { return bytes32(u256(0x1122n)); } get b(): External<bytes4> { return bytes4(u32(0xffn)); } }`,
      `contract C { function a() external pure returns(bytes32){ return bytes32(uint256(0x1122)); } function b() external pure returns(bytes4){ return bytes4(uint32(0xff)); } }`,
      [{ sig: 'a()' }, { sig: 'b()' }],
    );
  });

  it('#28 allocating value-array ternary as a multi-return tuple component (scalar sibling intact)', async () => {
    await rt(
      `class C { get f(c: bool): External<[u256, u256[]]> { return [7n, c ? [10n, 20n] : [30n]]; } }`,
      `contract C { function f(bool c) external pure returns(uint256, uint256[] memory){ uint256[] memory a; if(c){a=new uint256[](2);a[0]=10;a[1]=20;}else{a=new uint256[](1);a[0]=30;} return (7, a); } }`,
      [
        { sig: 'f(bool)', args: W(0n) },
        { sig: 'f(bool)', args: W(1n) },
      ],
    );
  });

  it('#21 ternary-string revert reason is byte-identical (incl. >=61 bytes)', async () => {
    const long = 'x'.repeat(61);
    await rt(
      `class C { f(x: bool): External<void> { revert(x ? "${long}" : "q"); } }`,
      `contract C { function f(bool x) external pure { revert(x ? "${long}" : "q"); } }`,
      [
        { sig: 'f(bool)', args: W(1n) },
        { sig: 'f(bool)', args: W(0n) },
      ],
    );
  });

  it('#22 dynamic-struct @error parameter revert data', async () => {
    await rt(
      `type D = { a: u256; s: string }; class C { E: error<{ d: D }>; f(): External<void> { revert(E(D(7n, "a string longer than thirty-two bytes for the tail"))); } }`,
      `contract C { struct D { uint256 a; string s; } error E(D d); function f() external pure { revert E(D(7, "a string longer than thirty-two bytes for the tail")); } }`,
      [{ sig: 'f()' }],
    );
  });

  it('#18 nested-dynamic-struct-field event param (non-indexed data + indexed topic)', async () => {
    const s = 'hello world over thirty-two bytes long!!';
    await rt(
      `type I = { p: u256; s: string }; type D2 = { x: u256; inner: I }; class C { E: event<{ d: D2 }>; T: event<{ d: indexed<D2> }>; f(): External<void> { emit(E(D2(1n, I(2n, "${s}")))); emit(T(D2(1n, I(2n, "${s}")))); } }`,
      `contract C { struct I { uint256 p; string s; } struct D2 { uint256 x; I inner; } event E(D2 d); event T(D2 indexed d); function f() external { emit E(D2(1, I(2, "${s}"))); emit T(D2(1, I(2, "${s}"))); } }`,
      [{ sig: 'f()' }],
    );
  });

  it('#7 calldata dyn-struct to storage: happy path + truncated EMPTY-revert (bounds validated)', async () => {
    const jeth = `type S = { a: u256; s: string }; class C { st: S; set(x: S): External<void> { this.st = x; } get gets(): External<string> { return this.st.s; } }`;
    const sol = `contract C { struct S { uint256 a; string s; } S st; function set(S calldata x) external { st = x; } function gets() external view returns (string memory) { return st.s; } }`;
    const str = 'a string that is definitely longer than thirty-two bytes!';
    const hex = Buffer.from(str)
      .toString('hex')
      .padEnd(Math.ceil(str.length / 32) * 64, '0');
    await rt(jeth, sol, [
      { sig: 'set((uint256,string))', args: W(0x20n) + W(7n) + W(0x40n) + W(BigInt(str.length)) + hex },
      { sig: 'gets()' },
      { sig: 'set((uint256,string))', args: W(0x20n) + W(7n) + W(0x40n) + W(33n) + 'aa'.repeat(32) }, // truncated -> EMPTY revert
    ]);
  });
});

describe('calldata dynamic-struct DEEP field access (byte-identical to solc)', () => {
  // string tail = [len][right-padded data]; pad to a 32-byte boundary
  const strT = (s: string): string => {
    const b = Buffer.from(s, 'utf8');
    const pad = Math.ceil(b.length / 32) * 32 || 0;
    return W(BigInt(b.length)) + b.toString('hex').padEnd(pad * 2, '0');
  };

  it('#6 return a whole nested struct field (o.inner) of a calldata dyn-struct param', async () => {
    const jeth = `type I = { name: string; vals: u256[] }; type O = { id: u256; inner: I; tag: u256 }; class C { get g(o: O): External<I> { return o.inner; } }`;
    const sol = `contract C { struct I { string name; uint256[] vals; } struct O { uint256 id; I inner; uint256 tag; } function g(O calldata o) external pure returns(I memory){ return o.inner; } }`;
    const inner = (nm: string, vals: bigint[]) => {
      const name = strT(nm);
      const valsBlob = W(BigInt(vals.length)) + vals.map(W).join('');
      return W(0x40n) + W(BigInt(0x40 + name.length / 2)) + name + valsBlob;
    };
    const O = (id: bigint, nm: string, vals: bigint[], tag: bigint) => W(id) + W(0x60n) + W(tag) + inner(nm, vals);
    await rt(jeth, sol, [
      {
        sig: 'g((uint256,(string,uint256[]),uint256))',
        args: W(0x20n) + O(1n, 'hello-world-inner-name', [11n, 22n, 33n], 99n),
      },
      { sig: 'g((uint256,(string,uint256[]),uint256))', args: W(0x20n) + O(5n, '', [], 7n) }, // empty name + empty vals
    ]);
  });

  it('#11 element of a string[] field (s.tags[i]) incl OOB Panic(0x32)', async () => {
    const jeth = `type S = { id: u256; tags: string[] }; class C { get g(s: S, i: u256): External<string> { return s.tags[i]; } }`;
    const sol = `contract C { struct S { uint256 id; string[] tags; } function g(S calldata s, uint256 i) external pure returns(string memory){ return s.tags[i]; } }`;
    const t = ['ab', 'this-is-a-much-longer-tag-value!!', ''].map(strT);
    const table =
      W(BigInt(3 * 32)) + W(BigInt(3 * 32 + t[0]!.length / 2)) + W(BigInt(3 * 32 + (t[0]!.length + t[1]!.length) / 2));
    const Sval = W(7n) + W(0x40n) + W(3n) + table + t.join('');
    const cd = (i: bigint) => W(0x40n) + W(i) + Sval;
    await rt(
      jeth,
      sol,
      [0n, 1n, 2n, 3n].map((i) => ({ sig: 'g((uint256,string[]),uint256)', args: cd(i) })),
    );
  });

  it('#12 element of a T[][] field (s.grid[i][j]) incl both-dim OOB', async () => {
    const jeth = `type S = { id: u256; grid: u256[][] }; class C { get g(s: S, i: u256, j: u256): External<u256> { return s.grid[i][j]; } }`;
    const sol = `contract C { struct S { uint256 id; uint256[][] grid; } function g(S calldata s, uint256 i, uint256 j) external pure returns(uint256){ return s.grid[i][j]; } }`;
    const rows = [[1n], [2n, 3n, 4n, 5n], []].map((r) => W(BigInt(r.length)) + r.map(W).join(''));
    const table =
      W(BigInt(3 * 32)) +
      W(BigInt(3 * 32 + rows[0]!.length / 2)) +
      W(BigInt(3 * 32 + (rows[0]!.length + rows[1]!.length) / 2));
    const Sval = W(9n) + W(0x40n) + W(3n) + table + rows.join('');
    const cd = (i: bigint, j: bigint) => W(0x60n) + W(i) + W(j) + Sval;
    await rt(
      jeth,
      sol,
      (
        [
          [1n, 2n],
          [0n, 0n],
          [0n, 1n],
          [3n, 0n],
        ] as [bigint, bigint][]
      ).map(([i, j]) => ({ sig: 'g((uint256,uint256[][]),uint256,uint256)', args: cd(i, j) })),
    );
  });

  it('#13 field of a dynamic-struct-array element field (s.items[i].name) incl OOB', async () => {
    const jeth = `type It = { name: string; v: u256 }; type S = { id: u256; items: It[] }; class C { get g(s: S, i: u256): External<string> { return s.items[i].name; } }`;
    const sol = `contract C { struct It { string name; uint256 v; } struct S { uint256 id; It[] items; } function g(S calldata s, uint256 i) external pure returns(string memory){ return s.items[i].name; } }`;
    const mkIt = (nm: string, v: bigint) => W(0x40n) + W(v) + strT(nm);
    const i0 = mkIt('aa', 10n),
      i1 = mkIt('this-name-is-deliberately-longer!', 20n);
    const Sval = W(8n) + W(0x40n) + W(2n) + W(BigInt(2 * 32)) + W(BigInt(2 * 32 + i0.length / 2)) + i0 + i1;
    const cd = (i: bigint) => W(0x40n) + W(i) + Sval;
    await rt(
      jeth,
      sol,
      [0n, 1n, 2n].map((i) => ({ sig: 'g((uint256,(string,uint256)[]),uint256)', args: cd(i) })),
    );
  });
});

describe('assignment evaluation order: RHS before LHS index/key (byte-identical to solc)', () => {
  // solc evaluates the RHS before the LHS location (incl its index/key). A side-effecting index with a
  // side-effecting RHS must match solc; previously JETH lowered the index first and silently miscompiled.
  const INC = `@state i: u256; inc(): u256 { let v: u256 = this.i; this.i = this.i + 1n; return v; }`;
  const SINC = `uint256 i; function inc() internal returns (uint256){ uint256 v=i; i++; return v; }`;
  const cases: [string, string, string][] = [
    [
      'fixed Arr a[inc()]=inc()',
      `class C { a: Arr<u256,2>; ${INC} f(): External<u256> { this.a[this.inc()] = this.inc(); return this.a[0n]*10n + this.a[1n]; } }`,
      `contract C { uint256[2] a; ${SINC} function f() external returns (uint256){ a[inc()]=inc(); return a[0]*10 + a[1]; } }`,
    ],
    [
      'dyn array a[inc()]=inc()',
      `class C { a: u256[]; ${INC} f(): External<u256> { this.a.push(0n); this.a.push(0n); this.a[this.inc()] = this.inc(); return this.a[0n]*100n + this.a[1n]; } }`,
      `contract C { uint256[] a; ${SINC} function f() external returns (uint256){ a.push(0); a.push(0); a[inc()]=inc(); return a[0]*100 + a[1]; } }`,
    ],
    [
      'mapping m[inc()]=inc()',
      `class C { m: mapping<u256,u256>; ${INC} f(): External<u256> { this.m[this.inc()] = this.inc(); return this.m[0n]*100n + this.m[1n]; } }`,
      `contract C { mapping(uint256=>uint256) m; ${SINC} function f() external returns (uint256){ m[inc()]=inc(); return m[0]*100 + m[1]; } }`,
    ],
    [
      'nested mapping m[inc()][inc()]=inc()',
      `class C { m: mapping<u256, mapping<u256, u256>>; ${INC} f(): External<u256> { this.m[this.inc()][this.inc()] = this.inc(); return this.m[0n][1n]*1000n + this.m[1n][2n]; } }`,
      `contract C { mapping(uint256=>mapping(uint256=>uint256)) m; ${SINC} function f() external returns (uint256){ m[inc()][inc()]=inc(); return m[0][1]*1000 + m[1][2]; } }`,
    ],
    [
      'memory-local a[inc()]=inc()',
      `class C { ${INC} f(): External<u256> { let a: Arr<u256,2> = [0n,0n]; a[this.inc()] = this.inc(); return a[0n]*10n + a[1n]; } }`,
      `contract C { ${SINC} function f() external returns (uint256){ uint256[2] memory a; a[inc()]=inc(); return a[0]*10 + a[1]; } }`,
    ],
    [
      'nested fixed aa[inc()][inc()]=inc() (success-vs-revert)',
      `class C { aa: Arr<Arr<u256,2>,2>; ${INC} f(): External<u256> { this.aa[this.inc()][this.inc()] = this.inc(); return this.aa[0n][1n]; } }`,
      `contract C { uint256[2][2] aa; ${SINC} function f() external returns (uint256){ aa[inc()][inc()]=inc(); return aa[0][1]; } }`,
    ],
    [
      'storage string m[inc()]=ternary',
      `class C { m: mapping<u256, string>; ${INC} f(): External<string> { this.m[this.inc()] = (this.i > 0n) ? "longstringvalue!!" : "x"; return this.m[0n]; } }`,
      `contract C { mapping(uint256=>string) m; ${SINC} function f() external returns (string memory){ m[inc()] = (i>0) ? "longstringvalue!!" : "x"; return m[0]; } }`,
    ],
  ];
  for (const [name, jeth, sol] of cases) {
    it(name, async () => {
      await rt(jeth, sol, [{ sig: 'f()' }]);
    });
  }

  it('W8A: aggregate-element assign with a side-effecting index AND value is byte-identical; pure/derived keys accept', async () => {
    // W8A: a whole-aggregate element write whose index AND value BOTH side-effect is now byte-identical.
    // inc() returns the PRE-increment value; solc evaluates the RHS `P(inc(), 9)` FIRST (inc()=0, i:0->1),
    // then the index `inc()` (=1, i:1->2). recs has ONE element, so recs[1] is OOB -> BOTH revert (Panic
    // 0x32) at the same point. The former JETH331 over-rejection is gone (materialize-RHS-then-index).
    await rt(
      `type P = { x: u256; y: u256 }; class C { recs: P[]; i: u256; inc(): u256 { let v: u256 = this.i; this.i=this.i+1n; return v; } f(): External<void> { this.recs.push(P(0n,0n)); this.recs[this.inc()] = P(this.inc(), 9n); } get gx(): External<u256> { return this.recs[0n].x; } get gi(): External<u256> { return this.i; } }`,
      `struct P { uint256 x; uint256 y; } contract C { P[] recs; uint256 i; function inc() internal returns(uint256){ uint256 v=i; i=i+1; return v; } function f() external { recs.push(P(0,0)); recs[inc()] = P(inc(), 9); } function gx() external view returns(uint256){ return recs[0].x; } function gi() external view returns(uint256){ return i; } }`,
      [{ sig: 'f()' }, { sig: 'gx()' }, { sig: 'gi()' }],
    );
    // a FIXED outer array (Arr<Arr<u256,2>,2>): the index is in bounds (0/1). RHS `[inc(), 9]` first
    // (inc()=0, i:0->1) then index inc() (=1, i:1->2) -> dd[1] = [0, 9]. Byte-identical, slots + i.
    await rt(
      `class C { dd: Arr<Arr<u256,2>,2>; i: u256; inc(): u256 { let v: u256 = this.i; this.i=this.i+1n; return v; } f(): External<void> { this.dd[this.inc()] = [this.inc(), 9n]; } get g10(): External<u256> { return this.dd[1n][0n]; } get g11(): External<u256> { return this.dd[1n][1n]; } get gi(): External<u256> { return this.i; } }`,
      `contract C { uint256[2][2] dd; uint256 i; function inc() internal returns(uint256){ uint256 v=i; i=i+1; return v; } function f() external { dd[inc()] = [inc(), uint256(9)]; } function g10() external view returns(uint256){ return dd[1][0]; } function g11() external view returns(uint256){ return dd[1][1]; } function gi() external view returns(uint256){ return i; } }`,
      [{ sig: 'f()' }, { sig: 'g10()' }, { sig: 'g11()' }, { sig: 'gi()' }],
    );
    // a PURE value-type cast key (address(lit), u8(x)) is NOT side-effecting: must stay accepted (this was
    // a regression-prone false positive in the side-effecting-key detector).
    expect(
      jethAccepts(
        `type P = { a: u256; b: u8 }; class C { mp: mapping<address, P>; f(): External<void> { this.mp[address(0x1n)] = P(1n, 2n); } }`,
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        `class C { bal: mapping<address, u256>; f(k: address, v: u256): External<void> { this.bal[address(0x1n)] += v; } }`,
      ),
    ).toBe(true);
  });
});

describe('creation callvalue guard + storage dyn-struct nested-aggregate event (byte-identical)', () => {
  it('a constructorless contract rejects deploy value (non-payable creation), like solc', async () => {
    const jb = compile(`class C { x: u256 = 9n; get g(): External<u256> { return this.x; } }`, {
      fileName: 'C.jeth',
    });
    const sb = compileSolidity(
      SPDX + `contract C { uint256 x = 9; function g() external view returns(uint256){ return x; } }`,
      'C',
    );
    for (const value of [0n, 5n]) {
      const hj = await Harness.create(),
        hs = await Harness.create();
      let jr = 'created',
        sr = 'created';
      try {
        await hj.deploy(jb.creationBytecode, { value });
      } catch {
        jr = 'reverted';
      }
      try {
        await hs.deploy(sb.creation, { value });
      } catch {
        sr = 'reverted';
      }
      expect(jr, `deploy value=${value}`).toBe(sr);
    }
  });

  it('emit a STORAGE dynamic struct with a nested multi-word static-aggregate field (topic + data)', async () => {
    const setA = W(7n) + W(8n) + W(0x60n) + W(11n) + Buffer.from('hello world').toString('hex').padEnd(64, '0');
    const calls = [{ sig: 'set(uint128,uint128,string)', args: setA }, { sig: 'go()' }];
    // non-indexed (data): nested packed struct Inn{u128,u128}
    await rt(
      `type Inn = { a: u128; b: u128; }; type D = { i: Inn; s: string; }; class C { d: D; E: event<{ v: D }>; set(a: u128, b: u128, s: string): External<void> { this.d.i = Inn(a, b); this.d.s = s; } go(): External<void> { emit(E(this.d)); } }`,
      `contract C { struct Inn { uint128 a; uint128 b; } struct D { Inn i; string s; } D d; event E(D v); function set(uint128 a, uint128 b, string calldata s) external { d.i = Inn(a,b); d.s = s; } function go() external { emit E(d); } }`,
      calls,
    );
    // indexed (topic = keccak of the flattened payload): same struct
    await rt(
      `type Inn = { a: u128; b: u128; }; type D = { i: Inn; s: string; }; class C { d: D; E: event<{ v: indexed<D> }>; set(a: u128, b: u128, s: string): External<void> { this.d.i = Inn(a, b); this.d.s = s; } go(): External<void> { emit(E(this.d)); } }`,
      `contract C { struct Inn { uint128 a; uint128 b; } struct D { Inn i; string s; } D d; event E(D indexed v); function set(uint128 a, uint128 b, string calldata s) external { d.i = Inn(a,b); d.s = s; } function go() external { emit E(d); } }`,
      calls,
    );
    // nested fixed-array field Arr<u256,2> (also >=2 head words)
    await rt(
      `type D = { i: Arr<u256,2>; s: string; }; class C { d: D; E: event<{ v: D }>; set(a: u128, b: u128, s: string): External<void> { this.d.i[0n] = u256(a); this.d.i[1n] = u256(b); this.d.s = s; } go(): External<void> { emit(E(this.d)); } }`,
      `contract C { struct D { uint256[2] i; string s; } D d; event E(D v); function set(uint128 a, uint128 b, string calldata s) external { d.i[0]=uint256(a); d.i[1]=uint256(b); d.s = s; } function go() external { emit E(d); } }`,
      calls,
    );
  });
});

describe('deep-sweep #2 over-rejections (byte-identical to solc)', () => {
  it('re-point a struct memory local via assignment (= ctor / = storage copy / = alias)', async () => {
    await rt(
      `type P = { x: u256; y: u256; }; class C { get f(a: u256): External<u256> { let s: P = P(a, a); s = P(9n, 9n); return s.x; } }`,
      `contract C { struct P { uint256 x; uint256 y; } function f(uint256 a) external pure returns (uint256) { P memory s = P(a, a); s = P(9, 9); return s.x; } }`,
      [{ sig: 'f(uint256)', args: W(5n) }],
    );
    // = storage is a COPY: mutating the local must not touch storage
    await rt(
      `type P = { x: u256; y: u256; }; class C { p: P; set(a: u256): External<void> { this.p = P(a, a); } get f(): External<u256> { let t: P = P(0n, 0n); t = this.p; t.x = 999n; return this.p.x; } }`,
      `contract C { struct P { uint256 x; uint256 y; } P p; function set(uint256 a) external { p = P(a, a); } function f() external returns (uint256) { P memory t = P(0, 0); t = p; t.x = 999; return p.x; } }`,
      [{ sig: 'set(uint256)', args: W(12345n) }, { sig: 'f()' }],
    );
  });

  it('delete a memory string / dynamic-array local (rebind to empty)', async () => {
    await rt(
      `class C { get f(s: string): External<string> { let b: string = s; delete b; return b; } }`,
      `contract C { function f(string calldata s) external pure returns (string memory) { string memory b = s; delete b; return b; } }`,
      [{ sig: 'f(string)', args: W(0x20n) + W(3n) + Buffer.from('abc').toString('hex').padEnd(64, '0') }],
    );
    expect(
      jethAccepts(
        `class C { get f(): External<u256> { let a: u256[] = [1n,2n,3n]; delete a; return a.length; } }`,
      ),
    ).toBe(true);
  });

  it('return a tuple-valued internal call directly', async () => {
    await rt(
      `class C { mk(n: u256): [u256, u256] { return [n, n + 1n]; } get f(n: u256): External<[u256, u256]> { return this.mk(n); } }`,
      `contract C { function mk(uint256 n) internal pure returns (uint256, uint256){ return (n, n+1); } function f(uint256 n) external pure returns (uint256, uint256){ return mk(n); } }`,
      [{ sig: 'f(uint256)', args: W(5n) }],
    );
  });

  it('internal call returning a struct with a dynamic field', async () => {
    await rt(
      `type S = { a: u256; s: string }; class C { mk(): S { return S(1n, "hello-world!"); } get f(): External<u256> { let r: S = this.mk(); return r.a; } get g(): External<string> { let r: S = this.mk(); return r.s; } }`,
      `contract C { struct S { uint256 a; string s; } function mk() internal pure returns (S memory){ return S(1, "hello-world!"); } function f() external pure returns (uint256){ S memory r = mk(); return r.a; } function g() external pure returns (string memory){ S memory r = mk(); return r.s; } }`,
      [{ sig: 'f()' }, { sig: 'g()' }],
    );
  });

  it('enum const folding: type(Enum).max/.min, @constant enum, @constant int from enum', async () => {
    await rt(
      `enum Color{Red,Green,Blue}\nclass C { static K: u8 = u8(Color.Blue); static DEF: Color = Color.Green; get mx(): External<u8> { return u8(type(Color).max); } get mn(): External<u8> { return u8(type(Color).min); } get k(): External<u8> { return this.K; } get def(): External<u8> { return u8(this.DEF); } }`,
      `contract C { enum Color{Red,Green,Blue} uint8 constant K = uint8(Color.Blue); Color constant DEF = Color.Green; function mx() external pure returns(uint8){ return uint8(type(Color).max); } function mn() external pure returns(uint8){ return uint8(type(Color).min); } function k() external pure returns(uint8){ return K; } function def() external pure returns(uint8){ return uint8(DEF); } }`,
      [{ sig: 'mx()' }, { sig: 'mn()' }, { sig: 'k()' }, { sig: 'def()' }],
    );
  });

  it('mapping with a dynamic (string) key and a STRUCT value: field write/read', async () => {
    const k = W(0x40n) + W(0n) + W(2n) + Buffer.from('hi').toString('hex').padEnd(64, '0'); // f(string,uint256): [k off=0x40][a]...
    await rt(
      `type S = { a: u256; b: u256 }; class C { m: mapping<string, S>; f(key: string, a: u256): External<void> { this.m[key].a = a; } get g(key: string): External<u256> { return this.m[key].a; } }`,
      `contract C { struct S { uint256 a; uint256 b; } mapping(string=>S) m; function f(string calldata key, uint256 a) external { m[key].a = a; } function g(string calldata key) external view returns(uint256){ return m[key].a; } }`,
      [
        {
          sig: 'f(string,uint256)',
          args: W(0x40n) + W(77n) + W(2n) + Buffer.from('hi').toString('hex').padEnd(64, '0'),
        },
        { sig: 'g(string)', args: W(0x20n) + W(2n) + Buffer.from('hi').toString('hex').padEnd(64, '0') },
      ],
    );
  });
});

describe('abi.encode of an array of dynamic elements: oversized length is an ABI-decode failure (empty revert)', () => {
  // solc decodes the calldata value before re-encoding; an inner length / outer length >= 2^64 is a
  // decode failure -> revert(0,0) (EMPTY), NOT Panic 0x41. The plain return-echo copy still Panics.
  const big = W(1n << 65n);
  it('abi.encode(bytes[]) bad inner / outer length -> empty revert; well-formed identical', async () => {
    await rt(
      `class C { get r(xs: bytes[]): External<bytes> { return abi.encode(xs); } }`,
      `contract C { function r(bytes[] calldata xs) external pure returns (bytes memory) { return abi.encode(xs); } }`,
      [
        { sig: 'r(bytes[])', args: W(0x20n) + W(1n) + W(0x20n) + big }, // inner bytes length 2^65 -> both empty-revert
        { sig: 'r(bytes[])', args: W(0x20n) + big }, // outer array length 2^65 -> both empty-revert
        {
          sig: 'r(bytes[])',
          args: W(0x20n) + W(1n) + W(0x20n) + W(3n) + Buffer.from('abc').toString('hex').padEnd(64, '0'),
        }, // well-formed
        { sig: 'r(bytes[])', args: W(0x20n) + W(0n) }, // empty array
      ],
    );
  });
  it('return-echo of the same bad calldata still Panics 0x41 (matches solc, unchanged)', async () => {
    await rt(
      `class C { get r(xs: bytes[]): External<bytes[]> { return xs; } }`,
      `contract C { function r(bytes[] calldata xs) external pure returns (bytes[] memory) { return xs; } }`,
      [{ sig: 'r(bytes[])', args: W(0x20n) + W(1n) + W(0x20n) + big }],
    );
  });
});
