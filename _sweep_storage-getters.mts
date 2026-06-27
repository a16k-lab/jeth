import { compile } from './src/compile.js';
import { compileSolidity } from './test/_solidity.js';
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const J = (s: string): string => {
  try { compile(s, { fileName: 'C.jeth' }); return 'ACCEPT'; }
  catch (e: any) { if (e && e.diagnostics) return e.diagnostics.map((d: any) => d.code).join(','); return 'CRASH:' + String((e && e.message) || e).slice(0, 80); }
};
const S = (s: string, n: string): string => {
  try { compileSolidity(SPDX + s, n); return 'ACCEPT'; }
  catch (e) { return 'REJECT'; }
};

// [name, jethSrc, solcSrc, solcContractName]
const cases: [string, string, string, string][] = [
  // ---------- harder @external getters ----------
  ['map-to-2d-array',
    `@contract class C { @external @state m: mapping<u256,u256[][]>; }`,
    `contract C { mapping(uint256=>uint256[][]) public m; }`, 'C'],
  ['map-to-struct-array',
    `@struct class S { x: u256; y: u256; } @contract class C { @external @state m: mapping<u256,S[]>; }`,
    `contract C { struct S { uint256 x; uint256 y; } mapping(uint256=>S[]) public m; }`, 'C'],
  ['fixed-array-of-struct',
    `@struct class S { x: u256; y: u256; } @contract class C { @external @state a: Arr<S,3>; }`,
    `contract C { struct S { uint256 x; uint256 y; } S[3] public a; }`, 'C'],
  ['struct-with-fixed-array-of-struct',
    `@struct class P { x: u256; y: u256; } @struct class S { id: u256; pts: Arr<P,2>; } @contract class C { @external @state s: S; }`,
    `contract C { struct P { uint256 x; uint256 y; } struct S { uint256 id; P[2] pts; } S public s; }`, 'C'],
  ['deeply-nested-struct',
    `@struct class A { v: u256; } @struct class B { a: A; w: u256; } @struct class D { b: B; z: u256; } @contract class C { @external @state d: D; }`,
    `contract C { struct A { uint256 v; } struct B { A a; uint256 w; } struct D { B b; uint256 z; } D public d; }`, 'C'],
  ['map-to-nested-dyn-struct',
    `@struct class S { x: u256; name: string; } @contract class C { @external @state m: mapping<address,S>; }`,
    `contract C { struct S { uint256 x; string name; } mapping(address=>S) public m; }`, 'C'],
  ['struct-array-elem-with-string',
    `@struct class S { x: u256; name: string; } @contract class C { @external @state arr: S[]; }`,
    `contract C { struct S { uint256 x; string name; } S[] public arr; }`, 'C'],
  ['map-to-bytes-key-to-struct',
    `@struct class S { x: u256; y: u256; } @contract class C { @external @state m: mapping<bytes,S>; }`,
    `contract C { struct S { uint256 x; uint256 y; } mapping(bytes=>S) public m; }`, 'C'],
  ['map-key-bytes32',
    `@contract class C { @external @state m: mapping<bytes32,u256>; }`,
    `contract C { mapping(bytes32=>uint256) public m; }`, 'C'],
  ['map-key-enum',
    `enum E { A, B } @contract class C { @external @state m: mapping<E,u256>; }`,
    `contract C { enum E { A, B } mapping(E=>uint256) public m; }`, 'C'],
  ['map-to-enum-value',
    `enum E { A, B } @contract class C { @external @state m: mapping<u256,E>; }`,
    `contract C { enum E { A, B } mapping(uint256=>E) public m; }`, 'C'],
  ['struct-with-enum-member-getter',
    `enum E { A, B } @struct class S { x: u256; e: E; } @contract class C { @external @state s: S; }`,
    `contract C { enum E { A, B } struct S { uint256 x; E e; } S public s; }`, 'C'],
  ['arr-of-bytes-getter',
    `@contract class C { @external @state a: bytes[]; }`,
    `contract C { bytes[] public a; }`, 'C'],
  ['fixed-array-of-string',
    `@contract class C { @external @state a: Arr<string,3>; }`,
    `contract C { string[3] public a; }`, 'C'],
  ['arr-2d-string',
    `@contract class C { @external @state a: string[][]; }`,
    `contract C { string[][] public a; }`, 'C'],
  ['map-to-fixed-string-array',
    `@contract class C { @external @state m: mapping<u256,Arr<string,2>>; }`,
    `contract C { mapping(uint256=>string[2]) public m; }`, 'C'],

  // ---------- packed @state getters ----------
  ['pack-getter-i16-i16-i16',
    `@contract class C { @external @state a: i16; @external @state b: i16; @external @state c: i16; }`,
    `contract C { int16 public a; int16 public b; int16 public c; }`, 'C'],
  ['pack-struct-getter',
    `@struct class S { a: u64; b: u64; c: u64; d: u64; } @contract class C { @external @state s: S; }`,
    `contract C { struct S { uint64 a; uint64 b; uint64 c; uint64 d; } S public s; }`, 'C'],

  // ---------- @constant edge getters ----------
  ['const-public-getter-bytes4',
    `@contract class C { @external @constant SEL: bytes4 = 0x12345678n; }`,
    `contract C { bytes4 public constant SEL = 0x12345678; }`, 'C'],
  ['const-public-getter-i256',
    `@contract class C { @external @constant N: i256 = -5n; }`,
    `contract C { int256 public constant N = -5; }`, 'C'],
  ['const-public-getter-u8',
    `@contract class C { @external @constant N: u8 = 200n; }`,
    `contract C { uint8 public constant N = 200; }`, 'C'],

  // ---------- @immutable edge getters ----------
  ['immut-public-getter-bytes32',
    `@contract class C { @external @immutable H: bytes32; constructor(h: bytes32) { this.H = h; } }`,
    `contract C { bytes32 public immutable H; constructor(bytes32 h) { H = h; } }`, 'C'],
  ['immut-public-getter-bool',
    `@contract class C { @external @immutable F: bool; constructor(f: bool) { this.F = f; } }`,
    `contract C { bool public immutable F; constructor(bool f) { F = f; } }`, 'C'],
  ['immut-public-getter-enum',
    `enum E { A, B } @contract class C { @external @immutable E0: E; constructor(e: E) { this.E0 = e; } }`,
    `contract C { enum E { A, B } E public immutable E0; constructor(E e) { E0 = e; } }`, 'C'],

  // ---------- delete edge cases ----------
  ['delete-packed-field',
    `@struct class S { a: u64; b: u64; } @contract class C { @state s: S; @external f(): void { delete this.s.a; } }`,
    `contract C { struct S { uint64 a; uint64 b; } S s; function f() external { delete s.a; } }`, 'C'],
  ['delete-nested-struct-field',
    `@struct class I { a: u256; } @struct class O { i: I; z: u256; } @contract class C { @state o: O; @external f(): void { delete this.o.i; } }`,
    `contract C { struct I { uint256 a; } struct O { I i; uint256 z; } O o; function f() external { delete o.i; } }`, 'C'],
  ['delete-struct-in-map',
    `@struct class S { x: u256; y: u256; } @contract class C { @state m: mapping<address,S>; @external f(k: address): void { delete this.m[k]; } }`,
    `contract C { struct S { uint256 x; uint256 y; } mapping(address=>S) m; function f(address k) external { delete m[k]; } }`, 'C'],
  ['delete-fixed-array',
    `@contract class C { @state a: Arr<u256,3>; @external f(): void { delete this.a; } }`,
    `contract C { uint256[3] a; function f() external { delete a; } }`, 'C'],
  ['delete-string',
    `@contract class C { @state s: string; @external f(): void { delete this.s; } }`,
    `contract C { string s; function f() external { delete s; } }`, 'C'],
  ['delete-map-field-of-value',
    `@contract class C { @state m: mapping<address,u256>; @external f(k: address): void { delete this.m[k]; } }`,
    `contract C { mapping(address=>uint256) m; function f(address k) external { delete m[k]; } }`, 'C'],
  ['delete-nested-array-elem',
    `@contract class C { @state a: u256[][]; @external f(i: u256, j: u256): void { delete this.a[i][j]; } }`,
    `contract C { uint256[][] a; function f(uint256 i, uint256 j) external { delete a[i][j]; } }`, 'C'],
  ['delete-struct-array-elem',
    `@struct class S { x: u256; y: u256; } @contract class C { @state arr: S[]; @external f(i: u256): void { delete this.arr[i]; } }`,
    `contract C { struct S { uint256 x; uint256 y; } S[] arr; function f(uint256 i) external { delete arr[i]; } }`, 'C'],

  // ---------- OVER-ACCEPTANCE candidates (solc rejects these) ----------
  ['oa-getter-name-collision',
    `@contract class C { @external @state x: u256; @external x(): u256 { return 1n; } }`,
    `contract C { uint256 public x; function x() external pure returns (uint256) { return 1; } }`, 'C'],
  ['oa-delete-whole-mapping',
    `@contract class C { @state m: mapping<address,u256>; @external f(): void { delete this.m; } }`,
    `contract C { mapping(address=>uint256) m; function f() external { delete m; } }`, 'C'],
  ['oa-immutable-non-value',
    `@contract class C { @external @immutable b: bytes; }`,
    `contract C { bytes public immutable b; }`, 'C'],
  ['oa-constant-non-const-init',
    `@contract class C { @external @state y: u256 = 1n; @constant X: u256 = 2n; @external f(): u256 { return this.X + this.y; } }`,
    `contract C { uint256 public y = 1; uint256 constant X = 2; function f() external view returns (uint256) { return X + y; } }`, 'C'],

  // ---------- combos ----------
  ['map-key-string-to-array',
    `@contract class C { @external @state m: mapping<string,u256[]>; }`,
    `contract C { mapping(string=>uint256[]) public m; }`, 'C'],
  ['triple-nested-map',
    `@contract class C { @external @state m: mapping<address,mapping<address,mapping<u256,u256>>>; }`,
    `contract C { mapping(address=>mapping(address=>mapping(uint256=>uint256))) public m; }`, 'C'],
  ['map-to-fixed-2d-array',
    `@contract class C { @external @state m: mapping<u256,Arr<Arr<u256,2>,3>>; }`,
    `contract C { mapping(uint256=>uint256[2][3]) public m; }`, 'C'],
  ['struct-with-2d-fixed-array',
    `@struct class S { id: u256; grid: Arr<Arr<u256,2>,2>; } @contract class C { @external @state s: S; }`,
    `contract C { struct S { uint256 id; uint256[2][2] grid; } S public s; }`, 'C'],
];

let over_rej = 0, over_acc = 0;
for (const [name, jeth, solc, n] of cases) {
  const jr = J(jeth);
  const sr = S(solc, n);
  const isJethDiag = jr.startsWith('JETH');
  const overRej = isJethDiag && sr === 'ACCEPT';
  const overAcc = jr === 'ACCEPT' && sr === 'REJECT';
  let flag = '';
  if (overRej) { flag = '  <<< OVER-REJECTION'; over_rej++; }
  if (overAcc) { flag = '  <<< OVER-ACCEPTANCE'; over_acc++; }
  console.log(`${name.padEnd(38)} J=${jr.padEnd(22)} S=${sr}${flag}`);
}
console.log(`\nTotal: ${cases.length} cases. over-rejections=${over_rej} over-acceptances=${over_acc}`);
