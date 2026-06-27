import { compile } from './src/compile.js';
import { compileSolidity } from './test/_solidity.js';
const SPDX='// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const J=(s:string)=>{ try{ compile(s,{fileName:'C.jeth'}); return 'ACCEPT'; }catch(e:any){ if(e&&e.diagnostics) return e.diagnostics.map((d:any)=>d.code).join(','); return 'CRASH:'+String((e&&e.message)||e).slice(0,80); } };
const S=(s:string,n:string)=>{ try{ compileSolidity(SPDX+s,n); return 'ACCEPT'; }catch(e){ return 'REJECT'; } };

type Case = [string,string,string,string];
const cases: Case[] = [
  // ---------- EVENTS ----------
  // indexed string param (solc hashes it for the topic)
  ['ev-indexed-string',
   `@contract class C { @event E(@indexed s: string, v: u256); @external f(): void { emit(E("hi", 1n)); } }`,
   `contract C { event E(string indexed s, uint256 v); function f() external { emit E("hi", 1); } }`, 'C'],
  // indexed bytes param
  ['ev-indexed-bytes',
   `@contract class C { @event E(@indexed b: bytes, v: u256); @external f(b: bytes): void { emit(E(b, 1n)); } }`,
   `contract C { event E(bytes indexed b, uint256 v); function f(bytes calldata b) external { emit E(b, 1); } }`, 'C'],
  // indexed dynamic array param uint256[]
  ['ev-indexed-uintarr',
   `@contract class C { @event E(@indexed a: u256[], v: u256); @external f(a: u256[]): void { emit(E(a, 1n)); } }`,
   `contract C { event E(uint256[] indexed a, uint256 v); function f(uint256[] calldata a) external { emit E(a, 1); } }`, 'C'],
  // non-indexed string array data param
  ['ev-strarr-data',
   `@contract class C { @event E(a: string[]); @external f(a: string[]): void { emit(E(a)); } }`,
   `contract C { event E(string[] a); function f(string[] calldata a) external { emit E(a); } }`, 'C'],
  // event with struct (non-indexed) data param
  ['ev-struct-data',
   `@struct class P { x: u256; y: u256; } @contract class C { @event E(p: P); @external f(): void { emit(E(P(1n,2n))); } }`,
   `contract C { struct P { uint256 x; uint256 y; } event E(P p); function f() external { emit E(P(1,2)); } }`, 'C'],
  // anonymous event with 4 indexed params (only legal w/ anonymous)
  ['ev-anon-4indexed',
   `@contract class C { @anonymous @event E(@indexed a: u256, @indexed b: u256, @indexed c: u256, @indexed d: u256); @external f(): void { emit(E(1n,2n,3n,4n)); } }`,
   `contract C { event E(uint256 indexed a, uint256 indexed b, uint256 indexed c, uint256 indexed d) anonymous; function f() external { emit E(1,2,3,4); } }`, 'C'],
  // event with no params, anonymous
  ['ev-anon-bare',
   `@contract class C { @anonymous @event E(); @external f(): void { emit(E()); } }`,
   `contract C { event E() anonymous; function f() external { emit E(); } }`, 'C'],
  // event declared with a fixed array Arr<T,N> data param
  ['ev-fixedarr-data',
   `@contract class C { @event E(a: Arr<u256,3>); @external f(a: Arr<u256,3>): void { emit(E(a)); } }`,
   `contract C { event E(uint256[3] a); function f(uint256[3] calldata a) external { emit E(a); } }`, 'C'],

  // ---------- CUSTOM ERRORS ----------
  // error with dynamic array arg
  ['err-arr-arg',
   `@contract class C { @error E(a: u256[]); @external f(a: u256[]): void { revert(E(a)); } }`,
   `contract C { error E(uint256[] a); function f(uint256[] calldata a) external { revert E(a); } }`, 'C'],
  // error with struct arg
  ['err-struct-arg',
   `@struct class P { x: u256; y: u256; } @contract class C { @error E(p: P); @external f(): void { revert(E(P(1n,2n))); } }`,
   `contract C { struct P { uint256 x; uint256 y; } error E(P p); function f() external { revert E(P(1,2)); } }`, 'C'],
  // error with bytes arg
  ['err-bytes-arg',
   `@contract class C { @error E(b: bytes); @external f(b: bytes): void { revert(E(b)); } }`,
   `contract C { error E(bytes b); function f(bytes calldata b) external { revert E(b); } }`, 'C'],
  // error with fixed array arg
  ['err-fixedarr-arg',
   `@contract class C { @error E(a: Arr<u256,3>); @external f(a: Arr<u256,3>): void { revert(E(a)); } }`,
   `contract C { error E(uint256[3] a); function f(uint256[3] calldata a) external { revert E(a); } }`, 'C'],
  // require with custom error having dynamic arg
  ['err-require-dyn',
   `@contract class C { @error E(s: string); @external f(x: u256, s: string): u256 { require(x > 0n, E(s)); return x; } }`,
   `contract C { error E(string s); function f(uint256 x, string calldata s) external returns(uint256) { require(x > 0, E(s)); return x; } }`, 'C'],
  // string[] error arg
  ['err-strarr-arg',
   `@contract class C { @error E(a: string[]); @external f(a: string[]): void { revert(E(a)); } }`,
   `contract C { error E(string[] a); function f(string[] calldata a) external { revert E(a); } }`, 'C'],
  // nested dynamic-struct error arg
  ['err-dynstruct-arg',
   `@struct class D { x: u256; s: string; } @contract class C { @error E(d: D); @external f(s: string): void { revert(E(D(1n, s))); } }`,
   `contract C { struct D { uint256 x; string s; } error E(D d); function f(string calldata s) external { revert E(D(1, s)); } }`, 'C'],

  // ---------- INHERITANCE ----------
  // event inherited from base, emitted in derived
  ['inh-event',
   `@abstract class A { @event E(v: u256); } @contract class C extends A { @external f(): void { emit(E(1n)); } }`,
   `abstract contract A { event E(uint256 v); } contract C is A { function f() external { emit E(1); } }`, 'C'],
  // error inherited from base, reverted in derived
  ['inh-error',
   `@abstract class A { @error E(v: u256); } @contract class C extends A { @external f(): void { revert(E(1n)); } }`,
   `abstract contract A { error E(uint256 v); } contract C is A { function f() external { revert E(1); } }`, 'C'],
  // internal fn inherited and called
  ['inh-internal-call',
   `@abstract class A { helper(x: u256): u256 { return x + 1n; } } @contract class C extends A { @external f(x: u256): u256 { return this.helper(x); } }`,
   `abstract contract A { function helper(uint256 x) internal pure returns(uint256){ return x+1; } } contract C is A { function f(uint256 x) external pure returns(uint256){ return helper(x); } }`, 'C'],
  // abstract base with implemented virtual, no override needed in derived (call inherited directly)
  ['inh-call-inherited-virtual',
   `@abstract class A { @virtual @external f(): u256 { return 5n; } } @contract class C extends A { @external g(): u256 { return this.f(); } }`,
   `abstract contract A { function f() external virtual returns(uint256){ return 5; } } contract C is A { function g() external returns(uint256){ return this.f(); } }`, 'C'],
  // super call from derived to base internal
  ['inh-super-internal',
   `@abstract class A { @virtual f(): u256 { return 1n; } } @contract class C extends A { @override f(): u256 { return super.f() + 1n; } @external g(): u256 { return this.f(); } }`,
   `abstract contract A { function f() internal virtual returns(uint256){ return 1; } } contract C is A { function f() internal override returns(uint256){ return super.f()+1; } function g() external returns(uint256){ return f(); } }`, 'C'],
  // 3-level inheritance chain
  ['inh-3level',
   `@abstract class A { @state x: u256; } @abstract class B extends A { @state y: u256; } @contract class C extends B { @external f(): u256 { this.x = 1n; this.y = 2n; return this.x + this.y; } }`,
   `abstract contract A { uint256 x; } abstract contract B is A { uint256 y; } contract C is B { function f() external returns(uint256){ x=1; y=2; return x+y; } }`, 'C'],

  // ---------- LIBRARY ----------
  // library internal call returning struct
  ['lib-struct-ret',
   `@struct class P { x: u256; y: u256; } @library class L { mk(a: u256): P { return P(a, a); } } @contract class C { @external @pure f(a: u256): P { return L.mk(a); } }`,
   `library L { struct P { uint256 x; uint256 y; } function mk(uint256 a) internal pure returns(P memory){ return P(a,a); } } contract C { function f(uint256 a) external pure returns(L.P memory){ return L.mk(a); } }`, 'C'],
  // @using attached method on a struct type
  ['lib-using-struct',
   `@struct class P { x: u256; y: u256; } @library class L { sum(p: P): u256 { return p.x + p.y; } } @contract @using(L) class C { @external @pure f(p: P): u256 { return p.sum(); } }`,
   `struct P { uint256 x; uint256 y; } library L { function sum(P memory p) internal pure returns(uint256){ return p.x+p.y; } } contract C { using L for P; function f(P memory p) external pure returns(uint256){ return p.sum(); } }`, 'C'],
  // @using for a value type u256 with attached method
  ['lib-using-u256',
   `@library class L { inc(x: u256): u256 { return x + 1n; } } @contract @using(L) class C { @external @pure f(x: u256): u256 { return x.inc(); } }`,
   `library L { function inc(uint256 x) internal pure returns(uint256){ return x+1; } } contract C { using L for uint256; function f(uint256 x) external pure returns(uint256){ return x.inc(); } }`, 'C'],
  // library fn taking array param
  ['lib-arr-param',
   `@library class L { sum(a: u256[]): u256 { let s: u256 = 0n; let i: u256 = 0n; while (i < a.length) { s = s + a[i]; i = i + 1n; } return s; } } @contract class C { @external @pure f(a: u256[]): u256 { return L.sum(a); } }`,
   `library L { function sum(uint256[] memory a) internal pure returns(uint256){ uint256 s; for(uint256 i; i<a.length; i++){ s+=a[i]; } return s; } } contract C { function f(uint256[] calldata a) external pure returns(uint256){ return L.sum(a); } }`, 'C'],

  // ---------- INTERFACE / TRY-CATCH ----------
  // interface returning a tuple
  ['if-tuple-ret',
   `@interface class IFoo { @external @view pair(): [u256, u256]; } @contract class C { @external f(t: address): u256 { let [a, b]: [u256, u256] = IFoo(t).pair(); return a + b; } }`,
   `interface IFoo { function pair() external view returns(uint256, uint256); } contract C { function f(address t) external returns(uint256){ (uint256 a, uint256 b) = IFoo(t).pair(); return a+b; } }`, 'C'],
  // interface call with bytes/string return
  ['if-string-ret',
   `@interface class IFoo { @external @view str(): string; } @contract class C { @external f(t: address): string { return IFoo(t).str(); } }`,
   `interface IFoo { function str() external view returns(string memory); } contract C { function f(address t) external returns(string memory){ return IFoo(t).str(); } }`, 'C'],
  // try/catch with value capture, returning the value
  ['try-value',
   `@interface class IFoo { @external echo(x: u256): u256; } @contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).echo(21n); return r; } catch (e) { return 999n; } } }`,
   `interface IFoo { function echo(uint256) external returns(uint256); } contract C { function f(address t) external returns(uint256){ try IFoo(t).echo(21) returns(uint256 r){ return r; } catch { return 999; } } }`, 'C'],
  // interface call passing an array argument
  ['if-arr-arg',
   `@interface class IFoo { @external sumIt(a: u256[]): u256; } @contract class C { @external f(t: address, a: u256[]): u256 { return IFoo(t).sumIt(a); } }`,
   `interface IFoo { function sumIt(uint256[] calldata) external returns(uint256); } contract C { function f(address t, uint256[] calldata a) external returns(uint256){ return IFoo(t).sumIt(a); } }`, 'C'],
];

let nOR=0, nOA=0;
for (const [name, jeth, solc, n] of cases) {
  const jr=J(jeth), sr=S(solc,n);
  const over_rej = jr.startsWith('JETH') && sr==='ACCEPT';
  const over_acc = jr==='ACCEPT' && sr==='REJECT';
  if (over_rej) nOR++;
  if (over_acc) nOA++;
  const flag = over_rej ? '  <<<< OVER-REJECTION' : over_acc ? '  <<<< OVER-ACCEPTANCE' : '';
  console.log(`${name.padEnd(28)} JETH=${jr.padEnd(20)} solc=${sr}${flag}`);
}
console.log(`\nTotal: ${cases.length} cases, ${nOR} over-rejections, ${nOA} over-acceptances`);
