import { compile } from './src/compile.js';
import { compileSolidity } from './test/_solidity.js';
const SPDX='// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
function jeth(src:string):string{ try{ compile(src,{fileName:'C.jeth'}); return 'ACCEPT'; }catch(e:any){ return e.diagnostics? 'REJECT['+[...new Set(e.diagnostics.map((d:any)=>d.code))].join(',')+']' : 'ERR '+e.message; } }
function sol(src:string):string{ try{ compileSolidity(SPDX+src,'C'); return 'ACCEPT'; }catch(e:any){ return 'REJECT'; } }
function row(id:string, j:string, s:string){ const div = (j.startsWith('ACCEPT')!==s.startsWith('ACCEPT')); console.log(`${div?'DIVERGE':'  same '} ${id}  J=${j}  S=${s}`); }
// A. exact-length hex literal -> bytesN (CAND 5/7/8)
row('A1 return 0x12345678n:bytes4', jeth(`@contract class C { @external @pure f(): bytes4 { return 0x12345678n; } }`), sol(`contract C { function f() external pure returns(bytes4){ return 0x12345678; } }`));
row('A2 let bytes4', jeth(`@contract class C { @external @pure f(): bytes4 { let b: bytes4 = 0x12345678n; return b; } }`), sol(`contract C { function f() external pure returns(bytes4){ bytes4 b=0x12345678; return b; } }`));
row('A3 @constant bytes4', jeth(`@contract class C { @constant B: bytes4 = 0x12345678n; @external @pure f(): bytes4 { return this.B; } }`), sol(`contract C { bytes4 constant B=0x12345678; function f() external pure returns(bytes4){ return B; } }`));
row('A4 SHORT 0x1234:bytes4 (both reject)', jeth(`@contract class C { @external @pure f(): bytes4 { return 0x1234n; } }`), sol(`contract C { function f() external pure returns(bytes4){ return 0x1234; } }`));
row('A5 encodeWithSelector(0x12345678n)', jeth(`@contract class C { @external @pure f(a:u256): bytes { return abi.encodeWithSelector(0x12345678n, a); } }`), sol(`contract C { function f(uint256 a) external pure returns(bytes memory){ return abi.encodeWithSelector(0x12345678, a); } }`));
// B. bytes push/pop/index-write through non-direct base (CAND 9-16)
row('B1 struct.bytes.push', jeth(`@struct class D { x: u256; data: bytes; } @contract class C { @state d: D; @external p(b: bytes1): void { this.d.data.push(b); } }`), sol(`contract C { struct D{uint256 x;bytes data;} D d; function p(bytes1 b) external { d.data.push(b); } }`));
row('B2 struct.bytes.pop', jeth(`@struct class D { x: u256; data: bytes; } @contract class C { @state d: D; @external p(): void { this.d.data.pop(); } }`), sol(`contract C { struct D{uint256 x;bytes data;} D d; function p() external { d.data.pop(); } }`));
row('B3 struct.bytes[i]=x', jeth(`@struct class D { x: u256; data: bytes; } @contract class C { @state d: D; @external s(i: u256, x: bytes1): void { this.d.data[i] = x; } }`), sol(`contract C { struct D{uint256 x;bytes data;} D d; function s(uint256 i,bytes1 x) external { d.data[i]=x; } }`));
row('B4 map<u256,bytes>.push', jeth(`@contract class C { @state m: mapping<u256, bytes>; @external p(k: u256, x: bytes1): void { this.m[k].push(x); } }`), sol(`contract C { mapping(uint256=>bytes) m; function p(uint256 k,bytes1 x) external { m[k].push(x); } }`));
row('B5 map<u256,bytes>[k][i]=x', jeth(`@contract class C { @state m: mapping<u256, bytes>; @external s(k: u256, i: u256, x: bytes1): void { this.m[k][i] = x; } }`), sol(`contract C { mapping(uint256=>bytes) m; function s(uint256 k,uint256 i,bytes1 x) external { m[k][i]=x; } }`));
row('B6 bytes[] elem .push', jeth(`@contract class C { @state a: bytes[]; @external p(i: u256, x: bytes1): void { this.a[i].push(x); } }`), sol(`contract C { bytes[] a; function p(uint256 i,bytes1 x) external { a[i].push(x); } }`));
row('B7 bytes[] elem [j]=x', jeth(`@contract class C { @state a: bytes[]; @external s(i: u256, j: u256, x: bytes1): void { this.a[i][j] = x; } }`), sol(`contract C { bytes[] a; function s(uint256 i,uint256 j,bytes1 x) external { a[i][j]=x; } }`));
row('B8 Arr<bytes,3> elem .push', jeth(`@contract class C { @state a: Arr<bytes,3>; @external p(i: u256, x: bytes1): void { this.a[i].push(x); } }`), sol(`contract C { bytes[3] a; function p(uint256 i,bytes1 x) external { a[i].push(x); } }`));
// C. bytes(string)[i] (CAND 17)
row('C1 bytes(s)[i]', jeth(`@contract class C { @external at(s: string, i: u256): bytes1 { return bytes(s)[i]; } }`), sol(`contract C { function at(string calldata s,uint256 i) external pure returns(bytes1){ return bytes(s)[i]; } }`));
// D. @error param types + reserved names + namespace (CAND 18,19,20,21)
row('D1 @error Panic (over-accept)', jeth(`@contract class C { @error Panic(code: u256); @external f(): void { revert(Panic(99n)); } }`), sol(`contract C { error Panic(uint256 code); function f() external { revert Panic(99); } }`));
row('D2 @error Error (over-accept)', jeth(`@contract class C { @error Error(s: string); @external f(): void { revert(Error("x")); } }`), sol(`contract C { error Error(string s); function f() external { revert Error("x"); } }`));
row('D3 @error static struct param', jeth(`@struct class P { x: u256; y: bool; } @contract class C { @error Bad(p: P); @external f(): void { revert(Bad(P(42n, true))); } }`), sol(`contract C { struct P{uint256 x;bool y;} error Bad(P p); function f() external { revert Bad(P(42,true)); } }`));
row('D4 @error fixed-array param', jeth(`@contract class C { @error Bad(a: Arr<u256, 2>); @external f(): void { let x: Arr<u256,2> = [5n,6n]; revert(Bad(x)); } }`), sol(`contract C { error Bad(uint256[2] a); function f() external { uint256[2] memory x=[uint256(5),6]; revert Bad(x); } }`));
row('D5 error X + event X collision (over-accept)', jeth(`@contract class C { @error X(a: u256); @event X(a: u256); @external f(): void { revert(X(1n)); } }`), sol(`contract C { error X(uint256 a); event X(uint256 a); function f() external { revert X(1); } }`));
// E. nested inline struct ctor in return (CAND 3)
row('E1 return Outer(id, Inner(c,v))', jeth(`@struct class Inner { c: u8; v: u32; } @struct class Outer { id: u16; inner: Inner; } @contract class C { @external @pure f(id: u16, c: u8, v: u32): Outer { return Outer(id, Inner(c, v)); } }`), sol(`contract C { struct Inner{uint8 c;uint32 v;} struct Outer{uint16 id;Inner inner;} function f(uint16 id,uint8 c,uint32 v) external pure returns(Outer memory){ return Outer(id, Inner(c,v)); } }`));
// F. whole memory fixed-array -> storage (CAND 6)
row('F1 this.g = m (Arr local)', jeth(`@contract class C { @state g: Arr<u256,3>; @external f(): u256 { let m: Arr<u256,3> = [111n,222n,333n]; this.g = m; return this.g[2n]; } }`), sol(`contract C { uint256[3] g; function f() external returns(uint256){ uint256[3] memory m=[uint256(111),222,333]; g=m; return g[2]; } }`));
// G. @constant rational fold (CAND 4)
row('G1 @constant (10n/4n)*4n', jeth(`@contract class C { @constant K: u256 = (10n/4n)*4n; @external @pure f(): u256 { return this.K; } }`), sol(`contract C { uint256 constant K=(10/4)*4; function f() external pure returns(uint256){ return K; } }`));
row('G2 @state x = (10n/4n)*4n', jeth(`@contract class C { @state x: u256 = (10n/4n)*4n; @external @pure f(): u256 { return 0n; } }`), sol(`contract C { uint256 x=(10/4)*4; function f() external pure returns(uint256){ return 0; } }`));
// H. enum -> i8 cast (CAND 1)
row('H1 i8(enum) over-accept', jeth(`enum Color { Red, Green, Blue } @contract class C { @external @pure f(c: Color): i8 { return i8(c); } }`), sol(`contract C { enum Color{Red,Green,Blue} function f(Color c) external pure returns(int8){ return int8(c); } }`));
row('H2 i16(enum) (both reject)', jeth(`enum Color { Red, Green, Blue } @contract class C { @external @pure f(c: Color): i16 { return i16(c); } }`), sol(`contract C { enum Color{Red,Green,Blue} function f(Color c) external pure returns(int16){ return int16(c); } }`));
// I. array literal wrong element count (CAND 2) HIGH
row('I1 [1,2,3,4,5] -> Arr<u256,3> (over-accept)', jeth(`@contract class C { @external @pure f(): Arr<u256,3> { let a: Arr<u256,3> = [1n,2n,3n,4n,5n]; return a; } }`), sol(`contract C { function f() external pure returns(uint256[3] memory){ uint256[3] memory a=[uint256(1),2,3,4,5]; return a; } }`));
row('I2 [1,2] -> Arr<u256,3> (over-accept)', jeth(`@contract class C { @external @pure f(): Arr<u256,3> { let a: Arr<u256,3> = [1n,2n]; return a; } }`), sol(`contract C { function f() external pure returns(uint256[3] memory){ uint256[3] memory a=[uint256(1),2]; return a; } }`));
