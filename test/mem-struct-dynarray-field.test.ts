// MEM-STRUCT-DYNARRAY-FIELD boundary pin (keep-reject + safe-target guard).
//
// A memory (or memory-constructed) struct whose field is a DYNAMIC ARRAY (u256[] / bytes[] / string[] /
// T[][] / Q[]) has two SEPARATE cases, on opposite sides of the ABSOLUTE BAR:
//
//  (1) SAFE, already byte-identical (no lift needed): construct the field from a TRUE dynamic-array VALUE
//      (a `new Array<E>(n)` local, an @internal-returning call, ...) and read it back. index / .length /
//      OOB Panic 0x32 / whole-field alias-out / whole-field return / abi.encode(field) / storage assign are
//      all byte-identical to solc 0.8.35. This is the "read side" the audit flagged - it works today via
//      buildStructFieldArg's dynamic-array-value branch + allocDynStructToMem's aggArgToMemPtr head word.
//
//  (2) KEEP-REJECT (must NOT be lifted): an inline array LITERAL directly as the constructor field arg -
//      `S({arr: [3n, 4n]})` / `P(7n, [Pt(..),Pt(..)])` / `D(1n, [bytes("x")])`. solc REJECTS this
//      ("Invalid implicit conversion from uint256[2] memory to uint256[] memory"): a fixed-array literal
//      `[a, b]` is a uint*[N] that does NOT implicitly convert to a dynamic array as a constructor field.
//      The runtime image JETH would build is byte-identical to the local form, BUT accepting a program solc
//      rejects is an OVER-ACCEPTANCE - a bar violation (see the OR-c anti-lift in audit-over-rejections.test.ts).
//      JETH's local-decl literal sugar (`let a: u256[] = [3n,4n]`, SUPPORTED.md) is a tolerated over-acceptance;
//      the struct-constructor-field position is deliberately held to solc parity and stays a clean JETH226 reject.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { hexToBytes, bytesToHex } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const hx = (s: string) => hexToBytes(('0x' + s) as `0x${string}`);
const pad = (n: bigint) => n.toString(16).padStart(64, '0');

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  let anyOk = false;
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
    if (rj.success) anyOk = true;
  }
  expect(anyOk, 'at least one call succeeds (non-vacuity)').toBe(true);
}

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};
// True iff solc REJECTS `src` at compile time (the keep-reject witness).
const solcRejects = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};

describe('MEM-STRUCT-DYNARRAY-FIELD: safe read side is byte-identical; literal construction stays a reject', () => {
  it('SAFE: construct a u256[] field from a local + read (index / length / OOB / alias / return / abi.encode)', async () => {
    const J = `type S={arr:u256[]}; class C{
      get g():External<u256>{ let a:u256[]=new Array<u256>(3n); a[0n]=10n;a[1n]=20n;a[2n]=30n; let s:S={arr:a}; return s.arr[2n]; }
      get l():External<u256>{ let a:u256[]=new Array<u256>(3n); let s:S={arr:a}; return s.arr.length; }
      get oob():External<u256>{ let a:u256[]=new Array<u256>(2n); let s:S={arr:a}; return s.arr[5n]; }
      get al():External<u256>{ let a:u256[]=new Array<u256>(3n); a[0n]=10n;a[1n]=20n;a[2n]=30n; let s:S={arr:a}; let b:u256[]=s.arr; return b[1n]; }
      get w():External<u256[]>{ let a:u256[]=new Array<u256>(3n); a[0n]=10n;a[1n]=20n;a[2n]=30n; let s:S={arr:a}; return s.arr; }
      get e():External<bytes>{ let a:u256[]=new Array<u256>(3n); a[0n]=10n;a[1n]=20n;a[2n]=30n; let s:S={arr:a}; return abi.encode(s.arr); }
    }`;
    const S = `contract C{ struct S{uint256[] arr;}
      function _m() internal pure returns(uint256[] memory a){ a=new uint256[](3); a[0]=10;a[1]=20;a[2]=30; }
      function g() external pure returns(uint256){ S memory s=S({arr:_m()}); return s.arr[2]; }
      function l() external pure returns(uint256){ uint256[] memory a=new uint256[](3); S memory s=S({arr:a}); return s.arr.length; }
      function oob() external pure returns(uint256){ uint256[] memory a=new uint256[](2); S memory s=S({arr:a}); return s.arr[5]; }
      function al() external pure returns(uint256){ S memory s=S({arr:_m()}); uint256[] memory b=s.arr; return b[1]; }
      function w() external pure returns(uint256[] memory){ S memory s=S({arr:_m()}); return s.arr; }
      function e() external pure returns(bytes memory){ S memory s=S({arr:_m()}); return abi.encode(s.arr); }
    }`;
    await eqCalls(J, S, [['g()', ''], ['l()', ''], ['oob()', ''], ['al()', ''], ['w()', ''], ['e()', '']]);
  });

  it('SAFE: packed value + bytes[]/string[] fields from a local + read', async () => {
    const J = `type S={n:u256,tags:bytes[],names:string[]}; class C{
      get n():External<u256>{ let t:bytes[]=[bytes("x")]; let m:string[]=["hi","yo"]; let s:S={n:7n,tags:t,names:m}; return s.n; }
      get t():External<bytes>{ let t:bytes[]=[bytes("x")]; let m:string[]=["hi","yo"]; let s:S={n:7n,tags:t,names:m}; return s.tags[0n]; }
      get nm():External<string>{ let t:bytes[]=[bytes("x")]; let m:string[]=["hi","yo"]; let s:S={n:7n,tags:t,names:m}; return s.names[1n]; }
    }`;
    const S = `contract C{ struct S{uint256 n;bytes[] tags;string[] names;}
      function _s() internal pure returns(S memory s){ bytes[] memory t=new bytes[](1); t[0]=bytes("x"); string[] memory m=new string[](2); m[0]="hi"; m[1]="yo"; s=S({n:7,tags:t,names:m}); }
      function n() external pure returns(uint256){ return _s().n; }
      function t() external pure returns(bytes memory){ return _s().tags[0]; }
      function nm() external pure returns(string memory){ return _s().names[1]; }
    }`;
    await eqCalls(J, S, [['n()', ''], ['t()', ''], ['nm()', '']]);
  });

  it('SAFE: storage assign of a locally-constructed struct - byte-identical getters AND raw storage', async () => {
    const J = `type S={n:u256,arr:u256[]}; class C{
      s: S;
      set(): External<void>{ let a:u256[]=new Array<u256>(3n); a[0n]=11n;a[1n]=22n;a[2n]=33n; this.s = {n:7n, arr:a}; }
      get n(): External<u256>{ return this.s.n; }
      get len(): External<u256>{ return this.s.arr.length; }
      get at2(): External<u256>{ return this.s.arr[2n]; }
    }`;
    const S = `contract C{ struct S{uint256 n;uint256[] arr;} S s;
      function set() external { uint256[] memory a=new uint256[](3); a[0]=11;a[1]=22;a[2]=33; s = S({n:7,arr:a}); }
      function n() external view returns(uint256){ return s.n; }
      function len() external view returns(uint256){ return s.arr.length; }
      function at2() external view returns(uint256){ return s.arr[2]; }
    }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj: Address = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as: Address = await hs.deploy(compileSolidity(SPDX + S, 'C').creation);
    await hj.call(aj, sel('set()'));
    await hs.call(as, sel('set()'));
    for (const g of ['n()', 'len()', 'at2()']) {
      expect((await hj.call(aj, sel(g))).returnHex, `getter ${g}`).toBe((await hs.call(as, sel(g))).returnHex);
    }
    // slot0=n, slot1=arr.length, keccak(slot1)+i = elements. A dropped payload would zero the element slots.
    const dataBase = BigInt('0x' + toHex(keccak(hx(pad(1n)))));
    for (const slot of [0n, 1n, dataBase, dataBase + 1n, dataBase + 2n]) {
      const vj = bytesToHex(await hj.evm.stateManager.getStorage(aj, hx(pad(slot))));
      const vs = bytesToHex(await hs.evm.stateManager.getStorage(as, hx(pad(slot))));
      expect(vj, `raw storage slot ${slot}`).toBe(vs);
    }
    expect(BigInt(bytesToHex(await hj.evm.stateManager.getStorage(aj, hx(pad(dataBase + 2n)))))).toBe(33n);
  });

  it('KEEP-REJECT: an inline array literal as a dynamic-array constructor field stays a clean JETH226 reject (solc parity)', () => {
    // Each of these is REJECTED by solc (fixed [N] -> dynamic implicit conversion), so JETH accepting it
    // would be an over-acceptance. JETH keeps the JETH226 reject; the differential-verified byte-identical
    // path is the local form (guarded by the SAFE tests above), not the literal.
    const cases: [string, string][] = [
      // [JETH source, solc twin that solc rejects]
      [
        `type S={arr:u256[]}; class C{ get g():External<u256>{ let s:S={arr:[3n,4n]}; return s.arr[0n]; } }`,
        `contract C{ struct S{uint256[] arr;} function g() external pure returns(uint256){ S memory s=S({arr:[uint256(3),4]}); return s.arr[0]; } }`,
      ],
      [
        `type P={id:u256,pts:u256[]}; class C{ get g():External<u256>{ let p:P=P(7n,[1n,2n]); return p.id; } }`,
        `contract C{ struct P{uint256 id;uint256[] pts;} function g() external pure returns(uint256){ P memory p=P(7,[uint256(1),2]); return p.id; } }`,
      ],
      [
        `type D={id:u256,tags:bytes[]}; class C{ get g():External<u256>{ let d:D=D(1n,[bytes("x")]); return d.id; } }`,
        `contract C{ struct D{uint256 id;bytes[] tags;} function g() external pure returns(uint256){ bytes[1] memory a=[bytes("x")]; D memory d=D(1,a); return d.id; } }`,
      ],
    ];
    for (const [j, s] of cases) {
      expect(codes(j), `JETH must reject: ${j.slice(0, 60)}`).toContain('JETH226');
      expect(solcRejects(s), `solc must reject the twin: ${s.slice(0, 60)}`).toBe(true);
    }
  });
});
