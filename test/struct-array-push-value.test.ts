// SOUNDNESS regression: this.arr.push(<a struct VALUE>) where the value is NOT a constructor literal.
// lowerStructPush previously wrote the pushed element only when the value was a structNew; EVERY other
// struct source (a memory struct local, a function param, a storage struct, a whole nested-dyn-struct
// field v.t, a storage array element) fell into the no-arg `push()` branch and silently stored an ALL-ZERO
// element - a wrong-bytes MISCOMPILE (the call succeeds, the array grows, but the data is lost). Fixed by
// routing any present push value through storeStructTo (the same writer `this.field = value` uses), which
// dispatches every source kind correctly. The no-arg `push()` still appends a zero element.
// Verified byte-identical to solc 0.8.35 by reading the pushed elements back through getters.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => n.toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

describe('struct[].push(<value>) writes the pushed value (not zeros) - byte-identical to solc 0.8.35', () => {
  it('push a dynamic-field struct memory local', async () => {
    await eqCalls(
      '@struct class T { n: u256; s: string } @contract class C { @state arr: T[]; @external setit(): void { let t: T = T(55n, "pushed"); this.arr.push(t); } @external @view rn(i: u256): u256 { return this.arr[i].n; } @external @view rs(i: u256): string { return this.arr[i].s; } }',
      'struct T { uint256 n; string s; } contract C { T[] arr; function setit() external { T memory t=T(55,"pushed"); arr.push(t); } function rn(uint256 i) external view returns(uint256){ return arr[i].n; } function rs(uint256 i) external view returns(string memory){ return arr[i].s; } }',
      [['setit()', ''], ['rn(uint256)', W(0n)], ['rs(uint256)', W(0n)]],
    );
  });

  it('push a static struct memory local (packed and unpacked)', async () => {
    await eqCalls(
      '@struct class Q { a: u8; b: u128; c: u256 } @contract class C { @state arr: Q[]; @external setit(): void { let q: Q = Q(3n, 4n, 5n); this.arr.push(q); } @external @view ra(i: u256): u8 { return this.arr[i].a; } @external @view rb(i: u256): u128 { return this.arr[i].b; } @external @view rc(i: u256): u256 { return this.arr[i].c; } }',
      'struct Q { uint8 a; uint128 b; uint256 c; } contract C { Q[] arr; function setit() external { Q memory q=Q(3,4,5); arr.push(q); } function ra(uint256 i) external view returns(uint8){ return arr[i].a; } function rb(uint256 i) external view returns(uint128){ return arr[i].b; } function rc(uint256 i) external view returns(uint256){ return arr[i].c; } }',
      [['setit()', ''], ['ra(uint256)', W(0n)], ['rb(uint256)', W(0n)], ['rc(uint256)', W(0n)]],
    );
  });

  it('push a struct memory/calldata function param', async () => {
    await eqCalls(
      '@struct class T { n: u256; s: string } @contract class C { @state arr: T[]; pm(t: T): void { this.arr.push(t); } @external viaMem(): void { this.pm(T(7n, "mp")); } @external viaCd(t: T): void { this.arr.push(t); } @external @view rn(i: u256): u256 { return this.arr[i].n; } @external @view rs(i: u256): string { return this.arr[i].s; } }',
      'struct T { uint256 n; string s; } contract C { T[] arr; function pm(T memory t) internal { arr.push(t); } function viaMem() external { pm(T(7,"mp")); } function viaCd(T calldata t) external { arr.push(t); } function rn(uint256 i) external view returns(uint256){ return arr[i].n; } function rs(uint256 i) external view returns(string memory){ return arr[i].s; } }',
      [
        ['viaMem()', ''],
        ['viaCd((uint256,string))', W(0x20n) + W(9n) + W(0x40n) + W(2n) + '6363'.padEnd(64, '0')],
        ['rn(uint256)', W(0n)], ['rs(uint256)', W(0n)],
        ['rn(uint256)', W(1n)], ['rs(uint256)', W(1n)],
      ],
    );
  });

  it('push a storage struct and a storage array element (copy)', async () => {
    await eqCalls(
      '@struct class T { n: u256; s: string } @contract class C { @state d: T; @state arr: T[]; @external setd(): void { this.d = T(9n, "sd"); this.arr.push(this.d); } @external dup(): void { this.arr.push(this.arr[0n]); } @external @view rn(i: u256): u256 { return this.arr[i].n; } @external @view rs(i: u256): string { return this.arr[i].s; } }',
      'struct T { uint256 n; string s; } contract C { T d; T[] arr; function setd() external { d=T(9,"sd"); arr.push(d); } function dup() external { arr.push(arr[0]); } function rn(uint256 i) external view returns(uint256){ return arr[i].n; } function rs(uint256 i) external view returns(string memory){ return arr[i].s; } }',
      [['setd()', ''], ['dup()', ''], ['rn(uint256)', W(0n)], ['rs(uint256)', W(0n)], ['rn(uint256)', W(1n)], ['rs(uint256)', W(1n)]],
    );
  });

  it('multiple pushes grow the array with the right values; no-arg push() appends a zero element', async () => {
    await eqCalls(
      '@struct class P { x: u256; y: u256 } @contract class C { @state arr: P[]; @external setit(): void { let a: P = P(1n, 2n); this.arr.push(a); this.arr.push(P(3n, 4n)); this.arr.push(); } @external @view len(): u256 { return u256(this.arr.length); } @external @view rx(i: u256): u256 { return this.arr[i].x; } @external @view ry(i: u256): u256 { return this.arr[i].y; } }',
      'struct P { uint256 x; uint256 y; } contract C { P[] arr; function setit() external { P memory a=P(1,2); arr.push(a); arr.push(P(3,4)); arr.push(); } function len() external view returns(uint256){ return arr.length; } function rx(uint256 i) external view returns(uint256){ return arr[i].x; } function ry(uint256 i) external view returns(uint256){ return arr[i].y; } }',
      [
        ['setit()', ''], ['len()', ''],
        ['rx(uint256)', W(0n)], ['ry(uint256)', W(0n)],
        ['rx(uint256)', W(1n)], ['ry(uint256)', W(1n)],
        ['rx(uint256)', W(2n)], ['ry(uint256)', W(2n)],
      ],
    );
  });
});
