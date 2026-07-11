// Edge C (over-rejection lifted byte-identical): an INDEXED event parameter that is an array of dynamic
// structs (P[] / Arr<P,N>) where the struct element has a DYNAMIC-ARRAY field (tags: u256[], names:
// string[], grid: u256[][]) or a NESTED DYNAMIC-STRUCT field (inner: Q). Previously JETH207. The topic is
// keccak256 of the packed-padded preimage: packTopicStructFromAbi now follows each such field through its
// head offset and recurses (a dyn-array field -> packTopicArray; a nested-dyn-struct field ->
// packTopicStructFromAbi), exactly mirroring the value/bytes/static-aggregate fields already supported and
// the single-indexed-struct path. The gate isTopicEncodableDynStruct was widened to match. Verified
// byte-identical to solc 0.8.35 by comparing the emitted log topics + data (the returnHex harness would
// miss a wrong topic). Sources are calldata params (a struct dyn-array field can't be built from an array
// literal - JETH226, a separate limitation).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => BigInt(n).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function logEq(jeth: string, sol: string, sig: string, args: string) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  const rj = await hj.call(aj, sel(sig) + args);
  const rs = await hs.call(as, sel(sig) + args);
  expect(rj.success, `${sig} success`).toBe(rs.success);
  const fmt = (r: { logs?: { topics: string[]; data: string }[] }) =>
    JSON.stringify((r.logs ?? []).map((l) => ({ t: l.topics, d: l.data })));
  expect(fmt(rj), `${sig} log`).toBe(fmt(rs));
}

const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: unknown) {
    return ((e as { diagnostics?: { code: string }[] })?.diagnostics ?? []).map((d) => d.code);
  }
};

describe('Edge C: indexed dyn-struct-element array with a dyn-array / nested-struct field - byte-identical to solc 0.8.35', () => {
  it('P[] where P has a u256[] field (multi-element, varying inner length, empty outer)', async () => {
    const J = 'type P = {a:u256;tags:u256[]}; class C { E: event<{ ps: indexed<P[]> }>; go(ps: P[]): External<void> { emit(E(ps)); } }';
    const S = 'contract C { struct P{uint256 a;uint256[] tags;} event E(P[] indexed ps); function go(P[] calldata ps) external { emit E(ps); } }';
    await logEq(J, S, 'go((uint256,uint256[])[])', W(0x20) + W(2) + W(0x40) + W(0x100) + W(7) + W(0x40) + W(2) + W(1) + W(2) + W(9) + W(0x40) + W(1) + W(3));
    await logEq(J, S, 'go((uint256,uint256[])[])', W(0x20) + W(0)); // empty outer
  });

  it('P[] where P has a string[] field', async () => {
    await logEq(
      'type P = {a:u256;names:string[]}; class C { E: event<{ ps: indexed<P[]> }>; go(ps: P[]): External<void> { emit(E(ps)); } }',
      'contract C { struct P{uint256 a;string[] names;} event E(P[] indexed ps); function go(P[] calldata ps) external { emit E(ps); } }',
      'go((uint256,string[])[])',
      W(0x20) + W(1) + W(0x20) + W(7) + W(0x40) + W(2) + W(0x40) + W(0x80) + W(2) + '6161'.padEnd(64, '0') + W(2) + '6262'.padEnd(64, '0'),
    );
  });

  it('P[] where P has a nested dynamic struct field Q{s:string} and Q{n:u256;b:bytes}', async () => {
    await logEq(
      'type Q = {s:string}; type P = {a:u256;inner:Q}; class C { E: event<{ ps: indexed<P[]> }>; go(ps: P[]): External<void> { emit(E(ps)); } }',
      'contract C { struct Q{string s;} struct P{uint256 a;Q inner;} event E(P[] indexed ps); function go(P[] calldata ps) external { emit E(ps); } }',
      'go((uint256,(string))[])',
      W(0x20) + W(1) + W(0x20) + W(5) + W(0x40) + W(0x20) + W(3) + '616263'.padEnd(64, '0'),
    );
    await logEq(
      'type Q = {n:u256;b:bytes}; type P = {a:u256;inner:Q}; class C { E: event<{ ps: indexed<P[]> }>; go(ps: P[]): External<void> { emit(E(ps)); } }',
      'contract C { struct Q{uint256 n;bytes b;} struct P{uint256 a;Q inner;} event E(P[] indexed ps); function go(P[] calldata ps) external { emit E(ps); } }',
      'go((uint256,(uint256,bytes))[])',
      W(0x20) + W(1) + W(0x20) + W(5) + W(0x40) + W(9) + W(0x40) + W(4) + '61626364'.padEnd(64, '0'),
    );
  });

  it('combined value + bytes + dyn-array fields, multi-element', async () => {
    await logEq(
      'type P = {a:u256;s:string;tags:u256[]}; class C { E: event<{ ps: indexed<P[]> }>; go(ps: P[]): External<void> { emit(E(ps)); } }',
      'contract C { struct P{uint256 a;string s;uint256[] tags;} event E(P[] indexed ps); function go(P[] calldata ps) external { emit E(ps); } }',
      'go((uint256,string,uint256[])[])',
      W(0x20) + W(2) + W(0x40) + W(0x140) +
        W(7) + W(0x60) + W(0xa0) + W(2) + '6869'.padEnd(64, '0') + W(2) + W(1) + W(2) +
        W(8) + W(0x60) + W(0x80) + W(0) + W(1) + W(9),
    );
  });

  it('deeper: a struct-element-array field (P{a; qs: Q[]}) and a nested value-array field (u256[][])', async () => {
    await logEq(
      'type Q = {m:u256;s:string}; type P = {a:u256;qs:Q[]}; class C { E: event<{ ps: indexed<P[]> }>; go(ps: P[]): External<void> { emit(E(ps)); } }',
      'contract C { struct Q{uint256 m;string s;} struct P{uint256 a;Q[] qs;} event E(P[] indexed ps); function go(P[] calldata ps) external { emit E(ps); } }',
      'go((uint256,(uint256,string)[])[])',
      W(0x20) + W(1) + W(0x20) + W(5) + W(0x40) + W(1) + W(0x20) + W(7) + W(0x40) + W(3) + '787978'.padEnd(64, '0'),
    );
    await logEq(
      'type P = {a:u256;grid:u256[][]}; class C { E: event<{ ps: indexed<P[]> }>; go(ps: P[]): External<void> { emit(E(ps)); } }',
      'contract C { struct P{uint256 a;uint256[][] grid;} event E(P[] indexed ps); function go(P[] calldata ps) external { emit E(ps); } }',
      'go((uint256,uint256[][])[])',
      W(0x20) + W(1) + W(0x20) + W(5) + W(0x40) + W(2) + W(0x40) + W(0xa0) + W(2) + W(1) + W(2) + W(1) + W(3),
    );
  });

  it('a single indexed struct with the same fields stays byte-identical (shared gate), plus a mixed event', async () => {
    await logEq(
      'type P = {a:u256;tags:u256[]}; class C { E: event<{ p: indexed<P> }>; go(p: P): External<void> { emit(E(p)); } }',
      'contract C { struct P{uint256 a;uint256[] tags;} event E(P indexed p); function go(P calldata p) external { emit E(p); } }',
      'go((uint256,uint256[]))',
      W(0x20) + W(7) + W(0x40) + W(3) + W(1) + W(2) + W(3),
    );
    await logEq(
      'type P = {a:u256;tags:u256[]}; class C { E: event<{ n: indexed<u256>; ps: indexed<P[]>; m: u256 }>; go(n: u256, ps: P[], m: u256): External<void> { emit(E(n, ps, m)); } }',
      'contract C { struct P{uint256 a;uint256[] tags;} event E(uint256 indexed n, P[] indexed ps, uint256 m); function go(uint256 n, P[] calldata ps, uint256 m) external { emit E(n, ps, m); } }',
      'go(uint256,(uint256,uint256[])[],uint256)',
      W(99) + W(0x80) + W(7) + W(0x20) + W(1) + W(0x20) + W(5) + W(0x40) + W(1) + W(8),
    );
  });

  it('the non-indexed (data) form of the same event is unaffected', async () => {
    await logEq(
      'type P = {a:u256;tags:u256[]}; class C { E: event<{ ps: P[] }>; go(ps: P[]): External<void> { emit(E(ps)); } }',
      'contract C { struct P{uint256 a;uint256[] tags;} event E(P[] ps); function go(P[] calldata ps) external { emit E(ps); } }',
      'go((uint256,uint256[])[])',
      W(0x20) + W(1) + W(0x20) + W(7) + W(0x40) + W(1) + W(42),
    );
  });

  it('the previously-accepted shapes (string field, static-element arrays) still compile', () => {
    expect(codes('type P = {a:u256;s:string}; class C { E: event<{ ps: indexed<P[]> }>; go(ps: P[]): External<void> { emit(E(ps)); } }')).toEqual([]);
  });
});
