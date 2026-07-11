// Round-1 coverage-proof finding (MC-1, docs/HANDOFF-pointer-headed-coverage.md Step 2): an
// INDEXED-event TOPIC of an abiDecode-sourced Arr<In,N> (an external self-call result this.produce(),
// lowered as abiDecode(extCall,T), or a literal abi.decode(b, Arr<In,2>)) was keccak256 of the
// POINTER-HEADED memory image (N absolute element-pointer words) instead of the flat inline payload -
// a wrong-topic MISCOMPILE (both compilers accepted, both calls succeeded, DATA logs matched, only
// topic1 differed). Root cause: isPointerHeadedStaticAggArg (the topic-path transcode gate) was
// missing the abiDecode kind that prepEncodeComponent's memFixedSrc (the abi.encode / call-arg path)
// already had, so materializeStaticAggToMem fell through to aggToMemPtr and hashed pointer words.
// Now the abiDecode source rides flattenPointerHeadedStaticAgg -> abiEncFromMem like every other
// pointer-headed source. Byte-identical LOG topics + data vs solc 0.8.35.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import type { LogEntry } from '../src/evm.js';

const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);
const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
  expect(a.map((l) => ({ t: l.topics, d: l.data }))).toEqual(b.map((l) => ({ t: l.topics, d: l.data })));

const J = `type In = { x: u256; y: u256 };
type In3 = { x: u256; y: u256; z: u256 };
type In2 = { p: In; q: u256 };
class C {
  Et: event<{ v: indexed<Arr<In,2>>; tag: u256 }>;
  Et3: event<{ v: indexed<Arr<In3,3>>; tag: u256 }>;
  Et1: event<{ v: indexed<Arr<In,1>>; tag: u256 }>;
  EtN: event<{ v: indexed<Arr<In2,2>>; tag: u256 }>;
  get produce(): External<Arr<In,2>> { let a: Arr<In,2> = [In(31n,32n),In(33n,34n)]; return a; }
  get produce3(): External<Arr<In3,3>> { let a: Arr<In3,3> = [In3(41n,42n,43n),In3(44n,45n,46n),In3(47n,48n,49n)]; return a; }
  get produce1(): External<Arr<In,1>> { let a: Arr<In,1> = [In(51n,52n)]; return a; }
  get produceN(): External<Arr<In2,2>> { let a: Arr<In2,2> = [In2(In(61n,62n),63n),In2(In(64n,65n),66n)]; return a; }
  eExt(): External<void> { emit(Et(this.produce(), 77n)); }
  eExt3(): External<void> { emit(Et3(this.produce3(), 78n)); }
  eExt1(): External<void> { emit(Et1(this.produce1(), 79n)); }
  eExtN(): External<void> { emit(EtN(this.produceN(), 80n)); }
  eDec(b: bytes): External<void> { emit(Et(abi.decode(b, Arr<In,2>), 81n)); }
  eDecNF(b: bytes): External<void> { let pre: Arr<u256,2> = [1n,2n]; emit(Et(abi.decode(b, Arr<In,2>), pre[0n] + 82n)); }
  eCtl(): External<void> { let a: Arr<In,2> = [In(31n,32n),In(33n,34n)]; emit(Et(a, 83n)); }
  ctlEnc(): External<bytes> { return abi.encode(this.produce()); } }`;

const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
struct In { uint256 x; uint256 y; }
struct In3 { uint256 x; uint256 y; uint256 z; }
struct In2 { In p; uint256 q; }
contract C {
  event Et(In[2] indexed v, uint256 tag);
  event Et3(In3[3] indexed v, uint256 tag);
  event Et1(In[1] indexed v, uint256 tag);
  event EtN(In2[2] indexed v, uint256 tag);
  function produce() external pure returns (In[2] memory) { In[2] memory a; a[0]=In(31,32); a[1]=In(33,34); return a; }
  function produce3() external pure returns (In3[3] memory) { In3[3] memory a; a[0]=In3(41,42,43); a[1]=In3(44,45,46); a[2]=In3(47,48,49); return a; }
  function produce1() external pure returns (In[1] memory) { In[1] memory a; a[0]=In(51,52); return a; }
  function produceN() external pure returns (In2[2] memory) { In2[2] memory a; a[0]=In2(In(61,62),63); a[1]=In2(In(64,65),66); return a; }
  function eExt() external { emit Et(this.produce(), 77); }
  function eExt3() external { emit Et3(this.produce3(), 78); }
  function eExt1() external { emit Et1(this.produce1(), 79); }
  function eExtN() external { emit EtN(this.produceN(), 80); }
  function eDec(bytes calldata b) external { emit Et(abi.decode(b, (In[2])), 81); }
  function eDecNF(bytes calldata b) external { uint256[2] memory pre = [uint256(1),2]; emit Et(abi.decode(b, (In[2])), pre[0] + 82); }
  function eCtl() external { In[2] memory a; a[0]=In(31,32); a[1]=In(33,34); emit Et(a, 83); }
  function ctlEnc() external returns (bytes memory) { return abi.encode(this.produce()); } }`;

describe('indexed-event topic of an abiDecode-sourced Arr<In,N> (MC-1) vs solc 0.8.35', () => {
  let jh: Harness, sh: Harness, aj: Address, as: Address;
  beforeAll(async () => {
    jh = await Harness.create();
    sh = await Harness.create();
    aj = await jh.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sh.deploy(compileSolidity(S, 'C').creation);
  });

  const blob = () => W(0x20n) + W(128n) + W(31n) + W(32n) + W(33n) + W(34n);

  it('ext-call-result topics across In N=2 / In3 N=3 / N=1 / nested In2', async () => {
    for (const sg of ['eExt()', 'eExt3()', 'eExt1()', 'eExtN()']) {
      const d = '0x' + sel(sg);
      const jr = await jh.call(aj, d);
      const sr = await sh.call(as, d);
      expect(jr.success, sg).toBe(sr.success);
      eqLogs(jr.logs, sr.logs);
    }
  });

  it('literal abi.decode topic, incl a non-first-in-memory decode', async () => {
    for (const sg of ['eDec(bytes)', 'eDecNF(bytes)']) {
      const d = '0x' + sel(sg) + blob();
      const jr = await jh.call(aj, d);
      const sr = await sh.call(as, d);
      expect(jr.success, sg).toBe(sr.success);
      eqLogs(jr.logs, sr.logs);
    }
    // non-vacuity anchor: solc's topic1 for eDec is keccak256(31||32||33||34) - assert the exact hash.
    const jr = await jh.call(aj, '0x' + sel('eDec(bytes)') + blob());
    expect(jr.logs[0]!.topics[1]).toBe('0x1e0b2445d31a2dab2f202a07cd3ead5f7ed58d0ef05b35180146f79317479292');
  });

  it('controls unregressed: literal-local topic + abiDecode source through abi.encode', async () => {
    for (const sg of ['eCtl()', 'ctlEnc()']) {
      const d = '0x' + sel(sg);
      const jr = await jh.call(aj, d);
      const sr = await sh.call(as, d);
      expect(jr.success, sg).toBe(sr.success);
      expect(jr.returnHex, sg).toBe(sr.returnHex);
      eqLogs(jr.logs, sr.logs);
    }
  });
});
