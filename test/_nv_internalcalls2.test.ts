import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

// Round 2: side-effecting argument evaluation, @external functions called by name,
// interleaved state mutation during recursion, args that mutate locals read by
// later args, post/pre-inc in argument position, chained assignment as args.
const JETH = `@contract class C {
  @state s: u256;
  @state log: u256;

  @pure cat3(a: u256, b: u256, c: u256): u256 { return ((a * 1000n + b) * 1000n + c); }
  @pure cat2(a: u256, b: u256): u256 { return a * 1000n + b; }

  // args mutate a local that later args read (left-to-right order for arg lists)
  @external @pure argSeq(): u256 {
    let x: u256 = 0n;
    return this.cat3((x = x * 10n + 1n), (x = x * 10n + 2n), (x = x * 10n + 3n)) * 10n + x;
  }
  // post/pre inc in arg position
  @external @pure argIncDec(): u256 {
    let x: u256 = 5n;
    return this.cat3(x++, ++x, x--) * 100n + x;
  }
  // nested internal call whose arg also has a side effect
  @external @pure argNestSeq(): u256 {
    let x: u256 = 0n;
    return this.cat2(this.cat2((x = x + 1n), (x = x + 10n)), (x = x + 100n)) * 10n + x;
  }
  // arg is a chained assignment used by sibling arg
  @external @pure argChain(): u256 {
    let x: u256 = 0n; let y: u256 = 0n;
    return this.cat2((x = y = 7n), x + y);
  }

  // state mutated as a side effect inside an internal-call arg, read by later arg
  @pure pass2(a: u256, b: u256): u256 { return a * 1000000n + b; }
  @external setSeq(): u256 {
    this.s = 0n;
    return this.pass2((this.s = this.s + 1n), this.s) * 10n + this.s;
  }

  // @external functions: callable externally AND by name internally
  @external @pure pdbl(x: u256): u256 { return x * 2n; }
  @external @pure padd(a: u256, b: u256): u256 { return a + b; }
  @external @pure usePublic(a: u256, b: u256): u256 { return this.padd(this.pdbl(a), this.pdbl(b)); }
  @external @pure usePublicBare(a: u256, b: u256): u256 { return padd(pdbl(a), pdbl(b)); }
  // public recursive
  @external @pure pfib(n: u256): u256 { if (n < 2n) { return n; } return this.pfib(n - 1n) + this.pfib(n - 2n); }

  // interleaved state mutation during recursion: each call writes then recurses
  accumDown(n: u256): u256 {
    if (n == 0n) { return this.s; }
    this.s = this.s + n;
    return this.accumDown(n - 1n);
  }
  @external runAccum(n: u256): u256 { this.s = 0n; return this.accumDown(n); }
  @view getS(): u256 { return this.s; }

  // a helper that both reads and writes, called in nested positions
  tick(): u256 { this.log = this.log + 1n; return this.log; }
  @external multiTick(): u256 {
    this.log = 0n;
    return this.cat3(this.tick(), this.tick(), this.tick());
  }

  // recursion where the recursive arg has overflow potential mid-tree
  @pure powc(base: u256, exp: u256): u256 {
    if (exp == 0n) { return 1n; }
    return base * this.powc(base, exp - 1n);
  }
  @external @pure powcE(base: u256, exp: u256): u256 { return this.powc(base, exp); }

  // linear recursion with no arithmetic risk, used to probe the deep-recursion
  // STACK-DEPTH divergence: solc lays internal-call frames on the EVM stack and
  // hits the 1024-slot limit at ~338 frames; JETH frames live in memory and run
  // far deeper. Pure value logic, so any divergence is purely the frame model.
  @pure down(n: u256): u256 { if (n == 0n) { return 0n; } return this.down(n - 1n) + 1n; }
  @external @pure downE(n: u256): u256 { return this.down(n); }

  // call returning bool feeding a require in the caller
  @pure okGt(a: u256, b: u256): bool { return a > b; }
  @external @pure needGt(a: u256, b: u256): u256 { require(this.okGt(a, b), "le"); return a - b; }

  // mutual recursion that also writes state on the way (count steps)
  mEven(n: u256): bool { this.log = this.log + 1n; if (n == 0n) { return true; } return this.mOdd(n - 1n); }
  mOdd(n: u256): bool { this.log = this.log + 1n; if (n == 0n) { return false; } return this.mEven(n - 1n); }
  @external runMutual(n: u256): u256 { this.log = 0n; let b: bool = this.mEven(n); return this.log * 10n + (b ? 1n : 0n); }

  // deeply nested same-call in a single expression with shared mutable arg
  @pure addOne(x: u256): u256 { return x + 1n; }
  @external @pure deepShared(): u256 {
    let x: u256 = 0n;
    return this.cat3(this.addOne((x = x + 1n)), this.addOne((x = x + 1n)), this.addOne((x = x + 1n))) * 10n + x;
  }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256 s;
  uint256 log;

  function cat3(uint256 a, uint256 b, uint256 c) internal pure returns (uint256){ return ((a * 1000 + b) * 1000 + c); }
  function cat2(uint256 a, uint256 b) internal pure returns (uint256){ return a * 1000 + b; }

  function argSeq() external pure returns (uint256){
    uint256 x = 0;
    return cat3((x = x * 10 + 1), (x = x * 10 + 2), (x = x * 10 + 3)) * 10 + x;
  }
  function argIncDec() external pure returns (uint256){
    uint256 x = 5;
    return cat3(x++, ++x, x--) * 100 + x;
  }
  function argNestSeq() external pure returns (uint256){
    uint256 x = 0;
    return cat2(cat2((x = x + 1), (x = x + 10)), (x = x + 100)) * 10 + x;
  }
  function argChain() external pure returns (uint256){
    uint256 x = 0; uint256 y = 0;
    return cat2((x = y = 7), x + y);
  }

  function pass2(uint256 a, uint256 b) internal pure returns (uint256){ return a * 1000000 + b; }
  function setSeq() external returns (uint256){
    s = 0;
    return pass2((s = s + 1), s) * 10 + s;
  }

  function pdbl(uint256 x) public pure returns (uint256){ return x * 2; }
  function padd(uint256 a, uint256 b) public pure returns (uint256){ return a + b; }
  function usePublic(uint256 a, uint256 b) external pure returns (uint256){ return padd(pdbl(a), pdbl(b)); }
  function usePublicBare(uint256 a, uint256 b) external pure returns (uint256){ return padd(pdbl(a), pdbl(b)); }
  function pfib(uint256 n) public pure returns (uint256){ if (n < 2) { return n; } return pfib(n - 1) + pfib(n - 2); }

  function accumDown(uint256 n) internal returns (uint256){
    if (n == 0) { return s; }
    s = s + n;
    return accumDown(n - 1);
  }
  function runAccum(uint256 n) external returns (uint256){ s = 0; return accumDown(n); }
  function getS() external view returns (uint256){ return s; }

  function tick() internal returns (uint256){ log = log + 1; return log; }
  function multiTick() external returns (uint256){
    log = 0;
    return cat3(tick(), tick(), tick());
  }

  function powc(uint256 base, uint256 exp) internal pure returns (uint256){
    if (exp == 0) { return 1; }
    return base * powc(base, exp - 1);
  }
  function powcE(uint256 base, uint256 exp) external pure returns (uint256){ return powc(base, exp); }

  function down(uint256 n) internal pure returns (uint256){ if (n == 0) { return 0; } return down(n - 1) + 1; }
  function downE(uint256 n) external pure returns (uint256){ return down(n); }

  function okGt(uint256 a, uint256 b) internal pure returns (bool){ return a > b; }
  function needGt(uint256 a, uint256 b) external pure returns (uint256){ require(okGt(a, b), "le"); return a - b; }

  function mEven(uint256 n) internal returns (bool){ log = log + 1; if (n == 0) { return true; } return mOdd(n - 1); }
  function mOdd(uint256 n) internal returns (bool){ log = log + 1; if (n == 0) { return false; } return mEven(n - 1); }
  function runMutual(uint256 n) external returns (uint256){ log = 0; bool b = mEven(n); return log * 10 + (b ? 1 : 0); }

  function addOne(uint256 x) internal pure returns (uint256){ return x + 1; }
  function deepShared() external pure returns (uint256){
    uint256 x = 0;
    return cat3(addOne((x = x + 1)), addOne((x = x + 1)), addOne((x = x + 1))) * 10 + x;
  }
}`;

describe('probe', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(
        label +
          ': jeth{ok=' +
          j.success +
          ',ret=' +
          j.returnHex +
          ',err=' +
          j.exceptionError +
          '} sol{ok=' +
          s.success +
          ',ret=' +
          s.returnHex +
          '}',
      );
  }
  async function drive(data: string) {
    await jeth.call(aj, data);
    await sol.call(as, data);
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    // side-effecting argument evaluation (pure)
    await eq('argSeq', encodeCall(sel('argSeq()'), []));
    await eq('argIncDec', encodeCall(sel('argIncDec()'), []));
    await eq('argNestSeq', encodeCall(sel('argNestSeq()'), []));
    await eq('argChain', encodeCall(sel('argChain()'), []));
    await eq('deepShared', encodeCall(sel('deepShared()'), []));

    // state side-effect in args: drive then read view
    await drive(encodeCall(sel('setSeq()'), []));
    await eq('setSeq ret', encodeCall(sel('setSeq()'), [])); // returns value directly
    await eq('multiTick', encodeCall(sel('multiTick()'), []));

    // @external called by name (this. and bare) + externally
    for (const [a, b] of [
      [1n, 2n],
      [10n, 20n],
      [M >> 2n, M >> 2n],
      [M - 1n, 0n],
    ] as [bigint, bigint][]) {
      await eq('usePublic(' + a + ',' + b + ')', encodeCall(sel('usePublic(uint256,uint256)'), [a, b]));
      await eq('usePublicBare(' + a + ',' + b + ')', encodeCall(sel('usePublicBare(uint256,uint256)'), [a, b]));
    }
    // call the public functions directly via their external selectors
    for (const x of [0n, 5n, M - 1n, M >> 1n]) await eq('pdbl(' + x + ')', encodeCall(sel('pdbl(uint256)'), [x]));
    for (const [a, b] of [
      [1n, 2n],
      [M - 1n, 1n],
      [M - 1n, 0n],
    ] as [bigint, bigint][])
      await eq('padd(' + a + ',' + b + ')', encodeCall(sel('padd(uint256,uint256)'), [a, b]));
    for (const n of [0n, 1n, 2n, 7n, 12n, 20n]) await eq('pfib(' + n + ')', encodeCall(sel('pfib(uint256)'), [n]));

    // interleaved state mutation during recursion
    for (const n of [0n, 1n, 3n, 10n, 50n]) {
      await drive(encodeCall(sel('runAccum(uint256)'), [n]));
      await eq('getS after runAccum(' + n + ')', encodeCall(sel('getS()'), []));
      await eq('runAccum ret(' + n + ')', encodeCall(sel('runAccum(uint256)'), [n]));
    }

    // recursion with overflow potential. NOTE: exp must stay below solc's EVM-stack
    // recursion limit (~250 frames for this 1-extra-local callee), else the two diverge
    // on a STACK-DEPTH artifact (documented below), not on arithmetic. 10^78 overflows
    // uint256 at a shallow depth (78 frames) -> checked-mul revert on both.
    for (const [b, e] of [
      [2n, 0n],
      [2n, 10n],
      [2n, 100n],
      [2n, 200n],
      [3n, 100n],
      [3n, 200n],
      [10n, 77n],
      [10n, 78n],
      [0n, 5n],
      [1n, 200n],
    ] as [bigint, bigint][])
      await eq('powcE(' + b + ',' + e + ')', encodeCall(sel('powcE(uint256,uint256)'), [b, e]));

    // bool result feeding require
    for (const [a, b] of [
      [5n, 3n],
      [3n, 5n],
      [0n, 0n],
      [1n, 1n],
      [M - 1n, 0n],
    ] as [bigint, bigint][])
      await eq('needGt(' + a + ',' + b + ')', encodeCall(sel('needGt(uint256,uint256)'), [a, b]));

    // mutual recursion with state writes (step count parity)
    for (const n of [0n, 1n, 2n, 5n, 10n, 21n])
      await eq('runMutual(' + n + ')', encodeCall(sel('runMutual(uint256)'), [n]));

    // Shallow linear recursion is byte-identical under solc's stack limit.
    for (const n of [0n, 1n, 100n, 300n, 337n]) await eq('downE(' + n + ')', encodeCall(sel('downE(uint256)'), [n]));

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
