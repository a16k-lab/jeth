// _vf_environment: adversarial differential probe of ENVIRONMENT & BUILTINS parity
// vs solc (cancun, optimizer on). Focus: msg.sender/value/sig, tx.origin,
// block.timestamp/number/coinbase/chainid/basefee/gaslimit/prevrandao, address(this),
// plus casts/arithmetic/comparisons over those env reads, and payable/nonpayable
// value-send semantics. Every probe must be BYTE-IDENTICAL to solc: both the success
// flag AND the returndata.
//
// JETH surface intentionally does NOT expose keccak256(...)/abi.encode(...)/
// abi.encodePacked/abi.decode/ecrecover/sha256/ripemd160/gasleft/selfbalance/.balance
// (they are not in the language). Those are not over-rejections; this file probes the
// env reads that ARE expressible, adversarially.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, customCommon, makeBlock, type BlockEnv } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const addr = (hex: string) => new Address(hexToBytes(('0x' + hex) as `0x${string}`));

// Distinct, dirty-ish env so every opcode is observable and not all-zero.
const CALLER = addr('ca'.repeat(20));
const ORIGIN = addr('be'.repeat(20));
const COINBASE = addr('cc'.repeat(20));
const RANDAO = hexToBytes(('0x' + 'ab'.repeat(32)) as `0x${string}`);
const CHAIN_ID = 1337;

const JETH = `
@contract
class C {
  @state owner: address;
  @state hits: mapping<address, u256>;

  // --- raw env reads ---
  @view sender(): address { return msg.sender; }
  @view origin(): address { return tx.origin; }
  @view self(): address { return address(this); }
  @view coinbase(): address { return block.coinbase; }
  @view ts(): u256 { return block.timestamp; }
  @view num(): u256 { return block.number; }
  @view cid(): u256 { return block.chainid; }
  @view fee(): u256 { return block.basefee; }
  @view glimit(): u256 { return block.gaslimit; }
  @view rand(): u256 { return block.prevrandao; }
  @pure sig(): bytes4 { return msg.sig; }
  @payable val(): u256 { return msg.value; }

  // --- casts over env reads ---
  @view senderU160(): u160 { return u160(msg.sender); }
  @view senderBytes20(): bytes20 { return bytes20(msg.sender); }
  @view selfU160(): u160 { return u160(address(this)); }
  @view selfBytes20(): bytes20 { return bytes20(address(this)); }
  @view originPayable(): address { return address(payable(tx.origin)); }
  @view senderRoundTrip(): address { return address(u160(msg.sender)); }
  @view senderB20RT(): address { return address(bytes20(msg.sender)); }
  @pure sigAsU32(): u32 { return u32(msg.sig); }
  @pure sigAsBytes4(): bytes4 { return bytes4(u32(msg.sig)); }

  // --- arithmetic / comparisons over env (uses block.* which are u256) ---
  @view tsPlusNum(): u256 { return block.timestamp + block.number; }
  @view feeTimesGas(): u256 { return block.basefee * block.gaslimit; }
  @view numMinusOne(): u256 { return block.number - 1n; }
  @view randXorTs(): u256 { return block.prevrandao ^ block.timestamp; }
  @view randShr(): u256 { return block.prevrandao >> 8n; }
  @payable valPlus(): u256 { return msg.value + 1000n; }
  @payable valDoubled(): u256 { return msg.value * 2n; }
  @view senderEqOrigin(): bool { return msg.sender == tx.origin; }
  @view senderNeSelf(): bool { return msg.sender != address(this); }
  @view selfIsZero(): bool { return address(this) == address(0n); }
  @view cidEq(): bool { return block.chainid == 1337n; }

  // --- value-conditioned control flow (require on msg.value) ---
  @payable needsValue(): u256 { require(msg.value > 0n); return msg.value; }
  @payable exactWei(): u256 { require(msg.value == 1n); return 42n; }

  // --- env as mapping key / writes (state-changing) ---
  bump(): u256 { this.hits[msg.sender] = this.hits[msg.sender] + 1n; return this.hits[msg.sender]; }
  @view hitOf(a: address): u256 { return this.hits[a]; }
  setOwner(): void { this.owner = msg.sender; }
  @view getOwner(): address { return this.owner; }
  @view isOwner(): bool { return msg.sender == this.owner; }

  // --- bytes4 sig comparisons / returns of casts ---
  @pure sigEqSelf(): bool { return msg.sig == msg.sig; }
  // sigIsSig() selector is 0xf7d6b9f1; compare msg.sig against that literal
  @pure sigIsSig(): bool { return msg.sig == bytes4(u32(0xf7d6b9f1n)); }
  @pure sigHi(): u256 { return u256(bytes32(msg.sig)); }
  // chained address casts: address -> u160 -> bytes20 -> address round trip
  @view selfChain(): address { return address(bytes20(u160(address(this)))); }
  @view senderToB32(): bytes32 { return bytes32(u256(u160(msg.sender))); }
  // mix env into a require comparison that can pass or fail by value
  @payable gateValGtNum(): u256 { require(msg.value > block.number); return msg.value; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  address owner;
  mapping(address => uint256) hits;

  function sender()   external view returns (address) { return msg.sender; }
  function origin()   external view returns (address) { return tx.origin; }
  function self()     external view returns (address) { return address(this); }
  function coinbase() external view returns (address) { return block.coinbase; }
  function ts()       external view returns (uint256) { return block.timestamp; }
  function num()      external view returns (uint256) { return block.number; }
  function cid()      external view returns (uint256) { return block.chainid; }
  function fee()      external view returns (uint256) { return block.basefee; }
  function glimit()   external view returns (uint256) { return block.gaslimit; }
  function rand()     external view returns (uint256) { return block.prevrandao; }
  function sig()      external pure returns (bytes4)  { return msg.sig; }
  function val()      external payable returns (uint256) { return msg.value; }

  function senderU160()      external view returns (uint160) { return uint160(msg.sender); }
  function senderBytes20()   external view returns (bytes20) { return bytes20(msg.sender); }
  function selfU160()        external view returns (uint160) { return uint160(address(this)); }
  function selfBytes20()     external view returns (bytes20) { return bytes20(address(this)); }
  function originPayable()   external view returns (address) { return address(payable(tx.origin)); }
  function senderRoundTrip() external view returns (address) { return address(uint160(msg.sender)); }
  function senderB20RT()     external view returns (address) { return address(bytes20(msg.sender)); }
  function sigAsU32()        external pure returns (uint32)  { return uint32(msg.sig); }
  function sigAsBytes4()     external pure returns (bytes4)  { return bytes4(uint32(msg.sig)); }

  function tsPlusNum()       external view returns (uint256) { return block.timestamp + block.number; }
  function feeTimesGas()     external view returns (uint256) { return block.basefee * block.gaslimit; }
  function numMinusOne()     external view returns (uint256) { return block.number - 1; }
  function randXorTs()       external view returns (uint256) { return block.prevrandao ^ block.timestamp; }
  function randShr()         external view returns (uint256) { return block.prevrandao >> 8; }
  function valPlus()         external payable returns (uint256) { return msg.value + 1000; }
  function valDoubled()      external payable returns (uint256) { return msg.value * 2; }
  function senderEqOrigin()  external view returns (bool) { return msg.sender == tx.origin; }
  function senderNeSelf()    external view returns (bool) { return msg.sender != address(this); }
  function selfIsZero()      external view returns (bool) { return address(this) == address(0); }
  function cidEq()           external view returns (bool) { return block.chainid == 1337; }

  function needsValue()      external payable returns (uint256) { require(msg.value > 0); return msg.value; }
  function exactWei()        external payable returns (uint256) { require(msg.value == 1); return 42; }

  function bump()            external returns (uint256) { hits[msg.sender] = hits[msg.sender] + 1; return hits[msg.sender]; }
  function hitOf(address a)  external view returns (uint256) { return hits[a]; }
  function setOwner()        external { owner = msg.sender; }
  function getOwner()        external view returns (address) { return owner; }
  function isOwner()         external view returns (bool) { return msg.sender == owner; }

  function sigEqSelf()       external pure returns (bool) { return msg.sig == msg.sig; }
  function sigIsSig()        external pure returns (bool) { return msg.sig == bytes4(uint32(0xf7d6b9f1)); }
  function sigHi()           external pure returns (uint256) { return uint256(bytes32(msg.sig)); }
  function selfChain()       external view returns (address) { return address(bytes20(uint160(address(this)))); }
  function senderToB32()     external view returns (bytes32) { return bytes32(uint256(uint160(msg.sender))); }
  function gateValGtNum()    external payable returns (uint256) { require(msg.value > block.number); return msg.value; }
}`;

describe('environment & builtins vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  const common = customCommon(CHAIN_ID);

  // default block for most calls
  const blockOf = (env: BlockEnv) => makeBlock(env, common);

  type Opts = { caller?: Address; origin?: Address; value?: bigint; block?: ReturnType<typeof makeBlock>; rawData?: string };

  async function eq(label: string, sigStr: string, words: bigint[], opts: Opts = {}) {
    count++;
    const data = opts.rawData ?? encodeCall(sel(sigStr), words);
    const callOpts = { caller: opts.caller ?? CALLER, origin: opts.origin ?? ORIGIN, value: opts.value, block: opts.block };
    const j = await jeth.call(aj, data, callOpts);
    const s = await sol.call(as, data, callOpts);
    if (j.success !== s.success || j.returnHex !== s.returnHex) {
      mism.push(
        label +
          ': jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError + '} ' +
          'sol{ok=' + s.success + ',ret=' + s.returnHex + '}',
      );
    }
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(common);
    sol = await Harness.create(common);
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
    // identical deploy => identical self() address
    expect(aj.toString()).toBe(as.toString());
  });

  it('runs', async () => {
    // ---- a matrix of block envs, incl. boundary values ----
    const MAX = M - 1n;
    const blocks: { name: string; env: BlockEnv }[] = [
      { name: 'b0', env: { number: 0n, timestamp: 0n, coinbase: addr('00'.repeat(20)), gasLimit: 0n, baseFeePerGas: 0n, prevRandao: hexToBytes(('0x' + '00'.repeat(32)) as `0x${string}`) } },
      { name: 'b1', env: { number: 1n, timestamp: 1n, coinbase: COINBASE, gasLimit: 1n, baseFeePerGas: 1n, prevRandao: hexToBytes(('0x' + '00'.repeat(31) + '01') as `0x${string}`) } },
      { name: 'bnorm', env: { number: 12345678n, timestamp: 1700000000n, coinbase: COINBASE, gasLimit: 30000000n, baseFeePerGas: 7n, prevRandao: RANDAO } },
      { name: 'bmax', env: { number: MAX, timestamp: MAX, coinbase: addr('ff'.repeat(20)), gasLimit: MAX, baseFeePerGas: MAX, prevRandao: hexToBytes(('0x' + 'ff'.repeat(32)) as `0x${string}`) } },
      { name: 'btop', env: { number: 1n << 255n, timestamp: (1n << 255n) + 5n, coinbase: COINBASE, gasLimit: 1n << 200n, baseFeePerGas: (1n << 128n) - 1n, prevRandao: hexToBytes(('0x80' + '00'.repeat(31)) as `0x${string}`) } },
    ];

    const VIEW_FNS = [
      'sender()', 'origin()', 'self()', 'coinbase()', 'ts()', 'num()', 'cid()', 'fee()', 'glimit()', 'rand()',
      'senderU160()', 'senderBytes20()', 'selfU160()', 'selfBytes20()', 'originPayable()',
      'senderRoundTrip()', 'senderB20RT()',
      'tsPlusNum()', 'feeTimesGas()', 'numMinusOne()', 'randXorTs()', 'randShr()', 'valPlus()',
      'senderEqOrigin()', 'senderNeSelf()', 'selfIsZero()', 'cidEq()',
    ];

    for (const b of blocks) {
      const block = blockOf(b.env);
      for (const fn of VIEW_FNS) {
        await eq(b.name + ':' + fn, fn, [], { block });
      }
    }

    // ---- pure msg.sig: allowed in @pure; depends ONLY on calldata first word ----
    await eq('sig:normal', 'sig()', []);
    await eq('sigAsU32:normal', 'sigAsU32()', []);
    await eq('sigAsBytes4:normal', 'sigAsBytes4()', []);
    await eq('sigEqSelf', 'sigEqSelf()', []);

    // ---- msg.value boundary cases on payable fns ----
    const block = blockOf(blocks[2]!.env);
    const VALUES = [0n, 1n, 2n, 1000n, 12345678n, (1n << 64n) - 1n, 1n << 64n, (1n << 128n) - 1n, 1n << 128n];
    for (const v of VALUES) {
      await eq('val:' + v, 'val()', [], { block, value: v });
      await eq('valDoubled:' + v, 'valDoubled()', [], { block, value: v });
      await eq('needsValue:' + v, 'needsValue()', [], { block, value: v });
      await eq('exactWei:' + v, 'exactWei()', [], { block, value: v });
    }

    // ---- sending value to a NONPAYABLE function must revert identically ----
    // (nonpayable bump/setOwner/getOwner with nonzero value -> revert in both)
    await eq('bump:value', 'bump()', [], { value: 5n });
    await eq('setOwner:value', 'setOwner()', [], { value: 5n });
    await eq('getOwner:value', 'getOwner()', [], { value: 1n });
    // view fns with value (solc treats external view as nonpayable in dispatch)
    await eq('sender:value', 'sender()', [], { value: 1n });
    await eq('ts:value', 'ts()', [], { value: 7n });

    // ---- env as mapping key & writes: bump from several callers, read back ----
    const callers = [CALLER, ORIGIN, addr('01'.repeat(20)), addr('00'.repeat(19) + '01'), addr('ff'.repeat(20))];
    for (const c of callers) {
      await eq('bump:' + c.toString().slice(2, 6), 'bump()', [], { caller: c });
      await eq('bump2:' + c.toString().slice(2, 6), 'bump()', [], { caller: c });
      await eq('hitOf:' + c.toString().slice(2, 6), 'hitOf(address)', [BigInt(c.toString())]);
    }
    // setOwner from a caller, then check isOwner from same & different caller
    await eq('setOwner', 'setOwner()', [], { caller: CALLER });
    await eq('getOwner', 'getOwner()', []);
    await eq('isOwner:same', 'isOwner()', [], { caller: CALLER });
    await eq('isOwner:other', 'isOwner()', [], { caller: ORIGIN });

    // ---- adversarial msg.sender / tx.origin: dirty-looking & boundary addresses ----
    const advCallers = [addr('00'.repeat(20)), addr('00'.repeat(19) + 'ff'), addr('ff'.repeat(20)), addr('de'.repeat(20))];
    const advOrigins = [addr('00'.repeat(20)), addr('ff'.repeat(20)), addr('be'.repeat(20))];
    for (const c of advCallers) {
      await eq('senderAdv:' + c.toString().slice(2, 6), 'sender()', [], { caller: c, block });
      await eq('senderU160Adv:' + c.toString().slice(2, 6), 'senderU160()', [], { caller: c, block });
      await eq('senderBytes20Adv:' + c.toString().slice(2, 6), 'senderBytes20()', [], { caller: c, block });
      for (const o of advOrigins) {
        await eq('eqOrigin:' + c.toString().slice(2, 6) + '/' + o.toString().slice(2, 6), 'senderEqOrigin()', [], { caller: c, origin: o, block });
      }
    }

    // ---- adversarial calldata for msg.sig: dirty trailing bytes / short calldata ----
    // (msg.sig reads the first 4 bytes of calldata only; trailing junk must not matter,
    // and shorter-than-4-byte calldata is zero-padded the same way in both.)
    const sigSel = sel('sig()');
    await eq('sig:trailingjunk', 'sig()', [], { rawData: sigSel + 'ff'.repeat(64) });
    await eq('sig:onelongword', 'sig()', [], { rawData: sigSel + 'deadbeef'.repeat(8) });
    await eq('sigAsU32:trailingjunk', 'sigAsU32()', [], { rawData: sel('sigAsU32()') + 'ab'.repeat(40) });

    // ---- adversarial: call with EXTRA trailing calldata on a no-arg env fn ----
    // solc ignores extra trailing calldata on functions with no dynamic args.
    await eq('sender:extra', 'sender()', [], { rawData: sel('sender()') + '00'.repeat(96), block });
    await eq('ts:extra', 'ts()', [], { rawData: sel('ts()') + 'ff'.repeat(96), block });
    await eq('cid:extra', 'cid()', [], { rawData: sel('cid()') + 'deadbeef'.repeat(16), block });

    // ---- hitOf with dirty high bits in the address arg (must be masked to 160 bits the same) ----
    const dirtyAddrWord = M - 1n; // all 256 bits set; low 160 = ffff...; solc masks address args
    await eq('hitOf:dirtyhi', 'hitOf(address)', [dirtyAddrWord]);
    const dirty2 = (1n << 200n) | BigInt('0x' + 'be'.repeat(20)); // dirty high bits above 160
    await eq('hitOf:dirtyhi2', 'hitOf(address)', [dirty2]);

    // ---- msg.sig literal comparison: true path (correct selector) ----
    await eq('sigIsSig:true', 'sigIsSig()', []);
    // false path: call sigIsSig's body but with a DIFFERENT first-word selector via rawData.
    // (solc still dispatches by the 4-byte selector, so we must keep the real selector to
    // reach the function; instead test the literal vs sig identity through sigEqSelf and
    // a deliberately-wrong sig literal by calling the function whose selector != literal.)
    await eq('sigHi', 'sigHi()', []);
    await eq('sigHi:dirty', 'sigHi()', [], { rawData: sel('sigHi()') + 'ff'.repeat(32) });
    await eq('selfChain', 'selfChain()', [], { block });
    await eq('senderToB32', 'senderToB32()', [], { block });
    for (const c of advCallers) {
      await eq('senderToB32:' + c.toString().slice(2, 6), 'senderToB32()', [], { caller: c, block });
    }

    // ---- gateValGtNum: passes only when msg.value > block.number; sweep both around boundary ----
    for (const b of blocks) {
      const blk = blockOf(b.env);
      const n = b.env.number ?? 0n;
      for (const dv of [n === 0n ? 0n : n - 1n, n, n + 1n, n + 2n]) {
        // cap value to a sane fundable amount to avoid harness funding overflow at bmax
        const v = dv > (1n << 120n) ? (1n << 120n) : dv;
        await eq('gateVGN:' + b.name + ':' + v, 'gateValGtNum()', [], { block: blk, value: v });
      }
    }

    // ---- msg.sig under genuinely SHORT calldata (< 4 bytes) ----
    // We cannot reach a named function with truncated calldata (solc would hit the
    // fallback and revert), but we CAN compare the dispatch behavior: a 0-byte and a
    // 3-byte calldata both miss every selector. Both must revert identically (no fallback).
    await eq('empty-calldata', 'sig()', [], { rawData: '0x' });
    await eq('1byte-calldata', 'sig()', [], { rawData: '0xab' });
    await eq('3byte-calldata', 'sig()', [], { rawData: '0xabcdef' });
    await eq('unknown-selector', 'sig()', [], { rawData: '0xdeadbeef' });

    // report
    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else {
      console.log('ALL ' + count + ' byte-identical');
    }
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
