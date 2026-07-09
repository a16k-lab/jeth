// Mutability inference. In NATIVE mode (item #8) the compiler infers a function's mutability from its
// body for ANY function with no explicit @view/@pure/@payable (writes -> nonpayable, reads-only -> view,
// neither -> pure); @read is the same inference restricted to read-only. A function with no @external is
// INTERNAL (excluded from the ABI, callable by name). Inference is codegen-neutral (view/pure/nonpayable
// are byte-identical), so it only sets the ABI stateMutability - to match an idiomatic solc contract that
// DECLARES the tightest mutability. Verified: the inferred-mutability ABI equals the explicit-mutability
// ABI, and the inferred contract is byte-identical to solc at runtime.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

// Inferred mutability: @read (-> pure/view from the body) and @external alone (-> nonpayable).
// `sum` / `pubImpl` carry no @external, so they are internal helpers (not in the ABI).
const INFERRED = `@contract class C {
  @state x: u256; @state y: u256;
  @external setXY(a: u256, b: u256): void { this.x = a; this.y = b; }
  @external @read addOne(a: u256): u256 { return a + 1n; }
  @external @read getX(): u256 { return this.x; }
  @external @read who(): address { return msg.sender; }
  @external @read viaHelper(): u256 { return this.sum(); }
  sum(): u256 { return this.x + this.y; }
  @external extOnly(): u256 { return 42n; }
  @external pubTarget(): u256 { return this.pubImpl(); }
  @external caller(): u256 { return this.pubImpl() + 1n; }
  pubImpl(): u256 { return 7n; }
}`;
// Explicit mutability: the SAME contract with @view/@pure spelled out instead of inferred.
const EXPLICIT = `@contract class C {
  @state x: u256; @state y: u256;
  @external setXY(a: u256, b: u256): void { this.x = a; this.y = b; }
  @external @pure addOne(a: u256): u256 { return a + 1n; }
  @external @view getX(): u256 { return this.x; }
  @external @view who(): address { return msg.sender; }
  @external @view viaHelper(): u256 { return this.sum(); }
  sum(): u256 { return this.x + this.y; }
  @external @pure extOnly(): u256 { return 42n; }
  @external @pure pubTarget(): u256 { return this.pubImpl(); }
  @external @pure caller(): u256 { return this.pubImpl() + 1n; }
  pubImpl(): u256 { return 7n; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256 x; uint256 y;
  function setXY(uint256 a, uint256 b) external { x = a; y = b; }
  function addOne(uint256 a) external pure returns (uint256){ return a + 1; }
  function getX() external view returns (uint256){ return x; }
  function who() external view returns (address){ return msg.sender; }
  function viaHelper() external view returns (uint256){ return sum(); }
  function sum() internal view returns (uint256){ return x + y; }
  function extOnly() external pure returns (uint256){ return 42; }
  function pubTarget() public pure returns (uint256){ return 7; }
  function caller() external pure returns (uint256){ return pubTarget() + 1; }
}`;

const fnMap = (abi: { type: string; name?: string; stateMutability?: string }[]) =>
  Object.fromEntries(abi.filter((e) => e.type === 'function').map((f) => [f.name, f.stateMutability]));

describe('@read / inferred-visibility / inference', () => {
  it('inferred-decorator ABI == explicit-decorator ABI', () => {
    const inf = compile(INFERRED, { fileName: 'C.jeth' }).abi;
    const exp = compile(EXPLICIT, { fileName: 'C.jeth' }).abi;
    // same function set (internal `sum` / `pubImpl` excluded from BOTH)
    expect(fnMap(inf)).toEqual(fnMap(exp));
    // explicit sanity on the resolved mutabilities
    expect(fnMap(inf)).toEqual({
      setXY: 'nonpayable',
      addOne: 'pure',
      getX: 'view',
      who: 'view',
      viaHelper: 'view',
      extOnly: 'pure',
      pubTarget: 'pure',
      caller: 'pure',
    });
    expect(inf.some((e) => (e as { name?: string }).name === 'sum')).toBe(false); // -> not in ABI
  });

  describe('runtime byte-identical to solc', () => {
    let jeth: Harness, sol: Harness, aj: Address, as: Address;
    async function eq(label: string, data: string) {
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
      expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    }
    beforeAll(async () => {
      const jb = compile(INFERRED, { fileName: 'C.jeth' });
      const sb = compileSolidity(SOL, 'C');
      jeth = await Harness.create();
      sol = await Harness.create();
      aj = await jeth.deploy(jb.creationBytecode);
      as = await sol.deploy(sb.creation);
      const seed =
        '0x' + sel('setXY(uint256,uint256)') + 5n.toString(16).padStart(64, '0') + 9n.toString(16).padStart(64, '0');
      await jeth.call(aj, seed);
      await sol.call(as, seed);
    });
    it('every inferred function matches solc', async () => {
      await eq('addOne', encodeCall(sel('addOne(uint256)'), [123n]));
      await eq('getX', encodeCall(sel('getX()'), []));
      await eq('who', encodeCall(sel('who()'), []));
      await eq('viaHelper', encodeCall(sel('viaHelper()'), []));
      await eq('extOnly', encodeCall(sel('extOnly()'), []));
      await eq('pubTarget', encodeCall(sel('pubTarget()'), []));
      await eq('caller', encodeCall(sel('caller()'), []));
    });
  });
});
