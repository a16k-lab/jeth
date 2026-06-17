// @read / no-visibility / @hidden compile-time inference. The compiler resolves @read -> pure/view,
// a missing visibility decorator -> external/public (public iff internally called), and @hidden ->
// internal, BEFORE ABI emission. Verified: the inferred-decorator ABI is identical to the explicit-
// decorator ABI, and the inferred contract is byte-identical to solc at runtime.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

// Inferred decorators: @read, no visibility, @hidden.
const INFERRED = `@contract class C {
  @state x: u256; @state y: u256;
  @external setXY(a: u256, b: u256): void { this.x = a; this.y = b; }
  @read addOne(a: u256): u256 { return a + 1n; }
  @read getX(): u256 { return this.x; }
  @read who(): address { return msg.sender; }
  @read viaHelper(): u256 { return this.sum(); }
  @hidden sum(): u256 { return this.x + this.y; }
  extOnly(): u256 { return 42n; }
  pubTarget(): u256 { return 7n; }
  caller(): u256 { return this.pubTarget() + 1n; }
}`;
// Explicit decorators: the SAME contract written the long way.
const EXPLICIT = `@contract class C {
  @state x: u256; @state y: u256;
  @external setXY(a: u256, b: u256): void { this.x = a; this.y = b; }
  @external @pure addOne(a: u256): u256 { return a + 1n; }
  @external @view getX(): u256 { return this.x; }
  @external @view who(): address { return msg.sender; }
  @external @view viaHelper(): u256 { return this.sum(); }
  @internal sum(): u256 { return this.x + this.y; }
  @external extOnly(): u256 { return 42n; }
  @public pubTarget(): u256 { return 7n; }
  @external caller(): u256 { return this.pubTarget() + 1n; }
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
  function extOnly() external returns (uint256){ return 42; }
  function pubTarget() public returns (uint256){ return 7; }
  function caller() external returns (uint256){ return pubTarget() + 1; }
}`;

const fnMap = (abi: { type: string; name?: string; stateMutability?: string }[]) =>
  Object.fromEntries(abi.filter((e) => e.type === 'function').map((f) => [f.name, f.stateMutability]));

describe('@read / inferred-visibility / @hidden inference', () => {
  it('inferred-decorator ABI == explicit-decorator ABI', () => {
    const inf = compile(INFERRED, { fileName: 'C.jeth' }).abi;
    const exp = compile(EXPLICIT, { fileName: 'C.jeth' }).abi;
    // same function set (hidden/internal `sum` excluded from BOTH)
    expect(fnMap(inf)).toEqual(fnMap(exp));
    // explicit sanity on the resolved mutabilities/visibility
    expect(fnMap(inf)).toEqual({
      setXY: 'nonpayable', addOne: 'pure', getX: 'view', who: 'view', viaHelper: 'view',
      extOnly: 'nonpayable', pubTarget: 'nonpayable', caller: 'nonpayable',
    });
    expect(inf.some((e) => (e as { name?: string }).name === 'sum')).toBe(false); // @hidden -> not in ABI
  });

  describe('runtime byte-identical to solc', () => {
    let jeth: Harness, sol: Harness, aj: Address, as: Address;
    async function eq(label: string, data: string) {
      const j = await jeth.call(aj, data); const s = await sol.call(as, data);
      expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
      expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    }
    beforeAll(async () => {
      const jb = compile(INFERRED, { fileName: 'C.jeth' });
      const sb = compileSolidity(SOL, 'C');
      jeth = await Harness.create(); sol = await Harness.create();
      aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
      const seed = '0x' + sel('setXY(uint256,uint256)') + (5n).toString(16).padStart(64, '0') + (9n).toString(16).padStart(64, '0');
      await jeth.call(aj, seed); await sol.call(as, seed);
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
