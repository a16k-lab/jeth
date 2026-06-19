// JETH213 lift: a whole STATIC calldata aggregate (Arr<T,N> or a static struct param) as a component
// of a multi-value return, e.g. `f(a: Arr<u256,2>, x): [Arr<u256,2>, u256] { return [a, x]; }`. The
// aggregate is encoded INLINE in the tuple head (no offset word), masking value-leaf fixed arrays /
// validating struct fields, matching solc's return decode-to-memory. Byte-identical to solc 0.8.35.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

describe('static calldata aggregate as a multi-return component (JETH213) vs solc', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const J = `@struct class S { a: u256; b: u256; }
@contract class C {
  @external @pure fa(a: Arr<u256,2>, x: u256): [Arr<u256,2>, u256] { return [a, x]; }
  @external @pure fs(s: S, x: u256): [S, u256] { return [s, x]; }
  @external @pure fn(a: Arr<u8,3>, x: u256): [Arr<u8,3>, u256] { return [a, x]; }
  @external @pure fm(a: Arr<u256,2>, b: u256[], x: u256): [Arr<u256,2>, u256[], u256] { return [a, b, x]; } }`;
  const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  struct S { uint256 a; uint256 b; }
  function fa(uint256[2] calldata a, uint256 x) external pure returns (uint256[2] memory, uint256) { return (a, x); }
  function fs(S calldata s, uint256 x) external pure returns (S memory, uint256) { return (s, x); }
  function fn(uint8[3] calldata a, uint256 x) external pure returns (uint8[3] memory, uint256) { return (a, x); }
  function fm(uint256[2] calldata a, uint256[] calldata b, uint256 x) external pure returns (uint256[2] memory, uint256[] memory, uint256) { return (a, b, x); } }`;

  beforeAll(async () => {
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    as = await sol.deploy(compileSolidity(S, 'C').creation);
  });
  const both = async (data: string) => {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success).toBe(s.success);
    expect(j.returnHex).toBe(s.returnHex);
  };

  it('fixed-array component [Arr<u256,2>, u256]', async () => {
    await both('0x' + sel('fa(uint256[2],uint256)') + pad32(11n) + pad32(22n) + pad32(99n));
  });
  it('static-struct component [S, u256]', async () => {
    await both('0x' + sel('fs((uint256,uint256),uint256)') + pad32(7n) + pad32(8n) + pad32(99n));
  });
  it('narrow fixed-array component masks clean+dirty like solc (return decode-to-memory)', async () => {
    const clean = '0x' + sel('fn(uint8[3],uint256)') + pad32(7n) + pad32(8n) + pad32(9n) + pad32(99n);
    const dirty = '0x' + sel('fn(uint8[3],uint256)') + ('ff' + pad32(7n).slice(2)) + pad32(8n) + pad32(9n) + pad32(99n);
    await both(clean);
    await both(dirty); // solc masks a value-leaf fixed array on the return path; JETH matches
  });
  it('mixed static + dynamic + value tuple [Arr<u256,2>, u256[], u256]', async () => {
    // calldata: a(2 words inline) + offset-to-b + x + b tail([len][e0][e1])
    const data = '0x' + sel('fm(uint256[2],uint256[],uint256)') +
      pad32(1n) + pad32(2n) +          // a inline
      pad32(0x80n) +                    // offset to b (relative to after selector): 4 words in -> 0x80
      pad32(42n) +                      // x
      pad32(2n) + pad32(5n) + pad32(6n); // b = [5, 6]
    await both(data);
  });
});
