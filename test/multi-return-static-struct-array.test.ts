// A fixed-array-of-STATIC-struct component in a multi-value tuple return (return [42, a] where
// a: Arr<In,N>, In a static struct). Arr<In,N> is ABI-STATIC (In has only static fields) but
// POINTER-HEADED in memory (N absolute-pointer words -> per-element struct images). The
// multi-value tuple-return encoder used to emit a verbatim mcopy of the pointer words (two
// dynamic-offset-looking words 0x80/0xc0 then garbage), DROPPING the struct payload (7,8,9,10) -
// a silent data-loss MISCOMPILE. It now flattens each element image INLINE via abiEncFromMem
// (the same recursive codec the solo-return / abi.encode paths use), byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const JETH = `@struct class In { x: u256; y: u256 }
@struct class In3 { x: u256; y: u256; z: u256 }
@struct class In2 { p: In; q: u256 }
@contract class C {
  // the exact reported miscompile: [scalar, Arr<In,2>]
  @external @pure two(): [u256, Arr<In,2>] { let a: Arr<In,2> = [In(7n,8n), In(9n,10n)]; return [42n, a]; }
  // N=1 and N=3
  @external @pure one(): [u256, Arr<In,1>] { let a: Arr<In,1> = [In(7n,8n)]; return [42n, a]; }
  @external @pure three(): [u256, Arr<In,3>] { let a: Arr<In,3> = [In(1n,2n),In(3n,4n),In(5n,6n)]; return [42n, a]; }
  // Arr<In,N> at FIRST / MIDDLE / LAST tuple position
  @external @pure first(): [Arr<In,2>, u256] { let a: Arr<In,2> = [In(1n,2n),In(3n,4n)]; return [a, 42n]; }
  @external @pure middle(): [u256, Arr<In,2>, u256] { let a: Arr<In,2> = [In(1n,2n),In(3n,4n)]; return [7n, a, 42n]; }
  @external @pure last(): [u256, u256, Arr<In,2>] { let a: Arr<In,2> = [In(1n,2n),In(3n,4n)]; return [42n, 7n, a]; }
  // 3-field element struct, nested-static-struct element
  @external @pure wide(): [u256, Arr<In3,2>] { let a: Arr<In3,2> = [In3(1n,2n,3n),In3(4n,5n,6n)]; return [42n, a]; }
  @external @pure nested(): [u256, Arr<In2,2>] { let a: Arr<In2,2> = [In2(In(1n,2n),3n), In2(In(4n,5n),6n)]; return [42n, a]; }
  // alongside a value array, another struct, a dynamic string sibling; two static-struct arrays
  @external @pure withValArr(): [Arr<In,2>, Arr<u256,3>] { let a: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let v: Arr<u256,3> = [11n,12n,13n]; return [a, v]; }
  @external @pure withStruct(): [In, Arr<In,2>] { let s: In = In(99n,100n); let a: Arr<In,2> = [In(1n,2n),In(3n,4n)]; return [s, a]; }
  @external @pure withStr(): [Arr<In,2>, string] { let a: Arr<In,2> = [In(1n,2n),In(3n,4n)]; return [a, "hello"]; }
  @external @pure twoArrs(): [Arr<In,2>, u256, Arr<In,3>] { let a: Arr<In,2> = [In(1n,2n),In(3n,4n)]; let b: Arr<In,3> = [In(5n,6n),In(7n,8n),In(9n,10n)]; return [a, 5n, b]; }
  @external @pure nestedArr(): [u256, Arr<Arr<In,2>,2>] { let a: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)]]; return [42n, a]; }
  // CONTROLS that must stay byte-identical (they exercise the sibling branches):
  @external @pure ctrlSolo(): Arr<In,2> { let a: Arr<In,2> = [In(7n,8n),In(9n,10n)]; return a; }
  @external @pure ctrlStructInTuple(): [u256, In] { let s: In = In(7n,8n); return [42n, s]; }
  @external @pure ctrlValArrInTuple(): [u256, Arr<u256,3>] { let a: Arr<u256,3> = [7n,8n,9n]; return [42n, a]; }
  @external @pure ctrlAbiEncode(): bytes { let a: Arr<In,2> = [In(7n,8n),In(9n,10n)]; return abi.encode(42n, a); }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
struct In { uint256 x; uint256 y; }
struct In3 { uint256 x; uint256 y; uint256 z; }
struct In2 { In p; uint256 q; }
contract C {
  function two() external pure returns(uint256, In[2] memory){ In[2] memory a=[In(7,8),In(9,10)]; return (42, a); }
  function one() external pure returns(uint256, In[1] memory){ In[1] memory a=[In(7,8)]; return (42, a); }
  function three() external pure returns(uint256, In[3] memory){ In[3] memory a=[In(1,2),In(3,4),In(5,6)]; return (42, a); }
  function first() external pure returns(In[2] memory, uint256){ In[2] memory a=[In(1,2),In(3,4)]; return (a, 42); }
  function middle() external pure returns(uint256, In[2] memory, uint256){ In[2] memory a=[In(1,2),In(3,4)]; return (7, a, 42); }
  function last() external pure returns(uint256, uint256, In[2] memory){ In[2] memory a=[In(1,2),In(3,4)]; return (42, 7, a); }
  function wide() external pure returns(uint256, In3[2] memory){ In3[2] memory a=[In3(1,2,3),In3(4,5,6)]; return (42, a); }
  function nested() external pure returns(uint256, In2[2] memory){ In2[2] memory a=[In2(In(1,2),3), In2(In(4,5),6)]; return (42, a); }
  function withValArr() external pure returns(In[2] memory, uint256[3] memory){ In[2] memory a=[In(1,2),In(3,4)]; uint256[3] memory v=[uint256(11),12,13]; return (a, v); }
  function withStruct() external pure returns(In memory, In[2] memory){ In memory s=In(99,100); In[2] memory a=[In(1,2),In(3,4)]; return (s, a); }
  function withStr() external pure returns(In[2] memory, string memory){ In[2] memory a=[In(1,2),In(3,4)]; return (a, "hello"); }
  function twoArrs() external pure returns(In[2] memory, uint256, In[3] memory){ In[2] memory a=[In(1,2),In(3,4)]; In[3] memory b=[In(5,6),In(7,8),In(9,10)]; return (a, 5, b); }
  function nestedArr() external pure returns(uint256, In[2][2] memory){ In[2][2] memory a=[[In(1,2),In(3,4)],[In(5,6),In(7,8)]]; return (42, a); }
  function ctrlSolo() external pure returns(In[2] memory){ In[2] memory a=[In(7,8),In(9,10)]; return a; }
  function ctrlStructInTuple() external pure returns(uint256, In memory){ In memory s=In(7,8); return (42, s); }
  function ctrlValArrInTuple() external pure returns(uint256, uint256[3] memory){ uint256[3] memory a=[uint256(7),8,9]; return (42, a); }
  function ctrlAbiEncode() external pure returns(bytes memory){ In[2] memory a=[In(7,8),In(9,10)]; return abi.encode(uint256(42), a); }
}`;

describe('fixed-array-of-static-struct multi-return component vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, sig: string) {
    const data = '0x' + sel(sig);
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return s.returnHex;
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('two(): payload is INLINED [0x2a, 7, 8, 9, 10] with no offset words (was miscompiled to [0x2a,0x80,0xc0,0x2a,0x00])', async () => {
    const ret = await eq('two', 'two()');
    // decode every word: NO dynamic offset words, the struct payload is inlined.
    const words = ret.replace(/^0x/, '').match(/.{64}/g)!;
    expect(words).toHaveLength(5);
    expect(BigInt('0x' + words[0])).toBe(0x2an);
    expect(BigInt('0x' + words[1])).toBe(7n);
    expect(BigInt('0x' + words[2])).toBe(8n);
    expect(BigInt('0x' + words[3])).toBe(9n);
    expect(BigInt('0x' + words[4])).toBe(10n);
  });

  it('N = 1 / 2 / 3', async () => {
    await eq('one', 'one()');
    await eq('two', 'two()');
    await eq('three', 'three()');
  });

  it('Arr<In,N> at first / middle / last tuple position', async () => {
    await eq('first', 'first()');
    await eq('middle', 'middle()');
    await eq('last', 'last()');
  });

  it('3-field element struct and nested-static-struct element', async () => {
    await eq('wide', 'wide()');
    await eq('nested', 'nested()');
  });

  it('alongside a value array / another struct / a string / two static-struct arrays / nested fixed', async () => {
    await eq('withValArr', 'withValArr()');
    await eq('withStruct', 'withStruct()');
    await eq('withStr', 'withStr()');
    await eq('twoArrs', 'twoArrs()');
    await eq('nestedArr', 'nestedArr()');
  });

  it('CONTROLS unregressed: solo return, static struct in tuple, value array in tuple, abi.encode', async () => {
    await eq('ctrlSolo', 'ctrlSolo()');
    await eq('ctrlStructInTuple', 'ctrlStructInTuple()');
    await eq('ctrlValArrInTuple', 'ctrlValArrInTuple()');
    await eq('ctrlAbiEncode', 'ctrlAbiEncode()');
  });
});
