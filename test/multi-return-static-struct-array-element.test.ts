// The 9th pointer-headed Arr<In,N> consumer (docs/HANDOFF-pointer-headed-coverage.md Step 1): a
// multi-value tuple return whose component is a fixed-array ELEMENT m[i] of type Arr<In,N> (source
// Arr<Arr<In,N>,M> or Arr<In,N>[]). Arr<In,N> is ABI-STATIC, so the component is encoded INLINE in
// the head (abiHeadWords(t) words, no offset word) - but the tuple encoder's arrayValue/memArrayExpr
// branch unconditionally wrote a dynamic offset word (and hw += 1 against a totalHead that reserved
// abiHeadWords), emitting [42, 0xa0, 0,0,0, payload] where solc emits [42, payload] - a silent
// miscompile (both calls succeed, different bytes). The sibling of the e33d131 plain-local fix: the
// branch now routes an ABI-static element through abiEncFromMem at the head position (dereferencing
// the pointer-headed element image; a flat value-array element image copies verbatim). A genuinely
// dynamic component (string[], u256[], Arr<string,N>) still gets its offset word.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);

const J = `@struct class In { x: u256; y: u256 }
@struct class In3 { x: u256; y: u256; z: u256 }
@contract class C {
  @external @pure fNest(): [u256, Arr<In,2>] { let m: Arr<Arr<In,2>,2> = [[In(11n,12n),In(13n,14n)],[In(15n,16n),In(17n,18n)]]; return [42n, m[1n]]; }
  @external @pure fDynOuter(): [u256, Arr<In,2>] { let m: Arr<In,2>[] = [[In(11n,12n),In(13n,14n)],[In(15n,16n),In(17n,18n)]]; return [42n, m[1n]]; }
  @external @pure fFirst(): [Arr<In,2>, u256] { let m: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)]]; return [m[0n], 42n]; }
  @external @pure fMid(): [u256, Arr<In,2>, u256] { let m: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)]]; return [7n, m[1n], 43n]; }
  @external @pure fLast(): [u256, u256, Arr<In,2>] { let m: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)]]; return [42n, 7n, m[0n]]; }
  @external @pure fIn3(): [u256, Arr<In3,2>] { let m: Arr<In3,2>[] = [[In3(1n,2n,3n),In3(4n,5n,6n)]]; return [42n, m[0n]]; }
  @external @pure fDeep(): [u256, Arr<Arr<In,2>,2>] { let m: Arr<Arr<Arr<In,2>,2>,2> = [[[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)]],[[In(21n,22n),In(23n,24n)],[In(25n,26n),In(27n,28n)]]]; return [42n, m[1n]]; }
  @external @pure fMixed(): [u256, Arr<In,2>, string] { let m: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)]]; return [42n, m[1n], "hello world"]; }
  @external @pure fValElem(): [u256, Arr<u256,2>] { let m: Arr<Arr<u256,2>,2> = [[31n,32n],[33n,34n]]; return [42n, m[1n]]; }
  @external @pure fValElemDyn(): [u256, Arr<u256,2>] { let m: Arr<u256,2>[] = [[31n,32n],[33n,34n]]; return [42n, m[1n]]; }
  @external @pure fTwoElems(): [Arr<In,2>, u256, Arr<In,2>] { let m: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)],[In(5n,6n),In(7n,8n)]]; return [m[0n], 5n, m[1n]]; }
  @external @pure ctrlLocal(): [u256, Arr<In,2>] { let a: Arr<In,2> = [In(15n,16n),In(17n,18n)]; return [42n, a]; }
  @external @pure ctrlEnc(): bytes { let m: Arr<Arr<In,2>,2> = [[In(11n,12n),In(13n,14n)],[In(15n,16n),In(17n,18n)]]; return abi.encode(m[1n]); }
  @external @pure ctrlDynStr(): [u256, string[]] { let ss: string[] = ["ab","cde"]; return [42n, ss]; }
  @external @pure ctrlDynArr(): [u256, u256[]] { let xs: u256[] = [7n,8n,9n]; return [42n, xs]; } }`;

const S = `struct In { uint256 x; uint256 y; } struct In3 { uint256 x; uint256 y; uint256 z; }
contract C {
  function fNest() external pure returns(uint256, In[2] memory){ In[2][2] memory m=[[In(11,12),In(13,14)],[In(15,16),In(17,18)]]; return (42, m[1]); }
  function fDynOuter() external pure returns(uint256, In[2] memory){ In[2][] memory m=new In[2][](2); m[0]=[In(11,12),In(13,14)]; m[1]=[In(15,16),In(17,18)]; return (42, m[1]); }
  function fFirst() external pure returns(In[2] memory, uint256){ In[2][2] memory m=[[In(1,2),In(3,4)],[In(5,6),In(7,8)]]; return (m[0], 42); }
  function fMid() external pure returns(uint256, In[2] memory, uint256){ In[2][2] memory m=[[In(1,2),In(3,4)],[In(5,6),In(7,8)]]; return (7, m[1], 43); }
  function fLast() external pure returns(uint256, uint256, In[2] memory){ In[2][2] memory m=[[In(1,2),In(3,4)],[In(5,6),In(7,8)]]; return (42, 7, m[0]); }
  function fIn3() external pure returns(uint256, In3[2] memory){ In3[2][] memory m=new In3[2][](1); m[0]=[In3(1,2,3),In3(4,5,6)]; return (42, m[0]); }
  function fDeep() external pure returns(uint256, In[2][2] memory){ In[2][2][2] memory m=[[[In(1,2),In(3,4)],[In(5,6),In(7,8)]],[[In(21,22),In(23,24)],[In(25,26),In(27,28)]]]; return (42, m[1]); }
  function fMixed() external pure returns(uint256, In[2] memory, string memory){ In[2][2] memory m=[[In(1,2),In(3,4)],[In(5,6),In(7,8)]]; return (42, m[1], "hello world"); }
  function fValElem() external pure returns(uint256, uint256[2] memory){ uint256[2][2] memory m=[[uint256(31),32],[uint256(33),34]]; return (42, m[1]); }
  function fValElemDyn() external pure returns(uint256, uint256[2] memory){ uint256[2][] memory m=new uint256[2][](2); m[0]=[uint256(31),32]; m[1]=[uint256(33),34]; return (42, m[1]); }
  function fTwoElems() external pure returns(In[2] memory, uint256, In[2] memory){ In[2][2] memory m=[[In(1,2),In(3,4)],[In(5,6),In(7,8)]]; return (m[0], 5, m[1]); }
  function ctrlLocal() external pure returns(uint256, In[2] memory){ In[2] memory a=[In(15,16),In(17,18)]; return (42, a); }
  function ctrlEnc() external pure returns(bytes memory){ In[2][2] memory m=[[In(11,12),In(13,14)],[In(15,16),In(17,18)]]; return abi.encode(m[1]); }
  function ctrlDynStr() external pure returns(uint256, string[] memory){ string[] memory ss=new string[](2); ss[0]="ab"; ss[1]="cde"; return (42, ss); }
  function ctrlDynArr() external pure returns(uint256, uint256[] memory){ uint256[] memory xs=new uint256[](3); xs[0]=7;xs[1]=8;xs[2]=9; return (42, xs); } }`;

describe('9th pointer-headed consumer: tuple return of a fixed-array ELEMENT m[i]: Arr<In,N>', () => {
  it('byte-identical to solc 0.8.35 across nestings, positions, widths, mixed tuples, and controls', async () => {
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    for (const sg of [
      'fNest()', 'fDynOuter()', 'fFirst()', 'fMid()', 'fLast()', 'fIn3()', 'fDeep()', 'fMixed()',
      'fValElem()', 'fValElemDyn()', 'fTwoElems()', 'ctrlLocal()', 'ctrlEnc()', 'ctrlDynStr()', 'ctrlDynArr()',
    ]) {
      const jr = await h.call(ja, sel(sg));
      const sr = await h.call(sa, sel(sg));
      expect(jr.returnHex, sg).toBe(sr.returnHex);
      expect(jr.success, sg).toBe(sr.success);
    }
    // non-vacuity anchor: the repro's exact expected bytes (42 then the m[1] payload inline, 5 words).
    const jr = await h.call(ja, sel('fNest()'));
    expect(jr.returnHex).toBe(
      '0x' + ['2a', 'f', '10', '11', '12'].map((v) => v.padStart(64, '0')).join(''),
    );
  });
});
