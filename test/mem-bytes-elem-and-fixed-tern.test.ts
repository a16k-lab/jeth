// Differential tests for two over-rejection lifts (W3-Y2b):
//   P0-35b: a single-byte element write into a MEMORY bytes[]/string[] element - `xs[i][j] = <bytes1>`
//           on a `bytes[] memory` local. Previously misrouted to the STORAGE strArrayElem resolver
//           (JETH055 @pure / JETH900); now an in-place bounds-checked mstore8 (memByteIndexStore),
//           byte-identical to solc.
//   P1-13:  a FIXED value-array ternary LVALUE - `(c ? xs : ys)[i] = v` on Arr<u256,N> locals (and a
//           nested value sub-array Arr<Arr<u256,2>,N>). Previously JETH151 (misleading); now the
//           taken branch is aliased and the element write lands on the selected array, byte-identical.
// Also asserts adjacent solc-rejected shapes still BOTH-REJECT and const-OOB stays a compile error.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

async function diff(jeth: string, sol: string, calls: { sig: string; args?: string }[]) {
  const jb = compile(jeth, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jb.creationBytecode);
  const as = await hs.deploy(sb.creation);
  for (const c of calls) {
    const data = '0x' + sel(c.sig) + (c.args ?? '');
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig}: returndata`).toBe(rs.returnHex);
  }
}

function jethRejects(jeth: string): string[] {
  try {
    compile(jeth, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    return ((e as { diagnostics?: { code: string }[] }).diagnostics ?? []).map((d) => d.code);
  }
}

describe('P0-35b: memory bytes[]/string[] single-byte element write vs Solidity', () => {
  it('bytes[] element byte write: solc "abc" with xs[0][1]=0x21 -> "a!c"', async () => {
    await diff(
      `class C { get f(): External<bytes> { const xs: bytes[] = [bytes("abc")]; xs[0n][1n] = 0x21n; return xs[0n]; } }`,
      `contract C { function f() external pure returns (bytes memory){ bytes[] memory xs=new bytes[](1); xs[0]=bytes("abc"); xs[0][1]=0x21; return xs[0]; } }`,
      [{ sig: 'f()' }],
    );
  });

  it('multiple element/byte writes across several elements', async () => {
    await diff(
      `class C { get f(): External<bytes> { const xs: bytes[] = [bytes("abc"), bytes("hello")]; xs[0n][0n]=0x41n; xs[0n][2n]=0x5an; xs[1n][1n]=0x21n; xs[1n][4n]=0x2an; return xs[1n]; } }`,
      `contract C { function f() external pure returns (bytes memory){ bytes[] memory xs=new bytes[](2); xs[0]=bytes("abc"); xs[1]=bytes("hello"); xs[0][0]=0x41; xs[0][2]=0x5a; xs[1][1]=0x21; xs[1][4]=0x2a; return xs[1]; } }`,
      [{ sig: 'f()' }],
    );
  });

  it('write-then-read the mutated byte (round trip)', async () => {
    await diff(
      `class C { get f(): External<bytes1> { const xs: bytes[] = [bytes("abc")]; xs[0n][2n] = 0x7fn; return xs[0n][2n]; } }`,
      `contract C { function f() external pure returns (bytes1){ bytes[] memory xs=new bytes[](1); xs[0]=bytes("abc"); xs[0][2]=0x7f; return xs[0][2]; } }`,
      [{ sig: 'f()' }],
    );
  });

  it('OOB byte index reverts Panic 0x32, byte-identical', async () => {
    await diff(
      `class C { get f(i: u256): External<bytes> { const xs: bytes[] = [bytes("abc")]; xs[0n][i] = 0x21n; return xs[0n]; } }`,
      `contract C { function f(uint256 i) external pure returns (bytes memory){ bytes[] memory xs=new bytes[](1); xs[0]=bytes("abc"); xs[0][i]=0x21; return xs[0]; } }`,
      [{ sig: 'f(uint256)', args: W(1n) }, { sig: 'f(uint256)', args: W(3n) }, { sig: 'f(uint256)', args: W(100n) }],
    );
  });

  it('OOB outer index reverts Panic 0x32, byte-identical', async () => {
    await diff(
      `class C { get f(i: u256): External<bytes> { const xs: bytes[] = [bytes("abc")]; xs[i][0n] = 0x21n; return xs[0n]; } }`,
      `contract C { function f(uint256 i) external pure returns (bytes memory){ bytes[] memory xs=new bytes[](1); xs[0]=bytes("abc"); xs[i][0]=0x21; return xs[0]; } }`,
      [{ sig: 'f(uint256)', args: W(0n) }, { sig: 'f(uint256)', args: W(1n) }, { sig: 'f(uint256)', args: W(5n) }],
    );
  });

  it('the write stays @view-clean (no state access): a @view fn compiles + matches', async () => {
    await diff(
      `class C { get f(): External<bytes> { const xs: bytes[] = [bytes("abc")]; xs[0n][1n]=0x5an; return xs[0n]; } }`,
      `contract C { function f() external view returns (bytes memory){ bytes[] memory xs=new bytes[](1); xs[0]=bytes("abc"); xs[0][1]=0x5a; return xs[0]; } }`,
      [{ sig: 'f()' }],
    );
  });

  it('nested bytes[][] element byte write (xs[i][j][k])', async () => {
    await diff(
      `class C { get f(): External<bytes> { const xs: bytes[][] = [[bytes("abc")]]; xs[0n][0n][1n]=0x5an; return xs[0n][0n]; } }`,
      `contract C { function f() external pure returns (bytes memory){ bytes[][] memory xs=new bytes[][](1); xs[0]=new bytes[](1); xs[0][0]=bytes("abc"); xs[0][0][1]=0x5a; return xs[0][0]; } }`,
      [{ sig: 'f()' }],
    );
  });

  it('a string[] element is NOT byte-indexable (both reject)', () => {
    // solc: "Index access for string is not possible." JETH: JETH205.
    expect(jethRejects(`class C { f(): External<void> { const xs: string[] = ["ab"]; xs[0n][0n]=0x41n; } }`)).toContain('JETH205');
  });

  it('STORAGE bytes[]/bytes byte-writes still route to storage (unchanged), byte-identical', async () => {
    await diff(
      `class C { d: bytes[]; add(b: bytes): External<void> { this.d.push(b); } set(i: u256, j: u256): External<void> { this.d[i][j] = 0x5an; } get get(i: u256): External<bytes> { return this.d[i]; } }`,
      `contract C { bytes[] d; function add(bytes calldata b) external { d.push(b); } function set(uint256 i,uint256 j) external { d[i][j]=0x5a; } function get(uint256 i) external view returns (bytes memory){ return d[i]; } }`,
      [
        { sig: 'add(bytes)', args: W(0x20n) + W(3n) + '616263'.padEnd(64, '0') },
        { sig: 'set(uint256,uint256)', args: W(0n) + W(1n) },
        { sig: 'get(uint256)', args: W(0n) },
      ],
    );
  });
});

describe('P1-13: fixed value-array ternary lvalue vs Solidity', () => {
  it('(c ? xs : ys)[0] = 9 writes THROUGH to the selected array (both branches)', async () => {
    await diff(
      `class C { get f(c: bool): External<u256> { const xs: Arr<u256,3> = [1n,2n,3n]; const ys: Arr<u256,3> = [4n,5n,6n]; (c ? xs : ys)[0n] = 9n; return xs[0n]*1000n + ys[0n]; } }`,
      `contract C { function f(bool c) external pure returns (uint256){ uint256[3] memory xs=[uint256(1),2,3]; uint256[3] memory ys=[uint256(4),5,6]; (c?xs:ys)[0]=9; return xs[0]*1000+ys[0]; } }`,
      [{ sig: 'f(bool)', args: W(1n) }, { sig: 'f(bool)', args: W(0n) }],
    );
  });

  it('write to a non-zero index with a runtime value', async () => {
    await diff(
      `class C { get f(c: bool, v: u256): External<u256> { const xs: Arr<u256,3> = [1n,2n,3n]; const ys: Arr<u256,3> = [4n,5n,6n]; (c ? xs : ys)[2n] = v; return xs[2n]*1000n + ys[2n]; } }`,
      `contract C { function f(bool c, uint256 v) external pure returns (uint256){ uint256[3] memory xs=[uint256(1),2,3]; uint256[3] memory ys=[uint256(4),5,6]; (c?xs:ys)[2]=v; return xs[2]*1000+ys[2]; } }`,
      [{ sig: 'f(bool,uint256)', args: W(1n) + W(77n) }, { sig: 'f(bool,uint256)', args: W(0n) + W(88n) }],
    );
  });

  it('READ of the ternary element, both branches + several indices', async () => {
    await diff(
      `class C { get f(c: bool, i: u256): External<u256> { const xs: Arr<u256,3> = [1n,2n,3n]; const ys: Arr<u256,3> = [4n,5n,6n]; return (c ? xs : ys)[i]; } }`,
      `contract C { function f(bool c, uint256 i) external pure returns (uint256){ uint256[3] memory xs=[uint256(1),2,3]; uint256[3] memory ys=[uint256(4),5,6]; return (c?xs:ys)[i]; } }`,
      [{ sig: 'f(bool,uint256)', args: W(1n) + W(0n) }, { sig: 'f(bool,uint256)', args: W(1n) + W(2n) }, { sig: 'f(bool,uint256)', args: W(0n) + W(1n) }],
    );
  });

  it('OOB runtime index reverts Panic 0x32, byte-identical', async () => {
    await diff(
      `class C { get f(c: bool, i: u256): External<u256> { const xs: Arr<u256,3> = [1n,2n,3n]; const ys: Arr<u256,3> = [4n,5n,6n]; (c ? xs : ys)[i] = 9n; return xs[0n]; } }`,
      `contract C { function f(bool c, uint256 i) external pure returns (uint256){ uint256[3] memory xs=[uint256(1),2,3]; uint256[3] memory ys=[uint256(4),5,6]; (c?xs:ys)[i]=9; return xs[0]; } }`,
      [{ sig: 'f(bool,uint256)', args: W(1n) + W(3n) }, { sig: 'f(bool,uint256)', args: W(0n) + W(100n) }],
    );
  });

  it('side-effecting condition runs once; only the taken branch is mutated', async () => {
    await diff(
      `class C { n: u256; f(): External<u256> { const xs: Arr<u256,2> = [1n,2n]; const ys: Arr<u256,2> = [3n,4n]; (this.bump() > 0n ? xs : ys)[0n] = 9n; return xs[0n]*100n + ys[0n]*10n + this.n; } bump(): u256 { this.n = this.n + 1n; return this.n; } }`,
      `contract C { uint256 public n; function f() external returns (uint256){ uint256[2] memory xs=[uint256(1),2]; uint256[2] memory ys=[uint256(3),4]; (bump() > 0 ? xs : ys)[0]=9; return xs[0]*100 + ys[0]*10 + n; } function bump() internal returns (uint256){ n=n+1; return n; } }`,
      [{ sig: 'f()' }],
    );
  });

  it('nested value sub-array ternary element write ((c ? xs : ys)[i][j] = v)', async () => {
    await diff(
      `class C { get f(c: bool): External<u256> { const xs: Arr<Arr<u256,2>,2> = [[1n,2n],[3n,4n]]; const ys: Arr<Arr<u256,2>,2> = [[5n,6n],[7n,8n]]; (c ? xs : ys)[0n][1n]=99n; return xs[0n][1n]*1000n + ys[0n][1n]; } }`,
      `contract C { function f(bool c) external pure returns (uint256){ uint256[2][2] memory xs=[[uint256(1),2],[uint256(3),4]]; uint256[2][2] memory ys=[[uint256(5),6],[uint256(7),8]]; (c?xs:ys)[0][1]=99; return xs[0][1]*1000 + ys[0][1]; } }`,
      [{ sig: 'f(bool)', args: W(1n) }, { sig: 'f(bool)', args: W(0n) }],
    );
  });

  it('const-OOB index into a fixed-array ternary is a compile error (both reject)', () => {
    // solc: "Out of bounds array access". JETH: JETH211 (was an over-acceptance before the memFixedLen wiring).
    expect(jethRejects(`class C { get f(c: bool): External<u256> { const xs: Arr<u256,3> = [1n,2n,3n]; const ys: Arr<u256,3> = [4n,5n,6n]; (c ? xs : ys)[5n] = 9n; return xs[0n]; } }`)).toContain('JETH211');
    expect(jethRejects(`class C { get f(c: bool): External<u256> { const xs: Arr<u256,3> = [1n,2n,3n]; const ys: Arr<u256,3> = [4n,5n,6n]; return (c ? xs : ys)[5n]; } }`)).toContain('JETH211');
  });

  it('a dynamic value-array ternary lvalue still works (regression)', async () => {
    await diff(
      `class C { get f(c: bool): External<u256> { const xs: u256[] = [1n,2n,3n]; const ys: u256[] = [4n,5n,6n]; (c ? xs : ys)[0n] = 9n; return xs[0n]*1000n + ys[0n]; } }`,
      `contract C { function f(bool c) external pure returns (uint256){ uint256[] memory xs=new uint256[](3); xs[0]=1;xs[1]=2;xs[2]=3; uint256[] memory ys=new uint256[](3); ys[0]=4;ys[1]=5;ys[2]=6; (c?xs:ys)[0]=9; return xs[0]*1000+ys[0]; } }`,
      [{ sig: 'f(bool)', args: W(1n) }, { sig: 'f(bool)', args: W(0n) }],
    );
  });
});
