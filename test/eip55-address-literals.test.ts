// EIP-55 address hex literals (Bucket-A "what's left" #5). A 40-hex-digit literal that passes the
// EIP-55 checksum is of type `address` (assignable/comparable without an address(...) cast, and only
// castable to uint160/bytes20); a 39/41-digit or bad-checksum hex literal is a hard error in any
// context. Accept/reject is byte-for-byte aligned with solc 0.8.35, and runtime results match.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const ones = '1'.repeat(40); // all-numeric 40-hex: trivially checksum-valid (an address)
const lower = 'a'.repeat(40); // all-lowercase letters: fails the checksum
const valid = 'dCad3a6d3569DF655070DEd06cb7A1b2Ccd1D3AF'; // a real EIP-55 checksummed address

function jethOk(jeth: string): boolean {
  try { compile(jeth, { fileName: 'C.jeth' }); return true; } catch { return false; }
}
function solcOk(sol: string): boolean {
  try { compileSolidity(SPDX + sol, 'C'); return true; } catch { return false; }
}

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

describe('EIP-55 address-literal acceptance matches solc', () => {
  // [label, jeth-expr, jeth-ret, sol-expr, sol-ret]
  const exprCases: [string, string, string, string, string][] = [
    ['numeric40 -> address', `0x${ones}n`, 'address', `0x${ones}`, 'address'],
    ['valid40 -> address', `0x${valid}n`, 'address', `0x${valid}`, 'address'],
    ['lower40 -> address (bad checksum)', `0x${lower}n`, 'address', `0x${lower}`, 'address'],
    ['validLower -> address (bad checksum)', `0x${valid.toLowerCase()}n`, 'address', `0x${valid.toLowerCase()}`, 'address'],
    ['numeric40 -> u256 (address not implicit int)', `0x${ones}n`, 'u256', `0x${ones}`, 'uint256'],
    ['u160(numeric40)', `u160(0x${ones}n)`, 'u160', `uint160(0x${ones})`, 'uint160'],
    ['u256(numeric40) (no address->u256 cast)', `u256(0x${ones}n)`, 'u256', `uint256(0x${ones})`, 'uint256'],
    ['u160(lower40) (bad checksum)', `u160(0x${lower}n)`, 'u160', `uint160(0x${lower})`, 'uint160'],
    ['bytes20(numeric40)', `bytes20(0x${ones}n)`, 'bytes20', `bytes20(0x${ones})`, 'bytes20'],
    ['bytes32(numeric40) (no address->bytes32)', `bytes32(0x${ones}n)`, 'bytes32', `bytes32(0x${ones})`, 'bytes32'],
    ['address(numeric40)', `address(0x${ones}n)`, 'address', `address(0x${ones})`, 'address'],
    ['address(lower40) (bad checksum in cast)', `address(0x${lower}n)`, 'address', `address(0x${lower})`, 'address'],
    ['u8(numeric40)', `u8(0x${ones}n)`, 'u8', `uint8(0x${ones})`, 'uint8'],
    ['39 digits (not exactly 40)', `0x${'1'.repeat(39)}n`, 'u256', `0x${'1'.repeat(39)}`, 'uint256'],
    ['41 digits (not exactly 40)', `0x${'1'.repeat(41)}n`, 'u256', `0x${'1'.repeat(41)}`, 'uint256'],
    ['38 digits (plain number)', `0x${'1'.repeat(38)}n`, 'u256', `0x${'1'.repeat(38)}`, 'uint256'],
  ];
  for (const [label, je, jr, se, sr] of exprCases) {
    it(label, () => {
      const j = jethOk(`@contract class C { @external @pure f(): ${jr} { return ${je}; } }`);
      const s = solcOk(`contract C { function f() external pure returns(${sr}){ return ${se}; } }`);
      expect(j, `JETH ${j ? 'accepts' : 'rejects'} but solc ${s ? 'accepts' : 'rejects'}`).toBe(s);
    });
  }

  it('@constant address: bare checksummed/numeric accepted, bad-checksum rejected (matches solc)', () => {
    const con = (lit: { jeth: string; sol: string }, ty = 'address', sty = 'address') =>
      [`@contract class C { @constant K: ${ty} = ${lit.jeth}; @external @view f(): ${ty} { return this.K; } }`,
       `contract C { ${sty} constant K = ${lit.sol}; function f() external view returns(${sty}){ return K; } }`] as const;
    const pairs: [string, { jeth: string; sol: string }][] = [
      ['bare valid', { jeth: `0x${valid}n`, sol: `0x${valid}` }],
      ['bare numeric', { jeth: `0x${ones}n`, sol: `0x${ones}` }],
      ['bare lower (reject)', { jeth: `0x${lower}n`, sol: `0x${lower}` }],
    ];
    for (const [label, lit] of pairs) {
      const [j, s] = con(lit);
      expect(jethOk(j), `${label}: JETH vs solc`).toBe(solcOk(s));
    }
    // a 40-hex address literal in a u256 constant is rejected by both (address not convertible).
    expect(jethOk(`@contract class C { @constant K: u256 = 0x${lower}n; @external @view f(): u256 { return this.K; } }`))
      .toBe(solcOk(`contract C { uint256 constant K = 0x${lower}; function f() external view returns(uint256){ return K; } }`));
  });
});

describe('EIP-55 address literals: runtime byte-identity vs solc', () => {
  it('bare literal as address return, casts, constant + comparison', async () => {
    await diff(
      `@contract class C { @external @pure a(): address { return 0x${ones}n; } @external @pure b(): address { return 0x${valid}n; } @external @pure c(): u160 { return u160(0x${ones}n); } @external @pure d(): bytes20 { return bytes20(0x${ones}n); } @external @pure e(): address { return address(0x${ones}n); } }`,
      `contract C { function a() external pure returns(address){ return 0x${ones}; } function b() external pure returns(address){ return 0x${valid}; } function c() external pure returns(uint160){ return uint160(0x${ones}); } function d() external pure returns(bytes20){ return bytes20(0x${ones}); } function e() external pure returns(address){ return address(0x${ones}); } }`,
      [{ sig: 'a()' }, { sig: 'b()' }, { sig: 'c()' }, { sig: 'd()' }, { sig: 'e()' }],
    );
  });

  it('bare @constant address (no address(...) cast), read + compare', async () => {
    await diff(
      `@contract class C { @constant K: address = 0x${valid}n; @external @view getK(): address { return this.K; } @external @view isK(x: address): bool { return x == this.K; } }`,
      `contract C { address constant K = 0x${valid}; function getK() external view returns(address){ return K; } function isK(address x) external view returns(bool){ return x == K; } }`,
      [{ sig: 'getK()' }, { sig: 'isK(address)', args: '00'.repeat(12) + valid }, { sig: 'isK(address)', args: pad32(0x2222n).slice(2) }],
    );
  });
});
