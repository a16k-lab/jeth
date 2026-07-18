// ADDRESS-INT-OPERATOR (JETH083, soundness OA closure): an ARITHMETIC or BITWISE binary operator between
// an INTEGER (uintN/intN) operand and an ADDRESS operand is a type error in solc ("Built-in binary operator
// + cannot be applied to types uint256 and address"). JETH already rejected the address-VARIABLE twin
// (`u256var + addrParam` -> JETH083 via commonNumericType) and the two-literal form (`1 + address(0)`), but
// an address LITERAL operand (`address(0)`, `address(this)`, a checksummed 40-hex literal) slipped through:
// retypeLiteral declines an address literal SILENTLY (no diagnostic), so unifyOperands returned undefined
// with no error and the expression error-recovery ACCEPTED the mismatched op (an over-acceptance). The fix
// makes unifyOperands emit the SAME JETH083 the variable path already produces when an address literal fails
// to retype, so the literal and variable operand paths reject identically. VALID address use is untouched:
// address<->address comparisons, uint160(addr) arithmetic, bytesN bitwise, and address(0) in value position
// all still ACCEPT and run byte-identically to solc.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);

const errCodes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.map((d) => d.code);
    throw e;
  }
};
const accepts = (src: string): boolean => errCodes(src).length === 0;
const solcRejects = (s: string): boolean => {
  try {
    compileSolidity(SPDX + s, 'C');
    return false;
  } catch {
    return true;
  }
};

async function runDiff(jeth: string, sol: string, calls: { sig: string; args?: string }[]) {
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

describe('ADDRESS-INT-OPERATOR: integer-vs-address arithmetic/bitwise is a type error (matches solc)', () => {
  // ---- the pinned OA: it must now flip accept -> reject, with solc rejecting too ----
  it('rejects the pinned OA `u256var + address(0)` with JETH083 (solc rejects too)', () => {
    const J = `class C { get f(a: u256): External<u256> { let q: u256 = a + address(0); return q; } }`;
    const S = `contract C { function f(uint256 a) external pure returns (uint256){ uint256 q = a + address(0); return q; } }`;
    expect(errCodes(J)).toContain('JETH083');
    expect(solcRejects(S)).toBe(true);
  });

  // ---- FULL-AXIS reject close: {u256,i256,u8,i8}-var {+,-,*,/,%,&,|,^} {address(0), addrParam, address(this)},
  //      both operand orders. Every one must reject in JETH and in solc. ----
  it('rejects every integer-var (op) address form, both orders, with solc-reject parity', () => {
    const widths: Array<[string, string]> = [
      ['u256', 'uint256'],
      ['i256', 'int256'],
      ['u8', 'uint8'],
      ['i8', 'int8'],
    ];
    const ops = ['+', '-', '*', '/', '%', '&', '|', '^'];
    // [jethAddr, solAddr, mutability, needsAddrParam]
    const addrs: Array<[string, string, string, boolean]> = [
      ['address(0)', 'address(0)', 'pure', false],
      ['b', 'b', 'pure', true],
      ['address(this)', 'address(this)', 'view', false],
    ];
    for (const [jw, sw] of widths) {
      for (const op of ops) {
        for (const [ja, sa, mut, needsParam] of addrs) {
          const jsig = needsParam ? `a: ${jw}, b: address` : `a: ${jw}`;
          const ssig = needsParam ? `${sw} a, address b` : `${sw} a`;
          // integer var OP address
          const J1 = `class C { get f(${jsig}): External<${jw}> { return a ${op} ${ja}; } }`;
          const S1 = `contract C { function f(${ssig}) external ${mut} returns (${sw}){ return a ${op} ${sa}; } }`;
          expect(accepts(J1), `${jw} a ${op} ${ja}`).toBe(false);
          expect(solcRejects(S1), `solc ${sw} a ${op} ${sa}`).toBe(true);
          // address OP integer var (other order)
          const J2 = `class C { get f(${jsig}): External<${jw}> { return ${ja} ${op} a; } }`;
          const S2 = `contract C { function f(${ssig}) external ${mut} returns (${sw}){ return ${sa} ${op} a; } }`;
          expect(accepts(J2), `${ja} ${op} ${jw} a`).toBe(false);
          expect(solcRejects(S2), `solc ${sa} ${op} ${sw} a`).toBe(true);
        }
      }
    }
  });

  // ---- an address VARIABLE combined arithmetically with an integer, and address (op) address, both reject ----
  it('rejects address-var + int-var, and address (arith) address (solc rejects)', () => {
    const cases: Array<[string, string]> = [
      [
        `class C { get f(a: address, b: u256): External<u256> { return a + b; } }`,
        `contract C { function f(address a, uint256 b) external pure returns (uint256){ return a + b; } }`,
      ],
      [
        `class C { get f(a: address, b: address): External<u256> { return a + b; } }`,
        `contract C { function f(address a, address b) external pure returns (uint256){ return a + b; } }`,
      ],
      [
        `class C { get f(a: address, b: address): External<u256> { return a & b; } }`,
        `contract C { function f(address a, address b) external pure returns (uint256){ return a & b; } }`,
      ],
    ];
    for (const [J, S] of cases) {
      expect(accepts(J), J).toBe(false);
      expect(solcRejects(S), S).toBe(true);
    }
  });

  // ---- the same mismatch under a COMPARISON (address literal vs integer) is also a solc type error;
  //      the address-literal-decline fix closes it identically. Two-address comparisons are UNAFFECTED. ----
  it('rejects address-literal vs integer comparison (== / <), solc rejects', () => {
    const cases: Array<[string, string]> = [
      [
        `class C { get f(a: u256): External<bool> { return address(0) == a; } }`,
        `contract C { function f(uint256 a) external pure returns (bool){ return address(0) == a; } }`,
      ],
      [
        `class C { get f(a: u256): External<bool> { return a == address(0); } }`,
        `contract C { function f(uint256 a) external pure returns (bool){ return a == address(0); } }`,
      ],
      [
        `class C { get f(a: u256): External<bool> { return a < address(0); } }`,
        `contract C { function f(uint256 a) external pure returns (bool){ return a < address(0); } }`,
      ],
    ];
    for (const [J, S] of cases) {
      expect(accepts(J), J).toBe(false);
      expect(solcRejects(S), S).toBe(true);
    }
  });

  // ---- NO NEW OVER-REJECTION: the literal path that already rejected must STILL reject with JETH083 ----
  it('keeps rejecting the two-literal `1 + address(0)` (regression guard)', () => {
    expect(errCodes(`class C { get f(): External<u256> { let q: u256 = 1n + address(0); return q; } }`)).toContain(
      'JETH083',
    );
  });

  // ---- NO NEW OVER-REJECTION: valid programs still ACCEPT and run byte-identically to solc ----
  it('valid integer arithmetic still compiles byte-identically', async () => {
    await runDiff(
      `class C { get f(a: u256, b: u256): External<u256> { return a + b; } }`,
      `contract C { function f(uint256 a, uint256 b) external pure returns (uint256){ return a + b; } }`,
      [{ sig: 'f(uint256,uint256)', args: pad32(7n).slice(2) + pad32(5n).slice(2) }],
    );
    await runDiff(
      `class C { get f(a: i256, b: i256): External<i256> { return a * b; } }`,
      `contract C { function f(int256 a, int256 b) external pure returns (int256){ return a * b; } }`,
      [{ sig: 'f(int256,int256)', args: pad32(6n).slice(2) + pad32(7n).slice(2) }],
    );
    await runDiff(
      `class C { get f(a: u8, b: u8): External<u256> { return a + b; } }`,
      `contract C { function f(uint8 a, uint8 b) external pure returns (uint256){ return uint256(a) + uint256(b); } }`,
      [{ sig: 'f(uint8,uint8)', args: pad32(200n).slice(2) + pad32(55n).slice(2) }],
    );
  });

  it('valid address comparisons and address(0) value use still compile byte-identically', async () => {
    // all six comparison operators between two addresses
    for (const op of ['<', '<=', '>', '>=', '==', '!=']) {
      const J = `class C { get f(a: address, b: address): External<bool> { return a ${op} b; } }`;
      const S = `contract C { function f(address a, address b) external pure returns (bool){ return a ${op} b; } }`;
      expect(accepts(J), J).toBe(true);
      expect(solcRejects(S), S).toBe(false);
      await runDiff(J, S, [
        { sig: 'f(address,address)', args: pad32(3n).slice(2) + pad32(9n).slice(2) },
        { sig: 'f(address,address)', args: pad32(9n).slice(2) + pad32(9n).slice(2) },
      ]);
    }
    // address(0) compared to a param, and used as a plain value
    await runDiff(
      `class C { get f(a: address): External<bool> { return address(0) == a; } }`,
      `contract C { function f(address a) external pure returns (bool){ return address(0) == a; } }`,
      [
        { sig: 'f(address)', args: pad32(0n).slice(2) },
        { sig: 'f(address)', args: pad32(1n).slice(2) },
      ],
    );
    await runDiff(
      `class C { get g(): External<address> { let z: address = address(0); return z; } }`,
      `contract C { function g() external pure returns (address){ address z = address(0); return z; } }`,
      [{ sig: 'g()' }],
    );
  });

  it('valid uint160(addr) arithmetic, bytesN bitwise, bool && bool, enum == still compile byte-identically', async () => {
    // an explicit uint160 cast of an address makes arithmetic legal on both sides
    await runDiff(
      `class C { get f(a: address): External<u160> { return u160(a) + 1n; } }`,
      `contract C { function f(address a) external pure returns (uint160){ return uint160(a) + 1; } }`,
      [{ sig: 'f(address)', args: pad32(41n).slice(2) }],
    );
    await runDiff(
      `class C { get f(a: address): External<u160> { return u160(a) & u160(255n); } }`,
      `contract C { function f(address a) external pure returns (uint160){ return uint160(a) & uint160(255); } }`,
      [{ sig: 'f(address)', args: pad32(BigInt('0x1ff')).slice(2) }],
    );
    // bytesN bitwise is legal
    await runDiff(
      `class C { get f(a: bytes32, b: bytes32): External<bytes32> { return a & b; } }`,
      `contract C { function f(bytes32 a, bytes32 b) external pure returns (bytes32){ return a & b; } }`,
      [{ sig: 'f(bytes32,bytes32)', args: pad32(0xff00n).slice(2) + pad32(0x0ff0n).slice(2) }],
    );
    // bool && bool is legal
    await runDiff(
      `class C { get f(a: bool, b: bool): External<bool> { return a && b; } }`,
      `contract C { function f(bool a, bool b) external pure returns (bool){ return a && b; } }`,
      [
        { sig: 'f(bool,bool)', args: pad32(1n).slice(2) + pad32(1n).slice(2) },
        { sig: 'f(bool,bool)', args: pad32(1n).slice(2) + pad32(0n).slice(2) },
      ],
    );
    // enum comparison is legal
    await runDiff(
      `enum E { A, B }\nclass C { get f(a: E, b: E): External<bool> { return a == b; } }`,
      `contract C { enum E { A, B } function f(E a, E b) external pure returns (bool){ return a == b; } }`,
      [
        { sig: 'f(uint8,uint8)', args: pad32(0n).slice(2) + pad32(1n).slice(2) },
        { sig: 'f(uint8,uint8)', args: pad32(1n).slice(2) + pad32(1n).slice(2) },
      ],
    );
  });
});
