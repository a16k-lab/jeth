// External self-call `this.f(args)`: when `f` is an @external method of the current contract, solc
// lowers `this.f(x)` to a REAL message-call to address(this) through the public ABI
// (encodeWithSelector(f.selector, x) -> CALL/STATICCALL -> bubble revert -> decode return), which also
// forces virtual dispatch to the most-derived override. JETH previously rejected this (JETH240); it
// now reuses the interface-call machinery (the IFoo(addr).bar path) treating the current contract as
// its own interface at address(this).
//
// Each test deploys the JETH contract and the equivalent solc contract, calls with identical calldata,
// and diffs success + returndata + logs (byte-identical parity, including revert/panic/custom-error
// bubbling). @view/@pure callees lower to STATICCALL; mutating callees to CALL.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

function jethRejects(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
}

/** Deploy the JETH contract + the equivalent solc contract in fresh harnesses, run each call against
 *  both, and assert success + returndata + logs are byte-identical. */
async function diff(jeth: string, sol: string, calls: { sig: string; args?: string }[]) {
  const cjb = compile(jeth, { fileName: 'C.jeth' });
  const csb = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const cj = await hj.deploy(cjb.creationBytecode);
  const cs = await hs.deploy(csb.creation);
  for (const c of calls) {
    const data = '0x' + sel(c.sig) + (c.args ?? '');
    const rj = await hj.call(cj, data, {});
    const rs = await hs.call(cs, data, {});
    expect(rj.success, `${c.sig} (${c.args ?? ''}): success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig} (${c.args ?? ''}): returndata`).toBe(rs.returnHex);
    expect(JSON.stringify(rj.logs), `${c.sig} (${c.args ?? ''}): logs`).toBe(JSON.stringify(rs.logs));
  }
}

describe('external self-call this.f(): byte-identical vs solc', () => {
  it('state mutation through this.f() then a getter', async () => {
    await diff(
      `class C {
        x: u256 = 0n;
        setX(v: u256): External<void> { this.x = v; }
        bump(): External<void> { this.setX(this.x + 1n); }
        get getX(): External<u256> { return this.x; }
      }`,
      `contract C {
        uint256 public x;
        function setX(uint256 v) external { x = v; }
        function bump() external { this.setX(x + 1); }
        function getX() external view returns (uint256) { return x; }
      }`,
      [{ sig: 'bump()' }, { sig: 'getX()' }, { sig: 'bump()' }, { sig: 'getX()' }],
    );
  });

  it('value return (CALL) used in an expression', async () => {
    await diff(
      `class C {
        get dbl(v: u256): External<u256> { return v * 2n; }
        go(v: u256): External<u256> { return this.dbl(v) + 1n; }
      }`,
      `contract C {
        function dbl(uint256 v) external pure returns (uint256) { return v * 2; }
        function go(uint256 v) external returns (uint256) { return this.dbl(v) + 1; }
      }`,
      [{ sig: 'go(uint256)', args: W(21n) }],
    );
  });

  it('a @view callee lowers to STATICCALL', async () => {
    await diff(
      `class C {
        y: u256 = 7n;
        get rd(): External<u256> { return this.y; }
        go(): External<u256> { return this.rd() + 100n; }
      }`,
      `contract C {
        uint256 y = 7;
        function rd() external view returns (uint256) { return y; }
        function go() external returns (uint256) { return this.rd() + 100; }
      }`,
      [{ sig: 'go()' }],
    );
  });

  it('let-binding of a value self-call result', async () => {
    await diff(
      `class C {
        get triple(v: u256): External<u256> { return v * 3n; }
        go(v: u256): External<u256> { let r: u256 = this.triple(v); return r + r; }
      }`,
      `contract C {
        function triple(uint256 v) external pure returns (uint256) { return v * 3; }
        function go(uint256 v) external returns (uint256) { uint256 r = this.triple(v); return r + r; }
      }`,
      [{ sig: 'go(uint256)', args: W(4n) }],
    );
  });

  it('void self-call as a statement', async () => {
    await diff(
      `class C {
        n: u256 = 0n;
        inc(): External<void> { this.n = this.n + 1n; }
        run2(): External<void> { this.inc(); this.inc(); }
        get get(): External<u256> { return this.n; }
      }`,
      `contract C {
        uint256 public n;
        function inc() external { n = n + 1; }
        function run2() external { this.inc(); this.inc(); }
        function get() external view returns (uint256) { return n; }
      }`,
      [{ sig: 'run2()' }, { sig: 'get()' }],
    );
  });

  it('inheritance / virtual dispatch: the most-derived override runs', async () => {
    await diff(
      `abstract class Base {
        @virtual get name(): External<u256> { return 1n; }
        who(): External<u256> { return this.name(); }
      }
      class C extends Base {
        @override get name(): External<u256> { return 2n; }
      }`,
      `contract Base {
        function name() external virtual returns (uint256) { return 1; }
        function who() external returns (uint256) { return this.name(); }
      }
      contract C is Base {
        function name() external override returns (uint256) { return 2; }
      }`,
      [{ sig: 'who()' }],
    );
  });

  it('string-revert bubbling through this.f()', async () => {
    await diff(
      `class C {
        get boom(v: u256): External<u256> { require(v > 10n, "too small"); return v; }
        go(v: u256): External<u256> { return this.boom(v); }
      }`,
      `contract C {
        function boom(uint256 v) external pure returns (uint256) { require(v > 10, "too small"); return v; }
        function go(uint256 v) external returns (uint256) { return this.boom(v); }
      }`,
      [{ sig: 'go(uint256)', args: W(5n) }, { sig: 'go(uint256)', args: W(20n) }],
    );
  });

  it('custom-error revert bubbling through this.f()', async () => {
    await diff(
      `class C {
        MyErr: error<{ code: u256 }>;
        get boom(): External<u256> { revert(MyErr(42n)); return 0n; }
        go(): External<u256> { return this.boom(); }
      }`,
      `contract C {
        error MyErr(uint256 code);
        function boom() external pure returns (uint256) { revert MyErr(42); }
        function go() external returns (uint256) { return this.boom(); }
      }`,
      [{ sig: 'go()' }],
    );
  });

  it('Panic (division by zero) bubbling through this.f()', async () => {
    await diff(
      `class C {
        get dv(a: u256, b: u256): External<u256> { return a / b; }
        go(b: u256): External<u256> { return this.dv(10n, b); }
      }`,
      `contract C {
        function dv(uint256 a, uint256 b) external pure returns (uint256) { return a / b; }
        function go(uint256 b) external returns (uint256) { return this.dv(10, b); }
      }`,
      [{ sig: 'go(uint256)', args: W(0n) }, { sig: 'go(uint256)', args: W(2n) }],
    );
  });

  it('struct arg + struct return through a self-call', async () => {
    await diff(
      `type P = { a: u256; b: u256; };
      class C {
        get swap(p: P): External<P> { return P(p.b, p.a); }
        go(): External<u256> { let q: P = this.swap(P(3n, 9n)); return q.a * 100n + q.b; }
      }`,
      `contract C {
        struct P { uint256 a; uint256 b; }
        function swap(P memory p) external pure returns (P memory) { return P(p.b, p.a); }
        function go() external returns (uint256) { P memory q = this.swap(P(3, 9)); return q.a * 100 + q.b; }
      }`,
      [{ sig: 'go()' }],
    );
  });

  it('overloaded external self-call resolves by arity', async () => {
    await diff(
      `class C {
        get f(a: u256): External<u256> { return a + 1n; }
        get f(a: u256, b: u256): External<u256> { return a + b; }
        go(): External<u256> { return this.f(10n) * 1000n + this.f(2n, 3n); }
      }`,
      `contract C {
        function f(uint256 a) external pure returns (uint256) { return a + 1; }
        function f(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }
        function go() external returns (uint256) { return this.f(10) * 1000 + this.f(2, 3); }
      }`,
      [{ sig: 'go()' }],
    );
  });

  it('tuple-return destructure: let [a, b] = this.f()', async () => {
    await diff(
      `class C {
        get pair(): External<[u256, u256]> { return [3n, 4n]; }
        go(): External<u256> { let [a, b]: [u256, u256] = this.pair(); return a * 10n + b; }
      }`,
      `contract C {
        function pair() external pure returns (uint256, uint256) { return (3, 4); }
        function go() external returns (uint256) { (uint256 a, uint256 b) = this.pair(); return a * 10 + b; }
      }`,
      [{ sig: 'go()' }],
    );
  });

  it('self-call in both ternary branches', async () => {
    await diff(
      `class C {
        get dbl(v: u256): External<u256> { return v * 2n; }
        go(c: bool): External<u256> { return c ? this.dbl(3n) : this.dbl(4n); }
      }`,
      `contract C {
        function dbl(uint256 v) external pure returns (uint256) { return v * 2; }
        function go(bool c) external returns (uint256) { return c ? this.dbl(3) : this.dbl(4); }
      }`,
      [{ sig: 'go(bool)', args: W(0n) }, { sig: 'go(bool)', args: W(1n) }],
    );
  });

  it('soundness: a @pure caller cannot make a mutating self-call (both reject)', () => {
    // solc: pure functions cannot read address(this), so `this.mut()` is rejected. JETH agrees.
    expect(
      jethRejects(`@contract class C {
        @external mut(): u256 { return 1n; }
        @external @pure bad(): u256 { return this.mut(); }
      }`),
    ).toBe(true);
  });

  it('an @internal this.f() is still an in-frame internal call (not changed by this lift)', () => {
    // No JETH240: a non-@external this.f() keeps the existing internal-call path.
    expect(
      jethRejects(`class C {
        f(a: u256): u256 { return a + 1n; }
        get go(): External<u256> { return this.f(5n); }
      }`),
    ).toBe(false);
  });
});
