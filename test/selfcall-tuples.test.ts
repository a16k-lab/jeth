// LIFT: tuple-returning `this.f()` EXTERNAL self-call. The single-value / void / tuple-DESTRUCTURE
// (`let [a,b] = this.f()`) forms already worked; this file covers the three remaining forms, each
// proven byte-identical to solc 0.8.35:
//   (a) DIRECT tuple return:   `return this.pair();`
//   (b) TUPLE-ASSIGN:          `[a, b] = this.pair();`
//   (c) try/catch controlling: `try { let [a,b] = this.pair(); ... } catch (e) { ... }`
//                              and the bare-statement form `try { this.pair(); ... } catch { ... }`.
//
// `this.f()` is an EXTERNAL message call, so the CALLER must be NON-pure (a @pure caller is rejected by
// solc and stays rejected by JETH). A @view/@pure callee -> STATICCALL; a mutating callee -> CALL.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

function jethRejects(src: string): string[] | null {
  try {
    compile(src, { fileName: 'C.jeth' });
    return null;
  } catch (e: any) {
    return (e?.diagnostics ?? []).map((d: any) => d.code);
  }
}

// Deploy a JETH source and a solc source, run each (sig, args) against both, assert {success, returnHex}
// are byte-identical for every call.
async function expectByteIdentical(
  jeth: string,
  sol: string,
  calls: [string, string][],
): Promise<void> {
  const cj = compile(jeth, { fileName: 'C.jeth' }).creationBytecode;
  const cs = compileSolidity(SPDX + sol, 'C').creation;
  const h = await Harness.create();
  const aj = await h.deploy(cj);
  const as = await h.deploy(cs);
  for (const [sig, args] of calls) {
    const data = '0x' + sel(sig) + (args || '');
    const rj = await h.call(aj, data, {});
    const rs = await h.call(as, data, {});
    expect({ sig, success: rj.success, ret: rj.returnHex }).toEqual({ sig, success: rs.success, ret: rs.returnHex });
  }
}

describe('external self-call tuple forms (this.f())', () => {
  it('(a) DIRECT tuple return: 2-tuple u256, @view callee -> staticcall', async () => {
    await expectByteIdentical(
      `@contract class C {
        @external @view pair(): [u256, u256] { return [11n, 22n]; }
        @external @view getDirect(): [u256, u256] { return this.pair(); }
      }`,
      `contract C {
        function pair() external view returns (uint256, uint256) { return (11, 22); }
        function getDirect() external view returns (uint256, uint256) { return this.pair(); }
      }`,
      [['getDirect()', '']],
    );
  });

  it('(a) DIRECT tuple return: 3-tuple mixed (address,u256,bool)', async () => {
    await expectByteIdentical(
      `@contract class C {
        @external @view trip(): [address, u256, bool] { return [address(0xAAn), 42n, true]; }
        @external @view get3(): [address, u256, bool] { return this.trip(); }
      }`,
      `contract C {
        function trip() external view returns (address, uint256, bool) { return (address(0xAA), 42, true); }
        function get3() external view returns (address, uint256, bool) { return this.trip(); }
      }`,
      [['get3()', '']],
    );
  });

  it('(a) DIRECT tuple return: mutating callee -> CALL (state mutation observed)', async () => {
    await expectByteIdentical(
      `@contract class C {
        @state x: u256;
        @external bump(): [u256, u256] { this.x = this.x + 1n; return [this.x, this.x * 2n]; }
        @external caller(): [u256, u256] { return this.bump(); }
      }`,
      `contract C {
        uint256 x;
        function bump() external returns (uint256, uint256) { x = x + 1; return (x, x * 2); }
        function caller() external returns (uint256, uint256) { return this.bump(); }
      }`,
      [['caller()', ''], ['caller()', '']],
    );
  });

  it('(a) DIRECT tuple return: dynamic component (u256, bytes)', async () => {
    await expectByteIdentical(
      `@contract class C {
        @external @view pb(): [u256, bytes] { return [9n, "hello"]; }
        @external @view get(): [u256, bytes] { return this.pb(); }
      }`,
      `contract C {
        function pb() external view returns (uint256, bytes memory) { return (9, "hello"); }
        function get() external view returns (uint256, bytes memory) { return this.pb(); }
      }`,
      [['get()', '']],
    );
  });

  it('(b) TUPLE-ASSIGN: 2-tuple u256', async () => {
    await expectByteIdentical(
      `@contract class C {
        @external @view pair(): [u256, u256] { return [3n, 4n]; }
        @external getAssign(): u256 { let a: u256 = 0n; let b: u256 = 0n; [a, b] = this.pair(); return a * 100n + b; }
      }`,
      `contract C {
        function pair() external view returns (uint256, uint256) { return (3, 4); }
        function getAssign() external returns (uint256) { uint256 a; uint256 b; (a, b) = this.pair(); return a * 100 + b; }
      }`,
      [['getAssign()', '']],
    );
  });

  it('(b) TUPLE-ASSIGN: 3-tuple mixed (address,u256,bool)', async () => {
    await expectByteIdentical(
      `@contract class C {
        @external @view trip(): [address, u256, bool] { return [address(0xBBn), 7n, false]; }
        @external go(): u256 {
          let a: address = address(0n); let n: u256 = 0n; let f: bool = true;
          [a, n, f] = this.trip();
          return n + (f ? 1n : 0n);
        }
      }`,
      `contract C {
        function trip() external view returns (address, uint256, bool) { return (address(0xBB), 7, false); }
        function go() external returns (uint256) {
          address a; uint256 n; bool f;
          (a, n, f) = this.trip();
          return n + (f ? 1 : 0);
        }
      }`,
      [['go()', '']],
    );
  });

  it('(b) TUPLE-ASSIGN: mutating callee -> CALL', async () => {
    await expectByteIdentical(
      `@contract class C {
        @state x: u256;
        @external bump(): [u256, u256] { this.x = this.x + 1n; return [this.x, this.x * 2n]; }
        @external caller(): u256 { let a: u256 = 0n; let b: u256 = 0n; [a, b] = this.bump(); return a + b; }
      }`,
      `contract C {
        uint256 x;
        function bump() external returns (uint256, uint256) { x = x + 1; return (x, x * 2); }
        function caller() external returns (uint256) { uint256 a; uint256 b; (a, b) = this.bump(); return a + b; }
      }`,
      [['caller()', ''], ['caller()', '']],
    );
  });

  it('(c) try/catch: bare controlling statement, success path', async () => {
    await expectByteIdentical(
      `@contract class C {
        @external @view pair(): [u256, u256] { return [1n, 2n]; }
        @external tryIt(): u256 { try { this.pair(); return 7n; } catch (e) { return 9n; } }
      }`,
      `contract C {
        function pair() external view returns (uint256, uint256) { return (1, 2); }
        function tryIt() external returns (uint256) {
          try this.pair() returns (uint256, uint256) { return 7; } catch (bytes memory e) { return 9; }
        }
      }`,
      [['tryIt()', '']],
    );
  });

  it('(c) try/catch: tuple binding + revert bubble to catch', async () => {
    await expectByteIdentical(
      `@contract class C {
        @external @view pair(x: u256): [u256, u256] { if (x == 0n) { revert("bad"); } return [x, x + 1n]; }
        @external tryIt(x: u256): u256 {
          try { let [a, b] = this.pair(x); return a + b; } catch (e) { return 999n; }
        }
      }`,
      `contract C {
        function pair(uint256 x) external view returns (uint256, uint256) { if (x == 0) revert("bad"); return (x, x + 1); }
        function tryIt(uint256 x) external returns (uint256) {
          try this.pair(x) returns (uint256 a, uint256 b) { return a + b; } catch (bytes memory e) { return 999; }
        }
      }`,
      [['tryIt(uint256)', W(5n)], ['tryIt(uint256)', W(0n)]],
    );
  });

  it('(c) try/catch: this.reason recovers the revert string', async () => {
    await expectByteIdentical(
      `@contract class C {
        @external @view pair(x: u256): [u256, u256] { if (x == 0n) { revert("bad"); } return [x, x + 1n]; }
        @external tryIt(x: u256): string {
          try { let [a, b] = this.pair(x); return "ok"; } catch (e) { return this.reason; }
        }
      }`,
      `contract C {
        function pair(uint256 x) external view returns (uint256, uint256) { if (x == 0) revert("bad"); return (x, x + 1); }
        function tryIt(uint256 x) external returns (string memory) {
          try this.pair(x) returns (uint256 a, uint256 b) { return "ok"; } catch Error(string memory reason) { return reason; } catch { return "other"; }
        }
      }`,
      [['tryIt(uint256)', W(5n)], ['tryIt(uint256)', W(0n)]],
    );
  });

  it('(c) try/catch: this.panic recovers a Panic code (div-by-zero in callee)', async () => {
    await expectByteIdentical(
      `@contract class C {
        @external @view pair(d: u256): [u256, u256] { return [100n / d, 5n]; }
        @external run(d: u256): u256 {
          try { let [a, b] = this.pair(d); return a + b; } catch (e) { return this.panic; }
        }
      }`,
      `contract C {
        function pair(uint256 d) external view returns (uint256, uint256) { return (100 / d, 5); }
        function run(uint256 d) external returns (uint256) {
          try this.pair(d) returns (uint256 a, uint256 b) { return a + b; } catch Panic(uint256 p) { return p; } catch { return 0; }
        }
      }`,
      [['run(uint256)', W(4n)], ['run(uint256)', W(0n)]],
    );
  });

  it('(c) try/catch: 3-tuple mutating callee + bubble', async () => {
    await expectByteIdentical(
      `@contract class C {
        @state x: u256;
        @external trip(k: u256): [address, u256, bool] {
          if (k == 0n) { revert("zero"); }
          this.x = this.x + k;
          return [address(0xCCn), this.x, true];
        }
        @external run(k: u256): u256 {
          try { let [a, n, f] = this.trip(k); return n + (f ? 10n : 0n); } catch (e) { return 12345n; }
        }
      }`,
      `contract C {
        uint256 x;
        function trip(uint256 k) external returns (address, uint256, bool) {
          if (k == 0) revert("zero");
          x = x + k;
          return (address(0xCC), x, true);
        }
        function run(uint256 k) external returns (uint256) {
          try this.trip(k) returns (address a, uint256 n, bool f) { return n + (f ? 10 : 0); } catch (bytes memory e) { return 12345; }
        }
      }`,
      [['run(uint256)', W(3n)], ['run(uint256)', W(0n)]],
    );
  });

  // ---- soundness: forms that MUST stay clean rejects (solc also rejects, or a precise diagnostic) ----

  it('a @pure caller making this.f() is rejected (external call reads env/state)', () => {
    const codes = jethRejects(`@contract class C {
      @external @view pair(): [u256, u256] { return [1n, 2n]; }
      @external @pure bad(): [u256, u256] { return this.pair(); }
    }`);
    expect(codes).not.toBeNull();
    // solc rejects the same source (pure cannot make an external call).
    expect(() => compileSolidity(SPDX + `contract C {
      function pair() external view returns (uint256, uint256) { return (1, 2); }
      function bad() external pure returns (uint256, uint256) { return this.pair(); }
    }`, 'C')).toThrow();
  });

  it('arity / single-value / void misuse give a precise JETH356 diagnostic', () => {
    expect(jethRejects(`@contract class C {
      @external @view pair(): [u256,u256] { return [1n,2n]; }
      @external go(): u256 { let a:u256=0n; let b:u256=0n; let c:u256=0n; [a,b,c]=this.pair(); return a; }
    }`)).toContain('JETH356');
    expect(jethRejects(`@contract class C {
      @external @view one(): u256 { return 1n; }
      @external go(): u256 { let a:u256=0n; let b:u256=0n; [a,b]=this.one(); return a; }
    }`)).toContain('JETH356');
    expect(jethRejects(`@contract class C {
      @external doit(): void { }
      @external go(): [u256,u256] { return this.doit(); }
    }`)).toContain('JETH356');
  });

  it('internal (non-external) tuple fns still route through the internal-call path', () => {
    expect(jethRejects(`@contract class C {
      pair(): [u256,u256] { return [1n,2n]; }
      @external @view get(): [u256,u256] { return this.pair(); }
    }`)).toBeNull();
    expect(jethRejects(`@contract class C {
      pair(): [u256,u256] { return [1n,2n]; }
      @external go(): u256 { let a:u256=0n; let b:u256=0n; [a,b]=this.pair(); return a+b; }
    }`)).toBeNull();
  });
});
