// Feature 2: try/catch around a high-level typed interface call. Differential tests vs solc 0.8.35.
//
// A JETH caller (`try { let r = IFoo(addr).m(args); ... } catch (e) { ... }`) and a solc caller
// (`try IFoo(addr).m(args) returns (T r) { ... } catch (bytes memory e) { ... }`) are deployed
// against the SAME behaviour target (the SAME solc bytecode in both harnesses, so a successful or
// reverting call's returndata is byte-identical). The callers are invoked with identical calldata
// (the target's harness address as the first arg) and success + returndata are diffed.
//
// CRITICAL solc control flow (all verified byte-identical here):
//  - a failed call (callee reverted) -> the CATCH body runs, with e = the verbatim returndata bytes;
//  - a NON-CONTRACT / EOA target -> the codeGuard makes the WHOLE try/catch REVERT EMPTY (not catch);
//  - a contract returning TOO FEW bytes to decode the declared return -> OUTER revert empty (not catch);
//  - this.reason  == solc's `catch Error(string r)` (SOFT decode, "" on a malformed Error payload);
//  - this.panic   == solc's `catch Panic(uint c)`  (SOFT decode, 0 on a non-Panic payload).
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

// The interface, identical shape in JETH and solc.
const IFACE_JETH = `@interface class IFoo {
  @external echo(x: u256): u256;
  @external @view view2(x: u256): u256;
  @external boom(): u256;
  @external custom(): u256;
  @external panicDiv(x: u256): u256;
  @external panicAssert(): u256;
  @external reqFalse(): u256;
  @external setX(x: u256): void;
  @external @view pair(): [u256, string];
  @external @view str(): string;
}`;
const IFACE_SOL = `interface IFoo {
  function echo(uint256) external returns(uint256);
  function view2(uint256) external view returns(uint256);
  function boom() external returns(uint256);
  function custom() external returns(uint256);
  function panicDiv(uint256) external returns(uint256);
  function panicAssert() external returns(uint256);
  function reqFalse() external returns(uint256);
  function setX(uint256) external;
  function pair() external view returns(uint256, string memory);
  function str() external view returns(string memory);
}`;

// The behaviour target. SAME solc source deployed in both harnesses (byte-identical bytecode).
const TARGET_SOL = `contract T {
  uint256 public stored;
  error MyErr(uint256 a);
  function echo(uint256 x) external pure returns(uint256){ return x * 2; }
  function view2(uint256 x) external view returns(uint256){ return x + uint256(uint160(address(this))) - uint256(uint160(address(this))); }
  function boom() external pure returns(uint256){ revert("kaboom"); }
  function custom() external pure returns(uint256){ revert MyErr(7); }
  function panicDiv(uint256 x) external pure returns(uint256){ return uint256(100) / x; }
  function panicAssert() external pure returns(uint256){ assert(false); return 0; }
  function reqFalse() external pure returns(uint256){ require(false); return 0; }
  function setX(uint256 x) external { stored = x; }
  function pair() external pure returns(uint256, string memory){ return (42, "hello world here"); }
  function str() external pure returns(string memory){ return "a string value"; }
}`;

/** Deploy the SAME (solc) target bytecode in both harnesses + a JETH and solc caller; diff results.
 *  The caller is invoked with the target's address as the first 32-byte arg. */
async function rt(callerJeth: string, callerSol: string, calls: { sig: string; noTarget?: boolean }[]) {
  const tsb = compileSolidity(SPDX + TARGET_SOL, 'T');
  const cjb = compile(callerJeth, { fileName: 'C.jeth' });
  const csb = compileSolidity(SPDX + callerSol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const cj = await hj.deploy(cjb.creationBytecode);
  const cs = await hs.deploy(csb.creation);
  for (const c of calls) {
    let aj: bigint, as: bigint;
    if (c.noTarget) {
      aj = 0x00000000000000000000000000000000deadbeefn;
      as = aj;
    } else {
      const tj = await hj.deploy(tsb.creation);
      const ts = await hs.deploy(tsb.creation);
      aj = BigInt(tj.toString());
      as = BigInt(ts.toString());
    }
    const dj = '0x' + sel(c.sig) + W(aj);
    const ds = '0x' + sel(c.sig) + W(as);
    const rj = await hj.call(cj, dj);
    const rs = await hs.call(cs, ds);
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig}: returndata`).toBe(rs.returnHex);
  }
}

describe('try/catch core (stage 2a): byte-identical vs solc', () => {
  it('success: a value-returning controlling call, r used in the try body', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).echo(21n); return r; } catch (e) { return 999n; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(uint256){ try IFoo(t).echo(21) returns(uint256 r){ return r; } catch (bytes memory e){ return 999; } } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('failure -> catch: e = the verbatim Error(string) returndata', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): bytes { try { let r: u256 = IFoo(t).boom(); return ""; } catch (e) { return e; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(bytes memory){ try IFoo(t).boom() returns(uint256 r){ return ""; } catch (bytes memory e){ return e; } } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('failure -> catch: e = the verbatim custom-error returndata', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): bytes { try { let r: u256 = IFoo(t).custom(); return ""; } catch (e) { return e; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(bytes memory){ try IFoo(t).custom() returns(uint256 r){ return ""; } catch (bytes memory e){ return e; } } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('failure -> catch: e = the verbatim Panic(assert) returndata', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): bytes { try { let r: u256 = IFoo(t).panicAssert(); return ""; } catch (e) { return e; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(bytes memory){ try IFoo(t).panicAssert() returns(uint256 r){ return ""; } catch (bytes memory e){ return e; } } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('failure -> catch: e = the verbatim Panic(div-by-zero) returndata', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): bytes { try { let r: u256 = IFoo(t).panicDiv(0n); return ""; } catch (e) { return e; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(bytes memory){ try IFoo(t).panicDiv(0) returns(uint256 r){ return ""; } catch (bytes memory e){ return e; } } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('failure -> catch: e = empty bytes for an empty revert (require(false))', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): bytes { try { let r: u256 = IFoo(t).reqFalse(); return ""; } catch (e) { return e; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(bytes memory){ try IFoo(t).reqFalse() returns(uint256 r){ return ""; } catch (bytes memory e){ return e; } } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('non-contract target -> the WHOLE try/catch reverts empty (does NOT enter catch)', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).echo(21n); return r; } catch (e) { return 999n; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(uint256){ try IFoo(t).echo(21) returns(uint256 r){ return r; } catch (bytes memory e){ return 999; } } }`,
      [{ sig: 'f(address)', noTarget: true }],
    );
  });

  it('void controlling call: the try body runs on success', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): u256 { try { IFoo(t).setX(5n); return 1n; } catch (e) { return 2n; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(uint256){ try IFoo(t).setX(5){ return 1; } catch (bytes memory e){ return 2; } } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('tuple return: [u256, string] decoded and bound in the try body', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external @view f(t: address): string { try { let [n, s]: [u256, string] = IFoo(t).pair(); return s; } catch (e) { return "fail"; } }
        @external @view g(t: address): u256 { try { let [n, s]: [u256, string] = IFoo(t).pair(); return n; } catch (e) { return 0n; } } }`,
      `${IFACE_SOL}
      contract C {
        function f(address t) external view returns(string memory){ try IFoo(t).pair() returns(uint256 n, string memory s){ return s; } catch (bytes memory e){ return "fail"; } }
        function g(address t) external view returns(uint256){ try IFoo(t).pair() returns(uint256 n, string memory s){ return n; } catch (bytes memory e){ return 0; } } }`,
      [{ sig: 'f(address)' }, { sig: 'g(address)' }],
    );
  });

  it('@view controlling call lowers to STATICCALL in a @view caller', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external @view f(t: address): u256 { try { let r: u256 = IFoo(t).view2(9n); return r; } catch (e) { return 1n; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external view returns(uint256){ try IFoo(t).view2(9) returns(uint256 r){ return r; } catch (bytes memory e){ return 1; } } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('catch with NO binding (`catch { }`) on a failing call', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).boom(); return r; } catch { return 5n; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(uint256){ try IFoo(t).boom() returns(uint256 r){ return r; } catch { return 5; } } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('catch (e) with e unused on a failing call', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).boom(); return r; } catch (e) { return 6n; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(uint256){ try IFoo(t).boom() returns(uint256 r){ return r; } catch (bytes memory e){ return 6; } } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('e.length is readable in the catch body', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).boom(); return r; } catch (e) { return e.length; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(uint256){ try IFoo(t).boom() returns(uint256 r){ return r; } catch (bytes memory e){ return e.length; } } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('nested try/catch: the inner catch handles the inner failure', async () => {
    await rt(
      `${IFACE_JETH}
      @contract class C { @external f(t: address): u256 {
        try { let a: u256 = IFoo(t).echo(1n);
          try { let b: u256 = IFoo(t).boom(); return b; } catch (e2) { return 100n; }
        } catch (e) { return 200n; } } }`,
      `${IFACE_SOL}
      contract C { function f(address t) external returns(uint256){
        try IFoo(t).echo(1) returns(uint256 a){
          try IFoo(t).boom() returns(uint256 b){ return b; } catch (bytes memory e2){ return 100; }
        } catch (bytes memory e){ return 200; } } }`,
      [{ sig: 'f(address)' }],
    );
  });
});

// A target whose value-returning method returns controlled-size returndata via raw assembly:
// 0 bytes / 31 bytes (both < head=32 -> the return decode reverts EMPTY = OUTER revert, NOT catch),
// and 64 bytes (> head -> decode succeeds, the trailing word ignored).
const RET_TARGET_SOL = `contract T {
  function zero() external pure returns(uint256){ assembly { return(0, 0) } }
  function short31() external pure returns(uint256){ assembly { mstore(0, 1) return(0, 31) } }
  function extra64() external pure returns(uint256){ assembly { mstore(0, 7) mstore(32, 99) return(0, 64) } }
}`;

describe('try/catch: return-decode bounds (byte-identical vs solc)', () => {
  async function rtRet(sig: string) {
    const tsb = compileSolidity(SPDX + RET_TARGET_SOL, 'T');
    const callerJeth = `@interface class IFoo { @external zero(): u256; @external short31(): u256; @external extra64(): u256; }
    @contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).${sig}(); return r; } catch (e) { return 777n; } } }`;
    const callerSol = `interface IFoo { function zero() external returns(uint256); function short31() external returns(uint256); function extra64() external returns(uint256); }
    contract C { function f(address t) external returns(uint256){ try IFoo(t).${sig}() returns(uint256 r){ return r; } catch (bytes memory e){ return 777; } } }`;
    const cjb = compile(callerJeth, { fileName: 'C.jeth' });
    const csb = compileSolidity(SPDX + callerSol, 'C');
    const hj = await Harness.create();
    const hs = await Harness.create();
    const tj = await hj.deploy(tsb.creation);
    const ts = await hs.deploy(tsb.creation);
    const cj = await hj.deploy(cjb.creationBytecode);
    const cs = await hs.deploy(csb.creation);
    const rj = await hj.call(cj, '0x' + sel('f(address)') + W(BigInt(tj.toString())));
    const rs = await hs.call(cs, '0x' + sel('f(address)') + W(BigInt(ts.toString())));
    expect(rj.success, `${sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${sig}: returndata`).toBe(rs.returnHex);
  }
  it('0-byte returndata < head -> OUTER revert empty (NOT catch)', async () => {
    await rtRet('zero');
  });
  it('31-byte returndata < head -> OUTER revert empty (NOT catch)', async () => {
    await rtRet('short31');
  });
  it('64-byte returndata > head -> decode, trailing word ignored', async () => {
    await rtRet('extra64');
  });
});

// A target whose `bad(mode)` reverts with arbitrary raw bytes (crafted via inline assembly). Deployed on
// BOTH harnesses (byte-identical bytecode) so the JETH and solc callers see identical malformed returndata.
const BAD_TARGET_SOL = `contract T {
  function bad(uint256 mode) external pure returns(uint256){
    if (mode == 0) { revert("a well formed error"); }
    if (mode == 1) { revert(string(new bytes(200))); }
    if (mode == 2) { assembly { mstore(0, shl(224, 0x08c379a0)) mstore(4, 0x11223344) revert(0, 8) } }
    if (mode == 3) { assembly { mstore(0, shl(224, 0x08c379a0)) mstore(4, not(0)) revert(0, 36) } }
    if (mode == 4) { assembly { mstore(0, shl(224, 0x08c379a0)) mstore(4, 0x20) mstore(36, 0x40) revert(0, 68) } }
    if (mode == 5) { assembly { mstore(0, shl(224, 0x4e487b71)) mstore(4, 0x12) revert(0, 36) } }
    if (mode == 6) { assembly { mstore(0, shl(224, 0x4e487b71)) mstore(4, 0x99) revert(0, 6) } }
    if (mode == 7) { assembly { revert(0, 0) } }
    if (mode == 8) { assembly { mstore(0, shl(224, 0xdeadbeef)) revert(0, 4) } }
    if (mode == 9) { assembly { mstore(0, shl(224, 0x08c379a0)) revert(0, 4) } }
    if (mode == 10) { assembly { mstore(0, shl(224, 0x08c379a0)) mstore(4, 0x20) mstore(36, 5) mstore(68, "hello") revert(0, 0x60) } }
    return 0;
  }
}`;

describe('try/catch helpers (stage 2b): this.reason / this.panic byte-identical vs solc', () => {
  // The JETH caller uses this.reason / this.panic; the solc caller uses the native catch Error/Panic forms.
  const CJ_REASON = `@interface class IFoo { @external bad(mode: u256): u256; }
  @contract class C { @external f(t: address, m: u256): string { try { let r: u256 = IFoo(t).bad(m); return ""; } catch (e) { return this.reason; } } }`;
  const CS_REASON = `interface IFoo { function bad(uint256) external returns(uint256); }
  contract C { function f(address t, uint256 m) external returns(string memory){ try IFoo(t).bad(m) returns(uint256 r){ return ""; } catch Error(string memory reason){ return reason; } catch { return ""; } } }`;
  const CJ_PANIC = `@interface class IFoo { @external bad(mode: u256): u256; }
  @contract class C { @external f(t: address, m: u256): u256 { try { let r: u256 = IFoo(t).bad(m); return 0n; } catch (e) { return this.panic; } } }`;
  const CS_PANIC = `interface IFoo { function bad(uint256) external returns(uint256); }
  contract C { function f(address t, uint256 m) external returns(uint256){ try IFoo(t).bad(m) returns(uint256 r){ return 0; } catch Panic(uint256 c){ return c; } catch { return 0; } } }`;

  async function rtBad(cj: string, cs: string) {
    const tsb = compileSolidity(SPDX + BAD_TARGET_SOL, 'T');
    const cjb = compile(cj, { fileName: 'C.jeth' });
    const csb = compileSolidity(SPDX + cs, 'C');
    const hj = await Harness.create();
    const hs = await Harness.create();
    const tj = await hj.deploy(tsb.creation);
    const ts = await hs.deploy(tsb.creation);
    const cj2 = await hj.deploy(cjb.creationBytecode);
    const cs2 = await hs.deploy(csb.creation);
    for (let m = 0n; m <= 10n; m++) {
      const dj = '0x' + sel('f(address,uint256)') + W(BigInt(tj.toString())) + W(m);
      const ds = '0x' + sel('f(address,uint256)') + W(BigInt(ts.toString())) + W(m);
      const rj = await hj.call(cj2, dj);
      const rs = await hs.call(cs2, ds);
      expect(rj.success, `mode ${m}: success`).toBe(rs.success);
      expect(rj.returnHex, `mode ${m}: returndata`).toBe(rs.returnHex);
    }
  }

  it('this.reason: all 11 payloads (valid / long / malformed Error / Panic / custom / empty)', async () => {
    await rtBad(CJ_REASON, CS_REASON);
  });
  it('this.panic: all 11 payloads (valid / short / non-Panic)', async () => {
    await rtBad(CJ_PANIC, CS_PANIC);
  });

  it('this.reason + this.panic used together == solc catch Panic / catch Error dispatch', async () => {
    const RT2 = `contract T {
      function boom() external pure returns(uint256){ revert("xy"); }
      function pdiv(uint256 x) external pure returns(uint256){ return 1/x; }
    }`;
    const ifj = `@interface class IFoo { @external boom(): u256; @external pdiv(x: u256): u256; }`;
    const ifs = `interface IFoo { function boom() external returns(uint256); function pdiv(uint256) external returns(uint256); }`;
    const cjShape = (target: string) =>
      `${ifj}\n@contract class C { @external f(t: address): string { try { let r: u256 = IFoo(t).${target}; return ""; } catch (e) { let p: u256 = this.panic; if (p != 0n) { return "panic"; } return this.reason; } } }`;
    const csShape = (target: string) =>
      `${ifs}\ncontract C { function f(address t) external returns(string memory){ try IFoo(t).${target} returns(uint256 r){ return ""; } catch Panic(uint256 p){ return "panic"; } catch Error(string memory s){ return s; } catch { return ""; } } }`;
    async function one(jt: string, st: string) {
      const tsb = compileSolidity(SPDX + RT2, 'T');
      const cjb = compile(cjShape(jt), { fileName: 'C.jeth' });
      const csb = compileSolidity(SPDX + csShape(st), 'C');
      const hj = await Harness.create();
      const hs = await Harness.create();
      const tj = await hj.deploy(tsb.creation);
      const ts = await hs.deploy(tsb.creation);
      const cj = await hj.deploy(cjb.creationBytecode);
      const cs = await hs.deploy(csb.creation);
      const rj = await hj.call(cj, '0x' + sel('f(address)') + W(BigInt(tj.toString())));
      const rs = await hs.call(cs, '0x' + sel('f(address)') + W(BigInt(ts.toString())));
      expect(rj.success).toBe(rs.success);
      expect(rj.returnHex).toBe(rs.returnHex);
    }
    await one('boom()', 'boom()'); // Error -> this.reason
    await one('pdiv(0n)', 'pdiv(0)'); // Panic -> "panic"
  });
});

describe('try/catch: clean rejections (no crash)', () => {
  const IF = `@interface class IFoo { @external bar(x: u256): u256; @external @view pair(): [u256, string]; @external nada(): void; }`;
  it('rejects this.reason outside a catch', () => {
    expect(jethRejects(`@contract class C { @external f(): string { return this.reason; } }`)).toBe(true);
  });
  it('rejects this.panic outside a catch', () => {
    expect(jethRejects(`@contract class C { @external f(): u256 { return this.panic; } }`)).toBe(true);
  });
  it('rejects this.reason inside the try body (not the catch)', () => {
    expect(
      jethRejects(
        `${IF}\n@contract class C { @external f(t: address): string { try { let r: u256 = IFoo(t).bar(1n); return this.reason; } catch (e) { return ""; } } }`,
      ),
    ).toBe(true);
  });
  it('rejects a finally clause', () => {
    expect(
      jethRejects(
        `${IF}\n@contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).bar(1n); return r; } catch (e) { return 0n; } finally { } } }`,
      ),
    ).toBe(true);
  });
  it('rejects a try with no catch', () => {
    expect(
      jethRejects(
        `${IF}\n@contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).bar(1n); return r; } finally { } } }`,
      ),
    ).toBe(true);
  });
  it('rejects a first statement that is not an interface call', () => {
    expect(
      jethRejects(
        `${IF}\n@contract class C { @external f(t: address): u256 { try { let r: u256 = 5n; return r; } catch (e) { return 0n; } } }`,
      ),
    ).toBe(true);
  });
  it('rejects a first statement that is an internal call', () => {
    // An INTERNAL `this.g()` (no @external) is an in-frame call, not a message call, so it is not a
    // valid controlling try expression. (An @external `this.g()` self-call IS a valid controlling
    // try expression - it is a message call - covered in selfcall-tuples.test.ts.)
    expect(
      jethRejects(
        `${IF}\n@contract class C { g(): u256 { return 1n; } @external f(t: address): u256 { try { let r: u256 = this.g(); return r; } catch (e) { return 0n; } } }`,
      ),
    ).toBe(true);
  });
  it('rejects a void method bound to a name', () => {
    expect(
      jethRejects(
        `${IF}\n@contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).nada(); return r; } catch (e) { return 0n; } } }`,
      ),
    ).toBe(true);
  });
  it('rejects a tuple method bound to a single name', () => {
    expect(
      jethRejects(
        `${IF}\n@contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).pair(); return r; } catch (e) { return 0n; } } }`,
      ),
    ).toBe(true);
  });
  it('rejects a catch binding annotated as a non-bytes type', () => {
    expect(
      jethRejects(
        `${IF}\n@contract class C { @external f(t: address): u256 { try { let r: u256 = IFoo(t).bar(1n); return r; } catch (e: u256) { return 0n; } } }`,
      ),
    ).toBe(true);
  });
  it('rejects an empty try block', () => {
    expect(
      jethRejects(`${IF}\n@contract class C { @external f(t: address): u256 { try { } catch (e) { return 0n; } } }`),
    ).toBe(true);
  });
  it('rejects a return-type annotation that mismatches the method return', () => {
    expect(
      jethRejects(
        `${IF}\n@contract class C { @external f(t: address): bool { try { let r: bool = IFoo(t).bar(1n); return r; } catch (e) { return false; } } }`,
      ),
    ).toBe(true);
  });
});
