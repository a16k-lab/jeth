// Phase 6: external low-level calls (addr.call / staticcall / tryCall / tryStaticcall / code /
// codehash / revertWith). Differential tests vs solc 0.8.35: a JETH caller + a JETH target and a
// solc caller + a solc target are deployed, the caller is invoked, and success + returndata + logs
// are diffed. For the success-path byte-identity the JETH and solc TARGETS must behave identically
// (same returndata), which they do (echo/boom/pay are trivial and match). For code/codehash the SAME
// target bytecode is deployed in both harnesses (so EXTCODE* sees identical code).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

function jethAccepts(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return true;
  } catch {
    return false;
  }
}
function jethRejects(src: string): boolean {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
}

// A shared target: echo doubles, boom reverts a string, pay returns the received value, big returns a
// 64-byte payload. Identical behaviour in JETH and solc, so a successful call's returndata matches.
const TARGET_JETH = `class T {
  get echo(x: u256): External<u256> { return x * 2n; }
  get boom(): External<u256> { revert("kaboom"); }
  pay(): Payable<u256> { return msg.value; }
}`;
const TARGET_SOL = `contract T {
  function echo(uint256 x) external view returns(uint256){ return x * 2; }
  function boom() external pure returns(uint256){ revert("kaboom"); }
  function pay() external payable returns(uint256){ return msg.value; }
}`;

/** Deploy a JETH caller + the JETH target and a solc caller + the solc target, then for each call
 *  invoke the caller (with the target's address as the first 32-byte arg, plus extraArgs) and diff
 *  success + returndata + logs. `value` is forwarded to the caller. */
async function rtCall(
  callerJeth: string,
  callerSol: string,
  calls: { sig: string; extraArgs?: string; value?: bigint }[],
) {
  const tjb = compile(TARGET_JETH, { fileName: 'T.jeth' });
  const tsb = compileSolidity(SPDX + TARGET_SOL, 'T');
  const cjb = compile(callerJeth, { fileName: 'C.jeth' });
  const csb = compileSolidity(SPDX + callerSol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const tj = await hj.deploy(tjb.creationBytecode);
  const ts = await hs.deploy(tsb.creation);
  const cj = await hj.deploy(cjb.creationBytecode);
  const cs = await hs.deploy(csb.creation);
  for (const c of calls) {
    const dj = '0x' + sel(c.sig) + W(BigInt(tj.toString())) + (c.extraArgs ?? '');
    const ds = '0x' + sel(c.sig) + W(BigInt(ts.toString())) + (c.extraArgs ?? '');
    const rj = await hj.call(cj, dj, { value: c.value });
    const rs = await hs.call(cs, ds, { value: c.value });
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig}: returndata`).toBe(rs.returnHex);
    expect(JSON.stringify(rj.logs), `${c.sig}: logs`).toBe(JSON.stringify(rs.logs));
  }
}

/** Deploy the SAME (solc) target bytecode in both harnesses (so its deployed code is byte-identical),
 *  plus a JETH and a solc caller; diff the caller results. Used for code/codehash. */
async function rtSameTarget(
  targetSol: string,
  callerJeth: string,
  callerSol: string,
  calls: { sig: string; extraArgs?: string }[],
) {
  const tsb = compileSolidity(SPDX + targetSol, 'T');
  const cjb = compile(callerJeth, { fileName: 'C.jeth' });
  const csb = compileSolidity(SPDX + callerSol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const tj = await hj.deploy(tsb.creation);
  const ts = await hs.deploy(tsb.creation);
  const cj = await hj.deploy(cjb.creationBytecode);
  const cs = await hs.deploy(csb.creation);
  for (const c of calls) {
    const dj = '0x' + sel(c.sig) + W(BigInt(tj.toString())) + (c.extraArgs ?? '');
    const ds = '0x' + sel(c.sig) + W(BigInt(ts.toString())) + (c.extraArgs ?? '');
    const rj = await hj.call(cj, dj);
    const rs = await hs.call(cs, ds);
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig}: returndata`).toBe(rs.returnHex);
  }
}

describe('external low-level calls: byte-identical vs solc', () => {
  it('step 1: tryCall -> [bool, bytes] (raw, no checks), ok+returndata identical', async () => {
    await rtCall(
      `class C {
        tok(t: address): External<bool> {
          let d: bytes = abi.encodeWithSignature("echo(uint256)", 5n);
          let [ok, ret]: [bool, bytes] = t.tryCall({ data: d });
          return ok;
        }
        tfail(t: address): External<bool> {
          let d: bytes = abi.encodeWithSignature("boom()");
          let [ok, ret]: [bool, bytes] = t.tryCall({ data: d });
          return ok;
        }
        tret(t: address): External<bytes> {
          let d: bytes = abi.encodeWithSignature("echo(uint256)", 5n);
          let [ok, ret]: [bool, bytes] = t.tryCall({ data: d });
          return ret;
        }
      }`,
      `contract C {
        function tok(address t) external returns(bool){
          bytes memory d = abi.encodeWithSignature("echo(uint256)", uint256(5));
          (bool ok, bytes memory ret) = t.call(d); ret;
          return ok;
        }
        function tfail(address t) external returns(bool){
          bytes memory d = abi.encodeWithSignature("boom()");
          (bool ok, bytes memory ret) = t.call(d); ret;
          return ok;
        }
        function tret(address t) external returns(bytes memory){
          bytes memory d = abi.encodeWithSignature("echo(uint256)", uint256(5));
          (bool ok, bytes memory ret) = t.call(d);
          return ret;
        }
      }`,
      [{ sig: 'tok(address)' }, { sig: 'tfail(address)' }, { sig: 'tret(address)' }],
    );
  });

  it('step 2: call with a string-literal success revert (success path + Error(string) failure)', async () => {
    await rtCall(
      `class C {
        ok(t: address): External<bytes> {
          let d: bytes = abi.encodeWithSignature("echo(uint256)", 7n);
          return t.call({ data: d, success: { condition: this.ok, revert: "callfail" } });
        }
        fail(t: address): External<bytes> {
          let d: bytes = abi.encodeWithSignature("boom()");
          return t.call({ data: d, success: { condition: this.ok, revert: "callfail" } });
        }
      }`,
      `contract C {
        function ok(address t) external returns(bytes memory){
          bytes memory d = abi.encodeWithSignature("echo(uint256)", uint256(7));
          (bool ok_, bytes memory ret) = t.call(d);
          if (!(ok_)) revert("callfail");
          return ret;
        }
        function fail(address t) external returns(bytes memory){
          bytes memory d = abi.encodeWithSignature("boom()");
          (bool ok_, bytes memory ret) = t.call(d);
          if (!(ok_)) revert("callfail");
          return ret;
        }
      }`,
      [{ sig: 'ok(address)' }, { sig: 'fail(address)' }],
    );
  });

  it('step 3a: custom-error success revert', async () => {
    await rtCall(
      `class C {
        Failed: error<{ code: u256 }>;
        f(t: address): External<bytes> {
          let d: bytes = abi.encodeWithSignature("boom()");
          return t.call({ data: d, success: { condition: this.ok, revert: Failed(99n) } });
        }
      }`,
      `contract C {
        error Failed(uint256 code);
        function f(address t) external returns(bytes memory){
          bytes memory d = abi.encodeWithSignature("boom()");
          (bool ok_, bytes memory ret) = t.call(d);
          if (!(ok_)) revert Failed(99);
          return ret;
        }
      }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('step 3b: array of ordered checks - first failing check wins (this.ok + this.data.length)', async () => {
    await rtCall(
      `class C {
        okfirst(t: address): External<bytes> {
          let d: bytes = abi.encodeWithSignature("echo(uint256)", 3n);
          return t.call({ data: d, success: [
            { condition: this.ok, revert: "first" },
            { condition: this.data.length > 100n, revert: "second" }
          ] });
        }
        failfirst(t: address): External<bytes> {
          let d: bytes = abi.encodeWithSignature("echo(uint256)", 3n);
          return t.call({ data: d, success: [
            { condition: this.data.length > 100n, revert: "early" },
            { condition: this.ok, revert: "late" }
          ] });
        }
        allpass(t: address): External<bytes> {
          let d: bytes = abi.encodeWithSignature("echo(uint256)", 3n);
          return t.call({ data: d, success: [
            { condition: this.ok, revert: "a" },
            { condition: this.data.length == 32n, revert: "b" }
          ] });
        }
      }`,
      `contract C {
        function okfirst(address t) external returns(bytes memory){
          bytes memory d = abi.encodeWithSignature("echo(uint256)", uint256(3));
          (bool ok_, bytes memory ret) = t.call(d);
          if (!(ok_)) revert("first");
          if (!(ret.length > 100)) revert("second");
          return ret;
        }
        function failfirst(address t) external returns(bytes memory){
          bytes memory d = abi.encodeWithSignature("echo(uint256)", uint256(3));
          (bool ok_, bytes memory ret) = t.call(d);
          if (!(ret.length > 100)) revert("early");
          if (!(ok_)) revert("late");
          return ret;
        }
        function allpass(address t) external returns(bytes memory){
          bytes memory d = abi.encodeWithSignature("echo(uint256)", uint256(3));
          (bool ok_, bytes memory ret) = t.call(d);
          if (!(ok_)) revert("a");
          if (!(ret.length == 32)) revert("b");
          return ret;
        }
      }`,
      [{ sig: 'okfirst(address)' }, { sig: 'failfirst(address)' }, { sig: 'allpass(address)' }],
    );
  });

  it('step 4: value + gas options', async () => {
    await rtCall(
      `class C {
        cv(t: address): Payable<bytes> {
          let d: bytes = abi.encodeWithSignature("pay()");
          return t.call({ data: d, value: msg.value, success: { condition: this.ok, revert: "vfail" } });
        }
        cg(t: address): External<bytes> {
          let d: bytes = abi.encodeWithSignature("echo(uint256)", 11n);
          return t.call({ data: d, gas: 100000n, success: { condition: this.ok, revert: "gfail" } });
        }
      }`,
      `contract C {
        function cv(address t) external payable returns(bytes memory){
          bytes memory d = abi.encodeWithSignature("pay()");
          (bool ok_, bytes memory ret) = t.call{value: msg.value}(d);
          if (!(ok_)) revert("vfail");
          return ret;
        }
        function cg(address t) external returns(bytes memory){
          bytes memory d = abi.encodeWithSignature("echo(uint256)", uint256(11));
          (bool ok_, bytes memory ret) = t.call{gas: 100000}(d);
          if (!(ok_)) revert("gfail");
          return ret;
        }
      }`,
      [{ sig: 'cv(address)', value: 555n }, { sig: 'cg(address)' }],
    );
  });

  it('step 5: staticcall + tryStaticcall (STATICCALL, no value)', async () => {
    await rtCall(
      `class C {
        get sok(t: address, x: u256): External<bytes> {
          let d: bytes = abi.encodeWithSignature("echo(uint256)", x);
          return t.staticcall({ data: d, success: { condition: this.ok, revert: "sfail" } });
        }
        get stok(t: address): External<bool> {
          let d: bytes = abi.encodeWithSignature("echo(uint256)", 4n);
          let [ok, ret]: [bool, bytes] = t.tryStaticcall({ data: d });
          return ok;
        }
        get stfail(t: address): External<bool> {
          let d: bytes = abi.encodeWithSignature("boom()");
          let [ok, ret]: [bool, bytes] = t.tryStaticcall({ data: d });
          return ok;
        }
      }`,
      `contract C {
        function sok(address t, uint256 x) external view returns(bytes memory){
          bytes memory d = abi.encodeWithSignature("echo(uint256)", x);
          (bool ok_, bytes memory ret) = t.staticcall(d);
          if (!(ok_)) revert("sfail");
          return ret;
        }
        function stok(address t) external view returns(bool){
          bytes memory d = abi.encodeWithSignature("echo(uint256)", uint256(4));
          (bool ok_, bytes memory ret) = t.staticcall(d); ret;
          return ok_;
        }
        function stfail(address t) external view returns(bool){
          bytes memory d = abi.encodeWithSignature("boom()");
          (bool ok_, bytes memory ret) = t.staticcall(d); ret;
          return ok_;
        }
      }`,
      [{ sig: 'sok(address,uint256)', extraArgs: W(20n) }, { sig: 'stok(address)' }, { sig: 'stfail(address)' }],
    );
  });

  it('step 6a: addr.code / addr.codehash (same deployed target on both sides)', async () => {
    await rtSameTarget(
      `contract T { uint256 public x; function set(uint256 v) external { x = v; } }`,
      `class C {
        get cc(t: address): External<bytes> { return t.code; }
        get ch(t: address): External<bytes32> { return t.codehash; }
      }`,
      `contract C {
        function cc(address t) external view returns(bytes memory){ return t.code; }
        function ch(address t) external view returns(bytes32){ return t.codehash; }
      }`,
      [{ sig: 'cc(address)' }, { sig: 'ch(address)' }],
    );
  });

  it('step 6b: revertWith(bytes) bubbles the callee raw reason (= assembly revert(add(b,0x20),mload(b)))', async () => {
    await rtCall(
      `class C {
        bub(t: address): External<bytes> {
          let d: bytes = abi.encodeWithSignature("boom()");
          let [ok, ret]: [bool, bytes] = t.tryCall({ data: d });
          if (!ok) { revertWith(ret); }
          return ret;
        }
      }`,
      `contract C {
        function bub(address t) external returns(bytes memory){
          bytes memory d = abi.encodeWithSignature("boom()");
          (bool ok_, bytes memory ret) = t.call(d);
          if (!ok_) { assembly { revert(add(ret, 0x20), mload(ret)) } }
          return ret;
        }
      }`,
      [{ sig: 'bub(address)' }],
    );
  });
});

describe('external low-level calls: accept / reject parity', () => {
  it('accepts the supported forms', () => {
    expect(
      jethAccepts(
        `class C { f(t: address, d: bytes): External<bytes> { let [ok, r]: [bool, bytes] = t.tryCall({ data: d }); return r; } }`,
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        `class C { f(t: address, d: bytes): External<bytes> { return t.call({ data: d, success: { condition: this.ok, revert: "x" } }); } }`,
      ),
    ).toBe(true);
    expect(
      jethAccepts(
        `class C { get f(t: address, d: bytes): External<bytes> { return t.staticcall({ data: d, success: { condition: this.ok, revert: "x" } }); } }`,
      ),
    ).toBe(true);
    expect(jethAccepts(`class C { get f(t: address): External<bytes> { return t.code; } }`)).toBe(true);
    expect(jethAccepts(`class C { get f(t: address): External<bytes32> { return t.codehash; } }`)).toBe(
      true,
    );
    expect(
      jethAccepts(
        `class C { f(t: address, d: bytes): External<void> { let [ok, r]: [bool, bytes] = t.tryCall({ data: d }); if (!ok) { revertWith(r); } } }`,
      ),
    ).toBe(true);
  });

  it('rejects unsound / malformed forms (mirrors solc structural rules)', () => {
    // staticcall cannot send value
    expect(
      jethRejects(
        `class C { get f(t: address, d: bytes): External<bytes> { return t.staticcall({ data: d, value: 1n, success: { condition: this.ok, revert: "x" } }); } }`,
      ),
    ).toBe(true);
    // call requires a mandatory success field
    expect(
      jethRejects(`class C { get f(t: address, d: bytes): External<bytes> { return t.call({ data: d }); } }`),
    ).toBe(true);
    // tryCall takes no success field
    expect(
      jethRejects(
        `class C { get f(t: address, d: bytes): External<bytes> { let [ok, r]: [bool, bytes] = t.tryCall({ data: d, success: { condition: this.ok, revert: "x" } }); return r; } }`,
      ),
    ).toBe(true);
    // data is required
    expect(
      jethRejects(
        `class C { get f(t: address): External<bytes> { return t.call({ success: { condition: this.ok, revert: "x" } }); } }`,
      ),
    ).toBe(true);
    // unknown option
    expect(
      jethRejects(
        `class C { get f(t: address, d: bytes): External<bytes> { return t.call({ data: d, bogus: 1n, success: { condition: this.ok, revert: "x" } }); } }`,
      ),
    ).toBe(true);
    // a state-mutating call cannot be @view
    expect(
      jethRejects(
        `@contract class C { @external @view f(t: address, d: bytes): bytes { return t.call({ data: d, success: { condition: this.ok, revert: "x" } }); } }`,
      ),
    ).toBe(true);
    // a state-mutating call cannot be @pure
    expect(
      jethRejects(
        `@contract class C { @external @pure f(t: address, d: bytes): bytes { return t.call({ data: d, success: { condition: this.ok, revert: "x" } }); } }`,
      ),
    ).toBe(true);
    // a staticcall reads the environment -> not @pure
    expect(
      jethRejects(
        `@contract class C { @external @pure f(t: address, d: bytes): bytes { return t.staticcall({ data: d, success: { condition: this.ok, revert: "x" } }); } }`,
      ),
    ).toBe(true);
    // tryCall in value position (must be destructured)
    expect(
      jethRejects(
        `class C { get f(t: address, d: bytes): External<bool> { let x: bool = t.tryCall({ data: d }); return x; } }`,
      ),
    ).toBe(true);
    // this.ok / this.data leak outside a success condition
    expect(jethRejects(`class C { get f(): External<bool> { return this.ok; } }`)).toBe(true);
    expect(jethRejects(`class C { get f(): External<bytes> { return this.data; } }`)).toBe(true);
    // success condition must be bool
    expect(
      jethRejects(
        `class C { get f(t: address, d: bytes): External<bytes> { return t.call({ data: d, success: { condition: this.data.length, revert: "x" } }); } }`,
      ),
    ).toBe(true);
    // revertWith requires bytes
    expect(jethRejects(`class C { f(): External<void> { revertWith(5n); } }`)).toBe(true);
    // .code / .codehash read the environment -> not @pure
    expect(jethRejects(`@contract class C { @external @pure f(t: address): bytes { return t.code; } }`)).toBe(true);
    expect(jethRejects(`@contract class C { @external @pure f(t: address): bytes32 { return t.codehash; } }`)).toBe(
      true,
    );
  });
});
