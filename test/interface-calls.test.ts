// Phase 6: typed interface declarations + high-level calls. Differential tests vs solc 0.8.35.
//
// A JETH caller (using `@interface IFoo { ... }` + `IFoo(addr).method(args)`) and a solc caller
// (using `interface IFoo { function method(...) external ...; }` + `IFoo(addr).method(args)`) are
// deployed against the SAME behaviour target (echo / boom / pay / pair / nada / etc.), invoked with
// identical calldata (the target's harness address as the first arg), and success + returndata + logs
// are diffed. The target is the SAME solc bytecode deployed in both harnesses for the success path so
// its returndata is byte-identical; for the EOA / non-contract path no target is deployed.
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
const IFACE_JETH = `interface IFoo {
  echo(x: u256): u256;
  view2(x: u256): View<u256>;
  boom(): u256;
  custom(): u256;
  panicDiv(x: u256): u256;
  panicAssert(): u256;
  reqFalse(): u256;
  pay(): Payable<u256>;
  setX(x: u256): void;
  pair(): View<[u256, string]>;
  str(): View<string>;
  shortRet(): View<u256>;
  extraRet(): View<u256>;
}`;

// The behaviour target. SAME solc source deployed in both harnesses (byte-identical bytecode), so any
// successful call's returndata is identical. setX writes state (so a STATICCALL to it reverts).
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
  function pay() external payable returns(uint256){ return msg.value; }
  function setX(uint256 x) external { stored = x; }
  function pair() external pure returns(uint256, string memory){ return (42, "hello world here"); }
  function str() external pure returns(string memory){ return "a string value"; }
  // returns a uint128 (32-byte head, == 32, OK) for shortRet/extraRet stand-ins via the same path
  function shortRet() external pure returns(uint256){ return 123; }
  function extraRet() external pure returns(uint256){ return 456; }
}`;

/** Deploy the SAME (solc) target bytecode in both harnesses + a JETH and solc caller; diff results.
 *  The caller is invoked with the target's address as the first 32-byte arg plus any extraArgs. */
async function rt(
  callerJeth: string,
  callerSol: string,
  calls: { sig: string; extraArgs?: string; value?: bigint; noTarget?: boolean }[],
) {
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
      // a non-contract address that was never deployed (an EOA): use a fixed non-deployed address.
      aj = 0x00000000000000000000000000000000deadbeefn;
      as = aj;
    } else {
      const tj = await hj.deploy(tsb.creation);
      const ts = await hs.deploy(tsb.creation);
      aj = BigInt(tj.toString());
      as = BigInt(ts.toString());
    }
    const dj = '0x' + sel(c.sig) + W(aj) + (c.extraArgs ?? '');
    const ds = '0x' + sel(c.sig) + W(as) + (c.extraArgs ?? '');
    const rj = await hj.call(cj, dj, { value: c.value });
    const rs = await hs.call(cs, ds, { value: c.value });
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig}: returndata`).toBe(rs.returnHex);
    expect(JSON.stringify(rj.logs), `${c.sig}: logs`).toBe(JSON.stringify(rs.logs));
  }
}

describe('typed interface calls: byte-identical vs solc', () => {
  it('success: a value-returning CALL', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        f(t: address): External<u256> { return IFoo(t).echo(21n); }
      }`,
      `interface IFoo { function echo(uint256) external returns(uint256); }
      contract C { function f(address t) external returns(uint256){ return IFoo(t).echo(21); } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('success: a @view method lowers to STATICCALL', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        get f(t: address): External<u256> { return IFoo(t).view2(9n); }
      }`,
      `interface IFoo { function view2(uint256) external view returns(uint256); }
      contract C { function f(address t) external view returns(uint256){ return IFoo(t).view2(9); } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('revert bubble: Error(string) verbatim', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        f(t: address): External<u256> { return IFoo(t).boom(); }
      }`,
      `interface IFoo { function boom() external returns(uint256); }
      contract C { function f(address t) external returns(uint256){ return IFoo(t).boom(); } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('revert bubble: a custom error verbatim', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        f(t: address): External<u256> { return IFoo(t).custom(); }
      }`,
      `interface IFoo { function custom() external returns(uint256); }
      contract C { function f(address t) external returns(uint256){ return IFoo(t).custom(); } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('revert bubble: Panic(0x12) divide-by-zero verbatim', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        f(t: address): External<u256> { return IFoo(t).panicDiv(0n); }
      }`,
      `interface IFoo { function panicDiv(uint256) external returns(uint256); }
      contract C { function f(address t) external returns(uint256){ return IFoo(t).panicDiv(0); } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('revert bubble: Panic(0x01) assert verbatim', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        f(t: address): External<u256> { return IFoo(t).panicAssert(); }
      }`,
      `interface IFoo { function panicAssert() external returns(uint256); }
      contract C { function f(address t) external returns(uint256){ return IFoo(t).panicAssert(); } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('revert bubble: require(false) empty revert verbatim', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        f(t: address): External<u256> { return IFoo(t).reqFalse(); }
      }`,
      `interface IFoo { function reqFalse() external returns(uint256); }
      contract C { function f(address t) external returns(uint256){ return IFoo(t).reqFalse(); } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('extcodesize guard: a call to a non-contract (EOA) reverts empty', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        f(t: address): External<u256> { return IFoo(t).echo(21n); }
      }`,
      `interface IFoo { function echo(uint256) external returns(uint256); }
      contract C { function f(address t) external returns(uint256){ return IFoo(t).echo(21); } }`,
      [{ sig: 'f(address)', noTarget: true }],
    );
  });

  it('extcodesize guard: a VOID call to a non-contract reverts empty (no value sent)', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        f(t: address): External<void> { IFoo(t).setX(5n); }
      }`,
      `interface IFoo { function setX(uint256) external; }
      contract C { function f(address t) external { IFoo(t).setX(5); } }`,
      [{ sig: 'f(address)', noTarget: true }],
    );
  });

  it('value: {value} on a @payable method (forwarded)', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        f(t: address): Payable<u256> { return IFoo(t, { value: 3n }).pay(); }
      }`,
      `interface IFoo { function pay() external payable returns(uint256); }
      contract C { function f(address t) external payable returns(uint256){ return IFoo(t).pay{value: 3}(); } }`,
      [{ sig: 'f(address)', value: 10n }],
    );
  });

  it('gas: {gas} option on a method', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        f(t: address): External<u256> { return IFoo(t, { gas: 50000n }).echo(11n); }
      }`,
      `interface IFoo { function echo(uint256) external returns(uint256); }
      contract C { function f(address t) external returns(uint256){ return IFoo(t).echo{gas: 50000}(11); } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('void: a void method called as a statement', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        f(t: address): External<u256> { IFoo(t).setX(99n); return 1n; }
      }`,
      `interface IFoo { function setX(uint256) external; }
      contract C { function f(address t) external returns(uint256){ IFoo(t).setX(99); return 1; } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('tuple return: (uint256, string) via destructuring', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        get f(t: address): External<u256> {
          let [n, s]: [u256, string] = IFoo(t).pair();
          return n;
        }
        get g(t: address): External<string> {
          let [n, s]: [u256, string] = IFoo(t).pair();
          return s;
        }
      }`,
      `interface IFoo { function pair() external view returns(uint256, string memory); }
      contract C {
        function f(address t) external view returns(uint256){ (uint256 n, string memory s) = IFoo(t).pair(); return n; }
        function g(address t) external view returns(string memory){ (uint256 n, string memory s) = IFoo(t).pair(); return s; }
      }`,
      [{ sig: 'f(address)' }, { sig: 'g(address)' }],
    );
  });

  it('string return: a single dynamic return', async () => {
    await rt(
      `${IFACE_JETH}
      class C {
        get f(t: address): External<string> { return IFoo(t).str(); }
      }`,
      `interface IFoo { function str() external view returns(string memory); }
      contract C { function f(address t) external view returns(string memory){ return IFoo(t).str(); } }`,
      [{ sig: 'f(address)' }],
    );
  });

  it('@view CALL of a state-writing method reverts under STATICCALL', async () => {
    // setX is non-view; calling it from a @view caller lowers to STATICCALL, which reverts on SSTORE.
    await rt(
      `${IFACE_JETH}
      class C {
        get f(t: address): External<u256> { return IFoo2(t).setX(5n); }
      }
      interface IFoo2 { setX(x: u256): View<u256>; }`,
      `interface IFoo2 { function setX(uint256) external view returns(uint256); }
      contract C { function f(address t) external view returns(uint256){ return IFoo2(t).setX(5); } }`,
      [{ sig: 'f(address)' }],
    );
  });
});

// A target whose methods return controlled-size returndata (via raw assembly) for a uint256-declared
// method: 0 bytes / 31 bytes (both < head=32 -> the decode reverts EMPTY) and 64 bytes (> head ->
// decode succeeds, the extra trailing word is ignored).
const RET_TARGET_SOL = `contract T {
  function zero() external pure returns(uint256){ assembly { return(0, 0) } }
  function short31() external pure returns(uint256){ assembly { mstore(0, 1) return(0, 31) } }
  function extra64() external pure returns(uint256){ assembly { mstore(0, 7) mstore(32, 99) return(0, 64) } }
}`;

describe('typed interface calls: returndatasize bounds (byte-identical vs solc)', () => {
  async function rtRet(sig: string) {
    const tsb = compileSolidity(SPDX + RET_TARGET_SOL, 'T');
    const callerJeth = `interface IFoo {
      zero(): u256;
      short31(): u256;
      extra64(): u256;
    }
    class C {
      f(t: address): External<u256> { return IFoo(t).${sig}(); }
    }`;
    const callerSol = `interface IFoo { function zero() external returns(uint256); function short31() external returns(uint256); function extra64() external returns(uint256); }
    contract C { function f(address t) external returns(uint256){ return IFoo(t).${sig}(); } }`;
    const cjb = compile(callerJeth, { fileName: 'C.jeth' });
    const csb = compileSolidity(SPDX + callerSol, 'C');
    const hj = await Harness.create();
    const hs = await Harness.create();
    const tj = await hj.deploy(tsb.creation);
    const ts = await hs.deploy(tsb.creation);
    const cj = await hj.deploy(cjb.creationBytecode);
    const cs = await hs.deploy(csb.creation);
    const dj = '0x' + sel('f(address)') + W(BigInt(tj.toString()));
    const ds = '0x' + sel('f(address)') + W(BigInt(ts.toString()));
    const rj = await hj.call(cj, dj);
    const rs = await hs.call(cs, ds);
    expect(rj.success, `${sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${sig}: returndata`).toBe(rs.returnHex);
  }
  it('0-byte returndata < head -> empty revert', async () => {
    await rtRet('zero');
  });
  it('31-byte returndata < head -> empty revert', async () => {
    await rtRet('short31');
  });
  it('64-byte returndata > head -> decode, extra trailing word ignored', async () => {
    await rtRet('extra64');
  });
});

describe('typed interface calls: clean rejections (no crash)', () => {
  const IF = `interface IFoo {
    bar(x: u256): u256;
    baz(): View<bool>;
    deposit(): Payable<u256>;
  }`;
  it('rejects {value} on a non-payable method', () => {
    expect(
      jethRejects(
        `${IF}\nclass C { get f(t: address): External<u256> { return IFoo(t, { value: 1n }).bar(5n); } }`,
      ),
    ).toBe(true);
  });
  it('rejects an unknown method', () => {
    expect(jethRejects(`${IF}\nclass C { get f(t: address): External<u256> { return IFoo(t).nope(5n); } }`)).toBe(
      true,
    );
  });
  it('rejects wrong arity', () => {
    expect(jethRejects(`${IF}\nclass C { get f(t: address): External<u256> { return IFoo(t).bar(); } }`)).toBe(
      true,
    );
  });
  it('rejects an argument type mismatch', () => {
    expect(
      jethRejects(`${IF}\nclass C { f(t: address): External<u256> { return IFoo(t).bar(true); } }`),
    ).toBe(true);
  });
  it('rejects a non-address receiver', () => {
    expect(jethRejects(`${IF}\nclass C { get f(): External<u256> { return IFoo(5n).bar(7n); } }`)).toBe(true);
  });
  it('rejects an unknown wrapper option', () => {
    expect(
      jethRejects(
        `${IF}\nclass C { get f(t: address): External<u256> { return IFoo(t, { gax: 1n }).bar(5n); } }`,
      ),
    ).toBe(true);
  });
  it('rejects a bare interface handle as a value', () => {
    expect(jethRejects(`${IF}\nclass C { get f(t: address): External<u256> { return IFoo(t); } }`)).toBe(true);
  });
  it('rejects a tuple return bound to a single name', () => {
    expect(
      jethRejects(
        `interface IFoo { pair(): [u256, string]; }\nclass C { f(t: address): External<u256> { let x: u256 = IFoo(t).pair(); return x; } }`,
      ),
    ).toBe(true);
  });
  it('rejects a void method used as a value', () => {
    expect(
      jethRejects(
        `interface IFoo { nada(): void; }\nclass C { f(t: address): External<u256> { let x: u256 = IFoo(t).nada(); return x; } }`,
      ),
    ).toBe(true);
  });
  it('rejects a method body in an interface', () => {
    expect(
      jethRejects(
        `interface IFoo { bar(): u256 { return 1n; } }\nclass C { get f(): External<u256> { return 0n; } }`,
      ),
    ).toBe(true);
  });
  it('rejects a state field in an interface', () => {
    expect(
      jethRejects(
        `interface IFoo { x: u256; bar(): u256; }\nclass C { get f(): External<u256> { return 0n; } }`,
      ),
    ).toBe(true);
  });
  it('rejects a private (#) method in an interface (native interface methods are implicitly external)', () => {
    // The legacy "@external required" rule is gone - a plain native interface method is implicitly the
    // external form; the surviving visibility rule is that an interface method may not be private.
    expect(
      jethRejects(`interface IFoo { #bar(): u256; }\nclass C { get f(): External<u256> { return 0n; } }`),
    ).toBe(true);
  });
  it('rejects method overloading in an interface', () => {
    expect(
      jethRejects(
        `interface IFoo { bar(x: u256): u256; bar(x: bool): u256; }\nclass C { get f(): External<u256> { return 0n; } }`,
      ),
    ).toBe(true);
  });
  it('rejects a constructor in an interface', () => {
    expect(
      jethRejects(
        `interface IFoo { constructor(): void; bar(): u256; }\nclass C { get f(): External<u256> { return 0n; } }`,
      ),
    ).toBe(true);
  });
  it('rejects an interface name colliding with a struct', () => {
    expect(
      jethRejects(
        `type IFoo = { x: u256; };\ninterface IFoo { bar(): u256; }\nclass C { get f(): External<u256> { return 0n; } }`,
      ),
    ).toBe(true);
  });
});
